#!/usr/bin/env python3
"""공개 차단 목록(Adblock Plus 문법)을 Duo Browser 형식 2 항목으로 바꾼다.

앱은 이 항목으로 WebKit 콘텐츠 규칙을 직접 만든다. 목록이 만들 수 있는 것은 다음뿐이다.
- block: 도메인(+경로) 막기
- patterns: 주소 패턴 막기 (WebKit url-filter 정규식의 좁은 부분 집합)
- allow: 위 막기의 예외 (@@ 규칙, ignore-previous-rules)
- hide / cookieHide: CSS 선택자로 요소 숨기기 (css-display-none)
허용 목록에 없는 문법·옵션은 버린다 (스크립트 주입, 페이지 바꾸기, 원시 정규식 등).
앱도 같은 검사를 다시 한다 (BlocklistUpdater.validate).
"""
from __future__ import annotations

import re
from collections import defaultdict

# --- 앱과 같은 검사 규칙 -------------------------------------------------------
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# url-filter에 쓰는 글자 (WebKit 정규식 부분 집합: . * + ? [ ] ( ) ^ $ \ 와 주소 글자)
FILTER_RE = re.compile(r"^[A-Za-z0-9._~:/?#@!$&'()*+,;=%\[\]^\\-]{1,400}$")
# CSS 선택자: 중괄호·세미콜론·@·역슬래시·꺾쇠 여는 것(<)은 금지 (스타일 주입 방지)
SELECTOR_RE = re.compile(r"^[A-Za-z0-9 #.:\[\]=\"'*^$|~>+(),_/?&%!-]{1,500}$")
RESOURCE_TYPES = {
    "script": "script", "image": "image", "stylesheet": "style-sheet", "font": "font",
    "media": "media", "subdocument": "document", "xmlhttprequest": "fetch", "ping": "ping",
    "websocket": "websocket", "other": "other", "popup": "popup", "object": "other",
}
# 브라우저 CSS가 아닌 확장 선택자 (Adblock Plus·uBlock 전용). WebKit은 이해하지 못해 그 숨기기 규칙이 통째로 무시되거나
# 숨기기 컴파일이 실패한다. 선택자 글자 검사(SELECTOR_RE)는 통과하므로 따로 거른다
EXTENDED_SELECTOR_RE = re.compile(
    r":-abp-|:has-text\(|:contains\(|:xpath\(|:matches-css|:matches-attr|:matches-path|:upward\(|:remove\(|"
    r":style\(|:watch-attr|:min-text-length|:others\(|:if\(|:if-not\(|:nth-ancestor\(|:matches-media"
)


def is_plain_selector(selector: str) -> bool:
    """WebKit css-display-none에 쓸 수 있는 보통 CSS 선택자인지"""
    return bool(SELECTOR_RE.match(selector)) and not selector.startswith("^") and not EXTENDED_SELECTOR_RE.search(selector)


# 앱과 같은 한도: 한 규칙의 도메인 수
MAX_DOMAINS = 2000
# 의미는 바꾸지 않아 무시해도 되는 옵션
IGNORED_OPTIONS = {"important", "match-case", "~match-case"}


def domain_list(value: str) -> tuple[list[str], list[str]] | None:
    """$domain=a.com|~b.com → (if, unless). 둘이 섞이면 WebKit 한 규칙에 못 넣으므로 None"""
    include, exclude = [], []
    for part in value.split("|"):
        neg = part.startswith("~")
        host = part[1:] if neg else part
        host = host.lower()
        if host.startswith("www."):
            host = host[4:]
        if not HOST_RE.match(host):
            return None
        (exclude if neg else include).append(host)
    if include and exclude:
        return None
    if len(include) > MAX_DOMAINS or len(exclude) > MAX_DOMAINS:
        return None
    return include, exclude


def abp_to_regex(pattern: str) -> str | None:
    """ABP 주소 패턴 → WebKit url-filter. 원시 정규식(/.../)은 쓰지 않는다"""
    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
        return None
    out = []
    i = 0
    if pattern.startswith("||"):
        out.append(r"^[^:]+://+([^:/]+\.)?")
        i = 2
    elif pattern.startswith("|"):
        out.append("^")
        i = 1
    body = pattern[i:]
    end_anchor = body.endswith("|")
    if end_anchor:
        body = body[:-1]
    if not body or body.strip("*^") == "":
        return None
    for ch in body:
        if ch == "*":
            out.append(".*")
        elif ch == "^":
            out.append(r"[^a-zA-Z0-9_.%-]")
        elif ch in ".+?()[]{}\\$|":
            if ch in "{}|":
                return None  # WebKit 정규식이 못 다루는 글자
            out.append("\\" + ch)
        else:
            out.append(ch)
    if end_anchor:
        out.append("$")
    regex = "".join(out)
    # 끝의 .* 는 의미가 없다
    while regex.endswith(".*"):
        regex = regex[:-2]
    if not FILTER_RE.match(regex):
        return None
    return regex


def simple_host(pattern: str) -> str | None:
    """||example.com^ 꼴이면 도메인만 (가장 흔하고 가장 빠른 규칙)"""
    m = re.fullmatch(r"\|\|([a-z0-9.-]+)\^?", pattern.lower())
    if not m:
        return None
    host = m.group(1)
    if host.startswith("www."):
        host = host[4:]
    return host if HOST_RE.match(host) else None


def parse_network(line: str) -> tuple[str, dict] | None:
    """네트워크 규칙 한 줄 → ('block'|'pattern'|'allow', 항목) 또는 None(버림)"""
    allow = line.startswith("@@")
    if allow:
        line = line[2:]
    pattern, _, opts = line.partition("$")
    if "$" in opts:
        return None
    entry: dict = {}
    types: list[str] = []
    for opt in filter(None, opts.split(",")):
        opt = opt.strip()
        if opt in IGNORED_OPTIONS:
            continue
        if opt == "third-party" or opt == "3p":
            entry["thirdParty"] = True
        elif opt in ("~third-party", "1p", "first-party"):
            entry["thirdParty"] = False
        elif opt.startswith("domain="):
            lists = domain_list(opt[7:])
            if lists is None:
                return None
            include, exclude = lists
            if include:
                entry["ifDomain"] = include
            if exclude:
                entry["unlessDomain"] = exclude
        elif opt in RESOURCE_TYPES:
            types.append(RESOURCE_TYPES[opt])
        else:
            return None  # csp, redirect, removeparam, ~script 같은 것은 바꿀 수 없다
    if types:
        entry["types"] = sorted(set(types))
    host = simple_host(pattern)
    if host and not allow and not entry:
        return "block", {"host": host}
    regex = abp_to_regex(pattern)
    if regex is None:
        return None
    entry["filter"] = regex
    return ("allow" if allow else "pattern"), entry


def convert(text: str, *, cookie: bool = False) -> dict[str, list]:
    """한 목록 → 항목들. cookie=True면 숨기기는 쿠키 동의 창 숨기기(cookieHide)로"""
    block: list[dict] = []
    patterns: list[dict] = []
    allow: list[dict] = []
    generic: set[str] = set()
    generic_except: dict[str, set[str]] = defaultdict(set)
    specific: dict[str, set[str]] = defaultdict(set)  # 선택자 → 도메인들
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("["):
            continue
        if "#@#" in line:
            domains, _, selector = line.partition("#@#")
            if is_plain_selector(selector):
                for d in filter(None, domains.split(",")):
                    d = d.lower().removeprefix("www.")
                    if HOST_RE.match(d):
                        generic_except[selector].add(d)
            continue
        if "##" in line:
            domains, _, selector = line.partition("##")
            if not is_plain_selector(selector) or selector.startswith("+js"):
                continue
            if not domains:
                generic.add(selector)
                continue
            parts = [d.lower().removeprefix("www.") for d in domains.split(",")]
            if any(p.startswith("~") for p in parts):
                continue
            hosts = [p for p in parts if HOST_RE.match(p)]
            if hosts:
                specific[selector].update(hosts)
            continue
        if "#?#" in line or "#$#" in line or "#%#" in line or "$$" in line:
            continue
        parsed = parse_network(line)
        if parsed is None:
            continue
        kind, entry = parsed
        {"block": block, "pattern": patterns, "allow": allow}[kind].append(entry)

    hides: list[dict] = []
    # 어디서나 숨기는 것: 예외 도메인이 같은 것끼리 묶어 규칙 수를 줄인다
    by_unless: dict[tuple, list[str]] = defaultdict(list)
    for selector in sorted(generic):
        by_unless[tuple(sorted(generic_except.get(selector, ())))].append(selector)
    for unless, selectors in sorted(by_unless.items()):
        if len(unless) > MAX_DOMAINS:
            continue  # 예외 사이트가 너무 많은 숨기기는 쓰지 않는다
        for chunk in chunks(selectors, 250):
            item: dict = {"selectors": chunk}
            if unless:
                item["unlessDomain"] = list(unless)
            hides.append(item)
    # 사이트별로 숨기는 것: 도메인 묶음이 같은 것끼리
    by_domains: dict[tuple, list[str]] = defaultdict(list)
    for selector, hosts in specific.items():
        by_domains[tuple(sorted(hosts))].append(selector)
    for hosts, selectors in sorted(by_domains.items()):
        if len(hosts) > MAX_DOMAINS:
            continue
        for chunk in chunks(sorted(selectors), 250):
            hides.append({"selectors": chunk, "ifDomain": list(hosts)})
    if cookie:
        # 쿠키 동의 창 목록은 숨기기만 쓴다 (동의 스크립트를 막으면 사이트가 멈추는 일이 있다)
        return {"cookieHide": hides}
    return {"block": block, "patterns": patterns, "allow": allow, "hide": hides}


def chunks(items: list, size: int) -> list[list]:
    return [items[i:i + size] for i in range(0, len(items), size)]
