#!/usr/bin/env python3
"""domains.txt를 검사해 dist/blocklist.json을 만들고 Ed25519로 서명한다 (Duo Browser 보안 B).

- 목록이 바뀌지 않았으면 아무것도 쓰지 않는다 (버전이 그대로라 앱도 다시 받지 않는다).
- 서명 키는 환경 변수 BLOCKLIST_SIGNING_KEY(32바이트 원시 키의 base64)로만 받는다. 저장소에 키를 두지 않는다.
- 앱은 서명이 맞고, 버전이 지금 것보다 크고, 항목이 아래 규칙을 지킬 때만 적용한다. 여기서도 같은 규칙으로 막는다.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "domains.txt"
OUT = ROOT / "dist" / "blocklist.json"
SIG = ROOT / "dist" / "blocklist.json.sig"
OUT_V2 = ROOT / "dist" / "blocklist-v2.json"
SIG_V2 = ROOT / "dist" / "blocklist-v2.json.sig"
VERSION_V2 = ROOT / "dist" / "blocklist-v2.version"
# 공개 목록은 매일 조금씩 바뀐다. 앱이 매일 6MB를 받지 않도록 공개 목록만 바뀐 것은 3일에 한 번만 새로 서명한다
# (직접 고른 목록·추적 값이 바뀌면 바로)
V2_MIN_AGE = 3 * 24 * 60 * 60
PARAMS = ROOT / "tracking-params.txt"

# 형식 2에 넣는 공개 목록 (라이선스는 앱 설정 > 정보에 함께 보인다)
SOURCES = [
    {"name": "EasyList", "license": "CC BY-SA 3.0", "url": "https://easylist.to/easylist/easylist.txt", "cookie": False},
    {"name": "EasyPrivacy", "license": "CC BY-SA 3.0", "url": "https://easylist.to/easylist/easyprivacy.txt", "cookie": False},
    {"name": "EasyList Cookie List", "license": "CC BY 3.0", "url": "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt", "cookie": True},
]
MAX_V2_RULES = 140_000
PARAM_RE = re.compile(r"^[a-z0-9_]{1,40}$")

MAX_RULES = 5000
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9/._~-]{0,199}$")


def parse(text: str) -> list[dict]:
    rules, seen = [], set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        host, slash, path = line.partition("/")
        path = "/" + path if slash else None
        if host.startswith("www."):
            host = host[4:]
        if not HOST_RE.match(host):
            sys.exit(f"{number}번째 줄: 도메인 형식이 아님: {raw!r}")
        if path is not None and not PATH_RE.match(path):
            sys.exit(f"{number}번째 줄: 경로 형식이 아님: {raw!r}")
        key = (host, path)
        if key in seen:
            sys.exit(f"{number}번째 줄: 중복: {raw!r}")
        seen.add(key)
        rules.append({"host": host} if path is None else {"host": host, "path": path})
    if not 1 <= len(rules) <= MAX_RULES:
        sys.exit(f"항목 수가 1~{MAX_RULES}개가 아님: {len(rules)}")
    return rules


def fetch(url: str) -> str:
    import urllib.request
    request = urllib.request.Request(url, headers={"User-Agent": "duo-browser-blocklist-build"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(20 * 1024 * 1024 + 1)
    if len(data) > 20 * 1024 * 1024:
        sys.exit(f"목록이 너무 큼: {url}")
    return data.decode("utf-8")


def build_v2(own: list[dict], texts: dict[str, str] | None = None) -> dict:
    """형식 2 항목 (version·서명 제외). texts가 없으면 SOURCES를 받아 온다"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from convert import convert

    merged: dict[str, list] = {"block": [], "patterns": [], "allow": [], "hide": [], "cookieHide": []}
    seen_hosts = set()
    for rule in own:  # 직접 고른 목록이 먼저
        key = (rule["host"], rule.get("path"))
        if key not in seen_hosts:
            seen_hosts.add(key)
            merged["block"].append(rule)
    for source in SOURCES:
        text = texts[source["name"]] if texts else fetch(source["url"])
        converted = convert(text, cookie=source["cookie"])
        for kind, items in converted.items():
            for item in items:
                if kind == "block":
                    key = (item["host"], item.get("path"))
                    if key in seen_hosts:
                        continue
                    seen_hosts.add(key)
                merged[kind].append(item)
    params = []
    for raw in PARAMS.read_text(encoding="utf-8").splitlines():
        name = raw.split("#", 1)[0].strip().lower()
        if not name:
            continue
        if not PARAM_RE.match(name):
            sys.exit(f"추적 값 이름 형식이 아님: {raw!r}")
        params.append(name)
    total = sum(len(v) for v in merged.values())
    if not 1 <= total <= MAX_V2_RULES:
        sys.exit(f"형식 2 규칙 수가 1~{MAX_V2_RULES}개가 아님: {total}")
    return {
        "format": 2,
        "sources": [{k: s[k] for k in ("name", "license", "url")} for s in SOURCES]
                   + [{"name": "Duo Browser", "license": "CC BY-SA 3.0", "url": "https://github.com/laesk2/duo-browser-blocklist"}],
        **merged,
        "trackingParams": sorted(set(params)),
    }


def sign_if_changed(payload_body: dict, out: Path, sig: Path, digest_key: str, own_digest: str) -> None:
    digest = hashlib.sha256(json.dumps(payload_body, sort_keys=True).encode()).hexdigest()
    force = os.environ.get("FORCE_SIGN") == "1"
    if out.exists():
        previous = json.loads(out.read_text(encoding="utf-8"))
        if previous.get(digest_key) == digest and not force:
            print(f"{out.name}: 바뀌지 않음, 그대로 둔다")
            return
        own_changed = previous.get("ownSHA256") != own_digest
        age = time.time() - int(previous.get("version", 0))
        if not own_changed and age < V2_MIN_AGE and not force:
            print(f"{out.name}: 공개 목록만 바뀜, {int(age // 3600)}시간 전에 서명해서 이번에는 건너뜀")
            return
        version = max(int(time.time()), int(previous.get("version", 0)) + 1)
    else:
        version = int(time.time())
    key_b64 = os.environ.get("BLOCKLIST_SIGNING_KEY")
    if not key_b64:
        sys.exit("BLOCKLIST_SIGNING_KEY가 없음")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_b64))
    payload = {**payload_body, "version": version, digest_key: digest, "ownSHA256": own_digest}
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    out.parent.mkdir(exist_ok=True)
    out.write_bytes(data)
    sig.write_text(base64.b64encode(key.sign(data)).decode() + "\n")
    # 앱이 먼저 받아 보는 작은 파일 (새 버전일 때만 큰 목록을 받는다)
    VERSION_V2.write_text(f"{version}\n")
    print(f"{out.name}: 버전 {version}, 규칙 {sum(len(payload_body[k]) for k in ('block','patterns','allow','hide','cookieHide'))}개를 서명함")


def own_digest(rules: list[dict]) -> str:
    return hashlib.sha256((json.dumps(rules, sort_keys=True) + PARAMS.read_text(encoding="utf-8")).encode()).hexdigest()


def main() -> None:
    rules = parse(SOURCE.read_text(encoding="utf-8"))
    # 형식 2 (빌드 42부터): 공개 목록 + 직접 고른 목록 + 추적 값
    if os.environ.get("SKIP_V2") != "1":
        sign_if_changed(build_v2(rules), OUT_V2, SIG_V2, "bodySHA256", own_digest(rules))
    digest = hashlib.sha256(json.dumps(rules, sort_keys=True).encode()).hexdigest()
    if OUT.exists():
        previous = json.loads(OUT.read_text(encoding="utf-8"))
        if previous.get("rulesSHA256") == digest and os.environ.get("FORCE_SIGN") != "1":
            print("목록이 바뀌지 않음: 그대로 둔다")
            return
        version = max(int(time.time()), int(previous.get("version", 0)) + 1)
    else:
        version = int(time.time())

    key_b64 = os.environ.get("BLOCKLIST_SIGNING_KEY")
    if not key_b64:
        sys.exit("BLOCKLIST_SIGNING_KEY가 없음")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_b64))
    payload = {"format": 1, "version": version, "rulesSHA256": digest, "rules": rules}
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_bytes(data)
    SIG.write_text(base64.b64encode(key.sign(data)).decode() + "\n")
    print(f"버전 {version}, 항목 {len(rules)}개를 서명함")


def write_bundle(out_path: str) -> None:
    """앱에 넣을 형식 2 목록 (서명하지 않는다: 앱 서명이 보호한다). 빌드 때 한 번 만든다"""
    rules = parse(SOURCE.read_text(encoding="utf-8"))
    body = build_v2(rules)
    payload = {**body, "version": int(time.time())}
    Path(out_path).write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                              encoding="utf-8")
    print(f"앱용 목록: 규칙 {sum(len(body[k]) for k in ('block','patterns','allow','hide','cookieHide'))}개 → {out_path}")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--bundle":
        write_bundle(sys.argv[2])
    else:
        main()
