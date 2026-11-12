#!/usr/bin/env python3
"""domains.txt를 검사해 dist/blocklist.json을 만들고 Ed25519로 서명한다 (Duo Browser 보안 B).

- 목록이 바뀌지 않았으면 아무것도 쓰지 않는다 (버전이 그대로라 앱도 다시 받지 않는다).
- 서명 키는 환경 변수 BLOCKLIST_SIGNING_KEY(32바이트 원시 키의 base64)로만 받는다. 저장소에 키를 두지 않는다.
- 앱은 서명이 맞고, 버전이 지금 것보다 크고, 항목이 아래 규칙을 지킬 때만 적용한다. 여기서도 같은 규칙으로 막는다.
"""
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


def main() -> None:
    rules = parse(SOURCE.read_text(encoding="utf-8"))
    digest = hashlib.sha256(json.dumps(rules, sort_keys=True).encode()).hexdigest()
    if OUT.exists():
        previous = json.loads(OUT.read_text(encoding="utf-8"))
        if previous.get("rulesSHA256") == digest:
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


if __name__ == "__main__":
    main()
