#!/usr/bin/env python3
"""dist의 목록(형식 1·2) 서명을 공개 키(signing-public-key.txt)로 확인한다. 앱과 같은 확인을 매일 한다."""
import base64
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent
key = Ed25519PublicKey.from_public_bytes(base64.b64decode((ROOT / "signing-public-key.txt").read_text().strip()))
for name in ("blocklist.json", "blocklist-v2.json"):
    path = ROOT / "dist" / name
    if not path.exists():
        if name == "blocklist.json":
            sys.exit(f"{name} 없음")
        continue
    signature = base64.b64decode((ROOT / "dist" / (name + ".sig")).read_text().strip())
    try:
        key.verify(signature, path.read_bytes())
    except InvalidSignature:
        sys.exit(f"{name}: 서명이 맞지 않음")
    print(f"{name}: 서명 확인됨")
