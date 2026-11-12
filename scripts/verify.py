#!/usr/bin/env python3
"""dist/blocklist.json의 서명을 공개 키(signing-public-key.txt)로 확인한다. 앱과 같은 확인을 매일 한다."""
import base64
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent
key = Ed25519PublicKey.from_public_bytes(base64.b64decode((ROOT / "signing-public-key.txt").read_text().strip()))
data = (ROOT / "dist" / "blocklist.json").read_bytes()
signature = base64.b64decode((ROOT / "dist" / "blocklist.json.sig").read_text().strip())
try:
    key.verify(signature, data)
except InvalidSignature:
    sys.exit("서명이 맞지 않음")
print("서명 확인됨")
