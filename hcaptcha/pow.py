"""
hCaptcha Proof-of-Work — Hashcash v1 + SHA-1.

Confirmed from keys.json: rust-hashcash/0.3.3 with the `sha1` feature
(not default SHA-3). Stamp format `1:bits:date:resource:ext:rand`.
Date format `YYYYMMDD` (UTC).
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone


def solve(req_jwt: str, difficulty: int, resource: str = "") -> str:
    """
    Return a Hashcash stamp meeting `difficulty` leading zero bits.
    Format: `1:{bits}:{YYYYMMDD}:{resource}:{ext}:{rand}`
    """
    bits = difficulty
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    ext = ""
    # resource = the JWT is mixed in so each challenge has a unique solution space
    if not resource:
        resource = req_jwt[:20]

    target_hex = bits // 4
    target = "0" * target_hex
    extra_bits = bits % 4

    counter = 0
    while True:
        rand = f"{counter:x}"
        stamp = f"1:{bits}:{date}:{resource}:{ext}:{rand}"
        digest = hashlib.sha1(stamp.encode()).hexdigest()

        if digest.startswith(target):
            if extra_bits == 0:
                return stamp
            next_val = int(digest[target_hex], 16)
            if next_val < (1 << (4 - extra_bits)):
                return stamp

        counter += 1