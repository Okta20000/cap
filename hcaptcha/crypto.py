"""
Wire-format crypto for hCaptcha.

Confirmed formats (CircuitSavage):
  HSJ  : ct(N) || tag(16) || iv(12) || 0x00     — AES-256-GCM
  HSW  : iv(12) || ct(N) || tag(16)             — AES-256-GCM
  n-tok: ct(N) || tag(16) || iv(12) || 0x02     — AES-256-CTR
         counter block = iv(12) || be32(counter)
         the 16-byte tag is a separate AES block, no AEAD MAC.
"""
from __future__ import annotations

import os
import struct
import zlib
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from config import GCM_IV_BYTES, GCM_TAG_BYTES, AES_KEY_BYTES


# ── HSJ (AES-256-GCM, format ct||tag||iv||0x00) ───────────────
def hsj_encrypt(plaintext: bytes, key_hex: str) -> bytes:
    key = bytes.fromhex(key_hex)
    iv = os.urandom(GCM_IV_BYTES)
    ct_tag = AESGCM(key).encrypt(iv, plaintext, None)
    return ct_tag[:-GCM_TAG_BYTES] + ct_tag[-GCM_TAG_BYTES:] + iv + b"\x00"


def hsj_decrypt(blob: bytes, key_hex: str) -> bytes:
    if blob[-1] != 0x00:
        raise ValueError("bad HSJ version byte")
    ct_tag = blob[:-1 - GCM_IV_BYTES]
    iv = blob[-1 - GCM_IV_BYTES:-1]
    return AESGCM(bytes.fromhex(key_hex)).decrypt(iv, ct_tag, None)


# ── HSW (AES-256-GCM, format iv||ct||tag) ─────────────────────
def hsw_encrypt(plaintext: bytes, key_hex: str) -> bytes:
    key = bytes.fromhex(key_hex)
    iv = os.urandom(GCM_IV_BYTES)
    return iv + AESGCM(key).encrypt(iv, plaintext, None)


def hsw_decrypt(blob: bytes, key_hex: str) -> bytes:
    iv = blob[:GCM_IV_BYTES]
    return AESGCM(bytes.fromhex(key_hex)).decrypt(iv, blob[GCM_IV_BYTES:], None)


# ── n-token (AES-256-CTR) ─────────────────────────────────────
def _ctr_keystream(key: bytes, iv: bytes, length: int) -> bytes:
    """CTR keystream: counter block = iv(12) || be32(counter)."""
    out = bytearray()
    counter = 0
    backend = default_backend()
    while len(out) < length:
        block = iv + struct.pack(">I", counter)
        enc = Cipher(algorithms.AES(key), modes.ECB(), backend=backend).encryptor()
        out += enc.update(block) + enc.finalize()
        counter += 1
    return bytes(out[:length])


def ntoken_encrypt(plaintext: bytes, key_hex: str) -> bytes:
    """Wire: ct(N) || tag(16) || iv(12) || 0x02"""
    key = bytes.fromhex(key_hex)
    iv = os.urandom(GCM_IV_BYTES)
    ks = _ctr_keystream(key, iv, len(plaintext) + 16)
    ct = bytes(p ^ k for p, k in zip(plaintext, ks[:len(plaintext)]))
    tag = ks[len(plaintext):len(plaintext) + 16]
    return ct + tag + iv + b"\x02"


def ntoken_decrypt(blob: bytes, key_hex: str) -> bytes:
    """Inverse of ntoken_encrypt."""
    if blob[-1] != 0x02:
        raise ValueError("bad n-token version byte")
    ct_len = len(blob) - 16 - GCM_IV_BYTES - 1
    ct = blob[:ct_len]
    iv = blob[ct_len + 16: ct_len + 16 + GCM_IV_BYTES]
    ks = _ctr_keystream(bytes.fromhex(key_hex), iv, ct_len)
    return bytes(c ^ k for c, k in zip(ct, ks))


# ── integrity ─────────────────────────────────────────────────
def compute_rand(json_payload: bytes) -> list:
    """CRC-32 of the JSON payload, scaled into [0,1)."""
    crc = zlib.crc32(json_payload) & 0xFFFFFFFF
    return [0.5, crc * 2.3283064365386963e-10]