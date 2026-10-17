"""Fallback payload protection in pure Python: one-time pad + Carter-Wegman one-time MAC.

Both use bits of the key that the entangled pairs produced, and each key is used exactly once.
  * One-time pad: ciphertext = message XOR pad. Perfect secrecy, but it can be flipped bit by bit.
  * One-time MAC: tag = poly(ciphertext, r) + s over the prime field GF(2^127 - 1). Without (r, s)
    the chance of forging a valid tag is at most (number of 15-byte blocks) / 2^127.
"""
from __future__ import annotations

import hmac

import numpy as np

P = (1 << 127) - 1
MAC_KEY_BYTES = 32   # 16 bytes for r and 16 bytes for s


def bits_to_bytes(bits) -> bytes:
    bits = np.asarray(bits, dtype=np.uint8)
    return np.packbits(bits[: len(bits) - len(bits) % 8]).tobytes()


def _poly(data: bytes, r: int) -> int:
    acc = 0
    for i in range(0, len(data), 15):
        block = int.from_bytes(data[i:i + 15] + b"\x01", "little")   # the 0x01 marks the real length
        acc = ((acc + block) * r) % P
    return acc


def _split(key: bytes, n: int):
    r = int.from_bytes(key[:16], "big") % P
    s = int.from_bytes(key[16:32], "big") % P
    return r, s, key[MAC_KEY_BYTES:MAC_KEY_BYTES + n]


def protect(plaintext: bytes, key: bytes):
    """Encrypt-then-MAC. Returns (ciphertext, tag). Raises ValueError if the key is too short."""
    if len(key) < MAC_KEY_BYTES + len(plaintext):
        raise ValueError("key too short for this message")
    r, s, pad = _split(key, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, pad))
    return ciphertext, (_poly(ciphertext, r) + s) % P


def open_(ciphertext: bytes, tag: int, key: bytes):
    """Return the plaintext, or None if the MAC does not verify."""
    r, s, pad = _split(key, len(ciphertext))
    expected = ((_poly(ciphertext, r) + s) % P).to_bytes(16, "big")
    if not hmac.compare_digest(expected, (int(tag) % (1 << 128)).to_bytes(16, "big")):
        return None
    return bytes(a ^ b for a, b in zip(ciphertext, pad))
