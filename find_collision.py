#!/usr/bin/env python3
"""Show why the number of signed digest bits matters.

The quantum signature only covers the FIRST N bits of SHA-256(message). If N is small, an attacker can search
for a different message whose first N bits are the same, then attach Alice's genuine signature to it: every
check passes, quantum or not. Searching costs about 2**N hashes.

    python find_collision.py "Meet at the lab at 5pm" --bits 16     # about 65,000 tries, instant
    python find_collision.py "Meet at the lab at 5pm" --bits 24     # about 17 million tries, a minute or so

Then in the web UI: set "Digest bits signed" to the same N, give the attacker "Edit, keep the signature" and
paste the printed text into "Fake message text". The forgery is accepted, even with a validator.
With N = 32 the search needs billions of hashes: out of reach for a classroom demo, but not for a determined
attacker. Real use needs a digest of 128 bits or more (the engine accepts up to 256).
"""
import argparse
import hashlib
import itertools
import time


def prefix(text: str, n: int) -> int:
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest(), "big") >> (256 - n)


def find(message: str, bits: int, stem: str = "Pay Charlie"):
    target = prefix(message, bits)
    for i in itertools.count(1):
        candidate = f"{stem} #{i}"
        if prefix(candidate, bits) == target:
            return candidate, i


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("message", help="the genuine message")
    ap.add_argument("--bits", type=int, default=16, help="how many digest bits the signature covers (default 16)")
    args = ap.parse_args()
    if not 1 <= args.bits <= 40:
        raise SystemExit("--bits must be between 1 and 40 here (more would take far too long).")
    start = time.time()
    text, tries = find(args.message, args.bits)
    print(f"Found after {tries:,} tries ({time.time() - start:.1f}s):\n  {text}")
    print(f"Same first {args.bits} digest bits as: {args.message}")


if __name__ == "__main__":
    main()
