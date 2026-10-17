"""Entanglement fallback: an E91-style key exchange over Bell pairs.

Steps (all simulated):
  1. A source gives Alice and Bob one half of each of N Bell pairs.
  2. For every pair each picks one of three measurement angles at random (backends.py).
  3. CHSH test: four of the nine angle combinations violate Bell's inequality (S up to 2*sqrt(2)
     = 2.83) only if the pairs are really entangled. An eavesdropper or heavy noise pulls S down
     towards or below the classical limit 2.
  4. Sifting: two angle combinations coincide -> Alice's and Bob's bits agree -> raw key.
  5. A random 25 % of the raw key is sacrificed to estimate the error rate (QBER).
  6. If S and QBER are fine, the rest becomes the shared key. Real systems would now run error
     correction and privacy amplification; here the final length uses the standard asymptotic
     rate n * (1 - 2*h2(q)) and both sides are assumed to hold identical bits (see the docs).
"""
from __future__ import annotations

import math

import numpy as np

from . import classical


def h2(p: float) -> float:
    """Binary entropy in bits."""
    if p <= 0 or p >= 1:
        return 0.0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


def auto_pairs(needed_bits: int, noise: float, cap: int) -> int:
    """How many Bell pairs to use so the final key is long enough (with a 50 % safety margin)."""
    q = min(0.5, noise / 2 + 0.02)                    # expected error rate + margin
    rate = max(1 - 2 * h2(q), 0.02)                   # secret fraction of the sifted bits
    per_pair = (2 / 9) * 0.75 * rate                  # 2/9 sifted, 75 % not used for the QBER sample
    return int(min(max(1.5 * needed_bits / per_pair, 3000), cap))


def run_e91(backend, n_pairs, noise, tap, rng, chsh_min, qber_max) -> dict:
    a_idx = rng.integers(0, 3, n_pairs)
    b_idx = rng.integers(0, 3, n_pairs)
    a_bits, b_bits = backend.measure(a_idx, b_idx, noise, tap, rng)

    def corr(ai, bi):
        m = (a_idx == ai) & (b_idx == bi)
        if not m.any():
            return 0.0
        return float(np.mean((1 - 2 * a_bits[m].astype(int)) * (1 - 2 * b_bits[m].astype(int))))

    S = corr(0, 0) - corr(0, 2) + corr(2, 0) + corr(2, 2)

    key_mask = ((a_idx == 1) & (b_idx == 0)) | ((a_idx == 2) & (b_idx == 1))
    ka, kb = a_bits[key_mask], b_bits[key_mask]
    sample = rng.random(len(ka)) < 0.25
    result = {"S": float(S), "pairs": int(n_pairs), "sifted": int(len(ka)), "qber": 1.0,
              "key": b"", "key_bits": 0, "secure": False, "reason": ""}
    if sample.sum() < 20:
        result["reason"] = "too few pairs to estimate the error rate"
        return result

    qber = float(np.mean(ka[sample] != kb[sample]))
    result["qber"] = qber
    if S <= chsh_min:
        result["reason"] = (f"CHSH S = {S:.2f} is not above {chsh_min}: the pairs are not entangled enough "
                            "(the link is being tapped or is too noisy), so nothing derived from them can be trusted")
    elif qber > qber_max:
        result["reason"] = f"error rate {qber:.1%} is above the {qber_max:.0%} limit"
    else:
        rest = ka[~sample]
        usable = int(len(rest) * max(0.0, 1 - 2 * h2(min(0.5, qber + 0.01))))
        key = classical.bits_to_bytes(rest[:usable])
        result.update(key=key, key_bits=8 * len(key), secure=True)
    return result
