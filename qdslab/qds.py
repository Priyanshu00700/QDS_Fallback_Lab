"""
Quantum Digital Signature (QDS) layer: a simplified BB84-state scheme simulated with NumPy.

The idea in one paragraph
-------------------------
Alice owns a *private key*: for every signed digest bit j and every possible bit value b in {0, 1}
she holds L random BB84 states, each described classically by (basis, value).
The *public key* is the matching set of **quantum** states, one copy sent to each recipient
(Bob and the validator). A recipient cannot read out the classical description from a single copy
(no-cloning), so he measures every qubit in a random basis and stores (basis, outcome).

To sign, Alice reveals the private-key blocks that belong to the digest bits of her message.
A recipient compares them with his record. Only positions where his measurement basis equals the
revealed basis can be checked. There an honest signature gives almost no mismatches (just channel
noise), while a forger who has to guess gives about 50 %.

Array shapes used throughout:  (J, 2, L) = (digest bit, bit value, position inside the block).
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

import numpy as np


@dataclass
class PrivateKey:
    basis: np.ndarray   # (J, 2, L) of 0 (Z basis) or 1 (X basis)
    value: np.ndarray   # (J, 2, L) of 0 or 1


@dataclass
class Record:
    """What a recipient measured while receiving the quantum states."""
    basis: np.ndarray   # (J, 2, L) basis he chose
    outcome: np.ndarray  # (J, 2, L) result he got


@dataclass
class Signature:
    basis: np.ndarray   # (J, L)
    value: np.ndarray   # (J, L)


def digest_bits(message: str, n: int) -> np.ndarray:
    """First n bits of SHA-256(message), as an array of 0/1."""
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    return np.unpackbits(np.frombuffer(digest, dtype=np.uint8))[:n].astype(np.intp)


def generate_private_key(J: int, L: int, rng: np.random.Generator) -> PrivateKey:
    shape = (J, 2, L)
    return PrivateKey(rng.integers(0, 2, shape, dtype=np.uint8), rng.integers(0, 2, shape, dtype=np.uint8))


def distribute(key: PrivateKey, rng: np.random.Generator, noise: float, tap: bool = False):
    """Send one copy of every public-key qubit to a recipient who measures it in a random basis.

    tap=True models an intercept-resend attacker on that quantum link: he measures every qubit in a
    random basis and forwards a fresh qubit prepared from his own result. Returns (record, eve_record).
    """
    shape = key.basis.shape
    sent_basis, sent_value = key.basis, key.value
    eve = None
    if tap:
        eb = rng.integers(0, 2, shape, dtype=np.uint8)
        eo = np.where(eb == sent_basis, sent_value, rng.integers(0, 2, shape, dtype=np.uint8)).astype(np.uint8)
        eve = Record(eb, eo)
        sent_basis, sent_value = eb, eo
    rb = rng.integers(0, 2, shape, dtype=np.uint8)
    # same basis -> deterministic outcome; different basis -> fair coin flip
    ro = np.where(rb == sent_basis, sent_value, rng.integers(0, 2, shape, dtype=np.uint8)).astype(np.uint8)
    ro ^= (rng.random(shape) < noise).astype(np.uint8)
    return Record(rb, ro), eve


def sign(key: PrivateKey, bits: np.ndarray) -> Signature:
    idx = np.arange(len(bits))
    return Signature(key.basis[idx, bits].copy(), key.value[idx, bits].copy())


def random_signature(J: int, L: int, rng: np.random.Generator) -> Signature:
    """A blind guess: what a forger with no information can produce."""
    return Signature(rng.integers(0, 2, (J, L), dtype=np.uint8), rng.integers(0, 2, (J, L), dtype=np.uint8))


def signature_from_record(rec: Record, bits: np.ndarray) -> Signature:
    """A forger who intercept-resent the states claims what he measured as the private key."""
    idx = np.arange(len(bits))
    return Signature(rec.basis[idx, bits].copy(), rec.outcome[idx, bits].copy())


def verify(record: Record, sig: Signature, bits: np.ndarray, threshold: float):
    """Check a signature for a message whose digest bits are `bits`.

    Returns (rates, checked, accepted): the mismatch rate and the number of checkable positions per
    block, and whether EVERY block is below the threshold (each digest bit is verified on its own).
    """
    idx = np.arange(len(bits))
    rb, ro = record.basis[idx, bits], record.outcome[idx, bits]
    comparable = rb == sig.basis
    checked = comparable.sum(axis=1)
    mismatches = ((ro != sig.value) & comparable).sum(axis=1)
    rates = np.where(checked > 0, mismatches / np.maximum(checked, 1), 1.0)
    return rates, checked, bool(np.all(rates < threshold))


# ---------------------------------------------------------------- security estimates (log10 scale)
def _log_pmf(i: int, n: int, p: float) -> float:
    return (math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
            + i * math.log(p) + (n - i) * math.log(1 - p))


def _log10_tail(lo: int, hi: int, n: int, p: float) -> float:
    """log10 of P(lo <= X <= hi) for X ~ Binomial(n, p)."""
    lo, hi = max(lo, 0), min(hi, n)
    if lo > hi:
        return -math.inf
    if p <= 0:
        return 0.0 if lo == 0 else -math.inf
    if p >= 1:
        return 0.0 if hi == n else -math.inf
    terms = [_log_pmf(i, n, p) for i in range(lo, hi + 1)]
    top = max(terms)
    return (top + math.log(sum(math.exp(t - top) for t in terms))) / math.log(10)


def _clip(x: float) -> float:
    return -9999.0 if x == -math.inf else round(x, 2)


def security_estimates(L: int, J: int, s_a: float, noise: float) -> dict:
    """Rough odds as powers of ten, assuming about L/2 checkable positions per block."""
    n = max(L // 2, 1)
    k = math.ceil(s_a * n) - 1                       # most mismatches that still count as "below s_a"
    forge_block = _log10_tail(0, k, n, 0.5)          # a blind forger passing ONE block
    reject_block = _log10_tail(k + 1, n, n, noise)   # an honest signature failing ONE block
    return {
        "forgery_log10_block": _clip(forge_block),
        "forgery_log10_message": _clip(forge_block * (J / 2)),   # a fake differs in ~J/2 digest bits
        "false_reject_log10": _clip(reject_block + math.log10(max(J, 1))),
    }
