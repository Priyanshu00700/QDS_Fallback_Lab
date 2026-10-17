"""Bell-pair measurement backends for the entanglement fallback.

Both backends answer the same question: "Alice and Bob each measure one half of a Bell pair
|Phi+> = (|00> + |11>)/sqrt(2) along a chosen angle in the x-z plane. What bits do they get?"

  * NumpyBackend  : exact analytic statistics, no extra libraries, instant.
  * QiskitBackend : real circuits (H, CX, Ry, measure) run on the Aer simulator, optional.

get_backend() never raises: if Qiskit is missing or broken it falls back to NumPy and says why.
"""
from __future__ import annotations

import numpy as np

# Measurement angles (radians). Alice and Bob each pick one of three at random for every pair.
# (A1,B0) and (A2,B1) use the same angle -> perfectly correlated -> secret key bits.
# (A0,B0), (A0,B2), (A2,B0), (A2,B2) -> the four CHSH terms (S = 2*sqrt(2) for ideal pairs).
ALICE_ANGLES = np.array([0.0, np.pi / 4, np.pi / 2])
BOB_ANGLES = np.array([np.pi / 4, np.pi / 2, 3 * np.pi / 4])


class NumpyBackend:
    name = "numpy"
    detail = "NumPy (exact Bell-pair statistics)"

    def measure(self, a_idx, b_idx, noise, eve, rng):
        """Return (alice_bits, bob_bits). eve=True: an intercept-resend attacker sits on Bob's half."""
        n = len(a_idx)
        visibility = (1.0 - noise) * (0.5 if eve else 1.0)   # depolarizing noise; Eve halves the correlation
        corr = visibility * np.cos(ALICE_ANGLES[a_idx] - BOB_ANGLES[b_idx])
        a = rng.integers(0, 2, n, dtype=np.uint8)
        same = rng.random(n) < (1.0 + corr) / 2.0
        return a, np.where(same, a, 1 - a).astype(np.uint8)


class QiskitBackend:
    name = "qiskit"

    def __init__(self):
        import qiskit
        from qiskit import QuantumCircuit, transpile
        from qiskit_aer import AerSimulator
        from qiskit_aer.noise import NoiseModel, depolarizing_error

        self._QC, self._transpile = QuantumCircuit, transpile
        self._Aer, self._NM, self._dep = AerSimulator, NoiseModel, depolarizing_error
        self._sims = {}
        self.detail = f"Qiskit {qiskit.__version__} + Aer simulator"

    def _sim(self, noise):
        key = round(float(noise), 6)
        if key not in self._sims:
            if key > 0:
                nm = self._NM()
                nm.add_all_qubit_quantum_error(self._dep(key, 1), ["id"])   # noise on the idle gate
                self._sims[key] = self._Aer(noise_model=nm)
            else:
                self._sims[key] = self._Aer()
        return self._sims[key]

    def _circuit(self, ai, bi, eve_basis, noise):
        qc = self._QC(2, 3 if eve_basis is not None else 2)
        qc.h(0)
        qc.cx(0, 1)                      # Bell pair
        if noise > 0:
            qc.id(1)                     # the depolarizing noise attaches to this gate
        if eve_basis is not None:        # intercept-resend: measure Bob's half, re-prepare it
            if eve_basis == 1:
                qc.h(1)
            qc.measure(1, 2)
            if eve_basis == 1:
                qc.h(1)
        qc.ry(-float(ALICE_ANGLES[ai]), 0)   # rotate so a Z-measurement reads the chosen angle
        qc.ry(-float(BOB_ANGLES[bi]), 1)
        qc.measure(0, 0)
        qc.measure(1, 1)
        return qc

    def measure(self, a_idx, b_idx, noise, eve, rng):
        n = len(a_idx)
        e = rng.integers(0, 2, n) if eve else np.full(n, -1)
        code = a_idx * 9 + b_idx * 3 + (e + 1)           # one circuit per (Alice, Bob, Eve) setting
        a_out, b_out = np.zeros(n, np.uint8), np.zeros(n, np.uint8)
        sim = self._sim(noise)
        for c in np.unique(code):
            pos = np.nonzero(code == c)[0]
            ai, bi, eb = int(c // 9), int((c % 9) // 3), int(c % 3) - 1
            qc = self._transpile(self._circuit(ai, bi, None if eb < 0 else eb, noise), sim, optimization_level=0)
            job = sim.run(qc, shots=len(pos), memory=True, seed_simulator=int(rng.integers(2**31 - 1)))
            bits = np.array([[int(s[-1]), int(s[-2])] for s in job.result().get_memory()], dtype=np.uint8)
            a_out[pos], b_out[pos] = bits[:, 0], bits[:, 1]
        return a_out, b_out


_cache = {}


def _qiskit():
    """Build the Qiskit backend once. Returns (backend_or_None, error_text_or_None)."""
    if "qiskit" not in _cache:
        try:
            be = QiskitBackend()
            be.measure(np.array([1]), np.array([0]), 0.0, False, np.random.default_rng(0))   # smoke test
            _cache["qiskit"] = (be, None)
        except Exception as exc:   # ImportError, version mismatch, Aer failure ...
            _cache["qiskit"] = (None, f"{type(exc).__name__}: {exc}")
    return _cache["qiskit"]


def get_backend(preference: str = "auto"):
    """Return (backend, warning). Falls back to NumPy instead of failing."""
    preference = (preference or "auto").lower()
    if preference == "numpy":
        return NumpyBackend(), None
    be, err = _qiskit()
    if be is not None:
        return be, None
    warning = None
    if preference == "qiskit":
        warning = (f"Qiskit backend requested but not usable ({err}). Using NumPy instead. "
                   "To enable Qiskit: pip install qiskit qiskit-aer")
    return NumpyBackend(), warning


def available_backends() -> dict:
    be, err = _qiskit()
    return {
        "numpy": {"available": True, "detail": NumpyBackend.detail},
        "qiskit": {"available": be is not None, "detail": be.detail if be else None, "error": err},
    }
