"""Default settings. Every value can be overridden from the web UI or the API."""

DEFAULTS = {
    # --- Quantum Digital Signature (QDS) layer ---
    "L": 256,            # qubits per (digest-bit, bit-value) block: the main security parameter
    "digest_bits": 32,   # how many bits of the message's SHA-256 digest get signed
    "s_a": 0.10,         # Bob accepts a signature if every block's mismatch rate is below this
    "s_v": 0.20,         # the validator accepts a forwarded signature below this (must be > s_a)
    "qds_noise": 0.02,   # probability that a measured qubit comes out flipped (channel + detector)
    # --- Entanglement fallback layer ---
    "ent_noise": 0.03,   # depolarizing noise on the Bell pairs (visibility = 1 - noise)
    "chsh_min": 2.2,     # abort the fallback if the CHSH value S is not above this (classical limit: 2)
    "qber_max": 0.11,    # abort the fallback if the key-sample error rate is above this
    "pairs": None,       # number of Bell pairs; None = chosen automatically from the message length
    "backend": "auto",   # "auto" (Qiskit if installed, else NumPy) | "numpy" | "qiskit"
    "seed": None,        # integer for reproducible runs; None = different every time
}

MODES = ("plain", "qds", "hybrid")
MODE_NAMES = {"plain": "plain (no protection)", "qds": "QDS only", "hybrid": "QDS + entanglement fallback"}
ROLES = ("sender", "receiver", "validator", "attacker", "bystander")
