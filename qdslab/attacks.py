"""Attacker behaviours. The engine asks this module what the attacker does to each message."""
from __future__ import annotations

from . import qds

PRIMARY = {
    "pass": "Passive: watches the primary route but changes nothing.",
    "drop": "Blocks Alice's message (denial of service).",
    "forge": "Blocks Alice's message and sends a forged one with a guessed signature (impersonation).",
    "tamper": "Edits the text but re-attaches Alice's genuine signature.",
    "intercept_resend": "Measures and re-sends the quantum states on the link to Bob, which disturbs them.",
    "eavesdrop_forge": "Intercept-resends Bob's quantum states, then forges a signature from what he measured.",
}
BACKUP = {
    "pass": "Leaves the backup route alone.",
    "block": "Blocks the backup route (availability attack).",
    "forge": "Re-encrypts his own text with the pad he recovered; he cannot compute a valid MAC tag.",
}


def apply_primary(mode, msg, sig, forged_text, J, L, rng, eve_rec):
    """What reaches Bob on the primary route: (message, signature, title, detail). message None = dropped."""
    if mode == "drop":
        return None, None, "blocks the message", "It never reaches the receiver."
    if mode == "forge":
        return (forged_text, qds.random_signature(J, L, rng), "replaces the message with a forgery",
                f"Sends “{forged_text}” as if it came from the sender. He holds no private key, so every "
                "signature element (basis and value) is a blind guess.")
    if mode == "tamper":
        return (forged_text, sig, "edits the message but keeps the genuine signature",
                f"Changes the text to “{forged_text}” and re-attaches the original signature.")
    if mode == "eavesdrop_forge":
        fake = qds.signature_from_record(eve_rec, qds.digest_bits(forged_text, J))
        return (forged_text, fake, "forges a signature from the states he intercepted",
                f"Sends “{forged_text}” and claims what he measured on the quantum link as the private key. "
                "It matches Bob's record (Bob measured Charlie's re-sent states) but not the validator's.")
    return msg, sig, "forwards the message unchanged", "Passive on the classical route."


def apply_backup(mode, ciphertext, tag, plaintext, forged_text):
    """What reaches Bob on the backup route: (ciphertext, tag, title, detail). ciphertext None = blocked."""
    if mode == "block":
        return None, None, "blocks the backup route", "No ciphertext arrives. Availability is lost, authenticity is not."
    if mode == "forge":
        pad = bytes(c ^ p for c, p in zip(ciphertext, plaintext))   # known plaintext: he saw it in clear on the primary route
        fake_plain = forged_text.encode("utf-8")[:len(ciphertext)].ljust(len(ciphertext), b" ")
        fake_ct = bytes(a ^ b for a, b in zip(pad, fake_plain))
        return (fake_ct, tag, "re-encrypts his own text with the recovered pad",
                "He saw the plaintext on the primary route, so he can swap the ciphertext. "
                "He cannot recompute the one-time MAC tag without the MAC key.")
    return ciphertext, tag, "leaves the backup route alone", ""
