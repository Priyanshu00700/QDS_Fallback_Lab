"""Scenario engine: sends one message from the sender to the receiver through the chosen security
mode, lets the attacker act, and returns a step-by-step event log plus metrics for the UI.

Modes
  plain   - no protection: the receiver accepts whatever arrives.
  qds     - quantum digital signature only.
  hybrid  - QDS first; if it fails, switch to the entanglement fallback (E91 key + one-time pad + MAC).
"""
from __future__ import annotations

import numpy as np

from . import attacks, backends, classical, entanglement, qds
from .config import DEFAULTS, MODE_NAMES, MODES

REASONS = {
    "no_message": "no message arrived on the primary route",
    "bob_reject": "the signature did not match the receiver's quantum record: forgery, tampering, "
                  "eavesdropping or plain noise, QDS cannot tell which",
    "validator_reject": "the validator could not confirm the signature, so it is not transferable",
}


class Log:
    def __init__(self):
        self.events = []

    def add(self, phase, kind, title, detail="", frm=None, to=None):
        """kind: info | ok | warn | bad | attack. frm/to are user names (used to animate packets)."""
        self.events.append({"n": len(self.events) + 1, "phase": phase, "kind": kind,
                            "title": title, "detail": detail, "from": frm, "to": to})


def _q(text):
    return f"“{text}”"


def _block_stats(rates, checked, accepted):
    return {"rates": [round(float(r), 4) for r in rates], "max": round(float(rates.max()), 4),
            "mean": round(float(rates.mean()), 4), "checked_mean": round(float(checked.mean()), 1),
            "accepted": bool(accepted)}


# ------------------------------------------------------------------------------- QDS phase
def _qds_phase(log, rng, S, msg, forged_text, prim, A, B, V, C):
    J, L = int(S["digest_bits"]), int(S["L"])
    if not 1 <= J <= 256:
        raise ValueError("digest_bits must be between 1 and 256.")
    if L < 8:
        raise ValueError("L must be at least 8.")
    sa, sv, noise = float(S["s_a"]), float(S["s_v"]), float(S["qds_noise"])
    nq = J * 2 * L
    m = {"L": L, "digest_bits": J, "s_a": sa, "s_v": sv, "noise": noise, "qubits_per_recipient": nq,
         "bob": None, "validator": None}
    m.update(qds.security_estimates(L, J, sa, noise))
    if sv <= sa:
        log.add("setup", "warn", "Thresholds overlap",
                f"s_v ({sv:.2f}) should be larger than s_a ({sa:.2f}); otherwise the validator is stricter than the receiver.")

    key = qds.generate_private_key(J, L, rng)
    tap = prim in ("intercept_resend", "eavesdrop_forge")
    rec_b, eve_rec = qds.distribute(key, rng, noise, tap)
    rec_v = qds.distribute(key, rng, noise, False)[0] if V else None

    log.add("distribution", "info", f"{A} sends the public key to {B}",
            f"{nq:,} BB84 qubits ({J} digest bits × 2 bit values × {L}). {B} measures each one in a random basis "
            "and keeps (basis, result).", frm=A, to=B)
    if tap:
        log.add("distribution", "attack", f"{C} taps the quantum link to {B}",
                "Intercept-resend: measures every qubit in a random basis and forwards a fresh one. Whenever the basis "
                f"guess is wrong (half the time) the qubit is scrambled, so about 25% of {B}'s checkable positions will be wrong.",
                frm=C, to=B)
    if V:
        log.add("distribution", "info", f"{A} sends a separate copy to {V}",
                f"{V} also measures in random bases. This independent record is what lets a third party check a signature.",
                frm=A, to=V)

    bits = qds.digest_bits(msg, J)
    sig = qds.sign(key, bits)
    log.add("signing", "info", f"{A} signs the message",
            f"SHA-256 digest, first {J} bits: {''.join(map(str, bits))}. For each digest bit the matching "
            f"private-key block ({L} basis/value pairs) is revealed as the signature.", frm=A)

    log.add("channel", "info", f"{A} sends the message and signature to {B}",
            f"{_q(msg)} over the primary (classical) route" + (f", which passes through {C}." if C else "."),
            frm=A, to=C or B)
    d_msg, d_sig, title, detail = attacks.apply_primary(prim, msg, sig, forged_text, J, L, rng, eve_rec)
    if C:
        active = prim in ("drop", "forge", "tamper", "eavesdrop_forge")
        log.add("channel", "attack" if active else "info", f"{C} {title}", detail, frm=C,
                to=B if d_msg is not None else None)

    if d_msg is None:
        log.add("verification", "bad", f"{B} receives nothing", "Timeout: no message arrived on the primary route.", to=B)
        return {"ok": False, "reason": "no_message", "accepted_text": None, "metrics": m}

    claimed = qds.digest_bits(d_msg, J)
    rates, checked, ok_b = qds.verify(rec_b, d_sig, claimed, sa)
    m["bob"] = _block_stats(rates, checked, ok_b)
    failing = int((rates >= sa).sum())
    log.add("verification", "ok" if ok_b else "bad", f"{B} checks the signature against the quantum record",
            f"Mismatch rate per block: mean {rates.mean():.3f}, worst {rates.max():.3f}; limit s_a = {sa:.2f}. "
            + (f"All {J} blocks pass: accepted." if ok_b else
               f"{failing} of {J} blocks fail: rejected. (A blind guess scores about 0.50, a disturbed link about 0.25.)"),
            to=B)
    if not ok_b:
        return {"ok": False, "reason": "bob_reject", "accepted_text": None, "metrics": m}

    if not V:
        log.add("verification", "warn", "No validator in this scenario",
                f"Only {B}'s check ran. The signature cannot be proven to anyone else, and nothing independent "
                f"can expose an attacker who controls {B}'s quantum link.")
        return {"ok": True, "reason": None, "accepted_text": d_msg, "metrics": m}

    log.add("verification", "info", f"{B} forwards the message and signature to {V}",
            "Transferability test: a genuine signature must also pass an independent recipient, at the looser limit s_v.",
            frm=B, to=V)
    rates_v, checked_v, ok_v = qds.verify(rec_v, d_sig, claimed, sv)
    m["validator"] = _block_stats(rates_v, checked_v, ok_v)
    log.add("verification", "ok" if ok_v else "bad", f"{V} checks it against an independent record",
            f"Mismatch rate per block: mean {rates_v.mean():.3f}, worst {rates_v.max():.3f}; limit s_v = {sv:.2f}. "
            + ("All blocks pass: the signature is transferable." if ok_v else
               f"{int((rates_v >= sv).sum())} of {J} blocks fail: {V} disagrees with {B}."), to=V)
    if not ok_v:
        return {"ok": False, "reason": "validator_reject", "accepted_text": None, "metrics": m}
    return {"ok": True, "reason": None, "accepted_text": d_msg, "metrics": m}


# ------------------------------------------------------------------------------- fallback phase
def _fallback_phase(log, rng, S, msg, forged_text, bk, tap_ent, A, B, C, qds_reason):
    m = {}
    backend, warning = backends.get_backend(S["backend"])
    if warning:
        log.add("fallback", "warn", "Backend notice", warning)
    plaintext = msg.encode("utf-8")
    needed = 8 * (classical.MAC_KEY_BYTES + len(plaintext))
    cap = 80000 if backend.name == "numpy" else 20000
    noise = float(S["ent_noise"])
    pairs = int(S["pairs"]) if S.get("pairs") else entanglement.auto_pairs(needed, noise, cap)
    m.update({"backend": backend.name, "backend_detail": backend.detail, "pairs": pairs,
              "needed_key_bits": needed, "chsh_min": float(S["chsh_min"]), "qber_max": float(S["qber_max"]),
              "ent_noise": noise})

    log.add("fallback", "warn", "QDS did not complete, so the fallback starts",
            f"Reason: {REASONS[qds_reason]}. {B} asks {A} for a secure re-send over the backup route.", frm=B, to=A)
    log.add("fallback", "info", f"A source shares {pairs:,} Bell pairs between {A} and {B} ({backend.name})",
            "Each side measures every pair at one of three random angles. Basis announcements are assumed to be "
            "authenticated with a small pre-shared secret, as in every QKD system.", frm=A, to=B)
    if tap_ent:
        log.add("fallback", "attack", f"{C} taps the entanglement link",
                f"Intercept-resend on {B}'s half of every pair: measure, then forward a fresh qubit. "
                "That destroys the entanglement the check relies on.", frm=C, to=B)

    e = entanglement.run_e91(backend, pairs, noise, tap_ent, rng, float(S["chsh_min"]), float(S["qber_max"]))
    m.update({"S": round(e["S"], 3), "qber": round(e["qber"], 4), "sifted": e["sifted"],
              "key_bits": e["key_bits"], "secure": bool(e["secure"]), "mac_ok": None})
    log.add("fallback", "ok" if e["secure"] else "bad",
            "Entanglement check " + ("passed" if e["secure"] else "failed"),
            f"CHSH S = {e['S']:.2f} (classical limit 2.00, quantum maximum 2.83, required above {S['chsh_min']}); "
            f"key-sample error rate {e['qber']:.1%} (limit {float(S['qber_max']):.0%}). "
            + ("" if e["secure"] else e["reason"] + "."), frm=A, to=B)
    if not e["secure"]:
        return {"ok": False, "reason": "the entanglement check failed (" + e["reason"] + ")", "metrics": m}

    key = e["key"]
    if len(key) < classical.MAC_KEY_BYTES + len(plaintext):
        return {"ok": False, "metrics": m,
                "reason": f"only {e['key_bits']} secret key bits survived, {needed} are needed: use more Bell pairs or a shorter message"}

    ciphertext, tag = classical.protect(plaintext, key)
    log.add("fallback", "info", f"{A} encrypts with a one-time pad and adds a one-time MAC",
            f"Uses {8 * len(plaintext)} pad bits and {8 * classical.MAC_KEY_BYTES} MAC-key bits from the entangled key. "
            f"Ciphertext {ciphertext.hex()[:40]}{'…' if len(ciphertext) > 20 else ''}, tag {tag:032x}.", frm=A, to=C or B)
    ct2, tag2, title, detail = attacks.apply_backup(bk, ciphertext, tag, plaintext, forged_text)
    if C and bk != "pass":
        log.add("fallback", "attack", f"{C} {title}", detail, frm=C, to=B if ct2 is not None else None)
    if ct2 is None:
        log.add("fallback", "bad", f"{B} receives nothing on the backup route", "Timeout.", to=B)
        return {"ok": False, "reason": "the backup route was blocked", "metrics": m}

    opened = classical.open_(ct2, tag2, key)
    m["mac_ok"] = opened is not None
    if opened is None:
        log.add("fallback", "bad", f"{B} rejects the ciphertext: the MAC does not verify",
                "The one-time MAC key is known only to the two ends, so the swapped ciphertext is discarded.", to=B)
        return {"ok": False, "reason": "the backup message failed its authentication check", "metrics": m}
    log.add("fallback", "ok", f"{B} decrypts the message and the MAC verifies",
            "Authenticity and secrecy come from the entangled key, not from the signature layer.", to=B)
    return {"ok": True, "accepted_text": opened.decode("utf-8", errors="replace"), "metrics": m}


# ------------------------------------------------------------------------------- verdict text
def _describe(verdict, mode, msg, accepted, qds_reason, fb_reason, A, B, C, V):
    if verdict == "delivered_qds":
        return ("Delivered: the quantum signature checked out", "ok",
                f"{B}'s mismatch rates stayed under the limit" + (f" and {V} confirmed them independently" if V else "")
                + f", so {B} accepted {_q(accepted)} as genuinely from {A}.")
    if verdict == "delivered_fallback":
        return ("Delivered through the entanglement fallback", "ok",
                f"The signature layer failed ({REASONS[qds_reason]}). {A} and {B} derived a one-time key from entangled "
                f"pairs, and {A}'s original message arrived encrypted and authenticated.")
    if verdict == "delivered_plain":
        return ("Delivered, but nothing proves who sent it", "warn",
                f"There is no signature to check, so {B} would have accepted whatever arrived.")
    if verdict == "compromised":
        if mode == "plain":
            tip = " Without a signature nothing could expose it."
        elif not V:
            tip = " Add a validator: an independent quantum record is what exposes this attack."
        else:
            tip = " The parameters are too weak for this attack: raise L or digest bits, or lower s_a."
        return (f"Forgery accepted: {B} believes the fake came from {A}", "bad",
                f"{B} accepted {_q(accepted)} instead of {_q(msg)}." + tip)
    if mode == "plain":
        who = C or "The network"
        return ("Nothing arrived", "warn", f"{who} blocked the message. Without protection {B} cannot even tell why.")
    if mode == "qds":
        return ("Not delivered, but no fake was accepted", "warn",
                f"The signature layer rejected the message ({REASONS[qds_reason]}). This mode has no fallback, so nothing arrived.")
    return ("Not delivered, but no fake was accepted", "warn",
            f"The signature layer failed ({REASONS[qds_reason]}) and so did the fallback ({fb_reason}). "
            "Nothing forged was accepted, but the message did not arrive.")


# ------------------------------------------------------------------------------- public API
def run_scenario(cfg: dict) -> dict:
    S = {**DEFAULTS, **(cfg.get("settings") or {})}
    mode = cfg.get("mode", "hybrid")
    if mode not in MODES:
        raise ValueError(f"Unknown mode '{mode}'. Use one of {', '.join(MODES)}.")
    A, B = cfg.get("sender"), cfg.get("receiver")
    if not A or not B:
        raise ValueError("Pick a sender and a receiver first.")
    if A == B:
        raise ValueError("The sender and the receiver must be different users.")
    V = cfg.get("validator") or None
    atk = cfg.get("attacker") or None
    C = atk["name"] if atk else None
    if V in (A, B) or (C and C in (A, B, V)):
        raise ValueError("Sender, receiver, validator and attacker must be four different users.")
    prim = (atk or {}).get("primary", "pass")
    bk = (atk or {}).get("backup", "pass")
    tap_ent = bool((atk or {}).get("tap_entanglement", False))
    if prim not in attacks.PRIMARY or bk not in attacks.BACKUP:
        raise ValueError("Unknown attack option.")
    msg = (cfg.get("message") or "").strip() or "Hello"
    forged_text = ((atk or {}).get("forged_text") or "").strip() or f"Send all funds to {C or 'Charlie'}"
    if mode == "plain":
        V = None

    rng = np.random.default_rng(S["seed"])
    log = Log()
    who = f"{A} (sender) → {B} (receiver)" + (f", {V} (validator)" if V else "") + (f", {C} (attacker)" if C else "")
    log.add("setup", "info", f"Scenario: {MODE_NAMES[mode]}", who)

    metrics, accepted, method, qds_reason, fb_reason = {}, None, None, None, None
    if mode == "plain":
        eff = {"eavesdrop_forge": "forge", "intercept_resend": "pass"}.get(prim, prim)
        log.add("channel", "info", f"{A} sends the message to {B}",
                f"{_q(msg)} as plain text, no signature" + (f", through {C}." if C else "."), frm=A, to=C or B)
        if C and prim == "intercept_resend":
            log.add("channel", "info", f"{C} has no quantum states to tap in this mode", "The attack has no effect.", frm=C)
        elif C and eff != "pass":
            title, detail = {"drop": ("blocks the message", "It never reaches the receiver."),
                             "forge": ("replaces the message", f"Sends {_q(forged_text)} as if from {A}."),
                             "tamper": ("edits the message", f"Changes it to {_q(forged_text)}.")}[eff]
            log.add("channel", "attack", f"{C} {title}", detail, frm=C, to=B if eff != "drop" else None)
        accepted = {"pass": msg, "drop": None, "forge": forged_text, "tamper": forged_text}[eff]
        method = "plain"
        if accepted is None:
            log.add("verification", "bad", f"{B} receives nothing", "Timeout.", to=B)
        else:
            log.add("verification", "warn", f"{B} accepts {_q(accepted)}", "There is nothing to verify, so it is taken on trust.", to=B)
    else:
        q = _qds_phase(log, rng, S, msg, forged_text, prim, A, B, V, C)
        metrics["qds"] = q["metrics"]
        if q["ok"]:
            accepted, method = q["accepted_text"], "qds"
        else:
            qds_reason = q["reason"]
            if mode == "hybrid":
                fb = _fallback_phase(log, rng, S, msg, forged_text, bk, tap_ent, A, B, C, qds_reason)
                metrics["fallback"] = fb["metrics"]
                if fb["ok"]:
                    accepted, method = fb["accepted_text"], "fallback"
                else:
                    fb_reason = fb["reason"]
            else:
                log.add("result", "bad", "QDS-only mode has no fallback", "The signature was refused and nothing else is tried.")

    if accepted is None:
        verdict = "not_delivered"
    elif accepted != msg:
        verdict = "compromised"
    else:
        verdict = {"qds": "delivered_qds", "fallback": "delivered_fallback", "plain": "delivered_plain"}[method]
    headline, level, explanation = _describe(verdict, mode, msg, accepted, qds_reason, fb_reason, A, B, C, V)
    log.add("result", level, headline, explanation, to=B if accepted is not None else None)

    return {
        "mode": mode, "verdict": verdict, "level": level, "headline": headline, "explanation": explanation,
        "secure": verdict != "compromised", "delivered": verdict.startswith("delivered"),
        "original": msg, "accepted_text": accepted, "method": method,
        "cast": {"sender": A, "receiver": B, "validator": V, "attacker": C},
        "attack": {"primary": prim, "backup": bk, "tap_entanglement": tap_ent} if C else None,
        "metrics": metrics, "events": log.events, "settings": {k: S[k] for k in DEFAULTS},
    }


def compare(cfg: dict) -> dict:
    """Run the same scenario in all three modes (seeds offset so they stay reproducible)."""
    settings = dict(cfg.get("settings") or {})
    base = settings.get("seed")
    out = {}
    for i, mode in enumerate(MODES):
        s = dict(settings)
        if base is not None:
            s["seed"] = int(base) + i
        out[mode] = run_scenario({**cfg, "mode": mode, "settings": s})
    return out
