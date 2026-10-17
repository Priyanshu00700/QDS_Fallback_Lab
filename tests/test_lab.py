"""Tests for the QDS + fallback lab. Run with `pytest` or simply `python tests/test_lab.py`."""
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from qdslab import backends, classical, engine, entanglement, qds  # noqa: E402

MSG = "Meet at the lab at 5pm"


def scenario(primary=None, mode="hybrid", validator="Dave", seed=1, backup="pass", tap=False, **settings):
    atk = None
    if primary is not None:
        atk = {"name": "Charlie", "primary": primary, "backup": backup, "tap_entanglement": tap,
               "forged_text": "Send all funds to Charlie"}
    return engine.run_scenario({"message": MSG, "mode": mode, "sender": "Alice", "receiver": "Bob",
                                "validator": validator, "attacker": atk,
                                "settings": {"backend": "numpy", "seed": seed, **settings}})


# ----------------------------------------------------------------------------- QDS layer
def test_honest_signature_passes_with_low_mismatch():
    r = scenario()
    assert r["verdict"] == "delivered_qds"
    assert r["metrics"]["qds"]["bob"]["max"] < 0.10


def test_blind_forgery_scores_about_half():
    r = scenario("forge", mode="qds")
    assert r["verdict"] == "not_delivered"
    assert 0.4 < r["metrics"]["qds"]["bob"]["mean"] < 0.6


def test_intercept_resend_disturbance_is_about_a_quarter():
    r = scenario("intercept_resend", mode="qds")
    assert r["verdict"] == "not_delivered"
    assert 0.18 < r["metrics"]["qds"]["bob"]["mean"] < 0.33


def test_tamper_is_rejected():
    assert scenario("tamper", mode="qds")["verdict"] == "not_delivered"


def test_validator_exposes_intercept_and_forge():
    r = scenario("eavesdrop_forge", mode="qds")
    q = r["metrics"]["qds"]
    assert q["bob"]["accepted"] is True            # Bob alone is fooled ...
    assert q["validator"]["accepted"] is False     # ... the independent record is not
    assert r["verdict"] == "not_delivered"


def test_without_validator_intercept_and_forge_succeeds():
    r = scenario("eavesdrop_forge", mode="qds", validator=None)
    assert r["verdict"] == "compromised" and r["secure"] is False


def test_weak_parameters_let_forgeries_through():
    wins = sum(scenario("forge", mode="qds", L=8, digest_bits=1, s_a=0.45, seed=i)["verdict"] == "compromised"
               for i in range(60))
    assert wins > 0, "with tiny L and a loose threshold some blind forgeries should pass"


def test_security_estimates_shrink_with_L():
    small = qds.security_estimates(64, 32, 0.10, 0.02)["forgery_log10_block"]
    large = qds.security_estimates(256, 32, 0.10, 0.02)["forgery_log10_block"]
    assert large < small < 0


def test_short_digest_lets_a_colliding_text_reuse_the_genuine_signature():
    from find_collision import find
    fake, tries = find(MSG, 16)
    atk = {"name": "Charlie", "primary": "tamper", "forged_text": fake}
    common = {"message": MSG, "sender": "Alice", "receiver": "Bob", "validator": "Dave", "attacker": atk}
    weak = engine.run_scenario({**common, "mode": "qds", "settings": {"backend": "numpy", "seed": 1, "digest_bits": 16}})
    assert weak["verdict"] == "compromised", "a 16-bit digest collision should pass every quantum check"
    assert weak["metrics"]["qds"]["validator"]["accepted"] is True
    strong = engine.run_scenario({**common, "mode": "qds", "settings": {"backend": "numpy", "seed": 1, "digest_bits": 32}})
    assert strong["verdict"] == "not_delivered", "the same text no longer collides once 32 bits are signed"


# ----------------------------------------------------------------------------- fallback layer
def test_hybrid_recovers_from_every_primary_attack():
    for attack in ("drop", "forge", "tamper", "intercept_resend", "eavesdrop_forge"):
        r = scenario(attack)
        assert r["verdict"] == "delivered_fallback", attack
        assert r["accepted_text"] == MSG


def test_noise_alone_triggers_the_fallback():
    r = scenario(None, qds_noise=0.15)
    assert r["verdict"] == "delivered_fallback"


def test_tapped_entanglement_link_is_detected():
    r = scenario("forge", tap=True)
    assert r["verdict"] == "not_delivered"
    assert r["metrics"]["fallback"]["S"] < 2.0


def test_backup_route_attacks_cannot_forge():
    for backup in ("block", "forge"):
        r = scenario("forge", backup=backup)
        assert r["verdict"] == "not_delivered" and r["secure"] is True, backup
    assert scenario("forge", backup="forge")["metrics"]["fallback"]["mac_ok"] is False


def test_plain_mode_is_defenceless():
    assert scenario("forge", mode="plain")["verdict"] == "compromised"
    assert scenario(None, mode="plain")["verdict"] == "delivered_plain"


def test_e91_numbers_numpy():
    be = backends.NumpyBackend()
    ok = entanglement.run_e91(be, 8000, 0.03, False, np.random.default_rng(3), 2.2, 0.11)
    assert ok["secure"] and ok["S"] > 2.5 and ok["qber"] < 0.05
    bad = entanglement.run_e91(be, 8000, 0.03, True, np.random.default_rng(3), 2.2, 0.11)
    assert not bad["secure"] and bad["S"] < 2.0


def test_otp_and_mac_round_trip_and_tamper_detection():
    key = bytes(range(64))
    ct, tag = classical.protect(b"hello", key)
    assert classical.open_(ct, tag, key) == b"hello"
    flipped = bytes([ct[0] ^ 1]) + ct[1:]
    assert classical.open_(flipped, tag, key) is None
    assert classical.open_(ct, tag ^ 1, key) is None


def test_qiskit_backend_matches_numpy_if_installed():
    be, warning = backends.get_backend("qiskit")
    if be.name != "qiskit":
        print("  (skipped: Qiskit not installed, NumPy fallback worked:", warning[:40], "...)")
        return
    r = entanglement.run_e91(be, 4000, 0.03, False, np.random.default_rng(2), 2.2, 0.11)
    assert r["secure"] and r["S"] > 2.4
    t = entanglement.run_e91(be, 4000, 0.0, True, np.random.default_rng(2), 2.2, 0.11)
    assert not t["secure"] and t["S"] < 2.0


# ----------------------------------------------------------------------------- engine and API
def test_input_validation():
    for bad in ({"sender": "Alice", "receiver": "Alice"}, {"sender": None, "receiver": "Bob"}):
        try:
            engine.run_scenario({"message": "x", "mode": "hybrid", **bad})
        except ValueError:
            continue
        raise AssertionError("expected ValueError")


def test_compare_returns_three_modes():
    out = engine.compare({"message": MSG, "sender": "Alice", "receiver": "Bob", "validator": "Dave",
                          "attacker": {"name": "Charlie", "primary": "forge"},
                          "settings": {"backend": "numpy", "seed": 4}})
    assert list(out) == ["plain", "qds", "hybrid"]
    assert [out[m]["verdict"] for m in out] == ["compromised", "not_delivered", "delivered_fallback"]


def test_http_server_end_to_end():
    """Start the real server on a free port and call it with the standard library only."""
    try:
        import json
        import socket
        import threading
        import time
        import urllib.error
        import urllib.request

        import uvicorn
        from qdslab.app import app
    except ImportError as exc:
        print("  (skipped HTTP test:", exc, ")")
        return
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"

    def call(path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as err:
            return err.code, err.read()

    try:
        for _ in range(200):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started, "server did not start"
        code, page = call("/")
        assert code == 200 and b"QDS fallback lab" in page
        code, raw = call("/api/status")
        assert code == 200 and json.loads(raw)["backends"]["numpy"]["available"]
        body = {"message": MSG, "mode": "hybrid", "sender": "Alice", "receiver": "Bob", "validator": "Dave",
                "attacker": {"name": "Charlie", "primary": "forge"}, "settings": {"backend": "numpy", "seed": 1}}
        code, raw = call("/api/run", body)
        assert code == 200 and json.loads(raw)["verdict"] == "delivered_fallback"
        code, raw = call("/api/compare", body)
        assert code == 200 and len(json.loads(raw)["results"]) == 3
        code, raw = call("/api/run", {**body, "receiver": "Alice"})
        assert code == 400 and "different users" in json.loads(raw)["detail"]
    finally:
        server.should_exit = True
        thread.join(timeout=5)


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as exc:   # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
