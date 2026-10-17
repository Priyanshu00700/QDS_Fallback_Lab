#!/usr/bin/env python3
"""Monte-Carlo experiments: how often does each attack succeed against each security mode?

    python experiments.py --runs 100                       table in the terminal + results.csv
    python experiments.py --runs 300 --noise 0.08          noisier quantum channel
    python experiments.py --runs 200 --only forge --set L=64 --set s_a=0.20
                                                           try other settings (repeat --set as needed)

Uses the NumPy backend, so it needs only numpy and finishes in seconds.
"""
import argparse
import csv
from collections import Counter
from pathlib import Path

from qdslab import engine

SCENARIOS = [  # label, attacker settings (None = nobody attacks), validator present?
    ("no attacker", None, True),
    ("drop message", {"primary": "drop"}, True),
    ("forge (impersonate)", {"primary": "forge"}, True),
    ("forge (impersonate), NO validator", {"primary": "forge"}, False),
    ("tamper (keep signature)", {"primary": "tamper"}, True),
    ("intercept quantum states", {"primary": "intercept_resend"}, True),
    ("intercept + forge, with validator", {"primary": "eavesdrop_forge"}, True),
    ("intercept + forge, NO validator", {"primary": "eavesdrop_forge"}, False),
    ("forge + block backup route", {"primary": "forge", "backup": "block"}, True),
    ("forge + tap entanglement link", {"primary": "forge", "tap_entanglement": True}, True),
]
SHORT = {"delivered_qds": "QDS", "delivered_fallback": "fallback", "delivered_plain": "plain-ok",
         "compromised": "COMPROMISED", "not_delivered": "not-delivered"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=50)
    ap.add_argument("--noise", type=float, default=0.02, help="quantum channel noise for the QDS layer")
    ap.add_argument("--csv", default="results.csv")
    ap.add_argument("--only", default="", help="run only scenarios whose name contains this text")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="override a setting, e.g. --set L=16 --set s_a=0.3 (repeatable)")
    args = ap.parse_args()
    extra = {}
    for item in args.set:
        key, _, value = item.partition("=")
        extra[key.strip()] = float(value) if "." in value else int(value)

    rows = []
    print(f"{args.runs} runs per cell, QDS noise {args.noise:.2f}" + (f", overrides {extra}" if extra else "") + "\n")
    print(f"{'scenario':36s} {'mode':7s} outcome counts")
    for label, atk, has_validator in SCENARIOS:
        if args.only.lower() not in label.lower():
            continue
        for mode in engine.MODES:
            counts = Counter()
            for i in range(args.runs):
                cfg = {"message": "Meet at the lab at 5pm", "mode": mode, "sender": "Alice", "receiver": "Bob",
                       "validator": "Dave" if has_validator else None,
                       "attacker": {"name": "Charlie", **atk} if atk else None,
                       "settings": {"backend": "numpy", "seed": i, "qds_noise": args.noise, **extra}}
                counts[engine.run_scenario(cfg)["verdict"]] += 1
            line = ", ".join(f"{SHORT[k]} {100 * v / args.runs:.0f}%" for k, v in counts.most_common())
            print(f"{label:36s} {mode:7s} {line}")
            rows.append({"scenario": label, "mode": mode, "runs": args.runs,
                         **{k: counts.get(k, 0) for k in SHORT}})
    out = Path(args.csv)
    with out.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nSaved {out}")


if __name__ == "__main__":
    main()
