#!/usr/bin/env python3
"""Launcher for the QDS + Entanglement Fallback Lab.

    python run.py              start the web UI (opens your browser)
    python run.py --check      only check the environment and say what to install
    python run.py --demo       run a text-only demo (needs just numpy)
    python run.py --port 8010  use another port

If a library is missing this script tells you exactly what to install and can do it for you.
"""
import argparse
import importlib
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

CORE = {"numpy": "numpy", "fastapi": "fastapi", "uvicorn": "uvicorn"}   # import name -> pip name


def missing(names):
    out = []
    for mod, pkg in names.items():
        try:
            importlib.import_module(mod)
        except ImportError:
            out.append(pkg)
    return out


def pip_install(packages):
    proc = subprocess.run([sys.executable, "-m", "pip", "install", *packages], capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-1500:], proc.stderr[-1500:])
        if "externally-managed-environment" in proc.stderr:
            print("\nYour system Python is locked (PEP 668). Create a virtual environment instead:\n"
                  "  python3 -m venv .venv && source .venv/bin/activate     (Windows: .venv\\Scripts\\activate)\n"
                  "  pip install -r requirements.txt\n  python run.py")
        else:
            print("\nInstall failed. Try it by hand:  python -m pip install " + " ".join(packages))
    return proc.returncode == 0


def ensure_core(names):
    need = missing(names)
    if not need:
        return True
    print(f"Missing required package(s): {', '.join(need)}")
    print(f"  fix:  {sys.executable} -m pip install {' '.join(need)}      (or: pip install -r requirements.txt)")
    if sys.stdin.isatty():
        if input("Install them now? [Y/n] ").strip().lower() in ("", "y", "yes"):
            if pip_install(need) and not missing(names):
                print("Installed.\n")
                return True
    return False


def report_environment():
    print(f"Python {sys.version.split()[0]} at {sys.executable}")
    if sys.version_info < (3, 9):
        print("  WARNING: Python 3.9 or newer is required.")
    for mod, pkg in CORE.items():
        try:
            m = importlib.import_module(mod)
            print(f"  ok       {pkg} {getattr(m, '__version__', '')}")
        except ImportError:
            print(f"  MISSING  {pkg}   ->  pip install {pkg}")
    try:
        from qdslab import backends
        info = backends.available_backends()["qiskit"]
        if info["available"]:
            print(f"  ok       qiskit backend ({info['detail']})")
        else:
            print("  optional qiskit not usable -> the NumPy backend is used (nothing breaks).")
            print("           to enable it:  pip install qiskit qiskit-aer")
            if info["error"] and "ModuleNotFoundError" not in info["error"]:
                print(f"           reason: {info['error']}")
    except Exception as exc:
        print(f"  could not probe Qiskit: {exc}")


def demo(attack):
    from qdslab import engine
    cast = {"name": "Charlie", "primary": attack, "backup": "pass", "tap_entanglement": False}
    for mode in engine.MODES:
        res = engine.run_scenario({"message": "Meet at the lab at 5pm", "mode": mode, "sender": "Alice",
                                   "receiver": "Bob", "validator": "Dave", "attacker": cast,
                                   "settings": {"backend": "numpy", "seed": 1}})
        print(f"\n=== {mode.upper():7s} | attack: {attack} | {res['verdict']} ===")
        for ev in res["events"]:
            print(f"  [{ev['kind']:6s}] {ev['title']}")
        print(f"  -> {res['headline']}")


def free_port(host, start):
    for port in range(start, start + 30):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    raise SystemExit(f"No free port between {start} and {start + 29}. Close other servers or pass --port.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    ap.add_argument("--check", action="store_true", help="only check the environment")
    ap.add_argument("--demo", action="store_true", help="run a text demo and exit")
    ap.add_argument("--attack", default="forge", help="attack for --demo (forge, drop, tamper, intercept_resend, eavesdrop_forge)")
    args = ap.parse_args()

    if args.check:
        report_environment()
        return
    if args.demo:
        if ensure_core({"numpy": "numpy"}):
            demo(args.attack)
        return
    if not ensure_core(CORE):
        raise SystemExit("\nStopped: install the missing packages above, then run  python run.py  again.")

    import uvicorn
    from qdslab.app import app

    port = free_port(args.host, args.port)
    if port != args.port:
        print(f"Port {args.port} is busy, using {port} instead.")
    url = f"http://{args.host}:{port}"
    print(f"\nQDS Fallback Lab running at {url}   (Ctrl+C to stop)")
    if not args.no_browser:
        threading.Thread(target=lambda: (time.sleep(1.2), webbrowser.open(url)), daemon=True).start()
    uvicorn.run(app, host=args.host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
