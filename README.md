# QDS fallback lab

A software simulation of **quantum digital signatures (QDS) with an entanglement-based fallback**, plus a web
interface where you add users, give each a role (sender, receiver, validator, attacker, bystander) and watch what
happens when one of them attacks.

Example: Alice sends, Bob receives, Dave validates, and **Charlie blocks Alice's message and sends a forged one
pretending to be Alice**. Bob's quantum check rejects the fake. The system then switches to a key made from
entangled pairs and Alice's real message still arrives.

| File | What it is for |
|---|---|
| `PROJECT_UNDERSTANDING.md` | The idea, the physics in plain language, the attacker model, what to expect, limits |
| `CODE_WALKTHROUGH.md` | How every file works, with formulas, data shapes and how to extend it |
| `README.md` (this file) | Install, run, use, and what to do when something goes wrong |

---

## 1. Quick start

You need **Python 3.9 or newer** (developed and tested on 3.12). Open a terminal in this folder (the one that
contains `run.py`).

```bash
# 1. (recommended) create an isolated environment
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

# 2. install the three required libraries
pip install -r requirements.txt

# 3. start the lab (opens http://127.0.0.1:8000 in your browser)
python run.py
```

Windows: use `py` instead of `python3` if `python3` is not found.

**Optional: run the Bell pairs on real Qiskit circuits.**
`pip install -r requirements-qiskit.txt`. Without it the built-in NumPy model is used and everything still
works; the badge at the top right of the page tells you which one is active.

### If `run.py` says a library is missing

`run.py` checks everything first. If something is missing it prints the exact command and, when you run it in a
terminal, offers to install it for you (`Install them now? [Y/n]`). To only check your setup:

```bash
python run.py --check
```

---

## 2. Using the interface

1. **Users and roles (left).** Add a user with a name and a role, or change a role from the drop-down. Click `×` to
   remove someone. Attackers get their own panel: choose what they do on the main route, the text of their fake
   message, what they do to the backup route, and whether they tap the entanglement link.
2. **Cast (above the diagram).** If several users share a role, pick who plays sender, receiver, validator and
   attacker this time. Choose **none** for validator or attacker to run without them.
3. **Protection level (right).** *None*, *Signature* (QDS only) or *Signature + fallback*.
4. **Run scenario.** Watch the steps animate, then read the stamped verdict, the charts and the step-by-step log.
5. **Compare protection levels.** Runs the same scenario in all three modes and shows one row each. Click a row to
   open its log.

Things worth trying first:

| Try this | You should see |
|---|---|
| Charlie = *Forge and replace*, mode *Signature + fallback* | Bob rejects (mismatch about 0.5), fallback delivers the real message |
| Same, mode *None* | **Forgery accepted** |
| Charlie = *Intercept states, then forge*, remove the validator | **Forgery accepted** even with the quantum signature |
| Same, put the validator back | Bob is fooled, Dave is not, fallback delivers |
| Quantum channel noise to 15%, no attacker | QDS fails by itself, fallback saves it |
| Charlie also ticks *Tap the entanglement link* | Fallback aborts (CHSH below 2), nothing forged is accepted |
| Charlie's backup route = *Block* | Not delivered, but still no forgery accepted |

---

## 3. Other commands

```bash
python run.py --port 8010          # another port (it also picks a free one automatically)
python run.py --no-browser         # do not open a browser tab
python run.py --demo               # text-only demo, needs just numpy
python run.py --demo --attack drop # drop | forge | tamper | intercept_resend | eavesdrop_forge
python tests/test_lab.py           # 20 tests, no pytest needed   (or: pip install -r requirements-dev.txt && pytest)
python experiments.py --runs 100   # success rates of every attack in every mode, saved to results.csv
python find_collision.py "Meet at the lab at 5pm" --bits 16   # why the signed digest length matters
```

---

## 4. When something goes wrong

Read the **last line** of the error message and find it below.

| What you see | Why | What to do |
|---|---|---|
| `ModuleNotFoundError: No module named 'numpy'` (or `fastapi`, `uvicorn`) | A required library is not installed in the Python you are using | `python -m pip install -r requirements.txt`. Use the same `python` you run the lab with. Or run `python run.py` and answer `Y` |
| `pip: command not found` | pip is not on your PATH | `python -m pip install -r requirements.txt` (Windows: `py -m pip ...`) |
| `error: externally-managed-environment` | Your system Python (Ubuntu 23.04+, Debian 12+, Homebrew) refuses global installs | Use a virtual environment: `python3 -m venv .venv`, activate it, then install (step 1 of the quick start) |
| `python: command not found` | Different command name | Try `python3 run.py` or, on Windows, `py run.py` |
| `No module named 'qdslab'` | You are not in the project folder | `cd` into the folder that contains `run.py`, then run it |
| `Address already in use` / port busy | Another program (or an old copy of the lab) uses port 8000 | `run.py` moves to the next free port by itself. Or stop the old server with Ctrl+C, or pass `--port 8010` |
| Page loads but says **Server not reachable** | You opened `static/index.html` directly from the disk | Start `python run.py` and use the address it prints |
| Badge says *NumPy (Qiskit not installed)* | Qiskit is optional | Nothing is wrong. To use it: `pip install -r requirements-qiskit.txt`, restart |
| Qiskit is installed but the badge still says NumPy | Installed into a different Python, or a version conflict | Run `python run.py --check` and read the reason it prints. Then `python -m pip install -U qiskit qiskit-aer` in the same environment. Python 3.10–3.12 is the safest choice for Qiskit |
| `cannot import name 'Aer' from 'qiskit'` | Older tutorials import `Aer` from `qiskit`; this project uses the separate `qiskit-aer` package | `pip install qiskit-aer` |
| A run with Qiskit takes a few seconds | Aer simulates thousands of circuit shots | Pick *NumPy (built in)* in the Bell-pair simulator list, or lower the noise so fewer pairs are needed |
| PowerShell: *running scripts is disabled* when activating the venv | Windows execution policy | `Set-ExecutionPolicy -Scope Process RemoteSigned`, or use `cmd` and `.venv\Scripts\activate.bat` |
| pip cannot download (SSL, proxy, offline) | Network restrictions | Install on a connected machine with `pip download -r requirements.txt -d wheels`, copy the `wheels` folder over, then `pip install --no-index --find-links wheels -r requirements.txt` |
| `pytest: command not found` | pytest is optional | `python tests/test_lab.py` runs the same tests without it |
| The user list is not remembered after a reload | The browser blocks storage (private window) | The lab still works; the list simply resets |
| *Forgery accepted* appears and you expected protection | Not a bug: no validator, a short signed digest (see `find_collision.py`), or L too small / s_a too loose | See section 6 of `PROJECT_UNDERSTANDING.md` |
| *Entanglement check failed* | CHSH S did not exceed the required value: the link is tapped or too noisy | Lower the entanglement noise, or untick *Tap the entanglement link* |

Still stuck? Run `python run.py --check` and keep its output together with the last lines of the error.

---

## 5. Folder layout

```
qds_fallback_lab/
├── README.md                  this file
├── PROJECT_UNDERSTANDING.md   the idea, the physics, the attacker model, limits
├── CODE_WALKTHROUGH.md        how the code works, file by file
├── run.py                     launcher with dependency checks, --check, --demo
├── experiments.py             Monte-Carlo success rates of every attack
├── find_collision.py          shows why the signed digest length matters
├── requirements.txt           numpy, fastapi, uvicorn
├── requirements-qiskit.txt    optional: qiskit, qiskit-aer
├── requirements-dev.txt       optional: pytest, httpx
├── qdslab/
│   ├── config.py              default parameters
│   ├── qds.py                 quantum digital signature layer
│   ├── entanglement.py        E91-style fallback key exchange
│   ├── backends.py            NumPy and Qiskit Bell-pair simulators
│   ├── classical.py           one-time pad and one-time MAC
│   ├── attacks.py             what each attacker mode does
│   ├── engine.py              runs a scenario, builds the log and the verdict
│   └── app.py                 FastAPI server
├── static/index.html          the whole web interface (one file, no external downloads)
└── tests/test_lab.py          20 tests
```

This is a teaching and research simulation. It is not a production cryptosystem, and no real quantum hardware is
involved. See the limits in `PROJECT_UNDERSTANDING.md` before quoting any number from it.
