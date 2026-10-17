# How the code works

A guided tour of every file: what it does, the data it uses, the formulas behind it, and how to change it.
For the ideas behind the code read `PROJECT_UNDERSTANDING.md` first. For installing and fixing errors see `README.md`.

---

## 1. Map of the project

```
run.py                  launcher: dependency check, --check, --demo, starts the server
experiments.py          Monte-Carlo success rates of every attack in every mode
find_collision.py       demo of the short-digest weakness
qdslab/
  config.py             default parameters, mode and role names
  qds.py                quantum digital signature layer (keys, distribution, signing, verifying, odds)
  backends.py           Bell-pair simulators: NumPy (always) and Qiskit (optional)
  entanglement.py       E91-style key exchange built on a backend
  classical.py          one-time pad + one-time MAC
  attacks.py            what each attacker mode does to a message
  engine.py             runs one scenario, writes the event log, decides the verdict
  app.py                FastAPI server: serves the page and runs scenarios
static/index.html       the whole interface (HTML + CSS + JavaScript, no build step, no downloads)
tests/test_lab.py       20 tests
```

Dependencies between modules (arrows point at what is imported):

```
app ──▶ engine ──▶ qds
                ├─▶ entanglement ──▶ classical
                ├─▶ backends          (the engine picks a backend and hands it to entanglement)
                ├─▶ classical
                └─▶ attacks ──▶ qds
```

Design rules that explain most choices:

- **The server is stateless.** The browser keeps the user list and sends the whole cast with every request.
- **The engine never prints or draws.** It returns data: a verdict, metrics and an event log. The interface, the
  text demo and the experiments script all consume the same result.
- **Nothing optional can break the core.** Qiskit is optional and falls back to NumPy; the engine and the tests
  need only NumPy.
- **Everything is vectorised NumPy.** A scenario involves tens of thousands of qubits; no Python loops over them.

---

## 2. One request from click to screen

```
 [Run scenario] click
      │  index.html: payload() collects message, mode, cast, attacker settings, slider values
      ▼
 POST /api/run  ── app.py: Scenario (pydantic) validates the shape ── engine.run_scenario(dict)
      │
      │   engine.run_scenario
      │     1. merge settings over config.DEFAULTS, validate the cast
      │     2. mode == "plain"?  → accept whatever arrives, done
      │     3. _qds_phase(...)   → distribute states, sign, let the attacker act, verify at Bob and at the validator
      │     4. QDS failed and mode == "hybrid"?  → _fallback_phase(...)
      │            E91 over Bell pairs → CHSH + QBER check → key → OTP + MAC → backup route → open
      │     5. verdict = f(accepted text, original text, method), plus headline and explanation
      ▼
 JSON { verdict, headline, explanation, metrics, events[] , ... }
      │
      ▼  index.html: show(res)  → timeline items appear one by one, the packet moves between nodes,
                                    then the stamped verdict, the charts and the facts are drawn
```

An example of what the log looks like for the headline scenario (seed 3, NumPy backend): Alice signs, Charlie
replaces the message, Bob measures a mean mismatch of 0.517 (worst block 0.617) against a limit of 0.10 and
rejects, the fallback shares 6,915 Bell pairs, CHSH S = 2.77 and the key-sample error rate is 2.7%, the key has 640
usable bits against 432 needed, Alice's ciphertext arrives, the MAC verifies and Bob decrypts "Meet at the lab at 5pm".

---

## 3. `qdslab/config.py`

`DEFAULTS` is the single list of tunable parameters. The interface sliders, the API and the tests all override
entries of this dictionary.

| Key | Default | Meaning |
|---|---|---|
| `L` | 256 | Qubits per (digest bit, value) block |
| `digest_bits` | 32 | Bits of SHA-256 that are signed |
| `s_a`, `s_v` | 0.10, 0.20 | Acceptance limits for the receiver and the validator |
| `qds_noise` | 0.02 | Probability a measured qubit is flipped |
| `ent_noise` | 0.03 | Depolarizing noise on Bell pairs (visibility = 1 − noise) |
| `chsh_min` | 2.2 | The fallback needs CHSH S above this |
| `qber_max` | 0.11 | The fallback needs the key-sample error rate at or below this |
| `pairs` | `None` | Number of Bell pairs; `None` = chosen from the message length |
| `backend` | `"auto"` | `"auto"`, `"numpy"` or `"qiskit"` |
| `seed` | `None` | Integer for reproducible runs |

---

## 4. `qdslab/qds.py`: the quantum signature layer

**Data shapes.** Every array is `(J, 2, L)`: `J` digest bits × 2 possible values of that bit × `L` positions.

| Object | Fields | Holds |
|---|---|---|
| `PrivateKey` | `basis`, `value` | Alice's secret: 0/1 for Z/X basis and the bit, per position |
| `Record` | `basis`, `outcome` | What a recipient measured: his random basis and the result |
| `Signature` | `basis`, `value`, shape `(J, L)` | The revealed blocks, one per digest bit |

**Functions in the order they are used:**

- `digest_bits(message, n)`: SHA-256, first `n` bits, as an index array of 0/1.
- `generate_private_key(J, L, rng)`: random bases and values.
- `distribute(key, rng, noise, tap)`: sends one copy of every qubit to one recipient who measures in random bases.
  The core rule, in one vectorised line:

  ```python
  ro = np.where(rb == sent_basis, sent_value, rng.integers(0, 2, shape))   # same basis: the bit, else a coin flip
  ro ^= (rng.random(shape) < noise)                                        # then flip with probability `noise`
  ```

  With `tap=True` an intercept-resend attacker sits in between. He measures with his own random bases
  (`eb`, result `eo`) and the recipient then measures *his* states. That produces the 25% disturbance
  automatically, and `distribute` also returns the attacker's record because the "intercept, then forge" attack
  needs it.
- `sign(key, bits)`: picks `key[idx, bits]`, the block for the actual value of each digest bit.
- `random_signature(J, L, rng)`: a blind guess (the forger who knows nothing).
- `signature_from_record(rec, bits)`: the intercept-and-forge attacker claims his own record as the private key.
- `verify(record, sig, bits, threshold)`: per block, take the positions where the recipient's basis equals the
  revealed basis, count disagreements, divide:

  ```python
  comparable = rb == sig.basis
  rates = mismatches / checked           # one rate per digest bit
  accepted = np.all(rates < threshold)   # every block must pass
  ```

  Verifying each digest bit separately matters. If rates were averaged, one fully wrong block among 32 would hide.
- `security_estimates(L, J, s_a, noise)`: the odds shown under the charts, as powers of ten. A blind forger passes
  one block with probability `P(Binomial(L/2, 1/2) < s_a·L/2)`; an honest signature fails one block with
  `P(Binomial(L/2, noise) ≥ s_a·L/2)`. The sums use log-gamma so that numbers like 10⁻³⁵⁴ do not underflow.

---

## 5. `qdslab/backends.py` and `qdslab/entanglement.py`: the fallback key

### Backends

Both answer one question: *Alice and Bob each measure half of a Bell pair |Φ⁺⟩ along chosen angles. What bits do they get?*
Angles are Bloch angles in the x-z plane:

```python
ALICE_ANGLES = [0, π/4, π/2]        BOB_ANGLES = [π/4, π/2, 3π/4]
```

Equal angles (Alice's second with Bob's first, Alice's third with Bob's second) give perfectly correlated bits: the
raw key. The four combinations (A0,B0), (A0,B2), (A2,B0), (A2,B2) give the CHSH value.

**`NumpyBackend.measure`** uses the exact statistics. For a pair with noise visibility `V` the correlation is
`E = V·cos(θA − θB)`, Alice's bit is a fair coin, and Bob's equals it with probability `(1 + E)/2`:

```python
visibility = (1 - noise) * (0.5 if eve else 1.0)    # depolarizing noise; an intercept-resend attacker halves it
same = rng.random(n) < (1 + visibility*np.cos(A[a_idx] - B[b_idx])) / 2
```

The factor ½ for an intercept-resend attacker is exact: averaging the Z-basis and X-basis measure-and-resend
cases gives `½·cos(θA − θB)`.

**`QiskitBackend.measure`** builds real circuits and runs them on Aer, one circuit per distinct setting, with one
shot per pair:

```
H(q0), CX(q0,q1)                 Bell pair
id(q1)                           carries the depolarizing noise (a NoiseModel attaches to 'id')
[Eve: (H), measure q1, (H)]      intercept-resend on Bob's half, only when the link is tapped
Ry(-θA) q0, Ry(-θB) q1           so that a Z measurement reads the chosen angle
measure q0, q1
```

`get_backend(preference)` never raises. `"auto"` uses Qiskit if a smoke test passes, otherwise NumPy.
`"qiskit"` without Qiskit returns NumPy plus a warning text that the engine writes into the event log.
The two backends agree: ideal pairs give S ≈ 2.8, 3% noise about 2.7, a tapped link 1.3–1.5.

### E91 in `entanglement.run_e91`

1. Draw random angle indices for Alice and Bob for every pair; call the backend.
2. **CHSH:** `S = E(A0,B0) − E(A0,B2) + E(A2,B0) + E(A2,B2)`, each `E` the mean of `(±1)·(±1)` over the pairs with that setting.
3. **Sift:** keep the pairs where the angles coincide. That is 2/9 of all pairs.
4. **QBER:** a random 25% of the sifted bits is compared in public and discarded.
5. **Decision:** secure only if `S > chsh_min` and `qber ≤ qber_max`.
6. **Key length:** `usable = n · (1 − 2·h₂(q + 0.01))`; the key is the first `usable` bits, packed to bytes.
   Error correction is assumed ideal and privacy amplification is replaced by this shortening (see the limits).

`auto_pairs(needed_bits, noise, cap)` chooses how many pairs to use, so the key is long enough with a 50% margin:

```python
q = noise/2 + 0.02;  rate = max(1 - 2*h2(q), 0.02);  per_pair = (2/9) * 0.75 * rate
pairs = clamp(1.5 * needed_bits / per_pair, 3000, cap)       # cap: 80 000 NumPy, 20 000 Qiskit
```

---

## 6. `qdslab/classical.py`: protecting the fallback message

The key from the entangled pairs is cut into: 16 bytes `r`, 16 bytes `s` (MAC key), then the pad.

```
ciphertext = message XOR pad
tag        = ( poly(ciphertext, r) + s )  mod  p,        p = 2^127 − 1
poly       = Σ block_i · r^(n−i+1)   with 15-byte blocks, each followed by a 0x01 byte so lengths cannot be confused
```

`protect(plaintext, key)` returns `(ciphertext, tag)`; `open_(ciphertext, tag, key)` returns the plaintext or `None`
if the tag does not match (compared in constant time). The pad hides the message; the MAC makes any change
detectable. An attacker who already knows the plaintext (it crossed the main route in the clear) can recover the
pad from the ciphertext (`pad = ciphertext XOR plaintext`) and re-encrypt his own text with it, but he cannot
produce a matching tag. The "Swap the ciphertext" backup attack in the lab does exactly this and fails.

---

## 7. `qdslab/attacks.py`

Two catalogues (`PRIMARY`, `BACKUP`) with one-line descriptions that the interface shows, and two functions:

- `apply_primary(mode, msg, sig, forged_text, J, L, rng, eve_rec)` returns what reaches Bob:
  `(message, signature, title, detail)`. `message is None` means dropped. Forgery, tampering and the
  intercept-and-forge signature are all built here.
- `apply_backup(mode, ciphertext, tag, plaintext, forged_text)` returns what reaches Bob on the backup route.

Attacks that act on the *quantum* link (`intercept_resend`, `eavesdrop_forge`) are not applied here but in
`engine._qds_phase`, which passes `tap=True` to `qds.distribute`. Tapping the entanglement link is a flag
(`tap_entanglement`) handled in `_fallback_phase`.

---

## 8. `qdslab/engine.py`: the orchestrator

**`run_scenario(cfg)`** takes a plain dictionary (the same shape the API receives):

```python
{"message": "...", "mode": "plain|qds|hybrid", "sender": "Alice", "receiver": "Bob",
 "validator": "Dave" | None,
 "attacker": {"name": "Charlie", "primary": "forge", "backup": "pass", "tap_entanglement": False, "forged_text": "..."} | None,
 "settings": {... overrides of DEFAULTS ...}}
```

It validates (four different users, known attack names), seeds `np.random.default_rng(settings["seed"])`, then:

| Mode | What runs |
|---|---|
| `plain` | The attacker's change is applied to plain text; Bob accepts what arrives |
| `qds` | `_qds_phase` only |
| `hybrid` | `_qds_phase`, and `_fallback_phase` if it did not succeed |

**`_qds_phase`**: generate the private key; distribute to Bob (tapped if the attack needs it) and to the validator
(never tapped); sign; send over the primary route and apply the attack; Bob verifies against `s_a`; if he accepts and a
validator exists, the validator verifies the forwarded message against `s_v`. It returns `ok`, a `reason`
(`no_message`, `bob_reject`, `validator_reject`), the text Bob accepted, and the metrics.

**`_fallback_phase`**: choose the backend and pair count, run E91, abort if the check fails, protect the message
with OTP + MAC, apply the backup-route attack, open it at Bob. Every failure returns a plain-language reason.

**Verdict** (after both phases):

| Condition | `verdict` | `level` |
|---|---|---|
| nothing accepted | `not_delivered` | warn |
| accepted text ≠ original | `compromised` | bad |
| accepted text = original, by QDS | `delivered_qds` | ok |
| … by the fallback | `delivered_fallback` | ok |
| … in plain mode | `delivered_plain` | warn |

`secure` is `verdict != "compromised"`, and `delivered` is true for the three `delivered_*` verdicts.

**The event log.** Every step calls `log.add(phase, kind, title, detail, frm, to)`. `kind` is `info`, `ok`, `warn`,
`bad` or `attack`; `frm` and `to` are user names and drive the moving packet in the interface. The same list
feeds the interface timeline, the text demo, and the tests.

**Result shape** (`/api/run` returns exactly this):

```
mode, verdict, level, headline, explanation, secure, delivered, original, accepted_text, method,
cast{sender,receiver,validator,attacker}, attack{primary,backup,tap_entanglement},
settings{...}, events[{n,phase,kind,title,detail,from,to}],
metrics{
  qds{ L, digest_bits, s_a, s_v, noise, qubits_per_recipient,
       bob{rates[],max,mean,checked_mean,accepted}, validator{...}|null,
       forgery_log10_block, forgery_log10_message, false_reject_log10 },
  fallback{ backend, backend_detail, pairs, needed_key_bits, S, qber, sifted, key_bits, secure, mac_ok, chsh_min, qber_max }
}
```

**`compare(cfg)`** runs the same scenario in all three modes. If a seed is set it is offset by 0, 1, 2 so each
mode is reproducible but not identical.

---

## 9. `qdslab/app.py`: the server

| Route | Does |
|---|---|
| `GET /` | Returns `static/index.html` |
| `GET /api/status` | Defaults, attack descriptions, and which Bell-pair backends work (this also warms Qiskit up) |
| `POST /api/run` | Body `Scenario` → `engine.run_scenario` |
| `POST /api/compare` | Same body → `{"results": {plain, qds, hybrid}, "order": [...]}` |

`ValueError` from the engine becomes HTTP 400 with the message in `detail`; the interface shows it as a toast.
The models use `Optional[...]` so they also work on older Python and Pydantic versions. Interactive API docs are at
`/docs` while the server runs.

---

## 10. `static/index.html`: the interface

One file. CSS in a `<style>`, JavaScript in one `<script>` (an immediately-invoked function, strict mode). It uses
no framework and downloads nothing, so it works offline.

**State** is one object saved to `localStorage` under `qdslab.v2`:
`{users, cast, mode, message, settings, animate, backend, seed}`.
`users` is a list of `{name, role}` (attackers also carry `primary`, `backup`, `tap_entanglement`, `forged_text`).
`cast` maps `sender / receiver / validator / attacker` to a user name (`""` means "none").

**Rendering helpers.** `h(tag, attrs, ...kids)` creates HTML and `sv(...)` creates SVG elements. Text is always
set with `textContent`, so user names cannot inject markup.

**Main functions:**

| Function | Role |
|---|---|
| `ensureCast()` | After any change, repairs the cast so each role points at a user who still has that role |
| `renderUsers()`, `attackerPanel(u)` | The left column, including the attacker's panel |
| `renderCast()` | The four "who plays what" drop-downs |
| `layout()`, `renderNetwork(active)` | Places sender and receiver left and right, attacker above, validator below, others in a top row; draws the three kinds of link and highlights the nodes of the current step |
| `movePacket(from, to, kind)` | Animates a dot between two nodes with `requestAnimationFrame` |
| `payload()` | Builds the request body from the state |
| `run()`, `compare()` | Clear the previous outcome, call the API, ignore responses that arrive out of order (a token), then call `show` |
| `show(res, instant)` | Plays the events one by one (340 ms apart), then draws verdict and metrics |
| `barChart()`, `gauge()` | The per-block mismatch bars and the CHSH gauge, drawn as inline SVG |
| `showCompare(data)` | The three-row comparison table |
| `buildSliders()`, `setMode()` | The right column |

The diagram labels are enlarged and the role text dropped below 760 px so that it stays readable on a phone.
Animation is off by default when the system asks for reduced motion.

---

## 11. `run.py`, `experiments.py`, `find_collision.py`

- **`run.py`** checks `numpy`, `fastapi` and `uvicorn` before importing them. If one is missing it prints the exact
  `pip` command and, in an interactive terminal, offers to run it. If pip refuses because the system Python is
  locked, it explains how to create a virtual environment. `--check` reports the environment (and why Qiskit is
  unusable, if it is), `--demo` prints the event log of the three modes with only NumPy installed, and the server
  picks the next free port when the chosen one is busy.
- **`experiments.py`** loops over ten attack scenarios × three modes × N seeds, counts verdicts, prints a table and
  writes `results.csv`. `--only TEXT` filters scenarios and `--set KEY=VALUE` overrides settings.
- **`find_collision.py`** searches for a different text that shares the first N digest bits (section 6.3 of the
  project document).

---

## 12. Tests (`tests/test_lab.py`)

Run with `python tests/test_lab.py` (no pytest needed) or `pytest`. 20 tests, all on the NumPy backend except one.

| Group | What is checked |
|---|---|
| QDS | Honest signatures pass with low mismatch; blind forgery scores about 0.5; intercept-resend about 0.25; tampering is rejected; the validator exposes intercept-and-forge; without it the attack succeeds; a 16-bit digest collision defeats QDS but not a 32-bit one; weak parameters let forgeries through; odds shrink with `L` |
| Fallback | Recovers from every primary attack; noise alone triggers it; a tapped entanglement link is detected (S < 2); backup-route attacks cannot forge; plain mode is defenceless; E91 numbers; OTP + MAC round-trip and tamper detection |
| Backends | Qiskit matches NumPy when installed; when it is not installed the NumPy fallback and its warning work |
| Engine and server | Input validation; `compare` returns the three expected verdicts; a real server on a free port answers `/`, `/api/status`, `/api/run`, `/api/compare` and a 400 error, using only the standard library for the requests |

---

## 13. How to extend it

**Add an attack.**
1. Add a key and description to `attacks.PRIMARY` (or `BACKUP`).
2. Handle the key in `apply_primary` (or `apply_backup`): return what reaches Bob.
3. If it acts on Bob's quantum link, add the key to the `tap` condition in `_qds_phase`.
4. Add a short label to `PRIMARY_LABEL` (or `BACKUP_LABEL`) in `index.html`.
5. Add a row to `SCENARIOS` in `experiments.py` and a test.

**Add a setting.** Add it to `config.DEFAULTS`, read `S["name"]` in the engine, and add an entry to `SLIDERS` in
`index.html`. The server and the saved state pick it up automatically.

**Swap the Bell-pair simulator** (another library, or a hardware API). Write a class with `name`, `detail` and
`measure(a_idx, b_idx, noise, eve, rng)` that returns two `uint8` arrays of bits, and return it from
`backends.get_backend`.

**Use a different QDS scheme.** Replace `distribute`, `sign` and `verify` in `qds.py`. `_qds_phase` only relies on
`Record`, `Signature` and `verify(...) → (rates, checked, accepted)`.

**Add a role.** Add it to `ROLES` in `config.py` and to `ROLES` and `ROLE_COLOR` in `index.html`. A role only does
something once `payload()` and `engine.run_scenario` give it a part to play.

**Make it more realistic.** The most valuable upgrades are the symmetrization step among recipients, unambiguous
state elimination, real error correction and privacy amplification for the fallback key, photon loss, and a
dishonest receiver.

---

## 14. If something fails

The table in `README.md`, section 4, covers missing libraries, locked system Python, busy ports, Qiskit problems
and a page that cannot reach the server. For anything else, run `python run.py --check`, then read the last line
of the error message first.
