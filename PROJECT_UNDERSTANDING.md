# Project understanding: quantum digital signatures with an entanglement fallback

This document explains **what the project is, why it exists, what the physics does, what the attacker can and
cannot do, how to read the results, and where the simulation stops being realistic.** Read it before the code.
(`CODE_WALKTHROUGH.md` explains the code; `README.md` explains how to install and run it.)

---

## 1. What this project is

A software simulation of a hybrid security system with three layers:

1. **A quantum digital signature (QDS).** Alice signs a message with quantum states. Bob, and an independent
   validator, check the signature. Its security comes from physics rather than from a hard maths problem.
2. **An entanglement fallback.** If the signature check fails, for any reason, Alice and Bob switch to a secret key
   made from entangled pairs and deliver the real message encrypted and authenticated over a second route.
3. **A role-assignment lab.** A web interface where you add users, give each a role (sender, receiver, validator,
   attacker, bystander), choose what the attacker does, and watch a step-by-step log, charts and a verdict.

The headline scenario from the original idea: **Alice sends, Bob receives, and Charlie stops Alice's message and
pretends to be Alice.** The lab shows that without protection Bob is fooled, with the quantum signature Bob refuses
the fake (but gets nothing), and with the fallback Bob refuses the fake *and* still gets Alice's real message.

Everything is simulated in Python. No quantum hardware is involved.

---

## 2. The problem it addresses

**Why quantum signatures at all.** Today's signatures (RSA, ECDSA) are safe only because certain maths problems
are hard for ordinary computers. A large quantum computer running Shor's algorithm would break them. A QDS instead
makes forging physically impossible: the public key is a set of quantum states, and the no-cloning theorem and the
limits on distinguishing unknown states stop anyone from copying it or reading it out well enough to forge the
matching private key. Its security does not depend on how fast the attacker's computer is.

**The weakness this project tackles.** A QDS check is statistical. The receiver counts mismatches between the
revealed key and what he measured. Mismatches have three possible causes that look identical to him:

- ordinary channel noise or detector errors,
- someone disturbing the quantum states (an eavesdropper),
- a forged or altered message.

When mismatches are too high the receiver must refuse. That is the safe choice, but it means **an attacker can
force a refusal just by disturbing the channel**, and ordinary noise causes refusals too. Security is kept; the
message is lost.

**The idea.** Do not give up when the signature fails. Use a *different* quantum resource, entangled pairs, to
create a fresh one-time key, certify that nobody tampered with the pairs, and deliver the real message with that
key. The fallback never lowers the standard of authenticity. It adds a second, independently protected way to get
the genuine message through.

---

## 3. The ideas in plain language

**Digital signature.** Proof that a message came from its owner and was not changed. Anyone can check it, only
the owner can produce it.

**BB84 states.** A qubit prepared as a bit in one of two bases (call them Z and X). If you measure in the basis it
was prepared in, you get the bit. If you measure in the other basis you get a coin flip. You cannot know the
basis from a single copy.

**QDS as used here.**
- *Private key (Alice only):* for every signed digest bit and for each of its two possible values (0, 1), a block of
  `L` random pairs `(basis, bit)`. That is `digest_bits × 2 × L` pairs.
- *Public key (quantum):* the same pairs, prepared as real qubits. One separate copy goes to Bob and one to the
  validator. Each recipient measures every qubit in a **random basis** and stores `(basis, result)`.
- *Signing:* Alice takes SHA-256 of the message, keeps the first `digest_bits` bits, and for each of those bits
  reveals the matching private-key block. The signature is those blocks.
- *Verifying:* for each block the recipient looks only at positions where the basis he happened to measure in
  equals the revealed basis (about half of them). There an honest signature gives the same bit, apart from noise.
  The **mismatch rate** of the block is the fraction that disagree. Every block must be below the threshold.

**Why a forger fails.** Someone without the private key does not know the bases or bits, so he guesses, and
guesses are wrong about half the time. His mismatch rate is about **0.50**, far above an honest signature's.

**Why a validator.** If an attacker controls Bob's quantum link he can measure and re-send every qubit, so *Bob's
own record is made of the attacker's states*. The attacker can then "sign" with exactly what he sent, and Bob sees
almost no mismatches. A second recipient with an independent record does see the problem: his states came
straight from Alice. This is why QDS is defined with at least two recipients. The lab shows both outcomes.

**Two thresholds.** Bob accepts below `s_a`. The validator, who receives the message forwarded by Bob, accepts
below the looser `s_v`. They need to satisfy: channel noise < `s_a` < `s_v` < 0.25. Section 6 explains why.

**Entangled pair (Bell pair).** Two qubits in the state (|00⟩ + |11⟩)/√2. Measured along the same angle, both give
the same random bit. Measured along different angles, they show correlations that no pre-agreed classical
strategy can reproduce.

**CHSH test.** Combine four such correlations into one number S. Any classical (local hidden variable) explanation
gives S ≤ 2. Perfect entangled pairs give S = 2√2 ≈ 2.83. If S is clearly above 2 the pairs are really entangled,
which means nobody measured and re-sent them (that would drop S to about 1.4).

**E91 key exchange.** Alice and Bob each pick one of three measurement angles per pair. Two angle combinations
coincide, giving identical bits: the raw key. Four combinations feed the CHSH test. A random 25% of the raw key is
sacrificed to estimate the error rate (QBER).

**One-time pad and one-time MAC.** The message is XOR-ed with secret key bits (perfect secrecy, but an attacker
can flip bits). A second chunk of key makes a short authentication tag over the ciphertext, so any change is
detected with probability about 1 − 2⁻¹⁰⁰. Both are used once, then thrown away.

---

## 4. The design

```
          main route (classical): message + signature
Alice ──────────────────────────────────────────────────▶ Bob ──forwards──▶ Dave (validator)
  │ ╲                                                      ▲
  │  ╲___ quantum states (public key), copy 1 _____________│
  │   ╲___ quantum states (public key), copy 2 ______________________________▲
  │
  └── backup route + entangled pairs ───────────────────────▶ Bob     (used only if the signature fails)

Charlie sits on the main route and can also reach the quantum link to Bob,
the backup route, and the entanglement link.
```

Decision flow for one message in "Signature + fallback" mode:

```
Alice signs ─▶ Bob checks every digest-bit block against s_a
                 │ all pass ─▶ Dave checks against s_v ─ all pass ─▶ DELIVERED by QDS
                 │                                      └ any fail ┐
                 └ fail, or nothing arrived ───────────────────────┤
                                                                   ▼
                            Bell pairs shared between Alice and Bob
                            CHSH S > 2.2  and  error rate ≤ 11% ?
                                 no ─▶ NOT DELIVERED (link tapped or too noisy; nothing forged accepted)
                                 yes ▼
                            key ─▶ one-time pad + one-time MAC ─▶ backup route
                                 route blocked / MAC fails ─▶ NOT DELIVERED (nothing forged accepted)
                                 MAC verifies ─▶ DELIVERED by the fallback
```

| Layer | Purpose | Where its security comes from | Code |
|---|---|---|---|
| QDS | Prove who sent the message, to anyone | No-cloning and state discrimination | `qdslab/qds.py` |
| Entanglement check | Certify that the key material was not tampered with | Bell inequality violation (CHSH) | `qdslab/entanglement.py`, `backends.py` |
| One-time pad + MAC | Deliver the real message secretly and authentically | Information-theoretic, given a secret key | `qdslab/classical.py` |

The three protection levels in the interface:

- **None:** the receiver accepts whatever arrives. A baseline to show what the other levels buy.
- **Signature:** QDS only. If the check fails, nothing is delivered.
- **Signature + fallback:** QDS first, entanglement fallback second.

---

## 5. Roles and the attacker model

| Role | What the user does |
|---|---|
| Sender | Signs the message and sends it |
| Receiver | Checks the signature before accepting |
| Validator | Second, independent checker; confirms the signature is transferable |
| Attacker | Acts against the message; you choose how (below) |
| Bystander | Present in the network, does nothing |

If several users share a role, you pick who plays it for each run. "None" is allowed for validator and attacker.

**What the attacker (Charlie) can do:**

| Choice | What Charlie does | What exposes it | Typical numbers |
|---|---|---|---|
| Watch only | Nothing | n/a | Honest mismatch ≈ channel noise (2%) |
| Block the message | Message never arrives | Timeout | none |
| Forge and replace | Blocks Alice's message, sends his own text with a guessed signature | Every block mismatches | ≈ 0.50 on every block |
| Edit, keep the signature | Changes the text, re-attaches Alice's genuine signature | Blocks whose digest bit changed mismatch | ≈ 0.50 on about half the blocks, noise on the rest |
| Intercept quantum states | Measures and re-sends the qubits to Bob | Disturbance | ≈ 0.25 on Bob's blocks |
| Intercept states, then forge | Intercepts Bob's qubits, then signs with what he measured | Bob is fooled; the validator is not | Bob ≈ noise, validator ≈ 0.25 |
| Backup route: block | Drops the fallback ciphertext | Timeout | availability lost, authenticity kept |
| Backup route: swap ciphertext | Re-encrypts his own text using the pad he recovered from the plaintext he saw | One-time MAC fails | forging chance about 2⁻¹⁰⁰ |
| Tap the entanglement link | Measures and re-sends Bob's half of each Bell pair | CHSH test | S ≈ 1.4 instead of 2.8 |

**What the verdicts mean** (the stamped box in the interface):

| Verdict | Meaning |
|---|---|
| Delivered (green) | Bob ended up with Alice's real message, via the signature or via the fallback |
| Delivered, but nothing proves who sent it (amber) | No protection was in use |
| Not delivered, but no fake was accepted (amber) | The system stayed safe but could not get the message through |
| Forgery accepted (red) | Bob accepted a message Alice never sent |

**What happens for each attack and protection level** (this is what `experiments.py` measures):

| Attack | None | Signature | Signature + fallback |
|---|---|---|---|
| none | delivered (unproven) | delivered | delivered |
| Block the message | nothing arrives | not delivered | **delivered via fallback** |
| Forge and replace | **forgery accepted** | not delivered | **delivered via fallback** |
| Edit, keep signature | **forgery accepted** | not delivered | **delivered via fallback** |
| Intercept quantum states | no effect | not delivered | **delivered via fallback** |
| Intercept states + forge, with validator | **forgery accepted** | not delivered | **delivered via fallback** |
| Intercept states + forge, **no validator** | **forgery accepted** | **forgery accepted** | **forgery accepted** |
| Forge + block backup route | **forgery accepted** | not delivered | not delivered (safe) |
| Forge + tap entanglement link | **forgery accepted** | not delivered | not delivered (safe) |

---

## 6. Reading the numbers, choosing parameters, and why "Forgery accepted" can happen

### 6.1 Mismatch rates

The bar charts show one bar per signed digest bit. The reference levels to remember:

| Situation | Mismatch rate |
|---|---|
| Honest signature | about the channel noise (default 2%) |
| Qubits disturbed by an intercept-resend attacker | about 25% (plus noise) |
| Intercept-and-forge, as seen by the **validator** | about 25% |
| Blind forgery | about 50% |

Where 25% comes from: when the attacker guesses the wrong basis (half the time), the re-sent qubit is scrambled and
the receiver's reading is wrong half of those times: ½ × ½ = ¼.

### 6.2 The thresholds `s_a` and `s_v`

Defaults: noise 0.02 < `s_a` = 0.10 < `s_v` = 0.20 < 0.25.

- `s_a` must sit above the noise, or honest signatures are refused. It should sit well below 0.25 and 0.50.
- `s_v` is looser than `s_a` so that a genuine signature that Bob accepted is also accepted by the validator
  despite slightly different noise on the two links. If it were not, a dishonest receiver could cause disputes.
- `s_v` must stay **below 0.25**. That is the best mismatch rate the intercept-and-forge attacker reaches on the
  validator's independent record. Raise `s_v` above it and that attack starts to pass.

Try it: set the quantum channel noise to 12–15% with no attacker. Honest signatures now exceed `s_a`, QDS
refuses, and the fallback delivers the message. This is the "noise kills QDS" case the project was designed for.

### 6.3 `L`, the digest length, and the odds shown under the charts

- **L** is the block length. A block has about `L/2` comparable positions. A blind forger passes a block only if
  fewer than a fraction `s_a` of them mismatch, and with a 50% mismatch chance per position that probability falls
  exponentially in `L`. At the defaults (`L` = 256, `s_a` = 0.10) it is about **1 in 10²² per block**.
- A forger who has **seen one genuine signature** (the "edit, keep the signature" attack) already knows the blocks
  for the digest bits his fake shares with the original, so he must guess only the roughly `digest_bits / 2`
  blocks that differ. The interface's "Fake message passes" line shows that, about 1 in 10³⁵⁴ at the defaults.
  A forger who has seen nothing must pass *every* block.
- **Cost:** each signed digest bit needs `2L` qubits per recipient: 16,384 qubits at the defaults.
- **The digest length is a classical weakness as well.** Only the first `digest_bits` bits of SHA-256 are signed.
  If two messages share those bits, Alice's genuine signature fits both, and every quantum check passes.
  Finding such a message costs about `2^digest_bits` hashes. Demonstration:

  ```
  python find_collision.py "Meet at the lab at 5pm" --bits 16
  Found after 86,967 tries (0.1s):  Pay Charlie #86967
  ```

  Set "Digest bits signed" to 16, give Charlie *Edit, keep the signature* with that text, and run in *Signature*
  mode: the forgery is **accepted, even with a validator**. At 32 bits the same text is rejected. 32 is a classroom
  default, not a safe value: a determined attacker can do 2³² hashes easily. Real use needs a digest of 128 bits
  or more (the engine accepts up to 256; the interface slider stops at 64).

### 6.4 Why you may see "Forgery accepted"

It is not a bug. It appears when (a) the protection level is *None*, (b) the attacker uses *Intercept states, then
forge* and there is **no validator**, (c) the signed digest is short enough to collide (6.3), or (d) `L` is tiny
or `s_a` is loose enough that guesses pass. The lab is meant to let you create exactly these situations.

### 6.5 Fallback numbers

- **CHSH S** for ideal pairs is 2.83. With depolarizing noise `p` it is `2.83 × (1 − p)`: about **2.74** at the 3%
  default. A tapped link gives about **1.4**. The fallback needs S above **2.2**, a margin over the classical limit
  of 2 that absorbs the statistical wobble of a finite number of pairs.
- **QBER** (key-sample error rate) is about `p/2`: 1.5% at the default. The limit is 11%, which is the familiar
  limit for key distribution of the BB84/E91 kind.
- **Key length** after the checks is estimated as `n × (1 − 2·h₂(q))`, with `n` the remaining raw bits, `q` the
  measured error rate (plus a 1% margin) and `h₂` the binary entropy. At `q` ≈ 11% this reaches zero.
- **Number of Bell pairs** is chosen automatically from the message length and the noise (more pairs for a longer
  message or a noisier link). The interface shows how many key bits were needed and how many survived.

---

## 7. Experiments to run, and a short demo for a panel

| # | Set up | Expect |
|---|---|---|
| 1 | Attacker *none*, mode *Signature* | Delivered; all bars near 0.02 |
| 2 | Charlie *Forge and replace*; run *Compare protection levels* | Forgery accepted / not delivered / delivered via fallback. This is the original scenario |
| 3 | Charlie *Edit, keep the signature* | Half the bars at 0.5, half near 0; rejected; fallback delivers |
| 4 | Charlie *Intercept quantum states* | Every bar near 0.25 and red; fallback delivers |
| 5 | Charlie *Intercept states, then forge*, with and without Dave | Without Dave: forgery accepted. With Dave: his chart is red, fallback delivers |
| 6 | No attacker, quantum channel noise 15% | QDS refuses by itself; fallback delivers |
| 7 | Quantum noise 15% **and** entanglement noise 40% | Both layers fail safely: S ≈ 1.7, nothing delivered, nothing forged |
| 8 | Charlie *Forge*, tick *Tap the entanglement link* | Fallback aborts, CHSH ≈ 1.4, not delivered |
| 9 | Charlie backup route *Block*, then *Swap the ciphertext* | Not delivered; MAC failure shown for the swap |
| 10 | `find_collision.py`, digest bits 16 | Forgery accepted with a validator present |
| 11 | `python experiments.py --runs 100` | Success rates of every attack in every mode, saved to `results.csv` |

**Five-minute demo script:** (1) show the default cast and run with no attacker; (2) turn Charlie on as *Forge and
replace* and press *Compare protection levels*; (3) open the fallback run and point at the CHSH gauge and the
step log; (4) remove Dave and switch Charlie to *Intercept states, then forge* to show why a validator is needed;
(5) raise quantum noise to 15% to show the fallback also covers plain noise; (6) finish with the limits in section 8.

---

## 8. Assumptions and limits (read before quoting any number)

1. **Simulation only.** No photons, no hardware. The quantum parts are the exact statistics of ideal BB84 states
   and Bell pairs plus simple noise: a bit-flip probability per qubit for QDS, depolarizing noise for the Bell
   pairs. Photon loss is not modelled.
2. **The QDS is a teaching model.** It uses BB84 states and basis-match comparison. Published protocols (Gottesman
   and Chuang; Dunjko, Wallden and Andersson; Amiri et al.) use more careful measurements, a symmetrization step
   between the recipients, and come with formal security proofs. The probabilities in this lab assume about `L/2`
   independent comparable positions per block and are rough estimates, not proofs.
3. **No dishonest receiver.** Bob forwards honestly to the validator over an authenticated link. Repudiation and
   forwarding attacks by a malicious recipient are not modelled.
4. **Charlie does not replace the whole quantum distribution.** If he could swap every state sent to *both*
   recipients, QDS would fail; the standard assumption is that this is not possible.
5. **Authenticated announcements in the fallback.** E91, like every key-distribution protocol, needs an
   authenticated classical channel for announcing measurement bases. In practice this uses a small pre-shared secret.
   The lab assumes it is in place and does not simulate it.
6. **The backup route must be independent of the attacker.** If Charlie blocks both routes nothing can deliver the
   message. What the design guarantees is that he cannot make Bob accept a fake. Availability is not guaranteed.
7. **Key distillation is simplified.** Error correction is assumed ideal and privacy amplification is replaced by
   shortening the key to `n(1 − 2·h₂(q))`. No finite-size analysis. A fully device-independent analysis would give
   lower rates.
8. **One message, one attacker, one validator per run.** Multiple attackers and multi-hop networks are not modelled.
9. **Key budget.** The fallback needs `32 + message length` bytes of key. Very long messages or very noisy links
   can run out (the lab then says so). Pair counts are capped (80,000 for NumPy, 20,000 for Qiskit).
10. **The pre-signing step is a hash.** The signature covers a truncated SHA-256 digest, so its strength is
    limited by `digest_bits` (section 6.3).

---

## 9. How this differs from the first outline

The first outline of this project made some statements that this implementation corrects or sharpens:

- **"If QBER exceeds about 11–15% the QDS layer aborts."** The 11% figure belongs to key distribution (BB84/E91).
  A QDS decides with its own two thresholds `s_a` and `s_v`. The lab uses 11% only inside the fallback key check.
- **"The fallback ensures message completion."** Only if a second route exists and the attacker does not control
  it. The lab has switches for that and reports honestly when delivery fails.
- **"Gracefully downgrades."** It does not downgrade the check. It switches to a different, independently
  authenticated channel. A downgrade that accepted weaker evidence would be a vulnerability.
- **Roles.** In the textbook three-party protocol "Charlie" is the second recipient. Here Charlie is the
  attacker and **Dave** is the second recipient (the validator), because an attacker is the more instructive
  character to put in the interface.
- **A validator is essential**, not optional decoration: section 6 and experiment 5 show the attack that
  succeeds without one.

---

## 10. Glossary

| Term | Meaning |
|---|---|
| Qubit | A two-level quantum system |
| BB84 state | A qubit prepared as bit 0/1 in the Z or X basis |
| Basis | The question a measurement asks. Same basis as preparation: the bit; other basis: a coin flip |
| Digest | A fixed-size fingerprint of the message (SHA-256); the first `digest_bits` bits are signed |
| Block | The `L` basis/bit pairs that belong to one digest bit and one value of it |
| Mismatch rate | Fraction of comparable positions in a block where revealed and measured values differ |
| `s_a`, `s_v` | Acceptance limits for the receiver and for the validator |
| Validator | The second recipient who independently checks a forwarded signature |
| Transferable | A signature that a third party will also accept |
| Bell pair | Two maximally entangled qubits |
| CHSH value S | Combination of four correlations. ≤ 2 classically, up to 2.83 with entanglement |
| QBER | Quantum bit error rate: fraction of disagreeing bits in the key sample |
| E91 | Key exchange based on measuring entangled pairs (Ekert, 1991) |
| Depolarizing noise | With some probability the qubit is replaced by random noise |
| One-time pad | XOR with a secret key as long as the message; perfect secrecy |
| One-time MAC | Short tag from a secret key that detects any change to the message |
| Fallback | The second path used when the signature check fails |

---

## 11. References

Check volume and page details before citing these in a paper.

- D. Gottesman, I. Chuang. *Quantum digital signatures.* arXiv:quant-ph/0105032 (2001).
- V. Dunjko, P. Wallden, E. Andersson. *Quantum digital signatures without quantum memory.* Phys. Rev. Lett. 112, 040502 (2014).
- R. Amiri, P. Wallden, A. Kent, E. Andersson. *Secure quantum signatures using insecure quantum channels.* Phys. Rev. A 93, 032325 (2016).
- C. H. Bennett, G. Brassard. *Quantum cryptography: public key distribution and coin tossing.* (1984).
- A. K. Ekert. *Quantum cryptography based on Bell's theorem.* Phys. Rev. Lett. 67, 661 (1991).
- J. F. Clauser, M. A. Horne, A. Shimony, R. A. Holt. *Proposed experiment to test local hidden-variable theories.* Phys. Rev. Lett. 23, 880 (1969).
- M. N. Wegman, J. L. Carter. *New hash functions and their use in authentication and set equality.* J. Comput. Syst. Sci. 22 (1981).
- P. W. Shor. *Polynomial-time algorithms for prime factorization and discrete logarithms on a quantum computer.* SIAM J. Comput. 26 (1997).
