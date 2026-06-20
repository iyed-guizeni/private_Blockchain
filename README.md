# Private Blockchains with Public Anchoring
## Formal Model & Runtime Verification 

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [File Structure](#4-file-structure)
3. [Installation & Execution](#5-installation--execution)
4. [Formal Verification Policy](#6-formal-verification-policy-fvp)
5. [Attack Taxonomy](#7-attack-taxonomy)
6. [Simulated Results & Log Analysis](#8-simulated-results--log-analysis)
---

## 1. Project Overview

This project is a fully functional, three-layer simulation of the private-blockchain-with-public-anchoring paradigm. It demonstrates:

- A **Private State Machine** executing confidential state transitions and generating cryptographic checkpoint commitments.
- A **Blind Public Smart Contract** accumulating those commitments on a public EVM chain without any semantic visibility into the private domain.
- An **Intelligent Runtime Monitor** enforcing a formal Verification Policy over the public event stream, detecting semantic attacks that the blind contract cannot.
---

## 2. CoreProblem

### The Fundamental Gap

A private blockchain executes transactions locally. To achieve public accountability without revealing confidential state, it posts **cryptographic state roots** (and optionally Zero-Knowledge Proofs) to a public smart contract as periodic **checkpoints**.

```
Private Domain                          Public Domain
─────────────────────────────           ─────────────────────────────
  S_0 → S_1 → S_2 → … → S_t            PublicAnchorContract
  (confidential transitions)      →         stores (R_t, seq_t, π_t)
                                            emits CheckpointPublished event
  R_t = hash(S_t)                            ↑
  π_t = ZKP(S_{t-1} → S_t)         (blind — cannot validate semantics)
```

**The problem:** The public contract is *semantically blind*. It cannot determine:

- Whether `seq_t` follows `seq_{t-1}` correctly (no skipped or replayed transitions).
- Whether `R_t` represents an *operationally stable* state (or a mid-attack snapshot).
- Whether the state is *safe for consumption* by external bridges or cross-chain protocols.

A malicious or compromised private-chain operator can submit **cryptographically valid-looking checkpoints** (correct hash format, valid signature) that are **semantically invalid** (skipped sequences, replayed roots, unauthorized state changes). The blind contract accepts them all.

### The Solution Demonstrated Here

An off-chain **Runtime Monitor** with a **Formal Verification Policy (FVP)** observes the public event stream and enforces semantic constraints the on-chain code cannot. Its verdicts are published back on-chain, closing the trust loop.

---

## 4. File Structure

```
.
├── PublicAnchorContract.sol    # Solidity: the blind public accumulator contract
├── sim.py               # Python: all three layers in a single runnable script

```

### `PublicAnchorContract.sol`

Key design decisions:

| Decision | Rationale |
|---|---|
| `submitCheckpoint()` performs **zero** semantic validation | Intentional — demonstrates the blind-contract problem |
| `DuplicateSequenceDetected` event emitted but not enforced | Informational signal only — contract cannot judge meaning |
| `setConsumability(bool)` restricted to `owner` | Owner represents the Runtime Monitor's publishing key |
| Append-only `checkpointSequences[]` array | Enables full history enumeration for formal audit |
| Immutable `owner` via `immutable` keyword | Prevents post-deploy authority hijacking |

### `simulation.py`

Key design patterns:

| Pattern | Where Used |
|---|---|
| **State Machine** | `PrivateStateMachine._state`, `RuntimeMonitor._prev_sequence` |
| **Strategy / Policy Object** | `FormalVerificationPolicy` injected into `RuntimeMonitor` |
| **Observer** | Monitor subscribes to contract events via `create_filter()` |
| **Circuit Breaker** | Monitor locks `isStateConsumable=False` on first violation |
| **Dataclass DTOs** | `CommitmentPacket`, `MonitorVerdict` — clean layer boundaries |

---

## 5. Installation & Execution

### Prerequisites

- Python ≥ 3.11
- pip

### Install Dependencies

```bash
pip install web3 py-evm eth-tester colorama
```

> **Note:** No external blockchain node is required. The simulation uses `eth-tester` with an in-process `PyEVM` backend — the entire EVM runs inside the Python process.

### Run

```bash
python simulation.py
```

Expected runtime: approximately 10–12 seconds (8 checkpoints at ~1s intervals).

### Optional: Connect to a Live Node

To run against Anvil or Hardhat instead of the in-process EVM, replace the provider in `PublicChainInterface.connect_and_deploy()`:

```python
# Current (in-process):
tester  = EthereumTester(PyEVMBackend())
self.w3 = Web3(Web3.EthereumTesterProvider(tester))

# Replace with:
self.w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
```

Then start Anvil:
```bash
anvil --block-time 1
```

And compile + deploy with the real bytecode from:
```bash
solcjs --optimize --bin --abi PublicAnchorContract.sol
```

---

## 6. Formal Verification Policy (FVP)

The `FormalVerificationPolicy` dataclass encodes three constraints evaluated by the Runtime Monitor on every `CheckpointPublished` event.

### C1 — Sequence Monotonicity

```
∀ n ∈ ℕ : seq_n = seq_{n-1} + 1
```

The monitor maintains `prev_sequence` and checks strict unit increment. Violations:

| Sub-type | Condition | Example |
|---|---|---|
| `C1_SEQUENCE_JUMP` | `seq_n > prev_seq + 1` | 4 → 7 (gap of 3) |
| `C1_SEQUENCE_REPLAY` | `seq_n == prev_seq` | 4 → 4 |
| `C1_SEQUENCE_REGRESSION` | `seq_n < prev_seq` | 4 → 2 |

### C2 — Timing Window

```
FVP_MIN_INTERVAL ≤ (T_n - T_{n-1}) ≤ FVP_MAX_INTERVAL
```

| Sub-type | Condition | Severity |
|---|---|---|
| `C2_FLOOD_ATTACK` | `Δt < min` | Violation (blocks consumption) |
| `C2_LIVENESS_WARNING` | `Δt > max` | Warning only (logged) |

### C3 — State Root Non-Repetition

```
∀ n ≠ m : stateRoot_n ≠ stateRoot_m
```

A set of seen state roots is maintained. Any re-occurrence signals a `STALE_STATE_ROOT` replay attack.

---

## 7. Attack Taxonomy

The `PrivateStateMachine` supports three adversarial modes via `trigger_state_manipulation_attack()`:

### `AttackType.SEQUENCE_JUMP`

**What:** The private chain skips `N` sequence numbers in its submission.  
**Why realistic:** A malicious operator may want to suppress evidence of intermediate transactions, or inject a forged state that skips over a dispute period.  
**Contract behavior:** Accepts unconditionally.  
**Monitor detection:** C1 fires immediately — `expected seq=5, received seq=7`.

```python
psm.trigger_state_manipulation_attack(
    attack_type=AttackType.SEQUENCE_JUMP,
    jump_magnitude=3
)
```

### `AttackType.SEQUENCE_REPLAY`

**What:** Re-submits a previously anchored sequence number with a different state root.  
**Why realistic:** An operator attempts to rewrite history by overwriting a prior checkpoint.  
**Contract behavior:** Emits `DuplicateSequenceDetected` (informational) but still records it.  
**Monitor detection:** C1 fires — `seq_n == prev_seq`.

### `AttackType.STALE_STATE_ROOT`

**What:** Submits a new sequence number but reuses an old state root hash.  
**Why realistic:** A replay of an earlier valid proof against a new sequence slot.  
**Contract behavior:** Accepts unconditionally (hashes look distinct from its perspective).  
**Monitor detection:** C3 fires — root already present in `seen_state_roots`.

---

## 8. Simulated Results & Log Analysis

Below is annotated output from an actual simulation run.

### Phase 1: Normal Operation (Steps 1–4)

```
STEP  1/8
12:07:43 [PRIVATE] ✓ Checkpoint emitted | seq=  1 | S_t=   1007 | Δ=  7 | root=aa7f17e1babc…
12:07:43 [PUBLIC ] ✓ submitCheckpoint mined | seq=1 | block=2 | clean
12:07:44 [MONITOR]  FVP PASSED | seq=  1 | Δt=N/A (first) | C1✓ C2✓ C3✓
12:07:44 [VERDICT]  seq=1 → PUBLIC CONSUMABLE FACT | Bridges may safely consume.

STEP  2/8
12:07:44 [PRIVATE] ✓ Checkpoint emitted | seq=  2 | S_t=   1011 | Δ=  4 | root=af56bf70a74f…
12:07:44 [PUBLIC ] ✓ submitCheckpoint mined | seq=2 | block=4 | clean
12:07:44 [MONITOR]  FVP PASSED | seq=  2 | Δt=0.95s | C1✓ C2✓ C3✓
12:07:44 [VERDICT]  seq=2 → PUBLIC CONSUMABLE FACT | Bridges may safely consume.
```

**Analysis:** Each checkpoint arrives with `seq_n = seq_{n-1} + 1`, unique state roots, and inter-arrival timing within the FVP window. The monitor confirms all three constraints pass and publishes `isStateConsumable = true` on-chain. External bridges see a green light.

---

### Phase 2: Attack Injection (Step 5)

```
STEP  5/8
12:07:47 [ATTACK ]   Attack mode ACTIVATED | type=SEQUENCE_JUMP | jump_magnitude=3
12:07:47 [ATTACK ]  SEQUENCE_JUMP injected | seq=7 (jumped +3, skipped 2 seq numbers) |
                   root=7584bd0cebdd… | Proof is SHA-256-valid (FOOLS contract)
12:07:47 [PUBLIC ]  submitCheckpoint mined | seq=7 | block=10 |   MALICIOUS ACCEPTED BLINDLY
12:07:47 [MONITOR]  FVP VIOLATION | seq=  7 |
                   C1_SEQUENCE_JUMP: expected seq=5, received seq=7 (gap=3, 2 seq numbers skipped)
12:07:47 [VERDICT]  seq=7 → STATE CONSUMPTION BLOCKED |
                   Formal policy violated — bridges MUST NOT consume this checkpoint.
12:07:47 [SYSTEM ] On-chain snapshot | total_cps=5 | latest_seq=7 | consumable=False
```


### Phase 3: Persistent Lockout (Steps 6–8)

```
STEP  6/8
12:07:48 [MONITOR]  FVP VIOLATION | seq=  8 |
          C1_SEQUENCE_JUMP: expected seq=5, received seq=8 (gap=4, 3 seq numbers skipped)
12:07:48 [VERDICT]  seq=8 → STATE CONSUMPTION BLOCKED

STEP  7/8
12:07:49 [MONITOR]  FVP VIOLATION | seq=  9 |
          C1_SEQUENCE_JUMP: expected seq=5, received seq=9 (gap=5, 4 seq numbers skipped)

STEP  8/8
12:07:50 [MONITOR]  FVP VIOLATION | seq= 10 |
          C1_SEQUENCE_JUMP: expected seq=5, received seq=10 (gap=6, 5 seq numbers skipped)
```

**Analysis:** Once the monitor's `prev_sequence` is locked at `4` (the last valid checkpoint), every subsequent submission registers an ever-growing gap. The private chain's honest post-attack transitions (seq 8, 9, 10) are still flagged because the continuity gap from the initial attack was never resolved. This demonstrates the **circuit-breaker property**: a single attack permanently blocks consumption until the gap is formally resolved (not shown here — but in a production system, this would trigger a governance or challenge process).

---


The report cleanly separates the pre-attack consumable window (`seq ∈ {1,2,3,4}`) from the post-attack lockout (`seq ∈ {7,8,9,10}`). This is the formal output a bridge protocol would consume to determine which checkpoints it may act upon.

---

