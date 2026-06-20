# Private Blockchains with Public Anchoring
## Formal Model & Runtime Verification — Micro-Project

> **Target:** CIFRE PhD Vacancy — ISEP / BaaS.sh  
> **Thesis title:** *Blockchains Privées à Ancrage Public : Modèle Formel et Vérification d'Exécution*  
> **Purpose:** Demonstrate research readiness by implementing the core thesis problem end-to-end in a running simulation.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Core Thesis Problem](#2-core-thesis-problem)
3. [Architecture](#3-architecture)
4. [File Structure](#4-file-structure)
5. [Installation & Execution](#5-installation--execution)
6. [Formal Verification Policy](#6-formal-verification-policy-fvp)
7. [Attack Taxonomy](#7-attack-taxonomy)
8. [Simulated Results & Log Analysis](#8-simulated-results--log-analysis)
9. [Alignment with PhD Proposal](#9-alignment-with-phd-proposal)
10. [Extension Roadmap](#10-extension-roadmap)

---

## 1. Project Overview

This project is a fully functional, three-layer simulation of the private-blockchain-with-public-anchoring paradigm at the heart of the PhD thesis. It demonstrates:

- A **Private State Machine** executing confidential state transitions and generating cryptographic checkpoint commitments.
- A **Blind Public Smart Contract** accumulating those commitments on a public EVM chain without any semantic visibility into the private domain.
- An **Intelligent Runtime Monitor** enforcing a formal Verification Policy over the public event stream, detecting semantic attacks that the blind contract cannot.

The project is runnable in under two minutes with a single Python command and produces richly annotated terminal output suitable for demonstration in a thesis interview.

---

## 2. Core Thesis Problem

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

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SIMULATION LAYERS                            │
│                                                                     │
│  ┌──────────────────────────┐                                       │
│  │  LAYER 1: Private Domain │  ← Python PrivateStateMachine        │
│  │                          │                                       │
│  │  S_t ∈ ℤ≥0               │  State space                        │
│  │  S_{t+1} = S_t + Δ       │  Transition function                 │
│  │  R_t = SHA-256(S_t‖seq‖n)│  State root commitment              │
│  │  π_t = SHA-256(R_t‖seq‖k)│  Mock ZKP                          │
│  │                          │                                       │
│  │  ⚠ Attack mode: injects  │                                       │
│  │    sequence_jump, replay,│                                       │
│  │    or stale_root attack  │                                       │
│  └──────────┬───────────────┘                                       │
│             │  CommitmentPacket(R_t, seq_t, π_t)                   │
│             ▼                                                       │
│  ┌──────────────────────────┐                                       │
│  │  LAYER 2: Public Domain  │  ← Solidity PublicAnchorContract     │
│  │                          │                                       │
│  │  submitCheckpoint()      │  Accepts ALL packets unconditionally │
│  │  → stores Checkpoint     │                                       │
│  │  → emits CheckpointPublished event                               │
│  │                          │                                       │
│  │  isStateConsumable bool  │  Written by monitor verdict          │
│  └──────────┬───────────────┘                                       │
│             │  CheckpointPublished(R_t, seq_t, π_t, block, ts)     │
│             ▼                                                       │
│  ┌──────────────────────────┐                                       │
│  │  LAYER 3: Runtime Monitor│  ← Python RuntimeMonitor             │
│  │                          │                                       │
│  │  FVP Constraint C1:      │  seq_n == prev_seq + 1              │
│  │  FVP Constraint C2:      │  min_Δt ≤ interval ≤ max_Δt        │
│  │  FVP Constraint C3:      │  root_n ∉ seen_roots               │
│  │                          │                                       │
│  │  PASS → "Consumable Fact"│  setConsumability(true)             │
│  │  FAIL → "Violation"      │  setConsumability(false)            │
│  └──────────────────────────┘                                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. File Structure

```
.
├── PublicAnchorContract.sol    # Solidity: the blind public accumulator contract
├── simulation.py               # Python: all three layers in a single runnable script
└── README.md                   # This document
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
12:07:44 [MONITOR] ✅ FVP PASSED | seq=  1 | Δt=N/A (first) | C1✓ C2✓ C3✓
12:07:44 [VERDICT] 🟢 seq=1 → PUBLIC CONSUMABLE FACT | Bridges may safely consume.

STEP  2/8
12:07:44 [PRIVATE] ✓ Checkpoint emitted | seq=  2 | S_t=   1011 | Δ=  4 | root=af56bf70a74f…
12:07:44 [PUBLIC ] ✓ submitCheckpoint mined | seq=2 | block=4 | clean
12:07:44 [MONITOR] ✅ FVP PASSED | seq=  2 | Δt=0.95s | C1✓ C2✓ C3✓
12:07:44 [VERDICT] 🟢 seq=2 → PUBLIC CONSUMABLE FACT | Bridges may safely consume.
```

**Analysis:** Each checkpoint arrives with `seq_n = seq_{n-1} + 1`, unique state roots, and inter-arrival timing within the FVP window. The monitor confirms all three constraints pass and publishes `isStateConsumable = true` on-chain. External bridges see a green light.

---

### Phase 2: Attack Injection (Step 5)

```
STEP  5/8
  ╔═══════════════════════════════════════════════════════╗
  ║  ⚠️   ADVERSARIAL ATTACK INJECTION                     ║
  ║      Type: SEQUENCE_JUMP (gap of 3)                    ║
  ║      The blind contract WILL accept this packet.       ║
  ║      The Runtime Monitor WILL detect the anomaly.      ║
  ╚═══════════════════════════════════════════════════════╝

12:07:47 [ATTACK ] ⚠️  Attack mode ACTIVATED | type=SEQUENCE_JUMP | jump_magnitude=3
12:07:47 [ATTACK ] 💀 SEQUENCE_JUMP injected | seq=7 (jumped +3, skipped 2 seq numbers) |
                   root=7584bd0cebdd… | Proof is SHA-256-valid (FOOLS contract)
12:07:47 [PUBLIC ] ✓ submitCheckpoint mined | seq=7 | block=10 | ⚠️  MALICIOUS ACCEPTED BLINDLY
12:07:47 [MONITOR] ❌ FVP VIOLATION | seq=  7 |
                   C1_SEQUENCE_JUMP: expected seq=5, received seq=7 (gap=3, 2 seq numbers skipped)
12:07:47 [VERDICT] 🔴 seq=7 → STATE CONSUMPTION BLOCKED |
                   Formal policy violated — bridges MUST NOT consume this checkpoint.
12:07:47 [SYSTEM ] On-chain snapshot | total_cps=5 | latest_seq=7 | consumable=False
```

**Analysis — The Core Thesis Demonstration:**

The blind `PublicAnchorContract` logs the message `"✓ submitCheckpoint mined"` without hesitation. It has no mechanism to detect that sequence 5 and 6 were skipped. The attacker's proof is a valid SHA-256 hash — the contract cannot distinguish it from a legitimate ZKP.

The Runtime Monitor, however, catches the anomaly **instantaneously**. Its state holds `prev_sequence = 4`, so it computes `expected_seq = 5`. Receiving `seq = 7` triggers C1 (`SEQUENCE_JUMP`). The monitor publishes `setConsumability(false)` on-chain. From this point, any bridge or cross-chain contract checking `isStateConsumable` will see `False` and block.

This is the exact failure mode described in the thesis: **the public contract cannot protect itself; it requires an off-chain formal verifier.**

---

### Phase 3: Persistent Lockout (Steps 6–8)

```
STEP  6/8
12:07:48 [MONITOR] ❌ FVP VIOLATION | seq=  8 |
          C1_SEQUENCE_JUMP: expected seq=5, received seq=8 (gap=4, 3 seq numbers skipped)
12:07:48 [VERDICT] 🔴 seq=8 → STATE CONSUMPTION BLOCKED

STEP  7/8
12:07:49 [MONITOR] ❌ FVP VIOLATION | seq=  9 |
          C1_SEQUENCE_JUMP: expected seq=5, received seq=9 (gap=5, 4 seq numbers skipped)

STEP  8/8
12:07:50 [MONITOR] ❌ FVP VIOLATION | seq= 10 |
          C1_SEQUENCE_JUMP: expected seq=5, received seq=10 (gap=6, 5 seq numbers skipped)
```

**Analysis:** Once the monitor's `prev_sequence` is locked at `4` (the last valid checkpoint), every subsequent submission registers an ever-growing gap. The private chain's honest post-attack transitions (seq 8, 9, 10) are still flagged because the continuity gap from the initial attack was never resolved. This demonstrates the **circuit-breaker property**: a single attack permanently blocks consumption until the gap is formally resolved (not shown here — but in a production system, this would trigger a governance or challenge process).

---

### Final Verification Report

```
════════════════════════════════════════════════════════════════════════
  RUNTIME MONITOR — FINAL FORMAL VERIFICATION REPORT
════════════════════════════════════════════════════════════════════════
  Total checkpoints evaluated  : 8
  ✅ Valid (consumable)          : 4
  ❌ Policy violations detected  : 4
  Consumable sequence numbers   : [1, 2, 3, 4]
────────────────────────────────────────────────────────────────────────
    SEQ  STATUS              Δt   DETAIL
────────────────────────────────────────────────────────────────────────
      1  ✅ VALID       N/A    All FVP constraints satisfied
      2  ✅ VALID      0.95s   All FVP constraints satisfied
      3  ✅ VALID      0.95s   All FVP constraints satisfied
      4  ✅ VALID      0.95s   All FVP constraints satisfied
      7  ❌ VIOLATED    N/A    C1_SEQUENCE_JUMP: expected seq=5, received seq=7
      8  ❌ VIOLATED    N/A    C1_SEQUENCE_JUMP: expected seq=5, received seq=8
      9  ❌ VIOLATED    N/A    C1_SEQUENCE_JUMP: expected seq=5, received seq=9
     10  ❌ VIOLATED    N/A    C1_SEQUENCE_JUMP: expected seq=5, received seq=10
════════════════════════════════════════════════════════════════════════
```

The report cleanly separates the pre-attack consumable window (`seq ∈ {1,2,3,4}`) from the post-attack lockout (`seq ∈ {7,8,9,10}`). This is the formal output a bridge protocol would consume to determine which checkpoints it may act upon.

---

## 9. Alignment with PhD Proposal

| Thesis Research Axis | Simulation Demonstration |
|---|---|
| **Formal model of private→public state anchoring** | `PrivateStateMachine` implements S_t, R_t = hash(S_t), π_t = mock-ZKP exactly as described in the formal model |
| **Blind public contract as accumulator** | `PublicAnchorContract.submitCheckpoint()` accepts all submissions unconditionally — the blindness is a design feature, not a bug |
| **Runtime verification of execution** | `RuntimeMonitor` with `FormalVerificationPolicy` evaluates C1/C2/C3 on every event, in real time |
| **State-space constraint modeling** | FVP constraints map directly to reachability predicates in an LTL/CTL temporal logic formulation |
| **Detection of ordering attacks** | `SEQUENCE_JUMP` attack is detected at C1 without any on-chain compute |
| **Consumable state declaration** | `isStateConsumable` boolean, toggled by monitor verdict, models the safe-to-consume signal external bridges need |
| **AI telemetry / stream processing background** | The monitor's event-driven architecture mirrors stream processing systems (Kafka consumers, Flink operators); the FVP is analogous to a streaming constraint policy |

### From Prior Background to Blockchain Research

The thesis candidate's background in **AI telemetry and stream processing** maps naturally:

- Kafka/Flink stream consumers → `poll_new_events()` event subscription pattern
- State-space anomaly detection models → `FormalVerificationPolicy` constraint engine
- Data-drift detection pipelines → sequence-gap and timing-window violation logic
- Operational health monitors → `isStateConsumable` consumability circuit breaker

This project demonstrates that these skills are not analogous to blockchain research — they *are* blockchain research applied to the runtime verification domain.

---

## 10. Extension Roadmap

The following extensions map directly to research chapters in the thesis:

### Chapter 2: Real ZK-Proof Integration
Replace the SHA-256 mock proof with a real Groth16/PLONK ZK circuit (e.g., via `snarkjs` or `gnark`). The public contract verifier can then cryptographically confirm state transition validity, reducing reliance on the off-chain monitor for proof authenticity.

### Chapter 3: Optimistic Challenge Game
Add a `challengeCheckpoint(uint256 seq)` function to the contract. External parties can dispute a checkpoint during a challenge window. This reduces the monitor's role from active blocker to passive evidence provider.

### Chapter 4: Formal Specification in TLA+/Temporal Logic
Express the FVP constraints in TLA+ or LTL and use a model checker (TLC, SPIN) to verify the monitor's correctness properties: *no valid checkpoint is ever blocked* and *no invalid checkpoint is ever declared consumable*.

### Chapter 5: Multi-Monitor Consensus
Deploy N monitors and require a threshold of verdicts before `isStateConsumable` is set — transforming the single-monitor trust assumption into a Byzantine-fault-tolerant committee.

### Chapter 6: Cross-Chain Bridge Integration
Connect a mock bridge contract that reads `isStateConsumable` before releasing locked assets. Demonstrate end-to-end: private chain state change → public checkpoint → monitor verdict → bridge release.

---

## License

MIT — Free for academic use.

---

*Generated as a research demonstration micro-project for the CIFRE PhD vacancy at ISEP / BaaS.sh.*
