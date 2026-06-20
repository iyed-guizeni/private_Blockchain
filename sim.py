
import asyncio
import hashlib
import json
import logging
import random
import sys
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from colorama import Fore, Style, init as colorama_init
from eth_tester import EthereumTester, PyEVMBackend
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware


# LOGGING

colorama_init(autoreset=True)


class LayerFormatter(logging.Formatter):
 
    LAYER_COLORS = {
        "PRIVATE": Fore.CYAN,
        "PUBLIC":  Fore.YELLOW,
        "MONITOR": Fore.GREEN,
        "ATTACK":  Fore.RED,
        "VERDICT": Fore.MAGENTA,
        "SYSTEM":  Fore.WHITE,
    }
    LEVEL_COLORS = {
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()

        # Pick color based on which layer tag appears in the message
        color = Style.RESET_ALL
        for tag, c in self.LAYER_COLORS.items():
            if f"[{tag}]" in msg:
                color = c
                break

        level_color = self.LEVEL_COLORS.get(record.levelno, "")
        ts = self.formatTime(record, "%H:%M:%S")
        return f"{color}{ts} {level_color}{msg}{Style.RESET_ALL}"


def make_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(LayerFormatter())
        logger.addHandler(h)
    return logger


log = make_logger("simulation")



# CONFIGURATION


# Seconds between each simulated private-chain transition
STEP_INTERVAL: float = 0.8

# Formal Verification Policy timing bounds (seconds)
FVP_MIN_INTERVAL: float = 0.1
FVP_MAX_INTERVAL: float = 10.0

# How many clean checkpoints to run before triggering the attack
NORMAL_STEPS: int = 4

# How many checkpoints to run after the attack (to show persistent lockout)
POST_ATTACK_STEPS: int = 3


# CONTRACT ARTIFACTS

CONTRACT_ABI = json.loads(
    '[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},'
    '{"inputs":[{"internalType":"address","name":"caller","type":"address"}],"name":"NotOwner","type":"error"},'
    '{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"stateRoot","type":"bytes32"},'
    '{"indexed":true,"internalType":"uint256","name":"sequenceNumber","type":"uint256"},'
    '{"indexed":false,"internalType":"bytes32","name":"proof","type":"bytes32"},'
    '{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"},'
    '{"indexed":false,"internalType":"uint256","name":"blockNumber","type":"uint256"}],'
    '"name":"CheckpointPublished","type":"event"},'
    '{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bool","name":"isConsumable","type":"bool"},'
    '{"indexed":true,"internalType":"address","name":"updatedBy","type":"address"},'
    '{"indexed":false,"internalType":"uint256","name":"atSequence","type":"uint256"}],'
    '"name":"ConsumabilityUpdated","type":"event"},'
    '{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"sequenceNumber","type":"uint256"},'
    '{"indexed":false,"internalType":"bytes32","name":"newStateRoot","type":"bytes32"},'
    '{"indexed":false,"internalType":"bytes32","name":"previousStateRoot","type":"bytes32"}],'
    '"name":"DuplicateSequenceDetected","type":"event"},'
    '{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"checkpointSequences",'
    '"outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},'
    '{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"checkpoints",'
    '"outputs":[{"internalType":"bytes32","name":"stateRoot","type":"bytes32"},'
    '{"internalType":"uint256","name":"sequenceNumber","type":"uint256"},'
    '{"internalType":"bytes32","name":"proof","type":"bytes32"},'
    '{"internalType":"uint256","name":"timestamp","type":"uint256"},'
    '{"internalType":"uint256","name":"blockNumber","type":"uint256"}],"stateMutability":"view","type":"function"},'
    '{"inputs":[],"name":"getAllSequenceNumbers","outputs":[{"internalType":"uint256[]","name":"sequences","type":"uint256[]"}],'
    '"stateMutability":"view","type":"function"},'
    '{"inputs":[{"internalType":"uint256","name":"sequenceNumber","type":"uint256"}],"name":"getCheckpoint",'
    '"outputs":[{"components":[{"internalType":"bytes32","name":"stateRoot","type":"bytes32"},'
    '{"internalType":"uint256","name":"sequenceNumber","type":"uint256"},'
    '{"internalType":"bytes32","name":"proof","type":"bytes32"},'
    '{"internalType":"uint256","name":"timestamp","type":"uint256"},'
    '{"internalType":"uint256","name":"blockNumber","type":"uint256"}],'
    '"internalType":"struct PublicAnchorContract.Checkpoint","name":"cp","type":"tuple"}],'
    '"stateMutability":"view","type":"function"},'
    '{"inputs":[],"name":"getCheckpointCount","outputs":[{"internalType":"uint256","name":"count","type":"uint256"}],'
    '"stateMutability":"view","type":"function"},'
    '{"inputs":[],"name":"isStateConsumable","outputs":[{"internalType":"bool","name":"","type":"bool"}],'
    '"stateMutability":"view","type":"function"},'
    '{"inputs":[],"name":"latestSequenceNumber","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],'
    '"stateMutability":"view","type":"function"},'
    '{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],'
    '"stateMutability":"view","type":"function"},'
    '{"inputs":[{"internalType":"bool","name":"verdict","type":"bool"}],"name":"setConsumability",'
    '"outputs":[],"stateMutability":"nonpayable","type":"function"},'
    '{"inputs":[{"internalType":"bytes32","name":"stateRoot","type":"bytes32"},'
    '{"internalType":"uint256","name":"sequenceNumber","type":"uint256"},'
    '{"internalType":"bytes32","name":"proof","type":"bytes32"}],"name":"submitCheckpoint",'
    '"outputs":[],"stateMutability":"nonpayable","type":"function"},'
    '{"inputs":[],"name":"totalCheckpointsReceived","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],'
    '"stateMutability":"view","type":"function"}]'
)

CONTRACT_BYTECODE = (
    "0x60a0604052348015600e575f5ffd5b50336080526004805460ff191690556080516106"
    "1561003c5f395f818161014e01526102de01526106155ff3fe608060405234801561000f"
    "575f5ffd5b50600436106100a6575f3560e01c80639d26f1141161006e5780639d26f114"
    "14610188578063ac2a324e1461019d578063b5d33b13146101a6578063b8a24252146101"
    "b9578063d99563df1461021d578063f1c0461614610232575f5ffd5b806320fc4881146100"
    "aa57806324b4123f146101075780633ad30290146101195780634e2bda37146101365780"
    "638da5cb5b14610149575b5f5ffd5b6100bd6100b8366004610513565b61023b565b6040"
    "516100fe91905f60a082019050825182526020830151602083015260408301516040830152"
    "606083015160608301526080830151608083015292915050565b60405180910390f35b6002"
    "545b6040519081526020016100fe565b6004546101269060ff1681565b604051901515815260"
    "20016100fe565b61010b610144366004610513565b6102b4565b6101707f00000000000000"
    "0000000000000000000000000000000000000000000000000081565b6040516001600160a0"
    "1b0390911681526020016100fe565b61019b61019636600461052a565b6102d3565b005b61"
    "010b60025481565b61019b6101b4366004610550565b61036f565b6101f56101c736600461"
    "0513565b5f60208190529081526040902080546001820154600283015460038401546004909"
    "401549293919290919085565b604080519586526020860194909452928401919091526060830"
    "152608082015260a0016100fe565b6102256104bd565b6040516100fe9190610579565b6101"
    "0b60035481565b6102686040518060a001604052805f81526020015f81526020015f8152602"
    "0015f81526020015f81525090565b505f9081526020818152604091829020825160a081018452"
    "8154815260018201549281019290925260028101549282019290925260038201546060820152"
    "600490910154608082015290565b600181815481106102c3575f80fd5b5f91825260209091200"
    "154905081565b336001600160a01b037f000000000000000000000000000000000000000000000"
    "00000000000000000001614610322576040516324 5aecd360e01b815233600482015260240160"
    "405180910390fd5b6004805460ff19168215159081179091556003546040519081523391907f20"
    "3300ccae60d2ea02a06db041f5b266945145939c77f10e11d8e1663026e2fd9060200160405180"
    "910390a350565b5f82815260208190526040902060030154156103cc575f828152602081815260"
    "40918290205482518681529182015283917f70b616e6c5bfaa0e539fb28bba0d11e8cb7a986708"
    "bc334f0c7cebd38584bffa910160405180910390a25b6040805160a0810182528481526020808201"
    "858152828401858152426060850190815243608086019081525f898152948590529584208551815592"
    "516001808501919091559151600280850191909155905160038401559451600490920191909155805480"
    "820182559082527fb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6018"
    "59055825491929061046b836105bb565b909155505060038390556040805183815242602082015243818"
    "301529051849186917f1516c452f9269970471139d6556d0f454a8c4e3305847699d2e4232f87222892"
    "9181900360600190a350505050565b6060600180548060200260200160405190810160405280929190818"
    "152602001828054801561050957602002820191905f5260205f20905b81548152602001906001019080831"
    "16104f5575b5050505050905090565b5f60208284031215610523575f5ffd5b5035919050565b5f60208284"
    "03121561053a575f5ffd5b81358015158114610549575f5ffd5b9392505050565b5f5f5f6060848603121561"
    "0562575f5ffd5b505081359360208301359350604090920135919050565b602080825282518282018190525f9"
    "18401906040840190835b818110156105b0578351835260209384019390920191600101610592565b509095945"
    "050505050565b5f600182016105d857634e487b7160e01b5f52601160045260245ffd5b506001019056fea26469"
    "70667358221220c7d02a3621620567f10ba32bcbed856aec753a3e8e59cb9ffb422389fe63cb9a64736f6c634300"
    "08230033"
).replace(" ", "")


# DATA MODELS

class AttackType(Enum):
    """
    The three adversarial strategies the private chain can inject.
    All of them produce cryptographically valid-looking hashes, which is why
    the blind contract cannot detect them and a semantic monitor is required.
    """
    SEQUENCE_JUMP    = auto()  # Skip N sequence numbers in one submission
    SEQUENCE_REPLAY  = auto()  # Re-submit a previously anchored sequence number
    STALE_STATE_ROOT = auto()  # Pair a new sequence number with an old state root


@dataclass
class CommitmentPacket:
    """
    The artifact that crosses the boundary from private domain to public domain.

    Only (state_root, sequence_number, proof) are published on-chain.
    The remaining fields stay local and are used for simulation bookkeeping.
    """
    state_root:      bytes
    sequence_number: int
    proof:           bytes
    private_state:   int           # The actual S_t value (never leaves private domain)
    wall_time:       float         # Local time of generation
    is_malicious:    bool
    attack_type:     Optional[AttackType] = None


@dataclass
class MonitorVerdict:
    """
    The result produced by the Runtime Monitor after evaluating one event.
    """
    sequence_number:  int
    is_valid:         bool
    is_consumable:    bool
    violation_reason: Optional[str]
    timing_delta_sec: Optional[float]
    expected_seq:     int


# LAYER 1 - PRIVATE STATE MACHINE

class PrivateStateMachine:
    def __init__(
        self,
        initial_state: int = 1000,
        secret_key: bytes = b"thesis_secret_v1",
    ):
        self._state         = initial_state
        self._sequence      = 0
        self._secret_key    = secret_key
        self._nonce         = 0
        self._attack_armed  = False
        self._attack_type: Optional[AttackType] = None
        self._jump_magnitude = 1
        self._history: list[CommitmentPacket] = []

        log.info(f"[PRIVATE] State machine initialized -- S_0 = {initial_state}")

    # -- Cryptographic primitives ---------------------------------------------

    def _state_root(self, state: int, seq: int) -> bytes:
        self._nonce += 1
        return hashlib.sha256(f"{state}:{seq}:{self._nonce}".encode()).digest()

    def _mock_proof(self, state_root: bytes, seq: int) -> bytes:
        return hashlib.sha256(
            state_root + str(seq).encode() + self._secret_key
        ).digest()

    def _transition(self) -> int:
        """Apply S_{t+1} = S_t + delta and return delta."""
        delta = random.randint(1, 20)
        self._state += delta
        return delta

    # -- Normal operation 

    def emit_checkpoint(self) -> CommitmentPacket:
        """
        Produce the next CommitmentPacket.

        If an attack has been armed via trigger_state_manipulation_attack(),
        this call produces a malicious packet and disarms the attack flag.
        """
        if self._attack_armed:
            return self._emit_malicious_checkpoint()

        delta = self._transition()
        self._sequence += 1
        root  = self._state_root(self._state, self._sequence)
        proof = self._mock_proof(root, self._sequence)

        packet = CommitmentPacket(
            state_root      = root,
            sequence_number = self._sequence,
            proof           = proof,
            private_state   = self._state,
            wall_time       = time.time(),
            is_malicious    = False,
        )
        self._history.append(packet)

        log.info(
            f"[PRIVATE] checkpoint emitted"
            f" | seq = {self._sequence:>3}"
            f" | S_t = {self._state:>7}"
            f" | delta = {delta:>3}"
            f" | root = {root.hex()[:12]}..."
        )
        return packet

    # -- Attack injection 

    def trigger_state_manipulation_attack(
        self,
        attack_type: AttackType = AttackType.SEQUENCE_JUMP,
        jump_magnitude: int = 3,
    ) -> None:
        
        self._attack_armed    = True
        self._attack_type     = attack_type
        self._jump_magnitude  = jump_magnitude

        log.warning(
            f"[ATTACK] attack armed"
            f" | type = {attack_type.name}"
            f" | current seq = {self._sequence}"
        )

    def _emit_malicious_checkpoint(self) -> CommitmentPacket:
        """Build and return the adversarial CommitmentPacket."""

        if self._attack_type == AttackType.SEQUENCE_JUMP:
            self._transition()
            self._sequence += self._jump_magnitude  # e.g. 4 -> 7
            root  = self._state_root(self._state, self._sequence)
            proof = self._mock_proof(root, self._sequence)
            packet = CommitmentPacket(
                state_root=root, sequence_number=self._sequence, proof=proof,
                private_state=self._state, wall_time=time.time(),
                is_malicious=True, attack_type=AttackType.SEQUENCE_JUMP,
            )
            log.warning(
                f"[ATTACK] SEQUENCE_JUMP packet built"
                f" | seq = {self._sequence}"
                f" | jumped +{self._jump_magnitude}"
                f" | {self._jump_magnitude - 1} seq numbers skipped"
                f" | root = {root.hex()[:12]}... (hash is valid, contract will accept)"
            )

        elif self._attack_type == AttackType.SEQUENCE_REPLAY:
            if not self._history:
                # No history yet; fall back to sequence jump
                self._attack_type = AttackType.SEQUENCE_JUMP
                return self._emit_malicious_checkpoint()

            previous = self._history[-1]
            fake_state = previous.private_state + 9999
            root  = self._state_root(fake_state, previous.sequence_number)
            proof = self._mock_proof(root, previous.sequence_number)
            packet = CommitmentPacket(
                state_root=root, sequence_number=previous.sequence_number,
                proof=proof, private_state=fake_state, wall_time=time.time(),
                is_malicious=True, attack_type=AttackType.SEQUENCE_REPLAY,
            )
            log.warning(
                f"[ATTACK] SEQUENCE_REPLAY packet built"
                f" | seq = {previous.sequence_number} (already published)"
                f" | new root = {root.hex()[:12]}..."
            )

        else:  # STALE_STATE_ROOT
            self._sequence += 1
            stale_root = self._history[0].state_root if self._history else bytes(32)
            proof = self._mock_proof(stale_root, self._sequence)
            packet = CommitmentPacket(
                state_root=stale_root, sequence_number=self._sequence,
                proof=proof, private_state=self._state, wall_time=time.time(),
                is_malicious=True, attack_type=AttackType.STALE_STATE_ROOT,
            )
            log.warning(
                f"[ATTACK] STALE_STATE_ROOT packet built"
                f" | seq = {self._sequence}"
                f" | reusing root from history[0]"
            )

        self._history.append(packet)
        self._attack_armed = False  # single-shot
        return packet

    @property
    def current_sequence(self) -> int:
        return self._sequence

    @property
    def history(self) -> list[CommitmentPacket]:
        return list(self._history)


# LAYER 2 - PUBLIC CHAIN INTERFACE

class PublicChainInterface:
   

    def __init__(self):
        self.w3: Optional[Web3] = None
        self.contract = None
        self.deployer: str = ""
        self._event_filter = None

    def connect_and_deploy(self) -> str:
        """
        Start the in-process EVM, deploy PublicAnchorContract, and return
        the deployed contract address.
        """
        log.info("[SYSTEM] starting in-process EVM (eth-tester / PyEVM)")

        tester   = EthereumTester(PyEVMBackend())
        self.w3  = Web3(Web3.EthereumTesterProvider(tester))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        if not self.w3.is_connected():
            raise RuntimeError("Could not connect to EVM backend")

        self.deployer = self.w3.eth.accounts[0]
        balance = self.w3.from_wei(self.w3.eth.get_balance(self.deployer), "ether")
        log.info(
            f"[SYSTEM] EVM ready"
            f" | deployer = {self.deployer[:14]}..."
            f" | balance = {balance:.0f} ETH"
        )

        log.info("[PUBLIC] deploying PublicAnchorContract")
        factory  = self.w3.eth.contract(abi=CONTRACT_ABI, bytecode=CONTRACT_BYTECODE)
        tx_hash  = factory.constructor().transact({"from": self.deployer, "gas": 3_000_000})
        receipt  = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        address  = receipt.contractAddress

        self.contract = self.w3.eth.contract(address=address, abi=CONTRACT_ABI)
        log.info(
            f"[PUBLIC] contract deployed"
            f" | address = {address}"
            f" | block = {receipt.blockNumber}"
            f" | gas used = {receipt.gasUsed}"
        )

        self._event_filter = self.contract.events.CheckpointPublished.create_filter(
            from_block="latest"
        )
        return address

    def submit_checkpoint(self, packet: CommitmentPacket) -> None:
        """
        Call submitCheckpoint() on the deployed contract.

        The contract performs no semantic validation.  A malicious packet is
        accepted and mined just as readily as an honest one.
        """
        root_b32  = (packet.state_root + bytes(32))[:32]
        proof_b32 = (packet.proof      + bytes(32))[:32]

        tx_hash = self.contract.functions.submitCheckpoint(
            root_b32,
            packet.sequence_number,
            proof_b32,
        ).transact({"from": self.deployer, "gas": 300_000})

        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        note = "(MALICIOUS -- accepted blindly by contract)" if packet.is_malicious else ""
        log.info(
            f"[PUBLIC] submitCheckpoint mined"
            f" | seq = {packet.sequence_number}"
            f" | block = {receipt.blockNumber}"
            f" {note}"
        )

    def set_consumability(self, verdict: bool) -> None:
        """
        Publish the Runtime Monitor's verdict back on-chain.
        This closes the off-chain -> on-chain trust loop.
        """
        self.contract.functions.setConsumability(verdict).transact(
            {"from": self.deployer, "gas": 100_000}
        )

    def poll_events(self) -> list:
        """Return new CheckpointPublished events since the last call."""
        return self._event_filter.get_new_entries()

    def chain_state(self) -> dict:
        """Read the current on-chain summary from the contract."""
        return {
            "total_checkpoints":   self.contract.functions.totalCheckpointsReceived().call(),
            "latest_sequence":     self.contract.functions.latestSequenceNumber().call(),
            "is_state_consumable": self.contract.functions.isStateConsumable().call(),
        }


# LAYER 3 - RUNTIME MONITOR

@dataclass
class FormalVerificationPolicy:
    
    min_interval: float = FVP_MIN_INTERVAL
    max_interval: float = FVP_MAX_INTERVAL
    seen_roots:   set   = field(default_factory=set)


class RuntimeMonitor:
    

    def __init__(self, chain: PublicChainInterface, policy: FormalVerificationPolicy):
        self._chain                              = chain
        self._policy                             = policy
        self._prev_sequence: Optional[int]       = None
        self._prev_arrival:  Optional[float]     = None
        self._verdicts: list[MonitorVerdict]     = []
        self._violation_count                    = 0
        self._consumable_sequences: list[int]    = []

        log.info(
            f"[MONITOR] runtime monitor ready"
            f" | C1 (seq monotonicity)"
            f" | C2 (interval {policy.min_interval}s - {policy.max_interval}s)"
            f" | C3 (root uniqueness)"
        )

    def evaluate(self, event: dict) -> MonitorVerdict:
        
        seq          = event["args"]["sequenceNumber"]
        state_root   = event["args"]["stateRoot"]
        arrival_time = time.time()

        expected_seq = (self._prev_sequence + 1) if self._prev_sequence is not None else 1
        violation    = None
        is_valid     = True

        # -- C1: sequence monotonicity ----------------------------------------
        if self._prev_sequence is not None and seq != expected_seq:
            is_valid = False
            gap = seq - self._prev_sequence
            if gap > 1:
                violation = (
                    f"C1_SEQUENCE_JUMP"
                    f" -- expected seq {expected_seq}, received seq {seq}"
                    f" (gap {gap}, {gap - 1} sequence numbers missing)"
                )
            elif gap == 0:
                violation = (
                    f"C1_SEQUENCE_REPLAY"
                    f" -- seq {seq} was already anchored"
                    f" (prev_seq = {self._prev_sequence})"
                )
            else:
                violation = (
                    f"C1_SEQUENCE_REGRESSION"
                    f" -- seq {seq} is less than prev_seq {self._prev_sequence}"
                )

        # -- C2: timing window ------------------------------------------------
        timing_delta = None
        if is_valid and self._prev_arrival is not None:
            timing_delta = arrival_time - self._prev_arrival
            if timing_delta < self._policy.min_interval:
                is_valid  = False
                violation = (
                    f"C2_FLOOD_ATTACK"
                    f" -- interval {timing_delta:.3f}s"
                    f" is below minimum {self._policy.min_interval}s"
                )
            elif timing_delta > self._policy.max_interval:
                log.warning(
                    f"[MONITOR] C2_LIVENESS_WARNING"
                    f" -- checkpoint arrived {timing_delta:.2f}s after previous"
                    f" (max = {self._policy.max_interval}s)"
                )

        # -- C3: state root uniqueness ----------------------------------------
        root_hex = (
            state_root.hex()
            if isinstance(state_root, (bytes, bytearray))
            else str(state_root)
        )
        if is_valid and root_hex in self._policy.seen_roots:
            is_valid  = False
            violation = (
                f"C3_STALE_STATE_ROOT"
                f" -- root {root_hex[:16]}... was previously anchored"
            )

        # -- Build verdict and publish -----------------------------------------
        verdict = MonitorVerdict(
            sequence_number  = seq,
            is_valid         = is_valid,
            is_consumable    = is_valid,
            violation_reason = violation,
            timing_delta_sec = timing_delta,
            expected_seq     = expected_seq,
        )
        self._verdicts.append(verdict)

        if is_valid:
            self._prev_sequence = seq
            self._prev_arrival  = arrival_time
            self._policy.seen_roots.add(root_hex)
            self._consumable_sequences.append(seq)
            delta_str = f"{timing_delta:.2f}s" if timing_delta else "first checkpoint"

            log.info(
                f"[MONITOR] PASS | seq = {seq:>3} | dt = {delta_str} | C1 C2 C3 all satisfied"
            )
            log.info(
                f"[VERDICT] CONSUMABLE"
                f" | seq {seq} is a Public Consumable Fact"
                f" | bridges may safely act on this state"
            )
            self._chain.set_consumability(True)

        else:
            self._violation_count += 1
            log.error(f"[MONITOR] FAIL | seq = {seq:>3} | {violation}")
            log.error(
                f"[VERDICT] BLOCKED"
                f" | seq {seq} violates the Formal Verification Policy"
                f" | bridge consumption prevented"
            )
            self._chain.set_consumability(False)

        return verdict

    def print_summary(self) -> None:
        """Print the final verification report after the simulation ends."""
        total   = len(self._verdicts)
        passed  = sum(1 for v in self._verdicts if v.is_valid)
        failed  = total - passed

        sep = "-" * 74
        print()
        print(sep)
        print("  RUNTIME MONITOR -- FINAL VERIFICATION REPORT")
        print(sep)
        print(f"  Checkpoints evaluated    : {total}")
        print(f"  Passed (consumable)      : {passed}")
        print(f"  Failed (violations)      : {failed}")
        print(f"  Consumable sequences     : {self._consumable_sequences}")
        print(sep)
        print(f"  {'SEQ':>5}  {'RESULT':<10}  {'INTERVAL':>10}  DETAIL")
        print(sep)
        for v in self._verdicts:
            result   = "PASS" if v.is_valid else "FAIL"
            interval = f"{v.timing_delta_sec:.2f}s" if v.timing_delta_sec else "N/A"
            detail   = v.violation_reason or "all constraints satisfied"
            print(f"  {v.sequence_number:>5}  {result:<10}  {interval:>10}  {detail}")
        print(sep)
        print()


# ORCHESTRATOR

async def run_simulation() -> None:
   
    print()
    print("=" * 72)
    print("  PRIVATE BLOCKCHAIN WITH PUBLIC ANCHORING -- SIMULATION")
    print("  Thesis: Formal Model and Runtime Verification")
    print("  ISEP / BaaS.sh CIFRE Preparation")
    print("=" * 72)
    print()

    # Initialize all three layers
    psm     = PrivateStateMachine(initial_state=1000)
    chain   = PublicChainInterface()
    monitor = RuntimeMonitor(chain=chain, policy=FormalVerificationPolicy())

    address = chain.connect_and_deploy()
    print(f"\n  PublicAnchorContract deployed at {address}\n")

    total_steps      = NORMAL_STEPS + 1 + POST_ATTACK_STEPS
    attack_triggered = False

    for step in range(1, total_steps + 1):
        print(f"\n  -- step {step}/{total_steps} " + "-" * 50)

        # Arm the attack on the step immediately after the clean phase
        if step == NORMAL_STEPS + 1 and not attack_triggered:
            print()
            print("  [!] ATTACK INJECTION")
            print("      Type           : SEQUENCE_JUMP")
            print("      Jump magnitude : 3  (seq 4 -> seq 7, skipping 5 and 6)")
            print("      The blind contract will accept this packet.")
            print("      The Runtime Monitor will detect the sequence gap.")
            print()
            psm.trigger_state_manipulation_attack(
                attack_type    = AttackType.SEQUENCE_JUMP,
                jump_magnitude = 3,
            )
            attack_triggered = True

        # Step 1: private domain generates a commitment packet
        packet = psm.emit_checkpoint()
        await asyncio.sleep(0.02)

        # Step 2: public contract receives it blindly
        chain.submit_checkpoint(packet)
        await asyncio.sleep(0.05)  # give eth-tester time to register the event

        # Step 3: monitor evaluates the published event
        for event in chain.poll_events():
            monitor.evaluate(event)

        # Snapshot the on-chain state for reference
        state = chain.chain_state()
        log.info(
            f"[SYSTEM] on-chain snapshot"
            f" | total checkpoints = {state['total_checkpoints']}"
            f" | latest seq = {state['latest_sequence']}"
            f" | consumable = {state['is_state_consumable']}"
        )

        await asyncio.sleep(STEP_INTERVAL)

    monitor.print_summary()

    print("=" * 72)
    print("  SIMULATION COMPLETE")
    print("=" * 72)
    print()
    
if __name__ == "__main__":
    asyncio.run(run_simulation())