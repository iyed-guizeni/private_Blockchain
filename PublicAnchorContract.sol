// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title PublicAnchorContract
 * @author PhD Micro-Project: "Private Blockchains with Public Anchoring"
 *
 * @notice This contract embodies the "Blind Public Domain" in the thesis architecture.
 *         It receives cryptographic checkpoint commitments from a private blockchain
 *         but has NO visibility into the private execution domain. It cannot validate
 *         the semantic correctness of the submitted proofs — it is intentionally "blind".
 *
 * @dev    Design Pattern: Blind Accumulator / Append-Only Commitment Log
 *         The contract records every checkpoint unconditionally. The intelligence
 *         needed to determine whether a checkpoint represents a "consumable" state
 *         lives entirely in the off-chain Runtime Monitor (see simulation.py).
 *
 *         This separation of concerns is central to the thesis:
 *           - On-chain: Immutability, censorship-resistance, public auditability
 *           - Off-chain: Formal verification, semantic constraint checking, policy enforcement
 */
contract PublicAnchorContract {

    // =========================================================================
    // TYPES
    // =========================================================================

    /**
     * @notice Represents a single checkpoint anchored from the private domain.
     * @param stateRoot       The Merkle/hash root of the private chain's state at this point.
     *                        Analogous to the S_t in the formal model.
     * @param sequenceNumber  A monotonically-increasing counter emitted by the private chain.
     *                        The Runtime Monitor uses this to detect ordering attacks.
     * @param proof           A mock Zero-Knowledge Proof (ZKP) commitment. In production,
     *                        this would be a SNARK/STARK proof verifiable on-chain.
     * @param timestamp       Block timestamp at the moment of anchoring (wall-clock signal).
     * @param blockNumber     Block number, used by the monitor for timing-window analysis.
     */
    struct Checkpoint {
        bytes32 stateRoot;
        uint256 sequenceNumber;
        bytes32 proof;
        uint256 timestamp;
        uint256 blockNumber;
    }

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Append-only log of all submitted checkpoints.
    ///         Key: sequenceNumber → Checkpoint data.
    ///         Intentionally allows overwrite to simulate blind acceptance of attacks.
    mapping(uint256 => Checkpoint) public checkpoints;

    /// @notice Ordered list of all sequence numbers received, for enumeration.
    uint256[] public checkpointSequences;

    /// @notice Total count of checkpoints received (not deduplicated).
    uint256 public totalCheckpointsReceived;

    /// @notice The sequence number of the most recently received checkpoint.
    uint256 public latestSequenceNumber;

    /**
     * @notice Whether the current state is "consumable" by external bridges/contracts.
     * @dev    This flag is written by the contract owner (representing the off-chain monitor
     *         publishing its verdict back on-chain). In a production system, this could be
     *         driven by a ZK-verifier or an optimistic challenge game.
     *         In this simulation, it is set externally by the Python Runtime Monitor.
     */
    bool public isStateConsumable;

    /// @notice Address authorized to update the `isStateConsumable` flag.
    address public immutable owner;

    // =========================================================================
    // EVENTS
    // =========================================================================

    /**
     * @notice Emitted unconditionally whenever a checkpoint is submitted.
     * @dev    The Runtime Monitor subscribes to this event via JSON-RPC `eth_subscribe`
     *         to drive its formal verification pipeline in real time.
     *
     * @param stateRoot      Hash root of the private chain state.
     * @param sequenceNumber Sequence counter from the private domain.
     * @param proof          Mock ZKP commitment bytes.
     * @param timestamp      On-chain block timestamp at submission.
     * @param blockNumber    Block number at submission.
     */
    event CheckpointPublished(
        bytes32 indexed stateRoot,
        uint256 indexed sequenceNumber,
        bytes32 proof,
        uint256 timestamp,
        uint256 blockNumber
    );

    /**
     * @notice Emitted when the off-chain monitor updates the consumability verdict.
     * @param isConsumable   New boolean verdict.
     * @param updatedBy      Address that triggered the update.
     * @param atSequence     The latest sequence number at the time of the verdict.
     */
    event ConsumabilityUpdated(
        bool indexed isConsumable,
        address indexed updatedBy,
        uint256 atSequence
    );

    /**
     * @notice Emitted when a duplicate sequence number is submitted (potential replay/attack).
     * @dev    The contract is blind to this being an attack; it still records it.
     *         The Runtime Monitor will catch the semantic violation.
     */
    event DuplicateSequenceDetected(
        uint256 indexed sequenceNumber,
        bytes32 newStateRoot,
        bytes32 previousStateRoot
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    /// @dev Thrown when a non-owner calls a privileged function.
    error NotOwner(address caller);

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    /**
     * @notice Initializes the contract, setting the deployer as the trusted owner.
     * @dev    The owner represents the off-chain Runtime Monitor's publishing key.
     *         In a production ZK-based system, this would be replaced by a verifier contract.
     */
    constructor() {
        owner = msg.sender;
        isStateConsumable = false;
    }

    // =========================================================================
    // CORE FUNCTIONS
    // =========================================================================

    /**
     * @notice Submits a checkpoint commitment from the private blockchain domain.
     *
     * @dev    INTENTIONALLY BLIND: This function performs NO semantic validation.
     *         It does not check:
     *           - Whether sequenceNumber is monotonically increasing.
     *           - Whether the proof is cryptographically valid.
     *           - Whether the stateRoot is consistent with prior state.
     *
     *         This blindness is a core thesis design point: it demonstrates that
     *         on-chain contracts cannot be the sole guardians of private chain integrity.
     *         The Runtime Monitor must serve as the off-chain formal verifier.
     *
     * @param stateRoot       Merkle root hash of the private chain's state.
     * @param sequenceNumber  Sequence number claimed by the private chain.
     * @param proof           Mock ZKP proof bytes (SHA-256 hash in simulation).
     */
    function submitCheckpoint(
        bytes32 stateRoot,
        uint256 sequenceNumber,
        bytes32 proof
    ) external {
        // --- Duplicate sequence detection (informational only, not enforced) ---
        if (checkpoints[sequenceNumber].timestamp != 0) {
            emit DuplicateSequenceDetected(
                sequenceNumber,
                stateRoot,
                checkpoints[sequenceNumber].stateRoot
            );
        }

        // --- Record the checkpoint unconditionally ---
        Checkpoint memory cp = Checkpoint({
            stateRoot: stateRoot,
            sequenceNumber: sequenceNumber,
            proof: proof,
            timestamp: block.timestamp,
            blockNumber: block.number
        });

        checkpoints[sequenceNumber] = cp;
        checkpointSequences.push(sequenceNumber);
        totalCheckpointsReceived++;
        latestSequenceNumber = sequenceNumber;

        // --- Emit the public signal for off-chain monitors ---
        emit CheckpointPublished(
            stateRoot,
            sequenceNumber,
            proof,
            block.timestamp,
            block.number
        );
    }

    /**
     * @notice Allows the authorized Runtime Monitor to publish its formal verdict
     *         on-chain, updating the consumability flag.
     *
     * @dev    This closes the loop: the monitor's off-chain analysis re-enters the
     *         public domain as an on-chain fact, enabling bridges and DeFi protocols
     *         to safely consume the private chain's state.
     *
     * @param verdict  True if the current state is formally verified as safe to consume.
     */
    function setConsumability(bool verdict) external {
        if (msg.sender != owner) revert NotOwner(msg.sender);

        isStateConsumable = verdict;

        emit ConsumabilityUpdated(verdict, msg.sender, latestSequenceNumber);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Returns the full Checkpoint struct for a given sequence number.
     * @param sequenceNumber  The sequence number to look up.
     * @return cp             The stored Checkpoint data.
     */
    function getCheckpoint(uint256 sequenceNumber)
        external
        view
        returns (Checkpoint memory cp)
    {
        return checkpoints[sequenceNumber];
    }

    /**
     * @notice Returns all sequence numbers ever submitted, in insertion order.
     * @return sequences  Array of all sequence numbers.
     */
    function getAllSequenceNumbers()
        external
        view
        returns (uint256[] memory sequences)
    {
        return checkpointSequences;
    }

    /**
     * @notice Returns the total number of checkpoints received.
     * @return count  Total count (may include duplicates if replayed).
     */
    function getCheckpointCount() external view returns (uint256 count) {
        return totalCheckpointsReceived;
    }
}
