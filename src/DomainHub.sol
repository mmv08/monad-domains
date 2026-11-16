// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {BitMaps} from "@openzeppelin/contracts/utils/structs/BitMaps.sol";
import {IDomainHub, IDomainMessageReceiver} from "./interfaces/IDomain.sol";
import {MessageLib} from "./libraries/MessageLib.sol";
import {InputQueue} from "./libraries/InputQueue.sol";

contract DomainHub is IDomainHub, EIP712 {
    using BitMaps for BitMaps.BitMap;

    error L1ChainIdNotAllowed();
    error DomainAlreadyRegistered();
    error ZeroQuorum();
    error QuorumExceedsValidators();
    error ZeroFeeRecipient();
    error ZeroCheckpointInterval();
    error InvalidMaxUnattestedPeriods();
    error InvalidViewingKey();
    error ZeroValidator();
    error DuplicateValidator();
    error DomainNotRegistered();
    error StaleBlockNumber();
    error BlockNumberNotInPast();
    error BlockNumberOffSchedule();
    error NotValidator();
    error AlreadyVoted();
    error SameDomain();
    error SourceNotRegistered();
    error ZeroTarget();
    error MessageAlreadyRelayed();
    error UnknownAnchor();
    error InvalidProof();
    error DestinationNotRegistered();
    error UnexpectedL1CallbackFee();
    error RetryOnDestinationDomain();
    error NotFailedMessage();
    error RetryFailed();
    error DomainBlockGasLimitExceeded();
    error DomainBlockSizeLimitExceeded();
    error FeeTransferFailed();
    error DeliveryFeeTooLow();
    error SequencingFeeTooLow();
    error SlotNumberProbeNotDeployed();

    /// @notice EIP-712 type of the digest a validator signs to approve a state transition.
    bytes32 public constant STATE_TRANSITION_TYPEHASH = keccak256(
        "StateTransition(uint64 domainChainId,uint256 stateNonce,uint64 domainBlockNumber,bytes32 newStateRoot,bytes32 domainAnchor)"
    );
    /// @notice Length of an X25519 public key: the only accepted viewing key encoding.
    uint256 public constant VIEWING_KEY_LENGTH = 32;
    /// @notice Price of one unit of domain gas, in wei; mirrored by the execution client.
    uint256 public constant DOMAIN_GAS_PRICE = 50 gwei;
    /// @notice Gas every sequenced transaction must buy: a transaction's intrinsic gas.
    uint256 public constant SEQUENCING_BASE_GAS = 21_000;
    /// @notice Gas a sequenced transaction must buy per payload byte: the calldata floor
    /// (EIP-7623) of a zero byte.
    uint256 public constant SEQUENCING_GAS_PER_BYTE = 10;
    /// @notice Gas a delivery needs beyond its payload to run or be recorded as failed: the
    /// system transaction's intrinsic gas, the spoke's own work and its reserve.
    uint256 public constant DELIVERY_BASE_GAS = 200_000;
    /// @notice Gas a delivery needs per payload byte: the calldata floor (EIP-7623) and the
    /// spoke's copies.
    uint256 public constant DELIVERY_GAS_PER_BYTE = 48;
    /// @notice Most gas each domain may sell per L1 block, across sequencing and messages.
    uint256 public constant DOMAIN_BLOCK_GAS_LIMIT = 150_000_000;
    /// @notice Most input queue words each domain's inputs may take per L1 block: a tenth of
    /// the queue, about 0.4 MB.
    uint256 public constant DOMAIN_BLOCK_WORD_LIMIT = InputQueue.CAPACITY / 10;
    /// @notice Contract that returns the L1 block's slot number (EIP-7843), or fails on an L1
    /// revision without one.
    address public immutable SLOT_NUMBER_PROBE;

    /// @dev The rest of a domain's registration and its per-input state live in the first
    /// page of its input queue. A vote reads and writes the first two words of this struct and
    /// a quorum also the third. Consecutive slots almost always share a MIP-8 storage page, so
    /// a vote loads one page here.
    struct DomainConfig {
        /// @dev Attested block numbers must be multiples of this interval. Also kept in the
        /// queue's config word; this copy spares a vote from loading the queue's page.
        uint64 checkpointInterval;
        /// @dev Monotonic transition counter bound into every digest, so a round's signatures
        /// cannot be replayed against a later transition.
        uint64 stateNonce;
        /// @dev L1 block number of the latest attested state root; strictly increasing.
        uint64 domainBlockNumber;
        /// @dev Distinct validator signatures required to advance the state.
        uint32 quorum;
        /// @dev Votes for `leadingProposal` in the current round; zero before the round's first
        /// vote.
        uint32 leadingVotes;
        /// @dev Digest of the first proposal voted for in the current round. Other proposals
        /// of the round are counted in `_otherVotes`.
        bytes32 leadingProposal;
        bytes32 stateRoot;
        address[] validators;
        /// @dev X25519 public key senders encrypt domain transactions to, or empty.
        bytes viewingKey;
        mapping(address => Voter) voters;
    }

    struct Voter {
        bool isValidator;
        /// @dev The last leading proposal it voted for. A digest binds the state nonce, so one
        /// from an earlier round never matches a proposal of the current round.
        bytes32 leadingVote;
    }

    /// @dev Registration of each domain, by chain id.
    mapping(uint64 => DomainConfig) internal _configs;
    /// @notice Attested batch roots of domain-origin messages, by source domain.
    mapping(uint64 => mapping(bytes32 => bool)) public domainAnchors;
    /// @dev Source nonces of the domain-origin messages already relayed, by source domain. A
    /// spoke gives each of its messages its own nonce, so one slot covers 256 messages.
    mapping(uint64 => BitMaps.BitMap) internal _relayed;
    /// @notice L1 callbacks that failed and await a successful retry, by source domain.
    mapping(uint64 => mapping(bytes32 => bool)) public failedDomainMessages;
    /// @dev Votes for proposals other than their round's leading one, by digest.
    mapping(bytes32 => uint256) internal _otherVotes;
    /// @dev Whether a validator voted for a proposal other than its round's leading one.
    mapping(bytes32 => mapping(address => bool)) internal _otherVoters;

    constructor() EIP712("MonadDomainHub", "1") {
        // Runtime `SLOTNUM PUSH0 MSTORE PUSH1 32 PUSH0 RETURN` behind the init code that
        // returns it: Solidity has no builtin for the opcode.
        bytes memory initCode = hex"664b5f5260205ff35f5260076019f3";
        address probe;
        assembly ("memory-safe") {
            probe := create(0, add(initCode, 32), mload(initCode))
        }
        if (probe == address(0)) revert SlotNumberProbeNotDeployed();
        SLOT_NUMBER_PROBE = probe;
    }

    // ---------------------------------------------------------------------
    // Registration
    // ---------------------------------------------------------------------

    function registerDomain(
        uint64 domainChainId,
        address[] calldata validators,
        uint256 quorum,
        address feeRecipient,
        bytes calldata viewingKey,
        uint64 checkpointInterval,
        uint8 maxUnattestedPeriods
    ) external {
        if (domainChainId == block.chainid) revert L1ChainIdNotAllowed();
        uint256 queue = InputQueue.base(domainChainId);
        if (InputQueue.load(queue, InputQueue.CONFIG) != 0) revert DomainAlreadyRegistered();
        if (quorum == 0) revert ZeroQuorum();
        if (quorum > validators.length) revert QuorumExceedsValidators();
        if (feeRecipient == address(0)) revert ZeroFeeRecipient();
        if (checkpointInterval == 0) revert ZeroCheckpointInterval();
        if (maxUnattestedPeriods == 0 || maxUnattestedPeriods > InputQueue.MAX_PERIODS) {
            revert InvalidMaxUnattestedPeriods();
        }
        if (viewingKey.length != 0 && viewingKey.length != VIEWING_KEY_LENGTH) revert InvalidViewingKey();

        uint256 queueConfig =
            (uint256(maxUnattestedPeriods) << 224) | (uint256(checkpointInterval) << 160) | uint160(feeRecipient);
        InputQueue.store(queue, InputQueue.CONFIG, queueConfig);
        // The registering L1 block is the domain's block 0.
        InputQueue.store(queue, InputQueue.LATEST, uint256(uint64(block.number)) << 64);
        InputQueue.State memory state;
        _openBlock(queue, state, queueConfig, 0, 0);
        InputQueue.storeState(queue, state);

        DomainConfig storage config = _configs[domainChainId];
        config.checkpointInterval = checkpointInterval;
        // The first checkpoint is the first scheduled height that covers the registering block.
        config.domainBlockNumber = uint64((block.number - 1) / checkpointInterval * checkpointInterval);
        config.quorum = SafeCast.toUint32(quorum);
        config.viewingKey = viewingKey;
        for (uint256 i = 0; i < validators.length; i++) {
            address validator = validators[i];
            if (validator == address(0)) revert ZeroValidator();
            if (config.voters[validator].isValidator) revert DuplicateValidator();
            config.voters[validator].isValidator = true;
            config.validators.push(validator);
        }

        emit DomainRegistered(domainChainId, feeRecipient, checkpointInterval);
        emit ViewingKeyRegistered(domainChainId, viewingKey);
    }

    function isDomainRegistered(uint64 domainChainId) external view returns (bool) {
        return _queueConfig(domainChainId) != 0;
    }

    function getValidators(uint64 domainChainId) external view returns (address[] memory) {
        return _configs[domainChainId].validators;
    }

    function quorums(uint64 domainChainId) external view returns (uint256) {
        return _configs[domainChainId].quorum;
    }

    function feeRecipients(uint64 domainChainId) external view returns (address) {
        return address(uint160(_queueConfig(domainChainId)));
    }

    function checkpointIntervals(uint64 domainChainId) external view returns (uint64) {
        return uint64(_queueConfig(domainChainId) >> 160);
    }

    function maxUnattestedPeriods(uint64 domainChainId) external view returns (uint8) {
        return uint8(_queueConfig(domainChainId) >> 224);
    }

    /// @dev `maxUnattestedPeriods(8) | checkpointInterval(64) | feeRecipient(160)`; zero for an
    /// unregistered domain.
    function _queueConfig(uint64 domainChainId) internal view returns (uint256) {
        return InputQueue.load(InputQueue.base(domainChainId), InputQueue.CONFIG);
    }

    function viewingKeys(uint64 domainChainId) external view returns (bytes memory) {
        return _configs[domainChainId].viewingKey;
    }

    // ---------------------------------------------------------------------
    // State attestation
    // ---------------------------------------------------------------------

    function stateRoots(uint64 domainChainId) external view returns (bytes32) {
        return _configs[domainChainId].stateRoot;
    }

    function stateNonces(uint64 domainChainId) external view returns (uint256) {
        return _configs[domainChainId].stateNonce;
    }

    function domainBlockNumbers(uint64 domainChainId) external view returns (uint64) {
        return _configs[domainChainId].domainBlockNumber;
    }

    function stateVotes(uint64 domainChainId, bytes32 digest) external view returns (uint256) {
        DomainConfig storage config = _configs[domainChainId];
        return config.leadingProposal == digest ? config.leadingVotes : _otherVotes[digest];
    }

    function hasVotedFor(uint64 domainChainId, bytes32 digest, address validator) external view returns (bool) {
        if (digest == bytes32(0)) return false;
        return _configs[domainChainId].voters[validator].leadingVote == digest || _otherVoters[digest][validator];
    }

    function stateTransitionDigest(
        uint64 domainChainId,
        uint64 domainBlockNumber,
        bytes32 newStateRoot,
        bytes32 domainAnchor
    ) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    STATE_TRANSITION_TYPEHASH,
                    domainChainId,
                    _configs[domainChainId].stateNonce,
                    domainBlockNumber,
                    newStateRoot,
                    domainAnchor
                )
            )
        );
    }

    function submitStateSignature(
        uint64 domainChainId,
        uint64 domainBlockNumber,
        bytes32 newStateRoot,
        bytes32 domainAnchor,
        bytes calldata signature
    ) external {
        DomainConfig storage config = _configs[domainChainId];
        uint64 checkpointInterval = config.checkpointInterval;
        if (checkpointInterval == 0) revert DomainNotRegistered();
        if (domainBlockNumber <= config.domainBlockNumber) revert StaleBlockNumber();
        if (domainBlockNumber >= block.number) revert BlockNumberNotInPast();
        if (domainBlockNumber % checkpointInterval != 0) revert BlockNumberOffSchedule();

        bytes32 digest = stateTransitionDigest(domainChainId, domainBlockNumber, newStateRoot, domainAnchor);
        address signer = ECDSA.recover(digest, signature);
        Voter storage voter = config.voters[signer];
        if (!voter.isValidator) revert NotValidator();

        // The round's first proposal leads it and is counted in the config, which a vote
        // loads anyway: the usual case, where validators agree. Another proposal of the round
        // is counted on its own, at a higher cost.
        if (config.leadingVotes == 0) config.leadingProposal = digest;
        uint256 votes;
        if (config.leadingProposal == digest) {
            if (voter.leadingVote == digest) revert AlreadyVoted();
            voter.leadingVote = digest;
            votes = ++config.leadingVotes;
        } else {
            if (_otherVoters[digest][signer]) revert AlreadyVoted();
            _otherVoters[digest][signer] = true;
            votes = ++_otherVotes[digest];
        }
        emit StateSignatureSubmitted(domainChainId, signer, domainBlockNumber, newStateRoot, domainAnchor, votes);

        // Advance exactly once, when the vote count first reaches quorum. The subsequent
        // stateNonce bump changes the digest, so this proposal can never be revisited.
        if (votes == config.quorum) {
            uint256 nonce = config.stateNonce++;
            config.stateRoot = newStateRoot;
            config.domainBlockNumber = domainBlockNumber;
            config.leadingVotes = 0;
            if (domainAnchor != bytes32(0)) domainAnchors[domainChainId][domainAnchor] = true;
            // The attested state covers every input up to this height: stop holding them.
            uint256 queue = InputQueue.base(domainChainId);
            uint64 latestL1Block = uint64(InputQueue.load(queue, InputQueue.LATEST) >> 64);
            InputQueue.release(
                queue, domainBlockNumber / checkpointInterval, _period(latestL1Block, checkpointInterval)
            );
            emit DomainStateUpdated(domainChainId, nonce, domainBlockNumber, newStateRoot, domainAnchor);
        }
    }

    // ---------------------------------------------------------------------
    // Delivery of domain messages
    // ---------------------------------------------------------------------

    function relayDomainMessage(MessageLib.DomainMessage calldata message, bytes32 anchor, bytes32[] calldata proof)
        external
        payable
        returns (bool success)
    {
        if (message.sourceChainId == message.destinationChainId) revert SameDomain();
        if (message.to == address(0)) revert ZeroTarget();
        BitMaps.BitMap storage relayed = _relayed[message.sourceChainId];
        if (relayed.get(message.sourceNonce)) revert MessageAlreadyRelayed();
        if (!domainAnchors[message.sourceChainId][anchor]) {
            // Only a registered domain has anchors: its registration is read only to name
            // the failure.
            if (_queueConfig(message.sourceChainId) == 0) revert SourceNotRegistered();
            revert UnknownAnchor();
        }
        bytes32 messageHash = MessageLib.hashDomainMessage(message, block.chainid, address(this));
        if (!MerkleProof.verifyCalldata(proof, anchor, messageHash)) revert InvalidProof();
        relayed.set(message.sourceNonce);

        if (message.destinationChainId != block.chainid) {
            if (_queueConfig(message.destinationChainId) == 0) revert DestinationNotRegistered();
            (uint256 deliveryNonce, uint256 config) = _sendL1Message(
                message.destinationChainId, message.sourceChainId, message.from, message.to, message.data, msg.value
            );
            emit DomainMessageRouted(messageHash, message.sourceChainId, message.destinationChainId, deliveryNonce);
            _payFee(config, msg.value);
            return true; // Queued atomically; destination execution happens asynchronously.
        }

        if (msg.value != 0) revert UnexpectedL1CallbackFee();
        (success,) = message.to
            .call(
                abi.encodeCall(
                    IDomainMessageReceiver.onDomainMessage, (message.sourceChainId, message.from, message.data)
                )
            );
        if (!success) failedDomainMessages[message.sourceChainId][messageHash] = true;
        emit DomainMessageRelayed(
            message.sourceChainId, messageHash, message.from, message.to, message.sourceNonce, success
        );
    }

    function relayedDomainMessages(uint64 sourceChainId, uint256 sourceNonce) external view returns (bool) {
        return _relayed[sourceChainId].get(sourceNonce);
    }

    function retryDomainMessage(MessageLib.DomainMessage calldata message) external {
        if (message.destinationChainId != block.chainid) revert RetryOnDestinationDomain();
        bytes32 messageHash = MessageLib.hashDomainMessage(message, block.chainid, address(this));
        if (!failedDomainMessages[message.sourceChainId][messageHash]) revert NotFailedMessage();
        delete failedDomainMessages[message.sourceChainId][messageHash];
        (bool success,) = message.to
            .call(
                abi.encodeCall(
                    IDomainMessageReceiver.onDomainMessage, (message.sourceChainId, message.from, message.data)
                )
            );
        if (!success) revert RetryFailed();
        emit DomainMessageRelayed(
            message.sourceChainId, messageHash, message.from, message.to, message.sourceNonce, true
        );
    }

    // ---------------------------------------------------------------------
    // Domain transactions: sequenced on the L1
    // ---------------------------------------------------------------------

    function minSequencingFee(uint256 payloadLength) public pure returns (uint256) {
        return (SEQUENCING_BASE_GAS + SEQUENCING_GAS_PER_BYTE * payloadLength) * DOMAIN_GAS_PRICE;
    }

    function sequenceToDomain(uint64 domainChainId, bytes calldata rlpTx) external payable {
        uint256 queue = InputQueue.base(domainChainId);
        uint256 config = _registeredConfig(queue);
        if (msg.value < minSequencingFee(rlpTx.length)) revert SequencingFeeTooLow();
        _recordInput(queue, config, InputQueue.loadState(queue), InputQueue.TRANSACTION, msg.value, rlpTx);
        emit DomainTransactionSequenced(domainChainId, rlpTx, msg.value);
        _payFee(config, msg.value);
    }

    // ---------------------------------------------------------------------
    // Messaging: L1 -> domain
    // ---------------------------------------------------------------------

    function minDeliveryFee(uint256 dataLength) public pure returns (uint256) {
        return (DELIVERY_BASE_GAS + DELIVERY_GAS_PER_BYTE * dataLength) * DOMAIN_GAS_PRICE;
    }

    function sendL1Message(uint64 domainChainId, address to, bytes calldata data) external payable {
        (, uint256 config) =
            _sendL1Message(domainChainId, SafeCast.toUint64(block.chainid), msg.sender, to, data, msg.value);
        _payFee(config, msg.value);
    }

    /// @dev Charges `fee` for the delivery, assigns the next delivery nonce of `domainChainId` and
    /// records the message for the domain client to deliver. Returns the domain's config word:
    /// the caller pays the fee out once it has nothing left to do.
    function _sendL1Message(
        uint64 domainChainId,
        uint64 sourceChainId,
        address from,
        address to,
        bytes memory data,
        uint256 fee
    ) internal returns (uint256 nonce, uint256 config) {
        uint256 queue = InputQueue.base(domainChainId);
        config = _registeredConfig(queue);
        if (fee < minDeliveryFee(data.length)) revert DeliveryFeeTooLow();
        InputQueue.State memory state = InputQueue.loadState(queue);
        nonce = state.messageCount++;
        _recordInput(
            queue,
            config,
            state,
            InputQueue.MESSAGE,
            fee,
            abi.encodePacked(sourceChainId, from, to, uint64(nonce), data)
        );
        bytes32 messageHash = MessageLib.hashMessage(MessageLib.Message(sourceChainId, from, to, data, nonce));
        emit L1MessageRecorded(domainChainId, sourceChainId, from, to, data, nonce, fee, messageHash);
    }

    function sendEncryptedL1Message(uint64 domainChainId, bytes calldata ciphertext) external payable {
        uint256 queue = InputQueue.base(domainChainId);
        uint256 config = _registeredConfig(queue);
        if (msg.value < minDeliveryFee(ciphertext.length)) revert DeliveryFeeTooLow();
        uint64 sourceChainId = SafeCast.toUint64(block.chainid);
        InputQueue.State memory state = InputQueue.loadState(queue);
        uint64 nonce = state.messageCount++;
        _recordInput(
            queue,
            config,
            state,
            InputQueue.ENCRYPTED_MESSAGE,
            msg.value,
            abi.encodePacked(sourceChainId, msg.sender, nonce, ciphertext)
        );
        emit EncryptedL1MessageRecorded(domainChainId, sourceChainId, msg.sender, ciphertext, nonce, msg.value);
        _payFee(config, msg.value);
    }

    function l1MessageCounts(uint64 domainChainId) external view returns (uint256) {
        return InputQueue.loadState(InputQueue.base(domainChainId)).messageCount;
    }

    // ---------------------------------------------------------------------
    // Input queue
    // ---------------------------------------------------------------------

    /// @dev The config word of `queue`'s domain, which must be registered.
    function _registeredConfig(uint256 queue) internal view returns (uint256 config) {
        config = InputQueue.load(queue, InputQueue.CONFIG);
        if (config == 0) revert DomainNotRegistered();
    }

    /// @dev Records one input in the domain's queue and counts its gas and its words against the
    /// domain's limits for this L1 block. The first input of an L1 block opens the domain's
    /// next block. Paying the fee out is left to the caller, as its last step: the recipient
    /// may call back in, and an input it records must follow this one in the queue and the logs.
    function _recordInput(
        uint256 queue,
        uint256 config,
        InputQueue.State memory state,
        uint8 kind,
        uint256 fee,
        bytes memory payload
    ) internal {
        uint256 latest = InputQueue.load(queue, InputQueue.LATEST);
        uint256 gasSold = latest >> 192;
        uint256 inputWords = uint64(latest >> 128);
        if (uint64(latest >> 64) != block.number) {
            uint64 domainBlockNumber = uint64(latest) + 1;
            _openBlock(queue, state, config, uint64(latest >> 64), domainBlockNumber);
            latest = (uint256(uint64(block.number)) << 64) | domainBlockNumber;
            gasSold = 0;
            inputWords = 0;
        }
        gasSold += fee / DOMAIN_GAS_PRICE;
        if (gasSold > DOMAIN_BLOCK_GAS_LIMIT) revert DomainBlockGasLimitExceeded();
        inputWords += InputQueue.inputWords(payload.length);
        if (inputWords > DOMAIN_BLOCK_WORD_LIMIT) revert DomainBlockSizeLimitExceeded();
        InputQueue.store(queue, InputQueue.LATEST, (gasSold << 192) | (inputWords << 128) | uint128(latest));

        // The gas limit above keeps `fee` far below the 88 bits a header holds.
        InputQueue.push(queue, state, InputQueue.inputHeader(kind, fee), payload);
        InputQueue.storeState(queue, state);
    }

    /// @dev Appends the block entry of `domainBlockNumber`, derived from this L1 block. If it
    /// is the first block of its checkpoint period in the queue, the period starts at it.
    function _openBlock(
        uint256 queue,
        InputQueue.State memory state,
        uint256 config,
        uint64 previousL1Block,
        uint64 domainBlockNumber
    ) internal {
        uint64 checkpointInterval = uint64(config >> 160);
        uint64 period = _period(uint64(block.number), checkpointInterval);
        if (state.head == state.tail || period != _period(previousL1Block, checkpointInterval)) {
            InputQueue.openPeriod(queue, state, period, uint8(config >> 224));
        }
        // The probe fails on an L1 revision without slot numbers, taking the gas it was given.
        uint56 slotNumber;
        (bool success, bytes memory result) = SLOT_NUMBER_PROBE.staticcall{gas: 200}("");
        if (success && result.length == 32) slotNumber = uint56(uint256(bytes32(result)));
        InputQueue.pushBlock(queue, state, InputQueue.blockHeader(domainBlockNumber, slotNumber), block.prevrandao);
    }

    /// @dev The checkpoint period of an L1 block: the first scheduled checkpoint at or above it.
    function _period(uint64 l1BlockNumber, uint64 checkpointInterval) internal pure returns (uint64) {
        return uint64((uint256(l1BlockNumber) + checkpointInterval - 1) / checkpointInterval);
    }

    /// @dev Pays `fee` to the fee recipient in `config`, who must accept it.
    function _payFee(uint256 config, uint256 fee) internal {
        if (fee == 0) return;
        (bool success,) = address(uint160(config)).call{value: fee}("");
        if (!success) revert FeeTransferFailed();
    }

    function blockGas(uint64 domainChainId) external view returns (uint64 blockNumber, uint192 gasSold) {
        uint256 latest = InputQueue.load(InputQueue.base(domainChainId), InputQueue.LATEST);
        return (uint64(latest >> 64), uint192(latest >> 192));
    }

    function latestDomainBlock(uint64 domainChainId)
        external
        view
        returns (uint64 l1BlockNumber, uint64 domainBlockNumber)
    {
        uint256 latest = InputQueue.load(InputQueue.base(domainChainId), InputQueue.LATEST);
        return (uint64(latest >> 64), uint64(latest));
    }

    function primeInputQueue(uint64 domainChainId, uint256 from, uint256 count) external {
        uint256 queue = InputQueue.base(domainChainId);
        _registeredConfig(queue);
        InputQueue.prime(queue, from, count);
    }
}
