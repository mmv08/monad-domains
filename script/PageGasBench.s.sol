// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {DomainHub} from "../src/DomainHub.sol";
import {IDomainMessageReceiver} from "../src/interfaces/IDomain.sol";
import {MessageLib} from "../src/libraries/MessageLib.sol";
import {MerkleTreeLib} from "../test/helpers/MerkleTreeLib.sol";

/// @dev Accepts every message and does nothing, so a relay measures the hub alone.
contract NoopReceiver is IDomainMessageReceiver {
    function onDomainMessage(uint64, address, bytes calldata) external {}
}

/// @notice Gas of the hub's checkpoint and relay paths as real transactions on a node that
/// prices storage by MIP-8 page, such as `anvil --network monad`. Run by
/// `script/page-gas-bench.sh`, which deploys with `deploy()`, mines past the registration and
/// then runs `measure(hub, receiver)`. Every transaction is preceded by a `TX,<label>` line,
/// which the runner pairs with the receipts.
///
/// Uses only calls both the current hub and the paged proof of concept expose, so the same
/// script compares the two.
contract PageGasBench is Script {
    uint64 internal constant DOMAIN = 7777;
    uint64 internal constant DESTINATION = 8888;
    /// @dev A domain with a validator set larger than a storage page.
    uint64 internal constant LARGE = 9999;
    uint256 internal constant LARGE_VALIDATORS = 130;
    /// @dev The first validator of `LARGE` that votes, near the end of its set.
    uint256 internal constant LARGE_FIRST_VOTER = 125;
    /// @dev Every past L1 height is on schedule, so rounds need no waiting.
    uint64 internal constant INTERVAL = 1;
    uint256 internal constant QUORUM = 3;
    /// @dev Messages of each attested batch: L1 callbacks, then messages routed to `DESTINATION`.
    uint256 internal constant L1_MESSAGES = 8;
    uint256 internal constant ROUTED_MESSAGES = 4;

    function _keys() internal pure returns (uint256[4] memory) {
        return [uint256(0xA11CE), 0xB0B, 0xCA401, 0xD0D];
    }

    function _largeValidators() internal pure returns (address[] memory validators) {
        validators = new address[](LARGE_VALIDATORS);
        for (uint256 i = 0; i < validators.length; i++) {
            validators[i] = vm.addr(0x1000 + i);
        }
    }

    function _validators() internal pure returns (address[] memory validators) {
        uint256[4] memory keys = _keys();
        validators = new address[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            validators[i] = vm.addr(keys[i]);
        }
    }

    function deploy() external {
        vm.startBroadcast();
        console.log("TX,deploy/hub");
        DomainHub hub = new DomainHub();
        console.log("TX,deploy/receiver");
        NoopReceiver receiver = new NoopReceiver();
        console.log("TX,register/source");
        hub.registerDomain(DOMAIN, _validators(), QUORUM, msg.sender, "", INTERVAL, 50);
        console.log("TX,register/destination");
        // Never attested here: a long interval keeps its queue within one period.
        hub.registerDomain(DESTINATION, _validators(), QUORUM, msg.sender, "", 1_000_000, 50);
        // Routed messages then rewrite ring words, as in a queue past its first lap.
        console.log("TX,prime/destination");
        hub.primeInputQueue(DESTINATION, 0, 3 * 128);
        console.log("TX,register/large");
        hub.registerDomain(LARGE, _largeValidators(), QUORUM, msg.sender, "", INTERVAL, 50);
        vm.stopBroadcast();
        console.log("HUB", address(hub));
        console.log("RECEIVER", address(receiver));
    }

    function measure(DomainHub hub, address receiver) external {
        uint64 height = hub.domainBlockNumbers(DOMAIN);
        uint256 nonce = 0;
        vm.startBroadcast();
        // Two rounds first, so slots a round reuses exist, as they would after the first
        // checkpoints. The third round is the one to read.
        for (uint256 round = 0; round < 3; round++) {
            string memory phase = round < 2 ? "warmup/" : "";
            MessageLib.DomainMessage[] memory batch = _batch(hub, receiver, nonce);
            nonce += batch.length;
            bytes32[] memory leaves = _leaves(hub, batch);
            bytes32 anchor = MerkleTreeLib.root(leaves);
            height += INTERVAL;
            bytes32 root = keccak256(abi.encode("state root", height));
            for (uint256 v = 0; v < QUORUM; v++) {
                bytes32 digest = hub.stateTransitionDigest(DOMAIN, height, root, anchor);
                (uint8 sv, bytes32 r, bytes32 s) = vm.sign(_keys()[v], digest);
                string memory vote = v + 1 == QUORUM ? "vote/quorum" : string.concat("vote/", vm.toString(v + 1));
                console.log(string.concat("TX,", phase, vote));
                hub.submitStateSignature(DOMAIN, height, root, anchor, abi.encodePacked(r, s, sv));
            }
            for (uint256 i = 0; i < batch.length; i++) {
                bool routed = batch[i].destinationChainId == DESTINATION;
                console.log(string.concat("TX,", phase, routed ? "relay/routed" : "relay/l1", "#", vm.toString(i)));
                hub.relayDomainMessage{value: routed ? hub.minDeliveryFee(batch[i].data.length) : 0}(
                    batch[i], anchor, MerkleTreeLib.getProof(leaves, i)
                );
            }
        }
        _measureLarge(hub);
        vm.stopBroadcast();
    }

    /// @dev Two rounds of `LARGE`, the first to warm up, voted by validators near the end of its set.
    function _measureLarge(DomainHub hub) internal {
        uint64 height = hub.domainBlockNumbers(LARGE);
        for (uint256 round = 0; round < 2; round++) {
            height += INTERVAL;
            bytes32 root = keccak256(abi.encode("large state root", height));
            bytes32 anchor = keccak256(abi.encode("large anchor", height));
            for (uint256 v = 0; v < QUORUM; v++) {
                bytes32 digest = hub.stateTransitionDigest(LARGE, height, root, anchor);
                (uint8 sv, bytes32 r, bytes32 s) = vm.sign(0x1000 + LARGE_FIRST_VOTER + v, digest);
                string memory vote = v + 1 == QUORUM ? "vote/quorum" : string.concat("vote/", vm.toString(v + 1));
                console.log(string.concat("TX,", round == 0 ? "warmup/" : "", "large/", vote));
                hub.submitStateSignature(LARGE, height, root, anchor, abi.encodePacked(r, s, sv));
            }
        }
    }

    /// @dev A batch shaped like token bridge withdrawals: a 96-byte transfer payload each.
    function _batch(DomainHub, address receiver, uint256 firstNonce)
        internal
        view
        returns (MessageLib.DomainMessage[] memory batch)
    {
        batch = new MessageLib.DomainMessage[](L1_MESSAGES + ROUTED_MESSAGES);
        for (uint256 i = 0; i < batch.length; i++) {
            uint256 nonce = firstNonce + i;
            batch[i] = MessageLib.DomainMessage({
                sourceChainId: DOMAIN,
                destinationChainId: i < L1_MESSAGES ? uint64(block.chainid) : DESTINATION,
                from: address(0xB41D6E),
                to: receiver,
                sourceNonce: nonce,
                salt: keccak256(abi.encode("salt", nonce)),
                data: MessageLib.encodeTransfer(address(uint160(0x1000 + nonce)), address(0x70CE4), 1 ether)
            });
        }
    }

    function _leaves(DomainHub hub, MessageLib.DomainMessage[] memory batch)
        internal
        view
        returns (bytes32[] memory leaves)
    {
        leaves = new bytes32[](batch.length);
        for (uint256 i = 0; i < batch.length; i++) {
            leaves[i] = MessageLib.hashDomainMessage(batch[i], block.chainid, address(hub));
        }
    }
}
