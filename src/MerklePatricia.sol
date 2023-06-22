pragma solidity ^0.8.17;

import "./trie/Node.sol";
import "./trie/Option.sol";
import "./trie/NibbleSlice.sol";
import "./trie/TrieDB.sol";

import "./trie/ethereum/EthereumTrieDB.sol";

// SPDX-License-Identifier: Apache2

/**
 * @title A Merkle Patricia library
 * @author Polytope Labs
 * @dev Use this library to verify merkle patricia proofs
 * @dev refer to research for more info. https://research.polytope.technology/state-(machine)-proofs
 */
library MerklePatricia {
    /// @notice libraries in solidity can only have constant variables
    /// @dev MAX_TRIE_DEPTH, we don't explore deeply nested trie keys.
    uint256 internal constant MAX_TRIE_DEPTH = 50;

    /**
     * @notice Verifies ethereum specific merkle patricia proofs as described by EIP-1188.
     * @param root hash of the merkle patricia trie
     * @param proof a list of proof nodes
     * @param key a key to verify
     * @return bytes a value corresponding to the supplied keys.
     */
    function VerifyEthereumProof(
        bytes32 root,
        bytes[] memory proof,
        bytes memory key
    ) external pure returns (bytes memory) {
        bytes memory value;
        TrieNode[] memory nodes = new TrieNode[](proof.length);

        for (uint256 i = 0; i < proof.length; i++) {
            nodes[i] = TrieNode(keccak256(proof[i]), proof[i]);
        }

        NibbleSlice memory keyNibbles = NibbleSlice(key, 0);
        NodeKind memory node = EthereumTrieDB.decodeNodeKind(
            TrieDB.get(nodes, root)
        );

        // worst case scenario, so we avoid unbounded loops
        for (uint256 j = 0; j < MAX_TRIE_DEPTH; j++) {
            NodeHandle memory nextNode;

            if (TrieDB.isLeaf(node)) {
                Leaf memory leaf = EthereumTrieDB.decodeLeaf(node);
                // Let's retrieve the offset to be used
                uint offset = keyNibbles.offset % 2 == 0
                    ? keyNibbles.offset / 2
                    : keyNibbles.offset / 2 + 1;
                // Let's cut the key passed as input
                keyNibbles = NibbleSlice(
                    NibbleSliceOps.bytesSlice(keyNibbles.data, offset),
                    0
                );
                if (NibbleSliceOps.eq(leaf.key, keyNibbles)) {
                    value = TrieDB.load(nodes, leaf.value);
                }
                break;
            } else if (TrieDB.isExtension(node)) {
                Extension memory extension = EthereumTrieDB.decodeExtension(
                    node
                );
                if (NibbleSliceOps.startsWith(keyNibbles, extension.key)) {
                    // Let's cut the key passed as input
                    keyNibbles = NibbleSlice(
                        NibbleSliceOps.bytesSlice(
                            keyNibbles.data,
                            NibbleSliceOps.len(extension.key)
                        ),
                        0
                    );
                    nextNode = extension.node;
                } else {
                    break;
                }
            } else if (TrieDB.isBranch(node)) {
                Branch memory branch = EthereumTrieDB.decodeBranch(node);
                if (NibbleSliceOps.isEmpty(keyNibbles)) {
                    if (Option.isSome(branch.value)) {
                        value = TrieDB.load(nodes, branch.value.value);
                    }
                    break;
                } else {
                    NodeHandleOption memory handle = branch.children[
                        NibbleSliceOps.at(keyNibbles, 0)
                    ];
                    if (Option.isSome(handle)) {
                        keyNibbles = NibbleSliceOps.mid(keyNibbles, 1);
                        nextNode = handle.value;
                    } else {
                        break;
                    }
                }
            } else if (TrieDB.isEmpty(node)) {
                break;
            }

            node = EthereumTrieDB.decodeNodeKind(TrieDB.load(nodes, nextNode));
        }

        return value;
    }
}
