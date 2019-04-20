
#ifndef __WIT_MERKLE_H__
#define __WIT_MERKLE_H__



#include <stdint.h>
#include <vector>


#if 0
uint256 ComputeMerkleRoot(const std::vector<uint256>& leaves, bool* mutated = NULL);
std::vector<uint256> ComputeMerkleBranch(const std::vector<uint256>& leaves, uint32_t position);
uint256 ComputeMerkleRootFromBranch(const uint256& leaf, const std::vector<uint256>& branch, uint32_t position);

/*
 * Compute the Merkle root of the transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 BlockMerkleRoot(const CBlock& block, bool* mutated = NULL);
#endif

/*
 * Compute the Merkle root of the witness transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 BlockWitnessMerkleRoot(const CBlock& block, bool* mutated = NULL);

#if 0
/*
 * Compute the Merkle branch for the tree of transactions in a block, for a
 * given position.
 * This can be verified using ComputeMerkleRootFromBranch.
 */
std::vector<uint256> BlockMerkleBranch(const CBlock& block, uint32_t position);
#endif



#endif /* ndef __WIT_MERKLE_H__ */
