
/*
 * @copyright
 *
 *  Copyright 2019 Brian Burrell
 *
 *  This file is part of Shioncoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcoind.h"
#include "block.h"
#include "util.h"
#include "sha256d_merkle.h"

uint256 sha256d_ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated) 
{
	uint256 hash = hashes[0];
	int i;

	for (i = 1; i < hashes.size(); i++) {
		const uint256& merkle = hashes[i];
		unsigned char merkle_bin[64];

		memcpy(merkle_bin, &hash, 32);
		memcpy(merkle_bin + 32, &merkle, 32);
		hash = Hash(merkle_bin, merkle_bin + 64);
	}

	return (hash);
}

uint256 sha256d_BlockMerkleRoot(const CBlock& block, bool* mutated)
{
	std::vector<uint256> leaves;

	leaves.resize(block.vtx.size());
	for (size_t s = 0; s < block.vtx.size(); s++) {
		leaves[s] = block.vtx[s].GetHash();
	}

	return sha256d_ComputeMerkleRoot(std::move(leaves), mutated);
}

uint256 sha256_BlockMerkleRoot(const CBlock& block, bool* mutated)
{
	std::vector<uint256> leaves;

	leaves.resize(block.vtx.size());
//	for (size_t s = 0; s < block.vtx.size(); s++) 
	{
		unsigned int s = 0;
		CDataStream ss(SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
		ss << block.vtx[s];
		unsigned int sBlockLen = ss.size();
		unsigned char *sBlockData = (unsigned char *)calloc(sBlockLen, sizeof(unsigned char));
		ss.read((char *)sBlockData, sBlockLen);
		SHA256(sBlockData, sBlockLen, (unsigned char *)&leaves[s]);
		free(sBlockData);
	}
	for (size_t s = 1; s < block.vtx.size(); s++) {
		leaves[s] = block.vtx[s].GetHash();
	}

	return sha256d_ComputeMerkleRoot(std::move(leaves), mutated);
}

uint256 sha256d_BlockWitnessMerkleRoot(const CBlock& block, bool* mutated)
{
	std::vector<uint256> leaves;

	leaves.resize(block.vtx.size());
	leaves[0].SetNull(); // The witness hash of the coinbase is 0.
	for (size_t s = 1; s < block.vtx.size(); s++) {
		leaves[s] = block.vtx[s].GetWitnessHash();
	}

	return sha256d_ComputeMerkleRoot(std::move(leaves), mutated);
}

