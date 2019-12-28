
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
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

#ifndef __SHC_BLOCK_H__
#define __SHC_BLOCK_H__

/**
 * @ingroup sharecoin_shc
 * @{
 */

#include <boost/assign/list_of.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>

class SHCBlock : public CBlock
{
	public:
		static const int CURRENT_VERSION=4;
		static SHC_CTxMemPool mempool; 
		static CBlockIndex *pindexBest;
		static CBlockIndex *pindexGenesisBlock;
		static int64 nTimeBestReceived;

		SHCBlock()
		{
			ifaceIndex = SHC_COIN_IFACE;
			SetNull();
		}

		SHCBlock(const CBlock &block)
		{
			ifaceIndex = SHC_COIN_IFACE;
			SetNull();
			*((CBlock*)this) = block;
		}

		SHCBlock(const CBlockHeader &block)
		{
			ifaceIndex = SHC_COIN_IFACE;
			SetNull();
			*((CBlockHeader*)this) = block;
		}

		void SetNull()
		{
			nVersion = SHCBlock::CURRENT_VERSION;
			CBlock::SetNull();
		}

		void InvalidChainFound(CBlockIndex* pindexNew);
		unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast);
		bool AcceptBlock();
		bool IsBestChain();
		CScript GetCoinbaseFlags();
		bool AddToBlockIndex();
		bool CheckBlock();
		bool ReadBlock(uint64_t nHeight);
		bool ReadArchBlock(uint256 hash);
		bool IsOrphan();
		bool Truncate();
		bool VerifyCheckpoint(int nHeight);
		uint64_t GetTotalBlocksEstimate();

		int64_t GetBlockWeight();

		bool CreateCheckpoint(); 

		int GetAlgo() const;

		bool SetBestChain(CBlockIndex* pindexNew);
		bool ConnectBlock(CBlockIndex* pindex);
		bool DisconnectBlock(CBlockIndex* pindex);
};

/**
 * A memory pool where an inventory of pending block transactions are stored.
 */
extern SHC_CTxMemPool SHC_mempool;

/**
 * The best known tail of the SHC block-chain.
 */
extern CBlockIndex* SHC_pindexBest;

/**
 * The initial block in the SHC block-chain's index reference.
 */
extern CBlockIndex* SHC_pindexGenesisBlock;

/**
 * The block hash of the initial block in the SHC block-chain.
 */
extern uint256 shc_hashGenesisBlock;


extern int SHC_nBestHeight;
extern uint256 SHC_hashBestChain;
extern int64 SHC_nTimeBestReceived;

/**
 * Create a block template with pending inventoried transactions.
 */
CBlock* shc_CreateNewBlock(const CPubKey& rkey);

/**
 * Generate the inital SHC block in the block-chain.
 */
bool shc_CreateGenesisBlock();

/**
 * Set the best known block hash.
 */
bool shc_SetBestChain(CBlock *block);

/**
 * Attempt to process an incoming block from a remote SHC coin service.
 */
bool shc_ProcessBlock(CNode* pfrom, CBlock* pblock);


int64 shc_GetBlockValue(int nHeight, int64 nFees);

bool shc_IsOrphanBlock(const uint256& hash);
void shc_AddOrphanBlock(CBlock *block);
void shc_RemoveOrphanBlock(const uint256& hash);
bool shc_GetOrphanPrevHash(const uint256& hash, uint256& retPrevHash);
CBlock *shc_GetOrphanBlock(const uint256& hash);
uint256 shc_GetOrphanRoot(uint256 hash);

/**
 * @}
 */

#endif /* ndef __SHC_BLOCK_H__ */

