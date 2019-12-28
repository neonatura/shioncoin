
/*
 * @copyright
 *
 *  Copyright 2018 Brian Burrell
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

#ifndef __TESTNET_BLOCK_H__
#define __TESTNET_BLOCK_H__

/**
 * @ingroup sharecoin_testnet
 * @{
 */

#include <boost/assign/list_of.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>

#ifdef TESTNET_SERVICE

class TESTNETBlock : public CBlock
{
	public:
		static const int CURRENT_VERSION=4;
		static TESTNET_CTxMemPool mempool; 
		static CBlockIndex *pindexBest;
		static CBlockIndex *pindexGenesisBlock;
		static int64 nTimeBestReceived;

		TESTNETBlock()
		{
			ifaceIndex = TESTNET_COIN_IFACE;
			SetNull();
		}

		TESTNETBlock(const CBlock &block)
		{
			ifaceIndex = TESTNET_COIN_IFACE;
			SetNull();
			*((CBlock*)this) = block;
		}

		TESTNETBlock(const CBlockHeader &block)
		{
			ifaceIndex = TESTNET_COIN_IFACE;
			SetNull();
			*((CBlockHeader*)this) = block;
		}

		void SetNull()
		{
			nVersion = TESTNETBlock::CURRENT_VERSION;
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

		bool SetBestChain(CBlockIndex* pindexNew);

		bool ConnectBlock(CBlockIndex* pindex);

		bool DisconnectBlock(CBlockIndex* pindex);

		bool CreateCheckpoint(); 

		int GetAlgo() const;

};


/**
 * A memory pool where an inventory of pending block transactions are stored.
 */
extern TESTNET_CTxMemPool TESTNET_mempool;

/**
 * The best known tail of the TESTNET block-chain.
 */
extern CBlockIndex* TESTNET_pindexBest;

/**
 * The initial block in the TESTNET block-chain's index reference.
 */
extern CBlockIndex* TESTNET_pindexGenesisBlock;

/**
 * The block hash of the initial block in the TESTNET block-chain.
 */
extern uint256 testnet_hashGenesisBlock;


extern int TESTNET_nBestHeight;
extern uint256 TESTNET_hashBestChain;
extern int64 TESTNET_nTimeBestReceived;

/**
 * Create a block template with pending inventoried transactions.
 */
CBlock* testnet_CreateNewBlock(const CPubKey& rkey);

/**
 * Generate the inital TESTNET block in the block-chain.
 */
bool testnet_CreateGenesisBlock();

/**
 * Set the best known block hash.
 */
bool testnet_SetBestChain(CBlock *block);

/**
 * Attempt to process an incoming block from a remote TESTNET coin service.
 */
bool testnet_ProcessBlock(CNode* pfrom, CBlock* pblock);


int64 testnet_GetBlockValue(int nHeight, int64 nFees);

bool testnet_IsOrphanBlock(const uint256& hash);
void testnet_AddOrphanBlock(CBlock *block);
void testnet_RemoveOrphanBlock(const uint256& hash);
bool testnet_GetOrphanPrevHash(const uint256& hash, uint256& retPrevHash);
CBlock *testnet_GetOrphanBlock(const uint256& hash);
uint256 testnet_GetOrphanRoot(uint256 hash);

#endif /* def TESTNET_SERVICE */

/**
 * @}
 */

#endif /* ndef __TESTNET_BLOCK_H__ */
