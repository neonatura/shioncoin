
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

#ifndef __COLOR_BLOCK_H__
#define __COLOR_BLOCK_H__


/**
 * @ingroup sharecoin_color
 * @{
 */

#include <boost/assign/list_of.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>


#define CLROPT_ERROR 0
#define CLROPT_DIFFICULTY 1
#define CLROPT_BLOCKTARGET 2
#define CLROPT_MATURITY 3
#define CLROPT_REWARDBASE 4
#define CLROPT_REWARDHALF 5
#define CLROPT_TXFEE 6
#define CLROPT_ALGO 7
#define MAX_CLROPT 8

#define CLROPT_ALGO_SHA256D BLOCK_ALGO_SHA256D
#define CLROPT_ALGO_KECCAK BLOCK_ALGO_KECCAK
#define CLROPT_ALGO_X11 BLOCK_ALGO_X11
#define CLROPT_ALGO_BLAKE2S BLOCK_ALGO_BLAKE2S


class COLORBlock : public CBlock
{
public:
    static const int CURRENT_VERSION=4;

    static COLOR_CTxMemPool mempool; 
    static CBlockIndex *pindexBest;
    static CBlockIndex *pindexGenesisBlock;
    static int64 nTimeBestReceived;

    COLORBlock(uint160 hColorIn = 0)
    {
        SetNull();
        ifaceIndex = COLOR_COIN_IFACE;
				hColor = hColorIn;
    }

    COLORBlock(const CBlock &block, uint160 hColorIn = 0)
    {
        SetNull();
        ifaceIndex = COLOR_COIN_IFACE;
        *((CBlock*)this) = block;
				hColor = hColorIn;
    }

    COLORBlock(const CAltBlock &header, uint160 hColorIn = 0)
    {
			SetNull();
			ifaceIndex = COLOR_COIN_IFACE;
			hColor = hColorIn;

			this->nVersion = header.nFlag;
			hashPrevBlock = header.hashPrevBlock;
			hashMerkleRoot = header.hashMerkleRoot;
			nTime = header.nTime;
			nBits = header.nBits;
			nNonce = header.nNonce;
    }

    void SetNull()
    {
      CBlock::SetNull();
      nVersion = COLORBlock::CURRENT_VERSION;
			hColor = 0;
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
extern COLOR_CTxMemPool COLOR_mempool;

/**
 * The best known tail of the COLOR block-chain.
 */
extern CBlockIndex* COLOR_pindexBest;

/**
 * The initial block in the COLOR block-chain's index reference.
 */
extern CBlockIndex* COLOR_pindexGenesisBlock;

extern int COLOR_nBestHeight;
extern uint256 COLOR_hashBestChain;
extern int64 COLOR_nTimeBestReceived;



/**
 * Generate the inital COLOR block in an alt block-chain.
 */
COLORBlock *color_CreateGenesisBlock(uint160 hColor, const color_opt& opt = color_opt());

void SetColorOpt(color_opt& opt, int mode, int val);

int GetColorOptValue(color_opt& opt, int mode);

/**
 * Set the best known block hash.
 */
bool color_SetBestChain(CBlock *block);

/**
 * Attempt to process an incoming block from a remote COLOR coin service.
 */
bool color_ProcessBlock(CNode* pfrom, CBlock* pblock);

int64 color_GetBlockValue(uint160 hColor, int nHeight, int64 nFees);

bool color_IsOrphanBlock(const uint256& hash);

void color_AddOrphanBlock(CBlock *block);

void color_RemoveOrphanBlock(const uint256& hash);

bool color_GetOrphanPrevHash(const uint256& hash, uint256& retPrevHash);

CBlock *color_GetOrphanBlock(const uint256& hash);

uint256 color_GetOrphanRoot(uint256 hash);

CBlock *color_GenerateNewBlock(CIface *iface, const CPubKey& rkey, uint160 hColor, vector<CTransaction> vTx, const color_opt& opt = color_opt());

bool color_VerifyGenesisBlock(const CBlock& block);

CBlockIndex *GetBestColorBlockIndex(CIface *iface, uint160 hColor);

bool GetColorBlockHeight(const uint256& hashBlock, unsigned int& nHeight);

bool GetColorBlockHeight(CBlockIndex *pindex, unsigned int& nHeight);

double color_CalculatePoolFeePriority(CPool *pool, CPoolTx *ptx, double dFeePrio = 0);

void color_GenerateNewBlockNonce(CIface *iface, CBlock *block);

void ParseColorOptScript(color_opt& opt, CScript script);

bool GetChainColorOpt(uint160 hColor, color_opt& opt);

bool GetChainColorOpt(CBlockIndex *pindex, color_opt& opt);

bool GetChainColorOpt(uint256 hBlock, color_opt& opt);

void SetChainColorOpt(uint160 hColor, color_opt& opt);

int64 color_GetMinTxFee(uint160 hColor);

int64 color_GetCoinbaseMaturity(uint160 hColor);

CBigNum color_GetMinDifficulty(uint160 hColor);

int64 color_GetBlockTarget(uint160 hColor);

int64 color_GetBlockValueBase(uint160 hColor);

int64 color_GetBlockValueRate(uint160 hColor);

/* Determine whether the alt-chain specified has any options defined that are not known in this node version. */
bool color_IsSupported(uint160 hColor);


/**
 * @}
 */

#endif /* ndef __COLOR_BLOCK_H__ */
