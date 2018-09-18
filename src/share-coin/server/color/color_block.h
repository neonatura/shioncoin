
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
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


class COLORBlock : public CBlock
{
public:
    static const int CURRENT_VERSION=2;

    static COLOR_CTxMemPool mempool; 
    static CBlockIndex *pindexBest;
    static CBlockIndex *pindexGenesisBlock;
    static CBigNum bnBestChainWork;
    static CBigNum bnBestInvalidWork;
    static int64 nTimeBestReceived;

		uint160 hColor;

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
extern CBigNum COLOR_bnBestChainWork;
extern CBigNum COLOR_bnBestInvalidWork;
extern uint256 COLOR_hashBestChain;
extern int64 COLOR_nTimeBestReceived;


/**
 * Generate the inital COLOR block in an alt block-chain.
 */
COLORBlock *color_CreateGenesisBlock(uint160 hColor);

/**
 * Set the best known block hash.
 */
bool color_SetBestChain(CBlock *block);

/**
 * Attempt to process an incoming block from a remote COLOR coin service.
 */
bool color_ProcessBlock(CNode* pfrom, CBlock* pblock);

int64 color_GetBlockValue(int nHeight, int64 nFees);

bool color_IsOrphanBlock(const uint256& hash);

void color_AddOrphanBlock(CBlock *block);

void color_RemoveOrphanBlock(const uint256& hash);

bool color_GetOrphanPrevHash(const uint256& hash, uint256& retPrevHash);

CBlock *color_GetOrphanBlock(const uint256& hash);

uint256 color_GetOrphanRoot(uint256 hash);

CBlock *color_GenerateNewBlock(CIface *iface, const CPubKey& rkey, uint160 hColor, vector<CTransaction> vTx);

bool color_VerifyGenesisBlock(const CBlock& block);

CBlockIndex *GetBestColorBlockIndex(CIface *iface, uint160 hColor);

bool GetColorBlockHeight(const uint256& hashBlock, unsigned int& nHeight);

bool GetColorBlockHeight(CBlockIndex *pindex, unsigned int& nHeight);

double color_CalculatePoolFeePriority(CPool *pool, CPoolTx *ptx, double dFeePrio = 0);

void color_GenerateNewBlockNonce(CIface *iface, CBlock *block);



/**
 * @}
 */

#endif /* ndef __COLOR_BLOCK_H__ */
