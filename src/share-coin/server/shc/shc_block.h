
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2013 shc Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


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



#if 0
class SHC_CTxMemPool : public CTxMemPool
{

  public:
    bool accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs, bool* pfMissingInputs);
    bool addUnchecked(const uint256& hash, CTransaction &tx);
    bool remove(CTransaction &tx);
    void queryHashes(std::vector<uint256>& vtxid);

};
#endif

class SHCBlock : public CBlock
{
public:
    // header
    static const int CURRENT_VERSION=2;
    static SHC_CTxMemPool mempool; 
    static CBlockIndex *pindexBest;
    static CBlockIndex *pindexGenesisBlock;
    static CBigNum bnBestChainWork;
    static CBigNum bnBestInvalidWork;
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

//  protected: bool SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew);

#ifdef USE_LEVELDB_COINDB
    bool SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew);
    bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex);
#else
    bool SetBestChain(CBlockIndex* pindexNew);
    bool ConnectBlock(CBlockIndex* pindex);
    bool DisconnectBlock(CBlockIndex* pindex);
#endif

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
extern CBigNum SHC_bnBestChainWork;
extern CBigNum SHC_bnBestInvalidWork;
extern uint256 SHC_hashBestChain;
extern int64 SHC_nTimeBestReceived;

extern std::map<uint256, SHCBlock*> SHC_mapOrphanBlocks;
extern std::multimap<uint256, SHCBlock*> SHC_mapOrphanBlocksByPrev;
extern std::map<uint256, std::map<uint256, CDataStream*> > SHC_mapOrphanTransactionsByPrev;
extern std::map<uint256, CDataStream*> SHC_mapOrphanTransactions;


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

/**
 * Get the first block in the best "alternate" chain not currently in the main block-chain.
 */
uint256 shc_GetOrphanRoot(const CBlock* pblock);

int64 shc_GetBlockValue(int nHeight, int64 nFees);


/**
 * @}
 */

#endif /* ndef __SHC_BLOCK_H__ */
