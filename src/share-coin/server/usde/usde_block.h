
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
// Copyright (c) 2011-2013 usde Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef __USDE_BLOCK_H__
#define __USDE_BLOCK_H__

#include <boost/assign/list_of.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>

#if 0
class USDE_CTxMemPool : public CTxMemPool
{

  public:
    bool accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs, bool* pfMissingInputs);
    bool addUnchecked(const uint256& hash, CTransaction &tx);
    bool remove(CTransaction &tx);
    void queryHashes(std::vector<uint256>& vtxid);

};
#endif

class USDEBlock : public CBlock
{
public:
    // header
    static const int CURRENT_VERSION=1;
    static USDE_CTxMemPool mempool; 
    static CBlockIndex *pindexBest;
    static CBlockIndex *pindexGenesisBlock;// = NULL;
    static CBigNum bnBestChainWork;// = 0;
    static CBigNum bnBestInvalidWork;// = 0;
    static int64 nTimeBestReceived ;//= 0;

    static int64 nTargetTimespan;
    static int64 nTargetSpacing;

    USDEBlock()
    {
        ifaceIndex = USDE_COIN_IFACE;
        SetNull();
    }
    USDEBlock(const CBlock &block)
    {
        ifaceIndex = USDE_COIN_IFACE;
        SetNull();
        *((CBlock*)this) = block;
    }

    void SetNull()
    {
      nVersion = USDEBlock::CURRENT_VERSION;
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
    bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    bool SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew);
#else
    bool DisconnectBlock(CBlockIndex* pindex);
    bool ConnectBlock(CBlockIndex* pindex);
    bool SetBestChain(CBlockIndex* pindexNew);
#endif

};



extern USDE_CTxMemPool USDE_mempool;

extern CBlockIndex* USDE_pindexGenesisBlock;
extern int USDE_nBestHeight;
extern CBigNum USDE_bnBestChainWork;
extern CBigNum USDE_bnBestInvalidWork;
extern uint256 USDE_hashBestChain;
extern CBlockIndex* USDE_pindexBest;
extern int64 USDE_nTimeBestReceived;

extern std::map<uint256, USDEBlock*> USDE_mapOrphanBlocks;
extern std::multimap<uint256, USDEBlock*> USDE_mapOrphanBlocksByPrev;
extern std::map<uint256, std::map<uint256, CDataStream*> > USDE_mapOrphanTransactionsByPrev;
extern std::map<uint256, CDataStream*> USDE_mapOrphanTransactions;
extern uint256 usde_hashGenesisBlock;



CBlock* usde_CreateNewBlock(const CPubKey& rkey);

bool usde_CreateGenesisBlock();

bool usde_SetBestChain(CBlock *block);


bool usde_ProcessBlock(CNode* pfrom, CBlock* pblock);

bool usde_CheckBlock(CBlock *block);

uint256 usde_GetOrphanRoot(const CBlock* pblock);

void usde_SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate);

int64 usde_GetBlockValue(int nHeight, int64 nFees);


#endif /* ndef __USDE_BLOCK_H__ */
