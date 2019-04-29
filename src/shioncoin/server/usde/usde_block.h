
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
 *
 *  This file is part of ShionCoin.
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

		bool CreateCheckpoint(); 

		int GetAlgo() const { return (0); }

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
extern uint256 USDE_hashBestChain;
extern CBlockIndex* USDE_pindexBest;
extern int64 USDE_nTimeBestReceived;
extern uint256 usde_hashGenesisBlock;

CBlock* usde_CreateNewBlock(const CPubKey& rkey);

bool usde_CreateGenesisBlock();

bool usde_SetBestChain(CBlock *block);


bool usde_ProcessBlock(CNode* pfrom, CBlock* pblock);

bool usde_CheckBlock(CBlock *block);

void usde_SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate);

int64 usde_GetBlockValue(int nHeight, int64 nFees);


bool usde_IsOrphanBlock(const uint256& hash); 
void usde_AddOrphanBlock(CBlock *block); 
void usde_RemoveOrphanBlock(const uint256& hash); 
bool usde_GetOrphanPrevHash(const uint256& hash, uint256& retPrevHash); 
CBlock *usde_GetOrphanBlock(const uint256& hash); 
uint256 usde_GetOrphanRoot(uint256 hash); 


#endif /* ndef __USDE_BLOCK_H__ */
