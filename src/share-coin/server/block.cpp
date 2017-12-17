
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

#include "shcoind.h"
#include "block.h"
#include "db.h"
#include <vector>
#include "spring.h"
#include "versionbits.h"
#include "wit_merkle.h"
#include "txmempool.h"
#include "coin.h"

using namespace std;

//map<uint256, CBlockIndex*> tableBlockIndex[MAX_COIN_IFACE];
blkidx_t tableBlockIndex[MAX_COIN_IFACE];
//vector <bc_t *> vBlockChain;

extern double GetDifficulty(int ifaceIndex, const CBlockIndex* blockindex = NULL);
extern std::string HexBits(unsigned int nBits);
extern void ScriptPubKeyToJSON(int ifaceIndex, const CScript& scriptPubKey, Object& out);



blkidx_t *GetBlockTable(int ifaceIndex)
{
#ifndef TEST_SHCOIND
  if (ifaceIndex == 0)
    return (NULL);
#endif
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  return (&tableBlockIndex[ifaceIndex]);
}

void CloseBlockChain(CIface *iface)
{
  if (iface->bc_block) {
    bc_close(iface->bc_block);
    iface->bc_block = NULL;
  }
  if (iface->bc_tx) {
    bc_close(iface->bc_tx);
    iface->bc_tx = NULL;
  }
  if (iface->bc_coin) {
    bc_close(iface->bc_coin);
    iface->bc_coin = NULL;
  }
}

CBlockIndex *GetBlockIndexByHeight(int ifaceIndex, unsigned int nHeight)
{
  CBlockIndex *pindex;

  pindex = GetBestBlockIndex(ifaceIndex);
  while (pindex && pindex->pprev && pindex->nHeight > nHeight)
    pindex = pindex->pprev;

  return (pindex);
}

CBlockIndex *GetBlockIndexByHash(int ifaceIndex, const uint256 hash)
{
  CBlockIndex *pindex;
  blkidx_t *blockIndex;

  blockIndex = GetBlockTable(ifaceIndex);
  if (!blockIndex)
    return (NULL);

  blkidx_t::iterator mi = blockIndex->find(hash);
  if (mi == blockIndex->end())
    return (NULL);

  return (mi->second);
}

json_spirit::Value ValueFromAmount(int64 amount)
{
    return (double)amount / (double)COIN;
}


#if 0
bool BlockChainErase(CIface *iface, size_t nHeight)
{
  bc_t *bc = GetBlockChain(iface);
  int err;

#if 0
  err = bc_purge(bc, nHeight);
  if (err)
    return error(err, "TruncateBlockChain[%s]: error truncating @ height %d.", iface->name, nHeight);
#endif
  int idx;
  int bestHeight = bc_idx_next(bc) - 1;
  for (idx = bestHeight; idx >= nHeight; idx--) {
    err = bc_idx_clear(bc, idx);
    if (err)
      return error(err, "BlockChainErase: error clearing height %d.", (int)nHeight);
  }

  return (true);
}
#endif

#if 0
bool BlockTxChainErase(uint256 hash)
{
return (true);
}

bool BlockChainErase(CIface *iface, size_t nHeight)
{
  bc_t *bc = GetBlockChain(iface);
  int bestHeight;
  int err;
  int idx;

  bestHeight = bc_idx_next(bc) - 1;
  if (nHeight < 0 || nHeight > bestHeight)
    return (true);

  CBlock *block = GetBlockByHeight(nHeight);
  if (block) {
    BOOST_FOREACH(const CTransaction &tx, block.vtx) {
      BlockTxChainErase(tx.GetHash());
    }
  }

  err = bc_idx_clear(bc, nHeight);
  if (err)
    return error(err, "BlockChainErase: error clearing height %d.", (int)nHeight);

  return (true);
}
#endif

void FreeBlockTable(CIface *iface)
{
  blkidx_t *blockIndex;
  char errbuf[1024];
  size_t memsize;
  size_t count;
  int ifaceIndex = GetCoinIndex(iface);

fprintf(stderr, "DEBUG: FreeBlockTable(%s)\n", iface->name);

  blockIndex = GetBlockTable(ifaceIndex);
  if (!blockIndex)
    return;

  vector<CBlockIndex *> removeList;
  BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, (*blockIndex)) 
  {
    CBlockIndex* pindex = item.second;
    removeList.push_back(pindex);
  }
  blockIndex->clear();

  count = 0;
  memsize = 0;
  BOOST_FOREACH(const CBlockIndex *pindex, removeList) 
  {
    memsize += sizeof(*pindex);
    count++;
    delete pindex;
  }

  if (iface->enabled) {
    sprintf(errbuf, "FreeBlockTable: deallocated %d records (%d bytes) in block-index.", count, memsize);
    unet_log(ifaceIndex, errbuf);
  }

}

/**
 * Closes all open block record databases.
 */
void CloseBlockChains(void)
{
  CIface *iface;
  int idx;

  for (idx = 0; idx < MAX_COIN_IFACE; idx++) {
#ifndef TEST_SHCOIND
    if (idx == 0) continue;
#endif

    iface = GetCoinByIndex(idx);
    if (!iface)
      continue;

    FreeBlockTable(iface);
    CloseBlockChain(iface);
  }
}

#if 0
bc_t *GetBlockChain(char *name)
{
  bc_t *bc;

  for(vector<bc_t *>::iterator it = vBlockChain.begin(); it != vBlockChain.end(); ++it) {
    bc = *it;
    if (0 == strcmp(bc_name(bc), name))
      return (bc);
  }

  bc_open(name, &bc);
  vBlockChain.push_back(bc);

  return (bc);
}

/**
 * Closes all open block record databases.
 */
void CloseBlockChains(void)
{
  bc_t *bc;

  for(vector<bc_t *>::iterator it = vBlockChain.begin(); it != vBlockChain.end(); ++it) {
    bc_t *bc = *it;
    bc_close(bc);
  }
  vBlockChain.clear();

}
#endif


int64 GetInitialBlockValue(int nHeight, int64 nFees)
{
  int64 nSubsidy = 4000 * COIN;

  if ((nHeight % 100) == 1)
  {
    nSubsidy = 100000 * COIN; //100k
  }else if ((nHeight % 50) == 1)
  {
    nSubsidy = 50000 * COIN; //50k
  }else if ((nHeight % 20) == 1)
  {
    nSubsidy = 20000 * COIN; //20k
  }else if ((nHeight % 10) == 1)
  {
    nSubsidy = 10000 * COIN; //10k
  }else if ((nHeight % 5) == 1)
  {
    nSubsidy = 5000 * COIN; //5k
  }

  //limit first blocks to protect against instamine.
  if (nHeight < 2){
    nSubsidy = 24000000 * COIN; // 1.5%
  }else if(nHeight < 500)
  {
    nSubsidy = 100 * COIN;
  }
  else if(nHeight < 1000)
  {
    nSubsidy = 500 * COIN;
  }

  nSubsidy >>= (nHeight / 139604);

  return (nSubsidy + nFees);
}

#if 0
int64 GetBlockValue(int nHeight, int64 nFees)
{
  int64 nSubsidy = 4000 * COIN;
  int base = nHeight;

  if (nHeight < 107500) {
    return (GetInitialBlockValue(nHeight, nFees));
  }

#if CLIENT_VERSION_REVISION > 4
  if (nHeight >= 1675248) {
    /* transition from 1.6bil cap to 1.6tril cap. */
    base /= 9;
  }
#endif

  nSubsidy >>= (base / 139604);

#if CLIENT_VERSION_REVISION > 4
  if (nHeight >= 1675248) {
    /* balance flux of reward. reduces max coin cap to 320bil */
    nSubsidy /= 5;
  }
#endif

  return nSubsidy + nFees;
}
#endif






#if 0
typedef map<uint256,int> tx_index_table_t;
static tx_index_table_t tx_index_table[MAX_COIN_IFACE];

tx_index_table_t *GetTxIndexTable(int ifaceIndex)
{

  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);

  return (&tx_index_table[ifaceIndex]);
}

int GetTxIndex(int ifaceIndex, uint256 txHash, int *txPos)
{
  tx_index_table_t *table;

  table = GetTxIndexTable(ifaceIndex);
  if (!table)
    return (SHERR_INVAL);

  tx_index_table_t::iterator mi = table->find(txHash);
  if (mi == table->end())
    return (SHERR_NOENT);

  *txPos = (*table)[txHash];
  return (0);
}

int SetTxIndex(int ifaceIndex, uint256 txHash, int txPos)
{
  tx_index_table_t *table;

  table = GetTxIndexTable(ifaceIndex);
  if (!table)
    return (SHERR_INVAL);

  (*table)[txHash] = txPos;
  return (0);
}

void EraseTxIndex(int ifaceIndex, uint256 txHash)
{
  tx_index_table_t *table;

  table = GetTxIndexTable(ifaceIndex);
  if (!table)
    return;

  table->erase(txHash);
}

int GetTxIndexCount(int ifaceIndex)
{
  tx_index_table_t *table;

  table = GetTxIndexTable(ifaceIndex);
  if (!table)
    return (0);

  return ((int)table->size());
}
#endif





const CTransaction *CBlock::GetTx(uint256 hash)
{
  BOOST_FOREACH(const CTransaction& tx, vtx)
    if (tx.GetHash() == hash)
      return (&tx);
  return (NULL);
}

bool CTransaction::WriteTx(int ifaceIndex, uint64_t blockHeight)
{
  bc_t *bc = GetBlockTxChain(GetCoinByIndex(ifaceIndex));
  uint256 hash = GetHash();
  char errbuf[1024];
  uint64_t blockPos;
  int txPos;
  int err;

  if (!bc) {
    unet_log(ifaceIndex, "CTransaction::WriteTx: error opening tx chain.");
    return (false);
  }

  err = bc_idx_find(bc, hash.GetRaw(), NULL, &txPos);
  if (!err) { /* exists */
    unsigned char *data;
    size_t data_len;

    err = bc_get(bc, txPos, &data, &data_len);
    if (!err) {
      if (data_len == sizeof(uint64_t)) {
        memcpy(&blockPos, data, sizeof(blockHeight));
        if (blockPos == blockHeight)
          return (true); /* and all is good */
      }
      free(data);

#if 0
      err = bc_idx_clear(bc, txPos);
      if (err)
        return error(err, "WriteTx; error clearing invalid previous hash tx [tx-idx-size %d] [tx-pos %d].", (int)data_len, (int)txPos);
#endif
    } else {
fprintf(stderr, "DEBUG: critical: CTransaction.WriteTx: bc_get error %d\n", err); 

    /* force re-open */
      CIface *iface = GetCoinByIndex(ifaceIndex);
      CloseBlockChain(iface);
      CloseBlockChain(iface);

      return (false);
    }
  }
#if 0
  if (0 == bc_idx_find(bc, hash.GetRaw(), NULL, NULL)) {
    /* transaction reference exists */
    return (true);
  }
#endif

  /* reference block height */
  err = bc_append(bc, hash.GetRaw(), &blockHeight, sizeof(blockHeight));
  if (err < 0) {
    sprintf(errbuf, "CTransaction::WriteTx: error writing block reference: %s.", sherrstr(err));
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

#if 0
  /* set cache entry */
  SetTxIndex(ifaceIndex, hash, err); 
#endif

  return (true);
}

bool CTransaction::ReadTx(int ifaceIndex, uint256 txHash)
{
  return (ReadTx(ifaceIndex, txHash, NULL));
}


bool CTransaction::ReadTx(int ifaceIndex, uint256 txHash, uint256 *hashBlock)
{
  CIface *iface;
  bc_t *bc;
  char errbuf[1024];
  unsigned char *data;
  uint64_t blockHeight;
  size_t data_len;
  int txPos;
  int err;

  SetNull();

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface) {
    sprintf(errbuf, "CTransaction::ReadTx: unable to obtain iface #%d.", ifaceIndex); 
    return error(SHERR_INVAL, errbuf);
  }

  bc = GetBlockTxChain(iface);
  if (!bc) { 
    return error(SHERR_INVAL, "CTransaction::ReadTx: unable to open block tx database."); 
  }

  err = bc_idx_find(bc, txHash.GetRaw(), NULL, &txPos); 
  if (err) {
    return (false); /* not an error condition */
  }

  err = bc_get(bc, txPos, &data, &data_len);
  if (err) {
    sprintf(errbuf, "CTransaction::ReadTx: tx position %d not found.", txPos);
    return error(err, errbuf);
  }
  if (data_len != sizeof(uint64_t)) {
    sprintf(errbuf, "CTransaction::ReadTx: block reference has invalid size (%d).", data_len);
    return error(SHERR_INVAL, errbuf);
  }
  memcpy(&blockHeight, data, sizeof(blockHeight));
  free(data);

  CBlock *block = GetBlankBlock(iface);
  if (!block) { 
    return error(SHERR_NOMEM, 
        "CTransaction::ReadTx: error allocating new block\n");
  }
  if (!block->ReadBlock(blockHeight)) {
    delete block;
    return error(SHERR_NOENT, "CTransaction::ReadTx: block height %d not valid.", blockHeight);
  }

  const CTransaction *tx = block->GetTx(txHash);
  if (!tx) {
    sprintf(errbuf, "CTransaction::ReadTx: block height %d does not contain tx.", blockHeight);
    delete block;
    return error(SHERR_INVAL, errbuf);
  }

  if (hashBlock) {
    *hashBlock = block->GetHash();
//    if (*hashBlock == 0) { fprintf(stderr, "DEBUG: ReadTx: invalid hash 0 \n"); }
  }

  Init(*tx);
  delete block;

  return (true);
}



bool GetTransaction(CIface *iface, const uint256 &hash, CTransaction &tx, uint256 *hashBlock)
{
  return (tx.ReadTx(GetCoinIndex(iface), hash, hashBlock));
}

CBlock *GetBlockByHeight(CIface *iface, int nHeight)
{
  int ifaceIndex = GetCoinIndex(iface);
  CTransaction tx;
  CBlock *block;
  int err;
  
  /* sanity */
  if (!iface)
    return (NULL);

  block = GetBlankBlock(iface);
  if (!block)
    return (NULL);

  if (!block->ReadBlock(nHeight))
    return (NULL);

  return (block);
}

CBlock *GetBlockByHash(CIface *iface, const uint256 hash)
{
  int ifaceIndex = GetCoinIndex(iface);
  CBlockIndex *pindex;
  CTransaction tx;
  CBlock *block;
  int err;
  
  /* sanity */
  if (!iface)
    return (NULL);

  pindex = GetBlockIndexByHash(ifaceIndex, hash);
  if (!pindex)
    return (NULL);

  /* generate block */
  block = GetBlankBlock(iface);
  if (!block)
    return (NULL);

  if (!block->ReadFromDisk(pindex))
    return (NULL);

  /* verify integrity */
  if (block->GetHash() != hash)
    return (NULL);

  return (block);
}

CBlock *GetArchBlockByHash(CIface *iface, const uint256 hash)
{
  CBlock *block;
  int err;
  
  /* sanity */
  if (!iface)
    return (NULL);

  /* generate block */
  block = GetBlankBlock(iface);
  if (!block)
    return (NULL);

  if (!block->ReadArchBlock(hash)) {
    delete block;
    return (NULL);
  }

  return (block);
}

CBlock *GetBlockByTx(CIface *iface, const uint256 hash)
{
  int ifaceIndex = GetCoinIndex(iface);
  CTransaction tx;
  CBlock *block;
  uint256 hashBlock;

  /* sanity */
  if (!iface)
    return (NULL);

  /* figure out block hash */
  if (!tx.ReadTx(GetCoinIndex(iface), hash, &hashBlock))
    return (NULL);

  return (GetBlockByHash(iface, hashBlock));
}

CBlockIndex *GetBlockIndexByTx(CIface *iface, const uint256 hash)
{
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
  CTransaction tx;
  CBlock *block;
  uint256 hashBlock;

  /* sanity */
  if (!iface)
    return (NULL);

  /* figure out block hash */
  if (!tx.ReadTx(GetCoinIndex(iface), hash, &hashBlock))
    return (NULL);

  map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hashBlock);
  if (mi == blockIndex->end()) 
    return (NULL);

  return (mi->second);
}

CBlock *CreateBlockTemplate(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  CBlock *block;
  char errbuf[256];
  int err;

  if (!iface->op_block_templ)
    return (NULL);

  block = NULL;
  err = iface->op_block_templ(iface, &block); 
  if (err) {
    sprintf(errbuf, "CreateBlockTemplate: error creating block template: %s.", sherrstr(err));
    unet_log(ifaceIndex, errbuf);
  }

  return (block);
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
  int err;

  if (!iface)
    return (false);

  if (!iface->op_block_process)
    return error(SHERR_OPNOTSUPP, "ProcessBlock[%s]: no block process operation suported.", iface->name);

  /* trace whether remote host submitted block */
  pblock->originPeer = pfrom;

  err = iface->op_block_process(iface, pblock);
  if (err) {
    char errbuf[1024];

    sprintf(errbuf, "error processing incoming block: %s [sherr %d].", sherrstr(err), err); 
    unet_log(pblock->ifaceIndex, errbuf);
    return (false);
  }

  return (true);
}





bool CTransaction::ClientConnectInputs(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTxMemPool *pool;

  if (!iface) {
    unet_log(ifaceIndex, "error obtaining coin interface.");
    return (false);
  }

  pool = GetTxMemPool(iface);
  if (!pool) {
    unet_log(ifaceIndex, "error obtaining tx memory pool.");
    return (false);
  }

  if (IsCoinBase())
    return false;

  // Take over previous transactions' spent pointers
  {
    int64 nValueIn = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
      // Get prev tx from single transactions in memory
      COutPoint prevout = vin[i].prevout;
      if (!pool->exists(prevout.hash))
        return false;
      CTransaction& txPrev = pool->lookup(prevout.hash);

      if (prevout.n >= txPrev.vout.size())
        return false;

      // Verify signature
      if (!VerifySignature(ifaceIndex, txPrev, *this, i, true, 0))
        return error(SHERR_INVAL, "ConnectInputs() : VerifySignature failed");

      ///// this is redundant with the mempool.mapNextTx stuff,
      ///// not sure which I want to get rid of
      ///// this has to go away now that posNext is gone
      // // Check for conflicts
      // if (!txPrev.vout[prevout.n].posNext.IsNull())
      //     return error("ConnectInputs() : prev tx already used");
      //
      // // Flag outpoints as used
      // txPrev.vout[prevout.n].posNext = posThisTx;

      nValueIn += txPrev.vout[prevout.n].nValue;

      if (!MoneyRange(ifaceIndex, txPrev.vout[prevout.n].nValue) || 
          !MoneyRange(ifaceIndex, nValueIn))
        return error(SHERR_INVAL, "ClientConnectInputs() : txin values out of range");
    }
    if (GetValueOut() > nValueIn)
      return false;
  }

  return true;
}



#if 0
bool CBlockIndex::IsInMainChain(int ifaceIndex) const
{
  if (pnext)
    return (true);
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface) return (false);
  CBlock *block = GetBlockByHash(iface, GetBlockHash()); 
  if (!block) return (false);
  bool ret = block->IsBestChain();
  delete block;
  return (ret);
} 
#endif

bool CBlockIndex::IsInMainChain(int ifaceIndex) const
{
  if (pnext)
    return (true); /* has valid parent */

  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  if (pindexBest && GetBlockHash() == pindexBest->GetBlockHash());
    return (true);

  return (false);
}

uint256 CBlockLocator::GetBlockHash()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CBlockIndex *pindex;

  // Find the first block the caller has in the main chain
  BOOST_FOREACH(const uint256& hash, vHave)
  {
    pindex = GetBlockIndexByHash(ifaceIndex, hash);
    if (pindex && pindex->IsInMainChain(ifaceIndex))
      return hash;
  }
  return GetGenesisBlockHash(ifaceIndex);
}
#if 0
uint256 CBlockLocator::GetBlockHash()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 

  // Find the first block the caller has in the main chain
  BOOST_FOREACH(const uint256& hash, vHave)
  {
    std::map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hash);
    if (mi != blockIndex->end())
    {
      CBlockIndex* pindex = (*mi).second;
      if (pindex->IsInMainChain(ifaceIndex))
        return hash;
    }
  }

  CBlock *block = GetBlockByHeight(iface, 0);
  if (!block) {
    uint256 hash;
    return (hash);
  }
  uint256 hashBlock = block->GetHash();
  delete block;
  return hashBlock;
//  return block->hashGenesisBlock;
}
#endif


int CBlockLocator::GetHeight()
{
  CBlockIndex* pindex = GetBlockIndex();
  if (!pindex)
    return 0;
  return pindex->nHeight;
}


CBlockIndex* CBlockLocator::GetBlockIndex()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CBlockIndex *pindex;

  // Find the first block the caller has in the main chain
  BOOST_FOREACH(const uint256& hash, vHave)
  {
    pindex = GetBlockIndexByHash(ifaceIndex, hash);
    if (pindex && pindex->IsInMainChain(ifaceIndex))
      return pindex;
  }

  return (GetGenesisBlockIndex(iface));
}


void CBlockLocator::Set(const CBlockIndex* pindex)
{
  vHave.clear();
  int nStep = 1;
  while (pindex)
  {
    vHave.push_back(pindex->GetBlockHash());

    // Exponentially larger steps back
    for (int i = 0; pindex && i < nStep; i++)
      pindex = pindex->pprev;
    if (vHave.size() > 10)
      nStep *= 2;
  }
  vHave.push_back(GetGenesisBlockHash(ifaceIndex));
}
#if 0
void CBlockLocator::Set(const CBlockIndex* pindex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  int nStep = 1;

  vHave.clear();
  while (pindex)
  {
    vHave.push_back(pindex->GetBlockHash());

    // Exponentially larger steps back
    for (int i = 0; pindex && i < nStep; i++)
      pindex = pindex->pprev;
    if (vHave.size() > 10)
      nStep *= 2;
  }

  /* all the way back */
  pindex = 
  CBlock *block = GetBlockByHeight(iface, 0);
  if (block) {
    uint256 hashBlock = block->GetHash();
    vHave.push_back(hashBlock);// hashGenesisBlock);
    delete block; 
  }
}
#endif



int CBlockLocator::GetDistanceBack()
{
  CBlockIndex *pindex;

  // Retrace how far back it was in the sender's branch
  int nDistance = 0;
  int nStep = 1;
  BOOST_FOREACH(const uint256& hash, vHave)
  {
    pindex = GetBlockIndexByHash(ifaceIndex, hash);
    if (pindex && pindex->IsInMainChain(ifaceIndex))
      return nDistance;

    nDistance += nStep;
    if (nDistance > 10)
      nStep *= 2;
  }
  return nDistance;
}

int GetBestHeight(CIface *iface)
{
  CBlockIndex *pindex = GetBestBlockIndex(iface);
  if (!pindex)
    return (-1);
  return (pindex->nHeight);
}
int GetBestHeight(int ifaceIndex)
{
  return (GetBestHeight(GetCoinByIndex(ifaceIndex)));
}

bool IsInitialBlockDownload(int ifaceIndex)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);

  if (pindexBest == NULL)
    return true;

  static int64 nLastUpdate;
  static CBlockIndex* pindexLastBest;
  if (pindexBest != pindexLastBest)
  {
    pindexLastBest = pindexBest;
    nLastUpdate = GetTime();
  }
  return (GetTime() - nLastUpdate < 15 &&
      pindexBest->GetBlockTime() < GetTime() - 24 * 60 * 60);
}

uint256 GetBestBlockChain(CIface *iface)
{
  uint256 hash;
  hash.SetRaw(iface->block_besthash);
  return (hash);
}

CBlockIndex *GetGenesisBlockIndex(CIface *iface) /* DEBUG: */
{
  int ifaceIndex = GetCoinIndex(iface);
  CBlock *block = GetBlockByHeight(iface, 0);
  if (!block)
    return (NULL);

  uint256 hash = block->GetHash();
  delete block;

  return (GetBlockIndexByHash(ifaceIndex, hash));
}

void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
  nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());
}

bool CTransaction::IsFinal(int ifaceIndex, int nBlockHeight, int64 nBlockTime) const
{
  // Time based nLockTime implemented in 0.1.6
  if (nLockTime == 0)
    return true;
  if (nBlockHeight == 0)
    nBlockHeight = GetBestHeight(ifaceIndex);
  if (nBlockTime == 0)
    nBlockTime = GetAdjustedTime();
  if ((int64)nLockTime < ((int64)nLockTime < LOCKTIME_THRESHOLD ? (int64)nBlockHeight : nBlockTime))
    return true;
  BOOST_FOREACH(const CTxIn& txin, vin)
    if (!txin.IsFinal())
      return false;
  return true;
}


void SetBestBlockIndex(CIface *iface, CBlockIndex *pindex)
{
  if (!pindex)
    return;
  uint256 hash = pindex->GetBlockHash();
  memcpy(iface->block_besthash, hash.GetRaw(), sizeof(bc_hash_t));
}
void SetBestBlockIndex(int ifaceIndex, CBlockIndex *pindex)
{
  SetBestBlockIndex(GetCoinByIndex(ifaceIndex), pindex);
}
CBlockIndex *GetBestBlockIndex(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  uint256 hash;

  hash.SetRaw(iface->block_besthash);
  return (GetBlockIndexByHash(ifaceIndex, hash));
}
CBlockIndex *GetBestBlockIndex(int ifaceIndex)
{
  return (GetBestBlockIndex(GetCoinByIndex(ifaceIndex)));
}

CBlock *GetBlankBlock(CIface *iface)
{
  CBlock *block;
  int err;

  if (!iface || !iface->op_block_new)
    return (NULL);

  block = NULL;
  err = iface->op_block_new(iface, &block);
  if (err) {
    int ifaceIndex = GetCoinIndex(iface);
    char errbuf[1024];

    sprintf(errbuf, "GetBlankBlock: error generating fresh block: %s [sherr %d].", sherrstr(err), err);
    unet_log(ifaceIndex, errbuf); 
  }

  return (block);
}
#if 0
CBlock *GetBlankBlock(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  CBlock *block;

  block = NULL;
  switch (ifaceIndex) {
    case SHC_COIN_IFACE:
      block = new SHCBlock();
      break;
    case USDE_COIN_IFACE:
      block = new USDEBlock();
      break;
  }

  return (block);
}
#endif

/* DEBUG: TODO: faster to read via nHeight */
bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc;
  int nHeight;
  int err;

  if (!iface)
    return (false);

  bc = GetBlockChain(iface);
  if (!bc)
    return (false);

  err = bc_find(bc, pindex->GetBlockHash().GetRaw(), &nHeight);
  if (err)
    return false;//error(err, "bc_find '%s' [height %d]", pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight);

  return (ReadBlock(nHeight));
}

bool CTransaction::CheckTransaction(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!iface)
    return (false);

  // Basic checks that don't depend on any context
  if (vin.empty())
    return error(SHERR_INVAL, "CTransaction::CheckTransaction() : vin empty");
  if (vout.empty())
    return error(SHERR_INVAL, "CTransaction::CheckTransaction() : vout empty");
  // Size limits
  if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION(iface)) > iface->max_block_size)
    return error(SHERR_INVAL, "CTransaction::CheckTransaction() : size limits failed");

  // Check for negative or overflow output values
  int64 nValueOut = 0;
  BOOST_FOREACH(const CTxOut& txout, vout)
  {
    if (txout.nValue < 0)
      return error(SHERR_INVAL, "CTransaction.CheckTransaction: invalid coin output [negative value]: %s", ToString(ifaceIndex).c_str());
    if (txout.nValue > iface->max_money)
      return error(SHERR_INVAL, "CTransaction::CheckTransaction() : txout.nValue too high");
    nValueOut += txout.nValue;
    if (!MoneyRange(ifaceIndex, nValueOut))
      return error(SHERR_INVAL, "CTransaction::CheckTransaction() : txout total out of range");
  }

  // Check for duplicate inputs
  set<COutPoint> vInOutPoints;
  BOOST_FOREACH(const CTxIn& txin, vin)
  {
    if (vInOutPoints.count(txin.prevout)) {
      return error(SHERR_INVAL, "CTransaction::CheckTransaction: duplicate input specified.\n");
}
    vInOutPoints.insert(txin.prevout);
  }

  if (IsCoinBase())
  {
    if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
      return error(SHERR_INVAL, "CTransaction::CheckTransaction() : coinbase script size invalid (2 < (%d) < 100)", vin[0].scriptSig.size());
  }
  else
  {
    BOOST_FOREACH(const CTxIn& txin, vin) {
      if (txin.prevout.IsNull()) {
        return error(SHERR_INVAL, "(core) CheckTransaction: prevout is null");
      }
#if 0 
      if (!VerifyTxHash(iface, txin.prevout.hash)) {
        print();
        return error(SHERR_INVAL, "(core) CheckTransaction: unknown prevout hash '%s'", txin.prevout.hash.GetHex().c_str());
      }
#endif
    }
  }

  return true;
}

/**
 * Verify that the transactions being referenced as inputs are valid.
 */
bool CTransaction::CheckTransactionInputs(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!iface)
    return (false);

  if (IsCoinBase())
    return (true);

  if (vin.empty())
    return error(SHERR_INVAL, "(core) CheckTransaction: vin empty");

  BOOST_FOREACH(const CTxIn& txin, vin) {
    if (txin.prevout.IsNull()) {
      return error(SHERR_INVAL, "(core) CheckTransactionInputs: prevout is null");
    }

    if (!VerifyTxHash(iface, txin.prevout.hash)) {
      return error(SHERR_INVAL, "(core) CheckTransactionInputs: unknown prevout hash '%s'", txin.prevout.hash.GetHex().c_str());
    }
  }

  return true;
}

bool CBlock::CheckTransactionInputs(int ifaceIndex)
{

  BOOST_FOREACH(CTransaction& tx, vtx) {
    bool fInBlock = false;
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
      BOOST_FOREACH(const CTransaction& t_tx, vtx) {
        if (tx != t_tx && t_tx.GetHash() == txin.prevout.hash) {
          fInBlock = true;
          break;
        }
      }
    }
    if (fInBlock)
      continue;

    if (!tx.CheckTransactionInputs(ifaceIndex))
      return (false);
  }

  return (true);
}

bool CBlock::WriteBlock(uint64_t nHeight)
{
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockChain(iface);
  uint64_t idx_next;
  unsigned int blockPos;
  long sBlockLen;
  char *sBlockData;
  int n_height;
  int err;

  if (!bc)
    return (false);

  uint256 hash = GetHash();

  /* check for existing record saved at height position */
  bc_hash_t rawhash;
  err = bc_get_hash(bc, (bcsize_t)nHeight, rawhash); 
  if (!err) { /* exists */
    uint256 t_hash;
    t_hash.SetRaw(rawhash);
    if (t_hash == hash)
      return (true); /* same hash as already written block */
    err = bc_clear(bc, nHeight);
    if (err)
      return error(err, "WriteBlock: clear block position %d.", (int)nHeight);
    bc_table_reset(bc, rawhash);
  }

  /* serialize into binary */
  sBlock << *this;
  sBlockLen = sBlock.size();
  sBlockData = (char *)calloc(sBlockLen, sizeof(char));
  if (!sBlockData)
    return error(SHERR_NOMEM, "allocating %d bytes for block data\n", (int)sBlockLen);
  sBlock.read(sBlockData, sBlockLen);
  n_height = bc_write(bc, nHeight, hash.GetRaw(), sBlockData, sBlockLen);
  if (n_height < 0)
    return error(SHERR_INVAL, "block-chain write: %s", sherrstr(n_height));
  free(sBlockData);

  /* write tx ref's */
  BOOST_FOREACH(CTransaction& tx, vtx) {
    tx.WriteTx(ifaceIndex, nHeight); 
  }

  trust(1, "healthy block processed");
  Debug("WriteBlock: %s @ height %u\n", hash.GetHex().c_str(), (unsigned int)nHeight);

  return (true);
}

bool CBlock::WriteArchBlock()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockChain(iface);
  uint64_t idx_next;
  unsigned int blockPos;
  long sBlockLen;
  char *sBlockData;
  int n_height;
  int err;

  if (!bc)
    return (false);

  uint256 hash = GetHash();

  /* serialize into binary */
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
  sBlock << *this;
  sBlockLen = sBlock.size();
  sBlockData = (char *)calloc(sBlockLen, sizeof(char));
  if (!sBlockData)
    return error(SHERR_NOMEM, "allocating %d bytes for block data\n", (int)sBlockLen);
  sBlock.read(sBlockData, sBlockLen);
  n_height = bc_arch_write(bc, hash.GetRaw(), sBlockData, sBlockLen);
  free(sBlockData);
  if (n_height < 0)
    return error(SHERR_INVAL, "block-chain write: %s", sherrstr(n_height));

  Debug("WriteArchBlock: %s", ToString().c_str());
  return (true);
}

bool VerifyTxHash(CIface *iface, uint256 hashTx)
{
  bc_t *bc = GetBlockTxChain(iface);
  int err;

  err = bc_idx_find(bc, hashTx.GetRaw(), NULL, NULL);
  if (err)
    return (false);

  return (true);
}


bool CTransaction::EraseTx(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockTxChain(iface);
  uint256 hash = GetHash();
  int posTx;
  int err;

  err = bc_find(bc, hash.GetRaw(), &posTx);
  if (err)
    return error(err, "CTransaction::EraseTx: tx '%s' not found.", GetHash().GetHex().c_str());

  bc_table_reset(bc, hash.GetRaw());
  err = bc_idx_clear(bc, posTx);
  if (err)
    return error(err, "CTransaction::EraseTx: error clearing tx pos %d.", posTx);


#if 0
  /* clear cache entry */
  EraseTxIndex(ifaceIndex, hash);
#endif
 
  Debug("CTransaction::EraseTx: cleared tx '%s'.", GetHash().GetHex().c_str());
  return (true);
}


uint256 GetGenesisBlockHash(int ifaceIndex)
{
  uint256 hash;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CBlock *block = GetBlockByHeight(iface, 0); 
  if (!block)
    return (false);
  hash = block->GetHash();
  delete block;
  return (hash);
}

extern int ProcessExecTx(CIface *iface, CNode *pfrom, CTransaction& tx);


/**
 * The core method of accepting a new block onto the block-chain.
 */
bool core_AcceptBlock(CBlock *pblock, CBlockIndex *pindexPrev)
{
  int ifaceIndex = pblock->ifaceIndex;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  uint256 hash = pblock->GetHash();
  shtime_t ts;
  bool ret;

  if (!pblock || !pindexPrev) {
    return error(SHERR_INVAL, "(core) AcceptBlock: invalid parameter.");
  }

  if (GetBlockIndexByHash(ifaceIndex, hash)) {
    return error(SHERR_INVAL, "(core) AcceptBlock: block already in chain.");
  }

  unsigned int nHeight = pindexPrev->nHeight+1;

  /* check proof of work */
  unsigned int nBits = pblock->GetNextWorkRequired(pindexPrev);
  if (pblock->nBits != nBits) {
    return (pblock->trust(-100, "(core) AcceptBlock: invalid difficulty (%x) specified (next work required is %x) for block height %d [prev '%s']\n", pblock->nBits, nBits, nHeight, pindexPrev->GetBlockHash().GetHex().c_str()));
  }

  BOOST_FOREACH(const CTransaction& tx, pblock->vtx) {
#if 0 /* not standard */
    if (!tx.IsCoinBase()) { // Check that all inputs exist
      BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        if (txin.prevout.IsNull())
          return error(SHERR_INVAL, "AcceptBlock(): prevout is null");
        if (!VerifyTxHash(iface, txin.prevout.hash))
          return error(SHERR_INVAL, "AcceptBlock(): unknown prevout hash '%s'", txin.prevout.hash.GetHex().c_str());
      }
    }
#endif

    /* check that all transactions are finalized. */ 
    if (!tx.IsFinal(ifaceIndex, nHeight, pblock->GetBlockTime())) {
      return (pblock->trust(-10, "(core) AcceptBlock: block contains a non-final transaction at height %u", nHeight));
    }
  }

  /* check that the block matches the known block hash for last checkpoint. */
  if (!pblock->VerifyCheckpoint(nHeight)) {
    return (pblock->trust(-100, "(core) AcceptBlock: rejected by checkpoint lockin at height %u", nHeight));
  }

  ret = pblock->AddToBlockIndex();
  if (!ret) {
    pblock->print();
    return error(SHERR_IO, "AcceptBlock: AddToBlockIndex failed");
  }

  /* inventory relay */
  int nBlockEstimate = pblock->GetTotalBlocksEstimate();
  if (GetBestBlockChain(iface) == hash) {
    timing_init("AcceptBlock:PushInventory", &ts);
    NodeList &vNodes = GetNodeList(ifaceIndex);
    {
      LOCK(cs_vNodes);
      BOOST_FOREACH(CNode* pnode, vNodes) {
        if (GetBestHeight(iface) > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate)) {
          pnode->PushInventory(CInv(ifaceIndex, MSG_BLOCK, hash));
        }
      }
    }
    timing_term(ifaceIndex, "AcceptBlock:PushInventory", &ts);
  }

  if (ifaceIndex == TEST_COIN_IFACE ||
      ifaceIndex == SHC_COIN_IFACE) {
    BOOST_FOREACH(CTransaction& tx, pblock->vtx) {
      if (tx.isFlag(CTransaction::TXF_CERTIFICATE)) {
        InsertCertTable(iface, tx, nHeight);
      }
      if (tx.isFlag(CTransaction::TXF_IDENT)) {
        InsertIdentTable(iface, tx);
      }
      if (tx.isFlag(CTransaction::TXF_EXEC)) {
        ProcessExecTx(iface, pblock->originPeer, tx);
      }
      if (tx.isFlag(CTransaction::TXF_ALIAS)) {
        bool fRet = CommitAliasTx(iface, tx, nHeight);
        if (!fRet) {
          error(SHERR_INVAL, "CommitAliasTx failure");
        }
      }
      if (tx.isFlag(CTransaction::TXF_LICENSE)) {
        bool fRet = CommitLicenseTx(iface, tx, nHeight);
        if (!fRet) {
          error(SHERR_INVAL, "CommitLicenseTx failure");
        }
      }
      if (tx.isFlag(CTransaction::TXF_CONTEXT)) {
        int err = CommitContextTx(iface, tx, nHeight);
        if (err) {
          error(err, "CommitContextTx failure");
        }
      }
    }
  }

  STAT_BLOCK_ACCEPTS(iface)++;
  return true;
}

bool CTransaction::IsStandard() const
{

  if (!isFlag(CTransaction::TX_VERSION) &&
      !isFlag(CTransaction::TX_VERSION_2)) {
    return error(SHERR_INVAL, "version flag not set (%d) [CTransaction::IsStandard]", nFlag);
  }

  BOOST_FOREACH(const CTxIn& txin, vin)
  {


    // Biggest 'standard' txin is a 3-signature 3-of-3 CHECKMULTISIG
    // pay-to-script-hash, which is 3 ~80-byte signatures, 3
    // ~65-byte public keys, plus a few script ops.
    if (txin.scriptSig.size() > 500) {
      return error(SHERR_INVAL, "script-sig size > 500 [CTransaction::IsStandard]");
    }
    if (!txin.scriptSig.IsPushOnly()) {
      return error(SHERR_INVAL, "script-sig is push-only [CTransaction::IsStandard]");
    }
  }

  BOOST_FOREACH(const CTxOut& txout, vout) {
    if (!::IsStandard(txout.scriptPubKey)) {
      return error(SHERR_INVAL, "pub key is not standard [CTransaction::IsStandard] %s", txout.scriptPubKey.ToString().c_str());
    }
  }

  return true;
}



CAlias *CTransaction::CreateAlias(std::string name, const uint160& hash, int type)
{
  nFlag |= CTransaction::TXF_ALIAS;

  //alias = CAlias(name, hash);
  alias = CAlias();
  alias.SetExpireSpan((double)DEFAULT_ALIAS_LIFESPAN);
  alias.SetLabel(name);
  alias.SetType(type);

  return (&alias);
}
CAlias *CTransaction::UpdateAlias(std::string name, const uint160& hash)
{
  nFlag |= CTransaction::TXF_ALIAS;

//  alias = CAlias(name, hash);
  alias = CAlias();
  alias.SetExpireSpan((double)DEFAULT_ALIAS_LIFESPAN);
  alias.SetLabel(name);

  return (&alias);
}
CAlias *CTransaction::RemoveAlias(std::string name)
{
  nFlag |= CTransaction::TXF_ALIAS;

  alias = CAlias();
  alias.SetExpireSpan((double)DEFAULT_ALIAS_LIFESPAN);
  alias.SetLabel(name);
  return (&alias);
}

/*
CIdent *CTransaction::CreateEntity(const char *name, cbuff secret)
{

  if (nFlag & CTransaction::TXF_ENTITY)
    return (NULL);

  nFlag |= CTransaction::TXF_ENTITY;
  entity = CIdent(name, secret);

  return (&entity);
}
*/

CCert *CTransaction::CreateCert(int ifaceIndex, string strTitle, CCoinAddr& addr, string hexSeed, int64 nLicenseFee)
{
  cbuff vchContext;

  if (nFlag & CTransaction::TXF_CERTIFICATE)
    return (NULL);

  nFlag |= CTransaction::TXF_CERTIFICATE;
  certificate = CCert(strTitle);
  certificate.SetSerialNumber();
  shgeo_local(&certificate.geo, SHGEO_PREC_DISTRICT);
  certificate.SetFee(nLicenseFee);
  certificate.Sign(ifaceIndex, addr, vchContext, hexSeed);

  return (&certificate);
}

CCert *CTransaction::DeriveCert(int ifaceIndex, string strTitle, CCoinAddr& addr, CCert *chain, string hexSeed, int64 nLicenseFee)
{

  if (nFlag & CTransaction::TXF_CERTIFICATE)
    return (NULL);

  nFlag |= CTransaction::TXF_CERTIFICATE;
  certificate = CCert(strTitle);
  certificate.SetSerialNumber();
  certificate.hashIssuer = chain->GetHash();

  certificate.nFlag |= SHCERT_CERT_CHAIN;
  certificate.nFlag |= SHCERT_CERT_LICENSE; /* capable of licensing */
  /* signing is revoked once parent is a chained cert */
  if (chain->nFlag & SHCERT_CERT_CHAIN)
    certificate.nFlag &= ~SHCERT_CERT_SIGN;

  shgeo_local(&certificate.geo, SHGEO_PREC_DISTRICT);
  certificate.SetFee(nLicenseFee);
  certificate.Sign(ifaceIndex, addr, chain, hexSeed);

  return (&certificate);
}

/**
 * @param lic_span The duration of the license in seconds.
 */
CCert *CTransaction::CreateLicense(CCert *cert)
{
  double lic_span;

  if (nFlag & CTransaction::TXF_LICENSE)
    return (NULL);
  
  nFlag |= CTransaction::TXF_LICENSE;
  CLicense license;//(*cert);

  license.nFlag |= SHCERT_CERT_CHAIN;
  license.nFlag &= ~SHCERT_CERT_SIGN;

  license.SetSerialNumber();
  shgeo_local(&license.geo, SHGEO_PREC_DISTRICT);
  license.hashIssuer = cert->GetHash();
  license.Sign(cert);

  certificate = (CCert&)license;

  return (&certificate);
}



COffer *CTransaction::CreateOffer()
{

  if (nFlag & CTransaction::TXF_OFFER)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER;
  offer = COffer();

  return (&offer);
}

COfferAccept *CTransaction::AcceptOffer(COffer *offerIn)
{
  uint160 hashOffer;

  if (nFlag & CTransaction::TXF_OFFER_ACCEPT)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER_ACCEPT;

  int64 nPayValue = -1 * offerIn->nXferValue;
  int64 nXferValue = -1 * offerIn->nPayValue;
  hashOffer = offerIn->GetHash();
  offer = *offerIn;

  offer.vPayAddr.clear();
  offer.vXferAddr.clear();
  offer.nPayValue = nPayValue;
  offer.nXferValue = nXferValue;
  offer.hashOffer = hashOffer;

 return ((COfferAccept *)&offer);
}

COffer *CTransaction::GenerateOffer(COffer *offerIn)
{
  if (nFlag & CTransaction::TXF_OFFER)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER;
  offer = *offerIn;

 return (&offer);
}

COfferAccept *CTransaction::PayOffer(COfferAccept *accept)
{

  if (nFlag & CTransaction::TXF_OFFER_ACCEPT)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER_ACCEPT;
  offer = COffer(*accept);

 return ((COfferAccept *)&offer);
}

COffer *CTransaction::RemoveOffer(uint160 hashOffer)
{
  if (nFlag & CTransaction::TXF_OFFER)
    return (NULL);
 return (NULL); 
}


CCert *CTransaction::CreateAsset(string strAssetName, string strAssetHash)
{

  if (nFlag & CTransaction::TXF_ASSET)
    return (NULL);

  nFlag |= CTransaction::TXF_ASSET;
  CAsset asset(strAssetName);

  asset.nFlag |= SHCERT_CERT_CHAIN;
  asset.nFlag &= ~SHCERT_CERT_SIGN;
  asset.nFlag &= ~SHCERT_CERT_DIGITAL;

  certificate = (CCert&)asset;

  return (&certificate);
}

CCert *CTransaction::UpdateAsset(const CAsset& assetIn, string strAssetName, string strAssetHash)
{

  if (nFlag & CTransaction::TXF_ASSET)
    return (NULL);

  nFlag |= CTransaction::TXF_ASSET;
  certificate = (CCert&)assetIn;
  certificate.SetLabel(strAssetName);

  return (&certificate);
}

CCert *CTransaction::SignAsset(const CAsset& assetIn, CCert *cert)
{

  if (nFlag & CTransaction::TXF_ASSET)
    return (NULL);

  nFlag |= CTransaction::TXF_ASSET;
  CAsset asset = assetIn;
  asset.Sign(cert);
  asset.hashIssuer = cert->GetHash();
  certificate = (CCert&)asset;

  return (&certificate);
}

CCert *CTransaction::RemoveAsset(const CAsset& assetIn)
{

  if (nFlag & CTransaction::TXF_ASSET)
    return (NULL);

  nFlag |= CTransaction::TXF_ASSET;
  certificate = (CCert&)assetIn;

  return (&certificate);
}

CIdent *CTransaction::CreateIdent(CIdent *ident)
{

  if (nFlag & CTransaction::TXF_IDENT)
    return (NULL);

  nFlag |= CTransaction::TXF_IDENT;
  certificate = CCert(*ident);
  shgeo_local(&certificate.geo, SHGEO_PREC_DISTRICT);

  return ((CIdent *)&certificate);
}

CIdent *CTransaction::CreateIdent(int ifaceIndex, CCoinAddr& addr)
{

  if (nFlag & CTransaction::TXF_IDENT)
    return (NULL);

  nFlag |= CTransaction::TXF_IDENT;

  certificate.SetNull();
  shgeo_local(&certificate.geo, SHGEO_PREC_DISTRICT);
  certificate.vAddr = vchFromString(addr.ToString());

  return ((CIdent *)&certificate);
}

bool CTransaction::VerifyValidateMatrix(const CTxMatrix& matrix, CBlockIndex *pindex)
{
  unsigned int height;

  if (!pindex)
    return (false);

  height = matrix.nHeight;
  height /= 27;
  height *= 27;

  while (pindex && pindex->pprev && pindex->nHeight > height)
    pindex = pindex->pprev;
  if (!pindex) {
    return (false);
  }

  bool ret;
  CTxMatrix cmp_matrix(matrixValidate);
  cmp_matrix.SetType(CTxMatrix::M_VALIDATE);
  cmp_matrix.Append(pindex->nHeight, pindex->GetBlockHash()); 
  ret = (cmp_matrix == matrix);

  return (ret);
}

/**
 * @note Verified against previous matrix when the block is accepted.
 */
CTxMatrix *CTransaction::GenerateValidateMatrix(int ifaceIndex, CBlockIndex *pindex)
{
  uint32_t best_height;
  int height;

  if (nFlag & CTransaction::TXF_MATRIX)
    return (NULL);

  if (!pindex) {
    pindex = GetBestBlockIndex(ifaceIndex);
    if (!pindex)
      return (NULL);
  }


  height = (pindex->nHeight - 27);
  height /= 27;
  height *= 27;

  if (height <= 27)
    return (NULL);

  if (matrixValidate.GetHeight() >= height)
    return (NULL);

  while (pindex && pindex->pprev && pindex->nHeight > height)
    pindex = pindex->pprev;
  if (!pindex) {
    return (NULL);
  }

  nFlag |= CTransaction::TXF_MATRIX;
  CTxMatrix matrixNew(matrixValidate);
  matrixNew.SetType(CTxMatrix::M_VALIDATE);
  matrixNew.Append(pindex->nHeight, pindex->GetBlockHash()); 
  matrix = (CTxMatrix&)matrixNew;

  return (&matrix);
}



bool CBlock::trust(int deg, const char *msg, ...)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  va_list arg_ptr;
  char errbuf[4096];
  char msgbuf[4096];

  if (deg == 0)
    return (true);

  if (!iface || !iface->enabled)
    return ((deg > 0) ? true : false);

  memset(msgbuf, 0, sizeof(msgbuf));
  if (msg) {
    va_start(arg_ptr, msg);
    (void)vsnprintf(msgbuf, sizeof(msgbuf) - 1, msg, arg_ptr);
    va_end(arg_ptr);
  }

  sprintf(errbuf, "TRUST %s%d", (deg >= 0) ? "+" : "", deg);
  if (*msgbuf)
    sprintf(errbuf + strlen(errbuf), " (%s)", msgbuf);

  if (deg > 0) {
    if (originPeer) {
      unet_log(ifaceIndex, errbuf); 
      if (originPeer->nMisbehavior > deg)
        originPeer->nMisbehavior -= deg;
    }
    return (true);
  }

  if (originPeer)
    originPeer->Misbehaving(-deg);

  shcoind_err(SHERR_INVAL, iface->name, errbuf);
  Debug("TRUST: %s", ToString());

  return (false);
}

std::string CTransactionCore::ToString(int ifaceIndex)
{
  return (write_string(Value(ToValue(ifaceIndex)), false));
}

std::string CTransaction::ToString(int ifaceIndex)
{
  return (write_string(Value(ToValue(ifaceIndex)), false));
}

std::string CBlockHeader::ToString()
{
  return (write_string(Value(ToValue()), false));
}

std::string CBlock::ToString()
{
  return (write_string(Value(ToValue()), false));
}

static inline string ToValue_date_format(time_t t)
{
  char buf[256];

  memset(buf, 0, sizeof(buf));
  strftime(buf, sizeof(buf)-1, "%x %T", localtime(&t));

  return (string(buf));
}

Object CTransactionCore::ToValue(int ifaceIndex)
{
  Object obj;

  obj.push_back(Pair("version", 
        isFlag(CTransaction::TX_VERSION) ? 1 : 
        isFlag(CTransaction::TX_VERSION_2) ? 2 : 0));
  obj.push_back(Pair("flag", nFlag));

  if (nLockTime != 0) {
    if ((int64)nLockTime < (int64)LOCKTIME_THRESHOLD) {
      obj.push_back(Pair("lock-height", (int)nLockTime));
    } else {
      obj.push_back(Pair("lock-time", (uint64_t)nLockTime));
      obj.push_back(Pair("lock-stamp", ToValue_date_format((time_t)nLockTime)));
    }
  }

  return (obj);
}

Object CTransaction::ToValue(int ifaceIndex)
{
  Object obj = CTransactionCore::ToValue(ifaceIndex);

  obj.push_back(Pair("txid", GetHash().GetHex()));
  obj.push_back(Pair("hash", GetWitnessHash().GetHex()));

  vector<uint256> vOuts;
  ReadCoins(ifaceIndex, vOuts);

  Array obj_vin;
  unsigned int n = 0;
  BOOST_FOREACH(const CTxIn& txin, vin)
  {
    Object in;
    if (IsCoinBase()) {
      in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    } else {
      in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
      in.push_back(Pair("vout", (boost::int64_t)txin.prevout.n));
      Object o;
      o.push_back(Pair("asm", txin.scriptSig.ToString()));
//      o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
      in.push_back(Pair("scriptSig", o));

    }   

    /* segwit */
    if (wit.vtxinwit.size() != 0) {
      const CTxInWitness& tx_wit = wit.vtxinwit[n];
      Array ar;
      for (unsigned int i = 0; i < tx_wit.scriptWitness.stack.size(); i++) {
        ar.push_back(HexStr(tx_wit.scriptWitness.stack[i].begin(), tx_wit.scriptWitness.stack[i].end()));
      }
      in.push_back(Pair("witness", ar));
    }

    in.push_back(Pair("sequence", (boost::int64_t)txin.nSequence));

    obj_vin.push_back(in);
    n++;
  }
  obj.push_back(Pair("vin", obj_vin));

  Array obj_vout;
  for (unsigned int i = 0; i < vout.size(); i++)
  {     
    const CTxOut& txout = vout[i];
    Object out;
    out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
    out.push_back(Pair("n", (boost::int64_t)i));
    out.push_back(Pair("scriptpubkey", txout.scriptPubKey.ToString().c_str()));
    if (i < vOuts.size() && !vOuts[i].IsNull())
      out.push_back(Pair("spent-tx", vOuts[i].GetHex()));
    ScriptPubKeyToJSON(ifaceIndex, txout.scriptPubKey, out);

    obj_vout.push_back(out);
  } 
  obj.push_back(Pair("vout", obj_vout));

  if (this->nFlag & TXF_CERTIFICATE) 
    obj.push_back(Pair("certificate", certificate.ToValue()));
  if (this->nFlag & TXF_LICENSE) {
    CLicense license(certificate);
    obj.push_back(Pair("license", license.ToValue()));
  }
  if (this->nFlag & TXF_ALIAS)
    obj.push_back(Pair("alias", alias.ToValue(ifaceIndex)));
  if (this->nFlag & TXF_ASSET) {
    CAsset asset(certificate);
    obj.push_back(Pair("asset", asset.ToValue()));
  }
  if (this->nFlag & TXF_EXEC) {
    CExec exec(certificate);
    obj.push_back(Pair("exec", exec.ToValue()));
  }
  if (this->nFlag & TXF_OFFER)
    obj.push_back(Pair("offer", offer.ToValue()));
  if (this->nFlag & TXF_OFFER_ACCEPT)
    obj.push_back(Pair("offeraccept", offer.ToValue()));
  if (this->nFlag & TXF_IDENT) {
    CIdent& ident = (CIdent&)certificate;
    obj.push_back(Pair("ident", ident.ToValue()));
  }
  if (this->nFlag & TXF_MATRIX) {
    obj.push_back(Pair("matrix", matrix.ToValue()));
  }
  if (this->nFlag & TXF_CHANNEL) {
    obj.push_back(Pair("channel", channel.ToValue()));
  }
  if (this->nFlag & TXF_CONTEXT) {
    CContext ctx(certificate);
    obj.push_back(Pair("context", ctx.ToValue()));
  }

  return (obj);
}

Object CTransaction::ToValue(CBlock *pblock)
{
  CBlockHeader& block = (CBlockHeader& )(*pblock);
  Object tx_obj = ToValue(pblock->ifaceIndex);
  Object obj;

  obj = block.ToValue();
  obj.push_back(Pair("tx", tx_obj));

  return (obj);
}

Object CBlockHeader::ToValue()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CBlockIndex *pindex;
  Object obj;
  uint256 hash = GetHash();

  obj.push_back(Pair("blockhash", hash.GetHex()));
//  obj.push_back(Pair("size", (int)::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION(iface))));
  obj.push_back(Pair("version", (nVersion & VERSIONBITS_TOP_BITS)));
  obj.push_back(Pair("merkleroot", hashMerkleRoot.GetHex()));
  obj.push_back(Pair("time", (boost::int64_t)GetBlockTime()));
  obj.push_back(Pair("stamp", ToValue_date_format((time_t)GetBlockTime())));
  obj.push_back(Pair("nonce", (boost::uint64_t)nNonce));
  obj.push_back(Pair("bits", HexBits(nBits)));

  if (iface)
    obj.push_back(Pair("confirmations", GetBlockDepthInMainChain(iface, hash)));

  pindex = GetBlockIndexByHash(ifaceIndex, hash);
  if (pindex) {
    obj.push_back(Pair("height", pindex->nHeight));
    obj.push_back(Pair("difficulty", GetDifficulty(ifaceIndex, pindex)));

    obj.push_back(Pair("chainwork", pindex->bnChainWork.ToString()));

    if (pindex->pprev)
      obj.push_back(Pair("previousblockhash", pindex->pprev->GetBlockHash().GetHex()));
    if (pindex->pnext)
      obj.push_back(Pair("nextblockhash", pindex->pnext->GetBlockHash().GetHex()));
  }

  return obj;
} 

Object CBlock::ToValue()
{
  Object obj = CBlockHeader::ToValue();

//  obj.push_back(Pair("size", (int)::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION)));
  obj.push_back(Pair("weight", (int)GetBlockWeight()));

  Array txs;
  BOOST_FOREACH(const CTransaction&tx, vtx)
    txs.push_back(tx.GetHash().GetHex());
  obj.push_back(Pair("tx", txs));

  return (obj);
}

bool CTransaction::IsInMemoryPool(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface) {
    unet_log(ifaceIndex, "error obtaining coin interface");
    return (false);
  }

  CTxMemPool *pool = GetTxMemPool(iface);
  if (!pool) {
    unet_log(ifaceIndex, "error obtaining tx memory pool");
    return (false);
  }

  return (pool->exists(GetHash()));
}

int CTransaction::GetDepthInMainChain(int ifaceIndex, CBlockIndex* &pindexRet) const
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  uint256 hashTx = GetHash();
  bool ret;

  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  if (!pindexBest)
    return (0);

  CBlockIndex *pindex = GetBlockIndexByTx(iface, hashTx);
  if (!pindex)
    return (0);

  if (!pindex->IsInMainChain(ifaceIndex))
    return 0;

  pindexRet = pindex;
  return pindexBest->nHeight - pindex->nHeight + 1;
}


CChannel *CTransaction::CreateChannel(CCoinAddr& src_addr, CCoinAddr& dest_addr, int64 nValue)
{

  if (isFlag(CTransaction::TXF_CHANNEL))
    return (NULL); /* already established */

  nFlag |= CTransaction::TXF_CHANNEL;

  CKeyID lcl_pubkey;
  if (!src_addr.GetKeyID(lcl_pubkey))
    return (NULL);

  CKeyID rem_pubkey;
  if (!dest_addr.GetKeyID(rem_pubkey))
    return (NULL);

  channel.SetNull();
  channel.GetOrigin()->addr = lcl_pubkey;
  channel.GetPeer()->addr = rem_pubkey;
  channel.SetOriginValue(nValue);

  return (&channel);
}

CChannel *CTransaction::ActivateChannel(const CChannel& channelIn, int64 nValue)
{

  if (isFlag(CTransaction::TXF_CHANNEL))
    return (NULL); /* already established */

  nFlag |= CTransaction::TXF_CHANNEL;

  channel.Init(channelIn);
  channel.SetPeerValue(nValue);

  return (&channel);
}

CChannel *CTransaction::PayChannel(const CChannel& channelIn)
{
  if (isFlag(CTransaction::TXF_CHANNEL))
    return (NULL); /* already established */

  nFlag |= CTransaction::TXF_CHANNEL;

  channel.Init(channelIn);
  channel.GetOrigin()->hdpubkey.clear();
  channel.GetPeer()->hdpubkey.clear();

  return (&channel);
}

CChannel *CTransaction::GenerateChannel(const CChannel& channelIn)
{

  if (isFlag(CTransaction::TXF_CHANNEL))
    return (NULL); /* already established */

  nFlag |= CTransaction::TXF_CHANNEL;

  channel.Init(channelIn);

  return (&channel);
}

CChannel *CTransaction::RemoveChannel(const CChannel& channelIn)
{

  return (&channel);
}

CExec *CTransaction::CreateExec()
{
  CExec *exec;

  if (nFlag & CTransaction::TXF_EXEC)
    return (NULL);

  nFlag |= CTransaction::TXF_EXEC;

  exec = (CExec *)&certificate;
  exec->SetNull();
  exec->SetExpireSpan((double)DEFAULT_EXEC_LIFESPAN);
  shgeo_local(&exec->geo, SHGEO_PREC_DISTRICT);

  return (exec);
}

CExec *CTransaction::UpdateExec(const CExec& execIn)
{
  CExec *exec;

  if (nFlag & CTransaction::TXF_EXEC)
    return (NULL);

  nFlag |= CTransaction::TXF_EXEC;

  exec = (CExec *)&certificate;
  exec->Init(execIn);

  return (exec);
}

CExec *CTransaction::ActivateExec(const CExec& execIn)
{
  CExec *exec;

  if (nFlag & CTransaction::TXF_EXEC)
    return (NULL);

  nFlag |= CTransaction::TXF_EXEC;

  exec = (CExec *)&certificate;
  exec->Init(execIn);

  return (exec);
}

CExec *CTransaction::TransferExec(const CExec& execIn)
{
  CExec *exec;

  if (nFlag & CTransaction::TXF_EXEC)
    return (NULL);

  nFlag |= CTransaction::TXF_EXEC;

  exec = (CExec *)&certificate;
  exec->Init(execIn);

  return (exec);
}

CExecCall *CTransaction::GenerateExec(const CExec& execIn, CCoinAddr& sendAddr)
{
  CExecCall *exec;

  if (nFlag & CTransaction::TXF_EXEC)
    return (NULL);

  nFlag |= CTransaction::TXF_EXEC;

  exec = (CExecCall *)&certificate;
  exec->Init(execIn);
  exec->signature.SetNull();
  exec->SetSendAddr(sendAddr);
  exec->vContext.clear();
  exec->nFee = 0;

  return (exec);
}

CExec *CTransaction::RemoveExec(const CExec& execIn)
{
  CExec *exec;

  if (nFlag & CTransaction::TXF_EXEC)
    return (NULL);

  nFlag |= CTransaction::TXF_EXEC;

  exec = (CExec *)&certificate;
  exec->Init(execIn);

  return (exec);

}

CContext *CTransaction::CreateContext()
{
  CContext *ctx;

  if (nFlag & CTransaction::TXF_CONTEXT)
    return (NULL);

  nFlag |= CTransaction::TXF_CONTEXT;

  ctx = (CContext *)&certificate;
  ctx->SetNull();

  /* each context value expires after two years */
  ctx->SetExpireSpan((double)DEFAULT_CONTEXT_LIFESPAN);

  return (ctx);
}




static bool GetCommitBranches(CBlockIndex *pbest, CBlockIndex *pindexNew, vector<CBlockIndex*>& vConnect, vector<CBlockIndex*>& vDisconnect)
{
  CBlockIndex* pfork = pbest;
  CBlockIndex* plonger = pindexNew;
 
  while (pfork && pfork != plonger)
  {   
    while (plonger->nHeight > pfork->nHeight) {
      plonger = plonger->pprev;
      if (!plonger)
        return (false);
    }
    if (pfork == plonger)
      break;

    pfork = pfork->pprev;
    if (!pfork)
      return (false);
  }

  /* discon tree */
  vDisconnect.clear();
  for (CBlockIndex* pindex = pbest; pindex != pfork; pindex = pindex->pprev)
    vDisconnect.push_back(pindex);

  /* connect tree */
  vConnect.clear();
  for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
    vConnect.push_back(pindex);
  reverse(vConnect.begin(), vConnect.end());

  if (vDisconnect.size() > 0) {
    Debug("REORGANIZE: Disconnect %lu blocks; %s..\n", (unsigned long)vDisconnect.size(), pfork->GetBlockHash().ToString().c_str());
    Debug("REORGANIZE: Connect %lu blocks; ..%s\n", (unsigned long)vConnect.size(), pindexNew->GetBlockHash().ToString().c_str());
  }

  return (true);
}



ValidIndexSet setBlockIndexValid[MAX_COIN_IFACE];

ValidIndexSet *GetValidIndexSet(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);

  return (&setBlockIndexValid[ifaceIndex]);
}


/* determine chain with greatest chain work */
bool core_ConnectBestBlock(int ifaceIndex, CBlock *block, CBlockIndex *pindexNew)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  ValidIndexSet *setValid = GetValidIndexSet(ifaceIndex);
  CBlockIndex *pindexBest;
  bool ret_val = true;

  pindexBest = GetBestBlockIndex(ifaceIndex);
  if (!pindexBest) {
    /* nothing to compare to */
    return (block->SetBestChain(pindexNew));
  } 

  while (true) {
    /* calculate 'best' known work */
    CBlockIndex *pindexNewBest;
    {
      std::set<CBlockIndex*,CBlockIndexWorkComparator>::reverse_iterator it = setValid->rbegin();
      if (it == setValid->rend()) {
        goto bail;
      }
      pindexNewBest = *it;
    }

    if (pindexNewBest == pindexBest ||
        pindexNewBest->bnChainWork == pindexBest->bnChainWork) {
      goto bail;
    }

    /* traverse candidate's ancestry */
    CBlockIndex *pindexTest = pindexNewBest;
    std::vector<CBlockIndex*> vAttach;
    while (true) {
      if ((pindexTest->nStatus & BIS_FAIL_VALID) ||
          (pindexTest->nStatus & BIS_FAIL_CHILD)) {
        CBlockIndex *pindexFailed = pindexNewBest;

        while (pindexTest != pindexFailed) {
          pindexFailed->nStatus |= BIS_FAIL_CHILD;
          setValid->erase(pindexFailed);
          //pblocktree->WriteBlockIndex(CDiskBlockIndex(pindexFailed));
          pindexFailed = pindexFailed->pprev;
        }

        //InvalidChainFound(pindexNewBest);
        error(SHERR_INVAL, "(core) ConnectBestBlock: InvalidChainFound: invalid block=%s  height=%d  work=%s  date=%s status(%u)",
            pindexNewBest->GetBlockHash().ToString().substr(0,20).c_str(),
            pindexNewBest->nHeight,
            pindexNewBest->bnChainWork.ToString().c_str(),
            DateTimeStrFormat("%x %H:%M:%S", pindexNewBest->GetBlockTime()).c_str(), pindexTest->nStatus);
        break;
      }

      if (pindexTest->bnChainWork > pindexBest->bnChainWork) {
        vAttach.push_back(pindexTest);
      }

      if (pindexTest->pprev == NULL || /* beginning of alt chain */
          pindexTest->pnext != NULL) { /* end of alt chain */
        uint256 cur_hash = block->GetHash();

        /* validate chain */
        reverse(vAttach.begin(), vAttach.end());
        BOOST_FOREACH(CBlockIndex *pindexSwitch, vAttach) {
          const uint256& t_hash = pindexSwitch->GetBlockHash();
          CBlock *t_block = NULL;
          bool ok;

          if (t_hash == cur_hash) {
            t_block = block;
          } else {
            t_block = GetBlockByHash(iface, t_hash);
            if (!t_block)
              t_block = GetArchBlockByHash(iface, t_hash); /* orphan */
            if (!t_block) {
              ret_val = false;
              error(SHERR_NOENT, "core_ConnectBestBlock: unknown block hash '%s'.", t_hash);
              goto bail;
            }
          }

          ok = t_block->SetBestChain(pindexSwitch);
          if (t_hash != cur_hash)
            delete t_block;
          if (!ok) {
            ret_val = false;
            error(SHERR_INVAL, "core_ConnectBestBlock: error setting best chain [hash %s] [height %u]", pindexSwitch->GetBlockHash().GetHex().c_str(), pindexSwitch->nHeight);
            goto bail;
          }
        }

        if (pindexNewBest->GetBlockHash() != pindexNew->GetBlockHash()) 
            block->WriteArchBlock();

        return (true);
      }

      pindexTest = pindexTest->pprev;
    } /* while(true */

  } /* while(true) */

bail:
  block->WriteArchBlock();
  return (ret_val);
}


int BackupBlockChain(CIface *iface, unsigned int maxHeight)
{
  bc_t *bc;
  char path[PATH_MAX+1];
  unsigned int height;
  unsigned int ten_per;
  int err;
  
  sprintf(path, "%s/backup/", bc_path_base());
  mkdir(path, 0777);

  sprintf(path, "backup/%s_block", iface->name);
  err = bc_open(path, &bc);
  if (err)
    return (err);

  height = MAX(1, bc_idx_next(bc));
  ten_per = (maxHeight / 10); /* ten percent of max */
  maxHeight = MIN(maxHeight - ten_per, height + ten_per);
  for (; height < maxHeight; height++) {
    CBlock *block = GetBlockByHeight(iface, height);
    if (!block) {
      error(err, "(%s) BackupBlockChain: load error (height: %u)", iface->name, height);
      break;
    }

    CDataStream sBlock(SER_DISK, CLIENT_VERSION);
    uint256 hash = block->GetHash();
    char *sBlockData;
    long sBlockLen;

    sBlock << *block;
    delete block;

    sBlockLen = sBlock.size();
    sBlockData = (char *)calloc(sBlockLen, sizeof(char));
    if (!sBlockData)
      return error(SHERR_NOMEM, "allocating %d bytes for block data\n", (int)sBlockLen);
    sBlock.read(sBlockData, sBlockLen);

    err = bc_write(bc, height, hash.GetRaw(), sBlockData, sBlockLen);
    free(sBlockData);
    if (err) {
      error(err, "bc_write [BackupBlockChain]");
      break;
    }
  }

  Debug("(%s) BackupBlockChain: total %u blocks stored.", 
      iface->name, height);
  
  bc_close(bc);
  
  return (0);
}   


int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
static int GetSkipHeight(int height) 
{

  if (height < 2)
    return 0;

  // Determine which height to jump back to. Any number strictly lower than height is acceptable,
  // but the following expression seems to perform well in simulations (max 110 steps to go back
  // up to 2**18 blocks).
  return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{

  if (height > nHeight || height < 0)
    return NULL;

  CBlockIndex* pindexWalk = this;
  int heightWalk = nHeight;
  while (heightWalk > height) {
    int heightSkip = GetSkipHeight(heightWalk);
    int heightSkipPrev = GetSkipHeight(heightWalk - 1);
    if (pindexWalk->pskip != NULL &&
        (heightSkip == height ||
         (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                   heightSkipPrev >= height)))) {
      // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
      pindexWalk = pindexWalk->pskip;
      heightWalk = heightSkip;
    } else {
      assert(pindexWalk->pprev);
      pindexWalk = pindexWalk->pprev;
      heightWalk--;
    }
  }

  return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}

void CBlockIndex::BuildSkip()
{
  if (pprev)
    pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}


static VersionBitsCache _version_bits_cache[MAX_COIN_IFACE];

VersionBitsCache *GetVersionBitsCache(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE) {
    return (NULL);
  }

  /* special case */
  if (ifaceIndex == USDE_COIN_IFACE)
    return (NULL);

  return (&_version_bits_cache[ifaceIndex]);
}

bool IsWitnessEnabled(CIface *iface, const CBlockIndex* pindexPrev)
{
  VersionBitsCache *cache;

  cache = GetVersionBitsCache(iface);
  if (!cache)
    return (false);

  return (VersionBitsState(pindexPrev, iface, DEPLOYMENT_SEGWIT, *cache) == THRESHOLD_ACTIVE);
}


int GetWitnessCommitmentIndex(const CBlock& block)
{
  int commitpos = -1;

  for (size_t o = 0; o < block.vtx[0].vout.size(); o++) {
    if (block.vtx[0].vout[o].scriptPubKey.size() >= 38 && block.vtx[0].vout[o].scriptPubKey[0] == OP_RETURN && block.vtx[0].vout[o].scriptPubKey[1] == 0x24 && block.vtx[0].vout[o].scriptPubKey[2] == 0xaa && block.vtx[0].vout[o].scriptPubKey[3] == 0x21 && block.vtx[0].vout[o].scriptPubKey[4] == 0xa9 && block.vtx[0].vout[o].scriptPubKey[5] == 0xed) {
      commitpos = o;
    }
  }

  return commitpos;
}

void core_UpdateUncommittedBlockStructures(CIface *iface, CBlock& block, const CBlockIndex* pindexPrev)
{
  int commitpos = GetWitnessCommitmentIndex(block);
  static const std::vector<unsigned char> nonce(32, 0x00);
  if (commitpos != -1 && IsWitnessEnabled(iface, pindexPrev) && block.vtx[0].wit.IsEmpty()) {
    block.vtx[0].wit.vtxinwit.resize(1);
    block.vtx[0].wit.vtxinwit[0].scriptWitness.stack.resize(1);
    block.vtx[0].wit.vtxinwit[0].scriptWitness.stack[0] = nonce;
  }
}

bool core_GenerateCoinbaseCommitment(CIface *iface, CBlock& block, CBlockIndex *pindexPrev)
{
  // std::vector<unsigned char> commitment;
  int commitpos = GetWitnessCommitmentIndex(block);
  std::vector<unsigned char> ret(32, 0x00);

  if (iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout != 0) {
    if (commitpos == -1) {
      uint256 witnessroot = BlockWitnessMerkleRoot(block, NULL);
      uint256 hashCommit;

      CTxOut out;
      out.nValue = 0;
      out.scriptPubKey.resize(38);
      out.scriptPubKey[0] = OP_RETURN; 
      out.scriptPubKey[1] = 0x24;
      out.scriptPubKey[2] = 0xaa;
      out.scriptPubKey[3] = 0x21;
      out.scriptPubKey[4] = 0xa9;
      out.scriptPubKey[5] = 0xed;

//      CHash256().Write(witnessroot.begin(), 32).Write(&ret[0], 32).Finalize(witnessroot.begin());
      hashCommit = Hash(witnessroot.begin(), witnessroot.end(), ret.begin(), ret.end());
      memcpy(&out.scriptPubKey[6], hashCommit.begin(), 32);
      
      //      commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
      const_cast<std::vector<CTxOut>*>(&block.vtx[0].vout)->push_back(out);   
      //      block.vtx[0].UpdateHash();
    }
  }

  core_UpdateUncommittedBlockStructures(iface, block, pindexPrev);
  // return commitment;

  return (false);
}




int core_ComputeBlockVersion(CIface *params, CBlockIndex *pindexPrev)
{
  int32_t nVersion = VERSIONBITS_TOP_BITS;
  VersionBitsCache *cache;

  cache = GetVersionBitsCache(params);
  if (!cache)
    return (1);

  for (int i = 0; i < (int)MAX_VERSION_BITS_DEPLOYMENTS; i++) {
    ThresholdState state = VersionBitsState(pindexPrev, params, (DeploymentPos)i, *cache);
    if (state == THRESHOLD_LOCKED_IN || state == THRESHOLD_STARTED) {
      nVersion |= VersionBitsMask(params, (DeploymentPos)i);
    }
  }

  return nVersion;
}

/**
 * Validation for witness commitments.
 * - Compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the coinbase (where 0x0000....0000 is used instead).
 * - The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness nonce (unconstrained).
 * - We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
 * - There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness nonce). In case there are multiple, the last one is used.
 */
bool core_CheckBlockWitness(CIface *iface, CBlock *pblock, CBlockIndex *pindexPrev)
{
  bool fHaveWitness = false;

  if (!iface || !pblock || !pindexPrev)
    return true; /* n/a */

  if (IsWitnessEnabled(iface, pindexPrev)) {
    int commitpos = GetWitnessCommitmentIndex(*pblock);
    if (commitpos != -1) {
      const CTransaction& commit_tx = pblock->vtx[0];
#if 0
      if (commit_tx.wit.vtxinwit.size() == 0) {
        /* non-standard -- fill in missing witness block structure */
        core_UpdateUncommittedBlockStructures(iface, *pblock, pindexPrev);
        /* DEBUG: */ error(SHERR_INVAL, "(emc2) core_CheckBlockWitness: filled missing witness nonce for block '%s'.", pblock->GetHash().GetHex().c_str());
      }
#endif

      /* The malleation check is ignored; as the transaction tree itself already does not permit it, it is impossible to trigger in the witness tree. */
      if (pblock->vtx[0].wit.vtxinwit.size() != 1 || 
          pblock->vtx[0].wit.vtxinwit[0].scriptWitness.stack.size() != 1 || 
          pblock->vtx[0].wit.vtxinwit[0].scriptWitness.stack[0].size() != 32) {
        return (error(SHERR_INVAL, "core_CheckBlockWitness: witness commitment validation error: \"%s\" [wit-size %d].", pblock->vtx[0].ToString(GetCoinIndex(iface)).c_str()), (int)pblock->vtx[0].wit.vtxinwit.size());
      }

      uint256 hashWitness = BlockWitnessMerkleRoot(*pblock, NULL);
      const cbuff& stack = pblock->vtx[0].wit.vtxinwit[0].scriptWitness.stack[0];
      hashWitness = Hash(hashWitness.begin(), hashWitness.end(), stack.begin(), stack.end());
//      CHash256().Write(hashWitness.begin(), 32).Write(&block.vtx[0].wit.vtxinwit[0].scriptWitness.stack[0][0], 32).Finalize(hashWitness.begin());
      if (memcmp(hashWitness.begin(), &pblock->vtx[0].vout[commitpos].scriptPubKey[6], 32)) {
        return (error(SHERR_INVAL, "core_CheckBlockWitness: witness commitment hash validation error: \"%s\".", pblock->vtx[0].ToString(GetCoinIndex(iface)).c_str()));
      }

      fHaveWitness = true;
    }
  }

  /* No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam. */
  if (!fHaveWitness) {
    for (size_t i = 0; i < pblock->vtx.size(); i++) {
      if (!pblock->vtx[i].wit.IsNull()) {
        return (error(SHERR_INVAL, "core_CheckBlockWitness: unexpected witness data error: \"%s\".", pblock->vtx[i].ToString(GetCoinIndex(iface)).c_str()));
      }
    }
  }

  return (true);
}

static size_t WitnessSigOps(int witversion, const std::vector<unsigned char>& witprogram, const CScriptWitness& witness, int flags)
{
  if (witversion == 0) {
    if (witprogram.size() == 20)
      return 1;

    if (witprogram.size() == 32 && witness.stack.size() > 0) {
      CScript subscript(witness.stack.back().begin(), witness.stack.back().end());
      return subscript.GetSigOpCount(true);
    }
  }

  // Future flags may be implemented here.
  return 0;
}   


size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags)
{
  static const CScriptWitness witnessEmpty;

  if (flags && !(flags & SCRIPT_VERIFY_WITNESS))
    return 0;
//  assert((flags & SCRIPT_VERIFY_P2SH) != 0);

  int witnessversion;
  std::vector<unsigned char> witnessprogram;
  if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
    return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
  }

  if (scriptPubKey.IsPayToScriptHash() && scriptSig.IsPushOnly()) {
    CScript::const_iterator pc = scriptSig.begin();
    vector<unsigned char> data;
    while (pc < scriptSig.end()) {
      opcodetype opcode;
      scriptSig.GetOp(pc, opcode, data);
    }
    CScript subscript(data.begin(), data.end());
    if (subscript.IsWitnessProgram(witnessversion, witnessprogram)) {
      return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
    }
  }

  return 0;
}

int64_t CTransaction::GetSigOpCost(tx_cache& mapInputs, int flags)
{
  int64_t nSigOps;

  nSigOps = GetLegacySigOpCount() * SCALE_FACTOR;

  if (IsCoinBase()) 
    return nSigOps;

  if ((flags == 0) || (flags & SCRIPT_VERIFY_P2SH)) {
    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); i++) {
      CTxOut prevout;

      if (!GetOutputFor(vin[i], mapInputs, prevout))
        continue;

      if (prevout.scriptPubKey.IsPayToScriptHash())
        nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig) * SCALE_FACTOR;
    }
  }

  if ((flags == 0) || (flags & SCRIPT_VERIFY_WITNESS)) {
    for (unsigned int i = 0; i < vin.size(); i++) {   
      CTxOut prevout;

      if (!GetOutputFor(vin[i], mapInputs, prevout))
        continue;

      nSigOps += CountWitnessSigOps(vin[i].scriptSig, prevout.scriptPubKey, i < wit.vtxinwit.size() ? &wit.vtxinwit[i].scriptWitness : NULL, flags);
    }
  }

  return nSigOps;
}

int64_t CTransaction::GetSigOpCost(MapPrevTx& mapInputs, int flags)
{
  int64_t nSigOps = GetLegacySigOpCount() * SCALE_FACTOR;

  if (IsCoinBase()) 
    return nSigOps;

  if (flags && (flags & SCRIPT_VERIFY_P2SH)) {
    nSigOps += GetP2SHSigOpCount(mapInputs) * SCALE_FACTOR;
  }

  for (unsigned int i = 0; i < vin.size(); i++) {   
    const CTxOut &prevout = GetOutputFor(vin[i], mapInputs);
    nSigOps += CountWitnessSigOps(vin[i].scriptSig, prevout.scriptPubKey, i < wit.vtxinwit.size() ? &wit.vtxinwit[i].scriptWitness : NULL, flags);
  }

  return nSigOps;
}




#ifdef USE_LEVELDB_COINDB

bool core_DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex, CBlock *pblock)
{
  CIface *iface = GetCoinByIndex(txdb.ifaceIndex);
  int err;

  if (!iface || !iface->enabled)
    return error(SHERR_INVAL, "coin interface not enabled.");

  Debug("DisonnectBlock[%s]: disconnect block '%s' (height %d).", iface->name, pindex->GetBlockHash().GetHex().c_str(), (int)pindex->nHeight);

  // Disconnect in reverse order
  for (int i = pblock->vtx.size()-1; i >= 0; i--)
    if (!pblock->vtx[i].DisconnectInputs(txdb))
      return false;

  return true;
}

/**
 * Verifies whether a vSpent has been spent.
 * @param hashTx The hash of the transaction attempting to spend the input.
 */
bool CPool::IsSpentTx(const CDiskTxPos& pos)
{
  uint256 hashTx = GetHash();

  if (pos.IsNull())
    return (false);

  /* this coin has been marked as spent. ensure this is not a re-write of the same transaction. */
  CTransaction spent;
  if (!spent.ReadFromDisk(pos))
    return false; /* spent being referenced does not exist. */

  if (hashTx == spent.GetHash())
    return false; /* spent was already cataloged in past */

  return true;
}

bool CTransaction::ReadFromDisk(CDiskTxPos pos)
{
  int ifaceIndex = pos.nFile;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *tx_bc = GetBlockTxChain(iface);
  bc_t *bc = GetBlockChain(iface);
  CBlock *block;
  bc_hash_t b_hash;
  char errbuf[1024];
  uint256 hashTx;
  int err;

  if (!iface) {// || ifaceIndex < 1 || ifaceIndex >= MAX_COIN_IFACE) {
    sprintf(errbuf, "CTransaction::ReadTx: error obtaining coin iface #%d\n", (int)pos.nFile);
    return error(SHERR_INVAL, errbuf);
  }

  err = bc_get_hash(tx_bc, pos.nTxPos, b_hash);
  if (err) {
    sprintf(errbuf, "CTransaction::ReadTx: error obtaining tx index #%u\n", (unsigned int)pos.nTxPos);
    return error(err, errbuf);
  }
  hashTx.SetRaw(b_hash);

  unsigned int nHeight = (unsigned int)pos.nBlockPos;
  block = GetBlockByHeight(iface, nHeight);
  if (!block) {
    sprintf(errbuf, "CTransaction::ReadTx: error obtaining block height %u.", nHeight);
    return error(SHERR_INVAL, errbuf);
  }

  const CTransaction *tx = block->GetTx(hashTx);
  if (!tx) {
    sprintf(errbuf, "CTransaction::ReadTx: block height %d '%s' does not contain tx '%s'.", nHeight, block->GetHash().GetHex().c_str(), hashTx.GetHex().c_str());
    delete block;
    return error(SHERR_INVAL, errbuf);
  }

  Init(*tx);
  delete block;

#if 0
  if (!CheckTransaction(ifaceIndex)) {
    sprintf(errbuf, "CTransaction::ReadTx: invalid transaction '%s' for block height %d\n", hashTx.GetHex().c_str(), nHeight);
    return error(SHERR_INVAL, errbuf);
  } 
#endif

  return (true);
}

bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet)
{
    SetNull();
    if (!txdb.ReadTxIndex(prevout.hash, txindexRet)) {
return error(SHERR_INVAL, "CTransaction::ReadFromDisk: ReadTxIndex failure");
        return false;
}
    if (!ReadFromDisk(txindexRet.pos)) {
return error(SHERR_INVAL, "CTransaction::ReadFromDisk: ReadFromDIsk(pos) failure");
        return false;
}
    if (prevout.n >= vout.size())
    {
        SetNull();
        return false;
    }
    return true;
}

bool CTransaction::FetchInputs(CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool, CBlock *pblockNew, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid)
{
  int ifaceIndex = txdb.ifaceIndex;
  CIface *iface = GetCoinByIndex(ifaceIndex);

  // FetchInputs can return false either because we just haven't seen some inputs
  // (in which case the transaction should be stored as an orphan)
  // or because the transaction is malformed (in which case the transaction should
  // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
  fInvalid = false;

  if (IsCoinBase())
    return true; // Coinbase transactions have no inputs to fetch.

  for (unsigned int i = 0; i < vin.size(); i++)
  {
    COutPoint prevout = vin[i].prevout;
    if (inputsRet.count(prevout.hash))
      continue; // Got it already

    // Read txindex
    CTxIndex& txindex = inputsRet[prevout.hash].first;
    bool fFound = true;
    if ((pblockNew || fMiner) && mapTestPool.count(prevout.hash))
    {
      // Get txindex from current proposed changes
      txindex = mapTestPool.find(prevout.hash)->second;
    }
    else
    {
      // Read txindex from txdb
      fFound = txdb.ReadTxIndex(prevout.hash, txindex);
    }

    /* allows for passage past this error condition for orphans. */
    if (!fFound && (pblockNew || fMiner)) {
      if (fMiner)
        return (false);

      return error(SHERR_NOENT, "FetchInputs: %s prev tx %s index entry not found", GetHash().GetHex().c_str(), prevout.hash.GetHex().c_str());
    }

    // Read txPrev
    CTransaction& txPrev = inputsRet[prevout.hash].second;
    if (!fFound || txindex.pos == CDiskTxPos(0,0,0)) 
    {
      // Get prev tx from single transactions in memory
      CTxMemPool *mempool = GetTxMemPool(iface);
      if (!mempool->exists(prevout.hash)) {
        return (error(SHERR_INVAL, "FetchInputs: mempool tx \"%s\" input \"%s\" not found.", GetHash().ToString().c_str(),  prevout.hash.ToString().c_str()));
      }
      txPrev = mempool->lookup(prevout.hash);
      if (!fFound)
        txindex.vSpent.resize(txPrev.vout.size());
    }
    else
    {
      /* Get prev tx from disk */
      if (!txPrev.ReadTx(txdb.ifaceIndex, prevout.hash)) {
        const CTransaction *tx;
        Debug("CTransaction::FetchInputs[%s]: for tx %s, ReadFromDisk prev tx %s failed", iface->name, GetHash().ToString().c_str(),  prevout.hash.ToString().c_str());

        if (!pblockNew ||
            !(tx = pblockNew->GetTx(prevout.hash))) {
          return error(SHERR_INVAL, "CTransaction::FetchInputs[%s]: for tx %s, prev tx %s unknown", iface->name, GetHash().ToString().c_str(),  prevout.hash.ToString().c_str());
        }

        txPrev.Init(*tx);
#if 0
      // Get prev tx from disk
      if (!txPrev.ReadFromDisk(txindex.pos))
        return error(SHERR_INVAL, "FetchInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
#endif
      }
    }
  }

  // Make sure all prevout.n's are valid:
  for (unsigned int i = 0; i < vin.size(); i++)
  {
    const COutPoint prevout = vin[i].prevout;
    assert(inputsRet.count(prevout.hash) != 0);
    const CTxIndex& txindex = inputsRet[prevout.hash].first;
    CTransaction& txPrev = inputsRet[prevout.hash].second;
    if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
    {
      // Revisit this if/when transaction replacement is implemented and allows
      // adding inputs:
      fInvalid = true;
      return error(SHERR_INVAL, "FetchInputs() : %s prevout.n out of range %d %d %d prev tx %s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str());
    }
  }

  return true;
}


bool core_CommitBlock(CTxDB& txdb, CBlock *pblock, CBlockIndex *pindexNew)
{
  CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
  CBlockIndex *pbest = GetBestBlockIndex(pblock->ifaceIndex);
  CTxMemPool *pool = GetTxMemPool(iface);
  vector<CBlockIndex*> vConnect;
  vector<CBlockIndex*> vDisconnect;
  map<CBlockIndex *, CBlock *> mConnectBlocks;
  map<CBlockIndex *, CBlock *> mDisconBlocks;
  vector<CBlock *> vFree;
  bool fValid = true;

  if  (!GetCommitBranches(pbest, pindexNew, vConnect, vDisconnect)) {
    return (error(SHERR_INVAL, "core_CommitBlock: error obtaining commit branches."));
  }

  if (!txdb.TxnBegin()) {
    return error(SHERR_INVAL, "core_CommitBlock: error initializing db transaction.");
  }

  if (pblock->hashPrevBlock != pbest->GetBlockHash()) {
    pblock->WriteArchBlock();
  }

  /* discon blocks */
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect) {
    const uint256& hash = pindex->GetBlockHash();
    CBlock *block;

    block = GetBlockByHash(iface, hash);
    if (!block)
      block = GetArchBlockByHash(iface, hash); /* orphan */
    if (!block) {
      error(SHERR_INVAL, "core_CommitBlock: error obtaining disconnect block '%s'", hash.GetHex().c_str());
      fValid = false;
      break;
    }

    mDisconBlocks[pindex] = block;
    vFree.push_back(block);
  }
  if (!fValid)
    goto fin;

  /* connect blocks */
  BOOST_FOREACH(CBlockIndex *pindex, vConnect) {
    const uint256& hash = pindex->GetBlockHash();
    CBlock *block;

    if (pindexNew->GetBlockHash() == pindex->GetBlockHash()) {
      block = pblock;
    } else {
      block = GetBlockByHash(iface, hash);
      if (!block)
        block = GetArchBlockByHash(iface, hash); /* orphan */
      if (block)
        vFree.push_back(block);
    }
    if (!block) {
      error(SHERR_INVAL, "core_CommitBlock: error obtaining connect block '%s'", hash.GetHex().c_str());
      fValid = false;
      break;
    }

    mConnectBlocks[pindex] = block;
  }
  if (!fValid)
    goto fin;

  /* perform discon */
  BOOST_FOREACH(PAIRTYPE(CBlockIndex *, CBlock *) r, mDisconBlocks) {
    CBlockIndex *pindex = r.first;
    CBlock *block = r.second;

    if (!block->DisconnectBlock(txdb, pindex)) {
      error(SHERR_INVAL, "Reorganize() : DisonnectBlock %s failed", pindex->GetBlockHash().ToString().c_str());
      fValid = false;
      break;
    }

    /* add discon block tx's into pending pool */
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (tx.IsCoinBase())
        continue;
      pool->AddTx(tx);
    }
  }
  if (!fValid)
    goto fin;

  /* perform connect */
  BOOST_FOREACH(PAIRTYPE(CBlockIndex *, CBlock *) r, mConnectBlocks) {
    CBlockIndex *pindex = r.first;
    CBlock *block = r.second;

    if (!block->ConnectBlock(txdb, pindex)) {
      error(SHERR_INVAL, "Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().c_str());
      fValid = false;
      break;
    }

#if 0
    /* remove connectd block tx's from pool */ 
    pool->Commit(*block);
#endif
  }
  if (!fValid)
    goto fin;

  if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash())) {
    fValid = false;
    error(SHERR_INVAL, "Reorganize() : WriteHashBestChain failed");
    goto fin;
  }

  // Make sure it's successfully written to disk before changing memory structure
  if (!txdb.TxnCommit()) {
    fValid = false;
    error(SHERR_INVAL, "Reorganize() : TxnCommit failed");
    goto fin;
  }

  // Disconnect shorter branch
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
    if (pindex->pprev)
      pindex->pprev->pnext = NULL;

  // Connect longer branch
  BOOST_FOREACH(CBlockIndex* pindex, vConnect)
    if (pindex->pprev)
      pindex->pprev->pnext = pindex;

  /* remove connectd block tx's from mempool */ 
  BOOST_FOREACH(PAIRTYPE(CBlockIndex *, CBlock *) r, mConnectBlocks) {
    CBlock *block = r.second;

    pool->Commit(*block);
  }

fin:
  if (!fValid) {
    txdb.TxnAbort(); /* abort the ship, matey */
    pblock->InvalidChainFound(pindexNew);
    error(SHERR_INVAL, "core_CommitBlock: invalid chain block: %s", pblock->ToString().c_str());
  }

  BOOST_FOREACH(CBlock *block, vFree) {
    delete block;
  }

  return (fValid);
}


#else /* USE_LEVELDB_COINDB */

bool core_DisconnectBlock(CBlockIndex* pindex, CBlock *pblock)
{
  CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
  int err;

  if (!iface || !iface->enabled)
    return error(SHERR_INVAL, "coin interface not enabled.");

  Debug("DisonnectBlock[%s]: disconnect block '%s' (height %d).", iface->name, pindex->GetBlockHash().GetHex().c_str(), (int)pindex->nHeight);

  // Disconnect in reverse order
  for (int i = pblock->vtx.size()-1; i >= 0; i--)
    if (!pblock->vtx[i].DisconnectInputs(pblock->ifaceIndex))
      return false;

  return true;
}



bool core_CommitBlock(CBlock *pblock, CBlockIndex *pindexNew)
{
  CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
  CBlockIndex *pbest = GetBestBlockIndex(pblock->ifaceIndex);
  CTxMemPool *pool = GetTxMemPool(iface);
  vector<CBlockIndex*> vConnect;
  vector<CBlockIndex*> vDisconnect;
  map<CBlockIndex *, CBlock *> mConnectBlocks;
  map<CBlockIndex *, CBlock *> mDisconBlocks;
  vector<CBlock *> vFree;
  bool fValid = true;


  if  (!GetCommitBranches(pbest, pindexNew, vConnect, vDisconnect)) {
    return (error(SHERR_INVAL, "core_CommitBlock: error obtaining commit branches."));
  }

  if (pblock->hashPrevBlock != pbest->GetBlockHash()) {
    pblock->WriteArchBlock();
  }

  /* discon blocks */
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect) {
    const uint256& hash = pindex->GetBlockHash();
    CBlock *block;

    block = GetBlockByHash(iface, hash);
    if (!block)
      block = GetArchBlockByHash(iface, hash); /* orphan */
    if (!block) {
      error(SHERR_INVAL, "core_CommitBlock: error obtaining disconnect block '%s'", hash.GetHex().c_str());
      fValid = false;
      break;
    }

    mDisconBlocks[pindex] = block;
    vFree.push_back(block);
  }
  if (!fValid)
    goto fin;

  /* connect blocks */
  BOOST_FOREACH(CBlockIndex *pindex, vConnect) {
    const uint256& hash = pindex->GetBlockHash();
    CBlock *block;

    if (pindexNew->GetBlockHash() == pindex->GetBlockHash()) {
      block = pblock;
    } else {
      block = GetBlockByHash(iface, hash);
      if (!block)
        block = GetArchBlockByHash(iface, hash); /* orphan */
      if (block)
        vFree.push_back(block);
    }
    if (!block) {
      error(SHERR_INVAL, "core_CommitBlock: error obtaining connect block '%s'", hash.GetHex().c_str());
      fValid = false;
      break;
    }

    mConnectBlocks[pindex] = block;
  }
  if (!fValid)
    goto fin;

  /* perform discon */
  BOOST_FOREACH(PAIRTYPE(CBlockIndex *, CBlock *) r, mDisconBlocks) {
    CBlockIndex *pindex = r.first;
    CBlock *block = r.second;

    if (!block->DisconnectBlock(pindex)) {
      error(SHERR_INVAL, "Reorganize() : DisonnectBlock %s failed", pindex->GetBlockHash().ToString().c_str());
      fValid = false;
      break;
    }

  }
  if (!fValid)
    goto fin;

  /* perform connect */
  BOOST_FOREACH(PAIRTYPE(CBlockIndex *, CBlock *) r, mConnectBlocks) {
    CBlockIndex *pindex = r.first;
    CBlock *block = r.second;

    if (!block->ConnectBlock(pindex)) {
      error(SHERR_INVAL, "Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().c_str());
      fValid = false;
      break;
    }
  }
  if (!fValid)
    goto fin;

  /* persist */
  WriteHashBestChain(iface, pindexNew->GetBlockHash());

  // Disconnect shorter branch
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
    if (pindex->pprev)
      pindex->pprev->pnext = NULL;

  // Connect longer branch
  BOOST_FOREACH(CBlockIndex* pindex, vConnect)
    if (pindex->pprev)
      pindex->pprev->pnext = pindex;

  /* add discon block tx's into pending pool */
  BOOST_FOREACH(PAIRTYPE(CBlockIndex *, CBlock *) r, mDisconBlocks) {
    CBlock *block = r.second;

    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (tx.IsCoinBase())
        continue;
      pool->AddTx(tx);
    }
  }

  /* remove connectd block tx's from pool */ 
  BOOST_FOREACH(PAIRTYPE(CBlockIndex *, CBlock *) r, mConnectBlocks) {
    CBlock *block = r.second;
    pool->Commit(*block);
  }

fin:
  if (!fValid) {
    pblock->InvalidChainFound(pindexNew);
    error(SHERR_INVAL, "core_CommitBlock: invalid chain block: %s", pblock->ToString().c_str());
  }

  BOOST_FOREACH(CBlock *block, vFree) {
    delete block;
  }

  return (fValid);
}

#if 0
bool CBlock::DisconnectBlock(CBlockIndex *pindex)
{
  return (core_DisconnectBlock(pindex, this));
}
#endif

#endif /* USE_LEVELDB_COINDB */


