
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
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "usde_pool.h"
#include "usde_block.h"
#include "usde_txidx.h"
#include "chain.h"
#include "coin.h"

#ifdef WIN32
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef fcntl
#undef fcntl
#endif

#include <boost/array.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>


using namespace std;
using namespace boost;



CBlockIndex static * InsertBlockIndex(uint256 hash)
{

  if (hash == 0)
    return NULL;

  // Return existing
  blkidx_t *mapBlockIndex = GetBlockTable(USDE_COIN_IFACE);
  map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex->find(hash);
  if (mi != mapBlockIndex->end())
    return (*mi).second;

  // Create new
  CBlockIndex* pindexNew = new CBlockIndex();
  if (!pindexNew)
    throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
  mi = mapBlockIndex->insert(make_pair(hash, pindexNew)).first;
  pindexNew->phashBlock = &((*mi).first);

  return pindexNew;
}

bool usde_FillBlockIndex()
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(USDE_COIN_IFACE);
  bc_t *bc = GetBlockChain(iface);
  bc_t *tx_bc = GetBlockTxChain(iface);
  CBlockIndex *lastIndex;
  USDEBlock block;
  uint256 hash;
  int nHeight;
  int err;

#if USE_LEVELDB_COINDB
  bool checkBest = false;
  uint256 hashBestChain;
  USDETxDB txdb;
  if (txdb.ReadHashBestChain(hashBestChain))
    checkBest = true;
  txdb.Close();
#endif

  int nMaxIndex = bc_idx_next(bc);

  lastIndex = NULL;
  for (nHeight = 0; nHeight < nMaxIndex; nHeight++) {
    if (0 != bc_idx_get(bc, nHeight, NULL))
      break;
    if (!block.ReadBlock(nHeight)) {
fprintf(stderr, "DEBUG: usde_FillBlockIndex: error reading block height %d in main chain.\n", nHeight);
      break;
    }
    hash = block.GetHash();

    if (nHeight == 0) {
      if (hash != usde_hashGenesisBlock) {
fprintf(stderr, "DEBUG: usde_FillBlockIndex: stopping at invalid genesis '%s' @ height %d\n", hash.GetHex().c_str(), nHeight);
        break; /* invalid genesis */
      }
    } else if (blockIndex->count(block.hashPrevBlock) == 0) {
fprintf(stderr, "DEBUG: usde_FillBlockIndex: stopping at orphan '%s' @ height %d\n", hash.GetHex().c_str(), nHeight);
      break;
    }

    CBlockIndex* pindexNew = InsertBlockIndex(blockIndex, hash);
    if (nHeight == 0) {
      USDEBlock::pindexGenesisBlock = pindexNew;
    }
    pindexNew->pprev = lastIndex;//InsertBlockIndex(blockIndex, block.hashPrevBlock);
    if (lastIndex) lastIndex->pnext = pindexNew;
//    if (lastIndex && lastIndex->pprev == pindexNew) pindexNew->pnext = InsertBlockIndex(blockIndex, lastIndex->GetBlockHash());   

    pindexNew->nHeight        = nHeight;
    pindexNew->nVersion       = block.nVersion;
    pindexNew->hashMerkleRoot = block.hashMerkleRoot;
    pindexNew->nTime          = block.nTime;
    pindexNew->nBits          = block.nBits;
    pindexNew->nNonce         = block.nNonce;

    if (lastIndex)
      pindexNew->BuildSkip();

    if (!pindexNew->CheckIndex())
      return error(SHERR_INVAL, "LoadBlockIndex() : CheckIndex failed at height %d", pindexNew->nHeight);

    if (nHeight == 0 && pindexNew->GetBlockHash() == usde_hashGenesisBlock)
      USDEBlock::pindexGenesisBlock = pindexNew;

    lastIndex = pindexNew;

#ifdef USE_LEVELDB_COINDB
    if (checkBest && hash == hashBestChain) {
      break;
    } 
#endif
  }
  SetBestBlockIndex(iface, lastIndex);

  return true;
}
#if 0
bool usde_FillBlockIndex()
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(USDE_COIN_IFACE);
  bc_t *bc = GetBlockChain(iface);
  CBlockIndex *pindexBest;
  CBlockIndex *lastIndex;
  USDEBlock block;
  uint256 hash;
  int nBestIndex;
  int nHeight;

  int nMaxIndex = bc_idx_next(bc) - 1;
  for (nBestIndex = 0; nBestIndex <= nMaxIndex; nBestIndex++) {
    if (0 != bc_idx_get(bc, nBestIndex, NULL))
      break;
  }
  nBestIndex--;

  lastIndex = NULL;
  pindexBest = NULL;
  for (nHeight = nBestIndex; nHeight >= 0; nHeight--) {
    if (!block.ReadBlock(nHeight))
      continue;
    hash = block.GetHash();

    CBlockIndex* pindexNew = InsertBlockIndex(blockIndex, hash);
    pindexNew->pprev = InsertBlockIndex(blockIndex, block.hashPrevBlock);
    if (lastIndex && lastIndex->pprev == pindexNew)
      pindexNew->pnext = InsertBlockIndex(blockIndex, lastIndex->GetBlockHash());   

    pindexNew->nHeight        = nHeight;
    pindexNew->nVersion       = block.nVersion;
    pindexNew->hashMerkleRoot = block.hashMerkleRoot;
    pindexNew->nTime          = block.nTime;
    pindexNew->nBits          = block.nBits;
    pindexNew->nNonce         = block.nNonce;

    if (!pindexNew->CheckIndex())
      return error(SHERR_INVAL, "LoadBlockIndex() : CheckIndex failed at height %d", pindexNew->nHeight);

    if (nHeight == 0 && pindexNew->GetBlockHash() == usde_hashGenesisBlock)
      USDEBlock::pindexGenesisBlock = pindexNew;

    if (!pindexBest && lastIndex) {
      if (lastIndex->pprev == pindexNew)
        pindexBest = lastIndex;
    }

    lastIndex = pindexNew;
  }

  CBlockIndex *pindex;
  if (USDEBlock::pindexGenesisBlock) {
    nHeight = 0;
    for (pindex = USDEBlock::pindexGenesisBlock; pindex && pindex->pnext; pindex = pindex->pnext) {
      if (pindex->nHeight != nHeight)
        fprintf(stderr, "DEBUG: FillBlockIndex: pindex->nHeight(%d) nHeight(%d)\n", pindex->nHeight, nHeight); 
      pindex->nHeight = nHeight++;
    }
    if (pindex) {
      SetBestBlockIndex(iface, pindex);
    }
  }

  return true;
}
#endif

static bool hasGenesisRoot(CBlockIndex *pindexBest)
{
  CBlockIndex *pindex;

  for (pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev) {
    if (pindex->nHeight == 0)
      break;
  }
  if (!pindex)
    return (false);

  if (pindex->nHeight != 0 || 
      pindex->GetBlockHash() != usde_hashGenesisBlock)
    return (false);

  return (true);
}

#ifdef USE_LEVELDB_COINDB
bool USDETxDB::LoadBlockIndex()
#else
static bool usde_LoadBlockIndex()
#endif
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  CWallet *wallet = GetWallet(USDE_COIN_IFACE);
  blkidx_t *mapBlockIndex = GetBlockTable(USDE_COIN_IFACE);
  char errbuf[1024];

#if 0
  if (!LoadBlockIndexGuts())
    return false;
#endif
  if (!usde_FillBlockIndex())
    return false;

  if (fRequestShutdown)
    return true;

  // Calculate bnChainWork
  vector<pair<int, CBlockIndex*> > vSortedByHeight;
  vSortedByHeight.reserve(mapBlockIndex->size());
  BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, (*mapBlockIndex))
  {
    CBlockIndex* pindex = item.second;
    vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
  }
  sort(vSortedByHeight.begin(), vSortedByHeight.end());
  BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight)
  {
    CBlockIndex* pindex = item.second;
    pindex->bnChainWork = (pindex->pprev ? pindex->pprev->bnChainWork : 0) + pindex->GetBlockWork();
  }

  // Load USDEBlock::hashBestChain pointer to end of best chain
  uint256 hashBestChain;
#ifdef USE_LEVELDB_COINDB
  if (!ReadHashBestChain(hashBestChain))
#else
  if (mapBlockIndex->size() == 0 ||
      !::ReadHashBestChain(iface, hashBestChain))
#endif
  {
    if (USDEBlock::pindexGenesisBlock == NULL) {
      //fprintf(stderr, "DEBUG: USDETxDB::LoadBlockIndex() : USDEBlock::hashBestChain not loaded\n");
      return true;
    }
    //    return error(SHERR_INVAL, "USDETxDB::LoadBlockIndex() : USDEBlock::hashBestChain not loaded");
  }

  CBlockIndex *pindexBest;


  pindexBest = NULL;
  if (mapBlockIndex->count(hashBestChain) != 0)
    pindexBest = (*mapBlockIndex)[hashBestChain];

  bool ok = true;
  if (!pindexBest) {
    Debug("(usde) LoadBlockIndex: Unable to establish block chain.");
    ok = false;
  } else if (pindexBest->nHeight > 0 && !pindexBest->pprev) {
    Debug("(usde) LoadBlockIndex: Block chain is severed at height %d.", (int)pindexBest->nHeight);
    ok = false;
  } else if (!hasGenesisRoot(pindexBest)) {
    Debug("(usde) LoadBlockIndex: Invalid genesis block based from height %d.", pindexBest->nHeight);
    ok = false;
  }
  if (!ok) {
    pindexBest = GetBestBlockIndex(iface);
    if (!pindexBest)
      return error(SHERR_INVAL, "USDETxDB::LoadBlockIndex() : USDEBlock::hashBestChain not found in the block index");
    hashBestChain = pindexBest->GetBlockHash();

    error(SHERR_IO, "(usde) LoadBlockIndex: falling back to highest block height %d (hash: %s)\n", pindexBest->nHeight, pindexBest->GetBlockHash().GetHex().c_str());
  }

  if (!pindexBest) {
    fprintf(stderr, "DEBUG: USDETxDB::LoadBlockIndex: error: hashBestChain '%s' not found in block index table\n", (hashBestChain).GetHex().c_str());
  }

  SetBestBlockIndex(USDE_COIN_IFACE, pindexBest);
  //  SetBestHeight(iface, pindexBest->nHeight);
  USDEBlock::bnBestChainWork = pindexBest->bnChainWork;
  pindexBest->pnext = NULL;

  Debug("(usde) LoadBlockIndex: hashBestChain=%s  height=%d  date=%s\n",
      hashBestChain.GetHex().c_str(), (int)GetBestHeight(USDE_COIN_IFACE),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

#ifdef USE_LEVELDB_COINDB
  // Load bnBestInvalidWork, OK if it doesn't exist
  ReadBestInvalidWork(USDEBlock::bnBestInvalidWork);
#endif

  int nCheckDepth = (GetBestHeight(USDE_COIN_IFACE) / 10000) + 640;
  int nWalletCheckDepth = nCheckDepth * 1.5;
  int nValidateCheckDepth = nCheckDepth * 4;
  int total = 0;
  int invalid = 0;
  int maxHeight = 0;
  int checkHeight = pindexBest->nHeight;

  CBlockIndex* pindexFork = NULL;
  map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
  CBlockIndex *pindex = pindexBest;
  for (; pindex && pindex->pprev; pindex = pindex->pprev)
  {
    //if (fRequestShutdown || pindex->nHeight < GetBestHeight(USDE_COIN_IFACE) - nCheckDepth)
    if (pindex->nHeight < GetBestHeight(USDE_COIN_IFACE) - nCheckDepth)
      break;
    USDEBlock block;
    if (!block.ReadFromDisk(pindex))
      return error(SHERR_INVAL, "LoadBlockIndex() : block.ReadFromDisk failed");

    total++;

    if (!block.CheckBlock() ||
        !block.CheckTransactionInputs(USDE_COIN_IFACE)) {
      error (SHERR_INVAL, "(usde) LoadBlockIndex: critical: found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());

      pindexFork = pindex->pprev;
      invalid++;
      continue;
    }
    if (pindex->nHeight > maxHeight)
      maxHeight = pindex->nHeight;
    if (pindex->nHeight < checkHeight)
      checkHeight = pindex->nHeight;
  }
//if (pindex) fprintf(stderr, "DEBUG: USDE: lowest validated height %d (%s)\n", pindex->nHeight, pindex->GetBlockHash().GetHex().c_str()); 
  if (pindexFork && !fRequestShutdown)
  {
    // Reorg back to the fork
    printf("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->nHeight);
    USDEBlock block;
    if (!block.ReadFromDisk(pindexFork))
      return error(SHERR_INVAL, "LoadBlockIndex() : block.ReadFromDisk failed");
#ifdef USE_LEVELDB_COINDB
    USDETxDB txdb;
    block.SetBestChain(txdb, pindexFork);
    txdb.Close();
#else
    WriteHashBestChain(iface, pindexFork->GetBlockHash());
#endif

    pindexBest = pindexFork;
  }

  /* (simple) validate block chain */
  maxHeight++;
  sprintf(errbuf, "USDE::LoadBlockIndex: Verified %-2.2f%% of %d total blocks: %d total invalid blocks found.", (double)(100 / (double)maxHeight * (double)total), maxHeight, invalid);
  unet_log(USDE_COIN_IFACE, errbuf);

  /* (extensive) validate block chain */
  nValidateCheckDepth = MIN(maxHeight-1, nValidateCheckDepth);
  InitServiceValidateEvent(wallet, maxHeight - nValidateCheckDepth);
  sprintf(errbuf, "USDE::LoadBlockIndex: Initiated block-chain validation of %d total blocks (%-3.3f%%).", nValidateCheckDepth, (100 / (double)maxHeight * (double)nValidateCheckDepth));
  unet_log(USDE_COIN_IFACE, errbuf);

  /* validate wallet transactions */
  nWalletCheckDepth = MIN(maxHeight-1, nWalletCheckDepth);
  InitServiceWalletEvent(wallet, maxHeight - nWalletCheckDepth);
  sprintf(errbuf, "USDE::LoadBlockIndex: Initiated wallet validation of %d total blocks (%-3.3f%%).", nWalletCheckDepth, (100 / (double)maxHeight * (double)nWalletCheckDepth));
  unet_log(USDE_COIN_IFACE, errbuf);

  if (!opt_bool(OPT_USDE_BACKUP_RESTORE)) {
    BackupBlockChain(iface, maxHeight); 
  }

  return true;
}

#if 0
bool USDETxDB::LoadBlockIndexGuts()
{
  blkidx_t *mapBlockIndex = GetBlockTable(USDE_COIN_IFACE);

  // Get database cursor
  Dbc* pcursor = GetCursor();
  if (!pcursor)
    return false;

  // Load mapBlockIndex
  unsigned int fFlags = DB_SET_RANGE;
  loop
  {
    // Read next record
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    if (fFlags == DB_SET_RANGE)
      ssKey << make_pair(string("blockindex"), uint256(0));
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
    fFlags = DB_NEXT;
    if (ret == DB_NOTFOUND)
      break;
    else if (ret != 0)
      return false;

    // Unserialize

    try {
      string strType;
      ssKey >> strType;
      if (strType == "blockindex" && !fRequestShutdown)
      {
        CDiskBlockIndex diskindex;
        ssValue >> diskindex;

        // Construct block index object
        CBlockIndex* pindexNew = InsertBlockIndex(diskindex.GetBlockHash());
        pindexNew->pprev          = InsertBlockIndex(diskindex.hashPrev);
        pindexNew->pnext          = InsertBlockIndex(diskindex.hashNext);
#if 0
        pindexNew->nFile          = diskindex.nFile;
        pindexNew->nBlockPos      = diskindex.nBlockPos;
#endif
        pindexNew->nHeight        = diskindex.nHeight;
        pindexNew->nVersion       = diskindex.nVersion;
        pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
        pindexNew->nTime          = diskindex.nTime;
        pindexNew->nBits          = diskindex.nBits;
        pindexNew->nNonce         = diskindex.nNonce;

        // Watch for genesis block
        if (USDEBlock::pindexGenesisBlock == NULL && diskindex.GetBlockHash() == usde_hashGenesisBlock)
          USDEBlock::pindexGenesisBlock = pindexNew;

        if (!pindexNew->CheckIndex())
          return error(SHERR_INVAL, "LoadBlockIndex() : CheckIndex failed at %d", pindexNew->nHeight);
      }
      else
      {
        break; // if shutdown requested or finished loading block index
      }
    }    // try
    catch (std::exception &e) {
      return error(SHERR_INVAL, "%s() : deserialize error", __PRETTY_FUNCTION__);
    }
  }
  pcursor->close();

  return true;
}
#endif


bool usde_InitBlockIndex()
{
  bool ret;

#ifdef USE_LEVELDB_COINDB
  USDETxDB txdb("cr");
  ret = txdb.LoadBlockIndex();
  txdb.Close();
#else
  ret = usde_LoadBlockIndex();
#endif
  if (!ret)
    return (false);

  if (!usde_CreateGenesisBlock())
    return (false);

  return (true);
}

bool usde_RestoreBlockIndex()
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  bc_t *chain = GetBlockChain(iface);
  bc_t *chain_tx = GetBlockTxChain(iface);
  bc_t *bc;
  char path[PATH_MAX+1];
  unsigned char *sBlockData;
  size_t sBlockLen;
  unsigned int maxHeight;
  bcsize_t height;
  int nBlockPos, nTxPos;
  int err;
  bool ret;


#ifdef USE_LEVELDB_COINDB
  {
    USDETxDB txdb("cr");
    txdb.Close();
  }
#endif


#if 0
  {
    CWallet *wallet = GetWallet(iface);
    if (wallet) {
fprintf(stderr, "DEBUG: usde_RestoreBlockIndex: erasing %d wallet transactions.\n", wallet->mapWallet.size());
      wallet->mapWallet.clear(); 
    }
  }
  {
    /* wipe old block-chain index  */
fprintf(stderr, "DEBUG: usde_RestoreBlockIndex: erased current block-chain index (%u bytes).\n", (unsigned int)chain->idx_map.hdr->of);
    chain->idx_map.hdr->of = 0;
  }
#endif

  if (!usde_CreateGenesisBlock())
    return (false);

  /* reset hash-map tables */
  bc_table_clear(chain);
  bc_table_clear(chain_tx);

#ifdef USE_LEVELDB_COINDB
  USDETxDB txdb;
#endif

  uint256 hash = usde_hashGenesisBlock;
  {
    sprintf(path, "backup/%s_block", iface->name);
    err = bc_open(path, &bc);
    if (err)
      return error(err, "usde_RestoreBlockIndex: error opening backup block-chain.");

    maxHeight = bc_idx_next(bc);
    for (height = 1; height < maxHeight; height++) {
      int n_height;

      err = bc_get(bc, height, &sBlockData, &sBlockLen);
      if (err)
        break;

      /* serialize binary data into block */
      CDataStream sBlock(SER_DISK, CLIENT_VERSION);
      sBlock.write((const char *)sBlockData, sBlockLen);
      USDEBlock block;
      sBlock >> block;
      hash = block.GetHash();

      err = bc_write(chain, height, hash.GetRaw(), sBlockData, sBlockLen);
      if (err < 0)
        return error(SHERR_INVAL, "block-chain write: %s", sherrstr(n_height));
      free(sBlockData);

      /* write tx ref's */
      BOOST_FOREACH(CTransaction& tx, block.vtx) {
        tx.WriteTx(USDE_COIN_IFACE, height);

#ifdef USE_LEVELDB_COINDB
        nBlockPos = nTxPos = -1;
        (void)bc_idx_find(chain, hash.GetRaw(), NULL, &nBlockPos);
        (void)bc_idx_find(chain_tx, tx.GetHash().GetRaw(), NULL, &nTxPos);
        CDiskTxPos posThisTx(USDE_COIN_IFACE, nBlockPos, nTxPos);
        txdb.AddTxIndex(tx, posThisTx, height);
#endif
      }

    }
    Debug("usde_RestoreBlocKIndex: rebuilt database -- wrote %d blocks\n", height);

    bc_close(bc);
  }
  bc_idle(chain);
  bc_idle(chain_tx);

#ifdef USE_LEVELDB_COINDB
  txdb.WriteHashBestChain(hash);
  ret = txdb.LoadBlockIndex();
  txdb.Close();
  if (!ret)
    return (false);
#else
  WriteHashBestChain(iface, hash);
#endif

  return (true);
}



#ifdef USE_LEVELDB_COINDB

bool USDETxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
  tx.SetNull();
  if (!ReadTxIndex(hash, txindex))
    return false;
  return (tx.ReadFromDisk(txindex.pos));
}

bool USDETxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
  CTxIndex txindex;
  return ReadDiskTx(hash, tx, txindex);
}

bool USDETxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
  return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool USDETxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
  CTxIndex txindex;
  return ReadDiskTx(outpoint.hash, tx, txindex);
}

#endif
