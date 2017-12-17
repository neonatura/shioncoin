
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
#include "shc_pool.h"
#include "shc_block.h"
#include "shc_txidx.h"
#include "chain.h"
#include "spring.h"
#include "coin.h"

#include <boost/array.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>

using namespace std;
using namespace boost;

extern bool IsIdentTx(const CTransaction& tx);



CBlockIndex static * InsertBlockIndex(uint256 hash)
{

  if (hash == 0)
    return NULL;

  // Return existing
  blkidx_t *mapBlockIndex = GetBlockTable(SHC_COIN_IFACE);
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

typedef vector<CBlockIndex*> txlist;
bool shc_FillBlockIndex(txlist& vMatrix, txlist& vSpring, txlist& vCert, txlist& vIdent, txlist& vLicense, txlist& vAlias, txlist& vContext)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  bc_t *bc = GetBlockChain(iface);
  bc_t *tx_bc = GetBlockTxChain(iface);
  CBlockIndex *pindexBest;
  CBlockIndex *lastIndex;
  SHCBlock block;
  uint256 hash;
  int nBestIndex;
  int nHeight;
  int err;

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

    if (lastIndex)
      pindexNew->BuildSkip();

    if (!pindexNew->CheckIndex())
      return error(SHERR_INVAL, "LoadBlockIndex() : CheckIndex failed at height %d", pindexNew->nHeight);

    if (nHeight == 0)
      SHCBlock::pindexGenesisBlock = pindexNew;

    if (!pindexBest && lastIndex) {
      if (lastIndex->pprev == pindexNew)
        pindexBest = lastIndex;
    }

    BOOST_FOREACH(CTransaction& tx, block.vtx) {
      /* register extended transactions. */
      if (tx.IsCoinBase() &&
          tx.isFlag(CTransaction::TXF_MATRIX)) {
        int mode;
        if (VerifyMatrixTx(tx, mode)) {
          if (mode == OP_EXT_VALIDATE)
            vMatrix.push_back(pindexNew);
          else if (mode == OP_EXT_PAY)
            vSpring.push_back(pindexNew);
        }
      }
      if (tx.isFlag(CTransaction::TXF_IDENT)) {
        vIdent.push_back(pindexNew);
      }
      if (tx.isFlag(CTransaction::TXF_CERTIFICATE)) {
        if (VerifyCert(iface, tx, nHeight))
          vCert.push_back(pindexNew);
      }
      if (tx.isFlag(CTransaction::TXF_ALIAS) &&
          IsAliasTx(tx)) {
        vAlias.push_back(pindexNew);
      }
      if (tx.isFlag(CTransaction::TXF_LICENSE) &&
          IsLicenseTx(tx)) {
        vLicense.push_back(pindexNew);
      }
      if (tx.isFlag(CTransaction::TXF_CONTEXT) &&
          IsContextTx(tx)) {
        vContext.push_back(pindexNew);
      }
    } /* FOREACH (tx) */

    lastIndex = pindexNew;
  }
  SetBestBlockIndex(iface, pindexBest);

  return true;
}

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
      pindex->GetBlockHash() != shc_hashGenesisBlock)
    return (false);

  return (true);
}

#ifdef USE_LEVELDB_TXDB
bool SHCTxDB::LoadBlockIndex()
#else
static bool shc_LoadBlockIndex()
#endif
{
  int ifaceIndex = SHC_COIN_IFACE;
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  CWallet *wallet = GetWallet(SHC_COIN_IFACE);
  blkidx_t *mapBlockIndex = GetBlockTable(SHC_COIN_IFACE);
  char errbuf[1024];


#if 0
  if (!LoadBlockIndexGuts())
    return false;
#endif
  txlist vSpring;
  txlist vMatrix;
  txlist vCert;
  txlist vIdent;
  txlist vLicense;
  txlist vAlias;
  txlist vContext;
  if (!shc_FillBlockIndex(vMatrix, vSpring, vCert, vIdent, vLicense, vAlias, vContext))
    return (false);

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
  CBlockIndex* pindex = NULL;
  BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight)
  {
    pindex = item.second;
    pindex->bnChainWork = (pindex->pprev ? pindex->pprev->bnChainWork : 0) + pindex->GetBlockWork();
  }
  if (pindex) {
    Debug("shc_LoadBlockIndex: chain work calculated (%s) for %d blocks.", pindex->bnChainWork.ToString().c_str(), vSortedByHeight.size());
  }

  // Load SHCBlock::hashBestChain pointer to end of best chain
  uint256 hashBestChain;
  if (mapBlockIndex->size() == 0 ||
      !ReadHashBestChain(iface, hashBestChain))
  {
    if (SHCBlock::pindexGenesisBlock == NULL) {
     // fprintf(stderr, "DEBUG: SHCTxDB::LoadBlockIndex() : SHCBlock::hashBestChain not loaded, but pindexGenesisBlock == NULL");
      return true;
    }
    //    return error(SHERR_INVAL, "SHCTxDB::LoadBlockIndex() : SHCBlock::hashBestChain not loaded");
  }
#if 0
  if (!mapBlockIndex->count(hashBestChain)) {
    CBlockIndex *pindexBest = GetBestBlockIndex(iface);
    if (!pindexBest)
      return error(SHERR_INVAL, "SHCTxDB::LoadBlockIndex() : SHCBlock::hashBestChain not found in the block index");
    fprintf(stderr, "DEBUG: SHC:LoadBlockIndex: falling back to highest block height %d\n", pindexBest->nHeight);
    hashBestChain = pindexBest->GetBlockHash();
  }
#endif

  CBlockIndex *pindexBest;

  pindexBest = NULL;
  if (mapBlockIndex->count(hashBestChain) != 0)
    pindexBest = (*mapBlockIndex)[hashBestChain];

  bool ok = true;
  if (!pindexBest)
    ok = false;
  else if (pindexBest->nHeight > 0 && !pindexBest->pprev)
    ok = false;
  else if (!hasGenesisRoot(pindexBest))
    ok = false;
  if (!ok) {
    pindexBest = GetBestBlockIndex(iface);
    if (!pindexBest)
      return error(SHERR_INVAL, "SHCTxDB::LoadBlockIndex() : SHCBlock::hashBestChain not found in the block index");
    fprintf(stderr, "DEBUG: LoadBlockIndex: falling back to highest block height %d\n", pindexBest->nHeight);
    hashBestChain = pindexBest->GetBlockHash();
  }

  if (!pindexBest) {
    fprintf(stderr, "DEBUG: SHCTxDB::LoadBlockIndex: error: hashBestChain '%s' not found in block index table\n", (hashBestChain).GetHex().c_str());
  }

  SetBestBlockIndex(SHC_COIN_IFACE, pindexBest);
  //  SetBestHeight(iface, pindexBest->nHeight);
  SHCBlock::bnBestChainWork = pindexBest->bnChainWork;
  pindexBest->pnext = NULL;

  //printf("LoadBlockIndex(): SHCBlock::hashBestChain=%s  height=%d  date=%s\n", hashBestChain.ToString().substr(0,20).c_str(), GetBestHeight(iface), DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

#ifdef USE_LEVELDB_COINDB
  // Load bnBestInvalidWork, OK if it doesn't exist
  ReadBestInvalidWork(SHCBlock::bnBestInvalidWork);
#endif

  int nCheckDepth = (GetBestHeight(SHC_COIN_IFACE) / 10000) + 640;
  int nWalletCheckDepth = nCheckDepth * 1.5;
  int nValidateCheckDepth = nCheckDepth * 4;
  int total = 0;
  int invalid = 0;
  int maxHeight = 0;
  int checkHeight = pindexBest->nHeight;

  CBlockIndex* pindexFork = NULL;
  map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
  for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
  {
    if (fRequestShutdown || pindex->nHeight < GetBestHeight(SHC_COIN_IFACE) - nCheckDepth)
      break;
    SHCBlock block;
    if (!block.ReadFromDisk(pindex)) {
      fprintf(stderr, "DEBUG: SHCBlock::LoadBlockIndex() : block.ReadFromDisk failed");
      pindexFork = pindex->pprev;
      continue;
    }
    total++;

    if (!block.CheckBlock() ||
        !block.CheckTransactionInputs(SHC_COIN_IFACE)) {
      error (SHERR_INVAL, "(shc) LoadBlockIndex: critical: found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());

      pindexFork = pindex->pprev;
      invalid++;
      continue;
    }

    if (pindex->nHeight > maxHeight)
      maxHeight = pindex->nHeight;
    if (pindex->nHeight < checkHeight)
      checkHeight = pindex->nHeight;
  }
  if (pindexFork && !fRequestShutdown)
  {
    // Reorg back to the fork
    fprintf(stderr, "DEBUG: LoadBlockIndex() : *** moving best chain pointer back to block %d '%s'\n", pindexFork->nHeight, pindexFork->GetBlockHash().GetHex().c_str());
    SHCBlock block;
    if (!block.ReadFromDisk(pindexFork))
      return error(SHERR_INVAL, "LoadBlockIndex() : block.ReadFromDisk failed");
#ifdef USE_LEVELDB_COINDB
    SHCTxDB txdb;
    block.SetBestChain(txdb, pindexFork);
    txdb.Close();
#else
    WriteHashBestChain(iface, pindexFork->GetBlockHash());
#endif

    pindexBest = pindexFork;
  }

  /* (simple) validate block chain */
  maxHeight++;
  sprintf(errbuf, "SHC::LoadBlockIndex: Verified %-3.3f%% of %d total blocks: %d total invalid blocks found.", (double)(100 / (double)maxHeight * (double)total), maxHeight, invalid);
  unet_log(SHC_COIN_IFACE, errbuf);

  /* (extensive) validate block chain */
  nValidateCheckDepth = MIN(maxHeight-1, nValidateCheckDepth);
  InitServiceValidateEvent(wallet, maxHeight - nValidateCheckDepth);
  sprintf(errbuf, "SHC::LoadBlockIndex: Initiated block-chain validation of %d total blocks (%-3.3f%%).", nValidateCheckDepth, (100 / (double)maxHeight * (double)nValidateCheckDepth));
  unet_log(SHC_COIN_IFACE, errbuf);

  /* validate wallet transactions */
  nWalletCheckDepth = MIN(maxHeight-1, nWalletCheckDepth);
  InitServiceWalletEvent(wallet, maxHeight - nWalletCheckDepth);
  sprintf(errbuf, "SHC::LoadBlockIndex: Initiated wallet validation of %d total blocks (%-3.3f%%).", nWalletCheckDepth, (100 / (double)maxHeight * (double)nWalletCheckDepth));
  unet_log(SHC_COIN_IFACE, errbuf);

  if (!opt_bool(OPT_SHC_BACKUP_RESTORE)) {
    BackupBlockChain(iface, maxHeight); 
  }

  /* Block-chain Validation Matrix */
  std::reverse(vMatrix.begin(), vMatrix.end());
  BOOST_FOREACH(CBlockIndex *pindex, vMatrix) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    if (!block) continue;

    CTransaction id_tx;
    const CTransaction& m_tx = block->vtx[0];
    const CTxMatrix& matrix = m_tx.matrix;

    if (matrix.nHeight > pindexBest->nHeight)
      break;

    CBlockIndex *tindex = pindex;
    while (tindex->pprev && tindex->nHeight > matrix.nHeight)
      tindex = tindex->pprev;

    matrixValidate.Append(tindex->nHeight, tindex->GetBlockHash()); 
  }

  /* ident */
  std::reverse(vIdent.begin(), vIdent.end());
  BOOST_FOREACH(CBlockIndex *pindex, vIdent) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (IsIdentTx(tx))
        InsertIdentTable(iface, tx);
    }
    delete block;
  }

  /* Spring Matrix */
  cert_list *idents = GetIdentTable(ifaceIndex);
  std::reverse(vSpring.begin(), vSpring.end());
  BOOST_FOREACH(CBlockIndex *pindex, vSpring) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    if (!block) continue;

    CTransaction id_tx;
    const CTransaction& m_tx = block->vtx[0];
    if (GetTxOfIdent(iface, m_tx.matrix.hRef, id_tx)) {
      shnum_t lat, lon;
      int mode;

      /* remove ident from pending list */
      CIdent& ident = (CIdent&)id_tx.certificate;
      const uint160& hIdent = ident.GetHash();
      idents->erase(hIdent);

      if (VerifyIdent(id_tx, mode) && mode == OP_EXT_NEW) {
        /* mark location as claimed */
        shgeo_loc(&ident.geo, &lat, &lon, NULL);
        spring_loc_claim(lat, lon);
      }
    }

    delete block;
  }

  std::reverse(vCert.begin(), vCert.end());
  BOOST_FOREACH(CBlockIndex *pindex, vCert) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (IsCertTx(tx))
        InsertCertTable(iface, tx, pindex->nHeight);
    }
    delete block;
  }

  /* license */
  std::reverse(vLicense.begin(), vLicense.end());
  BOOST_FOREACH(CBlockIndex *pindex, vLicense) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (IsLicenseTx(tx))
        CommitLicenseTx(iface, tx, pindex->nHeight);
    }
    delete block;
  }

  /* alias */
  std::reverse(vAlias.begin(), vAlias.end());
  BOOST_FOREACH(CBlockIndex *pindex, vAlias) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (IsAliasTx(tx)) {
        CommitAliasTx(iface, tx, pindex->nHeight);
      }
    }
    delete block;
  }

  /* context */
  std::reverse(vContext.begin(), vContext.end());
  BOOST_FOREACH(CBlockIndex *pindex, vContext) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (IsContextTx(tx))
        CommitContextTx(iface, tx, pindex->nHeight);
    }
    delete block;
  }

  return true;
}


#if 0
bool SHCTxDB::LoadBlockIndexGuts()
{
  blkidx_t *mapBlockIndex = GetBlockTable(SHC_COIN_IFACE);

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
        if (SHCBlock::pindexGenesisBlock == NULL && diskindex.GetBlockHash() == shc_hashGenesisBlock) {
          SHCBlock::pindexGenesisBlock = pindexNew;
}

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


bool shc_InitBlockIndex()
{
  bool ret;

#ifdef USE_LEVELDB_COINDB
  SHCTxDB txdb("cr");
  ret = txdb.LoadBlockIndex();
  txdb.Close();
#else
  ret = shc_LoadBlockIndex();
#endif
  if (!ret)
    return (false);

  if (!shc_CreateGenesisBlock())
    return (false);

  return (true);
}

bool shc_RestoreBlockIndex()
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  bc_t *chain = GetBlockChain(iface);
  bc_t *chain_tx = GetBlockTxChain(iface);
  bc_t *bc;
  char path[PATH_MAX+1];
  unsigned char *sBlockData;
  size_t sBlockLen;
  unsigned int maxHeight;
  bcsize_t height;
  int nBlockPos;
  int nTxPos;
  int err;
  bool ret;

/* DEBUG: TODO: remove "shc_block.*" and "shc_tx.*" first */

#if 0
  {
    CWallet *wallet = GetWallet(iface);
    if (wallet) {
fprintf(stderr, "DEBUG: shc_RestoreBlockIndex: erasing %d wallet transactions.\n", wallet->mapWallet.size());
      wallet->mapWallet.clear(); 
    }
  }
  {
    /* wipe old block-chain index  */
fprintf(stderr, "DEBUG: shc_RestoreBlockIndex: erased current block-chain index (%u bytes).\n", (unsigned int)chain->idx_map.hdr->of);
    chain->idx_map.hdr->of = 0;
  }
#endif

#ifdef USE_LEVELDB_COINDB
  /* create fresh "tx.dat" */
  {
    SHCTxDB txdb("cr");
    txdb.Close();
  }
#endif

#if 0
  {
    err = bc_idx_open(chain);
    if (!err) chain->idx_map.hdr->of = 0; /* woopsie-daisy */ 

    bc_t *tx_bc = GetBlockTxChain(iface);
    err = bc_idx_open(tx_bc);
    if (!err) tx_bc->idx_map.hdr->of = 0; /* woopsie-daisy */ 
  }
#endif

  /* unero numero */
  if (!shc_CreateGenesisBlock())
    return (false);

  /* reset hash tables now that their chain is open */
  bc_table_clear(chain);
  bc_table_clear(chain_tx);

#ifdef USE_LEVELDB_COINDB
  SHCTxDB txdb;
#endif

  uint256 hash = shc_hashGenesisBlock;
  {
    sprintf(path, "backup/%s_block", iface->name);
    err = bc_open(path, &bc);
    if (err)
      return error(err, "shc_RestoreBlockIndex: error opening backup block-chain.");

    maxHeight = bc_idx_next(bc);
    for (height = 1; height < maxHeight; height++) {
      int n_height;

      err = bc_get(bc, height, &sBlockData, &sBlockLen);
      if (err)
        break;

      /* serialize binary data into block */
      CDataStream sBlock(SER_DISK, CLIENT_VERSION);
      sBlock.write((const char *)sBlockData, sBlockLen);
      SHCBlock block;
      sBlock >> block;
      hash = block.GetHash();

      err = bc_write(chain, height, hash.GetRaw(), sBlockData, sBlockLen);
      if (err < 0)
        return error(SHERR_INVAL, "block-chain write: %s", sherrstr(n_height));
      free(sBlockData);

      /* write tx ref's */
      BOOST_FOREACH(CTransaction& tx, block.vtx) {
        tx.WriteTx(SHC_COIN_IFACE, height);

#ifdef USE_LEVELDB_COINDB
        nBlockPos = nTxPos = -1;
        (void)bc_idx_find(chain, hash.GetRaw(), NULL, &nBlockPos);
        (void)bc_idx_find(chain_tx, tx.GetHash().GetRaw(), NULL, &nTxPos);
        CDiskTxPos posThisTx(SHC_COIN_IFACE, nBlockPos, nTxPos);
        txdb.AddTxIndex(tx, posThisTx, height);
#else
        EraseTxCoins(iface, tx.GetHash());
#endif
      }
    }
    Debug("shc_RestoreBlocKIndex: database rebuilt -- wrote %d blocks", height);

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

bool SHCTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
  return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool SHCTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
  CTxIndex txindex;
  return ReadDiskTx(outpoint.hash, tx, txindex);
}
bool SHCTxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
  tx.SetNull();
  if (!ReadTxIndex(hash, txindex))
    return false;
  return (tx.ReadFromDisk(txindex.pos));
}

bool SHCTxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
  CTxIndex txindex;
  return ReadDiskTx(hash, tx, txindex);
}



#endif
