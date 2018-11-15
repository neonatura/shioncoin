
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
#include "emc2_pool.h"
#include "emc2_block.h"
#include "emc2_txidx.h"
#include "chain.h"
#include "spring.h"
#include "coin.h"

#include <boost/array.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>


using namespace std;

CScript EMC2_CHARITY_SCRIPT;





CBlockIndex static * InsertBlockIndex(uint256 hash)
{

  if (hash == 0)
    return NULL;

  // Return existing
  blkidx_t *mapBlockIndex = GetBlockTable(EMC2_COIN_IFACE);
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




bool emc2_FillBlockIndex()
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(EMC2_COIN_IFACE);
  bc_t *bc = GetBlockChain(iface);
  CBlockIndex *lastIndex;
  uint256 hash;
	bcpos_t nMaxIndex;
  int nHeight;
  int err;

	nMaxIndex = 0;
	(void)bc_idx_next(bc, &nMaxIndex);

  lastIndex = NULL;
  for (nHeight = 0; nHeight < nMaxIndex; nHeight++) {
		EMC2Block block;
    if (!block.ReadBlock(nHeight)) {
      break;
    }

    hash = block.GetHash();

    if (nHeight == 0) {
      if (hash != emc2_hashGenesisBlock) {
        break; /* invalid genesis */
      }
    } else if (blockIndex->count(block.hashPrevBlock) == 0) {
      break;
    }

    CBlockIndex* pindexNew = InsertBlockIndex(blockIndex, hash);
    if (nHeight == 0) {
      EMC2Block::pindexGenesisBlock = pindexNew;
    }
    pindexNew->pprev = lastIndex;//InsertBlockIndex(blockIndex, block.hashPrevBlock);
    if (lastIndex) lastIndex->pnext = pindexNew;

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

    if (nHeight == 0 && pindexNew->GetBlockHash() == emc2_hashGenesisBlock)
      EMC2Block::pindexGenesisBlock = pindexNew;

		pindexNew->bnChainWork =
			(lastIndex ? lastIndex->bnChainWork : 0) + 
			pindexNew->GetBlockWork();

    lastIndex = pindexNew;
  }
  SetBestBlockIndex(iface, lastIndex);

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
      pindex->GetBlockHash() != emc2_hashGenesisBlock)
    return (false);

  return (true);
}

#ifdef USE_LEVELDB_COINDB
bool EMC2TxDB::LoadBlockIndex()
#else
static bool emc2_LoadBlockIndex()
#endif
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  CWallet *wallet = GetWallet(EMC2_COIN_IFACE);
  blkidx_t *mapBlockIndex = GetBlockTable(EMC2_COIN_IFACE);
  ValidIndexSet *setValid = GetValidIndexSet(EMC2_COIN_IFACE);
  char errbuf[1024];

  if (!emc2_FillBlockIndex())
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
  BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight)
  {
    CBlockIndex* pindex = item.second;
//    pindex->bnChainWork = (pindex->pprev ? pindex->pprev->bnChainWork : 0) + pindex->GetBlockWork();
    setValid->insert(pindex);
  }

  // Load EMC2Block::hashBestChain pointer to end of best chain
  uint256 hashBestChain;
#ifdef USE_LEVELDB_COINDB
  if (!ReadHashBestChain(hashBestChain))
#else
  if (mapBlockIndex->size() == 0 ||
      !::ReadHashBestChain(iface, hashBestChain))
#endif
  {
    if (EMC2Block::pindexGenesisBlock == NULL) {
  //    fprintf(stderr, "DEBUG: EMC2TxDB::LoadBlockIndex() : EMC2Block::hashBestChain not loaded, but pindexGenesisBlock == NULL");
      return true;
    }
    //    return error(SHERR_INVAL, "EMC2TxDB::LoadBlockIndex() : EMC2Block::hashBestChain not loaded");
  }

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
      return error(SHERR_INVAL, "EMC2TxDB::LoadBlockIndex() : EMC2Block::hashBestChain not found in the block index");
//fprintf(stderr, "DEBUG: LoadBlockIndex: falling back to highest block height %d\n", pindexBest->nHeight);
    hashBestChain = pindexBest->GetBlockHash();
  }

  if (!pindexBest) {
//fprintf(stderr, "DEBUG: EMC2TxDB::LoadBlockIndex: error: hashBestChain '%s' not found in block index table\n", (hashBestChain).GetHex().c_str());
  }

  SetBestBlockIndex(EMC2_COIN_IFACE, pindexBest);
  //  SetBestHeight(iface, pindexBest->nHeight);
  wallet->bnBestChainWork = pindexBest->bnChainWork;
  pindexBest->pnext = NULL;

  //printf("LoadBlockIndex(): EMC2Block::hashBestChain=%s  height=%d  date=%s\n", hashBestChain.ToString().substr(0,20).c_str(), GetBestHeight(iface), DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

#ifdef USE_LEVELDB_COINDB
  // Load bnBestInvalidWork, OK if it doesn't exist
  ReadBestInvalidWork(EMC2Block::bnBestInvalidWork);
#endif

  int nCheckDepth = (GetBestHeight(EMC2_COIN_IFACE) / 10000) + 640;
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
    if (fRequestShutdown || pindex->nHeight < GetBestHeight(EMC2_COIN_IFACE) - nCheckDepth)
      break;
    EMC2Block block;
    if (!block.ReadFromDisk(pindex)) {
//fprintf(stderr, "DEBUG: EMC2Block::LoadBlockIndex() : block.ReadFromDisk failed");
      pindexFork = pindex->pprev;
      continue;
    }
    total++;

    if (!block.CheckBlock() ||
        !block.CheckTransactionInputs(EMC2_COIN_IFACE)) {
      error (SHERR_INVAL, "(emc2) LoadBlockIndex: critical: found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());

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
//fprintf(stderr, "DEBUG: LoadBlockIndex() : *** moving best chain pointer back to block %d '%s'\n", pindexFork->nHeight, pindexFork->GetBlockHash().GetHex().c_str());
    EMC2Block block;
    if (!block.ReadFromDisk(pindexFork))
      return error(SHERR_INVAL, "LoadBlockIndex() : block.ReadFromDisk failed");
#ifdef USE_LEVELDB_COINDB
    EMC2TxDB txdb;
    block.SetBestChain(txdb, pindexFork);
    txdb.Close();
#else
    WriteHashBestChain(iface, pindexFork->GetBlockHash());
#endif

    pindexBest = pindexFork;
  }

  /* (simple) validate block chain */
  maxHeight++;
  sprintf(errbuf, "EMC2::LoadBlockIndex: Verified %-2.2f%% of %d total blocks: %d total invalid blocks found.", (double)(100 / (double)maxHeight * (double)total), maxHeight, invalid);
  unet_log(EMC2_COIN_IFACE, errbuf);

  /* (extensive) validate block chain */
  nValidateCheckDepth = MIN(maxHeight-1, nValidateCheckDepth);
  InitServiceValidateEvent(wallet, maxHeight - nValidateCheckDepth);
  sprintf(errbuf, "EMC2::LoadBlockIndex: Initiated block-chain validation of %d total blocks (%-3.3f%%).", nValidateCheckDepth, (100 / (double)maxHeight * (double)nValidateCheckDepth));
  unet_log(EMC2_COIN_IFACE, errbuf);

  /* validate wallet transactions */
  nWalletCheckDepth = MIN(maxHeight-1, nWalletCheckDepth);
  InitServiceWalletEvent(wallet, maxHeight - nWalletCheckDepth);
  sprintf(errbuf, "EMC2::LoadBlockIndex: Initiated wallet validation of %d total blocks (%-3.3f%%).", nWalletCheckDepth, (100 / (double)maxHeight * (double)nWalletCheckDepth));
  unet_log(EMC2_COIN_IFACE, errbuf);

  if (!opt_bool(OPT_EMC2_BACKUP_RESTORE)) {
    BackupBlockChain(iface, maxHeight); 
  }

  return true;
}


bool emc2_InitBlockIndex()
{
  bool ret;

#define CHARITY_ADDRESS "1cec44c9f9b769ae08ebf9d694c7611a16edf615"
  EMC2_CHARITY_SCRIPT << OP_DUP << OP_HASH160 << ParseHex(CHARITY_ADDRESS) << OP_EQUALVERIFY << OP_CHECKSIG;

#ifdef USE_LEVELDB_COINDB
  EMC2TxDB txdb("cr");
  ret = txdb.LoadBlockIndex();
  txdb.Close();
#else
  ret = emc2_LoadBlockIndex();
#endif
  if (!ret)
    return (false);

  if (!emc2_CreateGenesisBlock())
    return (false);

  return (true);
}
   


bool emc2_RestoreBlockIndex()
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  bc_t *chain = GetBlockChain(iface);
  bc_t *chain_tx = GetBlockTxChain(iface);
  bc_t *bc;
  char path[PATH_MAX+1];
  unsigned char *sBlockData;
  size_t sBlockLen;
  bcpos_t maxHeight;
  bcsize_t height;
  int nBlockPos, nTxPos;
  int err;
  bool ret;

#ifdef USE_LEVELDB_COINDB
  {
    EMC2TxDB txdb("cr");
    txdb.Close();
  }
#endif

  if (!emc2_CreateGenesisBlock())
    return (false);

  bc_table_clear(chain);
  bc_table_clear(chain_tx);

#ifdef USE_LEVELDB_COINDB
  EMC2TxDB txdb;
#endif

  uint256 hash = emc2_hashGenesisBlock;
  {
    sprintf(path, "backup/%s_block", iface->name);
    err = bc_open(path, &bc);
    if (err)
      return error(err, "emc2_RestoreBlockIndex: error opening backup block-chain.");

		maxHeight = 0;
		(void)bc_idx_next(bc, &maxHeight);
    for (height = 1; height < maxHeight; height++) {
      int n_height;

      err = bc_get(bc, height, &sBlockData, &sBlockLen);
      if (err)
        break;

      /* serialize binary data into block */
      CDataStream sBlock(SER_DISK, CLIENT_VERSION);
      sBlock.write((const char *)sBlockData, sBlockLen);
      EMC2Block block;
      sBlock >> block;
      hash = block.GetHash();

      err = bc_write(chain, height, hash.GetRaw(), sBlockData, sBlockLen);
      free(sBlockData);
      if (err < 0)
        return error(SHERR_INVAL, "block-chain write: %s", sherrstr(n_height));

      /* write tx ref's */
      BOOST_FOREACH(CTransaction& tx, block.vtx) {
        tx.WriteTx(EMC2_COIN_IFACE, height);
      }

      /* mark spent coins */
      BOOST_FOREACH(CTransaction& tx, block.vtx) {
        if (tx.IsCoinBase())
          continue;

        const uint256& tx_hash = tx.GetHash();
        BOOST_FOREACH(const CTxIn& in, tx.vin) {
          CTransaction in_tx;
          if (GetTransaction(iface, in.prevout.hash, in_tx, NULL))
            in_tx.WriteCoins(EMC2_COIN_IFACE, in.prevout.n, tx_hash);
        }
      }

    }
    Debug("emc2_RestoreBlocKIndex: database rebuilt -- wrote %d blocks\n", height);

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

bool EMC2TxDB::WriteFlag(const std::string &name, bool fValue) 
{
  return Write(std::make_pair('F', name), fValue ? '1' : '0');
}

bool EMC2TxDB::ReadFlag(const std::string &name, bool &fValue) 
{
  char ch;
  if (!Read(std::make_pair('F', name), ch))
    return false;
  fValue = ch == '1';
  return true;
}

bool EMC2TxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
  tx.SetNull();
  if (!ReadTxIndex(hash, txindex))
    return false;
  return (tx.ReadFromDisk(txindex.pos));
}

bool EMC2TxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
  CTxIndex txindex;
  return ReadDiskTx(hash, tx, txindex);
}

bool EMC2TxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
  return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool EMC2TxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
  CTxIndex txindex;
  return ReadDiskTx(outpoint.hash, tx, txindex);
}

#endif


