
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

#include "shcoind.h"
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "testnet_pool.h"
#include "testnet_block.h"
#include "testnet_txidx.h"
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
  blkidx_t *mapBlockIndex = GetBlockTable(TESTNET_COIN_IFACE);
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
bool testnet_FillBlockIndex(txlist& vSpring, txlist& vCert, txlist& vIdent, txlist& vLicense, txlist& vAlias, txlist& vContext, txlist& vExec, txlist& vOffer)
{
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);
  CWallet *wallet = GetWallet(TESTNET_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(TESTNET_COIN_IFACE);
  bc_t *bc = GetBlockChain(iface);
  CBlockIndex *lastIndex;
  uint256 hash;
	bcpos_t nMaxIndex;
	bcpos_t nHeight;
	opcodetype opcode;
  int err;
	int mode;

	nMaxIndex = 0;
	(void)bc_idx_next(bc, &nMaxIndex);

	uint256 hTip;
	ReadHashBestChain(iface, hTip);

	lastIndex = NULL;
  for (nHeight = 0; nHeight < nMaxIndex; nHeight++) {
		TESTNETBlock block;
    if (!block.ReadBlock(nHeight))
			break;

    hash = block.GetHash();

    CBlockIndex* pindexNew = InsertBlockIndex(blockIndex, hash);
		pindexNew->pprev = lastIndex;//InsertBlockIndex(blockIndex, block.hashPrevBlock);
		if (lastIndex) lastIndex->pnext = pindexNew;

    pindexNew->nHeight        = nHeight;
    pindexNew->nVersion       = block.nVersion;
    pindexNew->hashMerkleRoot = block.hashMerkleRoot;
    pindexNew->nTime          = block.nTime;
    pindexNew->nBits          = block.nBits;
    pindexNew->nNonce         = block.nNonce;

		pindexNew->nStatus |= BLOCK_HAVE_DATA;

    if (lastIndex)
      pindexNew->BuildSkip();

    if (!pindexNew->CheckIndex())
      return error(SHERR_INVAL, "LoadBlockIndex() : CheckIndex failed at height %d", pindexNew->nHeight);

    if (nHeight == 0)
      TESTNETBlock::pindexGenesisBlock = pindexNew;

		pindexNew->bnChainWork =
			(lastIndex ? lastIndex->bnChainWork : 0) + 
			pindexNew->GetBlockWork();

		bool fCheck = true;

    BOOST_FOREACH(CTransaction& tx, block.vtx) {
			/* stats */
			BOOST_FOREACH(const CTxOut& out, tx.vout) {
				const CScript& script = out.scriptPubKey;
				CScript::const_iterator pc = script.begin();
				while (script.GetOp(pc, opcode)) {
					if (opcode == OP_RETURN) {
						STAT_TX_RETURNS(iface) += out.nValue;
						break;
					}
				}
			}

			/* register extended transactions. */
			if (tx.IsCoinBase()) {
				int nMode;
				if (VerifyMatrixTx(tx, nMode)) {
					if (nMode == OP_EXT_VALIDATE) {
						BlockAcceptValidateMatrix(iface, tx, pindexNew, fCheck);
					} else if (nMode == OP_EXT_PAY) {
						vSpring.push_back(pindexNew);
					}
				}
			} else {
				/* check for notary tx */
				if (tx.vin.size() == 1 && tx.vout.size() == 1 &&
						tx.vout[0].nValue <= MIN_INPUT_VALUE(iface)) {
					ProcessValidateMatrixNotaryTx(iface, tx);
				}
			}

			if (tx.isFlag(CTransaction::TXF_ALIAS)) {
        if (IsAliasTx(tx))
          vAlias.push_back(pindexNew);
      } 

			if (tx.isFlag(CTransaction::TXF_ASSET)) {
        /* not implemented. */
      } else if (tx.isFlag(CTransaction::TXF_CERTIFICATE)) {
        if (IsCertTx(tx))
          vCert.push_back(pindexNew);
      } else if (tx.isFlag(CTransaction::TXF_CONTEXT)) {
        if (IsContextTx(tx))
          vContext.push_back(pindexNew);
      } else if (tx.isFlag(CTransaction::TXF_CHANNEL)) {
        /* not implemented */
      } else if (tx.isFlag(CTransaction::TXF_IDENT)) {
        if (IsIdentTx(tx))
          vIdent.push_back(pindexNew);
      } else if (tx.isFlag(CTransaction::TXF_LICENSE)) {
        if (IsLicenseTx(tx))
          vLicense.push_back(pindexNew);
      } 

			/* non-exclusive */
			if (tx.isFlag(CTransaction::TXF_OFFER)) {
				if (IsOfferTx(tx))
					vOffer.push_back(pindexNew);
      }

			/* non-exclusive */
      if (tx.isFlag(CTransaction::TXF_EXEC)) {
        if (IsExecTx(tx, mode))
          vExec.push_back(pindexNew);
			}

			/* track highest block on alt-chain. */
			if (tx.isFlag(CTransaction::TXF_ALTCHAIN)) {
				if (IsAltChainTx(tx)) {
					CommitAltChainTx(iface, tx, NULL, true);
				}
			}
    } /* FOREACH (tx) */

		if (!fCheck) {
			error(ERR_INVAL, "(shc) FillBlockIndex: invalid matrix at height %d (block \"%s\").", pindexNew->nHeight, pindexNew->GetBlockHash().GetHex().c_str());
			break;
		}

    lastIndex = pindexNew;

		if (hTip == hash)
			break;
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
      pindex->GetBlockHash() != testnet_hashGenesisBlock)
    return (false);

  return (true);
}

static bool testnet_LoadBlockIndex()
{
  int ifaceIndex = TESTNET_COIN_IFACE;
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);
  CWallet *wallet = GetWallet(TESTNET_COIN_IFACE);
  blkidx_t *mapBlockIndex = GetBlockTable(TESTNET_COIN_IFACE);
  char errbuf[1024];
	int mode;

  txlist vSpring;
  txlist vCert;
  txlist vIdent;
  txlist vLicense;
  txlist vAlias;
  txlist vContext;
	txlist vExec;
	txlist vOffer;
  if (!testnet_FillBlockIndex(vSpring, vCert, vIdent, vLicense, vAlias, vContext, vExec, vOffer))
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
//    pindex->bnChainWork = (pindex->pprev ? pindex->pprev->bnChainWork : 0) + pindex->GetBlockWork();
  }
  if (pindex) {
    Debug("testnet_LoadBlockIndex: chain work calculated (%s) for %d blocks.", pindex->bnChainWork.ToString().c_str(), vSortedByHeight.size());
  }

  // Load TESTNETBlock::hashBestChain pointer to end of best chain
  uint256 hashBestChain;
  if (mapBlockIndex->size() == 0 ||
      !ReadHashBestChain(iface, hashBestChain))
  {
    if (TESTNETBlock::pindexGenesisBlock == NULL) {
      return true;
    }
    //    return error(SHERR_INVAL, "TESTNETTxDB::LoadBlockIndex() : TESTNETBlock::hashBestChain not loaded");
  }
#if 0
  if (!mapBlockIndex->count(hashBestChain)) {
    CBlockIndex *pindexBest = GetBestBlockIndex(iface);
    if (!pindexBest)
      return error(SHERR_INVAL, "TESTNETTxDB::LoadBlockIndex() : TESTNETBlock::hashBestChain not found in the block index");
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
      return error(SHERR_INVAL, "TESTNETTxDB::LoadBlockIndex() : TESTNETBlock::hashBestChain not found in the block index");
    hashBestChain = pindexBest->GetBlockHash();
  }

  if (!pindexBest) {
//fprintf(stderr, "DEBUG: TESTNETTxDB::LoadBlockIndex: error: hashBestChain '%s' not found in block index table\n", (hashBestChain).GetHex().c_str());
  }

  SetBestBlockIndex(TESTNET_COIN_IFACE, pindexBest);
  //  SetBestHeight(iface, pindexBest->nHeight);
  wallet->bnBestChainWork = pindexBest->bnChainWork;
  pindexBest->pnext = NULL;

  Debug("LoadBlockIndex(): TESTNETBlock::hashBestChain=%s  height=%d  date=%s\n", hashBestChain.ToString().substr(0,20).c_str(), GetBestHeight(iface), DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());


  int nCheckDepth = (GetBestHeight(TESTNET_COIN_IFACE) / 10000) + 640;
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
    if (fRequestShutdown || pindex->nHeight < GetBestHeight(TESTNET_COIN_IFACE) - nCheckDepth)
      break;
    TESTNETBlock block;
    if (!block.ReadFromDisk(pindex)) {
//fprintf(stderr, "DEBUG: TESTNETBlock::LoadBlockIndex() : block.ReadFromDisk failed");
      pindexFork = pindex->pprev;
      continue;
    }
    total++;

    if (!block.CheckBlock() ||
        !block.CheckTransactionInputs(TESTNET_COIN_IFACE)) {
      error (SHERR_INVAL, "(testnet) LoadBlockIndex: critical: found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());

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
    TESTNETBlock block;
    if (!block.ReadFromDisk(pindexFork))
      return error(SHERR_INVAL, "LoadBlockIndex() : block.ReadFromDisk failed");
    WriteHashBestChain(iface, pindexFork->GetBlockHash());

    pindexBest = pindexFork;
  }

  /* (simple) validate block chain */
  maxHeight++;
  sprintf(errbuf, "TESTNET::LoadBlockIndex: Verified %-3.3f%% of %d total blocks: %d total invalid blocks found.", (double)(100 / (double)maxHeight * (double)total), maxHeight, invalid);
  unet_log(TESTNET_COIN_IFACE, errbuf);

  /* (extensive) validate block chain */
  nValidateCheckDepth = MIN(maxHeight-1, nValidateCheckDepth);
  InitServiceValidateEvent(wallet, maxHeight - nValidateCheckDepth);
  sprintf(errbuf, "TESTNET::LoadBlockIndex: Initiated block-chain validation of %d total blocks (%-3.3f%%).", nValidateCheckDepth, (100 / (double)maxHeight * (double)nValidateCheckDepth));
  unet_log(TESTNET_COIN_IFACE, errbuf);

  /* validate wallet transactions */
  nWalletCheckDepth = MIN(maxHeight-1, nWalletCheckDepth);
  InitServiceWalletEvent(wallet, maxHeight - nWalletCheckDepth);
  sprintf(errbuf, "TESTNET::LoadBlockIndex: Initiated wallet validation of %d total blocks (%-3.3f%%).", nWalletCheckDepth, (100 / (double)maxHeight * (double)nWalletCheckDepth));
  unet_log(TESTNET_COIN_IFACE, errbuf);

#if 0
  if (!opt_bool(OPT_TESTNET_BACKUP_RESTORE)) {
    BackupBlockChain(iface, maxHeight); 
  }
#endif

  /* ident */
//  std::reverse(vIdent.begin(), vIdent.end());
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
//  std::reverse(vSpring.begin(), vSpring.end());
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

//  std::reverse(vCert.begin(), vCert.end());
  BOOST_FOREACH(CBlockIndex *pindex, vCert) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (IsCertTx(tx))
        InsertCertTable(iface, tx, pindex->nHeight);
    }
    delete block;
  }

  /* license */
//  std::reverse(vLicense.begin(), vLicense.end());
  BOOST_FOREACH(CBlockIndex *pindex, vLicense) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (IsLicenseTx(tx))
        CommitLicenseTx(iface, tx, pindex->nHeight);
    }
    delete block;
  }

  /* alias */
//  std::reverse(vAlias.begin(), vAlias.end());
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
//  std::reverse(vContext.begin(), vContext.end());
  BOOST_FOREACH(CBlockIndex *pindex, vContext) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (IsContextTx(tx))
        CommitContextTx(iface, tx, pindex->nHeight);
    }
    delete block;
  }

	/* exec */
	uint256 lhash;
  BOOST_FOREACH(CBlockIndex *pindex, vExec) {
		if (lhash == pindex->GetBlockHash())
			continue;

    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
			if (IsExecTx(tx, mode)) {
				ProcessExecTx(iface, NULL, tx, pindex->nHeight);
			}
    }
    delete block;

		lhash = pindex->GetBlockHash();
  }

  /* offer */
  BOOST_FOREACH(CBlockIndex *pindex, vOffer) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (IsOfferTx(tx))
        CommitOfferTx(iface, tx, pindex->nHeight);
    }
    delete block;
  }

  return true;
}


#if 0
bool TESTNETTxDB::LoadBlockIndexGuts()
{
  blkidx_t *mapBlockIndex = GetBlockTable(TESTNET_COIN_IFACE);

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
        if (TESTNETBlock::pindexGenesisBlock == NULL && diskindex.GetBlockHash() == testnet_hashGenesisBlock) {
          TESTNETBlock::pindexGenesisBlock = pindexNew;
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


bool testnet_InitBlockIndex()
{
  bool ret;

  ret = testnet_LoadBlockIndex();
  if (!ret)
    return (false);

  if (!testnet_CreateGenesisBlock())
    return (false);

  return (true);
}

bool testnet_RestoreBlockIndex()
{
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);
  bc_t *chain = GetBlockChain(iface);
  bc_t *chain_tx = GetBlockTxChain(iface);
  bc_t *bc;
  char path[PATH_MAX+1];
  unsigned char *sBlockData;
  size_t sBlockLen;
  bcpos_t maxHeight;
  bcpos_t height;
  int nTxPos;
  int err;
  bool ret;

/* DEBUG: TODO: remove "testnet_block.*" and "testnet_tx.*" first */

#if 0
  {
    CWallet *wallet = GetWallet(iface);
    if (wallet) {
fprintf(stderr, "DEBUG: testnet_RestoreBlockIndex: erasing %d wallet transactions.\n", wallet->mapWallet.size());
      wallet->mapWallet.clear(); 
    }
  }
  {
    /* wipe old block-chain index  */
fprintf(stderr, "DEBUG: testnet_RestoreBlockIndex: erased current block-chain index (%u bytes).\n", (unsigned int)chain->idx_map.hdr->of);
    chain->idx_map.hdr->of = 0;
  }
#endif



  /* unero numero */
  if (!testnet_CreateGenesisBlock())
    return (false);

  /* reset hash tables now that their chain is open */
  bc_table_clear(chain);
  bc_table_clear(chain_tx);


  uint256 hash = testnet_hashGenesisBlock;
  {
    sprintf(path, "backup/%s_block", iface->name);
    err = bc_open(path, &bc);
    if (err)
      return error(err, "testnet_RestoreBlockIndex: error opening backup block-chain.");

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
      TESTNETBlock block;
      sBlock >> block;
      hash = block.GetHash();

      err = bc_write(chain, height, hash.GetRaw(), sBlockData, sBlockLen);
      free(sBlockData);
      if (err < 0)
        return error(SHERR_INVAL, "block-chain write: %s", sherrstr(n_height));

      /* write tx ref's */
      BOOST_FOREACH(CTransaction& tx, block.vtx) {
        tx.WriteTx(TESTNET_COIN_IFACE, height);

      }

      /* mark spent coins */
      BOOST_FOREACH(CTransaction& tx, block.vtx) {
        if (tx.IsCoinBase())
          continue;

        const uint256& tx_hash = tx.GetHash();
        BOOST_FOREACH(const CTxIn& in, tx.vin) {
          CTransaction in_tx;
          if (GetTransaction(iface, in.prevout.hash, in_tx, NULL))
            in_tx.WriteCoins(TESTNET_COIN_IFACE, in.prevout.n, tx_hash);
        }
      }
    }
    Debug("testnet_RestoreBlocKIndex: database rebuilt -- wrote %d blocks", height);

    bc_close(bc);
  }
  bc_idle(chain);
  bc_idle(chain_tx);

  WriteHashBestChain(iface, hash);

  return (true);
}

