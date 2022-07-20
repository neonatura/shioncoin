
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
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

#include "shcoind.h"
#include "wallet.h"
#include "net.h"
#include "strlcpy.h"
#include "shc_pool.h"
#include "shc_block.h"
#include "shc_txidx.h"
#include "chain.h"
#include "spring.h"
#include "coin.h"
#include "ext/ext_param.h"

#include <boost/array.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>

using namespace std;
using namespace boost;

extern bool IsIdentTx(const CTransaction& tx);

extern bool shc_VerifyCheckpointHeight(int nHeight, uint256 hash);


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
bool shc_FillBlockIndex(txlist& vSpring, txlist& vCert, txlist& vIdent, txlist& vLicense, txlist& vAlias, txlist& vContext, txlist& vExec, txlist& vOffer, txlist& vAsset)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  bc_t *bc = GetBlockChain(iface);
  CBlockIndex *lastIndex;
  uint256 hash;
	bcpos_t nMaxIndex;
  bcpos_t nHeight;
	int mode;
  int err;

	vector<uint256> vTx;
	vector<uint256> vBlock;

	nMaxIndex = 0;
	bc_idx_next(bc, &nMaxIndex);
	nMaxIndex = MAX(1, nMaxIndex);// - 1;

	uint256 hTip;
	ReadHashBestChain(iface, hTip);

	lastIndex = NULL;
	for (nHeight = 0; nHeight < nMaxIndex; nHeight++) {
		SHCBlock block;
    if (!block.ReadBlock(nHeight))
      break;

    hash = block.GetHash();

		if (!shc_VerifyCheckpointHeight(nHeight, hash)) {
			error(ERR_INVAL, "(shc) LoadBlockIndex: checkpoint failure at height %d (block \"%s\").", nHeight, hash.GetHex().c_str());
			break;
		}


    CBlockIndex* pindexNew = InsertBlockIndex(blockIndex, hash);
		pindexNew->pprev = lastIndex;
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
      SHCBlock::pindexGenesisBlock = pindexNew;

		pindexNew->bnChainWork = 
			(lastIndex ? lastIndex->bnChainWork : 0) + 
			pindexNew->GetBlockWork();

		bool fCheck = true;

		opcodetype opcode;
		BOOST_FOREACH(CTransaction& tx, block.vtx) {

			bool fCoinbase = tx.IsCoinBase();

			/* stats */
			BOOST_FOREACH(const CTxOut& out, tx.vout) {
				bool fReturn = false;
				const CScript& script = out.scriptPubKey;
				CScript::const_iterator pc = script.begin();
				while (script.GetOp(pc, opcode)) {
					if (opcode == OP_RETURN) {
						STAT_TX_RETURNS(iface) += out.nValue;
						fReturn = true;
						break;
					}
				}
				if (fCoinbase && !fReturn) {
					STAT_TX_MINT(iface) += out.nValue;
				}
			}

			/* register extended transactions. */
			if (fCoinbase) {
				int nMode;
				if (VerifyMatrixTx(tx, nMode)) {
					if (nMode == OP_EXT_VALIDATE) {
						BlockAcceptValidateMatrix(iface, tx, lastIndex, fCheck);
					} else if (nMode == OP_EXT_PAY) {
						vSpring.push_back(pindexNew);
					}
				}
			} else {
				/* check for notary tx */
				if (tx.vin.size() == 1 && tx.vout.size() == 1 &&
						tx.vout[0].nValue <= CTxMatrix::MAX_NOTARY_TX_VALUE) {
					ProcessValidateMatrixNotaryTx(iface, tx);
				}
			}

			if (tx.isFlag(CTransaction::TXF_ALIAS)) {
				if (IsAliasTx(tx))
					vAlias.push_back(pindexNew);
      }

      if (tx.isFlag(CTransaction::TXF_CERTIFICATE)) {
				if (IsCertTx(tx))
          vCert.push_back(pindexNew);
      } else if (tx.isFlag(CTransaction::TXF_LICENSE)) {
				if (IsLicenseTx(tx))
					vLicense.push_back(pindexNew);
      }

      if (tx.isFlag(CTransaction::TXF_CONTEXT)) {
				if (IsContextTx(tx))
					vContext.push_back(pindexNew);
			}

      if (tx.isFlag(CTransaction::TXF_IDENT)) {
				if (IsIdentTx(tx))
					vIdent.push_back(pindexNew);
			}

			if (tx.isFlag(CTransaction::TXF_ASSET)) {
				if (IsAssetTx(tx))
					vAsset.push_back(pindexNew);
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

      if (tx.isFlag(CTransaction::TXF_PARAM)) {
				if (IsParamTx(tx)) {
					ConnectParamTx(iface, &tx, lastIndex);
				}
			}
    } /* FOREACH (tx) */

		if (!fCheck) {
			error(ERR_INVAL, "(shc) FillBlockIndex: invalid matrix at height %d (block \"%s\").", pindexNew->nHeight, pindexNew->GetBlockHash().GetHex().c_str());
			break;
		}

    lastIndex = pindexNew;

		if (hash == hTip)
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
      pindex->GetBlockHash() != shc_hashGenesisBlock)
    return (false);

  return (true);
}


static bool shc_LoadBlockIndex()
{
  int ifaceIndex = SHC_COIN_IFACE;
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  CWallet *wallet = GetWallet(SHC_COIN_IFACE);
  blkidx_t *mapBlockIndex = GetBlockTable(SHC_COIN_IFACE);
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
	txlist vAsset;

  if (!shc_FillBlockIndex(vSpring, vCert, vIdent, vLicense, vAlias, vContext, vExec, vOffer, vAsset))
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
    Debug("shc_LoadBlockIndex: chain work calculated (%s) for %d blocks.", pindex->bnChainWork.ToString().c_str(), vSortedByHeight.size());
  }

  // Load SHCBlock::hashBestChain pointer to end of best chain
  uint256 hashBestChain;
  if (mapBlockIndex->size() == 0 ||
      !ReadHashBestChain(iface, hashBestChain))
  {
    if (SHCBlock::pindexGenesisBlock == NULL) {
      return true;
    }
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
      return error(SHERR_INVAL, "SHCTxDB::LoadBlockIndex() : SHCBlock::hashBestChain not found in the block index");
    hashBestChain = pindexBest->GetBlockHash();
  }


  SetBestBlockIndex(SHC_COIN_IFACE, pindexBest);
  //  SetBestHeight(iface, pindexBest->nHeight);
  wallet->bnBestChainWork = pindexBest->bnChainWork;
  pindexBest->pnext = NULL;

  //printf("LoadBlockIndex(): SHCBlock::hashBestChain=%s  height=%d  date=%s\n", hashBestChain.ToString().substr(0,20).c_str(), GetBestHeight(iface), DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

  int nCheckDepth = (GetBestHeight(SHC_COIN_IFACE) / 640) + 640;
  int nWalletCheckDepth = nCheckDepth * 1.5;
  int nValidateCheckDepth = nCheckDepth * 3;
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
//fprintf(stderr, "DEBUG: SHCBlock::LoadBlockIndex() : block.ReadFromDisk failed");
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
  if (pindexFork && !fRequestShutdown) {
    // Reorg back to the fork
    SHCBlock block;
    if (!block.ReadFromDisk(pindexFork))
      return error(SHERR_INVAL, "LoadBlockIndex() : block.ReadFromDisk failed");
    WriteHashBestChain(iface, pindexFork->GetBlockHash());
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
      //CIdent& ident = (CIdent&)id_tx.certificate;
      CIdent& ident = (CIdent&)id_tx.ident;
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
      if (tx.isFlag(CTransaction::TXF_CERTIFICATE)) {
				InsertCertTable(iface, tx, pindex->nHeight);
			}
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

	/* asset */
  BOOST_FOREACH(CBlockIndex *pindex, vAsset) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (IsAssetTx(tx))
        ProcessAssetTx(iface, tx, pindex->nHeight);
    }
    delete block;
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

bool shc_InitBlockIndex()
{
  bool ret;

  ret = shc_LoadBlockIndex();
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
  bcpos_t maxHeight;
  bcpos_t height;
  int nTxPos;
  int err;
  bool ret;

/* NOTE: remove "shc_block.*" and "shc_tx.*" first */

  /* unero numero */
  if (!shc_CreateGenesisBlock())
    return (false);

  /* reset hash tables now that their chain is open */
  bc_table_clear(chain);
  bc_table_clear(chain_tx);

  uint256 hash = shc_hashGenesisBlock;
  {
    sprintf(path, "backup/%s_block", iface->name);
    err = bc_open(path, &bc);
    if (err)
      return error(err, "shc_RestoreBlockIndex: error opening backup block-chain.");

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
      SHCBlock block;
      sBlock >> block;
      hash = block.GetHash();

      err = bc_write(chain, height, hash.GetRaw(), sBlockData, sBlockLen);
      free(sBlockData);
      if (err < 0)
        return error(SHERR_INVAL, "block-chain write: %s", sherrstr(n_height));

      /* write tx ref's */
      BOOST_FOREACH(CTransaction& tx, block.vtx) {
        tx.WriteTx(SHC_COIN_IFACE, height);
      }

      /* mark spent coins */
      BOOST_FOREACH(CTransaction& tx, block.vtx) {
        if (tx.IsCoinBase())
          continue;

        const uint256& tx_hash = tx.GetHash();
        BOOST_FOREACH(const CTxIn& in, tx.vin) {
          CTransaction in_tx;
          if (GetTransaction(iface, in.prevout.hash, in_tx, NULL))
            in_tx.WriteCoins(SHC_COIN_IFACE, in.prevout.n, tx_hash);
        }
      }
    }
    Debug("shc_RestoreBlocKIndex: database rebuilt -- wrote %d blocks", height);

    bc_close(bc);
  }
  bc_idle(chain);
  bc_idle(chain_tx);

  WriteHashBestChain(iface, hash);

  return (true);
}


