
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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

#include "shcoind.h"
#include "wallet.h"
#include "net.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "color_pool.h"
#include "color_block.h"
#include "color_txidx.h"
#include "chain.h"
#include "spring.h"
#include "coin.h"

#include <boost/array.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>

using namespace std;
using namespace boost;


CBlockIndex static * InsertBlockIndex(uint256 hash)
{

  if (hash == 0)
    return NULL;

  // Return existing
  blkidx_t *mapBlockIndex = GetBlockTable(COLOR_COIN_IFACE);
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
static bool color_FillBlockIndex()
{
  CIface *iface = GetCoinByIndex(COLOR_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(COLOR_COIN_IFACE);
  bc_t *bc = GetBlockChain(iface);
	CBlockIndex *bestIndex;
  uint256 hash;
	bcpos_t nMaxIndex;
  bcpos_t nHeight;
	int mode;
  int err;

	nMaxIndex = 0;
	bc_idx_next(bc, &nMaxIndex);
//	nMaxIndex = MAX(1, nMaxIndex) - 1;

	bestIndex = NULL;
	for (nHeight = 0; nHeight < nMaxIndex; nHeight++) {
		COLORBlock block;
    if (!block.ReadBlock(nHeight))
      break;

    hash = block.GetHash();

    CBlockIndex* pindexNew = InsertBlockIndex(blockIndex, hash);
		if (blockIndex->count(block.hashPrevBlock) != 0) {
			pindexNew->pprev = (*blockIndex)[block.hashPrevBlock];
			pindexNew->pprev->pnext = pindexNew;
		}

		if (pindexNew->pprev)
			pindexNew->nHeight = pindexNew->pprev->nHeight + 1;

    pindexNew->nVersion       = block.nVersion;
    pindexNew->hashMerkleRoot = block.hashMerkleRoot;
    pindexNew->nTime          = block.nTime;
    pindexNew->nBits          = block.nBits;
    pindexNew->nNonce         = block.nNonce;

		pindexNew->nStatus |= BLOCK_HAVE_DATA;

    if (!pindexNew->CheckIndex())
      return error(SHERR_INVAL, "LoadBlockIndex() : CheckIndex failed at height %d", pindexNew->nHeight);

    if (!pindexNew->pprev) {
			pindexNew->bnChainWork = pindexNew->GetBlockWork();
		} else {
			pindexNew->bnChainWork = 
				pindexNew->pprev->bnChainWork  + pindexNew->GetBlockWork();
		}

    bestIndex = pindexNew;
  }

  SetBestBlockIndex(iface, bestIndex);
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

  return (true);
}

static bool color_LoadBlockIndex()
{
  int ifaceIndex = COLOR_COIN_IFACE;
  CIface *iface = GetCoinByIndex(COLOR_COIN_IFACE);
  CWallet *wallet = GetWallet(COLOR_COIN_IFACE);
  blkidx_t *mapBlockIndex = GetBlockTable(COLOR_COIN_IFACE);
  char errbuf[1024];
	int mode;

	/* color chain still populates CBlockIndex but extra care is taken to make sure the ->prev pointer is isolated to a particular color. */
  if (!color_FillBlockIndex())
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
  }
  if (pindex) {
    Debug("color_LoadBlockIndex: chain work calculated (%s) for %d blocks.", pindex->bnChainWork.ToString().c_str(), vSortedByHeight.size());
  }

  // Load COLORBlock::hashBestChain pointer to end of best chain
  uint256 hashBestChain;
  if (mapBlockIndex->size() == 0 ||
      !ReadHashBestChain(iface, hashBestChain))
  {
    if (COLORBlock::pindexGenesisBlock == NULL) {
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
      return error(SHERR_INVAL, "COLORTxDB::LoadBlockIndex() : COLORBlock::hashBestChain not found in the block index");
    hashBestChain = pindexBest->GetBlockHash();
  }

  SetBestBlockIndex(COLOR_COIN_IFACE, pindexBest);
  wallet->bnBestChainWork = pindexBest->bnChainWork;
  pindexBest->pnext = NULL;

  int nCheckDepth = (GetBestHeight(COLOR_COIN_IFACE) / 640) + 640;
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
    if (fRequestShutdown || pindex->nHeight < GetBestHeight(COLOR_COIN_IFACE) - nCheckDepth)
      break;
    COLORBlock block;
    if (!block.ReadFromDisk(pindex)) {
      pindexFork = pindex->pprev;
      continue;
    }
    total++;

    if (!block.CheckBlock() ||
        !block.CheckTransactionInputs(COLOR_COIN_IFACE)) {
      error (SHERR_INVAL, "(color) LoadBlockIndex: critical: found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());

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
    COLORBlock block;
    if (!block.ReadFromDisk(pindexFork))
      return error(SHERR_INVAL, "LoadBlockIndex() : block.ReadFromDisk failed");
    WriteHashBestChain(iface, pindexFork->GetBlockHash());

    pindexBest = pindexFork;
  }

  /* (simple) validate block chain */
  maxHeight++;
  sprintf(errbuf, "COLOR::LoadBlockIndex: Verified %-3.3f%% of %d total blocks: %d total invalid blocks found.", (double)(100 / (double)maxHeight * (double)total), maxHeight, invalid);
  unet_log(COLOR_COIN_IFACE, errbuf);

  return true;
}

bool color_InitBlockIndex()
{
  bool ret;

  ret = color_LoadBlockIndex();
  if (!ret)
    return (false);

  return (true);
}


