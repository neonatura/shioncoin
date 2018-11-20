
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
#include "wallet.h"
#include "chain.h"
#include "coin.h"

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

using namespace std;
using namespace boost;

#define MAX_BLOCK_DOWNLOAD_BATCH 64 /* 4m block * 64 = 256m */

ChainOp chain;


extern CCriticalSection cs_main;


#ifdef __cplusplus
extern "C" {
#endif
static void set_serv_state(CIface *iface, int flag)
{
  char errbuf[256];

  iface->flags |= flag;

  memset(errbuf, 0, sizeof(errbuf));
  if (flag & COINF_DL_SCAN) {
    strcpy(errbuf, "entering service mode: download block-chain [scan]");
  } else if (flag & COINF_WALLET_SCAN) {
    strcpy(errbuf, "entering service mode: wallet tx [scan]");
  } else if (flag & COINF_PEER_SCAN) {
    strcpy(errbuf, "entering service mode: peer list [scan]");
  } else if (flag & COINF_VALIDATE_SCAN) {
    strcpy(errbuf, "entering service mode: validate chain [scan]");
  }
  if (*errbuf)
    unet_log(GetCoinIndex(iface), errbuf);
}

static void unset_serv_state(CIface *iface, int flag)
{
  char errbuf[256];

  iface->flags &= ~flag;

  memset(errbuf, 0, sizeof(errbuf));
  if (flag & COINF_DL_SCAN) {
    strcpy(errbuf, "exiting service mode: download block-chain [scan]");
  } else if (flag & COINF_WALLET_SCAN) {
    strcpy(errbuf, "exiting service mode: wallet tx [scan]");
  } else if (flag & COINF_PEER_SCAN) {
    strcpy(errbuf, "exiting service mode: peer list [scan]");
  } else if (flag & COINF_VALIDATE_SCAN) {
    strcpy(errbuf, "exiting service mode: validate chain [scan]");
  }
  if (*errbuf)
    unet_log(GetCoinIndex(iface), errbuf);
}
static bool serv_state(CIface *iface, int flag)
{
  return (iface->flags & flag);
}
#ifdef __cplusplus
}
#endif



static void chain_UpdateWalletCoins(int ifaceIndex, const CTransaction& tx)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);
  uint256 tx_hash = tx.GetHash();

  BOOST_FOREACH(const CTxIn& txin, tx.vin) {
    const uint256& hash = txin.prevout.hash;
    int nOut = txin.prevout.n;

    if (wallet->mapWallet.count(hash) != 0) {
      vector<uint256> vOuts;
      CWalletTx& wtx = wallet->mapWallet[hash];

			/* coin db */
      if (wtx.ReadCoins(ifaceIndex, vOuts) &&
          nOut < vOuts.size() && vOuts[nOut].IsNull()) {
        vOuts[nOut] = tx_hash;
        if (wtx.WriteCoins(ifaceIndex, vOuts)) {
          Debug("(%s) core_UpdateCoins: updated tx \"%s\" [spent on \"%s\"].", iface->name, hash.GetHex().c_str(), tx_hash.GetHex().c_str());
        }
      }

			/* wallet db */
			if (!wtx.IsSpent(nOut) && wallet->IsMine(wtx.vout[nOut])) {
				wtx.MarkSpent(nOut);
				wtx.WriteToDisk();
			}
    }
  }
 
}

static bool ServiceWalletEvent(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (false);

  CWallet *wallet = GetWallet(iface);
  if (!wallet)
    return (false); /* no-op */

  unsigned int nBestHeight = GetBestHeight(iface);
  unsigned int nStartHeight = wallet->nScanHeight;
  unsigned int nHeight = wallet->nScanHeight;
  unsigned int nMaxHeight = nHeight + 1024;

  if (nHeight <= nBestHeight) {
    LOCK(wallet->cs_wallet);

    for (; nHeight <= nBestHeight && nHeight < nMaxHeight; nHeight++) {
      CBlock *block = GetBlockByHeight(iface, nHeight);
      if (!block) continue;

			/* check for new wallet tx's */
      BOOST_FOREACH(const CTransaction& tx, block->vtx) {
				if (wallet->mapWallet.count(tx.GetHash()) != 0)
					continue;
/* opt_bool(OPT_WALLET_REACCEPT */

#if 0
				if (wallet->mapWallet.count(tx.GetHash()) == 0) {
					/* check for a known relationship */
					wallet->AddToWalletIfInvolvingMe(tx, block, false, false);
				}
#endif

				/* check whether this a local tx */
				BOOST_FOREACH(const CTxOut& txout, tx.vout) {
					CTxDestination address;

					if (!ExtractDestination(txout.scriptPubKey, address) || 
							!IsMine(*wallet, address))
						continue;

					CWalletTx wtx(wallet, tx);
					wtx.SetMerkleBranch(block);
					wallet->AddToWallet(wtx);
					break;
				}
      }

			/* enforce validity on wallet & recent tx's spent chain */
      BOOST_FOREACH(const CTransaction& tx, block->vtx) {
				if (!tx.IsCoinBase())
					chain_UpdateWalletCoins(ifaceIndex, tx);
      }

      delete block;
      wallet->nScanHeight = nHeight;
    }
  }
  Debug("ServiceWalletEvent: scanned blocks %d .. %d", nStartHeight, nHeight);

  if (nHeight >= nBestHeight) {
    /* service event has completed task. */
    return (false); 
  }

  return (true);
}

static bool ServiceValidateEvent(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);
  if (!iface || !wallet) return (false);

  unsigned int nBestHeight = GetBestHeight(iface);
  unsigned int nStartHeight = wallet->nValidateHeight;
  unsigned int nHeight = wallet->nValidateHeight;
  unsigned int nMaxHeight = nHeight + 10;

  if (nHeight <= nBestHeight) {
    for (; nHeight <= nBestHeight && nHeight < nMaxHeight; nHeight++) {
      CBlock *block = GetBlockByHeight(iface, nHeight);
      if (!block) continue;

      if (!block->CheckBlock()) {
        error(SHERR_INVAL, "ServiceValidateEvent: block \"%s\" validation failure.", block->GetHash().GetHex().c_str());
      } else {
        if (!UpdateBlockCoins(*block)) {
          error(SHERR_INVAL, "ServiceValidateEvent: block \"%s\" input transaction validation failure.", block->GetHash().GetHex().c_str());
        }
      }

      delete block;
      wallet->nValidateHeight = nHeight;
    }
  }
  Debug("ServiceValidateEvent: scanned blocks %d .. %d", nStartHeight, nHeight);

  if (wallet->nValidateHeight >= nBestHeight) {
    /* service event has completed task. */
    return (false); 
  }

  return (true);
}


/* deprecate */
void ServiceWalletEventUpdate(CWallet *wallet, const CBlock *pblock)
{
  CBlockIndex *pindex;
  uint256 hash = pblock->GetHash();

  pindex = GetBlockIndexByHash(wallet->ifaceIndex, hash);
  if (!pindex)
    return;

  wallet->nScanHeight = MAX(wallet->nScanHeight, pindex->nHeight);
}

bool LoadExternalBlockchainFile()
{
  static int nIndex = 0;
  CIface *iface = GetCoinByIndex(chain.ifaceIndex);
  int err;

  {
    LOCK(cs_main);
    try {
      FILE *fl = fopen(chain.path, "rb");
      if (!fl) {
        return (false);
      }
      CAutoFile blkdat(fl, SER_DISK, DISK_VERSION);
      while (chain.pos != (unsigned int)-1 && blkdat.good() && !fRequestShutdown) {
        unsigned char pchData[65536];
        do {
          err = fseek(blkdat, chain.pos, SEEK_SET);
          if (err)
            return false;
          int nRead = fread(pchData, 1, sizeof(pchData), blkdat);
          if (nRead <= 8)
          {
#if 0
            chain.pos = (unsigned int)-1;
            break;
#endif
            return false;
          }
          void* nFind = memchr(pchData, iface->hdr_magic[0], nRead+1-sizeof(iface->hdr_magic));
          if (nFind)
          {
            if (memcmp(nFind, iface->hdr_magic, sizeof(iface->hdr_magic))==0)
            {
              chain.pos += ((unsigned char*)nFind - pchData) + sizeof(iface->hdr_magic);
              break;
            }
            chain.pos += ((unsigned char*)nFind - pchData) + 1;
          }
          else {
            chain.pos += sizeof(pchData) - sizeof(iface->hdr_magic) + 1;
}
        } while(!fRequestShutdown);
        if (chain.pos == (unsigned int)-1)
          return (false);
        fseek(blkdat, chain.pos, SEEK_SET);
        unsigned int nSize;
        blkdat >> nSize;
        chain.pos += 4 + nSize;
        if (nSize > 0 && nSize <= iface->max_block_size)
        { /* does not handle orphans */
          CBlock *block = GetBlankBlock(iface);
          blkdat >> *block;

#if 0
CBlockIndex *bestBlock = GetBestBlockIndex(iface);
if (bestBlock->GetBlockHash() != block->hashPrevBlock)
  continue;
#endif

          if (!ProcessBlock(NULL,block)) {
            delete block;
            continue;
          }
          delete block;

          chain.total++;
          if (chain.total == chain.max)
            return (false); /* too many puppies. */

#if 0
          if (ProcessBlock(NULL,block))
          {
            chain.total++;
            nIndex++;
            if (chain.total == chain.max)
              return (false); /* too many puppies. */
          }
#endif
        }

        nIndex++;
        if (249 == (nIndex % 250)) {
          /* continue later */
          nIndex++;
          return (true);
        }
      }
    }
    catch (std::exception &e) {
      chain.pos += 4;
      return (true);
    }
  }

  return (false);
}

bool SaveExternalBlockchainFile()
{
  CIface *iface = GetCoinByIndex(chain.ifaceIndex);
  int64 idx;

  if (chain.max == 0)
    chain.max = (int64)getblockheight(chain.ifaceIndex);

  {
    LOCK(cs_main);
    try {
      FILE *fl = fopen(chain.path, "ab");
      if (!fl) {
        return (false);
      }
      CAutoFile blkdat(fl, SER_DISK, DISK_VERSION);
      for (; chain.pos < chain.max; chain.pos++) {
        CBlock *pblock = GetBlockByHeight(iface, chain.pos);
        if (!pblock) continue; /* uh oh */
        /* hdr */
        unsigned int nSize = blkdat.GetSerializeSize(*pblock);
        blkdat << FLATDATA(iface->hdr_magic) << nSize;
        /* content */
        blkdat << *pblock;
        delete pblock;

        chain.total++;
        if (999 == (chain.total % 1000))
          return (true);
      }
    }
    catch (std::exception &e) {
      printf("%s() : Deserialize or I/O error caught during load\n",
          __PRETTY_FUNCTION__);
    }
  }

  return (false);
}

#define NODE_TIMEOUT 60
static bool chain_IsNodesBusy(int ifaceIndex)
{
	static time_t to_t;
	bool fBusy = false;
	time_t now;

	now = time(NULL);
	if ((to_t + NODE_TIMEOUT) < now)
		return (false);
	to_t = now;

	NodeList &vNodes = GetNodeList(ifaceIndex);
	BOOST_FOREACH(CNode* pnode, vNodes) {
		shbuf_t *pchBuf = descriptor_rbuff(pnode->hSocket);
		if (pchBuf) {
			shbuf_lock(pchBuf);
			if (shbuf_size(pchBuf) != 0)
				fBusy = true;
			shbuf_unlock(pchBuf);

			if (fBusy)
				return (true);
		}
	}

	return (false);
}

static CNode *chain_GetNextNode(int ifaceIndex)
{
  static int nNodeIndex;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CNode *pfrom;
	int idx;

	if (chain_IsNodesBusy(ifaceIndex))
		return (NULL);

	{
		NodeList &vNodes = GetNodeList(ifaceIndex);
		idx = (nNodeIndex % vNodes.size());
		pfrom = vNodes[idx];
		nNodeIndex++;
	}

	if (pfrom->nVersion == 0) {
		/* uninitialized connection. */
		return (NULL);
	}

	if (!pfrom->fPreferHeaders) {
		/* incompatible. */
		return (NULL);
	}

	if (!pfrom->fHaveWitness && 
			IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		/* incompatible. */
		return (NULL);
	}

	return (pfrom);
}

bool ServiceLegacyBlockEvent(int ifaceIndex, CNode *pfrom)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  NodeList &vNodes = GetNodeList(ifaceIndex);
  CIface *iface;
  time_t expire_t;

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (false);

  if (!iface->enabled)
    return (false);

  if (vNodes.size() == 0)
    return (true); /* keep trying */

  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  if (!pindexBest) {
    Debug("(%s) ServiceBlockEvent: no block hiearchy established.\n", iface->name);
    return (true); /* keep trying */
  }

  if (iface->blockscan_max == 0)
    return (true); /* keep trying */

	if (chain_IsNodesBusy(ifaceIndex))
		return (true); /* receiving stuff */

  if (pindexBest->nHeight >= iface->blockscan_max) {
    ServiceBlockEventUpdate(ifaceIndex);
    Debug("(%s) ServiceBlockEvent: finished at height %d.\n", 
        iface->name, (int)pindexBest->nHeight);
    return (false);
  }

  expire_t = time(NULL) - 20;
  if (iface->net_valid < expire_t) { /* done w/ last round */
    if (iface->net_valid < iface->net_invalid) {
      return (false); /* give up */
    }

#if 0
    int idx = (nNodeIndex % vNodes.size());
    pfrom = vNodes[idx];
    nNodeIndex++;
#endif

    if (pfrom->nVersion == 0)
      return (true); /* not ready yet */
    if (!pfrom->fHaveWitness && 
        IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
      /* incompatible, try next peer. */
      return (true);
    }

    Debug("(%s) ServiceBlockEvent: requesting blocks (height: %d)\n",
        iface->name, (int)pindexBest->nHeight);

		pfrom->PushGetBlocks(pindexBest, uint256(0));

    /* force next check to be later */
    iface->net_valid = time(NULL);
  }

  return (true);
}

bool ServiceBlockGetDataEvent(CWallet *wallet, CBlockIndex *tip, CBlockIndex* pindexBest)
{
  CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	CBlockIndex *pindex = NULL;
	CNode *pfrom;
	bool bFound = false;

	/* determine next block to download. */
	if (wallet->pindexBestHeader &&
			wallet->pindexBestHeader->nHeight > pindexBest->nHeight) {
		pindex = wallet->pindexBestHeader;
		while (pindex && pindex->nHeight > (pindexBest->nHeight + MAX_BLOCK_DOWNLOAD_BATCH + 1))
			pindex = pindex->pprev;
	}
	if (!pindex)
		return (false);

	pfrom = chain_GetNextNode(wallet->ifaceIndex);
	if (!pfrom) {
		return (false);
	}

	if (pfrom->pindexRecv == tip) {
		return (false);
	}
	pfrom->pindexRecv = tip;
#if 0
	CBlockIndex *p = pfrom->pindexRecv;
	if (p) {
		for (unsigned int i = 0; p && i < MAX_BLOCK_DOWNLOAD_BATCH; i++) {
			if (p->nHeight <= pindexBest->nHeight)
				break;
			if (pindex == p)
				return (false);
			p = p->pprev;
		}
	}
#endif

	int nFetchFlags = 0;
	if ((pfrom->nServices & NODE_WITNESS) && pfrom->fHaveWitness)
		nFetchFlags |= MSG_WITNESS_FLAG;

	/* ask for blocks */
	std::vector<CInv> vInv;
	while (pindex && 
			pindexBest->nHeight < pindex->nHeight) {
		/* request full block */
		vInv.insert(vInv.begin(), CInv(wallet->ifaceIndex,
					MSG_BLOCK | nFetchFlags, pindex->GetBlockHash()));

		/* iterate to next block */
		pindex = pindex->pprev;
	}

	pfrom->PushMessage("getdata", vInv);

	/* debug */
	Debug("(%s) ServiceBlockEvent: requesting %d blocks (height %d) from \"%s\".", iface->name, vInv.size(),  pindex->nHeight, pfrom->addr.ToString().c_str());

	return (true);
}

bool ServiceBlockHeadersEvent(CWallet *wallet, CBlockIndex *pindexBest)
{
  CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	CNode *pfrom;

	pfrom = chain_GetNextNode(wallet->ifaceIndex);
	if (!pfrom)
		return (false);

	CBlockIndex *pindex = wallet->pindexBestHeader ?
		wallet->pindexBestHeader : pindexBest;
	if (pfrom->pindexRecvHeader == pindex)
		return (false);

	/* ask for headers */
	CBlockLocator locator(wallet->ifaceIndex, wallet->pindexBestHeader);
	pfrom->PushMessage("getheaders", locator, uint256(0));

	/* retain */
	pfrom->pindexRecvHeader = pindex;

	Debug("(%s) ServiceBlockEvent: requesting block info (height %d) from \"%s\".", iface->name, pindex->nHeight, pfrom->addr.ToString().c_str());

	return (true);
}

bool ServiceBlockEvent(int ifaceIndex)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  NodeList &vNodes = GetNodeList(ifaceIndex);
  CIface *iface;

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (false);

  if (!iface->enabled)
    return (false);

  if (vNodes.size() == 0)
    return (true); /* keep trying */

  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  if (!pindexBest) {
    return (true); /* keep trying */
  }

  if (iface->blockscan_max == 0)
    return (true); /* keep trying */

	/* strive towards recognized best chain of headers. */
	if (wallet->pindexBestHeader &&
			wallet->pindexBestHeader->nHeight != -1)
		iface->blockscan_max = MAX(iface->blockscan_max, 
				wallet->pindexBestHeader->nHeight);

  if (pindexBest->nHeight >= iface->blockscan_max) {
    ServiceBlockEventUpdate(ifaceIndex);
    Debug("(%s) ServiceBlockEvent: finished at height %d.\n", 
        iface->name, (int)pindexBest->nHeight);
    return (false);
  }

	/* use headers or legacy method */
	if (ifaceIndex == USDE_COIN_IFACE) {
		CNode *pfrom = chain_GetNextNode(ifaceIndex);
		if (!pfrom) return (true); /* keep trying */
		return (ServiceLegacyBlockEvent(ifaceIndex, pfrom));
	}

	/* determine next block to download. */
	CBlockIndex *pindex = NULL;
	if (wallet->pindexBestHeader &&
			wallet->pindexBestHeader->nHeight > pindexBest->nHeight) {
		pindex = wallet->pindexBestHeader;
		while (pindex && pindex->nHeight > (pindexBest->nHeight + 1))
			pindex = pindex->pprev;
	}

	if (pindex) {
		ServiceBlockGetDataEvent(wallet, pindex, pindexBest);
	} else {
		ServiceBlockHeadersEvent(wallet, pindexBest);
	}

  return (true);
}

void PerformBlockChainOperation(int ifaceIndex)
{
  char buf[1024];
  bool ret;

  if (ifaceIndex != chain.ifaceIndex)
    return;

  switch (chain.mode) {
    case BCOP_IMPORT:
      ret = LoadExternalBlockchainFile();
      if (!ret) {
        sprintf(buf, "PerformBlockChainOperation: loaded %u blocks from path \"%s\" [pos %d].", chain.total, chain.path, chain.pos);
        unet_log(chain.ifaceIndex, buf);
        memset(&chain, 0, sizeof(chain));
      }
      break;

    case BCOP_EXPORT:
      ret = SaveExternalBlockchainFile();
      if (!ret) {
        sprintf(buf, "PerformBlockChainOperation: saved %u blocks to path \"%s\".", chain.total, chain.path);
        unet_log(chain.ifaceIndex, buf);
        memset(&chain, 0, sizeof(chain));
      }
      break;

		case BCOP_MINER:
			ret = UpdateServiceMinerEvent(chain.ifaceIndex);
			if (!ret) {
        sprintf(buf, "PerformBlockChainOperation: spent %u iterations mining a block.", chain.total);
        unet_log(chain.ifaceIndex, buf);
        memset(&chain, 0, sizeof(chain));
			}
			break;
  }
}

bool ServicePeerEvent(int ifaceIndex)
{
  NodeList &vNodes = GetNodeList(ifaceIndex);
  CNode *pfrom;
  int tot;

  if (vNodes.empty())
    return (true); /* keep checking. */

  pfrom = NULL;
  BOOST_FOREACH(CNode *node, vNodes) {
    if (node->fGetAddr)
      continue; /* already asked peer for addresses */
    if (node->fInbound)
      continue; /* mitigate fingerprinting */
    if (node->nVersion == 0)
      continue; /* stream not initialized */

    /* found match */
    pfrom = node;
    break;
  }
  if (!pfrom) {
    pfrom = vNodes.front();
    if (pfrom->nVersion == 0)
      return (true); /* keep checking. */

    /* nothing suitable found. */
    return (false); 
  }

#if 0
  pfrom = vNodes.front();
  if (pfrom->fGetAddr)
    return (false); /* op already performed against this node */
  if (!pfrom->fInbound)
    return (false); /* prevent fingerprinting attack */

  if (pfrom->nVersion == 0)
    return (true); /* not ready yet */
#endif

#if 0
  tot = unet_peer_total(ifaceIndex);
  if (tot < 5000) {
    pfrom->PushMessage("getaddr");
    pfrom->fGetAddr = true;
    Debug("ServicePeerEvent: requesting node address list for iface #%d (known: %d).\n", ifaceIndex, tot);
  }
#endif
  pfrom->PushMessage("getaddr");
  pfrom->fGetAddr = true;
  Debug("ServicePeerEvent: requesting node address list for iface #%d.\n", ifaceIndex);

  return (false); /* all done */
}

void ServiceEventState(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (serv_state(iface, COINF_DL_SCAN)) {
    if (!ServiceBlockEvent(ifaceIndex)) {
      unset_serv_state(iface, COINF_DL_SCAN);
    }
    return;
  }

  if (serv_state(iface, COINF_VALIDATE_SCAN)) {
    if (!ServiceValidateEvent(ifaceIndex)) {
      unset_serv_state(iface, COINF_VALIDATE_SCAN);
    }
    return;
  }

  if (serv_state(iface, COINF_WALLET_SCAN)) {
    if (!ServiceWalletEvent(ifaceIndex)) {
      unset_serv_state(iface, COINF_WALLET_SCAN);
    }
    return;
  }

  if (serv_state(iface, COINF_PEER_SCAN)) {
    if (!ServicePeerEvent(ifaceIndex)) {
      unset_serv_state(iface, COINF_PEER_SCAN);
    }
    return;
  }

  if (!serv_state(iface, COINF_DL_SYNC)) {
    set_serv_state(iface, COINF_DL_SYNC);
    set_serv_state(iface, COINF_DL_SCAN);
    return;
  }

  if (!serv_state(iface, COINF_VALIDATE_SYNC)) {
    set_serv_state(iface, COINF_VALIDATE_SYNC);
    set_serv_state(iface, COINF_VALIDATE_SCAN);
    return;
  } 

  if (!serv_state(iface, COINF_WALLET_SYNC)) {
    set_serv_state(iface, COINF_WALLET_SYNC);
    set_serv_state(iface, COINF_WALLET_SCAN);
    return;
  } 

  if (!serv_state(iface, COINF_PEER_SYNC)) {
    set_serv_state(iface, COINF_PEER_SYNC);
    set_serv_state(iface, COINF_PEER_SCAN);
    return;
  }

}

void ResetServiceWalletEvent(CWallet *wallet)
{
  CIface *iface = GetCoinByIndex(wallet->ifaceIndex);

  if (serv_state(iface, COINF_WALLET_SCAN))
    unset_serv_state(iface, COINF_WALLET_SCAN);

  if (serv_state(iface, COINF_WALLET_SYNC))
    unset_serv_state(iface, COINF_WALLET_SYNC);

  wallet->nScanHeight = 0;
}

void ResetServiceValidateEvent(CWallet *wallet)
{
  CIface *iface = GetCoinByIndex(wallet->ifaceIndex);

  if (serv_state(iface, COINF_VALIDATE_SYNC)) 
    unset_serv_state(iface, COINF_VALIDATE_SCAN);

  if (serv_state(iface, COINF_VALIDATE_SYNC)) 
    unset_serv_state(iface, COINF_VALIDATE_SYNC);

  wallet->nValidateHeight = 0;
}


void InitServiceWalletEvent(CWallet *wallet, uint64_t nHeight)
{
  CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
  if (GetBestHeight(wallet->ifaceIndex) == wallet->nScanHeight) {
    return; /* up-to-date, 'service wallet event' is redundant scan. */
  }

  if (serv_state(iface, COINF_WALLET_SYNC))
    unset_serv_state(iface, COINF_WALLET_SYNC);

  if (wallet->nScanHeight == 0)
    wallet->nScanHeight = nHeight;
  else
    wallet->nScanHeight = MIN(nHeight, wallet->nScanHeight); 


}

void InitServiceValidateEvent(CWallet *wallet, uint64_t nHeight)
{
  CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
  if (GetBestHeight(wallet->ifaceIndex) == wallet->nValidateHeight) {
    return; /* up-to-date, 'service validate-chain event' is redundant scan. */
  }

  if (serv_state(iface, COINF_VALIDATE_SYNC))
    unset_serv_state(iface, COINF_VALIDATE_SYNC);

  if (wallet->nValidateHeight == 0)
    wallet->nValidateHeight = nHeight;
  else
    wallet->nValidateHeight = MIN(nHeight, wallet->nValidateHeight);
}


#ifdef __cplusplus
extern "C" {
#endif

int InitChainImport(int ifaceIndex, const char *path, int offset)
{
  if (*chain.path)
    return (SHERR_AGAIN);

  if (ifaceIndex < 1 || ifaceIndex >= MAX_COIN_IFACE)
    return (SHERR_INVAL);

  if (!path)
    return (SHERR_INVAL);

  chain.mode = BCOP_IMPORT;
  chain.ifaceIndex = ifaceIndex;
  strncpy(chain.path, path, sizeof(chain.path)-1);
  chain.pos = offset;

  Debug("InitChainImport: importing (iface #%d) from path '%s'.\n", chain.ifaceIndex, chain.path);

  return (0);
} 

int InitChainExport(int ifaceIndex, const char *path, int min, int max)
{
  if (*chain.path)
    return (SHERR_AGAIN);

  if (ifaceIndex < 1 || ifaceIndex >= MAX_COIN_IFACE)
    return (SHERR_INVAL);

  if (!path)
    return (SHERR_INVAL);

  chain.mode = BCOP_EXPORT;
  chain.ifaceIndex = ifaceIndex;
  strncpy(chain.path, path, sizeof(chain.path)-1);
  chain.pos = min;
  chain.max = max;

  unlink(path);

  return (0);
} 

void ServiceBlockEventUpdate(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);

  if (!iface || !iface->enabled)
    return;

  CBlockIndex *bestIndex = GetBestBlockIndex(iface);
  if (!bestIndex)
    return;

	int nHeight = bestIndex->nHeight;
	if (wallet->pindexBestHeader)
		nHeight = MAX(nHeight, wallet->pindexBestHeader->nHeight);

  if (iface->blockscan_max == nHeight)
    return;

  iface->net_valid = time(NULL);

#if 0
			/* this is handled exclusively in acceptblock after new chain tip. */
	if (wallet->pindexBestHeader &&
			bestIndex->nHeight > wallet->pindexBestHeader->nHeight &&
			bestIndex->nHeight > iface->blockscan_max &&
			!IsInitialBlockDownload(ifaceIndex)) {
		/* inform of new block */
		NodeList &vNodes = GetNodeList(ifaceIndex);
		BOOST_FOREACH(CNode *node, vNodes) {
			if (node->nVersion == 0)
				continue; /* stream not initialized */

			node->PushBlockHash(bestIndex->GetBlockHash());
		}
	}
#endif

  iface->blockscan_max = MAX(iface->blockscan_max, nHeight);
}

void event_cycle_chain(int ifaceIndex)
{

  PerformBlockChainOperation(ifaceIndex); 

  ServiceEventState(ifaceIndex);

}

int InitServiceBlockEvent(int ifaceIndex, uint64_t nHeight)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!iface)
    return (SHERR_INVAL);
  if (!iface->enabled)
    return (SHERR_OPNOTSUPP);

  if (nHeight < iface->blockscan_max)
    return (0); /* all done */

  /* resync */
  iface->net_invalid = 0;
  iface->blockscan_max = MAX(iface->blockscan_max, nHeight);
  if (!serv_state(iface, COINF_DL_SCAN))
    unset_serv_state(iface, COINF_DL_SYNC);

  return (0);
}

static double GetDifficulty(unsigned int nBits)
{
	int nShift = (nBits >> 24) & 0xff;

	double dDiff =
		(double)0x0000ffff / (double)(nBits & 0x00ffffff);

	while (nShift < 29)
	{
		dDiff *= 256.0;
		nShift++;
	}
	while (nShift > 29)
	{
		dDiff /= 256.0;
		nShift--;
	}

	return dDiff;
}

static uint64_t nNonceCount;
int InitServiceMinerEvent(int ifaceIndex, uint64_t nIncr)
{

  chain.mode = BCOP_MINER;
	chain.ifaceIndex = ifaceIndex;

	nNonceCount = nIncr;
	chain.total = nIncr;

	return (0);
}

/* simple cpu miner for testnet */
bool UpdateServiceMinerEvent(int ifaceIndex)
{
  static uint32_t nNonceIndex = 0xF2222222;
	static uint32_t nNonceHeight;
	static CBlock *block;
  CIface *iface = GetCoinByIndex(ifaceIndex);
	uint32_t height;
	bool found;

	if (nNonceCount == 0)
		return (false);

	height = GetBestHeight(ifaceIndex);
	if (!block || nNonceHeight != height) {
		nNonceHeight = height;

		if (block)
			delete block;

		block = CreateBlockTemplate(iface);
		if (!block) { 
			unet_log(ifaceIndex, "UpdateServiceMinerEvent: unable to create new block.");
			return (false); /* stop */
		}

		block->hashMerkleRoot = block->BuildMerkleTree();

		{ /* debug */
			char errbuf[256];
			double dDiff = (double)GetDifficulty(block->nBits);
			sprintf(errbuf, "UpdateServiceMinerEvent: mining new block (diff %f): %s", dDiff, block->ToString().c_str());
			unet_log(ifaceIndex, errbuf);
		}

	}

	found = false;
  block->nNonce   = ++nNonceIndex;

  {
    uint256 hashTarget = CBigNum().SetCompact(block->nBits).getuint256();
    uint256 thash;
    char scratchpad[SCRYPT_SCRATCHPAD_SIZE];

    loop
    {
      scrypt_1024_1_1_256_sp(BEGIN(block->nVersion), BEGIN(thash), scratchpad);
      if (thash <= hashTarget) {
				found = true;
        break;
			}

      ++block->nNonce;
			if (block->nNonce == 0) {
				//printf("NONCE WRAPPED, incrementing time\n");
				++block->nTime;
			}

//			if ((block->nNonce & 0xFFF) == 0) { printf("nonce %08X: hash = %s (target = %s)\n", block->nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str()); }

			nNonceCount--;
			if (0 == (nNonceCount % 500)) /* ~250ms */
				break;
    }
  }
  nNonceIndex = block->nNonce;

	if (found) {
		char errbuf[256];
		bool ok = ProcessBlock(NULL /* local */, block);
		if (ok) {
			sprintf(errbuf, "UpdateServiceMinerEvent: found block \"%s\".", block->GetHash().GetHex().c_str());
		} else {
			sprintf(errbuf, "UpdateServiceMinerEvent: error processing block \"%s\".", block->GetHash().GetHex().c_str());
		}
		unet_log(ifaceIndex, errbuf);

		/* start anew */
		delete block;
		block = NULL;
	}

	return (true);
}



#ifdef __cplusplus
}
#endif



