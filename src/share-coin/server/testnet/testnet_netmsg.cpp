
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
#include "chain.h"
#include "validation.h"
#include "testnet_pool.h"
#include "testnet_block.h"
#include "testnet_txidx.h"

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
#include <share.h>

#include "rpccert_proto.h"

using namespace std;
using namespace boost;


/** Maximum number of headers to announce when relaying blocks with headers message. */
static const unsigned int MAX_BLOCKS_TO_ANNOUNCE = 8;

static const unsigned int MAX_INV_SZ = 50000;


extern CMedianFilter<int> cPeerBlockCounts;
extern map<uint256, CAlert> mapAlerts;
extern vector <CAddress> GetAddresses(CIface *iface, int max_peer);

#define MIN_TESTNET_PROTO_VERSION 2000000

#define TESTNET_COIN_HEADER_SIZE SIZEOF_COINHDR_T

#define LIMITED_STRING(obj,n) REF(LimitedString< n >(REF(obj)))

template<size_t Limit>
class LimitedString
{
  protected:
    std::string& string;

  public:
    LimitedString(std::string& string) : string(string) {}

    template<typename Stream>
      void Unserialize(Stream& s, int, int=0)
      {
        size_t size = ReadCompactSize(s);
        if (size > Limit) {
          throw std::ios_base::failure("String length limit exceeded");
        }
        string.resize(size);
        if (size != 0)
          s.read((char*)&string[0], size);
      }

    template<typename Stream>
      void Serialize(Stream& s, int, int=0) const
      {
        WriteCompactSize(s, string.size());
        if (!string.empty())
          s.write((char*)&string[0], string.size());
      }

    unsigned int GetSerializeSize(int, int=0) const
    {
      return GetSizeOfCompactSize(string.size()) + string.size();
    }
};




//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets

extern CBlockIndex *testnet_GetLastCheckpoint();


// get the wallet transaction with the given hash (if it exists)
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
  CWallet *pwallet = GetWallet(TESTNET_COIN_IFACE);

  if (pwallet) {
    if (pwallet->GetTransaction(hashTx,wtx))
      return true;
  }

  return false;
}

void testnet_RelayTransaction(const CTransaction& tx, const uint256& hash)
{
  RelayMessage(CInv(TESTNET_COIN_IFACE, MSG_TX, hash), (CTransaction)tx);
}


// notify wallets about an incoming inventory (for request counts)
void static Inventory(const uint256& hash)
{
  CWallet *pwallet = GetWallet(TESTNET_COIN_IFACE);

  if (pwallet)
    pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void static ResendWalletTransactions()
{
  CWallet *wallet = GetWallet(TESTNET_COIN_IFACE);
  wallet->ResendWalletTransactions();
}







//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


static bool AlreadyHave(CIface *iface, const CInv& inv)
{
  int ifaceIndex = GetCoinIndex(iface);

  switch (inv.type)
  {
    case MSG_TX:
      {
        bool fHave;

        /* pending in mem pool */
        fHave = false;
        {
          LOCK(TESTNETBlock::mempool.cs);
          fHave  = (TESTNETBlock::mempool.exists(inv.hash));
        }
        if (fHave)
          return (true);

        /* committed to database */
        fHave = false;
        {
          fHave = VerifyTxHash(iface, inv.hash);
        }
        if (fHave)
          return (true);

        CTxMemPool *pool = GetTxMemPool(iface);
        return (pool->IsPendingTx(inv.hash));
      }
      break;

    case MSG_BLOCK:
      blkidx_t *blockIndex = GetBlockTable(ifaceIndex);
      return blockIndex->count(inv.hash);// || testnet_IsOrphanBlock(inv.hash);
  }

  // Don't know what it is, just say we already got one
  return true;
}



static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520; // bytes

static void testnet_ProcessGetHeaders(CIface *iface, CNode *pfrom, CBlockLocator *locator, uint256 hashStop)
{
	CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

	if (IsInitialBlockDownload(TESTNET_COIN_IFACE))
		return; /* busy */

	CBlockIndex* pindex = NULL;
	if (locator->IsNull()) {
		// If locator is null, return the hashStop block
		pindex = GetBlockIndexByHash(ifaceIndex, hashStop);
	} else {
		// Find the last block the caller has in the main chain
		pindex = wallet->GetLocatorIndex(*locator);
		if (pindex)
			pindex = pindex->pnext;
	}
	if (!pindex) {
		Debug("(testnet) ProcessGetHeaders: unable to locate headers for \"%s\".", pfrom->addr.ToString().c_str()); 
		return;
	}

	vector<TESTNETBlock> vHeaders;
	int nLimit = 2000;
	for (; pindex; pindex = pindex->pnext)
	{
		const CBlockHeader& header = pindex->GetBlockHeader();

		TESTNETBlock block;
		block.nVersion       = header.nVersion;
		block.hashPrevBlock  = header.hashPrevBlock;
		block.hashMerkleRoot = header.hashMerkleRoot;
		block.nTime          = header.nTime;
		block.nBits          = header.nBits;
		block.nNonce         = header.nNonce;

		vHeaders.push_back(block);
		if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
			break;
	}
	pfrom->pindexBestHeaderSend = pindex ? pindex : GetBestBlockIndex(iface);
	pfrom->PushMessage("headers", vHeaders);

	Debug("testnet_ProcessGetHeaders: sent %d headers", vHeaders.size());
}


// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ascii, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.

bool testnet_ProcessMessage(CIface *iface, CNode* pfrom, string strCommand, CDataStream& vRecv)
{
  CWallet *wallet = GetWallet(TESTNET_COIN_IFACE);
  NodeList &vNodes = GetNodeList(iface);
  static map<CService, CPubKey> mapReuseKey;
  CWallet *walletMain = GetWallet(iface);
  CTxMemPool *pool = GetTxMemPool(iface);
  int ifaceIndex = GetCoinIndex(iface);
  char errbuf[256];
  shtime_t ts;

  if (strCommand == "version")
  {
    // Each connection can only send one version message
    if (pfrom->nVersion != 0)
    {
      pfrom->Misbehaving(1);
      return false;
    }

    int64 nTime;
    CAddress addrMe;
    CAddress addrFrom;
    uint64 nNonce = 1;
    vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;

    if (pfrom->nVersion < MIN_TESTNET_PROTO_VERSION)
    {
      sprintf(errbuf, "(testnet) %s using obsolete version %i", pfrom->addr.ToString().c_str(), pfrom->nVersion);
      pfrom->CloseSocketDisconnect(errbuf);
      return false;
    }

    if (!vRecv.empty())
      vRecv >> addrFrom >> nNonce;
    if (!vRecv.empty())
      vRecv >> pfrom->strSubVer;
    if (!vRecv.empty())
      vRecv >> pfrom->nStartingHeight;

    /* bloom filter option */
    if (!vRecv.empty())
      vRecv >> pfrom->fRelayTxes; // set to true after we get the first filter* message
    else
      pfrom->fRelayTxes = true;

    if (pfrom->fInbound && addrMe.IsRoutable())
    {
      pfrom->addrLocal = addrMe;
      SeenLocal(ifaceIndex, addrMe);
    }

    // Disconnect if we connected to ourself
    if (nNonce == nLocalHostNonce && nNonce > 1)
    {
      pfrom->CloseSocketDisconnect(NULL);
      return true;
    }

    // Be shy and don't send version until we hear
    if (pfrom->fInbound)
      pfrom->PushVersion();

    pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

    AddTimeData(pfrom->addr, nTime);

    // Change version
    pfrom->PushMessage("verack");
    pfrom->vSend.SetVersion(min(pfrom->nVersion, TESTNET_PROTOCOL_VERSION));

    if (!pfrom->fInbound) { // Advertise our address
      if (/*!fNoListen &&*/ !IsInitialBlockDownload(TESTNET_COIN_IFACE))
      {
        CAddress addr = GetLocalAddress(&pfrom->addr);
        addr.SetPort(iface->port);
        if (addr.IsRoutable()) {
          Debug("VERSION: Pushing (GetLocalAddress) '%s'..", addr.ToString().c_str());
          pfrom->PushAddress(addr);
          pfrom->addrLocal = addr;
        } else {
          Debug("VERSION: Pushing (GetLocalAddress) '%s' NOT ROUTABLE\n", addr.ToString().c_str());
        }
      }

    }

    CBlockIndex *pindexBest = GetBestBlockIndex(TESTNET_COIN_IFACE);
    if (pindexBest) {
      InitServiceBlockEvent(TESTNET_COIN_IFACE, pfrom->nStartingHeight);
    }

    // Relay alerts
    {
      LOCK(cs_mapAlerts);
      BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        item.second.RelayTo(pfrom);
    }

    pfrom->fSuccessfullyConnected = true;

    Debug("testnet_ProcessMessage: receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

    cPeerBlockCounts.input(pfrom->nStartingHeight);
  }


  else if (pfrom->nVersion == 0)
  {
    // Must have a version message before anything else
    pfrom->Misbehaving(1);
    return false;
  }


  else if (strCommand == "verack")
  {
    pfrom->vRecv.SetVersion(min(pfrom->nVersion, TESTNET_PROTOCOL_VERSION));

		/* prefer headers */
		pfrom->PushMessage("sendheaders");

    vector<CTransaction> pool_list = pool->GetActiveTx();
    BOOST_FOREACH(const CTransaction& tx, pool_list) {
      const uint256& hash = tx.GetHash();
      if (walletMain->mapWallet.count(hash) == 0)
        continue;

      CWalletTx& wtx = walletMain->mapWallet[hash];
      if (wtx.IsCoinBase())
        continue;

      const uint256& wtx_hash = wtx.GetHash();
      if (VerifyTxHash(iface, wtx_hash))
        continue; /* is known */

      CInv inv(ifaceIndex, MSG_TX, wtx_hash);
      pfrom->PushInventory(inv);
    }

  }


  else if (strCommand == "addr")
  {
    vector<CAddress> vAddr;
    vRecv >> vAddr;

    if (vAddr.size() > 1000)
    {
      pfrom->Misbehaving(20);
      return error(SHERR_INVAL, "message addr size() = %d", vAddr.size());
    }

		Debug("(%s) ProcessMessage: received %d node addresses.", iface->name, vAddr.size()); 

    int64 nNow = GetAdjustedTime();
    int64 nSince = nNow - 10 * 60;
    BOOST_FOREACH(CAddress& addr, vAddr)
    {
      if (fShutdown)
        return true;
      if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
        addr.nTime = nNow - 5 * 24 * 60 * 60;
      pfrom->AddAddressKnown(addr);
      if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
      {
        // Relay to a limited number of other nodes
        {
          LOCK(cs_vNodes);
          // Use deterministic randomness to send to the same nodes for 24 hours
          // at a time so the setAddrKnowns of the chosen nodes prevent repeats
          static uint256 hashSalt;
          if (hashSalt == 0)
            hashSalt = GetRandHash();
          uint64 hashAddr = addr.GetHash();
          uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));
          hashRand = Hash(BEGIN(hashRand), END(hashRand));
          multimap<uint256, CNode*> mapMix;
          BOOST_FOREACH(CNode* pnode, vNodes)
          {
            unsigned int nPointer;
            memcpy(&nPointer, &pnode, sizeof(nPointer));
            uint256 hashKey = hashRand ^ nPointer;
            hashKey = Hash(BEGIN(hashKey), END(hashKey));
            mapMix.insert(make_pair(hashKey, pnode));
          }
          int nRelayNodes = 2;
          for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
            ((*mi).second)->PushAddress(addr);
        }
      }
    }

    BOOST_FOREACH(const CAddress &addr, vAddr) {
      AddPeerAddress(iface, addr.ToStringIP().c_str(), addr.GetPort());
    }

    if (vAddr.size() < 1000)
      pfrom->fGetAddr = false;
  }


  else if (strCommand == "inv")
  {
    vector<CInv> vInv;
    vRecv >> vInv;
    if (vInv.size() > 50000)
    {
      pfrom->Misbehaving(20);
      return error(SHERR_INVAL, "message inv size() = %d", vInv.size());
    }

    // find last block in inv vector
    unsigned int nLastBlock = (unsigned int)(-1);
    for (unsigned int nInv = 0; nInv < vInv.size(); nInv++) {
      if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK) {
        nLastBlock = vInv.size() - 1 - nInv;
        break;
      }
    }
    {
      for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
      {
        CInv &inv = vInv[nInv];
				int nFetchFlags = 0;

        inv.ifaceIndex = TESTNET_COIN_IFACE;

        if (fShutdown)
          return true;

        bool fAlreadyHave = AlreadyHave(iface, inv);
				bool fSent = false;

        Debug("(testnet) INVENTORY: %s(%s) [%s]", 
            inv.GetCommand().c_str(), inv.hash.GetHex().c_str(), 
            fAlreadyHave ? "have" : "new");

				if ((pfrom->nServices & NODE_WITNESS) && pfrom->fHaveWitness)
					nFetchFlags |= MSG_WITNESS_FLAG;

				/* "headers" */
    		if (pfrom->fPreferHeaders) {
					if (inv.type == MSG_BLOCK) {
						UpdateBlockAvailability(ifaceIndex, pfrom, inv.hash);
						if (!fAlreadyHave) {
							pfrom->PushMessage("getheaders", wallet->GetLocator(wallet->pindexBestHeader), inv.hash); 
						}
						fSent = true;
					}
				}

				if (!fSent)
					pfrom->AddInventoryKnown(inv);

				if (inv.type == MSG_TX ||
						inv.type == MSG_BLOCK) {
					inv.type |= nFetchFlags;
				}

				if (inv.type == MSG_BLOCK && pfrom->fHaveWitness) {
					inv.type |= nFetchFlags;
				}

				if (!fSent) {
					/* already handled. */
				} if (!fAlreadyHave) {
          pfrom->AskFor(inv);
				} else if (inv.type == MSG_BLOCK && testnet_IsOrphanBlock(inv.hash)) {
          Debug("(testnet) ProcessMessage[inv]: received known orphan \"%s\", requesting blocks.", inv.hash.GetHex().c_str());
          pfrom->PushGetBlocks(GetBestBlockIndex(TESTNET_COIN_IFACE), testnet_GetOrphanRoot(inv.hash));
//          ServiceBlockEventUpdate(TESTNET_COIN_IFACE);
        } else if (nInv == nLastBlock) {

          // In case we are on a very long side-chain, it is possible that we already have
          // the last block in an inv bundle sent in response to getblocks. Try to detect
          // this situation and push another getblocks to continue.
          std::vector<CInv> vGetData(ifaceIndex, inv);
          CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, inv.hash);
          if (pindex) {
            CBlockIndex* pcheckpoint = testnet_GetLastCheckpoint();
            if (!pcheckpoint || pindex->nHeight >= pcheckpoint->nHeight) {
              pfrom->PushGetBlocks(pindex, uint256(0));
            }
          }
        }

        // Track requests for our stuff
        Inventory(inv.hash);
        Debug("(testnet) ProcessBlock: processed %d inventory items.", vInv.size());
      }
    }
  }


  else if (strCommand == "getdata")
  {
    vector<CInv> vInv;
    vRecv >> vInv;
    if (vInv.size() > 50000)
    {
      pfrom->Misbehaving(20);
      return error(SHERR_INVAL, "message getdata size() = %d", vInv.size());
    }

    BOOST_FOREACH(const CInv& inv, vInv)
    {
      if (fShutdown)
        return true;

      inv.ifaceIndex = TESTNET_COIN_IFACE;
      if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK) {
        CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, inv.hash);
        if (pindex) {
					TESTNETBlock block;
					if (block.ReadFromDisk(pindex) && block.CheckBlock() &&
							pindex->nHeight <= GetBestHeight(TESTNET_COIN_IFACE)) {
						if (inv.type == MSG_BLOCK) {
							pfrom->PushBlock(block, SERIALIZE_TRANSACTION_NO_WITNESS);
						} else if (inv.type == MSG_WITNESS_BLOCK) {
							pfrom->PushBlock(block);
						} else if (inv.type == MSG_CMPCT_BLOCK) {
							if (pfrom->fHaveWitness)
								pfrom->PushBlock(block);
							else
								pfrom->PushBlock(block, SERIALIZE_TRANSACTION_NO_WITNESS);
						} else if (inv.type == MSG_FILTERED_BLOCK ||
								inv.type == MSG_FILTERED_WITNESS_BLOCK) { /* bloom */
              LOCK(pfrom->cs_filter);
              CBloomFilter *filter = pfrom->GetBloomFilter();
              if (filter) {
                CMerkleBlock merkleBlock(block, *filter);
                pfrom->PushMessage("merkleblock", merkleBlock);
                typedef std::pair<unsigned int, uint256> PairType;
                BOOST_FOREACH(PairType& pair, merkleBlock.vMatchedTxn)
                  if (!pfrom->setInventoryKnown.count(CInv(TESTNET_COIN_IFACE, MSG_TX, pair.second)))
                    pfrom->PushMessage("tx", block.vtx[pair.first]);
              }
            } 
          } else {
            Debug("TESTNET: WARN: failure validating requested block '%s' at height %d\n", block.GetHash().GetHex().c_str(), pindex->nHeight);
            block.print();
          }

          // Trigger them to send a getblocks request for the next batch of inventory
          if (inv.hash == pfrom->hashContinue)
          {
            // Bypass PushInventory, this must send even if redundant,
            // and we want it right after the last block so they don't
            // wait for other stuff first.
            vector<CInv> vInv;
            vInv.push_back(CInv(ifaceIndex, MSG_BLOCK, GetBestBlockChain(iface)));
            pfrom->PushMessage("inv", vInv);
            pfrom->hashContinue = 0;
          }
        }
      } else if (inv.type == MSG_TX) {
        /* relay tx from mempool */
        CTransaction tx;
        if (pool->GetTx(inv.hash, tx)) {
          pfrom->PushTx(tx, SERIALIZE_TRANSACTION_NO_WITNESS);
        }
      } else if (inv.type == MSG_WITNESS_TX) {
        /* relay wit-tx from mempool */
        CTransaction tx;
        if (pool->GetTx(inv.hash, tx)) {
          pfrom->PushTx(tx);
        }
      }

      // Track requests for our stuff
      Inventory(inv.hash);
    }
  }


  else if (strCommand == "getblocks")
  {
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

		CBlockIndex *pindex = wallet->GetLocatorIndex(locator); 

    // Send the rest of the chain
    if (pindex)
      pindex = pindex->pnext;
    int nLimit = 500;
//fprintf(stderr, "DEBUG: getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str(), nLimit);
    for (; pindex; pindex = pindex->pnext)
    {
      if (pindex->GetBlockHash() == hashStop)
      {
//fprintf(stderr, "DEBUG:  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
        break;
      }
      pfrom->PushInventory(CInv(ifaceIndex, MSG_BLOCK, pindex->GetBlockHash()));
//fprintf(stderr, "DEBUG: testnet_ProcessMessage: PushBlock height %d\n", pindex->nHeight);
      if (--nLimit <= 0)
      {
        // When this block is requested, we'll send an inv that'll make them
        // getblocks the next batch of inventory.
//fprintf(stderr, "DEBUG:  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
        pfrom->hashContinue = pindex->GetBlockHash();
        break;
      }
    }
  }


  else if (strCommand == "getheaders")
  {
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

		testnet_ProcessGetHeaders(iface, pfrom, &locator, hashStop);
  }


  else if (strCommand == "tx")
  {
    CDataStream vMsg(vRecv);
    CTransaction tx;
    vRecv >> tx;

    CInv inv(ifaceIndex, MSG_TX, tx.GetHash());
    pfrom->AddInventoryKnown(inv);

    /* add to mempool */
    if (pool->AddTx(tx, pfrom)) {
      SyncWithWallets(iface, tx);
      RelayMessage(inv, vMsg);
      mapAlreadyAskedFor.erase(inv);
    }
  }


  else if (strCommand == "block")
  {
    TESTNETBlock block;
    vRecv >> block;

    CInv inv(ifaceIndex, MSG_BLOCK, block.GetHash());
    pfrom->AddInventoryKnown(inv);

    if (ProcessBlock(pfrom, &block))
      mapAlreadyAskedFor.erase(inv);
  }


  else if (strCommand == "getaddr")
  {

    /* mitigate fingerprinting attack */
    if (!pfrom->fInbound) {
      error(SHERR_ACCESS, "(testnet) warning: Outgoing connection requested address list.");
      return true;
    }


    /* our own addr */
    CAddress addrLocal = GetLocalAddress(&pfrom->addr);
    addrLocal.SetPort(iface->port);

    pfrom->vAddrToSend.clear();
    pfrom->vAddrToSend = GetAddresses(iface, TESTNET_MAX_GETADDR);
    pfrom->vAddrToSend.insert(pfrom->vAddrToSend.begin(), addrLocal);
    Debug("(testnet) ProcessMessage[getaddr]: sending %d addresses to node \"%s\".", pfrom->vAddrToSend.size(), pfrom->addr.ToString().c_str());

  }


  else if (strCommand == "checkorder")
  {
    uint256 hashReply;
    vRecv >> hashReply;

    if (!GetBoolArg("-allowreceivebyip"))
    {
      pfrom->PushMessage("reply", hashReply, (int)2, string(""));
      return true;
    }

    CWalletTx order;
    vRecv >> order;

    /// we have a chance to check the order here

    // Keep giving the same key to the same ip until they use it
    if (!mapReuseKey.count(pfrom->addr)) {
    //  walletMain->GetKeyFromPool(mapReuseKey[pfrom->addr], true);
			string strAccount("");
			mapReuseKey[pfrom->addr] = GetAccountPubKey(walletMain, strAccount, true);
		}

    // Send back approval of order and pubkey to use
    CScript scriptPubKey;
    scriptPubKey << mapReuseKey[pfrom->addr] << OP_CHECKSIG;
    pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
  }


  else if (strCommand == "reply")
  {
    uint256 hashReply;
    vRecv >> hashReply;

    CRequestTracker tracker;
    {
      LOCK(pfrom->cs_mapRequests);
      map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
      if (mi != pfrom->mapRequests.end())
      {
        tracker = (*mi).second;
        pfrom->mapRequests.erase(mi);
      }
    }
    if (!tracker.IsNull())
      tracker.fn(tracker.param1, vRecv);
  }

  /* exclusively used by bloom filter supported coin services, but does not require they have a bloom filter enabled for node. */
  else if (strCommand == "mempool")
  {
    std::vector<uint256> vtxid;
    LOCK2(TESTNETBlock::mempool.cs, pfrom->cs_filter);
    TESTNETBlock::mempool.queryHashes(vtxid);
    vector<CInv> vInv;
    CBloomFilter *filter = pfrom->GetBloomFilter();
    BOOST_FOREACH(uint256& hash, vtxid) {
      CInv inv(TESTNET_COIN_IFACE, MSG_TX, hash);
      if ((filter && filter->IsRelevantAndUpdate(TESTNETBlock::mempool.lookup(hash), hash)) ||
          (!filter))
        vInv.push_back(inv);
      if (vInv.size() == MAX_INV_SZ)
        break;
    }
    if (vInv.size() > 0)
      pfrom->PushMessage("inv", vInv);
  }


  /* exclusively used by bloom filter */
  else if (strCommand == "filterload")
  {
    CBloomFilter filter(TESTNET_COIN_IFACE);
    vRecv >> filter;

    if (!filter.IsWithinSizeConstraints()) {
      pfrom->Misbehaving(100);
    } else {
      pfrom->SetBloomFilter(filter);
    }

    pfrom->fRelayTxes = true;
  }


  else if (strCommand == "filteradd")
  {
    vector<unsigned char> vData;
    vRecv >> vData;

    // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
    // and thus, the maximum size any matched object can have) in a filteradd message
    if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
      pfrom->Misbehaving(100);
    } else {
      /* The following will initialize a new bloom filter if none previously existed. */
      LOCK(pfrom->cs_filter);
      CBloomFilter *filter = pfrom->GetBloomFilter();
      if (filter)
        filter->insert(vData);
    }
  }


  else if (strCommand == "filterclear")
  {
    pfrom->ClearBloomFilter();
    pfrom->fRelayTxes = true;
  }




  else if (strCommand == "ping")
  {
    if (pfrom->nVersion > BIP0031_VERSION)
    {
      uint64 nonce = 0;
      vRecv >> nonce;
      // Echo the message back with the nonce. This allows for two useful features:
      //
      // 1) A remote node can quickly check if the connection is operational
      // 2) Remote nodes can measure the latency of the network thread. If this node
      //    is overloaded it won't respond to pings quickly and the remote node can
      //    avoid sending us more work, like chain download requests.
      //
      // The nonce stops the remote getting confused between different pings: without
      // it, if the remote node sends a ping once per second and this node takes 5
      // seconds to respond to each, the 5th ping the remote sends would appear to
      // return very quickly.
      pfrom->PushMessage("pong", nonce);
    }
  }


  else if (strCommand == "alert")
  {
    CAlert alert;
    vRecv >> alert;

    if (alert.ProcessAlert(ifaceIndex))
    {
      // Relay
      pfrom->setKnown.insert(alert.GetHash());
      {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
          alert.RelayTo(pnode);
      }
    }
  }

  else if (strCommand == "sendheaders") {
    pfrom->fPreferHeaders = true;
		Debug("(testnet) ProcessMessage: received 'sendheaders' request from \"%s\".", pfrom->addr.ToString().c_str());
  }

  else if (strCommand == "sendcmpct") {
    /* not implemented */
    Debug("testnet_ProcessBlock: received 'sendcmpct'");

  } else 



	if (strCommand == "cmpctblock") {
		CBlockIndex *pindex;

		CBlockHeader header;
		vRecv >> header;

		const uint256& hBlock = header.GetHash();
		UpdateBlockAvailability(ifaceIndex, pfrom, hBlock);

		pindex = GetBlockIndexByHash(ifaceIndex, header.hashPrevBlock);
		if (!pindex) {
			/* ask for headers if prevhash is unknown. */
			if (!IsInitialBlockDownload(TESTNET_COIN_IFACE)) {
				pfrom->PushMessage("getheaders", wallet->GetLocator(wallet->pindexBestHeader), uint256());
			}
		}

		pindex = GetBlockIndexByHash(ifaceIndex, header.GetHash());
		if (!pindex) { /* unknown */
			CBlockIndex *pindexLast = NULL;
			vector<CBlockHeader> headers;

			/* process compact block as new header. */
			headers.push_back(header);
			ProcessNewBlockHeaders(iface, headers, &pindexLast);
		}

		Debug("testnet_ProcessBlock: processed 'cmpctblock'");
	}


  else if (strCommand == "getblocktxn") {
    Debug("testnet_ProcessBlock: received 'getblocktxn'");
  }

  else if (strCommand == "blocktxn") {
    Debug("testnet_ProcessBlock: receveed 'blocktxn'");
  } else 



	if (strCommand == "headers") {
		std::vector<CBlockHeader> headers;
		CBlockIndex *pindexLast;

		unsigned int nCount = ReadCompactSize(vRecv);
		if (nCount > MAX_HEADERS_RESULTS) {
			error(ERR_INVAL, "headers message size = %u", nCount);
			return (true);
		}
		if (nCount == 0)
			return (true); /* weird */
		headers.resize(nCount);
		for (unsigned int n = 0; n < nCount; n++) {
			vRecv >> headers[n];
			ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
		}

		pindexLast = GetBlockIndexByHash(ifaceIndex, headers[0].hashPrevBlock);
		if (!pindexLast) {
			if (nCount < MAX_BLOCKS_TO_ANNOUNCE) {
				/* what you talking about willace */
				pfrom->PushMessage("getheaders", wallet->GetLocator(wallet->pindexBestHeader), uint256());
				UpdateBlockAvailability(ifaceIndex, pfrom, headers.back().GetHash());
			}
			return (true);
		}

		/* verify block headers are continuous. */
		uint256 hashLastBlock;
		for (unsigned int i = 0; i < headers.size(); i++) {
			const CBlockHeader& header = headers[i];
			if (!hashLastBlock.IsNull() && header.hashPrevBlock != hashLastBlock) {
				error(ERR_INVAL, "non-continuous headers sequence");
				return (true);
			}
			hashLastBlock = header.GetHash();
		}

		if (!ProcessNewBlockHeaders(iface, headers, &pindexLast)) {
			error(ERR_INVAL, "testnet_ProcessBlock: error receiving %d headers", nCount);
			return (true);
		}

		UpdateBlockAvailability(ifaceIndex, pfrom, pindexLast->GetBlockHash());

		InitServiceBlockEvent(ifaceIndex, pindexLast->nHeight);

		Debug("testnet_ProcessBlock: received %d headers", nCount);

		if (nCount == MAX_HEADERS_RESULTS) {
			/* headers message had its maximum size; ask peer for more headers. */
			pfrom->PushMessage("getheaders", wallet->GetLocator(pindexLast), uint256());
		}
  }



  else if (strCommand == "reject") { /* remote peer is reporting block/tx error */
    string strMsg;
    unsigned char ccode;
    string strReason;

    vRecv >> LIMITED_STRING(strMsg, 12) >> ccode >> LIMITED_STRING(strReason, 111);
    ostringstream ss;
    ss << strMsg << " TESTNET code " << itostr(ccode) << ": " << strReason;

    if (strMsg == "block" || strMsg == "tx") {
      uint256 hash;
      vRecv >> hash;
      ss << ": hash " << hash.ToString();

      if (strMsg == "tx") {
        /* DEBUG: TODO: pool.DecrPriority(hash) */
      }
    }
    error(SHERR_REMOTE, ss.str().c_str());
  }


  else
  {
    // Ignore unknown commands for extensibility
  }


  // Update the last seen time for this node's address
  if (pfrom->fNetworkNode)
    if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
      AddressCurrentlyConnected(pfrom->addr);


  return true;
}

bool testnet_ProcessMessages(CIface *iface, CNode* pfrom)
{
  shtime_t ts;
  CDataStream& vRecv = pfrom->vRecv;
  if (vRecv.empty())
    return true;

  //
  // Message format
  //  (4) message start
  //  (12) command
  //  (4) size
  //  (4) checksum
  //  (x) data
  //

  loop
  {
    // Don't bother if send buffer is too full to respond anyway
    if (pfrom->vSend.size() >= SendBufferSize())
      break;

    // Scan for message start
    CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(),
        BEGIN(iface->hdr_magic), END(iface->hdr_magic));
    int nHeaderSize = TESTNET_COIN_HEADER_SIZE;
    if (vRecv.end() - pstart < nHeaderSize)
    {
      if ((int)vRecv.size() > nHeaderSize)
      {
        Debug("(testnet) warning: PROCESSMESSAGE MESSAGESTART NOT FOUND");
        vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
      }
      break;
    }
    if (pstart - vRecv.begin() > 0)
      Debug("(testnet) warning: PROCESSMESSAGE SKIPPED %d BYTES", pstart - vRecv.begin());

    vRecv.erase(vRecv.begin(), pstart);

    // Read header
    vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
    CMessageHeader hdr;
    vRecv >> hdr;
    if (!hdr.IsValid())
    {
      printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
      continue;
    }
    string strCommand = hdr.GetCommand();

    // Message size
    unsigned int nMessageSize = hdr.nMessageSize;
    if (nMessageSize > MAX_SIZE)
    {
      error(SHERR_2BIG, "ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE\n", strCommand.c_str(), nMessageSize);
      continue;
    }
    if (nMessageSize > vRecv.size())
    {
      // Rewind and wait for rest of message
      vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
      break;
    }

    // Checksum
    uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
    unsigned int nChecksum = 0;
    memcpy(&nChecksum, &hash, sizeof(nChecksum));
    if (nChecksum != hdr.nChecksum)
    {
//fprintf(stderr, "DEBUG: ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n", strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
      continue;
    }

    // Copy message to its own buffer
    CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
    vRecv.ignore(nMessageSize);


    // Process message
    bool fRet = false;
    try
    {
      {
        LOCK(cs_main);
        fRet = testnet_ProcessMessage(iface, pfrom, strCommand, vMsg);
      }
      if (fShutdown)
        return true;
    }
    catch (std::ios_base::failure& e)
    {
      if (strstr(e.what(), "end of data"))
      {
        // Allow exceptions from underlength message on vRecv
        printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
      }
      else if (strstr(e.what(), "size too large"))
      {
        // Allow exceptions from overlong size
        printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
      }
      else
      {
        PrintExceptionContinue(&e, "ProcessMessages()");
      }
    }
    catch (std::exception& e) {
      PrintExceptionContinue(&e, "ProcessMessages()");
    } catch (...) {
      PrintExceptionContinue(NULL, "ProcessMessages()");
    }

    if (!fRet)
      printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);
  }

  vRecv.Compact();
  return true;
}


bool testnet_SendMessages(CIface *iface, CNode* pto, bool fSendTrickle)
{
  NodeList &vNodes = GetNodeList(iface);
  int ifaceIndex = GetCoinIndex(iface);

  TRY_LOCK(cs_main, lockMain);
  if (lockMain) {
    // Don't send anything until we get their version message
    if (pto->nVersion == 0)
      return true;

    /* keep alive ping to prevent disconnect from idle (~ 23min) */
    if (pto->nLastSend && pto->vSend.empty() &&
        (GetTime() - pto->nLastSend) > 1400) {
      uint64 nonce = 0;
      if (pto->nVersion > BIP0031_VERSION)
        pto->PushMessage("ping", nonce);
      else
        pto->PushMessage("ping");
    }

    // Resend wallet transactions that haven't gotten in a block yet
    ResendWalletTransactions();

    // Address refresh broadcast
    static int64 nLastRebroadcast;
    if (!IsInitialBlockDownload(TESTNET_COIN_IFACE) && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
    {
      {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
          // Periodically clear setAddrKnown to allow refresh broadcasts
          if (nLastRebroadcast)
            pnode->setAddrKnown.clear();

          // Rebroadcast our address
          CAddress addr = GetLocalAddress(&pnode->addr);
          addr.SetPort(iface->port);
          if (addr.IsRoutable()) {
            pnode->PushAddress(addr);
            pnode->addrLocal = addr;
          }
        }
      }
      nLastRebroadcast = GetTime();
		}

		/* msg: "addr" */
		if (!pto->vAddrToSend.empty()) {
			vector<CAddress> vAddr;
			vAddr.reserve(pto->vAddrToSend.size());
			BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend) {
				if (pto->setAddrKnown.insert(addr).second) { /* if not known */
					vAddr.push_back(addr);
					if (vAddr.size() >= 1000)
						break;
				}
			}
			pto->vAddrToSend.clear();
			if (!vAddr.empty())
				pto->PushMessage("addr", vAddr);
		}


		/* try sending block announcements via headers. */
		{
			// If we have less than MAX_BLOCKS_TO_ANNOUNCE in our
			// list of block hashes we're relaying, and our peer wants
			// headers announcements, then find the first header
			// not yet known to our peer but would connect, and send.
			// If no header would connect, or if we have too many
			// blocks, or if the peer doesn't want headers, just
			// add all to the inv queue.
			LOCK(pto->cs_inventory);
			std::vector<TESTNETBlock> vHeaders;
#if 0
			bool fRevertToInv = ((!pto->fPreferHeaders &&
						(!pto->fPreferHeaderAndIDs || pto->vBlockHashesToAnnounce.size() > 1)) ||
					pto->vBlockHashesToAnnounce.size() > MAX_BLOCKS_TO_ANNOUNCE);
#endif
			bool fRevertToInv = !pto->fPreferHeaders ||
				(pto->vBlockHashesToAnnounce.size() > MAX_BLOCKS_TO_ANNOUNCE);
			const CBlockIndex *pBestIndex = NULL; // last header queued for delivery
      ProcessBlockAvailability(ifaceIndex, pto);
			if (!fRevertToInv) {
				bool fFoundStartingHeader = false;
				// Try to find first header that our peer doesn't have, and
				// then send all headers past that one.  If we come across any
				// headers that aren't on chainActive, give up.
				for (unsigned int idx = 0; idx < pto->vBlockHashesToAnnounce.size(); idx++) {
					const uint256 &hash = pto->vBlockHashesToAnnounce[idx];

					CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hash);
					//assert(mi != mapBlockIndex.end());

					if (GetBlockIndexByHeight(ifaceIndex, pindex->nHeight) != pindex) {
						/* bail out if we reorged away from this block. */
						fRevertToInv = true;
						break;
					}
					if (pBestIndex != NULL && pindex->pprev != pBestIndex) {
						// This means that the list of blocks to announce don't
						// connect to each other.
						// This shouldn't really be possible to hit during
						// regular operation (because reorgs should take us to
						// a chain that has some block not on the prior chain,
						// which should be caught by the prior check), but one
						// way this could happen is by using invalidateblock /
						// reconsiderblock repeatedly on the tip, causing it to
						// be added multiple times to vBlockHashesToAnnounce.
						// Robustly deal with this rare situation by reverting
						// to an inv.
						fRevertToInv = true;
						break;
					}
					pBestIndex = pindex;
					if (fFoundStartingHeader) {
						// add this to the headers message
						vHeaders.push_back(pindex->GetBlockHeader());
					} else if (pto->HasHeader(pindex)) {
						continue; // keep looking for the first new block
					} else if (pindex->pprev == NULL || 
							pto->HasHeader(pindex->pprev)) {
						// Peer doesn't have this header but they do have the prior one.
						// Start sending headers.
						fFoundStartingHeader = true;
						vHeaders.push_back(pindex->GetBlockHeader());
					} else {
						// Peer doesn't have this header or the prior one -- nothing will
						// connect, so bail out.
						fRevertToInv = true;
						break;
					}
				}
			}
			if (!fRevertToInv && !vHeaders.empty()) {
#if 0
				if (vHeaders.size() == 1 && pto->fPreferHeaderAndIDs) {
					// We only send up to 1 block as header-and-ids, as otherwise
					// probably means we're doing an initial-ish-sync or they're slow
					LogPrint(BCLog::NET, "%s sending header-and-ids %s to peer=%d\n", __func__,
							vHeaders.front().GetHash().ToString(), pto->GetId());

					int nSendFlags = pto->fWantsCmpctWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS;

					bool fGotBlockFromCache = false;
					{
						LOCK(cs_most_recent_block);
						if (most_recent_block_hash == pBestIndex->GetBlockHash()) {
							if (pto->fWantsCmpctWitness || !fWitnessesPresentInMostRecentCompactBlock)
								connman->PushMessage(pto, msgMaker.Make(nSendFlags, NetMsgType::CMPCTBLOCK, *most_recent_compact_block));
							else {
								CBlockHeaderAndShortTxIDs cmpctblock(*most_recent_block, pto->fWantsCmpctWitness);
								connman->PushMessage(pto, msgMaker.Make(nSendFlags, NetMsgType::CMPCTBLOCK, cmpctblock));
							}
							fGotBlockFromCache = true;
						}
					}
					if (!fGotBlockFromCache) {
						CBlock block;
						bool ret = ReadBlockFromDisk(block, pBestIndex, consensusParams);
						assert(ret);
						CBlockHeaderAndShortTxIDs cmpctblock(block, pto->fWantsCmpctWitness);
						connman->PushMessage(pto, msgMaker.Make(nSendFlags, NetMsgType::CMPCTBLOCK, cmpctblock));
					}
					pto->pindexBestHeaderSend = pBestIndex;
				} else 
#endif
				if (pto->fPreferHeaders) {
					if (vHeaders.size() > 1) {
						Debug("(testnet) SendMessages: %u headers [range (%s, %s)] to peer \"%s\".",
								vHeaders.size(),
								vHeaders.front().GetHash().ToString().c_str(),
								vHeaders.back().GetHash().ToString().c_str(), pto->addr.ToString().c_str());
					} else {
						Debug("(testnet) SendMessages: sending header \"%s\" to peer \"%s\".",
								vHeaders.front().GetHash().ToString().c_str(), 
								pto->addr.ToString().c_str());
					}
					pto->PushMessage("headers", vHeaders);
					pto->pindexBestHeaderSend = (CBlockIndex *)pBestIndex;
				} else {
					fRevertToInv = true;
				}
			}
			if (fRevertToInv) {
				// If falling back to using an inv, just try to inv the tip.
				// The last entry in vBlockHashesToAnnounce was our tip at some point
				// in the past.
				if (!pto->vBlockHashesToAnnounce.empty()) {
					const uint256 &hashToAnnounce = pto->vBlockHashesToAnnounce.back();
					CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hashToAnnounce);
					//assert(mi != mapBlockIndex.end());

					/* ignores re-org check.. */

					// If the peer's chain has this block, don't inv it back.
					if (!pto->HasHeader(pindex)) {
						pto->PushInventory(CInv(ifaceIndex, MSG_BLOCK, hashToAnnounce));
						Debug("sending inv peer=%s hash=%s\n",
								pto->addr.ToString().c_str(), hashToAnnounce.GetHex().c_str());
					}
				}
			}
			pto->vBlockHashesToAnnounce.clear();
		}

    /* msg: "inventory" */
    if (!pto->vInventoryToSend.empty()) {
      vector<CInv> vInv;
      {
        LOCK(pto->cs_inventory);
        vInv.reserve(pto->vInventoryToSend.size());
        BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
        {
          if (inv.type == MSG_BLOCK ||
							pto->setInventoryKnown.insert(inv).second) {
            vInv.push_back(inv);
            if (vInv.size() >= 1000) {
              pto->PushMessage("inv", vInv);
              vInv.clear();
            }
          }
        }
        pto->vInventoryToSend.clear();
      }
      if (!vInv.empty()) {
        pto->PushMessage("inv", vInv);
      }
    }

    /* msg: "getdata" */
    if (!pto->mapAskFor.empty()) {
      vector<CInv> vGetData;
      int64 nNow = GetTime() * 1000000;

      while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
      {
        const CInv& inv = (*pto->mapAskFor.begin()).second;
        if (!AlreadyHave(iface, inv))
        {
          vGetData.push_back(inv);
          if (vGetData.size() >= 1000)
          {
            pto->PushMessage("getdata", vGetData);
            vGetData.clear();
          }
          mapAlreadyAskedFor[inv] = nNow;
        }
        pto->mapAskFor.erase(pto->mapAskFor.begin());
      }

      if (!vGetData.empty())
        pto->PushMessage("getdata", vGetData);
    }

  }

  return true;
}


