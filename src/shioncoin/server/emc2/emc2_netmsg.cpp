
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

#include "shcoind.h"
#include "wallet.h"
#include "net.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "chain.h"
#include "validation.h"
#include "emc2_pool.h"
#include "emc2_block.h"
#include "emc2_txidx.h"

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

using namespace std;
using namespace boost;

static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520; /* (bytes) */
static const unsigned int MAX_INV_SZ = 50000;

static const unsigned int EMC2_MAX_HEADERS_RESULTS = 2000;

extern CMedianFilter<int> cPeerBlockCounts;
extern vector <CAddress> GetAddresses(CIface *iface, int max_peer);

#define MIN_EMC2_PROTO_VERSION 70002
#define EMC2_COIN_HEADER_SIZE SIZEOF_COINHDR_T

#define EMC2_SENDHEADERS_VERSION 70012

 
/** Maximum number of headers to announce when relaying blocks with headers message.*/
static const unsigned int MAX_BLOCKS_TO_ANNOUNCE = 8;



//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets



// notify wallets about an incoming inventory (for request counts)
void static Inventory(const uint256& hash)
{
  CWallet *pwallet = GetWallet(EMC2_COIN_IFACE);

  pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void static ResendWalletTransactions()
{
  CWallet *wallet = GetWallet(EMC2_COIN_IFACE); 
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
    case MSG_WITNESS_TX:
      {
        bool fHave;

        fHave = false;
        {
          LOCK(EMC2Block::mempool.cs);
          fHave = (EMC2Block::mempool.exists(inv.hash));
        }
        if (fHave)
          return (true);

        fHave = false;
        {
#if 0
          EMC2TxDB txdb;
          fHave = txdb.ContainsTx(inv.hash);
          txdb.Close();
#endif
          fHave = VerifyTxHash(iface, inv.hash);
        }
        if (fHave)
          return (true);

        CTxMemPool *pool = GetTxMemPool(iface);
        return (pool->IsPendingTx(inv.hash));
      }

    case MSG_BLOCK:
    case MSG_WITNESS_BLOCK:
      blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
      return blockIndex->count(inv.hash);// || emc2_IsOrphanBlock(inv.hash);
  }

  // Don't know what it is, just say we already got one
  return true;
}



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
#define LIMITED_STRING(obj,n) REF(LimitedString< n >(REF(obj)))

static void emc2_ProcessGetHeaders(CIface *iface, CNode *pfrom, CBlockLocator *locator, uint256 hashStop)
{
	CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

	if (IsInitialBlockDownload(EMC2_COIN_IFACE))
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
	if (!pindex)
		return;

//	CBlockIndex* pcheckpoint = emc2_GetLastCheckpoint();
//	if (pcheckpoint->nHeight > pindex->nHeight) 

	vector<EMC2Block> vHeaders;
	int nLimit = 2000;
	for (; pindex; pindex = pindex->pnext)
	{
		const CBlockHeader& header = pindex->GetBlockHeader();

		EMC2Block block;
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

	Debug("emc2_ProcessGetHeaders: sent %d headers", vHeaders.size());
}

CBlockIndex *emc2_GetLastCheckpoint()
{
	CWallet *wallet = GetWallet(EMC2_COIN_IFACE);
	if (!wallet || !wallet->checkpoints)
		return (NULL);
	return (wallet->checkpoints->GetLastCheckpoint());
}

// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ascii, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
bool emc2_ProcessMessage(CIface *iface, CNode* pfrom, string strCommand, CDataStream& vRecv)
{
  NodeList &vNodes = GetNodeList(iface);
  //static map<CService, CPubKey> mapReuseKey;
  CWallet *wallet = GetWallet(iface);
  CTxMemPool *pool = GetTxMemPool(iface);
  int ifaceIndex = GetCoinIndex(iface);
  char errbuf[256];
  shtime_t ts;

#if 0
  Debug("EMC2:ProcessMessage: received '%s' (%d bytes from %s)\n", strCommand.c_str(), vRecv.size(), pfrom->addr.ToString().c_str());
  RandAddSeedPerfmon();
  if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
  {
    printf("dropmessagestest DROPPING RECV MESSAGE\n");
    return true;
  }
#endif

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
    if (pfrom->nVersion < MIN_EMC2_PROTO_VERSION)
    {
      sprintf(errbuf, "peer %s using obsolete (emc2) version %i", pfrom->addr.ToString().c_str(), pfrom->nVersion);
      pfrom->CloseSocketDisconnect(errbuf);
      return false;
    }

    if (pfrom->nVersion == 10300)
      pfrom->nVersion = 300;
    if (!vRecv.empty())
      vRecv >> addrFrom >> nNonce;
    if (!vRecv.empty())
      vRecv >> pfrom->strSubVer;
    if (!vRecv.empty())
      vRecv >> pfrom->nStartingHeight;

#if 0 /* DEBUG: verify & implement if warranted */
    if (0 != strncmp(pfrom->strSubVer.c_str(), "/EMC2", 5)) {
      error(SHERR_INVAL, "(emc2) ProcessMessage: connect from wrong coin interface '%s' (%s), disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->strSubVer.c_str());
      pfrom->fDisconnect = true;
      return true;
    }
#endif

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

    if (pfrom->nServices & NODE_WITNESS) {
      pfrom->fHaveWitness = true;
    }

    AddTimeData(pfrom->addr, nTime);

    // Change version
    pfrom->PushMessage("verack");
    pfrom->vSend.SetVersion(min(pfrom->nVersion, EMC2_PROTOCOL_VERSION));

    if (!pfrom->fInbound) { // Advertise our address
      if (/*!fNoListen &&*/ !IsInitialBlockDownload(EMC2_COIN_IFACE))
      {
        CAddress addr = GetLocalAddress(&pfrom->addr);
        addr.SetPort(iface->port);
        if (addr.IsRoutable()) {
          pfrom->PushAddress(addr);
          pfrom->addrLocal = addr;
        }
      }

#if 0
      if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || (int)vNodes.size() == 1) {
        pfrom->PushMessage("getaddr");
        pfrom->fGetAddr = true;
      }
#endif
    }

#if 0
    // Ask the first connected node for block updates
    static int nAskedForBlocks = 0;
    if (!pfrom->fClient && !pfrom->fOneShot &&
        (pfrom->nVersion < NOBLKS_VERSION_START ||
         pfrom->nVersion >= NOBLKS_VERSION_END) &&
        (nAskedForBlocks < 1 || vNodes.size() <= 1))
    {
      nAskedForBlocks++;
      pfrom->PushGetBlocks(GetBestBlockIndex(EMC2_COIN_IFACE), uint256(0));
    }
#endif

    CBlockIndex *pindexBest = GetBestBlockIndex(EMC2_COIN_IFACE);
    if (pindexBest) {
      InitServiceBlockEvent(EMC2_COIN_IFACE, pfrom->nStartingHeight);
    }

    pfrom->fSuccessfullyConnected = true;

    Debug("received EMC2 version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

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
    pfrom->vRecv.SetVersion(min(pfrom->nVersion, EMC2_PROTOCOL_VERSION));

		/* prefer headers */
		pfrom->PushMessage("sendheaders");

    vector<CTransaction> pool_list = pool->GetActiveTx();
    BOOST_FOREACH(const CTransaction& tx, pool_list) {
      const uint256& hash = tx.GetHash();
      if (wallet->mapWallet.count(hash) == 0)
        continue;

      CWalletTx& wtx = wallet->mapWallet[hash];
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

        inv.ifaceIndex = EMC2_COIN_IFACE;

        if (fShutdown)
          return true;

        bool fAlreadyHave = AlreadyHave(iface, inv);
				bool fSent = false;

        Debug("(emc2) INVENTORY: %s(%s) [%s]", 
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

				if (fSent) {
					/* already handled. */
				} if (!fAlreadyHave) {
          pfrom->AskFor(inv);
				} else if (inv.type == MSG_BLOCK && emc2_IsOrphanBlock(inv.hash)) {
          Debug("(emc2) ProcessMessage[inv]: received known orphan \"%s\", requesting blocks.", inv.hash.GetHex().c_str());
          pfrom->PushGetBlocks(GetBestBlockIndex(EMC2_COIN_IFACE), emc2_GetOrphanRoot(inv.hash));
//          ServiceBlockEventUpdate(EMC2_COIN_IFACE);
        } else if (nInv == nLastBlock) {

          // In case we are on a very long side-chain, it is possible that we already have
          // the last block in an inv bundle sent in response to getblocks. Try to detect
          // this situation and push another getblocks to continue.
          std::vector<CInv> vGetData(ifaceIndex, inv);
          CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, inv.hash);
          if (pindex) {
            CBlockIndex* pcheckpoint = emc2_GetLastCheckpoint();
            if (!pcheckpoint || pindex->nHeight >= pcheckpoint->nHeight) {
              pfrom->PushGetBlocks(pindex, uint256(0));
            }
          }
        }

        // Track requests for our stuff
        Inventory(inv.hash);
        Debug("(emc2) ProcessBlock: processed %d inventory items.", vInv.size());
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

      inv.ifaceIndex = EMC2_COIN_IFACE;
      if (inv.type == MSG_BLOCK ||
          inv.type == MSG_FILTERED_BLOCK || 
          inv.type == MSG_CMPCT_BLOCK || 
          inv.type == MSG_WITNESS_BLOCK) {
        CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, inv.hash);
        if (pindex) {
          EMC2Block block;
          if (block.ReadFromDisk(pindex) && block.CheckBlock() &&
              pindex->nHeight <= GetBestHeight(EMC2_COIN_IFACE)) {
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
                  if (!pfrom->setInventoryKnown.count(CInv(EMC2_COIN_IFACE, MSG_TX, pair.second)))
                    pfrom->PushMessage("tx", block.vtx[pair.first]);
              }
            } 
          } else {
            Debug("EMC2: WARN: failure validating requested block '%s' at height %d\n", block.GetHash().GetHex().c_str(), pindex->nHeight);
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
          Debug("(emc2) PushTx: tx \"%s\" to peer \"%s\".", inv.hash.GetHex().c_str(), pfrom->addrName.c_str());
        }
      } else if (inv.type == MSG_WITNESS_TX) {
        /* relay wit-tx from mempool */
        CTransaction tx;
        if (pool->GetTx(inv.hash, tx)) {
          pfrom->PushTx(tx);
          Debug("(emc2) PushTx: wit-tx \"%s\" to peer \"%s\".", inv.hash.GetHex().c_str(), pfrom->addrName.c_str());
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

    // Find the last block the caller has in the main chain
    CBlockIndex* pindex = wallet->GetLocatorIndex(locator);

    // Send the rest of the chain
    if (pindex)
      pindex = pindex->pnext;
    int nLimit = 500;
    for (; pindex; pindex = pindex->pnext)
    {
      if (pindex->GetBlockHash() == hashStop)
      {
        break;
      }
      pfrom->PushInventory(CInv(ifaceIndex, MSG_BLOCK, pindex->GetBlockHash()));
      if (--nLimit <= 0)
      {
        // When this block is requested, we'll send an inv that'll make them
        // getblocks the next batch of inventory.
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

		emc2_ProcessGetHeaders(iface, pfrom, &locator, hashStop);
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

#if 0
    vector<uint256> vWorkQueue;
    vector<uint256> vEraseQueue;
    EMC2TxDB txdb;
    bool fMissingInputs = false;
    if (tx.AcceptToMemoryPool(txdb, true, &fMissingInputs)) {
      // Recursively process any orphan transactions that depended on this one
      for (unsigned int i = 0; i < vWorkQueue.size(); i++)
      {
        uint256 hashPrev = vWorkQueue[i];
        for (map<uint256, CDataStream*>::iterator mi = EMC2_mapOrphanTransactionsByPrev[hashPrev].begin();
            mi != EMC2_mapOrphanTransactionsByPrev[hashPrev].end();
            ++mi)
        {
          const CDataStream& vMsg = *((*mi).second);
          CTransaction tx;
          CDataStream(vMsg) >> tx;
          CInv inv(ifaceIndex, MSG_TX, tx.GetHash());
          bool fMissingInputs2 = false;

          if (tx.AcceptToMemoryPool(txdb, true, &fMissingInputs2))
          {
            printf("   accepted orphan tx %s\n", inv.hash.ToString().substr(0,10).c_str());
            SyncWithWallets(iface, tx);
            RelayMessage(inv, vMsg);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);
            vEraseQueue.push_back(inv.hash);
          }
          else if (!fMissingInputs2)
          {
            // invalid orphan
            vEraseQueue.push_back(inv.hash);
            printf("   removed invalid orphan tx %s\n", inv.hash.ToString().substr(0,10).c_str());
          }
        }
      }

      BOOST_FOREACH(uint256 hash, vEraseQueue)
        EraseOrphanTx(hash);
    }
    else if (fMissingInputs)
    {
      emc2_AddOrphanTx(vMsg);

      // DoS prevention: do not allow EMC2_mapOrphanTransactions to grow unbounded
      unsigned int nEvicted = emc2_LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS(iface));
      if (nEvicted > 0)
        printf("mapOrphan overflow, removed %u tx\n", nEvicted);
    }
    txdb.Close();
#endif

  }


  else if (strCommand == "block")
  {
    EMC2Block block;
    vRecv >> block;
    uint256 hash = block.GetHash();

    Debug("(emc2) ProcessBlock: received block \"%s\" from \"%s\".", hash.GetHex().c_str(), pfrom->addr.ToString().c_str());

    CInv inv(ifaceIndex, MSG_BLOCK, block.GetHash());
    pfrom->AddInventoryKnown(inv);

    if (ProcessBlock(pfrom, &block))
      mapAlreadyAskedFor.erase(inv);
#if 0
    if (block.nDoS) 
      pfrom->Misbehaving(block.nDoS);
#endif

  }


  else if (strCommand == "getaddr")
  {

    /* mitigate fingerprinting attack */
    if (!pfrom->fInbound) {
      error(SHERR_ACCESS, "(emc2) warning: Outgoing connection requested address list.");
      return true;
    }


		/* our own addr */
		CAddress addrLocal = GetLocalAddress(&pfrom->addr);
		addrLocal.SetPort(iface->port);

		pfrom->vAddrToSend.clear();
		pfrom->vAddrToSend = GetAddresses(iface, EMC2_MAX_GETADDR);
		pfrom->vAddrToSend.insert(pfrom->vAddrToSend.begin(), addrLocal);
		Debug("(emc2) ProcessMessage[getaddr]: sending %d addresses to node \"%s\".", pfrom->vAddrToSend.size(), pfrom->addr.ToString().c_str());

  }

  /* exclusively used by bloom filter supported coin services, but does not require they have a bloom filter enabled for node. */
  else if (strCommand == "mempool")
  {
    std::vector<uint256> vtxid;
    LOCK2(EMC2Block::mempool.cs, pfrom->cs_filter);
    EMC2Block::mempool.queryHashes(vtxid);
    vector<CInv> vInv;
    CBloomFilter *filter = pfrom->GetBloomFilter();
    BOOST_FOREACH(uint256& hash, vtxid) {
      CInv inv(EMC2_COIN_IFACE, MSG_TX, hash);
      if ((filter && filter->IsRelevantAndUpdate(EMC2Block::mempool.lookup(hash), hash)) ||
          (!filter))
        vInv.push_back(inv);
      if (vInv.size() == MAX_INV_SZ)
        break;
    }
    if (vInv.size() > 0)
      pfrom->PushMessage("inv", vInv);
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

  /* exclusively used by bloom filter */
  else if (strCommand == "filterload")
  {
    CBloomFilter filter(EMC2_COIN_IFACE);
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

  else if (strCommand == "sendheaders") {
    pfrom->fPreferHeaders = true;
  }

  else if (strCommand == "sendcmpct") {
    Debug("emc2_ProcessBlock: received 'sendcmpct'");
 
  }

  else if (strCommand == "cmpctblock") {
		CBlockIndex *pindex;

    CBlockHeader header;
		vRecv >> header;

		const uint256& hBlock = header.GetHash();
		UpdateBlockAvailability(ifaceIndex, pfrom, hBlock);

		pindex = GetBlockIndexByHash(ifaceIndex, header.hashPrevBlock);
		if (!pindex) {
			/* ask for headers if prevhash is unknown. */
			if (!IsInitialBlockDownload(EMC2_COIN_IFACE)) {
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

    Debug("emc2_ProcessBlock: processed 'cmpctblock'");
  }

  else if (strCommand == "getblocktxn") {
    Debug("emc2_ProcessBlock: received 'getblocktxn'");
  }

  else if (strCommand == "blocktxn") {
    Debug("emc2_ProcessBlock: receveed 'blocktxn'");
  }

  else if (strCommand == "headers") {
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
			error(ERR_INVAL, "emc2_ProcessBlock: error receiving %d headers", nCount);
			return (true);
		}

		UpdateBlockAvailability(ifaceIndex, pfrom, pindexLast->GetBlockHash());

		InitServiceBlockEvent(ifaceIndex, pindexLast->nHeight);

		Debug("emc2_ProcessBlock: received %d headers", nCount);

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
    ss << strMsg << " code " << itostr(ccode) << ": " << strReason;

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

  else if (strCommand == "feefilter") {
    int64 newFeeFilter = 0;
    vRecv >> newFeeFilter;

    Debug("(emc2) ProcessMessage[feefilter]: info: min fee %f", (double)newFeeFilter/COIN); 
#if 0

    if (MoneyRange(iface, newFeeFilter) &&
        newFeeFilter >= EMC2_MIN_TX_FEE &&
        newFeeFilter < EMC2_MAX_TX_FEE) {
      pfrom->nMinFee = newFeeFilter;
    }
#endif
  }

  else if (strCommand == "notfound") {
    /* ref: https://bitcoin.org/en/developer-reference#notfound */
    /* The notfound message is a reply to a getdata message which requested an object the receiving node does not have available for relay. Their payload is identical to an "inv" message. */

    vector<CInv> vInv;
    vRecv >> vInv;
    if (vInv.size() > 50000)
    {
      pfrom->Misbehaving(20);
      return error(SHERR_INVAL, "message notfound size() = %d", vInv.size());
    }

    for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
    {
      const CInv &inv = vInv[nInv];
      if (inv.type == MSG_TX || inv.type == MSG_WITNESS_TX) {
        Debug("emc2_ProcessMessage: received notfound message: tx '%s'.", inv.hash.GetHex().c_str());
      }

/* .. */
    }

  }

  else
  {
    // Ignore unknown commands for extensibility
   Debug("emc2_ProcessMessage: unknown cmd '%s'\n", strCommand.c_str()); 
  }


  // Update the last seen time for this node's address
  if (pfrom->fNetworkNode)
    if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
      AddressCurrentlyConnected(pfrom->addr);


  return true;
}

bool emc2_ProcessMessages(CIface *iface, CNode* pfrom)
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
    int nHeaderSize = EMC2_COIN_HEADER_SIZE;
    if (vRecv.end() - pstart < nHeaderSize)
    {
      if ((int)vRecv.size() > nHeaderSize)
      {
        Debug("(emc2) warning: PROCESSMESSAGE MESSAGESTART NOT FOUND");
        vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
      }
      break;
    }

    if (pstart - vRecv.begin() > 0)
      Debug("(emc2) warning: PROCESSMESSAGE SKIPPED %d BYTES", pstart - vRecv.begin());

    vRecv.erase(vRecv.begin(), pstart);

    // Read header
    vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
    CMessageHeader hdr;
    vRecv >> hdr;
    if (!hdr.IsValid())
    {
//fprintf(stderr, "DEBUG: EMC2: PROCESSMESSAGE: ERRORS IN HEADER %s\n", hdr.GetCommand().c_str());
      continue;
    }
    string strCommand = hdr.GetCommand();

    // Message size
    unsigned int nMessageSize = hdr.nMessageSize;
    if (nMessageSize > MAX_SIZE)
    {
      error(SHERR_2BIG, "emc2_ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE\n", strCommand.c_str(), nMessageSize);
      continue;
    }
    if (nMessageSize > vRecv.size())
    {
      /* Rewind and wait for rest of message */
      vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
      break;
    }

    // Checksum
    uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
    unsigned int nChecksum = 0;
    memcpy(&nChecksum, &hash, sizeof(nChecksum));
    if (nChecksum != hdr.nChecksum)
    {
//"emc2_ProcessMessages(%s, msg is %u bytes, buff is %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x buff nVersion=%u\n", strCommand.c_str(), nMessageSize, (unsigned int)vRecv.size(), nChecksum, hdr.nChecksum, (unsigned int)vRecv.nVersion);
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
        fRet = emc2_ProcessMessage(iface, pfrom, strCommand, vMsg);
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


bool emc2_SendMessages(CIface *iface, CNode* pto, bool fSendTrickle)
{
  NodeList &vNodes = GetNodeList(iface);
  int ifaceIndex = GetCoinIndex(iface);

  TRY_LOCK(cs_main, lockMain);
  if (lockMain) {
    // Don't send anything until we get their version message
    if (pto->nVersion == 0)
      return true;

    // Keep-alive ping. We send a nonce of zero because we don't use it anywhere
    // right now.
    if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60 && pto->vSend.empty()) {
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
    if (!IsInitialBlockDownload(EMC2_COIN_IFACE) && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
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
			std::vector<EMC2Block> vHeaders;
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
						Debug("(emc2) SendMessages: %u headers [range (%s, %s)] to peer \"%s\".",
								vHeaders.size(),
								vHeaders.front().GetHash().ToString().c_str(),
								vHeaders.back().GetHash().ToString().c_str(), pto->addr.ToString().c_str());
					} else {
						Debug("(emc2) SendMessages: sending header \"%s\" to peer \"%s\".",
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

    //
    // Message: inventory
    //
    vector<CInv> vInv;
    {
      LOCK(pto->cs_inventory);

      vInv.reserve(pto->vInventoryToSend.size());
      BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
      {
        if (inv.type == MSG_BLOCK ||
						pto->setInventoryKnown.insert(inv).second) {
          vInv.push_back(inv);
          if (vInv.size() >= 1000)
          {
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


    //
    // Message: getdata
    //
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
  return true;
}







