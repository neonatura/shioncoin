
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



// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ascii, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.

bool testnet_ProcessMessage(CIface *iface, CNode* pfrom, string strCommand, CDataStream& vRecv)
{
  NodeList &vNodes = GetNodeList(iface);
  static map<CService, CPubKey> mapReuseKey;
  CWallet *pwalletMain = GetWallet(iface);
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

    vector<CTransaction> pool_list = pool->GetActiveTx();
    BOOST_FOREACH(const CTransaction& tx, pool_list) {
      const uint256& hash = tx.GetHash();
      if (pwalletMain->mapWallet.count(hash) == 0)
        continue;

      CWalletTx& wtx = pwalletMain->mapWallet[hash];
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

    if (pfrom->nVersion < CADDR_TIME_VERSION)
      return true;

    if (vAddr.size() > 1000)
    {
      pfrom->Misbehaving(20);
      return error(SHERR_INVAL, "message addr size() = %d", vAddr.size());
    }

    BOOST_FOREACH(CAddress& addr, vAddr) {
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

        inv.ifaceIndex = TESTNET_COIN_IFACE;

        if (fShutdown)
          return true;
        pfrom->AddInventoryKnown(inv);

        bool fAlreadyHave = AlreadyHave(iface, inv);
        Debug("(testnet) INVENTORY: %s(%s) [%s]", 
            inv.GetCommand().c_str(), inv.hash.GetHex().c_str(), 
            fAlreadyHave ? "have" : "new");

        if (!fAlreadyHave)
          pfrom->AskFor(inv);
        else if (inv.type == MSG_BLOCK && testnet_IsOrphanBlock(inv.hash)) {
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
    CBlockLocator locator(ifaceIndex);
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    // Find the last block the caller has in the main chain
    CBlockIndex* pindex = locator.GetBlockIndex();

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
    CBlockLocator locator(ifaceIndex);
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    CBlockIndex* pindex = NULL;
    if (locator.IsNull())
    {
      // If locator is null, return the hashStop block
      pindex = GetBlockIndexByHash(ifaceIndex, hashStop);
      if (!pindex)
        return (true);
    }
    else
    {
      // Find the last block the caller has in the main chain
      pindex = locator.GetBlockIndex();
      if (pindex)
        pindex = pindex->pnext;
    }

    vector<CBlockHeader> vHeaders;
    int nLimit = 2000;
//fprintf(stderr, "DEBUG: getheaders %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str());
    for (; pindex; pindex = pindex->pnext)
    {
      vHeaders.push_back(pindex->GetBlockHeader());
      if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
        break;
    }
    pfrom->PushMessage("headers", vHeaders);
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

    pfrom->vAddrToSend.clear();
    pfrom->vAddrToSend = GetAddresses(iface, TESTNET_MAX_GETADDR);
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
    //  pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr], true);
			string strAccount("");
			mapReuseKey[pfrom->addr] = GetAccountPubKey(pwalletMain, strAccount, true);
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
    /* not implemented */
    pfrom->fPreferHeaders = true;
  }

  else if (strCommand == "sendcmpct") {
    /* not implemented */
    Debug("testnet_ProcessBlock: received 'sendcmpct'");

  }

  else if (strCommand == "cmpctblock") {
    Debug("testnet_ProcessBlock: received 'cmpctblock'");
  }

  else if (strCommand == "getblocktxn") {
    Debug("testnet_ProcessBlock: received 'getblocktxn'");
  }

  else if (strCommand == "blocktxn") {
    Debug("testnet_ProcessBlock: receveed 'blocktxn'");
  }

  else if (strCommand == "headers") {
    Debug("testnet_ProcessBlock: receveed 'headers'");
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
      const CAddress& addr = pto->vAddrToSend.front();
      if (0 == pto->setAddrKnown.count(addr)) {
        vector<CAddress> vAddr;
        vAddr.push_back(addr);
        pto->PushMessage("addr", vAddr);
        pto->setAddrKnown.insert(addr);
      }
      pto->vAddrToSend.erase(pto->vAddrToSend.begin());

      if (pto->setAddrKnown.size() >= TESTNET_MAX_GETADDR)
        pto->vAddrToSend.clear(); 
    }

    /* msg: "inventory" */
    if (!pto->vInventoryToSend.empty()) {
      vector<CInv> vInv;
      vector<CInv> vInvWait;
      {
        LOCK(pto->cs_inventory);
        vInv.reserve(pto->vInventoryToSend.size());
        vInvWait.reserve(pto->vInventoryToSend.size());
        BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
        {
          if (pto->setInventoryKnown.count(inv)) {
            continue;
          }

          // returns true if wasn't already contained in the set
          if (pto->setInventoryKnown.insert(inv).second)
          {
            vInv.push_back(inv);
            if (vInv.size() >= 1000)
            {
              pto->PushMessage("inv", vInv);
              vInv.clear();
            }
          }
        }
        pto->vInventoryToSend = vInvWait;
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


