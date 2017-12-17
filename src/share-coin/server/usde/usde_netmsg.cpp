
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
#include "chain.h"
#include "usde_pool.h"
#include "usde_block.h"
#include "usde_txidx.h"

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


extern CMedianFilter<int> cPeerBlockCounts;
extern map<uint256, CAlert> mapAlerts;
extern vector <CAddress> GetAddresses(CIface *iface, int max_peer);


#define MIN_USDE_PROTO_VERSION 209

#define USDE_COIN_HEADER_SIZE SIZEOF_COINHDR_T



//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets

extern CBlockIndex *usde_GetLastCheckpoint();


// get the wallet transaction with the given hash (if it exists)
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
  CWallet *pwallet = GetWallet(USDE_COIN_IFACE);

  if (pwallet->GetTransaction(hashTx,wtx))
    return true;

  return false;
}

// notify wallets about an incoming inventory (for request counts)
void static Inventory(const uint256& hash)
{
  CWallet *pwallet = GetWallet(USDE_COIN_IFACE);

  pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void static ResendWalletTransactions()
{
  CWallet *wallet = GetWallet(USDE_COIN_IFACE); 
  wallet->ResendWalletTransactions();
}




//////////////////////////////////////////////////////////////////////////////
//
// USDE_mapOrphanTransactions
//

bool usde_AddOrphanTx(const CDataStream& vMsg)
{
    CTransaction tx;
    CDataStream(vMsg) >> tx;
    uint256 hash = tx.GetHash();
    if (USDE_mapOrphanTransactions.count(hash))
        return false;

    CDataStream* pvMsg = new CDataStream(vMsg);

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:
    if (pvMsg->size() > 4096)
    {
        error(SHERR_INVAL, "warning: ignoring large orphan tx (size: %u, hash: %s)\n", pvMsg->size(), hash.ToString().substr(0,10).c_str());
        delete pvMsg;
        return false;
    }

    USDE_mapOrphanTransactions[hash] = pvMsg;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        USDE_mapOrphanTransactionsByPrev[txin.prevout.hash].insert(make_pair(hash, pvMsg));

    printf("stored orphan tx %s (mapsz %u)\n", hash.ToString().substr(0,10).c_str(),
        USDE_mapOrphanTransactions.size());
    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    if (!USDE_mapOrphanTransactions.count(hash))
        return;
    const CDataStream* pvMsg = USDE_mapOrphanTransactions[hash];
    CTransaction tx;
    CDataStream(*pvMsg) >> tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        USDE_mapOrphanTransactionsByPrev[txin.prevout.hash].erase(hash);
        if (USDE_mapOrphanTransactionsByPrev[txin.prevout.hash].empty())
            USDE_mapOrphanTransactionsByPrev.erase(txin.prevout.hash);
    }
    delete pvMsg;
    USDE_mapOrphanTransactions.erase(hash);
}

unsigned int usde_LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (USDE_mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, CDataStream*>::iterator it = USDE_mapOrphanTransactions.lower_bound(randomhash);
        if (it == USDE_mapOrphanTransactions.end())
            it = USDE_mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
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

        fHave = false;
        {
          LOCK(USDEBlock::mempool.cs);
          fHave = (USDEBlock::mempool.exists(inv.hash));
        }
        if (fHave)
          return (true);

        fHave = false;
        {
#if 0
          USDETxDB txdb;
          fHave = txdb.ContainsTx(inv.hash);
          txdb.Close();
#endif
          fHave = VerifyTxHash(iface, inv.hash);
        }
        if (fHave)
          return (true);

        return (USDE_mapOrphanTransactions.count(inv.hash));
      }

    case MSG_BLOCK:
      blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
      return blockIndex->count(inv.hash) ||
        USDE_mapOrphanBlocks.count(inv.hash);
  }

  // Don't know what it is, just say we already got one
  return true;
}






// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ascii, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.

bool usde_ProcessMessage(CIface *iface, CNode* pfrom, string strCommand, CDataStream& vRecv)
{
  NodeList &vNodes = GetNodeList(iface);
  static map<CService, CPubKey> mapReuseKey;
  CWallet *pwalletMain = GetWallet(iface);
  CTxMemPool *pool = GetTxMemPool(iface);
  int ifaceIndex = GetCoinIndex(iface);
  char errbuf[1024];
  shtime_t ts;

//fprintf(stderr, "USDE:ProcessMessage: received '%s' (%d bytes from %s)\n", strCommand.c_str(), vRecv.size(), pfrom->addr.ToString().c_str());


  RandAddSeedPerfmon();
  if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
  {
    printf("dropmessagestest DROPPING RECV MESSAGE\n");
    return true;
  }

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
    if (pfrom->nVersion < MIN_USDE_PROTO_VERSION)
    {
      // Since February 20, 2012, the protocol is initiated at version 209,
      // and earlier versions are no longer supported
      sprintf(errbuf, "(usde) %s using obsolete version %i", pfrom->addr.ToString().c_str(), pfrom->nVersion);
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

    if (0 != strncmp(pfrom->strSubVer.c_str(), "/USDE", 5)) {
      sprintf(errbuf, "(usde) ProcessMessage: connect from wrong coin interface '%s' (%s)", pfrom->addr.ToString().c_str(), pfrom->strSubVer.c_str());
      pfrom->CloseSocketDisconnect(errbuf);
      return true;
    }

    /* ready to send tx's */
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
    pfrom->vSend.SetVersion(min(pfrom->nVersion, USDE_PROTOCOL_VERSION));

    if (!pfrom->fInbound) { // Advertise our address
      if (/*!fNoListen &&*/ !IsInitialBlockDownload(USDE_COIN_IFACE)) {
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
      pfrom->PushGetBlocks(GetBestBlockIndex(USDE_COIN_IFACE), uint256(0));
    }
#endif

    CBlockIndex *pindexBest = GetBestBlockIndex(USDE_COIN_IFACE);
    if (pindexBest) {
      InitServiceBlockEvent(USDE_COIN_IFACE, pfrom->nStartingHeight);
fprintf(stderr, "DEBUG: USDE: (VER) requesting blocks up to height %d\n", pfrom->nStartingHeight);
    }


    // Relay alerts
    {
      LOCK(cs_mapAlerts);
      BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        item.second.RelayTo(pfrom);
    }

    pfrom->fSuccessfullyConnected = true;

    Debug("(usde) ProcessMessage: receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s, subver=%s\n", pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str(), pfrom->strSubVer.c_str()); 

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
    pfrom->vRecv.SetVersion(min(pfrom->nVersion, USDE_PROTOCOL_VERSION));
  }


  else if (strCommand == "addr")
  {
    vector<CAddress> vAddr;
    vRecv >> vAddr;

#if 0
    // Don't want addr from older versions unless seeding
    if (pfrom->nVersion < CADDR_TIME_VERSION && addrman.size() > 1000)
      return true;
#endif
    if (pfrom->nVersion < CADDR_TIME_VERSION)
      return true;

    if (vAddr.size() > 1000)
    {
      pfrom->Misbehaving(20);
      return error(SHERR_INVAL, "message addr size() = %d", vAddr.size());
    }

    // Store the new addresses
    vector<CAddress> vAddrOk;
    int64 nNow = GetAdjustedTime();
    int64 nSince = nNow - 10 * 60;
    BOOST_FOREACH(CAddress& addr, vAddr)
    {
      if (fShutdown)
        return true;
      if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
        addr.nTime = nNow - 5 * 24 * 60 * 60;
      pfrom->AddAddressKnown(addr);
      bool fReachable = IsReachable(addr);
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
            if (pnode->nVersion < CADDR_TIME_VERSION)
              continue;
            unsigned int nPointer;
            memcpy(&nPointer, &pnode, sizeof(nPointer));
            uint256 hashKey = hashRand ^ nPointer;
            hashKey = Hash(BEGIN(hashKey), END(hashKey));
            mapMix.insert(make_pair(hashKey, pnode));
          }
          int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
          for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
            ((*mi).second)->PushAddress(addr);
        }
      }
      // Do not store addresses outside our network
      if (fReachable)
        vAddrOk.push_back(addr);
    }

    int cnt = 0;
    BOOST_FOREACH(const CAddress &addr, vAddrOk) {
      AddPeerAddress(iface, addr.ToStringIP().c_str(), addr.GetPort());
    }
#if 0
    addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
#endif



    if (vAddr.size() < 1000)
      pfrom->fGetAddr = false;
#if 0
    if (pfrom->fOneShot)
      pfrom->fDisconnect = true;
#endif
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

    for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
    {
      const CInv &inv = vInv[nInv];

      inv.ifaceIndex = USDE_COIN_IFACE;

      if (fShutdown)
        return true;

      pfrom->AddInventoryKnown(inv);

      bool fAlreadyHave = AlreadyHave(iface, inv);

      if (!fAlreadyHave)
        pfrom->AskFor(inv);
      else if (inv.type == MSG_BLOCK && USDE_mapOrphanBlocks.count(inv.hash)) {
        CBlockIndex *pindexBest = GetBestBlockIndex(USDE_COIN_IFACE);
if (pindexBest) fprintf(stderr, "DEBUG: inv.type == MSG_BLOCK, request blocks from height %d\n", pindexBest->nHeight);
        pfrom->PushGetBlocks(pindexBest, usde_GetOrphanRoot(USDE_mapOrphanBlocks[inv.hash]));
      } else if (nInv == nLastBlock) {

        // In case we are on a very long side-chain, it is possible that we already have
        // the last block in an inv bundle sent in response to getblocks. Try to detect
        // this situation and push another getblocks to continue.
        std::vector<CInv> vGetData(ifaceIndex, inv);
        CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, inv.hash);
        if (pindex) {
          CBlockIndex* pcheckpoint = usde_GetLastCheckpoint();
          if (!pcheckpoint || pindex->nHeight >= pcheckpoint->nHeight)
            pfrom->PushGetBlocks(pindex, uint256(0));
        }
      }

      // Track requests for our stuff
      Inventory(inv.hash);
    }
    Debug("(usde) ProcessBlock: processed %d inventory items.", vInv.size());
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

      inv.ifaceIndex = USDE_COIN_IFACE;
      if (inv.type == MSG_BLOCK) {
        CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, inv.hash);
        if (pindex) {
          USDEBlock block;
          if (block.ReadFromDisk(pindex) && block.CheckBlock() &&
              pindex->nHeight <= GetBestHeight(USDE_COIN_IFACE)) {
            pfrom->PushMessage("block", block);
          } else {
            Debug("USDE: WARN: failure validating requested block '%s' at height %d\n", block.GetHash().GetHex().c_str(), pindex->nHeight);
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
        /* relay tx from mempool (no witness support) */
        CTransaction tx;
        if (pool->GetTx(inv.hash, tx)) {
          pfrom->PushTx(tx, SERIALIZE_TRANSACTION_NO_WITNESS);
        }
      }

#if 0
      else if (inv.IsKnownType())
      {
        // Send stream from relay memory
        {
          LOCK(cs_mapRelay);
          map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
          if (mi != mapRelay.end()) {
            string cmd = inv.GetCommand();
            pfrom->PushMessage(cmd.c_str(), (*mi).second);
          }
        }
      }
#endif

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

    if (pindex) {
      Debug("(usde) ProcessMessage[getblocks]: sending from height %d", (int)pindex->nHeight); 
    } else {
      Debug("(usde) ProcessMessage[getblocks]: suppressing block upload.");
    }

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
#if 0
    vector<uint256> vWorkQueue;
    vector<uint256> vEraseQueue;
    bool fMissingInputs = false;
    USDETxDB txdb;
    if (tx.AcceptToMemoryPool(txdb, true, &fMissingInputs)) {
      SyncWithWallets(iface, tx);
      RelayMessage(inv, vMsg);
      mapAlreadyAskedFor.erase(inv);
      vWorkQueue.push_back(inv.hash);
      vEraseQueue.push_back(inv.hash);

      // Recursively process any orphan transactions that depended on this one
      for (unsigned int i = 0; i < vWorkQueue.size(); i++)
      {
        uint256 hashPrev = vWorkQueue[i];
        for (map<uint256, CDataStream*>::iterator mi = USDE_mapOrphanTransactionsByPrev[hashPrev].begin();
            mi != USDE_mapOrphanTransactionsByPrev[hashPrev].end();
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
      usde_AddOrphanTx(vMsg);

      // DoS prevention: do not allow USDE_mapOrphanTransactions to grow unbounded
      unsigned int nEvicted = usde_LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS(iface));
      if (nEvicted > 0)
        printf("mapOrphan overflow, removed %u tx\n", nEvicted);
    }
    txdb.Close();
#endif
  }


  else if (strCommand == "block")
  {
    USDEBlock block;
    vRecv >> block;

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
    pfrom->vAddrToSend.clear();

#if 0
    /* send our own */
    if (pfrom->fSuccessfullyConnected)
    {
      CAddress addrLocal = GetLocalAddress(&pfrom->addr);
      if (addrLocal.IsRoutable() && (CService)addrLocal != (CService)pfrom->addrLocal)
      {
        pfrom->PushAddress(addrLocal);
        pfrom->addrLocal = addrLocal;
      }
    }
#endif

#if 0
    vector<CAddress> vAddr = GetAddresses(iface, USDE_MAX_GETADDR);
    BOOST_FOREACH(const CAddress &addr, vAddr)
      pfrom->PushAddress(addr);
#endif
    pfrom->vAddrToSend = GetAddresses(iface, USDE_MAX_GETADDR);
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
    if (!mapReuseKey.count(pfrom->addr))
      pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr], true);

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

bool usde_ProcessMessages(CIface *iface, CNode* pfrom)
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
    int nHeaderSize = USDE_COIN_HEADER_SIZE;
    if (vRecv.end() - pstart < nHeaderSize)
    {
      if ((int)vRecv.size() > nHeaderSize)
      {
        fprintf(stderr, "DEBUG: USDE_PROCESSMESSAGE MESSAGESTART NOT FOUND\n");
        vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
      }
      break;
    }
    if (pstart - vRecv.begin() > 0)
      fprintf(stderr, "DEBUG: PROCESSMESSAGE SKIPPED %d BYTES\n\n", pstart - vRecv.begin());
    vRecv.erase(vRecv.begin(), pstart);

    // Read header
    vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
    CMessageHeader hdr;
    vRecv >> hdr;
    if (!hdr.IsValid())
    {
      fprintf(stderr, "DEBUG: USDE: PROCESSMESSAGE: ERRORS IN HEADER %s\n", hdr.GetCommand().c_str());
      continue;
    }
    string strCommand = hdr.GetCommand();

    // Message size
    unsigned int nMessageSize = hdr.nMessageSize;
    if (nMessageSize > MAX_SIZE)
    {
      fprintf(stderr, "usde_ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE\n", strCommand.c_str(), nMessageSize);
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
      fprintf(stderr, "DEBUG: usde_ProcessMessages(%s, msg is %u bytes, buff is %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x buff nVersion=%u\n", strCommand.c_str(), nMessageSize, (unsigned int)vRecv.size(), nChecksum, hdr.nChecksum, (unsigned int)vRecv.nVersion);
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
        fRet = usde_ProcessMessage(iface, pfrom, strCommand, vMsg);
      }
      if (fShutdown)
        return true;
    }
    catch (std::ios_base::failure& e)
    {
      if (strstr(e.what(), "end of data"))
      {
        // Allow exceptions from underlength message on vRecv
       fprintf(stderr, "DEBUG: USDE: ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length [addr: %s] [recv-size: %d] [cmd: %s]", strCommand.c_str(), nMessageSize, e.what(), pfrom->addr.ToString().c_str(), (int)vRecv.size(), strCommand.c_str());
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


bool usde_SendMessages(CIface *iface, CNode* pto, bool fSendTrickle)
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
    if (!IsInitialBlockDownload(USDE_COIN_IFACE) && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
    {
      {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
          // Periodically clear setAddrKnown to allow refresh broadcasts
          if (nLastRebroadcast)
            pnode->setAddrKnown.clear();

          // Rebroadcast our address
//          if (!fNoListen) {
            CAddress addr = GetLocalAddress(&pnode->addr);
            addr.SetPort(iface->port);
            if (addr.IsRoutable()) {
              pnode->PushAddress(addr);
              pnode->addrLocal = addr;
            }
//          }
        }
      }
      nLastRebroadcast = GetTime();
    }

    //
    // Message: addr
    //
    if (fSendTrickle)
    {
      vector<CAddress> vAddr;
      vAddr.reserve(pto->vAddrToSend.size());
      BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
      {
        // returns true if wasn't already contained in the set
        if (pto->setAddrKnown.insert(addr).second)
        {
          vAddr.push_back(addr);
          // receiver rejects addr messages larger than 1000
          if (vAddr.size() >= 1000)
          {
            pto->PushMessage("addr", vAddr);
            vAddr.clear();
          }
        }
      }
      pto->vAddrToSend.clear();
      if (!vAddr.empty())
        pto->PushMessage("addr", vAddr);
    }


    //
    // Message: inventory
    //
    vector<CInv> vInv;
    vector<CInv> vInvWait;
    {
      LOCK(pto->cs_inventory);
      vInv.reserve(pto->vInventoryToSend.size());
      vInvWait.reserve(pto->vInventoryToSend.size());
      BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
      {
        if (pto->setInventoryKnown.count(inv))
          continue;

#if 0
        // trickle out tx inv to protect privacy
        if (inv.type == MSG_TX && !fSendTrickle)
        {
          // 1/4 of tx invs blast to all immediately
          static uint256 hashSalt;
          if (hashSalt == 0)
            hashSalt = GetRandHash();
          uint256 hashRand = inv.hash ^ hashSalt;
          hashRand = Hash(BEGIN(hashRand), END(hashRand));
          bool fTrickleWait = ((hashRand & 3) != 0);

          // always trickle our own transactions
          if (!fTrickleWait)
          {
            CWalletTx wtx;
            if (GetTransaction(inv.hash, wtx)) {
              if (wtx.fFromMe)
                fTrickleWait = true;
            }
          }

          if (fTrickleWait)
          {
            vInvWait.push_back(inv);
            continue;
          }
        }
#endif

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







