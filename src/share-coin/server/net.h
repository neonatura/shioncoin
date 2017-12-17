
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

#ifndef __SERVER__NET_H__
#define __SERVER__NET_H__

#include <deque>
#include <boost/array.hpp>
#include <boost/foreach.hpp>
#include <openssl/rand.h>

#ifndef WIN32
#include <arpa/inet.h>
#endif

#include "mruset.h"
#include "netbase.h"
#include "protocol.h"
#include "util.h"
#include "sync.h"

#include <map>
#include <vector>

class CRequestTracker;
class CNode;
class CBlockIndex;
class CBlock;
class CTransaction;
class COutPoint;
extern int nBestHeight;

#define SERIALIZE_TRANSACTION_NO_WITNESS 0x40000000


inline unsigned int ReceiveBufferSize() { return 1000*GetArg("-maxreceivebuffer", 5*1000); }
inline unsigned int SendBufferSize() { return 1000*GetArg("-maxsendbuffer", 1*1000); }

void AddOneShot(std::string strDest);
bool RecvLine(unsigned int hSocket, std::string& strLine);
bool GetMyExternalIP(CNetAddr& ipRet);
void AddressCurrentlyConnected(const CService& addr);
void MapPort();
unsigned short GetListenPort();
bool BindListenPort(const CService &bindAddr, std::string& strError=REF(std::string()));
void StartNode(void* parg);
bool StopNode();

enum
{
    LOCAL_NONE,   // unknown
    LOCAL_IF,     // address a local interface listens on
    LOCAL_BIND,   // address explicit bound to
    LOCAL_UPNP,   // address reported by UPnP
    LOCAL_IRC,    // address reported by IRC (deprecated)
    LOCAL_HTTP,   // address reported by whatismyip.com and similars
    LOCAL_MANUAL, // address explicitly specified (-externalip=)

    LOCAL_MAX
};

enum bloomflags
{
  BLOOM_UPDATE_NONE = 0,
  BLOOM_UPDATE_ALL = 1,
  // Only adds outpoints to the filter if the output is a pay-to-pubkey/pay-to-multisig script
  BLOOM_UPDATE_P2PUBKEY_ONLY = 2,
  BLOOM_UPDATE_MASK = 3 
};
/** Print debug relating to the operation that would normally be performed, but otherwise do not restrict activity from occurring. */
#define BLOOM_TEST (1 << 7)

void SetLimited(enum Network net, bool fLimited = true);
bool IsLimited(enum Network net);
bool IsLimited(const CNetAddr& addr);
bool AddLocal(const CService& addr, int nScore = LOCAL_NONE);
bool AddLocal(const CNetAddr& addr, int nScore = LOCAL_NONE);
bool IsLocal(const CService& addr);
bool GetLocal(CService &addr, const CNetAddr *paddrPeer = NULL);
bool IsReachable(const CNetAddr &addr);
void SetReachable(enum Network net, bool fFlag = true);
CAddress GetLocalAddress(const CNetAddr *paddrPeer = NULL);


CNode* ConnectNode(int ifaceIndex, CAddress addrConnect, const char *strDest = NULL, int64 nTimeout=0);
bool SeenLocal(int ifaceIndex, const CService& addr);

#define MSG_TYPE_MAX MSG_BLOCK

#define MSG_WITNESS_FLAG (1 << 30)
#define MSG_TYPE_MASK (0xffffffff >> 2)

/* inv only uses MSG_TX and MSG_BLOCK */
enum
{
    MSG_TX = 1, 
    MSG_BLOCK,
    MSG_FILTERED_BLOCK, /* bloom */
    MSG_CMPCT_BLOCK,
    MSG_WITNESS_BLOCK = MSG_BLOCK | MSG_WITNESS_FLAG,
    MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG,
    MSG_FILTERED_WITNESS_BLOCK = MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG
};

class CRequestTracker
{
public:
    void (*fn)(void*, CDataStream&);
    void* param1;

    explicit CRequestTracker(void (*fnIn)(void*, CDataStream&)=NULL, void* param1In=NULL)
    {
        fn = fnIn;
        param1 = param1In;
    }

    bool IsNull()
    {
        return fn == NULL;
    }
};


/** Thread types */
enum threadId
{
    THREAD_SOCKETHANDLER,
    THREAD_OPENCONNECTIONS,
    THREAD_MESSAGEHANDLER,
    THREAD_MINER,
    THREAD_RPCLISTENER,
    THREAD_UPNP,
    THREAD_DNSSEED,
    THREAD_ADDEDCONNECTIONS,
    THREAD_DUMPADDRESS,
    THREAD_RPCHANDLER,

    THREAD_MAX
};

extern bool fClient;
extern bool fDiscover;
extern bool fUseUPnP;
extern uint64 nLocalServices;
extern uint64 nLocalHostNonce;
extern boost::array<int, THREAD_MAX> vnThreadsRunning;

extern CCriticalSection cs_vNodes;


extern std::map<CInv, int64> mapAlreadyAskedFor;

#if 0
extern std::deque<std::pair<int64, CInv> > vRelayExpiration;
extern std::map<CInv, CDataStream> mapRelay;
extern CCriticalSection cs_mapRelay;
#endif



class CNodeStats
{
public:
    uint64 nServices;
    int64 nLastSend;
    int64 nLastRecv;
    int64 nTimeConnected;
    std::string addrName;
    int nVersion;
    std::string strSubVer;
    bool fInbound;
    int64 nReleaseTime;
    int nStartingHeight;
    int nMisbehavior;
};



/**
 * A Bloom filter is a space-efficient probabilistic data structure that is used to test membership of an element. The data structure achieves great data compression at the expense of a prescribed false positive rate.
 * 
 * A Bloom filter starts out as an array of n bits all set to 0. A set of k random hash functions are chosen, each of which output a single integer between the range of 1 and n.
 * 
 * When adding an element to the Bloom filter, the element is hashed k times separately, and for each of the k outputs, the corresponding Bloom filter bit at that index is set to 1.
 * 
 * Querying of the Bloom filter is done by using the same hash functions as before. If all k bits accessed in the bloom filter are set to 1, this demonstrates with high probability that the element lies in the set. Clearly, the k indices could have been set to 1 by the addition of a combination of other elements in the domain, but the parameters allow the user to choose the acceptable false positive rate.
 * 
 * Removal of elements can only be done by scrapping the bloom filter and re-creating it from scratch.
 * 
 * Rather than viewing the false positive rates as a liability, it is used to create a tunable parameter that represents the desired privacy level and bandwidth trade-off. A SPV client creates their Bloom filter and sends it to a full node using the message filterload, which sets the filter for which transactions are desired. The command filteradd allows addition of desired data to the filter without needing to send a totally new Bloom filter, and filterclear allows the connection to revert to standard block discovery mechanisms. If the filter has been loaded, then full nodes will send a modified form of blocks, called a merkle block. The merkle block is simply the block header with the merkle branch associated with the set Bloom filter.
 * 
 * An SPV client can not only add transactions as elements to the filter, but also public keys, data from signature scripts and pubkey scripts, and more. This enables P2SH transaction finding.
 * 
 * If a user is more privacy-conscious, he can set the Bloom filter to include more false positives, at the expense of extra bandwidth used for transaction discovery. If a user is on a tight bandwidth budget, he can set the false-positive rate to low, knowing that this will allow full nodes a clear view of what transactions are associated with his client.
 * @ingroup sharecoin
 * @defgroup sharecoin_bloom The bloom probabilistic filter.
 * @{
 */
class CBloomFilter
{
  private:
    std::vector<unsigned char> vData;
    bool isFull;
    bool isEmpty;
    unsigned int nHashFuncs;
    unsigned int nTweak;
    unsigned char nFlags;

    unsigned int Hash(unsigned int nHashNum, const std::vector<unsigned char>& vDataToHash) const;

  public:
    int ifaceIndex;

    // Creates a new bloom filter which will provide the given fp rate when filled with the given number of elements
    // Note that if the given parameters will result in a filter outside the bounds of the protocol limits,
    // the filter created will be as close to the given parameters as possible within the protocol limits.
    // This will apply if nFPRate is very low or nElements is unreasonably high.
    // nTweak is a constant which is added to the seed value passed to the hash function
    // It should generally always be a random value (and is largely only exposed for unit testing)
    // nFlags should be one of the BLOOM_UPDATE_* enums (not _MASK)
    CBloomFilter(int ifaceIndexIn, unsigned int nElements, double nFPRate, unsigned int nTweak, unsigned char nFlagsIn);

    CBloomFilter(int ifaceIndexIn)
    {
      isFull = true; /* disabled to start with */
      ifaceIndex = ifaceIndexIn;
    }

    IMPLEMENT_SERIALIZE
      (
       READWRITE(vData);
       READWRITE(nHashFuncs);
       READWRITE(nTweak);
       READWRITE(nFlags);
      )

    void insert(const std::vector<unsigned char>& vKey);
    void insert(const uint256& hash);
    void insert(const uint160& hash);

    bool contains(const std::vector<unsigned char>& vKey) const;
    bool contains(const COutPoint& outpoint) const;
    bool contains(const uint256& hash) const;
    bool contains(const uint160& hash) const;

    // True if the size is <= MAX_BLOOM_FILTER_SIZE and the number of hash functions is <= MAX_HASH_FUNCS
    // (catch a filter which was just deserialized which was too big)
    bool IsWithinSizeConstraints() const;

    // Also adds any outputs which match the filter to the filter (to match their spending txes)
    bool IsRelevantAndUpdate(const CTransaction& tx, const uint256& hash);

    bool IsRelevant(const CTransaction& tx, const uint256& hash, bool fUpdate = false);

    // Checks for empty and full filters to avoid wasting cpu
    void UpdateEmptyFull();

    void insert(const COutPoint& outpoint);

    /** The bloom filter update mode. (BLOOM_UPDATE_XXX) */
    int GetMode()
    {
      return (nFlags & BLOOM_UPDATE_MASK);
    }

    int GetFlags()
    {
      return ((int)nFlags);
    }

    bool IsTest()
    {
      return (GetFlags() & BLOOM_TEST);
    }

    std::string ToString();
};
/**
 * @}
 */


/** Information about a peer */
class CNode
{
public:
    // socket
    uint64 nServices;
    unsigned int hSocket;
    CDataStream vSend;
    CDataStream vRecv;
    CCriticalSection cs_vSend;
    CCriticalSection cs_vRecv;
    int64 nLastSend;
    int64 nLastRecv;
    int64 nLastSendEmpty;
    int64 nTimeConnected;
    int64 nMinFee;
    int nHeaderStart;
    unsigned int nMessageStart;
    CAddress addr;
    std::string addrName;
    CService addrLocal;
    int nVersion;
    std::string strSubVer;
    bool fClient;
    bool fInbound;
    bool fNetworkNode;
    bool fSuccessfullyConnected;
    bool fDisconnect;
    bool fHaveWitness;
    bool fPreferHeaders;
    CSemaphoreGrant grantOutbound;
protected:
    int nRefCount;

    // Denial-of-service detection/prevention
    // Key is ip address, value is banned-until-time
    static std::map<CNetAddr, int64> setBanned;
    static CCriticalSection cs_setBanned;

public:
    int nMisbehavior;
    int64 nReleaseTime;
    std::map<uint256, CRequestTracker> mapRequests;
    CCriticalSection cs_mapRequests;
    uint256 hashContinue;
    CBlockIndex* pindexLastGetBlocksBegin;
    uint256 hashLastGetBlocksEnd;
    int nStartingHeight;

    // flood relay
    std::vector<CAddress> vAddrToSend;
    std::set<CAddress> setAddrKnown;
    bool fGetAddr;
    std::set<uint256> setKnown;
    mutable int ifaceIndex;

    // inventory based relay
    mruset<CInv> setInventoryKnown;
    std::vector<CInv> vInventoryToSend;
    CCriticalSection cs_inventory;
    std::multimap<int64, CInv> mapAskFor;

    /* bloom filter */
    bool fRelayTxes;
    CCriticalSection cs_filter;
    CBloomFilter *pfilter;

    CNode(int ifaceIndexIn, unsigned int hSocketIn, CAddress addrIn, std::string addrNameIn = "", bool fInboundIn=false) : vSend(SER_NETWORK, MIN_PROTO_VERSION), vRecv(SER_NETWORK, MIN_PROTO_VERSION)
    {
        ifaceIndex = ifaceIndexIn;
        nServices = 0;
        hSocket = hSocketIn;
        nLastSend = 0;
        nLastRecv = 0;
        nLastSendEmpty = GetTime();
        nTimeConnected = GetTime();
        nMinFee = 0;
        nHeaderStart = -1;
        nMessageStart = -1;
        addr = addrIn;
        addrName = addrNameIn == "" ? addr.ToStringIPPort() : addrNameIn;
        nVersion = 0;
        strSubVer = "";
        fClient = false; // set by version message
        fInbound = fInboundIn;
        fNetworkNode = false;
        fSuccessfullyConnected = false;
        fDisconnect = false;
        fHaveWitness = false;
        fPreferHeaders = true;
        nRefCount = 0;
        nReleaseTime = 0;
        hashContinue = 0;
        pindexLastGetBlocksBegin = 0;
        hashLastGetBlocksEnd = 0;
        nStartingHeight = -1;
        fGetAddr = false;
        nMisbehavior = 0;
        setInventoryKnown.max_size(SendBufferSize() / 1000);

        fRelayTxes = false; /* enabled upon "version" message receival */
        pfilter = NULL;


        // Be shy and don't send version until we hear
        if (!fInbound)
            PushVersion();
    }

    ~CNode()
    {
        if (pfilter)
          delete pfilter;
    }

private:
    CNode(const CNode&);
    void operator=(const CNode&);
public:

    CBloomFilter *GetBloomFilter()
    {
      if (ifaceIndex == USDE_COIN_IFACE)
        return (NULL); /* not supported */

      {
        LOCK(cs_filter);
        if (!pfilter)
          pfilter = new CBloomFilter(ifaceIndex);
      }

      return (pfilter);
    }

    void RemoveBloomFilter()
    {
      LOCK(cs_filter);
      if (pfilter)
        delete(pfilter);
      pfilter = NULL;
    }

    void ClearBloomFilter()
    {
      LOCK(cs_filter);
      RemoveBloomFilter();
      pfilter = GetBloomFilter();
    }

    void SetBloomFilter(CBloomFilter& filterIn)
    {
      LOCK(cs_filter);
      RemoveBloomFilter();
      pfilter = new CBloomFilter(filterIn);
      pfilter->UpdateEmptyFull();
    }

    int GetRefCount()
    {
        return std::max(nRefCount, 0) + (GetTime() < nReleaseTime ? 1 : 0);
    }

    CNode* AddRef(int64 nTimeout=0)
    {
        if (nTimeout != 0)
            nReleaseTime = std::max(nReleaseTime, GetTime() + nTimeout);
        else
            nRefCount++;
        return this;
    }

    void Release()
    {
        nRefCount--;
    }



    void AddAddressKnown(const CAddress& addr)
    {
        setAddrKnown.insert(addr);
    }

    void PushAddress(const CAddress& addr)
    {
        // Known checking here is only to save space from duplicates.
        // SendMessages will filter it again for knowns that were added
        // after addresses were pushed.
        if (addr.IsValid() && !setAddrKnown.count(addr))
            vAddrToSend.push_back(addr);
    }


    void AddInventoryKnown(const CInv& inv)
    {
        {
            LOCK(cs_inventory);
            setInventoryKnown.insert(inv);
        }
    }

    void PushInventory(const CInv& inv)
    {
        {
            LOCK(cs_inventory);
            if (!setInventoryKnown.count(inv))
                vInventoryToSend.push_back(inv);
        }
    }

    void AskFor(const CInv& inv)
    {
        // We're using mapAskFor as a priority queue,
        // the key is the earliest time the request can be sent
        int64& nRequestTime = mapAlreadyAskedFor[inv];
        if (fDebugNet)
            printf("askfor %s   %" PRI64d "\n", inv.ToString().c_str(), nRequestTime);

        // Make sure not to reuse time indexes to keep things in the same order
        int64 nNow = (GetTime() - 1) * 1000000;
        static int64 nLastTime;
        ++nLastTime;
        nNow = std::max(nNow, nLastTime);
        nLastTime = nNow;

        // Each retry is 2 minutes after the last
        nRequestTime = std::max(nRequestTime + 2 * 60 * 1000000, nNow);
        mapAskFor.insert(std::make_pair(nRequestTime, inv));
    }



    void BeginMessage(const char* pszCommand)
    {
        ENTER_CRITICAL_SECTION(cs_vSend);
        if (nHeaderStart != -1)
            AbortMessage();
        nHeaderStart = vSend.size();
        vSend << CMessageHeader(ifaceIndex, pszCommand, 0);
        nMessageStart = vSend.size();
        if (fDebug)
            printf("sending: %s ", pszCommand);
    }

    void AbortMessage()
    {
        if (nHeaderStart < 0)
            return;
        vSend.resize(nHeaderStart);
        nHeaderStart = -1;
        nMessageStart = -1;
        LEAVE_CRITICAL_SECTION(cs_vSend);

        if (fDebug)
            printf("(aborted)\n");
    }

    void EndMessage()
    {
        if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
        {
            printf("dropmessages DROPPING SEND MESSAGE\n");
            AbortMessage();
            return;
        }

        if (nHeaderStart < 0)
            return;

        // Set the size
        unsigned int nSize = vSend.size() - nMessageStart;
        memcpy((char*)&vSend[nHeaderStart] + CMessageHeader::MESSAGE_SIZE_OFFSET, &nSize, sizeof(nSize));

        // Set the checksum
        uint256 hash = Hash(vSend.begin() + nMessageStart, vSend.end());
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        assert(nMessageStart - nHeaderStart >= CMessageHeader::CHECKSUM_OFFSET + sizeof(nChecksum));
        memcpy((char*)&vSend[nHeaderStart] + CMessageHeader::CHECKSUM_OFFSET, &nChecksum, sizeof(nChecksum));

        if (fDebug) {
            printf("(%d bytes)\n", nSize);
        }

        nHeaderStart = -1;
        nMessageStart = -1;
        LEAVE_CRITICAL_SECTION(cs_vSend);
    }

    void EndMessageAbortIfEmpty()
    {
        if (nHeaderStart < 0)
            return;
        int nSize = vSend.size() - nMessageStart;
        if (nSize > 0)
            EndMessage();
        else
            AbortMessage();
    }



    void PushVersion();

    void PushBlock(const CBlock& block)
    {
      if (fHaveWitness) {
        PushMessage("block", block);
      } else {
        CDataStream ss(SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
        ss.reserve(4096);
        ss << block;
        cbuff vchBlock(ss.begin(), ss.end());
        PushMessage("block", block);
      }
    }
    void PushTx(const CTransaction& tx, int flags = 0)
    {

      CDataStream ss(SER_GETHASH, flags);
      ss.reserve(1024);
      ss << tx;
      cbuff vchTx(ss.begin(), ss.end());
      PushMessage("tx", tx);
#if 0
      if (fHaveWitness) {
        PushMessage("tx", tx);
fprintf(stderr, "DEBUG: PushTx '%s' to peer [wit]\n", tx.GetHash().c_str());
      } else {
        CDataStream ss(SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
        ss.reserve(1024);
        ss << tx;
        cbuff vchTx(ss.begin(), ss.end());
        PushMessage("tx", tx);
fprintf(stderr, "DEBUG: PushTx '%s' to peer [!wit]\n", tx.GetHash().c_str());
      }
#endif

      //Debug("PushTx: tx \"%s\" to peer \"%s\" [flag %d]\n", tx.GetHash().c_str(), addrName.c_str(), flags);
    }

    void PushMessage(const char* pszCommand)
    {
        try
        {
            BeginMessage(pszCommand);
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1>
    void PushMessage(const char* pszCommand, const T1& a1)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5 << a6;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5 << a6 << a7;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7, const T8& a8)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7, const T8& a8, const T9& a9)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8 << a9;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }


    void PushRequest(const char* pszCommand,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        {
            LOCK(cs_mapRequests);
            mapRequests[hashReply] = CRequestTracker(fn, param1);
        }

        PushMessage(pszCommand, hashReply);
    }

    template<typename T1>
    void PushRequest(const char* pszCommand, const T1& a1,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        {
            LOCK(cs_mapRequests);
            mapRequests[hashReply] = CRequestTracker(fn, param1);
        }

        PushMessage(pszCommand, hashReply, a1);
    }

    template<typename T1, typename T2>
    void PushRequest(const char* pszCommand, const T1& a1, const T2& a2,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        {
            LOCK(cs_mapRequests);
            mapRequests[hashReply] = CRequestTracker(fn, param1);
        }

        PushMessage(pszCommand, hashReply, a1, a2);
    }



    void PushGetBlocks(CBlockIndex* pindexBegin, uint256 hashEnd);
    bool IsSubscribed(unsigned int nChannel);
    void Subscribe(unsigned int nChannel, unsigned int nHops=0);
    void CancelSubscribe(unsigned int nChannel);

    void CloseSocketDisconnect(const char *reason = NULL);

    void Cleanup();

    /** Decrease the connection preference of this network node. */
    void Distrust();

    /** Increase the connection preference of this network node. */
    void Trust();


    // Denial-of-service detection/prevention
    // The idea is to detect peers that are behaving
    // badly and disconnect/ban them, but do it in a
    // one-coding-mistake-won't-shatter-the-entire-network
    // way.
    // IMPORTANT:  There should be nothing I can give a
    // node that it will forward on that will make that
    // node's peers drop it. If there is, an attacker
    // can isolate a node and/or try to split the network.
    // Dropping a node for sending stuff that is invalid
    // now but might be valid in a later version is also
    // dangerous, because it can cause a network split
    // between nodes running old code and nodes running
    // new code.
    static void ClearBanned(); // needed for unit testing
    static bool IsBanned(CNetAddr ip);
    bool Misbehaving(int howmuch); // 1 == a little, 100 == a lot
    void copyStats(CNodeStats &stats);
};










/** Put on lists to offer to the other nodes */
inline void RelayInventory(const CInv& inv)
{
  NodeList &vNodes = GetNodeList(inv.ifaceIndex);
  {
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
      pnode->PushInventory(inv);
  }
}

  template<typename T>
void RelayMessage(const CInv& inv, const T& a)
{
  CIface *iface = GetCoinByIndex(inv.ifaceIndex);
  CDataStream ss(SER_NETWORK, PROTOCOL_VERSION(iface));
  ss.reserve(4096);
  ss << a;
  RelayMessage(inv, ss);
}

template<>
inline void RelayMessage<>(const CInv& inv, const CDataStream& ss)
{

#if 0
    {
        LOCK(cs_mapRelay);
        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
        {
            mapRelay.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }

        // Save original serialized message so newer versions are preserved
        mapRelay.insert(std::make_pair(inv, ss));
        vRelayExpiration.push_back(std::make_pair(GetTime() + 15 * 60, inv));
    }
#endif

    RelayInventory(inv);
}

#endif /* ndef __SERVER__NET_H__ */

