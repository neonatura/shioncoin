
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
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include "shcoind.h"
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "shc/shc_netmsg.h"
#include "usde/usde_netmsg.h"
#include "emc2/emc2_netmsg.h"
#include "ltc/ltc_netmsg.h"
#include "testnet/testnet_netmsg.h"
#include "chain.h"

#ifdef WIN32_VC
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef fcntl
#undef fcntl
#endif

#include <boost/array.hpp>

using namespace std;
using namespace boost;



void ThreadMessageHandler2(void* parg);
void ThreadSocketHandler2(void* parg);
void ThreadDNSAddressSeed2(void* parg);
//bool OpenNetworkConnection(int ifaceIndex, const CAddress& addrConnect, const char *strDest = NULL);

CSemaphore *semOutbound = NULL;


struct LocalServiceInfo {
    int nScore;
    int nPort;
};

//
// Global state variables
//
bool fClient = false;
bool fDiscover = true;
bool fUseUPnP = false;
static CCriticalSection cs_mapLocalHost;
static map<CNetAddr, LocalServiceInfo> mapLocalHost;
static bool vfReachable[NET_MAX] = {};
static bool vfLimited[NET_MAX] = {};
//static CNode* pnodeLocalHost = NULL;
uint64 nLocalHostNonce = 0;
//static std::vector<unsigned int> vhListenSocket;

extern int _shutdown_timer;


NodeList vServerNodes[MAX_COIN_IFACE];

vector<CNode*> vNodes;
CCriticalSection cs_vNodes;
map<CInv, int64> mapAlreadyAskedFor;

static deque<string> vOneShots;
CCriticalSection cs_vOneShots;

set<CNetAddr> setservAddNodeAddresses;
CCriticalSection cs_setservAddNodeAddresses;

boost::array<int, THREAD_MAX> vnThreadsRunning;


static NodeList blankList;
NodeList& GetNodeList(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE) {
    return (blankList);
  }
  return (vServerNodes[ifaceIndex]);
}
NodeList& GetNodeList(CIface *iface)
{
  return (GetNodeList(GetCoinIndex(iface)));
}


void AddOneShot(string strDest)
{
    LOCK(cs_vOneShots);
    vOneShots.push_back(strDest);
}

unsigned short GetListenPort(CIface *iface)
{
  if (!iface)
    return (0);
  return (iface->port);
}

void CNode::PushGetBlocks(CBlockIndex* pindexBegin, uint256 hashEnd)
{

#if 0
  /* last block may have been orphan */
  if (pindexBegin->pprev)
    pindexBegin = pindexBegin->pprev;
#endif

  // Filter out duplicate requests
  if (pindexBegin == pindexLastGetBlocksBegin && hashEnd == hashLastGetBlocksEnd) {
    return;
  }

  {
    CIface *iface = GetCoinByIndex(ifaceIndex);
    if (iface && iface->enabled) {
      if (pindexBegin)
        Debug("(%s) PushGetBlocks: requesting height %d to hash '%s'\n", iface->name, pindexBegin->nHeight, hashEnd.GetHex().c_str());
      else
        Debug("(%s) PushGetBlocks: requesting genesis to hash '%s'\n", iface->name, hashEnd.GetHex().c_str());
    }
  }

  pindexLastGetBlocksBegin = pindexBegin;
  hashLastGetBlocksEnd = hashEnd;

  PushMessage("getblocks", CBlockLocator(ifaceIndex, pindexBegin), hashEnd);

}

// find 'best' local address for a particular peer
bool GetLocal(CService& addr, const CNetAddr *paddrPeer)
{
    if (fNoListen)
        return false;

    int nBestScore = -1;
    int nBestReachability = -1;
    {
        LOCK(cs_mapLocalHost);
        for (map<CNetAddr, LocalServiceInfo>::iterator it = mapLocalHost.begin(); it != mapLocalHost.end(); it++)
        {
            int nScore = (*it).second.nScore;
            int nReachability = (*it).first.GetReachabilityFrom(paddrPeer);
            if (nReachability > nBestReachability || (nReachability == nBestReachability && nScore > nBestScore))
            {
                addr = CService((*it).first, (*it).second.nPort);
                nBestReachability = nReachability;
                nBestScore = nScore;
            }
        }
    }
    return nBestScore >= 0;
}

// get best local address for a particular peer as a CAddress
CAddress GetLocalAddress(const CNetAddr *paddrPeer)
{
#if 0
    CAddress ret(CService("0.0.0.0",0),0);
    CService addr;
    if (GetLocal(addr, paddrPeer))
    {
        ret = CAddress(addr);
        ret.nServices = nLocalServices;
        ret.nTime = GetAdjustedTime();
    }
    return ret;
#endif
    const char *ipaddr = unet_local_host();
    CAddress addr(CService(ipaddr, 0), 0);
    return (addr);
}

bool RecvLine(unsigned int hSocket, string& strLine)
{
  strLine = "";
  loop
  {
    char c;
    int nBytes = recv(hSocket, &c, 1, 0);
    if (nBytes > 0)
    {
      if (c == '\n')
        continue;
      if (c == '\r')
        return true;
      strLine += c;
      if (strLine.size() >= 9000)
        return true;
    }
    else if (nBytes <= 0)
    {
      if (fShutdown)
        return false;
      if (nBytes < 0)
      {
#if 0
        int nErr = WSAGetLastError();
        if (nErr == WSAEMSGSIZE)
          continue;
        if (nErr == WSAEWOULDBLOCK || nErr == WSAEINTR || nErr == WSAEINPROGRESS)
        {
          //Sleep(10);
          continue;
        }
#endif
        if (errno == EMSGSIZE || errno == EINTR || errno == EINPROGRESS)
          continue;
      }
      if (!strLine.empty())
        return true;
      if (nBytes == 0)
      {
        // socket closed
        return false;
      }
      else
      {
        // socket error
        return false;
      }
    }
  }
}

// used when scores of local addresses may have changed
// pushes better local address to peers
void static AdvertizeLocal(int ifaceIndex)
{
  NodeList &vNodes = GetNodeList(ifaceIndex);

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if (pnode->fSuccessfullyConnected)
        {
            CAddress addrLocal = GetLocalAddress(&pnode->addr);
            if (addrLocal.IsRoutable() && (CService)addrLocal != (CService)pnode->addrLocal)
            {
                pnode->PushAddress(addrLocal);
                pnode->addrLocal = addrLocal;
            }
        }
    }
}

void SetReachable(enum Network net, bool fFlag)
{
    LOCK(cs_mapLocalHost);
    vfReachable[net] = fFlag;
    if (net == NET_IPV6 && fFlag)
        vfReachable[NET_IPV4] = true;
}

// learn a new local address
bool AddLocal(int ifaceIndex, const CService& addr, int nScore)
{
  if (!addr.IsRoutable())
    return false;

  if (!fDiscover && nScore < LOCAL_MANUAL)
    return false;

  if (IsLimited(addr))
    return false;

  {
    LOCK(cs_mapLocalHost);
    bool fAlready = mapLocalHost.count(addr) > 0;
    LocalServiceInfo &info = mapLocalHost[addr];
    if (!fAlready || nScore >= info.nScore) {
      info.nScore = nScore;
      info.nPort = addr.GetPort() + (fAlready ? 1 : 0);
    }
    SetReachable(addr.GetNetwork());
  }

  AdvertizeLocal(ifaceIndex);

  return true;
}

bool AddLocal(int ifaceIndex, const CNetAddr &addr, int nScore)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  return AddLocal(ifaceIndex, CService(addr, GetListenPort(iface)), nScore);
}

/** Make a particular network entirely off-limits (no automatic connects to it) */
void SetLimited(enum Network net, bool fLimited)
{
    if (net == NET_UNROUTABLE)
        return;
    LOCK(cs_mapLocalHost);
    vfLimited[net] = fLimited;
}

bool IsLimited(enum Network net)
{
    LOCK(cs_mapLocalHost);
    return vfLimited[net];
}

bool IsLimited(const CNetAddr &addr)
{
    return IsLimited(addr.GetNetwork());
}

/** vote for a local address */
bool SeenLocal(int ifaceIndex, const CService& addr)
{
    {
        LOCK(cs_mapLocalHost);
        if (mapLocalHost.count(addr) == 0)
            return false;
        mapLocalHost[addr].nScore++;
    }

    AdvertizeLocal(ifaceIndex);

    return true;
}

/** check whether a given address is potentially local */
bool IsLocal(const CService& addr)
{
    LOCK(cs_mapLocalHost);
    return mapLocalHost.count(addr) > 0;
}

#if 0
/** check whether a given address is in a network we can probably connect to */
bool IsReachable(const CNetAddr& addr)
{
    LOCK(cs_mapLocalHost);
    enum Network net = addr.GetNetwork();
    return vfReachable[net] && !vfLimited[net];
}
#endif

void AddressCurrentlyConnected(const CService& addr)
{
}

CNode* FindNode(int ifaceIndex, const CNetAddr& ip)
{
  NodeList &vNodes = GetNodeList(ifaceIndex);

    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            if ((CNetAddr)pnode->addr == ip)
                return (pnode);
    }
    return NULL;
}

CNode* FindNode(int ifaceIndex, std::string addrName)
{
  NodeList &vNodes = GetNodeList(ifaceIndex);

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
        if (pnode->addrName == addrName)
            return (pnode);
    return NULL;
}

CNode* FindNode(int ifaceIndex, const CService& addr)
{
  NodeList &vNodes = GetNodeList(ifaceIndex);

    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            if ((CService)pnode->addr == addr)
                return (pnode);
    }
    return NULL;
}

CNode* FindNode(int ifaceIndex, unsigned int sk)
{
  NodeList &vNodes = GetNodeList(ifaceIndex);

  {
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
      if (pnode->hSocket == sk)
        return (pnode);
  }
  return NULL;
}

void CNode::CloseSocketDisconnect(const char *reason)
{

  if (reason != NULL)
    Distrust();

  if (hSocket != INVALID_SOCKET) /* close socket descriptor */
  {
    unet_close(hSocket, (char *)reason);
    hSocket = INVALID_SOCKET;
  }
  vRecv.clear();

  fDisconnect = true; /* trigger de-allocation */
}

void CNode::Cleanup()
{
}

void CNode::Distrust()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  shpeer_t *peer;
  char addr_str[256];

  if (!iface || !iface->enabled)
    return;

  sprintf(addr_str, "%s %d", addr.ToStringIP().c_str(), addr.GetPort());
  peer = shpeer_init(iface->name, addr_str);
  unet_peer_decr(ifaceIndex, peer);
  shpeer_free(&peer);
}

void CNode::Trust()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  shpeer_t *peer;
  char addr_str[256];

  if (!iface || !iface->enabled)
    return;

  sprintf(addr_str, "%s %d", addr.ToStringIP().c_str(), addr.GetPort());
  peer = shpeer_init(iface->name, addr_str);
  unet_peer_incr(ifaceIndex, peer);
  shpeer_free(&peer);
}

void CNode::PushVersion()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  int64 nTime = (fInbound ? GetAdjustedTime() : GetTime());

  CAddress addrYou = (addr.IsRoutable() && !IsProxy(addr) ? addr : CAddress(CService("0.0.0.0",0)));

  CAddress addrMe = GetLocalAddress(&addr);

  RAND_bytes((unsigned char*)&nLocalHostNonce, sizeof(nLocalHostNonce));


  if (ifaceIndex == EMC2_COIN_IFACE) {
    PushMessage("version", PROTOCOL_VERSION(iface), COIN_SERVICES(iface), nTime, addrYou, addrMe, nLocalHostNonce, FormatSubVersion("EinsteiniumCore", IFACE_VERSION(iface), std::vector<string>()), GetBestHeight(ifaceIndex));
  } else {
    PushMessage("version", PROTOCOL_VERSION(iface), COIN_SERVICES(iface), nTime, addrYou, addrMe, nLocalHostNonce, FormatSubVersion(GetClientName(iface), IFACE_VERSION(iface), std::vector<string>()), GetBestHeight(ifaceIndex));
  }

  {
    char buf[256];
    sprintf(buf, "PushVersion: version (proto %d / client %d), blocks=%d, us=%s, them=%s, peer=%s", PROTOCOL_VERSION(iface), IFACE_VERSION(iface), GetBestHeight(ifaceIndex), addrMe.ToString().c_str(), addrYou.ToString().c_str(), addr.ToString().c_str());
    unet_log(ifaceIndex, buf);
  }
}





std::map<CNetAddr, int64> CNode::setBanned;
CCriticalSection CNode::cs_setBanned;

void CNode::ClearBanned()
{
    setBanned.clear();
}


bool CNode::IsBanned(CNetAddr ip)
{
    bool fResult = false;
    {
        LOCK(cs_setBanned);
        std::map<CNetAddr, int64>::iterator i = setBanned.find(ip);
        if (i != setBanned.end())
        {
            int64 t = (*i).second;
            if (GetTime() < t)
                fResult = true;
        }
    }
    return fResult;
}

bool CNode::Misbehaving(int howmuch)
{
  static int ban_span;
  static time_t ban_max;
  char errbuf[1024];

  if (!ban_span) {
    ban_span = MAX(0, opt_num(OPT_BAN_SPAN));
    if (!ban_span) ban_span = 21600; /* default */
  }
  if (!ban_max) {
    ban_max = (time_t)MAX(0, opt_num(OPT_BAN_THRESHOLD));
    if (!ban_max) ban_max = 1000; /* default */
  }

  if (addr.IsLocal())
  {
    Debug("warning: local node %s misbehaving.", addrName.c_str());
    return false;
  }

  nMisbehavior += howmuch;
  if (nMisbehavior >= ban_max)
  {
    int64 banTime = GetTime() + ban_span;
    {
      LOCK(cs_setBanned);
      if (setBanned[addr] < banTime)
        setBanned[addr] = banTime;
    }
    sprintf(errbuf, "disconnected %s for misbehavior (score=%d).", addrName.c_str(), nMisbehavior);
    CloseSocketDisconnect(errbuf);
    return true;
  }

  return false;
}

#undef X
#define X(name) stats.name = name
void CNode::copyStats(CNodeStats &stats)
{
    X(nServices);
    X(nLastSend);
    X(nLastRecv);
    X(nTimeConnected);
    X(addrName);
    X(nVersion);
    X(strSubVer);
    X(fInbound);
    X(nReleaseTime);
    X(nStartingHeight);
    X(nMisbehavior);
}
#undef X










void usde_server_close(int fd, struct sockaddr *addr)
{
  NodeList &vNodes = GetNodeList(USDE_COIN_IFACE);

  LOCK(cs_vNodes);
  vector<CNode*> vNodesCopy = vNodes;
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {
    if (pnode->hSocket == fd) {
      pnode->fDisconnect = true;
    }
  }

}

void shc_server_close(int fd, struct sockaddr *addr)
{
  NodeList &vNodes = GetNodeList(SHC_COIN_IFACE);

  LOCK(cs_vNodes);
  vector<CNode*> vNodesCopy = vNodes;
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {
    if (pnode->hSocket == fd) {
      pnode->fDisconnect = true;
    }
  }

}

void usde_close_free(void)
{
  NodeList &vNodes = GetNodeList(USDE_COIN_IFACE);


  LOCK(cs_vNodes);
  vector<CNode*> vNodesCopy = vNodes;
  list<CNode*> vNodesDisconnected;

  // Disconnect unused nodes
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {
    if (pnode->fDisconnect ||
        (pnode->GetRefCount() <= 0 && pnode->vRecv.empty() && pnode->vSend.empty()))
    {
      // remove from vNodes
      vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());

      // release outbound grant (if any)
      pnode->grantOutbound.Release();

      pnode->Cleanup();

      // hold in disconnected pool until all refs are released
      pnode->nReleaseTime = max(pnode->nReleaseTime, GetTime() + 15 * 60);
      if (pnode->fNetworkNode || pnode->fInbound)
        pnode->Release();
      vNodesDisconnected.push_back(pnode);
    }
  }

  // Delete disconnected nodes
  BOOST_FOREACH(CNode* pnode, vNodesDisconnected)
  {
    delete pnode;
  }
}

void usde_server_accept(int hSocket, struct sockaddr *net_addr)
{
  NodeList &vNodes = GetNodeList(USDE_COIN_IFACE);
#ifdef USE_IPV6
  struct sockaddr_storage sockaddr;
#else
  struct sockaddr sockaddr;
#endif
  CAddress addr;
  int nInbound = 0;
  bool inBound = false;
  unet_table_t *t = get_unet_table(hSocket);

  if (t && (t->flag & UNETF_INBOUND))
    inBound = true;

  addr.SetSockAddr(net_addr);

  if (inBound) {
    {
      LOCK(cs_vNodes);
      BOOST_FOREACH(CNode* pnode, vNodes)
        if (pnode->fInbound)
          nInbound++;
    }

    if (nInbound >= opt_num(OPT_MAX_CONN) - MAX_OUTBOUND_CONNECTIONS)
    {
      {
        LOCK(cs_setservAddNodeAddresses);
        if (!setservAddNodeAddresses.count(addr)) {
          unet_close(hSocket, (char *)"inbound limit");
        }
      }
    }

    if (CNode::IsBanned(addr))
    {
      unet_close(hSocket, "banned");
      return;
    }
  } else {
    if (CNode::IsBanned(addr)) {
      /* force clear ban list due to manual connection initiation. */
      CNode::ClearBanned();
    }
  }

  if (inBound) {
    Debug("(usde) usde_server_accept: accepted connection '%s'.", 
        addr.ToString().c_str());
  } else {
    Debug("(usde) usde_server_accept: initialized connection '%s'.",
        addr.ToString().c_str());
  }

  CNode* pnode = new CNode(USDE_COIN_IFACE, hSocket, addr, 
      shaddr_print(shaddr(hSocket)), inBound);

  //if (inBound)
    pnode->AddRef();

  if (!inBound)
    pnode->fNetworkNode = true;

  {
    LOCK(cs_vNodes);
    vNodes.push_back(pnode);
  }

#if 0
  /* submit address to shared daemon */
  shared_addr_submit(shaddr_print(net_addr));
#endif
}

void usde_MessageHandler(CIface *iface)
{
  NodeList &vNodes = GetNodeList(iface);
  shtime_t ts;

  vector<CNode*> vNodesCopy;
  {
    LOCK(cs_vNodes);
    vNodesCopy = vNodes;
    BOOST_FOREACH(CNode* pnode, vNodesCopy)
      pnode->AddRef();
  }

  // Poll the connected nodes for messages
  CNode* pnodeTrickle = NULL;
  if (!vNodesCopy.empty())
    pnodeTrickle = vNodesCopy[GetRand(vNodesCopy.size())];
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {

    // Send messages
    timing_init("SendMessages", &ts);
    {
      TRY_LOCK(pnode->cs_vSend, lockSend);
      if (lockSend)
        usde_SendMessages(iface, pnode, pnode == pnodeTrickle);
    }
    timing_term(USDE_COIN_IFACE, "SendMessages", &ts);
    if (fShutdown)
      return;
  }

  {
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodesCopy)
      pnode->Release();
  }


}

void shc_MessageHandler(CIface *iface)
{
  NodeList &vNodes = GetNodeList(iface);
  shtime_t ts;

  vector<CNode*> vNodesCopy;
  {
    LOCK(cs_vNodes);
    vNodesCopy = vNodes;
    BOOST_FOREACH(CNode* pnode, vNodesCopy)
      pnode->AddRef();
  }

  // Poll the connected nodes for messages
  CNode* pnodeTrickle = NULL;
#if 0
  if (!vNodesCopy.empty())
    pnodeTrickle = vNodesCopy[GetRand(vNodesCopy.size())];
#endif
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {

    // Send messages
    timing_init("SendMessages", &ts);
    {
      TRY_LOCK(pnode->cs_vSend, lockSend);
      if (lockSend)
        shc_SendMessages(iface, pnode, pnode == pnodeTrickle);
    }
    timing_term(SHC_COIN_IFACE, "SendMessages", &ts);
    if (fShutdown)
      return;
  }

  {
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodesCopy)
      pnode->Release();
  }


}

extern bool usde_ProcessMessage(CIface *iface, CNode* pfrom, string strCommand, CDataStream& vRecv);
bool usde_coin_server_recv_msg(CIface *iface, CNode* pfrom)
{
  CDataStream& vRecv = pfrom->vRecv;
  shtime_t ts;

  if (vRecv.empty())
    return (true);

  CMessageHeader hdr;
  vRecv >> hdr;

  /* check checksum */
  string strCommand = hdr.GetCommand();
  unsigned int nMessageSize = hdr.nMessageSize;
  if (nMessageSize > MAX_SIZE) {
    error(SHERR_2BIG, "(usde) ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE", strCommand.c_str(), nMessageSize);
    return (false);
  }

  /* verify checksum */
  uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
  unsigned int nChecksum = 0;
  memcpy(&nChecksum, &hash, sizeof(nChecksum));
  if (nChecksum != hdr.nChecksum) {
    error(SHERR_INVAL, "ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n", strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
    return (false);
  }

  bool fRet = false;
  try {
    char *cmd = (char *)strCommand.c_str();
    {
//      LOCK(cs_main);
      fRet = usde_ProcessMessage(iface, pfrom, strCommand, vRecv);
    }
  } catch (std::ios_base::failure& e) {
    if (strstr(e.what(), "end of data"))
    {
      // Allow exceptions from underlength message on vRecv
      error(SHERR_INVAL, "(use) ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
    }
    else if (strstr(e.what(), "size too large"))
    {
      // Allow exceptions from overlong size
      error(SHERR_INVAL, "(use) ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
    }
    else
    {
      PrintExceptionContinue(&e, "(usde) ProcessMessage");
    }
  } catch (std::exception& e) {
    PrintExceptionContinue(&e, "(usde) ProcessMessage");
  } catch (...) {
    PrintExceptionContinue(NULL, "(usde) ProcessMessage");
  }

  return (fRet);
}

int usde_coin_server_recv(CIface *iface, CNode *pnode, shbuf_t *buff)
{
  coinhdr_t hdr;
  unsigned char *data;
  int size;

  if (pnode->vSend.size() >= SendBufferSize()) /* wait for output to flush */
    return (SHERR_AGAIN);

  size = shbuf_size(buff);
  if (size < SIZEOF_COINHDR_T)
    return (SHERR_AGAIN);

  data = (unsigned char *)shbuf_data(buff);
	if (!data)
		return (SHERR_AGAIN);

  mempcpy(&hdr, data, SIZEOF_COINHDR_T);

  /* verify magic sequence */
  if (0 != memcmp(hdr.magic, iface->hdr_magic, 4)) {
    shbuf_clear(buff);
    return (SHERR_ILSEQ);
  }

  if (hdr.size > MAX_SIZE) {
    shbuf_clear(buff);
    return (SHERR_INVAL);
  }

  if (size < SIZEOF_COINHDR_T + hdr.size)
    return (SHERR_AGAIN);

  CDataStream& vRecv = pnode->vRecv;

  /* clear previous contents */
  vRecv.clear();

  /* transfer to cli buffer */
  vRecv.resize(sizeof(hdr) + hdr.size);
  memcpy(&vRecv[0], data, sizeof(hdr) + hdr.size);
  shbuf_trim(buff, sizeof(hdr) + hdr.size);

  bool fRet = usde_coin_server_recv_msg(iface, pnode);
  if (!fRet) {
    error(SHERR_INVAL, "usde_coin_server_recv: usde_coin_server_recv_msg ret'd %s <%u bytes> [%s]\n", fRet ? "true" : "false", hdr.size, hdr.cmd); 
  }

  pnode->nLastRecv = GetTime();
  return (0);
}

void usde_server_timer(void)
{
  static int verify_idx;
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  NodeList &vNodes = GetNodeList(USDE_COIN_IFACE);
  shtime_t ts;
  bc_t *bc;
  int err;

  if (fShutdown)
    return;

  usde_close_free();

  //
  // Service each socket
  {
    vector<CNode*> vNodesCopy;
    {
      LOCK(cs_vNodes);
      vNodesCopy = vNodes;
      BOOST_FOREACH(CNode* pnode, vNodesCopy)
        pnode->AddRef();
    }

    BOOST_FOREACH(CNode* pnode, vNodesCopy)
    {
      if (fShutdown)
        return;

      shbuf_t *pchBuf = descriptor_rbuff(pnode->hSocket);
      if (pchBuf) {
				shbuf_lock(pchBuf);
				if (shbuf_size(pchBuf) != 0) {
					TRY_LOCK(pnode->cs_vRecv, lockRecv);
					if (lockRecv) {
						err = 0;
						while (err == 0) {
							timing_init("recv msg", &ts);
							err = usde_coin_server_recv(iface, pnode, pchBuf);
							timing_term(USDE_COIN_IFACE, "recv msg", &ts);

							double diff = shtime_diff(ts, shtime());
							if (diff >= 0.4)
								break;
						}
						if (err && err != SHERR_AGAIN) {
							error(err, "usde_coin_server_recv");
							pnode->CloseSocketDisconnect("usde_coin_server_recv");
							continue;
						}
					}
				}
				shbuf_unlock(pchBuf);
      }

      {
        LOCK(pnode->cs_vSend);
        /* transmit pending outgoing data */
        CDataStream& vSend = pnode->vSend;
        if (!vSend.empty())
        {
          size_t nBytes = vSend.size();
          int err = unet_write(pnode->hSocket, &vSend[0], nBytes);
          if (!err) {
            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
            pnode->nLastSend = GetTime();
          }
        }
      }
    }

    {
      LOCK(cs_vNodes);
      BOOST_FOREACH(CNode* pnode, vNodesCopy)
        pnode->Release();
    }
  }

  timing_init("MessageHandler", &ts);
  usde_MessageHandler(iface);
  timing_term(USDE_COIN_IFACE, "MessageHandler", &ts);

  event_cycle_chain(USDE_COIN_IFACE);

}




list<CNode*> shc_vNodesDisconnected;
static void shc_close_free(void)
{
  NodeList &vNodes = GetNodeList(SHC_COIN_IFACE);

  LOCK(cs_vNodes);
  vector<CNode*> vNodesCopy = vNodes;
vector<CNode*> shc_vNodesDisconnected;

  // Disconnect unused nodes
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {
    if (pnode->fDisconnect ||
        (pnode->GetRefCount() <= 0 && pnode->vRecv.empty() && pnode->vSend.empty()))
    {
      // remove from vNodes
      vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());

      // release outbound grant (if any)
      pnode->grantOutbound.Release();

      pnode->Cleanup();

      // hold in disconnected pool until all refs are released
      pnode->nReleaseTime = max(pnode->nReleaseTime, GetTime() + 15 * 60);
      if (pnode->fNetworkNode || pnode->fInbound)
        pnode->Release();
      shc_vNodesDisconnected.push_back(pnode);
    }
  }

  // Delete disconnected nodes
  BOOST_FOREACH(CNode* pnode, shc_vNodesDisconnected)
  {
    delete pnode;
  }
}

extern bool shc_ProcessMessage(CIface *iface, CNode* pfrom, string strCommand, CDataStream& vRecv);
bool shc_coin_server_recv_msg(CIface *iface, CNode* pfrom)
{
  int ifaceIndex = GetCoinIndex(iface);
  CDataStream& vRecv = pfrom->vRecv;
  shtime_t ts;

  if (vRecv.empty())
    return (true);

  CMessageHeader hdr;
  vRecv >> hdr;

  /* check checksum */
  string strCommand = hdr.GetCommand();
  unsigned int nMessageSize = hdr.nMessageSize;
  if (nMessageSize > MAX_SIZE) {
    error(SHERR_2BIG, "(shc) ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE", strCommand.c_str(), nMessageSize);
    return (false);
  }

  /* verify checksum */
  uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
  unsigned int nChecksum = 0;
  memcpy(&nChecksum, &hash, sizeof(nChecksum));
  if (nChecksum != hdr.nChecksum) {
    error(SHERR_INVAL, "ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n", strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
    return (false);
  }

  bool fRet = false;
  try {
    char *cmd = (char *)strCommand.c_str();
    timing_init(cmd, &ts);
    {
//      LOCK(cs_main);
      fRet = shc_ProcessMessage(iface, pfrom, strCommand, vRecv);
    }
    timing_term(SHC_COIN_IFACE, cmd, &ts);
  } catch (std::ios_base::failure& e) {
    if (strstr(e.what(), "end of data"))
    {
      // Allow exceptions from underlength message on vRecv
      error(SHERR_INVAL, "(shc) ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
    }
    else if (strstr(e.what(), "size too large"))
    {
      // Allow exceptions from overlong size
      error(SHERR_INVAL, "(shc) ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
    }
    else
    {
      PrintExceptionContinue(&e, "(shc) ProcessMessage");
    }
  } catch (std::exception& e) {
    PrintExceptionContinue(&e, "ProcessMessages()");
  } catch (...) {
    PrintExceptionContinue(NULL, "ProcessMessages()");
  }

  return (fRet);
}

int shc_coin_server_recv(CIface *iface, CNode *pnode, shbuf_t *buff)
{
  coinhdr_t hdr;
  unsigned char *data;
  int size;

#if 0
  if (pnode->vSend.size() >= SendBufferSize()) /* wait for output to flush */
    return (SHERR_AGAIN);
#endif

  size = shbuf_size(buff);
  if (size < SIZEOF_COINHDR_T)
    return (SHERR_AGAIN);

  data = (unsigned char *)shbuf_data(buff);
	if (!data)
		return (SHERR_AGAIN);

  mempcpy(&hdr, data, SIZEOF_COINHDR_T);

  /* verify magic sequence */
  if (0 != memcmp(hdr.magic, iface->hdr_magic, 4)) {
    shbuf_clear(buff);
    return (SHERR_ILSEQ);
  }

  if (hdr.size > MAX_SIZE) {
    shbuf_clear(buff);
    return (SHERR_INVAL);
  }

  if (size < SIZEOF_COINHDR_T + hdr.size)
    return (SHERR_AGAIN);

  CDataStream& vRecv = pnode->vRecv;

  /* clear previous contents */
  vRecv.clear();

  /* transfer to cli buffer */
  vRecv.resize(sizeof(hdr) + hdr.size);
  memcpy(&vRecv[0], data, sizeof(hdr) + hdr.size);
  shbuf_trim(buff, sizeof(hdr) + hdr.size);

  bool fRet = shc_coin_server_recv_msg(iface, pnode);
  if (!fRet) {
    error(SHERR_INVAL, "shc_coin_server_recv: shc_coin_server_recv_msg ret'd %s <%u bytes> [%s]\n", fRet ? "true" : "false", hdr.size, hdr.cmd); 
  }

	Debug("(shc) coin_server_recv: received <%u bytes> \"%s\" request from \"%s\".", hdr.size, hdr.cmd, pnode->addr.ToString().c_str());

  pnode->nLastRecv = GetTime();
  return (0);
}

void shc_server_timer(void)
{
  static int verify_idx;
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  NodeList &vNodes = GetNodeList(SHC_COIN_IFACE);
  shtime_t ts;
  bc_t *bc;
  int err;

  if (fShutdown)
    return;

  shc_close_free();

  //
  // Service each socket
  {
    vector<CNode*> vNodesCopy;
    {
      LOCK(cs_vNodes);
      vNodesCopy = vNodes;
      BOOST_FOREACH(CNode* pnode, vNodesCopy)
        pnode->AddRef();
    }

    BOOST_FOREACH(CNode* pnode, vNodesCopy)
    {
      if (fShutdown)
        return;

      shbuf_t *pchBuf = descriptor_rbuff(pnode->hSocket);
      if (pchBuf) {
				shbuf_lock(pchBuf);
				if (shbuf_size(pchBuf) != 0) {
					TRY_LOCK(pnode->cs_vRecv, lockRecv);
					if (lockRecv) {
						err = 0;
						while (err == 0) {
							timing_init("recv msg", &ts);
							err = shc_coin_server_recv(iface, pnode, pchBuf);
							timing_term(SHC_COIN_IFACE, "recv msg", &ts);

							double diff = shtime_diff(ts, shtime());
							if (diff >= 0.4)
								break;
						}
						if (err && err != SHERR_AGAIN) {
							error(err, "shc_coin_server_recv");
							pnode->CloseSocketDisconnect("shc_coin_server_recv");
							continue;
						}
					}
				}
				shbuf_unlock(pchBuf);
      }

      {
        LOCK(pnode->cs_vSend);
        /* transmit pending outgoing data */
        CDataStream& vSend = pnode->vSend;
        if (!vSend.empty())
        {
          size_t nBytes = vSend.size();
          int err = unet_write(pnode->hSocket, &vSend[0], nBytes);
          if (!err) {
            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
            pnode->nLastSend = GetTime();
          }
        }
      }
    }

    {
      LOCK(cs_vNodes);
      BOOST_FOREACH(CNode* pnode, vNodesCopy)
        pnode->Release();
    }
  }

  timing_init("MessageHandler", &ts);
  shc_MessageHandler(iface);
  timing_term(SHC_COIN_IFACE, "MessageHandler", &ts);

  event_cycle_chain(SHC_COIN_IFACE); 


}

void shc_server_accept(int hSocket, struct sockaddr *net_addr)
{
  NodeList &vNodes = GetNodeList(SHC_COIN_IFACE);
#ifdef USE_IPV6
  struct sockaddr_storage sockaddr;
#else
  struct sockaddr sockaddr;
#endif
  CAddress addr;
  int nInbound = 0;
  bool inBound = false;
  unet_table_t *t = get_unet_table(hSocket);

  if (t && (t->flag & UNETF_INBOUND))
    inBound = true;

  addr.SetSockAddr(net_addr);

  if (inBound) {
    {
      LOCK(cs_vNodes);
      BOOST_FOREACH(CNode* pnode, vNodes)
        if (pnode->fInbound)
          nInbound++;
    }

    if (nInbound >= opt_num(OPT_MAX_CONN) - MAX_OUTBOUND_CONNECTIONS)
    {
      {
        LOCK(cs_setservAddNodeAddresses);
        if (!setservAddNodeAddresses.count(addr)) {
          unet_close(hSocket, "inbound limit");
        }
      }
    }

    if (CNode::IsBanned(addr))
    {
      unet_close(hSocket, "banned");
      return;
    }
  } else {
    if (CNode::IsBanned(addr)) {
      /* force clear ban list due to manual connection initiation. */
      CNode::ClearBanned();
    }
  }

  if (inBound) {
    Debug("(shc) shc_server_accept: accepted connection '%s'.", 
        addr.ToString().c_str());
  } else {
    Debug("(shc) shc_server_accept: initialized connection '%s'.",
        addr.ToString().c_str());
  }


  CNode* pnode = new CNode(SHC_COIN_IFACE, hSocket, addr, 
      shaddr_print(shaddr(hSocket)), inBound);

  //if (inBound)
    pnode->AddRef();

  if (!inBound)
    pnode->fNetworkNode = true;

  {
    LOCK(cs_vNodes);
    vNodes.push_back(pnode);
  }

#if 0
  /* submit address to shared daemon */
  shared_addr_submit(shaddr_print(net_addr));
#endif
}

list<CNode*> testnet_vNodesDisconnected;
static void testnet_close_free(void)
{
  NodeList &vNodes = GetNodeList(TESTNET_COIN_IFACE);

  LOCK(cs_vNodes);
  vector<CNode*> vNodesCopy = vNodes;
vector<CNode*> testnet_vNodesDisconnected;

  // Disconnect unused nodes
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {
    if (pnode->fDisconnect ||
        (pnode->GetRefCount() <= 0 && pnode->vRecv.empty() && pnode->vSend.empty()))
    {
      // remove from vNodes
      vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());

      // release outbound grant (if any)
      pnode->grantOutbound.Release();

      pnode->Cleanup();

      // hold in disconnected pool until all refs are released
      pnode->nReleaseTime = max(pnode->nReleaseTime, GetTime() + 15 * 60);
      if (pnode->fNetworkNode || pnode->fInbound)
        pnode->Release();
      testnet_vNodesDisconnected.push_back(pnode);
    }
  }

  // Delete disconnected nodes
  BOOST_FOREACH(CNode* pnode, testnet_vNodesDisconnected)
  {
    delete pnode;
  }
}

extern bool testnet_ProcessMessage(CIface *iface, CNode* pfrom, string strCommand, CDataStream& vRecv);
bool testnet_coin_server_recv_msg(CIface *iface, CNode* pfrom)
{
  int ifaceIndex = GetCoinIndex(iface);
  CDataStream& vRecv = pfrom->vRecv;
  shtime_t ts;

  if (vRecv.empty())
    return (true);

  CMessageHeader hdr;
  vRecv >> hdr;

  /* check checksum */
  string strCommand = hdr.GetCommand();
  unsigned int nMessageSize = hdr.nMessageSize;
  if (nMessageSize > MAX_SIZE) {
    error(SHERR_2BIG, "(testnet) ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE", strCommand.c_str(), nMessageSize);
    return (false);
  }

  /* verify checksum */
  uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
  unsigned int nChecksum = 0;
  memcpy(&nChecksum, &hash, sizeof(nChecksum));
  if (nChecksum != hdr.nChecksum) {
    error(SHERR_INVAL, "ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n", strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
    return (false);
  }

  bool fRet = false;
  try {
    char *cmd = (char *)strCommand.c_str();
    timing_init(cmd, &ts);
    {
//      LOCK(cs_main);
      fRet = testnet_ProcessMessage(iface, pfrom, strCommand, vRecv);
    }
    timing_term(TESTNET_COIN_IFACE, cmd, &ts);
  } catch (std::ios_base::failure& e) {
    if (strstr(e.what(), "end of data"))
    {
      // Allow exceptions from underlength message on vRecv
      error(SHERR_INVAL, "(testnet) ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
    }
    else if (strstr(e.what(), "size too large"))
    {
      // Allow exceptions from overlong size
      error(SHERR_INVAL, "(testnet) ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
    }
    else
    {
      PrintExceptionContinue(&e, "(testnet) ProcessMessage");
    }
  } catch (std::exception& e) {
    PrintExceptionContinue(&e, "ProcessMessages()");
  } catch (...) {
    PrintExceptionContinue(NULL, "ProcessMessages()");
  }

  return (fRet);
}

int testnet_coin_server_recv(CIface *iface, CNode *pnode, shbuf_t *buff)
{
  coinhdr_t hdr;
  unsigned char *data;
  int size;

  if (pnode->vSend.size() >= SendBufferSize()) /* wait for output to flush */
    return (SHERR_AGAIN);

  size = shbuf_size(buff);
  if (size < SIZEOF_COINHDR_T)
    return (SHERR_AGAIN);

  data = (unsigned char *)shbuf_data(buff);
	if (!data)
		return (SHERR_AGAIN);

  mempcpy(&hdr, data, SIZEOF_COINHDR_T);

  /* verify magic sequence */
  if (0 != memcmp(hdr.magic, iface->hdr_magic, 4)) {
    shbuf_clear(buff);
    return (SHERR_ILSEQ);
  }

  if (hdr.size > MAX_SIZE) {
    shbuf_clear(buff);
    return (SHERR_INVAL);
  }

  if (size < SIZEOF_COINHDR_T + hdr.size)
    return (SHERR_AGAIN);

  CDataStream& vRecv = pnode->vRecv;

  /* clear previous contents */
  vRecv.clear();

  /* transfer to cli buffer */
  vRecv.resize(sizeof(hdr) + hdr.size);
  memcpy(&vRecv[0], data, sizeof(hdr) + hdr.size);
  shbuf_trim(buff, sizeof(hdr) + hdr.size);

  bool fRet = testnet_coin_server_recv_msg(iface, pnode);
  if (!fRet) {
    error(SHERR_INVAL, "testnet_coin_server_recv: testnet_coin_server_recv_msg ret'd %s <%u bytes> [%s]\n", fRet ? "true" : "false", hdr.size, hdr.cmd); 
  }

  pnode->nLastRecv = GetTime();
  return (0);
}

void testnet_MessageHandler(CIface *iface)
{
  NodeList &vNodes = GetNodeList(iface);
  shtime_t ts;

  vector<CNode*> vNodesCopy;
  {
    LOCK(cs_vNodes);
    vNodesCopy = vNodes;
    BOOST_FOREACH(CNode* pnode, vNodesCopy)
      pnode->AddRef();
  }

  // Poll the connected nodes for messages
  CNode* pnodeTrickle = NULL;
#if 0
  if (!vNodesCopy.empty())
    pnodeTrickle = vNodesCopy[GetRand(vNodesCopy.size())];
#endif
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {

    // Send messages
    timing_init("SendMessages", &ts);
    {
      TRY_LOCK(pnode->cs_vSend, lockSend);
      if (lockSend)
        testnet_SendMessages(iface, pnode, pnode == pnodeTrickle);
    }
    timing_term(TESTNET_COIN_IFACE, "SendMessages", &ts);
    if (fShutdown)
      return;
  }

  {
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodesCopy)
      pnode->Release();
  }


}


void testnet_server_timer(void)
{
  static int verify_idx;
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);
  NodeList &vNodes = GetNodeList(TESTNET_COIN_IFACE);
  shtime_t ts;
  bc_t *bc;
  int err;

  if (fShutdown)
    return;

  testnet_close_free();

  //
  // Service each socket
  {
    vector<CNode*> vNodesCopy;
    {
      LOCK(cs_vNodes);
      vNodesCopy = vNodes;
      BOOST_FOREACH(CNode* pnode, vNodesCopy)
        pnode->AddRef();
    }

    BOOST_FOREACH(CNode* pnode, vNodesCopy)
    {
      if (fShutdown)
        return;

      shbuf_t *pchBuf = descriptor_rbuff(pnode->hSocket);
      if (pchBuf) {
				shbuf_lock(pchBuf);
				if (shbuf_size(pchBuf) != 0) {
					TRY_LOCK(pnode->cs_vRecv, lockRecv);
					if (lockRecv) {
						err = 0;
						while (err == 0) {
							timing_init("recv msg", &ts);
							err = testnet_coin_server_recv(iface, pnode, pchBuf);
							timing_term(TESTNET_COIN_IFACE, "recv msg", &ts);

							double diff = shtime_diff(ts, shtime());
							if (diff >= 0.4)
								break;
						}
						if (err && err != SHERR_AGAIN) {
							error(err, "testnet_coin_server_recv");
							pnode->CloseSocketDisconnect("testnet_coin_server_recv");
							continue;
						}
					}
				}
				shbuf_unlock(pchBuf);
      }

      {
        LOCK(pnode->cs_vSend);
        /* transmit pending outgoing data */
        CDataStream& vSend = pnode->vSend;
        if (!vSend.empty())
        {
          size_t nBytes = vSend.size();
          int err = unet_write(pnode->hSocket, &vSend[0], nBytes);
          if (!err) {
            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
            pnode->nLastSend = GetTime();
          }
        }
      }
    }

    {
      LOCK(cs_vNodes);
      BOOST_FOREACH(CNode* pnode, vNodesCopy)
        pnode->Release();
    }
  }

  timing_init("MessageHandler", &ts);
  testnet_MessageHandler(iface);
  timing_term(TESTNET_COIN_IFACE, "MessageHandler", &ts);

  event_cycle_chain(TESTNET_COIN_IFACE); 

}

void testnet_server_accept(int hSocket, struct sockaddr *net_addr)
{
  NodeList &vNodes = GetNodeList(TESTNET_COIN_IFACE);
#ifdef USE_IPV6
  struct sockaddr_storage sockaddr;
#else
  struct sockaddr sockaddr;
#endif
  CAddress addr;
  int nInbound = 0;
  bool inBound = false;
  unet_table_t *t = get_unet_table(hSocket);

  if (t && (t->flag & UNETF_INBOUND))
    inBound = true;

  addr.SetSockAddr(net_addr);

  if (inBound) {
    {
      LOCK(cs_vNodes);
      BOOST_FOREACH(CNode* pnode, vNodes)
        if (pnode->fInbound)
          nInbound++;
    }

    if (nInbound >= opt_num(OPT_MAX_CONN) - MAX_OUTBOUND_CONNECTIONS)
    {
      {
        LOCK(cs_setservAddNodeAddresses);
        if (!setservAddNodeAddresses.count(addr)) {
          unet_close(hSocket, "inbound limit");
        }
      }
    }

    if (CNode::IsBanned(addr))
    {
      unet_close(hSocket, "banned");
      return;
    }
  } else {
    if (CNode::IsBanned(addr)) {
      /* force clear ban list due to manual connection initiation. */
      CNode::ClearBanned();
    }
  }

  if (inBound) {
    Debug("(testnet) testnet_server_accept: accepted connection '%s'.", 
        addr.ToString().c_str());
  } else {
    Debug("(testnet) testnet_server_accept: initialized connection '%s'.",
        addr.ToString().c_str());
  }


  CNode* pnode = new CNode(TESTNET_COIN_IFACE, hSocket, addr, 
      shaddr_print(shaddr(hSocket)), inBound);

  //if (inBound)
    pnode->AddRef();

  if (!inBound)
    pnode->fNetworkNode = true;

  {
    LOCK(cs_vNodes);
    vNodes.push_back(pnode);
  }

#if 0
  /* submit address to shared daemon */
  shared_addr_submit(shaddr_print(net_addr));
#endif
}

void testnet_server_close(int fd, struct sockaddr *addr)
{
  NodeList &vNodes = GetNodeList(TESTNET_COIN_IFACE);

  LOCK(cs_vNodes);
  vector<CNode*> vNodesCopy = vNodes;
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {
    if (pnode->hSocket == fd) {
      pnode->fDisconnect = true;
    }
  }

}


void static Discover()
{
int idx;
    if (!fDiscover)
        return;

#ifdef WIN32_VC
    // Get local host ip
    char pszHostName[1000] = "";
    if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
    {
        vector<CNetAddr> vaddr;
        if (LookupHost(pszHostName, vaddr))
        {
            BOOST_FOREACH (const CNetAddr &addr, vaddr)
            {
for (idx = 0; idx < MAX_COIN_IFACE; idx++)
                AddLocal(ifaceIndex, addr, LOCAL_IF);
            }
        }
    }
#else
    // Get local host ip
    struct ifaddrs* myaddrs;
    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs* ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == NULL) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            if (strcmp(ifa->ifa_name, "lo0") == 0) continue;
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                CNetAddr addr(s4->sin_addr);
for (idx = 0; idx < MAX_COIN_IFACE; idx++) 
                AddLocal(idx, addr, LOCAL_IF);
            }
#ifdef USE_IPV6
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct sockaddr_in6* s6 = (struct sockaddr_in6*)(ifa->ifa_addr);
                CNetAddr addr(s6->sin6_addr);
for (idx = 0; idx < MAX_COIN_IFACE; idx++) 
                AddLocal(idx, addr, LOCAL_IF);
            }
#endif
        }
        freeifaddrs(myaddrs);
    }
#endif

    //CreateThread(ThreadGetMyExternalIP, NULL);

  unet_local_init();

//  GetMyExternalIP(); 
}

void StartCoinServer(void)
{


  // Make this thread recognisable as the startup thread

  if (semOutbound == NULL) {
    // initialize semaphore
    int nMaxOutbound = min(MAX_OUTBOUND_CONNECTIONS, opt_num(OPT_MAX_CONN));
    semOutbound = new CSemaphore(nMaxOutbound);
  }


  Discover();

}


bool StopNode()
{
  fShutdown = true;
  // nTransactionsUpdated++;
  int64 nStart = GetTime();
  if (semOutbound)
    for (int i=0; i<MAX_OUTBOUND_CONNECTIONS; i++)
      semOutbound->post();
  do
  {
    int nThreadsRunning = 0;
    for (int n = 0; n < THREAD_MAX; n++)
      nThreadsRunning += vnThreadsRunning[n];
    if (nThreadsRunning == 0)
      break;
    if (GetTime() - nStart > 20)
      break;
    sleep(1);//Sleep(20);
  } while(true);

  return true;
}


#ifdef __cplusplus
extern "C" {
#endif

void start_node(void)
{
  char username[256];
  char password[256];

  /* set rpc credentials */
  get_rpc_cred(username, password);
  string strUser(username);
  string strPass(username);
  mapArgs["-rpcuser"] = strUser;
  mapArgs["-rpcpassword"] = strPass;

  /* start cpp threads */
  StartCoinServer();
}




#ifdef __cplusplus
}
#endif

vector <CAddress> GetAddresses(CIface *iface, int max_peer)
{
  int ifaceIndex = GetCoinIndex(iface);
  vector<CAddress> vAddr;
  shpeer_t **addr_list;
  shpeer_t *peer;
  unet_bind_t *bind;
  char hostname[256];
  char buf[256];
  int port;
  int idx;

  addr_list = unet_peer_track_list(ifaceIndex, max_peer);
  if (!addr_list)
    return (vAddr);

  for (idx = 0; addr_list[idx]; idx++) {
    peer = addr_list[idx];

    shpeer_host(peer, hostname, &port);
    shpeer_free(&peer);

    CAddress addr(CService(hostname, port));
    vAddr.push_back(addr);

    free(peer);
  }
  free(addr_list);

  return (vAddr);
}






#define CHKIP_HTML_TEMPLATE \
  "GET / HTTP/1.1\r\n" \
  "Host: checkip.dyndns.org\r\n" \
  "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n" \
  "Connection: close\r\n" \
  "\r\n"
static const char *CHKIP_IP_TAG = "Current IP Address: ";

int check_ip(char *serv_hostname, struct in_addr *net_addr)
{
  shbuf_t *buff;
  fd_set r_set;
  long to;
  char *text;
  int err;
  int sk;

  /* checkip.dyndns.org */ 
  sk = shconnect_host(serv_hostname, 80, SHNET_ASYNC);
  if (sk < 0) {
    return (sk);
  }

  err = shnet_write(sk, CHKIP_HTML_TEMPLATE, strlen(CHKIP_HTML_TEMPLATE));
  if (err < 0) {
    shnet_close(sk);
    return (err);  
  }

  to = 3000; /* 3s */
  FD_ZERO(&r_set);
  FD_SET(sk, &r_set);
  shnet_verify(&r_set, NULL, &to);

  buff = shnet_read_buf(sk);
  if (!buff || shbuf_size(buff) == 0) {
    shnet_close(sk);
    return (SHERR_INVAL);
  }

  text = (char *)shbuf_data(buff);
  text = strstr(text, CHKIP_IP_TAG);
  if (!text) {
    shnet_close(sk);
    return (SHERR_INVAL);
  }

  text += strlen(CHKIP_IP_TAG);
  strtok(text, "<");
  inet_aton(text, net_addr);

  shbuf_clear(buff);
  shnet_close(sk);

  return (0);
}


void GetMyExternalIP(void)
{
  CNetAddr addrLocalHost;
  struct in_addr addr;
  shgeo_t geo;
  char selfip_addr[MAXHOSTNAMELEN+1];
  char prbuf[1024];
  char buf[256];
  int idx;
  int err;

  memset(&addr, 0, sizeof(addr));

  /* check for previous cached IP address */
  memset(buf, 0, sizeof(buf));
  strncpy(buf, shpref_get("shcoind.net.addr", ""), sizeof(buf)-1);
  if (*buf && 0 == inet_aton(buf, &addr)) {
    addrLocalHost = CNetAddr(addr);
    if (addrLocalHost.IsValid() && addrLocalHost.IsRoutable()) {
      for (idx = 0; idx < MAX_COIN_IFACE; idx++)
        AddLocal(idx, addrLocalHost, LOCAL_HTTP);

      sprintf(buf, "info: listening on IP addr '%s' (cached).", inet_ntoa(addr));
      shcoind_log(buf);
      return;
    }
  }

  strcpy(selfip_addr, "91.198.22.70");
  err = check_ip(selfip_addr, &addr);
  if (err)
    return;

  addrLocalHost = CNetAddr(addr);
  if (!addrLocalHost.IsValid() || !addrLocalHost.IsRoutable())
    return;

  memset(buf, 0, sizeof(buf));
  strncpy(buf, inet_ntoa(addr), sizeof(buf)-1);
  shpref_set("shcoind.net.addr", buf);

  for (idx = 0; idx < MAX_COIN_IFACE; idx++)
    AddLocal(idx, addrLocalHost, LOCAL_HTTP);

  sprintf(prbuf, "info: listening on IP addr '%s'.", buf);
  shcoind_log(prbuf);


}


void AddPeerAddress(CIface *iface, const char *hostname, int port)
{
  int ifaceIndex = GetCoinIndex(iface);
  shpeer_t *peer;
  char addr_str[256];

  if (!iface || !iface->enabled)
    return;

  if (port == 0)
    port = iface->port;

  memset(addr_str, 0, sizeof(addr_str));
  snprintf(addr_str, sizeof(addr_str)-1, "%s %d", hostname, port); 

  /* add peer to tracking database. */
  peer = shpeer_init(iface->name, addr_str);
	/* store persistently */
	unet_peer_incr(ifaceIndex, peer);
#if 0
	/* connect immediately */
  create_uevent_verify_peer(GetCoinIndex(iface), peer);
#endif
	shpeer_free(&peer);

  Debug("(%s) AddPeerAddress: host '%s' (port: %d).", 
      iface->name, (char *)hostname, port);
}




void emc2_close_free(void)
{
  NodeList &vNodes = GetNodeList(EMC2_COIN_IFACE);

  LOCK(cs_vNodes);
  vector<CNode*> vNodesCopy = vNodes;
  vector<CNode*> vNodesDisconnected;

  // Disconnect unused nodes
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {
    if (pnode->fDisconnect ||
        (pnode->GetRefCount() <= 0 && pnode->vRecv.empty() && pnode->vSend.empty()))
    {
      // remove from vNodes
      vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());

      // release outbound grant (if any)
      pnode->grantOutbound.Release();

      pnode->Cleanup();

      // hold in disconnected pool until all refs are released
      pnode->nReleaseTime = max(pnode->nReleaseTime, GetTime() + 15 * 60);
      if (pnode->fNetworkNode || pnode->fInbound)
        pnode->Release();
      vNodesDisconnected.push_back(pnode);
    }
  }

  // Delete disconnected nodes
  BOOST_FOREACH(CNode* pnode, vNodesDisconnected)
  {
    delete pnode;
  }

}

void emc2_server_accept(int hSocket, struct sockaddr *net_addr)
{
  NodeList &vNodes = GetNodeList(EMC2_COIN_IFACE);
#ifdef USE_IPV6
  struct sockaddr_storage sockaddr;
#else
  struct sockaddr sockaddr;
#endif
  CAddress addr;
  int nInbound = 0;
  bool inBound = false;
  unet_table_t *t = get_unet_table(hSocket);

  if (t && (t->flag & UNETF_INBOUND))
    inBound = true;

  addr.SetSockAddr(net_addr);

  if (inBound) {
    {
      LOCK(cs_vNodes);
      BOOST_FOREACH(CNode* pnode, vNodes)
        if (pnode->fInbound)
          nInbound++;
    }

    if (nInbound >= opt_num(OPT_MAX_CONN) - MAX_OUTBOUND_CONNECTIONS)
    {
      {
        LOCK(cs_setservAddNodeAddresses);
        if (!setservAddNodeAddresses.count(addr)) {
          unet_close(hSocket, (char *)"inbound limit");
        }
      }
    }

    if (CNode::IsBanned(addr)) {
      unet_close(hSocket, "banned");
      return;
    }
  } else {
    if (CNode::IsBanned(addr)) {
      /* force clear ban list due to manual connection initiation. */
      CNode::ClearBanned();
    }
  }

  if (inBound) {
    Debug("(emc2) emc2_server_accept: accepted connection '%s'.", 
        addr.ToString().c_str());
  } else {
    Debug("(emc2) emc2_server_accept: initialized connection '%s'.",
        addr.ToString().c_str());
  }


  CNode* pnode = new CNode(EMC2_COIN_IFACE, hSocket, addr, 
      shaddr_print(shaddr(hSocket)), inBound);

  //if (inBound)
    pnode->AddRef();

  if (!inBound)
    pnode->fNetworkNode = true;

  {
    LOCK(cs_vNodes);
    vNodes.push_back(pnode);
  }

#if 0
  /* submit address to shared daemon */
  shared_addr_submit(shaddr_print(net_addr));
#endif
}

void emc2_server_close(int fd, struct sockaddr *addr)
{
  NodeList &vNodes = GetNodeList(EMC2_COIN_IFACE);

  LOCK(cs_vNodes);
  vector<CNode*> vNodesCopy = vNodes;
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {
    if (pnode->hSocket == fd) {
      pnode->fDisconnect = true;
    }
  }

}

extern bool emc2_ProcessMessage(CIface *iface, CNode* pfrom, string strCommand, CDataStream& vRecv);
bool emc2_coin_server_recv_msg(CIface *iface, CNode* pfrom)
{
  int ifaceIndex = GetCoinIndex(iface);
  CDataStream& vRecv = pfrom->vRecv;
  shtime_t ts;

  if (vRecv.empty())
    return (true);

  CMessageHeader hdr;
  vRecv >> hdr;

  /* check checksum */
  string strCommand = hdr.GetCommand();
  unsigned int nMessageSize = hdr.nMessageSize;
  if (nMessageSize > MAX_SIZE) {
    error(SHERR_2BIG, "(emc2) ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE", strCommand.c_str(), nMessageSize);
    return (false);
  }

  /* verify checksum */
  uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
  unsigned int nChecksum = 0;
  memcpy(&nChecksum, &hash, sizeof(nChecksum));
  if (nChecksum != hdr.nChecksum) {
    error(SHERR_INVAL, "ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n", strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
    return (false);
  }

  bool fRet = false;
  try {
    char *cmd = (char *)strCommand.c_str();
    {
//      LOCK(cs_main);
      fRet = emc2_ProcessMessage(iface, pfrom, strCommand, vRecv);
    }
  } catch (std::ios_base::failure& e) {
    if (strstr(e.what(), "end of data"))
    {
      // Allow exceptions from underlength message on vRecv
      error(SHERR_INVAL, "(use) ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
    }
    else if (strstr(e.what(), "size too large"))
    {
      // Allow exceptions from overlong size
      error(SHERR_INVAL, "(use) ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
    }
    else
    {
      PrintExceptionContinue(&e, "(emc2) ProcessMessage");
    }
  } catch (std::exception& e) {
    PrintExceptionContinue(&e, "(emc2) ProcessMessage");
  } catch (...) {
    PrintExceptionContinue(NULL, "(emc2) ProcessMessage");
  }

  return (fRet);
}

int emc2_coin_server_recv(CIface *iface, CNode *pnode, shbuf_t *buff)
{
  coinhdr_t hdr;
  unsigned char *data;
  int size;

  if (pnode->vSend.size() >= SendBufferSize()) /* wait for output to flush */
    return (SHERR_AGAIN);

  size = shbuf_size(buff);
  if (size < SIZEOF_COINHDR_T)
    return (SHERR_AGAIN);

  data = (unsigned char *)shbuf_data(buff);
	if (!data)
    return (SHERR_AGAIN);

  mempcpy(&hdr, data, SIZEOF_COINHDR_T);

  /* verify magic sequence */
  if (0 != memcmp(hdr.magic, iface->hdr_magic, 4)) {
    shbuf_clear(buff);
    return (SHERR_ILSEQ);
  }

  if (hdr.size > MAX_SIZE) {
    shbuf_clear(buff);
    return (SHERR_INVAL);
  }

  if (size < SIZEOF_COINHDR_T + hdr.size)
    return (SHERR_AGAIN);

  /* transfer to cli buffer */
  CDataStream& vRecv = pnode->vRecv;
  vRecv.resize(sizeof(hdr) + hdr.size);
  memcpy(&vRecv[0], data, sizeof(hdr) + hdr.size);
  shbuf_trim(buff, sizeof(hdr) + hdr.size);
  
  bool fRet = emc2_coin_server_recv_msg(iface, pnode);
  if (!fRet) {
    error(SHERR_INVAL, "emc2_coin_server_recv: emc2_coin_server_recv_msg ret'd %s <%u bytes> [%s]\n", fRet ? "true" : "false", hdr.size, hdr.cmd); 
  }

  vRecv.erase(vRecv.begin(), vRecv.end());
  vRecv.Compact();

  pnode->nLastRecv = GetTime();
  return (0);
}

void emc2_MessageHandler(CIface *iface)
{
  NodeList &vNodes = GetNodeList(iface);
  shtime_t ts;

  vector<CNode*> vNodesCopy;
  {
    LOCK(cs_vNodes);
    vNodesCopy = vNodes;
    BOOST_FOREACH(CNode* pnode, vNodesCopy)
      pnode->AddRef();
  }

  // Poll the connected nodes for messages
  CNode* pnodeTrickle = NULL;
  if (!vNodesCopy.empty())
    pnodeTrickle = vNodesCopy[GetRand(vNodesCopy.size())];
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {

    // Send messages
    timing_init("SendMessages", &ts);
    {
      TRY_LOCK(pnode->cs_vSend, lockSend);
      if (lockSend)
        emc2_SendMessages(iface, pnode, pnode == pnodeTrickle);
    }
    timing_term(EMC2_COIN_IFACE, "SendMessages", &ts);
    if (fShutdown)
      return;
  }

  {
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodesCopy)
      pnode->Release();
  }


}

void emc2_server_timer(void)
{
  static int verify_idx;
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  NodeList &vNodes = GetNodeList(EMC2_COIN_IFACE);
  shtime_t ts;
  bc_t *bc;
  int err;

  if (fShutdown)
    return;

  emc2_close_free();

  //
  // Service each socket
  {
    vector<CNode*> vNodesCopy;
    {
      LOCK(cs_vNodes);
      vNodesCopy = vNodes;
      BOOST_FOREACH(CNode* pnode, vNodesCopy)
        pnode->AddRef();
    }

    BOOST_FOREACH(CNode* pnode, vNodesCopy)
    {
      if (fShutdown)
        return;

      shbuf_t *pchBuf = descriptor_rbuff(pnode->hSocket);
      if (pchBuf) {
				shbuf_lock(pchBuf);
				if (shbuf_size(pchBuf) != 0) {
					TRY_LOCK(pnode->cs_vRecv, lockRecv);
					if (lockRecv) {
						err = 0;
						while (err == 0) {
							timing_init("recv msg", &ts);
							err = emc2_coin_server_recv(iface, pnode, pchBuf);
							timing_term(EMC2_COIN_IFACE, "recv msg", &ts);

							double diff = shtime_diff(ts, shtime());
							if (diff >= 0.4)
								break;
						}
						if (err && err != SHERR_AGAIN) {
							error(err, "emc2_coin_server_recv");
							pnode->CloseSocketDisconnect("emc2_coin_server_recv");
							continue;
						}
					}
				}
				shbuf_unlock(pchBuf);
      }

      {
        LOCK(pnode->cs_vSend);
        /* transmit pending outgoing data */
        CDataStream& vSend = pnode->vSend;
        if (!vSend.empty())
        {
          size_t nBytes = vSend.size();
          int err = unet_write(pnode->hSocket, &vSend[0], nBytes);
          if (!err) {
            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
            pnode->nLastSend = GetTime();
          }
        }
      }
    }

    {
      LOCK(cs_vNodes);
      BOOST_FOREACH(CNode* pnode, vNodesCopy)
        pnode->Release();
    }
  }

  timing_init("MessageHandler", &ts);
  emc2_MessageHandler(iface);
  timing_term(EMC2_COIN_IFACE, "MessageHandler", &ts);

  event_cycle_chain(EMC2_COIN_IFACE);

}





list<CNode*> ltc_vNodesDisconnected;
static void ltc_close_free(void)
{
  NodeList &vNodes = GetNodeList(LTC_COIN_IFACE);

  LOCK(cs_vNodes);
  vector<CNode*> vNodesCopy = vNodes;
vector<CNode*> ltc_vNodesDisconnected;

  // Disconnect unused nodes
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {
    if (pnode->fDisconnect ||
        (pnode->GetRefCount() <= 0 && pnode->vRecv.empty() && pnode->vSend.empty()))
    {
      // remove from vNodes
      vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());

      // release outbound grant (if any)
      pnode->grantOutbound.Release();

      pnode->Cleanup();

      // hold in disconnected pool until all refs are released
      pnode->nReleaseTime = max(pnode->nReleaseTime, GetTime() + 15 * 60);
      if (pnode->fNetworkNode || pnode->fInbound)
        pnode->Release();
      ltc_vNodesDisconnected.push_back(pnode);
    }
  }

  // Delete disconnected nodes
  BOOST_FOREACH(CNode* pnode, ltc_vNodesDisconnected)
  {
    delete pnode;
  }
}

extern bool ltc_ProcessMessage(CIface *iface, CNode* pfrom, string strCommand, CDataStream& vRecv);
bool ltc_coin_server_recv_msg(CIface *iface, CNode* pfrom)
{
  int ifaceIndex = GetCoinIndex(iface);
  CDataStream& vRecv = pfrom->vRecv;
  shtime_t ts;

  if (vRecv.empty())
    return (true);

  CMessageHeader hdr;
  vRecv >> hdr;

  /* check checksum */
  string strCommand = hdr.GetCommand();
  unsigned int nMessageSize = hdr.nMessageSize;
  if (nMessageSize > MAX_SIZE) {
    error(SHERR_2BIG, "(ltc) ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE", strCommand.c_str(), nMessageSize);
    return (false);
  }

  /* verify checksum */
  uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
  unsigned int nChecksum = 0;
  memcpy(&nChecksum, &hash, sizeof(nChecksum));
  if (nChecksum != hdr.nChecksum) {
    error(SHERR_INVAL, "ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n", strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
    return (false);
  }

  bool fRet = false;
  try {
    char *cmd = (char *)strCommand.c_str();
    timing_init(cmd, &ts);
    {
//      LOCK(cs_main);
      fRet = ltc_ProcessMessage(iface, pfrom, strCommand, vRecv);
    }
    timing_term(LTC_COIN_IFACE, cmd, &ts);
  } catch (std::ios_base::failure& e) {
    if (strstr(e.what(), "end of data"))
    {
      // Allow exceptions from underlength message on vRecv
      error(SHERR_INVAL, "(ltc) ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
    }
    else if (strstr(e.what(), "size too large"))
    {
      // Allow exceptions from overlong size
      error(SHERR_INVAL, "(ltc) ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
    }
    else
    {
      PrintExceptionContinue(&e, "(ltc) ProcessMessage");
    }
  } catch (std::exception& e) {
    PrintExceptionContinue(&e, "ProcessMessages()");
  } catch (...) {
    PrintExceptionContinue(NULL, "ProcessMessages()");
  }

  return (fRet);
}

int ltc_coin_server_recv(CIface *iface, CNode *pnode, shbuf_t *buff)
{
  coinhdr_t hdr;
  unsigned char *data;
  int size;

  if (pnode->vSend.size() >= SendBufferSize()) /* wait for output to flush */
    return (SHERR_AGAIN);

  size = shbuf_size(buff);
  if (size < SIZEOF_COINHDR_T)
    return (SHERR_AGAIN);

  data = (unsigned char *)shbuf_data(buff);
	if (!data)
    return (SHERR_AGAIN);

  mempcpy(&hdr, data, SIZEOF_COINHDR_T);

  /* verify magic sequence */
  if (0 != memcmp(hdr.magic, iface->hdr_magic, 4)) {
    shbuf_clear(buff);
    return (SHERR_ILSEQ);
  }

  if (hdr.size > MAX_SIZE) {
    shbuf_clear(buff);
    return (SHERR_INVAL);
  }

  if (size < SIZEOF_COINHDR_T + hdr.size)
    return (SHERR_AGAIN);

  CDataStream& vRecv = pnode->vRecv;

  /* clear previous contents */
  vRecv.clear();

  /* transfer to cli buffer */
  vRecv.resize(sizeof(hdr) + hdr.size);
  memcpy(&vRecv[0], data, sizeof(hdr) + hdr.size);
  shbuf_trim(buff, sizeof(hdr) + hdr.size);

  bool fRet = ltc_coin_server_recv_msg(iface, pnode);
  if (!fRet) {
    error(SHERR_INVAL, "ltc_coin_server_recv: ltc_coin_server_recv_msg ret'd %s <%u bytes> [%s]\n", fRet ? "true" : "false", hdr.size, hdr.cmd); 
  }


  pnode->nLastRecv = GetTime();
  return (0);
}

void ltc_MessageHandler(CIface *iface)
{
  NodeList &vNodes = GetNodeList(iface);
  shtime_t ts;

  vector<CNode*> vNodesCopy;
  {
    LOCK(cs_vNodes);
    vNodesCopy = vNodes;
    BOOST_FOREACH(CNode* pnode, vNodesCopy)
      pnode->AddRef();
  }

  // Poll the connected nodes for messages
  CNode* pnodeTrickle = NULL;
#if 0
  if (!vNodesCopy.empty())
    pnodeTrickle = vNodesCopy[GetRand(vNodesCopy.size())];
#endif
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {

    // Send messages
    timing_init("SendMessages", &ts);
    {
      TRY_LOCK(pnode->cs_vSend, lockSend);
      if (lockSend)
        ltc_SendMessages(iface, pnode, pnode == pnodeTrickle);
    }
    timing_term(LTC_COIN_IFACE, "SendMessages", &ts);
    if (fShutdown)
      return;
  }

  {
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodesCopy)
      pnode->Release();
  }


}


void ltc_server_timer(void)
{
  static int verify_idx;
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
  NodeList &vNodes = GetNodeList(LTC_COIN_IFACE);
  shtime_t ts;
  bc_t *bc;
  int err;

  if (fShutdown)
    return;

  ltc_close_free();

  //
  // Service each socket
  {
    vector<CNode*> vNodesCopy;
    {
      LOCK(cs_vNodes);
      vNodesCopy = vNodes;
      BOOST_FOREACH(CNode* pnode, vNodesCopy)
        pnode->AddRef();
    }

    BOOST_FOREACH(CNode* pnode, vNodesCopy)
    {
      if (fShutdown)
        return;

      shbuf_t *pchBuf = descriptor_rbuff(pnode->hSocket);
      if (pchBuf) {
				shbuf_lock(pchBuf);
				if (shbuf_size(pchBuf) != 0) {
					TRY_LOCK(pnode->cs_vRecv, lockRecv);
					if (lockRecv) {
						err = 0;
						while (err == 0) {
							timing_init("recv msg", &ts);
							err = ltc_coin_server_recv(iface, pnode, pchBuf);
							timing_term(LTC_COIN_IFACE, "recv msg", &ts);

							double diff = shtime_diff(ts, shtime());
							if (diff >= 0.4)
								break;
						}
						if (err && err != SHERR_AGAIN) {
							error(err, "ltc_coin_server_recv");
							pnode->CloseSocketDisconnect("ltc_coin_server_recv");
							continue;
						}
					}
				}
				shbuf_unlock(pchBuf);
      }

      {
        LOCK(pnode->cs_vSend);
        /* transmit pending outgoing data */
        CDataStream& vSend = pnode->vSend;
        if (!vSend.empty())
        {
          size_t nBytes = vSend.size();
          int err = unet_write(pnode->hSocket, &vSend[0], nBytes);
          if (!err) {
            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
            pnode->nLastSend = GetTime();
          }
        }
      }
    }

    {
      LOCK(cs_vNodes);
      BOOST_FOREACH(CNode* pnode, vNodesCopy)
        pnode->Release();
    }
  }

  timing_init("MessageHandler", &ts);
  ltc_MessageHandler(iface);
  timing_term(LTC_COIN_IFACE, "MessageHandler", &ts);

  event_cycle_chain(LTC_COIN_IFACE);

}

void ltc_server_accept(int hSocket, struct sockaddr *net_addr)
{
  NodeList &vNodes = GetNodeList(LTC_COIN_IFACE);
#ifdef USE_IPV6
  struct sockaddr_storage sockaddr;
#else
  struct sockaddr sockaddr;
#endif
  CAddress addr;
  int nInbound = 0;
  bool inBound = false;
  unet_table_t *t = get_unet_table(hSocket);

  if (t && (t->flag & UNETF_INBOUND))
    inBound = true;

  addr.SetSockAddr(net_addr);

  if (inBound) {
    {
      LOCK(cs_vNodes);
      BOOST_FOREACH(CNode* pnode, vNodes)
        if (pnode->fInbound)
          nInbound++;
    }

    if (nInbound >= opt_num(OPT_MAX_CONN) - MAX_OUTBOUND_CONNECTIONS)
    {
      {
        LOCK(cs_setservAddNodeAddresses);
        if (!setservAddNodeAddresses.count(addr)) {
          unet_close(hSocket, "inbound limit");
        }
      }
    }

    if (CNode::IsBanned(addr))
    {
      unet_close(hSocket, "banned");
      return;
    }
  } else {
    if (CNode::IsBanned(addr)) {
      /* force clear ban list due to manual connection initiation. */
      CNode::ClearBanned();
    }
  }

  if (inBound) {
    Debug("(ltc) ltc_server_accept: accepted connection '%s'.", 
        addr.ToString().c_str());
  } else {
    Debug("(ltc) ltc_server_accept: initialized connection '%s'.",
        addr.ToString().c_str());
  }


  CNode* pnode = new CNode(LTC_COIN_IFACE, hSocket, addr, 
      shaddr_print(shaddr(hSocket)), inBound);

  //if (inBound)
    pnode->AddRef();

  if (!inBound)
    pnode->fNetworkNode = true;

  {
    LOCK(cs_vNodes);
    vNodes.push_back(pnode);
  }

#if 0
  /* submit address to shared daemon */
  shared_addr_submit(shaddr_print(net_addr));
#endif
}

void ltc_server_close(int fd, struct sockaddr *addr)
{
  NodeList &vNodes = GetNodeList(LTC_COIN_IFACE);

  LOCK(cs_vNodes);
  vector<CNode*> vNodesCopy = vNodes;
  BOOST_FOREACH(CNode* pnode, vNodesCopy)
  {
    if (pnode->hSocket == fd) {
      pnode->fDisconnect = true;
    }
  }

}

bool CNode::HasHeader(CBlockIndex *pindex)
{
	if (pindexRecvHeader && 
			pindex == pindexRecvHeader->GetAncestor(pindex->nHeight))
		return true;
	if (pindexRecv && 
			pindex == pindexRecv->GetAncestor(pindex->nHeight))
		return true;
	if (pindexBestHeaderSend && 
			pindex == pindexBestHeaderSend->GetAncestor(pindex->nHeight))
		return true;
	return false;
}
