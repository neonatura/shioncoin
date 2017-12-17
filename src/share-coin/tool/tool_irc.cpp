

/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura
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

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2012 Litecoin Developers
// Copyright (c) 2013 usde Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "shcoind.h"
#include "irc.h"
#include "net.h"
#include "strlcpy.h"
#include "base58.h"
#include "protocol.h"

#include <boost/array.hpp>
#include <boost/foreach.hpp>

#ifndef WIN32
#include <arpa/inet.h>
#endif

using namespace std;
using namespace boost;

int nGotIRCAddresses = 0;

static CCriticalSection cs_mapLocalHost;

#pragma pack(push, 1)
struct ircaddr
{
    struct in_addr ip;
    short port;
};
#pragma pack(pop)

struct LocalServiceInfo {
    int nScore;
    int nPort;
};
static map<CNetAddr, LocalServiceInfo> mapLocalHost;


string EncodeAddress(const CService& addr)
{
    struct ircaddr tmp;
    if (addr.GetInAddr(&tmp.ip))
    {
        tmp.port = htons(addr.GetPort());

        vector<unsigned char> vch(UBEGIN(tmp), UEND(tmp));
        return string("u") + EncodeBase58Check(vch);
    }
    return "";
}

bool DecodeAddress(string str, CService& addr)
{
    vector<unsigned char> vch;
    if (!DecodeBase58Check(str.substr(1), vch))
        return false;

    struct ircaddr tmp;
    if (vch.size() != sizeof(tmp))
        return false;
    memcpy(&tmp, &vch[0], sizeof(tmp));

    addr = CService(tmp.ip, ntohs(tmp.port));
    return true;
}






static bool Send(unsigned int hSocket, const char* pszSend)
{
    if (strstr(pszSend, "PONG") != pszSend)
        printf("IRC SENDING: %s\n", pszSend);
    const char* psz = pszSend;
    const char* pszEnd = psz + strlen(psz);
    while (psz < pszEnd)
    {
        int ret = send(hSocket, psz, pszEnd - psz, MSG_NOSIGNAL);
        if (ret < 0)
            return false;
        psz += ret;
    }
    return true;
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
        int nErr = errno;
        if (nErr == EMSGSIZE || nErr == EINTR || nErr == EINPROGRESS || nErr == EMSGSIZE || nErr == EAGAIN)
          continue;
      }
      if (!strLine.empty())
        return true;
      if (nBytes == 0)
      {
        // socket closed
        printf("socket closed\n");
        return false;
      }
      else
      {
        // socket error
        int nErr = errno;
        printf("recv failed: %d\n", nErr);
        return false;
      }
    }
  }
}

bool RecvLineIRC(unsigned int hSocket, string& strLine)
{
    loop
    {
        bool fRet = RecvLine(hSocket, strLine);
        if (fRet)
        {
            if (fShutdown)
                return false;
            vector<string> vWords;
            ParseString(strLine, ' ', vWords);
            if (vWords.size() >= 1 && vWords[0] == "PING")
            {
                strLine[1] = 'O';
                strLine += '\r';
                Send(hSocket, strLine.c_str());
                continue;
            }
        }
        return fRet;
    }
}

int RecvUntil(unsigned int hSocket, const char* psz1, const char* psz2=NULL, const char* psz3=NULL, const char* psz4=NULL)
{
    loop
    {
        string strLine;
        strLine.reserve(10000);
        if (!RecvLineIRC(hSocket, strLine))
            return 0;
        printf("IRC %s\n", strLine.c_str());
        if (psz1 && strLine.find(psz1) != string::npos)
            return 1;
        if (psz2 && strLine.find(psz2) != string::npos)
            return 2;
        if (psz3 && strLine.find(psz3) != string::npos)
            return 3;
        if (psz4 && strLine.find(psz4) != string::npos)
            return 4;
    }
}

bool Wait(int nSeconds)
{
    if (fShutdown)
        return false;
    printf("IRC waiting %d seconds to reconnect\n", nSeconds);
    for (int i = 0; i < nSeconds; i++)
    {
        if (fShutdown)
            return false;
        sleep(1);//Sleep(1000);
    }
    return true;
}

bool RecvCodeLine(unsigned int hSocket, const char* psz1, string& strRet)
{
    strRet.clear();
    loop
    {
        string strLine;
        if (!RecvLineIRC(hSocket, strLine))
            return false;

        vector<string> vWords;
        ParseString(strLine, ' ', vWords);
        if (vWords.size() < 2)
            continue;

        if (vWords[1] == psz1)
        {
            printf("IRC %s\n", strLine.c_str());
            strRet = strLine;
            return true;
        }
    }
}

bool GetIPFromIRC(unsigned int hSocket, string strMyName, CNetAddr& ipRet)
{
    Send(hSocket, strprintf("USERHOST %s\r", strMyName.c_str()).c_str());

    string strLine;
    if (!RecvCodeLine(hSocket, "302", strLine))
        return false;

    vector<string> vWords;
    ParseString(strLine, ' ', vWords);
    if (vWords.size() < 4)
        return false;

    string str = vWords[3];
    if (str.rfind("@") == string::npos)
        return false;
    string strHost = str.substr(str.rfind("@")+1);

    // Hybrid IRC used by lfnet always returns IP when you userhost yourself,
    // but in case another IRC is ever used this should work.
    printf("GetIPFromIRC() got userhost %s\n", strHost.c_str());
    CNetAddr addr(strHost, true);
    if (!addr.IsValid())
        return false;
    ipRet = addr;

    return true;
}

bool AddLocal(CNetAddr& addr, int type)
{
  printf("Local Address: %s\n", addr.ToString().c_str());
  return true;
}

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
  CAddress ret(CService("0.0.0.0",0),0);
  CService addr;
  if (GetLocal(addr, paddrPeer))
  {
    ret = CAddress(addr);
    ret.nServices = 0;//nLocalServices;
    ret.nTime = GetAdjustedTime();
  }
  return ret;
}

void IRCDiscover(void)
{


  printf("IRC Discover started..\n");

  int nAttempts;

  CService addrConnect("irc.lfnet.org", 6667, true);

  unsigned int hSocket;
  if (!ConnectSocket(addrConnect, hSocket))
  {
    addrConnect = CService("pelican.heliacal.net", 6667, true);
    if (!ConnectSocket(addrConnect, hSocket))
    {
      printf("IRC connect failed\n");
      return;
    }
  } 

  if (!RecvUntil(hSocket, "Found your hostname", "using your IP address instead", "Couldn't look up your hostname", "ignoring hostname"))
  {
    closesocket(hSocket);
    hSocket = INVALID_SOCKET;
    return;
  }

  CNetAddr addrIPv4("1.2.3.4"); // arbitrary IPv4 address to make GetLocal prefer IPv4 addresses
  CService addrLocal;
  string strMyName;
  if (GetLocal(addrLocal, &addrIPv4))
    strMyName = EncodeAddress(GetLocalAddress(&addrConnect));
  if (strMyName == "")
    strMyName = strprintf("x%u", GetRand(1000000000));

  Send(hSocket, strprintf("NICK %s\r", strMyName.c_str()).c_str());
  Send(hSocket, strprintf("USER %s 8 * : %s\r", strMyName.c_str(), strMyName.c_str()).c_str());

  int nRet = RecvUntil(hSocket, " 004 ", " 433 ");
  if (nRet != 1)
  {
    closesocket(hSocket);
    hSocket = INVALID_SOCKET;
    if (nRet == 2)
    {
      printf("IRC name already in use\n");
    }
    return;
  }
  sleep(1);//Sleep(500);

  // Get our external IP from the IRC server and re-nick before joining the channel
  CNetAddr addrFromIRC;
  if (GetIPFromIRC(hSocket, strMyName, addrFromIRC))
  {
    printf("GetIPFromIRC() returned %s\n", addrFromIRC.ToString().c_str());
    if (addrFromIRC.IsRoutable())
    {
      // IRC lets you to re-nick
      AddLocal(addrFromIRC, LOCAL_IRC);
      strMyName = EncodeAddress(GetLocalAddress(&addrConnect));
      Send(hSocket, strprintf("NICK %s\r", strMyName.c_str()).c_str());
    }
  }

  if (fTestNet) {
    Send(hSocket, "JOIN #usdeTEST3\r");
    Send(hSocket, "WHO #usdeTEST3\r");
  } else {
    // randomly join #usde00-#usde99
    int channel_number = GetRandInt(100);
    channel_number = 0; // usde: for now, just use one channel
    Send(hSocket, strprintf("JOIN #usde%02d\r", channel_number).c_str());
    Send(hSocket, strprintf("WHO #usde%02d\r", channel_number).c_str());
  }

  int64 nStart = GetTime();
  string strLine;
  strLine.reserve(10000);
  for (nAttempts = 0; nAttempts < 100; nAttempts++) {
    if (!RecvLineIRC(hSocket, strLine))
      break;
    if (strLine.empty() || strLine.size() > 900 || strLine[0] != ':') {
      continue;
    }

    vector<string> vWords;
    ParseString(strLine, ' ', vWords);
    if (vWords.size() < 2) {
      continue;
    }

    char pszName[10000];
    pszName[0] = '\0';

    if (vWords[1] == "352" && vWords.size() >= 8)
    {
      // index 7 is limited to 16 characters
      // could get full length name at index 10, but would be different from join messages
      strlcpy(pszName, vWords[7].c_str(), sizeof(pszName));
      printf("IRC got who\n");
    }

    if (vWords[1] == "JOIN" && vWords[0].size() > 1)
    {
      // :username!username@50000007.F000000B.90000002.IP JOIN :#channelname
      strlcpy(pszName, vWords[0].c_str() + 1, sizeof(pszName));
      if (strchr(pszName, '!'))
        *strchr(pszName, '!') = '\0';
      printf("IRC got join\n");
    }

    if (pszName[0] == 'u')
    {
      CAddress addr;
      if (DecodeAddress(pszName, addr))
      {
        addr.nTime = GetAdjustedTime();
//        if (addrman.Add(addr, addrConnect, 51 * 60))
        printf("IRC got new address: %s\n", addr.ToString().c_str());

        nGotIRCAddresses++;
      }
      else
      {
        printf("IRC decode failed\n");
      }
    }
  }
  closesocket(hSocket);
  hSocket = INVALID_SOCKET;

}




