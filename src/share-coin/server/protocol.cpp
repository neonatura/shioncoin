
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
#include "main.h"
#include "protocol.h"
#include "util.h"
#include "netbase.h"
#include "coin_proto.h"

#ifndef WIN32
# include <arpa/inet.h>
#endif


static const char* ppszTypeName[] =
{
    "ERROR",
    "tx",
    "block",
    "filtered block",
    "compact block",
    "witness block",
    "witness tx",
    "filtered witness block",
};

CMessageHeader::CMessageHeader()
{
  memset(pchMessageStart, '\000', sizeof(pchMessageStart));
  memset(pchCommand, 0, sizeof(pchCommand));
  pchCommand[1] = 1;
  nMessageSize = -1;
  nChecksum = 0;
}

CMessageHeader::CMessageHeader(int ifaceIndexIn, const char* pszCommand, unsigned int nMessageSizeIn)
{
  ifaceIndex = ifaceIndexIn;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (iface) {
    memcpy(pchMessageStart, iface->hdr_magic, sizeof(pchMessageStart));
  } else {
    memset(pchMessageStart, '\000', sizeof(pchMessageStart));
  }
  strncpy(pchCommand, pszCommand, COMMAND_SIZE);
  nMessageSize = nMessageSizeIn;
  nChecksum = 0;
}

std::string CMessageHeader::GetCommand() const
{
    if (pchCommand[COMMAND_SIZE-1] == 0)
        return std::string(pchCommand, pchCommand + strlen(pchCommand));
    else
        return std::string(pchCommand, pchCommand + COMMAND_SIZE);
}

bool CMessageHeader::IsValid() const
{

  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface) {
    return (error(SHERR_INVAL, "CMessageHeader.IsValid: no coin interface (#%d).", ifaceIndex));
  }

  if (0 != memcmp(pchMessageStart, iface->hdr_magic, sizeof(pchMessageStart))) {
    return (error(SHERR_ILSEQ, "CMessageHeader.IsValid[%s]: no pchMessageStart prefix", iface->name));
  }

  for (const char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++)
  {
    if (*p1 == 0)
    {
      /* null bytes after trailing string terminator */
      for (; p1 < pchCommand + COMMAND_SIZE; p1++) {
        if (*p1 != 0) {
          return (error(SHERR_INVAL, "CMessageHeader::IsValid: no trailing zeros."));
        }
      }
    }
    else if (*p1 < ' ' || *p1 > 0x7E) {
      return false;
    }
  }

  /* ensure message is smaller than maximum encapsulation size. */
  if (nMessageSize > MAX_SIZE) {
    return (error(SHERR_INVAL, "CMessageHeader::IsValid() : (%s, %u bytes) nMessageSize > MAX_SIZE\n", GetCommand().c_str(), nMessageSize));
  }

  return (true); /* all good */
}



CInv::CInv()
{
  ifaceIndex = -1;
  type = 0;
  hash = 0;
}

CInv::CInv(int ifaceIndexIn, int typeIn, const uint256& hashIn)
{
  ifaceIndex = ifaceIndexIn;
  type = typeIn;
  hash = hashIn;
}

CInv::CInv(int ifaceIndexIn, const std::string& strType, const uint256& hashIn)
{
  ifaceIndex = ifaceIndexIn;

  unsigned int i;
  for (i = 1; i < ARRAYLEN(ppszTypeName); i++)
  {
    if (strType == ppszTypeName[i])
    {
      type = i;
      break;
    }
  }
  if (i == ARRAYLEN(ppszTypeName))
    throw std::out_of_range(strprintf("CInv::CInv(string, uint256) : unknown type '%s'", strType.c_str()));
  hash = hashIn;
}

bool operator<(const CInv& a, const CInv& b)
{
    return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
}

bool CInv::IsKnownType() const
{
  int masked = type & MSG_TYPE_MASK;
//    return (type >= 1 && type < (int)ARRAYLEN(ppszTypeName));
  return (
      masked == MSG_TX ||
      masked == MSG_BLOCK ||
      masked == MSG_FILTERED_BLOCK ||
      masked == MSG_CMPCT_BLOCK
      );
}

std::string CInv::GetCommand() const
{

  int masked = type & MSG_TYPE_MASK;
  string cmd;

  if (type & MSG_WITNESS_FLAG)
    cmd.append("witness-");

  switch (masked)
  {
    case MSG_TX:             cmd.append("tx"); break;
    case MSG_BLOCK:          cmd.append("block"); break;
    case MSG_FILTERED_BLOCK: cmd.append("merkleblock"); break;
    case MSG_CMPCT_BLOCK:    cmd.append("cmpctblock"); break;
    default:                 cmd.append("unknown"); break;
  }    

  return (cmd);

#if 0
    if (!IsKnownType())
        throw std::out_of_range(strprintf("CInv::GetCommand() : type=%d unknown type", type));
    return ppszTypeName[type];
#endif
}

std::string CInv::ToString() const
{
  return (hash.ToString());
}

void CInv::print() const
{
    printf("CInv(%s)\n", ToString().c_str());
}

