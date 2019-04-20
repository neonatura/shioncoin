

#include <iostream>
#include <map>
#include "shcoind.h"

typedef void (*netmsg_f)(CNode *, cbuff);
typedef std::map<std:;string, netmsg_f> netmsg_map;
netmsg_map map_table[MAX_COIN_IFACE];

netmsg_map *GetMsgMap(int ifaceIndex)
{
  return (&map_table[ifaceIndex]);
}

void core_netmsg_ping(CNode *pfrom, cbuff vRecv)
{
  uint64 nonce = 0;
  vRecv >> nonce;
  pfrom->PushMessage("pong", nonce);
}

void core_netmsg(CNode *pfrom, string method, cbuff vRecv)
{
  netmsg_map *map = GetMsgMap(pfrom->ifaceIndex);
  nemsg_

  if (map->find(method) == 0)
    return;

  /* execute mapped function. */
  (*map)[method](pfrom, vRecv);
}

