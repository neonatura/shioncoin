
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

#include "shcon.h"


#define DEFAULT_RPC_PORT 9447

static unsigned char _socket_buffer[65536];
#define SKBUF _socket_buffer

int net_conn(void)
{
  char hostname[MAXHOSTNAMELEN+1];
  int port;
  int err;

  memset(hostname, 0, sizeof(hostname));
  strncpy(hostname, opt_str(OPT_HOSTNAME), sizeof(hostname)-1);
  if (!*hostname)
    strcpy(hostname, "127.0.0.1");

  port = opt_num(OPT_PORT);
  if (port == 0)
    port = DEFAULT_RPC_PORT;

  err = shconnect_host(hostname, port, SHNET_ASYNC);
  if (err) {
    if (err == -1) err = -errno;
    return (err);
  }

  return (0);
}

void net_close(int sk)
{
  (void)shclose(sk);
}

