
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
#include "net.h"
#include "db.h"
#include "addrman.h"
#include "shcoind_rpc.h"
#include <share.h>
#include "proto/coin_proto.h"

#ifndef WIN32
#include <signal.h>
#endif


using namespace std;
using namespace boost;

shtime_t server_start_t;

extern void IRCDiscover(void);
extern void PrintPeers(void);
//extern void ListPeers(void);

void shcoind_tool_version(char *prog_name)
{
  fprintf(stdout,
      "%s version %s\n"
      "\n"
      "Copyright 2013 Neo Natura\n" 
      "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n"
      "This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n",
      prog_name,
      get_libshare_version());
}

void shcoind_tool_usage(char *prog_name)
{
  fprintf(stdout,
      "Usage: %s [COMMAND] [PARAMS]\n"
      "Perform RPC operations on the share-coin daemon.\n"
      "\n"
      "Commands:\n"
      "\tUse the \"help\" command in order to list all available RPC operations.\n"
      "\n"
      "Visit 'http://docs.sharelib.net/' for libshare API documentation."
      "Report bugs to <support@neo-natura.com>.\n",
      prog_name
      );
}


int main(int argc, char *argv[])
{
  char username[256];
  char password[256];
  int ret;
  int i;

  server_start_t = shtime();

  /* load rpc credentials */
  get_rpc_cred(username, password);
  string strUser(username);
  string strPass(username);
  mapArgs["-rpcuser"] = strUser;
  mapArgs["-rpcpassword"] = strPass; 

  for (i = 1; i < argc; i++) {
    if (0 == strcmp(argv[i], "-h") ||
        0 == strcmp(argv[i], "--help")) {
      shcoind_tool_usage(argv[0]);
      return (0);
    }
    if (0 == strcmp(argv[i], "-v") ||
        0 == strcmp(argv[i], "--version")) {
      shcoind_tool_version(argv[0]);
      return (0);
    }
  }

  opt_init();

  /* perform rpc operation */
  ret = CommandLineRPC(argc, argv);

  return (ret);
}



