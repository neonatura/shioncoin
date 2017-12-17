
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

#ifndef __SHCOIND_H__
#define __SHCOIND_H__

#include "config.h"

#ifndef NEED_W32_SOCKETS
#ifdef __USE_W32_SOCKETS
#undef __USE_W32_SOCKETS
#endif
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/select.h>
#include <share.h>

/**
 *  The share coin daemon combines a virtual currency daemon with a built-in stratum server. The stratum server provides extended operations for managing accounts and reviewing worker status. 
 *  @brief Share Coin Daemon
 *  @defgroup sharecoin
 *  @{
 */


/**
 * The share coin daemon's 'peer' reference.
 */
extern shpeer_t *server_peer;
/**
 * The message queue id for communicating with the share daemon.
 */
extern int server_msgq;
/**
 * A message queue buffer for pooling incoming messages from the share daemon.
 */ 
extern shbuf_t *server_msg_buff;

/* blockchain database */
#include "blockchain/bc.h"

/* shcoind network engine */
#include "unet/unet.h"

#include "proto.h"
#include "server_iface.h"
#include "shcoind_version.h"
#include "shcoind_signal.h"
#include "shcoind_opt.h"
#include "shcoind_log.h"
#include "shcoind_block.h"
#include "shcoind_rpc.h"
#include "shcoind_descriptor.h"

#include "proto/coin_proto.h"
#include "proto/shc_proto.h"
#include "proto/usde_proto.h"
#include "proto/emc2_proto.h"
#include "proto/test_proto.h"

//#include "stratum/stratum.h"
#include "shcoind_daemon.h"

#ifdef __cplusplus

/* standard c++ runtime */
#include <cstdio>
#include <cassert>
#include <limits>
#include <string>
#include <cstring>
#include <vector>
#include <set>
#include <list>
#include <map>
#include <db_cxx.h>
#include <stdarg.h>


/* boost c++ runtime */
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <boost/type_traits/is_fundamental.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/tuple/tuple_io.hpp>
#include <boost/thread.hpp>
#define BOOST_NO_CXX11_SCOPED_ENUMS
#include <boost/filesystem.hpp>
#undef BOOST_NO_CXX11_SCOPED_ENUMS


/* common typedefs */
typedef std::vector<unsigned char> cbuff;
typedef std::vector<cbuff> cstack_t;
typedef long long int64;
typedef unsigned long long uint64;

#endif

#include "server/server.h"

/**
 * @}
 */




/**
 * @mainpage Share Coin Daemon
 *
 * <h3>The Share Coin Daemon API reference manual.</h3>
 *
 * This project supplies the "shcoin" and "shcoind" programs.
 *
 * The "shcoind" program provides a fully-functional USDe currency service with a built-in stratum server.
 *
 * The "shcoin" utility program uses a SSL RPC connection to "shcoind" in order to perform administrative tasks.
 * <small>Note: The "shcoin" program must be ran as the same user as the "shcoind" daemon.</small>
 *
 * Note: Running additional programs from the share library suite is optional in order to run the coin+stratum service. The C share library is staticly linked against the coin service, and a 'make install' is not required to run the built programs.
 *
 */

#endif /* ndef __SHCOIND_H__ */


