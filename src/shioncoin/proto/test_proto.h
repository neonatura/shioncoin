
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
 *
 *  This file is part of Shioncoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */

#ifndef __TEST_PROTO_H__
#define __TEST_PROTO_H__

#define TEST_VERSION_MAJOR 4
#define TEST_VERSION_MINOR 1
#define TEST_VERSION_REVISION 0
#define TEST_VERSION_BUILD 2

#define TEST_COIN_DAEMON_PORT 0

#define TEST_MAX_GETADDR 2500

#define TEST_MAX_ORPHAN_TRANSACTIONS 10000

#define TEST_MAX_SIGOPS 32768

#define TEST_MAX_SCRIPT_SIZE 60624

#define TEST_MAX_SCRIPT_ELEMENT_SIZE 3368

/** The maximum allowed drift time (past/future) for accepting new blocks. */
#define TEST_MAX_DRIFT_TIME 1440 /* 24 minutes */ 

static const int TEST_PROTOCOL_VERSION = 1000000;

#define TEST_COIN (uint64_t)100000000

#define TEST_MAX_BLOCK_SIZE 1024000 /* 1m */

#define TEST_MAX_TRANSACTION_WEIGHT 820000 /* 205k */

#define TEST_MAX_STANDARD_TX_WEIGHT 410000

#define TEST_MAX_STANDARD_TX_SIGOP_COST 16000

#define TEST_DEFAULT_BYTES_PER_SIGOP 20

/*minimum tx size of free transactions. */
#define TEST_MAX_FREE_TX_SIZE 512


static const int64 TEST_MIN_INPUT = 1;
static const int64 TEST_MIN_TX_FEE = 10000;
static const int64 TEST_MIN_RELAY_TX_FEE = 1000;
static const int64 TEST_MAX_MONEY = 1600000000 * TEST_COIN;
//static const int TEST_COINBASE_MATURITY = 100;
static const int TEST_COINBASE_MATURITY = 10;

static const int64 TEST_MAX_TX_FEE = 1000 * SHC_COIN;

/* scaling factor */
static const int TEST_WITNESS_SCALE_FACTOR = SCALE_FACTOR;

#endif /* __TEST_PROTO_H__ */



