

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

#ifndef __TEST_PROTO_H__
#define __TEST_PROTO_H__

#define TEST_VERSION_MAJOR       0 
#define TEST_VERSION_MINOR       13
#define TEST_VERSION_REVISION    3
#define TEST_VERSION_BUILD       0

#define TEST_COIN_DAEMON_PORT 0

#define TEST_MAX_GETADDR 2500

#define TEST_MAX_ORPHAN_TRANSACTIONS 10000

#define TEST_MAX_SIGOPS 32768

/** The maximum allowed drift time (past/future) for accepting new blocks. */
#define TEST_MAX_DRIFT_TIME 1440 /* 24 minutes */ 

static const int TEST_PROTOCOL_VERSION = 1000000;

#define TEST_COIN (uint64_t)100000000

#define TEST_MAX_BLOCK_SIZE 1000000

#define TEST_MAX_BLOCK_SIZE_GEN TEST_MAX_BLOCK_SIZE/2
#define TEST_MAX_TRANSACTION_WEIGHT TEST_MAX_BLOCK_SIZE_GEN/5

#define TEST_MAX_STANDARD_TX_WEIGHT 400000

#define TEST_MAX_STANDARD_TX_SIGOP_COST 16000

#define TEST_DEFAULT_BYTES_PER_SIGOP 20

/** Largest byte size permitted for potential no-fee transaction. */
#define TEST_MAX_FREE_TX_SIZE 10000

static const int64 TEST_MIN_INPUT = 100;
static const int64 TEST_MIN_TX_FEE = 10000;
//static const int64 TEST_MIN_RELAY_TX_FEE = 10000;
static const int64 TEST_MAX_MONEY = 1600000000 * TEST_COIN;
//static const int TEST_COINBASE_MATURITY = 100;
static const int TEST_COINBASE_MATURITY = 10;

static const int64 TEST_MAX_TX_FEE = 1000 * SHC_COIN;

/* scaling factor */
static const int TEST_WITNESS_SCALE_FACTOR = SCALE_FACTOR;

#endif /* __TEST_PROTO_H__ */



