
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
 *
 *  This file is part of ShionCoin.
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

#ifndef __LTC_PROTO_H__
#define __LTC_PROTO_H__


#define LTC_VERSION_MAJOR       0
#define LTC_VERSION_MINOR       15
#define LTC_VERSION_REVISION    1
#define LTC_VERSION_BUILD       0

#define LTC_COIN_DAEMON_PORT 9333

#define LTC_MAX_GETADDR 500

#define LTC_MAX_ORPHAN_TRANSACTIONS 10000

#define LTC_MAX_SIGOPS 20000

#define LTC_MAX_DRIFT_TIME 7200 /* 2 hours */

static const int LTC_PROTOCOL_VERSION = 70015;

#define LTC_COIN (uint64_t)100000000

#define LTC_MAX_BLOCK_SIZE 1000000

#define LTC_MAX_BLOCK_SIZE_GEN LTC_MAX_BLOCK_SIZE/2
#define LTC_MAX_TRANSACTION_WEIGHT LTC_MAX_BLOCK_SIZE_GEN/5

#define LTC_MAX_STANDARD_TX_WEIGHT 100000

#define LTC_MAX_STANDARD_TX_SIGOP_COST 16000

#define LTC_DEFAULT_BYTES_PER_SIGOP 20

/* Disallow all free transactions. */
#define LTC_MAX_FREE_TX_SIZE 0

static const int64 LTC_MIN_INPUT = 294;
static const int64 LTC_MIN_TX_FEE = 10000;
static const int64 LTC_MIN_RELAY_TX_FEE = 1000;
static const int64 LTC_MAX_MONEY = 84000000 * LTC_COIN;

/** The official LTC maturity is 100 depth. */
static const int LTC_COINBASE_MATURITY = 100;

static const int64 LTC_MAX_TX_FEE = 1000 * SHC_COIN;

/* scaling factor */
static const int LTC_WITNESS_SCALE_FACTOR = SCALE_FACTOR;


#endif /* __LTC_PROTO_H__ */



