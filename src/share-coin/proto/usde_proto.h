

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

#ifndef __USDE_PROTO_H__
#define __USDE_PROTO_H__

#define USDE_VERSION_MAJOR       1
#define USDE_VERSION_MINOR       0
#define USDE_VERSION_REVISION    4
#define USDE_VERSION_BUILD       0

#define USDE_COIN_DAEMON_PORT 54449

#define USDE_MAX_GETADDR 500

#define USDE_MAX_ORPHAN_TRANSACTIONS 10000

#define USDE_MAX_SIGOPS 20000

static const int USDE_PROTOCOL_VERSION = 1000400;

#define USDE_COIN (uint64_t)100000000

#define USDE_MAX_BLOCK_SIZE 1000000

#define USDE_MAX_BLOCK_SIZE_GEN USDE_MAX_BLOCK_SIZE/2
#define USDE_MAX_TRANSACTION_WEIGHT USDE_MAX_BLOCK_SIZE_GEN/5

#define USDE_MAX_STANDARD_TX_WEIGHT 100000

#define USDE_MAX_STANDARD_TX_SIGOP_COST 16000

/** Largest byte size permitted for potential no-fee transaction. */
#define USDE_MAX_FREE_TX_SIZE 10000

static const int64 USDE_MIN_INPUT = 10000;
static const int64 USDE_MIN_TX_FEE = 10000000;
//static const int64 USDE_MIN_RELAY_TX_FEE = 10000000;
static const int64 USDE_MAX_MONEY = 1600000000 * USDE_COIN;

/** The official USDE maturity is 100 depth. */
static const int USDE_COINBASE_MATURITY = 100;

static const int64 USDE_MAX_TX_FEE = 1000 * SHC_COIN;

/* scaling factor */
static const int USDE_WITNESS_SCALE_FACTOR = SCALE_FACTOR;


#endif /* __USDE_PROTO_H__ */



