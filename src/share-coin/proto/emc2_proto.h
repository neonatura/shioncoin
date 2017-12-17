

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

#ifndef __EMC2_PROTO_H__
#define __EMC2_PROTO_H__

#define EMC2_VERSION_MAJOR       0
#define EMC2_VERSION_MINOR       13
#define EMC2_VERSION_REVISION    48
#define EMC2_VERSION_BUILD       0

#define EMC2_COIN_DAEMON_PORT 41878

#define EMC2_MAX_GETADDR 500

#define EMC2_MAX_ORPHAN_TRANSACTIONS 10000

#define EMC2_MAX_TRANSACTION_WEIGHT 400000

#define EMC2_MAX_SIGOPS 20000
//#define EMC2_MAX_SIGOPS 80000 /* consensus.h, 07.20.17 */

/** The maximum allowed drift time (past/future) for accepting new blocks. */
#define EMC2_MAX_DRIFT_TIME 900 /* 15 minutes */ 

static const int EMC2_PROTOCOL_VERSION = 70015;

#define EMC2_COIN (uint64_t)100000000

/** The maximum allowed size for a block excluding witness data, in bytes (network rule) */
#define EMC2_MAX_BLOCK_SIZE 1000000

#define EMC2_DEFAULT_BYTES_PER_SIGOP 20

#define EMC2_MAX_STANDARD_TX_WEIGHT 400000
#define EMC2_MAX_STANDARD_TX_SIGOP_COST 16000

/** Largest byte size permitted for potential no-fee transaction. */
#define EMC2_MAX_FREE_TX_SIZE 1000


/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int EMC2_MAX_BLOCK_SERIALIZED_SIZE = 4000000;

/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int EMC2_MAX_BLOCK_WEIGHT = 4000000;


static const int64 EMC2_MIN_INPUT = 100000;
static const int64 EMC2_MIN_TX_FEE = 100000;
//static const int64 EMC2_MIN_RELAY_TX_FEE = 100000;

static const int64 EMC2_MAX_TX_FEE = 0.1 * EMC2_COIN;

//static const int64 EMC2_MAX_MONEY = 299792458 * EMC2_COIN; < v0.13.3.0 
static const int64 EMC2_MAX_MONEY = 298937393 * EMC2_COIN;

/** The official EMC2 maturity is 40 depth. */
static const int EMC2_COINBASE_MATURITY = 100;

/* scaling factor */
static const int EMC2_WITNESS_SCALE_FACTOR = SCALE_FACTOR;



#endif /* __EMC2_PROTO_H__ */



