

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

#ifndef __COLOR_PROTO_H__
#define __COLOR_PROTO_H__


#define COLOR_VERSION_MAJOR 3
#define COLOR_VERSION_MINOR 2
#define COLOR_VERSION_REVISION 0
#define COLOR_VERSION_BUILD 0

/** The default socket port for the COLOR coin service (none). */
#define COLOR_COIN_DAEMON_PORT 0

/** The maximum number of peer network addresses to relay at once to a remote coin service. */
#define COLOR_MAX_GETADDR 500

#define COLOR_MAX_ORPHAN_TRANSACTIONS 4096


/**
 * The maximum number of signature "script" operations in a single block.
 */
#define COLOR_MAX_SIGOPS 4096

/** The maximum allowed drift time (past/future) for accepting new blocks. */
#define COLOR_MAX_DRIFT_TIME 2880 /* 48 minutes */ 

/**
 * The network protocol version used to communicate between COLOR services.
 */
static const int COLOR_PROTOCOL_VERSION = 2000000;

/**
 * Defines how many "satashi" constitutes a single coin.
 */
#define COLOR_COIN (uint64_t)100000000

/**
 * The maximum byte size permitted for a single block.
 */
#define COLOR_MAX_BLOCK_SIZE 512000

#define COLOR_MAX_BLOCK_SIZE_GEN COLOR_MAX_BLOCK_SIZE/2
#define COLOR_MAX_TRANSACTION_WEIGHT COLOR_MAX_BLOCK_SIZE_GEN/5

#define COLOR_MAX_STANDARD_TX_WEIGHT 200000

#define COLOR_MAX_STANDARD_TX_SIGOP_COST 2000

#define COLOR_DEFAULT_BYTES_PER_SIGOP 20

/** Largest byte size permitted for potential no-fee transaction. */
#define COLOR_MAX_FREE_TX_SIZE 512

/**
 * The minimum "satashi" permitted to be sent in a single transaction.
 */
static const int64 COLOR_MIN_INPUT = 100;

/**
 * Transaction fee applied to every 1k of size.
 */
static const int64 COLOR_MIN_TX_FEE = 1000;

/**
 * The minimum block transaction fee applied.
 */
static const int64 COLOR_MIN_RELAY_TX_FEE = 1000;

/** The maximum number of coins that will be generated during the life-time of the currency. */
static const int64 COLOR_MAX_MONEY = 722388 * COLOR_COIN; /* ~ 0.7mil max @ height 1.44mil */

/** The number of blocks generated before a "block reward" is considered spendable. */
static const int COLOR_COINBASE_MATURITY = 90;

static const int64 COLOR_MAX_TX_FEE = 1000 * COLOR_COIN;

/* scaling factor */
static const int COLOR_WITNESS_SCALE_FACTOR = SCALE_FACTOR;

#endif /* __COLOR_PROTO_H__ */



