

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

#ifndef __SHC_PROTO_H__
#define __SHC_PROTO_H__


#define SHC_VERSION_MAJOR  2 
#define SHC_VERSION_MINOR  29
#define SHC_VERSION_REVISION 0
#define SHC_VERSION_BUILD 0

/** The default socket port for the SHC coin service. */
#define SHC_COIN_DAEMON_PORT 24104

/** The maximum number of peer network addresses to relay at once to a remote coin service. */
#define SHC_MAX_GETADDR 500

#define SHC_MAX_ORPHAN_TRANSACTIONS 4096


/**
 * The maximum number of signature "script" operations in a single block.
 */
#define SHC_MAX_SIGOPS 32768

/** The maximum allowed drift time (past/future) for accepting new blocks. */
#define SHC_MAX_DRIFT_TIME 1440 /* 24 minutes */ 

/**
 * The network protocol version used to communicate between SHC services.
 */
static const int SHC_PROTOCOL_VERSION = 2000000;

/**
 * Defines how many "satashi" constitutes a single coin.
 */
#define SHC_COIN (uint64_t)100000000

/**
 * The maximum byte size permitted for a single block.
 */
#define SHC_MAX_BLOCK_SIZE 4096000

#define SHC_MAX_BLOCK_SIZE_GEN SHC_MAX_BLOCK_SIZE/2
#define SHC_MAX_TRANSACTION_WEIGHT SHC_MAX_BLOCK_SIZE_GEN/5

#define SHC_MAX_STANDARD_TX_WEIGHT 1600000

#define SHC_MAX_STANDARD_TX_SIGOP_COST 16000

#define SHC_DEFAULT_BYTES_PER_SIGOP 20

/** Largest byte size permitted for potential no-fee transaction. */
#define SHC_MAX_FREE_TX_SIZE 10000


/**
 * The minimum "satashi" permitted to be sent in a single transaction.
 */
static const int64 SHC_MIN_INPUT = 100;

/**
 * The minimum block transaction fee applied.
 */
static const int64 SHC_MIN_TX_FEE = 10000;
//static const int64 SHC_MIN_RELAY_TX_FEE = 10000;

/** The maximum number of coins that will be generated during the life-time of the currency. */
static const int64 SHC_MAX_MONEY = 1000000000 * SHC_COIN; /* 1bil max */

/** The number of blocks generated before a "block reward" is considered spendable. */
static const int SHC_COINBASE_MATURITY = 60;

static const int64 SHC_MAX_TX_FEE = 1000 * SHC_COIN;

/* scaling factor */
static const int SHC_WITNESS_SCALE_FACTOR = SCALE_FACTOR;

#endif /* __SHC_PROTO_H__ */



