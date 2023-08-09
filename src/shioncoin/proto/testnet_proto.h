
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

#ifndef __TESTNET_PROTO_H__
#define __TESTNET_PROTO_H__


#define TESTNET_VERSION_MAJOR 6
#define TESTNET_VERSION_MINOR 5
#define TESTNET_VERSION_REVISION 0 
#define TESTNET_VERSION_BUILD 0

/** The default socket port for the TESTNET coin service. */
#define TESTNET_COIN_DAEMON_PORT 26104

/** The maximum number of peer network addresses to relay at once to a remote coin service. */
#define TESTNET_MAX_GETADDR 500

#define TESTNET_MAX_ORPHAN_TRANSACTIONS 4096


/**
 * The maximum number of signature "script" operations in a single block.
 */
#define TESTNET_MAX_SIGOPS 32768

#define TESTNET_MAX_SCRIPT_SIZE 60624

#define TESTNET_MAX_SCRIPT_ELEMENT_SIZE 3368

/** The maximum allowed drift time (past/future) for accepting new blocks. */
#define TESTNET_MAX_DRIFT_TIME 1440 /* 24 minutes */ 

/**
 * The network protocol version used to communicate between TESTNET services.
 */
static const int TESTNET_PROTOCOL_VERSION = 2000000;

/**
 * Defines how many "satashi" constitutes a single coin.
 */
#define TESTNET_COIN (uint64_t)100000000

/**
 * The maximum byte size permitted for a single block.
 */
#define TESTNET_MAX_BLOCK_SIZE 4096000

#define TESTNET_MAX_TRANSACTION_WEIGHT 3280000

#define TESTNET_MAX_STANDARD_TX_WEIGHT 1600000

#define TESTNET_MAX_STANDARD_TX_SIGOP_COST 16000

#define TESTNET_DEFAULT_BYTES_PER_SIGOP 20

/* minimum tx size of free transactions. */
#define TESTNET_MAX_FREE_TX_SIZE 512



/**
 * The minimum "satashi" permitted to be sent in a single transaction.
 */
static const int64 TESTNET_MIN_INPUT = 1;

/**
 * The transaction fee per 1k of block content.
 */
static const int64 TESTNET_MIN_TX_FEE = 10000;

/**
 * The minimum block transaction fee applied (0.00001000).
 */
static const int64 TESTNET_MIN_RELAY_TX_FEE = 1000;

/** The maximum number of coins that will be generated during the life-time of the currency. */
static const int64 TESTNET_MAX_MONEY = 1000000000 * TESTNET_COIN; /* 1bil max */

/** The number of blocks generated before a "block reward" is considered spendable. */
static const int TESTNET_COINBASE_MATURITY = 32;

static const int64 TESTNET_MAX_TX_FEE = 1000 * TESTNET_COIN;

/* scaling factor */
static const int TESTNET_WITNESS_SCALE_FACTOR = SCALE_FACTOR;

#endif /* __TESTNET_PROTO_H__ */



