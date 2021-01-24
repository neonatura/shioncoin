
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura 
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
 *
 *  @file transaction.h
 */

#ifndef __BITS__TRANSACTION_H__
#define __BITS__TRANSACTION_H__


#define TXHASH_SCRYPT 1
#define TXHASH_FCRYPT 2


/**
 * Generate a new transaction.
 */
int generate_transaction_id(int tx_op, tx_t *tx, char *hash);

/**
 * Determines if the local node has access to process the transaction based on the originating entity.
 * @param id The identity associated with the transaction.
 * @param tx The transaction to process.
 * @returns TRUE if transaction is accessible or FALSE if prohibited.
 */
int has_tx_access(tx_id_t *id, tx_t *tx);

int prep_net_tx(tx_t *tx, tx_net_t *net, shkey_t *sink, size_t size);

#endif /* ndef __BITS__TRANSACTION_H__ */

