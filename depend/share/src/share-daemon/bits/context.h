
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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
 *  @file context.h
 */

#ifndef __BITS__CONTEXT_H__
#define __BITS__CONTEXT_H__


/** Allocate a transaction pertaining to a pre-existing context. */
tx_context_t *alloc_context(shkey_t *name_key);

/** Initialize a transaction pertaining to a pre-existing context. */
int inittx_context(tx_context_t *tx, shkey_t *name_key);

/** Allocate a transaction referencing new context data. */
tx_context_t *alloc_context_data(char *name, void *data, size_t data_len);

/** Initialize a transaction referencing new context data. */
int inittx_context_data(tx_context_t *tx, char *name, unsigned char *data, size_t data_len);


int txop_context_init(shpeer_t *cli_peer, tx_context_t *ctx);

int txop_context_confirm(shpeer_t *cli_peer, tx_context_t *ctx);

int txop_context_recv(shpeer_t *cli_peer, tx_context_t *ctx);

int txop_context_send(shpeer_t *cli_peer, tx_context_t *ctx);

int txop_context_wrap(shpeer_t *cli_peer, tx_context_t *ctx);


#endif /* ndef __BITS__CONTEXT_H__ */

