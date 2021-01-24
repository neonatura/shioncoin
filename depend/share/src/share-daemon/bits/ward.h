

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
 *  @file ward.h
 */

#ifndef __BITS__WARD_H__
#define __BITS__WARD_H__



/**
 * A trusted client is requesting a ward on a transaction be created.
 */
int inittx_ward(tx_ward_t *ward, tx_t *tx, tx_ref_t *ctx);

tx_ward_t *alloc_ward(tx_t *tx, tx_ref_t *ref);


int txop_ward_init(shpeer_t *cli_peer, tx_ward_t *ward);

int txop_ward_confirm(shpeer_t *peer, tx_ward_t *ward);

int txop_ward_send(shpeer_t *peer, tx_ward_t *ward);

int txop_ward_recv(shpeer_t *peer, tx_ward_t *ward);



#endif /* ndef __BITS__WARD_H__ */

