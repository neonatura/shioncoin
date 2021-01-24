
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
 *  @file init.h
 */

#ifndef __BITS__SUBSCRIBE_H__
#define __BITS__SUBSCRIBE_H__



int txop_sub_init(shpeer_t *cli_peer, tx_subscribe_t *sub);

int txop_sub_confirm(shpeer_t *cli_peer, tx_subscribe_t *sub);

int txop_sub_recv(shpeer_t *cli_peer, tx_subscribe_t *sub);

int txop_sub_send(shpeer_t *cli_peer, tx_subscribe_t *sub);

int txop_sub_wrap(shpeer_t *cli_peer, tx_subscribe_t *sub);


int inittx_subscribe(tx_subscribe_t *sub, shkey_t *key, int op_type, int flags);

tx_subscribe_t *alloc_subscribe(shkey_t *key, int op_type, int flags);



#endif /* ndef __BITS__SUBSCRIBE_H__ */

