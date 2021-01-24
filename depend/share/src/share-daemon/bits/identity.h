
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
 *  @file identity.h
 */

#ifndef __BITS__IDENTITY_H__
#define __BITS__IDENTITY_H__


int txop_ident_init(shpeer_t *cli_peer, tx_id_t *id);

int txop_ident_confirm(shpeer_t *cli_peer, tx_id_t *id, tx_id_t *ent);

int txop_ident_send(shpeer_t *cli_peer, tx_id_t *id, tx_id_t *ent);

int txop_ident_recv(shpeer_t *cli_peer, tx_id_t *id);


tx_id_t *alloc_ident(uint64_t uid, shpeer_t *app_peer);

int inittx_ident(tx_id_t *id, uint64_t uid, shpeer_t *app_peer);



#endif /* ndef __BITS__IDENTITY_H__ */
