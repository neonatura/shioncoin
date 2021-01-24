
/*
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
 */  

#ifndef __BITS__SESSION_H__
#define __BITS__SESSION_H__



int inittx_session(tx_session_t *sess, uint64_t uid, shkey_t *id_key, shtime_t stamp);

tx_session_t *alloc_session(uint64_t uid, shkey_t *id_key, shtime_t stamp);

tx_session_t *alloc_session_peer(uint64_t uid, shpeer_t *peer);

int txop_session_init(shpeer_t *cli_peer, tx_session_t *sess);

int txop_session_confirm(shpeer_t *cli_peer, tx_session_t *sess);

int txop_session_send(shpeer_t *cli_peer, tx_session_t *sess);

int txop_session_recv(shpeer_t *cli_peer, tx_session_t *sess);


#endif /* ndef __BITS__SESSION_H__ */


