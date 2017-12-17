
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


#ifndef __KEY__KEY_H__
#define __KEY__KEY_H__


#define RPC_AUTH_FREQ 300

int shcon_key_init(void);

void shcon_key_term(void);

/** Obtain a local-host RPC authorization key in hex. */ 
const char *key_auth_hex(shkey_t *auth_key);

/** Obtain a rotating PIN for RPC authorization. */
unsigned int key_auth_pin(shkey_t *auth_key);

/** Obtain an authorization token for a particular host. */
shkey_t *key_dat_pass(char *host);


#endif /* ndef __KEY__KEY_DAT_H__ */

