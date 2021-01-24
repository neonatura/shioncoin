

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
 *  @file account.h
 */

#ifndef __BITS__ACCOUNT_H__
#define __BITS__ACCOUNT_H__


/**
 * The default account associated with this server.
 */
tx_account_t *sharedaemon_account(void);

/**
 * Obtain and verify a pre-existing account or generate a new account if one is not referenced.
 * @see shpam_pass_gen()
 */
tx_account_t *alloc_account(uint64_t uid);

int inittx_account(tx_account_t *acc, uint64_t uid);


tx_account_t *alloc_account_user(char *username, char *passphrase, uint64_t salt);

int txop_account_init(shpeer_t *cli_peer, tx_account_t *acc);
int txop_account_confirm(shpeer_t *cli_peer, tx_account_t *acc);
int txop_account_send(shpeer_t *cli_peer, tx_account_t *acc);
int txop_account_recv(shpeer_t *cli_peer, tx_account_t *acc);

int txop_account_wrap(shpeer_t *peer, tx_account_t *acc);


#endif /* ndef __BITS__ACCOUNT_H__ */

