
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
 */

#ifndef __BITS__WALLET_H__
#define __BITS__WALLET_H__



int inittx_wallet_channel(tx_wallet_t *wal, shkey_t *origin, shkey_t *peer, shkey_t *redeem);

int txop_wallet_init(shpeer_t *cli_peer, tx_wallet_t *wallet);

int txop_wallet_confirm(shpeer_t *peer, tx_wallet_t *wallet);

int txop_wallet_send(shpeer_t *peer, tx_wallet_t *wallet);

int txop_wallet_recv(shpeer_t *peer, tx_wallet_t *wallet);

int txop_wallet_wrap(shpeer_t *cli_peer, tx_wallet_t *wal);



#endif /* ndef __BITS__WALLET_H__ */

