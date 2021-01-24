
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
 *  @file bond.h
 */

#ifndef __BITS__BOND_H__
#define __BITS__BOND_H__



int get_bond_state(tx_bond_t *bond);

void set_bond_state(tx_bond_t *bond, int state);

shkey_t *get_bond_key(shkey_t *sender, shkey_t *receiver, shkey_t *ref);

tx_bond_t *load_bond(shkey_t *bond_key);

tx_bond_t *load_bond_peer(shpeer_t *sender, shpeer_t *receiver, shpeer_t *ref);

tx_bond_t *create_bond(shkey_t *bond_key, double duration, double fee, double basis);

tx_bond_t *create_bond_peer(shpeer_t *receiver, shpeer_t *ref, double duration, double fee, double basis);

void save_bond(tx_bond_t *bond);

void free_bond(tx_bond_t **bond_p);

int confirm_bond_value(tx_bond_t *bond, double fee);

int complete_bond(tx_bond_t *bond); 


int txop_bond_init(shpeer_t *cli_peer, tx_bond_t *bond);
int txop_bond_confirm(shpeer_t *cli_peer, tx_bond_t *bond);
int txop_bond_recv(shpeer_t *cli_peer, tx_bond_t *bond);
int txop_bond_send(shpeer_t *cli_peer, tx_bond_t *bond);


#endif /* ndef __BITS__BOND_H__ */

