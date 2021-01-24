

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
 *  @file vm.h
 */

#ifndef __BITS__VM_H__
#define __BITS__VM_H__


int txop_vm_init(shpeer_t *cli_peer, tx_vm_t *th);
int txop_vm_confirm(shpeer_t *cli_peer, tx_vm_t *th);
int txop_vm_recv(shpeer_t *cli_peer, tx_vm_t *th);
int txop_vm_send(shpeer_t *cli_peer, tx_vm_t *th);


#endif /* ndef __BITS__VM_H__ */

