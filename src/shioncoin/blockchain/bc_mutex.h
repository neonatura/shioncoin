
/*
 * @copyright
 *
 *  Copyright 2016 Brian Burrell
 *
 *  This file is part of Shioncoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  


#ifndef __BLOCKCHAIN__BC_MUTEX_H__
#define __BLOCKCHAIN__BC_MUTEX_H__


int bc_lock(bc_t *bc);

int bc_trylock(bc_t *bc);

void bc_unlock(bc_t *bc);

void bc_mutex_init(bc_t *bc);

void bc_mutex_term(bc_t *bc);


#endif /* ndef __BLOCKCHAIN__BC_MUTEX_H__ */
