
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
 *
 *  This file is part of ShionCoin.
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

#ifndef __BLOCKCHAIN__BC_INDEX_H__ 
#define __BLOCKCHAIN__BC_INDEX_H__ 

int bc_idx_set(bc_t *bc, bcsize_t pos, bc_idx_t *idx);

int bc_idx_clear(bc_t *bc, bcsize_t pos);
int bc_idx_find(bc_t *bc, bc_hash_t hash, bc_idx_t *ret_idx, int *ret_pos);
int bc_idx_get(bc_t *bc, bcsize_t pos, bc_idx_t *ret_idx);

/**
 * @returns The next record index in the specified database.
 */
int bc_idx_next(bc_t *bc, bcpos_t *pos_p);

int bc_idx_reset(bc_t *bc, bcsize_t pos, bc_idx_t *idx);

int bc_idx_open(bc_t *bc);

void bc_idx_close(bc_t *bc);


#endif /* ndef __BLOCKCHAIN__BC_INDEX_H__  */
