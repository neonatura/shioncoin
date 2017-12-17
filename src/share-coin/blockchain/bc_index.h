
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

#ifndef __BLOCKCHAIN__BC_INDEX_H__ 
#define __BLOCKCHAIN__BC_INDEX_H__ 

int bc_idx_set(bc_t *bc, bcsize_t pos, bc_idx_t *idx);

int bc_idx_clear(bc_t *bc, bcsize_t pos);
int bc_idx_find(bc_t *bc, bc_hash_t hash, bc_idx_t *ret_idx, int *ret_pos);
int bc_idx_get(bc_t *bc, bcsize_t pos, bc_idx_t *ret_idx);

bcsize_t bc_idx_next(bc_t *bc);

int bc_idx_reset(bc_t *bc, bcsize_t pos, bc_idx_t *idx);

int bc_idx_open(bc_t *bc);


#endif /* ndef __BLOCKCHAIN__BC_INDEX_H__  */
