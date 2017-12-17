
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

#ifndef __BLOCKCHAIN__BC_ARCH_H__
#define __BLOCKCHAIN__BC_ARCH_H__


int bc_arch_open(bc_t *bc);

void bc_arch_close(bc_t *bc);

/**
 * Add a new "archived record" to the chain.
 */
int bc_arch_add(bc_t *bc, bc_idx_t *arch);

uint32_t bc_arch_crc(bc_hash_t hash);

int bc_arch_get(bc_t *bc, bcsize_t pos, bc_idx_t *ret_arch);

/**
 * @returns The next record index.
 */
bcsize_t bc_arch_next(bc_t *bc);

int bc_arch_set(bc_t *bc, bcsize_t pos, bc_idx_t *arch);

int bc_arch_find(bc_t *bc, bc_hash_t hash, bc_idx_t *ret_arch, bcsize_t *ret_pos);



#endif /* ndef __BLOCKCHAIN__BC_ARCH_H__ */

