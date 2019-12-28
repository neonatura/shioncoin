
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


#ifndef __BLOCKCHAIN__BC_TABLE_H__
#define __BLOCKCHAIN__BC_TABLE_H__

#ifdef __cplusplus
extern "C" {
#endif
 

//#define BC_TABLE_SIZE 262144 /* 64bit */
#define BC_TABLE_SIZE 1048576 /* 4meg "tmp" table file */

#define BC_TABLE_POS_MASK 0xFFFFFFF0
#define BC_TABLE_NULL_POS 0xFFFFFFF1
#define BC_TABLE_SEARCH_POS 0x0

#define BC_TABLE_EXTENSION "tmp"


int bc_table_find(bc_t *bc, bc_hash_t hash, bcpos_t *ret_pos);

int bc_table_set(bc_t *bc, bc_hash_t hash, bcpos_t pos);


/** Remove a hash from the index table. */
int bc_table_unset(bc_t *bc, bc_hash_t hash);

/** Mark a index table hash as unknown. */
int bc_table_reset(bc_t *bc, bc_hash_t hash);

/** Obtain a reference to the index position table value */
bcpos_t *bc_table_pos(bc_t *bc, bc_hash_t hash);

/** Obtain a hash code identifying the table entry. */
int bc_table_hash(bc_hash_t hash);

/** Clear all hashes from the entire table. */
int bc_table_clear(bc_t *bc);

int bc_table_open(bc_t *bc);

void bc_table_close(bc_t *bc);


#ifdef __cplusplus
}
#endif


#endif /* ndef __BLOCKCHAIN__BC_TABLE_H__ */

