
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

#ifndef __BLOCKCHAIN__BC_FMAP_H__ 
#define __BLOCKCHAIN__BC_FMAP_H__ 


void bc_map_free(bc_map_t *map);

int bc_map_open(bc_t *bc, bc_map_t *map);

int bc_map_alloc(bc_t *bc, bc_map_t *map, bcsize_t len);

int bc_map_append(bc_t *bc, bc_map_t *map, void *raw_data, bcsize_t data_len);

int bc_map_write(bc_t *bc, bc_map_t *map, bcsize_t of, void *raw_data, bcsize_t data_len);

int bc_map_trunc(bc_t *bc, bc_map_t *map, bcsize_t len);

shkey_t *get_bcmap_lock(void);

unsigned int bc_fmap_total(bc_t *bc);

void bc_map_close(bc_map_t *map);


#endif /* ndef __BLOCKCHAIN__BC_FMAP_H__  */

