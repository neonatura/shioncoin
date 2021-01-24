
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

#ifndef __MEM__SHMEM_DIFF_POOL_H__
#define __MEM__SHMEM_DIFF_POOL_H__


typedef int shdiff_pos;

typedef struct {
	const char *text;
	uint32_t len;
	int op;
	shdiff_pos next;
} shdiff_node;

typedef struct {
	shdiff_pos start, end;
} shdiff_range;

typedef struct {
	shdiff_node *pool;
	uint32_t pool_size, pool_used;
	shdiff_pos free_list;
	int error;
} shdiff_pool;

extern int shdiff_pool_alloc(shdiff_pool *pool, uint32_t start_pool);

extern void shdiff_pool_free(shdiff_pool *list);

extern shdiff_pos shdiff_range_init(
	shdiff_pool *list, shdiff_range *run,
	int op, const char *data, uint32_t offset, uint32_t len);

extern shdiff_pos shdiff_range_insert(
	shdiff_pool *list, shdiff_range *run, shdiff_pos pos,
	int op, const char *data, uint32_t offset, uint32_t len);

extern void shdiff_range_splice(
	shdiff_pool *list, shdiff_range *onto, shdiff_pos pos, shdiff_range *from);

extern int shdiff_range_len(shdiff_pool *pool, shdiff_range *run);

/* remove all 0-length nodes and advance 'end' to actual end */
extern void shdiff_range_normalize(shdiff_pool *pool, shdiff_range *range);

extern void shdiff_node_release(shdiff_pool *pool, shdiff_pos idx);

#define shdiff_node_at(POOL,POS)   (&((POOL)->pool[(POS)]))

#define shdiff_node_pos(POOL,NODE) ((shdiff_pos)((NODE) - (POOL)->pool))

#define shdiff_range_foreach(POOL, RANGE, IDX, PTR) \
	for (IDX = (RANGE)->start; IDX >= 0; IDX = (PTR)->next)	\
		if (((PTR) = shdiff_node_at((POOL),IDX))->len > 0)


#endif /* ndef __MEM__SHMEM_DIFF_POOL_H__ */
