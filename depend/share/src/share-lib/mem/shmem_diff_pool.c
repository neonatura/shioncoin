
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

#include "shmem_diff_int.h"
#include "shmem_diff_pool.h"

#define MIN_POOL	2
#define MAX_POOL_INCREMENT	128

int shdiff_pool_alloc(shdiff_pool *pool, uint32_t start_pool)
{
	memset(pool, 0, sizeof(*pool));

	if (start_pool < MIN_POOL)
		start_pool = MIN_POOL;

	pool->pool = calloc(start_pool, sizeof(shdiff_node));
	if (!pool->pool)
		return -1;

	pool->pool_size = start_pool;
	pool->pool_used = 1; /* set aside first item */
	pool->free_list = -1;

	return 0;
}

void shdiff_pool_free(shdiff_pool *pool)
{
	free(pool->pool);
}

void shdiff_node_release(shdiff_pool *pool, shdiff_pos idx)
{
	shdiff_node *node = shdiff_node_at(pool, idx);
	node->next = pool->free_list;
	pool->free_list = idx;
}

static shdiff_pos grow_pool(shdiff_pool *pool)
{
	uint32_t new_size;
	shdiff_node *new_pool;

	if (pool->pool_size > MAX_POOL_INCREMENT)
		new_size = pool->pool_size + MAX_POOL_INCREMENT;
	else
		new_size = pool->pool_size * 2;

	new_pool = realloc(pool->pool, new_size * sizeof(shdiff_node));
	if (!new_pool) {
		pool->error = -1;
		return -1;
	}

	pool->pool = new_pool;
	pool->pool_size = new_size;

	return pool->pool_used;
}

static shdiff_pos alloc_node(
	shdiff_pool *pool, int op, const char *data, uint32_t offset, uint32_t len)
{
	shdiff_pos   pos;
	shdiff_node *node;

	//assert(pool && data && op >= -1 && op <= 1);

	/* don't insert zero length INSERT or DELETE ops */
	if (len == 0 && op != 0)
		return -1;

	if (pool->free_list > 0) {
		pos = pool->free_list;
		node = shdiff_node_at(pool, pos);
		pool->free_list = node->next;
	}
	else {
		if (pool->pool_used >= pool->pool_size)
			(void)grow_pool(pool);

		pos = pool->pool_used;
		pool->pool_used += 1;
		node = shdiff_node_at(pool, pos);
	}

	node->text = data + offset;
	node->len  = len;
	node->op   = op;
	node->next = -1;

#ifdef BUGALICIOUS
	if (len > 0)
		fprintf(stderr, "adding <%c'%.*s'> (len %d) %02x\n",
				!node->op ? '=' : node->op < 0 ? '-' : '+',
				node->len, node->text, node->len, (int)*node->text);
#endif

	return pos;
}

shdiff_pos shdiff_range_init(
	shdiff_pool *pool, shdiff_range *run,
	int op, const char *data, uint32_t offset, uint32_t len)
{
	run->start = run->end = alloc_node(pool, op, data, offset, len);
	return run->start;
}

shdiff_pos shdiff_range_insert(
	shdiff_pool *pool, shdiff_range *run, shdiff_pos pos,
	int op, const char *data, uint32_t offset, uint32_t len)
{
	shdiff_node *node;
	shdiff_pos added_at = alloc_node(pool, op, data, offset, len);
	if (added_at < 0)
		return pos;

	node = shdiff_node_at(pool, added_at);

	if (pos == -1) {
		shdiff_node *end = shdiff_node_at(pool, run->end);
		node->next = end->next;
		end->next  = added_at;
		run->end   = added_at;
	}
	else if (pos == 0) {
		node->next = run->start;
		run->start = added_at;
	}
	else {
		shdiff_node *after = shdiff_node_at(pool, pos);
		node->next  = after->next;
		after->next = added_at;
	}

	return added_at;
}

void shdiff_range_splice(
	shdiff_pool *pool, shdiff_range *onto, shdiff_pos pos, shdiff_range *from)
{
	shdiff_node *tail;

	shdiff_range_normalize(pool, from);

	tail = shdiff_node_at(pool, from->end);

	if (pos == -1) {
		shdiff_node *after = shdiff_node_at(pool, onto->end);
		tail->next  = after->next;
		after->next = from->start;
		onto->end   = from->end;
	}
	else if (pos == 0) {
		tail->next  = onto->start;
		onto->start = from->start;
	}
	else {
		shdiff_node *after = shdiff_node_at(pool, pos);
		tail->next  = after->next;
		after->next = from->start;
	}
}

int shdiff_range_len(shdiff_pool *pool, shdiff_range *run)
{
	int count = 0;
	shdiff_pos scan;

	for (scan = run->start; scan != -1; ) {
		shdiff_node *node = shdiff_node_at(pool, scan);
		count++;
		scan = node->next;
	}

	return count;
}

void shdiff_range_normalize(shdiff_pool *pool, shdiff_range *range)
{
	shdiff_pos last_nonzero = -1, *pos = &range->start;

	while (*pos != -1) {
		shdiff_node *node = shdiff_node_at(pool, *pos);
		if (!node->len) {
			*pos = node->next;
			shdiff_node_release(pool, shdiff_node_pos(pool, node));
		} else {
			last_nonzero = *pos;
			pos = &node->next;
		}
	}

	if (last_nonzero >= 0)
		range->end = last_nonzero;
}
