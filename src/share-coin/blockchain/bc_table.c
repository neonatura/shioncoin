
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

#include "shcoind.h"

#define BC_INDEX_PAGE_SIZE 8096

#ifdef linux
#include <stdio.h>
#endif





int bc_table_hash(bc_hash_t hash)
{
  int i;
  uint32_t *p;
  uint32_t val;

  val = 0;
  p = (uint32_t *)hash;
  for (i = 0; i < 8; i++)
    val += p[i];

  return ((int)(val % BC_TABLE_SIZE));
}

uint64_t *bc_table_pos(bc_t *bc, bc_hash_t hash)
{
  uint64_t *tab;
  int idx;

  tab = (uint64_t *)bc->tab_map.raw;
  if (!tab)
    return (NULL);

  idx = bc_table_hash(hash);
  return (&tab[idx]);
}

static int _bc_table_get(bc_t *bc, bc_hash_t hash, uint64_t *ret_pos)
{
  uint64_t *pos_p;
  int err;
  int i;

  err = bc_table_open(bc);
  if (err)
    return (err);

  if (ret_pos)
    *ret_pos = BC_TABLE_NULL_POS; 

  pos_p = bc_table_pos(bc, hash);
  if (!pos_p)
    return (SHERR_INVAL);
  if (*pos_p == BC_TABLE_SEARCH_POS)
    return (SHERR_SRCH);
  if (*pos_p == BC_TABLE_NULL_POS)
    return (SHERR_NOENT); /* no record exists */

  if (ret_pos) {
    *ret_pos = *pos_p;
  }

  return (0);  
}

int bc_table_get(bc_t *bc, bc_hash_t hash, uint64_t *ret_pos)
{
  int err;

  bc_lock();
  err = _bc_table_get(bc, hash, ret_pos);
  bc_unlock();

  return (err);
}

static int _bc_table_set(bc_t *bc, bc_hash_t hash, uint64_t pos)
{
  uint64_t *pos_p;
  uint8_t a, b;
  int err;

  if (!bc || pos >= BC_TABLE_POS_MASK)
    return (SHERR_INVAL);

  err = bc_table_open(bc);
  if (err)
    return (err);

  pos_p = bc_table_pos(bc, hash);
  if (!pos_p)
    return (SHERR_INVAL);

  if (*pos_p < pos || *pos_p >= BC_TABLE_POS_MASK) {
    /* retain highest index position for hash entry */
    *pos_p = pos;
  }

  return (0);
}

int bc_table_set(bc_t *bc, bc_hash_t hash, uint64_t pos)
{
  int err;

  bc_lock();
  err = _bc_table_set(bc, hash, pos);
  bc_unlock();

  return (err);
}

static int _bc_table_unset(bc_t *bc, bc_hash_t hash)
{
  uint64_t *pos_p;
  uint8_t a, b;
  int err;

  if (!bc)
    return (SHERR_INVAL);

  err = bc_table_open(bc);
  if (err)
    return (err);

  pos_p = bc_table_pos(bc, hash);
  if (!pos_p)
    return (SHERR_INVAL);

  *pos_p = BC_TABLE_NULL_POS;

  return (0);
}

int bc_table_unset(bc_t *bc, bc_hash_t hash)
{
  int err;

  bc_lock();
  err = _bc_table_unset(bc, hash);
  bc_unlock();

  return (err);
}

static int _bc_table_reset(bc_t *bc, bc_hash_t hash)
{
  uint64_t *pos_p;
  uint8_t a, b;
  int err;

  if (!bc)
    return (SHERR_INVAL);

  err = bc_table_open(bc);
  if (err)
    return (err);

  pos_p = bc_table_pos(bc, hash);
  if (!pos_p)
    return (SHERR_INVAL);

  
  *pos_p = BC_TABLE_SEARCH_POS;

  return (0);
}

int bc_table_reset(bc_t *bc, bc_hash_t hash)
{
  int err;

  bc_lock();
  err = _bc_table_reset(bc, hash);
  bc_unlock();

  return (err);
}

static int _bc_table_open(bc_t *bc)
{
  char errbuf[256];
  int err;

  if (!bc)
    return (SHERR_INVAL);

  if (bc->tab_map.fd != 0) {
    return (0);
  }

  /* set map file extension */
  strncpy(bc->tab_map.ext, BC_TABLE_EXTENSION, sizeof(bc->tab_map.ext)-1);

  err = bc_map_open(bc, &bc->tab_map);
  if (err) {
    sprintf(errbuf, "bc_table_open: map open error: %s.", sherrstr(err));
    shcoind_log(errbuf);
    return (err);
  }

  err = bc_map_alloc(bc, &bc->tab_map, (BC_TABLE_SIZE * sizeof(uint64_t)));
  if (err) {
    sprintf(errbuf, "bc_table_open: map alloc error: %s.", sherrstr(err));
    shcoind_log(errbuf);
    return (err);
  }

  return (0);
}

int bc_table_open(bc_t *bc)
{
  int err;

  bc_lock();
  err = _bc_table_open(bc);
  bc_unlock();

  return (err);
}

static void _bc_table_close(bc_t *bc)
{

  if (bc->tab_map.fd != 0) {
    bc_map_close(&bc->tab_map);
  }
  
}

void bc_table_close(bc_t *bc)
{

  bc_lock();
  _bc_table_close(bc);
  bc_unlock();

}

static int _bc_table_clear(bc_t *bc)
{
  int err;

  err = bc_table_open(bc);
  if (err)
    return (err);

  /* mark entire hash-map table as 'search required'. */
  memset(bc->tab_map.raw, '\000', bc->tab_map.size - sizeof(bc_hdr_t));

  return (0);
}

int bc_table_clear(bc_t *bc)
{
  int err;

  bc_lock();
  err = _bc_table_clear(bc);
  bc_unlock();

  return (err);
}

