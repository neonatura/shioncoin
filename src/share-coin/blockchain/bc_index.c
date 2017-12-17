
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

#define BC_INDEX_EXTENSION "idx"

static int _bc_idx_open(bc_t *bc)
{
  char errbuf[256];
  int err;

  if (!bc)
    return (SHERR_INVAL);

  if (bc->idx_map.fd != 0) {
    return (0);
  }

  /* set map file extension */
  strncpy(bc->idx_map.ext, BC_INDEX_EXTENSION, sizeof(bc->idx_map.ext)-1);

  err = bc_map_open(bc, &bc->idx_map);
  if (err) {
    sprintf(errbuf, "bc_idx_open: map open error: %s.", sherrstr(err));
    shcoind_log(errbuf);
    return (err);
  }

  err = bc_map_alloc(bc, &bc->idx_map, 0);
  if (err) {
    sprintf(errbuf, "bc_idx_open: map alloc error: %s.", sherrstr(err));
    shcoind_log(errbuf);
    return (err);
  }

  return (0);
}

int bc_idx_open(bc_t *bc)
{
  int err;

  bc_lock();
  err = _bc_idx_open(bc);
  bc_unlock();

  return (err);
}

static void _bc_idx_close(bc_t *bc)
{

  if (bc->idx_map.fd != 0) {
    bc_map_close(&bc->idx_map);
  }
  
}

void bc_idx_close(bc_t *bc)
{

  bc_lock();
  _bc_idx_close(bc);
  bc_unlock();

}

static int _bc_idx_find(bc_t *bc, bc_hash_t hash, bc_idx_t *ret_idx, int *ret_pos)
{
  bc_hash_t t_hash;
  bc_idx_t *idx;
  bcsize_t len;
  uint64_t pos;
  int pos_high;
  int tab_hash;
  int crc;
  int err;
  int i;

  if (ret_idx)
    memset(ret_idx, '\000', sizeof(bc_idx_t));
  if (ret_pos)
    *ret_pos = -1;

  pos_high = -1;
  err = bc_table_get(bc, hash, &pos);
  if (err == SHERR_NOENT)
    return (SHERR_NOENT);
  if (err == 0) {
    /* current highest known position for table hash */
    pos_high = (int)pos;
  }

  err = bc_idx_open(bc);
  if (err)
    return (err);

  idx = (bc_idx_t *)bc->idx_map.raw;

  len = (bc->idx_map.hdr->of / sizeof(bc_idx_t)) - 1;
  if (pos_high > len)
    pos_high = -1;
  if (pos_high != -1)
    len = pos_high;

  tab_hash = bc_table_hash(hash);
  for (i = len; i >= 0; i--) {
    if (idx[i].size == 0) continue;

    if (bc_table_hash(idx[i].hash) == tab_hash)
      pos_high = MAX(pos_high, i);

    if (bc_hash_cmp(hash, idx[i].hash))
      break;
  }

  if (pos_high != -1) {
    if (pos != (uint64_t)pos_high) {
      /* record highest index pos for table hash. */
      bc_table_set(bc, hash, pos_high);
    }
  } else if (i < 0) {
    /* no entries found and no indexes matched table hash */
    bc_table_unset(bc, hash);
  }

  if (i < 0) {
    /* no index position found. */
    return (SHERR_NOENT);
  }

  if (ret_idx)
    memcpy(ret_idx, idx + i, sizeof(bc_idx_t));
  if (ret_pos)
    *ret_pos = i;

  return (0);
}

int bc_idx_find(bc_t *bc, bc_hash_t hash, bc_idx_t *ret_idx, int *ret_pos)
{
  int err;

  bc_lock();
  err = _bc_idx_find(bc, hash, ret_idx, ret_pos);
  bc_unlock();

  return (err);
}

static int _bc_idx_get(bc_t *bc, bcsize_t pos, bc_idx_t *ret_idx)
{
  bc_idx_t *idx;
  int err;

  if (!bc)
    return (SHERR_INVAL);

  if (pos < 0)
    return (SHERR_INVAL);

  err = bc_idx_open(bc);
  if (err)
    return (err);

  if (pos >= (bc->idx_map.hdr->of / sizeof(bc_idx_t)))
    return (SHERR_NOENT);

  idx = (bc_idx_t *)bc->idx_map.raw;
  if (idx[pos].size == 0)
    return (SHERR_NOENT); /* not filled in */

  if (ret_idx) {
    memcpy(ret_idx, idx + pos, sizeof(bc_idx_t));
  }

  return (0);
}

int bc_idx_get(bc_t *bc, bcsize_t pos, bc_idx_t *ret_idx)
{
  int err;

  bc_lock();
  err = _bc_idx_get(bc, pos, ret_idx);
  bc_unlock();

  return (err);

}

static int _bc_idx_set(bc_t *bc, bcsize_t pos, bc_idx_t *idx)
{
  bc_idx_t *f_idx;
  bcsize_t of;
  int err;

  if (!bc || pos < 0) {
    return (SHERR_INVAL);
  }

  err = bc_idx_open(bc);
  if (err) {
    return (err);
  }

#if 0
  if (pos == 0) {
    bc_idx_t blank_idx;

    /* blank initial record */
    memset(&blank_idx, 0, sizeof(blank_idx));
    err = bc_map_append(bc, &bc->idx_map, &blank_idx, sizeof(bc_idx_t));
    if (err)
      return (err);

    pos++;
  }
#endif

  if (bc_idx_get(bc, pos, NULL) != SHERR_NOENT)
    return (SHERR_EXIST);

  of = (pos * sizeof(bc_idx_t));
  if (pos >= (bc->idx_map.hdr->of / sizeof(bc_idx_t)) &&
      (of + sizeof(bc_idx_t)) > bc->idx_map.size) {
    bcsize_t f_len = (of + sizeof(bc_idx_t)) - bc->idx_map.size;

    err = bc_map_alloc(bc, &bc->idx_map, f_len);
    if (err) {
      return (err);
    }
  }

  /* write to file map */
  err = bc_map_write(bc, &bc->idx_map, of, idx, sizeof(bc_idx_t)); 
  if (err)
    return (err);

  /* mark table hash entry as requiring new search. */
  bc_table_reset(bc, idx->hash);

  return (0);
}

int bc_idx_set(bc_t *bc, bcsize_t pos, bc_idx_t *idx)
{
  int err;

  bc_lock();
  err = _bc_idx_set(bc, pos, idx);
  bc_unlock();

  return (err);
}

static int _bc_idx_reset(bc_t *bc, bcsize_t pos, bc_idx_t *idx)
{
  bc_idx_t n_idx;
  bcsize_t of;
  int err;

  if (!bc || pos < 0) {
    return (SHERR_INVAL);
  }

  err = bc_idx_open(bc);
  if (err) {
    return (err);
  }

#if 0
  if (pos == 0) {
    bc_idx_t blank_idx;

    /* blank initial record */
    memset(&blank_idx, 0, sizeof(blank_idx));
    err = bc_map_append(bc, &bc->idx_map, &blank_idx, sizeof(bc_idx_t));
    if (err)
      return (err);

    pos++;
  }
#endif

  if (bc_idx_get(bc, pos, &n_idx) != 0)
    return (SHERR_NOENT);

  of = (pos * sizeof(bc_idx_t));
  if (pos >= (bc->idx_map.hdr->of / sizeof(bc_idx_t)) ||
      (of + sizeof(bc_idx_t)) > bc->idx_map.size) {
    return (SHERR_IO);
  }

  /* write to file map */
  err = bc_map_write(bc, &bc->idx_map, of, idx, sizeof(bc_idx_t)); 
  if (err)
    return (err);

  return (0);
}

int bc_idx_reset(bc_t *bc, bcsize_t pos, bc_idx_t *idx)
{
  int err;

  bc_lock();
  err = _bc_idx_reset(bc, pos, idx);
  bc_unlock();

  return (err);
}

/**
 * @note (odd) only reduces index count when "pos" is last record in db.
 */
static int _bc_idx_clear(bc_t *bc, bcsize_t pos)
{
  bc_idx_t *f_idx;
  bc_idx_t blank_idx;
  bcsize_t n_pos;
  bcsize_t of;
  int err;

  if (!bc || pos < 0) {
    return (SHERR_INVAL);
  }

  err = bc_idx_open(bc);
  if (err)
    return (err);

  n_pos = MAX(0, (bc->idx_map.hdr->of / sizeof(bc_idx_t)));

  of = (pos * sizeof(bc_idx_t));
  if (pos >= (bc->idx_map.hdr->of / sizeof(bc_idx_t)) &&
      (of + sizeof(bc_idx_t)) > bc->idx_map.size) {
    /* no content - does not exist */
  } else {
    /* write to file map */
    memset(&blank_idx, 0, sizeof(blank_idx));
    err = bc_map_write(bc, &bc->idx_map, of, &blank_idx, sizeof(bc_idx_t)); 
    if (err)
      return (err);
  }

  return (0);
}

int bc_idx_clear(bc_t *bc, bcsize_t pos)
{
  int err;

  bc_lock();
  err = _bc_idx_clear(bc, pos);
  bc_unlock();

  return (err);
}



/**
 * @returns The next record index.
 */
bcsize_t bc_idx_next(bc_t *bc)
{
  bc_idx_t *idx;
  int err;

  if (!bc)
    return (SHERR_INVAL);

  err = bc_idx_open(bc);
  if (err)
    return (err);

  return MAX(0, (bc->idx_map.hdr->of / sizeof(bc_idx_t)));
}

uint32_t bc_idx_crc(bc_hash_t hash)
{
  return (shcrc(hash, sizeof(bc_hash_t)));
}

