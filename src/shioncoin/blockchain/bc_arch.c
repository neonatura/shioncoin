
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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

#include "shcoind.h"

#ifdef linux
#include <stdio.h>
#endif

#define BC_ARCH_EXTENSION "arch"

static int _bc_arch_open(bc_t *bc)
{
  int err;

  if (!bc)
    return (ERR_INVAL);

  if (bc->arch_map.fd != 0)
    return (0);

  /* set map file extension */
  strncpy(bc->arch_map.ext, BC_ARCH_EXTENSION, sizeof(bc->arch_map.ext)-1);

	err = bc_map_open(bc, &bc->arch_map);
	if (err) {
		return (err);
	}

	err = bc_map_alloc(bc, &bc->arch_map, 0);
	if (err) {
		return (err);
	}

  return (0);
}

int bc_arch_open(bc_t *bc)
{
	int err;

	if (!bc_lock(bc))
		return (ERR_NOLCK);
	err = _bc_arch_open(bc);
	bc_unlock(bc);

	return (err);
}

static void _bc_arch_close(bc_t *bc)
{

  if (bc->arch_map.fd != 0) {
    bc_map_close(&bc->arch_map);
  }
  
}

void bc_arch_close(bc_t *bc)
{

	if (bc_lock(bc)) {
		_bc_arch_close(bc);
		bc_unlock(bc);
	}
}

uint32_t bc_arch_crc(bc_hash_t hash)
{
  return (shcrc(hash, sizeof(bc_hash_t)));
}

int bc_arch_find(bc_t *bc, bc_hash_t hash, bc_idx_t *ret_arch, bcsize_t *ret_pos)
{
  bc_hash_t t_hash;
  bc_idx_t *arch;
  bcsize_t len;
  int crc;
  int err;
  int i;

  err = bc_arch_open(bc);
  if (err)
    return (err);

  if (ret_arch)
    memset(ret_arch, '\000', sizeof(bc_idx_t));
  if (ret_pos)
    *ret_pos = -1;

#if 0
  crc = bc_arch_crc(hash);
#endif

  arch = (bc_idx_t *)bc->arch_map.raw;
  len = bc->arch_map.hdr->of / sizeof(bc_idx_t);
  for (i = (len-1); i >= 0; i--) {
    if (arch[i].size == 0) continue;
#if 0
    if (arch[i].crc != crc)
      continue; /* hash checksum does not match */    

    err = bc_read(bc, i, t_hash, sizeof(t_hash));
    if (err)
      return (err);

    if (bc_hash_cmp(hash, t_hash)) {
      if (ret_arch)
        memcpy(ret_arch, arch + i, sizeof(bc_idx_t));
      if (ret_pos)
        *ret_pos = i;
      return (0);
    }
#endif
    if (bc_hash_cmp(hash, arch[i].hash)) {
      if (ret_arch)
        memcpy(ret_arch, arch + i, sizeof(bc_idx_t));
      if (ret_pos)
        *ret_pos = i;
      return (0);
    }
  }

  return (ERR_NOENT);
}

static int _bc_arch_get(bc_t *bc, bcpos_t pos, bc_idx_t *ret_arch)
{
  bc_idx_t *arch;
  int err;

  if (!bc)
    return (ERR_INVAL);

  err = bc_arch_open(bc);
  if (err)
    return (err);

  if (pos >= (bc->arch_map.hdr->of / sizeof(bc_idx_t)))
    return (ERR_NOENT);

  arch = (bc_idx_t *)bc->arch_map.raw;
  if (arch[pos].size == 0)
    return (ERR_NOENT); /* not filled in */

  if (ret_arch) {
    memcpy(ret_arch, arch + pos, sizeof(bc_idx_t));
  }

  return (0);
}

int bc_arch_get(bc_t *bc, bcpos_t pos, bc_idx_t *ret_arch)
{
	int err;

	if (!bc_lock(bc))
		return (ERR_NOLCK);
	err = _bc_arch_get(bc, pos, ret_arch);
	bc_unlock(bc);

	return (err);
}

/**
 * @returns The next record index.
 */
int bc_arch_next(bc_t *bc, bcpos_t *pos_p)
{
  bc_idx_t *arch;
  int err;

  err = bc_arch_open(bc);
  if (err)
    return (err);

	if (pos_p)
		*pos_p = bc->arch_map.hdr->of / sizeof(bc_idx_t);

	return (0);
}

/**
 * @todo consider clearing indexes which are brought back into main chain.
 */
static int _bc_arch_set(bc_t *bc, bcpos_t pos, bc_idx_t *arch)
{
  bc_idx_t *f_arch;
  bcsize_t of;
  int err;

  if (!bc) {
    return (ERR_INVAL);
  }

  err = bc_arch_open(bc);
  if (err) {
    return (err);
  }

  if (bc_arch_get(bc, pos, NULL) != ERR_NOENT)
    return (ERR_EXIST);

  of = (pos * sizeof(bc_idx_t));
  if (pos >= (bc->arch_map.hdr->of / sizeof(bc_idx_t)) &&
      (of + sizeof(bc_idx_t)) > bc->arch_map.size) {
    bcsize_t f_len = (of + sizeof(bc_idx_t)) - bc->arch_map.size;

    err = bc_map_alloc(bc, &bc->arch_map, f_len);
    if (err)
      return (err);
  }

  /* write to file map */
  err = bc_map_write(bc, &bc->arch_map, of, arch, sizeof(bc_idx_t)); 
  if (err)
    return (err);

  return (0);
}

int bc_arch_set(bc_t *bc, bcpos_t pos, bc_idx_t *arch)
{
	int err;

	if (!bc_lock(bc))
		return (ERR_NOLCK);
	err = _bc_arch_set(bc, pos, arch);
	bc_unlock(bc);

	return (err);
}

int bc_arch_add(bc_t *bc, bc_idx_t *arch)
{
	bcpos_t pos;
	int err;

	err = bc_arch_next(bc, &pos);
	if (err)
		return (err);

  return (bc_arch_set(bc, pos, arch));
}

