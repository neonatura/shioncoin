
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

#ifdef linux
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#endif

static shkey_t *BCMAP_LOCK_KEY;

char *bc_name(bc_t *bc)
{

  if (!bc)
    return (NULL);

  return (bc->name);
}

shlock_t *bc_lock(void)
{
  if (!BCMAP_LOCK_KEY)
    BCMAP_LOCK_KEY = shkey_str(BCMAP_LOCK);
  return (shlock_open(BCMAP_LOCK_KEY, 0));
}

void bc_unlock(void)
{
  if (!BCMAP_LOCK_KEY)
    BCMAP_LOCK_KEY = shkey_str(BCMAP_LOCK);
  shlock_close(BCMAP_LOCK_KEY);
}

static int _bc_open(char *name, bc_t **bc_p)
{
  bc_t *bc;
  int err;

  if (!bc_p)
    return (SHERR_INVAL);

  bc = (bc_t *)calloc(1, sizeof(bc_t));
  if (!bc)
    return (SHERR_NOMEM);

  strncpy(bc->name, name, sizeof(bc->name) - 1);

  err = bc_idx_open(bc);
  if (err)
    return (err);

  *bc_p = bc;

  return (0);
}

int bc_open(char *name, bc_t **bc_p)
{
  int err;

  bc_lock();
  err = _bc_open(name, bc_p);
  bc_unlock();

  return (err);
}

static void _bc_close(bc_t *bc)
{
  bc_map_t *map;
  int i;

  /* close index map */
  bc_idx_close(bc);

  /* close hash table */
  bc_table_close(bc);

  /* close data maps */
  for (i = 0; i < bc->data_map_len; i++) {
    map = bc->data_map + i;
    bc_map_close(map);
  }

  /* free data map list */
  free(bc->data_map);
  bc->data_map = NULL;
  bc->data_map_len = 0;

  free(bc);
}

void bc_close(bc_t *bc)
{
  bc_lock();
  _bc_close(bc);
  bc_unlock();
}

/**
 * @todo auto de-alloc maps that expire
 */
int bc_alloc(bc_t *bc, unsigned int jrnl)
{
  bc_map_t *map;
  char ext[64];
  int err;

  if (jrnl >= bc->data_map_len) {
    bc_map_t *o_data_map;
    bc_map_t *n_data_map;

    o_data_map = bc->data_map;
    n_data_map = (bc_map_t *)calloc(jrnl+1, sizeof(bc_map_t));
    if (o_data_map) {
      memcpy(n_data_map, o_data_map, bc->data_map_len * sizeof(bc_map_t));
      free(o_data_map);
    }

    bc->data_map = n_data_map;
    bc->data_map_len = jrnl+1;
  }

  map = bc->data_map + jrnl;

  if (!*map->ext) {
    sprintf(map->ext, "%u", jrnl);
  }

  err = bc_map_alloc(bc, map, 0);
  if (err)
    return (err);

  return (0);
}

#if 0
int bc_write(bc_t *bc, unsigned int jrnl, unsigned char *data, int data_len)
{
  bc_map_t *map;
  char ext[64];
  int err;

  err = bc_alloc(bc, jrnl);
  if (err)
    return (err);

  map = bc->data_map + jrnl;
  if (!*map->ext) {
    sprintf(map->ext, "%u", jrnl);
  }

  /* serialized block data */
  err = bc_map_append(bc, map, data, data_len);
  if (err)
    return (err);

  return (0);
}
#endif

static int _bc_rewrite(bc_t *bc, bcsize_t pos, bc_hash_t hash, void *raw_data, int data_len)
{
  unsigned char *data = (unsigned char *)raw_data;
  bc_idx_t idx;
  bc_map_t *map;
  char ext[64];
  char errbuf[256];
  int jrnl;
  int err;

  jrnl = bc_journal(pos);

  err = bc_alloc(bc, jrnl);
  if (err) {
    sprintf(errbuf, "bc_write: error: bc_alloc failed: %s.", sherrstr(err));
    shcoind_log(errbuf);
    return (err);
  }

  map = bc->data_map + jrnl;
  if (!*map->ext)
    sprintf(map->ext, "%u", idx.jrnl);

  err = bc_idx_get(bc, pos, &idx);
  if (err)
    return (err);

  if (idx.size != data_len)
    return (SHERR_EXIST);

  idx.crc = shcrc32(data, data_len);

  /* store fresh block index */
  err = bc_idx_reset(bc, pos, &idx);
  if (err) { 
    sprintf(errbuf, "bc_write: error: bc_idx_set failure: %s.", sherrstr(err));
    shcoind_log(errbuf);
    return (err);
  }

  /* store serialized block data */
  err = bc_map_write(bc, map, idx.of, data, data_len);
  if (err) { /* uh oh */
    sprintf(errbuf, "bc_write: error: bc_map_append failure: %s.", sherrstr(err));
    shcoind_log(errbuf);
    bc_idx_clear(bc, pos);
    bc_table_reset(bc, hash);
    return (err);
  }

  return (0);
}

int bc_rewrite(bc_t *bc, bcsize_t pos, bc_hash_t hash, void *raw_data, int data_len)
{
  int err;

  if (!bc_lock())
    return (SHERR_NOLCK);

  err = _bc_rewrite(bc, pos, hash, raw_data, data_len);
  bc_unlock();

  return (err);
}

static int _bc_write(bc_t *bc, bcsize_t pos, bc_hash_t hash, void *raw_data, int data_len)
{
  unsigned char *data = (unsigned char *)raw_data;
  bc_idx_t idx;
  bc_map_t *map;
  char ext[64];
  char errbuf[256];
  int jrnl;
  int err;

  jrnl = bc_journal(pos);

  err = bc_alloc(bc, jrnl);
  if (err) {
    sprintf(errbuf, "bc_write: error: bc_alloc failed: %s.", sherrstr(err));
    shcoind_log(errbuf);
    return (err);
  }

  map = bc->data_map + jrnl;
  if (!*map->ext)
    sprintf(map->ext, "%u", idx.jrnl);

  /* finialize block index */
  memset(&idx, 0, sizeof(idx));
  idx.jrnl = jrnl;
  idx.size = data_len;
  idx.of = map->hdr->of;
  idx.crc = shcrc32(data, data_len);
  memcpy(idx.hash, hash, sizeof(bc_hash_t));

  /* store fresh block index */
  err = bc_idx_set(bc, pos, &idx);
  if (err) { 
    if (err == SHERR_EXIST) {
      /* record already existed */
      err = _bc_rewrite(bc, pos, hash, raw_data, data_len); 
    }
    if (err)
      return (err);
  }

  /* store serialized block data */
  err = bc_map_append(bc, map, data, data_len);
  if (err) { /* uh oh */
    sprintf(errbuf, "bc_write: error: bc_map_append failure: %s.", sherrstr(err));
    shcoind_log(errbuf);
    bc_idx_clear(bc, pos);
    bc_table_reset(bc, hash);
    return (err);
  }

  return (0);
}

int bc_write(bc_t *bc, bcsize_t pos, bc_hash_t hash, void *raw_data, int data_len)
{
  int err;

  if (!bc_lock())
    return (SHERR_NOLCK);

  err = _bc_write(bc, pos, hash, raw_data, data_len);
  bc_unlock();

  return (err);
}

/**
 * @returns The new record position or a negative error code.
 */
static int _bc_append(bc_t *bc, bc_hash_t hash, void *data, size_t data_len)
{
  unsigned char *raw_data = (unsigned char *)data;
  bc_idx_t idx;
  bc_map_t *map;
  char errbuf[256];
  int pos;
  int err;

  err = bc_idx_open(bc);
  if (err) {
    sprintf(errbuf, "bc_append: error opening map index: %s.", sherrstr(err));
    shcoind_log(errbuf);
    return (err);
  }

  pos = bc_idx_next(bc);
  if (pos < 0) {
    sprintf(errbuf, "bc_append: error positioning map index: %s.", sherrstr(err));
    shcoind_log(errbuf);
    return (pos);
  }

  err = bc_write(bc, pos, hash, data, data_len);
  if (err) {
    sprintf(errbuf, "bc_append: write error: %s.", sherrstr(err));
    shcoind_log(errbuf);
    return (err); 
  }

  return (pos);
}

int bc_append(bc_t *bc, bc_hash_t hash, void *data, size_t data_len)
{
  int err;

  bc_lock();
  err = _bc_append(bc, hash, data, data_len);
  bc_unlock();

  return (err);
}


/**
 * Fills a pre-allocated binary segment with a specified size from a specified record position.
 */
static int _bc_read(bc_t *bc, int pos, void *data, bcsize_t data_len)
{
  bc_map_t *map;
  bc_idx_t idx;
  char errbuf[256];
  int err;

  /* obtain index for record position */
  memset(&idx, 0, sizeof(idx));
  err = bc_idx_get(bc, pos, &idx);
  if (err)
    return (err);

  /* ensure journal is allocated */
  err = bc_alloc(bc, idx.jrnl);
  if (err) {
    sprintf(errbuf, "bc_read: error allocating journal: %s.", sherrstr(err));
    shcoind_log(errbuf);
    return (err);
  }

  memset(data, 0, data_len);
  data_len = MIN(data_len, idx.size); 
  
  map = bc->data_map + idx.jrnl;

  if (shcrc32(map->raw + idx.of, idx.size) != idx.crc) {
    sprintf(errbuf, "bc_read: error: invalid crc {map: %x, idx: %x} mismatch at pos %d\n", shcrc32(map->raw + idx.of, idx.size), idx.crc, pos);
    shcoind_err(SHERR_ILSEQ, "bc_read", errbuf);
    return (SHERR_ILSEQ);
  }

  memcpy(data, map->raw + idx.of, data_len);

  return (0);
}

int bc_read(bc_t *bc, int pos, void *data, bcsize_t data_len)
{
  shkey_t *key;
  int err;
  int lk;

  if (!bc_lock())
    return (SHERR_NOLCK);

  err = _bc_read(bc, pos, data, data_len);
  bc_unlock();

  return (err);
}

/**
 * Obtains an allocated binary segment stored at the specified record position. 
 */
static int _bc_get(bc_t *bc, bcsize_t pos, unsigned char **data_p, size_t *data_len_p)
{
  bc_idx_t idx;
  unsigned char *data;
  char errbuf[1024];
  int err;

  if (!data_p) {
    sprintf(errbuf, "bc_get: error: no data pointer specified.");
    shcoind_log(errbuf);
    return (SHERR_INVAL);
  }

  /* obtain index for record position */
  memset(&idx, 0, sizeof(idx));
  err = bc_idx_get(bc, pos, &idx);
  if (err) {
    sprintf(errbuf, "bc_get: error obtaining index: %s [pos %d].", sherrstr(err), (int)pos);
    shcoind_log(errbuf);
    return (err);
  }

/* .. deal with idx.size == 0, i.e. prevent write of 0 */

  data = (unsigned char *)calloc(idx.size, sizeof(char)); 
  if (!data)
    return (SHERR_NOMEM);

  /* read in serialized binary data */
  err = bc_read(bc, pos, data, idx.size);
  if (err) {
    sprintf(errbuf, "bc_get: bc_read <%d bytes> error: %s [pos %d].", idx.size, sherrstr(err), (int)pos);
    shcoind_log(errbuf);
    return (err); 
  }

  *data_p = data;
  if (data_len_p)
    *data_len_p = idx.size;

  return (0);
}

int bc_get(bc_t *bc, bcsize_t pos, unsigned char **data_p, size_t *data_len_p)
{
  int err;

  bc_lock();
  err = _bc_get(bc, pos, data_p, data_len_p);
  bc_unlock();

  return (err);
}

int bc_arch(bc_t *bc, bcsize_t pos, unsigned char **data_p, size_t *data_len_p)
{
  bc_idx_t idx;
  bc_map_t *map;
  unsigned char *data;
  size_t data_len;
  char errbuf[256];
  int err;

  if (!data_p) {
    sprintf(errbuf, "bc_arch: no data pointer specified.");
    shcoind_log(errbuf);
    return (SHERR_INVAL);
  }

  *data_p = NULL;
  if (data_len_p)
    *data_len_p = 0;

  /* obtain index for record position */
  memset(&idx, 0, sizeof(idx));
  err = bc_arch_get(bc, pos, &idx);
  if (err) {
    sprintf(errbuf, "bc_arch_get: bc_idx_get error: %s [pos %d].", sherrstr(err), pos);
    shcoind_log(errbuf);
    return (err);
  }

/* .. deal with idx.size == 0, i.e. prevent write of 0 */
  data_len = idx.size;
  data = (unsigned char *)calloc(data_len, sizeof(char)); 
  if (!data)
    return (SHERR_NOMEM);

  /* ensure journal is allocated */
  err = bc_alloc(bc, idx.jrnl);
  if (err)
    return (err);

  /* read in serialized binary data */
  memset(data, 0, data_len);
  map = bc->data_map + idx.jrnl;

  if (shcrc32(map->raw + idx.of, idx.size) != idx.crc) {
    sprintf(errbuf, "bc_arch: error: invalid crc {map: %x, idx: %x} mismatch at pos %d\n", shcrc32(map->raw + idx.of, idx.size), idx.crc, pos);
    shcoind_log(errbuf);
    return (SHERR_ILSEQ);
  }

  memcpy(data, map->raw + idx.of, data_len);

  *data_p = data;
  if (data_len_p)
    *data_len_p = idx.size;

  return (0);
}

int bc_get_hash(bc_t *bc, bcsize_t pos, bc_hash_t ret_hash)
{
  bc_idx_t idx;
  int err;

  /* obtain index for record position */
  err = bc_idx_get(bc, pos, &idx);
  if (err)
    return (err);

  memcpy(ret_hash, idx.hash, sizeof(bc_hash_t));
  return (0);
}

/** 
 * Obtains the record position for a particular hash.
 */
int bc_find(bc_t *bc, bc_hash_t hash, int *pos_p)
{
  int err;

  err = bc_idx_find(bc, hash, NULL, pos_p);
  if (err)
    return (err);
  

  return (0);
}


/**
 * @bug this does not handle jrnls alloc'd past one being targeted.
 */
static int _bc_purge(bc_t *bc, bcsize_t pos)
{
  bc_map_t *map;
  bc_idx_t idx;
  bc_idx_t t_idx;
  char errbuf[256];
  int err;
  int i;

  if (pos < 0)
    return (SHERR_INVAL);

  /* obtain index for record position */
  memset(&idx, 0, sizeof(idx));
  err = bc_idx_get(bc, pos, &idx);
  if (err)
    return (err);

  /* ensure journal is allocated */
  err = bc_alloc(bc, idx.jrnl);
  if (err)
    return (err);

  map = bc->data_map + idx.jrnl;

  if (shcrc32(map->raw + idx.of, idx.size) != idx.crc) {
    sprintf(errbuf, "bc_purge: invalid crc {map: %x, idx: %x} mismatch at pos %d\n", shcrc32(map->raw + idx.of, idx.size), idx.crc, pos);
    shcoind_log(errbuf);
    return (SHERR_ILSEQ);
  }

  /* clear index of remaining entries */
  for (i = (bc_idx_next(bc)-1); i >= pos; i--) {
    bc_clear(bc, i);

    err = bc_idx_get(bc, pos, &t_idx);
    if (!err) {
      bc_table_reset(bc, t_idx.hash);
    }
//    bc_idx_clear(bc, i);
  }

#if 0
  /* truncate journal at offset */
  bc_map_trunc(bc, map, idx.of);
#endif

  return (0);
}

int bc_purge(bc_t *bc, bcsize_t pos)
{
  int err;

  if (!bc_lock())
    return (SHERR_NOLCK);

  err = _bc_purge(bc, pos);
  bc_unlock();

  return (err);
}


/**
 * @returns TRUE if the hashes are identical and FALSE otherwise.
 */
int bc_hash_cmp(bc_hash_t a_hash, bc_hash_t b_hash)
{
  int i;

  if (0 != memcmp((uint32_t *)a_hash, 
        (uint32_t *)b_hash, sizeof(bc_hash_t)))
    return (FALSE);

  return (TRUE);
}


/**
 * The base path of the blockchain database.
 */
const char *bc_path_base(void)
{
  static char ret_path[PATH_MAX+1];

  if (!*ret_path) {
    struct stat st;
    const char *base_path;

    /* base hierarchial path */
    base_path = get_libshare_path();
    if (0 != stat(base_path, &st))
      mkdir(base_path, 0777);

    /* block-chain module */
    sprintf(ret_path, "%s/blockchain", base_path);
    if (0 != stat(ret_path, &st))
      mkdir(ret_path, 0700);
  }

  return ((const char *)ret_path);
}

void bc_idle(bc_t *bc)
{
  bc_map_t *map;
  int i;

  if (bc_lock()) {
    for (i = 0; i < bc->data_map_len; i++) {
      map = bc->data_map + i;
      if (map->fd != 0) {
        if (bc_map_idle(bc, map) == 0)
          break; /* one at a time */
      }
    }
    bc_unlock();
  }

}

uint32_t bc_journal(int pos)
{
  return ( (pos / BC_BLOCKS_PER_JOURNAL) + 1 );
}

int bc_clear(bc_t *bc, bcsize_t pos)
{
  bc_idx_t idx;
  int err;

  err = bc_idx_get(bc, pos, &idx);
  if (err)
    return (err);

  err = bc_arch_add(bc, &idx);
  if (err)
    return (err);

  err = bc_idx_clear(bc, pos);
  if (err)
    return (err);

  return (0);
}


static int _bc_arch_write(bc_t *bc, bc_hash_t hash, void *raw_data, int data_len)
{
  unsigned char *data = (unsigned char *)raw_data;
  bcsize_t pos;
  bc_idx_t idx;
  bc_map_t *map;
  char ext[64];
  int jrnl;
  int err;

  /* use last journal */
  jrnl = bc_journal(bc_idx_next(bc));

  err = bc_alloc(bc, jrnl);
  if (err)
    return (err);

  map = bc->data_map + jrnl;
  if (!*map->ext)
    sprintf(map->ext, "%u", idx.jrnl);

  /* finialize block index */
  memset(&idx, 0, sizeof(idx));
  idx.jrnl = jrnl;
  idx.size = data_len;
  idx.of = map->hdr->of;
  idx.crc = shcrc32(data, data_len);
  memcpy(idx.hash, hash, sizeof(bc_hash_t));

  /* store serialized block data */
  err = bc_map_append(bc, map, data, data_len);
  if (err < 0)
    return (err);

  /* store archived block index */
  err = bc_arch_add(bc, &idx);
  if (err < 0)
    return (err);

  return (0);
}

int bc_arch_write(bc_t *bc, bc_hash_t hash, void *raw_data, int data_len)
{
  int err;

  if (!bc_lock())
    return (SHERR_NOLCK);

  err = _bc_arch_write(bc, hash, raw_data, data_len);
  bc_unlock();

  return (err);
}




/**
 * Opens a specific database of block records.
 */
bc_t *GetBlockChain(CIface *iface)
{
  int err;

  if (!iface->bc_block) {
    char name[256];

    sprintf(name, "%s_block", iface->name);
    err = bc_open(name, &iface->bc_block);
#if 0
if (err) {
fprintf(stderr, "DEBUG: GetBlockChain: %d = bc_open(\"%s\")\n", err, name);
return (NULL); /* DEBUG: */
}
#endif
  }

  return (iface->bc_block);
}


/**
 * Opens a specific database of block references. 
 */
bc_t *GetBlockTxChain(CIface *iface)
{
  int err;

  if (!iface->bc_tx) {
    char name[256];

    sprintf(name, "%s_tx", iface->name);
    err = bc_open(name, &iface->bc_tx);
#if 0
if (err) {
fprintf(stderr, "DEBUG: GetBlockTxChain: %d = bc_open(\"%s\")\n", err, name);
return (NULL); /* DEBUG: */
}
#endif
  }

  return (iface->bc_tx);
}

bc_t *GetBlockCoinChain(CIface *iface)
{

  if (!iface->bc_coin) {
    char name[4096];

    sprintf(name, "%s_coin", iface->name);
    bc_open(name, &iface->bc_coin);
  }

  return (iface->bc_coin);
}

static void _bc_chain_idle(void)
{
  CIface *iface;
  bc_t *bc;
  int ifaceIndex;

  for (ifaceIndex = 0; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
    iface = GetCoinByIndex(ifaceIndex);
    if (!iface || !iface->enabled)
      continue;

    bc = GetBlockChain(iface);
    if (bc)
      bc_idle(bc);

    bc = GetBlockTxChain(iface);
    if (bc)
      bc_idle(bc);

    bc = GetBlockCoinChain(iface);
    if (bc)
      bc_idle(bc);
  }
}

void bc_chain_idle(void)
{
  bc_lock();
  _bc_chain_idle();
  bc_unlock();
}
