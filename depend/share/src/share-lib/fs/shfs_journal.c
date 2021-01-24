
/*
 *  Copyright 2013 Neo Natura 
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
*/  

#include "share.h"

/** An process-scope cache of shfs journals. */
static shfs_journal_t **journal_table;

static void _shfs_journal_free(shfs_journal_t *jrnl)
{
  if (!jrnl)
    return;
  shbuf_free(&jrnl->buff);
  free(jrnl);
}

static shfs_journal_t *_shfs_journal_cache_get(shfs_t *tree, int index)
{
  shfs_journal_t *jrnl;
  int cidx;

  if (!journal_table)
    return (NULL); /* no cache established */

  cidx = index % MAX_JOURNAL_CACHE_SIZE;
  jrnl = (shfs_journal_t *)journal_table[cidx];
  if (!jrnl)
    return (NULL);

  if (!shkey_cmp(shpeer_kpriv(&tree->peer), &jrnl->fs_key))
    return (NULL);

  if (jrnl->index != index)
    return (NULL);

  return (jrnl);
}

static void _shfs_journal_cache_set(shfs_t *tree, int index, shfs_journal_t *jrnl)
{
  shfs_journal_t *j_prev;
  shfs_journal_t *j_next;
  shfs_journal_t *j;
  shfs_journal_t *c_jrnl;
  shtime_t expire;
  int cidx;
  int tot;

  if (!jrnl)
    return;

  if (!journal_table) {
    journal_table = (shfs_journal_t **)calloc(MAX_JOURNAL_CACHE_SIZE, sizeof(shfs_journal_t *));
    if (!journal_table)
      return;
  }

  cidx = index % MAX_JOURNAL_CACHE_SIZE;
  j = (shfs_journal_t *)journal_table[cidx];
  if (j) {
    if (j == jrnl)
      return;

    _shfs_journal_free(j);
  }
  journal_table[cidx] = jrnl;

  /* identify partition */
  memcpy(&jrnl->fs_key, shpeer_kpriv(&tree->peer), sizeof(shkey_t));
}

void shfs_journal_cache_free(shfs_t *tree)
{
  shfs_journal_t *j;
  int idx;

  if (!journal_table)
    return;

  for (idx = 0; idx < MAX_JOURNAL_CACHE_SIZE; idx++) {
    j = journal_table[idx];
    if (!j) continue;

    journal_table[idx] = NULL;
    _shfs_journal_free(j);
  }

  free(journal_table);
  journal_table = NULL;
}

void shfs_journal_path(shfs_t *tree, int index, char *ret_path)
{
  struct stat st;

  if (!ret_path)
    return;

  *ret_path = '\000';

  if (!tree)
    return;
  if (index < 0 || index >= SHFS_MAX_JOURNAL)
    return;

  sprintf(ret_path, "%s/fs", get_libshare_path());
#if 0
  if (0 != stat(ret_path, &st)) {
    mkdir(ret_path, 0777);
    chown(ret_path, 0, 0);
  }
#endif

  sprintf(ret_path+strlen(ret_path), "/_%x",
      shcrc(shpeer_kpub(&tree->peer), sizeof(shkey_t)));
  if (0 != stat(ret_path, &st)) {
    mkdir(ret_path, 0777);
    chown(ret_path, 0, 0);
  }

  sprintf(ret_path + strlen(ret_path), "/_%u", (unsigned int)index);
}


shfs_journal_t *shfs_journal_open(shfs_t *tree, int index)
{
  shfs_journal_t *j;
  struct stat st;
  ssize_t len;
  char *path;
  char *data;
  int err;

  if (!tree) {
    PRINT_RUSAGE("shfs_journal_open: null partition.");
    return (NULL); /* all done */
  }

  j = _shfs_journal_cache_get(tree, index);
  if (j)
    return (j);

  j = (shfs_journal_t *)calloc(1, sizeof(shfs_journal_t));
  if (!j) {
    PRINT_RUSAGE("shfs_journal_open: memory allocation error (1).");
    return (NULL); /* woop woop */
  }

//  j->tree = tree;
  j->index = index;

  shfs_journal_path(tree, index, j->path);
  _shfs_journal_cache_set(tree, index, j);

  return (j);
}

_TEST(shfs_journal_open)
{
  shfs_t *tree;
  shfs_journal_t *jrnl;
  int jno;

  _TRUEPTR(tree = shfs_init(NULL));
  if (!tree)
    return;

  for (jno = 0; jno < SHFS_MAX_JOURNAL; jno += 333) {
    jrnl = shfs_journal_open(tree, jno);    
    _TRUEPTR(jrnl);
    _TRUE(jrnl->index == jno);
    shfs_journal_close(&jrnl);
  }

  shfs_free(&tree);

}

int shfs_journal_close(shfs_journal_t **jrnl_p)
{
  shfs_journal_t *jrnl;

  if (!jrnl_p)
    return (0);

  jrnl = *jrnl_p;
  if (!jrnl)
    return (0);

  /* mark as used */
  jrnl->stamp = shtime();

  return (0);
}

int _shfs_journal_scan(shfs_t *tree, int jno, shfs_idx_t *idx)
{
  int crc;
  shfs_journal_t *jrnl;
  shfs_block_t *blk;
  ssize_t jlen;
  int ino_max;
  int ino_min;
  int ino_nr;
  int err;

  jrnl = shfs_journal_open(tree, jno);
  if (!jrnl) {
    return (SHERR_IO);
  }

  jlen = shfs_journal_size(jrnl);
  if (jlen <= 0)
    return (jlen);

retry:
  //ino_max = MIN(jlen / SHFS_MAX_BLOCK_SIZE, SHFS_MAX_BLOCK);
  ino_max = jlen / SHFS_MAX_BLOCK_SIZE;
  //
  //ino_min = jno ? 0 : 1; 
  ino_min = 1;

  for (ino_nr = (ino_max - 1); ino_nr >= ino_min; ino_nr--) {
    blk = (shfs_block_t *)shfs_journal_block(jrnl, ino_nr);
    if (!blk) {
      /* critical error reading shfs journal */
      shfs_journal_close(&jrnl);
      return (SHERR_IO);    
    }
    if (!blk->hdr.type)
      break; /* found empty inode */
  }

  if (ino_nr < ino_min) {
    if (ino_max >= SHFS_MAX_BLOCK)
      return (SHERR_NOSPC); /* ran out of space on journal (~225megs) */
 
    jlen = MAX(SHARE_PAGE_SIZE, jlen) * 2;
    err = shbuf_growmap(jrnl->buff, jlen);
    if (!err)
      goto retry;

//fprintf(stderr, "DEBUG: shfs_journal_scan: error creating inode [max %d] [jlen %u]\n", ino_max, jlen); 
    return (err);
  }

  err = shfs_journal_close(&jrnl);
  if (err)
    return (err);

  if (idx) {
    idx->jno = jno;
    idx->ino = ino_nr;
  } 

  return (0);
}

int shfs_journal_scan(shfs_t *tree, shkey_t *key, shfs_idx_t *idx)
{
  return (_shfs_journal_scan(tree, key ? shfs_journal_index(key) : 0, idx));
}

shfs_block_t *shfs_journal_block(shfs_journal_t *jrnl, int ino)
{
  size_t data_of;
  int err;

  if (ino < 0)
    return (NULL);

  /* establish memory map */
  if (!jrnl->buff) {
    jrnl->buff = shbuf_file(jrnl->path);
    if (!jrnl->buff)
      return (NULL);
//    chmod(jrnl->path, 0777);
    chown(jrnl->path, 0, 0);
  }

  data_of = (ino * SHFS_MAX_BLOCK_SIZE);
  if (data_of >= SHFS_MAX_JOURNAL_SIZE)
    return (NULL);

  /* expand journal as neccessary */
  if (data_of > jrnl->buff->data_max) {
    err = shbuf_grow(jrnl->buff, data_of); 
    if (err)
      return (NULL);
  }

  return ((shfs_block_t *)(jrnl->buff->data + data_of));
}

size_t shfs_journal_size(shfs_journal_t *jrnl)
{

  /* establish memory map */
  if (!jrnl->buff) {
    jrnl->buff = shbuf_file(jrnl->path);
    if (!jrnl->buff)
      return (0);
    chmod(jrnl->path, 0777);
    chown(jrnl->path, 0, 0);
  }

  return (jrnl->buff->data_of);
}

int shfs_journal_index(shkey_t *key)
{
  shfs_inode_off_t of;

  of = shcrc(key, sizeof(shkey_t));
  of = (of % (SHFS_MAX_JOURNAL - 1)) + 1;

  return (of);
}


