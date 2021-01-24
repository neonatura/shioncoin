

/*
 * @copyright
 *
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
 *
 *  @endcopyright
 */

#include "share.h"




int shfs_aux_write_deprec(shfs_ino_t *inode, shbuf_t *buff)
{
  shfs_block_t blk;
  shfs_block_t nblk;
  shfs_idx_t *idx;
  shkey_t *key;
  size_t b_len;
  size_t b_of;
  uint64_t seg_crc;
  int err;
  int jno;

  if (!buff)
    return (0);

  b_of = 0;
  idx = &inode->blk.hdr.fpos; /* first data segment of inode */

  memset(&blk, 0, sizeof(blk));
  if (!idx->ino) {
    /* create first block. */
    err = shfs_journal_scan(inode->tree, &inode->blk.hdr.name, idx);
    if (err)
      return (err);

    blk.hdr.type = SHINODE_AUX;
    memcpy(&blk.hdr.pos, idx, sizeof(shfs_idx_t));
    blk.hdr.ctime = shtime();

    key = shkey_bin((char *)&inode->blk, sizeof(shfs_block_t));
    memcpy(&blk.hdr.name, key, sizeof(shkey_t)); 
    shkey_free(&key);
  } else {
    /* read in existing initial data segment. */
    err = shfs_inode_read_block(inode->tree, idx, &blk);
    if (err)
      return (err);
  }

  seg_crc = 0;
  while (blk.hdr.pos.ino) {
    b_len = MIN(SHFS_BLOCK_DATA_SIZE, buff->data_of - b_of);

    idx = &blk.hdr.npos;
    memset(&nblk, 0, sizeof(nblk));

    /* retrieve next block reference. */
    if (!idx->ino) {
      /* create new block if data pending */
      if ((b_of + b_len) < buff->data_of) {
        err = shfs_journal_scan(inode->tree, &blk.hdr.name, idx);
        if (err)  
          return (err);

        nblk.hdr.type = SHINODE_AUX;
        memcpy(&nblk.hdr.pos, idx, sizeof(shfs_idx_t));
        nblk.hdr.ctime = shtime();

        key = shkey_bin((char *)&blk, sizeof(shfs_block_t));
        memcpy(&nblk.hdr.name, key, sizeof(shkey_t)); 
        shkey_free(&key);
      }
    } else {
      err = shfs_inode_read_block(inode->tree, idx, &nblk);
      if (err)
        return (err);
    }

    memset(blk.raw, 0, SHFS_BLOCK_DATA_SIZE);
    if (b_len) {
      memcpy(blk.raw, buff->data + b_of, b_len);
    }

    blk.hdr.size = b_len;
    blk.hdr.crc = shfs_crc_init(&blk);
    seg_crc += blk.hdr.crc;

    err = shfs_inode_write_block(inode->tree, &blk);
    if (err)
      return (err);

    b_of += b_len;
    memcpy(&blk, &nblk, sizeof(shfs_block_t));
  }

  /* write the inode to the parent directory */
  inode->blk.hdr.crc = seg_crc;
  inode->blk.hdr.size = buff->data_of;
  err = shfs_inode_write_entity(inode); 
  if (err) {
    PRINT_RUSAGE("shfs_inode_write: error writing entity.");
    return (err);
  }

  return (0);
}

static int shfs_aux_pwrite_create(shfs_ino_t *inode, shfs_block_t *blk, shfs_block_t *nblk, shfs_idx_t *idx)
{
  shkey_t *key;
  int err;

  err = shfs_journal_scan(inode->tree, &blk->hdr.name, idx);
  if (err)  
    return (err);

  nblk->hdr.type = SHINODE_AUX;
  memcpy(&nblk->hdr.pos, idx, sizeof(shfs_idx_t));
  nblk->hdr.ctime = shtime();

  key = shkey_bin((char *)blk, sizeof(shfs_block_t));
  memcpy(&nblk->hdr.name, key, sizeof(shkey_t)); 
  shkey_free(&key);

  return (0);
}

static void shfs_aux_pwrite_block(shfs_block_t *blk, shbuf_t *buff, off_t data_of, size_t data_len, off_t *write_of, size_t seek_of)
{
  size_t r_len;
  size_t w_len;
  off_t r_of;
  off_t w_of;

  if (!shbuf_data(buff))
    return; /* 06/08/15 */

  r_len = data_len;
  r_of = data_of;

  w_of = 0;
  w_len = r_len;

  if (*write_of + r_len < seek_of) {
    /* not past initial seek offset. */
    *write_of += r_len;
    return;
  }

  if (*write_of < seek_of) {
    /* partial buffer write. */
    w_of = seek_of - *write_of;
    w_len = r_len - w_of;
  }
  *write_of += r_len;

//  memset(blk->raw + w_of, 0, SHFS_BLOCK_DATA_SIZE - w_of);
  if (w_len) {
    memcpy(blk->raw + w_of, buff->data + r_of + w_of, w_len);
  }

}

int shfs_aux_pwrite(shfs_ino_t *inode, shbuf_t *buff, 
    off_t seek_of, size_t seek_max)
{
  shfs_block_t blk;
  shfs_block_t nblk;
  shfs_block_t oblk;
  shfs_idx_t *idx;
  shkey_t *key;
  size_t b_len;
  size_t b_of;
  uint64_t seg_crc;
  off_t wof;
  int err;
  int jno;

  if (!buff)
    return (0);

  b_of = 0;
  idx = &inode->blk.hdr.fpos; /* first data segment of inode */

  memset(&blk, 0, sizeof(blk));
  memset(&oblk, 0, sizeof(oblk));
  if (!idx->ino) {
    /* create first block. */
    err = shfs_journal_scan(inode->tree, &inode->blk.hdr.name, idx);
    if (err)
      return (err);

    blk.hdr.type = SHINODE_AUX;
    memcpy(&blk.hdr.pos, idx, sizeof(shfs_idx_t));
    blk.hdr.ctime = shtime();

    key = shkey_bin((char *)&inode->blk, sizeof(shfs_block_t));
    memcpy(&blk.hdr.name, key, sizeof(shkey_t)); 
    shkey_free(&key);
  } else {
    /* read in existing initial data segment. */
    err = shfs_inode_read_block(inode->tree, idx, &blk);
    if (err)
      return (err);

    memcpy(&oblk, &blk, sizeof(shfs_block_t));
  }

  wof = 0;
  seg_crc = 0;
  while (blk.hdr.pos.ino) {
    b_len = MIN(SHFS_BLOCK_DATA_SIZE, buff->data_of - b_of);

    idx = &blk.hdr.npos;
    memset(&nblk, 0, sizeof(nblk));

    /* retrieve next block reference. */
    if (!idx->ino) {
      /* create new block if data pending */
      if ((b_of + b_len) < buff->data_of) {
        err = shfs_aux_pwrite_create(inode, &blk, &nblk, idx);
        if (err)
          return (err);
#if 0
        err = shfs_journal_scan(inode->tree, &blk.hdr.name, idx);
        if (err)  
          return (err);

        nblk.hdr.type = SHINODE_AUX;
        memcpy(&nblk.hdr.pos, idx, sizeof(shfs_idx_t));
        nblk.hdr.ctime = shtime64();

        key = shkey_bin((char *)&blk, sizeof(shfs_block_t));
        memcpy(&nblk.hdr.name, key, sizeof(shkey_t)); 
        shkey_free(&key);
#endif
      }
    } else {
      err = shfs_inode_read_block(inode->tree, idx, &nblk);
      if (err)
        return (err);
    }

    shfs_aux_pwrite_block(&blk, buff, b_of, b_len, &wof, seek_of);

    /* write block to mem map */
    blk.hdr.size = b_len;
    blk.hdr.crc = 0;
    blk.hdr.crc = shfs_crc_init(&blk);

    /* calculate entire file's checksum. */
    seg_crc += blk.hdr.crc;

    if (0 != memcmp(&oblk, &blk, sizeof(shfs_block_t))) {
      err = shfs_inode_write_block(inode->tree, &blk);
      if (err) {
        return (err);
      }
    }

    /* prepare for next block. */
    b_of += b_len;
    memcpy(&blk, &nblk, sizeof(shfs_block_t));
    memcpy(&oblk, &blk, sizeof(shfs_block_t));
  }

  /* write the inode to the parent directory */
  inode->blk.hdr.crc = seg_crc;
  inode->blk.hdr.size = buff->data_of;
/* DEBUG: TODO: */
 // inode->blk.hdr.format = SHINODE_AUX;
  err = shfs_inode_write_entity(inode); 
  if (err) {
    PRINT_RUSAGE("shfs_inode_write: error writing entity.");
    return (err);
  }

  return (0);
}

int shfs_aux_write(shfs_ino_t *inode, shbuf_t *buff)
{
  return (shfs_aux_pwrite(inode, buff, 0, 0));
}

int shfs_aux_read_deprec(shfs_ino_t *inode, shbuf_t *ret_buff)
{
  shfs_hdr_t hdr;
  shfs_block_t blk;
  shfs_idx_t idx;
  size_t blk_max;
  size_t blk_nr;
  size_t b_of;
  size_t b_len;
  size_t data_len;
  size_t data_max;
  int err;

  data_len = inode->blk.hdr.size;

  b_of = 0;
  memcpy(&idx, &inode->blk.hdr.fpos, sizeof(shfs_idx_t));
  while (idx.ino) {
    memset(&blk, 0, sizeof(blk)); 
    err = shfs_inode_read_block(inode->tree, &idx, &blk);
    if (err)
      return (err);

    b_len = MIN(SHFS_BLOCK_DATA_SIZE, data_len - b_of);
    shbuf_cat(ret_buff, blk.raw, b_len);

    b_of += b_len;
    memcpy(&idx, &blk.hdr.npos, sizeof(shfs_idx_t));
  }

  return (0);
}

int shfs_aux_pread(shfs_ino_t *inode, shbuf_t *ret_buff, 
    off_t seek_of, size_t seek_max)
{
  shfs_hdr_t hdr;
  shfs_block_t blk;
  shfs_idx_t idx;
  size_t blk_max;
  size_t blk_nr;
  size_t b_of;
  size_t b_len;
  size_t data_len;
  size_t r_len;
  off_t r_of;
  int err;

  data_len = inode->blk.hdr.size;

  if (seek_of && seek_of >= data_len)
    return (0); /* all done */

  b_of = 0;
  memcpy(&idx, &inode->blk.hdr.fpos, sizeof(shfs_idx_t));
  while (idx.ino) {
    memset(&blk, 0, sizeof(blk)); 
    err = shfs_inode_read_block(inode->tree, &idx, &blk);
    if (err)
      return (err);

    b_len = MIN(SHFS_BLOCK_DATA_SIZE, data_len - b_of);
    if (!seek_of || b_of >= seek_of) {
      size_t len = b_len;
      /* full buffer read */
      if ((ret_buff->flags & SHBUF_FMAP) &&
          (ret_buff->data_max - ret_buff->data_of) < b_len) {
        len = MIN(b_len, (ret_buff->data_max - ret_buff->data_of)); 
      }
      shbuf_cat(ret_buff, (unsigned char *)blk.raw, len);
    } else if (seek_of && (b_of + b_len) >= seek_of) {
      /* partial buffer read */
      r_len = MIN(b_len, (b_of+b_len) - seek_of);
      r_of = b_len - r_len;
      if (seek_max && r_len > (seek_max - shbuf_size(ret_buff)))
        r_len = seek_max  - shbuf_size(ret_buff);
      shbuf_cat(ret_buff, (unsigned char *)blk.raw + r_of, r_len);
    }

    b_of += b_len;
    memcpy(&idx, &blk.hdr.npos, sizeof(shfs_idx_t));

    /* break out if we have exceeded the max size */
    if (seek_max && seek_max + seek_of < b_of)
      break;
  }

  return (0);
}

_TEST(shfs_aux_pread)
{
  shpeer_t *peer;
  shfs_t *tree;
  shfs_ino_t *inode;
  shfs_ino_t *aux;
  shbuf_t *buff;
  char *test_data;
  int err;

  test_data = (char *)calloc(10240, sizeof(char));
  _TRUEPTR(test_data);
  memset(test_data + 4096, '\001', 4096);

  peer = shpeer_init("test", NULL);

  /* write test file */
  tree = shfs_init(peer);
  _TRUEPTR(tree);
  inode = shfs_file_find(tree, "/aux_pread"); 

  /* write an empty buffer */
  buff = shbuf_init();
  _TRUE(0 == shfs_write(inode, buff));
  shbuf_free(&buff);

  /* write test buffer */
  buff = shbuf_init();
  shbuf_cat(buff, test_data, 10240);
  _TRUE(0 == shfs_write(inode, buff));
  shbuf_free(&buff);

  /* cached file read */
  buff = shbuf_init();
  _TRUE(0 == shfs_read(inode, buff));
  _TRUE(shbuf_size(buff) == 10240);
  _TRUE(0 == memcmp(shbuf_data(buff), test_data, 10240));
  shbuf_free(&buff);

  shfs_free(&tree);

  /* full [non-cached] file read */
  tree = shfs_init(peer);
  _TRUEPTR(tree);
  inode = shfs_file_find(tree, "/aux_pread"); 
  buff = shbuf_init();
  _TRUE(0 == shfs_read(inode, buff));
  _TRUE(shbuf_size(buff) == 10240);
  _TRUE(0 == memcmp(shbuf_data(buff), test_data, 10240));
  shbuf_free(&buff);
  shfs_free(&tree);

  free(test_data);
  shpeer_free(&peer);
}

int shfs_aux_read(shfs_ino_t *inode, shbuf_t *ret_buff)
{
  return (shfs_aux_pread(inode, ret_buff, 0, 0));
}


ssize_t shfs_aux_pipe(shfs_ino_t *inode, int fd)
{
  shfs_t *tree = inode->tree;
  char hier[NAME_MAX + 1];
  char dir[NAME_MAX + 1];
  char *n_tok;
  char *tok;
  char *data;
  size_t data_len;
  shbuf_t *buff;
  ssize_t b_len;
  ssize_t b_of;
  int err;

  buff = shbuf_init();
  err = shfs_aux_read(inode, buff);
  if (err == -1) {
    shbuf_free(&buff);
    return (err);
  }

  for (b_of = 0; b_of < buff->data_of; b_of++) {
    b_len = write(fd, buff->data + b_of, buff->data_of - b_of);
    if (b_len < 1)
      return (b_len);
    b_of += b_len;
  }

  shbuf_free(&buff);

//  printf ("Wrote %lu bytes to file descriptor %d.\n", (unsigned long)data_len, fd);

  return (0);
}

#if 0
uint64_t shfs_aux_crc(shfs_ino_t *inode)
{
  shfs_hdr_t hdr;
  shfs_block_t blk;
  shfs_idx_t idx;
  uint64_t crc;
  int err;
  int i;

  crc = 0;
  memcpy(&idx, &inode->blk.hdr.fpos, sizeof(shfs_idx_t));
  while (idx.ino) {
    memset(&blk, 0, sizeof(blk)); 
    err = shfs_inode_read_block(inode->tree, &idx, &blk);
    if (err)
      return (err);

    crc += blk.hdr.crc;

    memcpy(&idx, &blk.hdr.npos, sizeof(shfs_idx_t));
  }

  return (crc);
}
#endif


