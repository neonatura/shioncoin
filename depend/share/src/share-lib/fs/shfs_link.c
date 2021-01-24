
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




int shfs_link(shfs_ino_t *parent, shfs_ino_t *inode)
{
  shfs_block_t nblk;
  int err;

  if (!parent) {
    PRINT_RUSAGE("shfs_inode_link: null parent");
    return (SHERR_NOENT);
  }

  if (!IS_INODE_CONTAINER(parent->blk.hdr.type)) {
    PRINT_RUSAGE("shfs_inode_link: non-container parent.");
    return (SHERR_NOTDIR);
  }

  err = shfs_link_find(parent, &inode->blk.hdr.name, NULL);
  if (err == 0) {
    /* link already exists. */
    return (0);
  }

  /* assign 'next inode' reference to child. */
  memset(&nblk, 0, sizeof(nblk));
  if (parent->blk.hdr.fpos.ino) {
    /* read first block of inode list */
    err = shfs_inode_read_block(parent->tree, &parent->blk.hdr.fpos, &nblk);
    if (err)
      return (err);
  }
  memcpy(&inode->blk.hdr.npos, &nblk.hdr.pos, sizeof(shfs_idx_t));

  /* create position in partition for inode. */
  memset(&inode->blk.hdr.pos, 0, sizeof(shfs_idx_t));
  err = shfs_journal_scan(parent->tree, &inode->blk.hdr.name, &inode->blk.hdr.pos);
  if (err)
    return (err);

  /* assign 'birth' timestamp */
  inode->blk.hdr.ctime = inode->blk.hdr.mtime = shtime();

  /* set checksum */
  inode->blk.hdr.crc = shfs_crc_init(&inode->blk);

  /* assign inode index */
  err = shfs_inode_write_block(parent->tree, &inode->blk);
  if (err)
    return (err);

  /* assign 'first data' index to parent. */
  memcpy(&parent->blk.hdr.fpos, &inode->blk.hdr.pos, sizeof(shfs_idx_t));
  err = shfs_inode_write_block(parent->tree, &parent->blk);
  if (err)
    return (err);

//  fprintf(stderr, "shfs_link:%s(parent):%s\n", shfs_inode_print(inode), shfs_inode_print(parent));

  return (0);
}

_TEST(shfs_inode_link)
{
  shfs_t *tree;
  shfs_ino_t *file;

  _TRUEPTR(tree = shfs_init(NULL));
  _TRUEPTR(tree->base_ino);
  if (!tree || !tree->base_ino)
    return;

  _TRUEPTR(file = shfs_inode(NULL, "sfs_inode_link", 0));
  _TRUE(!shfs_link(tree->base_ino, file));

  shfs_free(&tree);
}

#if 0
int shfs_inode_unlink(shfs_ino_t *inode)
{

  if (!inode->parent)
    return (0);

  return (0);
}
#endif

int shfs_link_find(shfs_ino_t *parent, shkey_t *key, shfs_block_t *ret_blk)
{
  shfs_block_t blk;
  shfs_hdr_t hdr;
  shfs_idx_t idx;
  size_t b_of;
  size_t b_max;
  int err;

  if (!parent) {
    return (SHERR_NOENT);
  }
  if (!IS_INODE_CONTAINER(parent->blk.hdr.type)) {
    PRINT_RUSAGE("shfs_inode_link_search: warning: non-container parent.");
    return (SHERR_INVAL);
  }

  /* find existing link */
  memcpy(&idx, &parent->blk.hdr.fpos, sizeof(shfs_idx_t));
  while (idx.ino) {
    memset(&blk, 0, sizeof(blk));
    err = shfs_inode_read_block(parent->tree, &idx, &blk);
    if (err)
      return (err);

    if (blk.hdr.npos.jno == idx.jno && blk.hdr.npos.ino == idx.ino) {
      return (SHERR_IO);
    }


    if (0 == memcmp(&blk.hdr.name, key, sizeof(shkey_t))) {
      /* found existing link with same name and type */
      if (ret_blk) {
        memcpy(ret_blk, &blk, sizeof(shfs_block_t));
      }

      return (0);
    } 

    memcpy(&idx, &blk.hdr.npos, sizeof(shfs_idx_t));
  }

  return (SHERR_NOENT);
}

int shfs_link_count(shfs_ino_t *parent)
{
  shfs_block_t blk;
  shfs_hdr_t hdr;
  shfs_idx_t idx;
  size_t b_of;
  size_t b_max;
  char tbuf[64];
  int ret_tot;
  int err;

  if (!parent) {
    return (SHERR_NOENT);
  }

  if (!IS_INODE_CONTAINER(parent->blk.hdr.type)) {
    PRINT_RUSAGE("shfs_inode_link_search: warning: non-container parent.");
    return (SHERR_INVAL);
  }

  ret_tot = 0;

  /* find existing link */
  memcpy(&idx, &parent->blk.hdr.fpos, sizeof(shfs_idx_t));
  while (idx.ino) {
    memset(&blk, 0, sizeof(blk));
    err = shfs_inode_read_block(parent->tree, &idx, &blk);
    if (err)
      return (err);

    if (blk.hdr.npos.jno == idx.jno && blk.hdr.npos.ino == idx.ino) {
      return (SHERR_IO);
    }

    if (blk.hdr.type != SHINODE_NULL) {
      ret_tot++;
    }

    memcpy(&idx, &blk.hdr.npos, sizeof(shfs_idx_t));
  }

  return (ret_tot);
}



