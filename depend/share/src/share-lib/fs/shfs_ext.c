
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

#include "share.h"

int shfs_ext_read(shfs_ino_t *file, shbuf_t *buff)
{
  shfs_ino_t *ext;
  char *path;
  int err;

  if (!file)
    return (SHERR_INVAL);

  if (shfs_format(file) != SHINODE_EXTERNAL)
    return (SHERR_INVAL);

  ext = shfs_inode(file, NULL, SHINODE_EXTERNAL);
  if (!ext)
    return (SHERR_IO);

  path = (char *)ext->blk.raw;
  err = shfs_mem_read(path, buff);
  if (err)
    return (err);

  return (0);
}

int shfs_ext_write(shfs_ino_t *file, shbuf_t *buff)
{
  shfs_ino_t *ext;
  char *path;
  int err;

  if (file == NULL)
    return (SHERR_INVAL);

  if (shfs_format(file) != SHINODE_EXTERNAL)
    return (SHERR_INVAL);

  ext = shfs_inode(file, NULL, SHINODE_EXTERNAL);
  if (!ext)
    return (SHERR_IO);

  path = (char *)ext->blk.raw;
  err = shfs_mem_write(path, buff);
  if (err)
    return (err);

  return (0);
}

int shfs_ext_set(shfs_ino_t *file, const char *path)
{
  struct stat st;
  shfs_ino_t *ext;
  char fs_path[SHFS_PATH_MAX];
  int err;

  if (file == NULL || !path || !*path)
    return (SHERR_INVAL);

  err = stat(path, &st);
  if (err) {
    return (errno2sherr());
}

  ext = shfs_inode(file, NULL, SHINODE_EXTERNAL);
  if (!ext)
    return (SHERR_IO);

  memset(fs_path, 0, sizeof(fs_path));
  strncpy(fs_path, path, sizeof(fs_path) - 1);

  /* save local hard-drive path as inode data. */
  memset(ext->blk.raw, 0, SHFS_PATH_MAX);
  strcpy((char *)ext->blk.raw, fs_path);
  ext->blk.hdr.size = SHFS_PATH_MAX;
  ext->blk.hdr.crc = shcrc(fs_path, SHFS_PATH_MAX);
  err = shfs_inode_write_entity(ext);
  if (err)
    return (err);

  /* copy ext stats to file inode. */
  file->blk.hdr.mtime = ext->blk.hdr.mtime;
  file->blk.hdr.size = ext->blk.hdr.size;
  file->blk.hdr.crc = ext->blk.hdr.crc;
  file->blk.hdr.format = SHINODE_EXTERNAL;
  file->blk.hdr.attr |= SHATTR_LINK_EXT;

  return (0);
}

