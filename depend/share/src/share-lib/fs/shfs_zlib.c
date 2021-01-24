
/*
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
*/  

#include "share.h"

int shfs_zlib_read(shfs_ino_t *file, shbuf_t *buff)
{
  int err;
  shfs_ino_t *aux;

  if (file == NULL)
    return (SHERR_INVAL);

  if (shfs_format(file) != SHINODE_COMPRESS)
    return (SHERR_INVAL);

  aux = shfs_inode(file, NULL, SHINODE_COMPRESS);
  if (!aux)
    return (SHERR_IO);

  err = shfs_aux_read(aux, buff);
  if (err)
    return (err);

  return (0);
}

int shfs_zlib_write(shfs_ino_t *file, shbuf_t *buff)
{
  shfs_ino_t *aux;
  int err;

  if (!file)
    return (SHERR_INVAL);

  aux = shfs_inode(file, NULL, SHINODE_COMPRESS);
  if (!aux)
    return (SHERR_IO);

  err = shfs_aux_write(aux, buff);
  if (err)
    return (err);

  /* copy aux stats to file inode. */
  file->blk.hdr.mtime = aux->blk.hdr.mtime;
  file->blk.hdr.size = aux->blk.hdr.size;
  file->blk.hdr.crc = aux->blk.hdr.crc;
  file->blk.hdr.format = SHINODE_COMPRESS;

  return (0);
}

