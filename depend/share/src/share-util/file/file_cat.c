
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
#include "sharetool.h"


int share_file_cat(char *path, int pflags)
{
  shstat st;
  shfs_t *tree;
  shfs_ino_t *file;
  shbuf_t *buff;
  char fpath[PATH_MAX+1];
  unsigned char *data;
  size_t data_len;
  size_t of;
  int w_len;
  int err;

  tree = shfs_uri_init(path, 0, &file);
  if (!tree)
    return (SHERR_NOENT);

  err = shfs_fstat(file, &st);
  if (err) {
    shfs_free(&tree);
    return (err);
  }

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err) {
    shbuf_free(&buff);
    shfs_free(&tree);
    return (err);
  }

  of = 0;
  while (of < shbuf_size(buff)) {
    data_len = MIN((shbuf_size(buff) - of), 65536);
    data = shbuf_data(buff) + of;
    w_len = fwrite(data, sizeof(char), data_len, sharetool_fout);
    if (w_len < 0) {
      shbuf_free(&buff);
      shfs_free(&tree);
      return (-errno);
    }

    of += w_len;
  }

  shbuf_free(&buff);
  shfs_free(&tree);

  return (0);
}

