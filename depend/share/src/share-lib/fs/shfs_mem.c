
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

int shfs_mem_read(char *path, shbuf_t *buff)
{
  FILE *fl;
  struct stat st;
  size_t data_len;
  ssize_t r_len;
  char inbuff[4096];
  char *data;
  int r_of;
  int err;

  if (!path || !buff)
    return (SHERR_INVAL);

  memset(&st, 0, sizeof(st));
  err = stat(path, &st);
  if (err) {
    return (errno2sherr());
	}

  if (st.st_size == 0) {
    return (0);
	}

  if (S_ISDIR(st.st_mode)) {
    return (SHERR_ISDIR);
	}

  fl = fopen(path, "rb");
  if (!fl) {
    free(data);
    return (errno2sherr());
  }

  r_of = 0;
  while (r_of < st.st_size) {
    r_len = fread(inbuff, sizeof(char), sizeof(inbuff), fl);
    if (r_len < 0) {
      return (errno2sherr());
		}

    shbuf_cat(buff, inbuff, r_len);
    r_of += r_len;
  }

  err = fclose(fl);
  if (err) {
    return (errno2sherr());
	}

  return (0);
}

int shfs_read_mem(char *path, char **data_p, size_t *data_len_p)
{
  shbuf_t *buff;
  size_t data_len;
  int err;

  buff = shbuf_init();
  err = shfs_mem_read(path, buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }

  data_len = shbuf_size(buff);
  if (data_len_p) {
    *data_len_p = data_len;
  }
  if (data_p) {
    *data_p = shbuf_unmap(buff);
  } else {
    shbuf_free(&buff);
  }

  return (0);
}

int shfs_mem_write(char *path, shbuf_t *buff)
{
  FILE *fl;
  char hier[NAME_MAX + 1];
  char dir[NAME_MAX + 1];
  char *n_tok;
  char *tok;
  ssize_t b_of;
  ssize_t b_len;
  ssize_t len;
  int err;

  if (*path != '/') {
    /* recursive dir generation for relative paths. */
    memset(hier, 0, sizeof(hier));
    strncpy(hier, path, sizeof(hier) - 1); 
    tok = strtok(hier, "/");
    while (tok) {
      n_tok = strtok(NULL, "/");
      if (!n_tok)
        break;

      strcat(dir, tok);
      strcat(dir, "/");
      mkdir(dir, 0777);
      tok = n_tok;
    }
  }

  fl = fopen(path, "wb");
  if (!fl) {
		return (errno2sherr());
	}

  b_of = 0;
  while (b_of < shbuf_size(buff)) {
    len = MIN(65536, (shbuf_size(buff) - b_of));
    b_len = fwrite(shbuf_data(buff) + b_of, sizeof(char), len, fl);
    if (b_len < 0)
      return (errno2sherr());

    b_of += b_len;
  }

  err = fclose(fl);
  if (err) {
		return (errno2sherr());
	}

  return (0);
}

int shfs_write_mem(char *path, void *data, size_t data_len)
{
  shbuf_t *buff;
  int err;

  buff = shbuf_map(data, data_len);
  err = shfs_mem_write(path, buff);
  shbuf_unmap(buff);

  return (err);
}


