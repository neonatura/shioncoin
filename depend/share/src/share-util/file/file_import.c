/*
 *  Copyright 2013 Brian Burrell 
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


int share_file_import_file(char *path, int pflags)
{
  struct stat st;
  shfs_t *tree;
  shfs_ino_t *file;
  shbuf_t *buf;
  char fpath[PATH_MAX+1];
  char *data;
  size_t data_len;
  int err;

  data = NULL;
  tree = NULL;

  err = shfs_read_mem(path, &data, &data_len);
  if (err) {
    err = -errno;
    perror(path);
    goto done;
  }

  tree = shfs_init(NULL);
  if (!tree) {
    err = SHERR_IO;
    perror("shfs_init");
    goto done;
  }

  file = shfs_file_find(tree, path);
  if (!file) {
    err = SHERR_NOENT;
    perror(path);
    goto done;
  }
  if (file->blk.hdr.type == SHINODE_DIRECTORY) {
    err = SHERR_ISDIR;
    goto done;
  }

  buf = shbuf_init();
  shbuf_cat(buf, data, data_len);
  err = shfs_write(file, buf);
  shbuf_free(&buf);
  if (err)
    goto done;

  err = 0;
  printf ("[%s]\n", data_len, shfs_inode_print(file));

done:
  if (data)
    free(data);
  shfs_free(&tree);

  return (err);
}

int share_file_import(char *in_path, int pflags)
{
  struct stat st;
  char path[PATH_MAX+1];
  char cur_path[PATH_MAX+1];
  DIR *dir;
  struct dirent *ent;
  int err;


  err = stat(in_path, &st);
  if (err) {
    perror(path);
    return (err);
  }

  if (S_ISDIR(st.st_mode)) { 
    memset(path, 0, sizeof(path));
    strncpy(path, in_path, sizeof(path) - 1);
    if (path[strlen(path) - 1] == '/')
      path[strlen(path) - 1] = '\0';

    dir = opendir(path);
    while ((ent = readdir(dir))) {
      if (0 == strcmp(ent->d_name, ".") ||
          0 == strcmp(ent->d_name, ".."))
        continue;

      sprintf(cur_path, "%s/%s", path, ent->d_name);
      err = share_file_import(cur_path, pflags);
      if (err) {
        perror(path);
        return (err);
      }
    }
    closedir(dir);
  } else {
    memset(path, 0, sizeof(path));
    strncpy(path, in_path, sizeof(path) - 1);
    err = share_file_import_file(path, pflags);
    if (err) {
      perror(path);
      return (err);
    }
  }

  return (0);
}

