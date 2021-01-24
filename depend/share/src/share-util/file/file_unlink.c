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




int share_file_remove(char **args, int arg_cnt, int pflags)
{
  struct stat st;
  shfs_t *tree;
  shfs_ino_t *file;
  shbuf_t *buf;
  char fpath[PATH_MAX+1];
  char *data;
  size_t data_len;
  int err;
  int i;

  for (i = 1; i < arg_cnt; i++) {
    if (!*args[i] || 0 == strcmp(args[i], "/"))
      continue;

    tree = shfs_uri_init(args[i], 0, &file);
    if (!tree)
      return (SHERR_NOENT);

    err = shfs_fstat(file, &st);
    if (err) {
      fprintf(stderr, "%s: cannot remove %s: %s\n", 
        process_path, args[i], sherrstr(err));
      shfs_free(&tree);
      return (err);
    }

    if (!(pflags & PFLAG_RECURSIVE) &&
        shfs_type(file) == SHINODE_DIRECTORY) {
      err = SHERR_ISDIR;
      fprintf(stderr, "%s: cannot remove %s: %s\n", 
        process_path, args[i], sherrstr(err));
      shfs_free(&tree);
      return (err);
    }

    err = shfs_file_remove(file);
    if (err) {
      fprintf(stderr, "%s: cannot remove %s: %s\n", 
        process_path, args[i], sherrstr(err));
      shfs_free(&tree);
      return (err);
    }

    printf ("\tremoved %s\n", shfs_filename(file));
    shfs_free(&tree);
  }

  return (0);
}

