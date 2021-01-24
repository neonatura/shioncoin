
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

int share_file_list_cb(shfs_ino_t *file, int *arg_p)
{
  int level = *arg_p;

  if (run_flags & PFLAG_VERBOSE) {
  fprintf(sharetool_fout, "%-*.*s%s\n", 
      level, level, "", shfs_inode_print(file));
  } else {
    fprintf(sharetool_fout, "%-*.*s%s\n", 
        level, level, "", shfs_filename(file));
  }

  return (0);
}

#if 0
int share_file_list_container(shfs_ino_t *file, int level, int pflags)
{
  int ent_tot;
  int i; 

  ent_tot = shfs_list_cb(file, NULL,
      (shfs_list_f *)&share_file_list_cb, &level);
  if (ent_tot < 0)
    return (ent_tot);

  return (0);
}
#endif

int share_file_list(char *path, int pflags)
{
  shfs_t *tree;
  shfs_ino_t *file;
  shfs_ino_t *dir;
  struct stat st;
  char *tok, tok_r;
  char dirpath[PATH_MAX+1];
  char fname[PATH_MAX+1];
  char buf[256];
  char *ptr;
  int level;
  int err;

  memset(fname, 0, sizeof(fname));
  strncpy(fname, basename(path), sizeof(fname)-1);

  memset(dirpath, 0, sizeof(dirpath));
  strncpy(dirpath, path, strlen(path) - strlen(fname));
   
  tree = shfs_uri_init(dirpath, 0, &file);
  if (!tree)
    return (SHERR_NOENT);

  err = shfs_fstat(file, &st);
  if (err) {
    fprintf(stderr, "%s: cannot access %s: %s\n",
      process_path, path, sherrstr(err));
    shfs_free(&tree);
    return (err);
  }

  level = 0;
  if ((pflags & PFLAG_VERBOSE)) {
    memset(buf, 0, sizeof(buf));
    if (file->tree)
      strcpy(buf, shpeer_print(&file->tree->peer));
    if (file->blk.hdr.type == SHINODE_DIRECTORY) {
      printf("[%s \"%s\" @ %s]\n",
          shfs_type_str(shfs_type(file)),
          shfs_filename(file), buf);
      level++;
    } else if (file->parent && IS_INODE_CONTAINER(file->blk.hdr.type)) {
      /* print parent header */
      printf("[%s \"%s\" @ %s]\n",
          shfs_type_str(shfs_type(file->parent)),
          shfs_filename(file->parent), buf);
      level++;
    }
  }

  shfs_list_cb(file, *fname ? fname : NULL,
      (shfs_list_f *)&share_file_list_cb, &level);

#if 0
  if (file->blk.hdr.type == SHINODE_DIRECTORY) {
    share_file_list_container(file, 0, pflags);
    strcpy(fname, "*");
  } else {
    ent_tot = shfs_list_cb(file, fname, NULL, NULL);

    if ((pflags & PFLAG_VERBOSE)) {
      fprintf(sharetool_fout, "%s\n", shfs_inode_print(file));
      if (IS_INODE_CONTAINER(shfs_type(file))) {
        share_file_list_container(file, 1, pflags);
      }
    } else {
      fprintf(sharetool_fout, "%s\n", shfs_filename(file));
    }
  }
#endif

  shfs_free(&tree);
  return (0);
}




