
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
#include "sharetool.h"

#define MOD_MINUS -1
#define MOD_NONE 0
#define MOD_PLUS 1

int share_file_attr(char *path, int pflags)
{
  struct stat st;
  shfs_t *sharetool_fs;
  shfs_ino_t *file;
  shfs_attr_t attr_flag;
  char attr[PATH_MAX+1];
  char *ptr;
  int attr_idx;
  int mode;
  int idx;
  int err;
  int i;



  memset(attr, 0, sizeof(attr));
  if (*path == '+' || *path == '-') {
    strncpy(attr, path, sizeof(attr)-1);
    ptr = strchr(attr, ' ');
    if (ptr) {
      *ptr++ = '\0'; 
      path = ptr;
    }
  }

  sharetool_fs = shfs_uri_init(path, 0, &file);
  if (!sharetool_fs) {
    fprintf(stderr, "%s: %s\n", path, strerror(ENOENT));
    return;
  }

  err = shfs_fstat(file, &st);
  if (err) {
    fprintf(stderr, "%s: cannot access %s: %s\n", 
        process_path, path, sherrstr(err));
    return (err);
  }


  if (!*attr) {
    char buf[4096];

    printf("[%s]\n", shfs_inode_print(file));

    memset(buf, 0, sizeof(buf));
    for (i = 0; i < strlen(SHFS_ATTR_BITS); i++) {
      if ((attr_flag & (1 << i) || (pflags & PFLAG_VERBOSE))) {
        printf("\t%s: %s\n", shfs_attr_label(i), 
            (attr_flag & (1 << i)) ? "True" : "False");
      }
    }

    return (0);
  }

  mode = MOD_NONE;
  attr_flag = shfs_attr(file);
  for (i = 0; i < strlen(attr); i++) {
    if (attr[i] == '-') {
      mode = MOD_MINUS;
      continue;
    }
    if (attr[i] == '+') {
      mode = MOD_PLUS;
      continue;
    }
  
    attr[i] = tolower(attr[i]);
    attr_idx = stridx(SHFS_ATTR_BITS, attr[i]);
    
    if (attr_idx == -1) {
      fprintf(stderr, "%s: Unknown attribute '%c'.\n", path, attr[i]);
      continue;
    }

    switch (mode) {
      case MOD_PLUS:
        err = shfs_attr_set(file, (1 << attr_idx));
        if (err) {
          fprintf(stderr, "%s: set %s: %s\n",
              path, shfs_attr_label(attr_idx), sherrstr(err)); 
        } else {
          printf("%s: %s attribute set.\n",
              path, shfs_attr_label(attr_idx));
        }
        break;
      case MOD_MINUS:
        err = shfs_attr_unset(file, (1 << attr_idx));
        if (err) {
          fprintf(stderr, "%s: unset %s: %s\n",
              path, shfs_attr_label(attr_idx), sherrstr(err)); 
        } else {
          printf("%s: %s attribute unset.\n",
              path, shfs_attr_label(attr_idx));
        }
        break;
    }
  }

  printf("[%s]\n", shfs_inode_print(file));

  shfs_free(&sharetool_fs);

  return (0);
}




