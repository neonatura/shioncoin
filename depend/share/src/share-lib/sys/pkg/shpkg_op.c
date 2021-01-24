
/*
 *  Copyright 2015 Neo Natura 
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

#ifdef linux
#undef fnmatch /* undef gnu */
#endif

int shpkg_extract_files(shpkg_t *pkg, char *fspec)
{
  return (shpkg_op(pkg, SHPKGOP_EXTRACT, fspec));
}

int shpkg_clear(shpkg_t *pkg, char *fspec)
{
  int err;
  
  err = shpkg_op(pkg, SHPKGOP_REMOVE, fspec);
  if (err)
    return (err);

  return (0);
}

int shpkg_sign_files(shpkg_t *pkg, char **info_p)
{
  int err;

  if (info_p)
    *info_p = NULL;

  err = shpkg_op(pkg, SHPKGOP_SIGN, NULL);
  if (err)
    return (err);

  if (info_p && shbuf_data(pkg->pkg_buff))
    *info_p = strdup(shbuf_data(pkg->pkg_buff));

  return (0);
}

/**
 * Lists all of the files in a package.
 * @note The returned string must be free'd.
 */
char *shpkg_list_files(shpkg_t *pkg)
{
  int err;

  err = shpkg_op(pkg, SHPKGOP_SIGN, NULL);
  if (err)
    return (err);

  return (strdup(shbuf_data(pkg->pkg_buff)));
}

int shpkg_op_dir(shpkg_t *pkg, char *dir_name, char *fspec, shpkg_op_t op)
{
  SHFL *file;
  shfs_dir_t *dir;
  shfs_dirent_t *ent;
  shbuf_t *buff;
  shfs_t *fs;
  char pkg_dir[SHFS_PATH_MAX];
  char path[SHFS_PATH_MAX];
  char *sys_dir;
  char text[1024];
  int err;

  if (!pkg)
    return (SHERR_INVAL);

  sys_dir = shfs_sys_dir(SHFS_DIR_PACKAGE, shpkg_name(pkg));
  if (!sys_dir)
    return (SHERR_IO);

  memset(pkg_dir, 0, sizeof(pkg_dir));
  strncpy(pkg_dir, sys_dir, sizeof(pkg_dir)-1);

  fs = shfs_sys_init(NULL, NULL, NULL);
  sprintf(path, "%s/files/%s/", pkg_dir, dir_name);
  dir = shfs_opendir(fs, path);
  if (!dir) {
    shfs_free(&fs);
    return (0); /* nothing to list */
  }

  while ((ent = shfs_readdir(dir))) {
    if (ent->d_type == SHINODE_DIRECTORY)
      continue;

    if (fspec && *fspec && 
        0 != fnmatch(fspec, ent->d_name, 0))
      continue;

    sprintf(path, "%s/files/%s/%s", pkg_dir, dir_name, ent->d_name);
    file = shfs_file_find(fs, path);
    err = op(pkg, path, file);
    if (err) {
      shfs_closedir(dir);
      shfs_free(&fs);
      return (err);
    }
  }
  shfs_closedir(dir);

  shfs_free(&fs);

  return (0);
}

int shpkg_op(shpkg_t *pkg, shpkg_op_t op, char *fspec)
{
  char **dirs;
  int err;
  int i;

  if (!pkg)
    return (SHERR_INVAL);

  if (!pkg->pkg_buff)
    pkg->pkg_buff = shbuf_init();
  shbuf_clear(pkg->pkg_buff);

  dirs = shmime_default_dirs();
  for (i = 0; dirs[i]; i++) {
    err = shpkg_op_dir(pkg, dirs[i], fspec, op);
    if (err)
      return (err);
  }

  return (0);
}


int shpkg_sign_op(shpkg_t *pkg, char *path, SHFL *file)
{
  int err;

  err = shpkg_cert_file(pkg, file);
  if (err)
    return (err);

  return (0);
}

int shpkg_remove_op(shpkg_t *pkg, char *path, SHFL *file)
{
  return (shfs_file_remove(file));
}

int shpkg_extract_op(shpkg_t *pkg, char *path, SHFL *file)
{
  int err;

  err = shpkg_extract_file(pkg, file);
  if (err)
    return (err);

  return (0);
}

int shpkg_list_op(shpkg_t *pkg, char *path, SHFL *file)
{
  shbuf_catstr(pkg->pkg_buff, path);
  shbuf_catstr(pkg->pkg_buff, "\n");
}

