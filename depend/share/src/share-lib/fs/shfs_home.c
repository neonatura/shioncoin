
/*
 * @copyright
 *
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
 *
 *  @endcopyright
 *
 */  

#include "share.h"

shpeer_t *shfs_home_peer(shkey_t *id_key)
{
  char buf[SHFS_PATH_MAX];

  if (!id_key)
    return (NULL);

  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf) - 1, "home:%s", shkey_hex(id_key));
  return (shpeer_init(buf, NULL));
}

shfs_t *shfs_home_fs(shkey_t *id_key)
{
  shfs_t *fs;
  shfs_ino_t *file;
  shpeer_t *peer;

  peer = shfs_home_peer(id_key);
  if (!peer)
    return (NULL);

  fs = shfs_init(peer);
  if (!fs)
    return (NULL);

  /* initialize home directory */
  file = shfs_dir_find(fs, "/");
  shfs_access_owner_set(file, id_key);
  shfs_attr_set(file, SHATTR_SYNC); /* synchronize. */

  return (fs);
}

shfs_ino_t *shfs_home_file(shfs_t *fs, char *path)
{
  shfs_ino_t *dir;
  shfs_ino_t *file;
  char fs_path[SHFS_PATH_MAX];
  int err;

  /* obtain file reference to home dir path */
  if (*path == '/') path++;
  strcpy(fs_path, "/");
  strncpy(fs_path+1, path, sizeof(fs_path) - 2);
  file = shfs_file_find(fs, fs_path);

  return (file);
}

