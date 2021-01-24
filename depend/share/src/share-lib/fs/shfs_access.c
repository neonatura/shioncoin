
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




int shfs_access_read(shfs_ino_t *file, shkey_t *id_key)
{
  shkey_t *key;
  int is_owner;

  if (shfs_attr(file) & SHATTR_READ)
    return (0); /* global read access */

  is_owner = FALSE;
  if (id_key) {
    key = shfs_access_owner_get(file);
    if (!key)
      return (0);

    is_owner = shkey_cmp(id_key, key);
    shkey_free(&key);
  }
  if (!is_owner)
    return (SHERR_ACCESS);

  return (0);
}
int shfs_access_write(shfs_ino_t *file, shkey_t *id_key)
{
  shkey_t *key;
  int is_owner;

  if (shfs_attr(file) & SHATTR_WRITE)
    return (0); /* global write access */

  is_owner = FALSE;
  if (id_key) {
    key = shfs_access_owner_get(file);
    if (!key)
      return (0);

    is_owner = shkey_cmp(id_key, key);
    shkey_free(&key);
  }
  if (!is_owner)
    return (SHERR_ACCESS);

  return (0);
}
int shfs_access_exec(shfs_ino_t *file, shkey_t *id_key)
{
  shkey_t *key;
  int is_owner;

  if (shfs_attr(file) & SHATTR_EXE)
    return (0); /* global execute access */

  is_owner = FALSE;
  if (id_key) {
    key = shfs_access_owner_get(file);
    if (!key)
      return (0);

    is_owner = shkey_cmp(id_key, key);
    shkey_free(&key);
  }
  if (!is_owner)
    return (SHERR_ACCESS);

  return (0);
}

int shfs_access_owner_set(shfs_ino_t *file, shkey_t *id_key)
{
  if (!id_key)
    id_key = ashkey_blank();
  memcpy(&file->blk.hdr.owner, id_key, sizeof(shkey_t));
  return (0);
}

shkey_t *shfs_access_owner_get(shfs_ino_t *file)
{
  static shkey_t ret_key;

  if (shkey_cmp(&file->blk.hdr.owner, ashkey_blank()))
    return (NULL); /* public */

  memcpy(&ret_key, &file->blk.hdr.owner, sizeof(shkey_t));
  return (&ret_key);
}

