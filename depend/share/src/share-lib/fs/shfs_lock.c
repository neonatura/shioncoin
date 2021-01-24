
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

#define __SHFS_LOCK_C__
#include "share.h"


static int _shfs_lock_verify_hier(shfs_ino_t *inode)
{
  shfs_t *parent;
  int err;

  if (shfs_type(inode) == SHINODE_FILE_LOCK)
    return (SHERR_OPNOTSUPP);

  if ((shfs_attr(inode) & SHATTR_FLOCK)) {
    return (SHERR_ACCESS);
  }

  /* reference fs from parent for fresh inodes */
  parent = shfs_inode_parent(inode);
  if (parent) {
    err = _shfs_lock_verify_hier(parent);
    if (err)
      return (err);
  }

  return (0);
}

static int _shfs_lock_verify(shfs_ino_t *inode, int flags)
{
  shstat st;
  int err;

  err = shfs_fstat(inode, &st);
  if (err)
    return (err);

  return (_shfs_lock_verify_hier(inode));
}



int shfs_lock_of(shfs_ino_t *inode, int flags, size_t of, size_t len)
{
  shstat st;
  int err;

  err = shfs_fstat(inode, &st);
  if (err)
    return (err);

  if (shfs_type(inode) == SHINODE_FILE_LOCK)
    return (SHERR_OPNOTSUPP);

  return (shfs_attr_set(inode, SHATTR_FLOCK));
}

int shfs_lock(shfs_ino_t *inode, int flags)
{
  shstat st;
  int err;

  err = shfs_fstat(inode, &st);
  if (err)
    return (err);

  if (shfs_type(inode) == SHINODE_FILE_LOCK)
    return (SHERR_OPNOTSUPP);

  return (shfs_attr_set(inode, SHATTR_FLOCK));
}

int shfs_unlock(shfs_ino_t *inode)
{
  shstat st;
  int err;

  err = shfs_fstat(inode, &st);
  if (err)
    return (err);

  if (shfs_type(inode) == SHINODE_FILE_LOCK)
    return (SHERR_OPNOTSUPP);

  return (shfs_attr_unset(inode, SHATTR_FLOCK));
}

int shfs_locked(shfs_ino_t *inode)
{
  return (_shfs_lock_verify(inode, SHLK_NOWAIT)); 
}

