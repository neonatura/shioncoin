
#if 0

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

typedef struct shfs_idx_t
{
  size_t hash_max;
  uint64_t *crc;
  shkey_t *hash;
} shfs_idx_t;

shfs_idx_t *shfs_index(shfs_ino_t *dir)
{

  if (!dir->idx) {
    dir->idx = (shfs_idx_t *)calloc(1, sizeof(shfs_idx_t));
  }

  return (dir->idx);
}

shkey_t *shfs_index_key(shfs_idx_t *idx, uint64_t crc, shfs_dirent_t *ent_p)
{
  shkey_t *key;
  int h_num = (crc % 256);
  
  if (!idx->hash[h_num]) {
    key = shkey_bin(&crc, sizeof(uint64_t));
    idx->hash_ino[h_num] = shfs_inode(idx->file, shkey_hex(key), SHINODE_INDEX);
    shkey_free(&key);
    return (NULL);
  }
  for (i = 0; i < idx->hash_max[h_num]; i++) {
    if ((idx->key[h_num] + i) == crc) {
      return (idx->hash[h_num] + i); 
    }
  }

  return (NULL);
}

#endif
