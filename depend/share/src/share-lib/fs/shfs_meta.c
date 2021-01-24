
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


int shfs_meta(shfs_t *tree, shfs_ino_t *ent, shmap_t **val_p)
{
  shfs_ino_t *meta_ent;
  shmap_t *h;
  shbuf_t *buff;
  size_t of;
  int err;

  meta_ent = shfs_inode(ent, NULL, SHINODE_META);
  if (!meta_ent)
    return (-1);

  h = shmap_init();
  if (!h)
    return (-1);

  buff = shbuf_init();
  err = shfs_aux_read(meta_ent, buff);
  if (err < 0) {
    shmap_free(&h);
    PRINT_ERROR(err, "shfs_meta");
    return (err);
  }

  shmap_load(h, buff);
  shbuf_free(&buff);

  if (val_p)
    *val_p = h; 
  else
    shmap_free(&h);

  return (0);
}

_TEST(shfs_meta)
{
  shfs_t *tree;
  shpeer_t *peer;
  shfs_ino_t *file;
  shmap_t *val = NULL;

  peer = shpeer_init("test", NULL);
  _TRUEPTR(peer);
  tree = shfs_init(peer);
  shpeer_free(&peer);
  _TRUEPTR(tree);

  _TRUEPTR(file = shfs_inode(tree->base_ino, "shfs_meta", SHINODE_FILE));
  _TRUE(!shfs_meta(tree, file, &val));
  _TRUEPTR(val);
  shfs_meta_free(&val);

  shfs_free(&tree);
}

int shfs_meta_save(shfs_t *tree, shfs_ino_t *ent, shmap_t *h)
{
  shfs_ino_t *meta_ent;
  shsize_t data_len;
  shbuf_t *buff;
  char *data;
  char *map;
  int err;

  meta_ent = shfs_inode(ent, NULL, SHINODE_META);
  if (!meta_ent)
    return (SHERR_IO);

  buff = shbuf_init();
  if (!buff)
    return (SHERR_IO);

  if (h)
    shmap_print(h, buff);

  err = shfs_aux_write(meta_ent, buff);
  if (err)
    return (err);

  shbuf_free(&buff);

  return (0);
}

_TEST(shfs_meta_save)
{
  shfs_t *tree;
  shfs_ino_t *dir;
  shmap_t *h = NULL;
  shkey_t *key;
  char *str;
  h = shmap_init();
  _TRUEPTR(h);

  _TRUEPTR(tree = shfs_init(NULL)); 
  _TRUEPTR(dir = shfs_inode(tree->base_ino, "shfs_meta_save", SHINODE_DIRECTORY));

  key = shkey_uniq();

  /* save a definition to disk. */
  shmap_set_str(h, key, VERSION);
  _TRUE(!shfs_meta_save(tree, dir, h));
  shfs_meta_free(&h);

  _TRUE(!shfs_meta(tree, dir, &h));
  _TRUEPTR(h);

  _TRUEPTR(str = shmap_get_str(h, key)); 
  _TRUE(0 == strcmp(str, VERSION));
  shfs_meta_free(&h);

  shkey_free(&key);
  shfs_free(&tree);
}


int shfs_meta_set(shfs_ino_t *file, char *def, char *value)
{
  shkey_t *key;
  int err;

  if (!file)
    return (SHERR_INVAL);

  if (!file->meta) {
    err = shfs_meta(file->tree, file, &file->meta);  
    if (err)
      return (err);
  }

  key = shkey_str(def);
  shmap_set_astr(file->meta, key, value);
  shkey_free(&key);

  err = shfs_meta_save(file->tree, file, file->meta);
  if (err)
    return (err);

  return (0);
}

const char *shfs_meta_get(shfs_ino_t *file, char *def)
{
  static char blank_str[256];
  shkey_t *key;
  char *str;
  int err;
 
  if (!file->meta) {
    err = shfs_meta(file->tree, file, &file->meta);  
    if (err) {
      PRINT_ERROR(err, "shfs_meta_get");
      return ((const char *)blank_str);
    }
  }

  key = shkey_str(def);
  str = shmap_get_str(file->meta, key);
  shkey_free(&key);

  if (!str)
    return ((const char *)blank_str);

  return ((const char *)str);
}

int shfs_meta_perm(shfs_ino_t *file, char *def, shkey_t *user)
{
  const char *str;
 
  str = shfs_meta_get(file, def);
  if (0 == strcmp(str, shkey_print(user)))
    return (0);

  return (SHERR_ACCESS);
}

#if 0
int shfs_sig_gen(shfs_ino_t *file, shsig_t *sig)
{
  static shsig_t raw_sig;
  shkey_t *key;
  shkey_t *peer_key;
  shbuf_t *buff;
  shpeer_t *peer;
  time_t stamp;
  char *key_str;
  unsigned char *data;
  size_t data_len;
  int err;

  if (!file || !file->tree)
    return (SHERR_INVAL);

  if (!sig) {
    sig = &raw_sig;
  }
  memset(sig, 0, sizeof(shsig_t));

  /* peer key */
  peer = &file->tree->peer;
  memcpy(&sig->sig_peer, shpeer_kpub(peer), sizeof(shkey_t));

  sig->sig_stamp = file->blk.hdr.ctime;
  sig->sig_expire = shtime_adj(sig->sig_stamp, SHARE_DEFAULT_EXPIRE_TIME);
  key = shkey_cert(&sig->sig_peer, shfs_crc(file), sig->sig_stamp);
  memcpy(&sig->sig_key, key, sizeof(shkey_t));
  shkey_free(&key);

#if 0
  key = shkey_bin((char *)sig, sizeof(shsig_t));
  memcpy(&sig->sig_id, key, sizeof(shkey_t));
  shkey_free(&key);
#endif

  key_str = (char *)shkey_print(&sig->sig_key);
  err = shfs_meta_set(file, SHMETA_SIGNATURE, key_str);
  if (err)
    return (err);

#if 0
  {
    char idx_path[PATH_MAX+1];
    shfs_ino_t *idx_file;

    /* index signature */
    sprintf(idx_path, "/%s/%s/%s", BASE_SHMETA_PATH, SHMETA_SIGNATURE, shkey_print(&sig->sig_id));
    idx_file = shfs_file_find(file->tree, idx_path);
    buff = shbuf_init();
    shbuf_cat(buff, &sig, sizeof(shsig_t));
    err = shfs_write(idx_file, buff);
    shbuf_free(&buff);
    if (err)
      PRINT_ERROR(err, idx_path);
  }
#endif

  return (0);
}

int shfs_sig_get(shfs_ino_t *file, shsig_t *sig)
{
  int err;
  const char *key_str;

  if (!file || !sig)
    return (SHERR_INVAL);

  memset(&sig->sig_key, 0, sizeof(sig->sig_key));
  key_str = shfs_meta_get(file, SHMETA_SIGNATURE);
  if (key_str && *key_str) {
    shkey_t *key = shkey_gen((char *)key_str);
    memcpy(&sig->sig_key, key, sizeof(shkey_t));
    shkey_free(&key);
  }

  sig->sig_stamp = file->blk.hdr.ctime;

  return (0);
}

int shfs_sig_verify(shfs_ino_t *file, shkey_t *peer_key)
{
  shsig_t sig;
  int err;

  memset(&sig, 0, sizeof(sig));
  memcpy(&sig.sig_peer, peer_key, sizeof(sig.sig_peer));

  err = shfs_sig_get(file, &sig);
  if (err)
    return (err);

  err = shkey_verify(&sig.sig_key, shfs_crc(file), peer_key, sig.sig_stamp);
  if (err)
    return (err);

  return (0);
}

#endif
