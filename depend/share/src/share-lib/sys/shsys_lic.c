
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



#if 0
int shlic_load_sig(shkey_t *id_key, shesig_t *lic_p)
{
  shbuf_t *buff;
  shfs_t *tree;
  SHFL *lic_fl;
  shpeer_t *peer;
  char path[PATH_MAX+1];
  int err;

  peer = shpeer_init(NULL, NULL);
  tree = shfs_init(peer);
  shpeer_free(&peer);

  /* obtain derived license certificate */
  strcpy(path, shfs_sys_dir(SHFS_DIR_LICENSE, (char *)shkey_hex(id_key)));
  lic_fl = shfs_file_find(tree, path);
  buff = shbuf_init();
  err = shfs_read(lic_fl, buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }

  memset(lic_p, 0, sizeof(shesig_t));
  memcpy(lic_p, shbuf_data(buff), MIN(shbuf_size(buff), sizeof(shesig_t)));
  shbuf_free(&buff);

  return (0);
}

int shlic_load(shesig_t *cert, shesig_t *lic_p)
{
  shkey_t *id_key;
  int err;

  if (!cert)
    return (SHERR_INVAL);

  id_key = &cert->id;
  err = shlic_load_sig(id_key, lic_p);
  return (err);
}

int shlic_save_sig(shkey_t *id_key, shesig_t *lic)
{
  SHFL *lic_fl;
  shfs_t *tree;
  shbuf_t *buff;
  shpeer_t *peer;
  char path[PATH_MAX+1];
  int err;

  peer = shpeer_init(NULL, NULL);
  tree = shfs_init(peer);
  shpeer_free(&peer);

  /* save license using 'licensing certificate signature'. */
  strcpy(path, shfs_sys_dir(SHFS_DIR_LICENSE, (char *)shkey_hex(id_key)));
  lic_fl = shfs_file_find(tree, path);

  /* write license contents */
  buff = shbuf_map((unsigned char *)lic, sizeof(shesig_t));
  err = shfs_write(lic_fl, buff);
  free(buff);
  if (err)
    return (err);

  return (0);
}

int shlic_save(shesig_t *cert, shesig_t *lic)
{
  shkey_t *id_key;
  int err;

  if (!cert)
    return (SHERR_INVAL);

  id_key = &cert->id;
  err = shlic_save_sig(id_key, lic);
  return (err);
}
#endif










int shlic_get(SHFL *file, shlic_t *ret_lic)
{
  shlic_t lic;
  shfs_t *tree;
  shkey_t *id_key;
  char path[PATH_MAX+1];
  int err;

  id_key = shfs_sig_get(file);
  if (!id_key) {
    return (SHERR_INVAL);
  }

  memset(&lic, 0, sizeof(lic));
  err = shfs_cred_load(file, id_key, (unsigned char *)&lic, sizeof(lic));
  if (err) {
    shkey_free(&id_key);
    return (err);
  }

  if (!(lic.esig.flag & SHCERT_CERT_LICENSE)) {
    shkey_free(&id_key);
    return (SHERR_INVAL);
  }

  if (ret_lic) {
    memcpy(ret_lic, &lic, sizeof(shlic_t));
  }

  shkey_free(&id_key);

  return (0);
}



int shlic_set(SHFL *file, shlic_t *lic)
{
  shkey_t id_key;
  shkey_t *key;
  shfs_t *tree;
  int err;

  if (!file || !lic)
    return (SHERR_INVAL);

  /* assign certificate ID to file's meta info */
  memcpy(&id_key, &lic->esig.id, sizeof(id_key));
  err = shfs_sig_set(file, &id_key);
  if (err)
    return (err);

  tree = shfs_inode_tree(file);

  /* fill license */
  memcpy(&lic->lic_fs, shpeer_kpub(&tree->peer), sizeof(shkey_t));
  memcpy(&lic->lic_ino, shfs_token(file), sizeof(shkey_t));
//  memcpy(&lic->esig, id_key, sizeof(lic->esig)); 
//  lic->lic_expire = shesig_sub_expire(cert);
  lic->lic_crc = shfs_crc(file);

#if 0
  /* generate key from underlying cert+lic data. */
  key = shkey_bin(raw, raw_len);
  memcpy(&lic->lic_sig, key, sizeof(shkey_t));
  shkey_free(&key);
#endif

  /* store certificate + license inside file */
  err = shfs_cred_store(file, &id_key, (unsigned char *)lic, sizeof(shlic_t));
  if (err)
    return (err);

  return (0);
}

int shlic_sign(shlic_t *lic, shesig_t *parent, unsigned char *key_data, size_t key_len)
{
  int err;

  if (!lic || !parent)
    return (SHERR_INVAL);

#if 0
  if (!(lic->esig.flag & SHCERT_CERT_LICENSE)) {
    return (SHERR_INVAL);
  }
#endif

  memcpy(&lic->lic_pid, &parent->id, sizeof(lic->lic_pid));

  err = shesig_init(&lic->esig, parent->ent,
      SHESIG_ALG_DEFAULT, SHCERT_CERT_DIGITAL | SHCERT_CERT_LICENSE);
  if (err) {
    free(lic);
    return (err);
  }

  err = shesig_sign(&lic->esig, parent, key_data, key_len);
  if (err)
    return (err);

  return (0);
}

int shlic_apply(SHFL *file, shesig_t *cert, unsigned char *key_data, size_t key_len)
{
  shlic_t lic;
  int err;

  memset(&lic, 0, sizeof(lic));

  err = shlic_sign(&lic, cert, key_data, key_len);
  if (err)
    return (err);

  err = shlic_set(file, &lic);
  if (err)
    return (err);
  
  return (0);
}

int shlic_validate(SHFL *file)
{
  shesig_t *pcert;
  shlic_t lic;
  int err;

  memset(&lic, 0, sizeof(lic));
  err = shlic_get(file, &lic);
  if (err)
    return (err);

  err = shesig_load(&lic.lic_pid, &pcert);
  if (err)
    return (err);

  err = shesig_verify(&lic.esig, pcert);
  if (err)
    return (err);

  return (0);
}





_TEST(shlic_sign)
{
  unsigned char key_data[64];
  size_t key_len = 64;
  shpeer_t *peer;
  SHFL *file;
  shfs_t *fs;
  shlic_t lic;
  shlic_t cmp_lic;
  shesig_t cert;
  shesig_t lic_cert;
  shbuf_t *buff;
  int err;

  /* create cert */
  err = shesig_ca_init(&cert,
      "test_libshare: test licensing certificate (CA)",
      SHESIG_ALG_DEFAULT,
      SHCERT_ENT_ORGANIZATION | SHCERT_CERT_LICENSE | SHCERT_CERT_SIGN);
  _TRUE(0 == err);

  err = shesig_sign(&cert, NULL, key_data, key_len);
  _TRUE(0 == err);

  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);
  _TRUEPTR(fs);

  file = shfs_file_find(fs, "shlic_sign");

  buff = shbuf_init();
  shbuf_catstr(buff, "test shlic_sign");
  err = shfs_write(file, buff);
  shbuf_free(&buff);
  _TRUE(0 == err);

  memset(&lic, 0, sizeof(lic));

#if 0
/* DEBUG: */
  /* negative-proof */
  err = shlic_get(file, &cmp_lic);
fprintf(stderr, "DEBUG: TEST: shlic_sign: %d = shlic_get(): id '%s'\n", err, shkey_hex(&cmp_lic.esig.id));
  _TRUE(0 != err);
#endif

  /* obtain new license */ 
  memset(key_data, 1, key_len);
  err = shlic_apply(file, &cert, key_data, key_len);
  _TRUE(0 == err);
 
   /* verify license ownership */
  err = shlic_validate(file);
  _TRUE(0 == err);

  err = shfs_inode_remove(file);

  shfs_free(&fs);

}
