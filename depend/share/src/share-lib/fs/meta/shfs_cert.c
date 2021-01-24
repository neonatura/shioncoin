
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




/**
 * Apply a digital certificate on a sharefs file.
 * @param package The application package the file is a part of.
 */
int shfs_cert_apply(SHFL *file, shesig_t *cert)
{
  unsigned char *raw;
  shkey_t *id_key;
  shkey_t *key;
  shfs_t *tree;
  shlic_t *lic;
  size_t raw_len;
  int err;

  if (!file || !cert)
    return (SHERR_INVAL);

  /* assign certificate ID to file's meta info */
  id_key = &cert->id;
  err = shfs_sig_set(file, id_key);
  if (err)
    return (err);

  raw_len = sizeof(shesig_t) + sizeof(shlic_t);
  raw = (char *)calloc(raw_len, sizeof(char));
  if (!raw) {
    return (SHERR_NOMEM);
  }

  tree = shfs_inode_tree(file);
  lic = (shlic_t *)(raw + sizeof(shesig_t));

  /* copy cert */
  memcpy(raw, cert, sizeof(shesig_t));

  /* fill license */
  memcpy(&lic->lic_fs, shpeer_kpub(&tree->peer), sizeof(shkey_t));
  memcpy(&lic->lic_ino, shfs_token(file), sizeof(shkey_t));
  //memcpy(&lic->lic_cert, id_key, sizeof(lic->lic_cert)); 
//  lic->lic_expire = shesig_sub_expire(cert);
  lic->lic_crc = shfs_crc(file);

#if 0
  /* generate key from underlying cert+lic data. */
  key = shkey_bin(raw, raw_len);
  memcpy(&lic->lic_sig, key, sizeof(shkey_t));
  shkey_free(&key);
#endif

  /* store certificate + license inside file */
  err = shfs_cred_store(file, id_key, raw, raw_len);
  shkey_free(&key);
  if (err)
    return (err);

  return (0);
}

int shfs_cert_get(SHFL *fl, shesig_t **cert_p, shlic_t **lic_p)
{
  shkey_t *id_key;
  unsigned char *raw;
  size_t raw_len;
  int err;

  id_key = shfs_sig_get(fl);
  if (!id_key)
    return (SHERR_INVAL);

  raw_len = sizeof(shesig_t) + sizeof(shlic_t);
  raw = (unsigned char *)calloc(raw_len, sizeof(char));
  if (!raw) {
    shkey_free(&id_key);
    return (SHERR_NOMEM);
  }

  err = shfs_cred_load(fl, id_key, raw, raw_len);
  shkey_free(&id_key);
  if (err) {
    free(raw);
    return (err);
  }

  if (cert_p) {
    shesig_t *cert = (shesig_t *)calloc(1, sizeof(shesig_t));
    memcpy(cert, raw, sizeof(shesig_t));
    *cert_p = cert;
  }
  if (lic_p) {
    shlic_t *lic = (shlic_t *)calloc(1, sizeof(shlic_t));
    memcpy(lic, (raw + sizeof(shesig_t)), sizeof(shlic_t)); 
    *lic_p = lic;
  }

  free(raw);
  return (0);
}

#if 0
/* deprec */
int shfs_cert_verify(shfs_ino_t *file, shesig_t *parent)
{
  shesig_t *cert;
  int err;

  err = shfs_cert_get(file, &cert, NULL);
  if (err)
    return (err);

  err = shesig_verify(cert, parent);
  if (err)
    return (err);

  return (0);
}
int shfs_cert_verify_path(char *exec_path)
{
  shfs_t *fs;
  SHFL *file;
  shpeer_t *peer;
  struct stat st;
  char *app_name;
  char path[SHFS_PATH_MAX];
  int err;

  err = stat(exec_path, &st);
  if (!err && S_ISDIR(st.st_mode)) {
    PRINT_ERROR(SHERR_ISDIR, exec_path);
    return (SHERR_ISDIR);
  }
  if (err) {
    err = errno2sherr();
    PRINT_ERROR(err, exec_path);
    return (err);
  }

  app_name = shfs_app_name(exec_path);
  sprintf(path, "%s/%s", app_name, SHFS_FILE_EXECUTABLE);
  fs = shfs_sys_init(SHFS_DIR_APPLICATION, path, &file);
  err = shfs_cert_verify(file, NULL);
  shfs_free(&fs);
  if (err)
    return (err);

  return (0);
}
#endif

/**
 * Copy a sharefs file's certificate into another file's binary content.
 */
int shfs_cert_export(SHFL *file, SHFS *out_file)
{
  shesig_t *cert;
  shbuf_t *buff;
  int err;

  err = shfs_cert_get(file, &cert, NULL);
  if (err)
    return (err);

  buff = shbuf_map((unsigned char *)cert, sizeof(shesig_t));
  err = shfs_write(file, buff);
  free(buff);
  free(cert);
  if (err)
    return (err);

  return (0);
}

#if 0
char *shfs_cert_filename(shesig_t *cert)
{
  static char sig_name[MAX_SHARE_NAME_LENGTH];

  memset(sig_name, 0, sizeof(sig_name));
  strncpy(sig_name, shesig_id_hex(cert), sizeof(sig_name)-1);

  return (sig_name);
}

int shfs_cert_save_buff(shesig_t *cert, char *ref_path, shbuf_t *buff)
{
  SHFL *file;
  SHFL *l_file;
  shpeer_t *peer;
  shfs_t *fs;
  shbuf_t *in_buff;
  char *fname;
  int err;

  fname = shfs_cert_filename(cert);

#if 0
 /* @note Overwriting an existing (non-expire) certificate can only be performed by the original owner. */
 
  {
    shesig_t *acc_cert = shfs_cert_load_ref(fname);
    if (acc_cert) {
      if (shtime_before(shtime(), acc_cert->expire) &&
          shpam_euid() != acc_cert->uid) {
        shesig_free(&acc_cert);
        return (SHERR_ACCESS);
      }

      shesig_free(&acc_cert);
    }
  }
#endif

  /* store in sharefs sytem hierarchy of 'package' partition. */
  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE, fname, &file);
  if (!fs)
    return (SHERR_IO);

  if (buff)
    in_buff = buff;
  else
    in_buff = shbuf_map((unsigned char *)cert, sizeof(shesig_t));
  err = shfs_write(file, in_buff);
  if (!buff)
    free(in_buff);
  if (err)
    return (err);

  if (ref_path) {
    /* an alias's link reference. */
    l_file = shfs_file_find(fs, shfs_sys_dir(SHFS_DIR_CERTIFICATE, ref_path));
    shfs_ref_set(l_file, file);
  }

  shfs_free(&fs);
  if (err)
    return (err);

  return (0);
}

int shfs_cert_save(shesig_t *cert, char *ref_path)
{
  int err;

/* todo: use cert->size as buff len */

  err = shfs_cert_save_buff(cert, ref_path, NULL);
  if (err)
    return (err);

  return (0);
}

/**
 * Load a system-level certificate by it's serial number.
 */
shesig_t *shfs_cert_load(char *serial_no)
{
  SHFL *file;
  shesig_t *cert;
  shbuf_t *buff;
  shfs_t *fs;
  int err;

  buff = shbuf_init();
  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE, serial_no, &file);
  err = shfs_read(file, buff);
  if (err) {
    shbuf_free(&buff);
    return (NULL);
  }

  cert = (shesig_t *)calloc(1, sizeof(shesig_t));
  if (!cert) {
    shbuf_free(&buff);
    return (NULL);
  }
  memcpy(cert, shbuf_data(buff), MIN(sizeof(shesig_t), shbuf_size(buff)));
  shbuf_free(&buff);

  return (cert);

}
#endif

/**
 * Load a system-level certificate by an alias reference.
 * @ref_path The relative [to the sys cert dir] path of the file reference.
 */
shesig_t *shfs_cert_load_ref(char *ref_path)
{
  shesig_t *cert;
  int err;

  err = shesig_load_path(ref_path, &cert);
  if (err)
    return (NULL);

  return (cert);
#if 0
  SHFL *file;
  shesig_t *cert;
  shbuf_t *buff;
  shfs_t *fs;
  int err;

  buff = shbuf_init();
  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE, ref_path, &file);
  err = shfs_read(file, buff);
  if (err) {
    shbuf_free(&buff);
    return (NULL);
  }

  cert = (shesig_t *)calloc(1, sizeof(shesig_t));
  if (!cert) {
    shbuf_free(&buff);
    return (NULL);
  }
  memcpy(cert, shbuf_data(buff), MIN(sizeof(shesig_t), shbuf_size(buff)));
  shbuf_free(&buff);

  return (cert);
#endif
}

int shfs_cert_remove_ref(char *ref_path)
{
  return (shesig_remove_label(ref_path));
#if 0
  SHFL *file;
  shesig_t *cert;
  shbuf_t *buff;
  shfs_t *fs;
  int err;

  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE, ref_path, &file);
  err = shfs_file_remove(file);
  shfs_free(&fs);
  if (err) 
    return (err);

  return (0);
#endif
}

