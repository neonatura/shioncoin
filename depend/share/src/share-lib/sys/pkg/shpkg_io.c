
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

#define SHPKG_SPEC_FILENAME "spec"

SHFL *shpkg_spec_file(shpkg_t *pkg)
{
  return (shfs_inode(pkg->pkg_file, SHPKG_SPEC_FILENAME, SHINODE_FILE));
}

/**
 * Determines whether a particular system-level sharefs package exists.
 */
int shpkg_exists(char *pkg_name)
{
  struct shstat st;
  SHFL *file;
  shfs_t *fs;
  char path[SHFS_PATH_MAX];
  int err;

  sprintf(path, "%s/%s", pkg_name, SHPKG_SPEC_FILENAME);
  fs = shfs_sys_init(SHFS_DIR_PACKAGE, path, &file);
  err = shfs_fstat(file, &st);
  shfs_free(&fs);
  if (err)
    return (FALSE);

  return (TRUE);
}

_TEST(shpkg_exists)
{
  shpkg_t *pkg;
  int err;

  err = shpkg_init("test", &pkg);
  _TRUE(0 == err);

  _TRUE(shpkg_exists("test"));

  err = shpkg_remove(pkg);
  _TRUE(0 == err);

  shpkg_free(&pkg);

  _TRUE(!shpkg_exists("test"));
}

/** write package info to disk */
int shpkg_info_write(shpkg_t *pkg)
{
  SHFL *file;
  shbuf_t *buff;
  size_t data_len;
  unsigned char *data;
  char path[SHFS_PATH_MAX];
  int err;

  if (!pkg)
    return (SHERR_INVAL);


  err = shencode((char *)&pkg->pkg, sizeof(shpkg_info_t),
      &data, &data_len, (shkey_t *)shesig_sub_sig(&pkg->pkg.pkg_cert));
  if (err)
    return (err);

  file = shpkg_spec_file(pkg);

  if (!shfs_access_owner_get(file)) {
    /* set packagee owner as current account. */
    uint64_t uid = shpam_uid((char *)get_libshare_account_name());
    shkey_t *self_id_key = shpam_ident_gen(uid, &pkg->pkg_file->tree->peer);
    shfs_access_owner_set(file, self_id_key);
    shkey_free(&self_id_key);
  }

  buff = shbuf_map(data, data_len);
  err = shfs_write(file, buff); 
  free(buff);
  free(data);
  if (err)
    return (err);

  return (0);
}

int shpkg_info_read(shpkg_t *pkg)
{
  SHFL *file;
  shbuf_t *buff;
  char *data;
  char path[SHFS_PATH_MAX];
  size_t data_len;
  int err;
  
  /* read package info from disk */
  buff = shbuf_init();
  file = shpkg_spec_file(pkg);
  err = shfs_read(file, buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }

  err = shdecode(shbuf_data(buff), shbuf_size(buff),
    &data, &data_len, (shkey_t *)shesig_sub_sig(&pkg->pkg.pkg_cert));
  shbuf_free(&buff);
  if (err) {
    free(data);
    return (err);
  }

  /* fill supplied content as package data. */
  memcpy(&pkg->pkg, data, MIN(data_len, sizeof(shpkg_info_t)));
  free(data);

  return (0);
}


#if 0
shpkg_def_t *shpkg_def(shpkg_t *pkg, SHFL *file)
{
  SHFL *def_file;
  shpkg_def_t *def;
  shmime_t *mime;
  shbuf_t *buff;
  char path[SHFS_PATH_MAX];
  int err;

  def = (shpkg_def_t *)calloc(1, sizeof(shpkg_def_t));
  if (!def)
    return (NULL);

  buff = shbuf_init();
  sprintf(path, "/sys/pkg/%s/def/%s",
      pkg->pkg.pkg_name, shkey_print(shfs_token(file)));
  def_file = shfs_file_find(shfs_inode_tree(file), path);
  err = shfs_read(def_file, buff);
  if (!err) {
    memcpy(def, shbuf_data(buff), MIN(sizeof(shpkg_def_t), shbuf_size(buff)));
  } else {
    mime = shmime_file(file);
    if (!mime)
      return (NULL);

    memcpy(&def->def_mime, mime, sizeof(def->def_mime));
    strcpy(def->def_dir, mime->mime_dir);
  }

  shbuf_free(&buff);
  return (def);
}
#endif

/**
 * Add a fresh copy of a file to a share package.
 */
int shpkg_file_add(shpkg_t *pkg, SHFL *file, shmime_t *mime)
{
  SHFL *pkg_file;
  char path[SHFS_PATH_MAX];
  char *dir;
  int err;

  if (pkg->pkg.pkg_cert.ver != 0) {
    /* package has already been signed. */
    return (SHERR_INVAL);
  }

  sprintf(path, "/sys/pkg/%s/files/%s/%s", 
    pkg->pkg.pkg_name, mime->mime_dir, shfs_filename(file));
  pkg_file = shfs_file_find(pkg->pkg_fs, path);
  err = shfs_file_copy(file, pkg_file); 
  if (err)
    return (err);

  err = shmime_file_set(file, mime->mime_name);
  if (err)
    return (err);

  return (0);
}

/**
 * Apply a pakage license to an extracted file.
 */
int shpkg_file_license(shpkg_t *pkg, SHFL *file)
{
  static unsigned char key_data[64];
  size_t key_len = 32;
  int err;

  err = shlic_apply(file, &pkg->pkg.pkg_cert, key_data, key_len);
  if (err)
    return (err);

  return (0);
}

/**
 * Extract a file from a packge into the sharefs sytem diretory hierarchy.
 * @param The sharefs file being extracted from the package.
 * @note Erases pre-existing files that cannot be licensed.
 */
int shpkg_extract_file(shpkg_t *pkg, SHFL *file)
{
  SHFL *sys_file;
  shmime_t *mime;
  char path[SHFS_PATH_MAX];
  int err;

#if 0
  def = shpkg_def(pkg, file);
  if (!def)
    return (SHERR_INVAL);
#endif

  mime = shmime_file(file);
  sprintf(path, "/sys/%s/%s", mime->mime_dir, shfs_filename(file));
  sys_file = shfs_file_find(pkg->pkg_fs, path);
  err = shfs_file_copy(file, sys_file); 
  if (err)
    return (err);

  if (pkg->pkg.pkg_cert.ver != 0) {
    err = shpkg_file_license(pkg, file);
    if (err) {
      shfs_file_remove(sys_file);
      return (err);
    }
  }

  return (0);
}



#if 0
int shpkg_cert_load(char *pkg_name, shesig_t **cert_p)
{
  struct stat st;
  SHFL *file;
  shfs_t *fs;
  shbuf_t *buff;
  char path[SHFS_PATH_MAX];
  int err;

  pkg_name = shpkg_name_filter(pkg_name);
  sprintf(path, "pkg/%s", pkg_name);
  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE, path, &file);
  err = shfs_fstat(file, &st);
  if (err)
    return (err);

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err) {
    shbuf_free(&free);
    return (err);
  }

  cert = (shesig_t *)calloc(1, sizeof(shesig_t));
  if (!cert) {
    shbuf_free(&free);
    return (SHERR_NOMEM);
  }

  memcpy(cert, shbuf_data(buff), MIN(shbuf_size(buff), sizeof(shesig_t)));
  shbuf_free(&buff);

  if (cert_p) {
    /* return loaded certificate */
    *cert_p = cert;
  } else {
    free(cert);
  }

  return (0);
}
#endif

