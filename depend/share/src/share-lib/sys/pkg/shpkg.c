
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

char *shpkg_name(shpkg_t *pkg)
{
  return (pkg->pkg.pkg_name);
}

char *shpkg_version(shpkg_t *pkg)
{
  return (pkg->pkg.pkg_ver);
}
void shpkg_version_set(shpkg_t *pkg, char *ver_text)
{

  if (!ver_text || !*ver_text)
    ver_text = "0.0";

  memset(pkg->pkg.pkg_ver, 0, sizeof(pkg->pkg.pkg_ver));
  strncpy(pkg->pkg.pkg_ver, ver_text, sizeof(pkg->pkg.pkg_ver)-1);
}

int shpkg_owner(shpkg_t *pkg)
{
  static shkey_t *self_id_key;
  SHFL *file;
  shkey_t *pkg_id;
  uint64_t uid;
  int err;

  if (!self_id_key) {
    /* obtain default identity for current account. */
    uid = shpam_uid((char *)get_libshare_account_name());
    self_id_key = shpam_ident_gen(uid, &pkg->pkg_file->tree->peer);
  }

  file = shpkg_spec_file(pkg);
  pkg_id = shfs_access_owner_get(file);
  if (pkg_id && 0 != memcmp(pkg_id, self_id_key, sizeof(shkey_t))) {
    return (SHERR_ACCESS);
  }

  return (0);
}

_TEST(shpkg_owner)
{
  shpkg_t *pkg;
  	int err;

	err = shpkg_init("test", &pkg);
  _TRUE(0 == err);

		  err = shpkg_owner(pkg);
  _TRUE(0 == err); 

		  err = shpkg_remove(pkg);
  _TRUE(0 == err); 

  shpkg_free(&pkg);
}

char *shpkg_name_filter(char *in_name)
{
  static char ret_buf[MAX_SHARE_NAME_LENGTH];

  if (!in_name)
    return (NULL);

  memset(ret_buf, 0, sizeof(ret_buf));
  strncpy(ret_buf, in_name, sizeof(ret_buf));

  return (ret_buf);
}

/**
 * Obtain the package certificate's signature key.
 */
shkey_t *shpkg_sig(shpkg_t *pkg)
{
  return ((shkey_t *)shesig_sub_sig(&pkg->pkg.pkg_cert));
}

void shpkg_free(shpkg_t **pkg_p)
{
  shpkg_t *pkg;

  if (!pkg_p)
    return;
  pkg = *pkg_p;
  if (!pkg)
    return;
  *pkg_p = NULL;

  shfs_free(&pkg->pkg_fs);

  shbuf_free(&pkg->pkg_buff);

  free(pkg);
}

/**
 * Initialize a new package.
 */
int shpkg_init(char *pkg_name, shpkg_t **pkg_p)
{
  shpeer_t *pkg_peer;
  shpkg_t *pkg;
  shkey_t *self_id_key;
  SHFL *file;
  char path[SHFS_PATH_MAX];
  uint64_t uid;
  int err;

  if (shpkg_exists(pkg_name)) {
    return (SHERR_ALREADY);
  }

  pkg = (shpkg_t *)calloc(1, sizeof(shpkg_t));
  if (!pkg)
    return (SHERR_NOMEM);

  /* fill package info */
  strncpy(pkg->pkg.pkg_name, pkg_name, sizeof(pkg->pkg.pkg_name) - 1);
#if 0
  if (pkg_cert)
    memcpy(&pkg->pkg.pkg_cert, pkg_cert, sizeof(pkg->pkg.pkg_cert));
#endif

  memset(path, 0, sizeof(path));
  snprintf(path, sizeof(path)-1, "%s/", pkg_name);

  /* fill peer responsible for generating package */
  pkg->pkg_fs = shfs_sys_init(SHFS_DIR_PACKAGE, path, &pkg->pkg_file);
  if (!pkg->pkg_fs) {
    free(pkg);
    return (SHERR_IO);
}

  memcpy(&pkg->pkg.pkg_peer, &pkg->pkg_fs->peer, sizeof(pkg->pkg.pkg_peer));
  
  /* libshare "tar" format */ 
  err = shfs_attr_set(pkg->pkg_file, SHATTR_ARCH); 
  if (err) {
    shpkg_free(&pkg);
    return (err);
  }
  /* libshare "gzip" format */ 
  err = shfs_attr_set(pkg->pkg_file, SHATTR_COMP);
  if (err) {
    shpkg_free(&pkg);
    return (err);
  }

  /* write package info */
  err = shpkg_info_write(pkg);
  if (err) {
    shpkg_free(&pkg);
    return (err);
  }

#if 0
  if (pkg_cert) {
    /* generate package reference for certificate */
    sprintf(path, "pkg/%s", shpkg_name(pkg));
    err = shfs_cert_save(pkg_cert, path);
    if (err)
      return (err);
  }
#endif



  /* TODO: write to "package database" */

  if (pkg_p) {
    /* return generated package struct */
    *pkg_p = pkg;
  } else {
    shpkg_free(&pkg);
  }

  return (0);
}

/**
 * Load the resources from a share package.
 */
shpkg_t *shpkg_load(char *pkg_name, shkey_t *cert_sig)
{
  SHFL *pkg_file;
  SHFL *file;
  shpeer_t *pkg_peer;
  shesig_t *cert;
  shpkg_t *pkg;
  shfs_t *fs;
  shkey_t cmp_key;
  struct shstat st;
  char path[SHFS_PATH_MAX];
  char pkg_dirname[SHFS_PATH_MAX];
  int err;

  sprintf(pkg_dirname, "%s/", pkg_name);
  fs = shfs_sys_init(SHFS_DIR_PACKAGE, pkg_dirname, &pkg_file);
  err = shfs_fstat(pkg_file, &st);
  if (err) {
    return (NULL); /* no exist */
}

  pkg = (shpkg_t *)calloc(1, sizeof(shpkg_t)); 
  if (!pkg)
    return (NULL);

  pkg->pkg_fs = fs;
  pkg->pkg_file = pkg_file;
  err = shpkg_info_read(pkg);
  if (err) {
    shpkg_free(&pkg);
    return (NULL);
  }

  if (pkg->pkg.pkg_cert.ver != 0) {
    memcpy(&cmp_key, 0, sizeof(cmp_key));
    if (cert_sig) {
      /* use pre-specified key */
      memcpy(&cmp_key, cert_sig, sizeof(cmp_key));
    } else {
      /* load system-level package key */
//      sprintf(path, "pkg/%s", pkg_name);
      //cert = shfs_cert_load_ref(path);
      err = shesig_load_alias(pkg_name, &cert);
      if (!err) {
        memcpy(&cmp_key, shesig_sub_sig(cert), sizeof(cmp_key));
        shesig_free(&cert);
#if 0
      } else {
        /* use public key */
        memcpy(&cmp_key, shesig_sub_sig(shpkg_cert_public()), sizeof(cmp_key));
#endif
      }
    }
    err = memcmp(cert_sig, shesig_sub_sig(&pkg->pkg.pkg_cert), sizeof(shkey_t));
    if (err) {
      shpkg_free(&pkg);
      return (NULL);
    }
  }

  return (pkg);
}

_TEST(shpkg_load)
{
  shpkg_t *pkg;
  int err;

  err = shpkg_init("test", &pkg);
  _TRUE(0 == err);
  shpkg_free(&pkg);

  pkg = shpkg_load("test", NULL);
  _TRUEPTR(pkg);

  err = shpkg_remove(pkg);
  _TRUE(0 == err);
  shpkg_free(&pkg);

}

int shpkg_sign(shpkg_t *pkg, shesig_t *parent, int flags, unsigned char *key_data, size_t key_len)
{
  shbuf_t *buff;
  shesig_t cert;
  shfs_t *fs;
  char path[SHFS_PATH_MAX];
  int err;

  /* isolate certification to package administrator. */
  err = shpkg_owner(pkg);
  if (err)
    return (err);

  if (pkg->pkg.pkg_cert.ver != 0) {
    /* certificate is already signed. */
    return (SHERR_ALREADY);
  }

  /* remove previous certificate */
  shpkg_cert_clear(pkg);

  memset(&cert, 0, sizeof(cert));
  err = shesig_init(&cert, shpkg_name(pkg),
      SHESIG_ALG_DEFAULT, flags | SHCERT_CERT_LICENSE);
  if (err)
    return (err);

  err = shesig_sign(&cert, parent, key_data, key_len);
  if (err)
    return (err);

  /* apply certificate specified to package */
  memcpy(&pkg->pkg.pkg_cert, &cert, sizeof(pkg->pkg.pkg_cert));
  err = shpkg_info_write(pkg);
  if (err) {
    return (err);
  }

#if 0
  /* generate package reference for certificate */
  sprintf(path, "pkg/%s", shpkg_name(pkg));
  err = shesig_save(&cert, buff);
  //err = shfs_cert_save_buff(&cert, path, buff);
  shbuf_free(&buff);
  if (err) {
    return (err);
}
#endif

  err = shpkg_sign_files(pkg, NULL);
  if (err) {
    return (err);
}

  return (0);
}


int shpkg_sign_name(shpkg_t *pkg, char *parent_alias, int flags, unsigned char *key_data, size_t key_len)
{
  char path[SHFS_PATH_MAX+1];
  shesig_t *cert;
  int err;

  if (!pkg)
    return (SHERR_INVAL);
  if (!parent_alias)
    return (SHERR_INVAL);

  /* load certificate specified */
  sprintf(path, "alias/%s", shhex_str(parent_alias, strlen(parent_alias)));
#if 0
  cert = shfs_cert_load_ref(path);
  if (!cert)
    return (SHERR_NOENT);
#endif
  err = shesig_load_path(path, &cert);
  if (err)
    return (err);

  err = shpkg_sign(pkg, cert, flags, key_data, key_len);
  shesig_free(&cert);
  if (err)
    return (err);

  return (0);
}

_TEST(shpkg_sign)
{
  unsigned char key_data[32];
  size_t key_len = 32;
  shpkg_t *pkg;
  shesig_t cert;
  int err;

  memset(key_data, 1, sizeof(key_data));

  err = shpkg_init("test", &pkg);
  _TRUE(0 == err);

  memset(&cert, 0, sizeof(cert));
  err = shesig_ca_init(&cert, "test client", SHESIG_ALG_DEFAULT, SHCERT_ENT_ORGANIZATION | SHCERT_CERT_LICENSE);
  _TRUE(0 == err);

  err = shesig_sign(&cert, NULL, key_data, key_len);
  _TRUE(0 == err);

  err = shpkg_sign(pkg, &cert, SHCERT_ENT_ORGANIZATION, key_data, key_len);
  _TRUE(0 == err);

  err = shpkg_sign(pkg, &cert, SHCERT_ENT_ORGANIZATION, key_data, key_len);
  _TRUE(0 != err);

  err = shpkg_remove(pkg);
  _TRUE(0 == err);

  shpkg_free(&pkg);

}

/**
 * Lists the available packages on the system.
 */
int shpkg_list(char *pkg_name, shbuf_t *buff)
{
  struct shstat st;
  shfs_dir_t *dir;
  shfs_dirent_t *ent;
  shfs_t *fs;
  char *dir_path;
  char cmp_path[SHFS_PATH_MAX];
  char path[SHFS_PATH_MAX];
  char text[1024];
  int err;

  fs = shfs_sys_init(NULL, NULL, NULL);
  dir_path = shfs_sys_dir(SHFS_DIR_PACKAGE, "");
  dir = shfs_opendir(fs, dir_path);

  if (!dir)
    return (0); /* nothing to list */

  while ((ent = shfs_readdir(dir))) {
    if (ent->d_type != SHINODE_DIRECTORY)
      continue;

    strcpy(cmp_path, ent->d_name);
    strtok(cmp_path, "/");

    if (*pkg_name && 0 != fnmatch(pkg_name, cmp_path, 0))
      continue;

    /* ensure user has access to package */
    sprintf(path, "%s/%s/spec", dir_path, ent->d_name);
    err = shfs_stat(fs, path, &st);
    if (err)
      continue;

    sprintf(text, "%s [%s]\n", cmp_path, shcrcstr(ent->d_crc));
    shbuf_catstr(buff, text);
  }
  shfs_closedir(dir);

  shfs_free(&fs);

  return (0);
}

_TEST(shpkg_list)
{
  shpkg_t *pkg;
  shbuf_t *buff;
  int err;

  err = shpkg_init("test", &pkg);
  _TRUE(0 == err);

  buff = shbuf_init();
  err = shpkg_list("test", buff);
  _TRUE(0 == err);

  _TRUEPTR(shbuf_data(buff));
  _TRUEPTR(strstr(shbuf_data(buff), "test [")); 
  shbuf_free(&buff);

  err = shpkg_remove(pkg);
  _TRUE(0 == err);

  shpkg_free(&pkg);

}

int shpkg_remove(shpkg_t *pkg)
{
  SHFL *file;
  int err;

  /* restrict removal to creator */
  err = shpkg_owner(pkg);
  if (err) {
    return (err);
}

  /* remove installation files */
  err = shpkg_clear(pkg, NULL);
  if (err) {
    return (err);
  }

  /* remove certification */
  shpkg_cert_clear(pkg);

  err = shfs_file_remove(shpkg_spec_file(pkg));
  if (err) {
    return (err);
  }

  return (0);
}

int shpkg_add(shpkg_t *pkg, SHFL *file)
{
  shmime_t *mime;
  int err;

  if (shfs_type(file) == SHINODE_DIRECTORY) {
    return (SHERR_ISDIR);
  }

  mime = shmime_file(file);
  err = shpkg_file_add(pkg, file, mime);
  if (err)
    return (err);

  return (0);
}

int shpkg_extract(shpkg_t *pkg)
{
  return (shpkg_extract_files(pkg, NULL));  
}

_TEST(shpkg_extract)
{
  unsigned char key_data[64];
  size_t key_len;
  struct shstat st;
  shesig_t cert;
  shpeer_t *peer;
  shpkg_t *pkg;
  SHFL *file;
  shfs_t *fs;
  shbuf_t *buff;
  char text[1024];
  int err;

  memset(key_data, 1, sizeof(key_data));
  key_len = 32;

  memset(text, 0, sizeof(text));
  memset(text, ' ', 512);

  memset(&cert, 0, sizeof(cert));
  err = shesig_ca_init(&cert, "test client", SHESIG_ALG_DEFAULT, SHCERT_ENT_ORGANIZATION | SHCERT_CERT_LICENSE);
  _TRUE(0 == err);


  err = shesig_sign(&cert, NULL, key_data, key_len);
  _TRUE(0 == err);

  /* write content */
  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);
  file = shfs_file_find(fs, "/shpkg_extract");

  buff = shbuf_init();
  shbuf_catstr(buff, text);
  shfs_write(file, buff);

  shbuf_free(&buff);

  /* manage package */

  err = shpkg_init("test_shpkg_extract", &pkg);
  _TRUE(0 == err);

  err = shpkg_add(pkg, file);
  _TRUE(0 == err);

  err = shpkg_sign(pkg, &cert, 0, key_data, key_len);
  _TRUE(0 == err);

  err = shpkg_extract(pkg);
  _TRUE(0 == err);

  err = shfs_stat(pkg->pkg_fs, "/sys/data/txt/shpkg_extract", &st);
  _TRUE(0 == err);

  err = shpkg_remove(pkg);
  _TRUE(0 == err);

  shpkg_free(&pkg);
  shfs_free(&fs);
}

