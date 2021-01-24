
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

#include <stdio.h>
#include "share.h"
#undef fnmatch
#include "sharetool.h"
#include "bits.h"



int sharetool_package_list(char *pkg_name)
{
  shbuf_t *buff;

  buff = shbuf_init();
  shpkg_list(pkg_name, buff);
  if (shbuf_data(buff))
    fprintf(sharetool_fout, "%s", shbuf_data(buff));
  shbuf_free(&buff);

  return (0);
}

int sharetool_package_install(char *pkg_name, int is_remove)
{
/* .. shpkg_extract() */
}


#if 0
void write_stuff(void)
{
  buff = shbuf_init();

  sprintf(text, 
      "# Automatically generated on %-20.20s.\n"
      "\n",
      shctime(shtime())+4);
  shbuf_catstr(buff, text);

  sprintf(text, "%-16.16s %s\n", "Name:", pkg_name);
  shbuf_catstr(buff, text);
  sprintf(text, "%-16.16s %s\n", "Version:", "1.0");
  shbuf_catstr(buff, text);
  sprintf(text, "%-16.16s %s\n", "Summary:", "");
  shbuf_catstr(buff, text);
  sprintf(text, "%-16.16s %s\n", "License:", "");
  shbuf_catstr(buff, text);
  sprintf(text, "%-16.16s %s\n", "URL:", "");
  shbuf_catstr(buff, text);
  sprintf(text, "%-16.16s %s\n", "Requires:", "");
  shbuf_catstr(buff, text);

  shbuf_catstr(buff,
      "\n"
      "\%files\n"
      "\%{_docdir}\n"
      "\%{_bindir}\n"
      "\%{_sbindir}\n"
      "\%{_libdir}/*.so\n"
      "\%{_libdir}/*.dll\n"
      "\%{_mandir}/*.man\n"
      "\n");

  shbuf_catstr(buff,
      "\%files devel\n"
      "\%{_includedir}/*\n"
      "\%{_libdir}/*.a\n"
      "\n");

  err = shfs_write(file, buff);
  if (err)
    return (err);
}
#endif

int sharetool_package_create(char *pkg_name, char *ver_text)
{
  struct stat st;
  shpkg_t *pkg;
  shbuf_t *buff;
  shfs_t *fs;
  char path[SHFS_PATH_MAX];
  char text[256];
  int err;

  pkg_name = shpkg_name_filter(pkg_name);

  if (shpkg_exists(pkg_name)) {
    /* package already exists */
    return (SHERR_EXIST);
  }

  err = shpkg_init(pkg_name, &pkg);
  if (err)
    return (err);

  if (ver_text && *ver_text) {
    /* set version */
    shpkg_version_set(pkg, ver_text);
  }

  fprintf(sharetool_fout, "%s: Initialized package '%s' v%s.\n",
      process_path, shpkg_name(pkg), shpkg_version(pkg));


  shpkg_free(&pkg);

  return (0);
}

int sharetool_package_recreate(char *pkg_name, char *ver_text)
{
  struct stat st;
  shpkg_t *pkg;
  shbuf_t *buff;
  shfs_t *fs;
  char path[SHFS_PATH_MAX];
  char text[256];
  int err;

  pkg_name = shpkg_name_filter(pkg_name);
  if (shpkg_exists(pkg_name)) {
    err = shpkg_clear(pkg_name, NULL);
    if (err)
      return (err);
  }

  return (sharetool_package_create(pkg_name, ver_text));
}

int sharetool_package_update_file(shpkg_t *pkg, SHFL *file)
{
  struct shstat st;
  shmime_t *mime;
  shfs_t *fs;
  int err;

  err = shfs_fstat(file, &st);
  if (err)
    return (err);

  mime = shmime_file(file);
  if (!mime) {
    fprintf(sharetool_fout, "%s: %s: warning: unknown file type.\n", process_path, shfs_filename(file));
    return (0); /* skip */
  }

  err = shpkg_file_add(pkg, file, mime);
  if (err)
    return (err);

  shfs_free(&fs);
  return (0);
}

int sharetool_package_update(char *pkg_name, char **path_spec, int is_remove)
{
  SHFL *file;
  shesig_t *cert;
  shpkg_t *pkg;
  shfs_t *fs;
  int err;
  int idx;

  pkg_name = shpkg_name_filter(pkg_name);
  if (!shpkg_exists(pkg_name))
    return (SHERR_NOENT);

  pkg = shpkg_load(pkg_name, NULL);
  if (!pkg)
    return (SHERR_INVAL);

  for (idx = 0; path_spec[idx]; idx++) {

    if (!is_remove) {
      fs = shfs_uri_init(path_spec[idx], 0, &file);
      if (!fs)
        continue;

      err = sharetool_package_update_file(pkg, file);
      if (err) {
        fprintf(sharetool_fout, "%s: %s: %s.\n", process_path, path_spec[idx], sherrstr(err));
        continue;
      }

      fprintf(sharetool_fout, "%s: Added file '%s' (%s) to package '%s'.\n", shfs_filename(file), shpkg_name(pkg));

      shfs_free(&fs);
    } else {
      fprintf(sharetool_fout, "%s: %s: %s\n", process_path, path_spec[idx], sherrstr(SHERR_OPNOTSUPP));
    }

  }

  return (0);
}
#if 0
int sharetool_package_certify(shpkg_t *pkg, char *cert_alias)
{
  shesig_t *cert;
  shbuf_t *buff;
  shfs_t *fs;
  char path[SHFS_PATH_MAX];
  int err;

  /* load certificate specified */
  sprintf(path, "alias/%s", cert_alias);
  cert = shfs_cert_load_ref(path);
  if (!cert)
    return (SHERR_NOENT);

  /* apply certificate specified to package */
  memcpy(&pkg->pkg.pkg_cert, cert, sizeof(pkg->pkg.pkg_cert));
  err = shpkg_info_write(pkg);
  if (err) {
    shesig_free(&cert);
    return (err);
  }

  /* generate package reference for certificate */
  sprintf(path, "pkg/%s", shpkg_name(pkg));
  err = shfs_cert_save(cert, path);
  shesig_free(&cert);
  if (err)
    return (err);

  return (0);
}
#endif

int sharetool_package_version(char *pkg_name, char *ver_text)
{
  shpkg_t *pkg;
  shesig_t *cert;
  shbuf_t *buff;
  shfs_t *fs;
  char path[SHFS_PATH_MAX];
  int err;

  pkg_name = shpkg_name_filter(pkg_name);

  if (!pkg_name || !*pkg_name) { 
    fprintf(sharetool_fout, "%s: The package name must be specified.\n", process_path);
    return (SHERR_INVAL);
  }

  if (!ver_text || !*ver_text) { 
    fprintf(sharetool_fout, "%s: The package version must be specified.\n", process_path);
    return (SHERR_INVAL);
  }

  pkg = shpkg_load(pkg_name, NULL);
  if (!pkg)
    return (SHERR_NOENT);

  memset(pkg->pkg.pkg_ver, 0, sizeof(pkg->pkg.pkg_ver));
  strncpy(pkg->pkg.pkg_ver, ver_text, sizeof(pkg->pkg.pkg_ver)-1);
  err = shpkg_info_write(pkg);
  if (err) {
    shpkg_free(&pkg);
    return (err);
  }

  fprintf(sharetool_fout, "%s: Applied version '%s' to package '%s'.\n",
      process_path, shpkg_version(pkg), pkg_name);

  shpkg_free(&pkg);

  return (0);
}

int sharetool_package_sign(char *pkg_name, char *cert_alias)
{
unsigned char key_data[32];
size_t key_len;
  shpkg_t *pkg;
  shesig_t *cert;
  shbuf_t *buff;
  shfs_t *fs;
  char path[SHFS_PATH_MAX];
  int err;

  memset(key_data, 1, sizeof(key_data));
  key_len = sizeof(key_data);

  pkg_name = shpkg_name_filter(pkg_name);

  if (!pkg_name || !*pkg_name) { 
    fprintf(sharetool_fout, "%s: The package name must be specified.\n", process_path);
    return (SHERR_INVAL);
  }

  if (!cert_alias || !*cert_alias) { 
    fprintf(sharetool_fout, "%s: The certificate name must be specified.\n", process_path);
    return (SHERR_INVAL);
  }

  pkg = shpkg_load(pkg_name, NULL);
  if (!pkg)
    return (SHERR_NOENT);

  /* ensure no previous certificate has been defined. */
  if (pkg->pkg.pkg_cert.ver != 0) {
    fprintf(sharetool_fout, "%s: The package already has a certificate applied (%s).\n", process_path, cert->ent);
    return (SHERR_ALREADY);
  }

  err = shpkg_sign_name(pkg, cert_alias, 0, key_data, key_len);
  shpkg_free(&pkg);
  if (err)
    return (err);

  fprintf(sharetool_fout, "%s: Applied certificate '%s' to package '%s'.\n",
      process_path, cert_alias, pkg_name);

  return (0);
}

int sharetool_package_destroy(char *pkg_name)
{
  shpkg_t *pkg;
  int err;

  pkg = shpkg_load(pkg_name, NULL);
  if (!pkg)
    return (SHERR_NOPKG);

  err = shpkg_remove(pkg);
  shpkg_free(&pkg);
  if (err)
    return (err);

  return (0);
}

int sharetool_package(char **args, int arg_cnt, int pflags)
{
  char pkg_name[MAX_SHARE_NAME_LENGTH];
  char sig_fname[SHFS_PATH_MAX];
  char pkg_cmd[256];
  char **opts;
  int opt_cnt;
  int err;
  int i;

  if (arg_cnt <= 1)
    return (SHERR_INVAL);

  memset(sig_fname, 0, sizeof(sig_fname));

  opts = (char **)calloc(arg_cnt + 1, sizeof(char *));
  if (!opts)
    return (SHERR_NOMEM);

  opt_cnt = 0;
  memset(pkg_cmd, 0, sizeof(pkg_cmd));
  memset(pkg_name, 0, sizeof(pkg_name));
  for (i = 1; i < arg_cnt; i++) {
    if (args[i][0] == '-') {
      continue;
    }

    if (!*pkg_cmd) {
      strncpy(pkg_cmd, args[i], sizeof(pkg_cmd)-1);
    } else if (!*pkg_name) {
      strncpy(pkg_name, args[i], sizeof(pkg_name)-1);
    } else {
      opts[opt_cnt] = strdup(args[i]);
      opt_cnt++;
    }
  }

  err = SHERR_INVAL;
  if (0 == strcasecmp(pkg_cmd, "list")) {
    err = sharetool_package_list(pkg_name);
  } else if (0 == strcasecmp(pkg_cmd, "create")) {
    err = sharetool_package_create(pkg_name, opts[0]);
  } else if (0 == strcasecmp(pkg_cmd, "recreate")) {
    err = sharetool_package_recreate(pkg_name, opts[0]);
  } else if (0 == strcasecmp(pkg_cmd, "add")) {
    err = sharetool_package_update(pkg_name, opts, FALSE);
  } else if (0 == strcasecmp(pkg_cmd, "rm")) {
    err = sharetool_package_update(pkg_name, opts, TRUE);
  } else if (0 == strcasecmp(pkg_cmd, "sign")) {
    err = sharetool_package_sign(pkg_name, opts[0]);
  } else if (0 == strcasecmp(pkg_cmd, "install")) {
    err = sharetool_package_install(pkg_name, FALSE);
  } else if (0 == strcasecmp(pkg_cmd, "uninstall")) {
    err = sharetool_package_install(pkg_name, TRUE);
  } else if (0 == strcasecmp(pkg_cmd, "destroy")) {
    err = sharetool_package_destroy(pkg_name);
  }

  free(opts);

  return (err);
}

/* Only the package owner can remove a signature. */
