
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
#include "x509.h"
#include "x509_crt.h"
#include "bits.h" /* share-daemon/bits */





int sharetool_cert_load(char *sig_name, shesig_t **cert_p)
{
  shesig_t *cert;
  int err;

  cert = NULL;
  err = shesig_load_path(sig_name, &cert);
  if (err) {
    err = shesig_load_alias(sig_name, &cert);
    if (err)
      return (err);
  }

  *cert_p = cert;
  return (0);
} 

int sharetool_cert_list(char *cert_alias)
{
  shpeer_t *peer;
  shfs_dir_t *dir;
  shfs_dirent_t *ent;
  shfs_t *fs;
  SHFL *inode;
  char path[SHFS_PATH_MAX];
  int err;

  fs = shfs_sys_init(NULL, NULL, NULL);
  if (!fs)
    return (SHERR_IO);

  if (!cert_alias)
    cert_alias = "";

  printf ("Certificates:\n");
  dir = shfs_opendir(fs, shfs_sys_dir(SHFS_DIR_CERTIFICATE, cert_alias));
  if (dir) {
    while ((ent = shfs_readdir(dir))) {
      if (ent->d_type != SHINODE_FILE)
        continue;

#if 0
      if (*cert_alias && 0 != fnmatch(cert_alias, ent->d_name, 0))
        continue;
#endif

      sprintf(path, "%s/%s", shfs_sys_dir(SHFS_DIR_CERTIFICATE, cert_alias), ent->d_name);
      inode = shfs_file_find(fs, path);
      err = sharetool_cert_summary_inode(inode);
    }
    shfs_closedir(dir);
  }

  shfs_free(&fs);
  return (0);
}

int sharetool_cert_import(char *parent_name, char *sig_fname)
{
  struct shstat st;
  x509_crt *chain;
  shesig_t *cert;
  shesig_t *p_cert;
  shbuf_t *buff;
  shfs_t *fs;
  SHFL *file;
  int err;

  fs = shfs_uri_init(sig_fname, 0, &file);
  if (!fs)
    return (SHERR_NOENT);

  err = shfs_fstat(file, &st);
  if (err) {
    return (err);
  }

  /* read certificate file */
  buff = shbuf_init();
  err = shfs_read(file, buff);
  shfs_free(&fs);
  if (err) {
    printf ("ERROR: %d = shfs_read()\n", err);
    shbuf_free(&buff);
    return (err);
  }

  if (shbuf_size(buff) == 0) {
    return (SHERR_INVAL);
  }

  x509_pem_decode(buff);
  if (shbuf_size(buff) == 0) {
    return (SHERR_INVAL);
  }

  /* parse certificate */
  chain = (x509_crt *)calloc(1, sizeof(x509_crt));
  err = x509_cert_parse(chain, shbuf_data(buff), shbuf_size(buff));
  if (err) {
    free(chain);
    shbuf_free(&buff);
    return (err);
  }

  err = x509_cert_extract(chain, &cert);
  free(chain);
  shbuf_free(&buff);
  if (err)
    return (err);

  if (parent_name && *parent_name) {
    err = sharetool_cert_load(parent_name, &p_cert);
    if (err)
      return (err);

    err = shesig_sign(cert, p_cert, NULL, 0);
    free(p_cert);
    if (err)
      return (err);
  }

#if 0
  /* generate a print-out of certificate's underlying info. */
  buff = shbuf_init();
  shesig_print(cert, buff);
  fprintf(sharetool_fout, "%s", shbuf_data(buff));
  shbuf_free(&buff);
#endif

  free(cert);

  printf("%s: Imported certificate '%s'.\n", process_path, cert->ent);

  return (0);
}

/**
 * Create a new certificate.
 * @param sig_fname Specifies the certificate alias.
 * @param sig_fname Specifies a parent certificate alias, or NULL if not applicable.
 */
int sharetool_cert_create(char *parent_name, char *key_fname)
{
  SHFL *file;
  shesig_t *p_cert;
  shesig_t cert;
  shfs_t *fs;
  struct stat st;
  unsigned char *key_data;
  char path[SHFS_PATH_MAX];
  char type_str[64];
  char entity[MAX_SHARE_NAME_LENGTH]; 
  char passphrase[MAX_SHARE_NAME_LENGTH]; 
  size_t key_len;
  int flags;
  int err;

  p_cert = NULL;
  if (parent_name && *parent_name) {
    err = sharetool_cert_load(parent_name, &p_cert);
    if (err)
      return (err);
 
    fprintf(sharetool_fout, "Issuer: %s\n", p_cert->ent);
  }

  /* generate certificate */
  memset(&cert, 0, sizeof(cert));
  flags = 0;
  printf ("Enter certificate type (O=Org/C=Com/P=Person): ");
  fflush(stdout);
  memset(type_str, 0, sizeof(type_str));
  fgets(type_str, MAX_SHARE_NAME_LENGTH-1, stdin);
  switch (tolower(type_str[0])) {
    case 'o': flags |= SHCERT_ENT_ORGANIZATION; break;
    case 'c': flags |= SHCERT_ENT_COMPANY; break;
    case 'p': flags |= SHCERT_ENT_INDIVIDUAL; break;
  }

  printf ("Enter the entity name (real/company name): ");
  fflush(stdout);
  memset(entity, 0, sizeof(entity));
  fgets(entity, MAX_SHARE_NAME_LENGTH-1, stdin);
  strtok(entity, "\r\n");

  if (!*key_fname) {
    printf ("Enter a passphrase: ");
    fflush(stdout);
    memset(passphrase, 0, sizeof(passphrase));
    fgets(passphrase, MAX_SHARE_NAME_LENGTH-1, stdin);
    strtok(passphrase, "\r\n");

    key_data = (unsigned char *)strdup(passphrase);
    key_len = strlen(passphrase); 
  } else {
    err = stat(key_fname, &st);
    if (err)
      return (-errno);

    err = shfs_read_mem(key_fname, &key_data, &key_len);
    if (err)
      return (err);
  }


#if 0
  err = 0;
  if (parent_name && *parent_name) {
    struct stat st;
    unsigned char *key_data = NULL;
    size_t key_len = 0;

    err = sharetool_cert_load(parent_name, &p_cert);
    if (err)
      return (err);
  
    if (*key_fname) {
      err = stat(key_fname, &st);
      if (!err) {
        (void)shfs_read_mem(key_fname, &key_data, &key_len);
      }
    }
    err = shesig_sign(&cert, p_cert, key_data, key_len, NULL);
    if (key_data) free(key_data);
    free(p_cert);
    if (err)
      return (err);
  }
#endif
  if (p_cert) {
    err = shesig_init(&cert, entity, SHESIG_ALG_DEFAULT, flags);
    if (err)
      return (err);
  } else {
    err = shesig_ca_init(&cert, entity, SHESIG_ALG_DEFAULT, flags);
    if (err)
      return (err);
  }

  err = shesig_sign(&cert, p_cert, key_data, key_len);
  shesig_free(&p_cert);
  free(key_data);
  if (err)
    return (err);

  sharetool_cert_summary(&cert);

  return (0);
}

int sharetool_cert_remove(char *sig_name)
{
  struct shstat st;
  SHFL *file;
  shfs_t *fs;
  shbuf_t *buff;
  shesig_t *cert;
  int err;

  /* store in sharefs sytem hierarchy of 'package' partition. */
  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE, sig_name, &file);
  if (!fs)
    return (SHERR_IO);

  err = shfs_fstat(file, &st);
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  err = shfs_file_remove(file);
  shfs_free(&fs);
  if (err)
    return (err);

  printf("%s: Removed certificate '%s'.\n", process_path, sig_name);

  return (0);
}

int sharetool_cert_verify(char *cert_alias)
{
  shesig_t *cert;
  shesig_t *pcert;
  int valid;
  int ret_err;
  int err;

  /* load the certificate from the system hierarchy. */
  err = sharetool_cert_load(cert_alias, &cert);
  if (err)
    return (err);

  valid = TRUE;
  pcert = NULL;
  if ((cert->flag & SHCERT_CERT_CHAIN)) {
    /* load the certificate from the system hierarchy. */
    err = sharetool_cert_load(cert->iss, &pcert);
//fprintf(stderr, "DEBUG: %d = sharetool_cert_load/chain('%s')\n", err, cert->iss);
    if (err)
      return (err);
  }

  ret_err = shesig_verify(cert, pcert);
  if (ret_err == 0) {
    /* successful verification -- return something parseable. */
    fprintf(sharetool_fout, 
        "ID: %s\n"
        "Subject: %s\n"
        "Public Key: %s\n"
        "Chain Signature: %s\n",
      shkey_hex(&cert->id), cert->ent,
      shhex_str((unsigned char *)cert->pub, shalg_size(cert->pub)),
      shhex_str((unsigned char *)cert->data_sig, shalg_size(cert->data_sig)));
  }

  shesig_free(&pcert);
  shesig_free(&cert);

  return (ret_err);
}

int sharetool_cert_license_apply(char *cert_alias, char *lic_path)
{
  unsigned char key_data[32];
  size_t key_len = 32;
  SHFL *file;
  shesig_t *cert;
  shfs_t *fs;
  int err;

  /* load the certificate from the system hierarchy. */
  err = sharetool_cert_load(cert_alias, &cert);
  if (err) {
    fprintf(sharetool_fout, "error: unable to load certificate '%s': %s [sherr %d].", cert_alias, sherrstr(err), err);
    return (err);
  }

#if 0 /* DEBUG: */
  if (!(cert->cert_flag & SHCERT_CERT_LICENSE)) {
    /* certificate is not permitted to license */
    shesig_free(&cert);
    fprintf(sharetool_fout, "error: certificate is not permitted to license.\n");
    return (SHERR_INVAL);
  }
#endif

  fs = shfs_uri_init(lic_path, 0, &file);
  if (!fs) {
    shesig_free(&cert);
    fprintf(sharetool_fout, "error: unknown path '%s'.\n", lic_path); 
    return (SHERR_NOENT);
  }

  memset(key_data, 1, sizeof(key_data));
  err = shlic_apply(file, cert, key_data, key_len);
  shfs_free(&fs);
  if (err) { 
    shesig_free(&cert);
    fprintf(sharetool_fout, "error: unable to apply certificate: %s [sherr %d].", sherrstr(err), err);
    return (err);
  }

  if (!(run_flags & PFLAG_QUIET)) {
    fprintf(sharetool_fout, "info: applied certificate '%s' on '%s'\n", cert_alias, lic_path); 
  }

  shesig_free(&cert);
  return (0);
}

int sharetool_cert_license_verify(char *cert_alias, char *lic_path)
{
  SHFL *file;
  shesig_t *cert;
  shfs_t *fs;
  shkey_t *key;
  int err;

  /* load the certificate from the system hierarchy. */
  err = sharetool_cert_load(cert_alias, &cert);
  if (err) {
    fprintf(sharetool_fout, "error: unable to load certificate '%s': %s [sherr %d].", cert_alias, sherrstr(err), err);
    return (err);
  }

#if 0 /* DEBUG: */
  if (!(cert->cert_flag & SHCERT_CERT_LICENSE)) {
    /* certificate is not permitted to license */
    shesig_free(&cert);
    fprintf(sharetool_fout, "error: certificate is not permitted to license.\n");
    return (SHERR_INVAL);
  }
#endif

  fs = shfs_uri_init(lic_path, 0, &file);
  if (!fs) {
    shesig_free(&cert);
    fprintf(sharetool_fout, "error: unknown path '%s'.\n", lic_path); 
    return (SHERR_NOENT);
  }

  key = &cert->id;
  err = shfs_sig_verify(file, key);
  shfs_free(&fs);
  if (err) { 
    shesig_free(&cert);
    fprintf(sharetool_fout, "error: unable to verify certificate: %s [sherr %d].", sherrstr(err), err);
    return (err);
  }

  if (!(run_flags & PFLAG_QUIET)) {
    fprintf(sharetool_fout, "info: verified certification of '%s' on '%s'\n", cert_alias, lic_path); 
  }

  shesig_free(&cert);
  return (0);
}

int sharetool_cert_license_validate(char *lic_path)
{
  SHFL *file;
  shfs_t *fs;
  int err;

  fs = shfs_uri_init(lic_path, 0, &file);
  if (!fs) {
    fprintf(sharetool_fout, "error: unknown path '%s'.\n", lic_path); 
    return (SHERR_NOENT);
  }

  err = shlic_validate(file);
  shfs_free(&fs);
  if (err) {
    fprintf(sharetool_fout, "error: unable to validate certificate: %s [sherr %d].\n", sherrstr(err), err);
    return (err);
  } 

  if (!(run_flags & PFLAG_QUIET)) {
    fprintf(sharetool_fout, "info: validated license on '%s'\n", lic_path); 
  }

  return (0);
}


int sharetool_cert_summary(shesig_t *cert)
{
  shstat st;
  int err;

  fprintf(sharetool_fout, "ID: %s\n", shkey_hex(&cert->id));
  fprintf(sharetool_fout, "Subject: %s\n", cert->ent);
  if (*cert->iss)
    fprintf(sharetool_fout, "Issuer: %s\n", cert->iss);
  fprintf(sharetool_fout, "Flags: %s\n", shesig_flag_str(cert->flag));
  fprintf(sharetool_fout, "\n");

    
  return (0);
}
int sharetool_cert_summary_inode(SHFL *file)
{
  shstat st;
  shesig_t *cert;
  shbuf_t *buff;
  int err;

  err = shfs_fstat(file, &st);
  if (err) {
    return (err);
}

  buff = shbuf_init();
  err = shfs_read(file, buff); 
  if (err) {
    return (err);
}
  if (shbuf_size(buff) < sizeof(shesig_t)) {
    return (SHERR_INVAL);
}

/* .. expire etc */
  cert = (shesig_t *)shbuf_data(buff);
  sharetool_cert_summary(cert);

  shbuf_free(&buff);
    
  return (0);
}
int sharetool_cert_print(char *cert_alias)
{
  shesig_t *cert;
  shbuf_t *buff;
  int err;

  /* load the certificate from the system hierarchy. */
  err = sharetool_cert_load(cert_alias, &cert);
  if (err)
    return (err);

  /* generate a print-out of certificate's underlying info. */
  buff = shbuf_init();
  shesig_print(cert, buff);
  free(cert);

  /* flush data to output file pointer */
  fprintf(sharetool_fout, "%s", shbuf_data(buff));
shbuf_free(&buff);

  return (0);
}

int sharetool_cert_print_file(char *sig_name, char *sig_fname)
{
  struct shstat st;
  x509_crt *chain;
  shbuf_t *buff;
  shfs_t *fs;
  SHFL *file;
  int err;

  fs = shfs_uri_init(sig_fname, 0, &file);
  if (!fs)
    return (SHERR_NOENT);

  err = shfs_fstat(file, &st);
  if (err) {
    fprintf(stderr, "ERROR: fstat '%s': %s\n", sig_fname, sherrstr(err));
    return (err);
  }

  /* read certificate file */
  buff = shbuf_init();
  err = shfs_read(file, buff);
  shfs_free(&fs);
  if (err) {
    printf ("ERROR: %d = shfs_read()\n", err);
    shbuf_free(&buff);
    return (err);
  }

  if (shbuf_size(buff) == 0) {
    return (SHERR_INVAL);
  }

  x509_pem_decode(buff);
  if (shbuf_size(buff) == 0) {
    return (SHERR_INVAL);
  }

  /* parse certificate */
  chain = (x509_crt *)calloc(1, sizeof(x509_crt));
  err = x509_cert_parse(chain, shbuf_data(buff), shbuf_size(buff));
  if (err) {
    free(chain);
    shbuf_free(&buff);
    return (err);
  }

  /* print contents. */
  sharetool_cert_print_crt(chain);
  shbuf_free(&buff);

  free(chain);
  return (0);
}

int sharetool_certificate(char **args, int arg_cnt, int pflags)
{
  char cert_alias[MAX_SHARE_NAME_LENGTH];
  char parent_alias[MAX_SHARE_NAME_LENGTH];
  char x509_fname[SHFS_PATH_MAX];
  char key_fname[SHFS_PATH_MAX];
  char cert_cmd[256];
  int err;
  int i;

  if (arg_cnt <= 1)
    return (SHERR_INVAL);

  memset(x509_fname, 0, sizeof(x509_fname));
  memset(key_fname, 0, sizeof(key_fname));
  memset(parent_alias, 0, sizeof(parent_alias));
  memset(cert_cmd, 0, sizeof(cert_cmd));
  memset(cert_alias, 0, sizeof(cert_alias));

  for (i = 1; i < arg_cnt; i++) {
    if (args[i][0] == '-') {
      /* command argument */
      if (0 == strcmp(args[i], "-c") ||
          0 == strncmp(args[i], "--cert", 6)) {
        i++;
        if (i < arg_cnt)
          strncpy(x509_fname, args[i], sizeof(x509_fname)-1);
      } else if (0 == strcmp(args[i], "-k") ||
          0 == strncmp(args[i], "--key", 5)) {
        i++;
        if (i < arg_cnt)
          strncpy(key_fname, args[i], sizeof(key_fname)-1);
      }
      continue;
    }
    if (!*cert_cmd) {
      strncpy(cert_cmd, args[i], sizeof(cert_cmd)-1);
    } else if (!*cert_alias) {
      strncpy(cert_alias, args[i], sizeof(cert_alias)-1);
    } else if (!*parent_alias) {
      strncpy(parent_alias, args[i], sizeof(parent_alias)-1);
    }
  }


  err = SHERR_INVAL;
  if (0 == strcasecmp(cert_cmd, "list")) {
    err = sharetool_cert_list(cert_alias);
  } else if (0 == strcasecmp(cert_cmd, "create")) {
    if (!*x509_fname) {
      err = sharetool_cert_create(/*parent*/cert_alias, key_fname);
    } else {
      err = sharetool_cert_import(/*parent*/cert_alias, x509_fname);
    }
  } else if (0 == strcasecmp(cert_cmd, "remove")) {
    err = sharetool_cert_remove(cert_alias);
  } else if (0 == strcasecmp(cert_cmd, "verify")) {
    err = sharetool_cert_verify(cert_alias);
  } else if (0 == strcasecmp(cert_cmd, "apply")) {
    err = sharetool_cert_license_apply(cert_alias, parent_alias);
  } else if (0 == strcasecmp(cert_cmd, "verlic")) {
    err = sharetool_cert_license_verify(cert_alias, parent_alias);
  } else if (0 == strcasecmp(cert_cmd, "vallic")) {
    err = sharetool_cert_license_validate(cert_alias);
  } else if (0 == strcasecmp(cert_cmd, "print")) {
    if (!*x509_fname) {
      err = sharetool_cert_print(cert_alias);
    } else {
      /* print a X509 certificate stored in a file. */
      err = sharetool_cert_print_file(cert_alias, x509_fname);
    }
  }

  return (err);
}

