
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





#if 0

/**
 * Generate a license for a file using the given certificate.
 * @param lic A reference to the license to generate.
 */
int shlic_shr_sign(SHFL *file, shesig_t *cert)
{
  SHFL *lic_fl;
  shbuf_t *buff;
  shlic_t lic;
  shfs_t *tree;
  shsig_t sig;
  shkey_t *self_id_key;
  uint64_t uid;
  char path[SHFS_PATH_MAX];
  int err;

  /* generate a local-specific signature for the licence file */ 
  memset(&sig, 0, sizeof(sig));
  err = shfs_sig_gen(file, &sig);
  if (err)
    return (err);

  /* apply the certificate to the file. */
  err = shfs_cert_apply(file, cert);
  if (err)
    return (err);

  tree = shfs_inode_tree(file);
  if (!tree)
    return (SHERR_IO);

  memset(&lic, 0, sizeof(lic));
  memcpy(&lic.lic_fs, shpeer_kpriv(&tree->peer), sizeof(lic.lic_fs));
  memcpy(&lic.lic_ino, shfs_token(file), sizeof(lic.lic_ino));
  memcpy(&lic.lic_cert, shesig_sub_sig(cert), sizeof(lic.lic_cert));
  memcpy(&lic.lic_sig, &sig.sig_key, sizeof(lic.lic_sig)); 
  lic.lic_expire = sig.sig_expire;

  /* compute checksum from underlying license content */
  lic.lic_crc = shcrc(&lic, sizeof(lic));

  /* save license using 'license key'. */
  strcpy(path, shfs_sys_dir(SHFS_DIR_LICENSE, shkey_hex(&lic.lic_sig)));
  lic_fl = shfs_file_find(tree, path);

  /* set packagee owner as current account. */
  uid = shpam_uid((char *)get_libshare_account_name());
  self_id_key = shpam_ident_gen(uid, &tree->peer);
  shfs_access_owner_set(lic_fl, self_id_key);
  shkey_free(&self_id_key);

  /* write license contents */
  buff = shbuf_map((unsigned char *)&lic, sizeof(shlic_t));
  err = shfs_write(lic_fl, buff);
  free(buff);
  if (err)
    return (err);

  return (0);
}

int shlic_verify(SHFL *file)
{
  SHFL *lic_fl;
  shlic_t lic;
  shfs_t *tree;
  shesig_t *cert;
  shsig_t sig;
  shbuf_t *buff;
  char path[SHFS_PATH_MAX];
  uint64_t lic_crc;
  int err;

  memset(&sig, 0, sizeof(sig));
  err = shfs_sig_get(file, &sig);
  if (err) {
    return (err);
  }

  tree = shfs_inode_tree(file);
  strcpy(path, shfs_sys_dir(SHFS_DIR_LICENSE, shkey_hex(&sig.sig_key)));
  lic_fl = shfs_file_find(tree, path);

  buff = shbuf_init();
  err = shfs_read(lic_fl, buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }

  memset(&lic, 0, sizeof(lic));
  memcpy(&lic, shbuf_data(buff), MIN(shbuf_size(buff), sizeof(shlic_t)));
  shbuf_free(&buff);

  /* verify license checksum */
  lic_crc = lic.lic_crc;
  lic.lic_crc = 0;
  lic.lic_crc = shcrc(&lic, sizeof(lic));
  if (lic_crc != lic.lic_crc) {
    return (SHERR_INVAL);
  }

  /* ensure signature has not expired. */
  if (shtime_before(lic.lic_expire, shtime())) {
    return (SHERR_KEYEXPIRED);
  }

  /* verify license's signature key reference. */
  if (!shkey_cmp(&lic.lic_sig, &sig.sig_key))
    return (SHERR_NOKEY);

  /* verify local file-system partition and inode token */
  if (!shkey_cmp(&lic.lic_fs, shpeer_kpriv(&tree->peer))) {
    return (SHERR_INVAL); /* ~ NOMEDIUM */
  } 
  if (!shkey_cmp(&lic.lic_ino, shfs_token(file))) {
    return (SHERR_INVAL);
  } 

  err = shfs_cert_get(file, &cert, NULL);
  if (err) {
    return (err);
}

  /* verify cerficate's reference */
  if (!shkey_cmp(&lic.lic_cert, shesig_sub_sig(cert))) {
    shesig_free(&cert);
    return (SHERR_KEYREJECTED);
  } 

  /* ensure certificate has not expired. */
  if (shtime_before(shesig_sub_expire(cert), shtime())) {
    shesig_free(&cert);
    return (SHERR_KEYEXPIRED);
  }

  /* .. verify certificate chain .. */

  shesig_free(&cert);
  return (0);
}



int shlic_ecdsa_sign(SHFL *file, shesig_t *cert)
{
  int err;

  err = shfs_sig_ecdsa_gen(file, cert, NULL);
  if (err)
    return (err);

  err = shfs_cert_apply(file, cert);
  if (err)
    return (err);

  return (0);
}

/** 
 * Apply a licensing certificate to a shfs file.
 */
int shlic_certify(SHFL *file, shesig_t *cert)
{

  if (!(cert->cert_flag & SHCERT_CERT_LICENSE)) {
    /* certificate is not capable of licensing digital media. */
    return (SHERR_INVAL);
  }


  if (shesig_sub_alg(cert) & SHALG_ECDSA) {
    shlic_ecdsa_sign(file, cert);
  } else {
    shlic_shr_sign(file, cert);
  }

}


int shlic_ecdsa_verify(SHFL *file)
{
  SHFL *lic_fl;
  shlic_t lic;
  shfs_t *tree;
  shesig_t lic_cert;
  shesig_t pcert;
  shsig_t sig;
  shbuf_t *buff;
  char path[SHFS_PATH_MAX];
  uint64_t lic_crc;
  int err;

  /* obtain and verify licensing certificate attached to file */
  memset(&pcert, 0, sizeof(pcert));
  err = shfs_cert_get(file, &pcert, NULL);
  if (err)
    return (err);

  err = shfs_sig_ecdsa_verify(file, &pcert);
  if (err)
    return (err);

  /* obtain and verify license derived from licensing certificate. */
  memset(&sig, 0, sizeof(sig));
  err = shfs_sig_get(file, &sig);
  if (err)
    return (err);

  tree = shfs_inode_tree(file);
  strcpy(path, shfs_sys_dir(SHFS_DIR_LICENSE, shkey_hex(&sig.sig_key)));
  lic_fl = shfs_file_find(tree, path);

  buff = shbuf_init();
  err = shfs_read(lic_fl, buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }
  memset(&lic_cert, 0, sizeof(lic_cert));
  memcpy(&lic_cert, shbuf_data(buff), MIN(shbuf_size(buff), sizeof(lic_cert)));
  shbuf_free(&buff);

  /* ensure certificate has not expired. */
  if (shtime_before(shesig_sub_expire(&lic_cert), shtime()))
    return (SHERR_KEYEXPIRED);

  /* validate license against it's licensing certificate parent */
  err = shesig_verify(&lic_cert, &pcert);
  if (err)
    return (err);

/* DEBUG: TODO: validate entire chain hierarchy */

  return (0);
}

/**
 * Generate a license based on the file's attached certificate.
 */
int shlic_ecdsa_generate(SHFL *file, shesig_t **cert_p)
{
  shesig_t pcert;
  shesig_t *lic;
  int err;

  memset(&pcert, 0, sizeof(pcert));
  err = shfs_cert_get(file, &pcert, NULL);
  if (err)
    return (err);

  lic = (shesig_t *)calloc(1, sizeof(shesig_t));
  err = shesig_init(&pcert, pcert.cert_sub.ent_name, 0, 
      shesig_sub_alg(&pcert), SHCERT_CERT_DIGITAL | SHCERT_CERT_LICENSE);
  if (err) {
    free(lic);
    return (err);
  }

  *cert_p = lic;
  return (0);
}



#endif


