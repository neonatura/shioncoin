
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
 */


#include "share.h"

static void _shesig_serial_init(uint8_t *raw)
{
  uint64_t *v = (uint64_t *)raw;
  v[0] = shrand();
  v[1] = shrand();
}

static void _shesig_init_default(shesig_t *cert)
{

  /* certificate version */
  cert->ver = SHESIG_VERSION;

  /* assingn current time */
  cert->stamp = shtime_adj(shtime(), -1);

  /* default expiration date */
  cert->expire = shtime_adj(shtime(), SHARE_DEFAULT_EXPIRE_TIME);

  /* record UID of current user */
  cert->uid = shpam_euid();

  /* generate random serial number */
  _shesig_serial_init(cert->ser);

}

int shesig_init(shesig_t *cert, char *entity, int alg, int flags)
{
  shkey_t *key;

  _shesig_init_default(cert);

  /* the relevant name or entity subject */
  memset(cert->ent, 0, sizeof(cert->ent));
  if (entity)
    strncpy(cert->ent, entity, sizeof(cert->ent)-1);

  /* certificate attributes */
  cert->flag = flags;

  /* define algorithm for authentication */
  if (alg == 0)
    alg = SHESIG_ALG_DEFAULT; 
  cert->alg = htonl(alg);

  return (0);
}

int shesig_ca_init(shesig_t *cert, char *entity, int alg, int flags)
{
  return (shesig_init(cert, entity, alg,
        flags | SHCERT_CERT_SIGN | /* !CHAIN & can sign certs */
        SHCERT_AUTH_WEB_CLIENT | SHCERT_AUTH_WEB_SERVER | /* web-ssl */
        SHCERT_CERT_LICENSE | SHCERT_CERT_DIGITAL)); /* shpkg */
}


int shesig_sign(shesig_t *cert, shesig_t *parent, unsigned char *key_data, size_t key_len)
{
  static const unsigned char blank[64];
  static const size_t blank_len = 21;
  shesig_t *d_cert;
  shalg_t in_pub;
  shbuf_t *buff;
  int err;

  if (!key_data || key_len == 0) {
/* .. */
    key_data = (unsigned char *)blank;
    key_len = (size_t)blank_len;
  }

  memset(in_pub, 0, sizeof(in_pub));
  if (parent) {
    if (!(parent->flag & SHCERT_CERT_SIGN)) {
      /* parent certificate lacks ability to sign. */
      return (SHERR_INVAL);
    }

    /* assign issuer's 128-bit serial number (regardless of algorythm)  */
    memcpy(cert->ser, parent->ser, 16);

    if (shtime_after(cert->expire, parent->expire)) {
      /* derived record is not valid unless originating record is */
      cert->expire = parent->expire;
    }
    cert->flag |= parent->flag;
    cert->flag |= SHCERT_CERT_CHAIN;

    /* certificate issuer name */
    memset(cert->iss, 0, sizeof(cert->iss));
    strncpy(cert->iss, parent->ent, sizeof(cert->iss)-1);

    memcpy(in_pub, parent->pub, sizeof(in_pub));

    if (parent->flag & SHCERT_CERT_NONREPUDIATION) {
      if (!shalg_cmp(parent->pub, cert->pub)) {
        /* origin hierarchy is not identical */
        cert->flag &= ~SHCERT_CERT_NONREPUDIATION;
      }
    }
  }

  /* certificate uses redundant encipher to validate */
  cert->flag |= SHCERT_CERT_NONREPUDIATION_ENCIPHER;

#if 0
  /* record byte-size of private key */ 
  cert->plen = htonl(key_len);
#endif

  buff = shbuf_init();
  err = shencrypt_derive(cert, in_pub, buff, key_data, key_len);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }

  if (shbuf_size(buff) < sizeof(shesig_t))
    return (SHERR_INVAL);

  d_cert = (shesig_t *)shbuf_data(buff);
  if (parent && (parent->flag & SHCERT_CERT_NONREPUDIATION)) {
    /* same private key required for all derived records. */
    if (!shalg_cmp(d_cert->pub, parent->pub)) {
      shbuf_free(&buff);
      return (SHERR_ACCESS);
    }
  }

  /* fill [back] computed signatures */
  memcpy(cert, d_cert, sizeof(shesig_t));

  /* store to disk */
  err = shesig_save(cert, buff);
  shbuf_free(&buff);
  if (err)
    return (err);

  return (0);
}

/** Create a certificate which has already been signed. */
int shesig_import(shesig_t *cert, char *iss, shalg_t iss_pub)
{
  static const unsigned char blank[16];
  shbuf_t *buff;
  int err;

  if (!cert)
    return (SHERR_INVAL);

  /* no 'cert->sig' filled */
  memset(cert->sig, '\000', sizeof(cert->sig));
  cert->flag &= ~SHCERT_CERT_NONREPUDIATION_ENCIPHER;

  memset(cert->iss, 0, sizeof(cert->iss));
  if (iss && *iss) {
    cert->flag |= SHCERT_CERT_CHAIN;

    /* validate the authentication data */
    err = shdecrypt_derive_verify(cert, iss_pub);
    if (err)
      return (err);

    /* certificate issuer name */
    strncpy(cert->iss, iss, sizeof(cert->iss)-1);
  } else {
    shalg_t ca_pub;

    memset(ca_pub, 0, sizeof(ca_pub));
    shalg_size(ca_pub) = 21;

    err = shdecrypt_derive_verify(cert, ca_pub);
    if (err)
      return (err);

    /* parent not specified */
    cert->flag &= ~SHCERT_CERT_CHAIN;
  }

  if (0 == memcmp(cert->ser, blank, sizeof(cert->ser))) {
    _shesig_serial_init(cert->ser);
  }

  if (shkey_cmp(ashkey_blank(), &cert->id)) {
    /* assign permanent certificate ID */
    shesig_id_gen(cert);
  }

  /* store to disk */
  buff = shbuf_init();
  shbuf_cat(buff, cert, sizeof(shesig_t));
  err = shesig_save(cert, buff);
  shbuf_free(&buff);
  if (err)
    return (err);

  return (0);
}

int shesig_verify(shesig_t *cert, shesig_t *parent)
{
  shtime_t now;
  int err;

  if (!cert)
    return (SHERR_INVAL);

  now = shtime();
  if (!shtime_after(now, cert->stamp))
    return (SHERR_ACCESS);
  if (!shtime_before(now, cert->expire))
    return (SHERR_KEYEXPIRED);

  if (!(cert->flag & SHCERT_CERT_CHAIN)) {
    /* initial (CA) chain entity */
    if (parent)
      return (SHERR_INVAL);
  }

  if (parent) {
    err = shdecrypt_derive_verify(cert, parent->pub);
  } else {
    shalg_t ca_pub;

    memset(ca_pub, 0, sizeof(ca_pub));
    shalg_size(ca_pub) = 21;

    err = shdecrypt_derive_verify(cert, ca_pub);
  }
  if (err)
    return (err);

  return (0);
}

const char *shesig_serialno(shesig_t *cert)
{
  static char ret_buf[256];
  uint32_t *val;
  int i;

  memset(ret_buf, 0, sizeof(ret_buf));
  val = (uint32_t *)shesig_sub_ser(cert);
  for (i = 0; i < 4; i++) {
    sprintf(ret_buf+strlen(ret_buf), "%-8.8x", val[i]);
  }

  return (ret_buf);
}

static void _shesig_hex_print(shbuf_t *buff, unsigned char *data, size_t data_len, char *line_prefix)
{
  char text[256];
  unsigned int val;
  int i;

  if (!data_len)
    return;

  for (i = 0; i < data_len; i++) {
    if (i != 0) {
      shbuf_catstr(buff, ":");
      if (0 == (i % 22))
        shbuf_catstr(buff, "\n");
    }
    if (0 == (i % 22))
      shbuf_catstr(buff, line_prefix);

    val = (unsigned int)data[i];
    if (val || i < data_len - 3) {
      sprintf(text, "%-2.2x", val);
      shbuf_catstr(buff, text);
    }
  }
  shbuf_catstr(buff, "\n");

}


void shesig_print(shesig_t *cert, shbuf_t *pr_buff)
{
  char tbuf1[256];
  char tbuf2[256];
  char buf[4096];

  if (!cert || !pr_buff)
    return;

  shbuf_catstr(pr_buff, "Certificate:\n");
  shbuf_catstr(pr_buff, "  Data:\n");

  sprintf(buf, "    Version: %u\n", ntohl(cert->ver));
  shbuf_catstr(pr_buff, buf);

  shbuf_catstr(pr_buff, "    Serial Number: ");
  _shesig_hex_print(pr_buff, 
      shesig_sub_ser(cert), sizeof(shesig_sub_ser(cert)), "");

  sprintf(buf, "  Signature Algorithm: %s\n", shalg_str(shesig_sub_alg(cert)));
  shbuf_catstr(pr_buff, buf);

  if ((cert->flag & SHCERT_CERT_CHAIN)) {
    sprintf(buf, "    Issuer: %s\n", cert->iss);
    shbuf_catstr(pr_buff, buf);
  }

  strcpy(tbuf1, shctime(shesig_sub_stamp(cert))+4);
  strcpy(tbuf2, shctime(shesig_sub_expire(cert))+4);
  sprintf(buf, "    Validity: %-20.20s - %-20.20s\n", tbuf1, tbuf2); 
  shbuf_catstr(pr_buff, buf);

  sprintf(buf, "    Subject: %s\n", cert->ent);
  shbuf_catstr(pr_buff, buf);

  sprintf(buf, "    Public Key Algorithm: (%d bit) %s\n",
      shesig_sub_len(cert) * 8, shalg_str(shesig_sub_alg(cert)));
  shbuf_catstr(pr_buff, buf);

  sprintf(buf, "      Checksum: %llu\n", 
      shcrc((unsigned char *)cert->pub, shalg_size(cert->pub)));
  sprintf(buf, "      192-Bit: %s\n", 
      shhex_str((unsigned char *)cert->pub, shalg_size(cert->pub)));
  shbuf_catstr(pr_buff, buf);

#if 0
  if (shesig_sub_alg(cert) & SHALG_RSA) {
    shbuf_catstr(pr_buff, "      Modulus:\n");
    shesig_hex_print_reverse(pr_buff, cert->cert_sub.ent_sig.key.rsa.mod, 
        cert->cert_sub.ent_sig.key.rsa.mod_len, "        ");
  }
#endif

  shbuf_catstr(pr_buff, "    X509v3 extensions:\n");
  sprintf(buf, "      Basic Constraints: CA=%s\n", 
      (cert->flag & SHCERT_CERT_CHAIN) ? "false" : "true");
  shbuf_catstr(pr_buff, buf);

#if 0
  if (!shpeer_localhost(&cert->cert_sub.ent_peer)) {
    sprintf(buf, "      Alternate Subject: %s\n", 
        shpeer_print(&cert->cert_sub.ent_peer));
    shbuf_catstr(pr_buff, buf);
  }
#endif

  sprintf(buf, "      Extended Usage: %s\n", shesig_flag_str(cert->flag));
  shbuf_catstr(pr_buff, buf);

  sprintf(buf, "  Private Signature: %s (%d bytes)\n",
      shalg_str(shesig_sub_alg(cert)), shesig_sub_len(cert));
  shbuf_catstr(pr_buff, buf);

#if 0
  if (shesig_iss_alg(cert) & SHALG_MD5) {
    shesig_hex_print(pr_buff, cert->cert_iss.ent_sig.key.md.md, 
        cert->cert_iss.ent_sig.key.md.md_len, "    ");
  } else if (SHALG(shesig_iss_alg(cert), SHALG_SHA1)) {
    shesig_hex_print(pr_buff, cert->cert_iss.ent_sig.key.sha.sha, 
        cert->cert_iss.ent_sig.key.sha.sha_len, "    ");
  } else if (SHALG(shesig_iss_alg(cert), SHALG_SHA256)) {
    shesig_hex_print(pr_buff, cert->cert_iss.ent_sig.key.sha.sha, 
        cert->cert_iss.ent_sig.key.sha.sha_len, "    ");
  } else {
    sprintf(buf, "    Checksum: %llu\n", shkey_crc(shesig_iss_sig(cert)));
    shbuf_catstr(pr_buff, buf);
    sprintf(buf, "    192-Bit: %s\n", shkey_hex(shesig_iss_sig(cert)));
    shbuf_catstr(pr_buff, buf);
  }
#endif
  sprintf(buf, "    Checksum: %llu\n", 
      shcrc((unsigned char *)cert->data_sig, shalg_size(cert->data_sig)));
  shbuf_catstr(pr_buff, buf);
  sprintf(buf, "    192-Bit: %s\n",
      shhex_str((unsigned char *)cert->data_sig, shalg_size(cert->data_sig)));
  shbuf_catstr(pr_buff, buf);

}

void shesig_id_gen(shesig_t *cert)
{
  shr224_t ctx;

  if (!cert)
    return;

  memset(&ctx, 0, sizeof(ctx));
  shr224_init(&ctx);
  shr224_write(&ctx, (unsigned char *)cert->ser, sizeof(cert->ser));
  shr224_write(&ctx, (unsigned char *)&cert->expire, sizeof(cert->expire));
  shr224_write(&ctx, (unsigned char *)&cert->uid, sizeof(cert->uid));
  shr224_write(&ctx, (unsigned char *)cert->pub, shalg_size(cert->pub));
  shr224_result_key(&ctx, &cert->id);

}

int shesig_id_verify(shesig_t *cert)
{
  shr224_t ctx;
  shkey_t cmp_key;

  if (!cert)
    return;

  memset(&ctx, 0, sizeof(ctx));
  shr224_init(&ctx);
  shr224_write(&ctx, (unsigned char *)cert->ser, sizeof(cert->ser));
  shr224_write(&ctx, (unsigned char *)&cert->expire, sizeof(cert->expire));
  shr224_write(&ctx, (unsigned char *)&cert->uid, sizeof(cert->uid));
  shr224_write(&ctx, (unsigned char *)cert->pub, shalg_size(cert->pub));

  memset(&cmp_key, 0, sizeof(cmp_key));
  shr224_result_key(&ctx, &cmp_key);

  if (!shkey_cmp(&cert->id, &cmp_key))
    return (SHERR_INVAL);

  return (0);
}



char *shesig_flag_str(int flags)
{
  static char ret_buf[1024];

  memset(ret_buf, 0, sizeof(ret_buf));

  if (flags & SHCERT_ENT_INDIVIDUAL)
    strcat(ret_buf, "INDIVIDUAL ");
  if (flags & SHCERT_ENT_ORGANIZATION)
    strcat(ret_buf, "ORGANIZATION ");
  if (flags & SHCERT_ENT_COMPANY)
    strcat(ret_buf, "COMPANY ");
  if (flags & SHCERT_ENT_PRIVATE)
    strcat(ret_buf, "PRIVATE ");

  if (flags & SHCERT_CERT_CHAIN) 
    strcat(ret_buf, "CHAIN ");
  if (flags & SHCERT_CERT_SIGN)
    strcat(ret_buf, "SIGN ");
  if (flags & SHCERT_CERT_DIGITAL)
    strcat(ret_buf, "DIGITAL ");
  if (flags & SHCERT_CERT_CRL)
    strcat(ret_buf, "CRL ");
  if (flags & SHCERT_CERT_KEY)
    strcat(ret_buf, "KEY ");
  if (flags & SHCERT_CERT_ENCIPHER)
    strcat(ret_buf, "ENCIPHER ");
  if (flags & SHCERT_CERT_NONREPUDIATION)
    strcat(ret_buf, "NON-REPUDIATION ");
  if (flags & SHCERT_CERT_LICENSE)
    strcat(ret_buf, "LICENSE ");

  if (flags & SHCERT_AUTH_WEB_CLIENT)
    strcat(ret_buf, "WEB-CLIENT-AUTH ");
  if (flags & SHCERT_AUTH_WEB_SERVER)
    strcat(ret_buf, "WEB-SERVER-AUTH ");
  if (flags & SHCERT_AUTH_FILE)
    strcat(ret_buf, "WEB-FILE ");

  if (*ret_buf)
    ret_buf[strlen(ret_buf)-1] = '\000';

  return (ret_buf);
}


char *shesig_id_hex(shesig_t *cert)
{
  static char sig_name[MAX_SHARE_NAME_LENGTH];

  memset(sig_name, 0, sizeof(sig_name));
  strncpy(sig_name, shkey_hex(&cert->id), sizeof(sig_name)-1);

  return (sig_name);
}




void shesig_free(shesig_t **cert_p)
{
  shesig_t *cert;

  if (!cert_p)
    return;

  cert = *cert_p;
  *cert_p = NULL;

  free(cert);
}









/* member field access */


void shesig_ent_set(shesig_t *cert, char *name)
{
  if (!cert) return;
  memset(cert->ent, 0, sizeof(cert->ent));
  strncpy(cert->ent, name, sizeof(cert->ent)-1);
}

char *shesig_ent(shesig_t *cert)
{
  if (!cert) return (NULL);
  return (cert->ent);
}

void shesig_iss_set(shesig_t *cert, char *name)
{
  if (!cert) return;
  memset(cert->iss, 0, sizeof(cert->iss));
  strncpy(cert->iss, name, sizeof(cert->iss)-1);
}

char *shesig_iss(shesig_t *cert)
{
  if (!cert) return (NULL);
  return (cert->iss);
}

void shesig_stamp_set(shesig_t *cert, shtime_t stamp)
{
  if (!cert) return;
  cert->stamp = stamp;
}

shtime_t shesig_stamp(shesig_t *cert)
{
  if (!cert) return (SHTIME_UNDEFINED);
  return (cert->stamp);
}

void shesig_expire_set(shesig_t *cert, shtime_t stamp)
{
  if (!cert) return;
  cert->expire = stamp;
}

shtime_t shesig_expire(shesig_t *cert)
{
  if (!cert) return (SHTIME_UNDEFINED);
  return (cert->expire);
}

void shesig_ctx_set(shesig_t *cert, shkey_t *ctx_name)
{
  if (!cert) return;
  if (!ctx_name)
    ctx_name = ashkey_blank();
  memcpy(&cert->ctx, ctx_name, sizeof(cert->ctx));
}

void shesig_ctx_name_set(shesig_t *cert, char *label)
{
  shkey_t *key;

  if (!cert)
    return;

  key = shctx_key(label); 
  if (!key)
    return; 

  memcpy(&cert->ctx, key, sizeof(cert->ctx));
  shkey_free(&key);
}

shkey_t *shesig_ctx(shesig_t *cert)
{
  if (!cert) return (NULL);
  return (&cert->ctx);
}

uint64_t shesig_uid(shesig_t *cert)
{
  if (!cert) return (0);
  return (cert->uid);
}

void shesig_version_set(shesig_t *cert, unsigned int ver)
{
  if (!cert) return;
  cert->ver = htonl(ver);
}

unsigned int shesig_version(shesig_t *cert)
{
  if (!cert) return (0);
  return ((unsigned int)ntohl(cert->ver));
}

void shesig_serial_set(shesig_t *cert, unsigned char *serial, size_t serial_len)
{
  unsigned char buf[16];

  memset(buf, 0, sizeof(buf));
  memcpy(buf, serial, MIN(sizeof(buf), serial_len));
}

void shesig_serial(shesig_t *cert, unsigned char *ret_data, size_t *ret_len_p)
{
  if (!cert)
    return;
  memcpy(ret_data, cert->ser, 16);
  if (*ret_len_p)
    *ret_len_p = 16;
}


/* file i/o */

static char *_shesig_filename(shkey_t *id_key)
{
  static char fname[PATH_MAX+1];

  memset(fname, 0, sizeof(fname));
  strncpy(fname, shkey_hex(id_key), sizeof(fname)-1);

  return (fname);
}

static char *_shesig_alias_filename(char *label)
{
  static char fname[PATH_MAX+1];
  memset(fname, 0, sizeof(fname));
  snprintf(fname, sizeof(fname)-1, 
      "alias/%s", shhex_str(label, strlen(label)));
  return (fname);
}

int shesig_save(shesig_t *cert, shbuf_t *buff)
{
  shfs_t *fs;
  SHFL *file;
  int err;

  if (!cert || !buff)
    return (SHERR_INVAL);

  if (shalg_size(cert->pub) == 0 ||
      shalg_size(cert->data_sig) == 0) {
    return (SHERR_INVAL); /* not signed */
}

  /* store in sharefs sytem hierarchy of 'package' partition. */
  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE, _shesig_filename(&cert->id), &file);
  if (!fs)
    return (SHERR_IO);

  err = shfs_write(file, buff);
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  {
    SHFL *l_file;

    /* an alias's link reference to name. */
    l_file = shfs_file_find(fs, shfs_sys_dir(SHFS_DIR_CERTIFICATE, _shesig_alias_filename(cert->ent)));
    shfs_ref_set(l_file, file);
  }

  shfs_free(&fs);

  return (0);
}

int shesig_load_path(char *fname, shesig_t **cert_p)
{
  shfs_t *fs;
  SHFL *file;
  shbuf_t *buff;
  int err;

  /* store in sharefs sytem hierarchy of 'package' partition. */
  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE, fname, &file);
  if (!fs)
    return (SHERR_IO);

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  if (shbuf_size(buff) > sizeof(shesig_t)) {
    /* certificate is verified upon retrieval from disk. */
    err = shdecrypt_verify(shbuf_data(buff), shbuf_size(buff));  
    if (err)
      return (err);
  } else {
    shesig_t *cert = (shesig_t *)shbuf_data(buff);
    if (cert->flag & SHCERT_CERT_NONREPUDIATION_ENCIPHER) {
      /*
       * SHCERT_CERT_NONREPUDIATION_ENCIPHER:
       * Using this flag indicates that the underlying certificate
       * has been encrypted via a supplemental method.
       *
       * Currently, this requires a "shdecrypt_verify()" qualification.
       */ 
      return (SHERR_INVAL);
    }
  }

  if (cert_p) {
    /* returns entire encrypted payload */
    *cert_p = (shesig_t *)shbuf_data(buff);
    free(buff);
  } else {
    shbuf_free(&buff);
  }

  return (0);
}

int shesig_load(shkey_t *id, shesig_t **cert_p)
{
  return (shesig_load_path(_shesig_filename(id), cert_p));
}

int shesig_load_alias(char *label, shesig_t **cert_p)
{
  shfs_t *fs;
  SHFL *file;
shbuf_t *buff;
  int err;

  if (!label)
    return (SHERR_INVAL);

  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE, _shesig_alias_filename(label), &file);
  if (!fs)
    return (SHERR_IO);

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  if (shbuf_size(buff) > sizeof(shesig_t)) {
    err = shdecrypt_verify(shbuf_data(buff), shbuf_size(buff));  
    if (err)
      return (err);
  }

  if (cert_p) {
    shesig_t *ret_cert;

    ret_cert = (shesig_t *)calloc(1, sizeof(shesig_t));
    if (!ret_cert) {
      shbuf_free(&buff);
      return (SHERR_NOMEM);
    }

    memcpy(ret_cert, shbuf_data(buff), sizeof(shesig_t));
    *cert_p = ret_cert;
  }

  return (0);
}

int shesig_remove_label(char *ref_path)
{
  SHFL *file;
  shesig_t *cert;
  shbuf_t *buff;
  shfs_t *fs;
  int err;

  if (!ref_path)
    return (SHERR_INVAL);

  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE, ref_path, &file);
  err = shfs_file_remove(file);
  shfs_free(&fs);
  if (err)
    return (err);

  return (0);
}

int shesig_remove_alias(char *label)
{
  SHFL *file;
  shfs_t *fs;
  int err;

  if (!label)
    return (SHERR_INVAL);

  fs = shfs_sys_init(SHFS_DIR_CERTIFICATE,
      _shesig_alias_filename(label), &file);
  err = shfs_file_remove(file);
  shfs_free(&fs);
  if (err)
    return (err);
/* .. */

  return (0);
}




_TEST(shesig_sign)
{
  unsigned char key_data[64];
  size_t key_len = 64;
  shesig_t *cert;
  char buf[256];
  int idx;
  int err;

  memset(key_data, 1, key_len);
  cert = (shesig_t *)calloc(8, sizeof(shesig_t));
  for (idx = 0; idx < 8; idx++) {
    sprintf(buf, "cert #%d", (idx+1));
    if (idx == 0) {
      _TRUE(shesig_ca_init(cert + idx, buf, SHALG_ECDSA160R, SHCERT_ENT_ORGANIZATION) == 0);
      err = shesig_sign(cert + idx, NULL, key_data, key_len);
      _TRUE(err == 0);
    } else {
      _TRUE(shesig_init(cert + idx, buf, SHALG_ECDSA160R, SHCERT_ENT_ORGANIZATION) == 0);
      err = shesig_sign(cert + idx, cert + (idx -1), key_data, key_len);
      _TRUE(err == 0);
    }
  }

  for (idx = 0; idx < 8; idx++) {
    if (idx == 0) {
      _TRUE(shesig_verify(cert + idx, NULL) == 0);
    } else {
      _TRUE(shesig_verify(cert + idx, (cert + (idx - 1))) == 0);
    }
  }

  free(cert);

}

_TEST(shesig_import)
{
  unsigned char key_data[32];
  char buf[256];
shesig_t ca_cert;
shesig_t t_cert;
shesig_t in_cert;
  size_t key_len;
  int err;

  memset(key_data, 1, sizeof(key_data));
  key_len = 32;

  strcpy(buf, "shesig_import CA");
  err = shesig_ca_init(&ca_cert, buf, SHESIG_ALG_DEFAULT, SHCERT_ENT_ORGANIZATION);
  _TRUE(err == 0);
  err = shesig_sign(&ca_cert, NULL, key_data, key_len);
  _TRUE(err == 0);

  strcpy(buf, "shesig_import");
  err = shesig_init(&t_cert, buf, SHESIG_ALG_DEFAULT, SHCERT_ENT_ORGANIZATION);
  _TRUE(err == 0);
  err = shesig_sign(&t_cert, &ca_cert, key_data, key_len);
  _TRUE(err == 0);

  strcpy(buf, "shesig_import import");
  err = shesig_init(&in_cert, buf, SHESIG_ALG_DEFAULT, SHCERT_ENT_ORGANIZATION);
  _TRUE(err == 0);
  memcpy(in_cert.pub, t_cert.pub, sizeof(in_cert.pub));
  memcpy(in_cert.data_sig, t_cert.data_sig, sizeof(in_cert.data_sig));
  err = shesig_import(&in_cert, ca_cert.ent, ca_cert.pub);
  _TRUE(err == 0);
  err = shesig_verify(&in_cert, &ca_cert); /* data_sig verification only */
  _TRUE(err == 0);

}

