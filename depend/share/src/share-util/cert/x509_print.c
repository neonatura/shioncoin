
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



static void sharetool_cert_print_hex(FILE *out, unsigned char *data, size_t data_len, char *line_prefix)
{
  unsigned int val;
  int i;

  if (!data_len)
    return;

  for (i = 0; i < data_len; i++) {
    if (i != 0) {
      fprintf(out, ":");
      if (0 == (i % 22))
        fprintf(out, "\n");
    }
    if (0 == (i % 22))
      fprintf(out, "%s", line_prefix);

    val = (unsigned int)data[i];
    if (val || i < data_len - 3)
      fprintf(out, "%-2.2x", val);
  }
  fprintf(out, "\n");
}

static void sharetool_cert_print_altname(x509_sequence *subject_alt_name)
{
   size_t i;
  char buf[1024];
    size_t n = sizeof(buf)-1;
    char *p = buf;
    const x509_sequence *cur = subject_alt_name;
    const char *sep = "";
    size_t sep_len = 0;

memset(buf, 0, sizeof(buf));

    while( cur != NULL )
    {
        if( cur->buf.len + sep_len >= n )
        {
            *p = '\0';
            return;// (SHERR_INVAL);
        }

        n -= cur->buf.len + sep_len;
        for( i = 0; i < sep_len; i++ )
            *p++ = sep[i];
        for( i = 0; i < cur->buf.len; i++ )
            *p++ = cur->buf.p[i];

        sep = ", ";
        sep_len = 2;

        cur = cur->next;
    }
fprintf(sharetool_fout, "%s", buf);


}

static char *_reverse(unsigned char *data, size_t data_len)
{
  static shbuf_t *buff;
  int i;

  if (!buff)
    buff = shbuf_init();
  shbuf_clear(buff);

  for (i = data_len - 1; i >= 0; i--) {
    shbuf_cat(buff, data + i, 1);
  }

  return (shbuf_data(buff));
}

void sharetool_cert_print_crt(x509_crt *chain)
{
  x509_name *n;
  char buf[1024];
  struct tm tm;
  shkey_t *key;
  unsigned int val;
  time_t t_from;
  time_t t_expire;
  char t_from_str[256];
  char t_expire_str[256];
  char issuer[1024];
  char subject[1024];
  size_t buf_len;
  size_t pk_len;
  int i;

  fprintf(sharetool_fout, "Certificate:\n");

  fprintf(sharetool_fout,
      "  Data:\n"
      "    Version: %d\n"
      "    Serial Number: ",
      chain->version);
  sharetool_cert_print_hex(sharetool_fout, chain->serial.p+1, chain->serial.len-1, "");
//  fprintf(sharetool_fout, "\n");

  memset(buf, 0, sizeof(buf));
  x509_sig_alg_gets(buf, sizeof(buf)-1, &chain->sig_oid1,
      chain->sig_pk, chain->sig_md, chain->sig_opts );
  fprintf(sharetool_fout, "  Signature Algorithm: %s\n", buf);

  memset(buf, 0, sizeof(buf));
  x509_dn_gets(buf, sizeof(buf)-1, &chain->issuer );
  fprintf(sharetool_fout, "    Issuer: %s\n", buf);

  memset(&tm, 0, sizeof(tm));
  tm.tm_year = chain->valid_from.year - 1900;
  tm.tm_mon = chain->valid_from.mon;
  tm.tm_mday = chain->valid_from.day;
  tm.tm_hour = chain->valid_from.min;
  tm.tm_min = chain->valid_from.min;
  tm.tm_sec = chain->valid_from.sec;
  t_from = mktime(&tm);
  strcpy(t_from_str, ctime(&t_from)+4); 
  strtok(t_from_str, "\n");

  memset(&tm, 0, sizeof(tm));
  tm.tm_year = chain->valid_to.year - 1900;
  tm.tm_mon = chain->valid_to.mon;
  tm.tm_mday = chain->valid_to.day;
  tm.tm_hour = chain->valid_to.min;
  tm.tm_min = chain->valid_to.min;
  tm.tm_sec = chain->valid_to.sec;
  t_expire = mktime(&tm);
  strcpy(t_expire_str, ctime(&t_expire)+4); 
  strtok(t_expire_str, "\n");

  fprintf(sharetool_fout,
      "    Validity: %-20.20s - %s\n",
      t_from_str, t_expire_str);

  memset(buf, 0, sizeof(buf));
  x509_dn_gets(buf, sizeof(buf)-1, &chain->subject );
  fprintf(sharetool_fout, "    Subject: %s\n", buf);

  /* public key */
  pk_len = pk_get_size(&chain->pk);
  fprintf(sharetool_fout,
      "    Public Key Algorithm: (%d bit) %s\n",
      (int)pk_len, pk_get_name(&chain->pk));
  pk_len /= 8;

  if (chain->sig_pk == POLARSSL_PK_RSA) {
    shrsa_t *rsa;
    shbuf_t *buff;

    rsa = pk_rsa(chain->pk);

    buff = shbuf_init();
    shbuf_cat(buff, rsa->N.p, rsa->N.n*sizeof(t_uint));
    shbuf_cat(buff, rsa->E.p, rsa->E.n*sizeof(t_uint));
    key = shkey_bin(shbuf_data(buff), shbuf_size(buff));
    fprintf(sharetool_fout, "    Checksum: %llu\n", shkey_crc(key));
    fprintf(sharetool_fout, "    192-Bit: %s\n", shkey_hex(key));
    shkey_free(&key);
    shbuf_free(&buff);

    
    fprintf(sharetool_fout, "    Modulus:\n");
    sharetool_cert_print_hex(sharetool_fout,
        _reverse((unsigned char *)rsa->N.p, rsa->N.n*sizeof(t_uint)), 
        rsa->N.n * sizeof(t_uint), "      ");
  }


  fprintf(sharetool_fout, "    X509v3 extensions:\n");
  if( chain->ext_types & EXT_BASIC_CONSTRAINTS ){
    fprintf(sharetool_fout, "      Basic Constraints: CA=%s",
        chain->ca_istrue ? "true" : "false" );
    if (chain->max_pathlen > 0) {
      fprintf(sharetool_fout, ", Path-length=%d", (chain->max_pathlen-1));
    }
    fprintf(sharetool_fout, "\n");
  }
  if (chain->ext_types & EXT_SUBJECT_ALT_NAME) {
    fprintf(sharetool_fout, "      Alternate Subject: ");
    sharetool_cert_print_altname(&chain->subject_alt_names);
    fprintf(sharetool_fout, "\n");
  }
  if( chain->ext_types & EXT_NS_CERT_TYPE ) {
    memset(buf, 0, sizeof(buf));
    buf_len = sizeof(buf);
    fprintf(sharetool_fout, "      Certificate Type: ");
    if (chain->ns_cert_type & NS_CERT_TYPE_SSL_CLIENT) fprintf(sharetool_fout,          "SSL-client ");
    if (chain->ns_cert_type & NS_CERT_TYPE_SSL_SERVER) fprintf(sharetool_fout,          "SSL-server ");
    if (chain->ns_cert_type & NS_CERT_TYPE_EMAIL) fprintf(sharetool_fout,               "Email ");
    if (chain->ns_cert_type & NS_CERT_TYPE_OBJECT_SIGNING) fprintf(sharetool_fout,      "Object-signing ");
    if (chain->ns_cert_type & NS_CERT_TYPE_RESERVED) fprintf(sharetool_fout,            "Reserved ");
    if (chain->ns_cert_type & NS_CERT_TYPE_SSL_CA) fprintf(sharetool_fout,              "SSL-CA ");
    if (chain->ns_cert_type & NS_CERT_TYPE_EMAIL_CA) fprintf(sharetool_fout,            "Email-CA ");
    if (chain->ns_cert_type & NS_CERT_TYPE_OBJECT_SIGNING_CA) fprintf(sharetool_fout,   "Object-signing-CA ");
    fprintf(sharetool_fout, "\n");
  }
  if( chain->ext_types & EXT_KEY_USAGE ) {
    fprintf(sharetool_fout, "      Key Usage:");
    if (chain->key_usage & KU_DIGITAL_SIGNATURE) {
      fprintf(sharetool_fout, " Digital-signature");
    } else if (chain->key_usage & KU_NON_REPUDIATION) {
      fprintf(sharetool_fout, " Non-repudiation");
    } else if (chain->key_usage & KU_DATA_ENCIPHERMENT) {
      fprintf(sharetool_fout, " Data-encipherment");
    } else if (chain->key_usage & KU_KEY_AGREEMENT) {
      fprintf(sharetool_fout, " Key-agreement");
    } else if (chain->key_usage & KU_KEY_CERT_SIGN) {
      fprintf(sharetool_fout, " Certificate-sign");
    } else if (chain->key_usage & KU_CRL_SIGN) {
      fprintf(sharetool_fout, " CRL-sign");
    }
    fprintf(sharetool_fout, "\n");
  }
  if( chain->ext_types & EXT_EXTENDED_KEY_USAGE ) {
    const x509_sequence *cur = &chain->ext_key_usage;

    fprintf(sharetool_fout, "      Extended Key Usage:");
    while (cur) {
      char *desc;
      oid_get_extended_key_usage( &cur->buf, &desc );

      fprintf(sharetool_fout, " %s", desc);
      if (cur->next)
        fprintf(sharetool_fout, ",");

      cur = cur->next;
    }
    fprintf(sharetool_fout, "\n");
  }


  /* private key */
  memset(buf, 0, sizeof(buf));
  x509_sig_alg_gets(buf, sizeof(buf)-1, &chain->sig_oid1,
      chain->sig_pk, chain->sig_md, chain->sig_opts );
  fprintf(sharetool_fout, "  Private Signature: %s (%d bit)\n",
      buf, chain->sig.len * 8);
#if 0
  key = shkey_bin(chain->sig.p, chain->sig.len);
  fprintf(sharetool_fout, "    Checksum: %llu\n", shkey_crc(key));
  fprintf(sharetool_fout, "    192-Bit: %s\n", shkey_hex(key));
  shkey_free(&key);
#endif
  sharetool_cert_print_hex(sharetool_fout,
      (unsigned char *)chain->sig.p, chain->sig.len, "    ");

}

