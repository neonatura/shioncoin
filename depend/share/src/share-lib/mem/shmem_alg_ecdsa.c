
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

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "share.h"

#ifdef HAVE_LIBGMP
#include "ecdsa/ecdsa_gmp.h"
#include "ecdsa/ecdsa_param.h"
#include "ecdsa/ecdsa_numbertheory.h"
#include "ecdsa/ecdsa_curves.h"
#include "ecdsa/ecdsa_point.h"
#include "ecdsa/ecdsa_signature.h"
#endif


#define MIN_PRIVATE_KEY_SIZE 28

typedef ecdsa_parameters shcurve_t;




size_t shec_pub_size(int alg)
{
  if (alg & SHALG_384BIT)
    return (49);
  if (alg & SHALG_256BIT)
    return (33);
  if (alg & SHALG_224BIT)
    return (29);
  if (alg & SHALG_160BIT)
    return (21);
  if (alg & SHALG_128BIT)
    return (17);
  return (0);
}

size_t shec_priv_size(int alg)
{
  if (alg & SHALG_384BIT)
    return (304);
  if (alg & SHALG_256BIT)
    return (200);
  if (alg & SHALG_224BIT)
    return (180);
  if (alg & SHALG_160BIT)
    return (128);
  if (alg & SHALG_128BIT)
    return (104);
  return (0);
}

size_t shec_sig_size(int alg)
{
  if (alg & SHALG_384BIT)
    return (96);
  if (alg & SHALG_256BIT)
    return (64);
  if (alg & SHALG_224BIT)
    return (56);
  if (alg & SHALG_160BIT)
    return (40);
  if (alg & SHALG_128BIT)
    return (32);
  return (0);
}

static shcurve_t shec_curve(int alg)
{
  shcurve_t curve;

  /* setup parameters */
  curve = ecdsa_parameters_init();
  if (SHALG(alg, SHALG_ECDSA128R)) { 
    ecdsa_parameters_load_curve(curve, secp128r1);
  } else if (SHALG(alg, SHALG_ECDSA160R)) { 
    ecdsa_parameters_load_curve(curve, secp160r1);
  } else if (SHALG(alg, SHALG_ECDSA160K)) { 
    ecdsa_parameters_load_curve(curve, secp160k1);
  } else if (SHALG(alg, SHALG_ECDSA224R)) {
    ecdsa_parameters_load_curve(curve, secp224r1);
  } else if (SHALG(alg, SHALG_ECDSA224K)) {
    ecdsa_parameters_load_curve(curve, secp224k1);
  } else if (SHALG(alg, SHALG_ECDSA256R)) {
    ecdsa_parameters_load_curve(curve, secp256r1);
  } else if (SHALG(alg, SHALG_ECDSA256K)) {
    ecdsa_parameters_load_curve(curve, secp256k1);
  } else if (SHALG(alg, SHALG_ECDSA384R)) {
    ecdsa_parameters_load_curve(curve, secp384r1);
  }

  return (curve);
}

static void shec_curve_free(shcurve_t curve)
{
  ecdsa_parameters_clear(curve);
}



shec_t *shec_init(int alg)
{
  shec_t *ec;

  ec = (shec_t *)calloc(1, sizeof(shec_t));
  if (!ec)
    return (NULL);

  ec->alg = alg;
  return (ec);
}

void shec_free(shec_t **ec_p)
{
  shec_t *ec;

  if (!ec_p)
    return;
  ec = *ec_p;
  *ec_p = NULL;

  free(ec);
}

char *shec_priv(shec_t *ec)
{
  return (ec->priv);
}


shkey_t *shec_priv_key(shec_t *ec)
{
  shkey_t *key;
  unsigned char *raw_key;

  if (!*ec->priv)
    return (NULL);

  if (!(ec->alg & SHALG_ECDSA))
    return (NULL);

  if (strlen(ec->priv) > 56) {
    return (NULL);
  }

  key = (shkey_t *)calloc(1, sizeof(shkey_t));
  if (!key)
    return (NULL);

  shkey_alg_set(key, ec->alg);

  raw_key = ((unsigned char *)key) + sizeof(uint32_t);
  shhex_bin(ec->priv, raw_key, sizeof(shkey_t) - sizeof(uint32_t));

  return (key);
}

int shec_priv_key_set(shec_t *ec, shkey_t *key)
{
  unsigned char *raw;
  char *hex;

  if (!key)
    return (SHERR_INVAL);

  if (ec->alg != shkey_alg(key))
    return (SHERR_INVAL);

  raw = ((unsigned char *)key) + sizeof(uint32_t);
  memset(ec->priv, '\000', sizeof(ec->priv));
  strncpy(ec->priv, shhex_str(raw, MIN_PRIVATE_KEY_SIZE), sizeof(ec->priv)-1);

  return (0);
}

/** Turns \"secret data\" into a private key. */
char *shec_priv_gen(shec_t *ec, unsigned char *data, size_t data_len)
{
  unsigned char ret_data[512];
  size_t ret_len;
  int err;

  memset(ret_data, 0, sizeof(ret_data));
  memset(ec->priv, '\000', sizeof(ec->priv));

  ret_len = MAX(MIN_PRIVATE_KEY_SIZE, MIN(shec_priv_size(ec->alg), data_len));
  ret_len = MAX(ret_len, shec_priv_size(ec->alg) / 5); /* min 20% */
  if ((ec->alg & SHALG_128BIT) ||
      (ec->alg & SHALG_224BIT)) {
    err = shhkdf(SHALG_SHA224, NULL, 0, data, data_len, 
        NULL, 0, ret_data, ret_len);
  } else {
    err = shhkdf(SHALG_SHA384, NULL, 0, data, data_len, 
        NULL, 0, ret_data, ret_len);
  }
  if (err) {
    return (NULL);
}

  strncpy(ec->priv, shhex_str(ret_data, ret_len), sizeof(ec->priv)-1);

#if 0
  max_size = shec_priv_size(ec->alg);
  size = MAX(MIN_PRIVATE_KEY_SIZE, MIN(max_size, data_len));

  nr = 0;
  step = MAX(1, data_len / size);
  for (of = 0; of < data_len; of += step) {
    size_t len = MIN(MAX(8, step), data_len - of); 
    uint64_t val = shcrc(data + of, len);
    memcpy(raw + (nr*8), &val, 8);
    nr++;
  }

  strncpy(ec->priv, shhex_str(raw, size), sizeof(ec->priv)-1);
#endif

  return (ec->priv);
}

void shec_priv_set(shec_t *ec, char *hex_priv)
{

  memset(ec->priv, '\000', sizeof(ec->priv));

  if (!hex_priv)
    return;

  strncpy(ec->priv, hex_priv, sizeof(ec->priv)-1);
}

/** Generates a random private key. */
char *shec_priv_rand(shec_t *ec)
{
  unsigned char raw[64];

  memset(raw, 0, sizeof(raw));
  memcpy(raw, ashkey_uniq(), sizeof(shkey_t));

  return (shec_priv_gen(ec, raw + sizeof(uint32_t), MIN_PRIVATE_KEY_SIZE));
}

shkey_t *shec_pub_key(shec_t *ec)
{
  shkey_t *key;
  unsigned char *raw_key;

  if (!*ec->pub)
    return (NULL);

  if (!(ec->alg & SHALG_ECDSA))
    return (NULL);

  if (strlen(ec->pub) > 56)
    return (NULL);

  key = (shkey_t *)calloc(1, sizeof(shkey_t));
  if (!key)
    return (NULL);

  shkey_alg_set(key, ec->alg);

  raw_key = ((unsigned char *)key) + sizeof(uint32_t);
  shhex_bin(ec->pub, raw_key, sizeof(shkey_t) - sizeof(uint32_t));

  return (key);
}

int shec_pub_set(shec_t *ec, char *hex_pub)
{

  memset(ec->pub, '\000', sizeof(ec->pub));

  if (!hex_pub)
    return;

  strncpy(ec->pub, hex_pub, sizeof(ec->pub)-1);
}
int shec_pub_key_set(shec_t *ec, shkey_t *key)
{
  unsigned char *raw;
  char *hex;

  if (!key)
    return (SHERR_INVAL);

  if (ec->alg != shkey_alg(key))
    return (SHERR_INVAL);

  raw = ((unsigned char *)key) + sizeof(uint32_t);
  memset(ec->pub, '\000', sizeof(ec->pub));
  strncpy(ec->pub, shhex_str(raw, shec_pub_size(ec->alg)), sizeof(ec->pub)-1);

  return (0);
}

char *shec_pub_gen(shec_t *ec)
{
  ecdsa_parameters curve;
  ecdsa_point Q;
  mpz_t temp;
  mpz_t key;
  char *comp_hex;

  memset(ec->pub, 0, sizeof(ec->pub));

  curve = shec_curve(ec->alg);
  Q = ecdsa_point_init();

  /* initialize private key */
  mpz_init(key);
  mpz_set_str(key, ec->priv, 16);

#if 0
  /* key modulo n */
  mpz_init(temp);
  mpz_mod(temp, key, curve->n);
  mpz_set(key, temp);
  mpz_clear(temp);
#endif
 
  /* generate public key */
  ecdsa_signature_generate_key(Q, key, curve);
  comp_hex = ecdsa_point_compress(Q, shec_pub_size(ec->alg));
  if (!comp_hex) return; // (NULL);
  strncpy(ec->pub, comp_hex, sizeof(ec->pub)-1);
  free(comp_hex);

  ecdsa_point_clear(Q);
  mpz_clear(key);
  shec_curve_free(curve);

  return (ec->pub);
}

char *shec_pub(shec_t *ec)
{

  if (!*ec->pub && *ec->priv) {
    /* generate pub-key on the fly */
    shec_pub_gen(ec);
  }

  return (ec->pub);
}

void shec_msg_hex(int alg, char *ret_str, unsigned char *data, size_t data_len)
{

  *ret_str = '\000';

  if (alg & SHALG_384BIT) {
    shsha_hex(SHALG_SHA384, ret_str, data, data_len);
  } else if (alg & SHALG_256BIT) {
    shsha_hex(SHALG_SHA256, ret_str, data, data_len);
  } else if (alg & SHALG_224BIT) {
    shsha_hex(SHALG_SHA224, ret_str, data, data_len);
  } else {
    shsha_hex(SHALG_SHA1, ret_str, data, data_len);
  }

}

int shec_sign(shec_t *ec, unsigned char *data, size_t data_len)
{
  ecdsa_parameters curve;
  ecdsa_signature sig;
  unsigned char hash[1024];
  char *hex;
  int sig_len;
  mpz_t temp;
  mpz_t key;
  mpz_t m;
  int i;

  if (!*ec->priv)
    return (SHERR_INVAL);

  memset(ec->sig, '\000', sizeof(ec->sig));

  /* setup parameters */
  curve = shec_curve(ec->alg);

  /* generate private key from user-context */
  mpz_init(key);
  mpz_set_str(key, ec->priv, 16);

#if 0
  /* key modulo n */
  mpz_init(temp);
  mpz_mod(temp, key, curve->n);
  mpz_set(key, temp);
#endif

  /* process message into sha1 hash */
  mpz_init(m);
  memset(hash, 0, sizeof(hash));
  shec_msg_hex(ec->alg, hash, data, data_len); 
#if 0
  shsha_hex(SHALG_SHA1, hash, data, data_len);
#endif
  mpz_set_str(m, hash, 16);

  /* msg modulo n */
  mpz_init(temp);
  mpz_mod(temp, m, curve->n);
  mpz_set(m, temp);
  mpz_clear(temp);

  /* generate signature */
  sig = ecdsa_signature_init();
  ecdsa_signature_sign(sig, m, key, curve);

  sig_len = shec_sig_size(ec->alg); /* / 2 * 2 */

  hex = mpz_get_str(NULL, 16, sig->r);
  for (i = strlen(hex); i < sig_len; i++)
    strcat(ec->sig, "0");
  strcat(ec->sig, hex); 
  free(hex);

  hex = mpz_get_str(NULL, 16, sig->s);
  for (i = strlen(hex); i < sig_len; i++)
    strcat(ec->sig, "0");
  strcat(ec->sig, hex);  
  free(hex);

  ecdsa_signature_clear(sig);
  mpz_clear(key);
  mpz_clear(m);
  shec_curve_free(curve);

  return (0);
}

int shec_signstr(shec_t *ec, char *data)
{
  return (shec_sign(ec, (unsigned char *)data, (size_t)strlen(data)));
}

int shec_signnull(shec_t *ec)
{
  static const unsigned char blank[16];

  return (shec_sign(ec, (unsigned char *)blank, sizeof(blank)));
}

int shec_ver(shec_t *ec, unsigned char *data, size_t data_len)
{
  ecdsa_parameters curve;
  ecdsa_signature sig;
  ecdsa_point Q;
  mpz_t temp;
  mpz_t m;
  unsigned char hash[1024];
  char str_r[512];
  char str_s[512];
  int err;
  int ok;

  memset(str_r, 0, sizeof(str_r));
  memset(str_s, 0, sizeof(str_s));

#if 0
  err = shsha_hex(SHALG_SHA1, hash, data, data_len);
  if (err)
    return (err);
#endif

  /* setup parameters */
  curve = shec_curve(ec->alg);

  /* decompress public key */
  Q = ecdsa_point_init();
  ecdsa_point_decompress(Q, ec->pub, curve);

  /* process message into SHA hash */
  mpz_init(m);
  memset(hash, 0, sizeof(hash));
  shec_msg_hex(ec->alg, hash, data, data_len); 
  mpz_set_str(m, hash, 16);

  /* msg modulo n - note standard is bit-length not mod */
  mpz_init(temp);
  mpz_mod(temp, m, curve->n);
  mpz_set(m, temp);
  mpz_clear(temp);

  sig = ecdsa_signature_init();
  strncpy(str_r, ec->sig, (strlen(ec->sig)/2));
  strcpy(str_s, ec->sig + (strlen(ec->sig)/2));
  ecdsa_signature_set_str(sig, str_r, str_s, 16);

  /* verify signature */
  ok = ecdsa_signature_verify(m, sig, Q, curve);

  ecdsa_signature_clear(sig);
  ecdsa_point_clear(Q);
  mpz_clear(m);
  shec_curve_free(curve);

  if (!ok)
    return (SHERR_ACCESS);

  return (0);
}

int shec_verstr(shec_t *ec, char *data)
{
  return (shec_ver(ec, (unsigned char *)data, (size_t)strlen(data)));
}

int shec_vernull(shec_t *ec)
{
  static const unsigned char blank[16];

  return (shec_ver(ec, (unsigned char *)blank, sizeof(blank)));
}

int shec_sig_key_set(shec_t *ec, shkey_t *key)
{
  unsigned char *raw;
  char *hex;

  if (!key)
    return (SHERR_INVAL);

  if (ec->alg != shkey_alg(key))
    return (SHERR_INVAL);

  raw = ((unsigned char *)key) + sizeof(uint32_t);
  memset(ec->sig, '\000', sizeof(ec->sig));
  strncpy(ec->sig, shhex_str(raw, shec_sig_size(ec->alg)), sizeof(ec->sig)-1);

  return (0);
}
int shec_sig_set(shec_t *ec, char *hex_sig)
{

  memset(ec->sig, '\000', sizeof(ec->sig));

  if (!hex_sig)
    return;

  strncpy(ec->sig, hex_sig, sizeof(ec->sig)-1);
}




#define MAX_TEST_ALG 7
static const int _test_alg[MAX_TEST_ALG] = {
  SHALG_ECDSA128R,
  SHALG_ECDSA160R,
  SHALG_ECDSA160K,
  SHALG_ECDSA224R,
  SHALG_ECDSA224K,
  SHALG_ECDSA256R,
  SHALG_ECDSA256K
};
_TEST(shec_sign)
{
  shec_t *ec;
  shkey_t key;
  char *str;
  char *raw;
  int err;
  int i, n;

  raw = (char *)&key;
  for (i = 0; i < MAX_TEST_ALG; i++) {
    for (n = 0; n < 8; n++) {
      memcpy(&key, ashkey_uniq(), sizeof(shkey_t));

      ec = shec_init(_test_alg[i]);
      _TRUEPTR(ec);

      _TRUEPTR(shec_priv_rand(ec));

      _TRUEPTR(shec_pub(ec));

      err = shec_sign(ec, raw, sizeof(shkey_t));
      _TRUE(err == 0);

      err = shec_ver(ec, raw, sizeof(shkey_t));
      _TRUE(err == 0);

      shec_free(&ec);
    }
  }

}

_TEST(shec_key)
{
  shkey_t *key;
  shec_t *ec;
  char o_priv[256];
  char o_pub[256];
  int err;

  ec = shec_init(SHALG_ECDSA128R);
  _TRUEPTR(ec);

  _TRUEPTR(shec_priv_rand(ec));

  key = shec_priv_key(ec);
  _TRUEPTR(key);
  strcpy(o_priv, ec->priv);

  err = shec_priv_key_set(ec, key);
  _TRUE(err == 0);
  _TRUE(0 == strcmp(ec->priv, o_priv));

  _TRUEPTR(shec_pub_gen(ec));

  key = shec_pub_key(ec);
  _TRUEPTR(key);
  strcpy(o_pub, ec->pub);

  err = shec_pub_key_set(ec, key);
  _TRUE(err == 0);
  _TRUE(0 == strcmp(ec->pub, o_pub));

  shec_free(&ec);
}


















/**
 * Convert a public or private key's hex string to a shkey.
 */
shkey_t *shecdsa_key(char *hex_str)
{
  shkey_t *key;
  char buf[16];
  size_t of;
  int hex_len;
  int nr;
  int i;

  key = (shkey_t *)calloc(1, sizeof(shkey_t));
  if (!key)
    return (NULL);

  nr = 0;
  hex_len = strlen(hex_str);
  for (i = 0; i < hex_len && nr < SHKEY_WORDS; i += 8) {
    memset(buf, 0, sizeof(buf));
    strncpy(buf, (hex_str + i), 8);
#if defined(HAVE_STRTOLL)
    key->code[nr++] = (uint32_t)strtoll(buf, NULL, 16);
#else
    key->code[nr++] = (uint32_t)strtol(buf, NULL, 16);
#endif
  } 
  shkey_alg_set(key, SHALG_ECDSA160R);

  return (key);
}



/**
 * Generate a public key.
 */
shkey_t *shecdsa_key_priv(char *hex_seed)
{
#ifdef HAVE_LIBGMP
  ecdsa_parameters curve;
  mpz_t d;
  shkey_t *ret_key;
  shkey_t *ukey;

#if 0
  /* setup parameters */
  curve = ecdsa_parameters_init();
  ecdsa_parameters_load_curve(curve, secp160r1);

  /* public key */
  ecdsa_point Q = ecdsa_point_init();
  ecdsa_point Q_check = ecdsa_point_init();
#endif

  if (hex_seed) {
    ukey = shkey_hexgen(hex_seed);
  } else {
    ukey = shkey_uniq(); /* generate random */
  }
  if (!ukey) {
    return (NULL);
  }
  /* truncate to "21 bytes" */
  ukey->code[5] = (ukey->code[5] & 0xff);
  ukey->code[6] = 0;
//  ukey->code[7] = 0;
  shkey_alg_set(ukey, SHALG_ECDSA160R);

  ret_key = shecdsa_key((char *)shkey_hex(ukey));

  shkey_free(&ukey);

  return (ret_key);
#else
  return (NULL);
#endif
}

shkey_t *shecdsa_key_pub(shkey_t *priv_key)
{
#ifdef HAVE_LIBGMP
  ecdsa_parameters curve;
  mpz_t temp;
  mpz_t key;
  char pub_key[256];
  char *comp_hex;

  /* setup parameters */
  curve = ecdsa_parameters_init();
  ecdsa_parameters_load_curve(curve, secp160r1);

  /* initialize public key */
  ecdsa_point Q = ecdsa_point_init();
  mpz_init(key);
#if 0
  priv_key_hex = shkey_hex(priv_key);
  str_hash = shsha1_hash(priv_key_hex, strlen(priv_key_hex));
  mpz_set_str(key, str_hash, 16);
#endif
  mpz_set_str(key, shkey_hex(priv_key), 16);

#if 0
  /* key modulo n */
  mpz_init(temp);
  mpz_mod(temp, key, curve->n);
  mpz_set(key, temp);
  mpz_clear(temp);
#endif
 
  /* generate public key */
  memset(pub_key, 0, sizeof(pub_key));
  ecdsa_signature_generate_key(Q, key, curve);


  comp_hex = ecdsa_point_compress(Q, 21); 
  if (!comp_hex) return (NULL);
  strncpy(pub_key, comp_hex, sizeof(pub_key)-1);
  free(comp_hex);

  ecdsa_parameters_clear(curve);
  ecdsa_point_clear(Q);
  mpz_clear(key);

  return (shecdsa_key(pub_key));
#else
  return (NULL);
#endif
}

const char *shecdsa_pub(const char *hex_str)
{
#ifdef HAVE_LIBGMP
  static char pub_key[256];
  ecdsa_parameters curve;
  mpz_t temp;
  mpz_t key;
  char *comp_hex;

  memset(pub_key, 0, sizeof(pub_key));

  /* setup parameters */
  curve = ecdsa_parameters_init();
  ecdsa_parameters_load_curve(curve, secp160r1);

  /* initialize public key */
  ecdsa_point Q = ecdsa_point_init();
  mpz_init(key);
#if 0
  priv_key_hex = shkey_hex(priv_key);
  str_hash = shsha1_hash(priv_key_hex, strlen(priv_key_hex));
  mpz_set_str(key, str_hash, 16);
#endif
  mpz_set_str(key, hex_str, 16);

#if 0
  /* key modulo n */
  mpz_init(temp);
  mpz_mod(temp, key, curve->n);
  mpz_set(key, temp);
  mpz_clear(temp);
#endif
 
  /* generate public key */
  memset(pub_key, 0, sizeof(pub_key));
  ecdsa_signature_generate_key(Q, key, curve);

  comp_hex = ecdsa_point_compress(Q, 21); 
  if (!comp_hex) return (NULL);
  strncpy(pub_key, comp_hex, sizeof(pub_key)-1);
  free(comp_hex);

  ecdsa_parameters_clear(curve);
  ecdsa_point_clear(Q);
  mpz_clear(key);

  return (pub_key);
#else
  return (NULL);
#endif
}

int shecdsa_sign(shkey_t *priv_key, char *sig_r, char *sig_s, unsigned char *data, size_t data_len)
{
#ifdef HAVE_LIBGMP
  ecdsa_parameters curve;
  ecdsa_signature sig;
  mpz_t temp;
  mpz_t key;
  mpz_t m;
  unsigned char hash[512];
  char *hex;
  int sig_len;
  int i;

  /* setup parameters */
  curve = ecdsa_parameters_init();
  ecdsa_parameters_load_curve(curve, secp160r1);

  /* generate private key from user-context */
  mpz_init(key);
#if 0
  priv_key_hex = shkey_hex(priv_key);
  hash = shsha1_hash(priv_key_hex, strlen(priv_key_hex));
  mpz_set_str(key, hash, 16);
#endif
  mpz_set_str(key, shkey_hex(priv_key), 16);

#if 0
  /* key modulo n */
  mpz_init(temp);
  mpz_mod(temp, key, curve->n);
  mpz_set(key, temp);
#endif

  /* process message into sha1 hash */
  mpz_init(m);
  memset(hash, 0, sizeof(hash));
  shsha_hex(SHALG_SHA1, hash, data, data_len);
  //hash = shsha1_hash(data, data_len);
  mpz_set_str(m, hash, 16);

  /* msg modulo n */
  mpz_init(temp);
  mpz_mod(temp, m, curve->n);
  mpz_set(m, temp);
  mpz_clear(temp);

  /* generate signature */
  sig = ecdsa_signature_init();
  ecdsa_signature_sign(sig, m, key, curve);

#if 0
  {
    FILE *out = stdout;
    fprintf(out, "Signature:\n\tR:");
    mpz_out_str(out, 16, sig->r);
    fprintf(out, "\n\tS:");
    mpz_out_str(out, 16, sig->s);
    fprintf(out, "\n");
  }
#endif

  sig_len = shec_sig_size(SHALG_ECDSA160R);

  hex = mpz_get_str(NULL, 16, sig->r);
  memset(sig_r, 0, sizeof(sig_r));
  for (i = strlen(hex); i < sig_len; i++)
    strcat(sig_r, "0");
  strcat(sig_r, hex); 
  free(hex);

  hex = mpz_get_str(NULL, 16, sig->s);
  memset(sig_s, 0, sizeof(sig_s));
  for (i = strlen(hex); i < sig_len; i++)
    strcat(sig_s, "0");
  strcat(sig_s, hex); 
  free(hex);

  ecdsa_parameters_clear(curve);
  ecdsa_signature_clear(sig);
  mpz_clear(key);
  mpz_clear(m);

  return (0);
#else
  return (SHERR_OPNOTSUPP);
#endif
}

int shecdsa_verify(shkey_t *pub_key, char *str_r, char *str_s, unsigned char *data, size_t data_len)
{
#ifdef HAVE_LIBGMP
  ecdsa_parameters curve;
  ecdsa_signature sig;
  ecdsa_point Q;
  mpz_t temp;
  mpz_t m;
  unsigned char hash[512];
  int ok;


  /* setup parameters */
  curve = ecdsa_parameters_init();
  ecdsa_parameters_load_curve(curve, secp160r1);

  /* decompress public key */
  Q = ecdsa_point_init();
  ecdsa_point_decompress(Q, (char *)shkey_hex(pub_key), curve);

  /* process message into sha1 hash */
  mpz_init(m);
  memset(hash, 0, sizeof(hash));
  shsha_hex(SHALG_SHA1, hash, data, data_len);
  //hash = shsha1_hash(data, data_len);
  mpz_set_str(m, hash, 16);

  /* msg modulo n - note standard is bit-length not mod */
  mpz_init(temp);
  mpz_mod(temp, m, curve->n);
  mpz_set(m, temp);
  mpz_clear(temp);

  sig = ecdsa_signature_init();
  ecdsa_signature_set_str(sig, str_r, str_s, 16);

  /* verify signature */
  ok = ecdsa_signature_verify(m, sig, Q, curve);

  ecdsa_parameters_clear(curve);
  ecdsa_signature_clear(sig);
  ecdsa_point_clear(Q);
  mpz_clear(m);

  if (!ok)
    return (SHERR_ACCESS);


  return (0);
#else
  return (SHERR_OPNOTSUPP);
#endif
}
 

_TEST(ecdsa)
{
#ifdef HAVE_LIBGMP
  shkey_t *ukey;
  mpz_t d;
  mpz_t m;

  //Setting up domain parameters
  ecdsa_parameters curve = ecdsa_parameters_init();
  ecdsa_parameters_load_curve(curve, secp160r1);

  //Public key
  ecdsa_point Q = ecdsa_point_init();

  //Message
  mpz_init(m);

  //Private key
  mpz_init(d);

  //Signature
  ecdsa_signature sig = ecdsa_signature_init();

  //Message hash just a random number
  mpz_set_str(m, "2156842181254876268462177895321953219548746516484", 10);

  /* set private key to random "21 byte" integer */
  ukey = shkey_uniq(); /* generate random */
  ukey->code[5] = (ukey->code[5] & 0xff);
  ukey->code[6] = 0;
//  ukey->code[7] = 0;
  mpz_set_str(d, shkey_hex(ukey), 16);
  shkey_free(&ukey);

  //Generate ecdsa_signature
  ecdsa_signature_sign(sig, m, d, curve);

  //Generate public key
  ecdsa_signature_generate_key(Q, d, curve);

  //Verify result
  int result = ecdsa_signature_verify(m, sig, Q, curve);

  //Release memory
  mpz_clear(m);
  mpz_clear(d);
  ecdsa_point_clear(Q);
  ecdsa_signature_clear(sig);
  ecdsa_parameters_clear(curve);

  _TRUE(result);
#endif
}




_TEST(shecdsa)
{
#ifdef HAVE_LIBGMP
  shkey_t priv_key;
  shkey_t pub_key;
  shkey_t *key;
  char msg[256];
  char sig_r[1024];
  char sig_s[1024];
  int err;
  int idx;

  for (idx = 1; idx < 32; idx++) {
    memset(sig_r, 0, sizeof(sig_r));
    memset(sig_s, 0, sizeof(sig_s));

    /* fill test message. */
    memset(msg, (char)idx, sizeof(msg));

    /* obtain random key. */
    key = shecdsa_key_priv(NULL);
    _TRUEPTR(key);
    memcpy(&priv_key, key, sizeof(priv_key));
    shkey_free(&key);

    /* obtain public counter-part key. */
    key = shecdsa_key_pub(&priv_key);
    _TRUEPTR(key);
    memcpy(&pub_key, key, sizeof(pub_key));
    shkey_free(&key);

    /* sign the message with private key. */
    err = shecdsa_sign(&priv_key, sig_r, sig_s, msg, sizeof(msg));
    _TRUE(err == 0);

    /* verify the message with public key. */
    err = shecdsa_verify(&pub_key, sig_r, sig_s, msg, sizeof(msg));
    if (err) {
      fprintf(stderr, "DEBUG: TEST FAIL: PRV: %s\n", shkey_hex(&priv_key));
      fprintf(stderr, "DEBUG: TEST FAIL: PUB: %s\n", shkey_hex(&pub_key));
    }
    _TRUE(err == 0);
  }

#endif
}

_TEST(shecdsa_integrity)
{
#ifdef HAVE_LIBGMP
  ecdsa_parameters curve;
  ecdsa_point Q;
  shkey_t *priv_key;
  shkey_t *pub_key;
  int idx;

  /* setup parameters */
  curve = ecdsa_parameters_init();
  ecdsa_parameters_load_curve(curve, secp160r1);

  priv_key = shecdsa_key_priv(NULL);
  _TRUEPTR(priv_key);

  pub_key = shecdsa_key_pub(priv_key);
  _TRUEPTR(pub_key);

  /* decompress public key */
  Q = ecdsa_point_init();
  ecdsa_point_decompress(Q, (char *)shkey_hex(pub_key), curve);

  //A guessing ecdsa_point
  ecdsa_point guess = ecdsa_point_init();
  ecdsa_point_set(guess, curve->G);

  //A second guessing ecdsa_point explanation follows
  ecdsa_point guess2 = ecdsa_point_init();

  //Initialize two counter
  mpz_t i; mpz_init(i);
  mpz_t i2; mpz_init(i2);
  mpz_set_ui(i, 0);

  /* attempt a high-volume of guesses */
  for (idx = 0; idx < 100000; idx++) {
    //Break the loop if our guess matches the public key
    if(ecdsa_point_cmp(guess,Q))
      break;

    //Add G to the guess, store it in guess two (it can't be stored in guess)
    ecdsa_point_addition(guess2, guess, curve->G, curve);

    //Add one to our counter
    mpz_add_ui(i2, i, 1);

    //Break the loop if our guess matches the public key
    if(ecdsa_point_cmp(guess2,Q))
      break;

    //Add G to the guess2, store it in guess (it can't be stored in guess2)
    ecdsa_point_addition(guess, guess2, curve->G, curve);

    //Add one to our counter
    mpz_add_ui(i, i2, 1);
  }
  _TRUE(idx == 100000);

  if(mpz_cmp(i,i2) < 0)
    mpz_set(i, i2);
#if 0
  {
    FILE *out = stdout;
    fprintf(out, "Hashsum of the private key is:\n");
    mpz_out_str(out, 16, i);
    fprintf(out, "\n");
  }
#endif

  shkey_free(&priv_key);
  shkey_free(&pub_key);

  ecdsa_parameters_clear(curve);
  ecdsa_point_clear(Q);
  ecdsa_point_clear(guess);
  mpz_clear(i);

#endif /* HAVE_LIBGMP */
}



#if 0
static void *_memxor (void *restrict dest, const void *restrict src, size_t n)
{
  char const *s = (const char *)src;
  char *d = (char *)dest;

  for (; n > 0; n--)
    *d++ ^= *s++;

  return dest;
}
#define IPAD 0x36
#define OPAD 0x5c
static int _sha512_hmac(const unsigned char *key, size_t keylen,
    const unsigned char *in, size_t inlen, unsigned char *resbuf)
{
  sh_sha512_t inner;
  sh_sha512_t outer;
  unsigned char optkeybuf[64];
  unsigned char block[128];
  unsigned char innerhash[64];

  /* Reduce the key's size, so that it becomes <= 64 bytes large.  */

  if (keylen > 128)
  {
    sh_sha512_t keyhash;

    sh_sha512_init (&keyhash);
    sh_sha512_update (&keyhash, key, keylen);
    sh_sha512_final (&keyhash, optkeybuf);

    key = optkeybuf;
    keylen = 64;
  }

  /* Compute INNERHASH from KEY and IN.  */

  sh_sha512_init (&inner);

  memset (block, IPAD, sizeof (block));
  _memxor (block, key, keylen);

  sh_sha512_process (&inner, block); /* 128 bytes */
  sh_sha512_update (&inner, in, inlen);

  sh_sha512_final (&inner, innerhash);

  /* Compute result from KEY and INNERHASH.  */

  sh_sha512_init (&outer);

  memset (block, OPAD, sizeof (block));
  _memxor (block, key, keylen);

  sh_sha512_process (&outer, block); /* 128 bytes */
  sh_sha512_update (&outer, innerhash, 64);

  sh_sha512_final (&outer, resbuf);

  return 0;
}
#endif

bool hex2bin(unsigned char *p, const char *hexstr, size_t len);

void bin2hex(char *str, unsigned char *bin, size_t bin_len);

static char *_padd_hex(char *hex_str, size_t hex_len)
{
  char buf[1024];
  off_t of;

  if (strlen(hex_str) >= hex_len)
    return (hex_str);

  memset(buf, 0, sizeof(buf));
  strncpy(buf, hex_str, sizeof(buf)-1);

  memset(hex_str, 0, hex_len+1);
  memset(hex_str, '0', hex_len);

  of = MAX(0, hex_len - strlen(buf));
  strncpy(hex_str + of, buf, strlen(buf));

  return (hex_str);
}

#if 0
/**
 * @param secret The secret key in hexadecimal format.
 */
char *shecdsa_hd_point_hex(char *secret)
{
#ifdef HAVE_LIBGMP
  static char ret_buf[256];
  ecdsa_parameters curve = ecdsa_parameters_init();
  ecdsa_point Q = ecdsa_point_init();
  mpz_t key;
  char ret_x[256];
  char ret_y[256];
  char *hex;
  int of;

  ecdsa_parameters_load_curve(curve, secp256k1);

  mpz_init(key);
  mpz_set_str(key, secret, 16);

/* note that secret could be theoretically loaded as decompressed point */

  /* generate public key */
  ecdsa_signature_generate_key(Q, key, curve);

  mpz_get_str(ret_y, 16, Q->y);
  mpz_get_str(ret_x, 16, Q->x);
  _padd_hex(ret_y, 64);
  _padd_hex(ret_x, 64);

  memset(ret_buf, 0, sizeof(ret_buf));
  strcpy(ret_buf, "04");
  strcat(ret_buf, ret_y);
  strcat(ret_buf, ret_x);

  mpz_clear(key);
  ecdsa_point_clear(Q);
  ecdsa_parameters_clear(curve);

  return (ret_buf);
#else
  return (NULL);
#endif /* HAVE_LIBGMP */
}
#endif

char *shecdsa_hd_point_chex(ecdsa_point Q)
{
  static char ret_buf[512];
  char *str;

  str = ecdsa_point_compress(Q, 33);
  if (!str)
    return (NULL);

  strncpy(ret_buf, str, sizeof(ret_buf));
//  _padd_hex(ret_buf, 66); 

  return (ret_buf);
}

char *shecdsa_hd_point_dhex(ecdsa_point Q)
{
  static char ret_buf[512];
  char hex_x[256];
  char hex_y[256];

  mpz_get_str(hex_y, 16, Q->y);
  mpz_get_str(hex_x, 16, Q->x);

  _padd_hex(hex_y, 64);
  _padd_hex(hex_x, 64);

  memset(ret_buf, 0, sizeof(ret_buf));
  strcpy(ret_buf, "04");
  strcat(ret_buf, hex_y);
  strcat(ret_buf, hex_x);

  return (ret_buf);
}

/** 
 * Convert from a compressed/decompressed hexadecimal representation to a point.
 */
int shecdsa_hd_point_set(ecdsa_point Q, char *hex, int *fCompr)
{
  char hex_x[256];
  char hex_y[256];

  if (strlen(hex) == 130) { /* uncompressed */
    ecdsa_point_set_hex(Q, hex_x, hex_y);
    if (fCompr) *fCompr = FALSE;
  } else if (strlen(hex) == 66) { /* compressed */
    ecdsa_parameters curve = ecdsa_parameters_init();
    ecdsa_parameters_load_curve(curve, secp256k1);
    ecdsa_point_decompress(Q, hex, curve);
    ecdsa_parameters_clear(curve);
    if (fCompr) *fCompr = TRUE;
  } else {
    return (SHERR_INVAL);
  }

  return (0);
}

#if 0
char *shecdsa_hd_point(char *secret)
{
#ifdef HAVE_LIBGMP
  static char ret_buf[512];
  ecdsa_parameters curve = ecdsa_parameters_init();
  ecdsa_point Q = ecdsa_point_init();
  mpz_t key;
  char hex_y[256];
  char hex_x[256];

  ecdsa_parameters_load_curve(curve, secp256k1);

  mpz_init(key);
  mpz_set_str(key, secret, 16);

  /* generate public key */
  ecdsa_signature_generate_key(Q, key, curve);

  mpz_get_str(hex_y, 16, Q->y);
  mpz_get_str(hex_x, 16, Q->x);
  _padd_hex(hex_y, 64);
  _padd_hex(hex_x, 64);

  memset(ret_buf, 0, sizeof(ret_buf));
  strcpy(ret_buf, "04");
  strcat(ret_buf, hex_y);
  strcat(ret_buf, hex_x);

  mpz_clear(key);
  ecdsa_point_clear(Q);
  ecdsa_parameters_clear(curve);

  return (ret_buf);
#else
  return (NULL);
#endif /* HAVE_LIBGMP */
}
#endif

char *shecdsa_hd_pubkey(char *pubkey, char *chain, uint32_t idx)
{
  static char ret_buf[256];
#ifdef HAVE_LIBGMP
  ecdsa_parameters curve;
  mpz_t temp;
  mpz_t s;
  char buf[256];
  unsigned char data[256];
  unsigned char chain_data[256];
  char hmac_l_hex[256];
  char hmac[256];
  char hmac_l[256];
  char hmac_r[256];
  ecdsa_point R;
  ecdsa_point Q;
  ecdsa_point P;
  char t_buf[256];
  int of;
  int len;
  char *hex;
  char p[256];
  char k[256];
  int fCompr;
  int err;
  int i;

  memset(p, 0, sizeof(p));
  memset(k, 0, sizeof(k));

  /* compress point */
  P = ecdsa_point_init();
  err = shecdsa_hd_point_set(P, pubkey, &fCompr); 
  if (err) {
    ecdsa_point_clear(P);
    return (NULL);
  }
  len = 33;
  hex = ecdsa_point_compress(P, len);
//if (strlen(hex) != 66) fprintf(stderr, "DEBUG: shecdsa_hd_pubkey: warning: pubkey is %d characters: '%s'\n", strlen(hex), hex);
  hex2bin(data, hex, len);
  strncpy(k, hex, sizeof(k)-1);

  /* append sequence index */
  idx = htonl(idx); 
  memcpy(data + len, &idx, sizeof(idx));
  len += sizeof(idx);

  /* encode chain as binary (32 byte) segment */
//if (strlen(chain) != 64) fprintf(stderr, "DEBUG: shecdsa_hd_pubkey: warning: chain is %d bytes\n", strlen(chain)/2);
  hex2bin(chain_data, chain, 32);
 
  /* hash <point+index> using chain as key */
  memset(hmac, 0, sizeof(hmac));
  memset(hmac_l, 0, sizeof(hmac_l));
  memset(hmac_r, 0, sizeof(hmac_r));
  shhmac(SHALG_SHA512, chain_data, 32, data, len, hmac);
  bin2hex(hmac_l, hmac, 32);
  bin2hex(hmac_r, hmac + 32, 32);

  curve = ecdsa_parameters_init();
  ecdsa_parameters_load_curve(curve, secp256k1);

  Q = ecdsa_point_init();
  mpz_init(s);
  mpz_set_str(s, hmac_l, 16);
  ecdsa_signature_generate_key(Q, s, curve);
  mpz_clear(s);

  R = ecdsa_point_init();
  ecdsa_point_addition(R, P, Q, curve);

  if (fCompr) {
    strncpy(ret_buf, shecdsa_hd_point_chex(R), sizeof(ret_buf)-1);
  } else {
    strncpy(ret_buf, shecdsa_hd_point_dhex(R), sizeof(ret_buf)-1);
  }

  ecdsa_point_clear(P);
  ecdsa_point_clear(Q);
  ecdsa_point_clear(R);


  ecdsa_parameters_clear(curve);

  /* return new chain sequence */
  memset(chain, 0, 65);
  strncpy(chain, hmac_r, 64);

#endif /* HAVE_LIBGMP */
  return (ret_buf);
}

char *shecdsa_hd_privkey(char *secret, char *chain, uint32_t idx)
{
  static char ret_buf[256];
#ifdef HAVE_LIBGMP
  mpz_t pk;
  mpz_t hl;
  mpz_t r;
  mpz_t temp;
  mpz_t key;
  ecdsa_point Q;
  char buf[256];
  unsigned char data[256];
  unsigned char chain_data[256];
  char hmac[256];
  char hmac_l[256];
  char hmac_r[256];
  char hex_x[256];
  char hex_y[256];
  char hex_buf[1024];
  char *hex;
  uint32_t val;
  int i;
  size_t len;
  char pubkey[256];
  int fCompr;

  ecdsa_parameters curve;
  curve = ecdsa_parameters_init();
  ecdsa_parameters_load_curve(curve, secp256k1);

  mpz_init(key);
  Q = ecdsa_point_init();
  mpz_set_str(key, secret, 16);
  ecdsa_signature_generate_key(Q, key, curve);
  mpz_clear(key);

  memset(pubkey, 0, sizeof(pubkey));
  strncpy(pubkey, shecdsa_hd_point_chex(Q), sizeof(pubkey)-1);

  len = 33;
  hex2bin(data, pubkey, len);

  /* append sequence index */
  idx = htonl(idx); 
  memcpy(data + len, &idx, sizeof(idx)); /* +4 (=37) bytes */
  len += sizeof(idx);
//if (len != 37) fprintf(stderr, "DEBUG: shecdsa_hd_privkey: abnormal hmac data length <%d bytes>.\n", len);
#if 0
  memcpy(data + 33, &idx, sizeof(idx)); /* +4 (=37) bytes */
  len = 37;
#endif

  hex2bin(chain_data, chain, 32);
 
  memset(hmac, 0, sizeof(hmac));
  memset(hmac_l, 0, sizeof(hmac_l));
  memset(hmac_r, 0, sizeof(hmac_r));
  shhmac(SHALG_SHA512, chain_data, 32, data, len, hmac);
  bin2hex(hmac_l, hmac, 32);
  bin2hex(hmac_r, hmac + 32, 32);

  mpz_init(pk);
  mpz_init(hl);
  mpz_init(r);

  mpz_set_str(pk, secret, 16);
  mpz_set_str(hl, hmac_l, 16);
  mpz_add(r, hl, pk);

  /* key modulo n */
  mpz_init(temp);
  mpz_mod(temp, r, curve->n);
  mpz_set(r, temp);
  mpz_clear(temp);

  mpz_get_str(ret_buf, 16, r);
  _padd_hex(ret_buf, 64);

  mpz_clear(pk);
  mpz_clear(hl);
  mpz_clear(r);

  ecdsa_point_clear(Q);
  ecdsa_parameters_clear(curve);

  /* return new chain sequence */
  memset(chain, 0, 65);
  strncpy(chain, hmac_r, 64);

#endif /* HAVE_LIBGMP */
  return (ret_buf);
}

#if 0
char *shecdsa_hd_priv2pub(char *secret, char *chain, uint32_t self_idx)
{
  char *pub_hex;
  char *hex;

  pub_hex = shecdsa_hd_point_hex(secret); 
  hex = shecdsa_hd_pubkey(pub_hex, chain, self_idx);

  return (hex);
}

char *shecdsa_hd_priv2pub2(char *secret, char *chain, uint32_t self_idx)
{
  char t_secret[512];

  memset(t_secret, 0, sizeof(t_secret));
  strncpy(t_secret, shecdsa_hd_privkey(secret, chain, self_idx), sizeof(t_secret)-1);
  return (shecdsa_hd_point_hex(t_secret));
}
#endif

char *shecdsa_hd_par_pub(char *p_secret, char *p_chain, uint32_t idx)
{
  static char ret_buf[1024];
  char pubkey[512];

  memset(ret_buf, 0, sizeof(ret_buf));

  memset(pubkey, 0, sizeof(pubkey));
  strncpy(pubkey, shecdsa_hd_recover_pub(p_secret), sizeof(pubkey)-1);

  memset(ret_buf, 0, sizeof(ret_buf));
  strncpy(ret_buf, shecdsa_hd_pubkey(pubkey, p_chain, idx), sizeof(ret_buf)-1);

  return (ret_buf);
}

char *shecdsa_hd_recover_pub(char *secret)
{
  static char ret_buf[1024];
  ecdsa_parameters curve = ecdsa_parameters_init();
  ecdsa_point Q = ecdsa_point_init();
  mpz_t key;
  char ret_x[256];
  char ret_y[256];
  char *hex;
  int of;

  memset(ret_buf, 0, sizeof(ret_buf));

  ecdsa_parameters_load_curve(curve, secp256k1);

  mpz_init(key);
  mpz_set_str(key, secret, 16);
  ecdsa_signature_generate_key(Q, key, curve);
  
  hex = ecdsa_point_compress(Q, 33);
  if (!hex) return (NULL);
  strncpy(ret_buf, hex, sizeof(ret_buf));
  free(hex);

  mpz_clear(key);
  ecdsa_point_clear(Q);
  ecdsa_parameters_clear(curve);

  return (ret_buf);
}

char *shecdsa_hd_seed(char *seed_hex, char *chain)
{
  static char ret_buf[512];
  uint32_t magic = SHMEM32_MAGIC;
  unsigned char *raw_magic = (unsigned char *)&magic;
  unsigned char hmac[256];
  size_t seed_len;
  char hmac_l[256];
  char hmac_r[256];
  unsigned char seed[256];
  int err;

  memset(hmac, 0, sizeof(hmac));

  seed_len = MIN(sizeof(seed)*2, strlen(seed_hex)/2);
  hex2bin(seed, seed_hex, seed_len); 

  memset(hmac_l, 0, sizeof(hmac_l));
  memset(hmac_r, 0, sizeof(hmac_r));
  err = shhmac(SHALG_SHA512, seed, seed_len, raw_magic, sizeof(uint32_t), hmac);
  if (err) {
    sherr(err, "hmac [shecdsa_hd_seed]");
    return (NULL);
  }

  bin2hex(hmac_l, hmac, 32);
  bin2hex(hmac_r, hmac + 32, 32);

  if (chain) {
    /* return new chain sequence */
    strcpy(chain, hmac_r);
  }
  
  memset(ret_buf, 0, sizeof(ret_buf));
  strncpy(ret_buf, hmac_l, sizeof(ret_buf)-1);

  return (ret_buf);
}




static int _test_shecdsa_hd_derive(char *master_secret, char *master_pubkey, char *m_chain, int idx)
{
  static char last_privkey[256];
  char *pubkey_hex;
  char *privkey_hex;
  char r_chain[256];
  char pub_chain[256];
  char priv_chain[256];
  char pubkey2_hex[256];
  char pubkey3_hex[256];

  /* derive private key */
  strcpy(priv_chain, m_chain);
  privkey_hex = shecdsa_hd_privkey(master_secret, priv_chain, idx);

  /* derive public key */
  strcpy(pub_chain, m_chain);
  pubkey_hex = shecdsa_hd_pubkey(master_pubkey, pub_chain, idx);

  strcpy(pubkey2_hex, shecdsa_hd_recover_pub(privkey_hex));

  strcpy(r_chain, m_chain);
  strcpy(pubkey3_hex, shecdsa_hd_par_pub(master_secret, r_chain, idx));


  if (0 != strcmp(pub_chain, priv_chain)) {
    return (-1);
  }
  if (0 != strcmp(pub_chain, r_chain)) {
    return (-1);
  }

  if (0 == strcmp(last_privkey, privkey_hex)) {
    return (-1);
  }
  memset(last_privkey, 0, sizeof(last_privkey));
  strncpy(last_privkey, privkey_hex, sizeof(last_privkey)-1);

  if (0 != strcmp(pubkey_hex, pubkey2_hex)) {
    return (-1);
  }

  if (0 != strcmp(pubkey_hex, pubkey3_hex)) {
    return (-1);
  }

  return (0);
}



_TEST(shecdsa_hd)
{
  const char *m_seed = "7384f492935706bcc8b6a844d90e5c04e0b77907e0fbd3c2da6abc4ba61447da";
  char m_pubkey[256];
  char m_chain[256];
  char m_secret[256];
  int idx;

  memset(m_chain, 0, sizeof(m_chain));
  memset(m_secret, 0, sizeof(m_secret));
  strcpy(m_secret, shecdsa_hd_seed((char *)m_seed, m_chain));

  memset(m_pubkey, 0, sizeof(m_pubkey));
  strcpy(m_pubkey, shecdsa_hd_recover_pub(m_secret));

  for (idx = 1; idx < 10; idx++) {
    _TRUE(_test_shecdsa_hd_derive(m_secret, m_pubkey, m_chain, idx) == 0);
  }
 
}


int shecdsa_hd_sign(char *privkey_hex, char *sig_r, char *sig_s, char *hash_hex)
{
#ifdef HAVE_LIBGMP
  ecdsa_parameters curve;
  ecdsa_signature sig;
  uint8_t *hash;
  char *hex;
  mpz_t temp;
  mpz_t key;
  mpz_t m;
char data[256];
int data_len;

  if (strlen(hash_hex) != 64)
    return (SHERR_INVAL);

  /* setup parameters */
  curve = ecdsa_parameters_init();
  ecdsa_parameters_load_curve(curve, secp256k1);

  /* generate private key from user-context */
  mpz_init(key);
  mpz_set_str(key, privkey_hex, 16);

  mpz_init(m);
#if 0
{
  /* process message into sha1 hash */
  data_len = 32;
  hex2bin(data, hash_hex, data_len);
  hash = shsha1_hash(data, data_len);
  mpz_set_str(m, hash, 16);
}
#endif
  mpz_set_str(m, hash_hex, 16);

  /* msg modulo n */
  mpz_init(temp);
  mpz_mod(temp, m, curve->n);
  mpz_set(m, temp);
  mpz_clear(temp);

  /* generate signature */
  sig = ecdsa_signature_init();
  ecdsa_signature_sign(sig, m, key, curve);

  memset(sig_r, 0, sizeof(sig_r));
  hex = mpz_get_str(NULL, 16, sig->r);
  strcpy(sig_r, hex); 
  free(hex);
  _padd_hex(sig_r, 64);

  memset(sig_s, 0, sizeof(sig_s));
  hex = mpz_get_str(NULL, 16, sig->s);
  strcpy(sig_s, hex);
  free(hex);
  _padd_hex(sig_s, 64);

  ecdsa_parameters_clear(curve);
  ecdsa_signature_clear(sig);
  mpz_clear(key);
  mpz_clear(m);

  return (0);
#else
  return (SHERR_OPNOTSUPP);
#endif
}

int shecdsa_hd_verify(char *pubkey_hex, char *str_r, char *str_s, char *hash_hex)
{
#ifdef HAVE_LIBGMP
  ecdsa_parameters curve;
  ecdsa_signature sig;
  ecdsa_point Q;
  mpz_t temp;
  mpz_t m;
  char hex_y[256];
  char hex_x[256];
char data[256];
  uint8_t *hash;
int data_len;
char *hex;
  int ok;

  /* setup parameters */
  curve = ecdsa_parameters_init();
  ecdsa_parameters_load_curve(curve, secp256k1);


  Q = ecdsa_point_init();
  if (strlen(pubkey_hex) == 66) { /* compressed point */
    ecdsa_point_decompress(Q, pubkey_hex, curve);
  } else if (strlen(pubkey_hex) == 130) { /* decompressed point */
    memset(hex_y, 0, sizeof(hex_y));
    memset(hex_x, 0, sizeof(hex_x));
    strncpy(hex_y, pubkey_hex + 2, 64);
    strncpy(hex_x, pubkey_hex + 66, 64);
    ecdsa_point_set_hex(Q, hex_x, hex_y);
  } else {
    return (SHERR_INVAL);
  }
#if 0
  hex = ecdsa_point_compress(Q);
  ecdsa_point_decompress(Q, hex, curve);
#endif


#if 0
  /* decompress public key */
  Q = ecdsa_point_init();
  ecdsa_point_decompress(Q, pubkey_hex, curve);
#endif

  mpz_init(m);
#if 0
{
  /* process message into sha1 hash */
  data_len = 32;
  hex2bin(data, hash_hex, data_len);
  hash = shsha1_hash(data, data_len);
  mpz_set_str(m, hash, 16);
}
#endif
  mpz_set_str(m, hash_hex, 16);

  /* msg modulo n - note standard is bit-length not mod */
  mpz_init(temp);
  mpz_mod(temp, m, curve->n);
  mpz_set(m, temp);
  mpz_clear(temp);

  sig = ecdsa_signature_init();
  ecdsa_signature_set_str(sig, str_r, str_s, 16);

  /* verify signature */
  ok = ecdsa_signature_verify(m, sig, Q, curve);

  ecdsa_parameters_clear(curve);
  ecdsa_signature_clear(sig);
  ecdsa_point_clear(Q);
  mpz_clear(m);

  if (!ok)
    return (SHERR_ACCESS);

  return (0);
#else
  return (SHERR_OPNOTSUPP);
#endif
}

_TEST(shecdsa_hd_sign)
{
#ifdef HAVE_LIBGMP
  const char *m_seed = "7384f492935706bcc8b6a844d90e5c04e0b77907e0fbd3c2da6abc4ba61447da";
  const char *m_msg = "2884f492935206b668b6a844d90e5604e0b22902e0fbd362da6ab64ba61442da";
  char m_pubkey[512];
  char m_chain[512];
  char m_secret[512];
  char privkey[512];
  char pubkey[512];
  char cmp_pubkey[512];
  char privkey_chain[512];
  char pubkey_chain[512];
  char sig_r[1024];
  char sig_s[1024];
  char *hex;
  int err;
  int idx;

  idx = 1;
  memset(sig_r, 0, sizeof(sig_r));
  memset(sig_s, 0, sizeof(sig_s));

  memset(m_chain, 0, sizeof(m_chain));

  hex = shecdsa_hd_seed((char *)m_seed, m_chain);
  _TRUEPTR(hex);
  memset(m_secret, 0, sizeof(m_secret));
  strncpy(m_secret, hex, sizeof(m_secret)-1); 

  hex = shecdsa_hd_recover_pub(m_secret);
  _TRUEPTR(hex);
  memset(m_pubkey, 0, sizeof(m_pubkey));
  strncpy(m_pubkey, hex, sizeof(m_pubkey)-1);

  /* derive private key */
  memset(privkey_chain, 0, sizeof(privkey_chain));
  strcpy(privkey_chain, m_chain);
  memset(privkey, 0, sizeof(privkey));
  strncpy(privkey, shecdsa_hd_privkey(m_secret, privkey_chain, idx), sizeof(privkey)-1);

  /* derive public key */
  memset(pubkey_chain, 0, sizeof(pubkey_chain));
  strcpy(pubkey_chain, m_chain);
  memset(pubkey, 0, sizeof(pubkey));
  strncpy(pubkey, shecdsa_hd_pubkey(m_pubkey, pubkey_chain, idx), sizeof(pubkey)-1);

  _TRUE(0 == strcmp(pubkey_chain, privkey_chain));

  memset(cmp_pubkey, 0, sizeof(cmp_pubkey));
  strncpy(cmp_pubkey, shecdsa_hd_recover_pub(privkey), sizeof(cmp_pubkey)-1);
  _TRUE(0 == strcmp(cmp_pubkey, pubkey));

  memset(cmp_pubkey, 0, sizeof(cmp_pubkey));
  strncpy(cmp_pubkey,  shecdsa_hd_par_pub(m_secret, m_chain, idx), sizeof(cmp_pubkey)-1);
  _TRUE(0 == strcmp(cmp_pubkey, pubkey));

  memset(sig_r, 0, sizeof(sig_r));
  memset(sig_s, 0, sizeof(sig_s));
  err = shecdsa_hd_sign(privkey, sig_r, sig_s, m_msg);
  _TRUE(err == 0);

  {
    mpz_t key;
    ecdsa_point Q;
    ecdsa_parameters curve;
    char *comp_hex;
    char ret_buf[1024];
    char ret_y[256];
    char ret_x[256];

    Q = ecdsa_point_init();
    curve = ecdsa_parameters_init();
    ecdsa_parameters_load_curve(curve, secp256k1);
    mpz_init(key);
    mpz_set_str(key, privkey, 16);
    ecdsa_signature_generate_key(Q, key, curve);

    comp_hex = ecdsa_point_compress(Q, 33); 
    err = shecdsa_hd_verify(comp_hex, sig_r, sig_s, m_msg);
    _TRUE(err == 0);

    mpz_get_str(ret_y, 16, Q->y);
    mpz_get_str(ret_x, 16, Q->x);
    _padd_hex(ret_y, 64);
    _padd_hex(ret_x, 64);
    memset(ret_buf, 0, sizeof(ret_buf));
    strcpy(ret_buf, "04");
    strcat(ret_buf, ret_y);
    strcat(ret_buf, ret_x);

    err = shecdsa_hd_verify(ret_buf, sig_r, sig_s, m_msg);
    _TRUE(err == 0);

    ecdsa_point_clear(Q);
    ecdsa_parameters_clear(curve);
    mpz_clear(key);
  }

  err = shecdsa_hd_verify(pubkey, sig_r, sig_s, m_msg);
  _TRUE(err == 0);

  /* secondary extended key */
  for (idx = 1; idx < 10; idx++) {
    char ch_privkey[512];
    char ch_pubkey[512];
    char priv_chain[512];
    char pub_chain[512];
    char *hex;

    memset(sig_r, 0, sizeof(sig_r));
    memset(sig_s, 0, sizeof(sig_s));

    /* derive secondary private key */
    strcpy(priv_chain, privkey_chain);
    memset(ch_privkey, 0, sizeof(ch_privkey));
    strncpy(ch_privkey, shecdsa_hd_privkey(privkey, priv_chain, idx), sizeof(privkey)-1);

    /* derive secondary public key */
    strcpy(pub_chain, pubkey_chain);
    memset(ch_pubkey, 0, sizeof(ch_pubkey));
    strncpy(ch_pubkey, shecdsa_hd_pubkey(pubkey, pub_chain, idx), sizeof(pubkey)-1);

    memset(cmp_pubkey, 0, sizeof(cmp_pubkey));
    hex = shecdsa_hd_recover_pub(ch_privkey);
    _TRUEPTR(hex);
    _TRUE(0 == strcmp(ch_pubkey, hex));
    _TRUE(0 == strcmp(priv_chain, pub_chain));

    err = shecdsa_hd_sign(ch_privkey, sig_r, sig_s, m_msg);
    _TRUE(err == 0);
    err = shecdsa_hd_verify(ch_pubkey, sig_r, sig_s, m_msg);
    _TRUE(err == 0);
  }

#endif
}

