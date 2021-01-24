
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#define __MEM__SHMEM_ALG_C__
#include "share.h"

#define HMAC_IPAD_MAGIC 0x36
#define HMAC_OPAD_MAGIC 0x5C

#define SHALG_PRIV_RAND_SIZE 64

typedef struct shalg_table_t
{
  int alg;
  const char *label;
} shalg_table_t;
#define MAX_SHALG_TABLE 17
static shalg_table_t _shalg_table[MAX_SHALG_TABLE] = {
  { SHALG_SHR160, "shr160" },
  { SHALG_SHR224, "shr224" },
  { SHALG_ECDSA160R, "ecdsa160r" }, 
  { SHALG_ECDSA160K, "ecdsa160k" }, 
  { SHALG_ECDSA224R, "ecdsa224r" }, 
  { SHALG_ECDSA224K, "ecdsa224k" }, 
  { SHALG_ECDSA256R, "ecdsa256r" }, 
  { SHALG_ECDSA256K, "ecdsa256k" },
  { SHALG_ECDSA384R, "ecdsa384r" },
  { SHALG_SHA1, "sha1" },
  { SHALG_SHA224, "sha224" },
  { SHALG_SHA256, "sha256" },
  { SHALG_SHA384, "sha384" },
  { SHALG_SHA512, "sha512" },
  { SHALG_CRYPT256, "crypt256" },
  { SHALG_CRYPT512, "crypt512" },
  { SHALG_SHCR224, "shcr224" }
};

#define MAX_SHALG_FMT 5
static const char *_shalg_fmt_label[MAX_SHALG_FMT] = {
  "hex",
  "b32",
  "b58",
  "b64",
  "shr56"
};


int shalg_mode_str(char *mode_str)
{
  int i;

  for (i = 0; i < MAX_SHALG_TABLE; i++) {
    if (0 == strcasecmp(_shalg_table[i].label, mode_str))
      return (_shalg_table[i].alg);
  }

  return (SHERR_INVAL);
}




const char *shalg_str(int alg)
{
  static char ret_buf[4096];

  memset(ret_buf, 0, sizeof(ret_buf));

  if (SHALG(alg, SHALG_SHKEY)) {
    strcpy(ret_buf, "SHKEY 224BIT ");
  } else {
    if (alg & SHALG_SHR)
      strcat(ret_buf, "SHR ");
    if (alg & SHALG_RSA)
      strcat(ret_buf, "RSA ");
    if (alg & SHALG_SHA)
      strcat(ret_buf, "SHA ");
    if (alg & SHALG_ECDSA) {
      if (alg & SHALG_VR) {
        strcat(ret_buf, "ECDSAR ");
      } else {
        strcat(ret_buf, "ECDSAK ");
      }
    }
    if (alg & SHALG_CRYPT)
      strcat(ret_buf, "CRYPT ");

    if (alg & SHALG_128BIT)
      strcat(ret_buf, "128BIT ");
    if (alg & SHALG_160BIT)
      strcat(ret_buf, "160BIT ");
    if (alg & SHALG_224BIT)
      strcat(ret_buf, "224BIT ");
    if (alg & SHALG_256BIT)
      strcat(ret_buf, "256BIT ");
    if (alg & SHALG_384BIT)
      strcat(ret_buf, "384BIT ");
    if (alg & SHALG_512BIT)
      strcat(ret_buf, "512BIT ");
  }

  if (*ret_buf)
    ret_buf[strlen(ret_buf)-1] = '\000';

  return (ret_buf);
}

int shalg_fmt(char *label)
{
  int i;

  for (i = 0; i < MAX_SHALG_FMT; i++) {
    if (0 == strcasecmp(_shalg_fmt_label[i], label))
      return (i);
  }

  return (SHERR_INVAL);
}

char *shalg_fmt_str(int fmt)
{
  static char ret_buf[256];

  if (fmt < 0 || fmt >= MAX_SHALG_FMT)
    return (NULL);

  strncpy(ret_buf, _shalg_fmt_label[fmt], sizeof(ret_buf)-1);

  return (ret_buf);
}

int shalg_index_max(void)
{
  return (MAX_SHALG_TABLE);
}

int shalg_index(int index)
{
  if (index < 0 || index >= MAX_SHALG_TABLE)
    return (0);
  return (_shalg_table[index].alg);
}

static char *_shalg_encode_hex(char *ret_buf, size_t ret_buf_max, unsigned char *data, size_t data_len)
{
  int i;

  memset(ret_buf, 0, ret_buf_max);

  if (data_len >= (ret_buf_max * 2))
    return (NULL);

  for (i = 0; i < data_len; i++) {
    sprintf(ret_buf + strlen(ret_buf), "%-2.2x", data[i]);
  }

  return (ret_buf);
}

static char *_shalg_encode_b32(char *ret_buf, size_t ret_buf_max, unsigned char *data, size_t data_len)
{
  shbase32_encode(data, data_len, ret_buf, ret_buf_max);
  return (ret_buf);
}

static char *_shalg_encode_b58(char *ret_buf, size_t ret_buf_max, unsigned char *data, size_t data_len)
{
  int err;

  err = shbase58_encode(ret_buf, &ret_buf_max, data, data_len);
  if (err)
    return (NULL);

  return (ret_buf);
}

static char *_shalg_encode_b64(char *ret_buf, size_t ret_buf_max, unsigned char *data, size_t data_len)
{
  char *enc_data;
  int err;

  err = shbase64_encode(data, data_len, &enc_data);
  if (err)
    return (NULL);

  strncpy(ret_buf, enc_data, ret_buf_max);
  free(enc_data);

  return (ret_buf);
}

static char *_shalg_encode_shr56(char *ret_buf, size_t ret_buf_max, unsigned char *data, size_t data_len)
{
  uint32_t val;
  size_t of;
  int pad_len;
  int buf_len;
  int i;

  *ret_buf = '\000';

  for (of = 0; of < data_len; of += sizeof(uint32_t)) {
    buf_len = MIN(sizeof(uint32_t), data_len - of);
    memcpy(&val, data + of, MIN(sizeof(uint32_t), buf_len));
    sprintf(ret_buf+strlen(ret_buf), "%6.6s", shcrcstr((uint64_t)val));
  }
  for (i = 0; i < strlen(ret_buf); i++) {
    if (ret_buf[i] == ' ')
      ret_buf[i] = '.';
  }

  pad_len = (data_len % (int)sizeof(uint32_t));
  if (pad_len) {
    for (i = 4; i > pad_len; i--)
      strcat(ret_buf, ".");
  }
  
  return (ret_buf);
}

char *shalg_encode(int fmt, unsigned char *data, size_t data_len)
{
  static char ret_buf[4096];

  memset(ret_buf, '\000', sizeof(ret_buf));
  switch (fmt) {
    case SHFMT_HEX:
      return (_shalg_encode_hex(ret_buf, sizeof(ret_buf), data, data_len));
    case SHFMT_BASE32:
      return (_shalg_encode_b32(ret_buf, sizeof(ret_buf), data, data_len));
    case SHFMT_BASE58:
      return (_shalg_encode_b58(ret_buf, sizeof(ret_buf), data, data_len));
    case SHFMT_BASE64:
      return (_shalg_encode_b64(ret_buf, sizeof(ret_buf), data, data_len));
    case SHFMT_SHR56:
      return (_shalg_encode_shr56(ret_buf, sizeof(ret_buf), data, data_len));
  }  

  return (NULL);
}

static ssize_t _shalg_decode_hex(char *in_data, unsigned char *data, size_t data_max)
{
  char buf[16];
  uint8_t val;
  int len;
  int of;
  int i;

  len = strlen(in_data);
  for (of = 0; of < len; of += 2) {
    memset(buf, 0, sizeof(buf));
    strncpy(buf, in_data + of, 2);
    val = (uint8_t)strtol(buf, NULL, 16);
    memcpy(data + (of/2), &val, sizeof(uint8_t));
  }

  return ( (strlen(in_data) + 1) / 2 ); 
}

static ssize_t _shalg_decode_b32(char *in_text, unsigned char *data, size_t data_len)
{
  size_t out_len;
  int err;

  out_len = data_len;
  (void)shbase32_decode(in_text, strlen(in_text), data, &out_len);

  return ((ssize_t)out_len);
}

static ssize_t _shalg_decode_b58(char *in_text, unsigned char *data, size_t data_len)
{
  ssize_t ret_len;
  int err;

  ret_len = shbase58_decode_size(in_text, data_len);
  err = shbase58_decode(data, &ret_len, in_text);
  if (err)
    return (SHERR_INVAL);

  return (ret_len);
}

static ssize_t _shalg_decode_b64(char *in_text, unsigned char *data, size_t data_len)
{
  unsigned char *ret_data;
  ssize_t ret_len;
  int err;

  err = shbase64_decode(in_text, &ret_data, &ret_len);
  if (err)
    return (err);

  if (data_len < ret_len) {
    free(ret_data);
    return (SHERR_INVAL);
  }

  memcpy(data, ret_data, ret_len);
  free(ret_data);
 
  return (ret_len);
}


static ssize_t _shalg_decode_shr56(char *in_text, unsigned char *data, size_t data_len)
{
  uint32_t *val_p;
  uint32_t val;
  ssize_t ret_len;
  size_t ret_of;
  char buf[16];
  char *ptr;
  int of;
  int buf_len;
  int blks;
  int i;

  int in_len;
  int pad_len;

  in_len = strlen(in_text);
  pad_len = (in_len % 6);
  in_len -= pad_len;

  blks = in_len / 6;
  ret_len = (blks * 4) - pad_len;
  if (ret_len < 0 || ret_len > data_len)
    return (SHERR_INVAL);

  ret_of = 0;
  for (of = 0; of < in_len; of += 6) {
    memset(buf, 0, sizeof(buf));
    buf_len = MIN(6, (in_len - of));
    strncpy(buf, in_text + of, buf_len);

    ptr = buf;
    for (i = 0; i < buf_len; i++) {
      if (buf[i] != '.') break;
      ptr++;
    }
    val = (uint32_t)shcrcgen(ptr);

    val_p = (uint32_t *)(data + ret_of);
    memcpy(val_p, &val, MIN(sizeof(uint32_t), (ret_len - ret_of)));
    ret_of += sizeof(uint32_t);
  }

  return (ret_len);
}

int shalg_decode(int fmt, char *in_data, unsigned char *data, size_t *data_len_p)
{
  size_t data_max = *data_len_p;
  ssize_t len;

  if (data_max)
    memset(data, '\000', data_max);

  len = SHERR_OPNOTSUPP;
  switch (fmt) {
    case SHFMT_HEX:
      len = _shalg_decode_hex(in_data, data, data_max);
      break;
    case SHFMT_BASE32:
      len = _shalg_decode_b32(in_data, data, data_max);
      break;
    case SHFMT_BASE58:
      len = _shalg_decode_b58(in_data, data, data_max);
      break;
    case SHFMT_BASE64:
      len = _shalg_decode_b64(in_data, data, data_max);
      break;
    case SHFMT_SHR56:
      len = _shalg_decode_shr56(in_data, data, data_max);
      break;
  }
  if (len < 0)
    return (len);

  *data_len_p = (size_t)len;
  return (0);
}

char *shhex_str(unsigned char *data, size_t data_len)
{
  return (shalg_encode(SHFMT_HEX, data, data_len));
}

void shhex_bin(char *hex_str, unsigned char *data, size_t data_max)
{
  memset(data, '\000', data_max);
  (void)shalg_decode(SHFMT_HEX, hex_str, data, &data_max);
}


char *shalg_print(int fmt, shalg_t key)
{
  return (shalg_encode(fmt, (unsigned char *)key, shalg_size(key)));
}

static char *shalg_hstr(shalg_t key)
{
  return (shalg_print(SHFMT_HEX, key));
}

int shalg_gen(int fmt, char *in_data, shalg_t ret_key)
{
  size_t len;
  int err;

  memset(ret_key, '\000', sizeof(shalg_t));

  len = sizeof(shalg_t);
  err = shalg_decode(fmt, in_data, (unsigned char *)ret_key, &len);
  if (err < 0)
    return (err);

  shalg_size(ret_key) = len;
  return (0);
}

static void shalg_hbin(char *hex_str, shalg_t key)
{
  shalg_gen(SHFMT_HEX, hex_str, key);
}

static int _shalg_priv_shcr224(int alg, shalg_t ret_key, unsigned char *data, size_t data_len)
{

  memset(ret_key, 0, sizeof(ret_key));
  (void)shr224(data, data_len, (unsigned char *)ret_key);
  shalg_size(ret_key) = 28;

  return (0);
}

static int _shalg_priv_crypt(int alg, shalg_t ret_key, unsigned char *data, size_t data_len)
{
  unsigned char raw[128];
  unsigned char hash[128];
  char cr_salt[64];
  size_t len;
  int idx;
  int of;
  int i;

  memset(ret_key, 0, sizeof(ret_key));

  memset(cr_salt, 0, sizeof(cr_salt));
  if (alg == SHALG_CRYPT256) {
    if (data_len > 4 && 0 == strncmp(data, "$5$", 3)) {
      idx = stridx(data + 3, '$');
      if (idx != -1)
        strncpy(cr_salt, data + 3, idx);
      else
        strncpy(cr_salt, data + 3, sizeof(cr_salt)-1);
    }
  } else if (alg == SHALG_CRYPT512) {
    if (data_len > 4 && 0 == strncmp(data, "$6$", 3)) {
      char cr_salt[32];

      memset(cr_salt, 0, sizeof(cr_salt));
      idx = stridx(data + 3, '$');
      if (idx != -1)
        strncpy(cr_salt, data + 3, idx);
      else
        strncpy(cr_salt, data + 3, sizeof(cr_salt)-1);
    }
  } else {
    return (SHERR_OPNOTSUPP);
  }

  if (!*cr_salt) {
    memset(raw, 0, sizeof(raw));
    sh_sha224(data, data_len, hash);
    for (i = 0; i < 28; i++) {
      of = (i/3);
      raw[of] = raw[of] ^ hash[i]; 
    }
    shcrypt_b64_encode(cr_salt, raw, 9);
  }

  len = ((strlen(cr_salt) / 4) + 1) * 4;
  memcpy((char *)ret_key, cr_salt, len);
  shalg_size(ret_key) = len;

  return (0);
}

static int _shalg_priv_ecdsa(int alg, shalg_t ret_key, unsigned char *data, size_t data_len)
{
  shec_t *ec;
  char *hex;

  ec = shec_init(alg);
  if (!ec)
    return (SHERR_INVAL);

  hex = shec_priv_gen(ec, data, data_len);
  if (!hex) {
    shec_free(&ec);
    return (SHERR_INVAL);
  }

  shalg_hbin(hex, ret_key);
  shec_free(&ec);

  return (0);
}

static void _shalg_shr160(sh160_t ret_result, unsigned char *data, size_t data_len)
{
  sh_sha_t sha_ctx;
  uint8_t sha_result[32];

  memset(sha_result, 0, sizeof(sha_result));
  memset(ret_result, 0, sizeof(ret_result));

  memset(&sha_ctx, 0, sizeof(sha_ctx));
  sh_sha256_init(&sha_ctx);
  if (data && data_len)
    sh_sha256_write(&sha_ctx, data, data_len);
  sh_sha256_result(&sha_ctx, (unsigned char *)sha_result);

  sh_ripemd160((unsigned char *)sha_result, 32, ret_result);
}

static void _shalg_shr224(shalg_t ret_key, unsigned char *data, size_t data_len)
{
  int err;

  memset(ret_key, '\000', sizeof(shalg_t));
  (void)shr224(data, data_len, (unsigned char *)ret_key);
  shalg_size(ret_key) = SHR224_SIZE; 

#if 0
  const int key_len = SHKEY_WORDS * sizeof(uint32_t);
  uint32_t *code;
  uint64_t val;
  size_t step;
  size_t len;
  size_t of;
  int i;

  memset(ret_key, '\000', sizeof(shalg_t));
  shalg_size(ret_key) = key_len;

  if (data && data_len) {
    val = 0;
    code = (uint32_t *)ret_key;
    step = data_len / SHKEY_WORDS;
    for (i = 0; i < SHKEY_WORDS; i++) {
      of = step * i;
      len = MIN(data_len - of, step + 8);
      val += shcrc_shr224((char *)data + of, len);
      code[i] = (uint32_t)val;
    }
  }
#endif

}

static void _shalg_sha(int alg, shalg_t ret_key, unsigned char *data, size_t data_len)
{

  memset(ret_key, '\000', sizeof(ret_key));
  shsha(alg, (unsigned char *)ret_key, data, data_len);
  shalg_size(ret_key) = shsha_size(alg);

}

static int _shalg_priv_shr160(int alg, shalg_t ret_key, unsigned char *data, size_t data_len)
{
  sh160_t ret_result;

  _shalg_shr160(ret_result, data, data_len);
  memcpy(ret_key, ret_result, sizeof(sh160_t));
  shalg_size(ret_key) = sizeof(sh160_t);
  
  return (0);
}

static int _shalg_priv_shr224(int alg, shalg_t ret_key, unsigned char *data, size_t data_len)
{
  _shalg_shr224(ret_key, data, data_len);
  return (0);
}

static int _shalg_priv_sha(int alg, shalg_t ret_key, unsigned char *data, size_t data_len)
{
  _shalg_sha(alg, ret_key, data, data_len);
  return (0);
}

int shalg_priv(int alg, shalg_t ret_key, unsigned char *data, size_t data_len)
{

  if (SHALG(alg, SHALG_SHCR224))
    return (_shalg_priv_shcr224(alg, ret_key, data, data_len));
  if (alg & SHALG_CRYPT)
    return (_shalg_priv_crypt(alg, ret_key, data, data_len));
  if (alg & SHALG_ECDSA)
    return (_shalg_priv_ecdsa(alg, ret_key, data, data_len));
  if (alg & SHALG_SHA)
    return (_shalg_priv_sha(alg, ret_key, data, data_len));
  if (SHALG(alg, SHALG_SHR160))
    return (_shalg_priv_shr160(alg, ret_key, data, data_len));
  if (SHALG(alg, SHALG_SHR224))
    return (_shalg_priv_shr224(alg, ret_key, data, data_len));

  return (SHERR_OPNOTSUPP);
}

int shalg_priv_rand(int alg, shalg_t ret_key)
{
  static const int max = SHALG_PRIV_RAND_SIZE / 8;
  unsigned char raw[SHALG_PRIV_RAND_SIZE];
  uint64_t *v;
  int i;

  v = (uint32_t *)raw;
  for (i = 0; i < max; i++) {
    v[i] = shrand();
  } 

  return (shalg_priv(alg, ret_key, raw, sizeof(raw)));
}


static int _shalg_pub_shcr224(int alg, shalg_t priv_key, shalg_t ret_key)
{
  int err;

  err = shcr224_salt_bin_gen((unsigned char *)ret_key, priv_key, shalg_size(priv_key));
  if (err)
    return (err);

  shalg_size(ret_key) = SHCR224_SALT_SIZE;

  return (0);
}

static int _shalg_pub_crypt(int alg, shalg_t priv_key, shalg_t ret_key)
{
  size_t ret_len;

  ret_len = 0;
  memset(ret_key, 0, sizeof(ret_key));
  shcrypt_b64_decode((char *)priv_key, ret_key, &ret_len);
  shalg_size(ret_key) = ret_len; 

  return (0);
}

static int _shalg_pub_ecdsa(int alg, shalg_t priv_key, shalg_t ret_key)
{
  shec_t *ec;
  char *hex;

  ec = shec_init(alg);
  if (!ec)
    return (SHERR_INVAL);

  shec_priv_set(ec, shalg_hstr(priv_key));

  hex = shec_pub_gen(ec);
  if (!hex) {
    shec_free(&ec);
    return (SHERR_INVAL);
  }

  shalg_hbin(hex, ret_key);
  shec_free(&ec);

  return (0);
}

static int _shalg_pub_shr160(int alg, shalg_t priv_key, shalg_t ret_key)
{
  shec_t *ec;
  char *hex;

  ec = shec_init(SHALG_ECDSA256K);
  if (!ec)
    return (SHERR_INVAL);

  shec_priv_set(ec, shalg_hstr(priv_key));

  hex = shec_pub_gen(ec);
  if (!hex) {
    shec_free(&ec);
    return (SHERR_INVAL);
  }

  shalg_hbin(hex, ret_key);
  shec_free(&ec);

  return (0);
}
#if 0
static int _shalg_pub_shr160(int alg, shalg_t priv_key, shalg_t ret_key)
{
  unsigned char *data = (unsigned char *)priv_key;
  size_t data_len = (size_t)shalg_size(priv_key);
  sh160_t ret_result;

  _shalg_shr160(ret_result, data, data_len);
  memcpy(ret_key, ret_result, sizeof(sh160_t));
  shalg_size(ret_key) = sizeof(sh160_t);
  
  return (0);
}
#endif

#if 0
static int _shalg_pub_shr224(int alg, shalg_t priv_key, shalg_t ret_key)
{
  const int key_len = SHKEY_WORDS * sizeof(uint32_t);

  if (shalg_size(priv_key) != key_len)
    return (SHERR_INVAL);

  _shalg_shr224(ret_key, (unsigned char *)priv_key, key_len);
  return (0);
}
#endif
static int _shalg_pub_shr224(int alg, shalg_t priv_key, shalg_t ret_key)
{
  unsigned char k_ipad[256];
  unsigned char k_opad[256];
  unsigned char *priv_raw;
  unsigned char *ret_raw;
  sh_hmac_t ctx;
  size_t block_len;
  size_t key_len;
  size_t priv_len;
  int err;
  int i;

  key_len = SHR224_SIZE;

  priv_raw = (unsigned char *)priv_key;
  priv_len = shalg_size(priv_key);

  if (priv_len > key_len) {
    static unsigned char tempkey[256];
    shr224_t tcontext;

    err = shr224_init(&tcontext);
    if (err) return (err);
    err = shr224_write(&tcontext, priv_raw, priv_len);
    if (err) return (err);
    err = shr224_result(&tcontext, tempkey);
    if (err) return (err);

    priv_raw = tempkey; 
    priv_len = key_len;
  }

  /* store key into the pads, XOR'd with ipad and opad values */
  ret_raw = (unsigned char *)ret_key;
  for (i = 0; i < key_len; i++) {
    ret_raw[i] = priv_raw[i] ^ SHR224_IPAD_MAGIC;
    ret_raw[i+key_len] = priv_raw[i] ^ SHR224_OPAD_MAGIC;
  }
  shalg_size(ret_key) = key_len * 2;

  return (0);
}

static int _shalg_pub_sha(int alg, shalg_t priv_key, shalg_t ret_key)
{
  unsigned char k_ipad[256];
  unsigned char k_opad[256];
  unsigned char *priv_raw;
  unsigned char *ret_raw;
  sh_hmac_t ctx;
  size_t block_len;
  size_t key_len;
  size_t priv_len;
  int err;
  int i;

  key_len = shsha_size(alg);
  if (key_len == 0)
    return (SHERR_OPNOTSUPP);

  priv_raw = (unsigned char *)priv_key;
  priv_len = shalg_size(priv_key);

  if (priv_len > key_len) { /* note: standard is block-size and not hash-size */
    static unsigned char tempkey[256];
    sh_sha_t tcontext;

    err = shsha_init(&tcontext, alg);
    if (err) return (err);
    err = shsha_write(&tcontext, priv_raw, priv_len);
    if (err) return (err);
    err = shsha_result(&tcontext, tempkey);
    if (err) return (err);

    priv_raw = tempkey; 
    priv_len = key_len;
  }

  /* store key into the pads, XOR'd with ipad and opad values */
  ret_raw = (unsigned char *)ret_key;
  for (i = 0; i < key_len; i++) {
    ret_raw[i] = priv_raw[i] ^ HMAC_IPAD_MAGIC;
    ret_raw[i+key_len] = priv_raw[i] ^ HMAC_OPAD_MAGIC;
  }
  shalg_size(ret_key) = key_len * 2;

  return (0);
}

int shalg_pub(int alg, shalg_t priv_key, shalg_t ret_key)
{

  memset(ret_key, 0, sizeof(ret_key));

  if (SHALG(alg, SHALG_SHCR224))
    return (_shalg_pub_shcr224(alg, priv_key, ret_key));
  if (alg & SHALG_CRYPT)
    return (_shalg_pub_crypt(alg, priv_key, ret_key));
  if (alg & SHALG_ECDSA)
    return (_shalg_pub_ecdsa(alg, priv_key, ret_key));
  if (alg & SHALG_SHA)
    return (_shalg_pub_sha(alg, priv_key, ret_key));
  if (SHALG(alg, SHALG_SHR160))
    return (_shalg_pub_shr160(alg, priv_key, ret_key));
  if (SHALG(alg, SHALG_SHR224))
    return (_shalg_pub_shr224(alg, priv_key, ret_key));
  
  return (SHERR_OPNOTSUPP);
}

static int _shalg_sign_shcr224(int alg, shalg_t priv_key, shalg_t ret_sig, unsigned char *data, size_t data_len)
{
  unsigned char salt[SHCR224_SALT_SIZE];
  int err;

  memset(salt, 0, sizeof(salt));
  err = shcr224_salt_bin_gen(salt, priv_key, shalg_size(priv_key));
  if (err)
    return (err);

  err = shcr224_bin(salt, (unsigned char *)ret_sig, 0, data, data_len);
  if (err)
    return (err);

  shalg_size(ret_sig) = SHCR224_SIZE;

  return (0);
}

static int _shalg_sign_crypt(int alg, shalg_t priv_key, shalg_t ret_sig, unsigned char *data, size_t data_len)
{
  unsigned char hash[128];
  char hash_str[256];
  char *cr_salt;
  char *cr_key;
  char *sig;
  size_t sig_len;
  int err;
  int of;

  if (strlen(data) == data_len) {
    /* presume ascii */
    cr_key = (char *)data;
  } else {
    /* presume binary */
    memset(hash, 0, sizeof(hash));
    sh_sha512(data, data_len, hash);

    memset(hash_str, 0, sizeof(hash_str));
    shcrypt_b64_encode(hash_str, hash, 64);
    cr_key = hash_str;
  }

  sig = NULL;
  cr_salt = (char *)priv_key;
  if (alg == SHALG_CRYPT256) {
    sig = shcrypt_sha256(cr_key, cr_salt);
  } else if (alg == SHALG_CRYPT512) {
    sig = shcrypt_sha512(cr_key, cr_salt);
  }
  if (!sig || strlen(sig) < 3)
    return (SHERR_INVAL);

  of = stridx(sig + 3, '$');
  if (of == -1)
    return (SHERR_INVAL);

  of += 4;
  shcrypt_b64_decode(sig + of, (unsigned char *)ret_sig, &sig_len); 
  shalg_size(ret_sig) = sig_len;

  return (0);
}

static int _shalg_sign_ecdsa(int alg, shalg_t priv_key, shalg_t ret_sig, unsigned char *data, size_t data_len)
{
  shec_t *ec;
  int err;

  ec = shec_init(alg);
  if (!ec)
    return (SHERR_INVAL);

  shec_priv_set(ec, shalg_hstr(priv_key));
  err = shec_sign(ec, data, data_len);
  if (err) {
    shec_free(&ec);
    return (err);
  }

  shalg_hbin(ec->sig, ret_sig);

  shec_free(&ec);
  return (0);
}

static int _shalg_sign_shr160(int alg, shalg_t priv_key, shalg_t ret_sig, unsigned char *data, size_t data_len)
{
  shec_t *ec;
  int err;

  ec = shec_init(SHALG_ECDSA256K);
  if (!ec)
    return (SHERR_INVAL);

  shec_priv_set(ec, shalg_hstr(priv_key));
  err = shec_sign(ec, data, data_len);
  if (err) {
    shec_free(&ec);
    return (err);
  }

  shalg_hbin(ec->sig, ret_sig);

  shec_free(&ec);
  return (0);
}
#if 0
static int _shalg_sign_shr160(int alg, shalg_t priv_key, shalg_t ret_sig, unsigned char *data, size_t data_len)
{
  unsigned char raw[256];
  sh160_t ret_result;
  shalg_t pub_key;
  int err;

  /* generate public key */
  err = _shalg_pub_shr160(alg, priv_key, pub_key);
  if (err)
    return (err);

  /* generate message key */
  _shalg_shr160(ret_result, data, data_len);
  memcpy(raw, ret_result, sizeof(sh160_t));

  /* generate signature */
  memcpy(raw + sizeof(sh160_t), pub_key, sizeof(sh160_t));
  _shalg_shr160(ret_result, raw, (sizeof(sh160_t) * 2));
  memcpy(ret_sig, ret_result, sizeof(sh160_t));
  shalg_size(ret_sig) = sizeof(sh160_t);

  return (0);
}
#endif

#if 0
static int _shalg_sign_shr224(int alg, shalg_t priv_key, shalg_t ret_sig, unsigned char *data, size_t data_len)
{
  const int key_len = SHKEY_WORDS * sizeof(uint32_t);
  unsigned char raw[256];
  shalg_t data_key;
  shalg_t pub_key;
  int err;

  /* generate public key */
  err = _shalg_pub_shr224(alg, priv_key, pub_key);
  if (err)
    return (err);

  /* generate message key */
  _shalg_shr224(data_key, data, data_len);
  memcpy(raw, data_key, key_len);

  /* generate signature */
  memcpy(raw + key_len, pub_key, key_len);
  _shalg_shr224(ret_sig, raw, (key_len * 2));

  return (0);
}
#endif
static int _shalg_sign_shr224(int alg, shalg_t priv_key, shalg_t ret_sig, unsigned char *data, size_t data_len)
{
  int err;

  memset(ret_sig, 0, sizeof(ret_sig));
  err = shr224_hmac((unsigned char *)priv_key, shalg_size(priv_key), data, data_len, (unsigned char *)ret_sig);
  if (err)
    return (err);

  shalg_size(ret_sig) = SHR224_SIZE;

  return (0);
}

static int _shalg_sign_sha(int alg, shalg_t priv_key, shalg_t ret_sig, unsigned char *data, size_t data_len)
{
  int err;

  memset(ret_sig, 0, sizeof(ret_sig));
  err = shhmac(alg, (unsigned char *)priv_key, shalg_size(priv_key), data, data_len, (unsigned char *)ret_sig);
  if (err)
    return (err);

  shalg_size(ret_sig) = shsha_size(alg);

  return (0);
}

int shalg_sign(int alg, shalg_t priv_key, shalg_t ret_sig, unsigned char *data, size_t data_len)
{

  if (SHALG(alg, SHALG_SHCR224))
    return (_shalg_sign_shcr224(alg, priv_key, ret_sig, data, data_len));
  if (alg & SHALG_CRYPT)
    return (_shalg_sign_crypt(alg, priv_key, ret_sig, data, data_len)); 
  if (alg & SHALG_ECDSA)
    return (_shalg_sign_ecdsa(alg, priv_key, ret_sig, data, data_len)); 
  if (alg & SHALG_SHA)
    return (_shalg_sign_sha(alg, priv_key, ret_sig, data, data_len)); 
  if (SHALG(alg, SHALG_SHR160))
    return (_shalg_sign_shr160(alg, priv_key, ret_sig, data, data_len)); 
  if (SHALG(alg, SHALG_SHR224))
    return (_shalg_sign_shr224(alg, priv_key, ret_sig, data, data_len)); 

  return (0);
}

static _shalg_ver_shcr224(int alg, shalg_t pub_key, shalg_t sig_key, unsigned char *data, size_t data_len)
{
  int err;

  err = shcr224_bin_verify((unsigned char *)pub_key,
      (unsigned char *)sig_key, 0, data, data_len);
  if (err)
    return (err);

  return (0);
}

static _shalg_ver_crypt(int alg, shalg_t pub_key, shalg_t sig_key, unsigned char *data, size_t data_len)
{
  unsigned char hash[128];
  char hash_str[256];
  char cr_salt[256];
  shalg_t cmp_sig;
  size_t sig_len;
  char *cr_key;
  char *sig;
  int err;
  int of;

  if (strlen(data) == data_len) {
    /* presume ascii */
    cr_key = (char *)data;
  } else {
    /* presume binary */
    memset(hash, 0, sizeof(hash));
    sh_sha512(data, data_len, hash);

    memset(hash_str, 0, sizeof(hash_str));
    shcrypt_b64_encode(hash_str, hash, 64);
    cr_key = hash_str;
  }

  sig = NULL;
  memset(cr_salt, 0, sizeof(cr_salt));
  shcrypt_b64_encode(cr_salt, pub_key, shalg_size(pub_key));
  if (alg == SHALG_CRYPT256) {
    sig = shcrypt_sha256(cr_key, cr_salt);
  } else if (alg == SHALG_CRYPT512) {
    sig = shcrypt_sha512(cr_key, cr_salt);
  }
  if (!sig || strlen(sig) < 3)
    return (SHERR_INVAL);

  of = stridx(sig + 3, '$');
  if (of == -1)
    return (SHERR_INVAL);

  of += 4;
  memset(cmp_sig, 0, sizeof(cmp_sig));
  shcrypt_b64_decode(sig + of, (unsigned char *)cmp_sig, &sig_len); 
  shalg_size(cmp_sig) = sig_len;
  if (sig_len != shalg_size(sig_key))
    return (SHERR_ACCESS);
  if (0 != memcmp(sig_key, cmp_sig, sig_len))
    return (SHERR_ACCESS);

  return (0);
}

static _shalg_ver_ecdsa(int alg, shalg_t pub_key, shalg_t sig_key, unsigned char *data, size_t data_len)
{
  shec_t *ec;
  int err;

  ec = shec_init(alg);
  if (!ec)
    return (SHERR_INVAL);

  shec_pub_set(ec, shalg_hstr(pub_key));
  shec_sig_set(ec, shalg_hstr(sig_key));

  err = shec_ver(ec, data, data_len);
  shec_free(&ec);
  if (err)
    return (err);

  return (0);
}

static int _shalg_ver_shr160(int alg, shalg_t pub_key, shalg_t sig_key, unsigned char *data, size_t data_len)
{
  shec_t *ec;
  int err;

  ec = shec_init(SHALG_ECDSA256K);
  if (!ec)
    return (SHERR_INVAL);

  shec_pub_set(ec, shalg_hstr(pub_key));
  shec_sig_set(ec, shalg_hstr(sig_key));

  err = shec_ver(ec, data, data_len);
  shec_free(&ec);
  if (err)
    return (err);

  return (0);
}

#if 0
static int _shalg_ver_shr160(int alg, shalg_t pub_key, shalg_t sig_key, unsigned char *data, size_t data_len)
{
  unsigned char raw[256];
  sh160_t ret_result;
  int err;

  if (shalg_size(sig_key) != sizeof(sh160_t))
    return (SHERR_INVAL);

  /* generate message key */
  _shalg_shr160(ret_result, data, data_len);
  memcpy(raw, ret_result, sizeof(sh160_t));

  /* generate signature */
  memcpy(raw + sizeof(sh160_t), pub_key, sizeof(sh160_t));
  _shalg_shr160(ret_result, raw, (sizeof(sh160_t) * 2));

  /* compare signatures */
  if (0 != memcmp(ret_result, sig_key, sizeof(sh160_t)))
    return (SHERR_ACCESS);

  return (0);
}
#endif
#if 0
static int _shalg_ver_shr224(int alg, shalg_t pub_key, shalg_t sig_key, unsigned char *data, size_t data_len)
{
  const int key_len = SHKEY_WORDS * sizeof(uint32_t);
  unsigned char raw[256];
  shalg_t data_key;
  shalg_t cmp_sig;
  int err;

  memset(raw, 0, sizeof(raw));

  if (shalg_size(pub_key) != key_len)
    return (SHERR_INVAL);
  if (shalg_size(sig_key) != key_len)
    return (SHERR_INVAL);

  /* generate message key */
  _shalg_shr224(data_key, data, data_len);
  memcpy(raw, data_key, key_len);

  /* generate signature */
  memcpy(raw + key_len, pub_key, key_len);
  _shalg_shr224(cmp_sig, raw, (key_len * 2));

  /* compare singntures */
  if (0 != memcmp(sig_key, cmp_sig, key_len))
    return (SHERR_ACCESS);

  return (0);
}
#endif
static int _shalg_ver_shr224(int alg, shalg_t pub_key, shalg_t sig_key, unsigned char *data, size_t data_len)
{
  shr224_t shr;
  unsigned char cmp_sig[256]; 
  unsigned char mid_buf[256];
  unsigned char k_ipad[256];
  unsigned char k_opad[256];
  size_t block_len;
  size_t key_len;
  off_t nil_len;
  int err;

  key_len = SHR224_SIZE;

  if (shalg_size(pub_key) != (key_len * 2))
    return (SHERR_ILSEQ);

  if (shalg_size(sig_key) != key_len)
    return (SHERR_ILSEQ);

  memset(k_ipad, SHR224_IPAD_MAGIC, key_len);
  memcpy(k_ipad, (unsigned char *)pub_key, key_len);

  memset(k_opad, SHR224_OPAD_MAGIC, key_len);
  memcpy(k_opad, ((unsigned char *)pub_key) + key_len, key_len);

  /* first pass */
  err = shr224_init(&shr);
  if (err) return (err);

  err = shr224_write(&shr, k_ipad, key_len);
  if (err) return (err);

  err = shr224_write(&shr, data, data_len);
  if (err) return (err);

  err = shr224_result(&shr, mid_buf);
  if (err) return (err);

  /* second pass */
  err = shr224_init(&shr);
  if (err) return (err);

  err = shr224_write(&shr, k_opad, key_len);
  if (err) return (err);

  err = shr224_write(&shr, mid_buf, key_len);
  if (err) return (err);

  memset(cmp_sig, '\000', sizeof(cmp_sig));
  err = shr224_result(&shr, cmp_sig);
  if (err) return (err);

  /* compare signatures */
  if (0 != memcmp(sig_key, cmp_sig, key_len))
    return (SHERR_ACCESS);

  return (0);
}

static int _shalg_ver_sha(int alg, shalg_t pub_key, shalg_t sig_key, unsigned char *data, size_t data_len)
{
  sh_sha_t sha;
  unsigned char cmp_sig[256]; 
  unsigned char mid_buf[256];
  unsigned char k_ipad[256];
  unsigned char k_opad[256];
  size_t block_len;
  size_t key_len;
  off_t nil_len;
  int err;

  key_len = shsha_size(alg);

  if (shalg_size(pub_key) != (key_len * 2))
    return (SHERR_ILSEQ);

  if (shalg_size(sig_key) != key_len)
    return (SHERR_ILSEQ);

  block_len = shsha_blocksize(alg);

  memset(k_ipad, HMAC_IPAD_MAGIC, block_len);
  memcpy(k_ipad, (unsigned char *)pub_key, key_len);

  memset(k_opad, HMAC_OPAD_MAGIC, block_len);
  memcpy(k_opad, ((unsigned char *)pub_key) + key_len, key_len);

  /* first pass */
  err = shsha_init(&sha, alg);
  if (err) return (err);

  err = shsha_write(&sha, k_ipad, block_len);
  if (err) return (err);

  err = shsha_write(&sha, data, data_len);
  if (err) return (err);

  err = shsha_result(&sha, mid_buf);
  if (err) return (err);

  /* second pass */
  err = shsha_init(&sha, alg);
  if (err) return (err);

  err = shsha_write(&sha, k_opad, block_len);
  if (err) return (err);

  err = shsha_write(&sha, mid_buf, key_len);
  if (err) return (err);

  memset(cmp_sig, '\000', sizeof(cmp_sig));
  err = shsha_result(&sha, cmp_sig);
  if (err) return (err);

  /* compare signatures */
  if (0 != memcmp(sig_key, cmp_sig, key_len))
    return (SHERR_ACCESS);

  return (0);
}

int shalg_ver(int alg, shalg_t pub_key, shalg_t sig_key, unsigned char *data, size_t data_len)
{

  if (SHALG(alg, SHALG_SHCR224))
    return (_shalg_ver_shcr224(alg, pub_key, sig_key, data, data_len));
  if (alg & SHALG_CRYPT)
    return (_shalg_ver_crypt(alg, pub_key, sig_key, data, data_len)); 
  if (alg & SHALG_ECDSA)
    return (_shalg_ver_ecdsa(alg, pub_key, sig_key, data, data_len)); 
  if (alg & SHALG_SHA)
    return (_shalg_ver_sha(alg, pub_key, sig_key, data, data_len));
  if (SHALG(alg, SHALG_SHR160))
    return (_shalg_ver_shr160(alg, pub_key, sig_key, data, data_len));
  if (SHALG(alg, SHALG_SHR224))
    return (_shalg_ver_shr224(alg, pub_key, sig_key, data, data_len));

  return (SHERR_OPNOTSUPP);
}




#define MAX_TEST_ALG 17
static const int _test_alg[MAX_TEST_ALG] =
{
  SHALG_ECDSA160R,
  SHALG_ECDSA160K,
  SHALG_ECDSA224R,
  SHALG_ECDSA224K,
  SHALG_ECDSA256R,
  SHALG_ECDSA256K,
  SHALG_ECDSA384R,
  SHALG_SHR160,
  SHALG_SHR224,
  SHALG_SHA1,
  SHALG_SHA224,
  SHALG_SHA256,
  SHALG_SHA384,
  SHALG_SHA512,
  SHALG_CRYPT256,
  SHALG_CRYPT512,
  SHALG_SHCR224
}; 
_TEST(shalg_sign)
{
  static const char *text = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipssum.";
  shkey_t *key;
  char buf[512];
  char buf2[512];
  char enc_text[512];
  int err;
  shalg_t priv;
  shalg_t pub;
  shalg_t sig;
  shalg_t ill_sig;
  shalg_t cmp_sig;
  int b;
  size_t len;
  int _test_idx;

  for (_test_idx = 0; _test_idx < MAX_TEST_ALG; _test_idx++) {
    key = shkey_uniq();

    err = shalg_priv(_test_alg[_test_idx], priv, key, sizeof(key)); 
    _TRUE(err == 0);

    err = shalg_pub(_test_alg[_test_idx], priv, pub);
    _TRUE(err == 0);

    err = shalg_sign(_test_alg[_test_idx], priv, sig, text, strlen(text));
    _TRUE(err == 0);

    err = shalg_ver(_test_alg[_test_idx], pub, sig, text, strlen(text));
    _TRUE(err == 0);

    memset(ill_sig, 0, sizeof(ill_sig));
    memcpy(ill_sig, sig, shalg_size(sig)-4);
    shalg_size(ill_sig) = shalg_size(sig);
    err = shalg_ver(_test_alg[_test_idx], pub, ill_sig, text, strlen(text));
    _TRUE(err != 0);

    for (b = 0; b < MAX_SHFMT; b++) {
      char *str_text = shalg_print(b, sig);
      if (!str_text) continue;
      memset(enc_text, 0, sizeof(enc_text));
      strncpy(enc_text, str_text, sizeof(enc_text)-1);

      shalg_gen(b, enc_text, cmp_sig);
      str_text = shalg_encode(b, cmp_sig, shalg_size(cmp_sig));
      _TRUEPTR(str_text);

      err = shalg_ver(_test_alg[_test_idx], pub, cmp_sig, text, strlen(text));
      _TRUE(err == 0);
    }

    shkey_free(&key);
  }
}


int shalg_cmp(shalg_t alg_a, shalg_t alg_b)
{
  int ok;

  if (shalg_size(alg_a) != shalg_size(alg_b))
    return (FALSE);
  if (0 != memcmp(alg_a, alg_b, shalg_size(alg_a)))
    return (FALSE);

  return (TRUE);
}


