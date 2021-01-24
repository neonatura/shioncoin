
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

static uint32_t _crypt_magic = SHMEM32_MAGIC;
#define CRYPT_MAGIC_SIZE sizeof(uint32_t)
#define CRYPT_LENGTH_SIZE sizeof(uint32_t)
#define CRYPT_HEADER_SIZE (CRYPT_MAGIC_SIZE + CRYPT_LENGTH_SIZE)
#define IS_CRYPT_MAGIC(_data) \
  (0 == memcmp(_data, &_crypt_magic, CRYPT_MAGIC_SIZE))
#define SET_CRYPT_MAGIC(_data) \
  (memcpy(_data, &_crypt_magic, CRYPT_MAGIC_SIZE))
#define SET_CRYPT_LENGTH(_data, _size) \
  (memcpy((unsigned char *)_data + CRYPT_MAGIC_SIZE, \
          &(_size), sizeof(uint32_t)))
#define GET_CRYPT_LENGTH(_data) \
  *((uint32_t *)((unsigned char *)_data + CRYPT_MAGIC_SIZE))

/**
 *   Decrypt 64 bits with a 128 bit key using TEA
 *   From http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 * Arguments:
 *   v - array of two 32 bit uints to be decoded in place
 *   k - array of four 32 bit uints to act as key
 * Returns:
 *   v - decrypted result
 * Side effects:
 *   None
 */
static void TEA_decrypt (uint32_t* v, uint32_t* k) 
{
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;                                   
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

/**
 *   Encrypt 64 bits with a 128 bit key using TEA
 *   From http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 * Arguments:
 *   v - array of two 32 bit uints to be encoded in place
 *   k - array of four 32 bit uints to act as key
 * Returns:
 *   v - encrypted result
 * Side effects:
 *   None
 */
void TEA_encrypt (uint32_t* v, uint32_t* k) 
{
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

int shencrypt_bin(shbuf_t *buff, uint32_t *k, size_t k_len, unsigned char *data, size_t data_len)
{
  unsigned char chunk[32];
  size_t max;
  size_t len;
  size_t of;
  int k_of;
  int pad;
  int j;
  int i;

  if (!data)
    return (SHERR_INVAL);

  pad = (data_len % 8) ? 1 : 0;
  max = (data_len / 8) + pad;

  j = 0;
  for (i = 0; i < max; i++) {
    of = (8 * i);
    len = MIN(SHENCRYPT_BLOCK_SIZE, data_len - of);

    memset(chunk, 0, SHENCRYPT_BLOCK_SIZE);
    memcpy(chunk, data + of, len);

    k_of = (j++%k_len) * 4;
    TEA_encrypt((uint32_t *)chunk, (uint32_t *)k + k_of);

    shbuf_cat(buff, chunk, SHENCRYPT_BLOCK_SIZE); 
  }

  return (0);
}

int shdecrypt_bin(shbuf_t *buff, uint32_t *k, size_t k_len, unsigned char *data, size_t data_len)
{
  uint32_t v[2];
  size_t max;
  size_t len;
  size_t of;
  int k_of;
  int pad;
  int j;
  int i;

  if (!data)
    return (SHERR_INVAL);

  pad = (data_len % 8) ? 1 : 0;
  max = (data_len / 8) + pad;

  j = 0;
  for (i = 0; i < max; i++) {
    memcpy(v, data + (i * 8), SHENCRYPT_BLOCK_SIZE);

    k_of = (j++%k_len) * 4;
    TEA_decrypt(v, (uint32_t *)k + k_of);

    shbuf_cat(buff, (unsigned char *)v, 
        MIN(SHENCRYPT_BLOCK_SIZE, data_len - (i*8)));
  }

  return (0);
}


void TEA_encrypt_data(uint8_t *data, uint32_t len, uint32_t * key)
{
  uint32_t blocks, i;
  uint32_t * data32;

  // treat the data as 32 bit unsigned integers
  data32 = (uint32_t *) data;

  // Find the number of 8 byte blocks, add one for the length
  blocks = (len / 8);

  for (i = 0; i< blocks; i++)
    TEA_encrypt(&data32[i*2], key);

}

void TEA_decrypt_data(uint8_t *data, uint32_t len, uint32_t *key)
{
   uint32_t blocks, i;
   uint32_t * data32;

   // treat the data as 32 bit unsigned integers
   data32 = (uint32_t *) data;

   // Find the number of 8 byte blocks
   blocks = len/8;

   for(i = 0; i< blocks; i++)
   {
      TEA_decrypt(&data32[i*2], key);
   }
}

int ashencode(char *data, size_t *data_len_p, shkey_t *key)
{
  uint32_t l = (uint32_t)(*data_len_p);

  /* sanity checks */
  if (l < 8)
    return (0); /* all done */

  if (IS_CRYPT_MAGIC(data)) {
    /* this is already encrypted. */
    return (0);
  }

  /* add encryption identifier */
  memmove(data + CRYPT_HEADER_SIZE, data, l);
  SET_CRYPT_MAGIC(data);
  SET_CRYPT_LENGTH(data, l);

  /* encrypt segment */
  TEA_encrypt_data(data + CRYPT_HEADER_SIZE, l, (uint32_t *)key->code);

  /* add encryption identifier. */
  *data_len_p = (size_t)(l + CRYPT_HEADER_SIZE);

  return (0);
}

_TEST(ashencode)
{
  shkey_t *key = shkey_uniq();
  shbuf_t *buff = shbuf_init();
  char str[1024];

  _TRUEPTR(key);
  _TRUEPTR(buff);

  memset(str, 0, sizeof(str));
  memset(str, 'a', sizeof(str) - 1);
  shbuf_catstr(buff, str);
  shbuf_grow(buff, CRYPT_HEADER_SIZE + 1024 + SHMEM_PAD_SIZE);

  _TRUE(!ashencode(buff->data, &buff->data_of, key));
  _TRUE(!ashdecode(buff->data, &buff->data_of,  key));

  memset(str, 0, sizeof(str));
  memset(str, 'a', sizeof(str) - 64);
  _TRUE(0 != strcmp(buff->data, str));

  _TRUE(!ashencode(buff->data, &buff->data_of, key));
  /* re-encrypt */
  ashencode(buff->data, &buff->data_of, key);
  _TRUE(!ashdecode(buff->data, &buff->data_of,  key));

  memset(str, 0, sizeof(str));
  memset(str, 'a', sizeof(str) - 64);
  _TRUE(0 != strcmp(buff->data, str));

  shbuf_free(&buff);
  shkey_free(&key);

}

int shencode(char *data, size_t data_len, unsigned char **data_p, size_t *data_len_p, shkey_t *key)
{
  uint32_t l = (uint32_t)data_len;
  shbuf_t *buf;

  /* sanity checks */
  if (data_len < 8) {
    buf = shbuf_init();
    shbuf_cat(buf, data, data_len);
    *data_p = (uint8_t *)buf->data;
    *data_len_p = data_len;
    free(buf);
    return (0);
  }

  if (IS_CRYPT_MAGIC(data)) {
    /* this is already encrypted. */
    return (0);
  }

  buf = shbuf_init();

  /* add encryption identifier */
  shbuf_cat(buf, &_crypt_magic, CRYPT_MAGIC_SIZE);

  /* add size */
  shbuf_cat(buf, &l, sizeof(uint32_t));

  /* encrypt segment */
  shbuf_cat(buf, data, l);
  shbuf_grow(buf, CRYPT_HEADER_SIZE + l + SHMEM_PAD_SIZE);

  l = (uint32_t)buf->data_of - CRYPT_HEADER_SIZE;
  TEA_encrypt_data(buf->data + CRYPT_HEADER_SIZE, l, (uint32_t *)key->code);

  /* return encrypted segment. */
  *data_len_p = buf->data_of;
  *data_p = buf->data;
  free(buf);

  return (0);
}


shkey_t *shencode_str(char *data)
{
  shkey_t *key = shkey_str(data);
  size_t len = strlen(data) + 1;
  int err;

  err = ashencode(data, &len, key); 
  if (err) {
    shkey_free(&key);
    return (NULL);
  }

  return (key);
}

int ashdecode(uint8_t *data, size_t *data_len_p, shkey_t *key)
{
  uint32_t data_len = (uint32_t)*data_len_p;

  if (data_len < 8)
    return (0);

  if (!IS_CRYPT_MAGIC(data))
    return (0); /* not encrypted. */

  *data_len_p = GET_CRYPT_LENGTH(data);

  data_len -= CRYPT_HEADER_SIZE;
  memmove(data, data + CRYPT_HEADER_SIZE, data_len);
  TEA_decrypt_data(data, data_len, (uint32_t *)key->code);

  return (0);
}

_TEST(ashdecode)
{
  shkey_t *key;
  unsigned char *data;
  char str[1024];
  size_t data_len;

  key = shkey_uniq();
  _TRUEPTR(key);

  memset(str, 0, sizeof(str));
  memset(str, 'a', sizeof(str)-2);

  data_len = 1023;
  data = (char *)calloc(2048, sizeof(char));
  memcpy(data, str, data_len);

  _TRUE(!ashencode(data, &data_len, key));
  _TRUE(!ashdecode(data, &data_len, key));
  _TRUE(data_len == 1023);
  _TRUE(0 == strcmp(str, data));

  shkey_free(&key);
  free(data);
}

int shdecode(uint8_t *data, uint32_t data_len, char **data_p, size_t *data_len_p, shkey_t *key)
{
  uint32_t l = data_len;
  size_t dec_len;
  shbuf_t *buf;

  if (l < 8) {
    buf = shbuf_init();
    shbuf_cat(buf, data, l);
    *data_p = buf->data;
    *data_len_p = buf->data_of;
    free(buf);
    return (0);
  }

  if (!IS_CRYPT_MAGIC(data))
    return (0); /* not encrypted */

  buf = shbuf_init();
  if (!buf)
    return (-1);

  dec_len = GET_CRYPT_LENGTH(data);
  shbuf_cat(buf, data + CRYPT_HEADER_SIZE, l - CRYPT_HEADER_SIZE);

  l = (uint32_t)buf->data_of;
  TEA_decrypt_data(buf->data, l, (uint32_t *)key->code);

  *data_p = buf->data;
  *data_len_p = dec_len;
  free(buf);

  return (0);
}


int shdecode_str(char *data, shkey_t *key)
{
  size_t len;
  char *key_p = (char *)key;
  int err;

  len = GET_CRYPT_LENGTH(data) + CRYPT_HEADER_SIZE;
  err = ashdecode(data, &len, key); 
  if (err)
    return (err);

  return (0);
}

_TEST(shdecode_str)
{
  unsigned char *data;
  shkey_t *key;
  char str[1024];
  size_t len;

  memset(str, 0, sizeof(str));
  memset(str, 'a', sizeof(str) - 1);

  data = (char *)calloc(2048, sizeof(char));
  memcpy(data, str, 1024);

  key = shencode_str(data);
  _TRUEPTR(key);
  _TRUE(!shdecode_str(data, key));
  _TRUE(0 == strcmp(data, str));

  shkey_free(&key);
  free(data);
}

#if 0
int shencode_b64(char *data, size_t data_len, uint8_t **data_p, uint32_t *data_len_p, shkey_t *key)
{
  shbuf_t *buff;
  uint64_t *val_p;
  size_t raw_data_len;
  char *raw_data;
  char buf[8];
  int err;
  int of;
  
  err = shencode(data, data_len, &raw_data, &raw_data_len, key);
  if (err)
    return (err);

  buff = shbuf_init();
  val_p = (uint64_t *)buf;
  for (of = 0; of < raw_data_len; of += sizeof(uint64_t)) {
    char *str;

    memset(buf, 0, sizeof(buf));
    memcpy(buf, raw_data, MIN(sizeof(uint64_t), raw_data_len - of));
    str = shcrcstr(*val_p);
    shbuf_cat(buff, str, strlen(str)); 
  }

  *data_p = shbuf_data(buff);
  *data_len_p = shbuf_size(buff);
  free(buff);

  return (0);
}

int shdecode_b64(char *data, size_t data_len, uint8_t **data_p, uint32_t *data_len_p, shkey_t *key)
{
  shbuf_t *buff;
  uint64_t *val_p;
  size_t raw_data_len;
  size_t enc_data_len;
  uint8_t *enc_data;
  uint8_t *raw_data;
  char buf[8];
  char *ptr;
  int err;
  int of;
  int nr;

  enc_data_len = ((data_len / 4) + 1) * 6;
  enc_data = (char *)calloc(enc_data_len + 1, sizeof(char));
  val_p = (uint32_t *)enc_data;

  nr = 0;
  for (of = 0; of < data_len; of += 6) {
    memset(buf, 0, sizeof(buf));
    strncpy(buf, data + of, 6);
    ptr = buf;
    while (*ptr && *ptr == ' ')
      ptr++;

    val_p[nr++] = (uint32_t)shcrcgen(ptr);
  }

  err = shdecode(enc_data, enc_data_len, &raw_data, &raw_data_len, key);
  free(enc_data);
  if (err)
    return (err);

  *data_p = raw_data;
  *data_len_p = raw_data_len;

  return (0);
}
#endif

int shencode_b64(unsigned char *data, size_t data_len, char **out_p, shkey_t *key)
{
  unsigned char *enc_data;
  size_t enc_data_len;
  int err;

  err = shencode(data, data_len, &enc_data, &enc_data_len, key);
  if (err)
    return (err);

  err = shbase64_encode(enc_data, enc_data_len, out_p);
  free(enc_data);
  if (err)
    return (err);

  return (0);
}

int shdecode_b64(char *in_data, unsigned char **data_p, size_t *data_len_p, shkey_t *key)
{
  unsigned char *enc_data; 
  size_t enc_data_len;
  int err;

  err = shbase64_decode(in_data, &enc_data, &enc_data_len);
  if (err)
    return (err);

  err = shdecode((unsigned char *)enc_data,
      enc_data_len, (char **)data_p, data_len_p, key);
  free(enc_data);
  if (err)
    return (err);

  return (0);
}





static int _shencrypt_v0(shbuf_t *out_buff, unsigned char *data, size_t data_len, unsigned char *key_data, size_t key_len)
{
  static const uint32_t magic = SHMEM32_MAGIC;
  shenc32_hdr_t *hdr;
  uint32_t k[8];
  uint32_t l;
  int err;

  if (key_len < 20)
    return (SHERR_INVAL);

  /* reserve space for header */
  shbuf_padd(out_buff, sizeof(shenc32_hdr_t));

  memcpy(k, key_data + 4, 16);

  l = (data_len / 8) * 8;
  err = shencrypt_bin(out_buff, k, 1, data, l);
  if (err)
    return (err);

  if (data_len > l && (data_len - l) > 0) {
    shbuf_cat(out_buff, data + l, (data_len - l));
  }

  hdr = (shenc32_hdr_t *)shbuf_data(out_buff);
  /* add encryption identifier */
  memcpy(&hdr->magic, &magic, sizeof(magic));
  /* add size */
  l = data_len; 
  memcpy(&hdr->size, &l, sizeof(uint32_t));

  return (0);
}

static int _shdecrypt_v0(shbuf_t *out_buff, unsigned char *data, size_t data_len, unsigned char *key_data, size_t key_len)
{
  shenc32_hdr_t *hdr;
  uint32_t k[8];
  size_t size;
  uint32_t l;
  int err;

  if (key_len < 20)
    return (SHERR_INVAL);

  if (data_len < sizeof(shenc32_hdr_t))
    return (SHERR_INVAL);

  hdr = (shenc32_hdr_t *)data;
  if (hdr->magic != SHMEM32_MAGIC)
    return (SHERR_INVAL);

  if (hdr->size > (data_len - sizeof(shenc32_hdr_t)))
    return (SHERR_INVAL);
  size = hdr->size;

  memcpy(k, key_data + 4, 16);

  l = ((data_len - sizeof(shenc32_hdr_t)) / 8) * 8;
  data += sizeof(shenc32_hdr_t);
  err = shdecrypt_bin(out_buff, k, 1, data, l);
  if (err)
    return (err);
  
  if (size > l && (size - l) > 0) {
    /* remainder */
    shbuf_cat(out_buff, data + l, (size - l));
  }

  return (0);
}

static unsigned char *_shencrypt_v1_key(unsigned char *key, size_t key_len)
{
  static unsigned char ret_key[64];

  memset(ret_key, 0, sizeof(ret_key));
  if (key)
    sh_sha512(key, key_len, ret_key);

  return (ret_key);
}

/* sign unencrypted data payload */
static int _shencrypt_v1_dsig_sign(int alg, shesig_t *hdr, unsigned char *data, size_t data_len, shalg_t priv)
{
  int err;

  memset(hdr->data_sig, 0, sizeof(hdr->data_sig));
  err = shalg_sign(alg, priv, hdr->data_sig, data, data_len); 
  if (err)
    return (err);

  return (0);
}

/* verify unencrypted data payload */
static int _shdecrypt_v1_dsig_verify(shesig_t *cert, unsigned char *data, size_t data_len)
{
  int alg;
  int err;

  if (!cert)
    return (SHERR_INVAL);

  alg = ntohl(cert->alg);
  err = shalg_ver(alg, cert->pub, cert->data_sig, data, data_len); 
  if (err)
    return (err);

  return (0);
}

static int _shencrypt_v1_sign(int alg, shenc_hdr_t *hdr, unsigned char *data, size_t data_len, shalg_t priv)
{
  int err;

  if (!hdr)
    return (err);

#if 0
  memset(priv, 0, sizeof(priv));
  err = shalg_priv(alg, priv, key_data, key_len);
  if (err)
    return (err);

  memset(hdr->pub, 0, sizeof(hdr->pub));
  err = shalg_pub(alg, priv, hdr->pub);
  if (err)
    return (err);
#endif

  memset(hdr->sig, 0, sizeof(hdr->sig));
  err = shalg_sign(alg, priv, hdr->sig, data, data_len); 
  if (err)
    return (err);

  return (0);
}

static int _shdecrypt_v1_verify(shenc_hdr_t *hdr, unsigned char *data, size_t data_len)
{
  int alg;
  int err;

  if (!hdr)
    return (SHERR_INVAL);

  alg = ntohl(hdr->alg);
  err = shalg_ver(alg, hdr->pub, hdr->sig, data, data_len);
  if (err)
    return (err);

  return (0);
}
 

static void _shencrypt_serial_init(uint8_t *raw)
{
  uint64_t *v = (uint64_t *)raw;
  v[0] = shrand();
  v[1] = shrand();
}


static int _shencrypt_v1(int alg, shbuf_t *out_buff, unsigned char *data, size_t data_len, unsigned char *key_data, size_t key_len, shenc_hdr_t *attr)
{
  static unsigned char blank_serialno[16];
  static const uint64_t magic = SHMEM_MAGIC;
  shalg_t priv;
  unsigned char *key;
  unsigned char pub[1024];
  shenc_hdr_t *hdr;
  uint64_t l;
  int err;
    int of;


  if (data_len > sizeof(shenc_hdr_t)) {
    hdr = (shenc_hdr_t *)data;
    if (hdr->magic == SHMEM_MAGIC)
      return (SHERR_ALREADY);
  }

  of = shbuf_size(out_buff);

  /* reserve space for header */
  shbuf_padd(out_buff, sizeof(shenc_hdr_t));


  key = _shencrypt_v1_key(key_data, key_len);
  err = shencrypt_bin(out_buff, (uint32_t *)key, 4, data, data_len);
  if (err)
    return (err);

  hdr = (shenc_hdr_t *)shbuf_data(out_buff);
  if (attr) {
    memcpy(hdr, attr, sizeof(shenc_hdr_t));
  }

  /* time */
  if (hdr->stamp == SHTIME_UNDEFINED)
    hdr->stamp = shtime();

  /* add encryption identifier */
  memcpy(&hdr->magic, &magic, sizeof(magic));
  /* add size */
  l = htonll((uint64_t)data_len);
  memcpy(&hdr->size, &l, sizeof(uint64_t));
  /* algorithm */
  hdr->alg = htonl(alg);

  if (0 == memcmp(hdr->ser, blank_serialno, 16)) {
    /* serial no */
    _shencrypt_serial_init(hdr->ser);
  }

  /* redundant sanity checks */
  if (hdr->expire == SHTIME_UNDEFINED)
    hdr->expire = shtime_adj(shtime(), SHARE_DEFAULT_EXPIRE_TIME);
  if (hdr->ver == 0)
    hdr->ver = SHESIG_VERSION;
  if (hdr->uid == 0)
    hdr->uid = shpam_euid();

  /* generate private key from secret data */
  memset(priv, 0, sizeof(priv));
  err = shalg_priv(alg, priv, key_data, key_len);
  if (err)
    return (err);

  /* generate public key from private key */
  memset(hdr->pub, 0, sizeof(hdr->pub));
  err = shalg_pub(alg, priv, hdr->pub);
  if (err)
    return (err);

  /* generate an unique id for the certificate. */
  shesig_id_gen(hdr);

  /* sign unencrypted data payload */
  err = _shencrypt_v1_dsig_sign(alg, hdr, data, data_len, priv);
  if (err)
    return (err);

  /* generate signature for encryption data */
  of += sizeof(hdr->magic) + sizeof(hdr->sig);
  err = _shencrypt_v1_sign(alg, hdr, shbuf_data(out_buff) + of, shbuf_size(out_buff) - of, priv);
//  shbuf_free(&out_buff);
  if (err)
    return (err);

  return (0);
}


static int _shdecrypt_v1(shbuf_t *out_buff, unsigned char *data, size_t data_len, unsigned char *key_data, size_t key_len)
{
  unsigned char *key = _shencrypt_v1_key(key_data, key_len);
  unsigned char pub[29];
  unsigned char sig[56];
  shenc_hdr_t hdr;
  uint64_t size;
  uint32_t l;
  int err;
    int of;

  if (data_len < sizeof(shenc_hdr_t))
    return (SHERR_INVAL);

  memcpy(&hdr, data, sizeof(shenc_hdr_t));

  if (hdr.magic != SHMEM_MAGIC)
    return (SHERR_INVAL);

  size = ntohll(hdr.size);
  if (size > (data_len - sizeof(shenc_hdr_t)))
    return (SHERR_INVAL);

  err = shdecrypt_bin(out_buff, (uint32_t *)key, 4, 
    data + sizeof(shenc_hdr_t), size);
  if (err)
    return (err);

  return (0);
}


int shencrypt(int alg, shbuf_t *out_buff, unsigned char *data, size_t data_len, unsigned char *key, size_t key_len)
{

  if (alg == 0) {
    return (_shencrypt_v0(out_buff, data, data_len, key, key_len));
  }

  return (_shencrypt_v1(alg, out_buff, data, data_len, key, key_len, NULL));
}


int shdecrypt_verify(unsigned char *data, size_t data_len)
{
  static const uint64_t magic = SHMEM_MAGIC;
  static const uint32_t magic32 = SHMEM32_MAGIC;
  shenc_hdr_t *hdr;
  size_t of;
  int err;

  if (data_len < 8)
    return (SHERR_INVAL);

  if (0 == memcmp(data, &magic32, sizeof(magic32)) &&
      0 != memcmp(data, &magic, sizeof(magic))) {
    /* 32bit version */
    if (data_len < sizeof(shenc32_hdr_t))
      return (SHERR_INVAL);
    return (0);
  }
  if (0 != memcmp(data, &magic, sizeof(magic)))
    return (SHERR_ILSEQ);

  if (data_len < sizeof(shenc_hdr_t))
    return (SHERR_INVAL);

  hdr = (shenc_hdr_t *)data;
  of = sizeof(uint64_t) /* magic */ + sizeof(shalg_t); /* sig */
  err = _shdecrypt_v1_verify(hdr, data + of, data_len - of);
  if (err)
    return (err);

  return (0);
}

int shdecrypt(shbuf_t *out_buff, unsigned char *data, size_t data_len, unsigned char *key, size_t key_len)
{
  static const uint64_t magic = SHMEM_MAGIC;
  int err;

  err = shdecrypt_verify(data, data_len);
  if (err)
    return (err);

  if (0 != memcmp(data, &magic, sizeof(magic))) {
    return (_shdecrypt_v0(out_buff, data, data_len, key, key_len));
  }

  return (_shdecrypt_v1(out_buff, data, data_len, key, key_len));
}


int shencrypt_derive(shesig_t *cert, shalg_t pub, shbuf_t *buff, unsigned char *key_data, size_t key_len)
{
  shenc_hdr_t hdr;
  unsigned char *data;
  size_t data_len;
  shalg_t priv;
  int alg;
  int err;

  if (!cert)
    return (SHERR_INVAL);

  alg = ntohl(cert->alg);
  if (alg == 0)
    return (SHERR_OPNOTSUPP);

  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = cert->magic;
  hdr.ver = cert->ver;
  hdr.pk_alg = cert->pk_alg;
  hdr.stamp = cert->stamp;
  hdr.expire = cert->expire;
  hdr.flag = cert->flag;
  hdr.uid = cert->uid;
  strncpy(hdr.ent, cert->ent, sizeof(hdr.ent)-1);
  strncpy(hdr.iss, cert->iss, sizeof(hdr.iss)-1);
  memcpy(hdr.ser, cert->ser, sizeof(hdr.ser));
  memcpy(&hdr.ctx, &cert->ctx, sizeof(hdr.ctx));

#if 0
  /* certificate issuer name */
  memset(hdr.iss, 0, sizeof(hdr.iss));
  strncpy(hdr.iss, parent->ent, sizeof(hdr.iss)-1);
#endif
  memset(priv, 0, sizeof(priv));
  err = shalg_priv(alg, priv, key_data, key_len);
  if (err)
    return (err);

  if (shalg_size(pub) != 0) {
    hdr.flag |= SHCERT_CERT_CHAIN;
    data = (unsigned char *)pub;
    data_len = shalg_size(pub);
  } else {
    static unsigned char blank[64];
    data = (unsigned char *)blank;
    data_len = 21;
  }

  err = _shencrypt_v1_dsig_sign(alg, &hdr, data, data_len, priv); 
  if (err)
    return (err);

  return (_shencrypt_v1(alg, buff, data, data_len, key_data, key_len, &hdr));
}


/* verify unencrypted data */
int shdecrypt_derive_verify(shesig_t *cert, shalg_t pub)
{

  if (shalg_size(pub) > MAX_ALG_SIZE) 
    return (SHERR_INVAL);

#if 0
  if (shalg_size(pub) == 0) {
    memset(pub, 0, sizeof(pub));
    shalg_size(pub) = 21;
  }
#endif

  return (_shdecrypt_v1_dsig_verify(cert, (unsigned char *)pub, shalg_size(pub)));
}



#define TEST_TEXT "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
//#define TEST_TEXT_ENC_HEX_V0 "22888822e80000003c56bc3a3881936acc9996d64262b83d8dd1a1d163163ca24df9f16a974607633a9d8c93be3b3cbdadce6cc309ac9023858f46a2b181c090c87e81ac26550e43ed8b04a0fe5aa5ca61399b9a0d1b6d96eb7159cc30c50d16fc68f0bdf81373329476acbc4bd41b68921fae409056eabb8e70033b586fa517aa7d0e7f8ee2898a49b7012f2a4039eb24af600f5a12ac1f51bec48833793f76d149be5dd09b4dab01e7e8f65fa8e9904621a2ef31dd55ab762093589f9944108e7f8e582699c09d18d5b0bb1aa6f0b42a7f40d86bd84f7c1af7e7b27df1342c95618d6e13945c30850c413b530cb702"
_TEST(shencrypt)
{
  static unsigned char key_data[64];
  size_t key_len = 64;

  char *text = TEST_TEXT;
  size_t text_len = strlen(TEST_TEXT) + 1;
  shbuf_t *cmp_buff = shbuf_init();
  shbuf_t *buff = shbuf_init();
  int alg;
  int err;

  alg = SHESIG_ALG_DEFAULT;

  err = shencrypt(alg, buff, text, text_len, key_data, key_len);
  _TRUE(err == 0);

  err = shdecrypt(cmp_buff, shbuf_data(buff), shbuf_size(buff), key_data, key_len);
  _TRUE(err == 0);

  shbuf_free(&cmp_buff);
  shbuf_free(&buff);
}













