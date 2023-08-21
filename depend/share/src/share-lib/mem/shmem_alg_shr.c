
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


extern shkey_t _shmem_key;

#if 0
uint64_t shcrc_shr224(void *data, size_t data_len)
{
  unsigned char *raw_data = (unsigned char *)data;
  uint64_t b = 0;
  uint32_t a = 1;
  uint32_t num_data;
  int idx;

  if (raw_data) {
    for (idx = 0; idx < data_len; idx += 4) {
      num_data = 0;
      memcpy(&num_data, raw_data + idx, MIN(4, data_len - idx));

      a = (a + num_data);
      b = (b + a);
    }
  }

  return (htonll( (uint64_t)a + (b << 32) ));
}

void shkey_shr224_r(void *data, size_t data_len, shkey_t *key)
{
  uint64_t val;
  uint16_t crc;
  size_t step;
  size_t len;
  size_t of;
  int i;

  memset(key, 0, sizeof(shkey_t));
  key->alg = SHALG_SHR224;

  crc = 0;
  if (data && data_len) {
    val = 0;
    step = data_len / SHKEY_WORDS;
    for (i = 0; i < SHKEY_WORDS; i++) {
      /* add block to sha hash */
      of = step * i;
      len = MIN(data_len - of, step + 8);
      val += shcrc_shr224((char *)data + of, len);
      key->code[i] = (uint32_t)val;
      crc += (uint16_t)val;
    }
  }

  key->crc = crc;
}
#endif

uint64_t shr224_crc(shr224_t *ctx)
{
  return (htonll( (uint64_t)ctx->crc_a + (ctx->crc_b << 32) ));
}

int shr224_result_key(shr224_t *ctx, shkey_t *key)
{
  unsigned char *raw;
  unsigned char hash[64];
  int err;

  memset(hash, 0, sizeof(hash));
  err = shr224_result(ctx, hash);
  if (err)
    return (err);

  /* payload */
  raw = (unsigned char *)key + sizeof(uint32_t);
  memcpy(raw, hash, sizeof(shkey_t) - sizeof(uint32_t));

  /* attributes */
  shkey_alg_set(key, SHALG_SHR224);
  key->crc = (uint16_t)shr224_crc(ctx);

  return (0);
}

uint64_t shr224_result_crc(shr224_t *ctx, shkey_t *key)
{
  unsigned char hash[28];
  int err;

  memset(hash, 0, sizeof(hash));
  err = shr224_result(ctx, hash);
  if (err)
    return (err);

  return (shr224_crc(ctx));
}

static int _shkey_shr224_r(shkey_t *key, void *data, size_t data_len)
{
  unsigned char *raw;
  shr224_t ctx;
  int err;

  raw = (unsigned char *)key;
  memset(raw, 0, sizeof(shkey_t));

  err = shr224_init(&ctx);
  if (err)
    return (err);

  err = shr224_write(&ctx, data, data_len);
  if (err)
    return (err);

  err = shr224_result_key(&ctx, key);
  if (err)
    return (err);

  return (0);
}



/**
 * Generates a "SHR160" algorythm share-key from a 160bit binary segment.
 */
shkey_t *shkey_shr160(sh160_t raw)
{
  uint32_t *val = (uint32_t *)raw;
  shkey_t *key;
  int i;
  
  key = (shkey_t *)calloc(1, sizeof(shkey_t));
  shkey_alg_set(key, SHALG_SHR160);
  for (i = 0; i < 5; i++) {
    key->code[i] = val[i];
  }
  key->crc = 0;
  key->crc = (uint16_t)(shkey_crc(key) & 0xFFFF);

  return (key);
}

shkey_t *ashkey_shr160(sh160_t raw)
{
  uint32_t *val = (uint32_t *)raw;
  int i;
  
  memset(&_shmem_key, 0, sizeof(_shmem_key));
  for (i = 0; i < 5; i++) {
    _shmem_key.code[i] = val[i];
  }

  shkey_alg_set(&_shmem_key, SHALG_SHR160);

  _shmem_key.crc = 0;
  _shmem_key.crc = (uint16_t)(shkey_crc(&_shmem_key) & 0xFFFF);

  return (&_shmem_key);
}

void sh160_key(shkey_t *in_key, sh160_t u160)
{
  uint32_t *ret_val = (uint32_t *)u160;

  int i;

  memset(u160, 0, sizeof(5 * sizeof(uint32_t)));

  if (shkey_alg(in_key) != SHALG_SHR160)
    return;

  for (i = 0; i < 5; i++) { 
    ret_val[i] = in_key->code[i];
  }

}

void shkey_shr160_hash(shkey_t *ret_key, unsigned char *data, size_t data_len)
{
  sh_sha_t sha_ctx;
  uint8_t sha_result[32];
  sh160_t ret_result;

  if (!ret_key)
    return;

  memset(sha_result, 0, sizeof(sha_result));
  memset(ret_result, 0, sizeof(ret_result));

  memset(&sha_ctx, 0, sizeof(sha_ctx));
  sh_sha256_init(&sha_ctx);
  if (data && data_len)
    sh_sha256_write(&sha_ctx, data, data_len);
  sh_sha256_result(&sha_ctx, (unsigned char *)sha_result); 

  sh_ripemd160((unsigned char *)sha_result, 32, ret_result);
  memcpy(ret_key, ashkey_shr160(ret_result), sizeof(shkey_t));
} 

int shkey_shr160_ver(shkey_t *key)
{
  shkey_t cmp_key;
  uint16_t crc;

  if (!key)
    return (SHERR_INVAL);

  if (shkey_alg(key) != SHALG_SHR160)
    return (SHERR_INVAL);

  memcpy(&cmp_key, key, sizeof(cmp_key));
  cmp_key.crc = 0;
  crc = (uint16_t)(shkey_crc(&cmp_key) & 0xFFFF);
  if (crc != key->crc)
    return (SHERR_ILSEQ);

  return (0);
}

shkey_t *shkey_shr160_gen(char *key_str)
{
  char buf[256];
  shkey_t *ret_key;

  memset(buf, 0, sizeof(buf));
  memset(buf, '.', 42);
  if (key_str)
    strncpy(buf, key_str, 30); 

  ret_key = shkey_gen(buf);
  if (!ret_key)
    return (NULL);

  shkey_alg_set(ret_key, SHALG_SHR160);
  ret_key->crc = 0;
  ret_key->crc = (uint16_t)(shkey_crc(ret_key) & 0xFFFF);

  return (ret_key);
}

char *shkey_shr160_print(shkey_t *key)
{
  static char ret_str[256];  

  memset(ret_str, 0, sizeof(ret_str));
  strncpy(ret_str, shkey_print(key), 30);

  return (ret_str);
}

_TEST(shkey_shr160_hash)
{
  static const char *text = "shkey_shr160_hash";
  shkey_t *cmp_key;
  shkey_t key;

  cmp_key = shkey_shr160_gen("j2xi1BhckErAH6SOcCMw7sBBZGEl8C");
  _TRUEPTR(cmp_key);
  shkey_shr160_hash(&key, text, strlen(text));
  _TRUE(shkey_cmp(cmp_key, &key));
  shkey_free(&cmp_key);
}







/* shr224 */


/**
 * Reduces a segment of binary data to the SHR224 hash digest length (28 bytes).
 */
int shr224_shrink(uint64_t crc, unsigned char *data, size_t data_len, unsigned char *ret_digest)
{
  uint32_t a = 1;
  uint64_t b = 0;
  uint32_t c_val;
  uint32_t val;
  int idx;
  int i;
  int n;

  memset(ret_digest, '\000', SHR224_SIZE);

  if (crc) {
    a = a + (crc & 0xFFFFFFFF);
    b = (b + a);

    a = a + (crc >> 32);
    b = (b + a);
  }

  n = data_len / sizeof(uint32_t);
  for (i = 0; i < n; i++) {
    val = *((uint32_t *)data + i);

    a = a + val;
    b = (b + a);

    val = htonl(a);
    idx = (i % (SHR224_SIZE / sizeof(uint32_t)));
    memxor(ret_digest + (idx * sizeof(uint32_t)), &val, sizeof(uint32_t));
  }

  return (0);
}

int shr224_expand(unsigned char *digest, unsigned char *data, size_t data_len)
{
  uint32_t a = 1;
  uint64_t b = 0;
  uint32_t c_val;
  uint32_t *val;
  uint32_t h_val;
  int idx;
  int i;
  int n;

  memset(data, '\000', data_len);

  val = (uint32_t *)digest;
  n = (data_len / sizeof(uint32_t));
  for (i = 0; i < n; i++) {
    idx = (i % (SHR224_SIZE / sizeof(uint32_t)));
    a = a + val[idx];
    b = (b + a);

    h_val = htonl(a);
    memxor(data + (i * sizeof(uint32_t)), &h_val, sizeof(uint32_t));
  }

  return (0);
}


int shr224_init(shr224_t *ctx)
{

  if (!ctx)
    return (SHERR_INVAL);

  memset(ctx, 0, sizeof(shr224_t));

  memset(ctx->data, (uint8_t)(SHMEM_MAGIC & 0xFF), SHR224_BLOCK_SIZE);

  ctx->crc_a = 1;
  ctx->crc_b = 0;

  return (0);
}

int shr224_write(shr224_t *ctx, unsigned char *data, size_t data_len)
{
  char block[8];
  uint64_t val;
  size_t len;
  size_t of;
int idx;
  int i;
size_t w_of;


  of = 0;
  while (of < data_len) {
    w_of = 0;
    memset(block, 0, sizeof(block));

    if (ctx->buff_len) {
      memcpy(block, ctx->buff, ctx->buff_len);
      w_of = ctx->buff_len;
      ctx->buff_len = 0;
    }

    len = MIN(sizeof(uint64_t) - w_of, (data_len - of));
    memcpy(block + w_of, data + of, len);
    w_of += len;

    if (w_of != sizeof(uint64_t)) {
      memcpy(ctx->buff, block, sizeof(uint64_t));
      ctx->buff_len = w_of;
      break;
    }

    /* perform hash */
    val = *((uint64_t *)block);
    idx = (ctx->data_idx % SHR224_BLOCKS);
    memxor(&ctx->data[idx], block, sizeof(uint64_t));

    /* checksum */
    ctx->crc_a = (ctx->crc_a + (val & 0xFFFFFFFF));
    ctx->crc_b = (ctx->crc_a + ctx->crc_b);

    /* transition to next chunk */
    of += len;
    ctx->data_idx++;
    if (ctx->buff_len != 0) {
      memset(ctx->buff, 0, sizeof(ctx->buff));
      ctx->buff_len = 0;
    }
  }

  return (0);
}

int shr224_result(shr224_t *ctx, unsigned char *ret_digest)
{
  int err;

  if (!ctx || !ret_digest)
    return (SHERR_INVAL);

  if (ctx->buff_len != 0) {
    err = shr224_write(ctx, ctx->buff, ctx->buff_len);
    if (err)
      return (err);
  }

  err = shr224_shrink(shr224_crc(ctx),
      (unsigned char *)ctx->data, SHR224_BLOCKS * sizeof(uint64_t),
      ret_digest);
  if (err)
    return (err);

  return (0);
}

int shr224(unsigned char *data, size_t data_len, unsigned char *ret_digest)
{
  shr224_t ctx;
  int err;

  err = shr224_init(&ctx);
  if (err)
    return (err);

  err = shr224_write(&ctx, data, data_len);
  if (err)
    return (err);

  err = shr224_result(&ctx, ret_digest);
  if (err)
    return (err);
  
  return (0);
}


int shr224_hmac_init(shr224_t *ctx, unsigned char *key, size_t key_len)
{
  unsigned char k_hash[SHR224_SIZE];
  unsigned char k_ipad[SHR224_SIZE];
  int err;
  int i;

  memset(ctx, '\000', sizeof(ctx));  

  err = shr224_init(ctx); 
  if (err)
    return (err);

  memset(k_hash, '\000', sizeof(k_hash));
  if (key_len > SHR224_SIZE) {
    err = shr224_shrink(0, key, key_len, k_hash);
    if (err)
      return (err);

    key_len = SHR224_SIZE;
  } else {
    memcpy(k_hash, key, key_len); 
  }

  for (i = 0; i < key_len; i++) {
    k_ipad[i] = k_hash[i] ^ SHR224_IPAD_MAGIC;
    ctx->suff[i] = k_hash[i] ^ SHR224_OPAD_MAGIC;
  }
  for (; i < SHR224_SIZE; i++) {
    k_ipad[i] = SHR224_IPAD_MAGIC;
    ctx->suff[i] = SHR224_OPAD_MAGIC;
  }
  ctx->suff_len = SHR224_SIZE;

  err = shr224_write(ctx, k_ipad, SHR224_SIZE);
  if (err)
    return (err);

  return (0);
}

int shr224_hmac_write(shr224_t *ctx, unsigned char *data, size_t data_len)
{
  int err;

  err = shr224_write(ctx, data, data_len);
  if (err)
    return (err);

  return (0);
}

int shr224_hmac_result(shr224_t *ctx, unsigned char *ret_digest)
{
  unsigned char mid_digest[SHR224_SIZE];
  unsigned char k_opad[SHR224_SIZE];
  int err;

  memcpy(k_opad, ctx->suff, SHR224_SIZE);

  err = shr224_result(ctx, mid_digest);
  if (err)
    return (err);

  err = shr224_init(ctx);
  if (err)
    return (err);

  err = shr224_write(ctx, k_opad, SHR224_SIZE);
  if (err)
    return (err);

  err = shr224_write(ctx, mid_digest, SHR224_SIZE);
  if (err)
    return (err);

  err = shr224_result(ctx, ret_digest);
  if (err)
    return (err);

  return (0);
}

int shr224_hmac(unsigned char *key, size_t key_len, unsigned char *data, size_t data_len, unsigned char *ret_digest)
{
  shr224_t ctx;
  int err;

  err = shr224_hmac_init(&ctx, key, key_len);
  if (err)
    return (err);

  err = shr224_hmac_write(&ctx, data, data_len);
  if (err)
    return (err);

  err = shr224_hmac_result(&ctx, ret_digest);
  if (err)
    return (err);

  return (0);
}

shkey_t *ashkey_shr224(void *data, size_t data_len)
{
  int err;

  memset(&_shmem_key, 0, sizeof(_shmem_key));

  err = _shkey_shr224_r(&_shmem_key, data, data_len);
  if (err)
    return (NULL);

  return (&_shmem_key);
}

shkey_t *shkey_shr224(void *data, size_t data_len)
{
  shkey_t *ret_key;
  int err;

  ret_key = (shkey_t *)calloc(1, sizeof(shkey_t));
  if (!ret_key)
    return (NULL);

  err = _shkey_shr224_r(ret_key, data, data_len);
  if (err) {
    free(ret_key);
    return (NULL);
  }

  return (ret_key);
}

int shkey_shr224_ver(shkey_t *key, unsigned char *data, size_t data_len)
{
  shkey_t *cmp_key;
  int ok;

  cmp_key = shkey_shr224(data, data_len);
  ok = shkey_cmp(cmp_key, key);
  shkey_free(&cmp_key);

  if (!ok)
    return (SHERR_ACCESS);

  return (0);
}

_TEST(shr224)
{
  shkey_t *key;
  int err;

  key = shkey_shr224("test", 4);
  _TRUEPTR(key);
  err = shkey_shr224_ver(key, "test", 4);
  _TRUE(err == 0);
  shkey_free(&key);
}








/* alg - shcr224 */

extern void TEA_encrypt(uint32_t* v, uint32_t* k);

int shcr224_salt_bin_gen(unsigned char ret_key[SHCR224_SALT_SIZE], unsigned char *data, size_t data_len)
{
  static unsigned char blank[SHCR224_SIZE];
  shcr224_t salt;
  int err;

  memset(ret_key, 0, sizeof(ret_key));

  if (!data || data_len == 0) {
    data = blank;
    data_len = sizeof(blank);
  }

  memset(salt, 0, sizeof(salt));
  err = shr224_shrink(0, data, data_len, ret_key);
  if (err) 
    return (err);

  return (0);
}

char *shcr224_salt_gen(unsigned int rounds, unsigned char *data, size_t data_len)
{
  static char ret_str[256];
  shcr224_t ret_key;
  int err;

  memset(ret_key, 0, sizeof(ret_key));

  err = shcr224_salt_bin_gen(ret_key, data, data_len);
  if (err)
    return (NULL);

  rounds = MAX(rounds, SHCR224_DEFAULT_ROUNDS);
  rounds = htonl(rounds);
  memcpy(ret_key + SHCR224_SALT_SIZE, &rounds, 4);

  strncpy(ret_str, shalg_encode(SHFMT_SHR56, ret_key, 32), sizeof(ret_str)-1);
  return (ret_str);
}

int shcr224_salt_bin(unsigned char ret_key[SHCR224_SALT_SIZE])
{
  unsigned char salt_buf[SHCR224_SIZE];
  uint64_t *salt;
  int err;
  int i;

  salt = (uint64_t *)salt_buf;
  for (i = 0; i < (SHCR224_SIZE/8); i++) {
    salt[i] = shrand();
  }

  err = shcr224_salt_bin_gen(ret_key, salt_buf, sizeof(salt_buf));
  if (err)
    return (err);

  return (0);
}

char *shcr224_salt(unsigned int rounds)
{
  unsigned char salt_buf[SHCR224_SIZE];
  uint64_t *salt;
  int i;

  salt = (uint64_t *)salt_buf;
  for (i = 0; i < (SHCR224_SIZE/8); i++) {
    salt[i] = shrand();
  }

  return (shcr224_salt_gen(rounds, salt_buf, sizeof(salt_buf)));
}


int shcr224_bin(unsigned char salt_key[SHCR224_SALT_SIZE], shcr224_t ret_key, unsigned int rounds, unsigned char *data, size_t data_len)
{
  static const uint64_t magic = SHMEM_MAGIC;
  const int matrix_len = 7;
  unsigned char enc_data[4096];
  uint32_t matrix[7];
  shr224_t ctx;
  unsigned char salt[96];
  unsigned char hash[28];
  uint32_t *v;
  uint32_t *enc_key;
  int err;
  int idx;
  int i;
  int j;

  memset(ret_key, 0, sizeof(ret_key));

  err = shr224_expand(salt_key, salt, SHCR224_SIZE);
  if (err) return (err);

  err = shr224(data, data_len, hash);
  if (err)
    return (err);

  memset(enc_data, 0, sizeof(enc_data));
  err = shr224_expand(hash, enc_data, 4096);
  if (err)
    return (err);

  for (i = 0; i < 1023; i++) {
    idx = (i % 12);
    enc_key = (uint32_t *)salt + idx;
    TEA_encrypt((uint32_t *)enc_data + i, enc_key);
  }

  for (i = 0; i < matrix_len; i++)
    matrix[i]  = 0;

  rounds = MAX(rounds, SHCR224_DEFAULT_ROUNDS);
  for (i = 0; i < rounds; i++) {
    memset(&ctx, 0, sizeof(ctx));
    err = shr224_init(&ctx);
    if (err) 
      return (err);

    err = shr224_write(&ctx, (unsigned char *)&magic, sizeof(magic));
    if (err) return (err);

    err = shr224_write(&ctx, (unsigned char *)salt, SHCR224_SIZE);
    if (err) return (err);

    err = shr224_write(&ctx, (unsigned char *)matrix, 28);
    if (err) return (err);

    err = shr224_write(&ctx, enc_data, sizeof(enc_data));
    if (err) return (err);

    memset(hash, 0, sizeof(hash));
    err = shr224_result(&ctx, hash);
    if (err)
      return (err);

    v = (uint32_t *)hash;
    for (j = 0; j < matrix_len; j++)
      matrix[j] += v[j];
  }

  err = shr224_expand((unsigned char *)matrix, ret_key, SHCR224_SIZE);
  if (err)
    return (err);

  return (0);
}

int shcr224(char *salt, char *data, char *ret_str)
{
  unsigned char salt_key[256];
  shcr224_t sig_key;
  uint32_t rounds;
  size_t r_len;
  int err;

  r_len = sizeof(salt_key);
  memset(salt_key, 0, sizeof(salt_key));
  err = shalg_decode(SHFMT_SHR56, salt, salt_key, &r_len);
  if (err)
    return (err);

  memcpy(&rounds, salt_key + SHCR224_SALT_SIZE, sizeof(rounds));
  rounds = ntohl(rounds);

  memset(sig_key, 0, sizeof(sig_key));
  err = shcr224_bin(salt_key, sig_key, rounds, 
      (unsigned char *)data, (size_t)strlen(data));
  if (err)
    return (err);

  strcpy(ret_str, shalg_encode(SHFMT_SHR56, sig_key, SHCR224_SIZE));

  return (0);
}

int shcr224_bin_verify(unsigned char salt_key[SHCR224_SALT_SIZE], shcr224_t sig, unsigned int rounds, unsigned char *data, size_t data_len)
{
  shcr224_t cmp_sig;
  int err; 

  memset(cmp_sig, 0, sizeof(cmp_sig));
  rounds = MAX(rounds, SHCR224_DEFAULT_ROUNDS);
  err = shcr224_bin(salt_key, cmp_sig, rounds, data, data_len); 
  if (err)
    return (err);

  if (0 != memcmp(cmp_sig, sig, SHCR224_SIZE)) {
    return (SHERR_ACCESS);
  }

  return (0);
}

int shcr224_verify(char *salt, char *sig, char *data)
{
  shcr224_t salt_key;
  shcr224_t sig_key;
  uint32_t rounds;
  size_t r_len;
  size_t sig_key_len;
  int err;

  r_len = sizeof(salt_key);
  memset(salt_key, 0, sizeof(salt_key));
  err = shalg_decode(SHFMT_SHR56, salt, salt_key, &r_len);
  if (err)
    return (err);

  memcpy(&rounds, salt_key + SHCR224_SALT_SIZE, sizeof(rounds));
  rounds = ntohl(rounds);

  sig_key_len = SHCR224_SIZE;
  (void)shalg_decode(SHFMT_SHR56, sig, sig_key, &sig_key_len);

  err = shcr224_bin_verify(salt_key, sig_key, rounds, 
      (unsigned char *)data, (size_t)strlen(data));
  if (err)
    return (err);

  return (0);
}


_TEST(shcr224_bin)
{
  char *pass = "passphrase";
  unsigned char salt_data[256];
  shcr224_t salt;
  shcr224_t sig;
  int err;

  memset(salt_data, 1, sizeof(salt_data));
  err = shcr224_salt_bin_gen(salt, salt_data, sizeof(salt_data));
  _TRUE(err == 0);

  memset(sig, 0, sizeof(sig));
  err = shcr224_bin(salt, sig, 1002, (unsigned char *)pass, strlen(pass));
  _TRUE(err == 0);

  err = shcr224_bin_verify(salt, sig, 1002, (unsigned char *)pass, strlen(pass));
  _TRUE(err == 0);

  err = shcr224_bin_verify(salt, sig, 1001, (unsigned char *)pass, strlen(pass));
  _TRUE(err != 0);

}

_TEST(shcr224)
{
  const char *pass = "passphrase";
  char data[256];
  char *salt;
  char sig[256];
  int err;

  memset(data, 1, sizeof(data));

  //salt = shcr224_salt_gen(0, data, sizeof(data));
  salt = shcr224_salt(0);

  memset(sig, 0, sizeof(sig));
  err = shcr224(salt, (char *)pass, sig); /* ~ 100ms */ 
  _TRUE(err == 0);

  err = shcr224_verify(salt, sig, (char *)pass);
  _TRUE(err == 0);
}


/* BCRC: a checksum-oriented convience set of functions */
uint64_t bcrc(unsigned char *data, size_t data_len)
{
	unsigned char digest[64];
	uint64_t crc; 
	uint64_t b;
	uint32_t *i_val;
	int err;
	int i;

	b = 0;
	crc = 1;

	/* <data_len> -> 28 bytes */
	memset(digest, 0, sizeof(digest));
	(void)shr224(data, data_len, digest);

	/* 28 bytes -> 8 bytes */
	i_val = (uint32_t *)digest;
	for (i = 0; i < 7; i++) {
		crc += (uint64_t)i_val[i];
		b |= crc;
		crc += (b << 32);
	}

	return (crc);
}

uint64_t bcrc_str(char *str)
{
	return (bcrc(str, strlen(str)));
}

char *bcrc_hex(unsigned char *data, size_t data_len)
{
	static char ret_str[64];
	uint64_t crc;
	uint32_t *i_val;

	crc = bcrc(data, data_len);
	i_val = (uint32_t *)&crc;

	memset(ret_str, 0, sizeof(ret_str));
	sprintf(ret_str, "%-8.8x%-8.8x", i_val[0], i_val[1]);

	return (ret_str);
}

char *bcrc_strhex(char *str)
{
	return (bcrc_hex(str, strlen(str)));
}

