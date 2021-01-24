
/*
 * @copyright
 *
 *  Copyright 2013, 2014 Neo Natura
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

#define __MEM__SHMEM_KEY_C__
#include "share.h"

shkey_t _shkey_blank;

shkey_t _shmem_key;

void *memxor (void *dest, const void *src, size_t n)
{
  char const *s = (const char *)src;
  char *d = (char *)dest;

  for (; n > 0; n--)
    *d++ ^= *s++;

  return dest;
}


#define _SH_SHA256_BLOCK_SIZE 64 /* ( 512 / 8) */

static void shkey_bin_r(void *data, size_t data_len, shkey_t *key)
{
  uint32_t crc;
  size_t step;
  char hash[_SH_SHA256_BLOCK_SIZE];
  size_t len;
  size_t of;
  int i;
  memset(key, 0, sizeof(shkey_t));
  memset(hash, 0, sizeof(hash));
  step = data_len / SHKEY_WORDS;
  for (i = 0; i < SHKEY_WORDS; i++) {
    /* add block to sha hash */
    of = step * i;
    len = MIN(data_len - of, step + 8);
    sh_sha256(data + of, len, hash);
    /* created [32bit] checksum from sha hash */
    key->code[i] = (uint32_t)shcrc32(hash, sizeof(hash));
  }
}
#if 0
/* faster version */
static void shkey_bin_r(void *data, size_t data_len, shkey_t *key)
{
  uint64_t val;
  size_t step;
  size_t len;
  size_t of;
  int i;

  memset(key, 0, sizeof(shkey_t));

  val = 0;
  step = data_len / SHKEY_WORDS;
  for (i = 0; i < SHKEY_WORDS; i++) {
    /* add block to sha hash */
    of = step * i;
    len = MIN(data_len - of, step + 8);
    val += shcrc((char *)data + of, len);
    key->code[i] = (uint32_t)val;
  }
}
#endif

shkey_t *shkey_bin(char *data, size_t data_len)
{
  shkey_t *ret_key = (shkey_t *)calloc(1, sizeof(shkey_t));
  if (data && data_len)
    shkey_bin_r(data, data_len, ret_key);
  return (ret_key);
}

shkey_t *ashkey_bin(char *data, size_t data_len)
{
  if (data && data_len)
    shkey_bin_r(data, data_len, &_shmem_key);
  return (&_shmem_key);
}

_TEST(shkey_bin)
{
  shfs_ino_t fake_parent;
  shkey_t *key[256];
  char buf[4096];
  shkey_t *ukey;
  int i, j;

  memset(&fake_parent, 0, sizeof(fake_parent));
  memcpy(&fake_parent.blk.hdr.name, ashkey_uniq(), sizeof(shkey_t));

  memset(buf, 0, sizeof(buf));
  buf[0] = 'a';

  /* ensure similar data has unique keys. */
  for (i = 0; i < 256; i++) {
    buf[1] = i;
    key[i] = shkey_bin(buf, sizeof(buf));
  }
  for (i = 0; i < 256; i++) {
    _TRUE(!shkey_cmp(key[i], ashkey_blank()));
    for (j = 0; j < 256; j++) {
      if (i == j) continue;
      _TRUE(!shkey_cmp(key[i], key[j]));
    } 
  }
  for (i = 0; i < 256; i++) {
    shkey_free(&key[i]);
  }

}

shkey_t *shkey_str(char *kvalue)
{
  if (!kvalue)
    return (shkey_bin(NULL, 0));
  return (shkey_bin(kvalue, strlen(kvalue)));
}

_TEST(shkey_str)
{
  shkey_t *key1;
  shkey_t *key2;

  /* compare unique keys */
  key1 = shkey_str("a");
  key2 = shkey_str("b");
  _TRUE(0 != memcmp(key1, key2, sizeof(shkey_t)));
  shkey_free(&key1);
  shkey_free(&key2);

  /* compare identical keys */
  key1 = shkey_str("a");
  key2 = shkey_str("a");
  _TRUE(0 == memcmp(key1, key2, sizeof(shkey_t)));
  shkey_free(&key1);
  shkey_free(&key2);

}

shkey_t *shkey_num(long kvalue)
{
  shkey_t *ret_key = (shkey_t *)calloc(1, sizeof(shkey_t));
  size_t len = sizeof(kvalue);
  shkey_bin_r(&kvalue, len, ret_key);
  return (ret_key);
}

shkey_t *shkey_num64(uint64_t kvalue)
{
  shkey_t *ret_key = (shkey_t *)calloc(1, sizeof(shkey_t));
  size_t len = sizeof(kvalue);
  shkey_bin_r(&kvalue, len, ret_key);
  return (ret_key);
}

_TEST(shkey_num)
{
  shkey_t *key1;
  shkey_t *key2;
  int num;

  /* compare unique numbers. */
  num = rand();
  key1 = shkey_num(num);
  key2 = shkey_num(num + 1);
  _TRUE(0 != memcmp(key1, key2, sizeof(shkey_t)));
  shkey_free(&key1);
  shkey_free(&key2);

  /* compare identical numbers. */
  num = rand();
  key1 = shkey_num(num);
  key2 = shkey_num(num);
  _TRUE(0 == memcmp(key1, key2, sizeof(shkey_t)));
  shkey_free(&key1);
  shkey_free(&key2);
}

shkey_t *shkey_uniq(void)
{
  shkey_t *ret_key;
  int i;
 
  ret_key = (shkey_t *)calloc(1, sizeof(shkey_t));
  for (i = 0; i < SHKEY_WORDS; i++) {
    ret_key->code[i] = (uint32_t)htonl((uint32_t)shrand());
  }

  return (ret_key);
}


_TEST(shkey_uniq)
{
  shkey_t *key1 = shkey_uniq();
  shkey_t *key2 = shkey_uniq();
  _TRUE(0 != memcmp(key1, key2, sizeof(shkey_t)));
  shkey_free(&key1);
  shkey_free(&key2);
}

shkey_t *ashkey_uniq(void)
{
  int i;

  memset(&_shmem_key, 0, sizeof(_shmem_key));
  for (i = 0; i < SHKEY_WORDS; i++) {
    _shmem_key.code[i] = (uint32_t)htonl((uint32_t)shrand());
  }

  return (&_shmem_key);
}

_TEST(ashkey_uniq)
{
  shkey_t *key1 = shkey_uniq();
  shkey_t *key2 = shkey_uniq();
  _TRUE(0 != memcmp(key1, key2, sizeof(shkey_t)));
  shkey_free(&key1);
  shkey_free(&key2);
}

void shkey_free(shkey_t **key_p)
{
  shkey_t *key;

  if (!key_p)
    return;

  key = *key_p;
  *key_p = NULL;

  if (!key)
    return;

  if (key == (shkey_t *)&_shmem_key)
    return; /* on the stack */

  free(key);
}

shkey_t *ashkey_str(char *name)
{

  memset(&_shmem_key, 0, sizeof(_shmem_key));
  if (name && strlen(name))
    shkey_bin_r(name, strlen(name), &_shmem_key);

  return (&_shmem_key);
}

shkey_t *ashkey_num(long num)
{
  char buf[256];

  memset(buf, 0, sizeof(buf));
  memcpy(buf, &num, sizeof(num)); 
  memset(&_shmem_key, 0, sizeof(_shmem_key));
  shkey_bin_r(buf, strlen(buf), &_shmem_key);

  return (&_shmem_key);
}

uint64_t shkey_crc(shkey_t *key)
{
  if (!key)
    return (0);
  return (shcrc(key, sizeof(shkey_t)));
}

int shkey_cmp(shkey_t *key_1, shkey_t *key_2)
{
  int i;

  if (!key_1 || !key_2)
    return (FALSE); /* invalid */

  if (shkey_alg(key_1) != shkey_alg(key_2))
    return (FALSE); /* incompatible algorythm */

  if (key_1->crc != key_2->crc)
    return (FALSE); /* internal checksum invalidated */

  for (i = 0; i < SHKEY_WORDS; i++) {
    if (key_1->code[i] != key_2->code[i])
      return (FALSE);
  }

  return (TRUE);
}

const char *shkey_print(shkey_t *key)
{
  static char ret_str[256];
  int i;

  memset(ret_str, 0, sizeof(ret_str));
  if (key) {
    for (i = 0; i < SHKEY_WORDS; i++) {
      sprintf(ret_str+strlen(ret_str), "%6.6s",
          shcrcstr((uint64_t)key->code[i]));
    }
    for (i = 0; i < 256; i++)
      if (ret_str[i] == ' ')
        ret_str[i] = '.';
  }

  return (ret_str);
}

shkey_t *shkey_clone(shkey_t *key)
{
  shkey_t *ret_key;

  if (!key)
    return (NULL);

  ret_key = (shkey_t *)calloc(1, sizeof(shkey_t));
	if (!ret_key)
		return (NULL);

  memcpy(ret_key, key, sizeof(shkey_t));
  return (ret_key);
}

shkey_t *shkey_cert(shkey_t *key, uint64_t crc, shtime_t stamp)
{
  unsigned char shabuf[64];
  unsigned char keybuf[64];
  char *ptr;
  uint32_t *sha_ar;
  int i;

  if (!key)
    return (NULL);

  memset(shabuf, '@', 64);
  memcpy(shabuf, &crc, sizeof(uint64_t));
  memcpy(shabuf + 8, &stamp, sizeof(shtime_t));
  memcpy(shabuf + 16, key, sizeof(shkey_t));
  sha_ar = (uint32_t *)shabuf;
  for (i = 0; i < 16; i++) {
    sha_ar[i] = htonl(sha_ar[i]);
  }

  memset(keybuf, 0, sizeof(keybuf));
  sh_sha256(shabuf, sizeof(shabuf), keybuf);
  return (shkey_bin(keybuf, sizeof(keybuf)));
}

_TEST(shkey_cert)
{
  shpeer_t *peer;
  shkey_t *key;
  shkey_t *peer_key;
  uint64_t crc = 1;

  peer = shpeer_init(NULL, NULL);
  _TRUEPTR(peer);
  peer_key = shpeer_kpub(peer);
  key = shkey_cert(peer_key, crc, 0);
  _TRUEPTR(key);
  shkey_free(&key);
  shpeer_free(&peer);
}

int shkey_verify(shkey_t *sig, uint64_t crc, shkey_t *key, shtime_t stamp)
{
  shkey_t *sha_key;
  char *ptr;
  int valid;

  sha_key = shkey_cert(key, crc, stamp);

  valid = shkey_cmp(sha_key, sig);
  shkey_free(&sha_key);
  if (!valid)
    return (SHERR_INVAL);

  return (0);
}

_TEST(shkey_verify)
{
  shpeer_t *peer;
  shkey_t *key;
  shkey_t *peer_key;
  uint64_t crc = 1;

  peer = shpeer_init(NULL, NULL);
  peer_key = shpeer_kpub(peer);
  key = shkey_cert(peer_key, crc, 0);
  _TRUEPTR(key);
  _TRUE(0 == shkey_verify(key, crc, peer_key, 0));
  shkey_free(&key);
  shpeer_free(&peer);
}

shkey_t *shkey_gen(char *str)
{
  shkey_t *ret_key;
  char buf[256];
  char *ptr;
  int i;

  //if (!str || strlen(str) != 36)
  if (!str || strlen(str) != 42)
    return (NULL);

  ret_key = (shkey_t *)calloc(1, sizeof(shkey_t));

  for (i = 0; i < SHKEY_WORDS; i++) {
    memset(buf, 0, sizeof(buf));
    strncpy(buf, str + (i * 6), 6);
    ptr = buf;
    while (*ptr && *ptr == '.')
      ptr++;
    ret_key->code[i] = (uint32_t)shcrcgen(ptr);
  }

  return (ret_key);
}

_TEST(shkey_gen)
{
  shkey_t *key;
  shkey_t *cmp_key;
  char buf[256];

  key = shkey_str("shkey_gen");

  memset(buf, 0, sizeof(buf));
  strncpy(buf, shkey_print(key), sizeof(buf)-1);

  cmp_key = shkey_gen(buf);
  _TRUEPTR(cmp_key);
  _TRUE(shkey_cmp(cmp_key, key));
  shkey_free(&cmp_key);

  shkey_free(&key);
}

const char *shkey_hex(shkey_t *key)
{
  static char ret_buf[256];
  int i;

  memset(ret_buf, 0, sizeof(ret_buf));


  if (key) {
    for (i = 0; i < SHKEY_WORDS; i++) {
      if (SHALG(shkey_alg(key), SHALG_ECDSA160R)) {
        if (i == 6) 
          continue;
        if (i == 5) {
          sprintf(ret_buf + strlen(ret_buf), "%-2.2x", key->code[i]);
          continue;
        } 
      }
      sprintf(ret_buf + strlen(ret_buf), "%-8.8x", key->code[i]);
    }
  }
  
  return (ret_buf);
}

_TEST(shkey_hex)
{
  shkey_t *key;
  char *ptr;

  key = shkey_uniq();
  _TRUEPTR(key);

  ptr = (char *)shkey_hex(key);
  _TRUEPTR(ptr);
  //_TRUE(strlen(ptr) == 48);
  _TRUE(strlen(ptr) == 56);
  _TRUE(strtoll(ptr, NULL, 16));

  shkey_free(&key);
}

shkey_t *shkey_hexgen(char *hex_str)
{
  shkey_t *ret_key;
  char buf[256];
  int i;

  if (!hex_str || strlen(hex_str) != 56)
    return (NULL);

  ret_key = (shkey_t *)calloc(1, sizeof(shkey_t));

  for (i = 0; i < SHKEY_WORDS; i++) {
    memset(buf, 0, sizeof(buf));
    strncpy(buf, hex_str + (8 * i), 8);
#if defined(HAVE_STRTOLL)
    ret_key->code[i] = (uint32_t)strtoll(buf, NULL, 16);
#elif defined(HAVE_STRTOL)
    ret_key->code[i] = (uint32_t)strtol(buf, NULL, 16);
#endif
  }

  return (ret_key);
}

_TEST(shkey_hexgen)
{
  shkey_t *key;
  shkey_t *cmp_key;
  char buf[256];

  key = shkey_str("shkey_hexgen");

  memset(buf, 0, sizeof(buf));
  strncpy(buf, shkey_hex(key), sizeof(buf)-1);
  //_TRUE(strlen(buf) == 48);
  _TRUE(strlen(buf) == 56);
  cmp_key = shkey_hexgen(buf);
  _TRUE(shkey_cmp(cmp_key, key));
  shkey_free(&cmp_key);

  shkey_free(&key);
}

#define MAX_RANDOM_SEED_SIZE 64 
uint64_t shrand(void)
{
  char buf[MAX_RANDOM_SEED_SIZE];
  int i; 

  memset(buf, 0, sizeof(buf));
  FILE *ran = fopen("/dev/urandom", "r");
  if (ran) {
    fread(buf, 1, sizeof(buf), ran);
    fclose(ran);    
  } else {
    static int init;
    if (!init) {
      init = 1;
      srand((unsigned int)shtime());
    }
    unsigned int rval;
    for (i = 0; i < MAX_RANDOM_SEED_SIZE; i += 4) {
      rval = rand();
      memcpy(buf + i, &rval, sizeof(rval));     
    }
  }

  return (shcrc(buf, sizeof(buf)));
}

static void _shkey_xor(shkey_t *s_key1, shkey_t *s_key2, shkey_t *d_key)
{
  int i;

  memcpy(d_key, ashkey_blank(), sizeof(shkey_t));

  for (i = 0; i < SHKEY_WORDS; i++) {
    d_key->code[i] = (s_key1->code[i] ^ s_key2->code[i]);
  }

}

shkey_t *shkey_xor(shkey_t *key1, shkey_t *key2)
{
  shkey_t *ret_key;

  ret_key = (shkey_t *)calloc(1, sizeof(shkey_t));
  if (!ret_key) return (NULL);
  _shkey_xor(key1, key2, ret_key);

  return (ret_key);
}

shkey_t *ashkey_xor(shkey_t *key1, shkey_t *key2)
{
  _shkey_xor(key1, key2, &_shmem_key);
  return (&_shmem_key);
}

shkey_t *shkey_dup(shkey_t *key)
{
  shkey_t *dup;

  if (!key)
    return (NULL);

  dup = (shkey_t *)calloc(1, sizeof(shkey_t));
  memcpy(dup, key, sizeof(shkey_t));

  return (dup);
}



/**
 * A 224-bit key, or less, derived from a binary segment.
 * @returns An allocated share key. Use shkey_free() to de-allocate.
 */
shkey_t *shkey(int alg, unsigned char *data, size_t data_len)
{
  shkey_t *ret_key;

  ret_key = NULL;

  if (SHALG(alg, SHALG_SHR160)) {
    ret_key = (shkey_t *)calloc(1, sizeof(shkey_t));
    if (!ret_key) return (NULL); /* SHERR_NOMEM */
    shkey_shr160_hash(ret_key, data, data_len); 
  } else if (SHALG(alg, SHALG_SHR224)) {
    ret_key = shkey_shr224(data, data_len);
  } else {
    ret_key = shkey_bin(data, data_len);
  }

  return (ret_key);
}

/**
 * A 224-bit key derived from a binary segment.
 * @returns An non-allocated (stack) 224-bit key.
 */
shkey_t *ashkey(int alg, unsigned char *data, size_t data_len)
{
  static shkey_t *ret_key;
  static shkey_t _key;

  memset(&_key, 0, sizeof(ret_key));
  ret_key = &_key;

  if (SHALG(alg, SHALG_SHR160)) {
    shkey_shr160_hash(&_key, data, data_len); 
  } else if (SHALG(alg, SHALG_SHR224)) {
    ret_key = ashkey_shr224(data, data_len);
  } else {
    ret_key = ashkey_bin(data, data_len);
  }

  return (ret_key);
}


int shkey_alg(shkey_t *key)
{

  if (!key)
    return (SHERR_INVAL);

  return ((int)ntohs(key->alg));
}

void shkey_alg_set(shkey_t *key, int alg)
{

  if (!key)
    return;

  key->alg = htons((uint16_t)alg);
}


#undef __MEM__SHMEM_KEY_C__



