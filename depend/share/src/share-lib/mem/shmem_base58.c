
/*
 * @copyright
 *
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
 *
 *  @endcopyright
 */

/*
 * Copyright (c) 2012-2014 Luke Dashjr
 * Copyright (c) 2013-2014 Pavol Rusnak
 */

#include "share.h"

static const int8_t b58digits_map[] = {
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
  -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
  22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
  -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
  47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
};


#if 0
int shbase58_decode_size(char *b58, size_t max_size)
{
  const size_t binsz = max_size;
  size_t ret_len;
  const unsigned char *b58u = (void*)b58;
  size_t outisz = (binsz + 3) / 4;
  uint32_t outi[outisz];
  uint64_t t;
  uint32_t c;
  size_t i, j;
  uint8_t bytesleft = binsz % 4;
  uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
  unsigned zerocount = 0;
  size_t b58sz;

  b58sz = strlen(b58);
  memset(outi, 0, outisz * sizeof(*outi));

  ret_len = 0;

  // Leading zeros, just count
  for (i = 0; i < b58sz && !b58digits_map[b58u[i]]; ++i) {
    ret_len++;
  }

  for ( ; i < b58sz; ++i)
  {
    if (b58u[i] & 0x80)
      // High-bit set on invalid digit
      return -1;
    if (b58digits_map[b58u[i]] == -1)
      // Invalid base58 digit
      return -1;
    c = (unsigned)b58digits_map[b58u[i]];
    for (j = outisz; j--; )
    {
      t = ((uint64_t)outi[j]) * 58 + c;
      c = (t & 0x3f00000000) >> 32;
      outi[j] = t & 0xffffffff;
    }
    if (c)
      // Output number too big (carry to the next int32)
      return -1;
    if (outi[0] & zeromask)
      // Output number too big (last int32 filled too far)
      return -1;
  }

  for(j = 0; !outi[j]; j++);
  ret_len = (outisz - j) * 4;

  ret_len += bytesleft;

  {
    uint8_t *binu = data;
    for (i = 0; i < binsz; ++i)
    {
      if (binu[i])
        break;
      ret_len--;
    }
  }

  return (ret_len);
}
#endif

int shbase58_decode_size(char *b58, size_t max_size)
{
  size_t binsz = max_size;
  const unsigned char *b58u = (void*)b58;
  unsigned char *binu;
  size_t outisz = (binsz + 3) / 4;
  uint32_t outi[outisz];
  uint64_t t;
  uint32_t c;
  size_t i, j;
  uint8_t bytesleft = binsz % 4;
  uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
  unsigned zerocount = 0;
  size_t b58sz;
  size_t ret_len;
  uint8_t *data;

  ret_len = max_size;

  data = (unsigned char *)calloc(1, max_size);
  binu = data;

  b58sz = strlen(b58);
  memset(outi, 0, outisz * sizeof(*outi));
  // Leading zeros, just count
  for (i = 0; i < b58sz && !b58digits_map[b58u[i]]; ++i)
    ++zerocount;
  for ( ; i < b58sz; ++i)
  {
    if (b58u[i] & 0x80)
      // High-bit set on invalid digit
      return -1;
    if (b58digits_map[b58u[i]] == -1)
      // Invalid base58 digit
      return -1;
    c = (unsigned)b58digits_map[b58u[i]];
    for (j = outisz; j--; )
    {
      t = ((uint64_t)outi[j]) * 58 + c;
      c = (t & 0x3f00000000) >> 32;
      outi[j] = t & 0xffffffff;
    }
    if (c)
      // Output number too big (carry to the next int32)
      return -1;
    if (outi[0] & zeromask)
      // Output number too big (last int32 filled too far)
      return -1;
  }
  j = 0;
  switch (bytesleft) {
    case 3:
      *(binu++) = (outi[0] & 0xff0000) >> 16;
    case 2:
      *(binu++) = (outi[0] & 0xff00) >> 8;
    case 1:
      *(binu++) = (outi[0] & 0xff);
      ++j;
    default:
      break;
  }
  for (; j < outisz; ++j)
  {
    *(binu++) = (outi[j] >> 0x18) & 0xff;
    *(binu++) = (outi[j] >> 0x10) & 0xff;
    *(binu++) = (outi[j] >> 8) & 0xff;
    *(binu++) = (outi[j] >> 0) & 0xff;
  }
  // Count canonical base58 byte count
  binu = data;
  for (i = 0; i < binsz; ++i)
  {
    if (binu[i])
      break;
    ret_len--;
  }
  ret_len += zerocount;

  free(data);

  return (ret_len);
}

int shbase58_decode(unsigned char *data, size_t *data_len, char *b58)
{
  size_t binsz = *data_len;
  const unsigned char *b58u = (void*)b58;
  unsigned char *binu = data;
  size_t outisz = (binsz + 3) / 4;
  uint32_t outi[outisz];
  uint64_t t;
  uint32_t c;
  size_t i, j;
  uint8_t bytesleft = binsz % 4;
  uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
  unsigned zerocount = 0;
  size_t b58sz;

  b58sz = strlen(b58);
  memset(outi, 0, outisz * sizeof(*outi));
  // Leading zeros, just count
  for (i = 0; i < b58sz && !b58digits_map[b58u[i]]; ++i)
    ++zerocount;
  for ( ; i < b58sz; ++i)
  {
    if (b58u[i] & 0x80)
      // High-bit set on invalid digit
      return -1;
    if (b58digits_map[b58u[i]] == -1)
      // Invalid base58 digit
      return -1;
    c = (unsigned)b58digits_map[b58u[i]];
    for (j = outisz; j--; )
    {
      t = ((uint64_t)outi[j]) * 58 + c;
      c = (t & 0x3f00000000) >> 32;
      outi[j] = t & 0xffffffff;
    }
    if (c)
      // Output number too big (carry to the next int32)
      return -1;
    if (outi[0] & zeromask)
      // Output number too big (last int32 filled too far)
      return -1;
  }
  j = 0;
  switch (bytesleft) {
    case 3:
      *(binu++) = (outi[0] & 0xff0000) >> 16;
    case 2:
      *(binu++) = (outi[0] & 0xff00) >> 8;
    case 1:
      *(binu++) = (outi[0] & 0xff);
      ++j;
    default:
      break;
  }
  for (; j < outisz; ++j)
  {
    *(binu++) = (outi[j] >> 0x18) & 0xff;
    *(binu++) = (outi[j] >> 0x10) & 0xff;
    *(binu++) = (outi[j] >> 8) & 0xff;
    *(binu++) = (outi[j] >> 0) & 0xff;
  }
  // Count canonical base58 byte count
  binu = data;
  for (i = 0; i < binsz; ++i)
  {
    if (binu[i])
      break;
    --*data_len;
  }
  *data_len += zerocount;

  return (0);
}


static int b58check(const void *bin, size_t binsz, const char *base58str)
{
  unsigned char buf[32];
  const uint8_t *binc = bin;
  unsigned i;

  if (binsz < 4)
    return -4;
  sh_sha256(bin, binsz - 4, buf);
  sh_sha256(buf, 32, buf);
  if (memcmp(&binc[binsz - 4], buf, 4))
    return -1;
  // Check number of zeros is correct AFTER verifying checksum (to avoid possibility of accessing base58str beyond the end)
  for (i = 0; binc[i] == '\0' && base58str[i] == '1'; ++i)
  {} // Just finding the end of zeros, nothing to do in loop
  if (binc[i] == '\0' || base58str[i] == '1')
    return -3;
  return binc[0];
}

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
int shbase58_encode(char *b58, size_t *b58sz, unsigned char *data, size_t data_len)
{
  const uint8_t *bin = data;
  int carry;
  ssize_t i, j, high, zcount = 0;
  size_t binsz = data_len;
  size_t size;

  while (zcount < (ssize_t)binsz && !bin[zcount])
    ++zcount;
  size = (binsz - zcount) * 138 / 100 + 1;
  uint8_t buf[size];
  memset(buf, 0, size);
  for (i = zcount, high = size - 1; i < (ssize_t)binsz; ++i, high = j)
  {
    for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
    {
      carry += 256 * buf[j];
      buf[j] = carry % 58;
      carry /= 58;
    }
  }
  for (j = 0; j < (ssize_t)size && !buf[j]; ++j);
  if (*b58sz <= zcount + size - j)
  {
    *b58sz = zcount + size - j + 1;
    return -1;
  }
  if (zcount)
    memset(b58, '1', zcount);
  for (i = zcount; j < (ssize_t)size; ++i, ++j)
    b58[i] = b58digits_ordered[buf[j]];
  b58[i] = '\0';
  *b58sz = i + 1;

  return (0);
}

int shbase58_encode_check(const uint8_t *data, int datalen, char *str, int strsize)
{
  if (datalen > 128) {
    return 0;
  }
  uint8_t buf[datalen + 32];
  uint8_t *hash = buf + datalen;
  memcpy(buf, data, datalen);
  sh_sha256(data, datalen, hash);
  sh_sha256(hash, 32, hash);
  size_t res = strsize;
  bool success = (shbase58_encode(str, &res, buf, datalen + 4) == 0);
  memset(buf, '\0', sizeof(buf));
  return success ? res : 0;
}

int shbase58_decode_check(const char *str, uint8_t *data, int datalen)
{
  if (datalen > 128) {
    return 0;
  }
  uint8_t d[datalen + 4];
  size_t res = datalen + 4;
  if (shbase58_decode(d, &res, (char *)str) != 0) {
    return 0;
  }
  if (res != (size_t)datalen + 4) {
    return 0;
  }
  if (b58check(d, res, str) < 0) {
    return 0;
  }
  memcpy(data, d, datalen);
  return datalen;
}

_TEST(shbase58_decode)
{
#define SHBASE58_DECODE_TEST_SIZE 100
  char data[1024];
  char enc_data[1024];
  char dec_data[1024];
  size_t enc_len;
  size_t dec_len;
  int err;

  memset(data, '\0', sizeof(data));
  memset(data, 1, SHBASE58_DECODE_TEST_SIZE);

  enc_len = sizeof(enc_data);
  memset(enc_data, 0, enc_len);
  err = shbase58_encode(enc_data, &enc_len, data, SHBASE58_DECODE_TEST_SIZE);
  _TRUE(0 == err);
  _TRUE(enc_len > 128);

  dec_len = SHBASE58_DECODE_TEST_SIZE;
  memset(dec_data, 0, sizeof(dec_data));
  err = shbase58_decode(dec_data, &dec_len, enc_data);
  _TRUE(0 == err);
  _TRUE(dec_len == SHBASE58_DECODE_TEST_SIZE);
  _TRUE(0 == memcmp(data, dec_data, SHBASE58_DECODE_TEST_SIZE));
}


