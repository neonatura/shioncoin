
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

#include "share.h"

static const unsigned char _shbase64_decode_table[256] =
{
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

int shbase64_decode_len(char *enc_data)
{
  int nbytesdecoded;
  register const unsigned char *bufin;
  register int nprbytes;

  bufin = (const unsigned char *) enc_data;
  while (_shbase64_decode_table[*(bufin++)] <= 63);

  nprbytes = (bufin - (const unsigned char *) enc_data) - 1;
  nbytesdecoded = ((nprbytes + 3) / 4) * 3;

  return nbytesdecoded + 1;
}

int shbase64_encode_len(int len)
{
  return ((len + 2) / 3 * 4) + 1;
}

int shbase64_decode(char *enc_data, unsigned char **data_p, size_t *data_len_p) 
{
  int nbytesdecoded;
  register const unsigned char *bufin;
  register unsigned char *bufout;
  register int nprbytes;
  unsigned char *bufplain;
  size_t alloc_len;

  alloc_len = shbase64_decode_len(enc_data);
  bufplain = (unsigned char *)calloc(alloc_len + 1, sizeof(char));
  if (!bufplain)
    return (SHERR_NOMEM);

  bufin = (const unsigned char *) enc_data;
  while (_shbase64_decode_table[*(bufin++)] <= 63);
  nprbytes = (bufin - (const unsigned char *) enc_data) - 1;
  nbytesdecoded = ((nprbytes + 3) / 4) * 3;

  bufout = (unsigned char *) bufplain;
  bufin = (const unsigned char *) enc_data;

  while (nprbytes > 4) {
    *(bufout++) =
      (unsigned char) (_shbase64_decode_table[*bufin] << 2 | _shbase64_decode_table[bufin[1]] >> 4);
    *(bufout++) =
      (unsigned char) (_shbase64_decode_table[bufin[1]] << 4 | _shbase64_decode_table[bufin[2]] >> 2);
    *(bufout++) =
      (unsigned char) (_shbase64_decode_table[bufin[2]] << 6 | _shbase64_decode_table[bufin[3]]);
    bufin += 4;
    nprbytes -= 4;
  }

  /* Note: (nprbytes == 1) would be an error, so just ingore that case */
  if (nprbytes > 1) {
    *(bufout++) =
      (unsigned char) (_shbase64_decode_table[*bufin] << 2 | _shbase64_decode_table[bufin[1]] >> 4);
  }
  if (nprbytes > 2) {
    *(bufout++) =
      (unsigned char) (_shbase64_decode_table[bufin[1]] << 4 | _shbase64_decode_table[bufin[2]] >> 2);
  }
  if (nprbytes > 3) {
    *(bufout++) =
      (unsigned char) (_shbase64_decode_table[bufin[2]] << 6 | _shbase64_decode_table[bufin[3]]);
  }

  *(bufout++) = '\0';
  nbytesdecoded -= (4 - nprbytes) & 3;

  if (data_p)
    *data_p = bufplain; 
  else
    free(bufplain);
  if (data_len_p)
    *data_len_p = nbytesdecoded;

  return (0);
}

static const char _shbase64_encode_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int shbase64_encode(unsigned char *data, size_t data_len, char **enc_data_p)
{
  char *encoded;
  char *p;
  size_t alloc_len;
  int i;

  if (!enc_data_p)
    return (SHERR_INVAL);

  alloc_len = shbase64_encode_len(data_len);
  encoded = (char *)calloc(alloc_len + 1, sizeof(char));
  if (!encoded)
    return (SHERR_NOMEM);

  p = encoded;
  for (i = 0; i < data_len - 2; i += 3) {
    *p++ = _shbase64_encode_table[(data[i] >> 2) & 0x3F];
    *p++ = _shbase64_encode_table[((data[i] & 0x3) << 4) |
      ((int) (data[i + 1] & 0xF0) >> 4)];
    *p++ = _shbase64_encode_table[((data[i + 1] & 0xF) << 2) |
      ((int) (data[i + 2] & 0xC0) >> 6)];
    *p++ = _shbase64_encode_table[data[i + 2] & 0x3F];
  }
  if (i < data_len) {
    *p++ = _shbase64_encode_table[(data[i] >> 2) & 0x3F];
    if (i == (data_len - 1)) {
      *p++ = _shbase64_encode_table[((data[i] & 0x3) << 4)];
      *p++ = '=';
    }
    else {
      *p++ = _shbase64_encode_table[((data[i] & 0x3) << 4) |
        ((int) (data[i + 1] & 0xF0) >> 4)];
      *p++ = _shbase64_encode_table[((data[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
  }

//  *p++ = '\0';
  *enc_data_p = encoded;

  return (0);
}


