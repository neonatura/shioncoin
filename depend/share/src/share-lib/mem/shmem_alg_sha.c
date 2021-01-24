
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
#include "shmem_alg_sha.h"


#define PASS_CODE_LENGTH 6
#define SECRET_2FA_SIZE 10

#define PIN_2FA_MODULO(_seclen) \
  (uint32_t)pow(10, (_seclen-4)) 
//static int PIN_MODULO = pow(10, PASS_CODE_LENGTH);

/* Initial Hash Values: FIPS 180-3 section 5.3.2 */
static uint32_t SHA224_H0[SHA256HashSize/4] = {
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
    0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
};

/* Initial Hash Values: FIPS 180-3 section 5.3.3 */
static uint32_t SHA256_H0[SHA256HashSize/4] = {
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

/* Initial Hash Values: FIPS 180-3 sections 5.3.4 and 5.3.5 */
static uint64_t SHA384_H0[ ] = {
    0xCBBB9D5DC1059ED8ll, 0x629A292A367CD507ll, 0x9159015A3070DD17ll,
    0x152FECD8F70E5939ll, 0x67332667FFC00B31ll, 0x8EB44A8768581511ll,
    0xDB0C2E0D64F98FA7ll, 0x47B5481DBEFA4FA4ll
};
static uint64_t SHA512_H0[ ] = {
    0x6A09E667F3BCC908ll, 0xBB67AE8584CAA73Bll, 0x3C6EF372FE94F82Bll,
    0xA54FF53A5F1D36F1ll, 0x510E527FADE682D1ll, 0x9B05688C2B3E6C1Fll,
    0x1F83D9ABFB41BD6Bll, 0x5BE0CD19137E2179ll
};


static void SHA1ProcessMessageBlock(sh_sha1_t *context)
{
  /* Constants defined in FIPS 180-3, section 4.2.1 */
  const uint32_t K[4] = {
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
  };
  int        t;               /* Loop counter */
  uint32_t   temp;            /* Temporary word value */
  uint32_t   W[80];           /* Word sequence */
  uint32_t   A, B, C, D, E;   /* Word buffers */

  /*
   * Initialize the first 16 words in the array W
   */
  for (t = 0; t < 16; t++) {
    W[t]  = ((uint32_t)context->Message_Block[t * 4]) << 24;
    W[t] |= ((uint32_t)context->Message_Block[t * 4 + 1]) << 16;
    W[t] |= ((uint32_t)context->Message_Block[t * 4 + 2]) << 8;
    W[t] |= ((uint32_t)context->Message_Block[t * 4 + 3]);
  }

  for (t = 16; t < 80; t++)
    W[t] = SHA1_ROTL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];

  for (t = 0; t < 20; t++) {
    temp = SHA1_ROTL(5,A) + SHA_Ch(B, C, D) + E + W[t] + K[0];
    E = D;
    D = C;
    C = SHA1_ROTL(30,B);
    B = A;
    A = temp;
  }

  for (t = 20; t < 40; t++) {
    temp = SHA1_ROTL(5,A) + SHA_Parity(B, C, D) + E + W[t] + K[1];
    E = D;
    D = C;
    C = SHA1_ROTL(30,B);
    B = A;
    A = temp;
  }

  for (t = 40; t < 60; t++) {
    temp = SHA1_ROTL(5,A) + SHA_Maj(B, C, D) + E + W[t] + K[2];
    E = D;
    D = C;
    C = SHA1_ROTL(30,B);
    B = A;
    A = temp;
  }

  for (t = 60; t < 80; t++) {
    temp = SHA1_ROTL(5,A) + SHA_Parity(B, C, D) + E + W[t] + K[3];
    E = D;
    D = C;
    C = SHA1_ROTL(30,B);
    B = A;
    A = temp;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Message_Block_Index = 0;
}
static void SHA1PadMessage(sh_sha1_t *context, uint8_t Pad_Byte)
{
  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index >= (SHA1_Message_Block_Size - 8)) {
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    while (context->Message_Block_Index < SHA1_Message_Block_Size)
      context->Message_Block[context->Message_Block_Index++] = 0;

    SHA1ProcessMessageBlock(context);
  } else
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

  while (context->Message_Block_Index < (SHA1_Message_Block_Size - 8))
    context->Message_Block[context->Message_Block_Index++] = 0;

  /*
   * Store the message length as the last 8 octets
   */
  context->Message_Block[56] = (uint8_t) (context->Length_High >> 24);
  context->Message_Block[57] = (uint8_t) (context->Length_High >> 16);
  context->Message_Block[58] = (uint8_t) (context->Length_High >> 8);
  context->Message_Block[59] = (uint8_t) (context->Length_High);
  context->Message_Block[60] = (uint8_t) (context->Length_Low >> 24);
  context->Message_Block[61] = (uint8_t) (context->Length_Low >> 16);
  context->Message_Block[62] = (uint8_t) (context->Length_Low >> 8);
  context->Message_Block[63] = (uint8_t) (context->Length_Low);

  SHA1ProcessMessageBlock(context);
}
static void SHA1Finalize(sh_sha1_t *context, uint8_t Pad_Byte)
{
  int i;
  SHA1PadMessage(context, Pad_Byte);
  /* message may be sensitive, clear it out */
  for (i = 0; i < SHA1_Message_Block_Size; ++i)
    context->Message_Block[i] = 0;
  context->Length_High = 0;     /* and clear length */
  context->Length_Low = 0;
  context->Computed = 1;
}

static int SHA224_256Reset(sh_sha256_t *context, uint32_t *H0)
{
  if (!context) return SHERR_INVAL;

  context->Length_High = context->Length_Low = 0;
  context->Message_Block_Index  = 0;

  context->Intermediate_Hash[0] = H0[0];
  context->Intermediate_Hash[1] = H0[1];
  context->Intermediate_Hash[2] = H0[2];
  context->Intermediate_Hash[3] = H0[3];
  context->Intermediate_Hash[4] = H0[4];
  context->Intermediate_Hash[5] = H0[5];
  context->Intermediate_Hash[6] = H0[6];
  context->Intermediate_Hash[7] = H0[7];

  context->Computed  = 0;
  context->Corrupted = 0;

  return (0);
}
static void SHA224_256ProcessMessageBlock(sh_sha256_t *context)
{
  /* Constants defined in FIPS 180-3, section 4.2.2 */
  static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };
  int        t, t4;                   /* Loop counter */
  uint32_t   temp1, temp2;            /* Temporary word value */
  uint32_t   W[64];                   /* Word sequence */
  uint32_t   A, B, C, D, E, F, G, H;  /* Word buffers */

  /*
   * Initialize the first 16 words in the array W
   */
  for (t = t4 = 0; t < 16; t++, t4 += 4)
    W[t] = (((uint32_t)context->Message_Block[t4]) << 24) |
      (((uint32_t)context->Message_Block[t4 + 1]) << 16) |
      (((uint32_t)context->Message_Block[t4 + 2]) << 8) |
      (((uint32_t)context->Message_Block[t4 + 3]));

  for (t = 16; t < 64; t++)
    W[t] = SHA256_sigma1(W[t-2]) + W[t-7] +
      SHA256_sigma0(W[t-15]) + W[t-16];

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];
  F = context->Intermediate_Hash[5];
  G = context->Intermediate_Hash[6];
  H = context->Intermediate_Hash[7];

  for (t = 0; t < 64; t++) {
    temp1 = H + SHA256_SIGMA1(E) + SHA_Ch(E,F,G) + K[t] + W[t];
    temp2 = SHA256_SIGMA0(A) + SHA_Maj(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + temp1;
    D = C;
    C = B;
    B = A;
    A = temp1 + temp2;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Intermediate_Hash[5] += F;
  context->Intermediate_Hash[6] += G;
  context->Intermediate_Hash[7] += H;

  context->Message_Block_Index = 0;
}
static void SHA224_256PadMessage(sh_sha256_t *context, uint8_t Pad_Byte)
{

  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index >= (SHA256_Message_Block_Size-8)) {
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    while (context->Message_Block_Index < SHA256_Message_Block_Size)
      context->Message_Block[context->Message_Block_Index++] = 0;
    SHA224_256ProcessMessageBlock(context);
  } else
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

  while (context->Message_Block_Index < (SHA256_Message_Block_Size-8))
    context->Message_Block[context->Message_Block_Index++] = 0;

  /*
   * Store the message length as the last 8 octets
   */
  context->Message_Block[56] = (uint8_t)(context->Length_High >> 24);
  context->Message_Block[57] = (uint8_t)(context->Length_High >> 16);
  context->Message_Block[58] = (uint8_t)(context->Length_High >> 8);
  context->Message_Block[59] = (uint8_t)(context->Length_High);
  context->Message_Block[60] = (uint8_t)(context->Length_Low >> 24);
  context->Message_Block[61] = (uint8_t)(context->Length_Low >> 16);
  context->Message_Block[62] = (uint8_t)(context->Length_Low >> 8);
  context->Message_Block[63] = (uint8_t)(context->Length_Low);

  SHA224_256ProcessMessageBlock(context);
}
static void SHA224_256Finalize(sh_sha256_t *context, uint8_t Pad_Byte)
{
  int i;
  SHA224_256PadMessage(context, Pad_Byte);
  /* message may be sensitive, so clear it out */
  for (i = 0; i < SHA256_Message_Block_Size; ++i)
    context->Message_Block[i] = 0;
  context->Length_High = 0;     /* and clear length */
  context->Length_Low = 0;
  context->Computed = 1;
}
static int SHA224_256ResultN(sh_sha256_t *context, uint8_t Message_Digest[ ], int HashSize)
{
  int i;

  if (!context) return SHERR_INVAL;
  if (!Message_Digest) return SHERR_INVAL;
  if (context->Corrupted) return context->Corrupted;

  if (!context->Computed)
    SHA224_256Finalize(context, 0x80);

  for (i = 0; i < HashSize; ++i)
    Message_Digest[i] = (uint8_t)
      (context->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) ));

  return (0);
}



static int SHA384_512Reset(sh_sha512_t *context, uint64_t H0[SHA512HashSize/8])
{
  int i;

  if (!context) return SHERR_INVAL;
  context->Message_Block_Index = 0;

  context->Length_High = context->Length_Low = 0;

  for (i = 0; i < SHA512HashSize/8; i++)
    context->Intermediate_Hash[i] = H0[i];

  context->Computed = 0;
  context->Corrupted = 0;

  return (0);
}
static void SHA384_512ProcessMessageBlock(sh_sha512_t *context)
{
  /* Constants defined in FIPS 180-3, section 4.2.3 */
  static const uint64_t K[80] = {
    0x428A2F98D728AE22ll, 0x7137449123EF65CDll, 0xB5C0FBCFEC4D3B2Fll,
    0xE9B5DBA58189DBBCll, 0x3956C25BF348B538ll, 0x59F111F1B605D019ll,
    0x923F82A4AF194F9Bll, 0xAB1C5ED5DA6D8118ll, 0xD807AA98A3030242ll,
    0x12835B0145706FBEll, 0x243185BE4EE4B28Cll, 0x550C7DC3D5FFB4E2ll,
    0x72BE5D74F27B896Fll, 0x80DEB1FE3B1696B1ll, 0x9BDC06A725C71235ll,
    0xC19BF174CF692694ll, 0xE49B69C19EF14AD2ll, 0xEFBE4786384F25E3ll,
    0x0FC19DC68B8CD5B5ll, 0x240CA1CC77AC9C65ll, 0x2DE92C6F592B0275ll,
    0x4A7484AA6EA6E483ll, 0x5CB0A9DCBD41FBD4ll, 0x76F988DA831153B5ll,
    0x983E5152EE66DFABll, 0xA831C66D2DB43210ll, 0xB00327C898FB213Fll,
    0xBF597FC7BEEF0EE4ll, 0xC6E00BF33DA88FC2ll, 0xD5A79147930AA725ll,
    0x06CA6351E003826Fll, 0x142929670A0E6E70ll, 0x27B70A8546D22FFCll,
    0x2E1B21385C26C926ll, 0x4D2C6DFC5AC42AEDll, 0x53380D139D95B3DFll,
    0x650A73548BAF63DEll, 0x766A0ABB3C77B2A8ll, 0x81C2C92E47EDAEE6ll,
    0x92722C851482353Bll, 0xA2BFE8A14CF10364ll, 0xA81A664BBC423001ll,
    0xC24B8B70D0F89791ll, 0xC76C51A30654BE30ll, 0xD192E819D6EF5218ll,
    0xD69906245565A910ll, 0xF40E35855771202All, 0x106AA07032BBD1B8ll,
    0x19A4C116B8D2D0C8ll, 0x1E376C085141AB53ll, 0x2748774CDF8EEB99ll,
    0x34B0BCB5E19B48A8ll, 0x391C0CB3C5C95A63ll, 0x4ED8AA4AE3418ACBll,
    0x5B9CCA4F7763E373ll, 0x682E6FF3D6B2B8A3ll, 0x748F82EE5DEFB2FCll,
    0x78A5636F43172F60ll, 0x84C87814A1F0AB72ll, 0x8CC702081A6439ECll,
    0x90BEFFFA23631E28ll, 0xA4506CEBDE82BDE9ll, 0xBEF9A3F7B2C67915ll,
    0xC67178F2E372532Bll, 0xCA273ECEEA26619Cll, 0xD186B8C721C0C207ll,
    0xEADA7DD6CDE0EB1Ell, 0xF57D4F7FEE6ED178ll, 0x06F067AA72176FBAll,
    0x0A637DC5A2C898A6ll, 0x113F9804BEF90DAEll, 0x1B710B35131C471Bll,
    0x28DB77F523047D84ll, 0x32CAAB7B40C72493ll, 0x3C9EBE0A15C9BEBCll,
    0x431D67C49C100D4Cll, 0x4CC5D4BECB3E42B6ll, 0x597F299CFC657E2All,
    0x5FCB6FAB3AD6FAECll, 0x6C44198C4A475817ll
  };
  int        t, t8;                   /* Loop counter */
  uint64_t   temp1, temp2;            /* Temporary word value */
  uint64_t   W[80];                   /* Word sequence */
  uint64_t   A, B, C, D, E, F, G, H;  /* Word buffers */

  /*
   * Initialize the first 16 words in the array W
   */
  for (t = t8 = 0; t < 16; t++, t8 += 8)
    W[t] = ((uint64_t)(context->Message_Block[t8  ]) << 56) |
      ((uint64_t)(context->Message_Block[t8 + 1]) << 48) |
      ((uint64_t)(context->Message_Block[t8 + 2]) << 40) |
      ((uint64_t)(context->Message_Block[t8 + 3]) << 32) |
      ((uint64_t)(context->Message_Block[t8 + 4]) << 24) |
      ((uint64_t)(context->Message_Block[t8 + 5]) << 16) |
      ((uint64_t)(context->Message_Block[t8 + 6]) << 8) |
      ((uint64_t)(context->Message_Block[t8 + 7]));

  for (t = 16; t < 80; t++)
    W[t] = SHA512_sigma1(W[t-2]) + W[t-7] +
      SHA512_sigma0(W[t-15]) + W[t-16];
  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];
  F = context->Intermediate_Hash[5];
  G = context->Intermediate_Hash[6];
  H = context->Intermediate_Hash[7];

  for (t = 0; t < 80; t++) {
    temp1 = H + SHA512_SIGMA1(E) + SHA_Ch(E,F,G) + K[t] + W[t];
    temp2 = SHA512_SIGMA0(A) + SHA_Maj(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + temp1;
    D = C;
    C = B;
    B = A;
    A = temp1 + temp2;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Intermediate_Hash[5] += F;
  context->Intermediate_Hash[6] += G;
  context->Intermediate_Hash[7] += H;

  context->Message_Block_Index = 0;
}
static void SHA384_512PadMessage(sh_sha512_t *context, uint8_t Pad_Byte)
{
  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index >= (SHA512_Message_Block_Size-16)) {
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    while (context->Message_Block_Index < SHA512_Message_Block_Size)
      context->Message_Block[context->Message_Block_Index++] = 0;

    SHA384_512ProcessMessageBlock(context);
  } else
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

  while (context->Message_Block_Index < (SHA512_Message_Block_Size-16))
    context->Message_Block[context->Message_Block_Index++] = 0;

  /*
   * Store the message length as the last 16 octets
  */
  context->Message_Block[112] = (uint8_t)(context->Length_High >> 56);
  context->Message_Block[113] = (uint8_t)(context->Length_High >> 48);
  context->Message_Block[114] = (uint8_t)(context->Length_High >> 40);
  context->Message_Block[115] = (uint8_t)(context->Length_High >> 32);
  context->Message_Block[116] = (uint8_t)(context->Length_High >> 24);
  context->Message_Block[117] = (uint8_t)(context->Length_High >> 16);
  context->Message_Block[118] = (uint8_t)(context->Length_High >> 8);
  context->Message_Block[119] = (uint8_t)(context->Length_High);

  context->Message_Block[120] = (uint8_t)(context->Length_Low >> 56);
  context->Message_Block[121] = (uint8_t)(context->Length_Low >> 48);
  context->Message_Block[122] = (uint8_t)(context->Length_Low >> 40);
  context->Message_Block[123] = (uint8_t)(context->Length_Low >> 32);
  context->Message_Block[124] = (uint8_t)(context->Length_Low >> 24);
  context->Message_Block[125] = (uint8_t)(context->Length_Low >> 16);
  context->Message_Block[126] = (uint8_t)(context->Length_Low >> 8);
  context->Message_Block[127] = (uint8_t)(context->Length_Low);

  SHA384_512ProcessMessageBlock(context);
}
static void SHA384_512Finalize(sh_sha512_t *context, uint8_t Pad_Byte)
{
  int_least16_t i;
  SHA384_512PadMessage(context, Pad_Byte);
  /* message may be sensitive, clear it out */
  for (i = 0; i < SHA512_Message_Block_Size; ++i)
    context->Message_Block[i] = 0;
  context->Length_High = context->Length_Low = 0;
  context->Computed = 1;
}
static int SHA384_512ResultN(sh_sha512_t *context, uint8_t Message_Digest[ ], int HashSize)
{
  int i;

  if (!context) return SHERR_INVAL;
  if (!Message_Digest) return SHERR_INVAL;
  if (context->Corrupted) return context->Corrupted;

  if (!context->Computed)
    SHA384_512Finalize(context, 0x80);

  for (i = 0; i < HashSize; ++i)
    Message_Digest[i] = (uint8_t)
      (context->Intermediate_Hash[i>>3] >> 8 * ( 7 - ( i % 8 ) ));

  return (0);
}



int sh_sha1_init(sh_sha_t *sha)
{
  sh_sha1_t *context;

  if (!sha)
    return (SHERR_INVAL);

  memset(sha, '\000', sizeof(sha));
  sha->alg = SHALG_SHA1;
  context = &sha->ctx.sha1;

  context->Length_High = context->Length_Low = 0;
  context->Message_Block_Index = 0;

  /* Initial Hash Values: FIPS 180-3 section 5.3.1 */
  context->Intermediate_Hash[0]   = 0x67452301;
  context->Intermediate_Hash[1]   = 0xEFCDAB89;
  context->Intermediate_Hash[2]   = 0x98BADCFE;
  context->Intermediate_Hash[3]   = 0x10325476;
  context->Intermediate_Hash[4]   = 0xC3D2E1F0;

  context->Computed   = 0;
  context->Corrupted  = 0;

  return (0);
}

int sh_sha1_write(sh_sha_t *sha,
    const uint8_t *message_array, unsigned length)
{
  sh_sha1_t *context;

  if (!sha)
    return (SHERR_INVAL);

  if (!length) return (0);
  if (!message_array) return SHERR_INVAL;

  context = &sha->ctx.sha1;
  if (context->Computed) return context->Corrupted = SHERR_INVAL;
  if (context->Corrupted) return context->Corrupted;

  while (length--) {
    context->Message_Block[context->Message_Block_Index++] =
      *message_array;

    if ((SHA1AddLength(context, 8) == 0) &&
      (context->Message_Block_Index == SHA1_Message_Block_Size))
      SHA1ProcessMessageBlock(context);

    message_array++;
  }

  return context->Corrupted;
}

int sh_sha1_result(sh_sha_t *sha, uint8_t *Message_Digest/*[SHA1HashSize]*/)
{
  sh_sha1_t *context;
  int i;

  if (!sha) return SHERR_INVAL;
  if (!Message_Digest) return SHERR_INVAL;

  context = &sha->ctx.sha1;
  if (context->Corrupted) return context->Corrupted;

  if (!context->Computed)
    SHA1Finalize(context, 0x80);

  for (i = 0; i < SHA1HashSize; ++i)
    Message_Digest[i] = (uint8_t) (context->Intermediate_Hash[i>>2]
                                   >> (8 * ( 3 - ( i & 0x03 ) )));

  return (0);
}



/**
 * This function will initialize the SHA224Context in preparation for computing a new SHA224 message digest.
 *
 * @param context The context to reset.
 * @returns A libshare error code.
 */
int sh_sha224_init(sh_sha_t *sha)
{
  sh_sha256_t *context;

  if (!sha) return (SHERR_INVAL);

  memset(sha, '\000', sizeof(sha));
  sha->alg = SHALG_SHA224;
  context = &sha->ctx.sha256;

  return SHA224_256Reset(context, SHA224_H0);
}

/**
 * This function accepts an array of octets as the next portion of the message.
 *
 * @param context The SHA context to update.
 * @param message_array An array of octets representing the next portion of the message.
 * @param length The length of the message in message_array.
 * @returns A libshare error code.
 */
int sh_sha224_write(sh_sha_t *sha, const uint8_t *message_array, unsigned int length)
{
  return sh_sha256_write(sha, message_array, length);
}

/**
 * This function will return the 224-bit message digest into the Message_Digest array provided by the caller.
 *
 * @param context The context to use to calculate the SHA hash.
 * @param Message_Digest Where the digest is returned.
 *  @returns A libshare error code.
 *  @note The first octet of hash is stored in the element with index 0. The last octet of hash in the element with index 27.
 */
int sh_sha224_result(sh_sha_t *sha, uint8_t *Message_Digest)
{
  sh_sha256_t *context;

  if (!sha) return (SHERR_INVAL);
  context = &sha->ctx.sha256;

  return SHA224_256ResultN(context, Message_Digest, SHA224HashSize);
}

void sh_sha224(const unsigned char *message, unsigned int len, unsigned char *digest)
{
  sh_sha_t ctx;

  sh_sha224_init(&ctx);
  sh_sha224_write(&ctx, message, len);
  sh_sha224_result(&ctx, digest);
}

int sh_sha256_init(sh_sha_t *sha)
{
  sh_sha256_t *context;

  if (!sha) return SHERR_INVAL;

  memset(sha, '\000', sizeof(sha));
  sha->alg = SHALG_SHA256;
  context = &sha->ctx.sha256;

  return SHA224_256Reset(context, SHA256_H0);
}

int sh_sha256_write(sh_sha_t *sha, const uint8_t *message_array, unsigned int length)
{
  sh_sha256_t *context;

  if (!sha) return (SHERR_INVAL);
  if (!length) return (0);
  if (!message_array) return SHERR_INVAL;

  context = &sha->ctx.sha256;
  if (context->Computed) return context->Corrupted = SHERR_INVAL;
  if (context->Corrupted) return context->Corrupted;

  while (length--) {
    context->Message_Block[context->Message_Block_Index++] =
      *message_array;

    if ((SHA224_256AddLength(context, 8) == 0) &&
        (context->Message_Block_Index == SHA256_Message_Block_Size))
      SHA224_256ProcessMessageBlock(context);

    message_array++;
  }

  return context->Corrupted;
}

int sh_sha256_result(sh_sha_t *sha, uint8_t *Message_Digest/*[SHA256HashSize]*/)
{
  sh_sha256_t *context;

  if (!sha) return (SHERR_INVAL);
  context = &sha->ctx.sha256;

  return SHA224_256ResultN(context, Message_Digest, SHA256HashSize);
}

void sh_sha256(const unsigned char *message, unsigned int len, unsigned char *digest)
{
  sh_sha_t ctx;

  sh_sha256_init(&ctx);
  sh_sha256_write(&ctx, message, len);
  sh_sha256_result(&ctx, digest);
}





/**
 * This function will initialize the SHA384Context in preparation for computing a new SHA384 message digest.
 *
 * @param context The context to reset.
 * @returns A libshare error code.
 */
int sh_sha384_init(sh_sha_t *sha)
{

  if (!sha) return (SHERR_INVAL);
  memset(sha, '\000', sizeof(sha));
  sha->alg = SHALG_SHA384;

  return SHA384_512Reset(&sha->ctx.sha512, SHA384_H0);
}

/**
 * This function accepts an array of octets as the next portion of the message.
 *
 * @param context The SHA context to update.
 * @param message_array An array of octets representing the next portion of the message.
 * @param length The length of the message in message_array.
 * @returns A libshare error code.
 */
int sh_sha384_write(sh_sha_t *sha, const uint8_t *message_array, unsigned int length)
{
  return sh_sha512_write(sha, message_array, length);
}


/**
 * This function will return the 384-bit message digest into the Message_Digest array provided by the caller.
 *
 * @param sha The context to use to calculate the SHA hash.
 * @param Message_Digest Where the digest is returned.
 * @returns A libshare error code.
 * @note The first octet of hash is stored in the element with index 0. The last octet of hash in the element with index 47.
 */
int sh_sha384_result(sh_sha_t *sha, uint8_t *Message_Digest/*[SHA384HashSize]*/)
{
  sh_sha512_t *context;

  if (!sha) return SHERR_INVAL;
  context = &sha->ctx.sha512;

  return SHA384_512ResultN(context, Message_Digest, SHA384HashSize);
}

int sh_sha512_init(sh_sha_t *sha)
{
  sh_sha512_t *context;

  if (!sha) return SHERR_INVAL;

  memset(sha, '\000', sizeof(sha));
  sha->alg = SHALG_SHA512;
  context = &sha->ctx.sha512;

  return SHA384_512Reset(context, SHA512_H0);
}

int sh_sha512_write(sh_sha_t *sha, const uint8_t *message_array, unsigned int length)
{
  sh_sha512_t *context;

  if (!sha) return SHERR_INVAL;
  if (!length) return (0);
  if (!message_array) return SHERR_INVAL;

  context = &sha->ctx.sha512;
  if (context->Computed) return context->Corrupted = SHERR_INVAL;
  if (context->Corrupted) return context->Corrupted;

  while (length--) {
    context->Message_Block[context->Message_Block_Index++] =
      *message_array;

    if ((SHA384_512AddLength(context, 8) == 0) &&
        (context->Message_Block_Index == SHA512_Message_Block_Size))
      SHA384_512ProcessMessageBlock(context);

    message_array++;
  }

  return context->Corrupted;
}

int sh_sha512_result(sh_sha_t *sha, uint8_t *Message_Digest/*[SHA512HashSize]*/)
{
  sh_sha512_t *context;

  if (!sha) return (SHERR_INVAL);
  context = &sha->ctx.sha512;

  return SHA384_512ResultN(context, Message_Digest, SHA512HashSize);
}

void sh_sha512(const unsigned char *message, unsigned int len, unsigned char *digest)
{
  sh_sha_t ctx;

  sh_sha512_init(&ctx);
  sh_sha512_write(&ctx, message, len);
  sh_sha512_result(&ctx, digest);
}

size_t shsha_size(int alg)
{
  if (alg & SHALG_128BIT) {
    return (20);
  } else if (alg & SHALG_224BIT) {
    return (28);
  } else if (alg & SHALG_256BIT) {
    return (32);
  } else if (alg & SHALG_384BIT) {
    return (48);
  } else if (alg & SHALG_512BIT) {
    return (64);
  }

  return (0);
}

size_t shsha_blocksize(int alg)
{
  if (alg & SHALG_128BIT) {
    return (64);
  } else if (alg & SHALG_224BIT) {
    return (64);
  } else if (alg & SHALG_256BIT) {
    return (64);
  } else if (alg & SHALG_384BIT) {
    return (128);
  } else if (alg & SHALG_512BIT) {
    return (128);
  }

  return (0);
}

int shsha(int alg, unsigned char *ret_bin, unsigned char *data, size_t data_len)
{
  sh_sha_t ctx;
  int err;

  if (!(alg & SHALG_SHA))
    return (SHERR_INVAL);

  err = shsha_init(&ctx, alg);
  if (err)
    return (err);

  err = shsha_write(&ctx, data, data_len);
  if (err)
    return (err);

  err = shsha_result(&ctx, ret_bin); 
  if (err)
    return (err);

  return (0);
}

int shsha_hex(int alg, unsigned char *ret_digest, unsigned char *data, size_t data_len)
{
  char ret_buf[512];
  char *hex;
  int err;

  err = shsha(alg, ret_buf, data, data_len);
  if (err)
    return (err);

  *ret_digest = '\000';
  hex = shalg_encode(SHFMT_HEX, ret_buf, shsha_size(alg)); 
  if (hex)
    strcpy(ret_digest, hex);

  return (0);
}

int shsha_init(sh_sha_t *ctx, int alg)
{

  if (alg & SHALG_512BIT)
    return (sh_sha512_init(ctx));
  if (alg & SHALG_384BIT)
    return (sh_sha384_init(ctx));
  if (alg & SHALG_256BIT)
    return (sh_sha256_init(ctx));
  if (alg & SHALG_224BIT)
    return (sh_sha224_init(ctx));
  if (alg & SHALG_128BIT)
    return (sh_sha1_init(ctx));


  return (SHERR_OPNOTSUPP);
}

int shsha_write(sh_sha_t *ctx, unsigned char *data, size_t data_len)
{

  if (ctx->alg & SHALG_512BIT)
    return (sh_sha512_write(ctx, data, data_len));
  if (ctx->alg & SHALG_384BIT)
    return (sh_sha384_write(ctx, data, data_len));
  if (ctx->alg & SHALG_256BIT)
    return (sh_sha256_write(ctx, data, data_len));
  if (ctx->alg & SHALG_224BIT)
    return (sh_sha224_write(ctx, data, data_len));
  if (ctx->alg & SHALG_128BIT)
    return (sh_sha1_write(ctx, data, data_len));

  return (SHERR_OPNOTSUPP);
}

int shsha_result(sh_sha_t *ctx, unsigned char *ret_bin)
{

  if (ctx->alg & SHALG_512BIT)
    return (sh_sha512_result(ctx, ret_bin));
  if (ctx->alg & SHALG_384BIT)
    return (sh_sha384_result(ctx, ret_bin));
  if (ctx->alg & SHALG_256BIT)
    return (sh_sha256_result(ctx, ret_bin));
  if (ctx->alg & SHALG_224BIT)
    return (sh_sha224_result(ctx, ret_bin));
  if (ctx->alg & SHALG_128BIT)
    return (sh_sha1_result(ctx, ret_bin));

  return (0);
}

int shhmac(int alg, unsigned char *key, size_t key_len, const unsigned char *message_array, int length, unsigned char *digest)
{
  sh_hmac_t context;
  int err;

  err = shhmac_init(&context, alg, key, key_len);
  if (err)
    return (err);

  err = shhmac_write(&context, message_array, length);
  if (err)
    return (err);

  err = shhmac_result(&context, digest); 
  if (err)
    return (err);

  return (0);
}

int shhmac_init(sh_hmac_t *context, int alg, unsigned char *key, int key_len)
{
  int i, blocksize, hashsize, ret;
  unsigned char k_ipad[USHA_Max_Message_Block_Size];
  unsigned char tempkey[USHAMaxHashSize];

  if (!context) return SHERR_INVAL;

  memset(context, '\000', sizeof(sh_hmac_t));

  blocksize = context->blockSize = shsha_blocksize(alg);
  hashsize = context->hashSize = shsha_size(alg);
  context->alg = alg;

  /*
   * If key is longer than the hash blocksize,
   * reset it to key = HASH(key).
   */
  if (key_len > blocksize) {
    sh_sha_t tcontext;

    int err = shsha_init(&tcontext, alg) ||
      shsha_write(&tcontext, key, key_len) ||
      shsha_result(&tcontext, tempkey);
    if (err != 0) return err;

    key = tempkey;
    key_len = hashsize;
  }

  /*
   * The HMAC transform looks like:
   *
   * SHA(K XOR opad, SHA(K XOR ipad, text))
   *
   * where K is an n byte key, 0-padded to a total of blocksize bytes,
   * ipad is the byte 0x36 repeated blocksize times,
   * opad is the byte 0x5c repeated blocksize times,
   * and text is the data being protected.
   */

  /* store key into the pads, XOR'd with ipad and opad values */
  for (i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ 0x36;
    context->k_opad[i] = key[i] ^ 0x5c;
  }
  /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
  for ( ; i < blocksize; i++) {
    k_ipad[i] = 0x36;
    context->k_opad[i] = 0x5c;
  }

  /* perform inner hash */
  /* init context for 1st pass */
  ret = shsha_init(&context->shaContext, alg);
  if (ret) {
    context->Corrupted = ret;
    return (ret);
  }

  /* and start with inner pad */
  ret = shsha_write(&context->shaContext, k_ipad, blocksize);
  if (ret) {
    context->Corrupted = ret;
    return (ret);
  }

  return (0);
}

int shhmac_write(sh_hmac_t *context, const unsigned char *text, int text_len)
{
  if (!context) return SHERR_INVAL;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = SHERR_INVAL;
  /* then text of datagram */
  return context->Corrupted =
    shsha_write(&context->shaContext, text, text_len);
}

int shhmac_result(sh_hmac_t *context, uint8_t *digest)
{
  int ret;
  if (!context) return SHERR_INVAL;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = SHERR_INVAL;

  /* finish up 1st pass */
  /* (Use digest here as a temporary buffer.) */
  ret = shsha_result(&context->shaContext, digest) ||
    /* perform outer SHA */
    /* init context for 2nd pass */
    shsha_init(&context->shaContext, context->alg) ||
    /* start with outer pad */
    shsha_write(&context->shaContext, context->k_opad,
        context->blockSize) ||
    /* then results of 1st hash */
    shsha_write(&context->shaContext, digest, context->hashSize) ||
    /* finish up 2nd pass */
    shsha_result(&context->shaContext, digest);

  context->Computed = 1;
  return context->Corrupted = ret;
}

int shhkdf(int alg, unsigned char *salt, int salt_len, unsigned char *ikm, int ikm_len, unsigned char *info, int info_len, uint8_t *okm, int okm_len)
{
  uint8_t prk[USHAMaxHashSize];
  return shhkdf_extract(alg, salt, salt_len, ikm, ikm_len, prk) ||
    shhkdf_expand(alg, prk, shsha_size(alg), info,
        info_len, okm, okm_len);
}

int shhkdf_extract(int alg, unsigned char *salt, int salt_len, unsigned char *ikm, int ikm_len, uint8_t *prk/*[USHAMaxHashSize]*/)
{
  unsigned char nullSalt[USHAMaxHashSize];

  if (salt == 0) {
    salt = nullSalt;
    salt_len = shsha_size(alg);
    memset(nullSalt, '\0', salt_len);
  } else if (salt_len < 0) {
    return SHERR_INVAL;
  }

  return shhmac(alg, ikm, ikm_len, salt, salt_len, prk);
}

int shhkdf_expand(int alg, uint8_t *prk, int prk_len, unsigned char *info, int info_len, uint8_t *okm, int okm_len)
{
  static const unsigned char *blank_string = "";
  int hash_len, N;
  unsigned char T[USHAMaxHashSize];
  int Tlen, where, i;

  if (info == 0) {
    info = (unsigned char *)blank_string;
    info_len = 0;
  } else if (info_len < 0) {
    return SHERR_INVAL;
  }
  if (okm_len <= 0) return SHERR_INVAL;
  if (!okm) return SHERR_INVAL;

  hash_len = shsha_size(alg);
  if (prk_len < hash_len) return SHERR_INVAL;
  N = okm_len / hash_len;
  if ((okm_len % hash_len) != 0) N++;
  if (N > 255) return SHERR_INVAL;

  Tlen = 0;
  where = 0;
  for (i = 1; i <= N; i++) {
    sh_hmac_t context;
    unsigned char c = i;
    int ret = shhmac_init(&context, alg, prk, prk_len) ||
      shhmac_write(&context, T, Tlen) ||
      shhmac_write(&context, info, info_len) ||
      shhmac_write(&context, &c, 1) ||
      shhmac_result(&context, T);
    if (ret != 0) return ret;
    memcpy(okm + where, T,
        (i != N) ? hash_len : (okm_len - where));
    where += hash_len;
    Tlen = hash_len;
  }

  return (0);
}

int shhkdf_init(sh_hkdf_t *context, int alg, unsigned char *salt, int salt_len)
{
  unsigned char nullSalt[USHAMaxHashSize];
  if (!context) return SHERR_INVAL;

  context->alg = alg;
  context->hashSize = shsha_size(alg);
  if (salt == 0) {
    salt = nullSalt;
    salt_len = context->hashSize;
    memset(nullSalt, '\0', salt_len);
  }

  return shhmac_init(&context->hmacContext, alg, salt, salt_len);
}

int shhkdf_write(sh_hkdf_t *context, unsigned char *ikm, int ikm_len)
{
  if (!context) return SHERR_INVAL;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = SHERR_INVAL;
  return shhmac_write(&context->hmacContext, ikm, ikm_len);
}

int shhkdf_result(sh_hkdf_t *context, uint8_t *prk/*[USHAMaxHashSize]*/, unsigned char *info, int info_len, uint8_t *okm, int okm_len)
{
  uint8_t prkbuf[USHAMaxHashSize];
  int ret;

  if (!context) return SHERR_INVAL;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = SHERR_INVAL;
  if (!okm) return context->Corrupted = SHERR_INVAL;
  if (!prk) prk = prkbuf;

  ret = shhmac_result(&context->hmacContext, prk) ||
    shhkdf_expand(context->alg, prk,
        context->hashSize, info, info_len, okm, okm_len);
  context->Computed = 1;
  return context->Corrupted = ret;
}



uint32_t shsha_2fa_bin(int alg, unsigned char *secret, size_t secret_len, int freq)
{
  unsigned char hash[256];
  uint64_t t_be;
  uint64_t t;
  uint32_t hash32;
  int of;

  if (!secret)
    return (0);

  t = (uint64_t)(time(NULL) / freq);
  t_be = htonll(t);

  shhmac(alg, secret, secret_len, (unsigned char *)&t_be, sizeof(t_be), hash);
  
  of = (int)hash[19] & 0xf;
  hash32 = *((uint32_t *)(hash + of));
  hash32 = ntohl(hash32);
  //hash32 = hash32 % PIN_MODULO;
 
  if (secret_len <= 16) {  
    hash32 = hash32 % PIN_2FA_MODULO(secret_len);
  }

  return (hash32);
}

uint32_t shsha_2fa(char *secret_str)
{
  unsigned char secret[128];
  uint32_t ret_hash;
  size_t secret_len;

  if (!secret_str || strlen(secret_str) != 16)
    return (0);

  secret_len = SECRET_2FA_SIZE; 
  (void)shbase32_decode(secret_str, 16, secret, &secret_len);
  return (shsha_2fa_bin(SHALG_SHA1, secret, SECRET_2FA_SIZE, 30));
}

#if 0
uint32_t shsha_2fa(char *secret_str)
{
  const int alg = SHALG_SHA1;
  unsigned char hash[256];
  unsigned char secret[128];
  uint64_t t_be;
  uint64_t t;
  uint32_t hash32;
  size_t secret_len;
  int of;

  if (!secret_str)
    return (0);
  if (strlen(secret_str) != 16)
    return (0);

  secret_len = SECRET_2FA_SIZE; 
  (void)shbase32_decode(secret_str, 16, secret, &secret_len);

  t = (uint64_t)(time(NULL) / 30);
  t_be = htonll(t);

  secret_len = SECRET_2FA_SIZE; 
  shhmac(alg, secret, secret_len, (unsigned char *)&t_be, sizeof(t_be), hash);
  
  of = (int)hash[19] & 0xf;
  hash32 = *((uint32_t *)(hash + of));
  hash32 = ntohl(hash32);
  hash32 = hash32 % PIN_MODULO;

  return (hash32);
}
#endif

int shsha_2fa_bin_verify(int alg, unsigned char *secret, size_t secret_len, int freq, uint32_t pin)
{
  unsigned char hash[256];
  uint64_t t_st;
  uint64_t t_end;
  uint64_t t_be;
  uint64_t t;
  uint32_t hash32;
  int err;
  int of;

  if (!secret)
    return (SHERR_INVAL);

  t_st = (uint64_t)(time(NULL) / freq) - 1;
  t_end = t_st + 2;
  for (t = t_st; t <= t_end; t++) {
    t_be = htonll(t);

    shhmac(alg, secret, secret_len, (unsigned char *)&t_be, sizeof(t_be), hash);
    
    of = (int)hash[19] & 0xf;
    hash32 = *((uint32_t *)(hash + of));
    hash32 = ntohl(hash32);
    //hash32 = hash32 % PIN_MODULO;

    if (secret_len <= 16) {  
      hash32 = hash32 % PIN_2FA_MODULO(secret_len);
    }
    
    if (hash32 == pin)
      return (0); 
  }

  return (SHERR_ACCESS);
}

int shsha_2fa_verify(char *secret_str, uint32_t pin)
{
  unsigned char secret[128];
  size_t secret_len;
  int err;

  secret_len = SECRET_2FA_SIZE;
  (void)shbase32_decode(secret_str, 16, secret, &secret_len);
  err = shsha_2fa_bin_verify(SHALG_SHA1, secret, SECRET_2FA_SIZE, 30, pin); 
  if (err)
    return (err);

  return (0);
}


#if 0
/**
 * @returns A libshare error code.
 */
int shsha_2fa_verify(char *secret_str, uint32_t pin)
{
  const int alg = SHALG_SHA1;
  unsigned char hash[256];
  unsigned char secret[128];
  uint64_t t_st;
  uint64_t t_end;
  uint64_t t_be;
  uint64_t t;
  uint32_t hash32;
  size_t secret_len;
  int err;
  int of;

  if (!secret_str)
    return (SHERR_INVAL);
  if (strlen(secret_str) != 16)
    return (SHERR_INVAL);

  secret_len = SECRET_2FA_SIZE; Y
  (void)shbase32_decode(secret_str, 16, secret, &secret_len);

  t_st = (uint64_t)(time(NULL) / 30) - 1;
  t_end = t_st + 2;
  secret_len = SECRET_2FA_SIZE; 
  for (t = t_st; t <= t_end; t++) {
    t_be = htonll(t);

    shhmac(alg, secret, secret_len, (unsigned char *)&t_be, sizeof(t_be), hash);
    
    of = (int)hash[19] & 0xf;
    hash32 = *((uint32_t *)(hash + of));
    hash32 = ntohl(hash32);
    hash32 = hash32 % PIN_MODULO;
    
    if (hash32 == pin)
      return (0); 
  }

  return (SHERR_ACCESS);
}
#endif
 
void shsha_2fa_secret_bin(unsigned char *secret, size_t secret_len)
{
  size_t len;
  size_t of;
  uint64_t val;
  int i;

  memset(secret, 0, secret_len);

  secret_len /= 8;
  for (i = 0; i < secret_len; i++) {
    of = (i * sizeof(uint64_t));

    val = shrand();
    len = MIN(sizeof(uint64_t), secret_len - of);
    memcpy(secret + of, &val, len);
  }

}

char *shsha_2fa_secret(void)
{
  static unsigned char ret_str[64];
  unsigned char secret[16];

  shsha_2fa_secret_bin(secret, SECRET_2FA_SIZE);

  memset(ret_str, 0, sizeof(ret_str));
  (void)shbase32_encode(secret, SECRET_2FA_SIZE, ret_str, 16);

  return (ret_str);
}

#if 0
char *shsha_2fa_secret(void)
{
  static unsigned char ret_str[64];
  unsigned char secret[16];
  uint64_t *v;

  memset(ret_str, 0, sizeof(ret_str));

  memset(secret, 0, sizeof(secret));
  v = (uint64_t *)secret;  

  v[0] = shrand();
  v[1] = shrand();
  (void)shbase32_encode(secret, SECRET_2FA_SIZE, ret_str, 16);

  return (ret_str);
}
#endif








#define TEST_1 "abc"
#define TEST_2 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
#define TEST_3 "01234567"
#define TEST_4 "Sample #1"
#define TEST_5 "Sample #2"
#define TEST_6 "Sample #3"
#define TEST_7 "Sample #4"
static uint8_t hmacKey1[]={
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
  0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
};
static uint8_t hmacKey2[]={
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
  0x40,0x41,0x42,0x43
};
static uint8_t hmacKey3[]={
  0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
  0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
  0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,
  0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
  0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
  0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
  0xb0,0xb1,0xb2,0xb3
};
static uint8_t hmacKey4[]={
  0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,
  0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
  0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
  0xa0
};
_TEST(sha1)
{
  sh_sha_t s;
  unsigned char raw[1024];
  char buf[512];
  uint32_t a;

  memset(buf, 0, sizeof(buf));
  shsha_hex(SHALG_SHA1, buf, TEST_1, strlen(TEST_1));
  _TRUE(0 == strcmp(buf, "a9993e364706816aba3e25717850c26c9cd0d89d"));

  memset(buf, 0, sizeof(buf));
  shsha_hex(SHALG_SHA1, buf, TEST_2, strlen(TEST_2)); 
  _TRUE(0 == strcmp(buf, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"));

  memset(buf, 0, sizeof(buf));
  shsha_init(&s, SHALG_SHA1);
  for (a=0; a<80; a++) sh_sha1_write(&s, TEST_3, strlen(TEST_3));
  shsha_result(&s, raw);
  _TRUE(0 == strcmp(shalg_encode(SHFMT_HEX, raw, 20), 
        "dea356a2cddd90c7a7ecedc5ebb563934f460452"));

  memset(raw, 0, sizeof(raw));
  shhmac(SHALG_SHA1, hmacKey1, 64, TEST_4, strlen(TEST_4), raw);
  _TRUE(0 == strcmp(shalg_encode(SHFMT_HEX, raw, 20),
        "4f4ca3d5d68ba7cc0a1208c9c61e9c5da0403c0a"));

  shhmac(SHALG_SHA1, hmacKey2, 20, TEST_5, strlen(TEST_5), raw);
  _TRUE(0 == strcmp(shalg_encode(SHFMT_HEX, raw, 20),
        "0922d3405faa3d194f82a45830737d5cc6c75d24"));

  shhmac(SHALG_SHA1, hmacKey3, 100, TEST_6, strlen(TEST_6), raw);
  _TRUE(0 == strcmp(shalg_encode(SHFMT_HEX, raw, 20),
        "bcf41eab8bb2d802f3d05caf7cb092ecf8d1a3aa"));

  shhmac(SHALG_SHA1, hmacKey4, 49, TEST_7, strlen(TEST_7), raw);
  _TRUE(0 == strcmp(shalg_encode(SHFMT_HEX, raw, 20),
        "9ea886efe268dbecce420c7524df32e0751a2a26"));

}



_TEST(shsha_2fa)
{
  char *secret;
  uint32_t pin;
  int err;

  secret = shsha_2fa_secret();
  _TRUEPTR(secret);

  pin = shsha_2fa(secret);
  _TRUE(pin != 0);

  err = shsha_2fa_verify(secret, pin);
  _TRUE(err == 0);

}
