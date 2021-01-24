

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

#define __MEM__SHMEM_SCRYPT_GEN_C__
#include "share.h"
#include "shmem_scrypt_gen.h"

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)	((x & (y ^ z)) ^ z)
#define Maj(x, y, z)	((x & (y | z)) | (y & z))
#define SHR(x, n)	(x >> n)
#define ROTR(x, n)	((x >> n) | (x << (32 - n)))
#define S0(x)		(ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)		(ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)		(ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)		(ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k)			\
	t0 = h + S1(e) + Ch(e, f, g) + k;		\
	t1 = S0(a) + Maj(a, b, c);			\
	d += t0;					\
	h  = t0 + t1;

/* Adjusted round function for rotating state */
#define RNDr(S, W, i, k)			\
	RND(S[(64 - i) % 8], S[(65 - i) % 8],	\
	    S[(66 - i) % 8], S[(67 - i) % 8],	\
	    S[(68 - i) % 8], S[(69 - i) % 8],	\
	    S[(70 - i) % 8], S[(71 - i) % 8],	\
	    W[i] + k)


#ifdef WORDS_BIGENDIAN
#  define swap32tobe(out, in, sz)  ((out == in) ? (void)0 : memmove(out, in, sz))
#  define LOCAL_swap32be(type, var, sz)  ;
#  define swap32tole(out, in, sz)  swap32yes(out, in, sz)
#  define LOCAL_swap32le(type, var, sz)  LOCAL_swap32(type, var, sz)
#else
#  define swap32tobe(out, in, sz)  swap32yes(out, in, sz)
#  define LOCAL_swap32be(type, var, sz)  LOCAL_swap32(type, var, sz)
#  define swap32tole(out, in, sz)  ((out == in) ? (void)0 : memmove(out, in, sz))
#  define LOCAL_swap32le(type, var, sz)  ;
#endif

#define TNR_BAD -1
#define TNR_GOOD 1
#define TNR_HIGH 0

/* 131583 rounded up to 4 byte alignment */
#define SCRATCHBUF_SIZE	(131584)

typedef struct SHA256_CTX {
	uint32_t state[8];
	uint32_t buf[16];
} SHA256_CTX;


static const uint32_t hash1_init[] = {
        0,0,0,0,0,0,0,0,
        0x80000000,
          0,0,0,0,0,0,
                  0x100,
};


/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static inline void
be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		dst[i] = htobe32(src[i]);
}


/*
 * SHA256 block compression function.  The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
static void
SHA256_Transform(uint32_t * state, const uint32_t block[16], int swap)
{
	uint32_t W[64];
	uint32_t S[8];
	uint32_t t0, t1;
	int i;

	/* 1. Prepare message schedule W. */
	if(swap)
		for (i = 0; i < 16; i++)
			W[i] = htobe32(block[i]);
	else
		memcpy(W, block, 64);
	for (i = 16; i < 64; i += 2) {
		W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
		W[i+1] = s1(W[i - 1]) + W[i - 6] + s0(W[i - 14]) + W[i - 15];
	}

	/* 2. Initialize working variables. */
	memcpy(S, state, 32);

	/* 3. Mix. */
	RNDr(S, W, 0, 0x428a2f98);
	RNDr(S, W, 1, 0x71374491);
	RNDr(S, W, 2, 0xb5c0fbcf);
	RNDr(S, W, 3, 0xe9b5dba5);
	RNDr(S, W, 4, 0x3956c25b);
	RNDr(S, W, 5, 0x59f111f1);
	RNDr(S, W, 6, 0x923f82a4);
	RNDr(S, W, 7, 0xab1c5ed5);
	RNDr(S, W, 8, 0xd807aa98);
	RNDr(S, W, 9, 0x12835b01);
	RNDr(S, W, 10, 0x243185be);
	RNDr(S, W, 11, 0x550c7dc3);
	RNDr(S, W, 12, 0x72be5d74);
	RNDr(S, W, 13, 0x80deb1fe);
	RNDr(S, W, 14, 0x9bdc06a7);
	RNDr(S, W, 15, 0xc19bf174);
	RNDr(S, W, 16, 0xe49b69c1);
	RNDr(S, W, 17, 0xefbe4786);
	RNDr(S, W, 18, 0x0fc19dc6);
	RNDr(S, W, 19, 0x240ca1cc);
	RNDr(S, W, 20, 0x2de92c6f);
	RNDr(S, W, 21, 0x4a7484aa);
	RNDr(S, W, 22, 0x5cb0a9dc);
	RNDr(S, W, 23, 0x76f988da);
	RNDr(S, W, 24, 0x983e5152);
	RNDr(S, W, 25, 0xa831c66d);
	RNDr(S, W, 26, 0xb00327c8);
	RNDr(S, W, 27, 0xbf597fc7);
	RNDr(S, W, 28, 0xc6e00bf3);
	RNDr(S, W, 29, 0xd5a79147);
	RNDr(S, W, 30, 0x06ca6351);
	RNDr(S, W, 31, 0x14292967);
	RNDr(S, W, 32, 0x27b70a85);
	RNDr(S, W, 33, 0x2e1b2138);
	RNDr(S, W, 34, 0x4d2c6dfc);
	RNDr(S, W, 35, 0x53380d13);
	RNDr(S, W, 36, 0x650a7354);
	RNDr(S, W, 37, 0x766a0abb);
	RNDr(S, W, 38, 0x81c2c92e);
	RNDr(S, W, 39, 0x92722c85);
	RNDr(S, W, 40, 0xa2bfe8a1);
	RNDr(S, W, 41, 0xa81a664b);
	RNDr(S, W, 42, 0xc24b8b70);
	RNDr(S, W, 43, 0xc76c51a3);
	RNDr(S, W, 44, 0xd192e819);
	RNDr(S, W, 45, 0xd6990624);
	RNDr(S, W, 46, 0xf40e3585);
	RNDr(S, W, 47, 0x106aa070);
	RNDr(S, W, 48, 0x19a4c116);
	RNDr(S, W, 49, 0x1e376c08);
	RNDr(S, W, 50, 0x2748774c);
	RNDr(S, W, 51, 0x34b0bcb5);
	RNDr(S, W, 52, 0x391c0cb3);
	RNDr(S, W, 53, 0x4ed8aa4a);
	RNDr(S, W, 54, 0x5b9cca4f);
	RNDr(S, W, 55, 0x682e6ff3);
	RNDr(S, W, 56, 0x748f82ee);
	RNDr(S, W, 57, 0x78a5636f);
	RNDr(S, W, 58, 0x84c87814);
	RNDr(S, W, 59, 0x8cc70208);
	RNDr(S, W, 60, 0x90befffa);
	RNDr(S, W, 61, 0xa4506ceb);
	RNDr(S, W, 62, 0xbef9a3f7);
	RNDr(S, W, 63, 0xc67178f2);

	/* 4. Mix local working variables into global state */
	for (i = 0; i < 8; i++)
		state[i] += S[i];
}

static inline void
SHA256_InitState(uint32_t * state)
{
	/* Magic initialization constants */
	state[0] = 0x6A09E667;
	state[1] = 0xBB67AE85;
	state[2] = 0x3C6EF372;
	state[3] = 0xA54FF53A;
	state[4] = 0x510E527F;
	state[5] = 0x9B05688C;
	state[6] = 0x1F83D9AB;
	state[7] = 0x5BE0CD19;
}

static const uint32_t passwdpad[12] = {0x00000080, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80020000};
static const uint32_t outerpad[8] = {0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300};

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
static inline void
PBKDF2_SHA256_80_128(const uint32_t * passwd, uint32_t * buf)
{
	SHA256_CTX PShictx, PShoctx;
	uint32_t tstate[8];
	uint32_t ihash[8];
	uint32_t i;
	uint32_t pad[16];
	
	static const uint32_t innerpad[11] = {0x00000080, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa0040000};

  for (i = 0; i < 8; i++)
    ihash[i] = 0;
  for (i = 0; i < 8; i++)
    tstate[i] = 0;
  for (i = 0; i < 16; i++)
    pad[i] = 0;

	/* If Klen > 64, the key is really SHA256(K). */
	SHA256_InitState(tstate);
	SHA256_Transform(tstate, passwd, 1);
	memcpy(pad, passwd+16, 16);
	memcpy(pad+4, passwdpad, 48);
	SHA256_Transform(tstate, pad, 1);
	memcpy(ihash, tstate, 32);

	SHA256_InitState(PShictx.state);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 16; i++)
		pad[i] = 0x36363636;
	SHA256_Transform(PShictx.state, pad, 0);
	SHA256_Transform(PShictx.state, passwd, 1);
	be32enc_vect(PShictx.buf, passwd+16, 4);
	be32enc_vect(PShictx.buf+5, innerpad, 11);

	SHA256_InitState(PShoctx.state);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 16; i++)
		pad[i] = 0x5c5c5c5c;
	SHA256_Transform(PShoctx.state, pad, 0);
	memcpy(PShoctx.buf+8, outerpad, 32);

	/* Iterate through the blocks. */
	for (i = 0; i < 4; i++) {
		uint32_t istate[8];
		uint32_t ostate[8];
		
		memcpy(istate, PShictx.state, 32);
		PShictx.buf[4] = i + 1;
		SHA256_Transform(istate, PShictx.buf, 0);
		memcpy(PShoctx.buf, istate, 32);

		memcpy(ostate, PShoctx.state, 32);
		SHA256_Transform(ostate, PShoctx.buf, 0);
		be32enc_vect(buf+i*8, ostate, 8);
	}
}


static inline void
PBKDF2_SHA256_80_128_32(const uint32_t * passwd, const uint32_t * salt, uint32_t *ostate)
{
	uint32_t tstate[8];
	uint32_t ihash[8];
	uint32_t i;

	/* Compute HMAC state after processing P and S. */
	uint32_t pad[16];
	
	static const uint32_t ihash_finalblk[16] = {0x00000001,0x80000000,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x00000620};

	/* If Klen > 64, the key is really SHA256(K). */
	SHA256_InitState(tstate);
	SHA256_Transform(tstate, passwd, 1);
	memcpy(pad, passwd+16, 16);
	memcpy(pad+4, passwdpad, 48);
	SHA256_Transform(tstate, pad, 1);
	memcpy(ihash, tstate, 32);

	SHA256_InitState(ostate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 16; i++)
		pad[i] = 0x5c5c5c5c;
	SHA256_Transform(ostate, pad, 0);

	SHA256_InitState(tstate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 16; i++)
		pad[i] = 0x36363636;
	SHA256_Transform(tstate, pad, 0);
	SHA256_Transform(tstate, salt, 1);
	SHA256_Transform(tstate, salt+16, 1);
	SHA256_Transform(tstate, ihash_finalblk, 0);
	memcpy(pad, tstate, 32);
	memcpy(pad+8, outerpad, 32);

	/* Feed the inner hash to the outer SHA256 operation. */
	SHA256_Transform(ostate, pad, 0);
}


/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
static inline void
salsa20_8(uint32_t B[16], const uint32_t Bx[16])
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	size_t i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x04 ^= R(x00+x12, 7);	x09 ^= R(x05+x01, 7);	x14 ^= R(x10+x06, 7);	x03 ^= R(x15+x11, 7);
		x08 ^= R(x04+x00, 9);	x13 ^= R(x09+x05, 9);	x02 ^= R(x14+x10, 9);	x07 ^= R(x03+x15, 9);
		x12 ^= R(x08+x04,13);	x01 ^= R(x13+x09,13);	x06 ^= R(x02+x14,13);	x11 ^= R(x07+x03,13);
		x00 ^= R(x12+x08,18);	x05 ^= R(x01+x13,18);	x10 ^= R(x06+x02,18);	x15 ^= R(x11+x07,18);

		/* Operate on rows. */
		x01 ^= R(x00+x03, 7);	x06 ^= R(x05+x04, 7);	x11 ^= R(x10+x09, 7);	x12 ^= R(x15+x14, 7);
		x02 ^= R(x01+x00, 9);	x07 ^= R(x06+x05, 9);	x08 ^= R(x11+x10, 9);	x13 ^= R(x12+x15, 9);
		x03 ^= R(x02+x01,13);	x04 ^= R(x07+x06,13);	x09 ^= R(x08+x11,13);	x14 ^= R(x13+x12,13);
		x00 ^= R(x03+x02,18);	x05 ^= R(x04+x07,18);	x10 ^= R(x09+x08,18);	x15 ^= R(x14+x13,18);
#undef R
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

/* cpu and memory intensive function to transform a 80 byte buffer into a 32 byte output
   scratchpad size needs to be at least 63 + (128 * r * p) + (256 * r + 64) + (128 * r * N) bytes
 */
static void scrypt_1024_1_1_256_sp(const uint32_t* input, char* scratchpad, uint32_t *ostate)
{
	uint32_t * V;
	uint32_t X[64];
	uint32_t i;
	uint32_t j;
	uint32_t k;
	uint64_t *p1, *p2;

  for (i = 0; i < 64; i++)
    X[i] = 0;

memset(scratchpad, 0, SCRATCHBUF_SIZE);

	p1 = (uint64_t *)X;
	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	PBKDF2_SHA256_80_128(input, X);

	for (i = 0; i < 1024; i += 2) {
		memcpy(&V[i * 32], X, 128);

		salsa20_8(&X[0], &X[16]);
		salsa20_8(&X[16], &X[0]);

		memcpy(&V[(i + 1) * 32], X, 128);

		salsa20_8(&X[0], &X[16]);
		salsa20_8(&X[16], &X[0]);
	}
	for (i = 0; i < 1024; i += 2) {
		j = X[16] & 1023;
		p2 = (uint64_t *)(&V[j * 32]);
		for(k = 0; k < 16; k++)
			p1[k] ^=
 p2[k];

		salsa20_8(&X[0], &X[16]);
		salsa20_8(&X[16], &X[0]);

		j = X[16] & 1023;
		p2 = (uint64_t *)(&V[j * 32]);
		for(k = 0; k < 16; k++)
			p1[k] ^=
 p2[k];

		salsa20_8(&X[0], &X[16]);
		salsa20_8(&X[16], &X[0]);
	}

	PBKDF2_SHA256_80_128_32(input, X, ostate);
}


void scrypt_regenhash(struct scrypt_work *work)
{
	uint32_t data[20];
	char scratchbuf[SCRATCHBUF_SIZE];
	uint32_t *nonce = (uint32_t *)(work->data + 76);
	uint32_t *ohash = (uint32_t *)(work->hash);
int i;

  memset(scratchbuf, 0, sizeof(scratchbuf));
for (i = 0; i < 20; i++)
data[i] = 0;

	be32enc_vect(data, (const uint32_t *)work->data, 19);
	data[19] = htobe32(*nonce);
	scrypt_1024_1_1_256_sp(data, scratchbuf, ohash);
	flip32(ohash, ohash);

}

static const uint32_t diff1targ = 0x0000ffff;


/* Used externally as confirmation of correct OCL code */
int scrypt_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce)
{
  uint32_t tmp_hash7, Htarg = le32toh(((const uint32_t *)ptarget)[7]);
  uint32_t data[20], ohash[8];
  char scratchbuf[SCRATCHBUF_SIZE];
  char buf[256];
  int i;

  memset(scratchbuf, 0, SCRATCHBUF_SIZE);
  for (i = 0; i < 20; i++)
    data[i] = 0;
  for (i = 0; i < 8; i++)
    ohash[i] = 0;

  be32enc_vect(data, (const uint32_t *)pdata, 19);
  data[19] = htobe32(nonce);
  scrypt_1024_1_1_256_sp(data, scratchbuf, ohash);
  tmp_hash7 = be32toh(ohash[7]);

/*
  sprintf(buf, "scrypt_test [htarget %08lx, diff1 %08lx, hash %08lx, 1diff %f, nonce %u]\n", (long unsigned int)Htarg, (long unsigned int)diff1targ, (long unsigned int)tmp_hash7, ((double)diff1targ / (double)tmp_hash7), nonce);
  PRINT_RUSAGE(buf);
*/

#if 0
  if (tmp_hash7 > diff1targ)
    return -1;
#endif
  if (tmp_hash7 > Htarg)
    return 0;

  return 1;
}

bool scanhash_scrypt(const unsigned char *pmidstate, unsigned char *pdata, 
		     unsigned char *phash, const unsigned char *ptarget,
		     uint32_t max_nonce, uint32_t *last_nonce, uint32_t n,
         double *last_diff)
{
static const uint32_t diff1targ = 0x0000ffff;
	uint32_t *nonce = (uint32_t *)(pdata + 76);
	uint32_t data[20];
	uint32_t tmp_hash7;
	uint32_t Htarg = le32toh(((const uint32_t *)ptarget)[7]);
  uint32_t *ostate = (uint32_t *)phash;
  char scratchbuf[SCRATCHBUF_SIZE];
	int ret = 0;
  int i;

  *last_diff = 0;

  memset(scratchbuf, 0, SCRATCHBUF_SIZE);

  for (i = 0; i < 20; i++)
    data[i] = 0;
	be32enc_vect(data, (const uint32_t *)pdata, 19);

	while(1) {
    n++;
		*nonce = n;
		data[19] = htobe32(n);

		scrypt_1024_1_1_256_sp(data, scratchbuf, ostate);
		tmp_hash7 = be32toh(ostate[7]);

    if (tmp_hash7 <=
        Htarg) {
      ((uint32_t *)pdata)[19] = htobe32(n);
      flip32 (ostate, ostate);

			*last_nonce = n;
			*last_diff = ((double)diff1targ / (double)tmp_hash7);
      ret = true;
      break;
		}

		if ((n >= max_nonce)/* || thr->work_restart*/) {
			*last_nonce = n;
			break;
		}
	}

	return ret;
}

extern void bin2hex(char *out, const void *in, size_t len);

#if 0
static const char _hexchars[0x10] = "0123456789abcdef";
void bin2hex(char *out, const void *in, size_t len)
{
        const unsigned char *p = in;
        while (len--)
        {
                (out++)[0] = _hexchars[p[0] >> 4];
                (out++)[0] = _hexchars[p[0] & 0xf];
                ++p;
        }
        out[0] = '\0';
}
#endif


void gen_hash(unsigned char *data, unsigned char *hash, int len)
{
        unsigned char hash1[32];

        sh_sha256(data, len, hash1);
        sh_sha256(hash1, 32, hash);
}



static void suffix_string(uint64_t val, char *buf, size_t bufsiz, int sigdigits)
{
        const double  dkilo = 1000.0;
        const uint64_t kilo = 1000ull;
        const uint64_t mega = 1000000ull;
        const uint64_t giga = 1000000000ull;
        const uint64_t tera = 1000000000000ull;
        const uint64_t peta = 1000000000000000ull;
        const uint64_t exa  = 1000000000000000000ull;
        char suffix[2] = "";
        bool decimal = true;
        double dval;

        if (val >= exa) {
                val /= peta;
                dval = (double)val / dkilo;
                strcpy(suffix, "E");
        } else if (val >= peta) {
                val /= tera;
                dval = (double)val / dkilo;
                strcpy(suffix, "P");
        } else if (val >= tera) {
                val /= giga;
                dval = (double)val / dkilo;
                strcpy(suffix, "T");
        } else if (val >= giga) {
                val /= mega;
                dval = (double)val / dkilo;
                strcpy(suffix, "G");
        } else if (val >= mega) {
                val /= kilo;
                dval = (double)val / dkilo;
                strcpy(suffix, "M");
        } else if (val >= kilo) {
                dval = (double)val / dkilo;
                strcpy(suffix, "k");
        } else {
                dval = val;
                decimal = false;
        }
        if (!sigdigits) {
                if (decimal)
                        snprintf(buf, bufsiz, "%.3g%s", dval, suffix);
                else
                        snprintf(buf, bufsiz, "%d%s", (unsigned int)dval, suffix);
        } else {
                /* Always show sigdigits + 1, padded on right with zeroes
                 * followed by suffix */
                int ndigits = sigdigits - 1 - (dval > 0.0 ? floor(log10(dval)) : 0);

                snprintf(buf, bufsiz, "%*.*f%s", sigdigits + 1, ndigits, dval, suffix);
        }
}

/**
 * Last check before attempting to submit the work 
 * @note Side effect: sets work->data for us 
 */
bool scrypt_submit_nonce(struct scrypt_work *work_in, uint32_t nonce)
{
  int noffset = 0;
  struct scrypt_work work;
  struct timeval tv_work_found;
  int res;
  bool ret = true;

  memcpy(&work, work_in, sizeof(struct scrypt_work));

  res = test_nonce(&work, nonce);
  if (res == TNR_BAD) {
    PRINT_RUSAGE("submit nonce [TNR_BAD]");
    return (false);
  }
  if (res == TNR_HIGH) {
    PRINT_RUSAGE("submit nonce [TNR_HIGH]");
    return (false);
  }

  /* submit entire work block as output. */
//  shbuf_cat(work_in->buff, work.data, 80);

  return (true);
}


int64_t cpu_scanhash(struct scrypt_work *work, int64_t max_nonce)
{
  unsigned int first_nonce = work->nonce;
  unsigned int last_nonce = 0;
  double last_diff;
  //        unsigned char hash1[64];
  bool rc;


  //        memcpy(&hash1[0], &hash1_init[0], sizeof(hash1));


  memset(work->hash, 0, sizeof(work->hash));
  /* scan nonces for a proof-of-work hash */
  rc = scanhash_scrypt(
      work->midstate,
      work->data,
      work->hash,
      work->target,
      max_nonce,
      &last_nonce,
      work->nonce,
      &last_diff
      );

  /* if nonce found, submit work */
  if (rc) {
    bool ret = scrypt_submit_nonce(work, last_nonce);
    *(uint32_t *)&work->data[76] = le32toh(last_nonce);
    work->pool_diff = last_diff;
  }
  work->nonce = last_nonce;

  return (last_nonce - first_nonce);
}

/**
	* @note Depends on scrypt_test return matching enum values
	*/
int test_nonce(struct scrypt_work *work, uint32_t nonce)
{
  uint32_t *work_nonce = (uint32_t *) (work->data + 64 + 12);
  *work_nonce = htole32 (nonce);
  return scrypt_test (work->data, work->target, nonce);
}

