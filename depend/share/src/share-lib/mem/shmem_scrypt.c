

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

#define __MEM__SHMEM_SCRYPT_C__
#include "share.h"
#include "shmem_scrypt_gen.h"

static const char *version = "00000001"; /* block version 1 (usde) */
//static const char *version = "00000bb8"; /* 3000 */

static double DIFFEXACTONE = 26959946667150639794667015087019630673637144422540572481103610249215.0;
static const uint64_t diffone = 0xFFFF000000000000ull;

static const char *workpadding_bin = "\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\x02\0\0";

void shscrypt_swap256(void *dest_p, const void *src_p)
{
  uint32_t *dest = dest_p;
  const uint32_t *src = src_p;

  dest[0] = src[7];
  dest[1] = src[6];
  dest[2] = src[5];
  dest[3] = src[4];
  dest[4] = src[3];
  dest[5] = src[2];
  dest[6] = src[1];
  dest[7] = src[0];
}

static inline int _hex2bin_char(const char c)
{
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return (c - 'a') + 10;
        if (c >= 'A' && c <= 'F')
                return (c - 'A') + 10;
        return -1;
}

/* Does the reverse of bin2hex but does not allocate any ram */
bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
        int n, o;

        while (len--)
        {
                n = _hex2bin_char((hexstr++)[0]);
                if (n == -1)
                {
badchar:
                        if (!hexstr[-1])
                                fprintf(stderr, "DEBUG: hex2bin: str truncated\n");
                        else
                                fprintf(stderr, "DEBUG: hex2bin: invalid character 0x%02x\n", (int)hexstr[-1]);

                        return false;
                }
                o = _hex2bin_char((hexstr++)[0]);
                if (o == -1)
                        goto badchar;
                (p++)[0] = (n << 4) | o;
        }

        return (!hexstr[0]);
}

void bin2hex(char *str, unsigned char *bin, size_t bin_len)
{
  unsigned char val;
  unsigned int i;

  memset(str, 0, (bin_len * 2) + 1);
  for (i = 0; i < bin_len; i++) {
    val = (unsigned int)bin[i];
    sprintf(str + (i * 2), "%-2.2x", val); 
  } 

}

void shscrypt_peer_gen(scrypt_peer *peer, double diff)
{
  char nonce1[16];
  unsigned int xn1;

  /* generate unique key */
  xn1 = (unsigned int)shtime();

  memset(nonce1, 0, sizeof(nonce1));
  sprintf(nonce1, "%-8.8x", xn1);

  /* generate key and use for xnonce1. */
  shscrypt_peer(peer, nonce1, diff);
}

void shscrypt_peer(scrypt_peer *peer, char *nonce1, double diff)
{

  strncpy(peer->nonce1, nonce1, 8);
  peer->n1_len = 4;//strlen(peer->nonce1) / 2;
  peer->n2_len = 4;//8 - peer->n1_len; /* 4 (int) */

  peer->diff = diff; /* share difficulty */

}

static inline int _sh_timer_elapsed(struct timeval *begin_t, struct timeval *end_t)
{
  struct timeval now;
  if (!end_t) {
    gettimeofday(&now, NULL);
    return (now.tv_sec - begin_t->tv_sec);
  }
  return (end_t->tv_sec - begin_t->tv_sec);
}

/**
 * Diff 1 is a 256 bit unsigned integer of
 * 0x00000000ffff0000000000000000000000000000000000000000000000000000
 * so we use a big endian 64 bit unsigned integer centred on the 5th byte to
 * cover a huge range of difficulty targets, though not all 256 bits' worth 
 */
static void bdiff_target_leadzero(unsigned char *target, double diff)
{
  uint64_t *data64, h64;
  uint32_t *data32;
  unsigned char *rtarget = target;
  double d64;
  d64 = diffone;
  d64 /= diff;
  d64 = ceil(d64);
  h64 = d64;


  memset(target, 0, 32);
  memset(rtarget, 0, 32);
  if (d64 < 18446744073709551616.0) {
    data64 = (uint64_t *)(rtarget + 2);
    *data64 = htobe64(h64);
  } else {
    uint32_t frac_target = (double)65536 / diff;
    data32 = (uint32_t *)rtarget;
    *data32 = htobe32(frac_target);
    /* Support for the classic all FFs just-below-1 diff */
    memset(target+2, 0xff, 30);
  }
}

static void swab256(void *dest_p, const void *src_p)
{
  uint32_t *dest = dest_p;
  const uint32_t *src = src_p;

  dest[0] = swab32(src[7]);
  dest[1] = swab32(src[6]);
  dest[2] = swab32(src[5]);
  dest[3] = swab32(src[4]);
  dest[4] = swab32(src[3]);
  dest[5] = swab32(src[2]);
  dest[6] = swab32(src[1]);
  dest[7] = swab32(src[0]);
}

static void scrypt_set_target(unsigned char *dest_target, double diff)
{
  unsigned char rtarget[32];

  bdiff_target_leadzero(rtarget, diff);
  swab256(dest_target, rtarget);
}

#ifdef WORDS_BIGENDIAN
#  define swap32tole(out, in, sz)  swap32yes(out, in, sz)
#else
#  define swap32tole(out, in, sz)  ((out == in) ? (void)0 : memmove(out, in, sz))
#endif

void sh_calc_midstate(struct scrypt_work *work)
{
  sh_sha_t ctx;
  union {
    unsigned char c[64];
    uint32_t i[16];
  } data;

  swap32yes(&data.i[0], work->data, 16);
  sh_sha256_init(&ctx);
  sh_sha256_write(&ctx, data.c, 64);
  memcpy(work->midstate, ctx.ctx.sha1.Intermediate_Hash, sizeof(work->midstate));
  swap32tole(work->midstate, work->midstate, 8);
}



/*
administrativo@ltcmining1:~$ ./Litecoin/litecoin/src/litecoind getwork
{   
    "midstate" : "f2cfc038d83389f1e4e44eb67b4967f4e9c0352a9eb0cacb7cc01e04c84fa039",
    "data" : "00000001d8632caadf2260bf42d2067f60d987d6b790562b272653ae611ba0fa67fe1945e3c77cc0b144c2b408614956f4bdcff4ecf1c7f2818beb3e5c6cfd61083be20c4eb747fd1d019db000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000",
    "hash1" : "00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000",
    "target" : "0000000000000000000000000000000000000000000000000000b09d01000000"
}

~/litecoind getwork
{
    "midstate" : "40fd268321efcf60e625707d4e31f9deadd13157e228985de8a10a057b98ed4d",
    "data" : "0000000105e9a54b7f65b46864bc90f55d67cccd8b6404a02f5e064a6df69282adf6e2e5f7f953b0632b25b099858b717bb7b24084148cfa841a89f106bc6b655b18d2ed4ebb191a1d018ea700000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000",
    "hash1" : "00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000",
    "target" : "0000000000000000000000000000000000000000000000000000a78e01000000"
}
./netcoind getwork
{
    "midstate" : "86f4b9f4fa8f5cf5827fbc836d20d872d3ef4002453f501fc9e645ddde813834",
    "data" : "000000011328094d532943d9c65defebbbc86a121d3a08e430bd30d38580dd24a7bf6c597afc1fc1e11baf0770762963b01b77c004f40da8d8c695365ca6c381eb652645530e8a521c0f5e6f00000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000",
    "hash1" : "00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000",
    "target" : "000000000000000000000000000000000000000000000000006f5e0f00000000",
    "algorithm" : "scrypt:1024,1,1"
}

The data field is stored in big-endian format. We need to cover that to little-endian for each of the fields in the data because we can pass it to the hashing function.
Data is broken down to:
Version - 00000001 (4 bytes)
Previous hash - 05e9a54b7f65b46864bc90f55d67cccd8b6404a02f5e064a6df69282adf6e2e5 (32 bytes)
Merkle root - f7f953b0632b25b099858b717bb7b24084148cfa841a89f106bc6b655b18d2ed (32 bytes)
Timestamp - 4ebb191a (4 bytes)
Bits (target in compact form) - 1d018ea7 (4 bytes)
Nonce - 00000000 (4 bytes)
You need covert these from big-endian to little-endian. This is done 2 characters at a time because each byte is represented by 2 hex chars. (each hex char is 4 bits)
Version becomes 01000000
Previous hash becomes e5e2f6.....a5e905
Merkle root becomes edd218...53f9f7
Timestamp becomes 1a19bb4e
Bits becomes a78e011d
And Nonce is a 32-bit integer you choose that will make the scrypt hash be less than the target.
Remember that you will need to convert the 32-bit nonce to hex and little-endian also. So if you are trying the nonce 2504433986. The hex version is 9546a142 in big-endian and 42a14695 in little-endian.
You then concatenate these little-endian hex strings together to get the header string (80 bytes) you input into scrypt
01000000 e5e2f6.....a5e905 edd218...53f9f7 1a19bb4e a78e011d 42a14695
*/


/**
 * @param prev_hash a 64 character hex string.
 * @param nbit a 8 character (32bit) specifying the size of the underlying transaction list. 
 * @param ntime a 8 character (32bit) specifying when the tranaction initiated.
 * @param diff the degree of difficulty in generating the scrypt hash.
 * @param merkle_list string array of 64-char merkle root entries.
 * @param coinbase2 contains the hex of the block output (i.e. the pubkey hash which the address can be derived).
 */
void shscrypt_work(scrypt_peer *peer, scrypt_work *work, 
    char **merkle_list, char *prev_hash, 
    char *coinbase1, char *coinbase2, char *nbit, char *ntime)
{
  unsigned char coinbase[256], merkle_root[32], merkle_sha[64];
unsigned char hash_swap[32];
  //  uint8_t merkle_bin[32]; 
  char *merkle_bin;
  char *merkle_free;
char nonce_str[32];
  uint32_t *data32, *swap32;
  uint8_t diffbits[4];
  char cbuf[256];
  char merkle_buf[256];
  int cb1_len, cb2_len;
  int nonce2_offset;
  int merkle_cnt;
  int cb_len;
  int i;

  if (!coinbase1 || !*coinbase1)
    coinbase1 = "0000000000000000000000000000000000000000000000000000000000000000";
  if (!coinbase2 || !*coinbase2)
    coinbase2 = "0000000000000000000000000000000000000000000000000000000000000000";
  if (!prev_hash || !*prev_hash)
    prev_hash = "0000000000000000000000000000000000000000000000000000000000000000";

  work->restart = 0;

  work->sdiff = peer->diff;

  strncpy(work->ntime, ntime, sizeof(work->ntime) - 1);
  //work->ntime = be32toh(work->ntime);

  /* Generate coinbase */
  cb1_len = strlen(coinbase1) / 2;
  nonce2_offset = cb1_len + peer->n1_len;
  cb2_len = strlen(coinbase2) / 2;
  cb_len = nonce2_offset + peer->n2_len + cb2_len;
  memset(coinbase, 0, sizeof(coinbase));
  hex2bin(coinbase, coinbase1, cb1_len);
  hex2bin((coinbase + cb1_len), peer->nonce1, peer->n1_len);
  hex2bin((coinbase + nonce2_offset), work->xnonce2, peer->n2_len);
  hex2bin((coinbase + (nonce2_offset + peer->n2_len)), coinbase2, cb2_len);

#if 0
  fprintf(stderr, "DEBUG: shscrypt_work: cb1 \"%s\"\n", coinbase1);
  fprintf(stderr, "DEBUG: shscrypt_work: xnonce1 \"%s\"\n", peer->nonce1);
  fprintf(stderr, "DEBUG: shscrypt_work: xnonce2 \"%s\"\n", work->xnonce2);
  fprintf(stderr, "DEBUG: shscrypt_work: cb2 \"%s\"\n", coinbase2);
#endif

  merkle_cnt = 0;
  if (merkle_list)
    for (; merkle_list[merkle_cnt]; merkle_cnt++);

  merkle_bin = (char *)calloc((32 * (merkle_cnt+1)), sizeof(char));
  merkle_free = merkle_bin;
  for (i = 0; i < merkle_cnt; i++) {
    memset(merkle_buf, 0, sizeof(merkle_buf));
    memset(merkle_buf, '0', 64);
    strncpy(merkle_buf, merkle_list[i], strlen(merkle_list[i]));
    hex2bin(&merkle_bin[i * 32], merkle_buf, 32);
  }

  /* Generate merkle root 
     for (merkle_cnt = 0; merkle_list[merkle_cnt]; merkle_cnt++);
     merkle_bin = (char *)calloc((32 * (merkle_cnt+1)), sizeof(char));
     merkle_free = merkle_bin;
     for (i = 0; i < merkle_cnt; i++) {
     hex2bin(merkle_bin + (i * 32), merkle_list[i], 32);
     }
     */

/*
memset(cbuf, 0, sizeof(cbuf));
bin2hex(cbuf, coinbase, cb_len);
fprintf(stderr, "DEBUG: coinbase/prehash: %s\n", cbuf);
*/

  gen_hash(coinbase, merkle_root, cb_len);

/*
memset(cbuf, 0, sizeof(cbuf));
bin2hex(cbuf, merkle_root, 32);
fprintf(stderr, "DEBUG: merkle/prehash: %s\n", cbuf);
*/

  memcpy(merkle_sha, merkle_root, 32);
  for (i = 0; i < merkle_cnt; ++i, merkle_bin += 32) {
//fprintf(stderr, "DEBUG: merkle/tx: %s\n", merkle_list[i]);
    memcpy(merkle_sha + 32, merkle_bin, 32);
    gen_hash(merkle_sha, merkle_root, 64);
    memcpy(merkle_sha, merkle_root, 32);
  }
  data32 = (uint32_t *)merkle_sha;
  swap32 = (uint32_t *)merkle_root;
  flip32(swap32, data32);
  free(merkle_free);
/*
for (i = 0; i < 8; i++) {
fprintf(stderr, "DEBUG: merkle/hash[+%d: %x\n", i, data32[i]);
}
*/

  bin2hex(work->merkle_root, merkle_root, 32); /* store hash */

//fprintf(stderr, "DEBUG: merkle/hash[bin2hex]: %s\n", work->merkle_root);

  hex2bin(&diffbits[0], nbit, 4);

  hex2bin(work->data, version, 4);


  hex2bin(hash_swap, prev_hash, 32);
  shscrypt_swap256(&work->data[4], hash_swap);


  memcpy (&work->data[36], merkle_root, 32);

  hex2bin(&work->data[68], ntime, 4);
  //*((uint32_t*)&work->data[68]) = htobe32(work->ntime);
  //*((uint32_t*)&work->data[68]) = htobe32(work->ntime + _sh_timer_elapsed(&work->tv_received, NULL));


  memcpy(&work->data[72], diffbits, 4);

  sprintf(nonce_str, "%-8.8x", work->nonce);
  hex2bin(&work->data[76], nonce_str, 4);
//  fprintf(stderr, "DEBUG: using nonce %u (%s)\n", strtol(nonce_str, NULL, 16), nonce_str);

  memcpy(&work->data[80], workpadding_bin, 48);


  sh_calc_midstate(work);
  scrypt_set_target(work->target, work->sdiff);

  data32 = (uint32_t *)work->data;
  for (i = 0; i < 20; i++) {
    char hex_str[16];
    memset(hex_str, 0, 16);
    bin2hex(hex_str, (unsigned char *)(&data32[i]), 4); 
//    fprintf(stderr, "DEBUG: shscrypt_work[data %d]: %-8.8x (hex %s)\n", i, data32[i], hex_str);
  }

}

int shscrypt(scrypt_work *work, int step)
{
  uint32_t *hash_nonce = (uint32_t *)(work->data + 76);
  uint64_t ret;
  int err;

  ret = cpu_scanhash(work, step);
  work->hash_nonce = *hash_nonce;

  return (0);
}

int shscrypt_verify(scrypt_work *work)
{
  int err;

  err = test_nonce(work, work->nonce);
//  fprintf(stderr, "DEBUG: shscrypt_verify: %d = test_nonce(%u)\n", err, work->nonce);
#if 0
  if (err != 1) { 
    err = test_nonce(work, work->hash_nonce);
  fprintf(stderr, "DEBUG: shscrypt_verify: %d = test_nonce(%u)\n", err, work->hash_nonce);
  }
#endif
  if (err == 0)
    return (SHERR_FBIG);
  if (err != 1)
    return (SHERR_INVAL);

  return (0);
}


_TEST(shscrypt)
{
  int err;
  char prev_hash[256];
  char cb1[256];
  char cb2[256];
  char nbit[256];
  char buf[256];
  char nonce1[256];
  char **merkle_ar;
  char ntime[16];
  scrypt_peer speer;
  scrypt_work work;
  memset(&work, 0, sizeof(work));

  memset(&speer, 0, sizeof(speer));
  sprintf(nonce1, "%-8.8x", 0);
  shscrypt_peer(&speer, nonce1, 0.031); /* diff 1 */
  sprintf(work.xnonce2, "%-8.8x", 0x0);

  merkle_ar = (char **)calloc(2, sizeof(char *));
  //merkle_ar[0] = (char *)calloc(128, sizeof(char));
  //sprintf(merkle_ar[0], "%-64.64x", 0x0);

  /* sample data */
  strcpy(cb1, "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff070425eb9408");
  strcpy(cb2, "ffff010000768bc986080043410446efa04ed96b35e7b42bb649b00ad88d645e029e81062be3c7297801e4e74ef12440187c302df6bafa4878624361af108141c55aff99bd75ada3229096d4f6c6ac00000000");
  strcpy(prev_hash, "33abc26f9a026f1279cb49600efdd63f42e7c2d3a15463ad8090505d3e967752");
  strcpy(nbit, "1e0ffff0");

  sprintf(ntime, "%-8.8x", (unsigned int)time(NULL));
  shscrypt_work(&speer, &work, merkle_ar, prev_hash, cb1, cb2, nbit, ntime);
  _TRUE(0 == shscrypt(&work, 20480));
 {
    char hash[64];
    char block_hash[256];
    /* little-endian block hash */
    memcpy(hash, work.hash, 32);
    flip32(hash, hash);
    memset(block_hash, 0, sizeof(block_hash));
    bin2hex(block_hash, hash, 32);
//fprintf(stderr, "DEBUG: block_hash \"%s\"\n", block_hash);
  }

  _TRUE(0 == shscrypt_verify(&work));

  free(merkle_ar);
}

double shscrypt_hash_sdiff(scrypt_work *work)
{
  const unsigned char *target = work->hash;
  double targ = 0;
  signed int i;

  for (i = 31; i >= 0; --i)
    targ = (targ * 0x100) + target[i];

  return work->sdiff / (targ ?: 1);
}
double shscrypt_hash_diff(scrypt_work *work)
{
  const unsigned char *target = work->hash;
  double targ = 0;
  signed int i;

  for (i = 31; i >= 0; --i)
    targ = (targ * 0x100) + target[i];

  return DIFFEXACTONE / (targ ?: 1);
}
#if 0
static double target_diff(const unsigned char *target)
{
        double targ = 0;
        signed int i;

        for (i = 31; i >= 0; --i)
                targ = (targ * 0x100) + target[i];

        return DIFFEXACTONE / (targ ?: 1);
}
static uint64_t share_diff(const struct scrypt_work *work)
{
	uint64_t ret;
	bool new_best = false;
	char best_share[256];

	ret = target_diff(work->hash);
	suffix_string(ret, best_share, sizeof(best_share), 0);

	return ret;
}
#endif
