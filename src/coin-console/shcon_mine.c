
/*
 * @copyright
 *
 *  Copyright 2018 Brian Burrell
 *
 *  This file is part of ShionCoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcon.h"
#include <stdbool.h>
#include <share.h>


#define MAX_CYCLE_NONCE 3609 /* ~4s @ 3ghz */

typedef unsigned char uint256[32];

typedef struct block_t
{
	int32_t nVersion;
	uint256 hashPrevBlock;
	uint256 hashMerkleRoot;
	uint32_t nTime;
	uint32_t nBits;
	uint32_t nNonce;
	uint8_t padd[48];
} block_t;

time_t SHARE_LAST;
uint64_t SHARE_COUNT;
uint64_t SHARE_ATTEMPT;
uint64_t SHARE_FOUND;
double SHARE_TOTAL;
double SHARE_MAX;

bool hex2bin(unsigned char *p, const char *hexstr, size_t len);
void bin2hex(char *str, unsigned char *bin, size_t bin_len);


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

static inline uint32_t ByteReverse(uint32_t value)
{
	value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
	return (value<<16) | (value>>16);
}

int shcon_mine_run(char *raw_hex, char *ret_hex, double *diff_p)
{
	scrypt_work work;
	block_t block;
	int err;

	if (strlen(raw_hex) != 256)
		return (ERR_INVAL);

	memset(&block, 0, sizeof(block));
	hex2bin((unsigned char *)&block, raw_hex, 128);
	block.nNonce = 0;
	block.nTime = htonl(time(NULL)); /* update time */

#if 0
	printf ("version: %u\n", (unsigned int)ntohl(block.nVersion));
	printf ("time: %u\n", (unsigned int)ntohl(block.nTime));
	printf ("bits: %u\n", (unsigned int)ntohl(block.nBits));
#endif

	memset(&work, 0, sizeof(work));
	sprintf(work.xnonce2, "%-8.8x", 0x00000000);

	memcpy(work.merkle_root, block.hashMerkleRoot, 32);
	memcpy(work.data, &block, 80);

	work.sdiff = 0.125;
	sh_calc_midstate(&work);

	{
		unsigned char target[32];

		/* set target to minimum. */
		memset(target, 0, 2);
		memset(target+2, 0xff, 30);
		swab256(work.target, target);
	}

	SHARE_ATTEMPT++;
	SHARE_LAST = time(NULL);

	err = shscrypt(&work, MAX_CYCLE_NONCE);
	if (err || work.nonce == MAX_CYCLE_NONCE) {
		return (-EAGAIN);
	}

	SHARE_COUNT++;
	SHARE_TOTAL += work.pool_diff;
	SHARE_MAX = MAX(SHARE_MAX, work.pool_diff);

	err = shscrypt_verify(&work);
	if (err) {
		return (-EAGAIN);
	}

//fprintf(stderr, "DEBUG: found block at nonce %u\n", work.nonce);
	//block.nNonce = htonl(work.nonce);
	block.nNonce = work.nonce;

//	memset(ret_hex, 0, sizeof(ret_hex));
	memset(ret_hex, 0, 257);
	bin2hex(ret_hex, (unsigned char *)&block, 128);
//fprintf(stderr, "DEBUG: BLOCK: %s\n", ret_hex);

	if (diff_p)
		*diff_p = work.pool_diff;

	return (0);
}

