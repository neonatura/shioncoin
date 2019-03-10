
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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

// in init.cpp at top of AppInitParameterInteraction()
// int32_t bolo_init();
// bolo_init();

// in rpc/blockchain.cpp
// #include bolo_rpcblockchain.h
// ...
// { "blockchain",         "calc_MoM",               &calc_MoM,             {"height", "MoMdepth"}  },
// { "blockchain",         "height_MoM",             &height_MoM,             {"height"}  },

// in validation.cpp
// at end of ConnectBlock: bolo_connectblock(pindex,*(CBlock *)&block);
// at beginning DisconnectBlock: bolo_disconnect((CBlockIndex *)pindex,(CBlock *)&block);
/* add to ContextualCheckBlockHeader
    uint256 hash = block.GetHash();
    int32_t notarized_height;
    ....
    else if ( bolo_checkpoint(&notarized_height,(int32_t)nHeight,hash) < 0 )
    {
        CBlockIndex *heightblock = chainActive[nHeight];
        if ( heightblock != 0 && heightblock->GetBlockHash() == hash )
        {
            //fprintf(stderr,"got a pre notarization block that matches height.%d\n",(int32_t)nHeight);
            return true;
        } else return state.DoS(100, error("%s: forked chain %d older than last notarized (height %d) vs %d", __func__,nHeight, notarized_height));
    }
*/
/* add to getinfo
{
    int32_t bolo_prevMoMheight();
    extern uint256 NOTARIZED_HASH,NOTARIZED_DESTTXID,NOTARIZED_MOM;
    extern int32_t NOTARIZED_HEIGHT,NOTARIZED_MOMDEPTH;
    obj.pushKV("notarizedhash",         NOTARIZED_HASH.GetHex());
    obj.pushKV("notarizedtxid",         NOTARIZED_DESTTXID.GetHex());
    obj.pushKV("notarized",                (int)NOTARIZED_HEIGHT);
    obj.pushKV("prevMoMheight",                (int)bolo_prevMoMheight());
    obj.pushKV("notarized_MoMdepth",                (int)NOTARIZED_MOMDEPTH);
    obj.pushKV("notarized_MoM",         NOTARIZED_MOM.GetHex());
}*/

#include "shcoind.h"
#include "wallet.h"
#include "base58.h"
#include "txsignature.h"
#include "coinaddr.h"
#include "txcreator.h"
#include "bolo_validation03.h"

/* the coin value of each input for the final notary tx on the master chain. */
#define BOLO_NOTARY_COIN_VALUE 1000

/* the wallet account which is debited for notary tx creation. */
#define BOLO_ORIGIN_ACCOUNT "bank"
#define BOLO_NOTARY_ACCOUNT "bolo"

cbuff IntToByteVector(int val)
{
	unsigned char *raw = (unsigned char *)&val;
	return (cbuff(raw, raw + 4));
}

template <typename T>
std::vector<unsigned char> ToByteVector(const T& in)
{
	    return std::vector<unsigned char>(in.begin(), in.end());
}


#ifdef __cplusplus
extern "C" {
#endif



/* slave chain - block to notorize. */
int64 bolo_CHECKPOINT_HEIGHT;
uint256 bolo_CHECKPOINT_HASH;
uint256 bolo_CHECKPOINT_TXID;

/* slave chain - proposed block to notorize. */
int bolo_PROPOSED_HEIGHT;
uint256 bolo_PROPOSED_BLOCK;
uint256 bolo_PROPOSED_TXID;
int bolo_HWM_HEIGHT;

/* master chain - notary tx working variables. */
vector<CTxIn> bolo_mapNotary;
vector<CScript> bolo_mapNotaryScript;
int64 bolo_PROPOSED_LOCKTIME;
bool bolo_PROPOSED_NOTARY;

static CIface *bolo_master_iface;
static CIface *bolo_slave_iface;

struct less_than_key
{
	inline bool operator() (const CTxIn& struct1, const CTxIn& struct2)
	{
		if (struct1.prevout.hash == struct2.prevout.hash)
			return (struct1.prevout.n < struct2.prevout.n); 
		return (struct1.prevout.hash < struct2.prevout.hash);
	}
};


union _bits256 { uint8_t bytes[32]; uint16_t ushorts[16]; uint32_t uints[8]; uint64_t ulongs[4]; uint64_t txid; };
typedef union _bits256 bits256;

struct sha256_vstate { uint64_t length; uint32_t state[8],curlen; uint8_t buf[64]; };
struct rmd160_vstate { uint64_t length; uint8_t buf[64]; uint32_t curlen, state[5]; };
int32_t BOLO_TXINDEX = 1;

// following is ported from libtom
/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#define STORE32L(x, y)                                                                     \
{ (y)[3] = (uint8_t)(((x)>>24)&255); (y)[2] = (uint8_t)(((x)>>16)&255);   \
	(y)[1] = (uint8_t)(((x)>>8)&255); (y)[0] = (uint8_t)((x)&255); }

#define LOAD32L(x, y)                            \
{ x = (uint32_t)(((uint64_t)((y)[3] & 255)<<24) | \
		((uint32_t)((y)[2] & 255)<<16) | \
		((uint32_t)((y)[1] & 255)<<8)  | \
		((uint32_t)((y)[0] & 255))); }

#define STORE64L(x, y)                                                                     \
{ (y)[7] = (uint8_t)(((x)>>56)&255); (y)[6] = (uint8_t)(((x)>>48)&255);   \
	(y)[5] = (uint8_t)(((x)>>40)&255); (y)[4] = (uint8_t)(((x)>>32)&255);   \
	(y)[3] = (uint8_t)(((x)>>24)&255); (y)[2] = (uint8_t)(((x)>>16)&255);   \
	(y)[1] = (uint8_t)(((x)>>8)&255); (y)[0] = (uint8_t)((x)&255); }

#define LOAD64L(x, y)                                                       \
{ x = (((uint64_t)((y)[7] & 255))<<56)|(((uint64_t)((y)[6] & 255))<<48)| \
	(((uint64_t)((y)[5] & 255))<<40)|(((uint64_t)((y)[4] & 255))<<32)| \
	(((uint64_t)((y)[3] & 255))<<24)|(((uint64_t)((y)[2] & 255))<<16)| \
	(((uint64_t)((y)[1] & 255))<<8)|(((uint64_t)((y)[0] & 255))); }

#define STORE32H(x, y)                                                                     \
{ (y)[0] = (uint8_t)(((x)>>24)&255); (y)[1] = (uint8_t)(((x)>>16)&255);   \
	(y)[2] = (uint8_t)(((x)>>8)&255); (y)[3] = (uint8_t)((x)&255); }

#define LOAD32H(x, y)                            \
{ x = (uint32_t)(((uint64_t)((y)[0] & 255)<<24) | \
		((uint32_t)((y)[1] & 255)<<16) | \
		((uint32_t)((y)[2] & 255)<<8)  | \
		((uint32_t)((y)[3] & 255))); }

#define STORE64H(x, y)                                                                     \
{ (y)[0] = (uint8_t)(((x)>>56)&255); (y)[1] = (uint8_t)(((x)>>48)&255);     \
	(y)[2] = (uint8_t)(((x)>>40)&255); (y)[3] = (uint8_t)(((x)>>32)&255);     \
	(y)[4] = (uint8_t)(((x)>>24)&255); (y)[5] = (uint8_t)(((x)>>16)&255);     \
	(y)[6] = (uint8_t)(((x)>>8)&255); (y)[7] = (uint8_t)((x)&255); }

#define LOAD64H(x, y)                                                      \
{ x = (((uint64_t)((y)[0] & 255))<<56)|(((uint64_t)((y)[1] & 255))<<48) | \
	(((uint64_t)((y)[2] & 255))<<40)|(((uint64_t)((y)[3] & 255))<<32) | \
	(((uint64_t)((y)[4] & 255))<<24)|(((uint64_t)((y)[5] & 255))<<16) | \
	(((uint64_t)((y)[6] & 255))<<8)|(((uint64_t)((y)[7] & 255))); }

// Various logical functions
#define RORc(x, y) ( ((((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)((y)&31)) | ((uint32_t)(x)<<(uint32_t)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         RORc((x),(n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))
//#define MIN(x, y) ( ((x)<(y))?(x):(y) )

static inline int32_t sha256_vcompress(struct sha256_vstate * md,uint8_t *buf)
{
	uint32_t S[8],W[64],t0,t1,i;
	for (i=0; i<8; i++) // copy state into S
		S[i] = md->state[i];
	for (i=0; i<16; i++) // copy the state into 512-bits into W[0..15]
		LOAD32H(W[i],buf + (4*i));
	for (i=16; i<64; i++) // fill W[16..63]
		W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];

#define RND(a,b,c,d,e,f,g,h,i,ki)                    \
	t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];   \
	t1 = Sigma0(a) + Maj(a, b, c);                  \
	d += t0;                                        \
	h  = t0 + t1;

	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],0,0x428a2f98);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],1,0x71374491);
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],2,0xb5c0fbcf);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],3,0xe9b5dba5);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],4,0x3956c25b);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],5,0x59f111f1);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],6,0x923f82a4);
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],7,0xab1c5ed5);
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],8,0xd807aa98);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],9,0x12835b01);
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],10,0x243185be);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],11,0x550c7dc3);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],12,0x72be5d74);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],13,0x80deb1fe);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],14,0x9bdc06a7);
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],15,0xc19bf174);
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],16,0xe49b69c1);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],17,0xefbe4786);
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],18,0x0fc19dc6);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],19,0x240ca1cc);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],20,0x2de92c6f);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],21,0x4a7484aa);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],22,0x5cb0a9dc);
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],23,0x76f988da);
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],24,0x983e5152);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],25,0xa831c66d);
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],26,0xb00327c8);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],27,0xbf597fc7);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],28,0xc6e00bf3);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],29,0xd5a79147);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],30,0x06ca6351);
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],31,0x14292967);
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],32,0x27b70a85);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],33,0x2e1b2138);
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],34,0x4d2c6dfc);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],35,0x53380d13);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],36,0x650a7354);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],37,0x766a0abb);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],38,0x81c2c92e);
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],39,0x92722c85);
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],40,0xa2bfe8a1);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],41,0xa81a664b);
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],42,0xc24b8b70);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],43,0xc76c51a3);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],44,0xd192e819);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],45,0xd6990624);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],46,0xf40e3585);
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],47,0x106aa070);
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],48,0x19a4c116);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],49,0x1e376c08);
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],50,0x2748774c);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],51,0x34b0bcb5);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],52,0x391c0cb3);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],53,0x4ed8aa4a);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],54,0x5b9cca4f);
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],55,0x682e6ff3);
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],56,0x748f82ee);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],57,0x78a5636f);
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],58,0x84c87814);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],59,0x8cc70208);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],60,0x90befffa);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],61,0xa4506ceb);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],62,0xbef9a3f7);
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],63,0xc67178f2);
#undef RND
	for (i=0; i<8; i++) // feedback
		md->state[i] = md->state[i] + S[i];
	return(0);
}

#undef RORc
#undef Ch
#undef Maj
#undef S
#undef R
#undef Sigma0
#undef Sigma1
#undef Gamma0
#undef Gamma1

static inline void sha256_vinit(struct sha256_vstate * md)
{
	md->curlen = 0;
	md->length = 0;
	md->state[0] = 0x6A09E667UL;
	md->state[1] = 0xBB67AE85UL;
	md->state[2] = 0x3C6EF372UL;
	md->state[3] = 0xA54FF53AUL;
	md->state[4] = 0x510E527FUL;
	md->state[5] = 0x9B05688CUL;
	md->state[6] = 0x1F83D9ABUL;
	md->state[7] = 0x5BE0CD19UL;
}

static inline int32_t sha256_vprocess(struct sha256_vstate *md,const uint8_t *in,uint64_t inlen)
{
	uint64_t n; int32_t err;
	if ( md->curlen > sizeof(md->buf) )
		return(-1);
	while ( inlen > 0 )
	{
		if ( md->curlen == 0 && inlen >= 64 )
		{
			if ( (err= sha256_vcompress(md,(uint8_t *)in)) != 0 )
				return(err);
			md->length += 64 * 8, in += 64, inlen -= 64;
		}
		else
		{
			n = MIN(inlen,64 - md->curlen);
			memcpy(md->buf + md->curlen,in,(size_t)n);
			md->curlen += n, in += n, inlen -= n;
			if ( md->curlen == 64 )
			{
				if ( (err= sha256_vcompress(md,md->buf)) != 0 )
					return(err);
				md->length += 8*64;
				md->curlen = 0;
			}
		}
	}
	return(0);
}

static inline int32_t sha256_vdone(struct sha256_vstate *md,uint8_t *out)
{
	int32_t i;
	if ( md->curlen >= sizeof(md->buf) )
		return(-1);
	md->length += md->curlen * 8; // increase the length of the message
	md->buf[md->curlen++] = (uint8_t)0x80; // append the '1' bit
	// if len > 56 bytes we append zeros then compress.  Then we can fall back to padding zeros and length encoding like normal.
	if ( md->curlen > 56 )
	{
		while ( md->curlen < 64 )
			md->buf[md->curlen++] = (uint8_t)0;
		sha256_vcompress(md,md->buf);
		md->curlen = 0;
	}
	while ( md->curlen < 56 ) // pad upto 56 bytes of zeroes
		md->buf[md->curlen++] = (uint8_t)0;
	STORE64H(md->length,md->buf+56); // store length
	sha256_vcompress(md,md->buf);
	for (i=0; i<8; i++) // copy output
		STORE32H(md->state[i],out+(4*i));
	return(0);
}
// end libtom

void vcalc_sha256(char deprecated[(256 >> 3) * 2 + 1],uint8_t hash[256 >> 3],uint8_t *src,int32_t len)
{
	struct sha256_vstate md;
	sha256_vinit(&md);
	sha256_vprocess(&md,src,len);
	sha256_vdone(&md,hash);
}

bits256 bits256_doublesha256(char *deprecated,uint8_t *data,int32_t datalen)
{
	bits256 hash,hash2; int32_t i;
	vcalc_sha256(0,hash.bytes,data,datalen);
	vcalc_sha256(0,hash2.bytes,hash.bytes,sizeof(hash));
	for (i=0; i<(int32_t)sizeof(hash); i++)
		hash.bytes[i] = hash2.bytes[sizeof(hash) - 1 - i];
	return(hash);
}

int32_t iguana_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp)
{
	int32_t i; uint64_t x;
	if ( rwflag == 0 )
	{
		x = 0;
		for (i=len-1; i>=0; i--)
		{
			x <<= 8;
			x |= serialized[i];
		}
		switch ( len )
		{
			case 1: *(uint8_t *)endianedp = (uint8_t)x; break;
			case 2: *(uint16_t *)endianedp = (uint16_t)x; break;
			case 4: *(uint32_t *)endianedp = (uint32_t)x; break;
			case 8: *(uint64_t *)endianedp = (uint64_t)x; break;
		}
	}
	else
	{
		x = 0;
		switch ( len )
		{
			case 1: x = *(uint8_t *)endianedp; break;
			case 2: x = *(uint16_t *)endianedp; break;
			case 4: x = *(uint32_t *)endianedp; break;
			case 8: x = *(uint64_t *)endianedp; break;
		}
		for (i=0; i<len; i++,x >>= 8)
			serialized[i] = (uint8_t)(x & 0xff);
	}
	return(len);
}

int32_t iguana_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp)
{
	int32_t i;
	if ( rwflag == 0 )
	{
		for (i=0; i<len; i++)
			endianedp[i] = serialized[i];
	}
	else
	{
		for (i=0; i<len; i++)
			serialized[i] = endianedp[i];
	}
	return(len);
}

static bits256 iguana_merkle(bits256 *tree,int32_t txn_count)
{
	int32_t i,n=0,prev; uint8_t serialized[sizeof(bits256) * 2];
	if ( txn_count == 1 )
		return(tree[0]);
	prev = 0;
	while ( txn_count > 1 )
	{
		if ( (txn_count & 1) != 0 )
			tree[prev + txn_count] = tree[prev + txn_count-1], txn_count++;
		n += txn_count;
		for (i=0; i<txn_count; i+=2)
		{
			iguana_rwbignum(1,serialized,sizeof(*tree),tree[prev + i].bytes);
			iguana_rwbignum(1,&serialized[sizeof(*tree)],sizeof(*tree),tree[prev + i + 1].bytes);
			tree[n + (i >> 1)] = bits256_doublesha256(0,serialized,sizeof(serialized));
		}
		prev = n;
		txn_count >>= 1;
	}
	return(tree[n]);
}

int32_t bolo_init(int slaveIface, int masterIface)
{

	BOLO_TXINDEX = 0;

	bolo_master_iface = GetCoinByIndex(masterIface);
	if (!bolo_master_iface || !bolo_master_iface->enabled)
		return (-1);

	bolo_slave_iface = GetCoinByIndex(slaveIface);
	if (!bolo_slave_iface || !bolo_slave_iface->enabled)
		return (-1);

	return(0);
}

/* calculate a merkle tree hash from a chain of blocks. */
uint256 bolo_GetSlaveMerkle(int32_t height,int32_t MoMdepth)
{
	int ifaceIndex = GetCoinIndex(bolo_slave_iface);
	static uint256 zero;
	bits256 MoM, *tree; 
	int i;

	MoMdepth = MAX(0, MIN(MoMdepth, height - 1));
	//if ( MoMdepth >= height ) return(zero);

	tree = (bits256 *)calloc(MoMdepth * 3, sizeof(*tree));
	for (i=0; i < MoMdepth; i++) {
		CBlockIndex *pindex = GetBlockIndexByHeight(ifaceIndex, height - i);
		if (pindex)
			memcpy(&tree[i], &pindex->hashMerkleRoot, sizeof(bits256));
		else
		{
			free(tree);
			return(zero);
		}
	}

	memset(&MoM, 0, sizeof(MoM));
	if (MoMdepth != 0)
		MoM = iguana_merkle(tree, MoMdepth);

	free(tree);

	return(*(uint256 *)&MoM);
}

static bool bolo_checkpoint_create(int nHeight)
{
	CBlock *block;
	bool ok;

	if (nHeight <= 1)
		return (false);

	block = GetBlockByHeight(bolo_slave_iface, nHeight);
	if (!block)
		return (false);
	ok = block->CreateCheckpoint();

	if (ok) {
		/* retain */
		bolo_CHECKPOINT_HEIGHT = nHeight;
		bolo_CHECKPOINT_HASH = block->GetHash();
		bolo_CHECKPOINT_TXID = bolo_PROPOSED_TXID;
	}
	delete block;

	return (ok);
}

bool bolo_GetMasterFinalTx(const CTxOut& out, int& nHeight)
{
	uint256 hMerkle;
	uint256 hBlock;
	uint160 hIface;
	opcodetype opcode;
	cbuff vch;

	if (out.nValue != 0)
		return (false);

	if (out.scriptPubKey.size() < BOLO_ASSETCHAIN_MINLEN || 
			out.scriptPubKey.size() > BOLO_ASSETCHAIN_MAXLEN)
		return (false);

	const CScript& script = out.scriptPubKey;
	CScript::const_iterator pc = script.begin();
	if (!script.GetOp(pc, opcode) || opcode != OP_RETURN ||
			!script.GetOp(pc, opcode) || opcode != OP_11 ||
			!script.GetOp(pc, opcode) || opcode != OP_1 ||
			!script.GetOp(pc, opcode) || opcode != OP_11) {
		return (false);
	}

	vch.clear();
	if (!script.GetOp(pc, opcode, vch) || vch.size() != 20) {
		return (false);
	}
	hIface = uint160(vch);

	vch.clear();
	if (!script.GetOp(pc, opcode, vch) || vch.size() != 32) {
		return (false);
	}
	hBlock = uint256(vch);

	vch.clear();
	if (!script.GetOp(pc, opcode, vch) || vch.size() != 32) {
		return (false);
	}
	hMerkle = uint256(vch);

	vch.clear();
	if (!script.GetOp(pc, opcode, vch) || vch.size() != 4) {
		return (false);
	}
	memcpy(&nHeight, &vch[0], sizeof(nHeight));

	if (hIface == 0 || hBlock == 0 || nHeight == 0) /* hMerkle == 0 */
		return (false); /* sanity */

	if (nHeight <= bolo_CHECKPOINT_HEIGHT)
		return (false); /* stale */

	if (GetCoinHash(bolo_slave_iface->name) != hIface) {
		return (false); /* wrong service */
	}

	CBlockIndex *pindex = GetBlockIndexByHash(GetCoinIndex(bolo_slave_iface), hBlock);
	if (!pindex || pindex->nHeight != nHeight)
		return (false); /* unknown */

	if (nHeight != bolo_PROPOSED_HEIGHT) {
		/* wrong proposal. */
		Debug("(%s) bolo_GetMasterFinalTx: disregarding notary tx (height %d) with non-proposed height %d.", bolo_slave_iface->name, (int)nHeight, (int)bolo_PROPOSED_HEIGHT);
		return (false);
	}

	if (bolo_GetSlaveMerkle(nHeight, BOLO_BLOCK_MERKLE_DEPTH) != hMerkle) {
		Debug("(%s) bolo_GetMasterFinalTx: disregarding notary tx (height %d) with invalid merkle %s.", bolo_slave_iface->name, (int)nHeight, hMerkle.GetHex().c_str());
		return (false); /* chain merkle mismatch. */
	}

	return (true);
}


CScript bolo_MasterRedeemScript()
{
	const uint256& hBlock = bolo_PROPOSED_BLOCK;
	const int nHeight = bolo_PROPOSED_HEIGHT;
	CScript script;
	uint160 hIface;
	uint256 merk;

	merk = bolo_GetSlaveMerkle(nHeight, BOLO_BLOCK_MERKLE_DEPTH);
	hIface = GetCoinHash(bolo_slave_iface->name);
	script << OP_RETURN << OP_11 << OP_1 << OP_11 << ToByteVector(hIface) << ToByteVector(hBlock) << ToByteVector(merk) << IntToByteVector(nHeight) << OP_0;

	return (script);
}

bool bolo_GetMasterProposeTx(const CTransaction& tx, CTxIn& inOut, CScript& scriptOut)
{
	bool fBlock = false;
	bool fFund = false;
	CScript retScript;
	CTxIn retIn;
	int i;

	for (i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		CTxDestination dest;
		if (out.nValue == BOLO_NOTARY_COIN_VALUE &&
				ExtractDestination(out.scriptPubKey, dest)) {
			retIn.prevout.n = i;
			retIn.prevout.hash = tx.GetHash();
			retScript = out.scriptPubKey;
			fFund = true;
		} else if (out.nValue == 0 &&
				ExtractDestination(out.scriptPubKey, dest)) {
			CCoinAddr addr(GetCoinIndex(bolo_master_iface), dest);
			CScriptID scriptID;
			if (addr.GetScriptID(scriptID)) {
				const CScript& script = bolo_MasterRedeemScript();
				cbuff script_buf(script.begin(), script.end());
				if (Hash160(script_buf) == scriptID) {
					fBlock = true;
				}
			}
		}
	}

	if (fFund && fBlock) {
		Debug("(%s) bolo_GetMasterProposalTx: detected proposal tx \"%s\"\n", bolo_master_iface->name, tx.GetHash().GetHex().c_str()); 
		inOut = retIn;
		scriptOut = retScript;
		return (true);
	}

	return (false);
}


bool bolo_GetSlaveNotaryTx(const CTxOut& out)
{

	/* script: OP_RETURN OP_0 */
	if (out.scriptPubKey.size() != 2 ||
			out.scriptPubKey[0] != OP_RETURN ||
			out.scriptPubKey[1] != OP_0)
		return (false);

	if (out.nValue < 0 ||
			out.nValue > (int64)COIN)
		return (false);

	return (true);
}

void bolo_ResetMasterTx()
{
	bolo_mapNotary.clear();
	bolo_mapNotaryScript.clear();
	bolo_PROPOSED_BLOCK = 0;
	bolo_PROPOSED_HEIGHT = 0;
	bolo_PROPOSED_NOTARY = false;
}

/* propose a notary tx on the master chain referencing the specified block and height on the slave chain. */
bool bolo_ProposeMasterTx(const uint256& hBlock, int nHeight, CCoinAddr *addr)
{
	CWallet *wallet = GetWallet(bolo_master_iface);
	CTxCreator s_wtx(wallet, BOLO_ORIGIN_ACCOUNT);

	CCoinAddr p_addr(wallet->ifaceIndex);
	if (!addr) {
		p_addr = wallet->GetNotaryAddr(BOLO_NOTARY_ACCOUNT);
		addr = &p_addr;
	}

	/*
	 * Here we are sending from the "bank" acount to a new address which 
	 * will also be listed under the "bolo" account.
	 *
	 * Notary proposals transaction which do not get ratified or encounter
	 * an error will be credited to the "bolo" account sans transaction fees.
	 */

	/* minimum value output to be used as an input for final notary tx. */
	if (!s_wtx.AddOutput(addr->Get(), BOLO_NOTARY_COIN_VALUE))
		return (error(ERR_INVAL, "bolo_ProposeMasterTx: error adding output #1: %s", s_wtx.GetError().c_str()));

	/* zero value output to scriptid referencing final notary tx output. */
	const CScript& script = bolo_MasterRedeemScript();
	CScriptID scriptID = Hash160(cbuff(script.begin(), script.end()));
	if (!s_wtx.AddOutput(scriptID, 0))
		return (error(ERR_INVAL, "bolo_ProposeMasterTx: error adding output #2: %s", s_wtx.GetError().c_str()));

	/* commit transaction to master chain. */
	bolo_PROPOSED_NOTARY = s_wtx.Send();

	return (true);
}

/* sign the final notary tx on the master chain. */
bool bolo_SignMasterNotarySignature(CTransaction& tx, int nIn)
{
	int ifaceIndex = GetCoinIndex(bolo_master_iface);

	/* apply final sequence value. */
	tx.vin[nIn].nSequence = CTxIn::SEQUENCE_FINAL - 1;

	/* obtain script to sign. */
	CTransaction txFrom;
	if (!GetTransaction(bolo_master_iface,
				tx.vin[nIn].prevout.hash, txFrom, NULL))
		return (false); /* unknown tx */
	if (tx.vin[nIn].prevout.n >= txFrom.vout.size())
		return (false); /* sanity */

	const CScript& scriptIn = txFrom.vout[tx.vin[nIn].prevout.n].scriptPubKey;
	CSignature sig(ifaceIndex, &tx, nIn, SIGHASH_ANYONECANPAY); 
	return (sig.SignSignature(scriptIn));
}

bool bolo_VerifyMasterNotarySignature(CTransaction& tx, int nIn)
{
	int ifaceIndex = GetCoinIndex(bolo_master_iface);

	/* apply final sequence value. */
	tx.vin[nIn].nSequence = CTxIn::SEQUENCE_FINAL - 1;

	CTransaction txFrom;
	if (!GetTransaction(bolo_master_iface,
				tx.vin[nIn].prevout.hash, txFrom, NULL))
		return (false); /* unknown tx */
	if (tx.vin[nIn].prevout.n >= txFrom.vout.size())
		return (false); /* sanity */

	cstack_t witness;
	int nOut = tx.vin[nIn].prevout.n;
	CSignature sig(ifaceIndex, &tx, nIn, SIGHASH_ANYONECANPAY);
	return (VerifyScript(sig, tx.vin[nIn].scriptSig, witness,
				txFrom.vout[nOut].scriptPubKey, 0));
}

bool bolo_CreateMasterNotaryTx(CTransaction& tx)
{
	CWallet *wallet = GetWallet(bolo_master_iface);
	int i;

	/* allow 20 blocks for notary tx to be signed by at least 11 participants. */
	tx.nLockTime = GetBestHeight(bolo_master_iface) + BOLO_LOCKTIME_DEPTH;

	/* single output referencing block to notorize. */
	tx.vout.resize(1);
	tx.vout[0].scriptPubKey = bolo_MasterRedeemScript();
	tx.vout[0].nValue = 0;

	/* all proposals submitted for this height. */
	int nTotal = 0;
	tx.vin.resize(bolo_mapNotary.size());
	for (i = 0; i < bolo_mapNotary.size(); i++) {
		tx.vin[i] = bolo_mapNotary[i];
		if (wallet->IsMine(tx.vin[i])) {
			if (!bolo_SignMasterNotarySignature(tx, i)) {
				return (false); /* give up */
			}
		} else {
			/* initialize */
			tx.vin[i].nSequence = MAX(1, tx.vin[i].nSequence);
			if (tx.GetVersion() >= 2)
				tx.vin[i].nSequence |= CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG;
		}
	}

	/* sort by prevout hash */
	std::sort(tx.vin.begin(), tx.vin.end(), less_than_key());

	return (true);
}

/* verify that all inputs reference a known notary poposal tx commited on master chain. */
bool bolo_IsNotaryTx(const CTransaction& tx)
{
	int i, j;

	for (j = 0; j < tx.vin.size(); j++) {
		bool bFound = false;
		for (i = 0; i < bolo_mapNotary.size(); i++) {
			CTxIn& in = bolo_mapNotary[i];
			if (in.prevout.hash == tx.vin[j].prevout.hash &&
					in.prevout.n == tx.vin[j].prevout.n) {
				bFound = true;
				break;
			}
		}
		if (!bFound)
			return (false);
	}

	return (true);
}

bool bolo_ApplyNotarySignature(CWallet *wallet, CTransaction& tx, int nIn)
{
	CTxIn& in = tx.vin[nIn];
	bool fUpdated = false;
	int i;

	if (wallet->IsMine(in)) {
		if (in.scriptSig.size() != 0)
			return (false);

		return (bolo_SignMasterNotarySignature(tx, nIn));
	}

	if (in.scriptSig.size() == 0) {
		/* attempt to fill signature based on previous non-comitted tx's */
		for (i = 0; i < bolo_mapNotary.size(); i++) {
			if (bolo_mapNotary[i].scriptSig.size() != 0 &&
					bolo_mapNotary[i].prevout.hash == in.prevout.hash &&
					bolo_mapNotary[i].prevout.n == nIn)
				break;
		}
		if (i != bolo_mapNotary.size()) {
			in.nSequence = CTxIn::SEQUENCE_FINAL - 1;
			in.scriptSig = bolo_mapNotary[i].scriptSig;
			fUpdated = true;
		}
	}

	return (fUpdated);
}

void bolo_SaveNotarySignature(CTransaction& tx, int nIn)
{
	CWallet *wallet = GetWallet(bolo_master_iface);
	const CTxIn& in = tx.vin[nIn];
	int i;

	if (in.nSequence != (CTxIn::SEQUENCE_FINAL - 1))
		return;

	for (i = 0; i < bolo_mapNotary.size(); i++) {
		if (bolo_mapNotary[i].scriptSig.size() != 0)
			continue; /* already filled. */

		if (bolo_mapNotary[i].prevout.hash != in.prevout.hash ||
				bolo_mapNotary[i].prevout.n != in.prevout.n)
			continue; /* wrong notary ref */

		if (!bolo_VerifyMasterNotarySignature(tx, nIn)) {
			Debug("bolo_SaveNotarySignature: signature verification failure: %s\n", tx.vin[nIn].scriptSig.ToString().c_str());
			continue; /* junk */
		}

		bolo_mapNotary[i].scriptSig = in.scriptSig;
	}

}

bool bolo_UpdateMasterNotaryTx(CTransaction& tx)
{
	CWallet *wallet = GetWallet(bolo_master_iface);
	bool fUpdated = false;
	int i;

	if (!bolo_IsNotaryTx(tx))
		return (false);

	/* redundant lock-time check */
	if (tx.nLockTime != bolo_PROPOSED_LOCKTIME)
		return (false);

	/* single output referencing block to notorize (redundant check). */
	if (tx.vout.size() != 0 ||
			tx.vout[0].nValue != 0 ||
			tx.vout[0].scriptPubKey != bolo_MasterRedeemScript())
		return (false);

	/* sign local inputs. */
	for (i = 0; i < tx.vin.size(); i++) {
		if (tx.vin[i].scriptSig.size() == 0) {
			/* attempt to generate signature. */
			fUpdated = bolo_ApplyNotarySignature(wallet, tx, i);
		} else {
			/* retain signature. */
			bolo_SaveNotarySignature(tx, i);
		}
	}

	return (fUpdated);
}

void bolo_disconnectblock_master(CBlockIndex *pindex, CBlock *block)
{

	if ((int32_t)pindex->nHeight <= bolo_PROPOSED_LOCKTIME) {
		/* bruteforce shortcut. on any reorg, no active notarization until next one is seen. */
		bolo_ResetMasterTx();
	}

}

void bolo_disconnectblock_slave(CBlockIndex *pindex, CBlock *block)
{

	if ( (int32_t)pindex->nHeight <= bolo_CHECKPOINT_HEIGHT ) {
		/* bruteforce shortcut. on any reorg, no active notarization until next one is seen. */
		bolo_ResetMasterTx();
	}

}

/**
 * A notarized master transaction will have a eleven or more inputs of 0.00001 coins and a single zero-value output of "OP_RETURN << OP_11 << OP_1 << OP_11 << OP_HASH160 << <block hash: 32 bytes> << <block merkle: 32 bytes> << <height: 4 bytes> << OP_0" where OP_HASH160 is a uint160 hash of the coin interface's symbol.
 */
void bolo_connectblock_master(CBlockIndex *pindex, CBlock& block)
{
	CWallet *wallet = GetWallet(bolo_master_iface);
	int ifaceIndex = block.ifaceIndex;
	uint256 hBlock;
	int nHeight;

	if (GetCoinByIndex(ifaceIndex) != bolo_master_iface)
		return; /* wrong coin service. */

	if (bolo_PROPOSED_HEIGHT == 0)
		return; /* nothing has been proposed. */

	for (unsigned int i = 0; i < block.vtx.size(); i++) {
		CTransaction& tx = block.vtx[i];

		CTxIn in;
		CScript script;
		if (bolo_GetMasterProposeTx(tx, in, script)) {
			if (std::find(bolo_mapNotaryScript.begin(), bolo_mapNotaryScript.end(), script) != bolo_mapNotaryScript.end()) {
				/* a proposal for this destination already exists. */
				Debug("(%s) bolo_GetMasterFinalTx: ignoring duplicate proposal destination (%s).", bolo_master_iface->name, script.ToString().c_str());
				continue;
			}

			/* map notary proposals. */
			bolo_mapNotary.push_back(in);
			bolo_mapNotaryScript.push_back(script);

//fprintf(stderr, "DEBUG: bolo_connectblock_master: bolo_mapNotary.size() = %d\n", bolo_mapNotary.size());

			if (bolo_PROPOSED_NOTARY &&
					bolo_mapNotary.size() >= BOLO_MINRATIFY) {
				CWalletTx wtx(wallet);
				if (!bolo_CreateMasterNotaryTx(wtx))
					continue;
				if (wallet->CommitTransaction(wtx)) {
					bolo_PROPOSED_LOCKTIME = wtx.nLockTime;
					Debug("(%s) bolo_connectblock_master/bolo_CreateMasterNotaryTx: created notary tx \"%s\" (%d inputs) (lock-height %d).\n", bolo_master_iface->name, tx.GetHash().GetHex().c_str(), tx.vin.size(), bolo_PROPOSED_LOCKTIME);
				} else { 
					Debug("(%s) bolo_connectblock_master/bolo_CreateMasterNotaryTx: error committing notary tx \"%s\" (%d inputs).", bolo_master_iface->name, tx.GetHash().GetHex().c_str(), tx.vin.size());
				}
			}
			continue;
		}

		/* check for a final notarized/signed tx on master chain */
		if (tx.vout.size() == 1 &&
				bolo_GetMasterFinalTx(tx.vout[0], nHeight)) {

			/* at least notaries as inputs. */
			if (tx.vin.size() < BOLO_MINRATIFY) {
				continue;
			}

			Debug("bolo_GetMasterFinalTx: found [%s] notary tx on [%s] height %d.", bolo_master_iface->name, bolo_slave_iface->name, nHeight);

			tx_cache inputs;
			if (!wallet->FillInputs(tx, inputs)) {
				/* unable to aquire unspent inputs. */
				continue;
			}

			/* redundant signature check. */
			bool fValid = true;
			for (unsigned int j = 0; j < tx.vin.size(); j++) {
				const CTransaction &in_tx = inputs[tx.vin[j].prevout.hash];
				const int in_n = tx.vin[j].prevout.n;

				if (in_n >= in_tx.vout.size() ||
						in_tx.vout[in_n].nValue < BOLO_NOTARY_COIN_VALUE)
					fValid = false; /* insufficient funding of input. */
				else if (!bolo_VerifyMasterNotarySignature(tx, j))
					fValid = false; /* unable to verify input signature. */
			}
			if (!fValid) {
				Debug("(%s) bolo_connectblock_master: warning: discarding invalid notary tx \"%s\".", bolo_master_iface->name, tx.GetHash().GetHex().c_str());
				continue;
			}

			/* establish a new dynamic checkpoint on slave chain. */
			if (!bolo_checkpoint_create(nHeight)) {
				/* stale/fork checkpoint. */

				/* .. */
			}

			/* a bolo notary tx has been successfully generated. */
			bolo_PROPOSED_NOTARY = false;
		}

	}

}

/**
 * A notarized validation matrix tx will have a single coinbase input (the validation matrix) and a single output of OP_RETURN (0x6A) OP_0 (0x0).
 */
void bolo_connectblock_slave(CBlockIndex *pindex, CBlock& block)
{
	int ifaceIndex = block.ifaceIndex;

	if (GetCoinByIndex(ifaceIndex) != bolo_slave_iface)
		return; /* wrong coin service. */

	if (pindex->nHeight > bolo_HWM_HEIGHT) {
		bolo_HWM_HEIGHT = pindex->nHeight;
	} else if (pindex->nHeight != bolo_HWM_HEIGHT) {
		/* reorg */
		bolo_ResetMasterTx();
		return;
	}

	if (0 == (pindex->nHeight % BOLO_LOCKTIME_DEPTH)) {
		int nMinHeight = (int)((pindex->nHeight / BOLO_LOCKTIME_DEPTH) - 1) * BOLO_LOCKTIME_DEPTH;
		if (bolo_PROPOSED_HEIGHT >= nMinHeight &&
				bolo_PROPOSED_HEIGHT < pindex->nHeight) {
			/* commit a proposal tx onto master chain. */
			bolo_PROPOSED_NOTARY = false;
			bolo_ProposeMasterTx(bolo_PROPOSED_BLOCK, bolo_PROPOSED_HEIGHT);
			return;
		}
	}

	int nMinHeight = (int)(pindex->nHeight / BOLO_BLOCK_MERKLE_DEPTH) * BOLO_BLOCK_MERKLE_DEPTH;
	if (bolo_PROPOSED_HEIGHT <= nMinHeight) {
		/* track ongoing blank OP_RETURN's with a minimal coin value. */
		for (unsigned int i = 0; i < block.vtx.size(); i++) {
			const CTransaction& tx = block.vtx[i];

			for (unsigned int j = 0; j < tx.vout.size(); j++) {
				if (bolo_GetSlaveNotaryTx(tx.vout[j])) {
					/* retain oldest block in this 20-block range. */
					bolo_ResetMasterTx();
					bolo_PROPOSED_HEIGHT = pindex->nHeight; 
					bolo_PROPOSED_BLOCK = pindex->GetBlockHash();
					bolo_PROPOSED_TXID = tx.GetHash();
					break;
				}
			}

		}
	}

}

/* handles management of ongoing final notary tx on master chain. mutates tx (adds signature if notary) when it is added to local mem pool. */
bool bolo_updatetx_master(CTransaction& tx)
{
	const int ifaceIndex = GetCoinIndex(bolo_master_iface);
	CWallet *wallet = GetWallet(bolo_master_iface);
	int nHeight;
	int i;

	if (GetCoinByIndex(ifaceIndex) != bolo_master_iface)
		return (false); /* wrong coin service. */

	/* disregard if we have not submitted a proposal. */
	if (bolo_PROPOSED_NOTARY)
		return (false); /* no proposal submitted. */

	/* ensure all notaries are referencing the same notary tx. */
	if (tx.nLockTime != bolo_PROPOSED_LOCKTIME)
		return (false); /* incorrect sequence. */

	/* notary tx will always have a single output. */
	if (tx.vout.size() != 1)
		return (false);

	/* ensure tx is a bolo notary tx. */
	if (!bolo_GetMasterFinalTx(tx.vout[0], nHeight))
		return (false);

	/* notary tx is not for the height we are proposing. */
	if (nHeight != bolo_PROPOSED_HEIGHT)
		return (false);

	/* check whether we need to update the tx. */
	if (!bolo_UpdateMasterNotaryTx(tx))
		return (false);

	int nTotal = 0;
	vector<CTxIn> vin;
	for (i = 0; i < tx.vin.size(); i++) {
		if (tx.vin[i].nSequence != (CTxIn::SEQUENCE_FINAL - 1) &&
				tx.vin[i].scriptSig.size() != 0)
			continue;
		vin.push_back(tx.vin[i]);
		nTotal++;
	}
	if (vin.size() >= BOLO_MINRATIFY) {
		/* at least eleven signatures have been gathered. */
		tx.vin = vin;
	}

	/* sort by prevout hash */
	std::sort(tx.vin.begin(), tx.vin.end(), less_than_key());

	return (true);
}

bool bolo_IsSlaveIface(CIface *iface)
{
	return (bolo_slave_iface == iface);
}


#ifdef __cplusplus
}
#endif

