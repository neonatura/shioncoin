
/*
 * @copyright
 *
 *  Copyright 2019 Neo Natura
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

#ifndef __SERVER__ALGOBITS_H__
#define __SERVER__ALGOBITS_H__

#define ALGO_SCRYPT 0
#define ALGO_SHA256D 1
#define ALGO_KECCAK 2
#define ALGO_X11 3
#define ALGO_BLAKE2S 4
#define ALGO_QUBIT 5
#define ALGO_GROESTL 6
#define ALGO_SKEIN 7
#define MAX_ALGOBITS 8

#define BLOCK_ALGO_SCRYPT 0
#define BLOCK_ALGO_SHA256D (1 << 0)
#define BLOCK_ALGO_KECCAK (1 << 1)
#define BLOCK_ALGO_X11 (1 << 2)
#define BLOCK_ALGO_BLAKE2S (1 << 3)
#define BLOCK_ALGO_QUBIT (1 << 4)
#define BLOCK_ALGO_GROESTL (1 << 5)
#define BLOCK_ALGO_SKEIN (1 << 6)

/** What bits to set in version for algobits blocks */
#define ALGOBITS_TOP_BITS 0xE0000000UL
/** What bitmask determines whether algobits is in use */
#define ALGOBITS_TOP_MASK 0xE000FFFFUL
/** Total bits available for algobits */
#define ALGOBITS_NUM_BITS 16

#ifdef __cplusplus
std::string GetAlgoNameStr(int Algo);

bool IsAlgoBitsMask(unsigned int nVersion);
#endif

#ifdef __cplusplus
extern "C" {
#endif

const char *GetAlgoName(int Algo);

int32_t GetAlgoBits(int alg);

int GetVersionAlgo(unsigned int nVersion);

uint32_t GetAlgoWorkFactor(int alg);

double GetBlockBitsDifficulty(unsigned int nBits, unsigned int nVersion);

#ifdef __cplusplus
}
#endif

#endif /* ndef __SERVER__ALGOBITS_H__ */

