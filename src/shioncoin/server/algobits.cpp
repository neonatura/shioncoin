
/*
 * @copyright
 *
 *  Copyright 2019 Brian Burrell
 *
 *  This file is part of Shioncoin.
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

#include "shcoind.h"
#include "block.h"
#include "algobits.h"

static const char *algobits_label[MAX_ALGOBITS] = {
	"scrypt",
	"sha256d",
	"keccak-c",
	"x11",
	"blake2s",
	"qubit",
	"greostl",
	"skein"
};


const char *GetAlgoName(int alg)
{
	static const char *blank_str = "";

	if (alg < 0 || alg >= MAX_ALGOBITS)
		return (blank_str);

	return (algobits_label[alg]);
}

string GetAlgoNameStr(int alg)
{
	return (string(GetAlgoName(alg)));
}

int32_t GetAlgoBits(int alg)
{
	int nVersion = ALGOBITS_TOP_BITS;

	alg--;
	if (alg >= 0)
		nVersion += (1 << alg);

	return (nVersion);
} 

int GetVersionAlgo(unsigned int nVersion)
{
	unsigned int flag;
	int idx;

	if (IsAlgoBitsMask(nVersion)) {
		flag = nVersion - ALGOBITS_TOP_BITS;
		for (idx = 0; idx < ALGOBITS_NUM_BITS; idx++) {
			if (flag & (1 << idx))
				return (idx + 1);
		}
	}

	return (ALGO_SCRYPT);
}

bool IsAlgoBitsMask(unsigned int nVersion)
{

	if (nVersion >= ALGOBITS_TOP_BITS &&
			nVersion < ALGOBITS_TOP_MASK)
		return (true);

	return (false);
}

uint32_t GetAlgoWorkFactor(int alg)
{
	uint32_t rate = 1;

	switch (alg) {
		case ALGO_SHA256D:
			rate = 1552;
			break;
		case ALGO_KECCAKC:
			rate = 264;
			break;
		case ALGO_X11:
			rate = 8;
			break;
		case ALGO_BLAKE2S:
			rate = 600;
			break;
		case ALGO_QUBIT:
			rate = 12;
			break;
		case ALGO_GROESTL:
			rate = 30;
			break;
		case ALGO_SKEIN:
			rate = 150;
			break;
	}

	return (rate);
}

double GetBlockBitsDifficulty(unsigned int nBits, unsigned int nVersion)
{
	int nShift = (nBits >> 24) & 0xff;

	double dDiff =
		(double)0x0000ffff / (double)(nBits & 0x00ffffff);

	while (nShift < 29)
	{
		dDiff *= 256.0;
		nShift++;
	}
	while (nShift > 29)
	{
		dDiff /= 256.0;
		nShift--;
	}

	dDiff *= GetAlgoWorkFactor(GetVersionAlgo(nVersion));

	return (dDiff);
}

