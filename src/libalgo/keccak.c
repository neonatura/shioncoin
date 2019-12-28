
/*
 * @copyright
 *
 *  Copyright 2019 Brian Burrell
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

#include <string.h>
#include <stdint.h>
#include "keccak.h"
#include "sph_keccak.h"

void keccakhash(void *state, const void *input)
{
	sph_keccak256_context ctx_keccak;
	uint32_t hash[32];

	sph_keccak256_init(&ctx_keccak);
	sph_keccak256 (&ctx_keccak,input, 80);
	sph_keccak256_close(&ctx_keccak, hash);

	memcpy(state, hash, 32);
}

