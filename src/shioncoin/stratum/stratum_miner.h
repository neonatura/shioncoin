
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura
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

#ifndef __STRATUM__MINER_H__
#define __STRATUM__MINER_H__

#ifdef __cplusplus
extern "C" {
#endif

shjson_t *stratum_miner_getblocktemplate(int ifaceIndex, int nAlg);

int stratum_miner_submitblock(unsigned int workId, unsigned int nTime, unsigned int nNonce, char *xn_hex, char *ret_hash, double *ret_diff);

int is_stratum_miner_algo(int ifaceIndex, int nAlg);

void add_stratum_miner_block(int ifaceIndex, char *block_hash);

shjson_t *stratum_miner_lastminerblock(int ifaceIndex);

#ifdef __cplusplus
CBlockIndex *get_stratum_miner_block(int ifaceIndex, uint256 hBlock);
vector<CBlockIndex *> get_stratum_miner_blocks(int ifaceIndex);
}
#endif

#endif /* __STRATUM__MINER_H__ */

