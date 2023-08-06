
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
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

#include "test_shcoind.h"
#include <sexe.h>
#include <string>
#include <vector>
#include "wallet.h"
#include "txmempool.h"
#include "test/test_pool.h"
//#include "test/test_txidx.h"
#include "test/test_block.h"
//#include "test/test_wallet.h"
#include "color/color_pool.h"
#include "color/color_block.h"
#include "color/color_wallet.h"

#ifdef __cplusplus
extern "C" {
#endif

_TEST(sip22_altblock)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	uint160 hColor = 0x1;
	color_opt opt;

	CBlock *block1 = color_CreateGenesisBlock(hColor, opt);
	_TRUEPTR(block1);
	_TRUE(block1->hashPrevBlock == 0);
	_TRUE(color_VerifyGenesisBlock(*block1));

	uint256 block1_hash = block1->GetHash();
	CBlockIndex pindexPrev;
	pindexPrev.phashBlock = &block1_hash;
	pindexPrev.nVersion = block1->nVersion;
	pindexPrev.hashMerkleRoot = block1->hashMerkleRoot;
	pindexPrev.nTime = block1->nTime;
	pindexPrev.nBits = block1->nBits;
	pindexPrev.nNonce = block1->nNonce;
	delete block1;

	ECKey rkey;
	wallet->GenerateNewECKey(rkey);
	CBlock *block2 = color_CreateNewBlock(hColor, &pindexPrev, rkey.GetPubKey());
	_TRUEPTR(block2);
	_TRUE(block2->hashMerkleRoot == block2->BuildMerkleTree());
	for (int ntx = 0; ntx < block2->vtx.size(); ntx++) {
		CTransaction *tx = &block2->vtx[ntx];
		_TRUE(tx->CheckTransaction(COLOR_COIN_IFACE));
	}
	delete block2;
}

#ifdef __cplusplus
}
#endif
