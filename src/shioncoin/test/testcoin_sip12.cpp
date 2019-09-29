
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

#include "test_shcoind.h"
#include <sexe.h>
#include <string>
#include <vector>
#include "wallet.h"
#include "account.h"
#include "txcreator.h"
#include "bech32.h"
#include "versionbits.h"
#include "test/test_pool.h"
#include "test/test_block.h"
#include "test/test_txidx.h"

#ifdef __cplusplus
extern "C" {
#endif

_TEST(sip12_consensus)
{
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);
	CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	string strAccount("");
	int idx;

	opt_bool_set(OPT_PARAM_TX, TRUE);
	opt_num_set(OPT_BLOCK_SIZE, 2048000);

	CBlockIndex *pindexPrev = GetBestBlockIndex(iface);
	_TRUE(VersionBitsState(pindexPrev, iface, DEPLOYMENT_PARAM) == THRESHOLD_ACTIVE);

	/* begin */
	for (idx = 0; idx < 2; idx++) {
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}
	int64 bal = GetAccountBalance(TEST_COIN_IFACE, strAccount, 1);
	int64 step = MAX(10, (bal - COIN) / 10240 / 10);

	int of;
	for (of = 0; of < 2; of++) { /* x100 param */
		CCoinAddr addr = wallet->GetRecvAddr(strAccount);
		for (idx = 0; idx < 50; idx++) {
			CTxCreator s_wtx(wallet, strAccount);
			s_wtx.AddOutput(addr.Get(), step);
			AddParamIfNeccessary(iface, s_wtx); /* OP_PARAM */
			bool fOk = s_wtx.Send();
			_TRUE(fOk);
		}
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	/* fake x10000 */
	for (idx = 0; idx < 10139; idx++) {
		CTransaction tx;
		CParam *param = tx.UpdateParam(EXTPARAM_BLOCKSIZE, 2048000);
		wallet->mapParam.push_back(*param);
	}

	_TRUE(GetParamTxValue(iface, EXTPARAM_BLOCKSIZE) == 1024000);

	{
		CCoinAddr addr = wallet->GetRecvAddr(strAccount);
		CTxCreator s_wtx(wallet, strAccount);
		s_wtx.AddOutput(addr.Get(), step);
		AddParamIfNeccessary(iface, s_wtx); /* OP_PARAM */
		_TRUE(s_wtx.Send());

		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	_TRUE(GetParamTxValue(iface, EXTPARAM_BLOCKSIZE) == 2048000);

	/* end */
	for (idx = 0; idx < 2; idx++) {
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

}

#ifdef __cplusplus
}
#endif

