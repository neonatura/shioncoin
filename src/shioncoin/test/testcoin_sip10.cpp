
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
#include "account.h"
#include "txcreator.h"
#include "bech32.h"
#include "test/test_pool.h"
#include "test/test_block.h"
#include "test/test_txidx.h"
#include "context.h"


#ifdef __cplusplus
extern "C" {
#endif

_TEST(sip10_ctxtx)
{
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);
	CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	shgeo_t geo;
	int idx;
	int err;

	string strLabel("");

	for (idx = 0; idx < 3; idx++) {
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}
	int64 bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);

	CWalletTx wtx;
	int nBestHeight = GetBestHeight(iface) + 1;
	{
		const char *payload = "test context value";
		string strName = "test context name";
		cbuff vchValue(payload, payload + strlen(payload));
		err = init_ctx_tx(iface, wtx, strLabel, strName, vchValue);
		_TRUE(0 == err);
	}
	CContext ctx(wtx.certificate);
	uint160 hashContext = ctx.GetHash();

	_TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyContextTx(iface, wtx, nBestHeight) == true);
	_TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

	/* insert ctx into chain + create a coin balance */
	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	/* verify insertion */
	CTransaction t_tx;
	_TRUEPTR(GetContextByHash(iface, hashContext, t_tx));
	_TRUE(t_tx.GetHash() == wtx.GetHash());
	_TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	/* test geodetic context */
	shgeo_set(&geo, 46.7467, -114.1096, 0);
	string strName = "geo:46.7467,-114.1096";
	const char *payload = "{\"name\":\"mountain\",\"code\":\"AREA\"}";
	cbuff vchValue(payload, payload + strlen(payload));
	err = init_ctx_tx(iface, wtx, strLabel, strName, vchValue, &geo);
	_TRUE(err == 0);

	/* insert ctx into chain + create a coin balance */
	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

}

_TEST(sip10_di_ctxtx)
{
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);
	CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	string strLabel("");
	int idx;
	int err;

	opt_bool_set(OPT_DILITHIUM, TRUE);
	opt_bool_set(OPT_BECH32, TRUE);

	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	CWalletTx wtx;
	int64 bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
	int nBestHeight = GetBestHeight(iface) + 1;
	{
		const char *payload = "dilithium test context value";
		string strName = "dilithium test context name";
		cbuff vchValue(payload, payload + strlen(payload));
		err = init_ctx_tx(iface, wtx, strLabel, strName, vchValue);
		_TRUE(0 == err);
	}
	CContext ctx(wtx.certificate);
	uint160 hashContext = ctx.GetHash();

	_TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyContextTx(iface, wtx, nBestHeight) == true);
	_TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

	/* insert ctx into chain + create a coin balance */
	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	/* verify insertion */
	CTransaction t_tx;
	_TRUEPTR(GetContextByHash(iface, hashContext, t_tx));
	_TRUE(t_tx.GetHash() == wtx.GetHash());
	_TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

}

#ifdef __cplusplus
}
#endif

