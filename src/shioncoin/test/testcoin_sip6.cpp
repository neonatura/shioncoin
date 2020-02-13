
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
#include "script.h"
#include "txsignature.h"





#ifdef __cplusplus
extern "C" {
#endif

_TEST(sip6_aliastx)
{
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);
	CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	int idx;
	int err;

	string strLabel("");

	/* create a coin balance */
	for (idx = 0; idx < 2; idx++) {
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	CCoinAddr addr = GetAccountAddress(wallet, strLabel);//, false);
	_TRUE(addr.IsValid() == true);

	CWalletTx wtx;
	err = init_alias_addr_tx(iface, "test", addr, wtx);
	_TRUE(0 == err);

	_TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyAlias(wtx) == true);

	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	/* update */

	CWalletTx mod_wtx;
	err = update_alias_addr_tx(iface, "test", addr, mod_wtx);
	_TRUE(0 == err);
	_TRUE(mod_wtx.CheckTransaction(TEST_COIN_IFACE) == true); /* .. */
	_TRUE(VerifyAlias(mod_wtx) == true);
	_TRUE(mod_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

	/* insert into block-chain */
	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	_TRUE(mod_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	CTransaction t_tx;
	string strTitle("test");
	_TRUE(GetTxOfAlias(iface, strTitle, t_tx) == true);

	/* remove */

	CWalletTx rem_wtx;
	err = remove_alias_addr_tx(iface, strLabel, strTitle, rem_wtx);
	_TRUE(0 == err);
	_TRUE(rem_wtx.CheckTransaction(TEST_COIN_IFACE) == true); /* .. */
	_TRUE(VerifyAlias(rem_wtx) == true);
	_TRUE(rem_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

	/* insert into block-chain */
	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	_TRUE(rem_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);
	_TRUE(GetTxOfAlias(iface, strTitle, t_tx) == false);
}

_TEST(sip6_di_aliastx)
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

	CCoinAddr addr = GetAccountAddress(wallet, strLabel);
	_TRUE(addr.IsValid() == true);

	CWalletTx wtx;
	err = init_alias_addr_tx(iface, "test", addr, wtx);
	_TRUE(0 == err);

	_TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyAlias(wtx) == true);

	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	/* update */
	CWalletTx mod_wtx;
	err = update_alias_addr_tx(iface, "test", addr, mod_wtx);
	_TRUE(0 == err);
	_TRUE(mod_wtx.CheckTransaction(TEST_COIN_IFACE) == true); /* .. */
	_TRUE(VerifyAlias(mod_wtx) == true);
	_TRUE(mod_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

	/* insert into block-chain */
	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	_TRUE(mod_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	CTransaction t_tx;
	string strTitle("test");
	_TRUE(GetTxOfAlias(iface, strTitle, t_tx) == true);

}

#ifdef __cplusplus
}
#endif
