
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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
#include "test/test_pool.h"
#include "test/test_block.h"
#include "test/test_txidx.h"
#include "script.h"
#include "txsignature.h"

#ifdef __cplusplus
extern "C" {
#endif

_TEST(sip5_certtx)
{
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);
	CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	string strLabel("");
	int idx;
	int err;

	/* create a coin balance */
	for (idx = 0; idx < 2; idx++) {
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	CWalletTx wtx;
	unsigned int nBestHeight = GetBestHeight(iface) + 1;
	{
		string hexSeed;
		err = init_cert_tx(iface, wtx, strLabel, "SHCOIND TEST CA", hexSeed, 1);
		_TRUE(0 == err);
	}
	uint160 hashCert = wtx.certificate.GetHash();

	_TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyCert(iface, wtx, nBestHeight) == true);
	_TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

	/* insert cert into chain */
	for (idx = 0; idx < 2; idx++) {
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	/* verify insertion */
	CTransaction t_tx;
	_TRUE(GetTxOfCert(iface, hashCert, t_tx) == true);
	_TRUE(t_tx.GetHash() == wtx.GetHash());
	_TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);


	/* chained certificate */
	CWalletTx chain_wtx;
	string strTitle("SHCOIND TEST CHAIN");
	err = derive_cert_tx(iface, chain_wtx, hashCert, strLabel, strTitle);
	_TRUE(err == 0);
	_TRUE(chain_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyCert(iface, chain_wtx, nBestHeight) == true);
	_TRUE(chain_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

	for (unsigned int i = 0; i < 3; i++) { /* insert derived cert into chain */
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	/* verify insertion */
	t_tx.SetNull();
	hashCert = chain_wtx.certificate.GetHash();
	_TRUE(GetTxOfCert(iface, hashCert, t_tx) == true);
	_TRUE(t_tx.GetHash() == chain_wtx.GetHash());
	_TRUE(chain_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	/* generate test license from certificate */
	CWalletTx lic_wtx;
	err = init_license_tx(iface, strLabel, hashCert, lic_wtx);
	_TRUE(0 == err);

	_TRUE(lic_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyLicense(lic_wtx) == true);
	CLicense lic(lic_wtx.certificate);
	uint160 licHash = lic.GetHash();

	_TRUE(lic_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
	/* insert license */
	for (idx = 0; idx < 2; idx++) {
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}
	_TRUE(lic_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	/* verify insertion */
	CTransaction t2_tx;
	_TRUE(GetTxOfLicense(iface, licHash, t2_tx) == true);

}

_TEST(sip5_di_certtx)
{
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);
	CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	string strLabel("");
	int idx;
	int err;

	opt_bool_set(OPT_DILITHIUM, TRUE);
	opt_bool_set(OPT_BECH32, TRUE);

	/* create a coin balance */
	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	CWalletTx wtx;
	unsigned int nBestHeight = GetBestHeight(iface) + 1;
	{
		string hexSeed;
		err = init_cert_tx(iface, wtx, strLabel, "SHCOIND DILITHIUM TEST CA", hexSeed, 1);
		_TRUE(0 == err);
	}
	uint160 hashCert = wtx.certificate.GetHash();

	_TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyCert(iface, wtx, nBestHeight) == true);
	_TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

	/* insert cert into chain */
	for (idx = 0; idx < 2; idx++) {
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	/* verify insertion */
	CTransaction t_tx;
	_TRUE(GetTxOfCert(iface, hashCert, t_tx) == true);
	_TRUE(t_tx.GetHash() == wtx.GetHash());
	_TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);


	/* chained certificate */
	CWalletTx chain_wtx;
	string strTitle("SHCOIND DILITHIUM TEST CHAIN");
	err = derive_cert_tx(iface, chain_wtx, hashCert, strLabel, strTitle);
	_TRUE(err == 0);
	_TRUE(chain_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyCert(iface, chain_wtx, nBestHeight) == true);
	_TRUE(chain_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

	for (unsigned int i = 0; i < 3; i++) { /* insert derived cert into chain */
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	/* verify insertion */
	t_tx.SetNull();
	hashCert = chain_wtx.certificate.GetHash();
	_TRUE(GetTxOfCert(iface, hashCert, t_tx) == true);
	_TRUE(t_tx.GetHash() == chain_wtx.GetHash());
	_TRUE(chain_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

}

#ifdef __cplusplus
}
#endif

