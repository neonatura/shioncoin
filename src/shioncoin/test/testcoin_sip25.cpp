
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
#include "asset.h"

#ifdef __cplusplus
extern "C" {
#endif


_TEST(sip25_assettx)
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

	/* create certificate */
  CWalletTx cert_wtx;
	string hexSeed;
	err = init_cert_tx(iface, cert_wtx, strLabel, "asset", hexSeed, 1);
	_TRUE(0 == err);
  uint160 hashCert = cert_wtx.certificate.GetHash();
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CWalletTx wtx;
  err = init_asset_tx(iface, strLabel, hashCert, "test", addr.ToString(), wtx);
  _TRUE(0 == err);
  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyAsset(wtx) == true);
  CAsset *asset = wtx.GetAsset();
	_TRUEPTR(asset);
  uint160 hashAsset = asset->GetHash();
  _TRUE(asset->VerifySignature(TEST_COIN_IFACE));
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
	for (int i = 0; i < 2; i++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	/* perform asset update. */
	CWalletTx u_wtx(wallet);
  err = update_asset_tx(iface, strLabel, hashAsset, "test", "updated data", u_wtx);
  _TRUE(0 == err);
  _TRUE(u_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyAsset(u_wtx) == true);
  _TRUE(u_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
	for (int i = 0; i < 2; i++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  _TRUE(u_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);


	/* verify asset update */
	CTransaction u_tx;
	_TRUE(GetTxOfAsset(iface, hashAsset, u_tx) == true); 
	CAsset *u_asset = u_tx.GetAsset();
	_TRUEPTR(u_asset);
	_TRUE(u_asset->GetHash() == u_wtx.GetAsset()->GetHash());



	/* perform asset removal. */
	CWalletTx r_wtx(wallet);
  err = remove_asset_tx(iface, strLabel, hashAsset, r_wtx);
  _TRUE(0 == err);
  _TRUE(r_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyAsset(r_wtx) == true);
  _TRUE(r_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
	{
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  _TRUE(r_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	/* verify asset removal */
	CTransaction r_tx;
	_TRUE(GetTxOfAsset(iface, hashAsset, r_tx) == false);

	/* fall back to previous. */
	_TRUE(DisconnectAssetTx(iface, r_wtx) == true);
	CTransaction u2_tx;
	_TRUE(GetTxOfAsset(iface, hashAsset, u2_tx) == true);
	_TRUE(u2_tx.GetAsset()->GetHash() == u_tx.GetAsset()->GetHash());

}

_TEST(sip25_di_assettx)
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

	CCoinAddr addr = GetAccountAddress(wallet, strLabel);
	_TRUE(addr.IsValid() == true);

	/* create certificate */
	CWalletTx cert_wtx;
	string hexSeed;
	err = init_cert_tx(iface, cert_wtx, strLabel, "dilithium_asset", hexSeed, 1);
	_TRUE(0 == err);
	uint160 hashCert = cert_wtx.certificate.GetHash();
	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	/* create asset derivative */
	CWalletTx wtx;
	err = init_asset_tx(iface, strLabel, hashCert, "dilithium_test", addr.ToString(), wtx);
	_TRUE(0 == err);
	_TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyAsset(wtx) == true);
	CAsset *asset = wtx.GetAsset();
	_TRUEPTR(asset);
	uint160 hashAsset = asset->GetHash();
	_TRUE(asset->VerifySignature(TEST_COIN_IFACE));
	_TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
	for (int i = 0; i < 2; i++) {
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}
	_TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	/* perform asset update. */
	CWalletTx u_wtx(wallet);
	err = update_asset_tx(iface, strLabel, hashAsset, "dilithium_test", "updated data", u_wtx);
	_TRUE(0 == err);
	_TRUE(u_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
	for (int i = 0; i < 2; i++) {
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}
	_TRUE(u_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	/* verify asset update */
	CTransaction u_tx;
	_TRUE(GetTxOfAsset(iface, hashAsset, u_tx) == true); 
	CAsset *u_asset = u_tx.GetAsset();
	_TRUEPTR(u_asset);
	_TRUE(u_asset->GetHash() == u_wtx.GetAsset()->GetHash());
	_TRUE(u_tx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyAsset(u_tx) == true);

}

#ifdef __cplusplus
}
#endif
