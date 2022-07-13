
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
#include "asset.h"

#ifdef __cplusplus
extern "C" {
#endif


_TEST(sip25_assettx)
{
	char buf[256];
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  int idx;
  int err;

  string strLabel("");
	memset(buf, 0, sizeof(buf));

  /* create a coin balance */
  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CCoinAddr addr = GetAccountAddress(wallet, strLabel);//, false);
  _TRUE(addr.IsValid() == true);

  CCoinAddr extAddr = wallet->GetExtAddr(strLabel);
  _TRUE(extAddr.IsValid() == true);

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
	strcpy(buf, "asset content");
	cbuff data(buf, buf + (strlen(buf) + 1));
  err = init_asset_tx(iface, strLabel, hashCert, AssetType::DATA, data, 0, wtx);
  _TRUE(0 == err);
  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyAsset(wtx) == true);
  CAsset *asset = wtx.GetAsset();
	_TRUEPTR(asset);
  uint160 hashAsset = asset->GetHash();
  _TRUE(asset->VerifyContent(TEST_COIN_IFACE));
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
	for (int i = 0; i < 2; i++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	/* verify asset content. */
	cbuff cmpData;
	_TRUE(GetAssetContent(iface, wtx, cmpData));
	_TRUE(data == cmpData);



	/* perform asset update. */
	CWalletTx u_wtx(wallet);
	strcpy(buf, "updated asset content");
	cbuff updateData(buf, buf + (strlen(buf) + 1));
  err = update_asset_tx(iface, strLabel, hashAsset, updateData, u_wtx);
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

	cbuff cmpData2;
	_TRUE(GetAssetContent(iface, u_tx, cmpData2));



	string xferStrLabel("asset");
  CCoinAddr xferAddr = GetAccountAddress(wallet, xferStrLabel);//, false);
  _TRUE(addr.IsValid() == true);
  CCoinAddr xferExtAddr = wallet->GetExtAddr(xferStrLabel);

	/* send to extended tx storage account */
  CScript scriptPubKey;
  scriptPubKey.SetDestination(xferAddr.Get());
  for (idx = 0; idx < 3; idx++) {
    CTxCreator s_wtx(wallet, strLabel);
    _TRUE(s_wtx.AddOutput(scriptPubKey, COIN));
    _TRUE(s_wtx.Send());
    _TRUE(s_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  }

	/* perform asset update. */
	CWalletTx x_wtx(wallet);
  err = transfer_asset_tx(iface, strLabel, hashAsset, xferExtAddr, x_wtx);
  _TRUE(0 == err);
  _TRUE(x_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyAsset(x_wtx) == true);
  _TRUE(x_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
	for (int i = 0; i < 2; i++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  _TRUE(x_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	/* verify asset transfer */
	CTransaction x_tx;
	_TRUE(GetTxOfAsset(iface, hashAsset, x_tx) == true); 
	CAsset *x_asset = x_tx.GetAsset();
	_TRUEPTR(x_asset);
	_TRUE(x_asset->GetHash() == x_wtx.GetAsset()->GetHash());



	/* perform asset removal. */
	CWalletTx r_wtx(wallet);
  err = remove_asset_tx(iface, xferStrLabel, hashAsset, r_wtx);
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
	CTransaction r2_tx;
	_TRUE(GetTxOfAsset(iface, hashAsset, r2_tx) == true);
	_TRUE(r2_tx.GetAsset()->GetHash() == x_tx.GetAsset()->GetHash());

}

_TEST(sip25_di_assettx)
{
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);
	CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	string strLabel("");
	char buf[256];
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
	strcpy(buf, "asset content");
	cbuff data(buf, buf + (strlen(buf) + 1));
	err = init_asset_tx(iface, strLabel, hashCert, AssetType::DATA, data, 0, wtx);
	_TRUE(0 == err);
	_TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(VerifyAsset(wtx) == true);
	CAsset *asset = wtx.GetAsset();
	_TRUEPTR(asset);
	uint160 hashAsset = asset->GetHash();
	_TRUE(asset->VerifyContent(TEST_COIN_IFACE));
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
	strcpy(buf, "updated asset content");
	cbuff updateData(buf, buf + (strlen(buf) + 1));
	err = update_asset_tx(iface, strLabel, hashAsset, updateData, u_wtx);
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
