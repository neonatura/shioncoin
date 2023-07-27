
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

#ifdef __cplusplus
extern "C" {
#endif


_TEST(sip25_assettx)
{
	char *buf;
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
	buf = strdup("asset content");
	cbuff data(buf, buf + (strlen(buf) + 1));
  err = init_asset_tx(iface, strLabel, hashCert, AssetType::DATA, 0, data, 0, wtx);
	free(buf);
  _TRUE(0 == err);
  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(wtx.VerifyAsset(TEST_COIN_IFACE) == true);
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



	buf = (char *)calloc(120000, sizeof(char));
	memset(buf, 'a', 119999);
	cbuff updateData(buf, buf + (strlen(buf) + 1));
	free(buf);

	/* perform asset update. */
	CWalletTx u_wtx(wallet);
  err = update_asset_tx(iface, strLabel, hashAsset, updateData, u_wtx);
  _TRUE(0 == err);
  _TRUE(u_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(u_wtx.VerifyAsset(TEST_COIN_IFACE) == true);
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
	_TRUEPTR(GetAssetByHash(iface, hashAsset, u_tx));
	CAsset *u_asset = u_tx.GetAsset();
	_TRUEPTR(u_asset);
	_TRUE(u_asset->GetHash() == u_wtx.GetAsset()->GetHash());

	cbuff cmpData2;
	_TRUE(GetAssetContent(iface, u_tx, cmpData2));
	_TRUE(cmpData2 == updateData);



	string xferStrLabel("asset");
  CCoinAddr xferAddr = GetAccountAddress(wallet, xferStrLabel);//, false);
  _TRUE(addr.IsValid() == true);
  CCoinAddr xferExtAddr = wallet->GetExtAddr(xferStrLabel);

	/* send to extended tx storage account */
  CScript scriptPubKey;
  scriptPubKey.SetDestination(xferAddr.Get());
  for (idx = 0; idx < 5; idx++) {
    CTxCreator s_wtx(wallet, strLabel);
    _TRUE(s_wtx.AddOutput(scriptPubKey, COIN * 100));
    _TRUE(s_wtx.Send());
    _TRUE(s_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  }

	/* perform asset transfer. */
	CWalletTx x_wtx(wallet);
  err = transfer_asset_tx(iface, strLabel, hashAsset, xferExtAddr, x_wtx);
  _TRUE(0 == err);
  _TRUE(x_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(x_wtx.VerifyAsset(TEST_COIN_IFACE) == true);
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
	_TRUEPTR(GetAssetByHash(iface, hashAsset, x_tx));
	CAsset *x_asset = x_tx.GetAsset();
	_TRUEPTR(x_asset);
	_TRUE(x_asset->GetHash() == x_wtx.GetAsset()->GetHash());





	/* perform asset renewal. */
	CWalletTx a_wtx(wallet);
  err = activate_asset_tx(iface, xferStrLabel, hashAsset, 0, a_wtx);
  _TRUE(0 == err);
  _TRUE(a_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(a_wtx.VerifyAsset(TEST_COIN_IFACE) == true);
  _TRUE(a_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
	for (int i = 0; i < 2; i++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  _TRUE(a_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

	/* verify asset renewal. */
	CTransaction a_tx;
	_TRUEPTR(GetAssetByHash(iface, hashAsset, a_tx));
	CAsset *a_asset = a_tx.GetAsset();
	_TRUEPTR(a_asset);
	_TRUE(a_asset->GetHash() == a_wtx.GetAsset()->GetHash());
	_TRUE(a_asset->VerifyContentChecksum() == true);

	cbuff cmpData3;
	_TRUE(GetAssetContent(iface, a_tx, cmpData3));
	_TRUE(cmpData2 == cmpData3);




	/* perform asset removal. */
	CWalletTx r_wtx(wallet);
  err = remove_asset_tx(iface, xferStrLabel, hashAsset, r_wtx);
  _TRUE(0 == err);
  _TRUE(r_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(r_wtx.VerifyAsset(TEST_COIN_IFACE) == true);
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
	_TRUE(GetAssetByHash(iface, hashAsset, r_tx) == NULL);



	/* fall back to previous. */
	_TRUE(DisconnectAssetTx(iface, r_wtx) == true);
	CTransaction r2_tx;
	_TRUEPTR(GetAssetByHash(iface, hashAsset, r2_tx));
	_TRUE(r2_tx.GetAsset()->GetHash() == a_tx.GetAsset()->GetHash());




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
	strcpy(buf, "di asset content");
	cbuff data(buf, buf + (strlen(buf) + 1));
	err = init_asset_tx(iface, strLabel, hashCert, AssetType::DATA, 0, data, 0, wtx);
	_TRUE(0 == err);
	_TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(wtx.VerifyAsset(TEST_COIN_IFACE) == true);
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
	strcpy(buf, "di updated asset content");
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
	_TRUEPTR(GetAssetByHash(iface, hashAsset, u_tx));
	CAsset *u_asset = u_tx.GetAsset();
	_TRUEPTR(u_asset);
	_TRUE(u_asset->GetHash() == u_wtx.GetAsset()->GetHash());
	_TRUE(u_tx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
	_TRUE(u_tx.VerifyAsset(TEST_COIN_IFACE) == true);

}

#ifdef __cplusplus
}
#endif
