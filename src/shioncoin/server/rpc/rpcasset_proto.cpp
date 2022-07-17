
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

#undef GNULIB_NAMESPACE
#include "shcoind.h"
#include "base58.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "wallet.h"
#include "txmempool.h"
#include "asset.h"
#include "asset.h"
#include "rpc_proto.h"

using namespace std;
using namespace boost;
using namespace json_spirit;

extern json_spirit::Value ValueFromAmount(int64 amount);
extern int64 AmountFromValue(const Value& value);
extern string AccountFromValue(const Value& value);
extern bool IsAccountValid(CIface *iface, std::string strAccount);

static bool fHelp = false;

Value rpc_asset_new(CIface *iface, const Array& params, bool fHelp)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int err;

	if (params.size() < 4)
		throw runtime_error("invalid parameters");

	if (ifaceIndex != TEST_COIN_IFACE &&
			ifaceIndex != TESTNET_COIN_IFACE &&
			ifaceIndex != SHC_COIN_IFACE)
		throw runtime_error("Unsupported operation for coin service.");

	string strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_INVAL, "Invalid account name specified.");

	uint160 hIssuer = uint160(params[1].get_str());
	if (hIssuer == 0)
		throw JSONRPCError(ERR_INVAL, "invalid certificate hash");

	int nType = params[2].get_int();
	int nSubType = params[3].get_int();

	string strContent = params[4].get_str();
	if (strContent.length() > CAsset::MAX_ASSET_CONTENT_LENGTH) {
		throw JSONRPCError(ERR_INVAL, "asset data payload exceeds maximum length");
	}

	int64 nMinFee = 0;
	if (params.size() > 5) {
		nMinFee = AmountFromValue(params[5]);
		if (nMinFee < 0) {
			throw JSONRPCError(-5, "Invalid coin minimum fee value.");
		}
	}

	CWalletTx wtx;
	cbuff vContent(strContent.begin(), strContent.end());
	err = init_asset_tx(iface, strAccount, hIssuer, nType, nSubType, vContent, nMinFee, wtx);
	if (err) {
		throw JSONRPCError(err, "failure initializing asset transaction.");
	}

	return (wtx.ToValue(ifaceIndex));
}

Value rpc_asset_update(CIface *iface, const Array& params, bool fHelp)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int err;

	if (params.size() != 3)
		throw runtime_error("invalid parameters");

	if (ifaceIndex != TEST_COIN_IFACE &&
			ifaceIndex != TESTNET_COIN_IFACE &&
			ifaceIndex != SHC_COIN_IFACE)
		throw runtime_error("Unsupported operation for coin service.");

	string strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_INVAL, "Invalid account name specified.");

	uint160 hAsset = uint160(params[1].get_str());
	if (hAsset == 0)
		throw JSONRPCError(ERR_INVAL, "invalid asset hash");

	string strContent = params[2].get_str();
	if (strContent.length() >= CAsset::MAX_ASSET_CONTENT_LENGTH) {
		throw JSONRPCError(ERR_INVAL, "asset data payload exceeds maximum length");
	}

	CWalletTx wtx;
	cbuff vContent(strContent.begin(), strContent.end());
	err = update_asset_tx(iface, strAccount, hAsset, vContent, wtx);
	if (err)
		throw JSONRPCError(err, "failure updating asset transaction.");

	return (wtx.ToValue(ifaceIndex));
}

Value rpc_asset_transfer(CIface *iface, const Array& params, bool fHelp)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int err;

	if (params.size() != 3)
		throw runtime_error("invalid parameters");

	if (ifaceIndex != TEST_COIN_IFACE &&
			ifaceIndex != TESTNET_COIN_IFACE &&
			ifaceIndex != SHC_COIN_IFACE)
		throw runtime_error("Unsupported operation for coin service.");

	string strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_INVAL, "Invalid account name specified.");

	uint160 hAsset = uint160(params[1].get_str());
	if (hAsset == 0)
		throw JSONRPCError(ERR_INVAL, "invalid asset hash");

	string strAddress = params[2].get_str();
	CCoinAddr addr(ifaceIndex, strAddress);
	if (!addr.IsValid())
		throw JSONRPCError(err, "Invalid coin address specified.");

	CWalletTx wtx;
	err = transfer_asset_tx(iface, strAccount, hAsset, addr, wtx);
	if (err)
		throw JSONRPCError(err, "failure updating asset transaction.");

	return (wtx.ToValue(ifaceIndex));
}

Value rpc_asset_remove(CIface *iface, const Array& params, bool fHelp)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int err;

	if (params.size() != 2)
		throw runtime_error("invalid parameters");

	if (ifaceIndex != TEST_COIN_IFACE &&
			ifaceIndex != TESTNET_COIN_IFACE &&
			ifaceIndex != SHC_COIN_IFACE)
		throw runtime_error("Unsupported operation for coin service.");

	string strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_INVAL, "Invalid account name specified.");

	uint160 hAsset = uint160(params[1].get_str());
	if (hAsset == 0)
		throw JSONRPCError(ERR_INVAL, "invalid asset hash");

	CWalletTx wtx;
	err = remove_asset_tx(iface, strAccount, hAsset, wtx);
	if (err)
		throw JSONRPCError(err, "failure removing asset transaction.");

	return (wtx.ToValue(ifaceIndex));
}

Value rpc_asset_fee(CIface *iface, const Array& params, bool fHelp)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 2)
    throw runtime_error("invalid parameters");

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != TESTNET_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

	int nSize = CAsset::MAX_ASSET_CONTENT_LENGTH;
	if (params.size() >= 1) 
		nSize = MAX(0, MIN(CAsset::MAX_ASSET_CONTENT_LENGTH, params[0].get_int()));

	time_t nLifespan = 0;
	if (params.size() >= 2)
		nLifespan = ((time_t)params[1].get_int() * 31536000);

  int64 nFee = CalculateAssetFee(iface, (int)GetBestHeight(ifaceIndex), nSize, nLifespan);
	return (ValueFromAmount(nFee));
}

Value rpc_asset_get(CIface *iface, const Array& params, bool fHelp)
{
	int ifaceIndex = GetCoinIndex(iface);

	if (fHelp || params.size() != 1)
		throw runtime_error("invalid parameters");

	if (ifaceIndex != TEST_COIN_IFACE &&
			ifaceIndex != TESTNET_COIN_IFACE &&
			ifaceIndex != SHC_COIN_IFACE)
		throw runtime_error("Unsupported operation for coin service.");

	uint160 hAsset(params[0].get_str());

	asset_list *assets = GetAssetTable(ifaceIndex);
	if (assets->count(hAsset) == 0)
		throw JSONRPCError(-5, "Invalid assetificate hash specified.");

	CTransaction tx;
	if (!GetAssetByHash(iface, hAsset, tx)) {
		uint256 hTx = (*assets)[hAsset];

		CTxMemPool *mempool = GetTxMemPool(iface);
		{
			//LOCK(mempool->cs);
			if (!mempool->exists(hTx))
				throw JSONRPCError(ERR_INVAL, "Invalid asset hash specified.");

			tx = mempool->lookup(hTx);
		}
	}

	CAsset *asset = tx.GetAsset();
	if (!asset)
		throw JSONRPCError(ERR_INVAL, "Invalid asset hash specified.");
	Object result = asset->ToValue();
	result.push_back(Pair("txid", tx.GetHash().GetHex()));

	return (result);
}

static int GetTotalAssets(int ifaceIndex)
{
  asset_list *assets = GetAssetTable(ifaceIndex);
  return (assets->size());
}

Value rpc_asset_info(CIface *iface, const Array& params, bool fHelp)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || 0 != params.size())
    throw runtime_error("invalid parameters");

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != TESTNET_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

//  int64 nFee = CalculateAssetFee(iface, (int)GetBestHeight(ifaceIndex));
  Object result;

//  result.push_back(Pair("fee", ValueFromAmount(nFee)));
  result.push_back(Pair("total", (int64_t)GetTotalAssets(ifaceIndex)));
 
  return (result);
}

Value rpc_asset_listacc(CIface *iface, const Array& params, bool fHelp)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	string kwd("");

	if (params.size() > 2)
		throw runtime_error("invalid parameters");

	if (ifaceIndex != TEST_COIN_IFACE &&
			ifaceIndex != TESTNET_COIN_IFACE &&
			ifaceIndex != SHC_COIN_IFACE)
		throw runtime_error("Unsupported operation for coin service.");

	string strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_INVAL, "Invalid account name specified.");
	if (params.size() > 1)
		kwd = params[0].get_str();

	vector<COutput> vCoins;
	string strExtAccount = "@" + strAccount; /* where asset tx's are stored */
	wallet->AvailableAccountCoins(strExtAccount, vCoins, true);

	Object result;
	asset_list *assets = GetAssetTable(ifaceIndex);
	for (asset_list::const_iterator mi = assets->begin(); mi != assets->end(); ++mi) {
		const uint160 hAsset = mi->first;
		const uint256 hTx = mi->second;
		CTransaction tx;

		if (!GetTransaction(iface, hTx, tx, NULL)) {
			CTxMemPool *mempool = GetTxMemPool(iface);
			{
				//LOCK(mempool->cs);
				if (!mempool->exists(hTx))
					continue;

				tx = mempool->lookup(hTx);
			}
		}

		/* search for output in account list */
		int i, j;
		for (i = 0; i < tx.vout.size(); i++) {
			for (j = 0; j < vCoins.size(); j++) {
				int nOut = vCoins[j].i;
				const CTxOut& out = vCoins[j].tx->vout[nOut];
				if (out == tx.vout[i])
					break;
			}
			if (j != vCoins.size())
				break;
		}
		if (i == tx.vout.size())
			continue;

		if (!IsAssetTx(tx)) {
			continue;
		}

		CAsset *asset = tx.GetAsset();
		if (!asset) continue;

		if (kwd.length() != 0) {
			if (asset->GetLabel().find(kwd) == std::string::npos)
				continue;
		}

		result.push_back(Pair(asset->GetLabel().c_str(), hAsset.GetHex()));
	}

	return (result);
}

Value rpc_asset_listcert(CIface *iface, const Array& params, bool fHelp)
{
  int ifaceIndex = GetCoinIndex(iface);
	string kwd("");

  if (fHelp || params.size() > 2)
    throw runtime_error("invalid parameters");

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != TESTNET_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

	uint160 hCert(params[0].get_str());
	if (hCert == 0)
    throw JSONRPCError(ERR_INVAL, "invalid certificate hash");
  if (params.size() > 1)
    kwd = params[0].get_str();

  asset_list *assets = GetAssetTable(ifaceIndex);

  Object result;
  for (asset_list::const_iterator mi = assets->begin(); mi != assets->end(); ++mi) {
    const uint160 hAsset = mi->first;
    const uint256 hTx = mi->second;
    CTransaction tx;

    if (!GetTransaction(iface, hTx, tx, NULL)) {
      CTxMemPool *mempool = GetTxMemPool(iface);
      {
        //LOCK(mempool->cs);
        if (!mempool->exists(hTx))
          continue;

        tx = mempool->lookup(hTx);
      }
    }

    if (!IsAssetTx(tx)) {
      continue;
    }

		CAsset *asset = tx.GetAsset();
		if (!asset) continue;

		if (uint160(asset->vAddr) != hCert)
			continue;

    if (kwd.length() != 0) {
      if (asset->GetLabel().find(kwd) == std::string::npos)
        continue;
    }

    result.push_back(Pair(asset->GetLabel().c_str(), hAsset.GetHex()));
  }

  return (result);
}

Value rpc_asset_list(CIface *iface, const Array& params, bool fHelp)
{
	int ifaceIndex = GetCoinIndex(iface);
	string kwd("");

	if (fHelp || params.size() > 1)
		throw runtime_error("invalid parameters");

	if (params.size() > 0)
		kwd = params[0].get_str();

	if (ifaceIndex != TEST_COIN_IFACE &&
			ifaceIndex != TESTNET_COIN_IFACE &&
			ifaceIndex != SHC_COIN_IFACE)
		throw runtime_error("Unsupported operation for coin service.");

	asset_list *assets = GetAssetTable(ifaceIndex);

	Object result;
	for (asset_list::const_iterator mi = assets->begin(); mi != assets->end(); ++mi) {
		const uint160 hAsset = mi->first;
		const uint256 hTx = mi->second;
		CTransaction tx;

		if (!GetTransaction(iface, hTx, tx, NULL)) {
			CTxMemPool *mempool = GetTxMemPool(iface);
			{
				//LOCK(mempool->cs);
				if (!mempool->exists(hTx))
					continue;

				tx = mempool->lookup(hTx);
			}
		}

		if (!IsAssetTx(tx)) {
			continue;
		}

		CAsset *asset = tx.GetAsset();
		if (!asset) continue;

		if (kwd.length() != 0) {
			if (asset->GetLabel().find(kwd) == std::string::npos)
				continue;
		}

		result.push_back(Pair(asset->GetLabel().c_str(), hAsset.GetHex()));
	}

	return (result);
}

Value rpc_asset_newcert(CIface *iface, const Array& params, bool fStratum) 
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	string hexSeed;
	int64 nFee = 0;
  int err;

  if (params.size() < 2)
    throw runtime_error("invalid parameters");

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != TESTNET_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

  string strAccount = AccountFromValue(params[0]);
  if (!IsAccountValid(iface, strAccount))
    throw JSONRPCError(SHERR_INVAL, "Invalid account name specified.");

  string strTitle = params[1].get_str();
  if (strTitle.length() == 0 || strTitle.length() > 135)
    throw JSONRPCError(-5, "Certificate name must be between 1 and 135 characters.");

  if (wallet->mapCertLabel.count(strTitle))
    throw JSONRPCError(-5, "Certificate name must be unique.");

  CWalletTx wtx;
  err = init_cert_tx(iface, wtx, strAccount, strTitle, hexSeed, nFee);
  if (err)
    throw JSONRPCError(err, "Failure initializing transaction.");

  return (wtx.ToValue(ifaceIndex));
}

Value rpc_asset_activate(CIface *iface, const Array& params, bool fHelp)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int err;

	if (params.size() < 2)
		throw runtime_error("invalid parameters");

	if (ifaceIndex != TEST_COIN_IFACE &&
			ifaceIndex != TESTNET_COIN_IFACE &&
			ifaceIndex != SHC_COIN_IFACE)
		throw runtime_error("Unsupported operation for coin service.");

	string strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_INVAL, "Invalid account name specified.");

	uint160 hAsset = uint160(params[1].get_str());
	if (hAsset == 0)
		throw JSONRPCError(ERR_INVAL, "invalid asset hash");

	int64 nMinFee = 0; 
	if (params.size() > 2) {
		nMinFee = AmountFromValue(params[2]); 
	}

	CWalletTx wtx;
	err = activate_asset_tx(iface, strAccount, hAsset, nMinFee, wtx);
	if (err)
		throw JSONRPCError(err, "failure updating asset transaction.");

	return (wtx.ToValue(ifaceIndex));
}

