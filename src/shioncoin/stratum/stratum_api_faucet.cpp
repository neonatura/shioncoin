
/*
 * @copyright
 *
 *  Copyright 2015 Brian Burrell
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

#include "shcoind.h"
#include "stratum.h"
#include "coin_proto.h"
#include "wallet.h"
#include "mnemonic.h"
#include "txcreator.h"
#include "chain.h"
#include "rpc/rpc_proto.h"

extern bool GetOutputsForAccount(CWallet *wallet, string strAccount, vector<CTxDestination>& addr_list);
extern json_spirit::Value ValueFromAmount(int64 amount);

const ApiItems& stratum_api_faucet_send(int ifaceIndex, string strAccount, shjson_t *params, string& strError, uint160 hColor)
{
	static ApiItems items;
  CWallet *wallet = GetWallet(ifaceIndex);
  Array ret;
	double dAmount;
  int64 nAmount;
  int64 nBalance;
  int nMinDepth = 1; /* single confirmation requirement */
  int nMinConfirmDepth = 1; /* single confirmation requirement */
	bool found = false;

	items.clear();

	CCoinAddr address = wallet->GetPrimaryAddr("faucet");
	//CCoinAddr address = GetAccountAddress(wallet, "faucet", false);
	if (!address.IsValid()) {
		strError = string("invalid 'faucet' account.");
		return (items);
	}

	dAmount = atof(shjson_str(params, "amount", 0));
  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount)) {
		strError = string("coin denomination");
		return (items);
  }

  nBalance  = GetAccountBalance(ifaceIndex, strAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
		strError = string("insufficient funds");
		return (items);
  }

	CTxCreator wtx(wallet, strAccount);
  CScript scriptPub;
  scriptPub.SetDestination(address.Get());
	wtx.AddOutput(scriptPub, nAmount);
	if (!wtx.Send()) {
		strError = wtx.GetError();
		return (items);
	}

	tx_cache inputs;
	Object obj = GetSendTxObj(wallet, wtx, scriptPub, inputs);
	obj.push_back(Pair("txid", wtx.GetHash().GetHex()));
	items.push_back(obj);

  return (items);
}

const ApiItems& stratum_api_faucet_recv(int ifaceIndex, string strAccount, shjson_t *params, string& strError, uint160 hColor)
{
	static ApiItems items;
	static const int nMinConfirmDepth = 1; /* single confirmation requirement */
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(ifaceIndex);
	string strFaucet("faucet");
	int64 nBalance;
	int64 nAmount;
	bool found = false;

	items.clear();

	CCoinAddr address = wallet->GetPrimaryAddr("faucet");
	//CCoinAddr address = GetAccountAddress(wallet, strAccount, false);
	if (!address.IsValid()) {
		strError = string("invalid account coin address.");
		return (items);
	}

	nBalance  = GetAccountBalance(ifaceIndex, strFaucet, nMinConfirmDepth);
	nAmount = MIN(MIN_TX_FEE(iface) * 10, roundint64(nBalance / 1000));
	if (!MoneyRange(ifaceIndex, nAmount) ||
			nAmount < MIN_INPUT_VALUE(iface)) {
		strError = string("insufficient funds");
		return (items);
	}

	CScript scriptPub;
	scriptPub.SetDestination(address.Get());

	/* check last time 'faucet' account has been used. */
	bool bKeyUsed = false;
	time_t expire_t = time(NULL) - 3600;
	for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin();
			it != wallet->mapWallet.end();
			++it)
	{
		const CWalletTx& wtx = (*it).second;
		if (wtx.GetTxTime() > expire_t) {
			BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
				if (txout.scriptPubKey == scriptPub) {
					bKeyUsed = true;
				}
			}
		}
	}
	if (bKeyUsed) {
		strError = string("receive time limit reached.");
		return (items);
	}

	CTxCreator wtx(wallet, strFaucet);
	wtx.AddOutput(scriptPub, nAmount);
	if (!wtx.Send()) {
		strError = wtx.GetError();
		return (items);
	}

	int nTxSize = (int)wallet->GetVirtualTransactionSize(wtx);

	tx_cache inputs;
	Object obj = GetSendTxObj(wallet, wtx, scriptPub, inputs);
	obj.push_back(Pair("account", strAccount));
	obj.push_back(Pair("txid", wtx.GetHash().GetHex()));
	obj.push_back(Pair("txsize", nTxSize));
	obj.push_back(Pair("value", (double)nAmount / COIN));
	items.push_back(obj);

	return (items);
}

const ApiItems& stratum_api_faucet_list(int ifaceIndex, string strAccount, shjson_t *params)
{
	string strFaucet("faucet");
	return (stratum_api_account_txlist(ifaceIndex, strFaucet, params));
}

const ApiItems& stratum_api_faucet_info(int ifaceIndex, string strAccount, shjson_t *params)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(ifaceIndex);
	int64 begin_t = shjson_num(params, "timelimit", 0);
	int64 nBalance;
	int64 nTotal;
	int64 nTime;
	string strFaucet("faucet");

	items.clear();

	nBalance = GetAccountBalance(ifaceIndex, strFaucet, 0);

	vector<CTxDestination> addr_list;
	GetOutputsForAccount(wallet, strAccount, addr_list);

	nTime = 0;
	nTotal = 0;
	for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it) {
		CWalletTx* wtx = &((*it).second);
		int64 tx_time = wtx->GetTxTime();

		if (tx_time < begin_t)
			continue;

		for (int i = 0; i < wtx->vout.size(); i++) { 
			CTxOut& out = wtx->vout[i];
			const CScript& pk = out.scriptPubKey;

			CTxDestination address;
			if (!ExtractDestination(pk, address))
				continue;

			if (!IsOutputForAccount(wallet, addr_list, address))
				continue;

			nTime = MAX(wtx->GetTxTime(), nTime);
			nTotal += out.nValue;
		}
	}

	CCoinAddr address = wallet->GetPrimaryAddr("faucet");
//	CCoinAddr address = GetAccountAddress(wallet, "faucet", false);

	int64 nAmount = 0;
	{
		string strFaucet("faucet");
	  int64 nBalance  = GetAccountBalance(ifaceIndex, strFaucet, 1);
		nAmount = MIN(MIN_TX_FEE(iface) * 10, roundint64(nBalance / 1000));
	}


	Object entry;
	entry.push_back(Pair("address", address.ToString())); 
	entry.push_back(Pair("available", ValueFromAmount(nBalance)));
	entry.push_back(Pair("spent", ValueFromAmount(nTotal)));
	entry.push_back(Pair("amount", ValueFromAmount(nAmount)));
	entry.push_back(Pair("time", (uint64_t)nTime));
	items.push_back(entry);

	return (items);
}


