
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
#include "coin_proto.h"
#include "rpc/rpc_proto.h"
#include "shapi/shapi.h"
#include "wallet.h"
#include "account.h"
#include "mnemonic.h"
#include "txcreator.h"
#include "chain.h"
#include "txmempool.h"
#include "txfeerate.h"
#include "color/color_pool.h"
#include "color/color_block.h"
#include "stratum/stratum.h"

#define MAX_API_LIST_ITEMS 25
#ifndef DEFAULT_OFFER_LIFESPAN
#define DEFAULT_OFFER_LIFESPAN 1440
#endif

extern json_spirit::Value ValueFromAmount(int64 amount);
extern exec_list *GetExecTable(int ifaceIndex);
extern altchain_list *GetAltChainTable(int ifaceIndex);
extern offer_list *GetOfferTable(int ifaceIndex);
extern bool IsContextName(CIface *iface, string strName);
extern double print_rpc_difficulty(CBigNum val);
extern unsigned int GetDailyTxRate(CIface *iface); /* rpc_command.cpp */
extern double GetAverageBlockSpan(CIface *iface);
extern Value GetNetworkHashPS(int ifaceIndex, int lookup); /* rpc_parse.cpp */ 

static std::string HexBits(unsigned int nBits)
{
	union {
		int32_t nBits;
		char cBits[4];
	} uBits;
	uBits.nBits = htonl((int32_t)nBits);
	return HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}

static bool SHAPI_GetOutputsForAccount(CWallet *wallet, string strAccount, vector<CTxDestination>& addr_list)
{

	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook) {
		const string& account = item.second;
		if (account != strAccount)
			continue;

		addr_list.push_back(item.first);
	}

	return (FALSE);
}

static bool SHAPI_IsOutputForAccount(CWallet *wallet, vector<CTxDestination> addr_list, CTxDestination address)
{
	int i;
	
	for (i = 0; i < addr_list.size(); i++) {
		if (address == addr_list[i])
			return (true);
	}

	return (FALSE);
}

static uint256 get_private_key_hash(CWallet *wallet, CKeyID keyId)
{
	CSecret vchSecret;
	bool fCompressed;
	uint256 phash;

	if (!wallet->GetSecret(keyId, vchSecret, fCompressed))
		return (phash);

	CCoinSecret sec(wallet->ifaceIndex, vchSecret, fCompressed);
	if (!sec.IsValid()) {
		error(SHERR_INVAL, "get_private_key_hash: invalid secret for keyid '%s'.", keyId.ToString().c_str());
		return (phash);
	}

	string secret = sec.ToString();
	unsigned char *secret_str = (unsigned char *)secret.c_str();
	size_t secret_len = secret.length();
	SHA256(secret_str, secret_len, (unsigned char*)&phash);

	return (phash);
}

static bool valid_pkey_hash(const string strAccount, uint256 in_pkey)
{
	CWallet *wallet;
	uint256 acc_pkey;
	int valid;
	int idx;

	if (in_pkey == 0)
		return (false); /* sanity */

	for (idx = 0; idx < MAX_COIN_IFACE; idx++) {
		CWallet *alt_wallet = GetWallet(idx);
		if (!alt_wallet) continue;

		BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, alt_wallet->mapAddressBook) {
			const CCoinAddr& address = CCoinAddr(idx, item.first);
			const string& strName = item.second;
			CKeyID keyID;

			if (strName != strAccount)
				continue;

			if (!address.GetKeyID(keyID))
				continue;

			acc_pkey = get_private_key_hash(alt_wallet, keyID);
			if (acc_pkey == in_pkey)
				return (true);
		}
	}

	return (false);
}

static bool VerifyAccountName(CWallet *wallet, string strAccount)
{
  CCoinAddr address(wallet->ifaceIndex);

  /* Find all addresses that have the given account name. */
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook) {
    const string& strName = item.second;
    if (strName == strAccount) {
      address = CCoinAddr(wallet->ifaceIndex, item.first);
      if (!address.IsValid())
        continue;

			return (true);
    }
  }

	return (false);
}

static const ApiItems& shapi_api_account_create(int ifaceIndex, string strAccount, shjson_t *params, string& strError)
{
	static ApiItems items;
  CWallet *wallet = GetWallet(ifaceIndex);
  string coinAddr = "";
  uint256 phash = 0;
  CPubKey newKey;
  bool found;
  int idx;

	items.clear();

	if (strAccount.length() <= 1 || strAccount.length() > 135 ||
			!std::isalnum(strAccount[0])) {
		strError = "invalid account name";
		return (items);
	}

	/* check for duplicate against all coin services. */
	for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
		CWallet *wallet = GetWallet(idx); 
		if (!wallet)
			continue;

		if (VerifyAccountName(wallet, strAccount)) {
			strError = "account name is not unique.";
			return (items);
		}
	}

	/* generate new account for all coin services. */
	for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
		CWallet *alt_wallet = GetWallet(idx); 
		if (!alt_wallet)
			continue;

#if 0
		newKey = GetAccountPubKey(alt_wallet, strAccount, true);
		CKeyID keyId = newKey.GetID();
		alt_wallet->SetAddressBookName(keyId, strAccount);
		if (ifaceIndex == idx) {
			coinAddr = CCoinAddr(ifaceIndex, keyId).ToString();
			phash = get_private_key_hash(alt_wallet, keyId);
		}
#endif

		CPubKey pubkey;
		CAccountCache *acc = alt_wallet->GetAccount(strAccount);
		if (!acc->CreateNewPubKey(pubkey, 0))
			continue;
		const CKeyID& keyID = pubkey.GetID();

		if (ifaceIndex == idx) {
			CCoinAddr addrNew(ifaceIndex, keyID);
			coinAddr = addrNew.ToString();
			phash = get_private_key_hash(alt_wallet, keyID);
		}
	}

  Object result;
  result.push_back(Pair("address", coinAddr));
  result.push_back(Pair("api_id", strAccount));
  result.push_back(Pair("api_key", phash.GetHex()));
	items.push_back(result);

	return (items);
}

static const ApiItems& shapi_api_account_list(int ifaceIndex, string strAccount, shjson_t *params)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(iface);
	int64 now = (int64)time(NULL);
	int64 nUBal;
	int64 nBal;

	items.clear();

	nUBal = GetAccountBalance(ifaceIndex, strAccount, 0);
	nBal = GetAccountBalance(ifaceIndex, strAccount, 1);

	Object entry;
	entry.push_back(Pair("balance", ValueFromAmount(nUBal)));
	entry.push_back(Pair("available", ValueFromAmount(nBal)));
	entry.push_back(Pair("unconfirmed", ValueFromAmount(nUBal - nBal)));
	items.push_back(entry);

	return (items);
}

#if 0
const ApiItems& shapi_api_account_txlist(int ifaceIndex, string strAccount, shjson_t *params)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(ifaceIndex);
	int64 begin_t = shjson_num(params, "timelimit", 0);
	tx_cache inputs;

	items.clear();

	vector<CTxDestination> addr_list;
	SHAPI_GetOutputsForAccount(wallet, strAccount, addr_list);

	inputs.clear();
	for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it) {
		CWalletTx* wtx = &((*it).second);
		int64 tx_time = wtx->GetTxTime();

		if (tx_time < begin_t)
			continue;

		inputs.clear();
		if (wallet->FillInputs(*wtx, inputs, true)) {
			for (int i = 0; i < wtx->vin.size(); i++) { 
				CTxIn& in = wtx->vin[i];

				if (inputs.count(in.prevout.hash) == 0)
					continue;

				const CTransaction& tx = inputs[in.prevout.hash]; 
				const CTxOut& out = tx.vout[in.prevout.n];
				const CScript& pk = out.scriptPubKey;
				CTxDestination address;

				if (!ExtractDestination(pk, address))
					continue;

				if (!SHAPI_IsOutputForAccount(wallet, addr_list, address))
					continue;

				CCoinAddr c_addr(ifaceIndex, address);

				Object entry;
				entry.push_back(Pair("address", c_addr.ToString())); 
				entry.push_back(Pair("amount", ValueFromAmount(-1 * out.nValue)));
//				entry.push_back(Pair("hash", wtx->GetWitnessHash().GetHex()));
				entry.push_back(Pair("txid", wtx->GetHash().GetHex()));
				entry.push_back(Pair("n", i));
				entry.push_back(Pair("time", (uint64_t)wtx->GetTxTime()));

				items.push_back(entry);
			}
		}

		for (int i = 0; i < wtx->vout.size(); i++) { 
			CTxOut& out = wtx->vout[i];
			const CScript& pk = out.scriptPubKey;

			CTxDestination address;
			if (!ExtractDestination(pk, address))
				continue;

			if (!SHAPI_IsOutputForAccount(wallet, addr_list, address))
				continue;

			CCoinAddr c_addr(ifaceIndex, address);

			Object entry;
			entry.push_back(Pair("address", c_addr.ToString())); 
			entry.push_back(Pair("amount",ValueFromAmount(out.nValue)));
//			entry.push_back(Pair("hash", wtx->GetWitnessHash().GetHex()));
			entry.push_back(Pair("txid", wtx->GetHash().GetHex()));
			entry.push_back(Pair("n", i));
			entry.push_back(Pair("time", (uint64_t)wtx->GetTxTime()));

			items.push_back(entry);
		}
	}

	return (items);
}
#endif
const ApiItems& shapi_api_account_txlist(int ifaceIndex, string strAccount, shjson_t *params)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(ifaceIndex);
	int64 begin_t = shjson_num(params, "timelimit", 0);

	items.clear();

	vector<CTxDestination> addr_list;
	SHAPI_GetOutputsForAccount(wallet, strAccount, addr_list);

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

			if (!SHAPI_IsOutputForAccount(wallet, addr_list, address))
				continue;

			CCoinAddr c_addr(ifaceIndex, address);

			Object entry = out.ToValue(ifaceIndex);
//			entry.push_back(Pair("address", c_addr.ToString())); 
//			entry.push_back(Pair("amount",ValueFromAmount(out.nValue)));
//			entry.push_back(Pair("hash", wtx->GetWitnessHash().GetHex()));
			entry.push_back(Pair("n", i));
//			entry.push_back(Pair("script", out.scriptPubKey.ToString()));
			entry.push_back(Pair("time", (uint64_t)wtx->GetTxTime()));
			entry.push_back(Pair("txid", wtx->GetHash().GetHex()));

			items.push_back(entry);
		}
	}

	return (items);
}





static Object SHAPI_GetSendTxObj(CWallet *wallet, CWalletTx& wtx, CScript& scriptPub, tx_cache& inputs)
{
  int64 nValueOut = 0;
  int64 nChangeOut = 0;
  int64 nValueIn = 0;
  int64 nTxSize = 0;
  int nInputTotal = 0;
  int64 nSigTotal = 0;
	int64 nFee;

	{
    nInputTotal += wtx.vin.size();
    nSigTotal += wtx.GetLegacySigOpCount();

    wallet->FillInputs(wtx, inputs);
    nTxSize += wallet->GetVirtualTransactionSize(wtx);
  }
	{
    BOOST_FOREACH(const CTxIn& txin, wtx.vin) {
      CTxOut out;
      if (!wtx.GetOutputFor(txin, inputs, out))
        continue;

      nValueIn += out.nValue;
    }
  }

	{
    BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
      if (txout.scriptPubKey == scriptPub) {
        nValueOut += txout.nValue;
      } else {
        nChangeOut += txout.nValue;
      }
    }
  }

  /* calculate fee & new projected balance */
  nFee = nValueIn - nValueOut - nChangeOut;

  Object ret = wtx.ToValue(wallet->ifaceIndex);
  ret.push_back(Pair("change-amount", ValueFromAmount(nChangeOut)));
  ret.push_back(Pair("fee", ValueFromAmount(nFee)));
  ret.push_back(Pair("input-amount", ValueFromAmount(nValueIn)));
  ret.push_back(Pair("txinputs", (int)nInputTotal));
  ret.push_back(Pair("txsigops", (int)nSigTotal));
  ret.push_back(Pair("txsize", (int)nTxSize));
  ret.push_back(Pair("amount", ValueFromAmount(nValueOut)));
//	ret.push_back(Pair("txid", wtx.GetHash().GetHex().c_str()));

	return (ret);
}



#if 0
Object SHAPI_GetSendTxObj(CWallet *wallet, CWalletTx& wtx, CScript& scriptPub, tx_cache& inputs)
{
  int64 nValueOut = 0;
  int64 nChangeOut = 0;
  int64 nValueIn = 0;
  int64 nTxSize = 0;
  int nInputTotal = 0;
  int64 nSigTotal = 0;
	int64 nFee;

	{
    nInputTotal += wtx.vin.size();
    nSigTotal += wtx.GetLegacySigOpCount();

    wallet->FillInputs(wtx, inputs);
    nTxSize += wallet->GetVirtualTransactionSize(wtx);
  }
	{
    BOOST_FOREACH(const CTxIn& txin, wtx.vin) {
      CTxOut out;
      if (!wtx.GetOutputFor(txin, inputs, out))
        continue;

      nValueIn += out.nValue;
    }
  }

	{
    BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
      if (txout.scriptPubKey == scriptPub) {
        nValueOut += txout.nValue;
      } else {
        nChangeOut += txout.nValue;
      }
    }
  }

  /* calculate fee & new projected balance */
  nFee = nValueIn - nValueOut - nChangeOut;

  Object ret;
  ret.push_back(Pair("change-amount", ValueFromAmount(nChangeOut)));
  ret.push_back(Pair("fee", ValueFromAmount(nFee)));
  ret.push_back(Pair("input-amount", ValueFromAmount(nValueIn)));
  ret.push_back(Pair("txinputs", (int)nInputTotal));
  ret.push_back(Pair("txsigops", (int)nSigTotal));
  ret.push_back(Pair("txsize", (int)nTxSize));
  ret.push_back(Pair("amount", ValueFromAmount(nValueOut)));
	ret.push_back(Pair("txid", wtx.GetHash().GetHex().c_str()));

	return (ret);
}

static const ApiItems& shapi_api_account_send(int ifaceIndex, string strAccount, shjson_t *params, string& strError, uint160 hColor = 0)
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

	strError = "";
	items.clear();

	string strDestAddress(shjson_astr(params, "address", ""));
	CCoinAddr address(ifaceIndex, strDestAddress);
	if (!address.IsValid()) {
		strError = string("invalid coin address");
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
	Object obj = SHAPI_GetSendTxObj(wallet, wtx, scriptPub, inputs);
	obj.push_back(Pair("txid", wtx.GetHash().GetHex()));
	items.push_back(obj);

  return (items);
}

static const ApiItems& shapi_api_account_bsend(int ifaceIndex, string strAccount, shjson_t *params, string& strError, uint160 hColor = 0)
{
	static ApiItems items;
  static const int nMinConfirmDepth = 1; /* single confirmation requirement */
  CWallet *wallet = GetWallet(ifaceIndex);
  int64 nAmount;
  int64 nBalance;

	items.clear();

	double dAmount = atof(shjson_str(params, "amount", 0));
  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount)) {
		strError = string("coin denomination");
		return (items);
  }

  nBalance  = GetAccountBalance(ifaceIndex, strAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
		strError = string("insuffient funds");
		return (items);
  }

	string strDestAddress(shjson_astr(params, "address", ""));
	CCoinAddr address(ifaceIndex, strDestAddress);
	if (!address.IsValid()) {
		strError = string("invalid coin address");
		return (items);
	}

  CScript scriptPub;
  scriptPub.SetDestination(address.Get());
  CTxBatchCreator b_tx(wallet, strAccount, scriptPub, nAmount); 
  if (!b_tx.Send()) {
		strError = b_tx.GetError();
		return (items);
  }

	tx_cache inputs;
  vector<CWalletTx>& tx_list = b_tx.GetTxList();
	for (int i = 0; i < tx_list.size(); i++) {
		Object obj = SHAPI_GetSendTxObj(wallet, tx_list[i], scriptPub, inputs);
		obj.push_back(Pair("txid", tx_list[i].GetHash().GetHex()));
		items.push_back(obj);
	}

  return (items);
}

static const ApiItems& shapi_api_account_tsend(int ifaceIndex, string strAccount, shjson_t *params, string& strError, uint160 hColor = 0)
{
	static ApiItems items;
  static const int nMinConfirmDepth = 1; /* single confirmation requirement */
  CWallet *wallet = GetWallet(ifaceIndex);
  int64 nAmount;
  int64 nBalance;

	items.clear();

	double dAmount = atof(shjson_str(params, "amount", 0));
  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount)) {
		strError = string("coin denomination");
		return (items);
  }

  nBalance  = GetAccountBalance(ifaceIndex, strAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
		strError = string("insuffient funds");
		return (items);
  }

	string strDestAddress(shjson_astr(params, "address", ""));
	CCoinAddr address(ifaceIndex, strDestAddress);
	if (!address.IsValid()) {
		strError = string("invalid coin address");
		return (items);
	}

  CScript scriptPub;
  scriptPub.SetDestination(address.Get());
  CTxBatchCreator b_tx(wallet, strAccount, scriptPub, nAmount); 
  if (!b_tx.Generate()) {
		strError = b_tx.GetError();
		return (items);
  }

	tx_cache inputs;
  vector<CWalletTx>& tx_list = b_tx.GetTxList();
	for (int i = 0; i < tx_list.size(); i++) {
		items.push_back(SHAPI_GetSendTxObj(wallet, tx_list[i], scriptPub, inputs));
	}

  return (items);
}
#endif






static const ApiItems& shapi_api_account_send(int ifaceIndex, string strAccount, shjson_t *params, string& strError, uint160 hColor = 0)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
  Array ret;
	char fee_str[32];
	double dAmount;
	double dFee;
  int64 nAmount;
  int64 nFee;
  int64 nBalance;
  int nMinDepth = 1; /* single confirmation requirement */
  int nMinConfirmDepth = 1; /* single confirmation requirement */
	bool found = false;
	bool fTest = false;
	bool fBatch = false;
	int err;

	strError = "";
	items.clear();

	CCoinAddr address(ifaceIndex);
	string strDestAddress(shjson_astr(params, "address", ""));
	if (!GetCoinAddr(wallet, strDestAddress, address)) {
		strError = string("invalid coin address");
		return (items);
	}
#if 0
	CCoinAddr address(ifaceIndex, strDestAddress);
	if (!address.IsValid()) {
		strError = string("invalid coin address");
		return (items);
	}
#endif

	dAmount = atof(shjson_str(params, "amount", 0));
  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount)) {
		strError = string("coin denomination");
		return (items);
  }

	memset(fee_str, 0, sizeof(fee_str));
	strncpy(fee_str, shjson_astr(params, "fee", ""), sizeof(fee_str)-1);
	if (!isalpha(*fee_str)) {
		dFee = atof(fee_str);
		nFee = roundint64(dAmount * COIN);
	}

  nBalance  = GetAccountBalance(ifaceIndex, strAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
		strError = string("insufficient funds");
		return (items);
  }

	fTest = (bool)atoi(shjson_astr(params, "test", ""));
	fBatch = (bool)atoi(shjson_astr(params, "batch", ""));

	CScript scriptPub;
	scriptPub.SetDestination(address.Get());

	Object obj;
	bool ok = false;
	if (hColor != 0) {
		CWalletTx wtx;
		err = update_altchain_tx(iface, strAccount, hColor, address, nAmount, wtx);
		if (!err) {
			tx_cache inputs;
			Object obj = SHAPI_GetSendTxObj(wallet, wtx, scriptPub, inputs);
//			obj.push_back(Pair("txid", wtx.GetHash().GetHex()));
			items.push_back(obj);
		} else {
			strError = string(sherrstr(err));
		}
	} else if (!fBatch) {
		CTxCreator wtx(wallet, strAccount);
		wtx.SetMinFee(nFee);
		wtx.AddOutput(scriptPub, nAmount);
		if (!fTest) {
			if (wtx.Send())
				strError = wtx.GetError();
		} else /* fTest */ {
			if (wtx.Generate())
				strError = wtx.GetError();
		}

		tx_cache inputs;
		Object obj = SHAPI_GetSendTxObj(wallet, wtx, scriptPub, inputs);
//		obj.push_back(Pair("txid", wtx.GetHash().GetHex()));
		items.push_back(obj);
	} else /* fBatch */ {
		CTxBatchCreator b_tx(wallet, strAccount, scriptPub, nAmount); 

		if (isalpha(*fee_str)) {
			const int confTarget = 4;
			CBlockPolicyEstimator *est = GetFeeEstimator(iface);
			/* todo: not calc'n inputs */
			if (est) {
				int64 nBytes = (int64)wallet->GetVirtualTransactionSize(b_tx);
				if (0 == strcasecmp(fee_str, "economical")) {
					nFee = est->GetMinFee(nBytes).GetFee(nBytes);
				} else if (0 == strcasecmp(fee_str, "priority")) {
					nFee = est->estimateSmartFee(confTarget, NULL).GetFee(nBytes);
					nFee *= 2;
				} else { /* regular */
					nFee = est->estimateSmartFee(confTarget, NULL).GetFee(nBytes);
				}
			}
		}

		b_tx.SetMinFee(nFee);
		if (!fTest) {
			if (b_tx.Send())
				strError = b_tx.GetError();
		} else /* fTest */ {
			if (b_tx.Generate())
				strError = b_tx.GetError();
		}

		tx_cache inputs;
		vector<CWalletTx>& tx_list = b_tx.GetTxList();
		for (int i = 0; i < tx_list.size(); i++) {
			Object obj = SHAPI_GetSendTxObj(wallet, tx_list[i], scriptPub, inputs);
//			obj.push_back(Pair("txid", tx_list[i].GetHash().GetHex()));
			items.push_back(obj);
		}
	}

  return (items);
}







static CBlockIndex *GetBlockIndexDepth(int ifaceIndex, int depth, uint160 hColor)
{
	CBlockIndex *pindex = GetBestBlockIndex(ifaceIndex);
	while (pindex && depth > 0) {
		if (!pindex->pprev)
			break;
		pindex = pindex->pprev;
		depth--;
	}
	return (pindex);
}

static const ApiItems& shapi_api_account_unspent(int ifaceIndex, string strAccount, shjson_t *params, uint160 hColor = 0)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(ifaceIndex);
	int begin_t = (int64)shjson_num(params, "timelimit", 0);
	uint256 in_pkey = 0;

	items.clear();

	vector<COutput> vecOutputs;
	wallet->AvailableAccountCoins(strAccount, vecOutputs, true, hColor);
	BOOST_FOREACH(const COutput& out, vecOutputs) {
		int64 nValue = out.tx->vout[out.i].nValue;
		const CScript& pk = out.tx->vout[out.i].scriptPubKey;

		CTxDestination address;
		if (!ExtractDestination(pk, address))
			continue;  

		const CTransaction& tx = *out.tx;
		//		int nTxSize = (int)wallet->GetVirtualTransactionSize(tx);

		int64 stamp = time(NULL);
		CBlockIndex *pindexDepth = GetBlockIndexDepth(ifaceIndex, out.nDepth, hColor);
		if (pindexDepth)
			stamp = pindexDepth->GetBlockTime();

		if (stamp < begin_t)
			continue;

		CCoinAddr c_addr(ifaceIndex, address);

		Object entry;
		entry.push_back(Pair("address", c_addr.ToString()));
		entry.push_back(Pair("amount",ValueFromAmount(nValue)));
		entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
		//		entry.push_back(Pair("hash", out.tx->GetWitnessHash().GetHex()));
		entry.push_back(Pair("vout", out.i));
//		entry.push_back(Pair("script", pk.ToString()));
//		entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
		entry.push_back(Pair("confirmations",out.nDepth));
		//		entry.push_back(Pair("total-size", nTxSize)); 
		entry.push_back(Pair("time", (uint64_t)stamp));

		items.push_back(entry);
	}

	return (items);
}

static const ApiItems& shapi_api_account_addr(int ifaceIndex, string strAccount, shjson_t *params)
{
	static ApiItems items;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
	int64 now = (int64)time(NULL);

	items.clear();
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook) {
		const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
		const string& strName = item.second;
		CSecret vchSecret;
		CKeyID keyID;
		uint256 pkey;
		bool fCompressed;

		if (strName != strAccount)
			continue;

		Object result;
		result.push_back(Pair("address", address.ToString()));
		if (address.GetKeyID(keyID)) {
			result.push_back(Pair("pubkey", HexStr(keyID.begin(), keyID.end())));
		}

		items.push_back(result);
	}

  return (items);
}

static const ApiItems& shapi_api_account_secret(int ifaceIndex, string strAccount, shjson_t *params)
{
	static ApiItems items;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
	int64 now = (int64)time(NULL);

	items.clear();
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook) {
		const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
		const string& strName = item.second;
		CSecret vchSecret;
		CCoinSecret secret;
		CKeyID keyID;
		uint256 pkey;
		bool fCompressed;

		if (strName != strAccount)
			continue;

		if (!address.GetKeyID(keyID))
			continue;

		if (!wallet->GetSecret(keyID, vchSecret, fCompressed))
			continue;

		secret = CCoinSecret(ifaceIndex, vchSecret, fCompressed);
		pkey = get_private_key_hash(wallet, keyID);

		Object result;
		result.push_back(Pair("address", address.ToString()));
		result.push_back(Pair("apikey", pkey.GetHex()));
		result.push_back(Pair("compressed", fCompressed));
		result.push_back(Pair("mnemonic", EncodeMnemonicSecret(secret)));
		result.push_back(Pair("secret", secret.ToString()));

		items.push_back(result);
	}

  return (items);
}

static const ApiItems& shapi_api_book(int ifaceIndex, shapi_t *user, shjson_t *params)
{
	static ApiItems items;

	items.clear();

	return (items);
}

static const ApiItems& shapi_api_order_list(shapi_t *user, shjson_t *params)
{

	static ApiItems items;

	items.clear();

	return (items);
}

static const ApiItems& shapi_api_order_create(shapi_t *user, shjson_t *params)
{
	static ApiItems items;

	items.clear();

	return (items);
}

static const ApiItems& shapi_api_order_remove(shapi_t *user, shjson_t *params)
{
	static ApiItems items;

	items.clear();

	return (items);
}

static const ApiItems& shapi_api_order_ticker(shapi_t *user, shjson_t *params)
{
	static ApiItems items;

	items.clear();

	return (items);
}

static const ApiItems& shapi_api_order_fills(shapi_t *user, shjson_t *params)
{
	static ApiItems items;

	items.clear();

	return (items);
}

static const ApiItems& shapi_api_order_trades(shapi_t *user, shjson_t *params)
{
	static ApiItems items;

	items.clear();

	return (items);
}


static const ApiItems& shapi_api_alias_list(int ifaceIndex, string strAccount, shjson_t *params, int64 begin_t, bool fSelf)
{
	static ApiItems items;
  CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(ifaceIndex);
  Object ret;
  alias_list *list;

	items.clear();

  list = GetAliasTable(ifaceIndex);
	if (!list)
		return (items);

	string strExtAccount = "@" + strAccount;

	vector<CTxDestination> addr_list;
	SHAPI_GetOutputsForAccount(wallet, strExtAccount, addr_list);

  BOOST_FOREACH(PAIRTYPE(const string, uint256)& r, *list) {
    const string& label = r.first;
    uint256& hTx = r.second;
    CTransaction tx;
    uint256 hBlock;

    if (!GetTransaction(iface, hTx, tx, &hBlock))
      continue;

		CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hBlock);
		if (!pindex)
			continue;

		if (pindex->GetBlockTime() <= begin_t)
			continue;

		bool fOwner = false;
		if (fSelf) {
			CTxDestination dest;
			CScript script;
			int mode;
			int nOut;

			if (GetExtOutput(tx, OP_ALIAS, mode, nOut, script) &&
					ExtractDestination(script, dest) &&
					SHAPI_IsOutputForAccount(wallet, addr_list, dest))
				fOwner = true;
		}
		if (fSelf && !fOwner)
			continue;	

		Object obj = tx.GetAlias()->ToValue(ifaceIndex);
		obj.push_back(Pair("blockhash", hBlock.GetHex()));
		obj.push_back(Pair("hash", tx.GetAlias()->GetHash().GetHex()));
		obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
		obj.push_back(Pair("txid", hTx.GetHex()));
		if (!fSelf)
			obj.push_back(Pair("owner", fOwner));
		items.push_back(obj);
  }

  return (items);
}

static int shapi_api_alias_set(int ifaceIndex, ApiItems& result, string strAccount, shjson_t *params, string& strError)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(ifaceIndex);
	string strExtAccount = "@" + strAccount;
	CCoinAddr addr(ifaceIndex);
	CTransaction in_tx;
	CWalletTx wtx;
	bool fTest = false;
	int err;

	items.clear();

	const string test_str(shjson_astr(params, "test", ""));
	if (test_str == "1")
		fTest = true;

	const string alias_addr_str(shjson_astr(params, "address", ""));
	addr = CCoinAddr(ifaceIndex, alias_addr_str);
	if (!addr.IsValid()) {
		strError = "invalid coin addresss format";
		return (ERR_INVAL);
	}

	/* address specified must be relevant for underlying account. */
	bool found = false;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& l_address = CCoinAddr(ifaceIndex, item.first);
    const string& l_account = item.second;
    if (strAccount == l_account && addr == l_address) {
			found = true;
			break;
		}
  }
  if (!found) {
		strError = "coin address invalid for account";
		return (ERR_REMOTE);
  }

	vector<CTxDestination> addr_list;
	SHAPI_GetOutputsForAccount(wallet, strExtAccount, addr_list);

	string alias_name(shjson_astr(params, "label", ""));
  if(alias_name.size() == 0 ||
			alias_name.size() > 135) {
		strError = "invalid alias label length";
		return (ERR_INVAL);
	}

	CAlias *alias = GetAliasByName(iface, alias_name, in_tx);
	if (!alias) {
		err = init_alias_addr_tx(iface, alias_name.c_str(), addr, wtx, fTest);
		if (err) {
			strError = "initialize alias address transaction";
			return (err);
		}
	} else {
		CTxDestination dest;
		CScript script;
		int mode;
		int nOut;

		if (!GetExtOutput(in_tx, OP_ALIAS, mode, nOut, script) ||
				!ExtractDestination(script, dest) ||
				!SHAPI_IsOutputForAccount(wallet, addr_list, dest)) {
			/* wrong account specified. */
			strError = "error updating alias address";
			return (ERR_ACCESS);
		}

		err = update_alias_addr_tx(iface, alias_name.c_str(), addr, wtx, fTest);
		if (err) {
			strError = "error updating alias address";
			return (err);
		}
	}


	alias = wtx.GetAlias();
	if (alias) {
		int nTxSize = (int)wallet->GetVirtualTransactionSize(wtx);
		int64_t nOutValue = wtx.GetValueOut();
		int64_t nFee = wallet->GetTxFee(wtx);

		Object obj = wtx.GetAlias()->ToValue(ifaceIndex);
		obj.push_back(Pair("hash", alias->GetHash().GetHex()));
		obj.push_back(Pair("txid", wtx.GetHash().GetHex().c_str()));
		obj.push_back(Pair("fee", ValueFromAmount(nFee)));
		obj.push_back(Pair("txsize", nTxSize));

		items.push_back(obj);
	}

	result = items;
	return (0);
}

static const ApiItems& shapi_api_alias_get(int ifaceIndex, string strAccount, shjson_t *params, string& strError)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	Array ret;
	alias_list *list;
	uint160 hash;
	string label;

	strError = "";
	items.clear();

	list = GetAliasTable(ifaceIndex);
	if (!list) return (items);

	label = string(shjson_astr(params, "label", ""));
	if (label != "") {
		if (list->count(label) != 0) {
			const uint256& hTx = (*list)[label];
			CBlockIndex *pindex;
			CAlias *alias;
			CTransaction tx;
			uint256 hBlock;

			if (GetTransaction(iface, hTx, tx, &hBlock) &&
					(pindex = GetBlockIndexByHash(ifaceIndex, hBlock)) &&
					(alias = tx.GetAlias())) {
				Object obj = alias->ToValue(ifaceIndex);
				obj.push_back(Pair("blockhash", hBlock.GetHex()));
//				obj.push_back(Pair("hash", alias->GetHash().GetHex()));
				obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
				obj.push_back(Pair("txid", hTx.GetHex()));
				items.push_back(obj);
			}
		}
	}
#if 0
	else {
		hash = uint160(string(shjson_astr(params, "hash", "")));
		if (hash != 0) {
			BOOST_FOREACH(PAIRTYPE(const string, uint256)& r, *list) {
				const string& label = r.first;
				const uint256& hTx = r.second;
				CTransaction tx;
				uint256 hBlock;

				if (!GetTransaction(iface, hTx, tx, &hBlock))
					continue;

				if (tx.alias.GetHash() != hash)
					continue;

				CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hBlock);
				if (!pindex)
					continue;

				CAlias *alias = tx.GetAlias();
				if (!alias) continue;

				Object obj = alias->ToValue(ifaceIndex);
				obj.push_back(Pair("blockhash", hBlock.GetHex()));
				obj.push_back(Pair("hash", alias->GetHash().GetHex()));
				obj.push_back(Pair("time", (int)pindex->GetBlockTime()));
				obj.push_back(Pair("txid", hTx.GetHex()));
				items.push_back(obj);
				break;
			}
		}
	}
#endif
	if (items.size() == 0) {
		/* no record found */
		strError = string(error_str(ERR_NOENT));
	}

	return (items);
}

static const ApiItems& shapi_api_alias_info(int ifaceIndex, string strAccount, shjson_t *params, string& strError)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	int nBestHeight = GetBestHeight(iface);
	Array ret;
	alias_list *list;
	uint160 hash;
	string label;

	strError = "";
	items.clear();

	list = GetAliasTable(ifaceIndex);
	if (!list) return (items);

	Object obj;
	obj.push_back(Pair("fee", ValueFromAmount(GetAliasOpFee(iface, nBestHeight))));
	obj.push_back(Pair("total", (int)list->size()));
	items.push_back(obj);

	return (items);
}

static const ApiItems& shapi_api_context_list(int ifaceIndex, string strAccount, shjson_t *params, int64 begin_t, bool fSelf)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(ifaceIndex);
	Object ret;
	ctx_list *list;

	items.clear();

	list = GetContextTable(ifaceIndex);
	if (!list) return (items);

	string strExtAccount = "@" + strAccount;

	vector<CTxDestination> addr_list;
	SHAPI_GetOutputsForAccount(wallet, strExtAccount, addr_list);

	BOOST_FOREACH(PAIRTYPE(const uint160, uint256)& r, *list) {
		const uint160& hContext = r.first;
		const uint256& hTx = r.second;
		CTransaction tx;
		uint256 hBlock;

		if (!GetTransaction(iface, hTx, tx, &hBlock))
			continue;

		CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hBlock);
		if (!pindex)
			continue;

		if (pindex->GetBlockTime() < begin_t)
			continue;

		if (fSelf) {
			CTxDestination dest;
			CScript script;
			int mode;
			int nOut;

			if (!GetExtOutput(tx, OP_CONTEXT, mode, nOut, script))
				continue;
			if (!ExtractDestination(script, dest))
				continue;
			if (!SHAPI_IsOutputForAccount(wallet, addr_list, dest))
				continue;
		}

		Object obj = tx.GetContext()->ToValue();
		obj.push_back(Pair("blockhash", hBlock.GetHex()));
		obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
		obj.push_back(Pair("txid", hTx.GetHex()));
		items.push_back(obj);
	}

	return (items);
}

static const ApiItems& shapi_api_context_info(int ifaceIndex, string strAccount, shjson_t *params, string& strError)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	int nBestHeight = GetBestHeight(iface);
	Array ret;
	ctx_list *list;
	uint160 hash;
	string label;

	strError = "";
	items.clear();

	list = GetContextTable(ifaceIndex);
	if (!list) return (items);

	Object obj;
	obj.push_back(Pair("fee", ValueFromAmount(GetContextOpFee(iface, nBestHeight))));
	obj.push_back(Pair("total", (int)list->size()));
	items.push_back(obj);

	return (items);
}

static const ApiItems& shapi_api_context_set(int ifaceIndex, string strAccount, shjson_t *params, string& strError)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(ifaceIndex);
	string strName(shjson_astr(params, "label", ""));
	string strValue(shjson_astr(params, "value", ""));
	string strTest(shjson_astr(params, "value", ""));
	CContext *ctx;
	CWalletTx wtx;
	bool fTest = false;
	int err;

	strError = "";
	items.clear();

	string strExtAccount = "@" + strAccount;

	vector<CTxDestination> addr_list;
	SHAPI_GetOutputsForAccount(wallet, strExtAccount, addr_list);

	if (strTest == "1")
		fTest = true;

	cbuff vchValue(strValue.begin(), strValue.end());
	if (!IsContextName(iface, strName)) {
		err = init_ctx_tx(iface, wtx, strAccount, strName, vchValue, NULL, false, fTest);
		if (err) {
			strError = string(error_str(err));
			return (items);
		}
	} else {
		CTransaction in_tx;
		CTxDestination dest;
		CScript script;
		int mode;
		int nOut;

		script = CScript();
		if (!GetContextByName(iface, strName, in_tx) ||
				!GetExtOutput(in_tx, OP_CONTEXT, mode, nOut, script) ||
				!ExtractDestination(script, dest) ||
				!SHAPI_IsOutputForAccount(wallet, addr_list, dest)) {
			/* wrong account specified. */
			strError = string(error_str(ERR_ACCESS));
			return (items);
		}

		err = update_ctx_tx(iface, wtx, strAccount, strName, vchValue, NULL, false, fTest);
		if (err) {
			strError = string(error_str(err));
			return (items);
		}
	}

	int nTxSize = (int)wallet->GetVirtualTransactionSize(wtx);
	int64_t nOutValue = wtx.GetValueOut();
	int64_t nFee = nOutValue - nFee;

	ctx = (CContext *)&wtx.certificate;
	Object obj = ctx->ToValue();
	obj.push_back(Pair("txid", wtx.GetHash().GetHex()));
//	obj.push_back(Pair("fee", ValueFromAmount(nFee)));
	obj.push_back(Pair("txsize", nTxSize));
	items.push_back(obj);

	return (items);
}

static const ApiItems& shapi_api_context_get(int ifaceIndex, string strAccount, shjson_t *params, string& strError)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CContext *ctx;
	CTransaction tx;

	items.clear();

	string ctxLabel(shjson_astr(params, "label", ""));
	if (ctxLabel != "") {
		ctx = GetContextByName(iface, ctxLabel, tx);
		if (!ctx) {
			strError = string(error_str(ERR_NOENT));
			return (items);
		}
	} else {
		string ctxHashStr(shjson_astr(params, "hash", ""));
		uint160 hContext(ctxHashStr);
		ctx = GetContextByHash(iface, hContext, tx);
		if (!ctx) {
			strError = string(error_str(ERR_NOENT));
			return (items);
		}
	}

	Object obj = ctx->ToValue();
	obj.push_back(Pair("txid", tx.GetHash().GetHex()));
	items.push_back(obj);

	return (items);
}

static const ApiItems& shapi_api_ident_list(int ifaceIndex, shapi_t *user, shjson_t *params, int64 begin_t)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	Object ret;
	cert_list *list;

	list = GetIdentTable(ifaceIndex);

	items.clear();
	BOOST_FOREACH(PAIRTYPE(const uint160, uint256)& r, *list) {
		const uint160& hContext = r.first;
		const uint256& hTx = r.second;
		CTransaction tx;
		uint256 hBlock;

		if (!GetTransaction(iface, hTx, tx, &hBlock))
			continue;

		CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hBlock);
		if (!pindex)
			continue;

		if (pindex->GetBlockTime() < begin_t)
			continue;

		CIdent *ident = (CIdent *)&tx.certificate;
		Object obj = ident->ToValue();
		obj.push_back(Pair("blockhash", hBlock.GetHex()));
		obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
		obj.push_back(Pair("txid", hTx.GetHex()));
		items.push_back(obj);
	}

	return (items);
}

static const ApiItems& shapi_api_cert_info(int ifaceIndex, string strAccount, shjson_t *params)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	Object ret;
	cert_list *list;

	list = GetCertTable(ifaceIndex);
	items.clear();

	int nLocal = 0;
	BOOST_FOREACH(PAIRTYPE(const uint160, uint256)& r, *list) {
		const uint256& hTx = r.second;
		CTransaction tx;

		if (!GetTransaction(iface, hTx, tx, NULL))
			continue;
		if (!IsCertAccount(iface, tx, strAccount))
			continue;

		nLocal++;
	}

	Object result;
	result.push_back(Pair("fee", 
				ValueFromAmount(GetCertOpFee(iface, GetBestHeight(iface)))));
	result.push_back(Pair("total", (int64_t)list->size()));
	result.push_back(Pair("local", (int64_t)nLocal));
	items.push_back(result);

	return (items);
}


static const ApiItems& shapi_api_cert_list(int ifaceIndex, shapi_t *user, shjson_t *params, int64 begin_t)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	Object ret;
	cert_list *list;

	list = GetCertTable(ifaceIndex);

	items.clear();
	BOOST_FOREACH(PAIRTYPE(const uint160, uint256)& r, *list) {
		const uint160& hContext = r.first;
		const uint256& hTx = r.second;
		CTransaction tx;
		uint256 hBlock;

		if (!GetTransaction(iface, hTx, tx, &hBlock))
			continue;

		CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hBlock);
		if (!pindex)
			continue;

		if (pindex->GetBlockTime() < begin_t)
			continue;

		Object obj = tx.GetCertificate()->ToValue();
		obj.push_back(Pair("blockhash", hBlock.GetHex()));
		obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
		obj.push_back(Pair("txid", hTx.GetHex()));
		items.push_back(obj);
	}

	return (items);
}

static const ApiItems& shapi_api_license_list(int ifaceIndex, shapi_t *user, shjson_t *params, int64 begin_t)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	Object ret;
	cert_list *list;

	items.clear();

	list = GetLicenseTable(ifaceIndex);
	if (!list) return (items);

	BOOST_FOREACH(PAIRTYPE(const uint160, uint256)& r, *list) {
		const uint160& hOffer = r.first;
		const uint256& hTx = r.second;
		CTransaction tx;
		uint256 hBlock;

		if (!GetTransaction(iface, hTx, tx, &hBlock))
			continue;

		CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hBlock);
		if (!pindex)
			continue;

		if (pindex->GetBlockTime() < begin_t)
			continue;

		CLicense lic(tx.certificate);
		Object obj = lic.ToValue();
		obj.push_back(Pair("blockhash", hBlock.GetHex()));
		obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
		obj.push_back(Pair("txid", hTx.GetHex()));
		items.push_back(obj);
	}

	return (items);
}

static const ApiItems& shapi_api_asset_list(int ifaceIndex, shapi_t *user, shjson_t *params, int64 begin_t)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	Object ret;
	asset_list *list;

	items.clear();

	list = GetAssetTable(ifaceIndex);
	if (!list) return (items);

	BOOST_FOREACH(PAIRTYPE(const uint160, uint256)& r, *list) {
		const uint160& hOffer = r.first;
		const uint256& hTx = r.second;
		CTransaction tx;
		uint256 hBlock;

		if (!GetTransaction(iface, hTx, tx, &hBlock))
			continue;

		CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hBlock);
		if (!pindex)
			continue;

		if (pindex->GetBlockTime() < begin_t)
			continue;

		Object obj = tx.GetAsset()->ToValue();
		obj.push_back(Pair("blockhash", hBlock.GetHex()));
		obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
		obj.push_back(Pair("txid", hTx.GetHex()));
		items.push_back(obj);
	}

	return (items);
}

static const ApiItems& shapi_api_exec_list(int ifaceIndex, shapi_t *user, shjson_t *params, int64 begin_t)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	Object ret;
	exec_list *list;

	list = GetExecTable(ifaceIndex);

	items.clear();
	BOOST_FOREACH(PAIRTYPE(const uint160, uint256)& r, *list) {
		const uint160& hContext = r.first;
		const uint256& hTx = r.second;
		CTransaction tx;
		uint256 hBlock;

		if (!GetTransaction(iface, hTx, tx, &hBlock))
			continue;

		CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hBlock);
		if (!pindex)
			continue;

		if (pindex->GetBlockTime() < begin_t)
			continue;

		Object obj = tx.GetContext()->ToValue();
		obj.push_back(Pair("blockhash", hBlock.GetHex()));
		obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
		obj.push_back(Pair("txid", hTx.GetHex()));
		items.push_back(obj);
	}

	return (items);
}

static const ApiItems& shapi_api_offer_list(int ifaceIndex, shapi_t *user, shjson_t *params, int64 begin_t)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	Object ret;
	offer_list *list;

	items.clear();

	list = GetOfferTable(ifaceIndex);
	if (!list) return (items);

	BOOST_FOREACH(PAIRTYPE(const uint160, uint256)& r, *list) {
		const uint160& hOffer = r.first;
		const uint256& hTx = r.second;
		CTransaction tx;
		uint256 hBlock;

		if (!GetTransaction(iface, hTx, tx, &hBlock))
			continue;

		CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hBlock);
		if (!pindex)
			continue;

		if (pindex->GetBlockTime() < begin_t)
			continue;

		Object obj = tx.GetOffer()->ToValue();
		obj.push_back(Pair("blockhash", hBlock.GetHex()));
		obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
		obj.push_back(Pair("txid", hTx.GetHex()));
		items.push_back(obj);
	}

	return (items);
}

static const ApiItems& shapi_api_alt_list(int ifaceIndex, shapi_t *user, shjson_t *params, int64 begin_t)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CBlockIndex *pindex;
	altchain_list *list;

	items.clear();

	list = GetAltChainTable(ifaceIndex);
	if (!list) return (items);

	BOOST_FOREACH(PAIRTYPE(const uint160, uint256)& r, *list) {
		const uint160& hColor = r.first;
		const uint256& hBlock = r.second;

		pindex = GetBlockIndexByHash(COLOR_COIN_IFACE, hBlock);
		if (!pindex)
			continue;

		if (pindex->GetBlockTime() < begin_t)
			continue;

		Object obj;
		obj.push_back(Pair("blocks", (int)pindex->nHeight));
		obj.push_back(Pair("chainwork", pindex->bnChainWork.ToString()));
		obj.push_back(Pair("colorhash", hColor.GetHex()));
		obj.push_back(Pair("currentblockhash", hBlock.GetHex()));
		obj.push_back(Pair("difficulty", GetDifficulty(pindex->nBits, pindex->nVersion)));
		obj.push_back(Pair("symbol", GetAltColorHashAbrev(hColor)));
		obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
		items.push_back(obj);
	}

	return (items);
}

static const ApiItems& shapi_api_alt_get(int ifaceIndex, shapi_t *user, shjson_t *params, string& strError)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CIface *alt_iface = GetCoinByIndex(COLOR_COIN_IFACE);
	CTxMemPool *pool = GetTxMemPool(alt_iface);
	CBlockIndex *pindex;
	altchain_list *list;
	string strColor;
	string strDesc;
	char buf[64];
	uint160 hColor;
	uint32_t r, g, b, a;

	items.clear();

	strColor = string(shjson_astr(params, "label", ""));
	if (strColor != "") {
    hColor = GetAltColorHash(iface, strColor, strDesc);
	} else {
		hColor = uint160(string(shjson_astr(params, "color", "")));
		strDesc = "";
	}

	pindex = GetBestColorBlockIndex(iface, hColor);
	if (!pindex) {
		strError = string(error_str(ERR_NOENT));
		return (items);
	}

	int64 nBlockValueRate = color_GetBlockValueRate(hColor);
	int64 nBlockValueBase = color_GetBlockValueBase(hColor);
	int64 nBlockTarget = color_GetBlockTarget(hColor);
	int64 nCoinbaseMaturity = color_GetCoinbaseMaturity(hColor);
	int64 nMinTxFee = color_GetMinTxFee(hColor);
	CBigNum bnMinDifficulty = color_GetMinDifficulty(hColor);

	GetAltColorCode(hColor, &r, &g, &b, &a);
	sprintf(buf, "#%-2.2X%-2.2X%-2.2X", (r >> 24), (g >> 24), (b >> 24));

	Object obj;
	obj.push_back(Pair("blocktarget", (int)nBlockTarget));
	obj.push_back(Pair("blockvaluerate", (int)nBlockValueRate));
	obj.push_back(Pair("blockvaluebase", ((double)nBlockValueBase/COIN)));
	obj.push_back(Pair("blocks", (int)pindex->nHeight));
	obj.push_back(Pair("chainwork", pindex->bnChainWork.ToString()));
	if (strColor != "")
		obj.push_back(Pair("title", strColor));
	obj.push_back(Pair("colorcode", string(buf)));
	obj.push_back(Pair("colorhash", hColor.GetHex()));
	obj.push_back(Pair("currentblockhash", pindex->GetBlockHash().GetHex()));
	if (strDesc != "")
		obj.push_back(Pair("description", strDesc));
	obj.push_back(Pair("difficulty", GetDifficulty(pindex->nBits, pindex->nVersion)));
	obj.push_back(Pair("min-difficulty",
				print_rpc_difficulty(bnMinDifficulty)));
	obj.push_back(Pair("min-txfee", ((double)nMinTxFee/COIN)));
	obj.push_back(Pair("maturity", (int)nCoinbaseMaturity));
	obj.push_back(Pair("pooledtx", (uint64_t)pool->size()));
	obj.push_back(Pair("symbol", GetAltColorHashAbrev(hColor)));
	obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
	items.push_back(obj);

	return (items);
}

static const ApiItems& shapi_api_alt_block(int ifaceIndex, shapi_t *user, shjson_t *params, string& strError)
{
	static ApiItems items;
	CIface *alt_iface = GetCoinByIndex(COLOR_COIN_IFACE);
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CBlock *block;
	altchain_list *list;
	uint256 hBlock;
	uint160 hColor;

	items.clear();

//	hColor = uint160(string(shjson_astr(params, "color", "")));
	hBlock = uint256(string(shjson_astr(params, "hash", "")));

  block = GetBlockByHash(alt_iface, hBlock);
	if (!block) {
		strError = string(error_str(ERR_NOENT));
		return (items);
	}

	Object obj = block->ToValue();
//	obj.push_back(Pair("color", hColor.GetHex()));
	items.push_back(obj);
	delete block;

	return (items);
}

static const ApiItems& shapi_api_alt_tx(int ifaceIndex, shapi_t *user, shjson_t *params, string& strError)
{
	static ApiItems items;
	CIface *alt_iface = GetCoinByIndex(COLOR_COIN_IFACE);
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CTransaction tx;
	altchain_list *list;
	uint256 hBlock;
	uint256 hTx;
	uint160 hColor;

	items.clear();

//	hColor = uint160(string(shjson_astr(params, "color", "")));
	hTx = uint256(string(shjson_astr(params, "hash", "")));

	if (!GetTransaction(alt_iface, hTx, tx, &hBlock)) {
		strError = string(error_str(ERR_NOENT));
		return (items);
	}

	Object obj = tx.ToValue(COLOR_COIN_IFACE);
//	obj.push_back(Pair("color", hColor.GetHex()));
	obj.push_back(Pair("blockhash", hBlock.GetHex()));
	items.push_back(obj);

	return (items);
}

static const ApiItems& shapi_api_alt_send(int ifaceIndex, string strAccount, shjson_t *params, string& strError)
{
	static CBigNum max_diff(~uint256(0) >> 14);
	static ApiItems items;
	CIface *alt_iface = GetCoinByIndex(COLOR_COIN_IFACE);
	CIface *iface = GetCoinByIndex(ifaceIndex);
	uint160 hColor;
	int64 nAmount;
	int64 nBalance;
	int err;

	items.clear();

	hColor = uint160(string(shjson_astr(params, "color", "")));
	nAmount = (int64)(shjson_num(params, "amount", 0) * COIN);

	if (nAmount < MIN_INPUT_VALUE(alt_iface) ||
			!MoneyRange(COLOR_COIN_IFACE, nAmount)) {
		strError = string("coin denomination");
		return (items);
	}

	if (color_GetMinDifficulty(hColor) > max_diff) {
		strError = string("color chain's minimum difficulty too high to cpu mine.");
		return (items);
	}
	/* TODO: .. still quandry when next-block-diff is high */

	CWalletTx wtx;
	CCoinAddr address(ifaceIndex, string(shjson_astr(params, "address", "")));
	err = update_altchain_tx(iface, strAccount, hColor, address, nAmount, wtx);
	if (err) {
		strError = string(error_str(err));
		return (items);
	}
	items.push_back(wtx.ToValue(COLOR_COIN_IFACE));

	return (items);
}

static const ApiItems& shapi_api_alt_balance(int ifaceIndex, string strAccount, shjson_t *params, string& strError)
{
	static ApiItems items;
	CWallet *alt_wallet = GetWallet(COLOR_COIN_IFACE);
	map<uint160,int64> vCoins;

	items.clear();
	vCoins.clear();

	vector<CTxDestination> addr_list;
	SHAPI_GetOutputsForAccount(alt_wallet, strAccount, addr_list);

	for (map<uint256, CWalletTx>::const_iterator it = alt_wallet->mapWallet.begin(); it != alt_wallet->mapWallet.end(); ++it) {
		const CWalletTx* pcoin = &(*it).second;

		if (!pcoin->IsFinal(ifaceIndex))
			continue;
		if (!pcoin->IsConfirmed()) 
			continue;
		if (pcoin->IsCoinBase() &&
				pcoin->GetBlocksToMaturity(ifaceIndex) > 0)
			continue;

		for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
			/* check whether this output has already been used */
			if (pcoin->IsSpent(i))
				continue;

			/* filter via account */
			CTxDestination dest;
			if (!ExtractDestination(pcoin->vout[i].scriptPubKey, dest))
				continue;

			if (!SHAPI_IsOutputForAccount(alt_wallet, addr_list, dest))
				continue;

			uint160 hColor = pcoin->GetColor();
			vCoins[hColor] += pcoin->vout[i].nValue;
		}
	}

	BOOST_FOREACH(const PAIRTYPE(uint160, int64)& item, vCoins) {
		const uint160& hColor = item.first;
		int64 nAmount = item.second;

		if (nAmount == 0)
			continue;

		Object color_obj;
		color_obj.push_back(Pair("color", hColor.GetHex()));
		color_obj.push_back(Pair("available", (uint64_t)nAmount));
		items.push_back(color_obj);
	}

	return (items);
}

static const ApiItems& shapi_api_block_mined(int ifaceIndex, shapi_t *user, shjson_t *params, int64 begin_t)
{
	static ApiItems items;

	if (begin_t == 0)
		begin_t = (time(NULL) - 86400);
	items.clear();

	vector<CBlockIndex *> blocks = get_stratum_miner_blocks(ifaceIndex);
	for (int i = 0; i < blocks.size(); i++) {
		CBlockIndex *pindex = blocks[i];

		if (pindex->GetBlockTime() < begin_t)
			continue;

		Object obj;
		obj.push_back(Pair("blockhash", pindex->GetBlockHash().GetHex()));
		obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
		items.push_back(obj);
	}

	return (items);
}

extern double GetDifficulty(int ifaceIndex, const CBlockIndex* blockindex);

static const ApiItems& shapi_api_block_list(int ifaceIndex, shapi_t *user, shjson_t *params, int64 begin_t)
{
	static ApiItems items;

	if (begin_t == 0)
		begin_t = (time(NULL) - 86400);
	items.clear();

	CBlockIndex *pindex = GetBestBlockIndex(ifaceIndex);
	while (pindex && pindex->pprev) {
		Object obj;
		obj.push_back(Pair("blockhash", pindex->GetBlockHash().GetHex()));
		obj.push_back(Pair("merkleroot", pindex->hashMerkleRoot.GetHex()));
		obj.push_back(Pair("version", (int)pindex->nVersion));
		obj.push_back(Pair("time", (int)pindex->nTime));
		obj.push_back(Pair("height", pindex->nHeight));
		obj.push_back(Pair("bits", HexBits(pindex->nBits)));
		obj.push_back(Pair("difficulty", GetDifficulty(ifaceIndex, pindex)));

		items.push_back(obj);
		if (pindex->GetBlockTime() < begin_t)
			break;
		pindex = pindex->pprev;
	}

	return (items);
}

static const ApiItems& shapi_api_block_get(int ifaceIndex, shapi_t *user, shjson_t *params, int64 begin_t)
{
	static ApiItems items;
	CIface *iface = GetCoinByIndex(ifaceIndex);

	items.clear();

	uint256 hash(string(shjson_astr(params, "blockhash", "")));
	if (hash == 0)
		return (items);

	CBlock *block = GetBlockByHash(iface, hash);
	if (block) {
		items.push_back(block->ToValue());
		delete block;
	}

	return (items);
}

static const ApiItems& shapi_api_validate_list(int ifaceIndex, shapi_t *user, shjson_t *params, int64 begin_t)
{
	static ApiItems items;
	CWallet *wallet = GetWallet(ifaceIndex);
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CBlockIndex *pindex;
	Object ret;

	items.clear();

	BOOST_FOREACH(const uint256& hTx, wallet->mapValidateTx) {
		CTransaction tx;
		uint256 hBlock;

		if (!GetTransaction(iface, hTx, tx, &hBlock))
			continue;

		pindex = GetBlockIndexByHash(ifaceIndex, hBlock);
		if (!pindex)
			continue;

		if (pindex->GetBlockTime() < begin_t)
			continue;

		CTxMatrix *matrix = tx.GetMatrix();
		if (!matrix)
			continue;

		Object obj = matrix->ToValue();
		obj.push_back(Pair("blockhash", hBlock.GetHex()));
		obj.push_back(Pair("time", (uint64_t)pindex->GetBlockTime()));
		obj.push_back(Pair("txid", hTx.GetHex()));
		items.push_back(obj);
	}

	return (items);
}

static const ApiItems& shapi_api_block_info(int ifaceIndex, shapi_t *user, shjson_t *params)
{
	static ApiItems items;
	CWallet *wallet = GetWallet(ifaceIndex);
	CIface *iface = GetCoinByIndex(ifaceIndex);
	Object result;

	items.clear();

	if (!iface || !iface->enabled || !wallet)
		return (items);

	int nHeight = GetBestHeight(iface) + 1;
	int nNextHeight = nHeight;
	int64 nCurValue = wallet->GetBlockValue(nHeight, 0);

#if 0
	int64 nValue = nCurValue;
	do {
		nNextHeight++;
		nValue = wallet->GetBlockValue(nNextHeight, 0, 0);
	} while (nValue == nCurValue);
#endif

	/* max shioncoins */
	result.push_back(Pair("maxcoins", ValueFromAmount(iface->max_money)));
	/* minted shioncoins */
	result.push_back(Pair("mintcoins", (double)iface->stat.tot_tx_mint/COIN));
	/* burnt shioncoins */
	result.push_back(Pair("burncoins", (double)iface->stat.tot_tx_return/COIN));
	/* next reward reduction block height. */
	result.push_back(Pair("nextrewardheight", nNextHeight));
	/* total blocks */
	result.push_back(Pair("totalblocks", nHeight));
	/* ~ blocks per day */
	double avg_bspan = GetAverageBlockSpan(iface);
	if (avg_bspan == 0)
		result.push_back(Pair("blocksperday", 0));
	else
		result.push_back(Pair("blocksperday", 86400 / avg_bspan));
	/* ~ tx per day */
	result.push_back(Pair("txperday", (int)GetDailyTxRate(iface)));
	/* difficulty */
	result.push_back(Pair("difficulty", GetDifficulty(ifaceIndex, NULL)));
	/* hash rate [H/s] */
	result.push_back(Pair("hashrate", GetNetworkHashPS(ifaceIndex, 120)));
	/* current reward */
	result.push_back(Pair("reward", (double)nCurValue / COIN));
#if 0
	/* reward after next reduction */
	result.push_back(Pair("nextreward", (double)nValue / COIN));
#endif

	/* single object result */
	items.push_back(result);
	return (items);
}


static unsigned int GetObjectInt(Object obj, string cmp_name)
{
	for( Object::size_type i = 0; i != obj.size(); ++i )
	{
		const Pair& pair = obj[i];
		const string& name = pair.name_;

		if (cmp_name == name) {
			const Value& value = pair.value_;
			return ((unsigned int)value.get_int());
		}
	}

	return (0);
}

static bool sort_forward(Object a, Object b) {
	unsigned int t_a = GetObjectInt(a, "time");
	unsigned int t_b = GetObjectInt(b, "time");
	return (t_a < t_b);
}

static bool sort_reverse(Object a, Object b) {
	unsigned int t_a = GetObjectInt(a, "time");
	unsigned int t_b = GetObjectInt(b, "time");
	return (t_a > t_b);
}

shjson_t *shapi_request_api_list(int ifaceIndex, shapi_t *user, string strAccount, char *method, shjson_t *params)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	int64 begin_t = (int64)shjson_num(params, "timelimit", 0);
	ApiItems result;
	string strError = "";
	uint160 hColor;
	int codeError;
	int offset;
	int err;

	hColor = uint160(string(shjson_astr(params, "color", "0x0")));

	err = 0;
	if (0 == strcmp(method, "api.account.create")) {
		result = shapi_api_account_create(ifaceIndex, strAccount, params, strError);
	} else if (0 == strcmp(method, "api.account.list")) {
		result = shapi_api_account_list(ifaceIndex, strAccount, params);
	} else if (0 == strcmp(method, "api.account.txlist")) {
		result = shapi_api_account_txlist(ifaceIndex, strAccount, params);
	} else if (0 == strcmp(method, "api.account.addr")) {
		result = shapi_api_account_addr(ifaceIndex, strAccount, params);
	} else if (0 == strcmp(method, "api.account.secret")) {
		result = shapi_api_account_secret(ifaceIndex, strAccount, params);
	} else if (0 == strcmp(method, "api.account.unspent")) {
		result = shapi_api_account_unspent(ifaceIndex, strAccount, params, hColor);
	} else if (0 == strcmp(method, "api.account.send")) {
		result = shapi_api_account_send(ifaceIndex, strAccount, params, strError, hColor);
	} else if (0 == strcmp(method, "api.account.tsend")) {
		shjson_bool_add(params, "test", 1);
		result = shapi_api_account_send(ifaceIndex, strAccount, params, strError, hColor);
	} else if (0 == strcmp(method, "api.account.bsend")) {
		shjson_bool_add(params, "batch", 1);
		result = shapi_api_account_send(ifaceIndex, strAccount, params, strError, hColor);
#if 0
	} else if (0 == strcmp(method, "api.account.bsend")) {
		result = shapi_api_account_bsend(ifaceIndex, strAccount, params, strError, hColor);
	} else if (0 == strcmp(method, "api.account.tsend")) {
		result = shapi_api_account_tsend(ifaceIndex, strAccount, params, strError, hColor);
#endif
	} else if (0 == strcmp(method, "api.order.book")) {
		result = shapi_api_book(ifaceIndex, user, params);
	} else if (0 == strcmp(method, "api.order.list")) {
		result = shapi_api_order_list(user, params);
	} else if (0 == strcmp(method, "api.order.create")) {
		result = shapi_api_order_create(user, params);
	} else if (0 == strcmp(method, "api.order.remove")) {
		result = shapi_api_order_remove(user, params);
	} else if (0 == strcmp(method, "api.order.ticker")) {
		result = shapi_api_order_ticker(user, params);
	} else if (0 == strcmp(method, "api.order.fills")) {
		result = shapi_api_order_fills(user, params);
	} else if (0 == strcmp(method, "api.order.trades")) {
		result = shapi_api_order_trades(user, params);
	} else if (0 == strcmp(method, "api.alias.list")) {
		result = shapi_api_alias_list(ifaceIndex, strAccount, params, begin_t, false);
	} else if (0 == strcmp(method, "api.alias.self")) {
		result = shapi_api_alias_list(ifaceIndex, strAccount, params, begin_t, true);
	} else if (0 == strcmp(method, "api.alias.set")) {
		codeError = shapi_api_alias_set(ifaceIndex, result, strAccount, params, strError);
	} else if (0 == strcmp(method, "api.alias.get")) {
		result = shapi_api_alias_get(ifaceIndex, strAccount, params, strError);
	} else if (0 == strcmp(method, "api.alias.info")) {
		result = shapi_api_alias_info(ifaceIndex, strAccount, params, strError);
	} else if (0 == strcmp(method, "api.context.list")) {
		result = shapi_api_context_list(ifaceIndex, strAccount, params, begin_t, false);
	} else if (0 == strcmp(method, "api.context.self")) {
		result = shapi_api_context_list(ifaceIndex, strAccount,  params, begin_t, true);
	} else if (0 == strcmp(method, "api.context.info")) {
		result = shapi_api_context_info(ifaceIndex, strAccount, params, strError);
	} else if (0 == strcmp(method, "api.context.set")) {
		result = shapi_api_context_set(ifaceIndex, strAccount, params, strError);
	} else if (0 == strcmp(method, "api.context.get")) {
		result = shapi_api_context_get(ifaceIndex, strAccount, params, strError);
	} else if (0 == strcmp(method, "api.ident.list")) {
		result = shapi_api_ident_list(ifaceIndex, user, params, begin_t);
	} else if (0 == strcmp(method, "api.cert.info")) {
		result = shapi_api_cert_info(ifaceIndex, strAccount, params);
	} else if (0 == strcmp(method, "api.cert.list")) {
		result = shapi_api_cert_list(ifaceIndex, user, params, begin_t);
	} else if (0 == strcmp(method, "api.license.list")) {
		result = shapi_api_license_list(ifaceIndex, user, params, begin_t);
	} else if (0 == strcmp(method, "api.asset.list")) {
		result = shapi_api_asset_list(ifaceIndex, user, params, begin_t);
	} else if (0 == strcmp(method, "api.exec.list")) {
		result = shapi_api_exec_list(ifaceIndex, user, params, begin_t);
	} else if (0 == strcmp(method, "api.offer.list")) {
		result = shapi_api_offer_list(ifaceIndex, user, params, begin_t);
	} else if (0 == strcmp(method, "api.alt.list")) {
		result = shapi_api_alt_list(ifaceIndex, user, params, begin_t);
	} else if (0 == strcmp(method, "api.alt.get")) {
		result = shapi_api_alt_get(ifaceIndex, user, params, strError);
	} else if (0 == strcmp(method, "api.alt.block")) {
		result = shapi_api_alt_block(ifaceIndex, user, params, strError);
	} else if (0 == strcmp(method, "api.alt.tx")) {
		result = shapi_api_alt_tx(ifaceIndex, user, params, strError);
	} else if (0 == strcmp(method, "api.alt.send")) {
		result = shapi_api_alt_send(ifaceIndex, strAccount, params, strError);
	} else if (0 == strcmp(method, "api.alt.balance")) {
		result = shapi_api_alt_balance(ifaceIndex, strAccount, params, strError);
	} else if (0 == strcmp(method, "api.validate.list")) {
		result = shapi_api_validate_list(ifaceIndex, user, params, begin_t);
	} else if (0 == strcmp(method, "api.faucet.send")) {
		result = shapi_api_faucet_send(ifaceIndex, strAccount, params, strError);
	} else if (0 == strcmp(method, "api.faucet.recv")) {
		result = shapi_api_faucet_recv(ifaceIndex, strAccount, params, strError);
	} else if (0 == strcmp(method, "api.faucet.list")) {
		result = shapi_api_faucet_list(ifaceIndex, strAccount, params);
	} else if (0 == strcmp(method, "api.faucet.info")) {
		result = shapi_api_faucet_info(ifaceIndex, strAccount, params);
	} else if (0 == strcmp(method, "api.block.mined")) {
		result = shapi_api_block_mined(ifaceIndex, user, params, begin_t);
	} else if (0 == strcmp(method, "api.block.list")) {
		result = shapi_api_block_list(ifaceIndex, user, params, begin_t);
	} else if (0 == strcmp(method, "api.block.get")) {
		result = shapi_api_block_get(ifaceIndex, user, params, begin_t);
	} else if (0 == strcmp(method, "api.block.info")) {
		result = shapi_api_block_info(ifaceIndex, user, params);
	}
	if (result.size() == 0 && strError != "") {
		shjson_t *reply = shjson_init(NULL);
		if (codeError == 0) codeError = ERR_INVAL;
		set_shapi_error(reply, codeError, (char *)strError.c_str());
		shjson_null_add(reply, "result");
		return (reply);
	}

	shjson_t *reply = shjson_init(NULL);
	shjson_t *j_if = shjson_obj_add(reply, "result");

	int idx = 0;
	begin_t = (int64)shjson_num(params, "timelimit", 0);
	offset = (int)shjson_num(params, "offset", 0);

	if (begin_t == 0) { /* reverse */
		std::sort(result.begin(), result.end(), sort_reverse);
	} else { /* forward */
		std::sort(result.begin(), result.end(), sort_forward);
	}

	bool solo = false;
#if 0
	if (result.size() == 1) {
		const Object& obj = result.first();
		int t = GetObjectInt(obj, "time");
		if (t == 0) {
			shjson_t *tree = shjson_obj_add(j_if, iface->name);
			string json_text = write_string(Value(obj), false);
			shjson_t *node = shjson_init((char *)json_text.c_str());
			shjson_AddItemToArray(tree, node);
			solo = true;
		}
	}
#endif
	if (!solo) {
		shjson_t *tree = shjson_array_add(j_if, iface->name);
		BOOST_FOREACH(const Object& obj, result) {
			if (offset > idx) { idx++; continue; }

			string json_text = write_string(Value(obj), false);
			shjson_t *node = shjson_init((char *)json_text.c_str());
			shjson_AddItemToArray(tree, node);

			idx++;
			if (idx >= MAX_API_LIST_ITEMS) break;
		}
	}

	return (reply);
}


#ifdef __cplusplus
extern "C" {
#endif

shjson_t *shapi_request_api(int ifaceIndex, shapi_t *user, char *method, shjson_t *params, shjson_t *auth)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	string strAccount;
	shjson_t *result;
	char *pkey_str;
	char *psig_str;
	char sha_result[128]; /* result is 32 bytes binary and 64 bytes hex. */
	char tbuf[128];
	uint256 in_pkey = 0;
	int64 now = (int64)time(NULL);
	int64 api_t;
	int err;

	if (!iface || !iface->enabled) {
		shjson_t *reply = shjson_init(NULL);
		set_shapi_error(reply, SHERR_OPNOTSUPP, "coin interface");
		shjson_null_add(reply, "result");
		return (reply);
	}

	if (!auth) {
		shjson_t *reply = shjson_init(NULL);
		set_shapi_error(reply, ERR_ACCESS, "authorization");
		shjson_null_add(reply, "result");
		return (reply);
	}

	strAccount = string(shjson_astr(auth, "API_ID", ""));

	pkey_str = shjson_astr(auth, "API_KEY", "");
	if (pkey_str)
		in_pkey.SetHex(pkey_str);

	api_t = (int64)shjson_num(auth, "API_STAMP", 0);
	bool found = false;
	for (int i = 0; i < 3; i++) {
		if (api_t/30 != (now/30)+(i-1)) { /* within minute */
			found = true;
			break;
		}
	}

	psig_str = shjson_astr(auth, "API_SIG", "");

	char *j_text = shjson_print(params);
	shbuf_t *buff = shbuf_init();
	shbuf_catstr(buff, j_text);
	free(j_text);
	sprintf(tbuf, "%llu", api_t);
	shbuf_catstr(buff, tbuf);
	shbuf_catstr(buff, (char *)strAccount.c_str()); 
	memset(sha_result, 0, sizeof(sha_result));
	shsha_hex(SHALG_SHA256, (unsigned char *)sha_result,
			(unsigned char *)shbuf_data(buff), shbuf_size(buff));
	shbuf_free(&buff);
	if (0 != strcasecmp(psig_str, sha_result)) {
		shjson_t *reply = shjson_init(NULL);
		set_shapi_error(reply, SHERR_ACCESS, "api credential");
		shjson_null_add(reply, "result");
		return (reply);
	}

	if (0 != strcmp(method, "api.account.create") &&
			0 != strcmp(method, "api.block.mined") &&
			!valid_pkey_hash(strAccount, in_pkey)) {
		shjson_t *reply = shjson_init(NULL);
		set_shapi_error(reply, SHERR_ACCESS, "api credential");
		shjson_null_add(reply, "result");
		return (reply);
	}

	return (shapi_request_api_list(ifaceIndex, user, strAccount, method, params));
}


#ifdef __cplusplus
}
#endif

