
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura
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

#include "shcoind.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "util.h"
#include "ui_interface.h"
#include "rpc_proto.h"
#include "txcreator.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/convenience.hpp>
#ifndef WIN32
#include <signal.h>
#endif

#define WALLET_FILENAME_SUFFIX "wallet"

using namespace std;
using namespace boost;
using namespace json_spirit;


extern Value ValueFromAmount(int64 amount);



extern void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Array& ret);

extern string JSONRPCReply(const Value& result, const Value& error, const Value& id);


string address;

Object stratumerror_obj;
void SetStratumError(Object error)
{
  stratumerror_obj = error;
}
Object GetStratumError(void)
{
  return (stratumerror_obj);
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

static bool valid_pkey_hash(string strAccount, uint256 in_pkey)
{
  CWallet *wallet;
  uint256 acc_pkey;
  int ifaceIndex;
  int valid;

	if (in_pkey == 0)
		return (false);

  valid = 0;
  for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
    wallet = GetWallet(ifaceIndex);
    if (!wallet) 
      continue;

    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
    {
      const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
      const string& strName = item.second;
      CKeyID keyID;

      if (strName != strAccount)
        continue;
      if (!address.GetKeyID(keyID))
        continue;

      acc_pkey = get_private_key_hash(wallet, keyID);
      if (acc_pkey == in_pkey)
        valid++;
    }
  }

  if (valid > 0)
    return (true);
  return (false);
}



Object JSONAddressInfo(int ifaceIndex, CCoinAddr address, bool show_priv)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  CTxDestination dest = address.Get();
  string currentAddress = address.ToString();
  Object result;

  result.push_back(Pair("address", currentAddress));

  if (iface)
    result.push_back(Pair("coin", iface->name));

  if (show_priv) {
    CKeyID keyID;
    bool fCompressed;
    CSecret vchSecret;
    uint256 pkey;

    if (!address.GetKeyID(keyID)) {
      throw JSONRPCError(STERR_ACCESS_UNAVAIL,
          "Private key for address " + currentAddress + " is not known");
    }

    pkey = get_private_key_hash(pwalletMain, keyID);
    result.push_back(Pair("pkey", pkey.GetHex()));

    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
      throw JSONRPCError(STERR_ACCESS_UNAVAIL,
          "Private key for address " + currentAddress + " is not known");
    }
    result.push_back(Pair("secret", CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString()));
  }

//    bool fMine = IsMine(*pwalletMain, dest);
#if 0
  Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
  result.insert(result.end(), detail.begin(), detail.end());
#endif
  if (pwalletMain->mapAddressBook.count(dest))
    result.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));

  return (result);
}

CCoinAddr GetNewAddress(CWallet *wallet, string strAccount)
{

  return GetAccountAddress(wallet, strAccount, true);
}

string getnewaddr_str;
const char *json_getnewaddress(int ifaceIndex, const char *account)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strAccount(account);

  if (!wallet)
    return (NULL);

  // Generate a new key that is added to wallet
  CPubKey newKey;

	newKey = GetAccountPubKey(wallet, strAccount, true);

	CKeyID keyID = newKey.GetID();
  getnewaddr_str = CCoinAddr(ifaceIndex, keyID).ToString();

  return (getnewaddr_str.c_str());
}

static CCoinAddr GetAddressByAccount(CWallet *wallet, const char *accountName, bool& found)
{
  CCoinAddr address(wallet->ifaceIndex);
  string strAccount(accountName);
  Array ret;

  // Find all addresses that have the given account
  found = false;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const string& strName = item.second;
    if (strName == strAccount) {
      address = CCoinAddr(wallet->ifaceIndex, item.first);
      if (!address.IsValid()) {
        error(SHERR_INVAL, "GetAddressByAccount: account \"%s\" has invalid coin address.", accountName); 
        continue;
      }

      found = true;
      break;
    }
  }

  return (address);
}

const char *c_getaddressbyaccount(int ifaceIndex, const char *accountName)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  bool found = false;

  if (!wallet)
    return (NULL);

  CCoinAddr addr = GetAddressByAccount(wallet, accountName, found);
  if (!found || !addr.IsValid())
     return (NULL);
  return (addr.ToString().c_str());
}

static string walletkeylist_json;
static const char *cpp_stratum_walletkeylist(int ifaceIndex, const char *acc_name)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);
  string strAccount(acc_name);
  Object ret;

  if (!iface || !wallet || !iface->enabled)
    return (NULL);

  ret.push_back(Pair("account", strAccount));

  Array ar;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook) {
    const string& strName = item.second;
    if (strName == strAccount) {
      CCoinAddr address = CCoinAddr(wallet->ifaceIndex, item.first);
      bool fComp;
      CSecret secret;
      CKeyID keyID;
      CKey key;

      if (!address.IsValid())
        continue;
      if (!address.GetKeyID(keyID))
        continue;
      if (!wallet->GetKey(keyID, key))
        continue;

      secret = key.GetSecret(fComp); 
      //cbuff buff(secret.begin(), secret.end());
      ar.push_back(CCoinSecret(ifaceIndex, secret, fComp).ToString());
     // ar.push_back(HexStr(buff.begin(), buff.end()));
    }
  }
  ret.push_back(Pair("key", ar));

  walletkeylist_json = JSONRPCReply(ret, Value::null, Value::null);
  return (walletkeylist_json.c_str());
}

static string AccountFromString(const string strAccount)
{
    if (strAccount == "*")
      return ("");
    if (strAccount.length() > 0 && strAccount.at(0) == '@')
      return ("");

    return strAccount;
}
static void GetAccountAddresses(CWallet *wallet, string strAccount, set<CTxDestination>& setAddress)
{
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CTxDestination& address = item.first;
    const string& strName = item.second;
    if (strName == strAccount)
      setAddress.insert(address);
  }
}

/* how expensive is this? */
static Value account_alias_list(int ifaceIndex, int max_alias)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  Object ret;
  alias_list *list;
  int nBestHeight;

  list = GetAliasTable(ifaceIndex);

  nBestHeight = GetBestHeight(iface);
  ret.push_back(Pair("fee",
        ValueFromAmount(GetAliasOpFee(iface, nBestHeight))));

  ret.push_back(Pair("total", (int)list->size()));

  Object alias_list;
  BOOST_FOREACH(PAIRTYPE(const string, uint256)& r, *list) {
    const string& label = r.first;
    uint256& hTx = r.second;
    CTransaction tx;
    uint256 hBlock;

    if (!GetTransaction(iface, hTx, tx, NULL))
      continue;

    alias_list.push_back(Pair(tx.alias.GetHash().GetHex(), label));
  }
  ret.push_back(Pair("alias", alias_list));

  return (ret);
}

/* obtain alias from alias hash */
static Value account_alias_get(int ifaceIndex, char *alias_hash)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  Array ret;
  alias_list *list;
  uint160 hash;

  hash = uint160(string(alias_hash));

  list = GetAliasTable(ifaceIndex);
  BOOST_FOREACH(PAIRTYPE(const string, uint256)& r, *list) {
    const string& label = r.first;
    uint256& hTx = r.second;
    CTransaction tx;
    uint256 hBlock;

    if (!GetTransaction(iface, hTx, tx, NULL))
      continue;

    if (tx.alias.GetHash() == hash) {
      ret.push_back(tx.alias.ToValue(ifaceIndex));
      break;
    }
  }

  return (ret);
}

static Value account_alias_set(int ifaceIndex, char *alias_name, char *alias_addr)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CCoinAddr addr(ifaceIndex);
  CTransaction in_tx;
  CWalletTx wtx;
  int err;

  const string alias_addr_str(alias_addr);
  addr = CCoinAddr(ifaceIndex, alias_addr_str);

  CAlias *alias = GetAliasByName(iface, alias_name, in_tx);
  if (!alias) {
    err = init_alias_addr_tx(iface, alias_name, addr, wtx);
    if (err)
      throw JSONRPCError(err, "alias address [create]");
  } else {
    err = update_alias_addr_tx(iface, alias_name, addr, wtx);
    if (err)
      throw JSONRPCError(err, "alias address [update]");
  }
    
  return (wtx.ToValue(ifaceIndex));
}

#define DEFAULT_MAX_ALIAS 10000 /* for now */
static string accountalias_json;
static const char *cpp_accountalias(int ifaceIndex, char *account, char *pkey_str, char *mode, char *alias_name, char *alias_addr)
{
  string strAccount(account);
  uint256 in_pkey;

  in_pkey.SetHex(pkey_str);
  if (!valid_pkey_hash(strAccount, in_pkey)) {
    throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified for account.");
  }

  Value ret = Value::null;
  if (!mode) {
    /* .. */
  } else if (0 == strcmp(mode, "list")) { 
    ret = account_alias_list(ifaceIndex, DEFAULT_MAX_ALIAS);
  } else if (0 == strcmp(mode, "get")) {
    /* obtain alias via it's "alias hash" */
    ret = account_alias_get(ifaceIndex, alias_name);
  } else if (0 == strcmp(mode, "set")) {
    ret = account_alias_set(ifaceIndex, alias_name, alias_addr); 
  }

  accountalias_json = JSONRPCReply(ret, Value::null, Value::null);
  return (accountalias_json.c_str());
}

static Value account_context_list(int ifaceIndex, char *account, int max_context)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
  set<CTxDestination> setAddress;
  string strAccount(account);
  Object ret;
  ctx_list *list;
  int nBestHeight;

  list = GetContextTable(ifaceIndex);

  nBestHeight = GetBestHeight(iface);
  ret.push_back(Pair("fee",
        ValueFromAmount(GetContextOpFee(iface, nBestHeight))));

  ret.push_back(Pair("total", (int)list->size()));

  strAccount = AccountFromString(strAccount);
  if (strAccount == "")
    return (Value::null);

  /* get set of pub keys assigned to extended account. */
  string strExtAccount = "@" + strAccount;
  GetAccountAddresses(wallet, strExtAccount, setAddress);
  if (setAddress.size() == 0) {
    return (ret);
  }

  Array ctx_list;
  BOOST_FOREACH(const PAIRTYPE(uint160, uint256)& r, *list) {
    const uint160& hContext = r.first;
    const uint256& hTx = r.second;
    CTransaction tx;

    if (!GetTransaction(iface, hTx, tx, NULL))
      continue;

    /* filter by account name. */
    int nOut = IndexOfExtOutput(tx);
    if (nOut == -1)
      continue;

    CTxDestination dest;
    const CTxOut& txout = tx.vout[nOut];
    if (!ExtractDestination(txout.scriptPubKey, dest))
      continue;

    if (setAddress.count(dest) == 0)
      continue;

    ctx_list.push_back(hContext.GetHex());
  }
  ret.push_back(Pair("context", ctx_list));

  return (ret);
}

static Value account_context_get(int ifaceIndex, char *account, char *ctx_name)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CContext *ctx;
  CTransaction tx;
  set<CTxDestination> setAddress;
  ctx_list *list;
  string strAccount;
  int nBestHeight;

  string ctxNameStr(ctx_name);
  uint160 hContext(ctxNameStr);
  ctx = GetContextByHash(iface, hContext, tx);
  if (!ctx) {
    return (Value::null);//throw JSONRPCError(-5, string("unknown context hash"));
  }

  Object obj = ctx->ToValue();
  obj.push_back(Pair("tx", tx.GetHash().GetHex()));
  return (obj);
}

static Value account_context_set(int ifaceIndex, char *account, char *ctx_name, char *ctx_value)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
  string strAccount(account);
  string strName(ctx_name);
  string strValue(ctx_value);
  CContext *ctx;
  CWalletTx wtx;
  int err;

  cbuff vchValue(strValue.begin(), strValue.end());
  err = init_ctx_tx(iface, wtx, strAccount, strName, vchValue);
  if (err) {
    throw JSONRPCError(err, string(sherrstr(err)));
  }

  ctx = (CContext *)&wtx.certificate;
  Object obj = ctx->ToValue();
  obj.push_back(Pair("tx", wtx.GetHash().GetHex()));

  int nBestHeight = GetBestHeight(iface);
  int nTxSize = (int)wallet->GetVirtualTransactionSize(wtx);
  int64_t nFee = MIN_TX_FEE(iface);
  int64_t nOutValue = wtx.GetValueOut();
  int64_t nContextFee = nOutValue - nFee;

  obj.push_back(Pair("account", strAccount));
  obj.push_back(Pair("fee", ValueFromAmount(nFee)));
  obj.push_back(Pair("context-fee", ValueFromAmount(nContextFee)));
  obj.push_back(Pair("output-value", ValueFromAmount(nOutValue)));
  obj.push_back(Pair("total-size", nTxSize));

  return (obj);
}

#define DEFAULT_MAX_CONTEXT 10000 /* for now */
static string accountcontext_json;
static const char *cpp_accountcontext(int ifaceIndex, char *account, char *pkey_str, char *mode, char *ctx_name, char *ctx_value)
{
  string strAccount(account);
  uint256 in_pkey;

  in_pkey.SetHex(pkey_str);
  if (!valid_pkey_hash(strAccount, in_pkey)) {
    throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified for account.");
  }

  Value ret = Value::null;
  if (!mode) {
    /* .. */
  } else if (0 == strcmp(mode, "list")) { 
    ret = account_context_list(ifaceIndex, account, DEFAULT_MAX_CONTEXT);
  } else if (0 == strcmp(mode, "get")) {
    /* obtain context via it's "context hash" */
    ret = account_context_get(ifaceIndex, account, ctx_name);
  } else if (0 == strcmp(mode, "set")) {
    ret = account_context_set(ifaceIndex, account, ctx_name, ctx_value); 
  }

  accountcontext_json = JSONRPCReply(ret, Value::null, Value::null);
  return (accountcontext_json.c_str());
}

#define DEFAULT_MAX_CONTEXT 10000 /* for now */
static string accountcertificate_json;
static const char *cpp_accountcertificate(int ifaceIndex, char *account, char *pkey_str, char *mode, char *cert_name, char *cert_issuer, double fee)
{
  string strAccount(account);
  uint256 in_pkey;

  in_pkey.SetHex(pkey_str);
  if (!valid_pkey_hash(strAccount, in_pkey)) {
    throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified for account.");
  }

  Value ret = Value::null;

  if (!mode) {
    /* .. */
  } else if (0 == strcmp(mode, "list")) {
  } else if (0 == strcmp(mode, "get")) {
  } else if (0 == strcmp(mode, "set")) {
  }

  accountcertificate_json = JSONRPCReply(ret, Value::null, Value::null);
  return (accountcertificate_json.c_str());
}

/**
 * Sends a reward to a particular address.
 */
int c_setblockreward(int ifaceIndex, const char *accountName, double dAmount)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  string strMainAccount("");
  string strAccount(accountName);
  string strComment("sharenet");
  int64 nAmount;
  Array ret;
  int nMinDepth = 1; /* single confirmation requirement */
  int nMinConfirmDepth = 1; /* single confirmation requirement */
  bool found = false;
  int64 nBalance;

  if (dAmount <= 0)
    return (SHERR_INVAL);

  const CCoinAddr address = GetAddressByAccount(pwalletMain, accountName, found);
  if (!found) {
    error(SHERR_INVAL, "warning: c_setblockreward[iface #%d]: account '%s' not found\n", ifaceIndex, accountName);
    return (-5);
  }
  if (!address.IsValid()) {
    char errbuf[1024];
    sprintf(errbuf, "setblockreward: account '%s' has invalid %s address.", accountName, iface->name);
    shcoind_log(errbuf);
    return (-5);
  }


  if (dAmount <= 0.0 || dAmount > 84000000.0) {
    return (-3);
  }

  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount)) {
    return (-3);
  }

  nBalance  = GetAccountBalance(ifaceIndex, strMainAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
    shcoind_log("c_setblockreward: warning: main account has insufficient funds for block reward distribution.");
    return (-6);
  }

  CWalletTx wtx;
  wtx.strFromAccount = strMainAccount;
  wtx.mapValue["comment"] = strComment;
  string strError = pwalletMain->SendMoneyToDestination(strMainAccount, address.Get(), nAmount, wtx);
  if (strError != "") {
    //throw JSONRPCError(-4, strError);
    return (-4);
  }

  return (0);
}

//vector< pair<CScript, int64> > vecRewardSend;
map<string, int64> vecRewardSend;

int c_addblockreward(int ifaceIndex, const char *accountName, double dAmount)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  string strAccount(accountName);
  string strMainAccount("");
  int64 nAmount;
  Array ret;
  int nMinDepth = 1; /* single confirmation requirement */
  int nMinConfirmDepth = 1; /* single confirmation requirement */
  int64 nBalance;

  if (dAmount <= 0.0 || dAmount > 84000000.0)
    return (-3);
  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount))
    return (-3);

	if (vecRewardSend.count(strAccount) != 0)
		nAmount += vecRewardSend[strAccount];
	vecRewardSend[strAccount] = nAmount; 

	return (0);
}

void c_sendblockreward(int ifaceIndex)
{
	static int64 nAvgFee;
//	static int64 nRunFee;
  static const int nMinConfirmDepth = 1; /* single confirmation requirement */
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
	map<string, int64> vecNewRewardSend;
	string strMainAccount("");
	int64 nTotal;

	if (nAvgFee == 0)
		nAvgFee = MIN_TX_FEE(iface); 


	nTotal = 0;
	vector< pair<CScript, int64> > vecReward;
  BOOST_FOREACH(const PAIRTYPE(string, int64)& item, vecRewardSend) {
		const string& strAccount = item.first;
		const int64& nValue = item.second;

		bool found = false;
		CCoinAddr address = GetAddressByAccount(wallet, strAccount.c_str(), found);
		if (!found || !address.IsValid()) {
			continue;
		}

		if (nValue < MIN_TX_FEE(iface)) {
			vecNewRewardSend[strAccount] = nValue;
			continue;
		}

		CScript scriptPubKey;
		scriptPubKey.SetDestination(address.Get());
		vecReward.push_back(make_pair(scriptPubKey, nValue));

		nTotal += nValue;
	}

	/* check main account balance. */
  if (nTotal > MIN_INPUT_VALUE(iface)) {
		int64 nBalance  = GetAccountBalance(ifaceIndex, strMainAccount, nMinConfirmDepth);
		if (nTotal > nBalance) {
			shcoind_log("c_setblockreward: warning: main account has insufficient funds for block reward distribution.");
			return;
		}
	}

	/* clear pending payments. */
	vecRewardSend = vecNewRewardSend;

  if (vecReward.size() == 0)
    return; /* all done */

	/* create new vector with tx fee subtracted. */
	int64 nFee = nAvgFee / vecReward.size();
	vector< pair<CScript, int64> > vecSend;
  BOOST_FOREACH(const PAIRTYPE(CScript, int64)& item, vecReward) {
		int64 nValue = (item.second - nFee);
		vecSend.push_back(make_pair(item.first, nValue));
	}
	
#if 0
	/* add in dest for non-spent tx fees. */
	if (nRunFee > (MIN_TX_FEE(iface) * 2)) {
		const char *strBankAccountName = "bank";
		bool found = false;
		CCoinAddr bankAddr = GetAddressByAccount(wallet, strBankAccountName, found);
		if (found) {
			CScript scriptPubKey;

			/* send subsidy to "bank" account. */
			scriptPubKey.SetDestination(bankAddr.Get());
			vecSend.push_back(make_pair(scriptPubKey, nRunFee));

			/* clear running total */
			nRunFee = 0;
		}
	}
#endif

	/* commit the transaction. */
	{
		CWalletTx wtx;
		string strError;
		int64 nFeeRet;
		bool fRet;

		wtx.strFromAccount = strMainAccount;
		fRet = wallet->CreateAccountTransaction(strMainAccount, vecSend, wtx, strError, nFeeRet);
		if (!fRet)
			return;

		fRet = wallet->CommitTransaction(wtx);
		if (!fRet)
			return;

#if 0
		/* deduct the running fee not used to create tx's. */
		nRunFee += MAX(0, nFee - nFeeRet);
#endif

		/* keep running average of tx-fee required to send coins. */
		nAvgFee = MIN(MIN_TX_FEE(iface), (nAvgFee + nFeeRet) / 2);
		nAvgFee = MAX(nAvgFee, (nTotal / 1000)); /* 0.001% stratum fee */

		Debug("sendblockreward: sent %f coins for stratum reward(s) [tx-fee %f].", (double)nTotal/(double)COIN, (double)nFeeRet/(double)COIN);
	}

}

/**
 * Transfer currency between two accounts.
 */
static int c_wallet_account_transfer(int ifaceIndex, const char *sourceAccountName, const char *accountName, const char *comment, double dAmount)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);

  if (0 == strcmp(sourceAccountName, ""))
    return (-14);

  string strMainAccount(sourceAccountName);
  string strAccount(accountName);
  string strComment(comment);
  int64 nAmount;
  Array ret;
  int nMinDepth = 1; /* single confirmation requirement */
  int nMinConfirmDepth = 1; /* single confirmation requirement */
  bool found = false;
  int64 nBalance;

  // Find all addresses that have the given account
  CCoinAddr address(ifaceIndex);
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
  {
    const CCoinAddr& acc_address = CCoinAddr(ifaceIndex, item.first);
    const string& strName = item.second;
    if (strName == strAccount) {
      address = acc_address;
      found = true;
    }
  }
  if (!found) {
    return (-7);
  }

  if (dAmount <= 0.0 || dAmount > 84000000.0) {
    //throw JSONRPCError(-3, "Invalid amount");
    return (-3);
  }

  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount)) {
    //throw JSONRPCError(-3, "Invalid amount");
    return (-3);
  }


  nBalance  = GetAccountBalance(ifaceIndex, strMainAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
    //throw JSONRPCError(-6, "Account has insufficient funds");
    return (-6);
  }

  //address = GetAddressByAccount(accountName);
  if (!address.IsValid()) {
    return (-5);
  }

  CWalletTx wtx;
  wtx.strFromAccount = strMainAccount;
  wtx.mapValue["comment"] = strComment;
  string strError = pwalletMain->SendMoneyToDestination(strMainAccount, address.Get(), nAmount, wtx);
  if (strError != "") {
    return (-4);
  }

  return (0);
}

double c_getaccountbalance(int ifaceIndex, const char *accountName)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  string strAccount(accountName);

  int nMinDepth = 1;
  int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);

  return ((double)nBalance / (double)COIN);
}


bool GetStratumKeyAccount(uint256 in_pkey, string& strAccount)
{
  static uint256 local_site_key;
  CWallet *wallet;
  uint256 acc_pkey;
  int ifaceIndex;
  int valid;


  valid = 0;
  for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
    wallet = GetWallet(ifaceIndex);
    if (!wallet) 
      continue;

    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
    {
      const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
      const string& strName = item.second;
      CKeyID keyID;

      if (!address.GetKeyID(keyID))
        continue;

      acc_pkey = get_private_key_hash(wallet, keyID);
      if (acc_pkey == in_pkey) {
        strAccount = strName;
        return (true);
      }
    }
  }

  return (false);
}

static bool IsSentFromAccount(CIface *iface, string strAccount, const CTxIn& in)
{
  CWallet *wallet = GetWallet(iface);
  CTransaction tx;

  if (!GetTransaction(iface, in.prevout.hash, tx, NULL))
    return (FALSE);
 
  const CTxOut& out = tx.vout[in.prevout.n];
  const CScript& pk = out.scriptPubKey;
  CTxDestination address;

  if (!ExtractDestination(pk, address))
    return (FALSE);

  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook) {
    const string& account = item.second;
    if (account != strAccount)
      continue;

    if (address == item.first)
      return (TRUE);
  }

  return (FALSE);
}

/**
 * local up to 100 transactions associated with account name.
 * @param duration The range in the past to search for account transactions (in seconds).
 * @returns json string format 
 */
string accounttransactioninfo_json;
static const char *json_getaccounttransactioninfo(int ifaceIndex, const char *tx_account, const char *pkey_str)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
  string strAccount(tx_account);
  uint256 in_pkey = 0;

  Array result;
  try {
    in_pkey.SetHex(pkey_str);
    if (!valid_pkey_hash(strAccount, in_pkey)) {
      throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
    }

    vector<COutput> vecOutputs;
    wallet->AvailableAccountCoins(strAccount, vecOutputs, false);
    BOOST_FOREACH(const COutput& out, vecOutputs) {
      int64 nValue = out.tx->vout[out.i].nValue;
      const CScript& pk = out.tx->vout[out.i].scriptPubKey;

      CTxDestination address;
      if (!ExtractDestination(pk, address))
        continue;  

      BOOST_FOREACH(const CTxIn& in, out.tx->vin) {
        if (IsSentFromAccount(iface, strAccount, in)) {
          /* do not list change */
          continue;
        }
      }

      const CTransaction& tx = *out.tx;
      int nTxSize = (int)wallet->GetVirtualTransactionSize(tx);
      CCoinAddr c_addr(ifaceIndex, address);

      Object entry = JSONAddressInfo(ifaceIndex, c_addr, false);
      entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
      entry.push_back(Pair("hash", out.tx->GetWitnessHash().GetHex()));
      entry.push_back(Pair("vout", out.i));
      entry.push_back(Pair("script", pk.ToString()));
      entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
      entry.push_back(Pair("amount",ValueFromAmount(nValue)));
      entry.push_back(Pair("confirmations",out.nDepth));
      entry.push_back(Pair("total-size", nTxSize)); 
      result.push_back(entry);
    }
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  accounttransactioninfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (accounttransactioninfo_json.c_str());
}

string addressinfo_json;
const char *json_getaddressinfo(int ifaceIndex, const char *addr_hash, const char *pkey_str)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strAddr(addr_hash);
  Object result;
	uint256 in_pkey = 0;

	in_pkey.SetHex(pkey_str);
	if (in_pkey == 0) {
		throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
	}

  try {
    CCoinAddr address(ifaceIndex, strAddr);
    CKeyID keyID;

    if (!address.IsValid()) {
      throw JSONRPCError(STERR_INVAL, "Invalid coin destination address");
    }

    if (pkey_str && strlen(pkey_str) > 1) {
      uint256 acc_pkey;

      if (!address.GetKeyID(keyID)) {
        throw JSONRPCError(STERR_ACCESS, "Address does not refer to a key.");
      }

      acc_pkey = get_private_key_hash(wallet, keyID);
      if (acc_pkey != in_pkey) {
        throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
      }
    }

#if 0
    if (pkey_str) { /* optional */
      uint256 in_pkey = 0;
      uint256 acc_pkey;

      if (!address.GetKeyID(keyID)) {
        throw JSONRPCError(STERR_ACCESS, "Address does not refer to a key.");
      }

      in_pkey.SetHex(pkey_str);
      acc_pkey = get_private_key_hash(keyID);
      if (acc_pkey != in_pkey) {
        throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
      }
    }

    CTxDestination dest = address.Get();
    string currentAddress = address.ToString();
    result.push_back(Pair("address", currentAddress));
    if (pkey_str) {
      bool fCompressed;
      CSecret vchSecret;
      if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
        throw JSONRPCError(STERR_ACCESS_UNAVAIL,
            "Private key for address " + currentAddress + " is not known");
      }
      result.push_back(Pair("secret", CCoinSecret(vchSecret, fCompressed).ToString()));
    }

//    bool fMine = IsMine(*pwalletMain, dest);
    Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
    result.insert(result.end(), detail.begin(), detail.end());
    if (pwalletMain->mapAddressBook.count(dest))
      result.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));
#endif
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

	CCoinAddr addr(ifaceIndex, addr_hash);
  if (pkey_str && strlen(pkey_str) > 1) {
    result = JSONAddressInfo(ifaceIndex, addr, true);
  } else {
    result = JSONAddressInfo(ifaceIndex, addr, false);
  }

  addressinfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (addressinfo_json.c_str());
}

bool VerifyLocalAddress(CWallet *wallet, CKeyID vchAddress)
{
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(wallet->ifaceIndex, item.first);
    const string& strName = item.second;
    CKeyID keyID;
    address.GetKeyID(keyID);
    if (keyID == vchAddress)
      return (true);
  }

  return (false);
}

string createaccount_json;
static const char *json_stratum_create_account(int ifaceIndex, const char *acc_name)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strAccount(acc_name);
  string coinAddr = "";
  uint256 phash = 0;
  CPubKey newKey;
  bool found;
  int idx;

  try {
    if (strAccount == "" || strAccount == "*") {
      throw JSONRPCError(STERR_INVAL_PARAM, "The account name specified is invalid.");
    }

    /* check for duplicate against all coin services. */
    for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
      CWallet *wallet = GetWallet(idx); 
      if (!wallet)
        continue;

      found = false;
      CCoinAddr address = GetAddressByAccount(wallet, acc_name, found);
      if (found && address.IsValid()) {
        throw JSONRPCError(STERR_INVAL_PARAM, "Account name is not unique.");
      }

    }

    /* generate new account for all coin services. */
    for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
      CWallet *wallet = GetWallet(idx); 
      if (!wallet)
        continue;

#if 0
      /* Generate a new key that is added to wallet. */
      if (!wallet->GetKeyFromPool(newKey, false)) {
        if (!wallet->IsLocked())
          wallet->TopUpKeyPool();
        if (!wallet->GetKeyFromPool(newKey, false)) {
          throw JSONRPCError(STERR_INTERNAL_MAP, "No new keys currently available.");
          return (NULL);
        }
      }
#endif
      newKey = GetAccountPubKey(wallet, strAccount, true);


      CKeyID keyId = newKey.GetID();
      wallet->SetAddressBookName(keyId, strAccount);
      if (ifaceIndex == idx) {
        coinAddr = CCoinAddr(ifaceIndex, keyId).ToString();
        phash = get_private_key_hash(wallet, keyId);
      }
    }
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  Object result;
  result.push_back(Pair("address", coinAddr));
  result.push_back(Pair("key", phash.GetHex()));
  createaccount_json = JSONRPCReply(result, Value::null, Value::null);
  return (createaccount_json.c_str());
}

char *transferaccount_json;
static const char *c_stratum_account_transfer(int ifaceIndex, char *account, char *pkey_str, char *dest, double amount)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);
  string strAccount(account);
  const int nMinDepth = 1;
  int64 nFee = 0;
  int64 nSent;
  int64 nValue;
  int nBytes;
  int nInputs;

  if (!iface || !wallet || !iface->enabled) {
    return (NULL); //throw JSONRPCError(STERR_INVAL, "invalid coin service");
  }

  string strDestAddress(dest);

  std::vector<unsigned char> vchTemp;
  DecodeBase58Check(strDestAddress, vchTemp);
  if (vchTemp.empty()) {
    return (NULL);//throw JSONRPCError(STERR_INVAL, "invalid coin address");
  }

  CCoinAddr address(ifaceIndex, strDestAddress);
  if (!address.IsValid()) {
    return (NULL);//throw JSONRPCError(STERR_INVAL, "invalid coin address");
  }
#if 0
  if (address.GetVersion() != CCoinAddr::GetCoinAddrVersion(ifaceIndex)) {
    return (NULL);//throw JSONRPCError(-5, "Invalid address for coin service.");
  }
#endif

  uint256 in_pkey = 0;
  in_pkey.SetHex(pkey_str);
  if (!valid_pkey_hash(strAccount, in_pkey)) {
    return (NULL);//throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
  }

  int64 nAmount = roundint64(amount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount) || nAmount <= nFee) {
    return (NULL);//throw JSONRPCError(STERR_INVAL_AMOUNT, "Invalid coin amount.");
  }

  int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
  if (nAmount > nBalance)
    return (NULL);//throw JSONRPCError(-6, "Account has insufficient funds");

  /* init batch tx creator */
  CScript scriptPub;
  scriptPub.SetDestination(address.Get());
  CTxBatchCreator b_tx(wallet, strAccount, scriptPub, nAmount); 

  if (!b_tx.Generate()) {
    string strError = b_tx.GetError();
    if (strError == "")
      strError = "An unknown error occurred while generating the transactions.";
    return (NULL);//throw JSONRPCError(-6, strError);
  } 

  if (!b_tx.Send()) {
    return (NULL);
  }

  int64 nValueOut = 0;
  int64 nChangeOut = 0;
  int64 nValueIn = 0;
  int64 nTxSize = 0;
  int nInputTotal = 0;
  int64 nSigTotal = 0;

  vector<CWalletTx>& tx_list = b_tx.GetTxList();

  tx_cache inputs;
  BOOST_FOREACH(CWalletTx& wtx, tx_list) {
    nInputTotal += wtx.vin.size();
    nSigTotal += wtx.GetLegacySigOpCount();

    wallet->FillInputs(wtx, inputs);
    nTxSize += wallet->GetVirtualTransactionSize(wtx);
  }
  BOOST_FOREACH(CWalletTx& wtx, tx_list) {
    BOOST_FOREACH(const CTxIn& txin, wtx.vin) {
      CTxOut out;
      if (!wtx.GetOutputFor(txin, inputs, out)) {
        continue;
      }

      nValueIn += out.nValue;
    }
  }

  BOOST_FOREACH(CWalletTx& wtx, tx_list) {
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
  nBalance = MAX(0, nBalance - (nValueOut + nFee));

  Object ret;
  ret.push_back(Pair("fee", ValueFromAmount(nFee)));
  ret.push_back(Pair("input-value", ValueFromAmount(nValueIn)));
  ret.push_back(Pair("total-tx", (int)tx_list.size()));
  ret.push_back(Pair("total-inputs", (int)nInputTotal));
  ret.push_back(Pair("total-sigops", (int)nSigTotal));
  ret.push_back(Pair("total-size", (int)nTxSize));

  Object ret_out;
  ret_out.push_back(Pair("account", strAccount));
  ret_out.push_back(Pair("balance", ValueFromAmount(nBalance)));
  ret_out.push_back(Pair("output-value", ValueFromAmount(nValueOut)));
  ret_out.push_back(Pair("change-value", ValueFromAmount(nChangeOut)));
  ret_out.push_back(Pair("target-value", ValueFromAmount(nAmount)));
  ret.push_back(Pair("out", ret_out));

  Array ar;
  BOOST_FOREACH(CWalletTx& wtx, tx_list) {
    ar.push_back(wtx.GetHash().GetHex());
  }
  ret.push_back(Pair("tx", ar));

  if (transferaccount_json)
    free(transferaccount_json);
  string strJson = JSONRPCReply(ret, Value::null, Value::null);
  transferaccount_json = strdup(strJson.c_str());
  return ((const char *)transferaccount_json);
}

char *verifytransferaccount_json;
static const char *c_stratum_account_verify_transfer(int ifaceIndex, char *account, char *pkey_str, char *dest, double amount)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);
  string strAccount(account);
  const int nMinDepth = 1;
  int64 nFee = 0;
  int64 nSent;
  int64 nValue;
  int nBytes;
  int nInputs;

  if (!iface || !wallet || !iface->enabled) {
    return (NULL); //throw JSONRPCError(STERR_INVAL, "invalid coin service");
  }

  string strDestAddress(dest);

  std::vector<unsigned char> vchTemp;
  DecodeBase58Check(strDestAddress, vchTemp);
  if (vchTemp.empty()) {
    return (NULL);//throw JSONRPCError(STERR_INVAL, "invalid coin address");
  }

  CCoinAddr address(ifaceIndex, strDestAddress);
  if (!address.IsValid()) {
    return (NULL);//throw JSONRPCError(STERR_INVAL, "invalid coin address");
  }
#if 0
  if (address.GetVersion() != CCoinAddr::GetCoinAddrVersion(ifaceIndex)) {
    return (NULL);//throw JSONRPCError(-5, "Invalid address for coin service.");
  }
#endif

  uint256 in_pkey = 0;
  in_pkey.SetHex(pkey_str);
  if (!valid_pkey_hash(strAccount, in_pkey)) {
    return (NULL);//throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
  }

  int64 nAmount = roundint64(amount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount) || nAmount <= nFee) {
    return (NULL);//throw JSONRPCError(STERR_INVAL_AMOUNT, "Invalid coin amount.");
  }

  int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
  if (nAmount > nBalance)
    return (NULL);//throw JSONRPCError(-6, "Account has insufficient funds");

  /* init batch tx creator */
  CScript scriptPub;
  scriptPub.SetDestination(address.Get());
  CTxBatchCreator b_tx(wallet, strAccount, scriptPub, nAmount); 

  if (!b_tx.Generate()) {
    string strError = b_tx.GetError();
    if (strError == "")
      strError = "An unknown error occurred while generating the transactions.";
    return (NULL);//throw JSONRPCError(-6, strError);
  } 

  /* suppress Send() for verification.. */

  int64 nValueOut = 0;
  int64 nChangeOut = 0;
  int64 nValueIn = 0;
  int64 nTxSize = 0;
  int nInputTotal = 0;
  int64 nSigTotal = 0;

  vector<CWalletTx>& tx_list = b_tx.GetTxList();

  tx_cache inputs;
  BOOST_FOREACH(CWalletTx& wtx, tx_list) {
    nInputTotal += wtx.vin.size();
    nSigTotal += wtx.GetLegacySigOpCount();

    wallet->FillInputs(wtx, inputs);
    nTxSize += wallet->GetVirtualTransactionSize(wtx);
  }
  BOOST_FOREACH(CWalletTx& wtx, tx_list) {
    BOOST_FOREACH(const CTxIn& txin, wtx.vin) {
      CTxOut out;
      if (!wtx.GetOutputFor(txin, inputs, out)) {
        continue;
      }

      nValueIn += out.nValue;
    }
  }

  BOOST_FOREACH(CWalletTx& wtx, tx_list) {
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
  nBalance = MAX(0, nBalance - (nValueOut + nFee));

  Object ret;
  ret.push_back(Pair("fee", ValueFromAmount(nFee)));
  ret.push_back(Pair("input-value", ValueFromAmount(nValueIn)));
  ret.push_back(Pair("total-tx", (int)tx_list.size()));
  ret.push_back(Pair("total-inputs", (int)nInputTotal));
  ret.push_back(Pair("total-sigops", (int)nSigTotal));
  ret.push_back(Pair("total-size", (int)nTxSize));

  Object ret_out;
  ret_out.push_back(Pair("account", strAccount));
  ret_out.push_back(Pair("balance", ValueFromAmount(nBalance)));
  ret_out.push_back(Pair("output-value", ValueFromAmount(nValueOut)));
  ret_out.push_back(Pair("change-value", ValueFromAmount(nChangeOut)));
  ret_out.push_back(Pair("target-value", ValueFromAmount(nAmount)));
  ret.push_back(Pair("out", ret_out));

#if 0
  Array ar;
  BOOST_FOREACH(CWalletTx& wtx, tx_list) {
    ar.push_back(wtx.ToValue(ifaceIndex));    
  }
  ret.push_back(Pair("tx", ar));
#endif

  if (verifytransferaccount_json)
    free(verifytransferaccount_json);
  string strJson = JSONRPCReply(ret, Value::null, Value::null);
  verifytransferaccount_json = strdup(strJson.c_str());
  return ((const char *)verifytransferaccount_json);
}

string accountinfo_json;
static const char *c_stratum_account_info(int ifaceIndex, const char *acc_name, const char *pkey_str)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  CIface *iface = GetCoinByIndex(ifaceIndex);
  string strAccount(acc_name);
  int64 nConfirm;
  int64 nUnconfirm;
  int nMinDepth = 1;
  Object result;
  Array addr_list;
  uint256 phash;

  try {
    if (strAccount == "" || strAccount == "*") {
      return (NULL);//throw JSONRPCError(STERR_INVAL_PARAM, "The account name specified is invalid.");
    }

    if (pkey_str) {
      uint256 in_pkey;

      in_pkey.SetHex(pkey_str);
      if (!valid_pkey_hash(strAccount, in_pkey)) {
        return (NULL);//throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified for account.");
      }
    }

    nConfirm = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
    nUnconfirm = GetAccountBalance(ifaceIndex, strAccount, 0) - nConfirm;
    result.push_back(Pair("confirmed", ValueFromAmount(nConfirm)));
    result.push_back(Pair("unconfirmed", ValueFromAmount(nUnconfirm)));

    // Find all addresses that have the given account
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
    {
      const CCoinAddr& acc_address = CCoinAddr(ifaceIndex, item.first);
      const string& strName = item.second;
      if (strName == strAccount) {
        addr_list.push_back(JSONAddressInfo(ifaceIndex, acc_address, false));
      }
    }
    result.push_back(Pair("addresses", addr_list));
#if 0
    BOOST_FOREACH(const PAIRTYPE(CCoinAddr, string)& item, pwalletMain->mapAddressBook)
    {
      const CCoinAddr& acc_address = item.first;
      const string& strName = item.second;
      if (strName == strAccount) {
        addr_list.push_back(acc_address.ToString());

        CKeyID keyID;
        acc_address.GetKeyID(keyID);
        phash = get_private_key_hash(keyID);
      }
    }
    result.push_back(Pair("addresses", addr_list));
#endif
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  accountinfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (accountinfo_json.c_str());
}

string account_import_json;
static const char *json_stratum_account_import(int ifaceIndex, const char *acc_name, const char *privaddr_str)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *pwalletMain = GetWallet(iface);
  string strLabel(acc_name);
  string strSecret(privaddr_str);
  CCoinSecret vchSecret;
  CKeyID vchAddress;
  bool ok;

  try {
    ok = vchSecret.SetString(strSecret);
    if (!ok) {
      return (NULL);//throw JSONRPCError(STERR_INVAL, "Invalid private key specified.");
    }

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    vchAddress = key.GetPubKey().GetID();

    if (VerifyLocalAddress(pwalletMain, vchAddress)) {
      return (NULL);//throw JSONRPCError(STERR_INVAL_PARAM, "Address already registered to local account.");
    }

    {
      LOCK2(cs_main, pwalletMain->cs_wallet);

      pwalletMain->MarkDirty();
      pwalletMain->SetAddressBookName(vchAddress, strLabel);

      if (pwalletMain->AddKey(key)) {
        /* key did not previously exist in wallet db */
        pwalletMain->ScanForWalletTransactions(GetGenesisBlockIndex(iface));
        pwalletMain->ReacceptWalletTransactions();
      }
    }
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  Object result;
  CCoinAddr addr(ifaceIndex, vchAddress);

  result.push_back(Pair("address", addr.ToString()));
  account_import_json = JSONRPCReply(result, Value::null, Value::null);
  return (account_import_json.c_str());
}

string stratumerror_json;
const char *c_stratum_error_get(int req_id)
{
  Object error;
  Object reply;
  Value id = req_id;

  error = GetStratumError();
  stratumerror_json = JSONRPCReply(Value::null, error, id);
  return (stratumerror_json.c_str());
}



#ifdef __cplusplus
extern "C" {
#endif

const char *getaddressbyaccount(int ifaceIndex, const char *accountName)
{
  if (accountName || !*accountName)
    return (NULL);
  return (c_getaddressbyaccount(ifaceIndex, accountName));
}

double getaccountbalance(int ifaceIndex, const char *accountName)
{
  return (c_getaccountbalance(ifaceIndex, accountName));
}

int setblockreward(int ifaceIndex, const char *accountName, double amount)
{
  if (!*accountName)
    return (-5); /* invalid coin address */
  return (c_setblockreward(ifaceIndex, accountName, amount));
}

int addblockreward(int ifaceIndex, const char *accountName, double amount)
{
  if (!*accountName)
    return (-5); /* invalid coin address */
  return (c_addblockreward(ifaceIndex, accountName, amount));
}

int sendblockreward(int ifaceIndex)
{
  c_sendblockreward(ifaceIndex);
	return (0);
}

int wallet_account_transfer(int ifaceIndex, const char *sourceAccountName, const char *accountName, const char *comment, double amount)
{
  if (!accountName || !*accountName)
    return (-5); /* invalid address */
  return (c_wallet_account_transfer(ifaceIndex, sourceAccountName, accountName, comment, amount));
}

const char *getaccounttransactioninfo(int ifaceIndex, const char *account, const char *pkey_str)
{
  if (!account)
    return (NULL);
  return (json_getaccounttransactioninfo(ifaceIndex, account, pkey_str));
}

const char *stratum_getaddressinfo(int ifaceIndex, const char *addr_hash)
{
  if (!addr_hash)
    return (NULL);
  return (json_getaddressinfo(ifaceIndex, addr_hash, NULL));
}
const char *stratum_getaddresssecret(int ifaceIndex, const char *addr_hash, const char *pkey_str)
{
  if (!addr_hash)
    return (NULL);
  return (json_getaddressinfo(ifaceIndex, addr_hash, pkey_str));
}

const char *stratum_create_account(int ifaceIndex, const char *acc_name)
{
  if (!acc_name)
    return (NULL);
  return (json_stratum_create_account(ifaceIndex, acc_name));
}

const char *stratum_create_transaction(int ifaceIndex, char *account, char *pkey_str, char *dest, double amount)
{
  if (!account || !pkey_str || !dest)
    return (NULL);
  return (c_stratum_account_transfer(ifaceIndex, account, pkey_str, dest, amount));
}

const char *stratum_verify_transaction(int ifaceIndex, char *account, char *pkey_str, char *dest, double amount)
{
  if (!account || !pkey_str || !dest)
    return (NULL);
  return (c_stratum_account_verify_transfer(ifaceIndex, account, pkey_str, dest, amount));
}

const char *stratum_getaccountinfo(int ifaceIndex, const char *account, const char *pkey_str)
{
  if (!account)
    return (NULL);
  return (c_stratum_account_info(ifaceIndex, account, pkey_str));
}

const char *stratum_error_get(int req_id)
{
  return (c_stratum_error_get(req_id));
}

const char *stratum_importaddress(int ifaceIndex, const char *account, const char *privaddr_str)
{
  if (!account || !privaddr_str)
    return (NULL);
  return (json_stratum_account_import(ifaceIndex, account, privaddr_str));
}

const char *getnewaddress(int ifaceIndex, const char *account)
{
  return (json_getnewaddress(ifaceIndex, account));
}

static uint32_t generate_addrlist_crc(int ifaceIndex, const char *acc_name) 
{
  CIface *iface;
  CWallet *wallet;
  string strAccount;
  char buf[1024];
  uint32_t ret_crc;

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled) return (0);
  wallet = GetWallet(iface);
  if (!wallet) return (0);
  if (!acc_name) return (0);
  strAccount = acc_name;

  ret_crc = 0;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook) {
    const string& strName = item.second;
    if (strName == strAccount) {
      const CCoinAddr& acc_address = CCoinAddr(ifaceIndex, item.first);
      string strAddr = acc_address.ToString();

      memset(buf, 0, sizeof(buf));
      strncpy(buf, strAddr.c_str(), sizeof(buf)-1);
      ret_crc += shcrc32(buf, strlen(buf));
    }
  }

  return (ret_crc);
}

uint32_t stratum_addr_crc(int ifaceIndex, char *worker)
{
  char *addr;
  char acc_name[256];

  memset(acc_name, 0, sizeof(acc_name));
  strncpy(acc_name, worker, sizeof(acc_name)-1);
  strtok(acc_name, ".");

  return (generate_addrlist_crc(ifaceIndex, acc_name));
}

uint32_t stratum_ext_addr_crc(int ifaceIndex, char *worker)
{
  char *addr;
  char acc_name[256];

  memset(acc_name, 0, sizeof(acc_name));
  strcpy(acc_name, "@");
  strncat(acc_name+1, worker, sizeof(acc_name)-2);
  strtok(acc_name, ".");

  return (generate_addrlist_crc(ifaceIndex, acc_name));
}

const char *stratum_walletkeylist(int ifaceIndex, char *acc_name)
{
  return (cpp_stratum_walletkeylist(ifaceIndex, (const char *)acc_name));
}

string stratumRetAddr;
const char *stratum_getaccountaddress(int ifaceIndex, char *account)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strAccount(account); 
  const CCoinAddr& addr = GetAccountAddress(wallet, strAccount, false);
  if (!addr.IsValid())
    return (NULL);

  stratumRetAddr = addr.ToString();
  return (stratumRetAddr.c_str());
}

void stratum_listaddrkey(int ifaceIndex, char *account, shjson_t *obj)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strListAccount(account);
  string strListExtAccount = "@" + strListAccount;

  vector<string> vAcc;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
    const string& strAccount = entry.second;
    CKey pkey;

    if (strAccount != strListAccount &&
        strAccount != strListExtAccount)
      continue;

    const CCoinAddr& address = CCoinAddr(ifaceIndex, entry.first);
    if (!address.IsValid())
      continue;

    CKeyID keyID;
    if (!address.GetKeyID(keyID))
      continue;

    CSecret vchSecret;
    bool fCompressed;
    if (!wallet->GetSecret(keyID, vchSecret, fCompressed))
      continue;

    string priv_str = CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString();
    shjson_str_add(obj, NULL, (char *)priv_str.c_str());
  }

}

int stratum_getaddrkey(int ifaceIndex, char *account, char *pubkey, char *ret_pkey)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strListAccount(account);
  string strListExtAccount = "@" + strListAccount;

  if (ret_pkey)
    *ret_pkey = '\000';

  vector<string> vAcc;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
    const string& strAccount = entry.second;
    CKey pkey;

    if (strAccount != strListAccount &&
        strAccount != strListExtAccount)
      continue;

    const CCoinAddr& address = CCoinAddr(ifaceIndex, entry.first);
    if (!address.IsValid())
      continue;

    string addrStr = address.ToString();
    if (pubkey) {
      if (0 != strcmp(pubkey, addrStr.c_str()))
        continue;
    }

    if (ret_pkey) {
      CKeyID keyID;
      if (!address.GetKeyID(keyID))
        return (SHERR_ACCESS);

      CSecret vchSecret;
      bool fCompressed;
      if (!wallet->GetSecret(keyID, vchSecret, fCompressed))
        return (SHERR_ACCESS);

      string priv_str = CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString();
      strcpy(ret_pkey, priv_str.c_str());
    }

    return (0);
  }

  return (SHERR_NOENT);
}


int stratum_setdefaultkey(int ifaceIndex, char *account, char *pub_key)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strAccount(account);

  if (!wallet)
    return (SHERR_INVAL);

  CCoinAddr address(ifaceIndex, pub_key);
  if (!address.IsValid())
    return (SHERR_INVAL);

  if (wallet->mapAddressBook.count(address.Get()))
  {
    string strOldAccount = wallet->mapAddressBook[address.Get()];
    if (address == GetAccountAddress(wallet, strOldAccount))
      GetAccountAddress(wallet, strOldAccount, true);
  }

  wallet->SetAddressBookName(address.Get(), strAccount);

  return (0);
}

const char *stratum_accountalias(int ifaceIndex, char *account, char *pkey, char *mode, char *alias_name, char *alias_addr)
{
  return (cpp_accountalias(ifaceIndex, account, pkey, mode, alias_name, alias_addr));
}

const char *stratum_accountcontext(int ifaceIndex, char *account, char *pkey, char *mode, char *ctx_name, char *ctx_value)
{
  return (cpp_accountcontext(ifaceIndex, account, pkey, mode, ctx_name, ctx_value));
}

const char *stratum_accountcertificate(int ifaceIndex, char *account, char *pkey, char *mode, char *cert_name, char *cert_issuer, double fee)
{
  return (cpp_accountcertificate(ifaceIndex, account, pkey, mode, cert_name, cert_issuer, fee));
}


#ifdef __cplusplus
}
#endif


