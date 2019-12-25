
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

#include "shcoind.h"
#include <unistd.h>
using namespace std;
#include "main.h"
#include "wallet.h"
#include "txcreator.h"
#include "db.h"
#include "walletdb.h"
#include "net.h"
#include "base58.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "mnemonic.h"
#include "txmempool.h"
#include "txfeerate.h"
#include "rpc_proto.h"
#include "rpc_command.h"
#include "rpccert_proto.h"
#include "account.h"
#include "stratum/stratum.h"
#include <boost/assign/list_of.hpp>

using namespace boost;
using namespace json_spirit;
using namespace boost::assign;

extern json_spirit::Value ValueFromAmount(int64 amount);
extern bool IsAccountValid(CIface *iface, std::string strAccount);
extern string AccountFromValue(const Value& value);
extern int GetPubKeyMode(const char *tag);
extern string ToValue_date_format(time_t t);

struct tallyitem
{
    int64 nAmount;
    int nConf;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
    }
};
static Value ListReceived(CWallet *wallet, const Array& params, bool fByAccounts)
{
  int ifaceIndex = wallet->ifaceIndex;

  // Minimum confirmations
  int nMinDepth = 1;
  if (params.size() > 0)
    nMinDepth = params[0].get_int();

  // Whether to include empty accounts
  bool fIncludeEmpty = false;
  if (params.size() > 1)
    fIncludeEmpty = params[1].get_bool();

  // Tally
  map<CCoinAddr, tallyitem> mapTally;
  for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
  {
    const CWalletTx& wtx = (*it).second;

    if (wtx.IsCoinBase()) {
      if (wtx.vout.size() == 1)
      continue;
      nMinDepth = 1;
    } else {
      nMinDepth = 1;
    }
    if (!wtx.IsFinal(wallet->ifaceIndex))
      continue;
#if 0
    if (wtx.IsCoinBase() || !wtx.IsFinal(wallet->ifaceIndex))
      continue;
#endif

    int nDepth = wtx.GetDepthInMainChain(ifaceIndex);
    if (nDepth < nMinDepth)
      continue;

    BOOST_FOREACH(const CTxOut& txout, wtx.vout)
    {
      CTxDestination address;
      if (!ExtractDestination(txout.scriptPubKey, address) || !IsMine(*wallet, address))
        continue;

      CCoinAddr c_addr(wallet->ifaceIndex, address);
      tallyitem& item = mapTally[c_addr];
      item.nAmount += txout.nValue;
      item.nConf = min(item.nConf, nDepth);
    }
  }

  // Reply
  Array ret;
  map<string, tallyitem> mapAccountTally;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
    const string& strAccount = item.second;
    map<CCoinAddr, tallyitem>::iterator it = mapTally.find(address);
    if (it == mapTally.end() && !fIncludeEmpty)
      continue;

    int64 nAmount = 0;
    int nConf = std::numeric_limits<int>::max();
    if (it != mapTally.end())
    {
      nAmount = (*it).second.nAmount;
      nConf = (*it).second.nConf;
    }

    if (fByAccounts)
    {
      tallyitem& item = mapAccountTally[strAccount];
      item.nAmount += nAmount;
      item.nConf = min(item.nConf, nConf);
    }
    else
    {
      Object obj;
      obj.push_back(Pair("address",       address.ToString()));
      obj.push_back(Pair("account",       strAccount));
      obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
      obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
      ret.push_back(obj);
    }
  }

  if (fByAccounts)
  {
    for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
    {
      int64 nAmount = (*it).second.nAmount;
      int nConf = (*it).second.nConf;
      Object obj;
      obj.push_back(Pair("account",       (*it).first));
      obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
      obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
      ret.push_back(obj);
    }
  }

  return ret;
}

void rpcwallet_GetVerboseAddr(CWallet *wallet, CAccountCache *acc, CTxDestination dest, Object& ent)
{
	const int ifaceIndex = wallet->ifaceIndex;
	CCoinAddr addr(ifaceIndex, dest);
	bool fDilithium = false;
	CKeyID keyid;

	{
		txnouttype type;
		int nRequired;
		vector<CTxDestination> addresses;
		CScript scriptPubKey;
		scriptPubKey.SetDestination(dest);
		if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
			ent.push_back(Pair("type", GetTxnOutputType(TX_NONSTANDARD)));
		} else {
			ent.push_back(Pair("type", GetTxnOutputType(type)));
		}
	}

	if (!addr.GetKeyID(keyid))  {
		CScriptID scriptID;

		ent.push_back(Pair("address", addr.ToString()));
		if (addr.GetScriptID(scriptID)) {
			CScript script;

			if (wallet->GetCScript(scriptID, script)) {
				ent.push_back(Pair("script", script.ToString()));
			}
			ent.push_back(Pair("scriptid", scriptID.GetHex()));
		}

		{
			int witnessversion = 0;
			cbuff witnessprogram;
			CScript scriptPubKey;
			scriptPubKey.SetDestination(dest);
			if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
				ent.push_back(Pair("witness-version", witnessversion));
				ent.push_back(Pair("witness-size", (int)witnessprogram.size()));
			}
		}

		return;
	}

#if 0
	const CPubKey& pubkeyDefault = wallet->GetPrimaryPubKey(strAccount);
	const CKeyID& keyidDefault = pubkeyDefault.GetID();
	if (keyidDefault == keyid)
		ent.push_back(Pair("default", true));
#endif

	CKey *key = wallet->GetKey(keyid);
	if (key) {
		bool fCompressed = false;
		const CSecret& secret = key->GetSecret(fCompressed);

		fDilithium = key->IsDilithium();

		if (!fDilithium)
			ent.push_back(Pair("compressed", fCompressed));
		if (key->nCreateTime != 0)
			ent.push_back(Pair("created", ToValue_date_format((time_t)key->nCreateTime)));
		ent.push_back(Pair("key-length", secret.size())); 
		if (key->nFlag != 0)
			ent.push_back(Pair("flags", key->GetFlagString()));
		if (key->nFlag & CKeyMetadata::META_HD_KEY) {
			ent.push_back(Pair("hdkeypath", key->hdKeypath));
			ent.push_back(Pair("masterpubkey", key->hdMasterKeyID.GetHex().c_str()));
		}
	}

	if (!fDilithium) {
		ent.push_back(Pair("address", addr.ToString()));
		ent.push_back(Pair("algorithm", string("ecdsa")));
	} else {
		ent.push_back(Pair("algorithm", string("dilithium")));
	}

	ent.push_back(Pair("keyid", keyid.GetHex()));

	/* list all aliases of the pubkey address. */
	if (acc) {
		Array addr_list;
		vector<CTxDestination> vDest;

		acc->GetAddrDestination(keyid, vDest, (fDilithium ? ACCADDRF_DILITHIUM : 0));
		BOOST_FOREACH(const CTxDestination& destTmp, vDest) {
			if (destTmp == dest) continue; /* already reported on. */
			CCoinAddr addr(wallet->ifaceIndex, destTmp);
			addr_list.push_back(addr.ToString());
		}
		if (addr_list.size() != 0)
			ent.push_back(Pair("alias", addr_list));

		if (acc->account.masterKeyID == keyid)
			ent.push_back(Pair("master", true));
	}

}

Value rpc_wallet_validate(CIface *iface, const Array& params, bool fStratum)
{
	int ifaceIndex = GetCoinIndex(iface);
	string strAccount("");
	Object ent;

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *wallet = GetWallet(iface);

	if (params.size() != 1)
		throw runtime_error(
				"wallet.validate <coin-address>\n"
				"Return information about <coin-address>.");

	CCoinAddr address(ifaceIndex, params[0].get_str());
	bool isValid = true;//address.IsValid();

	ent.push_back(Pair("isvalid", isValid));
	if (isValid) {
		CTxDestination dest = address.Get();
		CAccountCache *acc = NULL;

		bool fMine = IsMine(*wallet, dest);
		ent.push_back(Pair("ismine", fMine));

		if (wallet->mapAddressBook.count(dest)) {
			strAccount = wallet->mapAddressBook[dest];
			ent.push_back(Pair("account", wallet->mapAddressBook[dest]));
			acc = wallet->GetAccount(strAccount);
		}

		rpcwallet_GetVerboseAddr(wallet, acc, dest, ent);

		{
			const CPubKey& pubkeyDefault = wallet->GetPrimaryPubKey(strAccount);
			const CKeyID& keyidDefault = pubkeyDefault.GetID();
			CCoinAddr addr(wallet->ifaceIndex, dest);
			CKeyID keyid;
			if (addr.GetKeyID(keyid) && keyidDefault == keyid)
				ent.push_back(Pair("default", true));
		}
	}

	return (ent);
}

Value rpc_wallet_addrlist(CIface *iface, const Array& params, bool fStratum)
{
	vector<CTxDestination> vAddr;
	bool fVerbose = false;

	if (params.size() > 2 || params.size() == 0)
		throw runtime_error("wallet.addrlist <account> [verbose]\n");
	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	string strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(SHERR_NOENT, "Invalid account name specified.");
	if (params.size() == 2 && params[1].get_bool() == true)
		fVerbose = true;

	/* find all addresses that have the given account. */
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
	{
		const string& strName = item.second;
		if (strName == strAccount) {
			vAddr.push_back(item.first);
		}
	}

	/* handle keys with no account designation. */
	if (strAccount.length() == 0) {
		std::set<CKeyID> keys;
		wallet->GetKeys(keys);
		BOOST_FOREACH(const CKeyID& key, keys) {
			if (wallet->mapAddressBook.count(key) == 0) {
				vAddr.push_back(key);
			}
		}
	}

	Array ret;
	if (!fVerbose) {
		BOOST_FOREACH(CTxDestination& key, vAddr) {
			CCoinAddr addr(ifaceIndex, key);
			ret.push_back(addr.ToString());
		}
	} else {
		const CPubKey& pubkeyDefault = wallet->GetPrimaryPubKey(strAccount);
		const CKeyID& keyidDefault = pubkeyDefault.GetID();
		CAccountCache *acc = wallet->GetAccount(strAccount);
		CKeyID keyid;

		BOOST_FOREACH(CTxDestination& dest, vAddr) {
			Object ent;
			rpcwallet_GetVerboseAddr(wallet, acc, dest, ent);
			{
				CCoinAddr addr(wallet->ifaceIndex, dest);
				if (addr.GetKeyID(keyid) && keyidDefault == keyid)
					ent.push_back(Pair("default", true));
			}
			ret.push_back(ent);
		}
	}

	return (ret);
}

Value rpc_wallet_extaddrlist(CIface *iface, const Array& params, bool fStratum)
{
	vector<CTxDestination> vAddr;
	bool fVerbose = false;

	if (params.size() > 2 || params.size() == 0)
		throw runtime_error("wallet.addrlist <account> [verbose]\n");
	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	string strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(SHERR_NOENT, "Invalid account name specified.");
	if (params.size() == 2 && params[1].get_bool() == true)
		fVerbose = true;

	/* use ext account */
	strAccount = "@" + strAccount;

	/* find all addresses that have the given account. */
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
	{
		const string& strName = item.second;
		if (strName == strAccount) {
			vAddr.push_back(item.first);
		}
	}

#if 0
	/* handle keys with no account designation. */
	if (strAccount.length() == 0) {
		std::set<CKeyID> keys;
		wallet->GetKeys(keys);
		BOOST_FOREACH(const CKeyID& key, keys) {
			if (wallet->mapAddressBook.count(key) == 0) {
				vAddr.push_back(key);
			}
		}
	}
#endif

	Array ret;
	if (!fVerbose) {
		BOOST_FOREACH(CTxDestination& key, vAddr) {
			CCoinAddr addr(ifaceIndex, key);
			ret.push_back(addr.ToString());
		}
	} else {
		const CPubKey& pubkeyDefault = wallet->GetPrimaryPubKey(strAccount);
		const CKeyID& keyidDefault = pubkeyDefault.GetID();
		CAccountCache *acc = wallet->GetAccount(strAccount);
		CKeyID keyid;

		BOOST_FOREACH(CTxDestination& dest, vAddr) {
			Object ent;
			rpcwallet_GetVerboseAddr(wallet, acc, dest, ent);
			{
				CCoinAddr addr(wallet->ifaceIndex, dest);
				if (addr.GetKeyID(keyid) && keyidDefault == keyid)
					ent.push_back(Pair("default", true));
			}
			ret.push_back(ent);
		}
	}

	return (ret);
}

Value rpc_wallet_listbyaddr(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() > 2)
		throw runtime_error(
				"wallet.listbyaddr [minconf=1] [includeempty=false]\n"
				"[minconf] is the minimum number of confirmations before payments are included.\n"
				"[includeempty] whether to include addresses that haven't received any payments.\n"
				"Returns an array of objects containing:\n"
				"  \"address\" : receiving address\n"
				"  \"account\" : the account of the receiving address\n"
				"  \"amount\" : total amount received by the address\n"
				"  \"confirmations\" : number of confirmations of the most recent transaction included");

	return ListReceived(GetWallet(iface), params, false);
}

Value rpc_wallet_listbyaccount(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() > 2)
		throw runtime_error(
				"wallet.listbyaccount [minconf=1] [includeempty=false]\n"
				"[minconf] is the minimum number of confirmations before payments are included.\n"
				"[includeempty] whether to include accounts that haven't received any payments.\n"
				"Returns an array of objects containing:\n"
				"  \"account\" : the account of the receiving addresses\n"
				"  \"amount\" : total amount received by addresses with this account\n"
				"  \"confirmations\" : number of confirmations of the most recent transaction included");

	return ListReceived(GetWallet(iface), params, true);
}

Value rpc_wallet_addr(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() > 3)
		throw runtime_error("invalid parameters");

	CWallet *wallet = GetWallet(iface);
	string strAccount = AccountFromValue(params[0]);
	int mode = ACCADDR_RECV;
	bool fVerbose = false;

	/* ensure account has already been established. */
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_NOENT, "Unknown account name specified.");

	if (params.size() > 1) {
		string strMode = params[1].get_str();
		mode = GetPubKeyMode(strMode.c_str());
		if (mode == -1)
			throw JSONRPCError(ERR_INVAL, "Invalid coin address mode specified.");
	}
	if (params.size() > 2)
		fVerbose = params[2].get_bool();

	/* this may generate addresses to initialize account */
	CAccountCache *account = wallet->GetAccount(strAccount);
	if (!account)
		throw JSONRPCError(ERR_INVAL, "Invalid account specified.");

	Object ent;
	Value ret;
	CCoinAddr addr = account->GetAddr(mode);

	if (!fVerbose) {
		ret = addr.ToString();
	} else {
		CAccountCache *acc = wallet->GetAccount(strAccount);
		ent.push_back(Pair("account", strAccount));
		rpcwallet_GetVerboseAddr(wallet, acc, addr.Get(), ent);
		ret = ent;
	}

	return (ret);
}

Value rpc_wallet_witaddr(CIface *iface, const Array& params, bool fStratum)
{
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() == 0 || params.size() > 2) {
		throw runtime_error(
				"wallet.witaddr <addr> [<type>]\n"
				"Returns a witness program which references the coin address specified.");
	}

	CWallet *wallet = GetWallet(iface);
	string strAccount;

	// Parse the account first so we don't generate a key if there's an error
	CCoinAddr address(ifaceIndex, params[0].get_str());
	if (!address.IsValid())
		throw JSONRPCError(-5, "Invalid coin address specified.");

	int output_mode = OUTPUT_TYPE_NONE;
	if (params.size() > 1) {
		string strMode = params[1].get_str();
		if (strMode == "bech32")
			output_mode = OUTPUT_TYPE_BECH32;
		else if (strMode == "p2sh" ||
				strMode == "p2sh-segwit")
			output_mode = OUTPUT_TYPE_P2SH_SEGWIT;
		else if (strMode == "default")
			output_mode = OUTPUT_TYPE_NONE;
		else
			throw JSONRPCError(ERR_INVAL, "invalid type parameter");
	}

	if (!IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		throw JSONRPCError(-4, "Segregated witness is not enabled on the network.");
	}

	if (!GetCoinAddr(wallet, address, strAccount)) {
		throw JSONRPCError(-5, "No account associated with coin address.");
	}

	/* convert into witness program. */
	CTxDestination result = address.GetWitness(output_mode); 
	wallet->SetAddressBookName(result, strAccount);
	return (CCoinAddr(ifaceIndex, result).ToString());
}

Value rpc_wallet_recvbyaccount(CIface *iface, const Array& params, bool fStratum)
{
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() < 1 || params.size() > 2)
		throw runtime_error(
				"wallet.recvbyaccount <account> [minconf=1]\n"
				"Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.");

	CWallet *wallet = GetWallet(iface);

	// Minimum confirmations
	int nMinDepth = 1;
	if (params.size() > 1)
		nMinDepth = params[1].get_int();

	// Get the set of pub keys assigned to account
	string strAccount = AccountFromValue(params[0]);
	set<CTxDestination> setAddress;
	GetAccountAddresses(wallet, strAccount, setAddress);

	// Tally
	int64 nAmount = 0;
	for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
	{
		const CWalletTx& wtx = (*it).second;
		if (wtx.IsCoinBase() || !wtx.IsFinal(ifaceIndex))
			continue;

		BOOST_FOREACH(const CTxOut& txout, wtx.vout)
		{
			CTxDestination address;
			if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*wallet, address) && setAddress.count(address))
				if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
					nAmount += txout.nValue;
		}
	}

	return (double)nAmount / (double)COIN;
}

Value rpc_wallet_recvbyaddr(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() < 1 || params.size() > 2)
		throw runtime_error(
				"wallet.recvbyaddr <coin-address> [minconf=1]\n"
				"Returns the total amount received by <coin-address> in transactions with at least [minconf] confirmations.");

	CCoinAddr address = CCoinAddr(ifaceIndex, params[0].get_str());
	if (!address.IsValid())
		throw JSONRPCError(-5, "Invalid coin address");

	CScript scriptPubKey;
	scriptPubKey.SetDestination(address.Get());
	if (!IsMine(*pwalletMain,scriptPubKey))
		return (double)0.0;

	// Minimum confirmations
	int nMinDepth = 1;
	if (params.size() > 1)
		nMinDepth = params[1].get_int();

	// Tally
	int64 nAmount = 0;
	for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
	{
		const CWalletTx& wtx = (*it).second;
		if (wtx.IsCoinBase() && wtx.vout.size() == 1)
			continue;
		if (!wtx.IsFinal(ifaceIndex))
			continue;


		BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
			CTxDestination out_addr;
			ExtractDestination(txout.scriptPubKey, out_addr);
			if (address.Get() == out_addr)
				if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
					nAmount += txout.nValue;
#if 0
			if (txout.scriptPubKey == scriptPubKey)
				if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
					nAmount += txout.nValue;
#endif
		}
	}

	return  ValueFromAmount(nAmount);
}

/** create a new coin address for the account specified. */
Value rpc_wallet_new(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int output_mode = OUTPUT_TYPE_NONE;
	bool fHDKey = opt_bool(OPT_HDKEY);
	bool fVerbose;

	if (fStratum)
		throw runtime_error("permission denied");

	if (params.size() == 0 || params.size() > 3)
		throw runtime_error("invalid parameters");

	string strAccount = params[0].get_str();
	
	if (params.size() > 1) {
		string strMode = params[1].get_str();
		if (strMode == "dilithium")
			output_mode = OUTPUT_TYPE_DILITHIUM;
		else if (strMode == "bech32")
			output_mode = OUTPUT_TYPE_BECH32;
		else if (strMode == "p2sh-segwit" ||
				strMode == "segwit")
			output_mode = OUTPUT_TYPE_P2SH_SEGWIT;
		else if (strMode == "legacy")
			output_mode = OUTPUT_TYPE_LEGACY;
		else if (strMode == "default")
			output_mode = OUTPUT_TYPE_NONE;
		else
			throw JSONRPCError(ERR_INVAL, "invalid type parameter");
	}
	if (params.size() > 2) {
		fVerbose = params[2].get_bool();
	}

	int flags = 0;
	if (output_mode == OUTPUT_TYPE_DILITHIUM)
		flags |= ACCADDRF_DILITHIUM;
	if (output_mode == OUTPUT_TYPE_DILITHIUM ||
			output_mode == OUTPUT_TYPE_BECH32 ||
			output_mode == OUTPUT_TYPE_P2SH_SEGWIT)
		flags |= ACCADDRF_WITNESS;
	if (fHDKey)
		flags |= ACCADDRF_DERIVE;

	if ((flags & ACCADDRF_WITNESS) &&
			!IsWitnessEnabled(iface, GetBestBlockIndex(iface)))
		throw JSONRPCError(ERR_INVAL, "incompatible address mode specified");

	CAccountCache *acc = wallet->GetAccount(strAccount);
	if (!acc)
		throw JSONRPCError(ERR_INVAL, "invalid account name specified");

	CTxDestination destRet;
	if (output_mode == OUTPUT_TYPE_NONE) { /* auto */
		if (!acc->CreateNewAddr(destRet, ACCADDR_RECV, 0))
			throw JSONRPCError(ERR_INVAL, "unable to generate new address");
	} else { /* manual */
		CPubKey pubkey;
		if (!acc->CreateNewPubKey(pubkey, flags))
			throw JSONRPCError(ERR_INVAL, "unable to generate new address");

		if (!(flags & ACCADDRF_WITNESS)) {
			destRet = pubkey.GetID();
		} else {
			CCoinAddr addr(wallet->ifaceIndex, pubkey.GetID());
			if (pubkey.IsDilithium()) {
				destRet = addr.GetWitness(OUTPUT_TYPE_DILITHIUM); /* WitnessV14KeyHash */
			} else if (output_mode == OUTPUT_TYPE_BECH32 || /* WitnessV0KeyHash */
					output_mode == OUTPUT_TYPE_P2SH_SEGWIT) { /* CScriptID */
				destRet = addr.GetWitness(output_mode);
			} else {
				destRet = addr.GetWitness(OUTPUT_TYPE_NONE); /* w/e */
			}
		}
	}
	if (destRet == CTxDestination(CNoDestination()))
		throw JSONRPCError(ERR_INVAL, "incompatible address mode");

#if 0
	/* obtain pubkey address. */
	CCoinAddr addr = GetAccountAddress(GetWallet(iface), strAccount);
	if (output_mode == OUTPUT_TYPE_NONE ||
			output_mode == OUTPUT_TYPE_P2SH_SEGWIT ||
			output_mode == OUTPUT_TYPE_BECH32) {
		if (IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
			/* convert to wit-addr program. */
			CTxDestination dest = addr.GetWitness(output_mode); 
			wallet->SetAddressBookName(dest, strAccount);
			addr = CCoinAddr(ifaceIndex, dest);
		}
	}
#endif

	Value ret;
	Object ent;
	if (!fVerbose) {
		CCoinAddr addr(wallet->ifaceIndex, destRet);
		ret = addr.ToString();
	} else {
		CAccountCache *acc = wallet->GetAccount(strAccount);
		ent.push_back(Pair("account", strAccount));
		rpcwallet_GetVerboseAddr(wallet, acc, destRet, ent);
		ret = ent;
	}

	return (ret);
}

Value rpc_wallet_derive(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("permission denied");

	if (params.size() != 2)
		throw runtime_error("invalid parameters");

	int ifaceIndex = GetCoinIndex(iface);
	CWallet *wallet = GetWallet(iface);
	string strAccount = AccountFromValue(params[0]);
	string strSeed = params[1].get_str();

	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_INVAL, "invalid account");

	CCoinAddr addr(ifaceIndex);
	if (!wallet->GetMergedAddress(strAccount, strSeed.c_str(), addr))
		throw JSONRPCError(-5, "Error obtaining merged coin address.");

	Object ret;
	ret.push_back(Pair("seed", strSeed));
	ret.push_back(Pair("addr", addr.ToString()));

	return (ret);
}

Value rpc_wallet_setkeyphrase(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("wallet.setkeyphrase");

	if (params.size() != 2)
		throw runtime_error("wallet.setkeyphrase");

	CCoinSecret vchSecret;
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	bool ret = DecodeMnemonicSecret(ifaceIndex, params[0].get_str(), vchSecret);
	if (!ret)
		throw JSONRPCError(-5, "Invalid private key");

	string strLabel = params[1].get_str();
	bool fGood = vchSecret.IsValid();
	if (!fGood) throw JSONRPCError(-5,"Invalid private key");

	bool fCompressed;
	CSecret secret = vchSecret.GetSecret(fCompressed);
	CKeyID vchAddress;
	int nFlag = 0;
	if (secret.size() == 96) { /* DILITHIUM */
		DIKey key;
		key.SetSecret(secret);
		vchAddress = key.GetPubKey().GetID();
		if (wallet->HaveKey(vchAddress))
			throw JSONRPCError(SHERR_NOTUNIQ, "Address already exists in wallet.");
		//		key.nFlag |= CKeyMetadata::META_DILITHIUM;
		if (!wallet->AddKey(key))
			throw JSONRPCError(ERR_INVAL, "error generating address");
		nFlag = key.nFlag;
	} else /* ECDSA */ {
		ECKey key;
		key.SetSecret(secret, fCompressed);
		vchAddress = key.GetPubKey().GetID();
		if (wallet->HaveKey(vchAddress))
			throw JSONRPCError(ERR_NOTUNIQ, "Address already exists in wallet.");
		if (!wallet->AddKey(key))
			throw JSONRPCError(ERR_INVAL, "error generating address");
		nFlag = key.nFlag;
	}

	CAccountCache *acc = wallet->GetAccount(strLabel);
	if (acc)
		acc->SetAddrDestinations(vchAddress);

	{
		LOCK2(cs_main, wallet->cs_wallet);
		wallet->MarkDirty();
		wallet->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
		wallet->ReacceptWalletTransactions();
	}

	Object ent;
	ent.push_back(Pair("account", strLabel));
	rpcwallet_GetVerboseAddr(wallet, acc, vchAddress, ent);
	return (ent);
}

Value rpc_wallet_setkey(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");
	if (params.size() < 2 || params.size() > 3)
		throw runtime_error("invalid parameters");

	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	CCoinSecret vchSecret;
	string strSecret = params[0].get_str();
	string strLabel = AccountFromValue(params[1]);
	/* TODO: arg for nCreateTime limit? */
	string strType;
	if (params.size() == 3)
		strType = params[2].get_str();

	bool fGood = vchSecret.SetString(strSecret);
	if (!fGood) {
		/* invalid private key 'string' for particular coin interface. */
		throw JSONRPCError(SHERR_ILSEQ, "private-key");
	}

	CAccountCache *acc = wallet->GetAccount(strLabel);
	if (!acc)
		throw JSONRPCError(SHERR_INVAL, "invalid account");

	bool fCompressed = true;
	CSecret secret = vchSecret.GetSecret(fCompressed); /* set's fCompressed */
	CKeyID vchAddress;
	{
		LOCK2(cs_main, wallet->cs_wallet);

		if (secret.size() == 96) { /* DILITHIUM */
			DIKey key;
			key.SetSecret(secret);
			const CPubKey& pubkey = key.GetPubKey();
			vchAddress = pubkey.GetID();
			if (wallet->HaveKey(vchAddress))
				throw JSONRPCError(SHERR_NOTUNIQ, "Address already exists in wallet.");
			if (!wallet->AddKey(key))
				throw JSONRPCError(ERR_INVAL, "error generating address");
			if (strType == "default")
				acc->SetDefaultAddr(pubkey);
		} else /* ECDSA */ {
			ECKey key;
			key.SetSecret(secret);
			const CPubKey& pubkey = key.GetPubKey();
			vchAddress = pubkey.GetID();
			if (wallet->HaveKey(vchAddress))
				throw JSONRPCError(SHERR_NOTUNIQ, "Address already exists in wallet.");
			if (!wallet->AddKey(key))
				throw JSONRPCError(ERR_INVAL, "error generating address");
			if (strType == "default")
				acc->SetDefaultAddr(pubkey);
		}

		wallet->MarkDirty();
		wallet->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
		wallet->ReacceptWalletTransactions();
	}

	Object ent;
	ent.push_back(Pair("account", strLabel)); 
	rpcwallet_GetVerboseAddr(wallet, acc, vchAddress, ent); 
	return ent;
}

