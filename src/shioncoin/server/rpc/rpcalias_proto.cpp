
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
#include "wallet.h"
#include "base58.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "certificate.h"
#include "account.h"
#include "script.h"
#include "rpc_proto.h"

using namespace std;
using namespace boost;
using namespace json_spirit;

extern json_spirit::Value ValueFromAmount(int64 amount);

extern Object rpcwallet_GetVerboseAddr(int ifaceIndex, CTxDestination destination);

extern void rpcwallet_GetWalletAddr(CWallet *wallet, shjson_t *tree, string strLabel, const CKeyID& keyID);

static bool fHelp = false;

Value rpc_alias_info(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);

  if (0 != params.size())
    throw runtime_error("invalid parameters");

  Object obj;

  int nBestHeight = GetBestHeight(iface); 
  obj.push_back(Pair("fee", ValueFromAmount(GetAliasOpFee(iface, nBestHeight))));

  alias_list *list = GetAliasTable(ifaceIndex);
  obj.push_back(Pair("active", (int)list->size()));

  aliasarch_list *archlist = GetAliasArchTable(ifaceIndex);
  obj.push_back(Pair("archived", (int)archlist->size()));

  return (obj);
}

Value rpc_alias_fee(CIface *iface, const Array& params, bool fStratum) 
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (0 != params.size())
    throw runtime_error("invalid parameters");

  int nBestHeight = GetBestHeight(iface); 
  return ValueFromAmount(GetAliasOpFee(iface, nBestHeight));
}


Value rpc_alias_addr(CIface *iface, const Array& params, bool fStratum) 
{
  throw runtime_error("unsupported operation");
}

Value rpc_alias_pubaddr_update(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || 2 > params.size() || 3 < params.size()) {
    throw runtime_error(
        "alias.addrupdate <aliasname> <coin-address>\n"
        "Update a coin address reference label.\n");
  }

  CWallet *wallet = GetWallet(iface);
	vector<unsigned char> vchName = vchFromValue(params[0]);
	if (vchName.size() == 0)
		throw runtime_error("You must specify an alias label.");
	if (vchName.size() > 135)
		throw runtime_error("alias name > 135 bytes!\n");

  CCoinAddr addr = CCoinAddr(ifaceIndex, params[1].get_str());
  if (!addr.IsValid())
    throw JSONRPCError(-5, "Invalid coin address");

#if 0
  CKeyID key_id;
  if (!addr.GetKeyID(key_id))
    throw JSONRPCError(-5, "Unsupported coin address");
#endif

	CWalletTx wtx;
  int err;
  err = update_alias_addr_tx(iface, params[0].get_str().c_str(), addr, wtx); 
  if (err) {
    if (err == SHERR_NOENT) {
      throw runtime_error("could not find an alias with this name");
    }
    if (err == SHERR_REMOTE) {
      throw runtime_error("Alias is not associated with a local account.");
    }
    if (err == ERR_FEE) {
      throw runtime_error("Not enough coins in account to perform the transaction.");
    }
    throw runtime_error("Error updating alias transaction.");
  }

  return (wtx.ToValue(ifaceIndex));
}

Value rpc_alias_pubaddr(CIface *iface, const Array& params, bool fStratum) 
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (params.size() < 1 || params.size() > 2)
    throw runtime_error("invalid parameters");

  int ifaceIndex = GetCoinIndex(iface);
  string vchTitleStr = params[0].get_str();
  string strAddress;
  if (params.size() > 1)
    strAddress = params[1].get_str();
  vector<unsigned char> vchTitle = vchFromValue(params[0]);
  int err;

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != TESTNET_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.\n");

  if(vchTitle.size() < 1)
    throw runtime_error("A label must be specified.");

  if(vchTitle.size() >= MAX_SHARE_NAME_LENGTH)
    throw runtime_error("The label exceeds 135 characters.");

  CTransaction in_tx;
  CAlias *alias = GetAliasByName(iface, vchTitleStr, in_tx); 

  if (strAddress.size() == 0) {
    if (!alias)
      throw JSONRPCError(-5, "Invalid alias name");

    CCoinAddr addr(ifaceIndex);
    if (!alias->GetCoinAddr(ifaceIndex, addr))
      throw JSONRPCError(-5, "Invalid coin address.");

		/* allow user to regenerate to refresh expiration time. */
		strAddress = addr.ToString();
  }

  if (strAddress.size() < 1)
    throw runtime_error("An invalid coin address was specified.");

  if (strAddress.size() >= MAX_SHARE_HASH_LENGTH)
    throw runtime_error("The coin address exceeds 135 characters.");

  CCoinAddr addr = CCoinAddr(ifaceIndex, strAddress);
  if (!addr.IsValid())
    throw JSONRPCError(-5, "Invalid coin address");

  CWalletTx wtx;

  if (!alias) {
    err = init_alias_addr_tx(iface, vchTitleStr.c_str(), addr, wtx); 
    if (err) {
      if (err == SHERR_INVAL)
        throw JSONRPCError(-5, "Invalid coin address specified.");
      if (err == SHERR_NOENT)
        throw JSONRPCError(-5, "Coin address not located in wallet.");
      if (err == ERR_FEE)
        throw JSONRPCError(-5, "Not enough coins in account to create alias.");
      throw JSONRPCError(-5, "Unable to generate transaction.");
    }
  } else {
    /* already exists */
    err = update_alias_addr_tx(iface, vchTitleStr.c_str(), addr, wtx); 
    if (err) {
      if (err == SHERR_INVAL)
        throw JSONRPCError(-5, "Invalid coin address specified.");
      if (err == SHERR_NOENT)
        throw JSONRPCError(-5, "Coin address not located in wallet.");
      if (err == ERR_FEE)
        throw JSONRPCError(-5, "Not enough coins in account to create alias.");
      throw JSONRPCError(-5, "Unable to generate transaction.");
    }
  }

  return (wtx.ToValue(ifaceIndex));
}

Value rpc_alias_get(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
  CTransaction tx;
  CAlias *alias;
  alias_list *list;

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  uint160 hash(params[0].get_str());

  list = GetAliasTable(ifaceIndex);
  BOOST_FOREACH(PAIRTYPE(const string, uint256)& r, *list) {
    const string& label = r.first;
    uint256& hTx = r.second;
    CTransaction tx;
    uint256 hBlock;

    if (!GetTransaction(iface, hTx, tx, NULL))
      continue;

    if (tx.alias.GetHash() == hash)
      return (tx.alias.ToValue(ifaceIndex));
  }

  throw JSONRPCError(-5, "invalid hash specified");
}

Value rpc_alias_getaddr(CIface *iface, const Array& params, bool fStratum) 
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CTransaction tx;
  CAlias *alias;
	CKeyID keyid;

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  string label = params[0].get_str();
  alias = GetAliasByName(iface, label, tx);
  if (!alias)
    throw JSONRPCError(-5, "invalid alias label");

	Object ent = alias->ToValue(ifaceIndex);
	ent.push_back(Pair("tx", tx.GetHash().GetHex()));

	CCoinAddr addr(wallet->ifaceIndex);
	if (alias->GetCoinAddr(ifaceIndex, addr) &&
			ExtractDestinationKey(wallet, addr.Get(), keyid)) {
		Object pubent = rpcwallet_GetVerboseAddr(ifaceIndex, addr.Get());
		ent.push_back(Pair("pubkey", pubent));
	}

	return (ent);
}

Value rpc_alias_listaddr(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
	bool fVerbose = false;
  CAlias *alias;
  alias_list *list;

  if (params.size() > 1)
    throw runtime_error("invalid parameters");

  string keyword;
  if (params.size() > 0)
    keyword = params[0].get_str();

  Object result;
  list = GetAliasTable(ifaceIndex);
  BOOST_FOREACH(PAIRTYPE(const string, uint256)& r, *list) {
    const string& label = r.first;
    uint256& hash = r.second;
    CTransaction tx;
    uint256 hBlock;

    if (keyword.length() != 0 &&
        label.find(keyword) == std::string::npos)
      continue;

    if (!GetTransaction(iface, hash, tx, NULL))
      continue;

    alias = (CAlias *)&tx.alias;

		CCoinAddr addr(ifaceIndex);
		if (!alias->GetCoinAddr(ifaceIndex, addr)) {
			continue;
		}
		if (!addr.IsValid()) {
			continue;
		}

		result.push_back(Pair(label, addr.ToString()));
	}

  return (result);
}


Value rpc_alias_remove(CIface *iface, const Array& params, bool fStratum) 
{
  CWallet *wallet = GetWallet(iface);

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (params.size() > 2)
    throw runtime_error("invalid parameters");

  int ifaceIndex = GetCoinIndex(iface);
  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != TESTNET_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("unsupported operation");

  string strTitle = params[0].get_str();
  string strAccount;
  if (params.size() > 1)
    strAccount = params[1].get_str();
  int err;

  if(strTitle.size() < 1)
    throw runtime_error("A label must be specified.");

  if(strTitle.size() >= MAX_SHARE_NAME_LENGTH)
    throw runtime_error("The label exceeds 135 characters.");

  CTransaction in_tx;
  CAlias *alias = GetAliasByName(iface, strTitle, in_tx); 
  if (!alias)
    throw JSONRPCError(-5, "invalid alias name");

  string strAliasAccount;
  CCoinAddr addr(ifaceIndex);
  if (!alias->GetCoinAddr(ifaceIndex, addr))
    throw JSONRPCError(-5, "Invalid coind address reference.");

  bool ret = GetCoinAddr(wallet, addr, strAliasAccount);
  if (!ret)
    throw JSONRPCError(-5, "Unknown reference account");

  if (fStratum || strAccount.size() != 0) {
    if (strAliasAccount != strAccount)
      throw JSONRPCError(-5, "Invalid reference account.");
  }
  strAccount = strAliasAccount;

  CWalletTx wtx;
  err = remove_alias_addr_tx(iface, strAccount, strTitle, wtx); 
  if (err) {
    if (err == SHERR_NOENT)
      throw JSONRPCError(-5, "Coin address not located in wallet.");
    if (err == ERR_FEE)
      throw JSONRPCError(-5, "Not enough coins in account to remove alias.");
    throw JSONRPCError(-5, "Unable to generate transaction.");
  }

  return (wtx.ToValue(ifaceIndex));
}

static bool IsAliasAccount(CWallet *wallet, string strAccount, const CTxDestination& destination)
{
	string strExtAccount = CWallet::EXT_ACCOUNT_PREFIX + strAccount;

	/* filter for account specified. */
	map<CTxDestination, string>::iterator mi = wallet->mapAddressBook.find(destination);
	if (mi == wallet->mapAddressBook.end()) {
		return (false);
	}
	if (mi->second != strAccount &&
			mi->second != strExtAccount) {
		return (false);
	}

	return (true);
}

static bool IsAliasAccount(CWallet *wallet, string strAccount, const CScript& scriptPubKey, CTxDestination& destination)
{

	if (!ExtractDestination(scriptPubKey, destination)) {
		return (false);
	}

	return (IsAliasAccount(wallet, strAccount, destination));
}

Value rpc_alias_export(CIface *iface, const Array& params, bool fStratum) 
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	vector<CTxDestination> vAddr;
	alias_list *list;
	string strAccount;

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != TESTNET_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE) {
    throw runtime_error("unsupported operation");
	}

	strAccount = params[0].get_str();

  list = GetAliasTable(ifaceIndex);
  BOOST_FOREACH(PAIRTYPE(const string, uint256)& r, *list) {
    uint256& hash = r.second;

    CTransaction tx;
    if (!GetTransaction(iface, hash, tx, NULL)) {
      continue;
		}

    CAlias *alias = tx.GetAlias();
		if (!alias) {
			continue;
		}
		if (alias->IsExpired()) {
			continue;
		}

		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			uint160 hAlias;
			hash;
			int mode;
			if (!DecodeAliasHash(txout.scriptPubKey, mode, hAlias)) {
				continue;
			}

			CTxDestination destination;
			if (!IsAliasAccount(wallet, strAccount, txout.scriptPubKey, destination)) {
				continue;
			}

			vAddr.push_back(destination);
		}


		CCoinAddr addr(ifaceIndex);
		if (alias->GetCoinAddr(ifaceIndex, addr)) {
			const CTxDestination& destination = addr.Get();
			if (!IsAliasAccount(wallet, strAccount, destination)) {
				continue;
			}

			vAddr.push_back(destination);
		}
	}

	/* compile return data */
	Array ret_val;
	BOOST_FOREACH(const CTxDestination& destination, vAddr) {
		CAccountAddressKey addr(ifaceIndex, destination);

		/* redundant ownership verification. */
		if (!addr.IsMine()) {
			continue;
		}

		ret_val.push_back(addr.ToValue());
	}
	return (ret_val);
}

