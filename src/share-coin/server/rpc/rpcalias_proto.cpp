
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#undef GNULIB_NAMESPACE
#include "shcoind.h"

#include "init.h"
#include "ui_interface.h"
#include "base58.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "certificate.h"
#include "rpc_proto.h"

using namespace std;
using namespace boost;
//using namespace boost::asio;
using namespace json_spirit;
//using namespace boost::assign;


extern json_spirit::Value ValueFromAmount(int64 amount);

static bool fHelp = false;

Value rpc_alias_info(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
  alias_list *list;

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (0 != params.size())
    throw runtime_error("invalid parameters");

  Object obj;

  int nBestHeight = GetBestHeight(iface); 
  obj.push_back(Pair("fee", ValueFromAmount(GetAliasOpFee(iface, nBestHeight))));

  list = GetAliasTable(ifaceIndex);
  obj.push_back(Pair("total", (int)list->size()));

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

  CCoinAddr addr = CCoinAddr(params[1].get_str());
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
    if (err == SHERR_AGAIN) {
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
    if (!alias->GetCoinAddr(addr))
      throw JSONRPCError(-5, "Invalid coin address.");

    return (addr.ToString());
  }

  if (strAddress.size() < 1)
    throw runtime_error("An invalid coin address was specified.");

  if (strAddress.size() >= MAX_SHARE_HASH_LENGTH)
    throw runtime_error("The coin address exceeds 135 characters.");

  CCoinAddr addr = CCoinAddr(strAddress);
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
      if (err == SHERR_AGAIN)
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
      if (err == SHERR_AGAIN)
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
  int ifaceIndex = GetCoinIndex(iface);
  CTransaction tx;
  CAlias *alias;

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  string label = params[0].get_str();
  alias = GetAliasByName(iface, label, tx);
  if (!alias)
    throw JSONRPCError(-5, "invalid alias label");

  return (alias->ToValue(ifaceIndex));
}

Value rpc_alias_listaddr(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
  CAlias *alias;
  alias_list *list;

  if (params.size() > 1)
    throw runtime_error("invalid parameters");

  string keyword;
  if (params.size() != 0)
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

    if (!GetTransaction(iface, hash, tx, &hBlock))
      continue;

    Object obj;

    obj.push_back(Pair("block", hBlock.GetHex()));
    obj.push_back(Pair("tx", tx.GetHash().GetHex()));

    alias = (CAlias *)&tx.alias;
    obj.push_back(Pair("alias", alias->GetHash().GetHex()));
    if (alias->GetType() == CAlias::ALIAS_COINADDR) {
      CCoinAddr addr(ifaceIndex);
      if (alias->GetCoinAddr(addr))
        obj.push_back(Pair("addr", addr.ToString().c_str()));
    }

    result.push_back(Pair(label, obj));
  }

  return (result);
}


Value rpc_alias_remove(CIface *iface, const Array& params, bool fStratum) 
{
  CWallet *wallet = GetWallet(iface);

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  int ifaceIndex = GetCoinIndex(iface);
  if (ifaceIndex != TEST_COIN_IFACE &&
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
  if (!alias->GetCoinAddr(addr))
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
    if (err == SHERR_AGAIN)
      throw JSONRPCError(-5, "Not enough coins in account to create alias.");
    throw JSONRPCError(-5, "Unable to generate transaction.");
  }

  return (wtx.ToValue(ifaceIndex));
}





