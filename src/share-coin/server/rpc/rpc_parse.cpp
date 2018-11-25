
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


#include "shcoind.h"
#include <unistd.h>
using namespace std;

#include "main.h"
#include "wallet.h"
#include "txcreator.h"
#include "db.h"
#include "walletdb.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "base58.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "mnemonic.h"
#include "txmempool.h"
#include "rpc_proto.h"
#include "rpc_command.h"
#include "rpccert_proto.h"
#include "stratum/stratum.h"

#include <boost/assign/list_of.hpp>

using namespace boost;
using namespace json_spirit;
using namespace boost::assign;



#define RPC_AUTH_FREQ 300

void ThreadRPCServer2(void* parg);

static std::string strRPCUserColonPass;
static CCriticalSection cs_THREAD_RPCHANDLER;

static int64 nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

static bool fHelp = false;


extern Value rpc_getrawtransaction(CIface *iface, const Array& params, bool fStratum); // in rcprawtransaction.cpp
extern Value rpc_tx_signraw(CIface *iface, const Array& params, bool fStratum);
extern Value rpc_sendrawtransaction(CIface *iface, const Array& params, bool fStratum);
extern bool OpenNetworkConnection(const CAddress& addrConnect, const char *strDest = NULL);
extern json_spirit::Value ValueFromAmount(int64 amount);
extern bool IsAccountValid(CIface *iface, std::string strAccount);
extern Value rpc_cert_export(CIface *iface, const Array& params, bool fStratum);


extern bool GetStratumKeyAccount(uint256 in_pkey, string& strAccount);


const Object emptyobj;


json_spirit::Value rpc_execute(CIface *iface, const std::string &strMethod, json_spirit::Array &params);




class JSONRequest
{
  public:
    Value id;
    string strMethod;
    Array params;
    CIface *iface;

    JSONRequest() { id = Value::null; }
    void parse(const Value& valRequest);
};

Object JSONRPCError(int code, const string& message)
{
    Object error;
		if (code == ERR_ACCESS) {
			code = -23; /* Bad signature */
		} else if (code == ERR_NOKEY) {
			code = -22; /* Signature unavailable. */
		} else if (code == ERR_KEYREJECTED ||
				code == ERR_KEYREVOKED || code == ERR_KEYEXPIRED) {
			code = -21; /* Signature unavailable */
		} else if (code == ERR_FEE) {
			code = -10; /* Fee required */
		} else if (code == ERR_NOMETHOD) { 
			code = -3; /* Method not found. */ 
		} else if (code == ERR_OPNOTSUPP) {
			code = -2; /* Service not found. */
		}
    error.push_back(Pair("code", code));
    error.push_back(Pair("message", message));
    return error;
}
void RPCTypeCheck(const Array& params,
                  const list<Value_type>& typesExpected)
{
    unsigned int i = 0;
    BOOST_FOREACH(Value_type t, typesExpected)
    {
        if (params.size() <= i)
            break;

       const Value& v = params[i];
        if (v.type() != t)
        {
            string err = strprintf("Expected type %s, got %s",
                                   Value_type_name[t], Value_type_name[v.type()]);
            throw JSONRPCError(-3, err);
        }
        i++;
    }
}
void RPCTypeCheck(const Object& o,
                  const map<string, Value_type>& typesExpected)
{
    BOOST_FOREACH(const PAIRTYPE(string, Value_type)& t, typesExpected)
    {
        const Value& v = find_value(o, t.first);
        if (v.type() == null_type)
            throw JSONRPCError(-3, strprintf("Missing %s", t.first.c_str()));
        if (v.type() != t.second)
        {
            string err = strprintf("Expected type %s for %s, got %s",
                                   Value_type_name[t.second], t.first.c_str(), Value_type_name[v.type()]);
            throw JSONRPCError(-3, err);
        }
    }
}

int64 AmountFromValue(const Value& value)
{
    double dAmount = value.get_real();
    if (dAmount <= 0.0 || dAmount > 84000000.0)
        throw JSONRPCError(-3, "Invalid amount");
    int64 nAmount = roundint64(dAmount * COIN);
#if 0
    if (!MoneyRange(nAmount))
        throw JSONRPCError(-3, "Invalid amount");
#endif
    return nAmount;
}

void WalletTxToJSON(int ifaceIndex, const CWalletTx& wtx, Object& entry)
{
    int confirms = wtx.GetDepthInMainChain(ifaceIndex);
    entry.push_back(Pair("confirmations", confirms));
    if (confirms)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
    }
    entry.push_back(Pair("txid", wtx.GetHash().GetHex()));
    entry.push_back(Pair("hash", wtx.GetWitnessHash().GetHex()));
    entry.push_back(Pair("time", (boost::int64_t)wtx.GetTxTime()));
    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

void GetAccountAddresses(CWallet *wallet, string strAccount, set<CTxDestination>& setAddress)
{
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CTxDestination& address = item.first;
    const string& strName = item.second;
    if (strName == strAccount)
      setAddress.insert(address);
  }
}

double GetDifficulty(int ifaceIndex, const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (GetBestBlockIndex(ifaceIndex) == NULL)
            return 1.0;
        else
            blockindex = GetBestBlockIndex(ifaceIndex);
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

Value GetNetworkHashPS(int ifaceIndex, int lookup) 
{
  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);

  if (pindexBest == NULL)
    return 0;

  // If lookup is -1, then use blocks since last difficulty change.
  if (lookup <= 0)
    lookup = pindexBest->nHeight % 2016 + 1;

  // If lookup is larger than chain, then set it to chain length.
  if (lookup > pindexBest->nHeight)
    lookup = pindexBest->nHeight;

  CBlockIndex* pindexPrev = pindexBest;
  for (int i = 0; i < lookup; i++)
    pindexPrev = pindexPrev->pprev;

  double timeDiff = pindexBest->GetBlockTime() - pindexPrev->GetBlockTime();
  double timePerBlock = timeDiff / lookup;

  return (boost::int64_t)(((double)GetDifficulty(ifaceIndex) * pow(2.0, 32)) / timePerBlock);
}

void ListTransactions(int ifaceIndex, const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
//  int64 nGeneratedImmature, nGeneratedMature, nFee;
  int64 nFee;
  string strSentAccount;
  list<pair<CTxDestination, int64> > listReceived;
  list<pair<CTxDestination, int64> > listSent;

//  wtx.GetAmounts(nGeneratedImmature, nGeneratedMature);
  wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount);

  bool fAllAccounts = (strAccount == string("*"));

#if 0
  // Generated blocks assigned to account ""
  if ((nGeneratedMature+nGeneratedImmature) != 0 && (fAllAccounts || strAccount == ""))
  {
    Object entry;
    entry.push_back(Pair("account", string("")));
    if (nGeneratedImmature)
    {
      entry.push_back(Pair("category", wtx.GetDepthInMainChain(ifaceIndex) ? "immature" : "orphan"));
      entry.push_back(Pair("amount", ValueFromAmount(nGeneratedImmature)));
    }
    else
    {
      entry.push_back(Pair("category", "generate"));
      entry.push_back(Pair("amount", ValueFromAmount(nGeneratedMature)));
    }
    if (fLong)
      WalletTxToJSON(ifaceIndex, wtx, entry);
    ret.push_back(entry);
  }
#endif

  // Sent
  if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
  {
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& s, listSent)
    {
      Object entry;
      entry.push_back(Pair("account", strSentAccount));
      entry.push_back(Pair("address", CCoinAddr(ifaceIndex, s.first).ToString()));
      entry.push_back(Pair("category", "send"));
      entry.push_back(Pair("amount", ValueFromAmount(-s.second)));
      entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
      if (fLong)
        WalletTxToJSON(ifaceIndex, wtx, entry);
      ret.push_back(entry);
    }
  }

  // Received
  if (listReceived.size() > 0 && wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
  {
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& r, listReceived)
    {
      string account;
      if (pwalletMain->mapAddressBook.count(r.first))
        account = pwalletMain->mapAddressBook[r.first];
      if (fAllAccounts || (account == strAccount))
      {
        Object entry;
        entry.push_back(Pair("account", account));
        entry.push_back(Pair("address", CCoinAddr(ifaceIndex, r.first).ToString()));
        entry.push_back(Pair("category", "receive"));
        entry.push_back(Pair("amount", ValueFromAmount(r.second)));
        if (fLong)
          WalletTxToJSON(ifaceIndex, wtx, entry);
        ret.push_back(entry);
      }
    }
  }
}

//
// Call Table
//




const char *_rpc_arg_label[MAX_RPC_ARG_TYPES] = {
  "",
  "s",
  "i",
  "i64",
  "d",
  "b",
  "ar",
  "obj",
  "acc",
  "addr"
};

typedef map <string,RPCOp> rpcfn_map;

static rpcfn_map rpcfn_table[MAX_COIN_IFACE];
static rpcfn_map rpcfn_alias[MAX_COIN_IFACE];




static string GetRPCArgLabel(RPCOp *op)
{
  string strRet;
  int i;

  for (i = 0; i < MAX_RPC_ARGS; i++) {
    if (op->arg[i] == RPC_NULL)
      break;

    if (i == op->min_arg)
      strRet += "[";

    strRet += _rpc_arg_label[op->arg[i]];
    if ((i+1) < MAX_RPC_ARGS &&
        op->arg[i+1] != RPC_NULL)
      strRet += ",";
  }
  if (op->min_arg < i)
    strRet += "]";

  return (strRet);
}

static int GetRPCMaxArgs(RPCOp *op)
{
  int i;

  for (i = 0; i < MAX_RPC_ARGS; i++) {
    if (op->arg[i] == RPC_NULL)
      break;
  }

  return (i);
}


rpcfn_map *GetRPCTable(int ifaceIndex)
{
#ifndef TEST_SHCOIND
  if (ifaceIndex == 0)
    return (NULL);
#endif
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  return (&rpcfn_table[ifaceIndex]);
}
rpcfn_map *GetRPCAliasTable(int ifaceIndex)
{
#ifndef TEST_SHCOIND
  if (ifaceIndex == 0)
    return (NULL);
#endif
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  return (&rpcfn_alias[ifaceIndex]);
}

void RegisterRPCOp(int ifaceIndex, string name, const RPCOp& op)
{
  rpcfn_map *map;

  map = GetRPCTable(ifaceIndex);
  (*map)[name] = op;
}

RPCOp *GetRPCOp(int ifaceIndex, string name)
{
  rpcfn_map *map;

  map = GetRPCTable(ifaceIndex);
  if (map->count(name) == 0)
    return (NULL);

  return ( & (*map)[name] );
}

void RegisterRPCAlias(int ifaceIndex, string name, const RPCOp& op)
{
  rpcfn_map *map;

  map = GetRPCAliasTable(ifaceIndex);
  (*map)[name] = op;
}

RPCOp *GetRPCAlias(int ifaceIndex, string name)
{
  rpcfn_map *map;

  map = GetRPCAliasTable(ifaceIndex);
  if (map->count(name) == 0)
    return (NULL);

  return ( & (*map)[name] );
}

static string rpc_command_usage_help(CIface *iface, string strCommand, RPCOp *op, bool fAbrev = false)
{
  string strArg = GetRPCArgLabel(op);
  string strRet;

  if (!fAbrev) {
    strRet += "Command: ";
  }
  strRet += strCommand;
  if (strArg.length() != 0) {
    strRet += " <";
    strRet += strArg;
    strRet += ">";
  } 
  strRet += "\n";

  if (!fAbrev) {
    strRet += op->usage;
  }

  return strRet;
}
static string rpc_command_help(CIface *iface, string strCommand)
{
  int ifaceIndex = GetCoinIndex(iface);
  RPCOp *op;

  if (strCommand.length() == 0) {
    rpcfn_map *map;
    string strRet;
    int i;

    map = GetRPCTable(ifaceIndex);
    BOOST_FOREACH(const PAIRTYPE(string, RPCOp)& item, *map) {
      RPCOp& op = (RPCOp&)item.second;
      strRet += rpc_command_usage_help(iface, item.first, &op, true);
    }

    /* truncate trailing '\n' character */
    if (strRet.size() > 0)
      strRet.resize(strRet.size() - 1);

    return (strRet);
  }

  op = GetRPCOp(ifaceIndex, strCommand);
  if (!op)
    op = GetRPCAlias(ifaceIndex, strCommand);
  if (!op)
    return (strprintf("help: unknown command: %s", strCommand.c_str()));

  return (rpc_command_usage_help(iface, strCommand, op));
}

Value rpc_sys_help(CIface *iface, const Array& params, bool fStratum)
{
  if (fHelp || params.size() > 1)
    throw runtime_error(
        "Syntax: <command>\n"
        "List all available commands or show verbose information on a particular command.");

  string strCommand;
  if (params.size() > 0)
    strCommand = params[0].get_str();

  return rpc_command_help(iface, strCommand);
}

const RPCOp SYS_HELP = {
  &rpc_sys_help, 0, {RPC_STRING},
  "List all available commands or verbose usage of a particular command."
};
const RPCOp SYS_SHUTDOWN = {
  &rpc_sys_shutdown, 0, {},
  "Shut down the shcoind server."
};
const RPCOp SYS_INFO = {
  &rpc_sys_info, 0, {},
  "The system attributes that control how the coin-service operates."
};
const RPCOp SYS_CONFIG = {
  &rpc_sys_config, 0, {},
  "The system configuration settings that control how the coin-service operates."
};
const RPCOp SYS_URL = {
  &rpc_sys_url, 0, {},
  "Web url references pertinent to the coin service."
};
const RPCOp BLOCK_INFO = {
  &rpc_block_info, 0, {},
  "Statistical and runtime information on block operations."
};
const RPCOp BLOCK_COUNT = {
  &rpc_block_count, 0, {},
  "Returns the number of blocks in the longest block chain."
};
const RPCOp BLOCK_DIFFICULTY = {
  &rpc_block_difficulty, 0, {},
  "Returns the proof-of-work difficulty as a multiple of the minimum difficulty."
};
const RPCOp BLOCK_EXPORT = {
  &rpc_block_export, 1, {RPC_STRING},
  "Syntax: <path>\n"
  "Exports a blockchain to the external path specified."
};
const RPCOp BLOCK_FREE = {
  &rpc_block_free, 0, {},
  "Deallocate cached resources used to map the block-chain."
};
const RPCOp BLOCK_GET = {
  &rpc_block_get, 1, {RPC_STRING},
  "Syntax: <block-hash>\n"
  "Returns details of a block for the specified block hash."
};
const RPCOp BLOCK_HASH = {
  &rpc_block_hash, 1, {RPC_INT64},
  "Syntax: <block-index>\n"
  "Returns hash of block index specified."
};
const RPCOp BLOCK_IMPORT = {
  &rpc_block_import, 1, {RPC_STRING, RPC_INT64},
  "Syntax: <path> <offset>\n"
  "Imports a blockchain from the specified path and optional byte offset."
};
const RPCOp BLOCK_LISTSINCE = {
  &rpc_block_listsince, 0, {RPC_STRING, RPC_INT64},
  "Syntax: <block-hash> <confirmations>\n"
  "Get all transactions in blocks since the specified block-hash, or all transactions if omitted."
};
const RPCOp BLOCK_PURGE = {
  &rpc_block_purge, 1, {RPC_INT64},
  "Syntax: <block-index>\n"
  "Warning: Use of this command may be hazardous.\n"
  "Truncate the block-chain to the specified height."
};
const RPCOp BLOCK_VERIFY = {
  &rpc_block_verify, 0, {RPC_INT64},
  "Default: 1024 blocks\n"
  "Verify a set of blocks from the tail of the block-chain."
};
const RPCOp BLOCK_MINE = {
  &rpc_block_mine, 0, {RPC_INT64},
  "Default: 10240 intervals\n"
  "Mine a block on the block-chain with an ongoing event.\n"
  "Note: Intended primary for use with the testnet network."
};
const RPCOp BLOCK_WORK = {
  &rpc_block_work, 0, {RPC_STRING},
  "Syntax: <data>\n"
  "Obtain basic mining work data or submits data if specified."
};
const RPCOp BLOCK_WORKEX = {
  &rpc_block_workex, 0, {RPC_STRING, RPC_STRING},
  "Syntax: <data>, <coinbase>\n"
  "Extended mining work data or submits data and coinbase if specified."
};
const RPCOp MSG_SIGN = {
  &rpc_msg_sign, 2, {RPC_STRING, RPC_STRING},
  "Syntax: <coin-addr> <message>\n"
  "Sign a message with the private key of an address."
};
const RPCOp MSG_VERIFY = {
  &rpc_msg_verify, 3, {RPC_STRING, RPC_STRING, RPC_STRING},
  "Syntax: <coin-address> <signature> <message>\n"
  "Verify a signed message"
};

/* peer */
const RPCOp PEER_INFO = {
  &rpc_peer_info, 0, {},
  "Statistical and runtime information on network operations."
};
const RPCOp PEER_HASHPS = {
  &rpc_peer_hashps, 0, {RPC_INT}, 
  "Syntax: <blocks>\n"
  "Returns the estimated network hashes per second based on the last 120 blocks.\n"
  "Pass in <blocks> to override # of blocks, -1 specifies since last difficulty change."
};
const RPCOp PEER_ADD = {
  &rpc_peer_add, 1, {RPC_STRING}, 
  "Syntax: <host>[:<port>]\n"
  "Submit a new peer connection for the coin server."
};
const RPCOp PEER_COUNT = {
  &rpc_peer_count, 0, {}, 
  "Returns the number of connections to other nodes."
};
const RPCOp PEER_IMPORT = {
  &rpc_peer_import, 1, {RPC_STRING}, 
  "Syntax: <path>\n"
  "Export entire database of network peers in JSON format."
};
const RPCOp PEER_IMPORTDAT = {
  &rpc_peer_importdat, 1, {RPC_STRING}, 
  "Syntax: <path>\n"
  "Import a legacy 'peers.dat' datafile."
};
const RPCOp PEER_LIST = {
  &rpc_peer_list, 0, {}, 
  "Statistical and runtime information on network peers."
};
const RPCOp PEER_EXPORT = {
  &rpc_peer_export, 1, {RPC_STRING}, 
  "Syntax: <path>\n"
  "Export entire database of network peers in JSON format."
};
const RPCOp PEER_REMOVE = {
  &rpc_peer_remove, 1, {RPC_STRING},
  "Syntax: <addr>\n"
  "Remove an IP address from the peer database."
};

const RPCOp TX_DECODE = {
  &rpc_tx_decode, 1, {RPC_STRING},
  "Syntax: <hex string>\n"
  "Return a JSON object representing the serialized, hex-encoded transaction."
};
const RPCOp TX_GET = {
  &rpc_tx_get, 1, {RPC_STRING},
  "Syntax: <txid>\n"
  "Get detailed information about a block transaction."
};
const RPCOp TX_GETRAW = {
  &rpc_getrawtransaction, 1, {RPC_STRING, RPC_INT64},
  "Syntax: <txid> [verbose=0]\n"
  "If verbose=0, returns a string that is\n"
  "serialized, hex-encoded data for <txid>.\n"
  "If verbose is non-zero, returns an Object\n"
  "with information about <txid>."
};
const RPCOp TX_LIST = {
  &rpc_tx_list, 1, {RPC_ACCOUNT, RPC_INT64, RPC_INT64},
  "Syntax: <account> [<count>=10] [<from>=0]\n"
  "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account]."
};
const RPCOp TX_POOL = {
  &rpc_tx_pool, 0, {},
  "Returns all transaction awaiting confirmation."
};
const RPCOp TX_PRUNE = {
  &rpc_tx_prune, 0, {},
  "Revert pending transactions in an invalid state."
};
const RPCOp TX_PURGE = {
  &rpc_tx_purge, 0, {},
  "Reverts all transaction awaiting confirmation."
};
const RPCOp WALLET_ADDR = {
  &rpc_wallet_addr, 1, {RPC_ACCOUNT},
  "Syntax: <account>\n"
  "Returns the current hash address for receiving payments to this account."
}; 
const RPCOp WALLET_WITADDR = {
  &rpc_wallet_witaddr, 1, {RPC_STRING},
  "Syntax: <coin address>\n"
  "Returns a witness program which references the coin address specified."
}; 
const RPCOp WALLET_LISTADDR = {
  &rpc_wallet_addrlist, 1, {RPC_ACCOUNT},
  "Syntax: <account>\n"
  "Returns the list of coin addresses for the given account."
}; 
const RPCOp WALLET_BALANCE = {
  &rpc_wallet_balance, 0, {RPC_ACCOUNT, RPC_INT},
  "wallet.balance [account] [minconf=1]\n"
  "If [account] is not specified, returns the server's total available balance.\n"
  "If [account] is specified, returns the balance in the account."
}; 
const RPCOp WALLET_EXPORT = {
  &rpc_wallet_export, 1, {RPC_STRING},
  "Syntax: <path>\n"
  "Export the coin wallet to the specified path in JSON format."
}; 
const RPCOp WALLET_EXPORTDAT = {
  &rpc_wallet_exportdat, 1, {RPC_STRING},
  "Syntax: <path>\n"
  "Export the coin wallet to the specified path (dir or file)."
}; 
const RPCOp WALLET_GET = {
  &rpc_wallet_get, 1, {RPC_STRING},
  "wallet.get <coin address>\n"
  "Returns the account associated with the given address."
}; 

const RPCOp WALLET_INFO = {
  &rpc_wallet_info, 0, {}, 
  "Statistical and runtime information on wallet operations."
};
const RPCOp TX_VALIDATE = {
  &rpc_tx_validate, 1, {RPC_STRING}, 
  "Validate a wallet transaction."
};
const RPCOp WALLET_IMPORT = {
  &rpc_wallet_import, 1, {RPC_STRING}, 
  "Syntax: <path>\n"
  "Import a JSON wallet file."
};
const RPCOp WALLET_KEY = {
  &rpc_wallet_key, 1, {RPC_STRING},
  "Syntax: <address>\n"
  "Summary: Reveals the private key corresponding to a public coin address.\n"
  "Params: [ <address> The coin address. ]\n"
  "\n"
  "The 'wallet.key' command provides a method to obtain the private key associated\n"
  "with a particular coin address.\n"
  "\n"
  "The coin address must be available in the local wallet in order to print it's pr\n"
  "ivate address.\n"
  "\n"
  "The private coin address can be imported into another system via the 'wallet.setkey' command.\n"
  "\n"
  "The entire wallet can be exported to a file via the 'wallet.export' command."
};
const RPCOp WALLET_LIST = {
  &rpc_wallet_list, 0, {RPC_INT},
  "wallet.list [<minconf>=1]\n"
  "Returns Object that has account names as keys, account balances as values."
};
const RPCOp WALLET_LISTBYACCOUNT = {
  &rpc_wallet_listbyaccount, 0, {RPC_INT64, RPC_BOOL},
  "Syntax: [<minconf>=1] [<includeempty>=false]\n"
  "[minconf] is the minimum number of confirmations before payments are included.\n"
  "[includeempty] whether to include accounts that haven't received any payments.\n"
  "Returns an array of objects containing:\n"
  "  \"account\" : the account of the receiving addresses\n"
  "  \"amount\" : total amount received by addresses with this account\n"
  "  \"confirmations\" : number of confirmations of the most recent transaction included"
};
const RPCOp WALLET_LISTBYADDR = {
  &rpc_wallet_listbyaddr, 0, {RPC_INT64, RPC_BOOL}, 
  "Syntax: [minconf=1] [includeempty=false]\n"
  "[minconf] is the minimum number of confirmations before payments are included.\n"
  "[includeempty] whether to include addresses that haven't received any payments.\n"
  "Returns an array of objects containing:\n"
  "  \"address\" : receiving address\n"
  "  \"account\" : the account of the receiving address\n"
  "  \"amount\" : total amount received by the address\n"
  "  \"confirmations\" : number of confirmations of the most recent transaction included"
};
const RPCOp WALLET_MOVE = {
  &rpc_wallet_move, 3, {RPC_ACCOUNT, RPC_STRING, RPC_DOUBLE, RPC_INT64, RPC_STRING},
  "Syntax: <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
  "Move from one account in your wallet to another."
};
const RPCOp WALLET_MULTISEND = {
  &rpc_wallet_multisend, 2, {RPC_ACCOUNT, RPC_OBJECT, RPC_INT64, RPC_INT, RPC_STRING}, 
  "Syntax: <fromaccount> {address:amount,...} [minconf=1] [comment]\n"
  "Note: Coin amounts are double-precision floating point numbers."
};
const RPCOp WALLET_NEW = {
  &rpc_wallet_new, 1, {RPC_ACCOUNT},
  "Syntax: <account>\n"
  "Returns a new address for receiving payments to the specified account."
};
const RPCOp WALLET_DERIVE = {
  &rpc_wallet_derive, 2, {RPC_ACCOUNT, RPC_STRING},
  "Syntax: <account> <str-seed>\n"
  "Summary: Dervies a new coin address.\n"
  "Params: [ <account> The account to obtain the originating coin address, <str-seed> A string which will be used as a merge seed. ]\n"
  "\n"
  "Derives a new address from the private key of the receiving address for a given account."
};
const RPCOp WALLET_RECVBYACCOUNT = {
  &rpc_wallet_recvbyaccount, 1, {RPC_ACCOUNT, RPC_INT64},
  "Syntax: <account> [<minconf>=1]\n"
  "Print the total amount received by addresses with <account> in transactions with at least [minconf] confirmations."
};
const RPCOp WALLET_RECVBYADDR = {
  &rpc_wallet_recvbyaddr, 1, {RPC_STRING, RPC_INT64},
  "Syntax: <coin-address> [minconf=1]\n"
  "Returns the total amount received by <coin-address> in transactions with at least [minconf] confirmations."
};
const RPCOp WALLET_VERIFY = {
  &rpc_wallet_verify, 1, {RPC_INT64},
  "Syntax: [<depth>]\n"
  "Rescan the block-chain for personal wallet transactions."
};
const RPCOp WALLET_SEND = {
  &rpc_wallet_send, 3, {RPC_ACCOUNT, RPC_COINADDR, RPC_DOUBLE, RPC_INT64, RPC_STRING, RPC_STRING},
  "Syntax: <fromaccount> <toaddress> <amount> [minconf=1] [comment] [comment-to]\n"
  "Note: The <amount> is a real and is rounded to the nearest 0.00000001"
};
const RPCOp WALLET_BSEND = {
  &rpc_wallet_bsend, 3, {RPC_ACCOUNT, RPC_COINADDR, RPC_DOUBLE, RPC_INT64, RPC_STRING, RPC_STRING},
  "Syntax: <fromaccount> <toaddress> <amount> [minconf=1] [comment] [comment-to]\n"
  "\n"
  "Create a batch of transactions, as neccessary, in order to send the coin value to the destination address.\n"
  "Note: The <amount> is a real and is rounded to the nearest 0.00000001"
};
const RPCOp WALLET_TSEND = {
  &rpc_wallet_tsend, 3, {RPC_ACCOUNT, RPC_COINADDR, RPC_DOUBLE, RPC_INT64},
  "Syntax: <fromaccount> <toaddress> <amount> [minconf=1]\n"
  "\n"
  "Return information about a send transaction without block-chain commit.\n"
  "Used in order to obtain information about the details involved if a particular transaction were to take place -- without actually performing the transaction.\n"
  "Note: The <amount> is a real and is rounded to the nearest 0.00000001"
};
const RPCOp WALLET_SET = {
  &rpc_wallet_set, 2, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: <coin-address> <account>\n"
  "Sets the account associated with the given address."
};
const RPCOp WALLET_SETKEY = {
  &rpc_wallet_setkey, 2, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: <priv-key> <account>\n"
  "Adds a private key (as returned by wallet.key) to your wallet."
};
const RPCOp WALLET_TX = {
  &rpc_wallet_tx, 1, {RPC_STRING}, 
  "Syntax: <txid>\n"
  "Get detailed information about in-wallet transaction <txid>."
};
const RPCOp WALLET_UNCONFIRM = {
  &rpc_wallet_unconfirm, 0, {}, 
  "Display a list of all unconfirmed wallet transactions."
};
const RPCOp WALLET_UNSPENT = {
  &rpc_wallet_unspent, 1, {RPC_ACCOUNT, RPC_INT64},
  "Syntax: <account> [<minconf>=1]\n"
  "Returns array of unspent transaction outputs with minimum specified confirmations."
};
const RPCOp WALLET_SPENT = {
  &rpc_wallet_spent, 1, {RPC_ACCOUNT},
  "Syntax: <account>\n"
  "Returns array of spent transaction outputs for the account."
};
const RPCOp WALLET_SELECT = {
  &rpc_wallet_select, 2, {RPC_ACCOUNT, RPC_DOUBLE},
  "Syntax: <account> <value>\n"
  "Returns array of sample transaction outputs to spend."
};
const RPCOp WALLET_VALIDATE = {
  &rpc_wallet_validate, 1, {RPC_COINADDR},
  "Syntax: <coin-address>\n"
  "Return summarized information about <coin-address>."
};

const RPCOp STRATUM_KEYADD = {
  &rpc_stratum_keyadd, 0, {},
  "Add a remove stratum synchronization key."
};
const RPCOp STRATUM_INFO = {
  &rpc_stratum_info, 0, {},
  "Return summarized information about the stratum service."
};
const RPCOp STRATUM_LIST = {
  &rpc_stratum_list, 0, {},
  "List individual users associated with the stratum service."
};
const RPCOp STRATUM_KEY = {
  &rpc_stratum_key, 0, {},
  "Print the local stratum synchronization key."
};
const RPCOp STRATUM_KEYREMOVE = {
  &rpc_stratum_keyremove, 0, {},
  "Remove a stratum synchronization key."
};



void RegisterRPCOpDefaults(int ifaceIndex)
{

  RegisterRPCAlias(ifaceIndex, "help", SYS_HELP);


  RegisterRPCOp(ifaceIndex, "block.info", BLOCK_INFO); 
  RegisterRPCAlias(ifaceIndex, "getinfo", BLOCK_INFO); 

  RegisterRPCOp(ifaceIndex, "block.count", BLOCK_COUNT);
  RegisterRPCAlias(ifaceIndex, "getblockcount", BLOCK_COUNT);

  RegisterRPCOp(ifaceIndex, "block.difficulty", BLOCK_DIFFICULTY);
  RegisterRPCAlias(ifaceIndex, "getdifficulty", BLOCK_DIFFICULTY);

  RegisterRPCOp(ifaceIndex, "block.export", BLOCK_EXPORT);

  if (opt_bool(OPT_ADMIN)) {
    RegisterRPCOp(ifaceIndex, "block.free", BLOCK_FREE);
  }

  RegisterRPCOp(ifaceIndex, "block.get", BLOCK_GET);
  RegisterRPCAlias(ifaceIndex, "getblock", BLOCK_GET);

  RegisterRPCOp(ifaceIndex, "block.hash", BLOCK_HASH);
  RegisterRPCAlias(ifaceIndex, "getblockhash", BLOCK_HASH);

  RegisterRPCOp(ifaceIndex, "block.import", BLOCK_IMPORT);

  RegisterRPCOp(ifaceIndex, "block.listsince", BLOCK_LISTSINCE);

  if (opt_bool(OPT_ADMIN)) {
    RegisterRPCOp(ifaceIndex, "block.purge", BLOCK_PURGE);
  }

  RegisterRPCOp(ifaceIndex, "block.verify", BLOCK_VERIFY);

  RegisterRPCOp(ifaceIndex, "block.mine", BLOCK_MINE);

  RegisterRPCOp(ifaceIndex, "block.work", BLOCK_WORK);
  RegisterRPCAlias(ifaceIndex, "getwork", BLOCK_WORK);

  RegisterRPCOp(ifaceIndex, "block.workex", BLOCK_WORKEX);
  RegisterRPCAlias(ifaceIndex, "getworkex", BLOCK_WORKEX);

  RegisterRPCOp(ifaceIndex, "msg.sign", MSG_SIGN);
  RegisterRPCAlias(ifaceIndex, "signmessage", MSG_SIGN);

  RegisterRPCOp(ifaceIndex, "msg.verify", MSG_VERIFY);
  RegisterRPCAlias(ifaceIndex, "verifymessage", MSG_VERIFY);

  RegisterRPCOp(ifaceIndex, "sys.config", SYS_CONFIG);

  RegisterRPCOp(ifaceIndex, "sys.info", SYS_INFO);

  RegisterRPCOp(ifaceIndex, "sys.shutdown", SYS_SHUTDOWN);
  RegisterRPCAlias(ifaceIndex, "stop", SYS_SHUTDOWN);

//  RegisterRPCOp(ifaceIndex, "sys.url", SYS_URL);
  
  RegisterRPCOp(ifaceIndex, "peer.add", PEER_ADD);

  RegisterRPCOp(ifaceIndex, "peer.count", PEER_COUNT);
  RegisterRPCAlias(ifaceIndex, "getpeercount", PEER_COUNT);

  RegisterRPCOp(ifaceIndex, "peer.export", PEER_EXPORT);

  RegisterRPCOp(ifaceIndex, "peer.hashps", PEER_HASHPS);
  RegisterRPCAlias(ifaceIndex, "getnetworkhashps", PEER_HASHPS);

  RegisterRPCOp(ifaceIndex, "peer.import", PEER_IMPORT);

  RegisterRPCOp(ifaceIndex, "peer.importdat", PEER_IMPORTDAT);

  RegisterRPCOp(ifaceIndex, "peer.info", PEER_INFO);

  RegisterRPCOp(ifaceIndex, "peer.list", PEER_LIST);
  RegisterRPCAlias(ifaceIndex, "getpeerinfo", PEER_LIST);

  RegisterRPCOp(ifaceIndex, "peer.remove", PEER_REMOVE); 

  /* stratum service */
  RegisterRPCOp(ifaceIndex, "stratum.keyadd", STRATUM_KEYADD);
  RegisterRPCOp(ifaceIndex, "stratum.info", STRATUM_INFO);
  if (opt_bool(OPT_ADMIN)) {
    RegisterRPCOp(ifaceIndex, "stratum.key", STRATUM_KEY);
  }
  RegisterRPCOp(ifaceIndex, "stratum.list", STRATUM_LIST);
  RegisterRPCOp(ifaceIndex, "stratum.keyremove", STRATUM_KEYREMOVE);

  RegisterRPCOp(ifaceIndex, "tx.decode", TX_DECODE);
  RegisterRPCAlias(ifaceIndex, "decoderawtransaction", TX_DECODE);

  RegisterRPCOp(ifaceIndex, "tx.get", TX_GET);

  RegisterRPCOp(ifaceIndex, "tx.getraw", TX_GETRAW);
  RegisterRPCAlias(ifaceIndex, "getrawtransaction", TX_GETRAW);

  RegisterRPCOp(ifaceIndex, "tx.list", TX_LIST);
  RegisterRPCAlias(ifaceIndex, "listtransactions", TX_LIST);

  RegisterRPCOp(ifaceIndex, "tx.pool", TX_POOL);
  RegisterRPCAlias(ifaceIndex, "getrawmempool", TX_POOL);

  RegisterRPCOp(ifaceIndex, "tx.prune", TX_PRUNE);

  if (opt_bool(OPT_ADMIN)) {
    RegisterRPCOp(ifaceIndex, "tx.purge", TX_PURGE);
  }

  RegisterRPCOp(ifaceIndex, "tx.validate", TX_VALIDATE);

  RegisterRPCOp(ifaceIndex, "wallet.addr", WALLET_ADDR);
  RegisterRPCOp(ifaceIndex, "wallet.witaddr", WALLET_WITADDR);
  RegisterRPCOp(ifaceIndex, "wallet.listaddr", WALLET_LISTADDR);
  RegisterRPCOp(ifaceIndex, "wallet.balance", WALLET_BALANCE);
  RegisterRPCOp(ifaceIndex, "wallet.export", WALLET_EXPORT);
  RegisterRPCOp(ifaceIndex, "wallet.exportdat", WALLET_EXPORTDAT);
  RegisterRPCOp(ifaceIndex, "wallet.get", WALLET_GET);

//  RegisterRPCOp(ifaceIndex, "wallet.info", WALLET_INFO);
  RegisterRPCOp(ifaceIndex, "wallet.import", WALLET_IMPORT);

  RegisterRPCOp(ifaceIndex, "wallet.key", WALLET_KEY);
  RegisterRPCAlias(ifaceIndex, "dumpprivkey", WALLET_KEY);

  RegisterRPCOp(ifaceIndex, "wallet.list", WALLET_LIST);

  RegisterRPCOp(ifaceIndex, "wallet.listbyaccount", WALLET_LISTBYACCOUNT);
  RegisterRPCAlias(ifaceIndex, "listreceivedbyaccount", WALLET_LISTBYACCOUNT);

  RegisterRPCOp(ifaceIndex, "wallet.listbyaddr", WALLET_LISTBYADDR);
  RegisterRPCAlias(ifaceIndex, "listreceivedbyaddress", WALLET_LISTBYADDR);

  RegisterRPCOp(ifaceIndex, "wallet.move", WALLET_MOVE);
  RegisterRPCOp(ifaceIndex, "wallet.multisend", WALLET_MULTISEND);

  RegisterRPCOp(ifaceIndex, "wallet.new", WALLET_NEW);

  RegisterRPCOp(ifaceIndex, "wallet.derive", WALLET_DERIVE);

  RegisterRPCOp(ifaceIndex, "wallet.recvbyaccount", WALLET_RECVBYACCOUNT);
  RegisterRPCAlias(ifaceIndex, "getreceivedbyaccount", WALLET_RECVBYACCOUNT);

  RegisterRPCOp(ifaceIndex, "wallet.recvbyaddr", WALLET_RECVBYADDR);
  RegisterRPCAlias(ifaceIndex, "getreceivedbyaddr", WALLET_RECVBYADDR);

  RegisterRPCOp(ifaceIndex, "wallet.verify", WALLET_VERIFY);

  RegisterRPCOp(ifaceIndex, "wallet.send", WALLET_SEND);
  RegisterRPCAlias(ifaceIndex, "sendfrom", WALLET_SEND);

  RegisterRPCOp(ifaceIndex, "wallet.bsend", WALLET_BSEND);

  RegisterRPCOp(ifaceIndex, "wallet.tsend", WALLET_TSEND);

  RegisterRPCOp(ifaceIndex, "wallet.set", WALLET_SET);

  RegisterRPCOp(ifaceIndex, "wallet.setkey", WALLET_SETKEY);
  RegisterRPCAlias(ifaceIndex, "importprivkey", WALLET_SETKEY);

  RegisterRPCOp(ifaceIndex, "wallet.tx", WALLET_TX);
  RegisterRPCOp(ifaceIndex, "wallet.unconfirm", WALLET_UNCONFIRM);
  RegisterRPCOp(ifaceIndex, "wallet.unspent", WALLET_UNSPENT);
  RegisterRPCOp(ifaceIndex, "wallet.spent", WALLET_SPENT);
  RegisterRPCOp(ifaceIndex, "wallet.select", WALLET_SELECT);
  RegisterRPCOp(ifaceIndex, "wallet.validate", WALLET_VALIDATE);


}


void JSONRequest::parse(const Value& valRequest)
{

  // Parse request
  if (valRequest.type() != obj_type)
    throw JSONRPCError(-32600, "Invalid Request object");
  const Object& request = valRequest.get_obj();

  // Parse id now so errors from here on will have the id
  id = find_value(request, "id");

  /* determine coin iface */
  Value ifaceVal = find_value(request, "iface");
  if (ifaceVal.type() == str_type) {
    string iface_str = ifaceVal.get_str();
    iface = GetCoin(iface_str.c_str());
  }
  if (!iface) {
    /* default */
    iface = GetCoinByIndex(USDE_COIN_IFACE);
  }

  // Parse method
  Value valMethod = find_value(request, "method");
  if (valMethod.type() == null_type)
    throw JSONRPCError(-32600, "Missing method");
  if (valMethod.type() != str_type)
    throw JSONRPCError(-32600, "Method must be a string");
  strMethod = valMethod.get_str();
  if (strMethod != "getwork" && strMethod != "getblocktemplate") {
    Debug("ThreadRPCServer method=%s\n", strMethod.c_str());
  }

  // Parse params
  Value valParams = find_value(request, "params");
  if (valParams.type() == array_type)
    params = valParams.get_array();
  else if (valParams.type() == null_type)
    params = Array();
  else
    throw JSONRPCError(-32600, "Params must be an array");
}






template<typename T>
void RPCConvertTo(string strJSON, Value& value)
{
  if (value.type() == str_type)
  {
    // reinterpret string as unquoted json value
    Value value2;
//    string strJSON = value.get_str();
    if (!read_string(strJSON, value2))
      throw runtime_error(string("Error parsing JSON:")+strJSON);
    value = value2.get_value<T>();
  }
  else
  {
    value = value.get_value<T>();
  }
}

static string RPCConvertToAddr(CIface *iface, string str)
{

  if (!iface || !iface->enabled)
    throw JSONRPCError(-5, "unsupported operation");

  if (str.length() == 0)
    throw JSONRPCError(-5, "blank coin address specified");
    
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  CCoinAddr addr(ifaceIndex);
  bool isValid = GetCoinAddr(wallet, str, addr); 

  if (!isValid) {
    char buf[256];

    sprintf (buf, "(%s) invalid coin address specified \"%s\".", 
        iface->name, str.c_str()); 
    throw JSONRPCError(-3, buf);
  }

  return (addr.ToString());
}

static void RPCConvertParam(CIface *iface, RPCOp *op, int arg_idx, Array& param)
{
  string str;

  if (param[arg_idx].type() == str_type)
    str = param[arg_idx].get_str();

  switch (op->arg[arg_idx]) {
    case RPC_INT:
      RPCConvertTo<int>(str, param[arg_idx]);
      break;
    case RPC_INT64:
      RPCConvertTo<boost::int64_t>(str, param[arg_idx]);
      break;
    case RPC_DOUBLE:
      RPCConvertTo<double>(str, param[arg_idx]);
      break;
    case RPC_BOOL:
      RPCConvertTo<bool>(str, param[arg_idx]);
      break;
    case RPC_ARRAY:
      RPCConvertTo<Array>(str, param[arg_idx]);
      break;
    case RPC_OBJECT:
      RPCConvertTo<Object>(str, param[arg_idx]);
      break;
    case RPC_COINADDR:
      param[arg_idx] = Value(RPCConvertToAddr(iface, str));
      break;
  }

}

extern "C" {
extern int shjson_array_count(shjson_t *json, char *name);
}

Object JSONRPCReplyObj(const Value& result, const Value& error, const Value& id)
{
  Object reply;
  if (error.type() != null_type)
    reply.push_back(Pair("result", Value::null));
  else
    reply.push_back(Pair("result", result));
  reply.push_back(Pair("error", error));
  reply.push_back(Pair("id", id));
  return reply;
}

string JSONRPCReply(const Value& result, const Value& error, const Value& id)
{
  Object reply = JSONRPCReplyObj(result, error, id);
  return write_string(Value(reply), false) + "\n";
}

static bool _verify_rpc_auth(const uint256& auth_key, unsigned int auth_pin)
{
  static uint256 local_site_key;
  static shkey_t s_key;
  unsigned int local_site_pin;

  if (auth_key == 0 || auth_pin == 0)
    return (false);

  if (local_site_key.IsNull()) {
    shkey_t *skey = get_rpc_dat_password(NULL);
    if (!skey)
      return (false);

    unsigned char ret_str[256];
    shsha_hex(SHALG_SHA256, ret_str, 
        (unsigned char *)skey, sizeof(shkey_t));
    string key_hash_str((const char *)ret_str);
    local_site_key = uint256(key_hash_str);
    memcpy(&s_key, skey, sizeof(s_key));
    shkey_free(&skey);
  }

  if (auth_key != local_site_key) {
    return (false);
}

  local_site_pin = shsha_2fa_bin(SHALG_SHA256, 
      (unsigned char *)&s_key, sizeof(s_key), RPC_AUTH_FREQ);
  if (local_site_pin != auth_pin) {
    return (false);
}

  return (true);
}

int ExecuteStratumRPC(int ifaceIndex, shjson_t *json, shbuf_t *buff)
{
  int ar_len = shjson_array_count(json, "params");
  Array param;
  RPCOp *op;
  char method[256];
  uint256 auth_hash;
  uint32_t auth_pin;
  int i;
  bool fVerified;

  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled)
    return (SHERR_OPNOTSUPP);

  memset(method, 0, sizeof(method));
  strncpy(method, shjson_astr(json, "method", ""), sizeof(method)-1);
  string strMethod(method);

  op = GetRPCOp(ifaceIndex, strMethod);
  if (!op)
    return (SHERR_INVAL);

  int max_arg = GetRPCMaxArgs(op);
  if (ar_len < op->min_arg ||
      ar_len > max_arg) {
    return (SHERR_INVAL);
  }

  /* limit RPC commands to those requiring an account being specified. */
  bool fNeedAccount = false;
  for (i = 0; op->arg[i] != RPC_NULL && i < MAX_RPC_ARGS; i++) {
    if (op->arg[i] == RPC_ACCOUNT) {
      fNeedAccount = true; 
      break;
    }
  }
  if (!fNeedAccount)
    return (SHERR_INVAL);

  for (i = 0; op->arg[i] != RPC_NULL && i < MAX_RPC_ARGS; i++) {
    if (i >= op->min_arg)
      break;
    if (op->arg[i] == RPC_ACCOUNT) {
      //if (!account || i >= ar_len)
      if (i >= ar_len)
        return (SHERR_INVAL);
      break; /* only first occurrence */
    }
  }

  fVerified = false;
  try
  {
    for (i = 0; i < ar_len; i++) {
      if (op->arg[i] == RPC_ACCOUNT && !fVerified) {
        string acc_str;
        const char *pkey_str = shjson_array_astr(json, "params", i);
        uint256 pkey(pkey_str);
        if (!GetStratumKeyAccount(pkey, acc_str))
          return (SHERR_ACCESS);

        param.push_back(acc_str);
        fVerified = true;
      } else {
        const char *pstr = shjson_array_astr(json, "params", i);
        if (pstr) {
          string p_str(pstr);
          param.push_back(p_str);
        } else {
          char buf[256];
          if (op->arg[i] == RPC_DOUBLE) 
            sprintf(buf, "%f", shjson_array_num(json, "params", i));
          else
            sprintf(buf, "%lld", 
                (signed long long)shjson_array_num(json, "params", i));
          string p_str(buf);
          param.push_back(p_str);
        }

        RPCConvertParam(iface, op, i, param);
      }
    }

    // Execute
    Value result;
    {
      result = op->actor(iface, param, true);
    }

    string json = JSONRPCReply(result, Value::null, Value::null);
    shbuf_catstr(buff, (char *)json.c_str());
    return (0);
  }
  catch (std::runtime_error& e)
  {
    Debug("stratum (rpc call) runtime error: %s", e.what());
  }
  catch (std::exception& e)
  {
    Debug("stratum (rpc call) exception: %s", e.what());
  }
  
  return (SHERR_INVAL);
}

int ExecuteRPC(int ifaceIndex, shjson_t *json, shbuf_t *buff)
{
  int ar_len = shjson_array_count(json, "params");
  Array param;
  RPCOp *op;
  char method[256];
  uint256 auth_hash;
  uint32_t auth_pin;
  int i;
  bool fRPC;

  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled)
    return (SHERR_OPNOTSUPP);

  memset(method, 0, sizeof(method));
  strncpy(method, shjson_astr(json, "method", ""), sizeof(method)-1);
  string strMethod(method);

  /* verify rpc auth hash & pin */
  string auth_buf(shjson_astr(json, "auth_hash", ""));
  auth_hash = uint256(auth_buf); /* hex */
  auth_pin = (unsigned int)shjson_num(json, "auth_pin", 0);
  if (!_verify_rpc_auth(auth_hash, auth_pin))
    return (SHERR_ACCESS);

  op = GetRPCOp(ifaceIndex, strMethod);
  if (!op) {
    op = GetRPCAlias(ifaceIndex, strMethod);
    if (!op) {
      Value result = rpc_command_help(iface, strMethod);
      string json = JSONRPCReply(result, Value::null, Value::null);
      shbuf_catstr(buff, (char *)json.c_str());
      return (0);
    }
  }

  int max_arg = GetRPCMaxArgs(op);
  if (ar_len < op->min_arg ||
      ar_len > max_arg) {
    Value result = rpc_command_help(iface, strMethod);
    string json = JSONRPCReply(result, Value::null, Value::null);
    shbuf_catstr(buff, (char *)json.c_str());
    return (0);
  }

  try
  {
    for (i = 0; i < ar_len; i++) {
      const char *pstr = shjson_array_astr(json, "params", i);
      if (pstr) {
        string p_str(pstr);
        param.push_back(p_str);
      } else if (op->arg[i] == RPC_ACCOUNT || RPC_STRING) {
        string p_str();
        param.push_back(p_str);
      } else {
        char buf[256];
        if (op->arg[i] == RPC_DOUBLE) 
          sprintf(buf, "%f", shjson_array_num(json, "params", i));
        else
          sprintf(buf, "%lld", 
              (signed long long)shjson_array_num(json, "params", i));
        string p_str(buf);
        param.push_back(p_str);
      }

      RPCConvertParam(iface, op, i, param);
    }

    // Execute
    Value result;
    {
      result = op->actor(iface, param, false);
    }

    string json = JSONRPCReply(result, Value::null, Value::null);
    shbuf_catstr(buff, (char *)json.c_str());
    return (0);
  } catch (Object& objError) {
    string json = JSONRPCReply(Value::null, objError, Value::null);
    shbuf_catstr(buff, (char *)json.c_str());
    return (0);
  } catch (std::exception& e) {
    /* .. */
//fprintf(stderr, "DEBUG: ExecuteRPC: EXCEPTION: %s\n", e.what()); 
  }
  
  return (SHERR_INVAL);
}



