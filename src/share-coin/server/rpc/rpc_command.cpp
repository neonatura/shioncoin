
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


double GetDifficulty(int ifaceIndex, const CBlockIndex* blockindex = NULL)
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

std::string HexBits(unsigned int nBits)
{
    union {
        int32_t nBits;
        char cBits[4];
    } uBits;
    uBits.nBits = htonl((int32_t)nBits);
    return HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}

std::string HelpRequiringPassphrase()
{
#if 0
    return pwalletMain->IsCrypted()
        ? "\nrequires wallet passphrase to be set with walletpassphrase first"
        : "";
#endif
return "";
}

void EnsureWalletIsUnlocked()
{
#if 0
    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");
#endif
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

string AccountFromValue(const Value& value)
{
    string strAccount = value.get_str();
    if (strAccount == "*")
      throw JSONRPCError(-11, "Invalid account name");
    if (strAccount.length() > 0 && strAccount.at(0) == '@')
      throw JSONRPCError(-11, "Invalid account name");

    return strAccount;
}


Value stop(const Array& params, bool fStratum)
{

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "stop\n"
        "Stop coin server.");

  set_shutdown_timer();
#if 0
    // Shutdown will take long enough that the response should get back
    StartServerShutdown();
#endif

  return "coin server has now stopped running!";
}




// coin: Return average network hashes per second based on last number of blocks.
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












Value rpc_sys_shutdown(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (params.size() != 0)
    throw runtime_error("invalid parameters");

  set_shutdown_timer();

  return "The shcoind daemon has been shutdown.";
}

Value rpc_peer_count(CIface *iface, const Array& params, bool fStratum)
{
  NodeList &vNodes = GetNodeList(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "peer.count\n"
        "Returns the number of connections to other nodes.");

  LOCK(cs_vNodes);
  return (int)vNodes.size();
}

Value rpc_peer_hashps(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 1)
    throw runtime_error(
        "peer.hashps [blocks]\n"
        "Returns the estimated network hashes per second based on the last 120 blocks.\n"
        "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.");

  return GetNetworkHashPS(ifaceIndex, params.size() > 0 ? params[0].get_int() : 120);
}

Value rpc_peer_info(CIface *iface, const Array& params, bool fStratum)
{
  NodeList &vNodes = GetNodeList(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "peer.info\n"
        "Statistical and runtime information on network operations.");

  Object obj;

  obj.push_back(Pair("clientversion",   (int)CLIENT_VERSION));
  obj.push_back(Pair("protocolversion", (int)PROTOCOL_VERSION(iface)));
  obj.push_back(Pair("socketport",      (int)iface->port));
  obj.push_back(Pair("connections",     (int)vNodes.size()));
  obj.push_back(Pair("networkhashps",   rpc_peer_hashps(iface, params, false)));
  obj.push_back(Pair("errors",          GetWarnings(ifaceIndex, "statusbar")));

  return obj;
}

Value rpc_sys_info(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  bc_t *bc;
  char tbuf[256];

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "sys.info\n"
        "The system attributes that control how the coin-service operates.");

  Object obj;

  /* versioning */
  obj.push_back(Pair("version",       (int)iface->proto_ver));
  obj.push_back(Pair("blockversion",  (int)iface->block_ver));
  obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));

  /* attributes */
  obj.push_back(Pair("paytxfee",      ValueFromAmount(nTransactionFee)));
  obj.push_back(Pair("mininput",      ValueFromAmount(MIN_INPUT_VALUE(iface))));
  obj.push_back(Pair("maxblocksize",  (int)iface->max_block_size));
  obj.push_back(Pair("mintxfee",      ValueFromAmount(MIN_TX_FEE(iface))));
  obj.push_back(Pair("maxmoney",      ValueFromAmount(iface->max_money)));
  obj.push_back(Pair("maturity",      (int)iface->coinbase_maturity));
  obj.push_back(Pair("maxsigops",     (int)iface->max_sigops));

  /* stats */
  obj.push_back(Pair("blocksubmit",  (int)iface->stat.tot_block_submit));
  obj.push_back(Pair("blockaccept",  (int)iface->stat.tot_block_accept));
  obj.push_back(Pair("txsubmit",  (int)iface->stat.tot_tx_submit));
  obj.push_back(Pair("txaccept",  (int)iface->stat.tot_tx_accept));

  bc = GetBlockChain(iface);
  obj.push_back(Pair("blockfmaps", (int)bc_fmap_total(bc)));
  bc = GetBlockTxChain(iface); 
  obj.push_back(Pair("txfmaps", (int)bc_fmap_total(bc)));

#if 0
  /* transaction blockchain index cache */
  obj.push_back(Pair("txindex", GetTxIndexCount(ifaceIndex)));
#endif

  if (iface->net_valid) {
    sprintf(tbuf, "%-20.20s", ctime(&iface->net_valid));
    string val_str(tbuf);
    obj.push_back(Pair("lastvalidblock", val_str));
  }

  if (iface->net_invalid) {
    sprintf(tbuf, "%-20.20s", ctime(&iface->net_invalid));
    string inval_str(tbuf);
    obj.push_back(Pair("lastinvalidblock", inval_str));
  }

  /* wallet */
  obj.push_back(Pair("wallettx", (int)pwalletMain->mapWallet.size()));
  obj.push_back(Pair("walletaddr", (int)pwalletMain->mapAddressBook.size()));

  /* witseg */
  obj.push_back(Pair("segwit",
        IsWitnessEnabled(iface, GetBestBlockIndex(iface))));
  obj.push_back(Pair("segwit-commit", 
        (iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout != 0) ? "true" : "false"));

  return obj;
}

static void add_sys_config_opt_num(Object& obj, const char *opt_name)
{
  int val = opt_num((char *)opt_name);
  char buf[256];

  sprintf(buf, "%d", val);
  string opt_s(buf);
  obj.push_back(Pair(opt_name, opt_s)); 
}

static void add_sys_config_opt_bool(Object& obj, const char *opt_name)
{
  int val = opt_num((char *)opt_name);
  char buf[256];

  if (val)
    strcpy(buf, "true");
  else
    strcpy(buf, "false");
  string opt_s(buf);
  obj.push_back(Pair(opt_name, opt_s)); 
}

static void add_sys_config_opt_str(Object& obj, const char *opt_name)
{
  const char *val = opt_str((char *)opt_name);
  if (!val)
    return;

  string opt_s(val);
  obj.push_back(Pair(opt_name, opt_s));
}

Value rpc_sys_config(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  bc_t *bc;
  char tbuf[256];

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "sys.config\n"
        "The system configuration settings that control how the coin-service operates.");

  Object obj;

  add_sys_config_opt_bool(obj, OPT_DEBUG);
  add_sys_config_opt_num(obj, OPT_MAX_CONN);
  add_sys_config_opt_bool(obj, OPT_PEER_SEED);
  add_sys_config_opt_num(obj, OPT_BAN_SPAN);
  add_sys_config_opt_num(obj, OPT_BAN_THRESHOLD);
  add_sys_config_opt_num(obj, OPT_RPC_PORT);

  return obj;
}

Value rpc_sys_url(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  char hostname[MAXHOSTNAMELEN+1];

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "sys.url\n");

  string base_url;
  memset(hostname, 0, sizeof(hostname));
  base_url += "http://";
  base_url += unet_local_host();
  base_url += ":9448/";

  Object obj;

  string stat_url = base_url;
  stat_url += iface->name;
  stat_url += "/";
  obj.push_back(Pair("status", stat_url));

  if (ifaceIndex == SHC_COIN_IFACE) {
    string spring_url = base_url;
    spring_url += "image/spring_matrix.bmp?span=0.1&x=128&y=128";
    obj.push_back(Pair("spring-matrix", spring_url));
  }

  return obj;
}

Value rpc_block_info(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "block.info\n"
        "Statistical and runtime information on block operations.");


  Object obj;

  obj.push_back(Pair("version",       (int)iface->proto_ver));
  obj.push_back(Pair("blockversion",  (int)iface->block_ver));
  obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));

  obj.push_back(Pair("blocks",        (int)GetBestHeight(iface)));
  obj.push_back(Pair("difficulty",    (double)GetDifficulty(ifaceIndex)));

  CTxMemPool *pool = GetTxMemPool(iface);
  obj.push_back(Pair("pooledtx",      (uint64_t)pool->size()));

  CBlockIndex *pindexBest = GetBestBlockIndex(iface);
  if (pindexBest)
    obj.push_back(Pair("currentblockhash",     pindexBest->GetBlockHash().GetHex()));
#if 0
  obj.push_back(Pair("currentblocksize",(uint64_t)nLastBlockSize));
  obj.push_back(Pair("currentblocktx",(uint64_t)nLastBlockTx));
#endif

  obj.push_back(Pair("errors",        GetWarnings(ifaceIndex, "statusbar")));

  return obj;
}

Value rpc_block_count(CIface *iface, const Array& params, bool fStratum)
{
  if (fHelp || params.size() != 0)
    throw runtime_error(
        "block.count\n"
        "Returns the number of blocks in the longest block chain.");

  return (int)GetBestHeight(iface);
}

Value rpc_block_hash(CIface *iface, const Array& params, bool fStratum)
{
  bc_t *bc = GetBlockChain(iface);
  int ifaceIndex = GetCoinIndex(iface);
  bc_hash_t ret_hash;
  uint256 hash;
  int err;

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "block.hash <index>\n"
        "Returns hash of block in best-block-chain at <index>.");

  int nHeight = params[0].get_int();
  if (nHeight < 0 || nHeight > GetBestHeight(iface))
    throw runtime_error("Block number out of range.");

  err = bc_get_hash(bc, nHeight, ret_hash);
  if (err) 
    throw runtime_error("Error reading from block-chain.");

  hash.SetRaw((unsigned int *)ret_hash);
  return (hash.GetHex());
}

Value rpc_block_difficulty(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "block.difficulty\n"
        "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.");

  return GetDifficulty(ifaceIndex);
}

Value rpc_block_export(CIface *iface, const Array& params, bool fStratum)
{
  blkidx_t *blockIndex;
  int ifaceIndex = GetCoinIndex(iface);
  unsigned int minHeight = 0;
  unsigned int maxHeight = 0;
  int err;

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "block.export <path> [min-height] [<max-height>]\n"
        "Exports a blockchain to an external file.");

  std::string strPath = params[0].get_str();
  if (params.size() > 1)
    minHeight = params[1].get_int();
  if (params.size() > 2)
    maxHeight = params[2].get_int();

  err = InitChainExport(ifaceIndex, strPath.c_str(), minHeight, maxHeight);
  if (err)
    throw JSONRPCError(-5, sherrstr(err));

  Object result;
  result.push_back(Pair("mode", "export-block"));
  result.push_back(Pair("minheight", (int)minHeight));
  result.push_back(Pair("maxheight", (int)maxHeight));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "init"));
  return (result);
}

Value rpc_block_import(CIface *iface, const Array& params, bool fStratum)
{
  blkidx_t *blockIndex;
  int ifaceIndex = GetCoinIndex(iface);
  unsigned int posFile = 0;
  int err;

  if (fHelp || params.size() == 0 || params.size() > 2)
    throw runtime_error(
        "block.import <path> [<offset>]\n"
        "Imports a blockchain from an external file.");

  std::string strPath = params[0].get_str();
  if (params.size() > 1)
    posFile = params[1].get_int();

  err = InitChainImport(ifaceIndex, strPath.c_str(), posFile);
  if (err)
    throw JSONRPCError(-5, sherrstr(err));

  Object result;
  result.push_back(Pair("mode", "import-block"));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "init"));

  return (result);
}

Value rpc_block_free(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (params.size() != 0)
    throw runtime_error("invalid parameters");

  CloseBlockChain(iface);

  return (true);
}

Value rpc_block_get(CIface *iface, const Array& params, bool fStratum)
{
  blkidx_t *blockIndex;
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 1) {
    throw runtime_error("block.get <hash>\nReturns details of a block with the given block-hash.");
  }

  blockIndex = GetBlockTable(ifaceIndex);
  if (!blockIndex)
    throw JSONRPCError(SHERR_INVAL, "block-chain");

  std::string strHash = params[0].get_str();
  uint256 hash(strHash);

  if (blockIndex->count(hash) == 0)
    throw JSONRPCError(SHERR_NOENT, "block-index");

  CBlockIndex* pblockindex = (*blockIndex)[hash];
  if (!pblockindex)
    throw JSONRPCError(SHERR_INVAL, "block-index");

  CBlock *block = GetBlockByHeight(iface, pblockindex->nHeight);
  if (!block) {
    throw JSONRPCError(SHERR_NOENT, "block-chain");
  }

  //Object ret = blockToJSON(iface, *block, pblockindex);
  Object ret = block->ToValue();

  ret.push_back(Pair("confirmations", 
        GetBlockDepthInMainChain(iface, block->GetHash())));
  if (pblockindex->pprev)
    ret.push_back(Pair("previousblockhash",
          pblockindex->pprev->GetBlockHash().GetHex()));
  if (pblockindex->pnext)
    ret.push_back(Pair("nextblockhash", 
          pblockindex->pnext->GetBlockHash().GetHex()));

  delete block;

  return (ret);
}

Value rpc_block_work(CIface *iface, const Array& params, bool fStratum)
{
  NodeList &vNodes = GetNodeList(iface);
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 1)
    throw runtime_error(
        "block.work [data]\n"
        "If [data] is not specified, returns formatted hash data to work on:\n"
        "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
        "  \"data\" : block data\n"
        "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
        "  \"target\" : little endian hash target\n"
        "If [data] is specified, tries to solve the block and returns true if it was successful.");

  if (vNodes.empty())
    throw JSONRPCError(-9, "coin service is not connected!");

  if (IsInitialBlockDownload(ifaceIndex))
    throw JSONRPCError(-10, "coin service is downloading blocks...");

  typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
  static mapNewBlock_t mapNewBlock;    // FIXME: thread safety
  static vector<CBlock*> vNewBlock;
  static CReserveKey reservekey(pwalletMain);

  if (params.size() == 0)
  {
    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64 nStart;
    static CBlock* pblock;
    if (pindexPrev != GetBestBlockIndex(iface) ||
        (STAT_TX_ACCEPTS(iface) != nTransactionsUpdatedLast && GetTime() - nStart > 60))
    {
      if (pindexPrev != GetBestBlockIndex(iface))
      {
        // Deallocate old blocks since they're obsolete now
        mapNewBlock.clear();
        BOOST_FOREACH(CBlock* pblock, vNewBlock)
          delete pblock;
        vNewBlock.clear();
      }
      nTransactionsUpdatedLast = STAT_TX_ACCEPTS(iface);
      pindexPrev = GetBestBlockIndex(iface);
      nStart = GetTime();

#if 0
      // Create new block
      pblock = CreateNewBlock(reservekey);
      if (!pblock)
        throw JSONRPCError(-7, "Out of memory");
#endif

      pblock = CreateBlockTemplate(iface);
      if (!pblock)
        throw JSONRPCError(-7, "Out of memory");

      vNewBlock.push_back(pblock);
    }

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    // Update nExtraNonce
    static unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

    // Save
    mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

    // Prebuild hash buffers
    char pmidstate[32];
    char pdata[128];
    char phash1[64];
    FormatHashBuffers(pblock, pmidstate, pdata, phash1);

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    Object result;
    result.push_back(Pair("midstate", HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated
    result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
    result.push_back(Pair("hash1",    HexStr(BEGIN(phash1), END(phash1)))); // deprecated
    result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));
    result.push_back(Pair("algorithm", "scrypt:1024,1,1"));  // specify that we should use the scrypt algorithm
    return result;
  }
  else
  {
    // Parse parameters
    vector<unsigned char> vchData = ParseHex(params[0].get_str());
    if (vchData.size() != 128)
      throw JSONRPCError(-8, "Invalid parameter");
    CBlock* pdata = (CBlock*)&vchData[0];

    // Byte reverse
    for (int i = 0; i < 128/4; i++)
      ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);

    // Get saved block
    if (!mapNewBlock.count(pdata->hashMerkleRoot))
      return false;
    CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

    pblock->nTime = pdata->nTime;
    pblock->nNonce = pdata->nNonce;
    pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();

    return CheckWork(pblock, *pwalletMain, reservekey);
  }
}

Value rpc_block_workex(CIface *iface, const Array& params, bool fStratum)
{
  NodeList &vNodes = GetNodeList(iface);
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 2)
    throw runtime_error(
        "block.workex [data, coinbase]\n"
        "If [data, coinbase] is not specified, returns extended work data.\n"
        );

  if (vNodes.empty())
    throw JSONRPCError(-9, "coin service is not connected!");

  if (IsInitialBlockDownload(ifaceIndex))
    throw JSONRPCError(-10, "coin service is downloading blocks...");

  typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
  static mapNewBlock_t mapNewBlock;
  static vector<CBlock*> vNewBlock;
  static CReserveKey reservekey(pwalletMain);

  if (params.size() == 0)
  {
    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64 nStart;
    static CBlock* pblock;
    if (pindexPrev != GetBestBlockIndex(iface) ||
        (STAT_TX_ACCEPTS(iface) != nTransactionsUpdatedLast && GetTime() - nStart > 60))
    {
      if (pindexPrev != GetBestBlockIndex(iface)) {
        // Deallocate old blocks since they're obsolete now
        mapNewBlock.clear();
        BOOST_FOREACH(CBlock* pblock, vNewBlock)
          delete pblock;
        vNewBlock.clear();
      }
      nTransactionsUpdatedLast = STAT_TX_ACCEPTS(iface);
      pindexPrev = GetBestBlockIndex(iface);
      nStart = GetTime();

#if 0
      // Create new block
      pblock = CreateNewBlock(iface, reservekey);
      if (!pblock)
        throw JSONRPCError(-7, "Out of memory");
#endif

      pblock = CreateBlockTemplate(iface);
      if (!pblock)
        throw JSONRPCError(-7, "Out of memory");

      vNewBlock.push_back(pblock);
    }

    // Update nTime
    pblock->nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());
    pblock->nNonce = 0;

    // Update nExtraNonce
    static unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

    // Save
    mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

    // Prebuild hash buffers
    char pmidstate[32];
    char pdata[128];
    char phash1[64];
    FormatHashBuffers(pblock, pmidstate, pdata, phash1);

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    CTransaction coinbaseTx = pblock->vtx[0];
    std::vector<uint256> merkle = pblock->GetMerkleBranch(0);

    Object result;
    result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
    result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface));
    ssTx << coinbaseTx;
    result.push_back(Pair("coinbase", HexStr(ssTx.begin(), ssTx.end())));

    Array merkle_arr;

    BOOST_FOREACH(uint256 merkleh, merkle) {
      merkle_arr.push_back(HexStr(BEGIN(merkleh), END(merkleh)));
    }

    result.push_back(Pair("merkle", merkle_arr));


    return result;
  }
  else
  {
    // Parse parameters
    vector<unsigned char> vchData = ParseHex(params[0].get_str());
    vector<unsigned char> coinbase;

    if(params.size() == 2)
      coinbase = ParseHex(params[1].get_str());

    if (vchData.size() != 128)
      throw JSONRPCError(-8, "Invalid parameter");

    CBlock* pdata = (CBlock*)&vchData[0];

    // Byte reverse
    for (int i = 0; i < 128/4; i++)
      ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);

    // Get saved block
    if (!mapNewBlock.count(pdata->hashMerkleRoot))
      return false;
    CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

    pblock->nTime = pdata->nTime;
    pblock->nNonce = pdata->nNonce;

    if(coinbase.size() == 0)
      pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
    else
      CDataStream(coinbase, SER_NETWORK, PROTOCOL_VERSION(iface)) >> pblock->vtx[0]; // FIXME - HACK!

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();

    return CheckWork(pblock, *pwalletMain, reservekey);
  }
}

Value rpc_msg_sign(CIface *iface, const Array& params, bool fStratum)
{
  if (fStratum)
    throw runtime_error("unsupported operation");
  CWallet *pwalletMain = GetWallet(iface);
  if (fHelp || params.size() != 2)
    throw runtime_error(
        "msg.sign <coin-addr> <message>\n"
        "Sign a message with the private key of an address");

  EnsureWalletIsUnlocked();

  string strAddress = params[0].get_str();
  string strMessage = params[1].get_str();

  CCoinAddr addr(strAddress);
  if (!addr.IsValid())
    throw JSONRPCError(-3, "Invalid address");

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    throw JSONRPCError(-3, "Address does not refer to key");

  CKey key;
  if (!pwalletMain->GetKey(keyID, key))
    throw JSONRPCError(-4, "Private key not available");

  string strMessageMagic;
  if (0 == strcasecmp(iface->name, "emc2"))
    strMessage.append("Einsteinium");
  else
    strMessage.append(iface->name);
  strMessage.append(" Signed Message:\n");
//const string strMessageMagic = "usde Signed Message:\n";


  CDataStream ss(SER_GETHASH, 0);
  ss << strMessageMagic;
  ss << strMessage;

  vector<unsigned char> vchSig;
  if (!key.SignCompact(Hash(ss.begin(), ss.end()), vchSig))
    throw JSONRPCError(-5, "Sign failed");

  return EncodeBase64(&vchSig[0], vchSig.size());
}

Value rpc_msg_verify(CIface *iface, const Array& params, bool fStratum)
{
  if (fStratum)
    throw runtime_error("unsupported operation");
  if (fHelp || params.size() != 3)
    throw runtime_error(
        "msg.verify <coin-address> <signature> <message>\n"
        "Verify a signed message");

  string strAddress  = params[0].get_str();
  string strSign     = params[1].get_str();
  string strMessage  = params[2].get_str();

  CCoinAddr addr(strAddress);
  if (!addr.IsValid())
    throw JSONRPCError(-3, "Invalid address");

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    throw JSONRPCError(-3, "Address does not refer to key");

  bool fInvalid = false;
  vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

  if (fInvalid)
    throw JSONRPCError(-5, "Malformed base64 encoding");

  string strMessageMagic;
  if (0 == strcasecmp(iface->name, "emc2"))
    strMessage.append("Einsteinium");
  else
    strMessage.append(iface->name);
  strMessage.append(" Signed Message:\n");

  CDataStream ss(SER_GETHASH, 0);
  ss << strMessageMagic;
  ss << strMessage;

  CKey key;
  if (!key.SetCompactSignature(Hash(ss.begin(), ss.end()), vchSig))
    return false;

  return (key.GetPubKey().GetID() == keyID);
}

Value rpc_wallet_balance(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 2)
    throw runtime_error(
        "wallet.balance [account] [minconf=1]\n"
        "If [account] is not specified, returns the server's total available balance.\n"
        "If [account] is specified, returns the balance in the account.");

  if (params.size() == 0)
    return  ValueFromAmount(pwalletMain->GetBalance());

  int nMinDepth = 1;
  if (params.size() > 1)
    nMinDepth = params[1].get_int();

  if (params[0].get_str() == "*") {
    // Calculate total balance a different way from GetBalance()
    // (GetBalance() sums up all unspent TxOuts)
    // getbalance and getbalance '*' should always return the same number.
    int64 nBalance = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
      const CWalletTx& wtx = (*it).second;
      if (!wtx.IsFinal(ifaceIndex))
        continue;

      int64 allGeneratedImmature, allGeneratedMature, allFee;
      allGeneratedImmature = allGeneratedMature = allFee = 0;
      string strSentAccount;
      list<pair<CTxDestination, int64> > listReceived;
      list<pair<CTxDestination, int64> > listSent;
      wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount);
      //wtx.GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount);
      if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
      {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listReceived)
          nBalance += r.second;
      }
      BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listSent)
        nBalance -= r.second;
      nBalance -= allFee;
//      nBalance += allGeneratedMature;
    }
    return  ValueFromAmount(nBalance);
  }

  string strAccount = AccountFromValue(params[0]);

  int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);

  return ValueFromAmount(nBalance);
}

Value rpc_wallet_export(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");
    
  if (params.size() != 1)
    throw runtime_error("wallet.export");

  std::string strPath = params[0].get_str();

  int ifaceIndex = GetCoinIndex(iface);
  shjson_t *json = shjson_init(NULL);
  shjson_t *tree = shjson_array_add(json, iface->name);
  shjson_t *node;
  FILE *fl;
  char *text;

  CWallet *pwalletMain = GetWallet(iface);

  std::set<CKeyID> keys;
  pwalletMain->GetKeys(keys);
  BOOST_FOREACH(const CKeyID& key, keys) {
    if (pwalletMain->mapAddressBook.count(key) == 0) { /* loner */

/* todo: try again w/ txdb removed */
#if 0
/* DEBUG: commented out; takes too long with large wallet */
      /* was this key ever used. */
      int nTxInput = 0;
      int nTxSpent = 0;
      BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
        const CWalletTx& tx = item.second;
        int i;
        for (i = 0; i < tx.vout.size(); i++) {
          CTxDestination dest;
          if (!ExtractDestination(tx.vout[i].scriptPubKey, dest))
            continue;
          CKeyID k1;
          CCoinAddr(ifaceIndex, dest).GetKeyID(k1);
          if (k1 == key) {
            if (tx.IsSpent(i)) {
              nTxSpent++;
            }
            nTxInput++;
          }
        }
      }
      if (nTxInput == 0 || (nTxSpent >= nTxInput))
        continue; /* never used or spent */
#endif

      /* pub key */
      CCoinAddr addr(ifaceIndex, key);

      /* priv key */
      CSecret vchSecret;
      bool fCompressed;
      if (!pwalletMain->GetSecret(key, vchSecret, fCompressed))
        continue;
      CCoinSecret csec(ifaceIndex, vchSecret, fCompressed);
      string strKey = csec.ToString();

      node = shjson_obj_add(tree, NULL);
      shjson_str_add(node, "key", (char *)strKey.c_str()); 
      shjson_str_add(node, "label", "coinbase");
      shjson_str_add(node, "addr", (char *)addr.ToString().c_str());
//      shjson_str_add(node, "phrase", (char *)EncodeMnemonicSecret(csec).c_str());
//      shjson_num_add(node, "inputs", (nTxInput - nTxSpent));
    }
  }
  

  map<string, int64> mapAccountBalances;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
    CTxDestination dest = entry.first;
    string strLabel = entry.second;

    if (!IsMine(*pwalletMain, dest))
      continue;

#if 0
    CCoinAddr address;
    if (!address.SetString(strLabel))
      continue;//throw JSONRPCError(-5, "Invalid address");
#endif

    CCoinAddr addr(ifaceIndex, dest);
    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
      continue;//throw JSONRPCError(-3, "Address does not refer to a key");

    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
      continue;//throw JSONRPCError(-4,"Private key for address " + strLabel + " is not known");
    CCoinSecret csec(ifaceIndex, vchSecret, fCompressed);
    string strKey = csec.ToString();

    node = shjson_obj_add(tree, NULL);
    shjson_str_add(node, "key", (char *)strKey.c_str()); 
    shjson_str_add(node, "label", (char *)strLabel.c_str());
    shjson_str_add(node, "addr", (char *)addr.ToString().c_str());
//    shjson_str_add(node, "phrase", (char *)EncodeMnemonicSecret(csec).c_str());
  }

  text = shjson_print(json);
  shjson_free(&json);

  fl = fopen(strPath.c_str(), "wb");
  if (fl) {
    fwrite(text, sizeof(char), strlen(text), fl);
    fclose(fl);
  }
  free(text);

  return Value::null;
}

/** removes from address book only -- does not remove from keystore */
Value rpc_wallet_prune(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *pwalletMain = GetWallet(iface);

  if (fStratum)
    throw runtime_error("unsupported operation");
    
  if (params.size() != 1)
    throw runtime_error("wallet.prune");

  string strAccount = AccountFromValue(params[0]);

  vector<CTxDestination> vRemove;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
    CTxDestination book_dest = entry.first;
    string strLabel = entry.second;

    if (!IsMine(*pwalletMain, book_dest))
      continue;

    CKeyID key;
    CCoinAddr(ifaceIndex, book_dest).GetKeyID(key);

    /* was this key ever used. */
    int nTxInput = 0;
    int nTxSpent = 0;
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
      const CWalletTx& tx = item.second;
      int i;
      for (i = 0; i < tx.vout.size(); i++) {
        CTxDestination dest;
        if (!ExtractDestination(tx.vout[i].scriptPubKey, dest))
          continue;
        CKeyID k1;
        CCoinAddr(ifaceIndex, dest).GetKeyID(k1);
        if (k1 == key) {
          if (tx.IsSpent(i)) {
            nTxSpent++;
          }
          nTxInput++;
        }
      }
    }

    if (nTxInput == 0 || (nTxSpent >= nTxInput)) {
      /* never used or spent */
      vRemove.push_back(book_dest);
    }

  }

  BOOST_FOREACH(const CTxDestination& dest, vRemove) {
    pwalletMain->mapAddressBook.erase(dest);  
  }

  return Value::null;
}

bool BackupWallet(const CWallet& wallet, const string& strDest)
{
  if (!wallet.fFileBacked)
    return false;
  while (!fShutdown)
  {
    {
      LOCK(bitdb.cs_db);
      if (!bitdb.mapFileUseCount.count(wallet.strWalletFile) || bitdb.mapFileUseCount[wallet.strWalletFile] == 0)
      {
        // Flush log data to the dat file
        bitdb.CloseDb(wallet.strWalletFile);
        bitdb.CheckpointLSN(wallet.strWalletFile);
        bitdb.mapFileUseCount.erase(wallet.strWalletFile);

        // Copy wallet.dat
        filesystem::path pathSrc = GetDataDir() / wallet.strWalletFile;
        filesystem::path pathDest(strDest);
        if (filesystem::is_directory(pathDest))
          pathDest /= wallet.strWalletFile;

        try {
#if 0
#if BOOST_VERSION >= 104000
          filesystem::copy_file(pathSrc, pathDest, filesystem::copy_option::overwrite_if_exists);
#else
          filesystem::copy_file(pathSrc, pathDest);
#endif
#endif
          filesystem::copy_file(pathSrc, pathDest);
          printf("copied wallet.dat to %s\n", pathDest.string().c_str());
          return true;
        } catch(const filesystem::filesystem_error &e) {
          printf("error copying wallet.dat to %s - %s\n", pathDest.string().c_str(), e.what());
          return false;
        }
      }
    }
//    Sleep(100);
  }
  return false;
}

Value rpc_wallet_exportdat(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");
    
  if (params.size() != 1)
    throw runtime_error("wallet.exportdat");

  CWallet *wallet = GetWallet(iface);
  if (!wallet)
    throw runtime_error("Wallet not available.");

  string strDest = params[0].get_str();
  if (!BackupWallet(*wallet, strDest))
    throw runtime_error("Failure writing wallet datafile.");

  return Value::null;
}

Value rpc_wallet_get(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  CWallet *pwalletMain = GetWallet(iface);
  if (params.size() != 1)
    throw runtime_error("wallet.get");

  CCoinAddr address(params[0].get_str());
  if (!address.IsValid())
    throw JSONRPCError(-5, "Invalid coin address");

  string strAccount;
  map<CTxDestination, string>::iterator mi = pwalletMain->mapAddressBook.find(address.Get());
  if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.empty())
    strAccount = (*mi).second;
  return strAccount;
}

Value rpc_wallet_key(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.key <address>\n"
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
        "The entire wallet can be exported to a file via the 'wallet.export' command.\n"
        );

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  string strAddress = params[0].get_str();
  CCoinAddr address(strAddress);
  if (!address.IsValid())
    throw JSONRPCError(-5, "Invalid address");
  CKeyID keyID;
  if (!address.GetKeyID(keyID))
    throw JSONRPCError(-3, "Address does not refer to a key");
  CSecret vchSecret;
  bool fCompressed;
  if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
    throw JSONRPCError(-4,"Private key for address " + strAddress + " is not known");
  return CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString();
}

Value rpc_wallet_info(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (params.size() != 0)
    throw runtime_error("invalid parameters specified");

  Object obj;
  obj.push_back(Pair("version",       (int)CLIENT_VERSION));
  obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));

  obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance())));

  obj.push_back(Pair("keypoololdest", (boost::int64_t)pwalletMain->GetOldestKeyPoolTime()));
  obj.push_back(Pair("keypoolsize",   pwalletMain->GetKeyPoolSize()));

//  obj.push_back(Pair("txcachecount",   (int)pwalletMain->mapWallet.size()));
//  obj.push_back(Pair("errors",        GetWarnings(ifaceIndex, "statusbar")));

  return obj;

}

Value rpc_tx_validate(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (params.size() != 1)
    throw runtime_error("invalid parameters specified");

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  uint256 hash(params[0].get_str());

  if (0 == pwalletMain->mapWallet.count(hash)) {
    throw JSONRPCError(-4, "Transaction is not contained in wallet.");
  }

  CWalletTx& wtx = pwalletMain->mapWallet[hash];

  Array ret;

  int nOut = 0;
  BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
    bool fValid = false;
    Object obj;

    CTxDestination dest;
    if (!wtx.CheckTransaction(ifaceIndex) ||
        !ExtractDestination(txout.scriptPubKey, dest)) {
      obj.push_back(Pair("isvalid", "false"));
    } else {
      CCoinAddr addr(ifaceIndex, dest);
      obj.push_back(Pair("spent", wtx.IsSpent(nOut) ? "true" : "false"));
      obj.push_back(Pair("ismine", pwalletMain->IsMine(wtx) ? "true" : "false")); 
      obj.push_back(Pair("address", addr.ToString()));
    }

    ret.push_back(obj);
    nOut++;
  }

  return ret;
}

Value rpc_wallet_import(CIface *iface, const Array& params, bool fStratum)
{
  if (fStratum)
    throw runtime_error("unsupported operation");
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 1) {
    throw runtime_error(
        "wallet.import <path>\n"
        "Import a JSON wallet file.");
  }

  std::string strPath = params[0].get_str();

  {
  shjson_t *json;
  shjson_t *tree;
shjson_t *node;
char *text;
struct stat st;
FILE *fl;
    char label[256];
    char addr[256];
    char key[256];

    memset(label, 0, sizeof(label));
    memset(addr, 0, sizeof(addr));
    memset(key, 0, sizeof(key));

    fl = fopen(strPath.c_str(), "rb");
    if (!fl)
      throw runtime_error("error opening file.");

    memset(&st, 0, sizeof(st));
    fstat(fileno(fl), &st);
    if (st.st_size == 0)
      throw runtime_error("file is not in JSON format.");

    text = (char *)calloc(st.st_size + 1, sizeof(char));
    if (!text)
      throw runtime_error("not enough memory to allocate file.");

    fread(text, sizeof(char), st.st_size, fl);
    fclose(fl);

    //    serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

    json = shjson_init(text);
    free(text);
    if (!json) {
      throw runtime_error("file is not is JSON format.");
    }

    tree = json->child;
    if (tree && tree->string) {
      if (0 != strcmp(tree->string, iface->name))
        throw runtime_error("wallet file references incorrect coin service.");

      for (node = tree->child; node; node = node->next) {
        strncpy(label, shjson_astr(node, "label", ""), sizeof(label)-1);
        strncpy(addr, shjson_astr(node, "addr", ""), sizeof(addr)-1);
        strncpy(key, shjson_astr(node, "key", ""), sizeof(key)-1);
        if (!*key) continue;

        string strSecret(key);
        string strLabel(label);

        CCoinSecret vchSecret;
        bool fGood = vchSecret.SetString(strSecret);
        if (!fGood) {
          continue;// throw JSONRPCError(-5,"Invalid private key");
        }

        CKey key;
        bool fCompressed;
        CSecret secret = vchSecret.GetSecret(fCompressed);
        key.SetSecret(secret, fCompressed);
        CKeyID vchAddress = key.GetPubKey().GetID();


        {
          LOCK2(cs_main, pwalletMain->cs_wallet);

          if (pwalletMain->HaveKey(vchAddress)) {
            /* pubkey has already been assigned to an account. */
            continue;
          }

          if (!pwalletMain->AddKey(key)) {
            //JSONRPCError(-4,"Error adding key to wallet"); 
            continue; 
          }

          pwalletMain->MarkDirty();
          pwalletMain->SetAddressBookName(vchAddress, strLabel);
        }
      }
    }

    shjson_free(&json);
  }
pwalletMain->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
pwalletMain->ReacceptWalletTransactions();

#if 0
  string strSecret = params[0].get_str();
  string strLabel = "";
//  if (params.size() > 1)
    strLabel = params[1].get_str();
  CCoinSecret vchSecret;
  bool fGood = vchSecret.SetString(strSecret);

  if (!fGood) throw JSONRPCError(-5,"Invalid private key");

  CKey key;
  bool fCompressed;
  CSecret secret = vchSecret.GetSecret(fCompressed);
  key.SetSecret(secret, fCompressed);
  CKeyID vchAddress = key.GetPubKey().GetID();
  {
    LOCK2(cs_main, pwalletMain->cs_wallet);

    pwalletMain->MarkDirty();
    pwalletMain->SetAddressBookName(vchAddress, strLabel);

    if (!pwalletMain->AddKey(key))
      throw JSONRPCError(-4,"Error adding key to wallet");

    pwalletMain->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
    pwalletMain->ReacceptWalletTransactions();
  }
#endif

  return Value::null;
}

Value rpc_wallet_list(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 1)
    throw runtime_error(
        "wallet.list [minconf=1]\n"
        "Returns Object that has account names as keys, account balances as values.");

  int nMinDepth = 1;
  if (params.size() > 0)
    nMinDepth = params[0].get_int();


  vector<string> vAcc;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
    const string& strAccount = entry.second;

    if (strAccount.length() != 0 && strAccount.at(0) == '@')
      continue; /* ext account */

    if (find(vAcc.begin(), vAcc.end(), strAccount) != vAcc.end())
      continue; /* already established account name */

    if (IsMine(*wallet, entry.first)) { // This address belongs to me
      vAcc.push_back(strAccount);
    }
  }

  map<string, int64> mapAccountBalances;
  BOOST_FOREACH(const string& strAccount, vAcc) {
    int64 nTotal = 0;

    vector<COutput> vCoins;
    wallet->AvailableAccountCoins(strAccount, vCoins);
    BOOST_FOREACH(const COutput& out, vCoins) {
      nTotal += out.tx->vout[out.i].nValue;
    }

    mapAccountBalances[strAccount] = nTotal;
  }

  /* ?? */
  list<CAccountingEntry> acentries;
  CWalletDB(wallet->strWalletFile).ListAccountCreditDebit("*", acentries);
  BOOST_FOREACH(const CAccountingEntry& entry, acentries) {
    mapAccountBalances[entry.strAccount] += entry.nCreditDebit;
  }

  Object ret;
  BOOST_FOREACH(const PAIRTYPE(string, int64)& accountBalance, mapAccountBalances) {
    ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
  }

  return ret;
}

Value rpc_wallet_addr(CIface *iface, const Array& params, bool fStratum)
{
  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.addr <account>\n"
        "Returns the current hash address for receiving payments to this account.");

  // Parse the account first so we don't generate a key if there's an error
  string strAccount = AccountFromValue(params[0]);

  Value ret;

  ret = GetAccountAddress(GetWallet(iface), strAccount).ToString();

  return ret;
}





Value rpc_wallet_witaddr(CIface *iface, const Array& params, bool fStratum)
{

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.witaddr <addr>\n"
        "Returns a witness program which references the coin address specified.");

  CWallet *wallet = GetWallet(iface);
  string strAccount;

  // Parse the account first so we don't generate a key if there's an error
  CCoinAddr address(params[0].get_str());
  if (!address.IsValid())
    throw JSONRPCError(-5, "Invalid coin address specified.");

  if (!IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
    throw JSONRPCError(-4, "Segregated witness is not enabled on the network.");
  }

  if (!GetCoinAddr(wallet, address, strAccount)) {
    throw JSONRPCError(-5, "No account associated with coin address.");
  }

  CKeyID keyID;
  CScriptID scriptID;
  CScriptID result;
  if (address.GetKeyID(keyID)) {
    CScript basescript = GetScriptForDestination(keyID);

    if (!IsMine(*wallet, basescript))
      throw JSONRPCError(-5, "No local account associated with coin address.");

    CScript witscript = GetScriptForWitness(basescript);
    wallet->AddCScript(witscript);
    result = CScriptID(witscript);
  } else if (address.GetScriptID(scriptID)) {
    CScript subscript;
    if (wallet->GetCScript(scriptID, subscript)) {
      int witnessversion;
      std::vector<unsigned char> witprog;
      if (subscript.IsWitnessProgram(witnessversion, witprog)) {
        /* ID is already for a witness program script */
        result = scriptID;
      } else {
        //isminetype typ;
        //typ = IsMine(*pwalletMain, subscript, SIGVERSION_WITNESS_V0);
        //if (typ != ISMINE_SPENDABLE && typ != ISMINE_WATCH_SOLVABLE)
        if (!IsMine(*wallet, subscript))
          throw JSONRPCError(-5, "No local account associated with coin address.");

        CScript witscript = GetScriptForWitness(subscript);
        wallet->AddCScript(witscript);
        result = CScriptID(witscript);
      }
    }
  } else /* ?? */ {
    throw JSONRPCError(-5, "Coin address could not be parsed.");
  }

  /* persist */
  wallet->SetAddressBookName(result, strAccount);

  return (CCoinAddr(result).ToString());
}

Value rpc_wallet_recvbyaccount(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() < 1 || params.size() > 2)
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

  if (fHelp || params.size() < 1 || params.size() > 2)
    throw runtime_error(
        "wallet.recvbyaddr <coin-address> [minconf=1]\n"
        "Returns the total amount received by <coin-address> in transactions with at least [minconf] confirmations.");

  CCoinAddr address = CCoinAddr(params[0].get_str());
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

void ResetServiceWalletEvent(CWallet *wallet);

Value rpc_wallet_rescan(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  vector<uint256> hash_list;
  tx_cache inputs;
  uint256 bhash;
  uint64_t bestHeight;
  uint64_t minTime;
  uint64_t minHeight;

  if (fStratum)
    throw runtime_error("unsupported operation");
  if (fHelp || params.size() != 0)
    throw runtime_error("wallet.rescan\nRescan coin inputs associated with local wallet transactions.\n");

  bestHeight = GetBestHeight(iface);
  minHeight = bestHeight + 1;
  minTime = time(NULL) + 1;

  /* scan wallet's 'previous hiearchy' */
  for (map<uint256, CWalletTx>::const_iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
  {
    const CWalletTx& pcoin = (*it).second;
    const uint256& pcoin_hash = pcoin.GetHash();
    uint256 bhash = 0;

    const CTransaction& pcoin_tx = (CTransaction)pcoin;
    inputs[pcoin_hash] = pcoin_tx;

    BOOST_FOREACH(const CTxIn& txin, pcoin.vin) {
      CTransaction tx;
      if (inputs.count(txin.prevout.hash) != 0) {
        tx = inputs[txin.prevout.hash];
      } else if (::GetTransaction(iface, txin.prevout.hash, tx, &bhash)) {
        inputs[txin.prevout.hash] = tx;
      } else {
        /* unknown */
        continue;
      }

      wallet->FillInputs(tx, inputs);
    }

    if (bhash != 0 && 
        find(hash_list.begin(), hash_list.end(), bhash) != hash_list.end()) {
        hash_list.insert(hash_list.end(), bhash);
    }
  }

  /* scan wallet's 'next hiearchy' */
  for (tx_cache::iterator it = inputs.begin(); it != inputs.end(); ++it) {
    CTransaction& tx = (*it).second;
    vector<uint256> vOuts;

    if (!tx.ReadCoins(ifaceIndex, vOuts))
      continue; /* unknown */
    if (tx.vout.size() > vOuts.size())
      continue; /* invalid */

    
    BOOST_FOREACH(const uint256& tx_hash, vOuts) {
      uint256 bhash;
      if (!::GetTransaction(iface, tx_hash, tx, &bhash)) 
        continue;

      if (inputs.count(tx_hash) == 0)
        inputs[tx_hash] = tx;
      if (find(hash_list.begin(), hash_list.end(), bhash) != hash_list.end())
        hash_list.insert(hash_list.end(), bhash);

      wallet->FillInputs(tx, inputs);
    }
  }

  /* add any missing wallet tx's */
  for (tx_cache::const_iterator it = inputs.begin(); it != inputs.end(); ++it) {
    const CTransaction& tx = (*it).second;
    wallet->AddToWalletIfInvolvingMe(tx, NULL, true);
  }

  /* find earliest block inovolved. */
  BOOST_FOREACH(const uint256& bhash, hash_list) {
    CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, bhash);
    if (!pindex) continue; /* unknown */ 

    if (pindex->nHeight < minHeight)
      minHeight = pindex->nHeight;
    if (pindex->nTime < minTime)
      minTime = pindex->nTime;
  }

#if 0
  /* find near-reach hierarchial parents of wallet-txs */
  for (map<uint256, CWalletTx>::const_iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
  {
    const CWalletTx& pcoin = (*it).second;
    BOOST_FOREACH(const CTxIn& txin, pcoin.vin) {
      CTransaction tx;
      if (!::GetTransaction(iface, txin.prevout.hash, tx, &bhash))
        continue;
      wallet->AddToWalletIfInvolvingMe(tx, NULL, true);
    }
  }
#endif

  minHeight = MIN(bestHeight, minHeight);
  if (minHeight != bestHeight) {
    /* reset wallet-scan event state */
    ResetServiceWalletEvent(wallet);
    /* scan entire chain for corrections to wallet & coin-db. */
    InitServiceWalletEvent(wallet, minHeight);
  }

  Object ret;
  ret.push_back(Pair("scan-height", minHeight));
#if 0
  if (minHeight != bestHeight) {
    ret.push_back(Pair("min-stamp", ToValue_date_format((time_t)minTime)));
    ret.push_back(Pair("min-time", minTime));
  }
#endif
  ret.push_back(Pair("prescan-tx", (int)inputs.size()));
  ret.push_back(Pair("wallet-tx", (int)wallet->mapWallet.size()));

  return (ret);
}

Value rpc_wallet_send(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() < 3 || params.size() > 6)
    throw runtime_error(
        "wallet.send <fromaccount> <toaddress> <amount> [minconf=1] [comment] [comment-to]\n"
        "<amount> is a real and is rounded to the nearest 0.00000001"
        + HelpRequiringPassphrase());

  /* originating account  */
  string strAccount = AccountFromValue(params[0]);

  /* destination coin address */
  CCoinAddr address(params[1].get_str());
#if 0
  if (!address.IsValid())
    throw JSONRPCError(-5, "Invalid coin address");
#endif
  if (address.GetVersion() != CCoinAddr::GetCoinAddrVersion(ifaceIndex))
    throw JSONRPCError(-5, "Invalid address for coin service.");

  int64 nAmount = AmountFromValue(params[2]);
  int nMinDepth = 1;
  if (params.size() > 3)
    nMinDepth = params[3].get_int();

  CTxCreator wtx(wallet, strAccount);
  //CWalletTx wtx;
  //wtx.strFromAccount = strAccount;
  if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
    wtx.mapValue["comment"] = params[4].get_str();
  if (params.size() > 5 && params[5].type() != null_type && !params[5].get_str().empty())
    wtx.mapValue["to"]      = params[5].get_str();

  // EnsureWalletIsUnlocked();

  // Check funds
  int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
  if (nAmount > nBalance)
    throw JSONRPCError(-6, "Account has insufficient funds");

  if (!wtx.AddOutput(address.Get(), nAmount))
    throw JSONRPCError(-5, "Invalid destination address specified.");

  if (!wtx.Send())
    throw JSONRPCError(-5, wtx.GetError());
#if 0
  //string strError = wallet->SendMoneyToDestination(address.Get(), nAmount, wtx);
  string strError = wallet->SendMoney(strAccount, address.Get(), nAmount, wtx);
  if (strError != "")
    throw JSONRPCError(-4, strError);
#endif

  return wtx.GetHash().GetHex();
}

Value rpc_wallet_tsend(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (params.size() < 3)
    throw runtime_error("invalid parameters");

  /* originating account  */
  string strAccount = AccountFromValue(params[0]);

  /* destination coin address */
  CCoinAddr address(params[1].get_str());
  if (address.GetVersion() != CCoinAddr::GetCoinAddrVersion(ifaceIndex))
    throw JSONRPCError(-5, "Invalid address for coin service.");

  int64 nAmount = AmountFromValue(params[2]);
  int nMinDepth = 1;
  if (params.size() > 3)
    nMinDepth = params[3].get_int();

  int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
  if (nAmount > nBalance)
    throw JSONRPCError(-6, "Account has insufficient funds");

  CTxCreator wtx(wallet, strAccount);
/*
  string strError = wallet->SendMoney(strAccount, address.Get(), nAmount, wtx, true);
  if (strError != "" && strError != "ABORTED")
    throw JSONRPCError(-4, strError);
*/

  wtx.AddOutput(address.Get(), nAmount);
  if (!wtx.Generate())
    throw JSONRPCError(-4, wtx.GetError());

  unsigned int nBytes = ::GetSerializeSize(wtx, SER_NETWORK, 
      PROTOCOL_VERSION(iface) | SERIALIZE_TRANSACTION_NO_WITNESS);
  int64 nFee = wallet->GetTxFee(wtx);

  tx_cache inputs;
  if (!wallet->FillInputs(wtx, inputs))
    throw JSONRPCError(-4, "error filling inputs");
  double dPriority = wallet->GetPriority(wtx, inputs);

  int64 nVirtSize = wallet->GetVirtualTransactionSize(wtx);

  Object ret_obj;
  ret_obj.push_back(Pair("amount", ValueFromAmount(nAmount)));
  ret_obj.push_back(Pair("tx-amount", ValueFromAmount(wtx.GetValueOut())));
  ret_obj.push_back(Pair("size", (int)nBytes));
  ret_obj.push_back(Pair("virt-size", (int)nVirtSize));
  //ret_obj.push_back(Pair("maxsize", (int)nMaxBytes));
  ret_obj.push_back(Pair("fee", ValueFromAmount(nFee)));
  ret_obj.push_back(Pair("inputs", inputs.size()));
  ret_obj.push_back(Pair("priority", dPriority));

  return ret_obj;
}

Value rpc_wallet_bsend(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  const int nMinDepth = 1;
  int64 nSent;
  int64 nValue;
  int nBytes;
  int nInputs;

  if (params.size() < 3)
    throw runtime_error("invalid parameters");

  /* originating account  */
  string strAccount = AccountFromValue(params[0]);

  /* destination coin address */
  CCoinAddr address(params[1].get_str());
  if (address.GetVersion() != CCoinAddr::GetCoinAddrVersion(ifaceIndex))
    throw JSONRPCError(-5, "Invalid address for coin service.");

  int64 nAmount = AmountFromValue(params[2]);

  int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
  if (nAmount > nBalance)
    throw JSONRPCError(-6, "Account has insufficient funds");

  /* init batch tx creator */
  CScript scriptPub;
  scriptPub.SetDestination(address.Get());
  CTxBatchCreator b_tx(wallet, strAccount, scriptPub, nAmount); 

  if (!b_tx.Generate()) {
    string strError = b_tx.GetError();
    if (strError == "")
      strError = "An unknown error occurred while generating the transactions.";
    throw JSONRPCError(-6, strError);
  } 

  if (!b_tx.Send()) {
    string strError = b_tx.GetError();
    if (strError == "")
      strError = "An unknown error occurred while commiting the batch transaction operation.";
    throw JSONRPCError(-6, strError);
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


  Object ret;
  int64 nFee = nValueIn - nValueOut - nChangeOut;
  nBalance = MAX(0, nBalance - (nValueOut + nFee));

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
    ar.push_back(wtx.ToValue(ifaceIndex));    
  }
  ret.push_back(Pair("tx", ar));

  return (ret);
}


Value rpc_wallet_set(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  CWallet *pwalletMain = GetWallet(iface);
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "wallet.set <coin-address> <account>\n"
            "Sets the account associated with the given address.");

    CCoinAddr address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(-5, "Invalid coin address");


    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Detect when changing the account of an address that is the 'unused current key' of another account:
    if (pwalletMain->mapAddressBook.count(address.Get()))
    {
        string strOldAccount = pwalletMain->mapAddressBook[address.Get()];
        if (address == GetAccountAddress(GetWallet(iface), strOldAccount))
            GetAccountAddress(GetWallet(iface), strOldAccount, true);
    }

    pwalletMain->SetAddressBookName(address.Get(), strAccount);

    return Value::null;
}

Value rpc_wallet_setkey(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");
  if (fHelp || params.size() != 2) {
    throw runtime_error(
        "wallet.setkey <priv-key> <account>\n"
        "Adds a private key (as returned by wallet.key) to your wallet.");
  }

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CCoinSecret vchSecret;
  string strSecret = params[0].get_str();
  string strLabel = params[1].get_str();

  bool fGood = vchSecret.SetString(strSecret);
  if (!fGood) {
    /* invalid private key 'string' for particular coin interface. */
    throw JSONRPCError(SHERR_ILSEQ, "private-key");
  }

  CKey key;
  bool fCompressed = true;
  CSecret secret = vchSecret.GetSecret(fCompressed); /* set's fCompressed */
  key.SetSecret(secret, fCompressed);
  CKeyID vchAddress = key.GetPubKey().GetID();

  {
    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (pwalletMain->HaveKey(vchAddress)) {
      /* pubkey has already been assigned to an account. */
      throw JSONRPCError(-8, "Private key already exists.");
    }

    if (!pwalletMain->AddKey(key)) {
      /* error adding key to wallet */
      throw JSONRPCError(-4, "Error adding key to wallet."); 
    }

    /* create a link between account and coin address. */ 
    pwalletMain->SetAddressBookName(vchAddress, strLabel);
    pwalletMain->MarkDirty();

    /* rescan entire block-chain for unspent coins */
    pwalletMain->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
    pwalletMain->ReacceptWalletTransactions();
  }

  return Value::null;
}

Value rpc_wallet_setkeyphrase(CIface *iface, const Array& params, bool fStratum)
{

  if (fHelp || params.size() != 2) {
    throw runtime_error(
        "wallet.setkeyphrase \"<phrase>\" <account>\n"
        "Adds a private key to your wallet from a key phrase..");
  }

  CCoinSecret vchSecret;
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  bool ret = DecodeMnemonicSecret(ifaceIndex, params[0].get_str(), vchSecret);
  if (!ret)
    throw JSONRPCError(-5, "Invalid private key");

  string strLabel = params[1].get_str();
  bool fGood = vchSecret.IsValid();
  if (!fGood) throw JSONRPCError(-5,"Invalid private key");

  CKey key;
  bool fCompressed;
  CSecret secret = vchSecret.GetSecret(fCompressed);
  key.SetSecret(secret, fCompressed);
  CKeyID vchAddress = key.GetPubKey().GetID();
  {
    LOCK2(cs_main, wallet->cs_wallet);

    std::map<CTxDestination, std::string>::iterator mi = wallet->mapAddressBook.find(vchAddress);
    if (mi != wallet->mapAddressBook.end()) {
      throw JSONRPCError(SHERR_NOTUNIQ, "Address already exists in wallet.");
    }

    wallet->MarkDirty();
    wallet->SetAddressBookName(vchAddress, strLabel);

    if (!wallet->AddKey(key))
      throw JSONRPCError(-4,"Error adding key to wallet");

    wallet->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
    wallet->ReacceptWalletTransactions();
  }

  return Value::null;
}


Value rpc_wallet_unspent(CIface *iface, const Array& params, bool fStratum)
{

  if (params.size() == 0)
    throw runtime_error("unsupported operation");

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strAccount = params[0].get_str();

  int nMinDepth = 1;
  if (params.size() > 1)
    nMinDepth = params[1].get_int();

  Array results;
  vector<COutput> vecOutputs;
  pwalletMain->AvailableAccountCoins(strAccount, vecOutputs, false);
  BOOST_FOREACH(const COutput& out, vecOutputs)
  {
    if (out.nDepth < nMinDepth)
      continue;

    int64 nValue = out.tx->vout[out.i].nValue;
    const CScript& pk = out.tx->vout[out.i].scriptPubKey;
    Object entry;
    entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
    entry.push_back(Pair("hash", out.tx->GetWitnessHash().GetHex()));
    entry.push_back(Pair("vout", out.i));
    entry.push_back(Pair("script", pk.ToString()));
    entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
    entry.push_back(Pair("amount",ValueFromAmount(nValue)));
    entry.push_back(Pair("confirmations",out.nDepth));
    results.push_back(entry);
  }

  return results;
}

Value rpc_wallet_spent(CIface *iface, const Array& params, bool fStratum)
{
  string strSysAccount("*");

  if (params.size() == 0)
    throw runtime_error("unsupported operation");

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strAccount = params[0].get_str();
  int i;

  Array results;
  for (map<uint256, CWalletTx>::const_iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
  {
    const CWalletTx& pcoin = (*it).second;
    if (strAccount != strSysAccount &&
        pcoin.strFromAccount != strAccount)
      continue;

    bool fIsSpent = false;
    for (i = 0; i < pcoin.vout.size(); i++) {
      if (pcoin.IsSpent(i)) {
        fIsSpent = true;
        break;
      }
    }
    if (fIsSpent) {
      results.push_back(pcoin.GetHash().GetHex());
    }
  }

  return (results);
}

Value rpc_wallet_select(CIface *iface, const Array& params, bool fStratum)
{

  if (params.size() != 2)
    throw runtime_error("unsupported operation");

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strAccount = params[0].get_str();
  int64 nAmount = AmountFromValue(params[1]);

  Array results;
  vector<COutput> vecOutputs;
  pwalletMain->AvailableAccountCoins(strAccount, vecOutputs, false);

  int64 nValueRet;
  set<pair<const CWalletTx*,unsigned int> > setCoins;
  if (!pwalletMain->SelectAccountCoins(strAccount, nAmount, setCoins, nValueRet))
    throw JSONRPCError(-6, "Insufficient funds for account.");

  BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins) {
    const CWalletTx *wtx = pcoin.first; 
    int nOut = pcoin.second;
    int64 nCredit = wtx->vout[nOut].nValue;
    const CScript& pk = wtx->vout[nOut].scriptPubKey;

    Object entry;
    entry.push_back(Pair("txid", wtx->GetHash().GetHex()));
    entry.push_back(Pair("hash", wtx->GetWitnessHash().GetHex()));
    entry.push_back(Pair("vout", nOut));
    entry.push_back(Pair("script", pk.ToString()));
    entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
    entry.push_back(Pair("amount",ValueFromAmount(nCredit)));
    results.push_back(entry);
  }

  return results;
}

Value rpc_wallet_unconfirm(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "wallet.unconfirm\n"
        "Display a list of all unconfirmed transactions.\n");

  Array results;
  {
    LOCK(pwalletMain->cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
      const CWalletTx& pcoin = (*it).second;
      if (!pcoin.IsCoinBase()) continue;
      int depth = pcoin.GetBlocksToMaturity(ifaceIndex);
      if (depth > 0 && pcoin.GetDepthInMainChain(ifaceIndex) >= 2) {
        CTransaction& tx = (CTransaction&)pcoin;
        results.push_back(tx.ToValue(ifaceIndex));
      }
    }
  }

  return results;
} 

Value rpc_wallet_validate(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fStratum)
    throw runtime_error("unsupported operation");

  CWallet *wallet = GetWallet(iface);

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.validate <coin-address>\n"
        "Return information about <coin-address>.");

  CCoinAddr address(params[0].get_str());
  bool isValid = true;//address.IsValid();

  Object ret;
  ret.push_back(Pair("isvalid", isValid));
  if (isValid)
  {
    CTxDestination dest = address.Get();
    string currentAddress = address.ToString();
    ret.push_back(Pair("address", currentAddress));
    bool fMine = IsMine(*wallet, dest);
    ret.push_back(Pair("ismine", fMine));
#if 0
    if (fMine) {
      Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
      ret.insert(ret.end(), detail.begin(), detail.end());
    }
#endif
    if (wallet->mapAddressBook.count(dest))
      ret.push_back(Pair("account", wallet->mapAddressBook[dest]));
  }
  return ret;
}

Value rpc_stratum_info(CIface *iface, const Array& params, bool fStratum)
{
  user_t *user;
  int tot;

  if (fStratum)
    throw runtime_error("unsupported operation");

  tot = 0;
  for (user = client_list; user; user = user->next) {
    if (user->flags & USER_RPC)
      continue;

    tot++;
  }

  Object obj;

  obj.push_back(Pair("users", tot));

  return (obj);
}
Value rpc_stratum_list(CIface *iface, const Array& params, bool fStratum)
{
  user_t *user;
  char tag[256];
  int idx;

  if (fStratum)
    throw runtime_error("unsupported operation");

  Array ret;
  for (user = client_list; user; user = user->next) {
    if (user->flags & USER_RPC)
      continue;

    Object obj;
    string miner_ver_str(user->cli_ver);

    obj.push_back(Pair("label", user->worker));

    obj.push_back(Pair("netid", shkey_print(&user->netid)));

    if (user->work_diff >= 0.0001)
      obj.push_back(Pair("mine-diff", user->work_diff));

    for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
      iface = GetCoinByIndex(idx);
      if (!iface || !iface->enabled) continue;

      if (user->balance[idx] >= 0.00000001) {
        sprintf(tag, "pend-%s", iface->name);
        obj.push_back(Pair(tag, user->balance[idx]));
      }
    }

    if (user->block_tot >= 0.0001)
      obj.push_back(Pair("shares", user->block_tot));

    if (user->flags & USER_SYNC) {
      if (user->sync_flags & SYNC_RESP_ALL) {
        obj.push_back(Pair("sync-state", "wait"));
      } else {
        obj.push_back(Pair("sync-state", "idle"));
      }
    }

    obj.push_back(Pair("type", get_user_flag_label(user->flags)));

    if (miner_ver_str != "")
      obj.push_back(Pair("version", miner_ver_str));

    ret.push_back(obj);
  }

  return (ret);
}
Value rpc_stratum_keyadd(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  return (Value::null);
}
Value rpc_stratum_keyremove(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  return (Value::null);
}


static string json_stratum_key_str;
Value rpc_stratum_key(CIface *iface, const Array& params, bool fStratum)
{
  shpeer_t *peer;
  char host[256];
  const char *text;
  shkey_t *key;

  key = get_rpc_dat_password(NULL);
  if (!key)
    return (Value::null);

  json_stratum_key_str = string(shkey_print(key));
  return (json_stratum_key_str);
}

Value rpc_wallet_addrlist(CIface *iface, const Array& params, bool fStratum)
{

  if (fHelp || params.size() != 1)
    throw runtime_error("wallet.addrlist <account>\nReturns the list of coin addresses for the given account.");

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strAccount = AccountFromValue(params[0]);
  if (!IsAccountValid(iface, strAccount))
    throw JSONRPCError(SHERR_NOENT, "Invalid account name specified.");

  // Find all addresses that have the given account
  Array ret;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
    const string& strName = item.second;
    if (strName == strAccount)
      ret.push_back(address.ToString());
  }

  return ret;
}

Value rpc_wallet_listbyaddr(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (fHelp || params.size() > 2)
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

Value rpc_block_purge(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  uint256 hash;
  int err;

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "block.purge <index>\n"
        "Truncate the block-chain to height <index>.\n");

  int nHeight = params[0].get_int();
  if (nHeight < 0 || nHeight > GetBestHeight(iface))
    throw runtime_error("Block number out of range.");

  CBlock *block = GetBlockByHeight(iface, nHeight);
  if (!block)
    throw runtime_error("Block not found in block-chain.");

  hash = block->GetHash();
  block->Truncate();
  delete block;

  return (hash.GetHex());
}

Value rpc_block_listsince(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  CWallet *pwalletMain = GetWallet(iface);
  CBlockIndex *pindexBest = GetBestBlockIndex(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp)
    throw runtime_error(
        "block.listsince [blockhash] [target-confirmations]\n"
        "Get all transactions in blocks since block [blockhash], or all transactions if omitted");

  CBlockIndex *pindex = NULL;
  int target_confirms = 1;

  if (params.size() > 0)
  {
    uint256 blockId = 0;

    blockId.SetHex(params[0].get_str());
    pindex = CBlockLocator(ifaceIndex, blockId).GetBlockIndex();
  }

  if (params.size() > 1)
  {
    target_confirms = params[1].get_int();

    if (target_confirms < 1)
      throw JSONRPCError(-8, "Invalid parameter");
  }

  int depth = pindex ? (1 + GetBestHeight(iface) - pindex->nHeight) : -1;

  Array transactions;

  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
  {
    CWalletTx tx = (*it).second;

    if (depth == -1 || tx.GetDepthInMainChain(ifaceIndex) < depth)
      ListTransactions(ifaceIndex, tx, "*", 0, true, transactions);
  }

  uint256 lastblock;

  if (target_confirms == 1)
  {
    //lastblock = hashBestChain;
    lastblock = GetBestBlockChain(iface);
  }
  else
  {
    int target_height = pindexBest->nHeight + 1 - target_confirms;

    CBlockIndex *block;
    for (block = pindexBest;
        block && block->nHeight > target_height;
        block = block->pprev)  { }

    lastblock = block ? block->GetBlockHash() : 0;
  }

  Object ret;
  ret.push_back(Pair("transactions", transactions));
  ret.push_back(Pair("lastblock", lastblock.GetHex()));

  return ret;
}

Value rpc_wallet_listbyaccount(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (fHelp || params.size() > 2)
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

Value rpc_wallet_move(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  CWallet *pwalletMain = GetWallet(iface);

  if (fHelp || params.size() < 3 || params.size() > 5)
    throw runtime_error(
        "wallet.move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
        "Move from one account in your wallet to another.");

  string strFrom = AccountFromValue(params[0]);
  string strTo = AccountFromValue(params[1]);
  int64 nAmount = AmountFromValue(params[2]);
  if (params.size() > 3)
    // unused parameter, used to be nMinDepth, keep type-checking it though
    (void)params[3].get_int();
  string strComment;
  if (params.size() > 4)
    strComment = params[4].get_str();

  CWalletDB walletdb(pwalletMain->strWalletFile);
  if (!walletdb.TxnBegin())
    throw JSONRPCError(-20, "database error");

  int64 nNow = GetAdjustedTime();

  // Debit
  CAccountingEntry debit;
  debit.strAccount = strFrom;
  debit.nCreditDebit = -nAmount;
  debit.nTime = nNow;
  debit.strOtherAccount = strTo;
  debit.strComment = strComment;
  walletdb.WriteAccountingEntry(debit);

  // Credit
  CAccountingEntry credit;
  credit.strAccount = strTo;
  credit.nCreditDebit = nAmount;
  credit.nTime = nNow;
  credit.strOtherAccount = strFrom;
  credit.strComment = strComment;
  walletdb.WriteAccountingEntry(credit);

  if (!walletdb.TxnCommit())
    throw JSONRPCError(-20, "database error");

  return true;
}

Value rpc_wallet_multisend(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() < 2 || params.size() > 4)
    throw runtime_error(
        "wallet.multisend <fromaccount> {address:amount,...} [minconf=1] [comment]\n"
        "amounts are double-precision floating point numbers"
        + HelpRequiringPassphrase());

  string strAccount = AccountFromValue(params[0]);
  Object sendTo = params[1].get_obj();
  int nMinDepth = 1;
  if (params.size() > 2)
    nMinDepth = params[2].get_int();

  CWalletTx wtx;
  wtx.strFromAccount = strAccount;
  if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
    wtx.mapValue["comment"] = params[3].get_str();

  set<CCoinAddr> setAddress;
  vector<pair<CScript, int64> > vecSend;

  int64 totalAmount = 0;
  BOOST_FOREACH(const Pair& s, sendTo)
  {
    CCoinAddr address(s.name_);
    if (!address.IsValid())
      throw JSONRPCError(-5, string("Invalid coin address:")+s.name_);

    if (setAddress.count(address))
      throw JSONRPCError(-8, string("Invalid parameter, duplicated address: ")+s.name_);
    setAddress.insert(address);

    CScript scriptPubKey;
    scriptPubKey.SetDestination(address.Get());
    int64 nAmount = AmountFromValue(s.value_);
    totalAmount += nAmount;

    vecSend.push_back(make_pair(scriptPubKey, nAmount));
  }

  EnsureWalletIsUnlocked();

  // Check funds
  int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
  if (totalAmount > nBalance)
    throw JSONRPCError(-6, "Account has insufficient funds");

  // Send
  CReserveKey keyChange(pwalletMain);
  int64 nFeeRequired = 0;
  bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired);
  if (!fCreated)
  {
    if (totalAmount + nFeeRequired > pwalletMain->GetBalance())
      throw JSONRPCError(-6, "Insufficient funds");
    throw JSONRPCError(-4, "Transaction creation failed");
  }
  if (!pwalletMain->CommitTransaction(wtx))
    throw JSONRPCError(-4, "Transaction commit failed");

  return wtx.GetHash().GetHex();
}

/** create a new coin address for the account specified. */
Value rpc_wallet_new(CIface *iface, const Array& params, bool fStratum)
{

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  Value ret;
  string strAccount = params[0].get_str();
  ret = GetAccountAddress(GetWallet(iface), strAccount, true).ToString();

  return ret;
}

Value rpc_wallet_derive(CIface *iface, const Array& params, bool fStratum)
{

  if (params.size() != 2)
    throw runtime_error("invalid parameters");

  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
  string strAccount = params[0].get_str();
  string strSeed = params[1].get_str();

  CCoinAddr raddr = GetAccountAddress(GetWallet(iface), strAccount, false);
  if (!raddr.IsValid())
    throw JSONRPCError(-5, "Unknown account name.");

  CCoinAddr addr(ifaceIndex);
  if (!wallet->GetMergedAddress(strAccount, strSeed.c_str(), addr))
    throw JSONRPCError(-5, "Error obtaining merged coin address.");


  Object ret;
  ret.push_back(Pair("seed", strSeed));
  ret.push_back(Pair("origin", raddr.ToString()));
  ret.push_back(Pair("addr", addr.ToString()));

  return (ret);
}

Value rpc_peer_add(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "peer.add <host>[:<port>]\n"
        "Submit a new peer connection for the coin server.\n");

  string strHost;
  CService vserv;
  char buf[256];
  char *ptr;
  int port;

  strHost = params[0].get_str();

  port = 0;
  memset(buf, 0, sizeof(buf));
  strncpy(buf, strHost.c_str(), sizeof(buf)-1);
  ptr = strchr(buf, ':');
  if (!ptr)
    ptr = strchr(buf, ' '); /* ipv6 */
  if (ptr) {
    port = atoi(ptr+1);
    *ptr = '\000';
  }
  if (port == 0)
    port = iface->port;

  if (Lookup(strHost.c_str(), vserv, port, false)) {
    shpeer_t *peer;
    char buf2[1024];
    char buf[1024];

    sprintf(buf, "%s %d", strHost.c_str(), port);
    peer = shpeer_init(iface->name, buf);
    create_uevent_connect_peer(GetCoinIndex(iface), peer); /* keep alloc'd */

    sprintf(buf2, "addpeer: initiating peer connection to '%s'.\n",
        shpeer_print(peer));
    unet_log(GetCoinIndex(iface), buf2);
  }

  return "initiated new peer connection.";
}

static void CopyNodeStats(CIface *iface, std::vector<CNodeStats>& vstats)
{
  NodeList &vNodes = GetNodeList(iface);

  vstats.clear();

  LOCK(cs_vNodes);
  vstats.reserve(vNodes.size());
  BOOST_FOREACH(CNode* pnode, vNodes) {
    CNodeStats stats;
    pnode->copyStats(stats);
    vstats.push_back(stats);
  }
}

Value rpc_peer_export(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "peer.export <path>\n"
        "Export entire database of network peers in JSON format.");

  std::string strPath = params[0].get_str();

  {
    FILE *fl;
//    shpeer_t *serv_peer;
    shjson_t *json;
    shdb_t *db;
    char *text;

//    serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

    db = shnet_track_open(iface->name);
    if (!db) 
      throw JSONRPCError(-5, "Error opening peer track database.");
    json = shdb_json_write(db, SHPREF_TRACK, 0, 0);
    text = shjson_print(json);
    shjson_free(&json);
    shnet_track_close(db);

    fl = fopen(strPath.c_str(), "wb");
    if (fl) {
      if (text)
        fwrite(text, sizeof(char), strlen(text), fl);
      fclose(fl);
    }
    free(text);

//    shpeer_free(&serv_peer);
  }


  Object result;
  result.push_back(Pair("mode", "peer.export"));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "finished"));

  return (result);
}

Value rpc_peer_remove(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface);
  shpeer_t *peer;
  char host[MAXHOSTNAMELEN+1];
  char *ptr;
  int err;
  int sk;

  if (fStratum)
    throw runtime_error("unsupported exception");

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  unet_bind_t *bind = unet_bind_table(ifaceIndex);
  if (!bind || !bind->peer_db)
    throw JSONRPCError(-5, "peer not found");

  memset(host, 0, sizeof(host));
  strncpy(host, params[0].get_str().c_str(), sizeof(host)-1);

  ptr = strchr(host, ':');
  if (ptr)
    *ptr = ' ';

  peer = shpeer_init(iface->name, host);
  err = shnet_track_remove(bind->peer_db, peer);
  if (err) {
    shpeer_free(&peer);
    throw JSONRPCError(-5, "peer not found");
  } 

  sk = unet_peer_find(ifaceIndex, shpeer_addr(peer)); 
  shpeer_free(&peer);
  if (sk) {
    unet_shutdown(sk); 
  }

  return (Value::null);
}

Value rpc_peer_import(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  int ifaceIndex = GetCoinIndex(iface);
  FILE *fl;
  struct stat st;
  shpeer_t *peer;
  shjson_t *json;
  shjson_t *node;
  shdb_t *db;
  char hostname[PATH_MAX+1];
  char *text;

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "peer.import <path>\n"
        "Export entire database of network peers in JSON format.");

  std::string strPath = params[0].get_str();

  {
    fl = fopen(strPath.c_str(), "rb");
    if (!fl)
      throw runtime_error("error opening file.");

    memset(&st, 0, sizeof(st));
    fstat(fileno(fl), &st);
    if (st.st_size == 0)
      throw runtime_error("file is not in JSON format.");

    text = (char *)calloc(st.st_size + 1, sizeof(char));
    if (!text)
      throw runtime_error("not enough memory to allocate file.");

    fread(text, sizeof(char), st.st_size, fl);
    fclose(fl);
    
//    serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

    json = shjson_init(text);
    free(text);
    if (!json) {
      throw runtime_error("file is not is JSON format.");
    }

    if (json->child) {
      unet_bind_t *bind = unet_bind_table(ifaceIndex);
      if (bind && bind->peer_db) {
        for (node = json->child; node; node = node->next) {
          char *host = shjson_astr(node, "host", "");
          char *label = shjson_astr(node, "label", "");
          if (!*host || !*label) continue;

          peer = shpeer_init(label, host);
          shnet_track_add(bind->peer_db, peer);
          shpeer_free(&peer);
        }
      }
    }

    shjson_free(&json);
  }


  Object result;
  result.push_back(Pair("mode", "peer-import"));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "finished"));

  return (result);
}


Value rpc_peer_list(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "peer.list\n"
        "Statistical and runtime information on network peers.");

  vector<CNodeStats> vstats;
  CopyNodeStats(iface, vstats);

  Array ret;

  BOOST_FOREACH(const CNodeStats& stats, vstats) {
    Object obj;

    obj.push_back(Pair("addr", stats.addrName));
    obj.push_back(Pair("services", strprintf("%08" PRI64x, stats.nServices)));
    obj.push_back(Pair("lastsend", (boost::int64_t)stats.nLastSend));
    obj.push_back(Pair("lastrecv", (boost::int64_t)stats.nLastRecv));
    obj.push_back(Pair("conntime", (boost::int64_t)stats.nTimeConnected));
    obj.push_back(Pair("version", stats.nVersion));
    obj.push_back(Pair("subver", stats.strSubVer));
    obj.push_back(Pair("inbound", stats.fInbound));
    obj.push_back(Pair("releasetime", (boost::int64_t)stats.nReleaseTime));
    obj.push_back(Pair("startingheight", stats.nStartingHeight));
    obj.push_back(Pair("banscore", stats.nMisbehavior));

    ret.push_back(obj);
  }

  return ret;
}

Value rpc_peer_importdat(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "peer.importdat <path>\n"
        "Import a legacy 'peers.dat' datafile.");

  std::string strPath = params[0].get_str();

  int ifaceIndex = GetCoinIndex(iface);
  char addr_str[256];
  shpeer_t *peer;
  shpeer_t *serv_peer;

  if (!iface)
    throw runtime_error("peer db not available.");

//  serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

  CAddrMan addrman;
  {
    long nStart = GetTimeMillis();
    {
      CAddrDB adb(strPath.c_str());
      if (!adb.Read(addrman))
        throw runtime_error("specified path is not a peers.dat database.");
    }
    Debug("Exported %d addresses from peers.dat  %dms\n",
        (int)addrman.size(), (int)(GetTimeMillis() - nStart));
  }

  vector<CAddress> vAddr = addrman.GetAddr();

  unet_bind_t *bind = unet_bind_table(ifaceIndex);
  if (bind && bind->peer_db) {
    BOOST_FOREACH(const CAddress &addr, vAddr) {
      sprintf(addr_str, "%s %d", addr.ToStringIP().c_str(), addr.GetPort());
      peer = shpeer_init(iface->name, addr_str);
      shnet_track_add(bind->peer_db, peer);
      shpeer_free(&peer);
    }
  }


  Object result;
  result.push_back(Pair("mode", "peer.importdat"));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "success"));

  return (result);
}











Value settxfee(const Array& params, bool fStratum)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    // Amount
    int64 nAmount = 0;
    if (params[0].get_real() != 0.0)
        nAmount = AmountFromValue(params[0]);        // rejects 0.0 amounts

    nTransactionFee = nAmount;
    return true;
}




void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Array& ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        Object entry;
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", (boost::int64_t)acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}


Value rpc_tx_decode(CIface *iface, const Array& params, bool fStratum)
{

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "tx.decode <hex string>\n"
        "Return a JSON object representing the serialized, hex-encoded transaction.");

  int ifaceIndex = GetCoinIndex(iface);
  RPCTypeCheck(params, list_of(str_type));
  vector<unsigned char> txData(ParseHex(params[0].get_str()));
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION(iface));
  CTransaction tx;
  try {
    ssData >> tx;
  }
  catch (std::exception &e) {
    throw JSONRPCError(-22, "TX decode failed");
  }

  return (tx.ToValue(ifaceIndex));
}

Value rpc_tx_list(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 3)
    throw runtime_error(
        "tx.list [account] [count=10] [from=0]\n"
        "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");

  string strAccount = "*";
  if (params.size() > 0)
    strAccount = params[0].get_str();
  int nCount = 10;
  if (params.size() > 1)
    nCount = params[1].get_int();
  int nFrom = 0;
  if (params.size() > 2)
    nFrom = params[2].get_int();

  if (nCount < 0)
    throw JSONRPCError(-8, "Negative count");
  if (nFrom < 0)
    throw JSONRPCError(-8, "Negative from");

  Array ret;
  CWalletDB walletdb(pwalletMain->strWalletFile);

  // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
  typedef pair<CWalletTx*, CAccountingEntry*> TxPair;
  typedef multimap<int64, TxPair > TxItems;
  TxItems txByTime;

  // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
  // would make this much faster for applications that do this a lot.
  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
  {
    CWalletTx* wtx = &((*it).second);
    txByTime.insert(make_pair(wtx->GetTxTime(), TxPair(wtx, (CAccountingEntry*)0)));
  }
  list<CAccountingEntry> acentries;
  walletdb.ListAccountCreditDebit(strAccount, acentries);
  BOOST_FOREACH(CAccountingEntry& entry, acentries)
  {
    txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
  }

  // iterate backwards until we have nCount items to return:
  for (TxItems::reverse_iterator it = txByTime.rbegin(); it != txByTime.rend(); ++it)
  {
    CWalletTx *const pwtx = (*it).second.first;
    if (pwtx != 0)
      ListTransactions(ifaceIndex, *pwtx, strAccount, 0, true, ret);
    CAccountingEntry *const pacentry = (*it).second.second;
    if (pacentry != 0)
      AcentryToJSON(*pacentry, strAccount, ret);

    if ((int)ret.size() >= (nCount+nFrom)) break;
  }
  // ret is newest to oldest

  if (nFrom > (int)ret.size())
    nFrom = ret.size();
  if ((nFrom + nCount) > (int)ret.size())
    nCount = ret.size() - nFrom;
  Array::iterator first = ret.begin();
  std::advance(first, nFrom);
  Array::iterator last = ret.begin();
  std::advance(last, nFrom+nCount);

  if (last != ret.end()) ret.erase(last, ret.end());
  if (first != ret.begin()) ret.erase(ret.begin(), first);

  std::reverse(ret.begin(), ret.end()); // Return oldest to newest

  return ret;
}

Value rpc_tx_pool(CIface *iface, const Array& params, bool fStratum)
{

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "tx.pool\n"
        "Returns all transaction awaiting confirmation.");

  CTxMemPool *pool = GetTxMemPool(iface);

  Array a;
  if (pool) {
    vector<CTransaction> mapTx = pool->GetActiveTx();
    BOOST_FOREACH(CTransaction& tx, mapTx) {
      a.push_back(tx.ToValue(GetCoinIndex(iface)));
    }
  }

  return a;
}

Value rpc_tx_prune(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (params.size() != 0)
    throw runtime_error("invalid parameters");

  CTxMemPool *pool = GetTxMemPool(iface);
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  Array a;
  vector<CTransaction> v;
  if (iface && iface->enabled && pool && wallet) {
    vector<CTransaction> mapTx = pool->GetActiveTx();
    BOOST_FOREACH(CTransaction& tx, mapTx) {
      const uint256& tx_hash = tx.GetHash();

      bool fValid = true;

      if (!tx.CheckTransaction(ifaceIndex)) {
        fValid = false;
        Debug("rpc_tx_prune: transaction '%s' is invalid.", tx_hash.GetHex().c_str());
      } else {
        BOOST_FOREACH(const CTxIn& in, tx.vin) {
          if (pool->exists(in.prevout.hash))
            continue; /* dependant on another tx in pool */

          CTransaction prevtx;
          const uint256& prevhash = in.prevout.hash;

          if (!GetTransaction(iface, prevhash, prevtx, NULL)) {
            /* the input tx is unknown. */
            Debug("rpc_tx_prune: previous transaction '%s' is invalid.", prevhash.GetHex().c_str());
            fValid = false;
            continue;
          }

          const CTxOut& out = prevtx.vout[in.prevout.n];
          if (!wallet->IsMine(out)) {
            Debug("rpc_tx_prune: previous transaction \"%s\" output (#%d) is foreign.", (int)in.prevout.n, prevhash.GetHex().c_str());
            /* we are attempting to spend someone else's input */
            fValid = false;
            continue;
          }

/* DEBUG: TODO: load wallet tx from db */
#if 0
          CWalletTx wtx(wallet, prevtx);
          if (wtx.IsSpent(in.prevout.n)) {
            Debug("rpc_tx_prune: previous transaction \"%s\" output (#%d) is already spent.", prevhash.GetHex().c_str(), (int)in.prevout.n);
            /* we are attempting to double-spend */
            fValid = false;
            continue;
          }
#endif

        }
      }
      if (fValid)
        continue; /* a-ok boss */

      v.push_back(tx);
      a.push_back(tx_hash.GetHex());
    }

    /* erase invalid entries from pool */
    BOOST_FOREACH(CTransaction& tx, v) {
      wallet->UnacceptWalletTransaction(tx);
    }
  }

  return a;
}

Value rpc_tx_purge(CIface *iface, const Array& params, bool fStratum)
{

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "tx.purge\n"
        "Reverts all transaction awaiting confirmation.");

  CTxMemPool *pool = GetTxMemPool(iface);
  CWallet *wallet = GetWallet(iface);

  Array a;
  vector<CTransaction> v;
  if (iface->enabled && pool && wallet) {
    vector<CTransaction> mapTx = pool->GetActiveTx();
    BOOST_FOREACH(CTransaction& tx, mapTx) {
      const uint256& hash = tx.GetHash();

      v.push_back(tx);
      a.push_back(hash.GetHex());
    }
    BOOST_FOREACH(const CTransaction& tx, v) {
      wallet->UnacceptWalletTransaction(tx);
    }

//    pool->mapTx.clear();
  }

  return a;
}


Value rpc_addmultisigaddress(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        string msg = "addmultisigaddress <nrequired> <'[\"key\",\"key\"]'> [account]\n"
            "Add a nrequired-to-sign multisignature address to the wallet\"\n"
            "each key is a coin address or hex-encoded public key\n"
            "If [account] is specified, assign address to [account].";
        throw runtime_error(msg);
    }

    int nRequired = params[0].get_int();
    const Array& keys = params[1].get_array();
    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %d keys, but need at least %d to redeem)", keys.size(), nRequired));
    std::vector<CKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();

        // Case 1: coin address and we have full public key:
        CCoinAddr address(ks);
        if (address.IsValid())
        {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw runtime_error(
                    strprintf("%s does not refer to a key",ks.c_str()));
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(keyID, vchPubKey))
                throw runtime_error(
                    strprintf("no full public key for address %s",ks.c_str()));
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
                throw runtime_error(" Invalid public key: "+ks);
        }

        // Case 2: hex public key
        else if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
                throw runtime_error(" Invalid public key: "+ks);
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner;
    inner.SetMultisig(nRequired, pubkeys);
    CScriptID innerID = inner.GetID();
    pwalletMain->AddCScript(inner);

    pwalletMain->SetAddressBookName(innerID, strAccount);
    return CCoinAddr(innerID).ToString();
}

Value rpc_tx_get(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);
  CWallet *pwalletMain = GetWallet(iface);

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "tx.get <txid>\n"
        "Get detailed information about a block transaction."
        );

  uint256 hash;
  hash.SetHex(params[0].get_str());


  CTransaction tx;
  uint256 hashBlock;

  if (!tx.ReadTx(ifaceIndex, hash, &hashBlock))
    throw JSONRPCError(-5, "Invalid transaction id");

  Object entry = tx.ToValue(ifaceIndex);

  if (hashBlock != 0)
  {
    entry.push_back(Pair("blockhash", hashBlock.GetHex()));
    map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hashBlock);
    if (mi != blockIndex->end() && (*mi).second)
    {
      CBlockIndex* pindex = (*mi).second;
      if (pindex->IsInMainChain(ifaceIndex))
      {
        entry.push_back(Pair("confirmations", (int)(1 + GetBestHeight(iface) - pindex->nHeight)));
        entry.push_back(Pair("time", (boost::int64_t)pindex->nTime));
      }
      else
        entry.push_back(Pair("confirmations", 0));
    }
  }

  return entry;
}

Value rpc_wallet_tx(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.tx <txid>\n"
        "Get detailed information about in-wallet transaction <txid>");

  uint256 hash;
  hash.SetHex(params[0].get_str());

  Object entry;

  if (pwalletMain->mapWallet.count(hash))
    throw JSONRPCError(-5, "Invalid transaction id");

  const CWalletTx& wtx = pwalletMain->mapWallet[hash];

  int64 nCredit = wtx.GetCredit();
  int64 nDebit = wtx.GetDebit();
  int64 nNet = nCredit - nDebit;
  int64 nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);

  entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
  if (wtx.IsFromMe())
    entry.push_back(Pair("fee", ValueFromAmount(nFee)));

  WalletTxToJSON(ifaceIndex, wtx, entry);

  Array details;
  ListTransactions(ifaceIndex, wtx, "*", 0, true, details);
  entry.push_back(Pair("details", details));

  return entry;
}

Value rpc_wallet_keyphrase(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (params.size() != 1)
    throw runtime_error("wallet.keyphrase");

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strAddress = params[0].get_str();
  CCoinAddr address(ifaceIndex);
  if (!address.SetString(strAddress))
    throw JSONRPCError(-5, "Invalid address");
  CKeyID keyID;
  if (!address.GetKeyID(keyID))
    throw JSONRPCError(-3, "Address does not refer to a key");
  CSecret vchSecret;
  bool fCompressed;
  if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
    throw JSONRPCError(-4,"Private key for address " + strAddress + " is not known");

  CCoinSecret secret(ifaceIndex, vchSecret, fCompressed);
  string phrase = EncodeMnemonicSecret(secret);

  return (phrase);
}


Value rpc_block_verify(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *wallet = GetWallet(iface);
  int nBestHeight;
  int nDepth;

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (fHelp || params.size() >= 2)
    throw runtime_error(
        "block.verify <block depth>\n"
        "Verify a set of blocks from the end of the block-chain. (default: 1024).\n");

  nBestHeight = (int)GetBestHeight(iface);

  nDepth = 1024;
  if (params.size() > 0)
    nDepth = MAX(1, params[0].get_int());

#if 0
  return (core_block_verify(iface, nDepth));
#endif
  int nHeight = MAX(1, nBestHeight - nDepth);
  ResetServiceValidateEvent(wallet);
  InitServiceValidateEvent(wallet, nHeight);

  Object obj;
  obj.push_back(Pair("height", nHeight));
  return (obj);
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
const RPCOp WALLET_RESCAN = {
  &rpc_wallet_rescan, 0, {},
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

  RegisterRPCOp(ifaceIndex, "sys.url", SYS_URL);
  
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

  RegisterRPCOp(ifaceIndex, "wallet.info", WALLET_INFO);
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

  RegisterRPCOp(ifaceIndex, "wallet.rescan", WALLET_RESCAN);

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


#if 0
json_spirit::Value rpc_execute(CIface *iface, const std::string &strMethod, json_spirit::Array &params)
{
  RPCOp *op;
  int i;

  if (!iface || !iface->enabled)
    throw JSONRPCError(-32601, "Coin service not accessible.");

  int ifaceIndex = GetCoinIndex(iface);
  op = GetRPCOp(ifaceIndex, strMethod);
  if (!op)
    op = GetRPCAlias(ifaceIndex, strMethod);
  if (!op)
    throw JSONRPCError(-32601, "Method not found");

  if (!GetWallet(iface))
    throw JSONRPCError(-32601, "Wallet not accessible.");

  int max_arg = GetRPCMaxArgs(op);
  if (params.size() < op->min_arg ||
      params.size() > max_arg)
    return (rpc_command_help(iface, strMethod)); 


  /* decapsulate complex parameters */
  for (i = 0; i < max_arg; i++) {
    if (i >= params.size())
      break;

    RPCConvertParam(iface, op, i, params);
#if 0
    string str = params[i].get_str();
    switch (op->arg[i]) {
      case RPC_INT:
        RPCConvertTo<int>(str, params[i]);
        break;
      case RPC_INT64:
        RPCConvertTo<boost::int64_t>(str, params[i]);
        break;
      case RPC_DOUBLE:
        RPCConvertTo<double>(str, params[i]);
        break;
      case RPC_BOOL:
        RPCConvertTo<bool>(str, params[i]);
        break;
      case RPC_ARRAY:
        RPCConvertTo<Array>(str, params[i]);
        break;
      case RPC_OBJECT:
        RPCConvertTo<Object>(str, params[i]);
        break;
    }
#endif
  }

  try
  {
    // Execute
    Value result;
    {
      result = op->actor(iface, params, false);
    }
    return result;
  }
  catch (std::exception& e)
  {
    throw JSONRPCError(-1, e.what());
  }
}
#endif

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
      string help_str = rpc_command_help(iface, strMethod);
      shbuf_catstr(buff, (char *)help_str.c_str());
      return (0);
    }
  }

  int max_arg = GetRPCMaxArgs(op);
  if (ar_len < op->min_arg ||
      ar_len > max_arg) {
    string help_str = rpc_command_help(iface, strMethod);
    shbuf_catstr(buff, (char *)help_str.c_str());
    return (0);
  }

  try
  {
    for (i = 0; i < ar_len; i++) {
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
  }
  
  return (SHERR_INVAL);
}



