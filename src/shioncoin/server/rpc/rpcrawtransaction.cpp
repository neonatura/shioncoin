
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
#include "main.h"
#include <boost/assign/list_of.hpp>
#include "base58.h"
#include "db.h"
#include "net.h"
#include "wallet.h"
#include "txmempool.h"

using namespace std;
using namespace boost;
using namespace boost::assign;

static bool fHelp = false;

// These are all in bitcoinrpc.cpp:
extern Object JSONRPCError(int code, const string& message);
extern int64 AmountFromValue(const Value& value);
extern Value ValueFromAmount(int64 amount);
extern std::string HelpRequiringPassphrase();
extern void EnsureWalletIsUnlocked();

void ScriptPubKeyToJSON(int ifaceIndex, const CScript& scriptPubKey, Object& out)
{
  txnouttype type;
  vector<CTxDestination> addresses;
  int nRequired;

//  out.push_back(Pair("script", scriptPubKey.ToString()));
  //    out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

  if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired))
  {
    out.push_back(Pair("type", GetTxnOutputType(TX_NONSTANDARD)));
    return;
  }

  out.push_back(Pair("reqSigs", nRequired));
  out.push_back(Pair("type", GetTxnOutputType(type)));

  Array a;
  BOOST_FOREACH(const CTxDestination& addr, addresses)
    a.push_back(CCoinAddr(ifaceIndex, addr).ToString());
  out.push_back(Pair("addresses", a));
}

#if 0
void TxToJSON(CIface *iface, const CTransaction& tx, const uint256 hashBlock, Object& entry)
{
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);

  entry.push_back(Pair("txid", tx.GetHash().GetHex()));
  entry.push_back(Pair("version", tx.isFlag(CTransaction::TX_VERSION) ? 1 : 0));
  entry.push_back(Pair("flag", tx.nFlag));
  entry.push_back(Pair("locktime", (boost::int64_t)tx.nLockTime));
  Array vin;
  BOOST_FOREACH(const CTxIn& txin, tx.vin)
  {
    Object in;
    if (tx.IsCoinBase())
      in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    else
    {
      in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
      in.push_back(Pair("vout", (boost::int64_t)txin.prevout.n));
      Object o;
      o.push_back(Pair("asm", txin.scriptSig.ToString()));
      o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
      in.push_back(Pair("scriptSig", o));
    }
    in.push_back(Pair("sequence", (boost::int64_t)txin.nSequence));
    vin.push_back(in);
  }
  entry.push_back(Pair("vin", vin));
  Array vout;
  for (unsigned int i = 0; i < tx.vout.size(); i++)
  {
    const CTxOut& txout = tx.vout[i];
    Object out;
    out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
    out.push_back(Pair("n", (boost::int64_t)i));
    Object o;
    ScriptPubKeyToJSON(txout.scriptPubKey, o);
    out.push_back(Pair("scriptPubKey", o));
    vout.push_back(out);
  }
  entry.push_back(Pair("vout", vout));

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
}
#endif

Value rpc_getrawtransaction(CIface *iface, const Array& params, bool fStratum)
{
  if (fHelp || params.size() < 1 || params.size() > 2)
    throw runtime_error(
        "tx.getraw <txid> [verbose=0]\n"
        "If verbose=0, returns a string that is\n"
        "serialized, hex-encoded data for <txid>.\n"
        "If verbose is non-zero, returns an Object\n"
        "with information about <txid>.");

  uint256 hash;
  hash.SetHex(params[0].get_str());

  bool fVerbose = false;
  if (params.size() > 1)
    fVerbose = (params[1].get_int() != 0);

  int ifaceIndex = GetCoinIndex(iface);
  CTransaction tx;
  uint256 hashBlock;
  if (!GetTransaction(iface, hash, tx, &hashBlock))
    throw JSONRPCError(-5, "No information available about transaction");

  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface));
  ssTx << tx;
  string strHex = HexStr(ssTx.begin(), ssTx.end());

  if (!fVerbose)
    return strHex;

  Object result = tx.ToValue(ifaceIndex);
  result.push_back(Pair("hex", strHex));
//  TxToJSON(iface, tx, hashBlock, result);
  return result;
}

Value rpc_sendrawtransaction(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface);
	bool fHighFee;

	if (fStratum)
		throw runtime_error("unsupported operation");

  if (fHelp || params.size() < 1 || params.size() > 2)
    throw runtime_error(
        "tx.sendraw <hex string> [highfee]\n"
        "Submits raw transaction (serialized, hex-encoded) to local node and network.");

	/* TODO: not implemented. */
	fHighFee = false;
	if (params.size() > 1 && 
			params[1].get_bool() == true)
		fHighFee = true;

  // parse hex string from parameter
  vector<unsigned char> txData(ParseHex(params[0].get_str()));
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION(iface));
  CTransaction tx;

  // deserialize binary data stream
  try {
    ssData >> tx;
  }
  catch (std::exception &e) {
    throw JSONRPCError(ERR_ILSEQ, "TX decode failed");
  }
  uint256 hashTx = tx.GetHash();

  // See if the transaction is already in a block
  // or in the memory pool:
  CTransaction existingTx;
  uint256 hashBlock = 0;
  if (GetTransaction(iface, hashTx, existingTx, &hashBlock))
  {
    if (hashBlock != 0)
      throw JSONRPCError(-5, string("transaction already in block ")+hashBlock.GetHex());
    // Not in block, but already in the memory pool; will drop
    // through to re-relay it.
  } else {
		/* add to local memory pool */
		CTxMemPool *pool = GetTxMemPool(iface);
		if (pool) {
			if (!pool->AddTx(tx))
				throw JSONRPCError(ERR_INVAL, "TX rejected");
		}
  }
	RelayTransaction(ifaceIndex, tx, hashTx);

  return hashTx.GetHex();
}


