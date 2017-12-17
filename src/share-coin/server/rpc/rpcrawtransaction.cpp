
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
#include "main.h"
#include <boost/assign/list_of.hpp>
#include "base58.h"
#include "db.h"
#include "init.h"
#include "net.h"
#include "wallet.h"
#include "usde/usde_netmsg.h"

using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace json_spirit;

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

#if 0
Value listunspent(const Array& params, bool fStratum)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listunspent [minconf=1] [maxconf=999999]\n"
            "Returns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Results are an array of Objects, each of which has:\n"
            "{txid, vout, scriptPubKey, amount, confirmations}");

    RPCTypeCheck(params, list_of(int_type)(int_type));

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    int nMaxDepth = 999999;
    if (params.size() > 1)
        nMaxDepth = params[1].get_int();

    Array results;
    vector<COutput> vecOutputs;
    pwalletMain->AvailableCoins(vecOutputs, false);
    BOOST_FOREACH(const COutput& out, vecOutputs)
    {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        int64 nValue = out.tx->vout[out.i].nValue;
        const CScript& pk = out.tx->vout[out.i].scriptPubKey;
        Object entry;
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
        entry.push_back(Pair("amount",ValueFromAmount(nValue)));
        entry.push_back(Pair("confirmations",out.nDepth));
        results.push_back(entry);
    }

    return results;
}
#endif

#if 0
Value createrawtransaction(const Array& params, bool fStratum)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "createrawtransaction [{\"txid\":txid,\"vout\":n},...] {address:amount,...}\n"
            "Create a transaction spending given inputs\n"
            "(array of objects containing transaction id and output number),\n"
            "sending to given address(es).\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not stored in the wallet or transmitted to the network.");

    RPCTypeCheck(params, list_of(array_type)(obj_type));

    Array inputs = params[0].get_array();
    Object sendTo = params[1].get_obj();

    CTransaction rawTx;

    BOOST_FOREACH(Value& input, inputs)
    {
        const Object& o = input.get_obj();

        const Value& txid_v = find_value(o, "txid");
        if (txid_v.type() != str_type)
            throw JSONRPCError(-8, "Invalid parameter, missing txid key");
        string txid = txid_v.get_str();
        if (!IsHex(txid))
            throw JSONRPCError(-8, "Invalid parameter, expected hex txid");

        const Value& vout_v = find_value(o, "vout");
        if (vout_v.type() != int_type)
            throw JSONRPCError(-8, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(-8, "Invalid parameter, vout must be positive");

        CTxIn in(COutPoint(uint256(txid), nOutput));
        rawTx.vin.push_back(in);
    }

    set<CCoinAddr> setAddress;
    BOOST_FOREACH(const Pair& s, sendTo)
    {
        CCoinAddr address(s.name_);
        if (!address.IsValid())
            throw JSONRPCError(-5, string("Invalid Bitcoin address:")+s.name_);

        if (setAddress.count(address))
            throw JSONRPCError(-8, string("Invalid parameter, duplicated address: ")+s.name_);
        setAddress.insert(address);

        CScript scriptPubKey;
        scriptPubKey.SetDestination(address.Get());
        int64 nAmount = AmountFromValue(s.value_);

        CTxOut out(nAmount, scriptPubKey);
        rawTx.vout.push_back(out);
    }

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION(iface));
    ss << rawTx;
    return HexStr(ss.begin(), ss.end());
}

Value decoderawtransaction(const Array& params, bool fStratum)
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "decoderawtransaction <hex string>\n"
        "Return a JSON object representing the serialized, hex-encoded transaction.");

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

  Object result;
  TxToJSON(iface, tx, 0, result);

  return result;
}
#endif

#if 0
Value signrawtransaction(const Array& params, bool fStratum)
{
    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
            "signrawtransaction <hex string> [{\"txid\":txid,\"vout\":n,\"scriptPubKey\":hex},...] [<privatekey1>,...] [sighashtype=\"ALL\"]\n"
            "Sign inputs for raw transaction (serialized, hex-encoded).\n"
            "Second optional argument is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the blockchain.\n"
            "Third optional argument is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
            "Fourth option is a string that is one of six values; ALL, NONE, SINGLE or\n"
            "ALL|ANYONECANPAY, NONE|ANYONECANPAY, SINGLE|ANYONECANPAY.\n"
            "Returns json object with keys:\n"
            "  hex : raw transaction with signature(s) (hex-encoded string)\n"
            "  complete : 1 if transaction has a complete set of signature (0 if not)"
            + HelpRequiringPassphrase());

    if (params.size() < 3)
        EnsureWalletIsUnlocked();

    RPCTypeCheck(params, list_of(str_type)(array_type)(array_type));

    vector<unsigned char> txData(ParseHex(params[0].get_str()));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    vector<CTransaction> txVariants;
    while (!ssData.empty())
    {
        try {
            CTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        }
        catch (std::exception &e) {
            throw JSONRPCError(-22, "TX decode failed");
        }
    }

    if (txVariants.empty())
        throw JSONRPCError(-22, "Missing transaction");

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CTransaction mergedTx(txVariants[0]);
    bool fComplete = true;

    // Fetch previous transactions (inputs):
    map<COutPoint, CScript> mapPrevOut;
    {
        MapPrevTx mapPrevTx;
        CTxDB txdb("r");
        map<uint256, CTxIndex> unused;
        bool fInvalid;
        mergedTx.FetchInputs(txdb, unused, false, false, mapPrevTx, fInvalid);

        // Copy results into mapPrevOut:
        BOOST_FOREACH(const CTxIn& txin, mergedTx.vin)
        {
            const uint256& prevHash = txin.prevout.hash;
            if (mapPrevTx.count(prevHash))
                mapPrevOut[txin.prevout] = mapPrevTx[prevHash].second.vout[txin.prevout.n].scriptPubKey;
        }
        txdb.Close();
    }

    // Add previous txouts given in the RPC call:
    if (params.size() > 1)
    {
        Array prevTxs = params[1].get_array();
        BOOST_FOREACH(Value& p, prevTxs)
        {
            if (p.type() != obj_type)
                throw JSONRPCError(-22, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            Object prevOut = p.get_obj();

            RPCTypeCheck(prevOut, map_list_of("txid", str_type)("vout", int_type)("scriptPubKey", str_type));

            string txidHex = find_value(prevOut, "txid").get_str();
            if (!IsHex(txidHex))
                throw JSONRPCError(-22, "txid must be hexadecimal");
            uint256 txid;
            txid.SetHex(txidHex);

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0)
                throw JSONRPCError(-22, "vout must be positive");

            string pkHex = find_value(prevOut, "scriptPubKey").get_str();
            if (!IsHex(pkHex))
                throw JSONRPCError(-22, "scriptPubKey must be hexadecimal");
            vector<unsigned char> pkData(ParseHex(pkHex));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            COutPoint outpoint(txid, nOut);
            if (mapPrevOut.count(outpoint))
            {
                // Complain if scriptPubKey doesn't match
                if (mapPrevOut[outpoint] != scriptPubKey)
                {
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + mapPrevOut[outpoint].ToString() + "\nvs:\n"+
                        scriptPubKey.ToString();
                    throw JSONRPCError(-22, err);
                }
            }
            else
                mapPrevOut[outpoint] = scriptPubKey;
        }
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (params.size() > 2)
    {
        fGivenKeys = true;
        Array keys = params[2].get_array();
        BOOST_FOREACH(Value k, keys)
        {
            CCoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood)
                throw JSONRPCError(-5,"Invalid private key");
            CKey key;
            bool fCompressed;
            CSecret secret = vchSecret.GetSecret(fCompressed);
            key.SetSecret(secret, fCompressed);
            tempKeystore.AddKey(key);
        }
    }
    const CKeyStore& keystore = (fGivenKeys ? tempKeystore : *pwalletMain);

    int nHashType = SIGHASH_ALL;
    if (params.size() > 3)
    {
        static map<string, int> mapSigHashValues =
            boost::assign::map_list_of
            (string("ALL"), int(SIGHASH_ALL))
            (string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))
            (string("NONE"), int(SIGHASH_NONE))
            (string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY))
            (string("SINGLE"), int(SIGHASH_SINGLE))
            (string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
            ;
        string strHashType = params[3].get_str();
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            throw JSONRPCError(-8, "Invalid sighash param");
    }

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++)
    {
        CTxIn& txin = mergedTx.vin[i];
        if (mapPrevOut.count(txin.prevout) == 0)
        {
            fComplete = false;
            continue;
        }
        const CScript& prevPubKey = mapPrevOut[txin.prevout];

        txin.scriptSig.clear();
        SignSignature(keystore, prevPubKey, mergedTx, i, nHashType);

        // ... and merge in other signatures:
        BOOST_FOREACH(const CTransaction& txv, txVariants)
        {
            txin.scriptSig = CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig);
        }
        if (!VerifyScript(txin.scriptSig, prevPubKey, mergedTx, i, true, 0))
            fComplete = false;
    }

    Object result;
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface));
    ssTx << mergedTx;
    result.push_back(Pair("hex", HexStr(ssTx.begin(), ssTx.end())));
    result.push_back(Pair("complete", fComplete));

    return result;
}
#endif

#if 0
Value rpc_tx_signraw(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() < 1 || params.size() > 4)
    throw runtime_error(
        "tx.signraw <hex string> [{\"txid\":txid,\"vout\":n,\"scriptPubKey\":hex},...] [<privatekey1>,...] [sighashtype=\"ALL\"]\n"
        "Sign inputs for raw transaction (serialized, hex-encoded).\n"
        "Second optional argument is an array of previous transaction outputs that\n"
        "this transaction depends on but may not yet be in the blockchain.\n"
        "Third optional argument is an array of base58-encoded private\n"
        "keys that, if given, will be the only keys used to sign the transaction.\n"
        "Fourth option is a string that is one of six values; ALL, NONE, SINGLE or\n"
        "ALL|ANYONECANPAY, NONE|ANYONECANPAY, SINGLE|ANYONECANPAY.\n"
        "Returns json object with keys:\n"
        "  hex : raw transaction with signature(s) (hex-encoded string)\n"
        "  complete : 1 if transaction has a complete set of signature (0 if not)"
        + HelpRequiringPassphrase());

  if (params.size() < 3)
    EnsureWalletIsUnlocked();

  RPCTypeCheck(params, list_of(str_type)(array_type)(array_type));

  vector<unsigned char> txData(ParseHex(params[0].get_str()));
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
  vector<CTransaction> txVariants;
  while (!ssData.empty())
  {
    try {
      CTransaction tx;
      ssData >> tx;
      txVariants.push_back(tx);
    }
    catch (std::exception &e) {
      throw JSONRPCError(-22, "TX decode failed");
    }
  }

  if (txVariants.empty())
    throw JSONRPCError(-22, "Missing transaction");

  // mergedTx will end up with all the signatures; it
  // starts as a clone of the rawtx:
  CTransaction mergedTx(txVariants[0]);
  bool fComplete = true;

  // Fetch previous transactions (inputs):
  map<COutPoint, CScript> mapPrevOut;
  {
    MapPrevTx mapPrevTx;
    CTxDB txdb(ifaceIndex, "r");
    map<uint256, CTxIndex> unused;
    bool fInvalid;
    mergedTx.FetchInputs(txdb, unused, false, false, mapPrevTx, fInvalid);

    // Copy results into mapPrevOut:
    BOOST_FOREACH(const CTxIn& txin, mergedTx.vin)
    {
      const uint256& prevHash = txin.prevout.hash;
      if (mapPrevTx.count(prevHash))
        mapPrevOut[txin.prevout] = mapPrevTx[prevHash].second.vout[txin.prevout.n].scriptPubKey;
    }
    txdb.Close();
  }

  // Add previous txouts given in the RPC call:
  if (params.size() > 1)
  {
    Array prevTxs = params[1].get_array();
    BOOST_FOREACH(Value& p, prevTxs)
    {
      if (p.type() != obj_type)
        throw JSONRPCError(-22, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

      Object prevOut = p.get_obj();

      RPCTypeCheck(prevOut, map_list_of("txid", str_type)("vout", int_type)("scriptPubKey", str_type));

      string txidHex = find_value(prevOut, "txid").get_str();
      if (!IsHex(txidHex))
        throw JSONRPCError(-22, "txid must be hexadecimal");
      uint256 txid;
      txid.SetHex(txidHex);

      int nOut = find_value(prevOut, "vout").get_int();
      if (nOut < 0)
        throw JSONRPCError(-22, "vout must be positive");

      string pkHex = find_value(prevOut, "scriptPubKey").get_str();
      if (!IsHex(pkHex))
        throw JSONRPCError(-22, "scriptPubKey must be hexadecimal");
      vector<unsigned char> pkData(ParseHex(pkHex));
      CScript scriptPubKey(pkData.begin(), pkData.end());

      COutPoint outpoint(txid, nOut);
      if (mapPrevOut.count(outpoint))
      {
        // Complain if scriptPubKey doesn't match
        if (mapPrevOut[outpoint] != scriptPubKey)
        {
          string err("Previous output scriptPubKey mismatch:\n");
          err = err + mapPrevOut[outpoint].ToString() + "\nvs:\n"+
            scriptPubKey.ToString();
          throw JSONRPCError(-22, err);
        }
      }
      else
        mapPrevOut[outpoint] = scriptPubKey;
    }
  }

  bool fGivenKeys = false;
  CBasicKeyStore tempKeystore;
  if (params.size() > 2)
  {
    fGivenKeys = true;
    Array keys = params[2].get_array();
    BOOST_FOREACH(Value k, keys)
    {
      CCoinSecret vchSecret;
      bool fGood = vchSecret.SetString(k.get_str());
      if (!fGood)
        throw JSONRPCError(-5,"Invalid private key");
      CKey key;
      bool fCompressed;
      CSecret secret = vchSecret.GetSecret(fCompressed);
      key.SetSecret(secret, fCompressed);
      tempKeystore.AddKey(key);
    }
  }
  const CKeyStore& keystore = (fGivenKeys ? tempKeystore : *pwalletMain);

  int nHashType = SIGHASH_ALL;
  if (params.size() > 3)
  {
    static map<string, int> mapSigHashValues =
      boost::assign::map_list_of
      (string("ALL"), int(SIGHASH_ALL))
      (string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))
      (string("NONE"), int(SIGHASH_NONE))
      (string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY))
      (string("SINGLE"), int(SIGHASH_SINGLE))
      (string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
      ;
    string strHashType = params[3].get_str();
    if (mapSigHashValues.count(strHashType))
      nHashType = mapSigHashValues[strHashType];
    else
      throw JSONRPCError(-8, "Invalid sighash param");
  }

  // Sign what we can:
  for (unsigned int i = 0; i < mergedTx.vin.size(); i++)
  {
    CTxIn& txin = mergedTx.vin[i];
    if (mapPrevOut.count(txin.prevout) == 0)
    {
      fComplete = false;
      continue;
    }
    const CScript& prevPubKey = mapPrevOut[txin.prevout];

    txin.scriptSig.clear();
    SignSignature(keystore, prevPubKey, mergedTx, i, nHashType);

    // ... and merge in other signatures:
    BOOST_FOREACH(const CTransaction& txv, txVariants)
    {
      txin.scriptSig = CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig);
    }
    if (!VerifyScript(txin.scriptSig, prevPubKey, mergedTx, i, true, 0))
      fComplete = false;
  }

  Object result;
  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface));
  ssTx << mergedTx;
  result.push_back(Pair("hex", HexStr(ssTx.begin(), ssTx.end())));
  result.push_back(Pair("complete", fComplete));

  return result;
}
#endif

#if 0
Value rpc_sendrawtransaction(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() < 1 || params.size() > 1)
    throw runtime_error(
        "tx.sendraw <hex string>\n"
        "Submits raw transaction (serialized, hex-encoded) to local node and network.");

  RPCTypeCheck(params, list_of(str_type));

  // parse hex string from parameter
  vector<unsigned char> txData(ParseHex(params[0].get_str()));
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
  CTransaction tx;

  // deserialize binary data stream
  try {
    ssData >> tx;
  }
  catch (std::exception &e) {
    throw JSONRPCError(-22, "TX decode failed");
  }
  uint256 hashTx = tx.GetHash();

  // See if the transaction is already in a block
  // or in the memory pool:
  CTransaction existingTx;
  uint256 hashBlock = 0;
  if (GetTransaction(iface, hashTx, existingTx, hashBlock))
  {
    if (hashBlock != 0)
      throw JSONRPCError(-5, string("transaction already in block ")+hashBlock.GetHex());
    // Not in block, but already in the memory pool; will drop
    // through to re-relay it.
  }
  else
  {
    // push to local node
    CTxDB txdb(ifaceIndex, "r");
    if (!tx.AcceptToMemoryPool(txdb))
      throw JSONRPCError(-22, "TX rejected");
    txdb.Close();

    usde_SyncWithWallets(tx, NULL, true);
  }
  RelayMessage(CInv(MSG_TX, hashTx), tx);

  return hashTx.GetHex();
}
#endif


