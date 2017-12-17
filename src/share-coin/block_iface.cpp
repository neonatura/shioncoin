
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura
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
#include "wallet.h"
#include "db.h"
#include "walletdb.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "base58.h"
#include "server_iface.h" /* BLKERR_XXX */

#undef printf
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/shared_ptr.hpp>
#include <list>
#define printf OutputDebugStringF

using namespace std;
using namespace boost;
using namespace json_spirit;

#define MAX_NONCE_SEQUENCE 16

//std::map<uint256, CBlockIndex*> transactionMap;

string blocktemplate_json; 
string mininginfo_json; 
string transactioninfo_json;

typedef map<unsigned int, CBlock*> work_map;
work_map mapWork;

extern std::string HexBits(unsigned int nBits);
extern string JSONRPCReply(const Value& result, const Value& error, const Value& id);
extern void ScriptPubKeyToJSON(int ifaceIndex, const CScript& scriptPubKey, Object& out);
extern Value ValueFromAmount(int64 amount);
extern void WalletTxToJSON(int ifaceIndex, const CWalletTx& wtx, Object& entry);

//extern void ListTransactions(int ifaceIndex, const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret);
extern double GetDifficulty(int ifaceIndex, const CBlockIndex* blockindex = NULL);

static double nextDifficulty;
double GetBitsDifficulty(unsigned int nBits)
{
  // Floating point number that is a multiple of the minimum difficulty,
  // minimum difficulty = 1.0.

  int nShift = (nBits >> 24) & 0xff;

  double dDiff =
    (double)0x0000ffff / (double)(nBits & 0x00ffffff);

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

  return (dDiff);
}

static CBlock *altBlock[MAX_COIN_IFACE];
static unsigned int altHeight[MAX_COIN_IFACE];

/**
 * Generate a block to work on.
 * @returns JSON encoded block state information
 */
const char *c_getblocktemplate(int ifaceIndex)
{
  static unsigned int work_id;
  static time_t last_reset_t;
  unsigned int nHeight;
  CIface *iface;
  CBlock* pblock;
  int reset;


  iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (NULL);

  if (!GetWallet(iface))
    return (NULL); /* coin service disabled. */

  CBlockIndex *pindexPrev = GetBestBlockIndex(iface);
  if (!pindexPrev)
    return (NULL); /* chain not established */

#if 0
  if (IsInitialBlockDownload(ifaceIndex))
    return (NULL);
#endif

  if (iface->blockscan_max > pindexPrev->nHeight)
    return (NULL); /* downloading blocks */

  /* prune worker blocks (< 5 min) */
  vector<unsigned int> vDelete;
  time_t timeExpire = GetAdjustedTime() - 360;
  for (work_map::const_iterator mi = mapWork.begin(); mi != mapWork.end(); ++mi) {
    CBlock *tblock = mi->second;
    if (tblock->nTime < timeExpire) {
      unsigned int id = (unsigned int)mi->first;
      vDelete.push_back(id);
      delete tblock;
    }
  }
  BOOST_FOREACH (unsigned int id, vDelete) {
    mapWork.erase(id);
  }

  
  if (altHeight[ifaceIndex] != (GetBestHeight(ifaceIndex) + 1)) {
#if 0
    /* delete all worker blocks. */
    for (map<int, CBlock*>::const_iterator mi = mapWork.begin(); mi != mapWork.end(); ++mi)
    {
      CBlock *tblock = mi->second;
      delete tblock;
    }
    mapWork.clear();
#endif

    altBlock[ifaceIndex] = NULL;
  }
  nHeight = pindexPrev->nHeight + 1;
  altHeight[ifaceIndex] = nHeight;

  pblock = NULL;
  try {
    pblock = CreateBlockTemplate(iface);
  } catch (std::exception& e) {
fprintf(stderr, "DEBUG: c_getblocktemplate: CreateBlockTemplate: %s\n", e.what()); 
 }
  if (!pblock) {
fprintf(stderr, "DEBUG: c_getblocktemplate: error creating block template\n"); 
    return (NULL);
}

  /* store "worker" block for until height increment. */
  work_id++;
  mapWork[work_id] = pblock; 
  altBlock[ifaceIndex] = pblock;

  // Update nTime
  pblock->UpdateTime(pindexPrev);
  pblock->nNonce = 0;

  SetNextDifficulty(ifaceIndex, pblock->nBits);

  Array transactions;
  //map<uint256, int64_t> setTxIndex;
  int i = 0;
  BOOST_FOREACH (CTransaction& tx, pblock->vtx)
  {
    uint256 txHash = tx.GetHash();

    if (tx.IsCoinBase())
      continue;
    transactions.push_back(txHash.GetHex());
  }

  uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();


  Object result;

#if 0 
  /* all pool mining is defunc when "connections=0". */
  result.push_back(Pair("connections",   (int)vNodes.size()));
#endif

  result.push_back(Pair("version", pblock->nVersion));
  result.push_back(Pair("task", (int64_t)work_id));
  result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
  result.push_back(Pair("transactions", transactions));
  result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
  result.push_back(Pair("target", hashTarget.GetHex()));
  result.push_back(Pair("sizelimit", (int64_t)iface->max_block_size));
  result.push_back(Pair("curtime", (int64_t)pblock->nTime));
  result.push_back(Pair("bits", HexBits(pblock->nBits)));

  if (!pindexPrev) {
    /* mining is defunct when "height < 2" */
    result.push_back(Pair("height", (int64_t)0));
  } else {
    result.push_back(Pair("height", (int64_t)nHeight));
  }

  /* dummy nExtraNonce */
  SetExtraNonce(pblock, "f0000000f0000000");

  /* coinbase */
  CTransaction coinbaseTx = pblock->vtx[0];
  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface) | SERIALIZE_TRANSACTION_NO_WITNESS);
  ssTx << coinbaseTx;
  result.push_back(Pair("coinbase", HexStr(ssTx.begin(), ssTx.end())));
  //  result.push_back(Pair("sigScript", HexStr(pblock->vtx[0].vin[0].scriptSig.begin(), pblock->vtx[0].vin[0].scriptSig.end())));
  CScript COINBASE_FLAGS = pblock->GetCoinbaseFlags();
  result.push_back(Pair("coinbaseflags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

  blocktemplate_json = JSONRPCReply(result, Value::null, Value::null);
  return (blocktemplate_json.c_str());
}

#if SUBMIT_ALT_BLOCK_CHAIN
void c_processaltblock(int altIndex, unsigned int nMinNonce, char *xn_hex)
{
  shtime_t ts;
  int ifaceIndex;
  unsigned int nNonce;
  int idx;

  for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
    if (altIndex == ifaceIndex)
      continue; /* already processed block */

    CIface *iface = GetCoinByIndex(ifaceIndex);
    if (!iface->enabled)
      continue;
    if (GetWallet(ifaceIndex) == NULL)
      continue; /* disabled */

    CBlock *alt_block = altBlock[ifaceIndex];
    if (!alt_block || !alt_block->ifaceIndex)
      continue; /* no block avail for mining */
    
    CBlockIndex *bestIndex = GetBestBlockIndex(iface);
    if (alt_block->hashPrevBlock != bestIndex->GetBlockHash()) {
      continue; /* BLKERR_INVALID_JOB */
    }
    if (alt_block->nTime < bestIndex->nTime) {
      continue; /* BLKERR_INVALID_BLOCK */
    }

    CNode *pfrom = NULL;

      alt_block->nNonce = nNonce; /* jic */
    SetExtraNonce(alt_block, xn_hex);
    alt_block->hashMerkleRoot = alt_block->BuildMerkleTree();

    timing_init("ProcessAltBlock/Nonce", &ts);
    uint256 hashTarget = CBigNum().SetCompact(alt_block->nBits).getuint256();
    for (idx = 0; idx < MAX_NONCE_SEQUENCE; idx++) {
      alt_block->nNonce = nMinNonce + idx;
      uint256 hash = alt_block->GetPoWHash();
      if (hash <= hashTarget)
        break; 
    }
    timing_term(altIndex, "ProcessAltBlock/Nonce", &ts);
    if (idx == MAX_NONCE_SEQUENCE) {
      continue; /* BLKERR_TARGET_LOW */
    }

    // Check for duplicate
    uint256 hash = alt_block->GetHash();
    if (GetBlockIndexByHash(ifaceIndex, hash)) { /* || IsBlockOrphan() */
      continue;  // BLKERR_DUPLICATE_BLOCK
    }

    /* verify integrity */
    if (!alt_block->CheckBlock()) {
      continue; // BLKERR_CHECKPOINT
    }

    // Store to disk
    if (!alt_block->AcceptBlock()) {
      continue; // BLKERR_INVALID_BLOCK
    }

    break;
  }

}
#endif /* SUBMIT_ALT_BLOCK_CHAIN */

/**
 * Called by miner [i.e., via stratum] to submit a new block.
 * @see ProcessBlock()
 */
int c_processblock(CBlock* pblock)
{
  NodeList &vNodes = GetNodeList(pblock->ifaceIndex);
  CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
  CNode *pfrom = NULL;

  if (vNodes.empty()) {
    return (0); 
  }

  CBlockIndex *bestIndex = GetBestBlockIndex(iface);
  if (!bestIndex)
    return (BLKERR_INVALID_JOB); /* work not up-to-date */

  if (bestIndex->nHeight < iface->blockscan_max) {
    /* still downloading blocks. */
fprintf(stderr, "DEBUG: processblock: still downloading blocks.. skipping submitted block.\n"); 
    return (0);
  }

  // Check for duplicate
  uint256 hash = pblock->GetHash();
  if (GetBlockIndexByHash(pblock->ifaceIndex, hash) || pblock->IsOrphan())
    return (BLKERR_DUPLICATE_BLOCK);

  // Preliminary checks
  if (!pblock->CheckBlock()) {
    shcoind_log("c_processblock: !CheckBlock()");
    return (BLKERR_CHECKPOINT);
  }

  if (pblock->hashPrevBlock != bestIndex->GetBlockHash()) {
    return (BLKERR_INVALID_JOB); /* work not up-to-date */
  }
  if (pblock->nTime < bestIndex->nTime) {
    return (BLKERR_INVALID_BLOCK);
  }

  // Store to disk
  if (!pblock->AcceptBlock()) {
    shcoind_log("c_processblock: !AcceptBlock()");
    return (BLKERR_INVALID_BLOCK);
  }

  /* stats */
  STAT_BLOCK_SUBMITS(iface)++;
  iface->net_valid = time(NULL);

  return (0);
}

#if 0
static bool QuickCheckWork(CBlock* pblock, double *ret_diff)
{
  uint256 hash = pblock->GetPoWHash();
  uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
//  uint256 bhash = Hash(BEGIN(pblock->nVersion), END(pblock->nNonce));

  if (ret_diff)
    *ret_diff = GetBitsDifficulty(hash.GetCompact());

  if (hash > hashTarget)
    return false;

fprintf(stderr, "generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

  return true;
}
#endif

#if 0
  CTransaction coinbaseTx = pblock->vtx[0];
  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
  ssTx << coinbaseTx;
  fprintf(stderr, "DEBUG: submitblock: coinbase %s\n", HexStr(ssTx.begin(), ssTx.end()).c_str());
#endif
int c_submitblock(unsigned int workId, unsigned int nTime, unsigned int nNonce, char *xn_hex, char *ret_hash, double *ret_diff)
{
  CBlock *pblock;
  shtime_t ts;
  uint256 hash;
  uint256 hashTarget;
  int idx;
  int err;
  bool ok;

  if (ret_hash)
    ret_hash[0] = '\000';
  if (ret_diff)
    *ret_diff = 0.0;

  if (mapWork.count(workId) == 0) {
    return (SHERR_TIME); /* task is stale */
  }

  pblock = mapWork[workId];
  if (pblock->nNonce == nNonce) {
    return (SHERR_ALREADY);
  }

  pblock->nTime = nTime;
  pblock->nNonce = nNonce;

  SetExtraNonce(pblock, xn_hex);
  pblock->hashMerkleRoot = pblock->BuildMerkleTree();

  timing_init("ProcessBlock/Nonce", &ts);
  hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
  for (idx = 0; idx < MAX_NONCE_SEQUENCE; idx++) {
    pblock->nNonce = nNonce + idx;
    hash = pblock->GetPoWHash();
    if (hash <= hashTarget) {
      if (ret_diff) {
        const char *hash_str = hash.ToString().c_str();
        char nbit_str[256];
        uint64_t nbit;

        memset(nbit_str, '\000', sizeof(nbit_str));
        strcpy(nbit_str, hash.ToString().substr(0,12).c_str());

        nbit = (uint64_t)strtoll(nbit_str, NULL, 16);
        if (nbit == 0) nbit = 1;

        *ret_diff = ((double)0x0000ffff /  (double)(nbit & 0x00ffffff));
      }
      break;
    }
  }
  timing_term(pblock->ifaceIndex, "ProcessBlock/Nonce", &ts);

  if (idx == MAX_NONCE_SEQUENCE) {
#if SUBMIT_ALT_BLOCK_CHAIN
    /* try nonce on alt coins */ 
    c_processaltblock(pblock->ifaceIndex, nNonce, xn_hex);
#endif
  } else {
    err = c_processblock(pblock);
    if (!err) {
      string submit_block_hash;
      char errbuf[1024];

      submit_block_hash = pblock->GetHash().GetHex();
      if (ret_hash)
        strcpy(ret_hash, submit_block_hash.c_str());

      sprintf(errbuf, "submitblock[iface #%d]: mined block (%s) generated %s coins.\n", pblock->ifaceIndex, submit_block_hash.c_str(), FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());
      shcoind_log(errbuf);
      pblock->print();
    }

  }
  return (0);
}

Object c_AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Object entry)
{
  bool fAllAccounts = (strAccount == string("*"));

  if (fAllAccounts || acentry.strAccount == strAccount)
  {
    entry.push_back(Pair("account", acentry.strAccount));
    entry.push_back(Pair("category", "move"));
    entry.push_back(Pair("time", (boost::int64_t)acentry.nTime));
    entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
    entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
    entry.push_back(Pair("comment", acentry.strComment));
  }

  return (entry);
}

#if 0
bool c_ListGenerateTransactions(const CWalletTx& wtx, Object entry)
{
  string strAccount = "*";
  int64 nGeneratedImmature, nGeneratedMature, nFee;
  string strSentAccount;
  list<pair<CTxDestination, int64> > listReceived;
  list<pair<CTxDestination, int64> > listSent;

  wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount);

  bool fAllAccounts = (strAccount == string("*"));

  // Generated blocks assigned to account ""
  //if ((nGeneratedMature+nGeneratedImmature) != 0) {
  if (nGeneratedMature) {
    entry.push_back(Pair("account", string("")));
    entry.push_back(Pair("category", "generate"));
    entry.push_back(Pair("amount", ValueFromAmount(nGeneratedMature)));
    WalletTxToJSON(wtx, entry);
    return (true);
  }

  return (false);
}
#endif
void c_ListTransactions(int ifaceIndex, const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret)
{
  int64 nGeneratedImmature, nGeneratedMature, nFee;
  string strSentAccount;
  list<pair<CTxDestination, int64> > listReceived;
  list<pair<CTxDestination, int64> > listSent;

  wtx.GetAmounts(ifaceIndex, nGeneratedImmature, nGeneratedMature);
  //wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount);

  bool fAllAccounts = (strAccount == string("*"));

  // Generated blocks assigned to account ""
  if (nGeneratedMature != 0)
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

}


#if 0
const char *c_getblocktransactions(int ifaceIndex)
{
  static int block_height;
  CWallet *wallet = GetWallet(ifaceIndex);
  const CPubKey& pubkey = wallet->GetMainAccountPubKey(wallet);

  /* scan blocks for matching miner destination. */
  
  

}
#endif

const char *c_getblocktransactions(int ifaceIndex)
{
  NodeList &vNodes = GetNodeList(ifaceIndex);
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  if (!pwalletMain)
    return (NULL);

  CWalletDB walletdb(pwalletMain->strWalletFile);
  string strAccount = "";
  int nCount = 1;
  int nFrom = 0;
  Array ret;

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

/*
  list<CAccountingEntry> acentries;
  walletdb.ListAccountCreditDebit(strAccount, acentries);
  BOOST_FOREACH(CAccountingEntry& entry, acentries)
  {
    txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
  }
*/

  if ((int)vNodes.size() >= 1) { /* if more than one coin connection */
    // iterate backwards until we have nCount items to return:
    for (TxItems::reverse_iterator it = txByTime.rbegin(); it != txByTime.rend(); ++it)
    {
      CWalletTx *const pwtx = (*it).second.first;
      if (pwtx != 0)
        c_ListTransactions(ifaceIndex, *pwtx, strAccount, 0, true, ret);
      /*
         CAccountingEntry *const pacentry = (*it).second.second;
         if (pacentry != 0)
         AcentryToJSON(*pacentry, strAccount, ret);
         */

      if ((int)ret.size() >= (nCount+nFrom)) break;
    }
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

  /* convert to a json string. */
  if (ret.size() > 0)
    blocktemplate_json = JSONRPCReply(ret.at(0), Value::null, Value::null);
  else
    blocktemplate_json = JSONRPCReply(ret, Value::null, Value::null);
  return (blocktemplate_json.c_str());
}

#if 0
const char *c_getblocktransactions(void)
{

  string strAccount = "*";
  int nCount = 10;
  int nFrom = 0;


//  Array ret;
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

  Object result;

  // iterate backwards until we have nCount items to return:
  for (TxItems::reverse_iterator it = txByTime.rbegin(); it != txByTime.rend(); ++it)
  {
    CWalletTx *const pwtx = (*it).second.first;
    if (pwtx != 0) {
      if (c_ListGenerateTransactions(*pwtx, result))
        break; /* found mature generation. */
    }
  }
  // ret is newest to oldest

  blocktemplate_json = JSONRPCReply(result, Value::null, Value::null);
  return (blocktemplate_json.c_str());
}
#endif

double c_GetNetworkHashRate(int ifaceIndex)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  int lookup = 120;

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

  return ((double)GetDifficulty(ifaceIndex) * pow(2.0, 32)) / (double)timePerBlock;
}

const char *c_getmininginfo(int ifaceIndex)
{
  Array result;

  int height = (int)GetBestHeight(ifaceIndex);
  result.push_back((int)height);

  if (nextDifficulty > 0.00000000)
    result.push_back((double)nextDifficulty);
  else
    result.push_back((double)GetDifficulty(ifaceIndex));

  if (height > 0)
    result.push_back((double)c_GetNetworkHashRate(ifaceIndex));
  else
    result.push_back((double)0.0);

  mininginfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (mininginfo_json.c_str());
}

double c_getdifficulty(int ifaceIndex)
{
  return ((double)GetDifficulty(ifaceIndex));
}

string blockinfo_json;
const char *c_getblockindexinfo(int ifaceIndex, CBlockIndex *pblockindex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CBlock *block;
  Object result;

  block = GetBlockByHash(iface, pblockindex->GetBlockHash());

  result.push_back(Pair("hash", block->GetHash().GetHex()));
  CMerkleTx txGen(block->vtx[0]);
  txGen.SetMerkleBranch(block);
  result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain(ifaceIndex)));
  result.push_back(Pair("size", (int)::GetSerializeSize(*block, SER_NETWORK, PROTOCOL_VERSION(iface))));
  result.push_back(Pair("height", pblockindex->nHeight));
  result.push_back(Pair("version", block->nVersion));
  result.push_back(Pair("merkleroot", block->hashMerkleRoot.GetHex()));

  Array txs;
  int64 nAmount = 0;
  BOOST_FOREACH(const CTransaction&tx, block->vtx) {
    txs.push_back(tx.GetHash().GetHex());
    nAmount += tx.GetValueOut();
  }
  result.push_back(Pair("tx", txs));
  result.push_back(Pair("amount", ValueFromAmount(nAmount)));

  result.push_back(Pair("time", (boost::int64_t)block->GetBlockTime()));
  result.push_back(Pair("nonce", (boost::uint64_t)block->nNonce));
  result.push_back(Pair("bits", HexBits(block->nBits)));
  result.push_back(Pair("difficulty", GetDifficulty(ifaceIndex, pblockindex)));

  if (pblockindex->pprev)
    result.push_back(Pair("previousblockhash", pblockindex->pprev->GetBlockHash().GetHex()));
  if (pblockindex->pnext)
    result.push_back(Pair("nextblockhash", pblockindex->pnext->GetBlockHash().GetHex()));

  blockinfo_json = JSONRPCReply(result, Value::null, Value::null);
  delete block;

  return (blockinfo_json.c_str());
}

const char *c_getblockinfo(int ifaceIndex, const char *hash_addr)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  long nHeight;

  if (!hash_addr)
    return (NULL);

  std::string strHash(hash_addr);

  if (strlen(hash_addr) <= 12 && (nHeight = atol(hash_addr))) {
    /* convert block index to block hash */
    if (nHeight < 0 || nHeight > GetBestHeight(ifaceIndex)) {
      shcoind_log("c_getblockinfo: block number out of range.");
      return (NULL);
    }

    CBlock *block = GetBlockByHeight(iface, nHeight);
    if (!block) {
      shcoind_log("c_getblockinfo: block not found.");
      return (NULL);
    }

#if 0
    uint256 hashBestChain = GetBestBlockChain(iface);
    CBlockIndex* pblockindex = (*blockIndex)[hashBestChain];
    if (!pblockindex) {
      shcoind_log("c_getblockinfo: block index not found.");
      return (NULL);
    }
    while (pblockindex->nHeight > nHeight)
      pblockindex = pblockindex->pprev;
    strHash = pblockindex->phashBlock->GetHex();
#endif

    strHash = block->GetHash().GetHex();
    delete block;
  }

  uint256 hash(strHash);
  CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, hash);
  if (!pindex)
    return (NULL);
  return (c_getblockindexinfo(ifaceIndex, pindex));
}
#if 0
  CBlock block;
  block.ReadFromDisk(pblockindex, true);

  Object result;
  result.push_back(Pair("hash", block.GetHash().GetHex()));
  CMerkleTx txGen(block.vtx[0]);
  txGen.SetMerkleBranch(&block);
  result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
  result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
  result.push_back(Pair("height", pblockindex->nHeight));
  result.push_back(Pair("version", block.nVersion));
  result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
  Array txs;
  BOOST_FOREACH(const CTransaction&tx, block.vtx)
    txs.push_back(tx.GetHash().GetHex());
  result.push_back(Pair("tx", txs));
  result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
  result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
  result.push_back(Pair("bits", HexBits(block.nBits)));
  result.push_back(Pair("difficulty", GetDifficulty(pblockindex)));

  if (pblockindex->pprev)
    result.push_back(Pair("previousblockhash", pblockindex->pprev->GetBlockHash().GetHex()));
  if (pblockindex->pnext)
    result.push_back(Pair("nextblockhash", pblockindex->pnext->GetBlockHash().GetHex()));

  blockinfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (blockinfo_json.c_str());
}
#endif

#if 0
int findBlockTransaction(CBlockIndex *pblockindex, const char *tx_id, CTransaction& ret_tx, time_t dur)
{
  USDEBlock block;
  uint256 hashTx;
  int64 nOut;
  int confirms;
  time_t min_t;

  if (!tx_id || !*tx_id)
    return (NULL);

  hashTx.SetHex(tx_id);

  min_t = 0;
  if (dur)
    min_t = time(NULL) - dur;

  block.ReadFromDisk(pblockindex, true);
  if (min_t && ((time_t)block.GetBlockTime() < min_t)) {
    /* exceeds duration limit */
    return (-1);
  }
  BOOST_FOREACH(CTransaction&tx, block.vtx) {
/*
    std::string txStr = tx.GetHash().GetHex();
    if (0 == strcasecmp(txStr.c_str(), tx_id)) {
      ret_tx = tx;
      return (0);
    }
*/
    if (tx.GetHash() == hashTx) {
      ret_tx = tx;
      return (0);
    }

  }

  return (-1);
}
#endif

static CBlockIndex *findTransaction(int ifaceIndex, uint256 hashTx, CTransaction& ret_tx)
{
  CBlockIndex *pindex;
  uint256 hashBlock;
  
  if (!ret_tx.ReadTx(ifaceIndex, hashTx, &hashBlock))
    return (NULL);

  pindex = GetBlockIndexByHash(ifaceIndex, hashBlock);
  if (!pindex)
    return (NULL);

  return (pindex);
}




#define MAX_HISTORY_TIME 10454400 /* 1/3 year */
const char *c_gettransactioninfo(int ifaceIndex, const char *tx_id)
{
  CTransaction tx;
  CBlockIndex *pblockindex;
  Object result;
  shtime_t ts;
  uint256 hashBlock;
  uint256 hashTx;
  int64 nOut;
  int confirms;
  int err;

  if (!tx_id || !*tx_id)
    return (NULL);


  hashTx.SetHex(tx_id);
  pblockindex = findTransaction(ifaceIndex, hashTx, tx);
  if (!pblockindex)
    return (NULL);

  hashTx = tx.GetHash();
#if 0
//  pblockindex = transactionMap[hashTx]; /* check tx map */
  if (!pblockindex) {
    pblockindex = findTransaction(ifaceIndex, hashTx, tx);
    if (!pblockindex)
      return (NULL);

    hashTx = tx.GetHash();
  } else {
    err = findBlockTransaction(pblockindex, tx_id, tx, MAX_HISTORY_TIME);
    if (err)
      return (NULL);
  }
#endif

  hashBlock = 0;
  if (pblockindex)
    hashBlock = pblockindex->GetBlockHash();

  if (hashBlock != 0)
  {
    result.push_back(Pair("blockhash", hashBlock.GetHex()));

    if (!pblockindex) { /* redundant secondary lookup */
      pblockindex = GetBlockIndexByHash(ifaceIndex, hashBlock);
    }

    if (pblockindex && pblockindex->IsInMainChain(ifaceIndex))
    {
      result.push_back(Pair("confirmations", (int)(1 + GetBestHeight(ifaceIndex) - pblockindex->nHeight)));
      result.push_back(Pair("time", (boost::int64_t)pblockindex->nTime));
    }
    else {
      result.push_back(Pair("confirmations", 0));
    }
  }

  result.push_back(Pair("txid", tx.GetHash().GetHex()));
  result.push_back(Pair("version", tx.isFlag(CTransaction::TX_VERSION) ? 1 : 0));
  result.push_back(Pair("flag", tx.nFlag));
  result.push_back(Pair("locktime", (boost::int64_t)tx.nLockTime));
  result.push_back(Pair("amount", ValueFromAmount(tx.GetValueOut())));
  result.push_back(Pair("fee", ValueFromAmount(GetTxFee(ifaceIndex, tx))));

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
      in.push_back(Pair("asm", txin.scriptSig.ToString()));
      in.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    }
    in.push_back(Pair("sequence", (boost::int64_t)txin.nSequence));
    vin.push_back(in);
  }
  result.push_back(Pair("vin", vin));

  Array vout;
  for (unsigned int i = 0; i < tx.vout.size(); i++)
  {
    const CTxOut& txout = tx.vout[i];
    Object out;
    out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
    out.push_back(Pair("n", (boost::int64_t)i));
    ScriptPubKeyToJSON(ifaceIndex, txout.scriptPubKey, out);
    vout.push_back(out);
  }
  result.push_back(Pair("vout", vout));

  transactioninfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (transactioninfo_json.c_str());
}
#if 0
const char *c_gettransactioninfo(const char *tx_id)
{

  if (!tx_id)
    return (NULL);

  std::string txStr(tx_id);
  uint256 hash;
  hash.SetHex(txStr);

  Object result;
  if (!pwalletMain->mapWallet.count(hash)) {
    //  throw JSONRPCError(-5, "Invalid or non-wallet transaction id");
    return (NULL);
  }
  const CWalletTx& wtx = pwalletMain->mapWallet[hash];

  int64 nCredit = wtx.GetCredit();
  int64 nDebit = wtx.GetDebit();
  int64 nNet = nCredit - nDebit;
  int64 nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);

  result.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
  //if (wtx.IsFromMe())
  result.push_back(Pair("fee", ValueFromAmount(nFee)));

  int confirms = wtx.GetDepthInMainChain();
  result.push_back(Pair("confirmations", confirms));
  if (confirms)
  {
    result.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
    result.push_back(Pair("blockindex", wtx.nIndex));
  }
  result.push_back(Pair("txid", wtx.GetHash().GetHex()));
  result.push_back(Pair("time", (boost::int64_t)wtx.GetTxTime()));
  BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
    result.push_back(Pair(item.first, item.second));

  Array details;
  ListTransactions(wtx, "*", 0, false, details);
  result.push_back(Pair("details", details));

  transactioninfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (transactioninfo_json.c_str());
}
#endif

const char *c_getlastblockinfo(int ifaceIndex, int target_height)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  CBlockIndex *block;
  uint256 blockId;
  int blockHeight;

  for (block = pindexBest; block; block = block->pprev)  {
    if (target_height == 0 || block->nHeight == target_height)
      return (c_getblockindexinfo(ifaceIndex, block));
  }

  return (NULL);
}

uint64_t c_getblockheight(int ifaceIndex)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  
  if (!pindexBest) {
    /* mining is defunct when "height < 2" */
    return (0);
  }

  return ((int64_t)(pindexBest->nHeight+1));
}

string miningtransactioninfo_json;
const char *c_getminingtransactions(int ifaceIndex, unsigned int workId)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  Array result;
//  map<uint256, int64_t> setTxIndex;
  int i = 0;
  CBlock *pblock;
  int err;
  bool ok;

  if (mapWork.count(workId) == 0) {
    return (NULL);
  }
 
  pblock = mapWork[workId];

  BOOST_FOREACH (CTransaction& tx, pblock->vtx)
  {
    Object entry;

    if (tx.IsCoinBase())
      continue;

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface));
    ssTx << tx;

    result.push_back(HexStr(ssTx.begin(), ssTx.end()));
  }

  miningtransactioninfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (miningtransactioninfo_json.c_str());
}

int GetBlockDepthInMainChain(CIface *iface, uint256 blockHash)
{
  int ifaceIndex = GetCoinIndex(iface);
  CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, blockHash);

  if (!pindex || !pindex->IsInMainChain(ifaceIndex))
    return (0);

  return 1 + GetBestHeight(ifaceIndex) - pindex->nHeight;
}

int GetTxDepthInMainChain(CIface *iface, uint256 txHash)
{
  CTransaction tx;
  uint256 blockHash;
  bool ret;

  ret = GetTransaction(iface, txHash, tx, &blockHash);
  if (!ret)
    return (0);

  return (GetBlockDepthInMainChain(iface, blockHash));
}


#ifdef __cplusplus
extern "C" {
#endif

const char *getblocktemplate(int ifaceIndex)
{
  return (c_getblocktemplate(ifaceIndex));
}

int submitblock(unsigned int workId, unsigned int nTime, unsigned int nNonce, char *xn_hex, char *ret_hash, double *ret_diff)
{
  return (c_submitblock(workId, nTime, nNonce, xn_hex, ret_hash, ret_diff));
}

const char *getblocktransactions(int ifaceIndex)
{
  return (c_getblocktransactions(ifaceIndex));
}

const char *getmininginfo(int ifaceIndex)
{
  return (c_getmininginfo(ifaceIndex));
}

double getdifficulty(int ifaceIndex)
{
  return (c_getdifficulty(ifaceIndex));
}

const char *getblockinfo(int ifaceIndex, const char *hash)
{
  return (c_getblockinfo(ifaceIndex, hash));
}

const char *gettransactioninfo(int ifaceIndex, const char *hash)
{
  return (c_gettransactioninfo(ifaceIndex, hash));
}

const char *getlastblockinfo(int ifaceIndex, int height)
{
  return (c_getlastblockinfo(ifaceIndex, height));
}

uint64_t getblockheight(int ifaceIndex)
{
  return (c_getblockheight(ifaceIndex));
}

const char *getminingtransactioninfo(int ifaceIndex, unsigned int workId)
{
  return (c_getminingtransactions(ifaceIndex, workId));
}
#if 0
const int reloadblockfile(const char *path)
{
  return (cxx_reloadblockfile(path));
}
#endif

/** Set by stratum server when block changes via getblocktemplate(). */
void SetNextDifficulty(int ifaceIndex, unsigned int nBits)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (iface != NULL)
    iface->blk_diff = GetBitsDifficulty(nBits);
}
double GetNextDifficulty(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (iface == NULL)
    return (0.0);
  return (iface->blk_diff);
}


#ifdef __cplusplus
}
#endif

