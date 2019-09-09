
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
#include "main.h"
#include "wallet.h"
#include "db.h"
#include "net.h"
#include "ui_interface.h"
#include "base58.h"
#include "server_iface.h" /* BLKERR_XXX */

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

using namespace std;
using namespace boost;
using namespace json_spirit;

#define MAX_NONCE_SEQUENCE 4

string blocktemplate_json; 
string mininginfo_json; 
string transactioninfo_json;

typedef map<unsigned int, CBlock*> work_map;
work_map mapWork;

extern string JSONRPCReply(const Value& result, const Value& error, const Value& id);
extern void ScriptPubKeyToJSON(int ifaceIndex, const CScript& scriptPubKey, Object& out);
extern Value ValueFromAmount(int64 amount);
extern void WalletTxToJSON(int ifaceIndex, const CWalletTx& wtx, Object& entry);

//extern void ListTransactions(int ifaceIndex, const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret);
extern double GetDifficulty(int ifaceIndex, const CBlockIndex* blockindex = NULL);
extern std::string HexBits(unsigned int nBits);

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

const char *c_getblocktransactions(int ifaceIndex)
{
  NodeList &vNodes = GetNodeList(ifaceIndex);
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  if (!pwalletMain)
    return (NULL);

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
  CWallet *wallet = GetWallet(ifaceIndex);
  Array result;

  int height = (int)GetBestHeight(ifaceIndex);
  result.push_back((int)height);

	result.push_back((double)GetDifficulty(ifaceIndex));

  if (height > 0)
    result.push_back((double)c_GetNetworkHashRate(ifaceIndex));
  else
    result.push_back((double)0.0);

	if (wallet)
		result.push_back((double)wallet->GetBlockValue(height, 0, 0) / COIN);
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

extern double GetAverageBlockSpan(CIface *iface);
extern unsigned int GetDailyTxRate(CIface *iface);
extern Value GetNetworkHashPS(int ifaceIndex, int lookup);

string chaininfo_json;
const char *c_getchaininfo(int ifaceIndex)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
	Array result;

	if (!iface || !iface->enabled || !wallet)
		return (NULL);

	int nHeight = GetBestHeight(iface) + 1;
	int nNextHeight = nHeight;
	int64 nCurValue = wallet->GetBlockValue(nHeight, 0);
	int64 nValue = nCurValue;
	do {
		nNextHeight++;
		nValue = wallet->GetBlockValue(nNextHeight, 0, 0);
	} while (nValue == nCurValue);

	/* max shioncoins */
	result.push_back(ValueFromAmount(iface->max_money));
	/* minted shioncoins */
	result.push_back((double)iface->stat.tot_tx_mint/COIN);
	/* burnt shioncoins */
	result.push_back((double)iface->stat.tot_tx_return/COIN);
	/* next reward reduction block height. */
	result.push_back(nNextHeight);
	/* total blocks */
	result.push_back(nHeight);
	/* ~ blocks per day */
	result.push_back(86400 / GetAverageBlockSpan(iface));
	/* ~ tx per day */
	result.push_back((int)GetDailyTxRate(iface));
	/* difficulty */
	result.push_back(GetDifficulty(ifaceIndex, NULL));
	/* hash rate [H/s] */
	result.push_back(GetNetworkHashPS(ifaceIndex, 120));
	/* current reward */
	result.push_back((double)nCurValue / COIN);
	/* reward after next reduction */
	result.push_back((double)nValue / COIN);

  chaininfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (chaininfo_json.c_str());
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

const char *c_gettransactioninfo(int ifaceIndex, const char *tx_id)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CTransaction tx;
	Object result;
	uint256 hashBlock;
	uint256 hashTx;

	if (!iface || !iface->enabled)
		return (NULL);

	hashTx.SetHex(tx_id);
	if (!GetTransaction(iface, hashTx, tx, &hashBlock))
		return (NULL);

	result = tx.ToValue(ifaceIndex);
	result.push_back(Pair("blockhash", hashBlock.GetHex()));
	result.push_back(Pair("amount", ValueFromAmount(tx.GetValueOut())));
	if (!tx.IsCoinBase())
		result.push_back(Pair("fee", ValueFromAmount(GetTxFee(ifaceIndex, tx))));

	transactioninfo_json = JSONRPCReply(result, Value::null, Value::null);
	return (transactioninfo_json.c_str());
}

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
  CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
	if (!iface)
		return (NULL);

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

	int nDepth = 0;
	CBlockIndex *pindexBest = NULL;
	if (ifaceIndex == COLOR_COIN_IFACE) {
		/* count manually as each color has it's own 'best block index'. */
		pindexBest = pindex;

		while (pindexBest && pindexBest->pnext) {
			pindexBest = pindexBest->pnext;
			nDepth++;
		}

		return (1 + nDepth);
	}

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

string aliaslist_json;
const char *c_getaliaslist(int ifaceIndex)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	Object ret;
	alias_list *list;
	int nBestHeight;

	list = GetAliasTable(ifaceIndex);

	Object alias_list;
	BOOST_FOREACH(PAIRTYPE(const string, uint256)& r, *list) {
		const string& label = r.first;
		uint256& hTx = r.second;
		CTransaction tx;
		uint256 hBlock;

		if (!GetTransaction(iface, hTx, tx, NULL))
			continue;

		alias_list.push_back(Pair(label, tx.alias.ToValue(SHC_COIN_IFACE)));
	}
	ret.push_back(Pair("alias", alias_list));

	aliaslist_json = JSONRPCReply(ret, Value::null, Value::null);
	return (aliaslist_json.c_str());
}

string contextlist_json;
const char *c_getcontextlist(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
  set<CTxDestination> setAddress;
  Object ret;
  ctx_list *list;
  int nBestHeight;

  list = GetContextTable(ifaceIndex);
  BOOST_FOREACH(const PAIRTYPE(uint160, uint256)& r, *list) {
    const uint160& hContext = r.first;
    const uint256& hTx = r.second;

    CTransaction tx;
    if (!GetTransaction(iface, hTx, tx, NULL))
      continue;

		CContext *ctx = tx.GetContext();
		if (!ctx)
			continue;

    ret.push_back(Pair(ctx->GetHash().GetHex().c_str(), ctx->ToValue()));
  }

  contextlist_json = JSONRPCReply(ret, Value::null, Value::null);
  return (contextlist_json.c_str());
}

int cpp_stratum_isinitialdownload(int ifaceIndex)
{
	if (IsInitialBlockDownload(ifaceIndex))
		return (TRUE);
	return (FALSE);
}

#ifdef __cplusplus
extern "C" {
#endif

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

const char *getchaininfo(int ifaceIndex)
{
  return (c_getchaininfo(ifaceIndex));
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

const char *getaliaslist(int ifaceIndex)
{
	return (c_getaliaslist(ifaceIndex));
}

const char *getcontextlist(int ifaceIndex)
{
	return (c_getcontextlist(ifaceIndex));
}

int stratum_isinitialdownload(int ifaceIndex)
{
	return (cpp_stratum_isinitialdownload(ifaceIndex));
}

double GetNextDifficulty(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (iface == NULL)
    return (0.0);
  return (iface->blk_diff);
}

static int64_t _nExtraNonce;
extern shpeer_t *shcoind_peer(void);

unsigned int GetSiteExtraNonce()
{
  shpeer_t *peer;
  shkey_t *kpub;

  if (_nExtraNonce == 0) {
    /* generate unique site nonce. */
    peer = shcoind_peer();
    kpub = shpeer_kpub(peer);
    _nExtraNonce = (unsigned int)shcrc32(kpub, sizeof(shkey_t)); 
  }

  return (_nExtraNonce);
}

const char *GetSiteExtraNonceHex()
{
  static char ret_buf[256];
  sprintf(ret_buf, "%-8.8x", GetSiteExtraNonce());
  return ((const char *)ret_buf);
}

/* remove all pending work */
void map_work_term(void)
{

  for (work_map::const_iterator mi = mapWork.begin(); mi != mapWork.end(); ++mi) {
    CBlock *tblock = mi->second;
    unsigned int id = (unsigned int)mi->first;
    delete tblock;
  }
  mapWork.clear();

}

#ifdef __cplusplus
}
#endif

