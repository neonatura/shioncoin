
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
#include "init.h"
#include "base58.h"
#include "server_iface.h" /* BLKERR_XXX */
#include "algobits.h"
#include "stratum.h"
#include "color/color_pool.h"
#include "color/color_block.h"

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

#define MAX_NONCE_SEQUENCE 4

typedef map<unsigned int, CBlock*> work_map;

/* blocks generated by a coin service. */
map<const uint256, CBlockIndex *> vGenBlocks[MAX_COIN_IFACE];

static work_map mapWork;
static CCriticalSection cs_mapWork;


extern string JSONRPCReply(const Value& result, const Value& error, const Value& id);

#ifdef __cplusplus
extern "C" {
#endif

static std::string HexBits(unsigned int nBits)
{
	union {
		int32_t nBits;
		char cBits[4];
	} uBits;
	uBits.nBits = htonl((int32_t)nBits);
	return HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}

static double GetBitsDifficulty(unsigned int nBits)
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

/**
 * Generate a block to work on.
 * @returns JSON encoded block state information
 */
shjson_t *stratum_miner_getblocktemplate(int ifaceIndex, int nAlg)
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

  if (IsInitialBlockDownload(ifaceIndex))
    return (NULL);
#if 0
  if (iface->blockscan_max > pindexPrev->nHeight)
    return (NULL); /* downloading blocks */
#endif

	{
		LOCK(cs_mapWork);

		/* prune stale worker blocks (see SHC_MAX_DRIFT_TIME) */
		vector<unsigned int> vDelete;
		time_t timeExpire = GetAdjustedTime() - 1440;
		for (work_map::const_iterator mi = mapWork.begin(); mi != mapWork.end(); ++mi) {
			CBlock *tblock = mi->second;
			if (tblock->nTime < timeExpire) {
				unsigned int id = (unsigned int)mi->first;
				vDelete.push_back(id);
	//      delete tblock;
			}
		}
		BOOST_FOREACH (unsigned int id, vDelete) {
			if (mapWork.count(id) == 0)
				continue;
			CBlock *tblock = mapWork[id];
			mapWork.erase(id);
			delete tblock;
		}
	}
  
  nHeight = pindexPrev->nHeight + 1;

  pblock = NULL;
	{
		CWallet *wallet = GetWallet(ifaceIndex); 
		if (wallet) {
			LOCK(wallet->cs_wallet);
			try {
				pblock = CreateBlockTemplate(iface);
			} catch (std::exception& e) {
				error(SHERR_INVAL, "c_getblocktemplate: CreateBlockTemplate: %s", e.what()); 
		 }
		}
	}
  if (!pblock) {
    error(SHERR_INVAL, "c_getblocktemplate: error creating block template."); 
    return (NULL);
	}

  // Update nTime
  pblock->UpdateTime(pindexPrev);
  pblock->nNonce = 0;

	/* apply miner PoW algo. */
	switch (nAlg) {
		case ALGO_SCRYPT:
			/* retain */
			iface->blk_diff = GetBitsDifficulty(pblock->nBits);
			break;

		case ALGO_SHA256D:
		case ALGO_KECCAK:
		case ALGO_X11:
		case ALGO_BLAKE2S:
		case ALGO_QUBIT:
		case ALGO_GROESTL:
		case ALGO_SKEIN:
			/* set algo version. */
		  pblock->nVersion = GetAlgoBits(nAlg);
			pblock->nBits = pblock->GetNextWorkRequired(pindexPrev);
#if 0
			/* set difficulty for algo. */
			CBigNum diff;
			diff.SetCompact(pblock->nBits);
			diff /= GetAlgoWorkFactor(nAlg);
			pblock->nBits = diff.GetCompact();
#endif

			/* update merkle root. */
			pblock->hashMerkleRoot = pblock->BuildMerkleTree();
			break;
	}

  /* store "worker" block for until height increment. */
  work_id++;
	if (work_id >= 0xFFFFFF)
		work_id = 1;
	{
		LOCK(cs_mapWork);
		mapWork[work_id] = pblock; 
	}

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

#if 0
  /* dummy nExtraNonce */
  SetExtraNonce(pblock, "f0000000f0000000");
#endif

  /* coinbase */
  CTransaction coinbaseTx = pblock->vtx[0];
  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface) | SERIALIZE_TRANSACTION_NO_WITNESS);
  ssTx << coinbaseTx;
  result.push_back(Pair("coinbase", HexStr(ssTx.begin(), ssTx.end())));
  //  result.push_back(Pair("sigScript", HexStr(pblock->vtx[0].vin[0].scriptSig.begin(), pblock->vtx[0].vin[0].scriptSig.end())));
  CScript COINBASE_FLAGS = GetCoinbaseFlags(pblock->ifaceIndex);
  result.push_back(Pair("coinbaseflags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

	return (shjson_init((char *)JSONRPCReply(result, Value::null, Value::null).c_str()));
}

int64 stratum_miner_minerblockvalue(int ifaceIndex, const CWalletTx& wtx)
{
  int64 nGeneratedImmature, nGeneratedMature;

	nGeneratedImmature = 0;
	nGeneratedMature = 0;
  wtx.GetAmounts(ifaceIndex, nGeneratedImmature, nGeneratedMature);

  /* generated blocks assigned to account "". */
	return (nGeneratedMature);
}

shjson_t *stratum_miner_lastminerblock(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
  uint256 retHash;
  int64 retValue;
  int64 nTime;

	if (!iface || !iface->enabled)
		return (NULL);

  retHash = 0;
  retValue = 0;

  nTime = 0;
  for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
  {
    const CWalletTx& wtx = (*it).second;

    if (wtx.nTimeReceived < nTime)
      continue;

    if (!wtx.IsCoinBase())
      continue;

    int64 nValue = stratum_miner_minerblockvalue(ifaceIndex, wtx);
    if (nValue == 0)
      continue;

    retHash = wtx.GetHash();
    retValue = nValue;

    nTime = wtx.nTimeReceived;
  }
  if (retValue == 0) 
    return (NULL);

	uint256 hTx = retHash;
	CTransaction t_tx;
	if (!GetTransaction(iface, hTx, t_tx, &retHash))
		return (NULL);

  shjson_t *tree = shjson_init(NULL);
  shjson_str_add(tree, "txhash", (char *)hTx.GetHex().c_str());
  shjson_str_add(tree, "blockhash", (char *)retHash.GetHex().c_str());
  shjson_num_add(tree, "amount", (double)retValue / COIN);
  shjson_str_add(tree, "category", "generate");
  shjson_num_add(tree, "time", nTime);
  return (tree);
}

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

int stratum_miner_submitblock(unsigned int workId, unsigned int nTime, unsigned int nNonce, char *xn_hex, char *ret_hash, double *ret_diff)
{
	static char errbuf[1024];
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

	{
		LOCK(cs_mapWork);

		if (mapWork.count(workId) == 0) {
			return (SHERR_TIME); /* task is stale */
		}

		pblock = mapWork[workId];
	}

  if (pblock->nNonce == nNonce) {
    /* same as last nonce submitted */
    return (SHERR_ALREADY);
  }

  CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
  if (!iface || !iface->enabled)
    return (SHERR_OPNOTSUPP); /* sanity */

  pblock->nTime = nTime;
  pblock->nNonce = nNonce;

  core_SetExtraNonce(pblock, xn_hex);
//pblock->hashMerkleRoot = pblock->BuildMerkleTree();

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

  if (idx == MAX_NONCE_SEQUENCE) {
    /* retain for dup check */
    pblock->nNonce = nNonce;
 
		Debug("(%s) submitblock: share received (nonce: %u) (workid: %u).", iface->name, nNonce, workId);
  } else {
    err = c_processblock(pblock);
    if (!err) {
      string submit_block_hash = pblock->GetHash().GetHex();
      if (ret_hash)
        strcpy(ret_hash, submit_block_hash.c_str());

      sprintf(errbuf, "(%s) submitblock: mined block (%s) generated %s coins.", iface->name, submit_block_hash.c_str(), FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());
      shcoind_log(errbuf);
    } else {
      shcoind_err(err, iface->name, "submit block");
    }
  }

  return (0);
}

int is_stratum_miner_algo(int ifaceIndex, int nAlg)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(ifaceIndex); 
	CBlockIndex *pindexPrev = NULL;

	if (!wallet)
		return (FALSE);

	if (ifaceIndex == TESTNET_COIN_IFACE) {
#ifdef TESTNET_SERVICE
		if (!opt_bool(OPT_STRATUM_TESTNET))
			return (FALSE);
#else
		return (FALSE);	
#endif
	}

	uint160 hColor = 0;
	if (ifaceIndex == COLOR_COIN_IFACE) {
#if 0 /* not supported yet. requires custom processblock handling. */
		const char *opt_val = opt_str(OPT_STRATUM_COLOR);
		if (!opt_val || !*opt_val)
			return (FALSE);

		hColor = uint160(string(opt_val));
		if (hColor == 0)
			return (FALSE);

		CIface *alt_iface = GetCoinByIndex(SHC_COIN_IFACE);
		pindexPrev = GetBestColorBlockIndex(alt_iface, hColor);
#endif
		return (FALSE);
	} else {
		pindexPrev = GetBestBlockIndex(iface);
	}

	if (nAlg != ALGO_SCRYPT) {
		if (!pindexPrev || 
				!wallet->IsAlgoSupported(nAlg, pindexPrev, hColor)) {
			/* not supported by coin service. */
			return (FALSE);
		}
	}

	switch (nAlg) {
		case ALGO_SHA256D:
			if (!opt_bool(OPT_STRATUM_SHA256D))
				return (FALSE);
			break;
		case ALGO_KECCAK:
			if (!opt_bool(OPT_STRATUM_KECCAK))
				return (FALSE);
			break;
		case ALGO_X11:
			if (!opt_bool(OPT_STRATUM_X11))
				return (FALSE);
			break;
		case ALGO_BLAKE2S:
			if (!opt_bool(OPT_STRATUM_BLAKE2S))
				return (FALSE);
			break;
		case ALGO_QUBIT:
			if (!opt_bool(OPT_STRATUM_QUBIT))
				return (FALSE);
			break;
		case ALGO_GROESTL:
			if (!opt_bool(OPT_STRATUM_GROESTL))
				return (FALSE);
			break;
		case ALGO_SKEIN:
			if (!opt_bool(OPT_STRATUM_SKEIN))
				return (FALSE);
			break;
	}

	return (TRUE);
}

void add_stratum_miner_block(int ifaceIndex, char *block_hash)
{
	uint256 hBlock(block_hash);
	CBlockIndex *pindex;
	
	pindex = GetBlockIndexByHash(ifaceIndex, hBlock);
	if (!pindex) {
    shcoind_log("add_stratum_miner_block: unknown block hash specified.");
		return;
	}

	if (vGenBlocks[ifaceIndex].count(hBlock) == 0)
		vGenBlocks[ifaceIndex][hBlock] = pindex;
}

CBlockIndex *get_stratum_miner_block(int ifaceIndex, uint256 hBlock)
{

	if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
		return (NULL);

	if (vGenBlocks[ifaceIndex].count(hBlock) == 0)
		return (NULL);

	return (vGenBlocks[ifaceIndex][hBlock]);
}

vector<CBlockIndex *> get_stratum_miner_blocks(int ifaceIndex)
{
	vector<CBlockIndex *> vRet;

	if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
		return (vRet);

	BOOST_FOREACH(PAIRTYPE(const uint256, CBlockIndex *)& item, vGenBlocks[ifaceIndex]) {
		vRet.push_back(item.second);
	}

	return (vRet);
}

int stratum_miner_extranonce_subscribe(CIface *iface, user_t *user, shjson_t *param, shjson_t **reply_p)
{
	user->flags |= USER_EXTRANONCE;
	return (0);
}

int stratum_miner_get_transactions(CIface *iface, user_t *user, shjson_t *param, shjson_t **reply_p)
{
  CBlock *pblock;
	shjson_t *tx_list;
	shjson_t *reply;
	unsigned int workId;
	char *str;
  int err;

	str = shjson_array_str(param, NULL, 0);
	if (!str)
		return (ERR_NOENT);
	workId = (unsigned int)strtoul(str, NULL, 16);
  if (mapWork.count(workId) == 0)
		return (ERR_NOENT);

  pblock = mapWork[workId];
  iface = GetCoinByIndex(pblock->ifaceIndex);
  if (!iface || !iface->enabled)
		return (ERR_OPNOTSUPP);

	reply = shjson_init(NULL); 
	shjson_null_add(reply, "error");
	tx_list = shjson_array_add(reply, "result");
  BOOST_FOREACH (CTransaction& tx, pblock->vtx)
  {
    if (tx.IsCoinBase())
      continue;

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface));
    ssTx << tx;
		shjson_str_add(tx_list, NULL, 
				(char *)HexStr(ssTx.begin(), ssTx.end()).c_str());
  }

	*reply_p = reply;
	return (0);
}

#ifdef __cplusplus
}
#endif

