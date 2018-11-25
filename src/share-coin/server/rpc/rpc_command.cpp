
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

static bool fHelp = false;

extern json_spirit::Value ValueFromAmount(int64 amount);
extern bool GetStratumKeyAccount(uint256 in_pkey, string& strAccount);



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

extern unsigned int GetBlockScriptFlags(CIface *iface, const CBlockIndex* pindex);
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
  obj.push_back(Pair("mintxfeerate",  ValueFromAmount(MIN_TX_FEE(iface))));
  obj.push_back(Pair("minrelaytxfee", ValueFromAmount(MIN_RELAY_TX_FEE(iface))));
  obj.push_back(Pair("maxmoney",      ValueFromAmount(iface->max_money)));
  obj.push_back(Pair("maturity",      (int)iface->coinbase_maturity));
  obj.push_back(Pair("maxsigops",     (int)iface->max_sigops));

  /* stats */
  obj.push_back(Pair("blocksubmit",  (int)iface->stat.tot_block_submit));
  obj.push_back(Pair("blockaccept",  (int)iface->stat.tot_block_accept));
  obj.push_back(Pair("blockorphan",  (int)iface->stat.tot_block_orphan));
  obj.push_back(Pair("txsubmit",     (int)iface->stat.tot_tx_submit));
  obj.push_back(Pair("txaccept",     (int)iface->stat.tot_tx_accept));
  obj.push_back(Pair("burnt-coins",  (double)iface->stat.tot_tx_return/COIN));

  {
    bc = GetBlockChain(iface);
    obj.push_back(Pair("blockfmaps", (int)bc_fmap_total(bc)));
  }
  {
    bc = GetBlockTxChain(iface); 
    obj.push_back(Pair("txfmaps", (int)bc_fmap_total(bc)));
  }

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


	CBlockIndex *pindexBest = GetBestBlockIndex(iface);
	if (pindexBest) {
		unsigned int flags = GetBlockScriptFlags(iface, pindexBest);
		string flag_str = "";

		if (flags & SCRIPT_VERIFY_P2SH)
			flag_str += "BIP16 ";
		if (iface->BIP34Height != -1 && pindexBest->nHeight >= iface->BIP34Height) {
			flag_str += "BIP34 ";
		} else if (iface->BIP30Height != -1 && pindexBest->nHeight >= iface->BIP30Height) {
			flag_str += "BIP30 ";
		}
		if (flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)
			flag_str += "BIP65 ";
		if (flags & SCRIPT_VERIFY_DERSIG)
			flag_str += "BIP66 ";
		if (flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)
			flag_str += "BIP68 ";

		if (flag_str != "") {
			obj.push_back(Pair("scriptflags", flag_str));
		}
	}

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
  add_sys_config_opt_bool(obj, OPT_ADMIN);
#ifdef RPC_SERVICE
  add_sys_config_opt_bool(obj, OPT_SERV_RPC);
  add_sys_config_opt_num(obj, OPT_RPC_PORT);
#endif
#ifdef RPC_SERVICE
  add_sys_config_opt_bool(obj, OPT_SERV_STRATUM);
  add_sys_config_opt_num(obj, OPT_STRATUM_PORT);
#endif

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
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "block.info\n"
        "Statistical and runtime information on block operations.");


  Object obj;

  obj.push_back(Pair("version",       (int)iface->proto_ver));
  obj.push_back(Pair("blockversion",  (int)iface->block_ver));
  obj.push_back(Pair("walletversion", wallet->GetVersion()));

  obj.push_back(Pair("blocks",        (int)GetBestHeight(iface)));
	if (wallet->pindexBestHeader) {
		obj.push_back(Pair("headers", wallet->pindexBestHeader->nHeight));
	}

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

	if (pindexBest) {
		CBlock *block = GetBlockByHash(iface, pindexBest->GetBlockHash());
		int nTotal = block->GetTotalBlocksEstimate();
		delete block;
		obj.push_back(Pair("checkpoint", nTotal));
	}

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

  Object ret = block->ToValue();

  ret.push_back(Pair("confirmations", 
        GetBlockDepthInMainChain(iface, block->GetHash())));
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

#if 0
  if (vNodes.empty())
    throw JSONRPCError(-9, "coin service is not connected!");

  if (IsInitialBlockDownload(ifaceIndex))
    throw JSONRPCError(-10, "coin service is downloading blocks...");
#endif

  typedef map<uint256, CBlock*> mapNewBlock_t;
  static mapNewBlock_t mapNewBlock;    // FIXME: thread safety
  static vector<CBlock*> vNewBlock;

  if (params.size() == 0)
  {
    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64 nStart;
    static CBlock* pblock;
    if (pindexPrev != GetBestBlockIndex(iface) ||
        (STAT_TX_ACCEPTS(iface) != nTransactionsUpdatedLast && GetTime() - nStart >= 15))
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


			// Update nTime
			pblock->UpdateTime(pindexPrev);
			pblock->nNonce = 0;

			// Update nExtraNonce
			core_IncrementExtraNonce(pblock, pindexPrev);

			pblock->hashMerkleRoot = pblock->BuildMerkleTree();

      vNewBlock.push_back(pblock);
		
			// Save
			mapNewBlock[pblock->hashMerkleRoot] = pblock;
    }

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
		unsigned char data[128];

    // Parse parameters
    vector<unsigned char> vchData = ParseHex(params[0].get_str());
    if (vchData.size() != 128)
      throw JSONRPCError(-8, "Invalid parameter");

		memcpy(data, vchData.data(), 128); 

    for (int i = 0; i < 128/4; i++)
      ((unsigned int*)data)[i] = ByteReverse(((unsigned int*)data)[i]);

		uint256 hMerkleRoot;
		memcpy(&hMerkleRoot, data + 36, sizeof(hMerkleRoot));

    // Get saved block
    if (!mapNewBlock.count(hMerkleRoot)) {
      return false;
		}
    CBlock* pblock = mapNewBlock[hMerkleRoot];

		/* may be multiple */
		if (pblock->hashMerkleRoot != hMerkleRoot)
			return (false);

		unsigned int nTime = *((unsigned int *)(data + 68)); 
    pblock->nTime = nTime;//pdata->nTime;
		unsigned int nNonce = *((unsigned int *)(data + 76)); 
    pblock->nNonce = nNonce;//pdata->nNonce;
//    pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
//    pblock->hashMerkleRoot = pblock->BuildMerkleTree();

    bool ok =  CheckWork(pblock, *pwalletMain);
		if (ok) {
			Debug("(%s) rpc_block_work: generated block \"%s\".", iface->name, pblock->GetHash().GetHex().c_str());
		}
		return (ok);
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
    core_IncrementExtraNonce(pblock, pindexPrev);

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

		CBlockHeader *pdata = (CBlockHeader *)vchData.data();

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

    return CheckWork(pblock, *pwalletMain);
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
  if (bind) {// && bind->peer_db) {
    BOOST_FOREACH(const CAddress &addr, vAddr) {
      sprintf(addr_str, "%s %d", addr.ToStringIP().c_str(), addr.GetPort());
      peer = shpeer_init(iface->name, addr_str);
      unet_peer_track_add(ifaceIndex, peer);
      shpeer_free(&peer);
    }
  }


  Object result;
  result.push_back(Pair("mode", "peer.importdat"));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "success"));

  return (result);
}

Value rpc_peer_export(CIface *iface, const Array& params, bool fStratum)
{
  int ifaceIndex = GetCoinIndex(iface); 
  int err;

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "peer.export <path>\n"
        "Export entire database of network peers in JSON format.");

  std::string strPath = params[0].get_str();

  err = unet_peer_export_path(ifaceIndex, (char *)strPath.c_str());
  if (err)
    throw JSONRPCError(err, "unet peer export");

  Object result;
  result.push_back(Pair("mode", "peer.export"));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "finished"));

  return (result);
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
  shjson_t *tree;
  shjson_t *node;
  shdb_t *db;
  char hostname[PATH_MAX+1];
  char errbuf[256];
  char *text;
  int total;

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "peer.import <path>\n"
        "Export entire database of network peers in JSON format.");

  std::string strPath = params[0].get_str();

  total = 0;
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

    tree = shjson_obj_get(json, "track");
    if (tree->child) {
      unet_bind_t *bind = unet_bind_table(ifaceIndex);
      if (bind) {
        for (node = tree->child; node; node = node->next) {
          char *host = shjson_astr(node, "host", "");
          char *label = shjson_astr(node, "label", "");
          if (!*host || !*label) continue;

          peer = shpeer_init(label, host);
          unet_peer_track_add(ifaceIndex, peer);
          shpeer_free(&peer);
          total++;
        }
      }
    }

    shjson_free(&json);
  }

  sprintf(errbuf, "rpc_peer_import: imported x%d %s peers.", total, iface->name);
  shcoind_log(errbuf);

  Object result;
  result.push_back(Pair("mode", "peer-import"));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("total", total));
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
  if (!bind)
    throw JSONRPCError(-5, "peer not found");

  memset(host, 0, sizeof(host));
  strncpy(host, params[0].get_str().c_str(), sizeof(host)-1);

  ptr = strchr(host, ':');
  if (ptr)
    *ptr = ' ';

  peer = shpeer_init(iface->name, host);
#if 0
  err = shnet_track_remove(bind->peer_db, peer);
  if (err) {
    shpeer_free(&peer);
    throw JSONRPCError(-5, "peer not found");
  } 
#endif
  (void)unet_peer_track_remove(ifaceIndex, peer); 

  sk = unet_peer_find(ifaceIndex, shpeer_addr(peer)); 
  shpeer_free(&peer);
  if (sk) {
    unet_shutdown(sk); 
  }

  return (Value::null);
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
    return CCoinAddr(ifaceIndex, innerID).ToString();
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

Value rpc_block_mine(CIface *iface, const Array& params, bool fStratum)
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (fHelp || params.size() > 1)
    throw runtime_error(
        "block.mine <iterations>\n"
        "Mine a block on the block-chain. (default: 10240).\n");

	uint64_t nIncr = 10240;
	if (params.size() > 0) {
		nIncr = (uint64_t)params[0].get_int();
	}

	InitServiceMinerEvent(GetCoinIndex(iface), nIncr);
	
	return (Value::null);
}




