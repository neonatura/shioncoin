
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

#include "shcoind.h"
#include "block.h"
#include "db.h"
#include <vector>
#include "spring.h"
#include "versionbits.h"
#include "wit_merkle.h"
#include "txmempool.h"
#include "coin.h"
#include "wallet.h"
#include "algobits.h"
#include "keccak.h"
#include "x11.h"
#include "blake2.h"
#include "qubit.h"
#include "groestl.h"
#include "skein.h"
#include "bolo/bolo_validation03.h"

using namespace std;

#define MAX_BLOCK_DOWNLOAD_TIME 1296000 /* 15d */

#define DEFAULT_PARAM_LIFESPAN 2592000 /* 30d */ 

#define MAX_OPCODE(_iface) \
	(0xf9)

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static const unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);
/** Use GetMedianTimePast() instead of nTime for end point timestamp. */
static const unsigned int LOCKTIME_MEDIAN_TIME_PAST = (1 << 1);

static const unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS = 
		LOCKTIME_VERIFY_SEQUENCE |
		LOCKTIME_MEDIAN_TIME_PAST;



blkidx_t tableBlockIndex[MAX_COIN_IFACE];

extern double GetDifficulty(int ifaceIndex, const CBlockIndex* blockindex = NULL);
extern std::string HexBits(unsigned int nBits);
extern void ScriptPubKeyToJSON(int ifaceIndex, const CScript& scriptPubKey, Object& out);
extern bool color_GetBlockColor(CIface *iface, CBlockIndex *pindex, uint160& hColor);



blkidx_t *GetBlockTable(int ifaceIndex)
{
#ifndef TEST_SHCOIND
  if (ifaceIndex == 0)
    return (NULL);
#endif
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  return (&tableBlockIndex[ifaceIndex]);
}

void CloseBlockChain(CIface *iface)
{
  if (iface->bc_block) {
    bc_close(iface->bc_block);
    iface->bc_block = NULL;
  }
  if (iface->bc_tx) {
    bc_close(iface->bc_tx);
    iface->bc_tx = NULL;
  }
  if (iface->bc_coin) {
    bc_close(iface->bc_coin);
    iface->bc_coin = NULL;
  }
}

CBlockIndex *GetBlockIndexByHeight(int ifaceIndex, unsigned int nHeight)
{
  CBlockIndex *pindex;

  pindex = GetBestBlockIndex(ifaceIndex);
  while (pindex && pindex->pprev && pindex->nHeight > nHeight)
    pindex = pindex->pprev;

  return (pindex);
}

CBlockIndex *GetBlockIndexByHash(int ifaceIndex, const uint256 hash)
{
  CBlockIndex *pindex;
  blkidx_t *blockIndex;

  blockIndex = GetBlockTable(ifaceIndex);
  if (!blockIndex)
    return (NULL);

  blkidx_t::iterator mi = blockIndex->find(hash);
  if (mi == blockIndex->end())
    return (NULL);

  return (mi->second);
}

json_spirit::Value ValueFromAmount(int64 amount)
{
	return (double)amount / (double)COIN;
}

void FreeBlockTable(CIface *iface)
{
  blkidx_t *blockIndex;
  char errbuf[1024];
  size_t memsize;
  size_t count;
  int ifaceIndex = GetCoinIndex(iface);

  blockIndex = GetBlockTable(ifaceIndex);
  if (!blockIndex)
    return;

  vector<CBlockIndex *> removeList;
  BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, (*blockIndex)) 
  {
    CBlockIndex* pindex = item.second;
    removeList.push_back(pindex);
  }
  blockIndex->clear();

  count = 0;
  memsize = 0;
  BOOST_FOREACH(const CBlockIndex *pindex, removeList) 
  {
    memsize += sizeof(*pindex);
    count++;
    delete pindex;
  }

  if (iface->enabled) {
    sprintf(errbuf, "FreeBlockTable: deallocated %d records (%d bytes) in block-index.", count, memsize);
    unet_log(ifaceIndex, errbuf);
  }

}

/**
 * Closes all open block record databases.
 */
void CloseBlockChains(void)
{
  CIface *iface;
  int idx;

  for (idx = 0; idx < MAX_COIN_IFACE; idx++) {
#ifndef TEST_SHCOIND
    if (idx == 0) continue;
#endif

    iface = GetCoinByIndex(idx);
    if (!iface)
      continue;

    FreeBlockTable(iface);
    CloseBlockChain(iface);
  }
}

int64 GetInitialBlockValue(int nHeight, int64 nFees)
{
  int64 nSubsidy = 4000 * COIN;

  if ((nHeight % 100) == 1)
  {
    nSubsidy = 100000 * COIN; //100k
  }else if ((nHeight % 50) == 1)
  {
    nSubsidy = 50000 * COIN; //50k
  }else if ((nHeight % 20) == 1)
  {
    nSubsidy = 20000 * COIN; //20k
  }else if ((nHeight % 10) == 1)
  {
    nSubsidy = 10000 * COIN; //10k
  }else if ((nHeight % 5) == 1)
  {
    nSubsidy = 5000 * COIN; //5k
  }

  /* limit first blocks to protect against instamine. */
  if (nHeight < 2){
    nSubsidy = 24000000 * COIN; // 1.5%
  }else if(nHeight < 500)
  {
    nSubsidy = 100 * COIN;
  }
  else if(nHeight < 1000)
  {
    nSubsidy = 500 * COIN;
  }

  nSubsidy >>= (nHeight / 139604);

  return (nSubsidy + nFees);
}

const CTransaction *CBlock::GetTx(uint256 hash)
{
  BOOST_FOREACH(const CTransaction& tx, vtx)
    if (tx.GetHash() == hash)
      return (&tx);
  return (NULL);
}

bool CTransaction::WriteTx(int ifaceIndex, uint64_t blockHeight)
{
  bc_t *bc = GetBlockTxChain(GetCoinByIndex(ifaceIndex));
  uint256 hash = GetHash();
  char errbuf[1024];
  uint64_t blockPos;
  int txPos;
  int err;

  if (!bc) {
    unet_log(ifaceIndex, "CTransaction::WriteTx: error opening tx chain.");
    return (false);
  }

  err = bc_idx_find(bc, hash.GetRaw(), NULL, &txPos);
  if (!err) { /* exists */
    unsigned char *data;
    size_t data_len;

    err = bc_get(bc, txPos, &data, &data_len);
    if (!err) {
      if (data_len == sizeof(uint64_t)) {
        memcpy(&blockPos, data, sizeof(blockHeight));
        if (blockPos == blockHeight)
          return (true); /* and all is good */
      }
      free(data);

    } else {

    /* force re-open */
      CIface *iface = GetCoinByIndex(ifaceIndex);
      CloseBlockChain(iface);
      CloseBlockChain(iface);

      return (false);
    }
  }

  /* reference block height */
  err = bc_append(bc, hash.GetRaw(), &blockHeight, sizeof(blockHeight));
  if (err < 0) {
    sprintf(errbuf, "CTransaction::WriteTx: error writing block reference: %s.", sherrstr(err));
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

  return (true);
}

bool CTransaction::ReadTx(int ifaceIndex, uint256 txHash)
{
  return (ReadTx(ifaceIndex, txHash, NULL));
}


bool CTransaction::ReadTx(int ifaceIndex, uint256 txHash, uint256 *hashBlock)
{
  CIface *iface;
  bc_t *bc;
  char errbuf[1024];
  unsigned char *data;
  uint64_t blockHeight;
  size_t data_len;
  int txPos;
  int err;

  SetNull();

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface) {
    sprintf(errbuf, "CTransaction::ReadTx: unable to obtain iface #%d.", ifaceIndex); 
    return error(SHERR_INVAL, errbuf);
  }

  bc = GetBlockTxChain(iface);
  if (!bc) { 
    return error(SHERR_INVAL, "CTransaction::ReadTx: unable to open block tx database."); 
  }

  err = bc_idx_find(bc, txHash.GetRaw(), NULL, &txPos); 
  if (err) {
    return (false); /* not an error condition */
  }

  err = bc_get(bc, txPos, &data, &data_len);
  if (err) {
    sprintf(errbuf, "CTransaction::ReadTx: tx position %d not found.", txPos);
    return error(err, errbuf);
  }
  if (data_len != sizeof(uint64_t)) {
    sprintf(errbuf, "CTransaction::ReadTx: block reference has invalid size (%d).", data_len);
    free(data);
    return error(SHERR_INVAL, errbuf);
  }
  memcpy(&blockHeight, data, sizeof(blockHeight));
  free(data);

  CBlock *block = GetBlankBlock(iface);
  if (!block) { 
    return error(SHERR_NOMEM, 
        "CTransaction::ReadTx: error allocating new block\n");
  }
  if (!block->ReadBlock(blockHeight)) {
    delete block;
    return error(SHERR_NOENT, "CTransaction::ReadTx: block height %d not valid.", blockHeight);
  }

  const CTransaction *tx = block->GetTx(txHash);
  if (!tx) {
    sprintf(errbuf, "CTransaction::ReadTx: block height %d does not contain tx '%s'.", blockHeight, txHash.GetHex().c_str());
    delete block;
    return error(SHERR_INVAL, errbuf);
  }

  if (hashBlock) {
    *hashBlock = block->GetHash();
  }

  Init(*tx);
  delete block;

  return (true);
}



bool GetTransaction(CIface *iface, const uint256 &hash, CTransaction &tx, uint256 *hashBlock)
{
  return (tx.ReadTx(GetCoinIndex(iface), hash, hashBlock));
}

CBlock *GetBlockByHeight(CIface *iface, int nHeight)
{
  int ifaceIndex = GetCoinIndex(iface);
  CTransaction tx;
  CBlock *block;
  int err;
  
  /* sanity */
  if (!iface)
    return (NULL);

  block = GetBlankBlock(iface);
  if (!block)
    return (NULL);

  if (!block->ReadBlock(nHeight))
    return (NULL);

  return (block);
}

bool HasBlockHash(CIface *iface, uint256 hash)
{
  bc_t *bc;
  bcpos_t nHeight;
  int err;

  if (!iface || !iface->enabled)
    return (false);

  bc = GetBlockChain(iface);
  if (!bc)
    return (false);

  err = bc_find(bc, hash.GetRaw(), &nHeight);
  if (err)
    return false;

  return (true);
}

CBlock *GetBlockByHash(CIface *iface, const uint256 hash)
{
  int ifaceIndex = GetCoinIndex(iface);
  CBlockIndex *pindex;
  CTransaction tx;
  CBlock *block;
  int err;
  
  /* sanity */
  if (!iface)
    return (NULL);

  pindex = GetBlockIndexByHash(ifaceIndex, hash);
  if (!pindex)
    return (NULL);

  /* generate block */
  block = GetBlankBlock(iface);
  if (!block)
    return (NULL);

  if (!block->ReadFromDisk(pindex))
    return (NULL);

  /* verify integrity */
  if (block->GetHash() != hash)
    return (NULL);

	if (ifaceIndex == COLOR_COIN_IFACE)
		color_GetBlockColor(iface, pindex, block->hColor);

  return (block);
}

CBlock *GetArchBlockByHash(CIface *iface, const uint256 hash)
{
  CBlock *block;
  int err;
  
  /* sanity */
  if (!iface)
    return (NULL);

  /* generate block */
  block = GetBlankBlock(iface);
  if (!block)
    return (NULL);

  if (!block->ReadArchBlock(hash)) {
    delete block;
    return (NULL);
  }

  return (block);
}

CBlock *GetBlockByTx(CIface *iface, const uint256 hash)
{
  int ifaceIndex = GetCoinIndex(iface);
  CTransaction tx;
  CBlock *block;
  uint256 hashBlock;

  /* sanity */
  if (!iface)
    return (NULL);

  /* figure out block hash */
  if (!tx.ReadTx(GetCoinIndex(iface), hash, &hashBlock))
    return (NULL);

  return (GetBlockByHash(iface, hashBlock));
}

CBlockIndex *GetBlockIndexByTx(CIface *iface, const uint256 hash)
{
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
  CTransaction tx;
  CBlock *block;
  uint256 hashBlock;

  /* sanity */
  if (!iface)
    return (NULL);

  /* figure out block hash */
  if (!tx.ReadTx(GetCoinIndex(iface), hash, &hashBlock))
    return (NULL);

  map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hashBlock);
  if (mi == blockIndex->end()) 
    return (NULL);

  return (mi->second);
}

CBlock *CreateBlockTemplate(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  CBlock *block;
  char errbuf[256];
  int err;

  if (!iface->op_block_templ)
    return (NULL);

  block = NULL;
  err = iface->op_block_templ(iface, &block); 
  if (err) {
    sprintf(errbuf, "CreateBlockTemplate: error creating block template: %s.", sherrstr(err));
    unet_log(ifaceIndex, errbuf);
  }

  return (block);
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
  int err;

  if (!iface)
    return (false);

  if (!iface->op_block_process)
    return error(SHERR_OPNOTSUPP, "ProcessBlock[%s]: no block process operation suported.", iface->name);

  /* trace whether remote host submitted block */
  pblock->originPeer = pfrom;

  err = iface->op_block_process(iface, pblock);
  if (err) {
    char errbuf[1024];

    sprintf(errbuf, "error processing incoming block: %s [sherr %d].", sherrstr(err), err); 
    unet_log(pblock->ifaceIndex, errbuf);
    return (false);
  }

  return (true);
}




/* no longer used */
bool CTransaction::ClientConnectInputs(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTxMemPool *pool;

  if (!iface) {
    unet_log(ifaceIndex, "error obtaining coin interface.");
    return (false);
  }

  pool = GetTxMemPool(iface);
  if (!pool) {
    unet_log(ifaceIndex, "error obtaining tx memory pool.");
    return (false);
  }

  if (IsCoinBase())
    return false;

  // Take over previous transactions' spent pointers
  {
    int64 nValueIn = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
      // Get prev tx from single transactions in memory
      COutPoint prevout = vin[i].prevout;
      if (!pool->exists(prevout.hash))
        return false;
      CTransaction& txPrev = pool->lookup(prevout.hash);

      if (prevout.n >= txPrev.vout.size())
        return false;

      // Verify signature
      if (!VerifySignature(ifaceIndex, txPrev, *this, i, true, 0))
        return error(SHERR_INVAL, "ConnectInputs() : VerifySignature failed");

      nValueIn += txPrev.vout[prevout.n].nValue;

      if (!MoneyRange(ifaceIndex, txPrev.vout[prevout.n].nValue) || 
          !MoneyRange(ifaceIndex, nValueIn))
        return error(SHERR_INVAL, "ClientConnectInputs() : txin values out of range");
    }
    if (GetValueOut() > nValueIn)
      return false;
  }

  return true;
}

bool CBlockIndex::IsInMainChain(int ifaceIndex) const
{
	return (nStatus & BLOCK_HAVE_DATA);
}

int GetBestHeight(CIface *iface)
{
  CBlockIndex *pindex = GetBestBlockIndex(iface);
  if (!pindex)
    return (-1);
  return (pindex->nHeight);
}
int GetBestHeight(int ifaceIndex)
{
  return (GetBestHeight(GetCoinByIndex(ifaceIndex)));
}

bool IsInitialBlockDownload(int ifaceIndex)
{

	if (ifaceIndex == COLOR_COIN_IFACE ||
			ifaceIndex == TESTNET_COIN_IFACE)
		return (false);

	CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
	if (pindexBest == NULL)
		return (true);

	CWallet *wallet = GetWallet(ifaceIndex);
	if (!wallet || !wallet->pindexBestHeader)
		return (false);

	if (wallet->pindexBestHeader->nTime > pindexBest->nTime &&
			(wallet->pindexBestHeader->nTime - pindexBest->nTime) > MAX_BLOCK_DOWNLOAD_TIME) {
		return (true);
	}

	return (false);
}

uint256 GetBestBlockChain(CIface *iface)
{
  uint256 hash;
  hash.SetRaw(iface->block_besthash);
  return (hash);
}

/* @note function not compatible with colored coins. */
CBlockIndex *GetGenesisBlockIndex(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  CBlock *block = GetBlockByHeight(iface, 0);
  if (!block)
    return (NULL);

  uint256 hash = block->GetHash();
  delete block;

  return (GetBlockIndexByHash(ifaceIndex, hash));
}

void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
	if (!pindexPrev) {
		nTime = GetAdjustedTime();
		return;
	}

  nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());
  nTime = max(nTime, pindexPrev->nTime);
}

bool CTransaction::IsFinal(int ifaceIndex, int nBlockHeight, int64 nBlockTime) const
{
  // Time based nLockTime implemented in 0.1.6
  if (nLockTime == 0)
    return true;
  if (nBlockHeight == 0)
    nBlockHeight = GetBestHeight(ifaceIndex);
  if (nBlockTime == 0)
    nBlockTime = GetAdjustedTime();
  if ((int64)nLockTime < ((int64)nLockTime < LOCKTIME_THRESHOLD ? (int64)nBlockHeight : nBlockTime))
    return true;
  BOOST_FOREACH(const CTxIn& txin, vin)
    if (!txin.IsFinal())
      return false;
  return true;
}

bool CheckFinalTx(CIface *iface, const CTransaction& tx, CBlockIndex *pindexPrev, int flags)
{
	int64 nBlockTime;
	int nHeight = 0;

	if (!pindexPrev)
		pindexPrev = GetBestBlockIndex(iface);
	if (!pindexPrev)
		return (false);

	nHeight = pindexPrev->nHeight + 1;

	if (flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) { /* BIP68 */
		nBlockTime = pindexPrev->GetMedianTimePast(); /* BIP113 */
	} else {
		nBlockTime = GetAdjustedTime();
	}

	return (tx.IsFinal(GetCoinIndex(iface), nHeight, nBlockTime));
}


void SetBestBlockIndex(CIface *iface, CBlockIndex *pindex)
{
  if (!pindex)
    return;
  uint256 hash = pindex->GetBlockHash();
  memcpy(iface->block_besthash, hash.GetRaw(), sizeof(bc_hash_t));
}
void SetBestBlockIndex(int ifaceIndex, CBlockIndex *pindex)
{
  SetBestBlockIndex(GetCoinByIndex(ifaceIndex), pindex);
}
CBlockIndex *GetBestBlockIndex(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  uint256 hash;

  hash.SetRaw(iface->block_besthash);
  return (GetBlockIndexByHash(ifaceIndex, hash));
}
CBlockIndex *GetBestBlockIndex(int ifaceIndex)
{
  return (GetBestBlockIndex(GetCoinByIndex(ifaceIndex)));
}

CBlock *GetBlankBlock(CIface *iface)
{
  CBlock *block;
  int err;

  if (!iface || !iface->op_block_new)
    return (NULL);

  block = NULL;
  err = iface->op_block_new(iface, &block);
  if (err) {
    int ifaceIndex = GetCoinIndex(iface);
    char errbuf[1024];

    sprintf(errbuf, "GetBlankBlock: error generating fresh block: %s [sherr %d].", sherrstr(err), err);
    unet_log(ifaceIndex, errbuf); 
  }

  return (block);
}

/* TODO: faster to read via nHeight */
bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc;
  bcpos_t nHeight;
  int err;

  if (!iface)
    return (false);

  bc = GetBlockChain(iface);
  if (!bc)
    return (false);

  err = bc_find(bc, pindex->GetBlockHash().GetRaw(), &nHeight);
  if (err)
    return false;

  return (ReadBlock(nHeight));
}

static bool tx_HasValidOps(CIface *iface, const CScript& script)
{
	CScript::const_iterator it = script.begin();

	while (it < script.end()) {
		opcodetype opcode;
		std::vector<unsigned char> item;
		if (!script.GetOp(it, opcode, item) || 
				opcode > MAX_OPCODE(iface) || 
				item.size() > MAX_SCRIPT_ELEMENT_SIZE(iface)) { 
			return (false);
		}
	}

	return (true);
}

bool CTransaction::CheckTransaction(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!iface)
    return (false);

  // Basic checks that don't depend on any context
  if (vin.empty())
    return error(SHERR_INVAL, "CTransaction::CheckTransaction() : vin empty: %s", ToString(ifaceIndex).c_str());
  if (vout.empty())
    return error(SHERR_INVAL, "CTransaction::CheckTransaction() : vout empty");
  // Size limits
  if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION(iface)) > iface->max_block_size)
    return error(SHERR_INVAL, "CTransaction::CheckTransaction() : size limits failed");

  // Check for negative or overflow output values
  int64 nValueOut = 0;
  BOOST_FOREACH(const CTxOut& txout, vout)
  {
    if (txout.nValue < 0)
      return error(SHERR_INVAL, "CTransaction.CheckTransaction: invalid coin output [negative value]: %s", ToString(ifaceIndex).c_str());
    if (txout.nValue > iface->max_money)
      return error(SHERR_INVAL, "CTransaction::CheckTransaction() : txout.nValue too high");
    nValueOut += txout.nValue;
    if (!MoneyRange(ifaceIndex, nValueOut))
      return error(SHERR_INVAL, "CTransaction::CheckTransaction() : txout total out of range");
		if (!tx_HasValidOps(iface, txout.scriptPubKey))
			return (ERR_2BIG, "(%s) CTransaction.CheckTransaction: output script is invalid: %s", iface->name, txout.scriptPubKey.ToString().c_str());
		if (txout.scriptPubKey.size() > MAX_SCRIPT_SIZE(iface))
			return (ERR_2BIG, "(%s) CTransaction.CheckTransaction: output script <%d bytes> exceeds maximum length (%d).", iface->name, (int)txout.scriptPubKey.size(), MAX_SCRIPT_SIZE(iface));
  }

  // Check for duplicate inputs
  set<COutPoint> vInOutPoints;
  BOOST_FOREACH(const CTxIn& txin, vin)
  {
    if (vInOutPoints.count(txin.prevout)) {
      return error(SHERR_INVAL, "CTransaction::CheckTransaction: duplicate input specified.\n");
}
    vInOutPoints.insert(txin.prevout);
  }

  if (IsCoinBase())
  {
    if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
      return error(SHERR_INVAL, "CTransaction::CheckTransaction() : coinbase script size invalid (2 < (%d) < 100)", vin[0].scriptSig.size());
  }
  else
  {
    BOOST_FOREACH(const CTxIn& txin, vin) {
      if (txin.prevout.IsNull()) {
        return error(SHERR_INVAL, "(core) CheckTransaction: prevout is null");
      }

			if (!tx_HasValidOps(iface, txin.scriptSig))
				return (ERR_2BIG, "(%s) CTransaction.CheckTransaction: input script is invalid: %s", iface->name, txin.scriptSig.ToString().c_str());
			if (txin.scriptSig.size() > MAX_SCRIPT_SIZE(iface))
				return (ERR_2BIG, "(%s) CTransaction.CheckTransaction: input script <%d bytes> exceeds maximum length (%d).", iface->name, (int)txin.scriptSig.size(), MAX_SCRIPT_SIZE(iface));
    }
  }

  return true;
}

/**
 * Verify that the transactions being referenced as inputs are valid.
 */
bool CTransaction::CheckTransactionInputs(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!iface)
    return (false);

  if (IsCoinBase())
    return (true);

  if (vin.empty())
    return error(SHERR_INVAL, "(core) CheckTransaction: vin empty: %s", ToString(ifaceIndex).c_str());

  BOOST_FOREACH(const CTxIn& txin, vin) {
    if (txin.prevout.IsNull()) {
      return error(SHERR_INVAL, "(core) CheckTransactionInputs: prevout is null");
    }

    if (!VerifyTxHash(iface, txin.prevout.hash)) {
      return error(SHERR_INVAL, "(core) CheckTransactionInputs: unknown prevout hash '%s'", txin.prevout.hash.GetHex().c_str());
    }
  }

  return true;
}

bool CBlock::CheckTransactionInputs(int ifaceIndex)
{

  BOOST_FOREACH(CTransaction& tx, vtx) {
    bool fInBlock = false;
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
      BOOST_FOREACH(const CTransaction& t_tx, vtx) {
        if (tx != t_tx && t_tx.GetHash() == txin.prevout.hash) {
          fInBlock = true;
          break;
        }
      }
    }
    if (fInBlock)
      continue;

    if (!tx.CheckTransactionInputs(ifaceIndex))
      return (false);
  }

  return (true);
}

bool CBlock::WriteBlock(uint64_t nHeight)
{
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockChain(iface);
  uint64_t idx_next;
  unsigned int blockPos;
  long sBlockLen;
  char *sBlockData;
  int n_height;
  int err;

  if (!bc)
    return (false);

  uint256 hash = GetHash();

  /* check for existing record saved at height position */
  bc_hash_t rawhash;
  err = bc_get_hash(bc, (bcsize_t)nHeight, rawhash); 
  if (!err) { /* exists */
    uint256 t_hash;
    t_hash.SetRaw(rawhash);
    if (t_hash == hash)
      return (true); /* same hash as already written block */
    err = bc_clear(bc, nHeight);
    if (err)
      return error(err, "WriteBlock: clear block position %d.", (int)nHeight);
    bc_table_reset(bc, rawhash);
  }

  /* serialize into binary */
  sBlock << *this;
  sBlockLen = sBlock.size();
  sBlockData = (char *)calloc(sBlockLen, sizeof(char));
  if (!sBlockData)
    return error(SHERR_NOMEM, "allocating %d bytes for block data\n", (int)sBlockLen);
  sBlock.read(sBlockData, sBlockLen);
  n_height = bc_write(bc, nHeight, hash.GetRaw(), sBlockData, sBlockLen);
  if (n_height < 0)
    return error(SHERR_INVAL, "block-chain write: %s", sherrstr(n_height));
  free(sBlockData);

  /* write tx ref's */
  BOOST_FOREACH(CTransaction& tx, vtx) {
    tx.WriteTx(ifaceIndex, nHeight); 
  }

  trust(1, "healthy block");
  Debug("(%s) WriteBlock: block \"%s\" [height: %u]", 
			iface->name, hash.GetHex().c_str(), (unsigned int)nHeight);

  return (true);
}

bool CBlock::WriteArchBlock()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockChain(iface);
  uint64_t idx_next;
  unsigned int blockPos;
  long sBlockLen;
  char *sBlockData;
  int err;

  if (!bc)
    return (false);

  uint256 hash = GetHash();

	err = bc_find(bc, hash.GetRaw(), NULL);
	if (err == 0)
		return true; /* already stored */

  /* serialize into binary */
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
  sBlock << *this;
  sBlockLen = sBlock.size();
  sBlockData = (char *)calloc(sBlockLen, sizeof(char));
  if (!sBlockData)
    return error(SHERR_NOMEM, "allocating %d bytes for block data\n", (int)sBlockLen);
  sBlock.read(sBlockData, sBlockLen);
  err = bc_arch_write(bc, hash.GetRaw(), sBlockData, sBlockLen);
  free(sBlockData);
  if (err < 0)
    return error(err, "WriteArchBlock [%s]", hash.GetHex().c_str());

  Debug("WriteArchBlock: %s", ToString().c_str());
  return (true);
}

bool VerifyTxHash(CIface *iface, uint256 hashTx)
{
	CTransaction tmp_tx;
	return (GetTransaction(iface, hashTx, tmp_tx, NULL)); 
}


bool CTransaction::EraseTx(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockTxChain(iface);
  uint256 hash = GetHash();
  bcpos_t posTx;
  int err;

  err = bc_find(bc, hash.GetRaw(), &posTx);
  if (err)
    return error(err, "CTransaction::EraseTx: tx '%s' not found.", GetHash().GetHex().c_str());

  err = bc_idx_clear(bc, posTx);
  if (err)
    return error(err, "CTransaction::EraseTx: error clearing tx pos %d.", posTx);

  bc_table_reset(bc, hash.GetRaw());
 
  Debug("CTransaction::EraseTx: cleared tx '%s'.", GetHash().GetHex().c_str());
  return (true);
}


uint256 GetGenesisBlockHash(int ifaceIndex)
{
  uint256 hash;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CBlock *block = GetBlockByHeight(iface, 0); 
  if (!block)
    return (false);
  hash = block->GetHash();
  delete block;
  return (hash);
}

extern int ProcessExecTx(CIface *iface, CNode *pfrom, CTransaction& tx);



bool CTransaction::IsStandard() const
{

  BOOST_FOREACH(const CTxOut& txout, vout) {
    if (!::IsStandard(txout.scriptPubKey)) {
      return error(SHERR_INVAL, "pub key is not standard [CTransaction::IsStandard] %s", txout.scriptPubKey.ToString().c_str());
    }
  }

  return true;
}

CParam *CTransaction::UpdateParam(std::string strName, int64_t nValue)
{
	CParam *par;

  if (nFlag & CTransaction::TXF_PARAM)
    return (NULL);

  nFlag |= CTransaction::TXF_PARAM;

  par = GetParam();
	if (!par)
		return (NULL);

	par->SetNull();
  par->SetLabel(strName);
	par->nValue = (int64)nValue;

	/* expiration is primarily for creating a unique hash. */
  par->SetExpireSpan((double)DEFAULT_PARAM_LIFESPAN);

  return (par);
}


CAlias *CTransaction::CreateAlias(std::string name, int type)
{
  nFlag |= CTransaction::TXF_ALIAS;

  alias = CAlias();
  alias.SetExpireSpan((double)DEFAULT_ALIAS_LIFESPAN); /* 12yr */
  alias.SetLabel(name);
  alias.SetType(type);

  return (&alias);
}

CAlias *CTransaction::UpdateAlias(std::string name, const uint160& hash)
{
  nFlag |= CTransaction::TXF_ALIAS;

  alias = CAlias();
  alias.SetExpireSpan((double)DEFAULT_ALIAS_LIFESPAN);
  alias.SetLabel(name);

  return (&alias);
}

CAlias *CTransaction::RemoveAlias(std::string name)
{
  nFlag |= CTransaction::TXF_ALIAS;

  alias = CAlias();
  alias.SetExpireSpan((double)DEFAULT_ALIAS_LIFESPAN);
  alias.SetLabel(name);
  return (&alias);
}

CCert *CTransaction::CreateCert(int ifaceIndex, string strTitle, CCoinAddr& addr, string hexSeed, int64 nLicenseFee)
{
  cbuff vchContext;

  if ((nFlag & CTransaction::TXF_CERTIFICATE) ||
			(nFlag & CTransaction::TXF_LICENSE) ||
			(nFlag & CTransaction::TXF_CONTEXT))
    return (NULL); /* already in use */

  nFlag |= CTransaction::TXF_CERTIFICATE;
  certificate = CCert(strTitle);
  certificate.SetExpireTime();
  certificate.SetSerialNumber();
  shgeo_local(&certificate.geo, SHGEO_PREC_DISTRICT);
  certificate.SetFee(nLicenseFee);
  certificate.Sign(ifaceIndex, addr, vchContext, hexSeed);

  return (&certificate);
}

CCert *CTransaction::DeriveCert(int ifaceIndex, string strTitle, CCoinAddr& addr, CCert *chain, string hexSeed, int64 nLicenseFee)
{

  if (nFlag & CTransaction::TXF_CERTIFICATE)
    return (NULL);

  nFlag |= CTransaction::TXF_CERTIFICATE;
  certificate = CCert(strTitle);
  certificate.SetSerialNumber();
  certificate.hashIssuer = chain->GetHash();

  certificate.nFlag |= SHCERT_CERT_CHAIN;
  certificate.nFlag |= SHCERT_CERT_LICENSE; /* capable of licensing */
  /* signing is revoked once parent is a chained cert */
  if (chain->nFlag & SHCERT_CERT_CHAIN)
    certificate.nFlag &= ~SHCERT_CERT_SIGN;

  shgeo_local(&certificate.geo, SHGEO_PREC_DISTRICT);
  certificate.SetFee(nLicenseFee);
  certificate.Sign(ifaceIndex, addr, chain, hexSeed);

  return (&certificate);
}

/**
 * @param lic_span The duration of the license in seconds.
 */
CCert *CTransaction::CreateLicense(CCert *cert)
{
  double lic_span;

  if ((nFlag & CTransaction::TXF_CERTIFICATE) ||
			(nFlag & CTransaction::TXF_LICENSE) ||
			(nFlag & CTransaction::TXF_CONTEXT))
    return (NULL); /* already in use */
  
  nFlag |= CTransaction::TXF_LICENSE;
  CLicense license;

  license.nFlag |= SHCERT_CERT_CHAIN;
  license.nFlag &= ~SHCERT_CERT_SIGN;

  license.SetSerialNumber();
  shgeo_local(&license.geo, SHGEO_PREC_DISTRICT);
  license.hashIssuer = cert->GetHash();
  license.Sign(cert);

  certificate = (CCert&)license;

  return (&certificate);
}



COffer *CTransaction::CreateOffer()
{
	COffer *off;

  if (nFlag & CTransaction::TXF_OFFER)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER;

  off = GetOffer();
  off->SetExpireSpan((double)1440); /* 24m */

  return (off);
}

COffer *CTransaction::AcceptOffer(COffer *offerIn)
{
  uint160 hashOffer;

  if (nFlag & CTransaction::TXF_OFFER)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER;

  hashOffer = offerIn->GetHash();
  offer = *offerIn;

	COffer *off = GetOffer();
  off->hashOffer = hashOffer;

	/* extend back expiration time */
  off->SetExpireSpan((double)1440); /* 24m */

 return (off);
}

COffer *CTransaction::GenerateOffer(COffer *offerIn)
{
	COffer *off;

  if (nFlag & CTransaction::TXF_OFFER)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER;
  offer = *offerIn;

	off = GetOffer();
	if (!off)
		return (NULL);

  off->SetExpireSpan((double)1440); /* 24m */

 return (off);
}

COffer *CTransaction::PayOffer(COffer *accept)
{
	/* n/a */
	return (NULL);
}

/* cancel operation */
COffer *CTransaction::RemoveOffer(uint160 hashOffer)
{
  if (nFlag & CTransaction::TXF_OFFER)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER;

	COffer *off = GetOffer();
	off->SetNull();

  off->hashOffer = hashOffer;

	return (off);
}

CAsset *CTransaction::CreateAsset(CCert *cert, int nType, int nSubType, const cbuff& vContent)
{
	CAsset *newAsset;

	newAsset = GetNewAsset();
	if (!newAsset) {
		return (NULL);
	}

	newAsset->SetLabel(cert->GetLabel());
	newAsset->SetCertificateHash(cert->GetHash());
	newAsset->SetType(nType);
	newAsset->SetSubType(nSubType);
	newAsset->SetContent(vContent);

	if (newAsset->GetLabel().length() > CAsset::MAX_ASSET_LABEL_LENGTH) {
		string label = string(newAsset->GetLabel());
		label.resize(CAsset::MAX_ASSET_LABEL_LENGTH);
		newAsset->SetLabel(label);
	}

  return (newAsset);
}

CAsset *CTransaction::UpdateAsset(CAsset *assetIn, const cbuff& vContent)
{
	CAsset *newAsset;

	newAsset = GetDerivedAsset(assetIn);
	if (!newAsset) {
		return (NULL);
	}

	newAsset->SetContent(vContent);
	newAsset->SetHashIssuer(assetIn->GetHash());
  return (newAsset);
}

CAsset *CTransaction::TransferAsset(CAsset *assetIn)
{
	CAsset *newAsset;

	newAsset = GetDerivedAsset(assetIn);
	if (!newAsset) {
		return (NULL);
	}

	newAsset->ResetContent();
	newAsset->SetHashIssuer(assetIn->GetHash());
  return (newAsset);
}

CAsset *CTransaction::ActivateAsset(CAsset *assetIn)
{
	CAsset *newAsset;

	newAsset = GetDerivedAsset(assetIn);
	if (!newAsset) {
		return (NULL);
	}

	newAsset->SetHashIssuer(assetIn->GetHash());
  return (newAsset);
}

CAsset *CTransaction::RemoveAsset(CAsset *assetIn)
{
	CAsset *newAsset;

	newAsset = GetDerivedAsset(assetIn);
	if (!newAsset) {
		return (NULL);
	}

	newAsset->ResetContent();
	newAsset->SetHashIssuer(assetIn->GetHash());

	return (newAsset);
}

bool CTransaction::VerifyAsset(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
	uint160 hashAsset;
	int nOut;
	int err;

	if (!iface)
		return (false);

	/* core verification */
	if (!IsAssetTx(*this)) {
		return (false); /* tx not flagged as asset */
	}

	/* verify hash in pub-script matches asset hash */
	nOut = IndexOfAssetOutput(*this);
	if (nOut == -1) {
		return (false); /* no extension output */
	}

	int mode;
	if (!DecodeAssetHash(vout[nOut].scriptPubKey, mode, hashAsset)) {
		return (false); /* no asset hash in output */
	}

	if (mode != OP_EXT_NEW &&
			mode != OP_EXT_ACTIVATE &&
			mode != OP_EXT_UPDATE &&
			mode != OP_EXT_TRANSFER &&
			mode != OP_EXT_REMOVE)
		return (false);

	CAsset *asset = GetAsset();
	if (hashAsset != asset->GetHash()) {
		return error(SHERR_INVAL, "asset hash mismatch");
	}

	err = asset->VerifyTransaction();
	if (err != 0) {
		return (error(err, "asset verification failure"));
	}

	{
		int nHeight = GetBestHeight(iface);
		int64 nBaseFee = asset->CalculateFee(iface, nHeight);
		int64 nCredit = vout[nOut].nValue;

fprintf(stderr, "DEBUG: VerifyAsset(): nCredit %-8.8f\n", (nCredit/COIN)); 
fprintf(stderr, "DEBUG: VerifyAsset(): nBaseFee %-8.8f\n", (nBaseFee/COIN)); 

		/** asset fee must be at least base asset fee. */
		if (nCredit < nBaseFee) {
			return (error(ERR_FEE, "insufficient asset fund"));
		}

		if (!asset->VerifyLifespan(iface, nCredit)) {
			return (error(ERR_INVAL, "expiration exceeds limit"));
		}
	}

	return (true);
}

CIdent *CTransaction::CreateIdent(CIdent *identIn)
{

  if (nFlag & CTransaction::TXF_IDENT)
    return (NULL); /* already in use */

  nFlag |= CTransaction::TXF_IDENT;
  //certificate = CCert(*ident);
	ident = CIdent(*identIn);
//  shgeo_local(&certificate.geo, SHGEO_PREC_DISTRICT);
  shgeo_local(&ident.geo, SHGEO_PREC_DISTRICT);

  //return ((CIdent *)&certificate);
  return ((CIdent *)&ident);
}

CIdent *CTransaction::CreateIdent(int ifaceIndex, CCoinAddr& addr)
{

  if (nFlag & CTransaction::TXF_IDENT)
    return (NULL);

  nFlag |= CTransaction::TXF_IDENT;

#if 0
  certificate.SetNull();
  shgeo_local(&certificate.geo, SHGEO_PREC_DISTRICT);
  certificate.vAddr = vchFromString(addr.ToString());
#endif
  ident.SetNull();
  shgeo_local(&ident.geo, SHGEO_PREC_DISTRICT);
  ident.vAddr = vchFromString(addr.ToString());

  //return ((CIdent *)&certificate);
  return ((CIdent *)&ident);
}

bool CTransaction::VerifyValidateMatrix(int ifaceIndex, const CTxMatrix& matrix, CBlockIndex *pindex)
{
	CWallet *wallet = GetWallet(ifaceIndex);
  unsigned int height;

	if (!wallet)
		return (false);
  if (!pindex)
    return (false);

  height = matrix.nHeight;
  height /= 27;
  height *= 27;

  while (pindex && pindex->pprev && pindex->nHeight > height)
    pindex = pindex->pprev;
  if (!pindex) {
    return (error(ERR_INVAL, "VerifyValidateMatrix: matrix root not found."));
  }

  bool ret;
  CTxMatrix cmp_matrix(wallet->matrixValidate);
  cmp_matrix.SetType(CTxMatrix::M_VALIDATE);
  cmp_matrix.Append(pindex->nHeight, pindex->GetBlockHash()); 
  ret = (cmp_matrix == matrix);
	if (!ret) {
		CTxMatrix *mp = (CTxMatrix *)&matrix;
		return (error(ERR_INVAL, "VerifyValidateMatrix: matrix mismatch: local matrix(%s) != block matrix(%s)\n", cmp_matrix.ToString().c_str(), mp->ToString().c_str()));
	}

  return (true);
}

/**
 * @note Verified against previous matrix when the block is accepted.
 */
CTxMatrix *CTransaction::GenerateValidateMatrix(int ifaceIndex, CBlockIndex *pindex)
{
	CWallet *wallet = GetWallet(ifaceIndex);
  uint32_t best_height;
  int height;

	if (!wallet)
		return (NULL);

  if (nFlag & CTransaction::TXF_MATRIX)
    return (NULL);

  if (!pindex) {
    pindex = GetBestBlockIndex(ifaceIndex);
    if (!pindex)
      return (NULL);
  }

  height = (pindex->nHeight - 27);
  height /= 27;
  height *= 27;

  if (height <= 27)
    return (NULL);

  if (wallet->matrixValidate.GetHeight() >= height)
    return (NULL);

  while (pindex && pindex->pprev && pindex->nHeight > height)
    pindex = pindex->pprev;
  if (!pindex) {
    return (NULL);
  }

  nFlag |= CTransaction::TXF_MATRIX;

  matrix = CTxMatrix(wallet->matrixValidate);
  matrix.SetType(CTxMatrix::M_VALIDATE);
  matrix.Append(pindex->nHeight, pindex->GetBlockHash()); 

  return (&matrix);
}



bool CBlock::trust(int deg, const char *msg, ...)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  va_list arg_ptr;
  char errbuf[4096];
  char msgbuf[4096];

  if (deg == 0)
    return (true);

  if (!iface || !iface->enabled)
    return ((deg > 0) ? true : false);

  memset(msgbuf, 0, sizeof(msgbuf));
  if (msg) {
    va_start(arg_ptr, msg);
    (void)vsnprintf(msgbuf, sizeof(msgbuf) - 1, msg, arg_ptr);
    va_end(arg_ptr);
  }

	if (originPeer || deg < 0) {
		sprintf(errbuf, "(%s) TRUST %s%d", 
				iface->name, (deg >= 0) ? "+" : "", deg);
		if (*msgbuf)
			sprintf(errbuf + strlen(errbuf), " (%s)", msgbuf);
		if (originPeer)
			sprintf(errbuf + strlen(errbuf), " (%s)", 
					originPeer->addr.ToString().c_str());
		Debug("%s", errbuf);
	}

  if (deg > 0) {
    if (originPeer) {
      if (originPeer->nMisbehavior > deg)
        originPeer->nMisbehavior -= deg;
    }
    return (true);
  }

  if (originPeer) {
		if (deg < 0)
			originPeer->Misbehaving(-deg);
	}

  return (false);
}

void CBlockHeader::reject(CValidateState *state, int err_code, string err_text)
{
	if (!state->peer) return;
	const uint256& hash = GetHash();
	state->hash = hash;
	state->nTrust -= 10;
	state->nError = err_code;
	state->sError = err_text;

	Debug("REJECT[%s]: block: %s",
			state->peer->addr.ToString().c_str(), ToString().c_str());
}

void CTransaction::reject(CValidateState *state, int err_code, string err_text)
{
	if (!state->peer) return;
	const uint256& hash = GetHash();
	state->nTrust -= 10;
	state->hash = hash;
	state->nError = err_code;
	state->sError = err_text;

	Debug("REJECT[%s]: tx: %s",
			state->peer->addr.ToString().c_str(), ToString(state->ifaceIndex).c_str());
}

std::string CTransactionCore::ToString(int ifaceIndex)
{
  return (write_string(Value(ToValue(ifaceIndex)), false));
}

std::string CTransaction::ToString(int ifaceIndex)
{
  return (write_string(Value(ToValue(ifaceIndex)), false));
}

std::string CBlockHeader::ToString()
{
  return (write_string(Value(ToValue()), false));
}

std::string CBlock::ToString(bool fVerbose)
{
  return (write_string(Value(ToValue(fVerbose)), false));
}

string ToValue_date_format(time_t t)
{
  char buf[256];

  memset(buf, 0, sizeof(buf));
  strftime(buf, sizeof(buf)-1, "%x %T", localtime(&t));

  return (string(buf));
}

Object CTransactionCore::ToValue(int ifaceIndex)
{
  Object obj;

  obj.push_back(Pair("version", GetVersion())); 

  if (nLockTime != 0) {
    if ((int64)nLockTime < (int64)LOCKTIME_THRESHOLD) {
      obj.push_back(Pair("lock-height", (int)nLockTime));
    } else {
      obj.push_back(Pair("lock-time", (uint64_t)nLockTime));
      obj.push_back(Pair("lock-stamp", ToValue_date_format((time_t)nLockTime)));
    }
  }

  return (obj);
}

Object CTransaction::ToValue(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  Object obj = CTransactionCore::ToValue(ifaceIndex);
	int flags = GetFlags();

  /* primary identification */
  obj.push_back(Pair("txid", GetHash().GetHex()));
  obj.push_back(Pair("hash", GetWitnessHash().GetHex()));

  vector<uint256> vOuts;
  ReadCoins(ifaceIndex, vOuts);

  Array obj_vin;
  unsigned int n = 0;
  BOOST_FOREACH(const CTxIn& txin, vin)
  {
    Object in;
    if (IsCoinBase()) {
      in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    } else {
      in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
      in.push_back(Pair("vout", (boost::int64_t)txin.prevout.n));

			Object sig;
			sig.push_back(Pair("asm", txin.scriptSig.ToString()));
			sig.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()))); 
      in.push_back(Pair("scriptSig", sig));
    }   

    /* segwit */
    if (wit.vtxinwit.size() != 0) {
      const CTxInWitness& tx_wit = wit.vtxinwit[n];
      Array ar;
      for (unsigned int i = 0; i < tx_wit.scriptWitness.stack.size(); i++) {
        ar.push_back(HexStr(tx_wit.scriptWitness.stack[i].begin(), tx_wit.scriptWitness.stack[i].end()));
      }
      in.push_back(Pair("witness", ar));
    }

    in.push_back(Pair("sequence", (boost::int64_t)txin.nSequence));

    obj_vin.push_back(in);
    n++;
  }
  obj.push_back(Pair("vin", obj_vin));

  Array obj_vout;
  for (unsigned int i = 0; i < vout.size(); i++)
  {     
    const CTxOut& txout = vout[i];
    Object out;
    out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
    out.push_back(Pair("n", (boost::int64_t)i));

		Object scriptSig;
		scriptSig.push_back(Pair("asm", txout.scriptPubKey.ToString()));
		scriptSig.push_back(Pair("hex", HexStr(txout.scriptPubKey.begin(), txout.scriptPubKey.end()))); 
		out.push_back(Pair("scriptSig", scriptSig));

    if (i < vOuts.size() && !vOuts[i].IsNull())
      out.push_back(Pair("spent-tx", vOuts[i].GetHex()));

    ScriptPubKeyToJSON(ifaceIndex, txout.scriptPubKey, out);

    obj_vout.push_back(out);
  } 
  obj.push_back(Pair("vout", obj_vout));

	if (ifaceIndex == TEST_COIN_IFACE ||
			ifaceIndex == TESTNET_COIN_IFACE ||
			ifaceIndex == SHC_COIN_IFACE) {
		if (this->nFlag & TXF_CERTIFICATE) 
			obj.push_back(Pair("certificate", certificate.ToValue()));
		if (this->nFlag & TXF_LICENSE) {
			CLicense license(certificate);
			obj.push_back(Pair("license", license.ToValue()));
		}
		if (flags & TXF_ALIAS)
			obj.push_back(Pair("alias", alias.ToValue(ifaceIndex)));
		if (flags & TXF_ASSET) {
			//CAsset asset(certificate);
			obj.push_back(Pair("asset", asset.ToValue()));
		}
		if (flags & TXF_EXEC) {
			int mode;
			if (IsExecTx(*this, mode)) {
				if (mode == OP_EXT_NEW) {
					CExec *exec = GetExec();
					obj.push_back(Pair("exec", exec->ToValue(ifaceIndex)));
				} else if (mode == OP_EXT_UPDATE) {
					CExecCheckpoint *cp = GetExecCheckpoint();
					obj.push_back(Pair("exec-checkpoint", cp->ToValue(ifaceIndex)));
				} else if (mode == OP_EXT_GENERATE) {
					CExecCall *call = GetExecCall();
					obj.push_back(Pair("exec-call", call->ToValue(ifaceIndex)));
				}
			}
		}
		if (flags & TXF_OFFER)
			obj.push_back(Pair("offer", offer.ToValue()));
		if (flags & TXF_IDENT) {
			//CIdent& ident = (CIdent&)certificate;
			obj.push_back(Pair("ident", ident.ToValue()));
		}
		if (flags & TXF_MATRIX) {
			obj.push_back(Pair("matrix", matrix.ToValue()));
		}
		if (flags & TXF_CONTEXT) {
			CContext ctx(certificate);
			obj.push_back(Pair("context", ctx.ToValue()));
		}
		if (flags & TXF_ALTCHAIN) {
			CAltChain *alt = GetAltChain();
			if (alt) {
				obj.push_back(Pair("altchain", alt->ToValue()));
			}
		}
	}

  return (obj);
}

Object CTransaction::ToValue(CBlock *pblock)
{
  CBlockHeader& block = (CBlockHeader& )(*pblock);
  Object tx_obj = ToValue(pblock->ifaceIndex);
  Object obj;

  obj = block.ToValue();
  obj.push_back(Pair("tx", tx_obj));

  return (obj);
}

Object CBlockHeader::ToValue()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CBlockIndex *pindex;
  Object obj;
  uint256 hash = GetHash();
	char buf[32];

	sprintf(buf, "%x", nVersion);

  obj.push_back(Pair("blockhash", hash.GetHex()));
  obj.push_back(Pair("version", string(buf)));
  obj.push_back(Pair("merkleroot", hashMerkleRoot.GetHex()));
  obj.push_back(Pair("time", (boost::int64_t)GetBlockTime()));
  obj.push_back(Pair("stamp", ToValue_date_format((time_t)GetBlockTime())));
  obj.push_back(Pair("nonce", (boost::uint64_t)nNonce));
  obj.push_back(Pair("bits", HexBits(nBits)));

  obj.push_back(Pair("previousblockhash", hashPrevBlock.GetHex().c_str()));

  if (iface)
    obj.push_back(Pair("confirmations", GetBlockDepthInMainChain(iface, hash)));

  pindex = GetBlockIndexByHash(ifaceIndex, hash);
  if (pindex) {
    obj.push_back(Pair("height", pindex->nHeight));
    obj.push_back(Pair("difficulty", GetDifficulty(ifaceIndex, pindex)));

    obj.push_back(Pair("chainwork", pindex->bnChainWork.ToString()));

    if (pindex->pnext)
      obj.push_back(Pair("nextblockhash", pindex->pnext->GetBlockHash().GetHex()));
		obj.push_back(Pair("mediantime", (boost::int64_t)pindex->GetMedianTimePast()));
  }

  return obj;
} 

Object CBlock::ToValue(bool fVerbose)
{
  Object obj = CBlockHeader::ToValue();

	obj.push_back(Pair("pow", GetAlgoNameStr(GetAlgo()))); 

  obj.push_back(Pair("weight", (int)GetBlockWeight()));

  Array txs;
	if (!fVerbose) {
		BOOST_FOREACH(const CTransaction&tx, vtx)
			txs.push_back(tx.GetHash().GetHex());
		obj.push_back(Pair("tx", txs));
	} else {
		BOOST_FOREACH(CTransaction&tx, vtx)
			txs.push_back(tx.ToValue(ifaceIndex));
		obj.push_back(Pair("tx", txs));
	}

  return (obj);
}

bool CTransaction::IsInMemoryPool(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface) {
    unet_log(ifaceIndex, "error obtaining coin interface");
    return (false);
  }

  CTxMemPool *pool = GetTxMemPool(iface);
  if (!pool) {
    unet_log(ifaceIndex, "error obtaining tx memory pool");
    return (false);
  }

  return (pool->exists(GetHash()));
}

int CTransaction::GetDepthInMainChain(int ifaceIndex, CBlockIndex* &pindexRet) const
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  uint256 hashTx = GetHash();
  bool ret;

	CBlockIndex *pindex = GetBlockIndexByTx(iface, hashTx);
	if (!pindex)
		return (0);

  CBlockIndex *pindexBest = NULL;
	if (ifaceIndex == COLOR_COIN_IFACE) {
		/* count manually as each color has it's own 'best block index'. */
		pindexBest = pindex;
		while (pindexBest && pindexBest->pnext) {
			pindexBest = pindexBest->pnext;
		}
	} else {
		pindexBest = GetBestBlockIndex(ifaceIndex);
	}
  if (!pindexBest)
    return (0);


  if (!pindex->IsInMainChain(ifaceIndex))
    return 0;

  pindexRet = pindex;
  return pindexBest->nHeight - pindex->nHeight + 1;
}

CExec *CTransaction::CreateExec()
{
	CExec *exec;

  if (nFlag & CTransaction::TXF_EXEC)
    return (NULL);

  nFlag |= CTransaction::TXF_EXEC;

	exec = GetExec();
	if (!exec)
		return (NULL);

  exec->SetNull();
	exec->nVersion = 3;
  exec->SetExpireSpan((double)DEFAULT_EXEC_LIFESPAN);

  return (exec);
}

CExecCheckpoint *CTransaction::UpdateExec(const CExec& execIn)
{
  CExecCheckpoint *cp;

  if (nFlag & CTransaction::TXF_EXEC)
    return (NULL);

  nFlag |= CTransaction::TXF_EXEC;

	cp = GetExecCheckpoint();
	if (!cp)
		return (NULL);

	cp->SetNull();
	cp->nVersion = 3;
	cp->tExpire = execIn.tExpire; /* Expiration Date */

  return (cp);
}

CExec *CTransaction::TransferExec(const CExec& execIn)
{
	return (NULL);
}

CExecCall *CTransaction::GenerateExec(const CExec& execIn)
{

  if (nFlag & CTransaction::TXF_EXEC)
    return (NULL);

  nFlag |= CTransaction::TXF_EXEC;
	CExecCall *call = GetExecCall();
	if (!call)
		return (NULL);

  call->SetNull();
	call->nVersion = 3;
	call->tExpire = execIn.tExpire; /* Expiration Date */

  return (call);
}

CContext *CTransaction::CreateContext()
{
  CContext *ctx;

  if ((nFlag & CTransaction::TXF_CERTIFICATE) ||
			(nFlag & CTransaction::TXF_LICENSE) ||
			(nFlag & CTransaction::TXF_CONTEXT))
    return (NULL); /* already in use */

  nFlag |= CTransaction::TXF_CONTEXT;

  ctx = (CContext *)&certificate;
  ctx->SetNull();

  /* each context value expires after two years */
  ctx->SetExpireSpan((double)DEFAULT_CONTEXT_LIFESPAN);

  return (ctx);
}

CAltChain *CTransaction::CreateAltChain()
{
	CAltChain *alt;

	if (nFlag & CTransaction::TXF_ALTCHAIN)
		return (NULL);

	nFlag |= CTransaction::TXF_ALTCHAIN;

	alt = GetAltChain();
	alt->SetNull();

	/* does not expire */
	alt->tExpire = SHTIME_UNDEFINED;

	return (alt);
}



static bool GetCommitBranches(CBlockIndex *pbest, CBlockIndex *tip, CBlockIndex *pindexNew, vector<CBlockIndex*>& vConnect, vector<CBlockIndex*>& vDisconnect)
{
  CBlockIndex* pfork = pbest;
  CBlockIndex* plonger = pindexNew;

  vConnect.clear();
  vDisconnect.clear();

  while (pfork && pfork != plonger)
  {   
    while (plonger->nHeight > pfork->nHeight) {
      plonger = plonger->pprev;
      if (!plonger)
        return (false);
    }
    if (pfork == plonger) {
			/* progress until we have reached a fork that is on the current chain. */
			break;
		}

    pfork = pfork->pprev;
    if (!pfork) {
			/* could not find a fork. most likely invalid/malicious block data. */
      return (false);
		}
  }

  /* discon tree */
  for (CBlockIndex* pindex = pbest; pindex != pfork; pindex = pindex->pprev)
    vDisconnect.push_back(pindex);

  /* connect tree */
  for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
    vConnect.push_back(pindex);
  reverse(vConnect.begin(), vConnect.end());

  if (vDisconnect.size() > 0) {
    Debug("REORGANIZE: Disconnect %lu blocks; %s..\n", (unsigned long)vDisconnect.size(), pfork->GetBlockHash().ToString().c_str());
    Debug("REORGANIZE: Connect %lu blocks; ..%s\n", (unsigned long)vConnect.size(), pindexNew->GetBlockHash().ToString().c_str());
  }

  return (true);
}



ValidIndexSet setBlockIndexValid[MAX_COIN_IFACE];

ValidIndexSet *GetValidIndexSet(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);

  return (&setBlockIndexValid[ifaceIndex]);
}

int BackupBlockChain(CIface *iface, unsigned int maxHeight)
{
  bc_t *bc;
  char path[PATH_MAX+1];
	uint32_t height;
  unsigned int ten_per;
  int err;
  
  sprintf(path, "%s/backup/", bc_path_base());
  mkdir(path, 0777);

  sprintf(path, "backup/%s_block", iface->name);
  err = bc_open(path, &bc);
  if (err)
    return (err);

	err = bc_idx_next(bc, &height);
	if (err)
		return (err);

  height = MAX(1, height);
  ten_per = (maxHeight / 10); /* ten percent of max */
  maxHeight = MIN(maxHeight - ten_per, height + ten_per);
  for (; height < maxHeight; height++) {
    CBlock *block = GetBlockByHeight(iface, height);
    if (!block) {
      error(err, "(%s) BackupBlockChain: load error (height: %u)", iface->name, height);
      break;
    }

    CDataStream sBlock(SER_DISK, CLIENT_VERSION);
    uint256 hash = block->GetHash();
    char *sBlockData;
    long sBlockLen;

    sBlock << *block;
    delete block;

    sBlockLen = sBlock.size();
    sBlockData = (char *)calloc(sBlockLen, sizeof(char));
    if (!sBlockData)
      return error(SHERR_NOMEM, "allocating %d bytes for block data\n", (int)sBlockLen);
    sBlock.read(sBlockData, sBlockLen);

    err = bc_write(bc, height, hash.GetRaw(), sBlockData, sBlockLen);
    free(sBlockData);
    if (err) {
      error(err, "bc_write [BackupBlockChain]");
      break;
    }
  }

  Debug("(%s) BackupBlockChain: total %u blocks stored.", 
      iface->name, height);
  
  bc_close(bc);
  
  return (0);
}   


int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
static int GetSkipHeight(int height) 
{

  if (height < 2)
    return 0;

  // Determine which height to jump back to. Any number strictly lower than height is acceptable,
  // but the following expression seems to perform well in simulations (max 110 steps to go back
  // up to 2**18 blocks).
  return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{

  if (height > nHeight || height < 0)
    return NULL;

  CBlockIndex* pindexWalk = this;
  int heightWalk = nHeight;
  while (heightWalk > height) {
    int heightSkip = GetSkipHeight(heightWalk);
    int heightSkipPrev = GetSkipHeight(heightWalk - 1);
    if (pindexWalk->pskip != NULL &&
        (heightSkip == height ||
         (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                   heightSkipPrev >= height)))) {
      // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
      pindexWalk = pindexWalk->pskip;
      heightWalk = heightSkip;
    } else {
      assert(pindexWalk->pprev);
      pindexWalk = pindexWalk->pprev;
      heightWalk--;
    }
  }

  return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}

void CBlockIndex::BuildSkip()
{
  if (pprev)
    pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

bool IsWitnessEnabled(CIface *iface, const CBlockIndex* pindexPrev)
{
  return (VersionBitsState(pindexPrev, iface, DEPLOYMENT_SEGWIT) == THRESHOLD_ACTIVE);
}

int GetWitnessCommitmentIndex(const CBlock& block)
{
	int commitpos = -1;

	for (size_t o = 0; o < block.vtx[0].vout.size(); o++) {
		if (block.vtx[0].vout[o].scriptPubKey.size() >= 38 && block.vtx[0].vout[o].scriptPubKey[0] == OP_RETURN && block.vtx[0].vout[o].scriptPubKey[1] == 0x24 && block.vtx[0].vout[o].scriptPubKey[2] == 0xaa && block.vtx[0].vout[o].scriptPubKey[3] == 0x21 && block.vtx[0].vout[o].scriptPubKey[4] == 0xa9 && block.vtx[0].vout[o].scriptPubKey[5] == 0xed) {
			commitpos = o;
		}
	}

	return commitpos;
}

void core_UpdateUncommittedBlockStructures(CIface *iface, CBlock *block, const CBlockIndex* pindexPrev)
{
  int commitpos = GetWitnessCommitmentIndex(*block);
  static const std::vector<unsigned char> nonce(32, 0x00);
  if (commitpos != -1 && IsWitnessEnabled(iface, pindexPrev) && block->vtx[0].wit.IsEmpty()) {
    block->vtx[0].wit.vtxinwit.resize(1);
    block->vtx[0].wit.vtxinwit[0].scriptWitness.stack.resize(1);
    block->vtx[0].wit.vtxinwit[0].scriptWitness.stack[0] = nonce;
  }
}

bool core_GenerateCoinbaseCommitment(CIface *iface, CBlock *block, CBlockIndex *pindexPrev)
{
  int commitpos = GetWitnessCommitmentIndex(*block);
  std::vector<unsigned char> ret(32, 0x00);

  if (iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout != 0) {
    if (commitpos == -1) {
      uint256 witnessroot = BlockWitnessMerkleRoot(*block, NULL);
      uint256 hashCommit;

      CTxOut out;
      out.nValue = 0;
      out.scriptPubKey.resize(38);
      out.scriptPubKey[0] = OP_RETURN; 
      out.scriptPubKey[1] = 0x24;
      out.scriptPubKey[2] = 0xaa;
      out.scriptPubKey[3] = 0x21;
      out.scriptPubKey[4] = 0xa9;
      out.scriptPubKey[5] = 0xed;

      hashCommit = Hash(witnessroot.begin(), witnessroot.end(), ret.begin(), ret.end());
      memcpy(&out.scriptPubKey[6], hashCommit.begin(), 32);
      
      const_cast<std::vector<CTxOut>*>(&block->vtx[0].vout)->push_back(out);   
    }
  }

  core_UpdateUncommittedBlockStructures(iface, block, pindexPrev);

  return (false);
}


int core_ComputeBlockVersion(CIface *params, CBlockIndex *pindexPrev)
{
  int32_t nVersion = VERSIONBITS_TOP_BITS;

  for (int i = 0; i < (int)MAX_VERSION_BITS_DEPLOYMENTS; i++) {
    ThresholdState state = VersionBitsState(pindexPrev, params, (DeploymentPos)i);
    if (state == THRESHOLD_LOCKED_IN || state == THRESHOLD_STARTED) {
      nVersion |= VersionBitsMask(params, (DeploymentPos)i);
    }
  }

  return nVersion;
}

/**
 * Validation for witness commitments.
 * - Compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the coinbase (where 0x0000....0000 is used instead).
 * - The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness nonce (unconstrained).
 * - We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
 * - There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness nonce). In case there are multiple, the last one is used.
 */
bool core_CheckBlockWitness(CIface *iface, CBlock *pblock, CBlockIndex *pindexPrev)
{
  bool fHaveWitness = false;

  if (!iface || !pblock || !pindexPrev)
    return true; /* n/a */

  if (IsWitnessEnabled(iface, pindexPrev)) {
    int commitpos = GetWitnessCommitmentIndex(*pblock);
    if (commitpos != -1) {
      /* The malleation check is ignored; as the transaction tree itself already does not permit it, it is impossible to trigger in the witness tree. */
      if (pblock->vtx[0].wit.vtxinwit.size() != 1 || 
          pblock->vtx[0].wit.vtxinwit[0].scriptWitness.stack.size() != 1 || 
          pblock->vtx[0].wit.vtxinwit[0].scriptWitness.stack[0].size() != 32) {
        return (error(SHERR_INVAL, "core_CheckBlockWitness: witness commitment validation error: \"%s\" [wit-size %d].", pblock->vtx[0].ToString(GetCoinIndex(iface)).c_str()), (int)pblock->vtx[0].wit.vtxinwit.size());
      }

			bool malleated = false;
      uint256 hashWitness = BlockWitnessMerkleRoot(*pblock, &malleated);
      const cbuff& stack = pblock->vtx[0].wit.vtxinwit[0].scriptWitness.stack[0];
      hashWitness = Hash(hashWitness.begin(), hashWitness.end(), stack.begin(), stack.end());
      if (memcmp(hashWitness.begin(), &pblock->vtx[0].vout[commitpos].scriptPubKey[6], 32)) {
        return (error(SHERR_INVAL, "core_CheckBlockWitness: witness commitment hash validation error: \"%s\".", pblock->vtx[0].ToString(GetCoinIndex(iface)).c_str()));
      }

      fHaveWitness = true;
    }
  }

  /* No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam. */
  if (!fHaveWitness) {
    for (size_t i = 0; i < pblock->vtx.size(); i++) {
      if (!pblock->vtx[i].wit.IsNull()) {
        return (error(SHERR_INVAL, "core_CheckBlockWitness: unexpected witness data error: \"%s\".", pblock->vtx[i].ToString(GetCoinIndex(iface)).c_str()));
      }
    }
  }

  return (true);
}

static size_t WitnessSigOps(int witversion, const std::vector<unsigned char>& witprogram, const CScriptWitness& witness, int flags)
{
  if (witversion == 0) {
    if (witprogram.size() == 20)
      return 1;

    if (witprogram.size() == 32 && witness.stack.size() > 0) {
      CScript subscript(witness.stack.back().begin(), witness.stack.back().end());
      return subscript.GetSigOpCount(true);
    }
  }

  return 0;
}   


size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags)
{
  static const CScriptWitness witnessEmpty;

  if (flags && !(flags & SCRIPT_VERIFY_WITNESS))
    return 0;

  int witnessversion;
  std::vector<unsigned char> witnessprogram;
  if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
    return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
  }

  if (scriptPubKey.IsPayToScriptHash() && scriptSig.IsPushOnly()) {
    CScript::const_iterator pc = scriptSig.begin();
    vector<unsigned char> data;
    while (pc < scriptSig.end()) {
      opcodetype opcode;
      scriptSig.GetOp(pc, opcode, data);
    }
    CScript subscript(data.begin(), data.end());
    if (subscript.IsWitnessProgram(witnessversion, witnessprogram)) {
      return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
    }
  }

  return 0;
}

int64_t CTransaction::GetSigOpCost(tx_cache& mapInputs, int flags)
{
  int64_t nSigOps;

  nSigOps = GetLegacySigOpCount() * SCALE_FACTOR;

  if (IsCoinBase()) 
    return nSigOps;

  if ((flags == 0) || (flags & SCRIPT_VERIFY_P2SH)) {
    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); i++) {
      CTxOut prevout;

      if (!GetOutputFor(vin[i], mapInputs, prevout))
        continue;

      if (prevout.scriptPubKey.IsPayToScriptHash())
        nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig) * SCALE_FACTOR;
    }
  }

  if ((flags == 0) || (flags & SCRIPT_VERIFY_WITNESS)) {
    for (unsigned int i = 0; i < vin.size(); i++) {   
      CTxOut prevout;

      if (!GetOutputFor(vin[i], mapInputs, prevout))
        continue;

      nSigOps += CountWitnessSigOps(vin[i].scriptSig, prevout.scriptPubKey, i < wit.vtxinwit.size() ? &wit.vtxinwit[i].scriptWitness : NULL, flags);
    }
  }

  return nSigOps;
}

int64_t CTransaction::GetSigOpCost(MapPrevTx& mapInputs, int flags)
{
  int64_t nSigOps = GetLegacySigOpCount() * SCALE_FACTOR;

  if (IsCoinBase()) 
    return nSigOps;

  if (flags && (flags & SCRIPT_VERIFY_P2SH)) {
    nSigOps += GetP2SHSigOpCount(mapInputs) * SCALE_FACTOR;
  }

  for (unsigned int i = 0; i < vin.size(); i++) {   
    const CTxOut &prevout = GetOutputFor(vin[i], mapInputs);
    nSigOps += CountWitnessSigOps(vin[i].scriptSig, prevout.scriptPubKey, i < wit.vtxinwit.size() ? &wit.vtxinwit[i].scriptWitness : NULL, flags);
  }

  return nSigOps;
}

CScript GetCoinbaseFlags(int ifaceIndex)
{
  const char* pszXN = "/XN/";
  CScript script;
  script << std::vector<unsigned char>(pszXN, pszXN+strlen(pszXN));
  return (script);
}


void core_IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev)
{
  CScript COINBASE_FLAGS = GetCoinbaseFlags(pblock->ifaceIndex);
  char hex[256];
  unsigned int nHeight;
  unsigned int qual;

  /* qualifier */
	nHeight = pindexPrev ? (pindexPrev->nHeight+1) : 0;
	CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
	if (iface && iface->BIP34Height != -1 && 
			nHeight >= iface->BIP34Height) { /* BIP34 */
    qual = nHeight;
	} else { /* BIP30 */
    qual = pblock->nTime;
	}

  sprintf(hex, "%sf0000000", GetSiteExtraNonceHex());
  string hexStr(hex, hex + strlen(hex));
  pblock->vtx[0].vin[0].scriptSig = 
    (CScript() << qual << ParseHex(hexStr)) + 
    COINBASE_FLAGS;
  if (pblock->vtx[0].vin[0].scriptSig.size() > 100) {
    error(SHERR_2BIG, "warning: coinbase signature exceeds 100 characters.");
  }

  pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}

void core_SetExtraNonce(CBlock* pblock, const char *xn_hex)
{
  CScript COINBASE_FLAGS = GetCoinbaseFlags(pblock->ifaceIndex);
  CBlockIndex *pindexPrev = GetBestBlockIndex(pblock->ifaceIndex);
  char hex[256];
  unsigned int qual;

  /* qualifier */ 
	qual = pindexPrev ? (pindexPrev->nHeight+1) : 0;

  sprintf(hex, "%s%s", GetSiteExtraNonceHex(), xn_hex);
  string hexStr = hex;
  pblock->vtx[0].vin[0].scriptSig = 
    (CScript() << qual << ParseHex(hexStr)) + 
    COINBASE_FLAGS;
  if (pblock->vtx[0].vin[0].scriptSig.size() > 100) {
    error(SHERR_2BIG, "warning: coinbase signature exceeds 100 characters.");
  }

  pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}




bool core_DisconnectBlock(CBlockIndex* pindex, CBlock *pblock)
{
  CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
  int err;

  if (!iface || !iface->enabled)
    return error(SHERR_INVAL, "coin interface not enabled.");

	/* SIP31 (BOLO) */
	bolo_disconnectblock_master(pindex, pblock);
	bolo_disconnectblock_slave(pindex, pblock);

	pindex->nStatus &= ~BLOCK_HAVE_DATA;
  Debug("DisconnectBlock[%s]: disconnect block '%s' (height %d).", iface->name, pindex->GetBlockHash().GetHex().c_str(), (int)pindex->nHeight);

  /* disconnect in reverse order. */
  for (int i = pblock->vtx.size()-1; i >= 0; i--)
    if (!pblock->vtx[i].DisconnectInputs(pblock->ifaceIndex))
      return false;

  return true;
}



bool core_CommitBlock(CBlock *pblock, CBlockIndex *pindexNew)
{
  CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
	CWallet *wallet = GetWallet(pblock->ifaceIndex);
  CBlockIndex *pbest = GetBestBlockIndex(pblock->ifaceIndex);
  CBlockIndex *pindexLast = pbest;
  CBlockIndex *pindexFail = NULL;
  CTxMemPool *pool = GetTxMemPool(iface);
  vector<CBlockIndex*> vConnect;
  vector<CBlockIndex*> vDisconnect;
  map<uint256, CBlock *> mConnectBlocks;
  map<uint256, CBlock *> mDisconBlocks;
  vector<CBlock *> vFree;
  bool fValid = true;

	if (!iface || !iface->enabled)
		return (false);
	if (!wallet)
		return (false);

  if  (!GetCommitBranches(pbest, wallet->pindexBestHeader, pindexNew, vConnect, vDisconnect)) {
    return (error(ERR_NOLINK, "(%s) CommitBlock: error obtaining commit branches.", iface->name));
  }

  if (pblock->hashPrevBlock != pbest->GetBlockHash()) {
		/* ensure new chain has no previously invalidated blocks. */
		for (unsigned int i = 0; i < vConnect.size(); i++) {
			CBlockIndex *pindexTest = vConnect[i];
			if (pindexTest->nStatus & BLOCK_FAILED_MASK) {
				return (error(ERR_INVAL, "(%s) CommitBlock: rejecting new work; chain block \"%s\" is invalid.", iface->name, pindexTest->GetBlockHash().GetHex().c_str()));
			}
		}

		/* retain in archive db */
    if (pblock->WriteArchBlock())
			pindexNew->nStatus |= BLOCK_HAVE_UNDO;
	}
	/* ensure we can connect chain. */
	for (unsigned int i = 0; i < vConnect.size(); i++) {
		CBlockIndex *pindexTest = vConnect[i];
		if (pindexTest != pindexNew &&
				!(pindexTest->nStatus & BLOCK_HAVE_DATA) &&
				!(pindexTest->nStatus & BLOCK_HAVE_UNDO)) {
			return (error(ERR_NOLINK, "GetCommitBranches: warning: cannot connect reorg chain due to missing block data for \"%s\" (height %d).", pindexTest->GetBlockHash().GetHex().c_str(), pindexTest->nHeight));
		}
	}

  /* discon blocks */
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect) {
    const uint256& hash = pindex->GetBlockHash();
    CBlock *block;

    block = GetBlockByHash(iface, hash);
    if (!block)
      block = GetArchBlockByHash(iface, hash); /* orphan */
    if (!block) {
      error(SHERR_INVAL, "(%s) CommitBlock: error obtaining disconnect block '%s'", iface->name, hash.GetHex().c_str());
      fValid = false;
      break;
    }

    mDisconBlocks[hash] = block;
    vFree.push_back(block);
  }
  if (!fValid)
    goto fin;

  /* connect blocks */
  BOOST_FOREACH(CBlockIndex *pindex, vConnect) {
    const uint256& hash = pindex->GetBlockHash();
    CBlock *block;

    if (pindexNew->GetBlockHash() == pindex->GetBlockHash()) {
      block = pblock;
    } else {
      block = GetBlockByHash(iface, hash);
      if (!block)
        block = GetArchBlockByHash(iface, hash); /* orphan */
      if (block)
        vFree.push_back(block);
    }
    if (!block) {
			error(SHERR_INVAL, "(%s) CommitBlock: unknown connect block '%s'", iface->name, hash.GetHex().c_str());
			fValid = false;
      break;
    }

    mConnectBlocks[hash] = block;
  }
  if (!fValid)
    goto fin;

  /* perform discon */
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect) {
    CBlock *block = mDisconBlocks[pindex->GetBlockHash()];

    if (!block->DisconnectBlock(pindex)) {
      error(SHERR_INVAL, "Reorganize() : DisonnectBlock %s failed", pindex->GetBlockHash().ToString().c_str());
      fValid = false;
			pindexFail = pindex;
      break;
    }

    if (pblock->WriteArchBlock())
			pindex->nStatus |= BLOCK_HAVE_UNDO;
		if (pindex->pprev) 
			pindexLast = pindex->pprev;
  }
  if (!fValid)
    goto fin;

  /* perform connect */
  BOOST_FOREACH(CBlockIndex *pindex, vConnect) {
    CBlock *block = mConnectBlocks[pindex->GetBlockHash()];
		bool fOk;

    fOk = block->ConnectBlock(pindex);
		if (!fOk) {
      error(SHERR_INVAL, "(%s) core_CommitBlock: ConnectBlock \"%s\" failure.", iface->name, pindex->GetBlockHash().ToString().c_str());
      fValid = false;
			pindexFail = pindex;
      break;
    }

		pindex->nStatus |= BLOCK_HAVE_DATA;
		pindexLast = pindex;
  }
  if (!fValid)
    goto fin;

  // Disconnect shorter branch
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
    if (pindex->pprev)
      pindex->pprev->pnext = NULL;

  // Connect longer branch
  BOOST_FOREACH(CBlockIndex* pindex, vConnect)
    if (pindex->pprev)
      pindex->pprev->pnext = pindex;

  /* add discon block tx's into pending pool */
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect) {
    CBlock *block = mDisconBlocks[pindex->GetBlockHash()];
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (tx.IsCoinBase())
        continue;

      pool->AddTx(tx);
    }
  }

  /* remove connected block tx's from pool */ 
  BOOST_FOREACH(CBlockIndex* pindex, vConnect) {
    CBlock *block = mConnectBlocks[pindex->GetBlockHash()];
    pool->Commit(*block);
  }

fin:
	if (!fValid && pindexFail) {
		error(SHERR_INVAL, "(%s) core_CommitBlock: invalid chain block=%s  height=%d  work=%s  date=%s\n",
				iface->name, pindexFail->GetBlockHash().GetHex().c_str(),
				pindexFail->nHeight, pindexFail->bnChainWork.ToString().c_str(),
				DateTimeStrFormat("%x %H:%M:%S", pindexFail->GetBlockTime()).c_str());
	}

	if (pbest != pindexLast->pprev) {
		/* re-establish chain at our failure/success point. */
		WriteHashBestChain(iface, pindexLast->GetBlockHash());
		SetBestBlockIndex(pblock->ifaceIndex, pindexLast);
		wallet->bnBestChainWork = pindexLast->bnChainWork;
		wallet->pindexBestHeader = pindexLast;

		/* mark block as invalid. */
		iface->net_invalid = time(NULL);
		if (pindexFail)
			pindexFail->nStatus |= BLOCK_FAILED_VALID;

		Debug("(%s) core_CommitBlock: re-established chain at block \"%s\" (height %u).", iface->name, pindexLast->GetBlockHash().GetHex().c_str(), (unsigned int)pindexLast->nHeight); 
	} else {
		/* added one new block. */
		WriteHashBestChain(iface, pindexNew->GetBlockHash());
		SetBestBlockIndex(pblock->ifaceIndex, pindexNew);
	}

  BOOST_FOREACH(CBlock *block, vFree) {
    delete block;
  }

  return (fValid);
}

void CTransaction::Init(const CTransaction& tx)
{
  int i;

  nFlag = tx.nFlag;
	/*
  vin = tx.vin;
  vout = tx.vout;
  wit = tx.wit;
	*/
  nLockTime = tx.nLockTime;

  vin.resize(tx.vin.size());
  for (i = 0; i < tx.vin.size(); i++)
    vin[i] = tx.vin[i]; 
  vout.resize(tx.vout.size());
  for (i = 0; i < tx.vout.size(); i++)
    vout[i] = tx.vout[i]; 
  wit.vtxinwit.resize(tx.wit.vtxinwit.size());
  for (i = 0; i < tx.wit.vtxinwit.size(); i++)
    wit.vtxinwit[i] = tx.wit.vtxinwit[i]; 

	if (this->nFlag & TXF_MATRIX)
		matrix = tx.matrix;

	if (this->nFlag & TXF_ALIAS)
		alias = CAlias(tx.alias);

	if (this->nFlag & TXF_CERTIFICATE)
		certificate = tx.certificate;
	else if (this->nFlag & TXF_CONTEXT)
		certificate = tx.certificate;
	else if (this->nFlag & TXF_LICENSE)
		certificate = tx.certificate;

	if (this->nFlag & TXF_IDENT)
		ident = tx.ident;

	if (this->nFlag & TXF_ASSET) {
		asset = tx.asset;
	}

	/* non-exclusive */
	if (this->nFlag & TXF_OFFER)
		offer = tx.offer;

	/* non-exclusive */
	if (this->nFlag & TXF_EXEC)
		exec = tx.exec;

	/* non-exclusive */
	if (this->nFlag & TXF_ALTCHAIN)
		altchain = tx.altchain;

	/* non-exclusive */
	if (this->nFlag & TXF_PARAM)
		param = tx.param;

}

unsigned int GetBlockScriptFlags(CIface *iface, const CBlockIndex* pindex)
{
	unsigned int flags = SCRIPT_VERIFY_NONE;

	// Start enforcing P2SH (BIP16)
	if (iface->BIP16Height != -1 &&
			pindex->nHeight >= iface->BIP16Height) {
		flags |= SCRIPT_VERIFY_P2SH;
	}

	// Start enforcing the DERSIG (BIP66) rule
	if (iface->BIP66Height != -1 &&
			pindex->nHeight >= iface->BIP66Height) {
		flags |= SCRIPT_VERIFY_DERSIG;
	}

	// Start enforcing CHECKLOCKTIMEVERIFY (BIP65) rule
	if (iface->BIP65Height != -1 &&
			pindex->nHeight >= iface->BIP65Height) {
		flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
	}

	/* enforce BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic. */
	if (VersionBitsState(pindex->pprev, iface, DEPLOYMENT_CSV) == THRESHOLD_ACTIVE) {
		flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
	}

	// Start enforcing WITNESS rules using versionbits logic.
	if (IsWitnessEnabled(iface, pindex->pprev)) {
		flags |= SCRIPT_VERIFY_WITNESS;
		flags |= SCRIPT_VERIFY_NULLDUMMY;
	}

	return flags;
}


std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{

	// Will be set to the equivalent height- and time-based nLockTime
	// values that would be necessary to satisfy all relative lock-
	// time constraints given our view of block chain history.
	// The semantics of nLockTime are the last invalid height/time, so
	// use -1 to have the effect of any height or time being valid.
	int nMinHeight = -1;
	int64_t nMinTime = -1;

	if (prevHeights->size() != tx.vin.size())
		return std::make_pair(nMinHeight, nMinTime); /* invalid param */


	// tx.nVersion is signed integer so requires cast to unsigned otherwise
	// we would be doing a signed comparison and half the range of nVersion
	// wouldn't support BIP 68.
	bool fEnforceBIP68 = 
		(tx.GetVersion() >= 2) &&
		(flags & LOCKTIME_VERIFY_SEQUENCE);

	// Do not enforce sequence numbers as a relative lock time
	// unless we have been instructed to
	if (!fEnforceBIP68) {
		return std::make_pair(nMinHeight, nMinTime);
	}

	for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
		const CTxIn& txin = tx.vin[txinIndex];

		// Sequence numbers with the most significant bit set are not
		// treated as relative lock-times, nor are they given any
		// consensus-enforced meaning at this point.
		if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
			// The height of this input is not relevant for sequence locks
			(*prevHeights)[txinIndex] = 0;
			continue;
		}

		int nCoinHeight = (*prevHeights)[txinIndex];

		if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
			int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
			// NOTE: Subtract 1 to maintain nLockTime semantics
			// BIP 68 relative lock times have the semantics of calculating
			// the first block or time at which the transaction would be
			// valid. When calculating the effective block time or height
			// for the entire transaction, we switch to using the
			// semantics of nLockTime which is the last invalid block
			// time or height.  Thus we subtract 1 from the calculated
			// time or height.

			// Time-based relative lock-times are measured from the
			// smallest allowed timestamp of the block containing the
			// txout being spent, which is the median time past of the
			// block prior.
			nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
		} else {
			nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
		}
	}

	return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
	if (!block.pprev)
		return (false);
	int64_t nBlockTime = block.pprev->GetMedianTimePast();
	if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
		return false;

	return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
	return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

bool CheckSequenceLocks(CIface *iface, const CTransaction &tx, int flags)
{
	CBlockIndex *tip = GetBestBlockIndex(iface);

	if (!tip)
		return (false); /* invalid state */

	CBlockIndex index;
	index.pprev = tip;
	// CheckSequenceLocks() uses chainActive.Height()+1 to evaluate
	// height based locks because when SequenceLocks() is called within
	// ConnectBlock(), the height of the block *being*
	// evaluated is what is used.
	// Thus if we want to know if a transaction can be part of the
	// *next* block, we need to use one more than chainActive.Height()
	index.nHeight = tip->nHeight + 1;

	std::pair<int, int64_t> lockPair;

	// pcoinsTip contains the UTXO set for chainActive.Tip()
	CTxMemPool *pool = GetTxMemPool(iface);
	std::vector<int> prevheights;
	prevheights.resize(tx.vin.size());
	for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
		const CTxIn& txin = tx.vin[txinIndex];
		CTransaction txIn;

		int nHeight = tip->nHeight + 1;
		CBlockIndex *pindexIn = GetBlockIndexByTx(iface, txin.prevout.hash);
		if (pindexIn) {
			nHeight = pindexIn->nHeight;
		} else if (pool->GetTx(txin.prevout.hash, txIn)) {
			nHeight = tip->nHeight + 1;
		} else {
			return (false); /* unknown input tx */
		}
 
		prevheights[txinIndex] = nHeight;
	}

	lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
	return EvaluateSequenceLocks(index, lockPair);
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-nullptr. */
CBlockIndex* LastCommonAncestor(CBlockIndex* pa, CBlockIndex* pb) 
{
	if (pa->nHeight > pb->nHeight) {
		pa = pa->GetAncestor(pb->nHeight);
	} else if (pb->nHeight > pa->nHeight) {
		pb = pb->GetAncestor(pa->nHeight);
	}

	while (pa != pb && pa && pb) {
		pa = pa->pprev;
		pb = pb->pprev;
	}

	return pa;
} 

uint256 CBlockHeader::GetPoWHash() const
{
	uint256 thash;

	thash = ~0;

	if (ifaceIndex == TEST_COIN_IFACE ||
			ifaceIndex == TESTNET_COIN_IFACE ||
			ifaceIndex == SHC_COIN_IFACE ||
			ifaceIndex == COLOR_COIN_IFACE) {
		switch (GetVersionAlgo(nVersion)) {
			case ALGO_SHA256D:
				{
					return GetHash();
				}
			case ALGO_KECCAK:
				{
					keccakhash(UBEGIN(thash), UBEGIN(nVersion));
					return (thash);
				}
			case ALGO_X11:
				{
					x11hash(UBEGIN(thash), UBEGIN(nVersion));
					return (thash);
				}
			case ALGO_BLAKE2S:
				{
					blake2s_hash(UBEGIN(thash), UBEGIN(nVersion));
					return (thash);
				}
			case ALGO_QUBIT:
				{
					qubithash(UBEGIN(thash), UBEGIN(nVersion));
					return (thash);
				}
			case ALGO_GROESTL:
				{
					groestlhash(UBEGIN(thash), UBEGIN(nVersion));
					return (thash);
				}
			case ALGO_SKEIN:
				{
					skeinhash(UBEGIN(thash), UBEGIN(nVersion));
					return (thash);
				}
		}
	}

	/* default: case ALGO_SCRYPT: */
	scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
	return thash;
}

const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, int algo)
{

	for (; pindex; pindex = pindex->pprev) {
		if (GetVersionAlgo(pindex->nVersion) != algo)
			continue;

		return pindex;
	}

	return nullptr;
}

CBigNum CBlockIndex::GetBlockWork(bool fUseAlgo) const
{
	CBigNum bnTarget;
	bnTarget.SetCompact(nBits);
	bnTarget *= GetAlgoWorkFactor(GetVersionAlgo(nVersion));
	if (bnTarget <= 0)
		return 0;
	return (CBigNum(1)<<256) / (bnTarget+1);
}

static void _PubKeyToJSON(int ifaceIndex, const CScript& scriptPubKey, Object& out)
{
	txnouttype type;
	vector<CTxDestination> addresses;
	int nRequired;

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

Object CTxOut::ToValue(int ifaceIndex)
{
  Object obj;

	obj.push_back(Pair("value", ValueFromAmount(nValue)));

	Object scriptSig;
	scriptSig.push_back(Pair("asm", scriptPubKey.ToString()));
	scriptSig.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
	obj.push_back(Pair("scriptSig", scriptSig));

	_PubKeyToJSON(ifaceIndex, scriptPubKey, obj); 

	return (obj);
}

std::string CTxOut::ToString(int ifaceIndex)
{
  return (write_string(Value(ToValue(ifaceIndex)), false));
}


