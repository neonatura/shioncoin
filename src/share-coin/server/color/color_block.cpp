
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "color_pool.h"
#include "color_block.h"
#include "color_wallet.h"
#include "color_txidx.h"
#include "chain.h"
#include "coin.h"

#ifdef WIN32
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef fcntl
#undef fcntl
#endif

using namespace std;
using namespace boost;


static int clropt_default_table[MAX_CLROPT] = 
{
	0,
	1, /* DIFF: >> 11 */
	1, /* TARGET: 60s */
	1, /* MATURE: 60 */
	1, /* REWARD: 1 */
	1, /* HALF: 1000 */
	1, /* FEE: 0.0000001 */
};

/* there is no pre-defined single genesis block for an alt-chain. */
static const CBigNum COLOR_bnGenesisProofOfWorkLimit(~uint256(0) >> 12);

/* the minimum proof-of-work to create a new block on an alt-chain. */ 
static const CBigNum COLOR_bnProofOfWorkLimit(~uint256(0) >> 11);

static std::map<uint160, color_opt> mapColorOpt;

static unsigned int color_KimotoGravityWell(const CBlockIndex* pindexLast, const CBlock *pblock, uint64 TargetBlocksSpacingSeconds, uint64 PastBlocksMin, uint64 PastBlocksMax, CBigNum bnProofOfWorkLimit) 
{
  const CBlockIndex *BlockLastSolved	= pindexLast;
  const CBlockIndex *BlockReading	= pindexLast;
  uint64	PastBlocksMass	= 0;
  int64	PastRateActualSeconds	= 0;
  int64	PastRateTargetSeconds	= 0;
  double	PastRateAdjustmentRatio	= double(1);
  CBigNum	PastDifficultyAverage;
  CBigNum	PastDifficultyAveragePrev;
  double	EventHorizonDeviation;
  double	EventHorizonDeviationFast;
  double	EventHorizonDeviationSlow;

  if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64)BlockLastSolved->nHeight < PastBlocksMin) { return bnProofOfWorkLimit.GetCompact(); }

  int64 LatestBlockTime = BlockLastSolved->GetBlockTime();

  for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
    if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
    PastBlocksMass++;

    if (i == 1)	{ PastDifficultyAverage.SetCompact(BlockReading->nBits); }
    else	{ PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev; }
    PastDifficultyAveragePrev = PastDifficultyAverage;

    if (LatestBlockTime < BlockReading->GetBlockTime())
      LatestBlockTime = BlockReading->GetBlockTime();

    PastRateActualSeconds                   = LatestBlockTime - BlockReading->GetBlockTime();
    PastRateTargetSeconds	= TargetBlocksSpacingSeconds * PastBlocksMass;
    PastRateAdjustmentRatio	= double(1);

    if (PastRateActualSeconds < 1)
      PastRateActualSeconds = 1;

    if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
      PastRateAdjustmentRatio	= double(PastRateTargetSeconds) / double(PastRateActualSeconds);
    }
    EventHorizonDeviation	= 1 + (0.7084 * pow((double(PastBlocksMass)/double(144)), -1.228));
    EventHorizonDeviationFast	= EventHorizonDeviation;
    EventHorizonDeviationSlow	= 1 / EventHorizonDeviation;

    if (PastBlocksMass >= PastBlocksMin) {
      if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) { assert(BlockReading); break; }
    }
    if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
    BlockReading = BlockReading->pprev;
  }

  CBigNum bnNew(PastDifficultyAverage);
  if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
    bnNew *= PastRateActualSeconds;
    bnNew /= PastRateTargetSeconds;
  }
  if (bnNew > bnProofOfWorkLimit) { bnNew = bnProofOfWorkLimit; }

  return bnNew.GetCompact();
}

static unsigned int color_KimotoGravityWell(const CBlockIndex* pindexLast, const CBlock *pblock, uint160 hColor)
{
  static unsigned int	TimeDaySeconds	= 60 * 60 * 24;
	int64 BlocksTargetSpacing;
	CBigNum bnProofOfWorkLimit;

	BlocksTargetSpacing = color_GetBlockTarget(hColor);
  int64	PastSecondsMin	= TimeDaySeconds * 0.10;
  int64	PastSecondsMax	= TimeDaySeconds * 2.8;
  uint64	PastBlocksMin	= PastSecondsMin / BlocksTargetSpacing;
  uint64	PastBlocksMax	= PastSecondsMax / BlocksTargetSpacing;	

	if (pindexLast == NULL)
		bnProofOfWorkLimit = COLOR_bnGenesisProofOfWorkLimit;
	else
		bnProofOfWorkLimit = color_GetMinDifficulty(hColor);

	return (color_KimotoGravityWell(pindexLast, pblock, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax, bnProofOfWorkLimit));
}


/* ** BLOCK ORPHANS ** */

typedef map<uint256, uint256> orphan_map;
static orphan_map COLOR_mapOrphanBlocksByPrev;

bool color_IsOrphanBlock(const uint256& hash)
{
  CBlockIndex *pindex;
  COLORBlock block;
  uint256 prevHash;
  bool ok;

  if (color_GetOrphanPrevHash(hash, prevHash)) {
    /* already mapped. */
    return (true);
  }

#if 0
  pindex = GetBlockIndexByHash(COLOR_COIN_IFACE, hash);
  if (pindex) {
    if (GetBestHeight(COLOR_COIN_IFACE) >= pindex->nHeight &&
        block.ReadFromDisk(pindex))
      return (false); /* present in block-chain */
  }

  if (!block.ReadArchBlock(hash))
    return (false); /* no record in archive db */
  return (true);
#endif

  return (false); 
}

void color_AddOrphanBlock(CBlock *block)
{

  COLOR_mapOrphanBlocksByPrev.insert(
      make_pair(block->hashPrevBlock, block->GetHash()));
  block->WriteArchBlock();

}

void color_RemoveOrphanBlock(const uint256& hash)
{
  bool found;

  orphan_map::iterator it = COLOR_mapOrphanBlocksByPrev.begin(); 
  while (it != COLOR_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found)
      break;
    ++it;
  }
  if (it != COLOR_mapOrphanBlocksByPrev.end()) {
    COLOR_mapOrphanBlocksByPrev.erase(it);
  }
  
}

bool color_GetOrphanPrevHash(const uint256& hash, uint256& retPrevHash)
{
  bool found;

  orphan_map::iterator it = COLOR_mapOrphanBlocksByPrev.begin(); 
  while (it != COLOR_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found) {
      retPrevHash = it->first;
      return (true);
    }
    ++it;
  }

  return (false);
}

bool color_GetOrphanNextHash(const uint256& hash, uint256& retNextHash)
{
  bool found;

  orphan_map::iterator it = COLOR_mapOrphanBlocksByPrev.find(hash);
  if (it != COLOR_mapOrphanBlocksByPrev.end()) {
    retNextHash = it->second;
    return (true);
  }
  return (false);
}

CBlock *color_GetOrphanBlock(const uint256& hash)
{
  COLORBlock block;  

  if (!block.ReadArchBlock(hash))
    return (NULL);

  return (new COLORBlock(block));
}

uint256 color_GetOrphanRoot(uint256 hash)
{
  uint256 prevHash;

  while (color_GetOrphanPrevHash(hash, prevHash)) {
    hash = prevHash;
  }
  return (hash);
}

unsigned int COLORBlock::GetNextWorkRequired(const CBlockIndex* pindexLast)
{
  if (pindexLast == NULL)
    return (COLOR_bnGenesisProofOfWorkLimit.GetCompact());
  return color_KimotoGravityWell(pindexLast, this, hColor);
}

static int64_t color_GetTxWeight(const CTransaction& tx)
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(tx, SER_NETWORK, COLOR_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (COLOR_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(tx, SER_NETWORK, COLOR_PROTOCOL_VERSION);

  return (weight);
}

int64 color_GetBlockValue(uint160 hColor, int nHeight, int64 nFees)
{
  double base;
  double fact;
	double rate;
  int64 nValue;

	base = (double)color_GetBlockValueBase(hColor);
	rate = (double)color_GetBlockValueBase(hColor); 
    
  fact = ((nHeight + 1) / rate) + 1;
  nValue = (int64)(base / fact) + nFees;
    
  nValue /= 1000000;
  nValue *= 10000000;

  return (nValue);
}

CBlockIndex *GetBestColorBlockIndex(CIface *iface, uint160 hColor)
{
	CWallet *wallet = GetWallet(iface);
	blkidx_t *blockIndex;
	uint256 hash;

	blockIndex = GetBlockTable(COLOR_COIN_IFACE);
	if (!blockIndex)
		return (NULL);

	if (wallet->mapColorPool.count(hColor) != 0) {
		/* alt-chain pool */
		hash = wallet->mapColorPool[hColor];
		blkidx_t::iterator mi = blockIndex->find(hash);
		if (mi != blockIndex->end())
			return (mi->second);
	}

	if (wallet->mapColor.count(hColor) != 0) {
		/* alt-chain for color */
		hash = wallet->mapColor[hColor];
		blkidx_t::iterator mi = blockIndex->find(hash);
		if (mi != blockIndex->end())
			return (mi->second);
	}

	return (NULL);
}

bool color_GetBlockColor(CIface *iface, CBlockIndex *pindex, uint160& hColor)
{
	CWallet *wallet = GetWallet(iface);

	if (!wallet)
		return (false);

	while (pindex && pindex->pprev)
		pindex = pindex->pprev;
	if (!pindex)
		return (false);
	
	const uint256& hBlock = pindex->GetBlockHash();
	if (wallet->mapColorHead.count(hBlock) == 0)
		return (false);

	hColor = wallet->mapColorHead[hBlock]; 
	return (true);
}

COLORBlock* color_CreateNewBlock(uint160 hColor, CBlockIndex *pindexPrev, const CPubKey& rkey)
{
  CIface *iface = GetCoinByIndex(COLOR_COIN_IFACE);
  int64 nFees = 0;

  auto_ptr<COLORBlock> pblock(new COLORBlock());
  if (!pblock.get())
    return NULL;

	pblock->hColor = hColor;

  /* coinbase */
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vin[0].prevout.SetNull();
  txNew.vout.resize(1);

	//txNew.vout[0].scriptPubKey.SetDestination(rkey.GetID());
  txNew.vout[0].scriptPubKey << rkey << OP_CHECKSIG;
  pblock->vtx.push_back(txNew);

	/* calculate current tail-block height */
	unsigned int nHeight = 0;
	GetColorBlockHeight(pindexPrev, nHeight);

  CTxMemPool *pool = GetTxMemPool(iface); 
  vector<CTransaction> vPriority = pool->GetActiveColorTx(hColor); 
  BOOST_FOREACH(CTransaction tx, vPriority) {
    const uint256& hash = tx.GetHash();
    tx_cache mapInputs;

    if (pool->FetchInputs(hash, mapInputs)) {
      int64 nTxFee = tx.GetValueIn(mapInputs)-tx.GetValueOut();
      nFees += nTxFee;
      pblock->vtx.push_back(tx);
    }
  }

  /* calculate reward */
	pblock->vtx[0].vout[0].nValue = color_GetBlockValue(hColor, nHeight+1, nFees);

  /* define core header */
  pblock->nVersion = 4;//core_ComputeBlockVersion(iface, pindexPrev);
  pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
  pblock->UpdateTime(pindexPrev);
  pblock->nBits          = pblock->GetNextWorkRequired(pindexPrev);
  pblock->nNonce         = 0;

	//core_IncrementExtraNonce(pblock.get(), pindexPrev);
	{ /* BIP39 */
		CScript COINBASE_FLAGS = GetCoinbaseFlags(pblock->ifaceIndex);
		unsigned int qual = nHeight + 1;
		char hex[256];

		sprintf(hex, "%sf0000000", GetSiteExtraNonceHex());
		string hexStr(hex, hex + strlen(hex));
		pblock->vtx[0].vin[0].scriptSig = 
			(CScript() << qual << ParseHex(hexStr)) + 
			COINBASE_FLAGS;
	}

  return pblock.release();
}


void SetColorOpt(color_opt& opt, int mode, int val)
{
	opt[mode] = val;
}

int GetColorOptValue(color_opt& opt, int mode)
{
	if (opt.count(mode) == 0)
		return (0);
	return ((int)opt[mode]);
}

CScript GetColorOptScript(const color_opt& opt)
{
	CScript script;

	script << OP_RETURN << OP_0;
	BOOST_FOREACH(const PAIRTYPE(int, int)& tok, opt) {
		script << CScript::EncodeOP_N(tok.first); 
		script << CScript::EncodeOP_N(tok.second); 
	}

	return (script);
}

void ParseColorOptScript(color_opt& opt, CScript script)
{
	CScript::const_iterator pc1 = script.begin();
	opcodetype modecode, valuecode;
	int mode, value;

	if (!script.GetOp(pc1, modecode))
		return;
	if (!script.GetOp(pc1, valuecode))
		return;
	if (modecode != OP_RETURN) {
		return; /* invalid format */
	}
	if (valuecode != OP_0) {
		return; /* invalid format */
	}

	while (pc1 != script.end()) {
		if (!script.GetOp(pc1, modecode))
			break;
		if (!script.GetOp(pc1, valuecode))
			break;
		mode = CScript::DecodeOP_N(modecode);
		value = CScript::DecodeOP_N(valuecode);
		if (mode == 0 || value == 0) continue;
		opt[mode] = value;
	}

}

/** Creates the intial block in a chain for a particular color. Requires finding a suitable nonce against the genesis difficulty and provides no coin reward. */ 
COLORBlock *color_CreateGenesisBlock(uint160 hColor, const color_opt& opt)
{

  auto_ptr<COLORBlock> pblock(new COLORBlock());
  if (!pblock.get())
    return NULL;

	/* define color */
	pblock->hColor = hColor;

  /* coinbase */
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vin[0].prevout.SetNull();
  txNew.vout.resize(1);
  txNew.vout[0].scriptPubKey += GetColorOptScript(opt);
  txNew.vout[0].nValue = color_GetBlockValue(hColor, 0, 0);
  pblock->vtx.push_back(txNew);

  /* define core header */
  pblock->nVersion = 4;
  pblock->hashPrevBlock  = 0;
  pblock->nBits          = pblock->GetNextWorkRequired(NULL);
  pblock->UpdateTime(NULL);
  pblock->nNonce         = 0;

	{ /* BIP39 */
		CScript COINBASE_FLAGS = GetCoinbaseFlags(pblock->ifaceIndex);
		unsigned int qual = 0;
		char hex[256];

		sprintf(hex, "%sf0000000", GetSiteExtraNonceHex());
		string hexStr(hex, hex + strlen(hex));
		pblock->vtx[0].vin[0].scriptSig = 
			(CScript() << qual << ParseHex(hexStr)) + 
			COINBASE_FLAGS;
	}

  return (pblock.release());
}

/** Verify the initial block of an alt-chain. */
bool color_VerifyGenesisBlock(const CBlock& block)
{
	
	if (block.nVersion == 0)
		return (false);
	if (block.hashPrevBlock != 0)
		return (false);
	if (block.vtx.size() == 0)
		return (false);
	if (!block.vtx[0].vin[0].prevout.IsNull())
		return (false);
	if (block.vtx[0].vout.size() == 0)
		return (false);

  CBigNum bnResult;
  bnResult.SetCompact(block.nBits);
	if (bnResult > COLOR_bnGenesisProofOfWorkLimit) {
		/* too low difficulty. */
		return (false);
	}

	return (true);
}

CBlock *color_GenerateNewBlock(CIface *iface, const CPubKey& rkey, uint160 hColor, vector<CTransaction> vTx, const color_opt& opt)
{
	CBlockIndex *pindexPrev;
	COLORBlock *pblock;

	pindexPrev = GetBestColorBlockIndex(iface, hColor);

	// Create new block
	if (!pindexPrev) {
		/* create genesis block. */
		pblock = color_CreateGenesisBlock(hColor, opt);
	} else {
		/* chained color block */
		CWallet *wallet = GetWallet(COLOR_COIN_IFACE);
		pblock = color_CreateNewBlock(hColor, pindexPrev, rkey);
	}
	if (!pblock)
		return (NULL);

	if (vTx.size() != 0) {
		for (int i = 0; i < vTx.size(); i++) {
			pblock->vtx.insert(pblock->vtx.end(), vTx[i]);
		}
	}

	return pblock;
}

void color_GenerateNewBlockNonce(CIface *iface, CBlock *block)
{
	static unsigned int nNonceIndex = 0xE2222222;

	if (!block)
		return;

	block->nNonce   = ++nNonceIndex;
	{
		uint256 hashTarget = CBigNum().SetCompact(block->nBits).getuint256();
		uint256 thash;
		char scratchpad[SCRYPT_SCRATCHPAD_SIZE];

		loop
		{
			scrypt_1024_1_1_256_sp(BEGIN(block->nVersion), BEGIN(thash), scratchpad);
			if (thash <= hashTarget)
				break;

			++block->nNonce;
			if (block->nNonce == 0)
			{
				++block->nTime;
			}
		}
	}
	nNonceIndex = block->nNonce;

}



static bool color_IsFromMe(CTransaction& tx)
{
  CWallet *pwallet = GetWallet(COLOR_COIN_IFACE);

  if (pwallet->IsFromMe(tx))
    return true;

  return false;
}

static void color_EraseFromWallets(uint256 hash)
{
  CWallet *pwallet = GetWallet(COLOR_COIN_IFACE);

  pwallet->EraseFromWallet(hash);
}

bool color_ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(COLOR_COIN_IFACE);
  int ifaceIndex = COLOR_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
  shtime_t ts;

  // Check for duplicate
  uint256 hash = pblock->GetHash();

  // Preliminary checks
  if (!pblock->CheckBlock()) {
    return error(SHERR_INVAL, "ProcessBlock() : CheckBlock FAILED");
  }

  if (!pblock->CheckTransactionInputs(ifaceIndex)) {
    Debug("(color) ProcessBlock: invalid input transaction [prev %s].", pblock->hashPrevBlock.GetHex().c_str());
    return (true);
  }

  /* store to disk */
  if (!pblock->AcceptBlock()) {
    iface->net_invalid = time(NULL);
    return error(SHERR_IO, "COLORBlock::AcceptBlock: error adding block '%s'.", pblock->GetHash().GetHex().c_str());
  }

  return true;
}

bool color_CheckProofOfWork(uint256 hash, unsigned int nBits)
{
  CBigNum bnTarget;
  bnTarget.SetCompact(nBits);

  // Check range
  if (bnTarget <= 0 || bnTarget > COLOR_bnProofOfWorkLimit)
    return error(SHERR_INVAL, "CheckProofOfWork() : nBits below minimum work");

  // Check proof of work matches claimed amount
  if (hash > bnTarget.getuint256())
    return error(SHERR_INVAL, "CheckProofOfWork() : hash doesn't match nBits");

  return true;
}

/**
 * @note These are checks that are independent of context that can be verified before saving an orphan block.
 */
bool COLORBlock::CheckBlock()
{
  CIface *iface = GetCoinByIndex(COLOR_COIN_IFACE);

	if (hashPrevBlock == 0) {
		if (!color_VerifyGenesisBlock(*this))
			return (error(-80, "(color) CheckBlock: invalid genesis block."));
	}

  if (vtx.empty()) { 
    return (trust(-80, "(color) CheckBlock: block submitted with zero transactions"));
  }

  int64_t weight = GetBlockWeight();
  if (weight > MAX_BLOCK_WEIGHT(iface)) {
    return (trust(-80, "(color) CheckBlock: block weight (%d) > max (%d)", weight, MAX_BLOCK_WEIGHT(iface)));
  }


#if 0
  if (vtx[0].GetValueOut() > color_GetBlockValue(nHeight, nFees)) {
    return (false);
  }
#endif

  if (vtx.empty() || !vtx[0].IsCoinBase())
    return error(SHERR_INVAL, "CheckBlock() : first tx is not coinbase");

  // Check proof of work matches claimed amount
  if (!color_CheckProofOfWork(GetPoWHash(), nBits)) {
    return error(SHERR_INVAL, "CheckBlock() : proof of work failed");
  }

  // Check timestamp
  if (GetBlockTime() > GetAdjustedTime() + COLOR_MAX_DRIFT_TIME) {
    return error(SHERR_INVAL, "CheckBlock() : block timestamp too far in the future");
  }

  for (unsigned int i = 1; i < vtx.size(); i++)
    if (vtx[i].IsCoinBase()) {
      return error(SHERR_INVAL, "CheckBlock() : more than one coinbase");
    }

  // Check transactions
  BOOST_FOREACH(CTransaction& tx, vtx)
    if (!tx.CheckTransaction(COLOR_COIN_IFACE)) {
      return error(SHERR_INVAL, "CheckBlock() : CheckTransaction failed");
    }

  // Check for duplicate txids. This is caught by ConnectInputs(),
  // but catching it earlier avoids a potential DoS attack:
  set<uint256> uniqueTx;
  BOOST_FOREACH(const CTransaction& tx, vtx)
  {
    uniqueTx.insert(tx.GetHash());
  }
  if (uniqueTx.size() != vtx.size()) {
    return error(SHERR_INVAL, "CheckBlock() : duplicate transaction");
  }

  unsigned int nSigOps = 0;
  BOOST_FOREACH(const CTransaction& tx, vtx)
  {
    nSigOps += tx.GetLegacySigOpCount();
  }
  if (nSigOps > MAX_BLOCK_SIGOPS(iface)) {
    return error(SHERR_INVAL, "CheckBlock() : out-of-bounds SigOpCount");
  }

  // Check merkleroot
  if (hashMerkleRoot != BuildMerkleTree()) {
    return error(SHERR_INVAL, "CheckBlock() : hashMerkleRoot mismatch");
  }

  return true;
}

void COLORBlock::InvalidChainFound(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(COLOR_COIN_IFACE);
  char errbuf[1024];

  
  sprintf(errbuf, "COLOR: InvalidChainFound: invalid block=%s  height=%d  work=%s  date=%s\n", pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight, pindexNew->bnChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
  unet_log(COLOR_COIN_IFACE, errbuf);


}

// notify wallets about a new best chain
void static COLOR_SetBestChain(const CBlockLocator& loc)
{
  CWallet *pwallet = GetWallet(COLOR_COIN_IFACE);

  pwallet->SetBestChain(loc);
}

bool COLORBlock::IsBestChain()
{
  CBlockIndex *pindexBest = GetBestBlockIndex(COLOR_COIN_IFACE);
  return (pindexBest && GetHash() == pindexBest->GetBlockHash());
}

unsigned int color_GetTotalBlocks()
{
	CIface *iface = GetCoinByIndex(COLOR_COIN_IFACE);
	bcpos_t nHeight = 0;
	(void)bc_idx_next(GetBlockChain(iface), &nHeight);
	return ((unsigned int)nHeight);
}

bool COLORBlock::AcceptBlock()
{
	CIface *iface = GetCoinByIndex(COLOR_COIN_IFACE);
	CWallet *alt_wallet = GetWallet(COLOR_COIN_IFACE);
	blkidx_t *blockIndex = GetBlockTable(COLOR_COIN_IFACE);
	map<uint256, CTransaction> mapTx;
	tx_map mapOutputs;
	int64 nFees = 0;
	int nSigOps = 0;
	int mode;

	/* verify integrity */
	CBlockIndex* pindexPrev = NULL;
	if (hashPrevBlock != 0) {
		map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hashPrevBlock);
		if (mi == blockIndex->end()) {
			return error(SHERR_INVAL, "(color) AcceptBlock: prev block '%s' not found", hashPrevBlock.GetHex().c_str());
		}
		pindexPrev = (*mi).second;
	}

	if (GetBlockTime() > GetAdjustedTime() + COLOR_MAX_DRIFT_TIME) {
		print();
		return error(SHERR_INVAL, "(color) AcceptBlock: block's timestamp too new.");
	}

	if (pindexPrev) {
		if (GetBlockTime() <= pindexPrev->GetMedianTimePast() ||
				GetBlockTime() < pindexPrev->GetBlockTime()) {	
			print();
			return error(SHERR_INVAL, "(color) AcceptBlock: block's timestamp is too old.");
		}
	}

	int nHeight = (pindexPrev ? (pindexPrev->nHeight+1) : 0);
	if (iface->BIP34Height != -1 && nHeight >= iface->BIP34Height) {
		/* check for obsolete blocks. */
		if (nVersion < 2)
			return (error(SHERR_INVAL, "(%s) AcceptBlock: rejecting obsolete block (ver: %u) (hash: %s) [BIP34].", iface->name, (unsigned int)nVersion, GetHash().GetHex().c_str()));

		/* verify height inclusion. */
		CScript expect = CScript() << nHeight;
		if (vtx[0].vin[0].scriptSig.size() < expect.size() ||
				!std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
			return error(SHERR_INVAL, "(%s) AcceptBlock: submit block \"%s\" has invalid commit height (next block height is %u).", iface->name, GetHash().GetHex().c_str(), nHeight);
	}
	if (iface->BIP66Height != -1 && nVersion < 3 && 
			nHeight >= iface->BIP66Height) {
		return (error(SHERR_INVAL, "(%s) AcceptBlock: rejecting obsolete block (ver: %u) (hash: %s) [BIP66].", iface->name, (unsigned int)nVersion, GetHash().GetHex().c_str()));
	}
	if (iface->BIP65Height != -1 && nVersion < 4 && 
			nHeight >= iface->BIP65Height) {
		return (error(SHERR_INVAL, "(%s) AcceptBlock: rejecting obsolete block (ver: %u) (hash: %s) [BIP65].", iface->name, (unsigned int)nVersion, GetHash().GetHex().c_str()));
	}

	unsigned int nBits = GetNextWorkRequired(pindexPrev);
	if (nBits != nBits) {
		return (trust(-100, "(core) AcceptBlock: invalid difficulty (%x) specified (next work required is %x) for block height %d [prev '%s']\n", nBits, nBits, pindexPrev?(pindexPrev->nHeight+1):0, pindexPrev->GetBlockHash().GetHex().c_str()));
	}
	if (!pindexPrev) {
		if (!color_VerifyGenesisBlock(*this)) {
			return (error(SHERR_INVAL, "(color) AcceptBlock: block failed genesis test."));
		}
	}

	/* add to memory block-chain list */
	if (!AddToBlockIndex()) {
		return(error(SHERR_INVAL, "(color) AcceptBlock: error adding block to block index table."));
	}
	CBlockIndex *pindex = GetBlockIndexByHash(COLOR_COIN_IFACE, GetHash());
	if (!pindex) {
		return(error(SHERR_INVAL, "(color) AcceptBlock: block index table lookup error."));
	}

#if 0
	/* do some more tests */
	BOOST_FOREACH(CTransaction& tx, vtx) {
		/* verify input signatures. */
		if (!core_ConnectCoinInputs(COLOR_COIN_IFACE, &tx, pindex, mapOutputs, mapTx, nSigOps, nFees, true, false, true, this)) {
			return (error(ERR_INVAL, "(color) AcceptBlock: ConnectCoinInputs error"));
		}
	}
	if (nSigOps > MAX_BLOCK_SIGOPS(iface)) {
		return error(SHERR_INVAL, 
				"(color) AcceptBlock: too many sigops (%d)", nSigOps);
	}
	if (vtx[0].GetValueOut() >
			alt_wallet->GetBlockValue(pindex->nHeight, nFees)) {
		return (error(SHERR_INVAL, 
					"(color) AcceptBlock: coinbaseValueOut(%f) > BlockValue(%f) @ height %d [fee %llu]", 
					((double)vtx[0].GetValueOut()/(double)COIN), ((double)alt_wallet->GetBlockValue(pindex->nHeight, nFees)/(double)COIN), pindex->nHeight, (unsigned long long)nFees));
	}
#endif

	/* permanently establish block. */
	uint64_t nTotalHeight = (uint64_t)color_GetTotalBlocks();
	if (!WriteBlock(nTotalHeight)) {
		return(error(SHERR_INVAL, "(color) AcceptBlock: error adding block to block-chain."));
	}

	/* update wallet */
	BOOST_FOREACH(CTransaction& tx, vtx) {
		const uint256& hTx = tx.GetHash();

		if (alt_wallet->IsFromMe(tx) || alt_wallet->IsMine(tx)) {
			CWalletTx wtx(alt_wallet, tx);
			// Get merkle branch if transaction was found in a block
			wtx.SetColor(hColor);
			wtx.SetMerkleBranch(this);
			wtx.BindWallet(alt_wallet);
			alt_wallet->AddToWallet(wtx);

			/* color_wallet.dat -- market spent */
			BOOST_FOREACH(const CTxIn& txin, wtx.vin)
			{
				if (alt_wallet->mapWallet.count(txin.prevout.hash) == 0)
					continue;

				CWalletTx &coin = alt_wallet->mapWallet[txin.prevout.hash];
				coin.BindWallet(alt_wallet);
				coin.MarkSpent(txin.prevout.n);
				coin.WriteToDisk();
			}

			Debug("(color) AcceptBlock: new wallet transaction \"%s\".", 
					hTx.GetHex().c_str());
		}

		{
			/* color_coin db */
			BOOST_FOREACH(const CTxIn& txin, tx.vin) {
				if (alt_wallet->mapWallet.count(txin.prevout.hash) == 0)
					continue;

				CWalletTx &coin = alt_wallet->mapWallet[txin.prevout.hash];
				coin.WriteCoins(COLOR_COIN_IFACE, txin.prevout.n, hTx); 
			}
		}

	}

	STAT_BLOCK_ACCEPTS(iface)++;
	return (true);
}

/* remove me */
CScript COLORBlock::GetCoinbaseFlags()
{
  return (COLOR_COINBASE_FLAGS);
}

static void color_UpdatedTransaction(const uint256& hashTx)
{
  CWallet *pwallet = GetWallet(COLOR_COIN_IFACE);

  pwallet->UpdatedTransaction(hashTx);
}

bool COLORBlock::ReadBlock(uint64_t nHeight)
{
int ifaceIndex = COLOR_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  size_t sBlockLen;
  unsigned char *sBlockData;
  char errbuf[1024];
  bc_t *bc;
  int err;

  bc = GetBlockChain(iface);
  if (!bc)
    return (false);

  err = bc_get(bc, nHeight, &sBlockData, &sBlockLen);
  if (err) {
    sprintf(errbuf, "CBlock::ReadBlock[height %d]: %s (sherr %d).",
      (int)nHeight, sherrstr(err), err);
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

  /* serialize binary data into block */
  {
    CDataStream sBlock(SER_DISK, CLIENT_VERSION);
    sBlock.write((const char *)sBlockData, sBlockLen);
    sBlock >> *this;
  }
  free(sBlockData);

  return (true);
}

bool COLORBlock::ReadArchBlock(uint256 hash)
{
  int ifaceIndex = COLOR_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
  size_t sBlockLen;
  unsigned char *sBlockData;
  char errbuf[1024];
  bcsize_t nPos;
  bc_t *bc;
  int err;

  bc = GetBlockChain(iface);
  if (!bc)
    return (false);

  err = bc_arch_find(bc, hash.GetRaw(), NULL, &nPos);
  if (err)
    return false;

  err = bc_arch(bc, nPos, &sBlockData, &sBlockLen);
  if (err) {
    sprintf(errbuf, "CBlock::ReadBlock[arch-idx %d]: %s (sherr %d).",
      (int)nPos, sherrstr(err), err);
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

  SetNull();

  /* serialize binary data into block */
  sBlock.write((const char *)sBlockData, sBlockLen);
  sBlock >> *this;
  free(sBlockData);

  return (true);
}

bool COLORBlock::IsOrphan()
{
  return (color_IsOrphanBlock(GetHash()));
}

bool COLORBlock::Truncate()
{
  CIface *iface = GetCoinByIndex(COLOR_COIN_IFACE);
  return (core_Truncate(iface, GetHash()));
}

bool COLORBlock::VerifyCheckpoint(int nHeight)
{
	return (true);
}
uint64_t COLORBlock::GetTotalBlocksEstimate()
{
	/* not supported by coin service. */
	return (0);
}

bool COLORBlock::AddToBlockIndex()
{
  blkidx_t *blockIndex = GetBlockTable(COLOR_COIN_IFACE);
  uint256 hash;
  CBlockIndex *pindexNew;

  // Check for duplicate
  hash = GetHash();
  if (blockIndex->count(hash) == 0)  {
		/* create new index */
		pindexNew = new CBlockIndex(*this);
		if (!pindexNew)
			return error(SHERR_INVAL, "AddToBlockIndex() : new CBlockIndex failed");
	} else {
		pindexNew = (*blockIndex)[hash];
	}

  map<uint256, CBlockIndex*>::iterator mi = blockIndex->insert(make_pair(hash, pindexNew)).first;
  pindexNew->phashBlock = &((*mi).first);
  map<uint256, CBlockIndex*>::iterator miPrev = blockIndex->find(hashPrevBlock);
  if (miPrev != blockIndex->end())
  {
    pindexNew->pprev = (*miPrev).second;
    pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
		(*miPrev).second->pnext = pindexNew;
  }

  pindexNew->bnChainWork = (pindexNew->pprev ? pindexNew->pprev->bnChainWork : 0) + pindexNew->GetBlockWork();

  return true;
}

int64_t COLORBlock::GetBlockWeight()
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(*this, SER_NETWORK, COLOR_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (COLOR_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(*this, SER_NETWORK, COLOR_PROTOCOL_VERSION);

  return (weight);
}


bool COLORBlock::SetBestChain(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(COLOR_COIN_IFACE);
	CWallet *wallet = GetWallet(iface);
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

#if 0
  if (COLORBlock::pindexGenesisBlock == NULL && hash == color_hashGenesisBlock)
  {
    COLORBlock::pindexGenesisBlock = pindexNew;
  } else {
    ret = core_CommitBlock(this, pindexNew); 
    if (!ret)
      return (false);
  }
#endif
	ret = core_CommitBlock(this, pindexNew); 
	if (!ret)
		return (false);

#if 0
  // Update best block in wallet (so we can detect restored wallets)
  bool fIsInitialDownload = IsInitialBlockDownload(COLOR_COIN_IFACE);
  if (!fIsInitialDownload) {
    const CBlockLocator locator(COLOR_COIN_IFACE, pindexNew);
    COLOR_SetBestChain(locator);
  }
#endif

  // New best block
  wallet->bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();

  return true;
}

bool COLORBlock::ConnectBlock(CBlockIndex* pindex)
{
  bool ok = core_ConnectBlock(this, pindex);
  if (ok)
    color_RemoveOrphanBlock(pindex->GetBlockHash());
  return (ok);
}

bool COLORBlock::DisconnectBlock(CBlockIndex* pindex)
{
	CBlock *block = (CBlock *)this;

	if (!core_DisconnectBlock(pindex, block))
		return (false);

	return (true);
}


bool GetColorBlockHeight(CBlockIndex *pindex, unsigned int& nHeight)
{

	nHeight = 0;
	if (pindex)
		pindex = pindex->pprev;
	while (pindex) {
		nHeight++;
		pindex = pindex->pprev;
	}

	return (true);
}

bool GetColorBlockHeight(const uint256& hashBlock, unsigned int& nHeight)
{
	CBlockIndex *pindex;

	pindex = GetBlockIndexByHash(COLOR_COIN_IFACE, hashBlock);
	if (!pindex)
		return (false);

	return (GetColorBlockHeight(pindex, nHeight));
}


double color_CalculatePoolFeePriority(CPool *pool, CPoolTx *ptx, double dFeePrio)
{
	CAltChain *alt;

	alt = ptx->tx.GetAltChain();
	if (!alt)
		return (dFeePrio);

	uint256 hWork = 0;
	{ /* PoW work */ 
		char scratchpad[SCRYPT_SCRATCHPAD_SIZE];

		scrypt_1024_1_1_256_sp(
				BEGIN(alt->block.nFlag), BEGIN(hWork), scratchpad);
	}
	uint64_t uWork;
	memcpy(&uWork, ((uint8_t *)&hWork) + (sizeof(hWork)-sizeof(uWork)), sizeof(uWork));
	dFeePrio -= 1 / sqrt((double)uWork);

	vector<CTransaction> vTx = pool->GetActiveTx();
	for (int i = 0; i < vTx.size(); i++) {
		const CTransaction& p_tx = vTx[i];

		CAltChain *p_alt = p_tx.GetAltChain();
		if (!p_alt)
			continue;

		if (p_alt->block.GetHash() != alt->block.hashPrevBlock)
			continue;

		/* found pool tx with altchain that has parent hash. */
		CPoolTx *p_ptx = pool->GetPoolTx(p_tx.GetHash());
		if (p_ptx) {
			/* decrease there priority in order to resolve order. */
			dFeePrio = MIN(dFeePrio / 2, p_ptx->dFeePriority);
		}
	}

	return (dFeePrio);
}

bool GetChainColorOpt(uint160 hColor, color_opt& opt)
{

	opt.clear();

	if (mapColorOpt.count(hColor) == 0) {
		return (false);
	}

	opt = mapColorOpt[hColor];
	return (true);
}

bool GetChainColorOpt(CIface *iface, CBlockIndex *pindex, color_opt& opt)
{
	uint160 hColor;

	if (!color_GetBlockColor(iface, pindex, hColor)) {
		return (false);
	}

	return (GetChainColorOpt(hColor, opt));
}

bool GetChainColorOpt(CIface *iface, uint256 hBlock, color_opt& opt)
{
	CBlockIndex *pindex;

  pindex = GetBlockIndexByHash(COLOR_COIN_IFACE, hBlock);
	if (!pindex)
		return (false);

	return (GetChainColorOpt(iface, pindex, opt));
}

void SetChainColorOpt(uint160 hColor, color_opt& opt)
{
	mapColorOpt[hColor] = opt;
}


CBigNum color_GetMinDifficulty(color_opt& opt)
{
	const int mode = CLROPT_DIFFICULTY;
	int val = 0;

	if (opt.count(mode) != 0) {
		val = opt[mode];
	}
	if (val == 0)
		val = clropt_default_table[CLROPT_DIFFICULTY];
	val = 10 + MIN(val, 8);

	return (CBigNum(~uint256(0) >> val));
}

CBigNum color_GetMinDifficulty(uint160 hColor)
{
	color_opt opt;
	GetChainColorOpt(hColor, opt);
	return (color_GetMinDifficulty(opt));
}

int64 color_GetBlockTarget(color_opt& opt)
{
	const int mode = CLROPT_BLOCKTARGET;
	int64 val = 0;
	int64 nSpacing = 0;

	if (opt.count(mode) != 0) {
		val = opt[mode];
	}
	if (val == 0)
		val = clropt_default_table[CLROPT_BLOCKTARGET];

	return ((int64)(val * 60));
}

int64 color_GetBlockTarget(uint160 hColor)
{
	color_opt opt;
	GetChainColorOpt(hColor, opt);
	return (color_GetBlockTarget(opt));
}

int64 color_GetCoinbaseMaturity(color_opt& opt)
{
	const int mode = CLROPT_MATURITY;
	int64 val = 0;
	int64 nSpacing = 0;

	if (opt.count(mode) != 0) {
		val = opt[mode];
	}
	if (val == 0)
		val = clropt_default_table[CLROPT_MATURITY];
	val = MIN(val, 8);

	return ((int64)(val * 60));
}

int64 color_GetCoinbaseMaturity(uint160 hColor)
{
	color_opt opt;
	GetChainColorOpt(hColor, opt);
	return (color_GetCoinbaseMaturity(opt));
}

int64 color_GetBlockValueBase(color_opt& opt)
{
	const int mode = CLROPT_REWARDBASE;
	double dValue;
	int64 val = 0;

	if (opt.count(mode) != 0)
		val = opt[mode];
	if (val == 0)
		val = clropt_default_table[mode];
	val = MIN(val, 10);

	dValue = pow(2, (double)val);
	return ((int64)(dValue * COIN));
}

int64 color_GetBlockValueBase(uint160 hColor)
{
	color_opt opt;
	GetChainColorOpt(hColor, opt);
	return (color_GetBlockValueBase(opt));
}

int64 color_GetBlockValueRate(color_opt& opt)
{
	const int mode = CLROPT_REWARDHALF;
	int64 val = 0;

	if (opt.count(mode) != 0)
		val = opt[mode];
	if (val == 0)
		val = clropt_default_table[mode];

	return ((int64)val * 1000);
}

int64 color_GetBlockValueRate(uint160 hColor)
{
	color_opt opt;
	GetChainColorOpt(hColor, opt);
	return (color_GetBlockValueRate(opt));
}

int64 color_GetMinTxFee(color_opt& opt)
{
	const int mode = CLROPT_TXFEE;
	int64 val = 0;

	if (opt.count(mode) != 0)
		val = opt[mode];
	if (val == 0)
		val = clropt_default_table[mode];
	val = MIN(val, 10) + 1;

	return ((int64)pow(10, (double)val));
}

int64 color_GetMinTxFee(uint160 hColor)
{
	color_opt opt;
	GetChainColorOpt(hColor, opt);
	return (color_GetMinTxFee(opt));
}

bool COLORBlock::CreateCheckpoint()
{
	return (false);
}
