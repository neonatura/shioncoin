
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
#include "wallet.h"
#include "net.h"
#include "strlcpy.h"
#include "shc_pool.h"
#include "shc_block.h"
#include "shc_wallet.h"
#include "shc_txidx.h"
#include "chain.h"
#include "coin.h"
#include "versionbits.h"
#include "algobits.h"

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


extern VersionBitsCache *GetVersionBitsCache(CIface *iface);


uint256 shc_hashGenesisBlock("0xa2128a434c48ff41bfb911857639fa24b69012aebf690b12e6dfa799cd5d914e");
static uint256 shc_hashGenesisMerkle("0xd395f73903efc28ce99ade1778666e404be2ee018f4022205a5d871c533548c8");
static CBigNum SHC_bnGenesisProofOfWorkLimit(~uint256(0) >> 20);
static CBigNum SHC_bnProofOfWorkLimit(~uint256(0) >> 21);
static unsigned int KimotoGravityWell(const CBlockIndex* pindexLast, const CBlock *pblock, uint64 TargetBlocksSpacingSeconds, uint64 PastBlocksMin, uint64 PastBlocksMax)
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

  if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64)BlockLastSolved->nHeight < PastBlocksMin) { return SHC_bnProofOfWorkLimit.GetCompact(); }

  int64 LatestBlockTime = BlockLastSolved->GetBlockTime();

  for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
    if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
    PastBlocksMass++;

		CBigNum bnDiff;
		bnDiff.SetCompact(BlockReading->nBits);
		/* reduce to scrypt factor. */
		bnDiff *= GetAlgoWorkFactor(GetVersionAlgo(BlockReading->nVersion));

		if (i == 1)	{
			//PastDifficultyAverage.SetCompact(BlockReading->nBits);
			PastDifficultyAverage = bnDiff;
		} else	{ 
			//PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
			PastDifficultyAverage = ((bnDiff - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
		}
		PastDifficultyAveragePrev = PastDifficultyAverage;

    if (LatestBlockTime < BlockReading->GetBlockTime())
      LatestBlockTime = BlockReading->GetBlockTime();

    PastRateActualSeconds = LatestBlockTime - BlockReading->GetBlockTime();
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
  if (bnNew > SHC_bnProofOfWorkLimit) { bnNew = SHC_bnProofOfWorkLimit; }

  return bnNew.GetCompact();
}


/* ** BLOCK ORPHANS ** */

typedef map<uint256, uint256> orphan_map;
static orphan_map SHC_mapOrphanBlocksByPrev;

bool shc_IsOrphanBlock(const uint256& hash)
{
  CBlockIndex *pindex;
  SHCBlock block;
  uint256 prevHash;
  bool ok;

  if (shc_GetOrphanPrevHash(hash, prevHash)) {
    /* already mapped. */
    return (true);
  }

  return (false); 
}

void shc_AddOrphanBlock(CBlock *block)
{

  SHC_mapOrphanBlocksByPrev.insert(
      make_pair(block->hashPrevBlock, block->GetHash()));
  block->WriteArchBlock();

}

void shc_RemoveOrphanBlock(const uint256& hash)
{
  bool found;

  orphan_map::iterator it = SHC_mapOrphanBlocksByPrev.begin(); 
  while (it != SHC_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found)
      break;
    ++it;
  }
  if (it != SHC_mapOrphanBlocksByPrev.end()) {
    SHC_mapOrphanBlocksByPrev.erase(it);
  }
  
}

bool shc_GetOrphanPrevHash(const uint256& hash, uint256& retPrevHash)
{
  bool found;

  orphan_map::iterator it = SHC_mapOrphanBlocksByPrev.begin(); 
  while (it != SHC_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found) {
      retPrevHash = it->first;
      return (true);
    }
    ++it;
  }

  return (false);
}

bool shc_GetOrphanNextHash(const uint256& hash, uint256& retNextHash)
{
  bool found;

  orphan_map::iterator it = SHC_mapOrphanBlocksByPrev.find(hash);
  if (it != SHC_mapOrphanBlocksByPrev.end()) {
    retNextHash = it->second;
    return (true);
  }
  return (false);
}

CBlock *shc_GetOrphanBlock(const uint256& hash)
{
  SHCBlock block;  

  if (!block.ReadArchBlock(hash))
    return (NULL);

  return (new SHCBlock(block));
}

uint256 shc_GetOrphanRoot(uint256 hash)
{
  uint256 prevHash;

  while (shc_GetOrphanPrevHash(hash, prevHash)) {
    hash = prevHash;
  }
  return (hash);
}

unsigned int SHCBlock::GetNextWorkRequired(const CBlockIndex* pindexLast)
{
	static const int64	BlocksTargetSpacing	= 1.0 * 60; // 1.0 minutes
	static const unsigned int	TimeDaySeconds	= 60 * 60 * 24;
	CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
	int64	PastSecondsMin	= TimeDaySeconds * 0.10;
	int64	PastSecondsMax	= TimeDaySeconds * 2.8;
	uint64	PastBlocksMin	= PastSecondsMin / BlocksTargetSpacing;
	uint64	PastBlocksMax	= PastSecondsMax / BlocksTargetSpacing;	
	int nHeight = pindexLast->nHeight + 1;
	int nAlg = ALGO_SCRYPT;
	uint32_t nBits;

	if (pindexLast == NULL) /* Genesis block */
		return (SHC_bnGenesisProofOfWorkLimit.GetCompact());

	if (VersionBitsState(pindexLast, iface, DEPLOYMENT_ALGO) == THRESHOLD_ACTIVE) {
		nAlg = GetVersionAlgo(nVersion);
	}

	pindexLast = GetLastBlockIndexForAlgo(pindexLast, nAlg);
	if (!pindexLast) {
		nBits = SHC_bnProofOfWorkLimit.GetCompact(); 
	} else {
		nBits = KimotoGravityWell(pindexLast, this, 
				BlocksTargetSpacing, PastBlocksMin, PastBlocksMax);
	}
	if (nAlg == ALGO_SCRYPT)
		return (nBits);

	/* base work factor off "compacted" difficulty. */
	CBigNum bnNew;
	bnNew.SetCompact(nBits);
	bnNew /= GetAlgoWorkFactor(nAlg);
	return (bnNew.GetCompact());
}

int64 shc_GetBlockValue(int nHeight, int64 nFees)
{
  if (nHeight == 0) return (800 * COIN);

  int64 nSubsidy = 3334 * SHC_COIN;
  nSubsidy >>= (nHeight / 749918);
  nSubsidy /= 10000000;
  nSubsidy *= 1000000;
  return ((int64)nSubsidy + nFees);
}

static int64_t shc_GetTxWeight(const CTransaction& tx)
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(tx, SER_NETWORK, SHC_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (SHC_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(tx, SER_NETWORK, SHC_PROTOCOL_VERSION);

  return (weight);
}

CBlock* shc_CreateNewBlock(const CPubKey& rkey)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  CBlockIndex *pindexPrev = GetBestBlockIndex(iface);

  auto_ptr<SHCBlock> pblock(new SHCBlock());
  if (!pblock.get())
    return NULL;

  /* coinbase */
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vin[0].prevout.SetNull();
  txNew.vout.resize(1);
  txNew.vout[0].scriptPubKey << rkey << OP_CHECKSIG;
  pblock->vtx.push_back(txNew);

  pblock->nVersion = core_ComputeBlockVersion(iface, pindexPrev);

  int64 nFees = 0;
  CTxMemPool *pool = GetTxMemPool(iface); 
  vector<CTransaction> vPriority = pool->GetActiveTx(); 
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
  bool ret = false;
  int64 reward = shc_GetBlockValue(pindexPrev->nHeight+1, nFees);
  if (pblock->vtx.size() == 1)
    ret = BlockGenerateValidateMatrix(iface, pblock->vtx[0], reward, pindexPrev->nHeight + 1, pblock->GetTotalBlocksEstimate());
  if (!ret)
    ret = BlockGenerateSpringMatrix(iface, pblock->vtx[0], reward);
  pblock->vtx[0].vout[0].nValue = reward; 

  /* define core header */
  pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
  pblock->hashMerkleRoot = pblock->BuildMerkleTree();
  pblock->UpdateTime(pindexPrev);
  pblock->nBits          = pblock->GetNextWorkRequired(pindexPrev);
  pblock->nNonce         = 0;

  /* declare consensus attributes. */
  core_GenerateCoinbaseCommitment(iface, pblock.get(), pindexPrev);

  /* fill coinbase signature (BIP34) */
  core_IncrementExtraNonce(pblock.get(), pindexPrev);

  return pblock.release();
}

bool shc_CreateGenesisBlock()
{
	CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
	blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
	bool ret;

  if (blockIndex->count(shc_hashGenesisBlock) != 0)
    return (true); /* already created */

  // Genesis block
  const char* pszTimestamp = "Neo Natura (shioncoin) 2019";
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vout.resize(1);
  txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
  txNew.vout[0].nValue = shc_GetBlockValue(0, 0);
  txNew.vout[0].scriptPubKey = CScript() << ParseHex("04a5814813115273a109cff99907ba4a05d951873dae7acb6c973d0c9e7c88911a3dbc9aa600deac241b91707e7b4ffb30ad91c8e56e695a1ddf318592988afe0a") << OP_CHECKSIG;
  SHCBlock block;
  block.vtx.push_back(txNew);
  block.hashPrevBlock = 0;
  block.hashMerkleRoot = block.BuildMerkleTree();
  block.nVersion = 2;
  block.nTime = 1555780563;
  block.nBits = 0x1e0ffff0;
	block.nNonce = 0xe2280fad;

  block.print();
  if (block.GetHash() != shc_hashGenesisBlock)
    return (false);
  if (block.hashMerkleRoot != shc_hashGenesisMerkle)
    return (false);

  if (!block.WriteBlock(0)) {
    return (false);
  }

  ret = block.AddToBlockIndex();
  if (!ret)
    return (false);
  (*blockIndex)[shc_hashGenesisBlock]->nStatus |= BLOCK_HAVE_DATA;

  return (true);
}

static bool shc_IsFromMe(CTransaction& tx)
{
  CWallet *pwallet = GetWallet(SHC_COIN_IFACE);

  if (pwallet->IsFromMe(tx))
    return true;

  return false;
}

static void shc_EraseFromWallets(uint256 hash)
{
  CWallet *pwallet = GetWallet(SHC_COIN_IFACE);

  pwallet->EraseFromWallet(hash);
}

bool shc_ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(SHC_COIN_IFACE);
  int ifaceIndex = SHC_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
  shtime_t ts;

  // Check for duplicate
  uint256 hash = pblock->GetHash();

	if (pblock->hashPrevBlock == 0 &&
			hash != shc_hashGenesisBlock) {
		Debug("(shc) ProcessBlock: warning: invalid genesis block \"%s\" submitted by \"%s\".", hash.GetHex().c_str(), (pfrom?pfrom->addr.ToString().c_str():"<local>"));
		return (false);
	}

  /*
   * SHC: If previous hash and it is unknown.
   */ 
  if (pblock->hashPrevBlock != 0 &&
      !blockIndex->count(pblock->hashPrevBlock)) {
    Debug("(shc) ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.GetHex().c_str());
    if (pfrom) {
      shc_AddOrphanBlock(pblock);
      STAT_BLOCK_ORPHAN(iface)++;

      /* request missing blocks */
      CBlockIndex *pindexBest = GetBestBlockIndex(SHC_COIN_IFACE);
      if (pindexBest) {
        Debug("(shc) ProcessBlocks: requesting blocks from height %d due to orphan '%s'.\n", pindexBest->nHeight, pblock->GetHash().GetHex().c_str()); 
        pfrom->PushGetBlocks(GetBestBlockIndex(SHC_COIN_IFACE), shc_GetOrphanRoot(pblock->GetHash()));
				InitServiceBlockEvent(SHC_COIN_IFACE, pindexBest->nHeight);
      }
    }
    return true;
  }

  /* store to disk */
  if (!pblock->AcceptBlock()) {
    iface->net_invalid = time(NULL);
    return error(SHERR_IO, "SHCBlock::AcceptBlock: error adding block '%s'.", pblock->GetHash().GetHex().c_str());
  }

  ServiceBlockEventUpdate(SHC_COIN_IFACE);

  return true;
}

CBlockIndex *shc_GetLastCheckpoint()
{
	CWallet *wallet = GetWallet(SHC_COIN_IFACE);
	if (!wallet || !wallet->checkpoints)
		return (NULL);
	return (wallet->checkpoints->GetLastCheckpoint());
}

bool shc_CheckProofOfWork(uint256 hash, unsigned int nBits, const CBigNum& bnProofOfWorkLimit)
{
  CBigNum bnTarget;
  bnTarget.SetCompact(nBits);

  // Check range
  if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
    return error(SHERR_INVAL, "CheckProofOfWork() : nBits below minimum work");

  // Check proof of work matches claimed amount
  if (hash > bnTarget.getuint256())
    return error(SHERR_INVAL, "CheckProofOfWork() : hash doesn't match nBits");

  return true;
}

/**
 * @note These are checks that are independent of context that can be verified before saving an orphan block.
 */
bool SHCBlock::CheckBlock()
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
	bool ok;

  if (vtx.empty()) { 
    return (trust(-80, "(shc) CheckBlock: block submitted with zero transactions"));
  }

  int64_t weight = GetBlockWeight();
  if (weight > MAX_BLOCK_WEIGHT(iface)) {
    return (trust(-80, "(shc) CheckBlock: block weight (%d) > max (%d)", weight, MAX_BLOCK_WEIGHT(iface)));
  }

  if (vtx.empty() || !vtx[0].IsCoinBase())
    return error(SHERR_INVAL, "CheckBlock() : first tx is not coinbase");

	/* verify difficulty match proof-of-work hash. */
	if (GetHash() == shc_hashGenesisBlock) { /* genesis block */
		ok = shc_CheckProofOfWork(GetPoWHash(), nBits, SHC_bnGenesisProofOfWorkLimit);
	} else {
		ok = shc_CheckProofOfWork(GetPoWHash(), nBits, SHC_bnProofOfWorkLimit);
	}
  if (!ok) {
    return error(SHERR_INVAL, "CheckBlock() : proof of work failed");
  }

  // Check timestamp
  if (GetBlockTime() > GetAdjustedTime() + SHC_MAX_DRIFT_TIME) {
    return error(SHERR_INVAL, "CheckBlock() : block timestamp too far in the future");
  }

  for (unsigned int i = 1; i < vtx.size(); i++)
    if (vtx[i].IsCoinBase()) {
      return error(SHERR_INVAL, "CheckBlock() : more than one coinbase");
    }

  // Check transactions
  BOOST_FOREACH(CTransaction& tx, vtx)
    if (!tx.CheckTransaction(SHC_COIN_IFACE)) {
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

  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  map<uint256, CBlockIndex*>::iterator miPrev = blockIndex->find(hashPrevBlock);
  if (miPrev != blockIndex->end()) {
    CBlockIndex *pindexPrev = (*miPrev).second;
    if (!core_CheckBlockWitness(iface, (CBlock *)this, pindexPrev))
      return (trust(-10, "(shc) CheckBlock: invalid witness integrity."));
  }


/* addition verification.. 
 * ensure genesis block has higher payout in coinbase
 * ensure genesis block has lower difficulty (nbits)
 * ensure genesis block has earlier block time
 */


  return true;
}


void SHCBlock::InvalidChainFound(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  char errbuf[1024];

  sprintf(errbuf, "SHC: InvalidChainFound: invalid block=%s  height=%d  work=%s  date=%s\n", pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight, pindexNew->bnChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
  unet_log(SHC_COIN_IFACE, errbuf);

}

// notify wallets about a new best chain
void static SHC_SetBestChain(const CBlockLocator& loc)
{
  CWallet *pwallet = GetWallet(SHC_COIN_IFACE);

  pwallet->SetBestChain(loc);
}


bool SHCBlock::IsBestChain()
{
  CBlockIndex *pindexBest = GetBestBlockIndex(SHC_COIN_IFACE);
  return (pindexBest && GetHash() == pindexBest->GetBlockHash());
}


bool BlockVerifyValidateMatrix(CIface *iface, CTransaction& tx, CBlockIndex *pindex);

bool SHCBlock::AcceptBlock()
{
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  int mode;

  map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hashPrevBlock);
  if (mi == blockIndex->end()) {
    return error(SHERR_INVAL, "(shc) AcceptBlock: prev block '%s' not found", hashPrevBlock.GetHex().c_str());
  }
  CBlockIndex* pindexPrev = (*mi).second;

  if (GetBlockTime() > GetAdjustedTime() + SHC_MAX_DRIFT_TIME) {
    print();
    return error(SHERR_INVAL, "(shc) AcceptBlock: block's timestamp more than fifteen minutes in the future.");

  }
  if (GetBlockTime() <= pindexPrev->GetMedianTimePast() ||
			GetBlockTime() < pindexPrev->GetBlockTime()) {	
    print();
    return error(SHERR_INVAL, "(shc) AcceptBlock: block's timestamp is too old.");
  }

	/* redundant */
  if (vtx.size() != 0 && VerifyMatrixTx(vtx[0], mode)) {
    bool fCheck = false;
    if (mode == OP_EXT_VALIDATE) {
#if 0
			bool fValMatrix = false;
			fValMatrix = BlockAcceptValidateMatrix(iface, vtx[0], NULL, fCheck);
			if (fValMatrix && !fCheck)
				return error(SHERR_ILSEQ, "(shc) AcceptBlock: ValidateMatrix verification failure.");
#endif
			if (!BlockVerifyValidateMatrix(iface, vtx[0], NULL))
				return (false);
    } else if (mode == OP_EXT_PAY) {
      bool fHasSprMatrix = BlockAcceptSpringMatrix(iface, vtx[0], fCheck);
      if (fHasSprMatrix && !fCheck)
        return error(SHERR_ILSEQ, "(shc) AcceptBlock: SpringMatrix verification failure.");
    }
  }

  return (core_AcceptBlock(this, pindexPrev));
}

/* remove me */
CScript SHCBlock::GetCoinbaseFlags()
{
  return (SHC_COINBASE_FLAGS);
}

static void shc_UpdatedTransaction(const uint256& hashTx)
{
  CWallet *pwallet = GetWallet(SHC_COIN_IFACE);

  pwallet->UpdatedTransaction(hashTx);
}

bool SHCBlock::ReadBlock(uint64_t nHeight)
{
int ifaceIndex = SHC_COIN_IFACE;
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

bool SHCBlock::ReadArchBlock(uint256 hash)
{
  int ifaceIndex = SHC_COIN_IFACE;
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

bool SHCBlock::IsOrphan()
{
  return (shc_IsOrphanBlock(GetHash()));
}

bool SHCBlock::Truncate()
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  return (core_Truncate(iface, GetHash()));
}

bool SHCBlock::VerifyCheckpoint(int nHeight)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(SHC_COIN_IFACE);

	if (hashPrevBlock != pindexBest->GetBlockHash()) {
		CBlockIndex *checkpoint = shc_GetLastCheckpoint();
		if (checkpoint) {
			if (nHeight < checkpoint->nHeight) {
				/* forked chain */
				return (ERR_INVAL, "(shc) VerifyCheckpoint: unknown chain (height) [hash %s].", GetHash().GetHex().c_str());
			}

			int64 deltaTime = nTime - checkpoint->nTime;
			if (deltaTime < 0)
				return (ERR_INVAL, "(shc) VerifyCheckpoint: unknown chain (time) [hash %s].", GetHash().GetHex().c_str());
		}
	}

	CWallet *wallet = GetWallet(SHC_COIN_IFACE);
	if (!wallet || !wallet->checkpoints) return (true);
  return (wallet->checkpoints->CheckBlock(nHeight, GetHash()));
}

bool shc_VerifyCheckpointHeight(int nHeight, uint256 hash)
{
	CWallet *wallet = GetWallet(SHC_COIN_IFACE);
	if (!wallet || !wallet->checkpoints) return (true);
  return (wallet->checkpoints->CheckBlock(nHeight, hash));
}

uint64_t SHCBlock::GetTotalBlocksEstimate()
{
	CWallet *wallet = GetWallet(SHC_COIN_IFACE);
	if (!wallet || !wallet->checkpoints) return (true);
  return ((uint64_t)wallet->checkpoints->GetTotalBlocksEstimate());
}

bool SHCBlock::AddToBlockIndex()
{
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
	CWallet *wallet = GetWallet(SHC_COIN_IFACE);
  uint256 hash = GetHash();
  CBlockIndex *pindexNew;
  shtime_t ts;

  // Check for duplicate
  if (blockIndex->count(hash)) 
    return error(SHERR_INVAL, "AddToBlockIndex() : %s already exists", hash.GetHex().c_str());

  /* create new index */
  pindexNew = new CBlockIndex(*this);
  if (!pindexNew)
    return error(SHERR_INVAL, "AddToBlockIndex() : new CBlockIndex failed");

  map<uint256, CBlockIndex*>::iterator mi = blockIndex->insert(make_pair(hash, pindexNew)).first;
  pindexNew->phashBlock = &((*mi).first);
  map<uint256, CBlockIndex*>::iterator miPrev = blockIndex->find(hashPrevBlock);
  if (miPrev != blockIndex->end())
  {
    pindexNew->pprev = (*miPrev).second;
    pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    pindexNew->BuildSkip();
  }

  pindexNew->bnChainWork = (pindexNew->pprev ? pindexNew->pprev->bnChainWork : 0) + pindexNew->GetBlockWork();

  if (IsWitnessEnabled(GetCoinByIndex(SHC_COIN_IFACE), pindexNew->pprev)) {
    pindexNew->nStatus |= BLOCK_OPT_WITNESS;
  }

  if (pindexNew->bnChainWork > wallet->bnBestChainWork) {
    bool ret = SetBestChain(pindexNew);
    if (!ret)
      return (false);
  } else {
    WriteArchBlock();
  }

  return true;
}

int64_t SHCBlock::GetBlockWeight()
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(*this, SER_NETWORK, SHC_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (SHC_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(*this, SER_NETWORK, SHC_PROTOCOL_VERSION);

  return (weight);
}


bool SHCBlock::SetBestChain(CBlockIndex* pindexNew)
{
	static char *timing_tag = "SHC.SetBestChain/CommitBlock";
	CWallet *wallet = GetWallet(SHC_COIN_IFACE);
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

  if (SHCBlock::pindexGenesisBlock == NULL && hash == shc_hashGenesisBlock)
  {
    SHCBlock::pindexGenesisBlock = pindexNew;
		WriteHashBestChain(iface, pindexNew->GetBlockHash());
		SetBestBlockIndex(ifaceIndex, pindexNew);
  } else {
    timing_init(timing_tag, &ts);
    ret = core_CommitBlock(this, pindexNew); 
    timing_term(SHC_COIN_IFACE, timing_tag, &ts);
    if (!ret)
      return (false);
  }

  // New best block
  wallet->bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();

  return true;
}

bool SHCBlock::ConnectBlock(CBlockIndex* pindex)
{
  bool ok = core_ConnectBlock(this, pindex);
  if (ok)
    shc_RemoveOrphanBlock(pindex->GetBlockHash());
  return (ok);
}

bool SHCBlock::DisconnectBlock(CBlockIndex* pindex)
{
	CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
	CWallet *wallet = GetWallet(SHC_COIN_IFACE);
	CBlock *block = (CBlock *)this;

	if (pindex->pprev) {
		BOOST_FOREACH(CTransaction& tx, vtx) {
			if (tx.IsCoinBase()) {
				if (tx.isFlag(CTransaction::TXF_MATRIX)) {
					CTxMatrix& matrix = tx.matrix;
					if (matrix.GetType() == CTxMatrix::M_VALIDATE) {
						/* retract block hash from Validate matrix */
						BlockRetractValidateMatrix(iface, tx, pindex);
					} else if (matrix.GetType() == CTxMatrix::M_SPRING) {
						BlockRetractSpringMatrix(iface, tx, pindex);
					}
				}
			}
		}
	}

	if (!core_DisconnectBlock(pindex, block))
		return (false);

	return (true);
}

bool SHCBlock::CreateCheckpoint()
{
	CWallet *wallet = GetWallet(SHC_COIN_IFACE);
	CBlockIndex *pindex;

	if (!wallet || !wallet->checkpoints)
		return (false);

	pindex = GetBlockIndexByHash(SHC_COIN_IFACE, GetHash());
	if (!pindex)
		return (false);

	return (wallet->checkpoints->AddCheckpoint(pindex));
}

int SHCBlock::GetAlgo() const
{
	return (GetVersionAlgo(nVersion));
}

