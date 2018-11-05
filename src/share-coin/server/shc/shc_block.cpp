
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
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "shc_pool.h"
#include "shc_block.h"
#include "shc_wallet.h"
#include "shc_txidx.h"
#include "chain.h"
#include "coin.h"
#include "versionbits.h"

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


uint256 shc_hashGenesisBlock("0xf4319e4e89b35b5f26ec0363a09d29703402f120cf1bf8e6f535548d5ec3c5cc");
static uint256 shc_hashGenesisMerkle("0xd3f4bbe7fe61bda819369b4cd3a828f3ad98d971dda0c20a466a9ce64846c321");
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
  if (bnNew > SHC_bnProofOfWorkLimit) { bnNew = SHC_bnProofOfWorkLimit; }


#if 0
  /// debug print
  printf("Difficulty Retarget - Kimoto Gravity Well\n");
  printf("PastRateAdjustmentRatio = %g\n", PastRateAdjustmentRatio);
  printf("Before: %08x %s\n", BlockLastSolved->nBits, CBigNum().SetCompact(BlockLastSolved->nBits).getuint256().ToString().c_str());
  printf("After: %08x %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
#endif

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

#if 0
  pindex = GetBlockIndexByHash(SHC_COIN_IFACE, hash);
  if (pindex) {
    if (GetBestHeight(SHC_COIN_IFACE) >= pindex->nHeight &&
        block.ReadFromDisk(pindex))
      return (false); /* present in block-chain */
  }

  if (!block.ReadArchBlock(hash))
    return (false); /* no record in archive db */
  return (true);
#endif

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
  int nHeight = pindexLast->nHeight + 1;

  int64 nInterval;
  int64 nActualTimespanMax;
  int64 nActualTimespanMin;
  int64 nTargetTimespanCurrent;

  // Genesis block
  if (pindexLast == NULL)
    return (SHC_bnGenesisProofOfWorkLimit.GetCompact());
    //return (SHC_bnProofOfWorkLimit.GetCompact());

  static const int64	BlocksTargetSpacing	= 1.0 * 60; // 1.0 minutes
  unsigned int	TimeDaySeconds	= 60 * 60 * 24;
  int64	PastSecondsMin	= TimeDaySeconds * 0.10;
  int64	PastSecondsMax	= TimeDaySeconds * 2.8;
  uint64	PastBlocksMin	= PastSecondsMin / BlocksTargetSpacing;
  uint64	PastBlocksMax	= PastSecondsMax / BlocksTargetSpacing;	

  return KimotoGravityWell(pindexLast, this, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax);
}

namespace SHC_Checkpoints
{
  typedef std::map<int, uint256> MapCheckpoints;

  //
  // What makes a good checkpoint block?
  // + Is surrounded by blocks with reasonable timestamps
  //   (no blocks before with a timestamp after, none after with
  //    timestamp before)
  // + Contains no strange transactions
  //
  static MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    ( 0, uint256("0xf4319e4e89b35b5f26ec0363a09d29703402f120cf1bf8e6f535548d5ec3c5cc") )

    /* Feb '17 */
    ( 29011, uint256("0x860e1b1ed3ebb78822d9e1c99dfa34ac1066c6eee17753f95b4ae0d354e61e5d") )
    ( 29012, uint256("0x82fe60a87c9f3a71e3edd897871a03d2f7ffb8d3eb8f2526a79f5630a50f9411") )
    ( 29013, uint256("0x7e2a6b592d7316bf137d7591298ae597057b16616d7df3ca4407d0ace6d8855e") )
    ( 29014, uint256("0x9c9e871541ced1c418e1ec483e0827bf812274e55596d5585f525410fee74b42") )

    /* May '17 */
    ( 49123, uint256("0x685651fb79d40cb8f53378e424bd4b3bc865de1554590c930d04801b8a7ecdfe") )
    ( 49124, uint256("0xda1e2aefb75b5c218e1e86abc89a913347cdf1e1dd81dd210a5fd33f09808009") )
    ( 49125, uint256("0x5e4a101dae9f04d9a28d54d0bfc742ac8c2c6887c53fd7063a3c3b73087a9c53") ) 
    ( 49126, uint256("0xe1e089319ca2bbdb036a462361560e130009f17bb7fdb030d5056069e96b92f1") )
    ( 49127, uint256("0x31cd03e68bc0ff6cc0ab98eef2574dfcc30f8815501f9ccdf02accc41598352c") )
    ( 49128, uint256("0x20ef53261360002ad1eddd2c5bf7c2166aecedad236be0efd636085cd8111440") )

		/* Feb '18 */
    ( 59123, uint256("0x47c8bce54da6e3412e8b27092cd9ece71dc942b47c4a9c133df0058f0a111488") )
    ( 59124, uint256("0xf68049663a540964b730fe7cbc2200ecefedf94fab7adcdfb60b6f31af9e737a") )
    ( 59125, uint256("0x84750f65256d837e6742372a4257a0ce65f721248ae4adcb185173b113589f75") )
    ( 59126, uint256("0x587a174683903a3f255a1784508a15b4bcfbaaae9b371fae4c9f1a18c060f54c") )
    ( 59127, uint256("0x7ddbb72740b40ff434717d5938fc1fedd1e9173d25d30e5554eef3b10743515d") )
    ( 59128, uint256("0xf19bc1a7e3416751daf8ea6ca116aded43b0f541ac4576ccd99a7c494fb50f20") )

		/* Nov '18 */ 
		( 78003, uint256("0x8759db8220ea122999cfdfcb8a2a3a332cf9189947955bd12bc9ed2c2ac71403") )
		( 78004, uint256("0x9194d30c93aebd46d538a65f3962aced87c18a530ee947ca0200524c48fa67c6") )
		( 78005, uint256("0x191d1b362ec5c04d80731a2f782bccefebdb4b976c19dfcc400e8eb1fd6b172a") )
		( 78006, uint256("0x780128527b837c3456a111341d9e0b135c7afe335f0cfcfd8664efccfa1d577e") )
		( 78007, uint256("0xcbb3bc5241bf4d528214b5bad95bc17e92d047db85a1d68587d505de60e76189") )

    ;

  bool CheckBlock(int nHeight, const uint256& hash)
  {
    if (fTestNet) return true; // Testnet has no checkpoints

    MapCheckpoints::const_iterator i = mapCheckpoints.find(nHeight);
    if (i == mapCheckpoints.end()) return true;
    return hash == i->second;
  }

  int GetTotalBlocksEstimate()
  {
    if (fTestNet) return 0;
    return mapCheckpoints.rbegin()->first;
  }

  CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
  {
    if (fTestNet) return NULL;

    BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, mapCheckpoints)
    {
      const uint256& hash = i.second;
      std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
      if (t != mapBlockIndex.end())
        return t->second;
    }
    return NULL;
  }

	void AddCheckpoint(int height, uint256 hash)
	{
		mapCheckpoints.insert(mapCheckpoints.end(), make_pair(height, hash));
		Debug("(shc) AddCheckpoint: new dynamic checkpoint (height %d): %s",height, hash.GetHex().c_str());
	}

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
  const char* pszTimestamp = "Neo Natura (share-coin) 2016";
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
  block.nVersion = SHCBlock::CURRENT_VERSION;
  block.nTime    = 1461974400; /* 04/30/16 12:00am */
  block.nBits    = 0x1e0ffff0;
  block.nNonce   = 3293840;


  block.print();
  if (block.GetHash() != shc_hashGenesisBlock)
    return (false);
  if (block.hashMerkleRoot != shc_hashGenesisMerkle)
    return (false);

  if (!block.WriteBlock(0)) {
    return (false);
  }

  ret = block.AddToBlockIndex();
  if (!ret) {
    return (false);
  }

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



#if 0
// minimum amount of work that could possibly be required nTime after
// minimum work required was nBase
//
static unsigned int shc_ComputeMinWork(unsigned int nBase, int64 nTime)
{
  static int64 nTargetTimespan = 2 * 60 * 60;
  static int64 nTargetSpacing = 60;

  CBigNum bnResult;
  bnResult.SetCompact(nBase);
  while (nTime > 0 && bnResult < SHC_bnProofOfWorkLimit)
  {
    // Maximum 136% adjustment...
    bnResult = (bnResult * 75) / 55; 
    // ... in best-case exactly 4-times-normal target time
    nTime -= nTargetTimespan*4;
  }
  if (bnResult > SHC_bnProofOfWorkLimit)
    bnResult = SHC_bnProofOfWorkLimit;
  return bnResult.GetCompact();
}
#endif

bool shc_ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(SHC_COIN_IFACE);
  int ifaceIndex = SHC_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
  shtime_t ts;

  // Check for duplicate
  uint256 hash = pblock->GetHash();

#if 0
  if (blockIndex->count(hash)) {
    return Debug("(shc) ProcessBlock: already have block %s", hash.GetHex().c_str());
  }
  if (pindexBest && 
      pblock->hashPrevBlock != pindexBest->GetBlockHash() &&
      shc_IsOrphanBlock(hash)) {
    return Debug("(shc) ProcessBlock: already have block (orphan) %s", hash.ToString().c_str());
  }
#endif

  // Preliminary checks
  if (!pblock->CheckBlock()) {
    return error(SHERR_INVAL, "ProcessBlock() : CheckBlock FAILED");
  }

  CBlockIndex* pcheckpoint = SHC_Checkpoints::GetLastCheckpoint(*blockIndex);
  if (pcheckpoint && pblock->hashPrevBlock != GetBestBlockChain(iface)) {
    // Extra checks to prevent "fill up memory by spamming with bogus blocks"
    int64 deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
    if (deltaTime < 0)
    {
      if (pfrom)
        pfrom->Misbehaving(100);
      return error(SHERR_INVAL, "ProcessBlock() : block with timestamp before last checkpoint");
    }
#if 0
    CBigNum bnNewBlock;
    bnNewBlock.SetCompact(pblock->nBits);
    CBigNum bnRequired;
    bnRequired.SetCompact(shc_ComputeMinWork(pcheckpoint->nBits, deltaTime));
    if (bnNewBlock > bnRequired)
    {
      if (pfrom)
        pfrom->Misbehaving(100);
      return error(SHERR_INVAL, "ProcessBlock() : block with too little proof-of-work");
    }
#endif
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

  if (!pblock->CheckTransactionInputs(SHC_COIN_IFACE)) {
    Debug("(shc) ProcessBlock: invalid input transaction [prev %s].", pblock->hashPrevBlock.GetHex().c_str());
    return (true);
  }

  /* store to disk */
  if (!pblock->AcceptBlock()) {
    iface->net_invalid = time(NULL);
    return error(SHERR_IO, "SHCBlock::AcceptBlock: error adding block '%s'.", pblock->GetHash().GetHex().c_str());
  }

  uint256 nextHash;
  while (shc_GetOrphanNextHash(hash, nextHash)) {
    hash = nextHash;
    CBlock *block = shc_GetOrphanBlock(hash);
    if (!block || !block->AcceptBlock())
      break;
    shc_RemoveOrphanBlock(hash);
    STAT_BLOCK_ORPHAN(iface)--;
  }

  ServiceBlockEventUpdate(SHC_COIN_IFACE);

	/* initiate notary tx, if needed. */
	int mode;
	const CTransaction& tx = pblock->vtx[0];
	if ((tx.GetFlags() & CTransaction::TXF_MATRIX) &&
			GetExtOutputMode(tx, OP_MATRIX, mode) &&
			mode == OP_EXT_VALIDATE) {
		RelayValidateMatrixNotaryTx(iface, tx);
	}

  return true;
}

CBlockIndex *shc_GetLastCheckpoint()
{
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  return (SHC_Checkpoints::GetLastCheckpoint(*blockIndex));
}

bool shc_CheckProofOfWork(uint256 hash, unsigned int nBits)
{
  CBigNum bnTarget;
  bnTarget.SetCompact(nBits);

  // Check range
  if (bnTarget <= 0 || bnTarget > SHC_bnProofOfWorkLimit)
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

  if (vtx.empty()) { 
    return (trust(-80, "(shc) CheckBlock: block submitted with zero transactions"));
  }

  int64_t weight = GetBlockWeight();
  if (weight > MAX_BLOCK_WEIGHT(iface)) {
    return (trust(-80, "(shc) CheckBlock: block weight (%d) > max (%d)", weight, MAX_BLOCK_WEIGHT(iface)));
  }


#if 0
  if (vtx[0].GetValueOut() > shc_GetBlockValue(nHeight, nFees)) {
    return (false);
  }
#endif

  if (vtx.empty() || !vtx[0].IsCoinBase())
    return error(SHERR_INVAL, "CheckBlock() : first tx is not coinbase");

  // Check proof of work matches claimed amount
  if (!shc_CheckProofOfWork(GetPoWHash(), nBits)) {
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

  if (pindexNew->bnChainWork > bnBestInvalidWork)
  {
    bnBestInvalidWork = pindexNew->bnChainWork;
#ifdef USE_LEVELDB_COINDB
    SHCTxDB txdb;
    txdb.WriteBestInvalidWork(bnBestInvalidWork);
    txdb.Close();
#endif
    //    uiInterface.NotifyBlocksChanged();
  }

  
  sprintf(errbuf, "SHC: InvalidChainFound: invalid block=%s  height=%d  work=%s  date=%s\n", pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight, pindexNew->bnChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
  unet_log(SHC_COIN_IFACE, errbuf);

  CBlockIndex *pindexBest = GetBestBlockIndex(SHC_COIN_IFACE);

//fprintf(stderr, "critical: InvalidChainFound:  current best=%s  height=%d  work=%s  date=%s\n", GetBestBlockChain(iface).ToString().substr(0,20).c_str(), GetBestHeight(SHC_COIN_IFACE), bnBestChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());
  if (pindexBest && bnBestInvalidWork > bnBestChainWork + pindexBest->GetBlockWork() * 6)
    unet_log(SHC_COIN_IFACE, "InvalidChainFound: WARNING: Displayed transactions may not be correct!  You may need to upgrade, or other nodes may need to upgrade.\n");
}

#ifdef USE_LEVELDB_TXDB
bool shc_SetBestChainInner(CBlock *block, CTxDB& txdb, CBlockIndex *pindexNew)
{
  uint256 hash = block->GetHash();
  bc_t *bc = GetBlockChain(GetCoinByIndex(SHC_COIN_IFACE));


  // Adding to current best branch
  if (!block->ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
  {
/* truncate block-chain to failed block height. */
// bc_truncate(bc, pindexNew->nHeight);
    txdb.TxnAbort();
    block->InvalidChainFound(pindexNew);
    return false;
  }
  if (!txdb.TxnCommit())
    return error(SHERR_IO, "SetBestChain() : TxnCommit failed");

  // Add to current best branch
  pindexNew->pprev->pnext = pindexNew;

  // Delete redundant memory transactions
  BOOST_FOREACH(CTransaction& tx, block->vtx)
    SHCBlock::mempool.CommitTx(tx);

  return true;
}
#endif

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
	if (nVersion < VERSIONBITS_TOP_BITS &&
			IsWitnessEnabled(iface, pindexPrev)) {
		return (error(SHERR_INVAL, "(%s) AcceptBlock: rejecting obsolete block (ver: %u) (hash: %s) [segwit].", iface->name, (unsigned int)nVersion, GetHash().GetHex().c_str()));
	}

  if (vtx.size() != 0 && VerifyMatrixTx(vtx[0], mode)) {
    bool fCheck = false;
    if (mode == OP_EXT_VALIDATE) {
      bool fValMatrix = false;
      fValMatrix = BlockAcceptValidateMatrix(iface, vtx[0], fCheck);
      if (fValMatrix && !fCheck)
        return error(SHERR_ILSEQ, "(shc) AcceptBlock: ValidateMatrix verification failure.");
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


#if 0
  if (!CheckBlock()) {
    unet_log(ifaceIndex, "CBlock::ReadBlock: block validation failure.");
    return (false);
  }
#endif

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

#ifdef USE_LEVELDB_COINDB
bool shc_Truncate(uint256 hash)
{
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  CBlockIndex *pBestIndex;
  CBlockIndex *cur_index;
  CBlockIndex *pindex;
	bcpos_t nMaxHeight;
	bcpos_t nHeight;
  int err;

  if (!blockIndex || !blockIndex->count(hash))
    return error(SHERR_INVAL, "Erase: block not found in block-index.");

  cur_index = (*blockIndex)[hash];
  if (!cur_index)
    return error(SHERR_INVAL, "Erase: block not found in block-index.");

  pBestIndex = GetBestBlockIndex(iface);
  if (!pBestIndex)
    return error(SHERR_INVAL, "Erase: no block-chain established.");
  if (cur_index->nHeight > pBestIndex->nHeight)
    return error(SHERR_INVAL, "Erase: height is not valid.");

  bc_t *bc = GetBlockChain(iface);
  unsigned int nMinHeight = MAX(1, cur_index->nHeight);

	nMaxHeight = 0;
	(void)bc_idx_next(bc, &nMaxHeight);
	nMaxHeight = MAX(1, nMaxHeight) - 1;

  SHCTxDB txdb; /* OPEN */

  for (nHeight = nMaxHeight; nHeight > nMinHeight; nHeight--) {
    SHCBlock block;
    if (block.ReadBlock(nHeight)) {
      uint256 t_hash = block.GetHash();
      if (hash == cur_index->GetBlockHash())
        break; /* bad */
      if (blockIndex->count(t_hash) != 0)
        block.DisconnectBlock(txdb, (*blockIndex)[t_hash]);
      bc_table_reset(bc, t_hash.GetRaw());
    }
  }
  for (nHeight = nMaxHeight; nHeight > nMinHeight; nHeight--) {
    bc_clear(bc, nHeight);
  }  

  SetBestBlockIndex(iface, cur_index);
  bool ret = txdb.WriteHashBestChain(cur_index->GetBlockHash());

  txdb.Close(); /* CLOSE */

  if (!ret)
    return error(SHERR_INVAL, "Truncate: WriteHashBestChain '%s' failed", hash.GetHex().c_str());

  cur_index->pnext = NULL;
  SHCBlock::bnBestChainWork = cur_index->bnChainWork;
  InitServiceBlockEvent(SHC_COIN_IFACE, cur_index->nHeight + 1);

  return (true);
}
bool SHCBlock::Truncate()
{
  return (shc_Truncate(GetHash()));
}
#else
bool SHCBlock::Truncate()
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  return (core_Truncate(iface, GetHash()));
}
#endif

bool SHCBlock::VerifyCheckpoint(int nHeight)
{
  return (SHC_Checkpoints::CheckBlock(nHeight, GetHash()));
}
uint64_t SHCBlock::GetTotalBlocksEstimate()
{
  return ((uint64_t)SHC_Checkpoints::GetTotalBlocksEstimate());
}

bool SHCBlock::AddToBlockIndex()
{
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
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
    pindexNew->nStatus |= BIS_OPT_WITNESS;
  }

  if (pindexNew->bnChainWork > bnBestChainWork) {
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
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

  if (SHCBlock::pindexGenesisBlock == NULL && hash == shc_hashGenesisBlock)
  {
    SHCBlock::pindexGenesisBlock = pindexNew;
  } else {
    timing_init("SetBestChain/commit", &ts);
    ret = core_CommitBlock(this, pindexNew); 
    timing_term(SHC_COIN_IFACE, "SetBestChain/commit", &ts);
    if (!ret)
      return (false);
  }

  // Update best block in wallet (so we can detect restored wallets)
  bool fIsInitialDownload = IsInitialBlockDownload(SHC_COIN_IFACE);
  if (!fIsInitialDownload) {
    const CBlockLocator locator(SHC_COIN_IFACE, pindexNew);
    timing_init("SetBestChain/locator", &ts);
    SHC_SetBestChain(locator);
    timing_term(SHC_COIN_IFACE, "SetBestChain/locator", &ts);

    WriteHashBestChain(iface, hash);
  }

  // New best block
  SetBestBlockIndex(SHC_COIN_IFACE, pindexNew);
  bnBestChainWork = pindexNew->bnChainWork;
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

	if (!core_DisconnectBlock(pindex, block))
		return (false);

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

	return (true);
}

bool SHCBlock::CreateCheckpoint()
{
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
	const uint256& hBlock = GetHash();
  CBlockIndex *prevIndex;
  CBlockIndex *pindex;
	
	/* ensure is valid in main chain. */
	if (blockIndex->count(hBlock) == 0)
		return (false);
	pindex = (*blockIndex)[hBlock];

	/* compare height against last checkpoint. */
	prevIndex = SHC_Checkpoints::GetLastCheckpoint(*blockIndex);
	if (prevIndex && pindex->nHeight <= prevIndex->nHeight)
		return (false); /* stale */

	SHC_Checkpoints::AddCheckpoint(pindex->nHeight, hBlock);
	return (true);
}




