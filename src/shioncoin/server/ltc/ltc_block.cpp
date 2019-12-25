
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
#include "wallet.h"
#include "net.h"
#include "strlcpy.h"
#include "ltc_pool.h"
#include "ltc_block.h"
#include "ltc_txidx.h"
#include "ltc_wallet.h"
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

#include <boost/array.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>


using namespace std;
using namespace boost;


#define LTC_MAJORITY_WINDOW 2500


uint256 ltc_hashGenesisBlock("0x4e56204bb7b8ac06f860ff1c845f03f984303b5b97eb7b42868f714611aed94b");
static CBigNum ltc_bnProofOfWorkLimit(~uint256(0) >> 20);
static const int64 ltc_nTargetTimespan = 3.5 * 24 * 60 * 60; // Einsteinium: 3.5 days
static const int64 ltc_nTargetTimespanNEW = 60;
static const int64 ltc_nTargetSpacing = 2.5 * 60; 
static const int64 ltc_nInterval = ltc_nTargetTimespan / ltc_nTargetSpacing;
static const int64 ltc_nDiffChangeTarget = 56000; // Patch effective @ block 56000



/* ** BLOCK ORPHANS ** */

typedef map<uint256, uint256> orphan_map;
static orphan_map LTC_mapOrphanBlocksByPrev;

bool ltc_IsOrphanBlock(const uint256& hash)
{
  CBlockIndex *pindex;
  LTCBlock block;
  uint256 prevHash;
  bool ok;

  if (ltc_GetOrphanPrevHash(hash, prevHash)) {
    /* already mapped. */
    return (true);
  }

#if 0
  pindex = GetBlockIndexByHash(LTC_COIN_IFACE, hash);
  if (pindex) {
    if (GetBestHeight(LTC_COIN_IFACE) >= pindex->nHeight &&
        block.ReadFromDisk(pindex))
      return (false); /* present in block-chain */
  }

  if (!block.ReadArchBlock(hash))
    return (false); /* no record in archive db */
  return (true);
#endif

  return (false);
}

void ltc_AddOrphanBlock(CBlock *block)
{

  LTC_mapOrphanBlocksByPrev.insert(
      make_pair(block->hashPrevBlock, block->GetHash()));
  block->WriteArchBlock();

}

void ltc_RemoveOrphanBlock(const uint256& hash)
{
  bool found;

  orphan_map::iterator it = LTC_mapOrphanBlocksByPrev.begin(); 
  while (it != LTC_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found)
      break;
    ++it;
  }
  if (it != LTC_mapOrphanBlocksByPrev.end()) {
    LTC_mapOrphanBlocksByPrev.erase(it);
  }
  
}

bool ltc_GetOrphanPrevHash(const uint256& hash, uint256& retPrevHash)
{
  bool found;

  orphan_map::iterator it = LTC_mapOrphanBlocksByPrev.begin(); 
  while (it != LTC_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found) {
      retPrevHash = it->first;
      return (true);
    }
    ++it;
  }

  return (false);
}

bool ltc_GetOrphanNextHash(const uint256& hash, uint256& retNextHash)
{
  bool found;

  orphan_map::iterator it = LTC_mapOrphanBlocksByPrev.find(hash);
  if (it != LTC_mapOrphanBlocksByPrev.end()) {
    retNextHash = it->second;
    return (true);
  }
  return (false);
}

CBlock *ltc_GetOrphanBlock(const uint256& hash)
{
  LTCBlock block;  

  if (!block.ReadArchBlock(hash))
    return (NULL);

  return (new LTCBlock(block));
}

uint256 ltc_GetOrphanRoot(uint256 hash)
{
  uint256 prevHash;

  while (ltc_GetOrphanPrevHash(hash, prevHash)) {
    hash = prevHash;
  }
  return (hash);
}


#define nPowTargetSpacing 150
#define nPowTargetTimespan 302400
#define nDifficultyAdjustmentInterval 2016

static unsigned int ltc_CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime)
{

	// Limit adjustment step
	int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
	if (nActualTimespan < nPowTargetTimespan/4)
		nActualTimespan = nPowTargetTimespan/4;
	if (nActualTimespan > nPowTargetTimespan*4)
		nActualTimespan = nPowTargetTimespan*4;

#if 0
	// Retarget
	arith_uint256 bnNew;
	arith_uint256 bnOld;
	bnNew.SetCompact(pindexLast->nBits);
	bnOld = bnNew;
	// Litecoin: intermediate uint256 can overflow by 1 bit
	const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
	bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
	if (fShift)
		bnNew >>= 1;
	bnNew *= nActualTimespan;
	bnNew /= params.nPowTargetTimespan;
	if (fShift)
		bnNew <<= 1;

	if (bnNew > bnPowLimit)
		bnNew = bnPowLimit;
#endif
  CBigNum bnNew;
  bnNew.SetCompact(pindexLast->nBits);
	bool fShift = bnNew.bits() > ltc_bnProofOfWorkLimit.bits() - 1; 
  bnNew *= nActualTimespan;
  bnNew /= nPowTargetTimespan;
	if (fShift)
		bnNew = bnNew << 1;

  if (bnNew > ltc_bnProofOfWorkLimit)
    bnNew = ltc_bnProofOfWorkLimit;

	return bnNew.GetCompact();
}

unsigned int LTCBlock::GetNextWorkRequired(const CBlockIndex* pindexLast)
{

	// Only change once per difficulty adjustment interval
	if (((pindexLast->nHeight+1) % nDifficultyAdjustmentInterval) != 0) {
		return pindexLast->nBits;
	}

	// Go back by what we want to be 14 days worth of blocks
	// Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
	// Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
	int blockstogoback = nDifficultyAdjustmentInterval-1;
	if ((pindexLast->nHeight+1) != nDifficultyAdjustmentInterval)
		blockstogoback = nDifficultyAdjustmentInterval;

	// Go back by what we want to be 14 days worth of blocks
	const CBlockIndex* pindexFirst = pindexLast;
	for (int i = 0; pindexFirst && i < blockstogoback; i++)
		pindexFirst = pindexFirst->pprev;

	return ltc_CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime());
}



#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>

static int ltc_generateMTRandom(unsigned int s, int range)
{
  boost::mt19937 gen(s);
  boost::uniform_int<> dist(1, range);
  return dist(gen);
}

#if 0
int64 ltc_GetBlockValue(int nHeight, int64 nFees)
{

  if (nHeight == 0)
    return (50 * COIN);

  int64 nSubsidy = 0;
  int StartOffset;
  int WormholeStartBlock;
  int mod = nHeight % 36000;
  if (mod != 0) mod = 1;

  int epoch = (nHeight / 36000) + mod;
  long wseed = 5299860 * epoch; // Discovered: 1952, Atomic number: 99 Melting Point: 860

  StartOffset = ltc_generateMTRandom(wseed, 35820);
  WormholeStartBlock = StartOffset + ((epoch - 1)  * 36000); // Wormholes start from Epoch 2


  if(epoch > 1 && epoch < 148 && nHeight >= WormholeStartBlock && nHeight < WormholeStartBlock + 180)  
  {   
    nSubsidy = 2973 * COIN;
  }       
  else
  {
    if (nHeight == 1) nSubsidy = 10747 * COIN;
    else if (nHeight <= 72000) nSubsidy = 1024 * COIN;
    else if(nHeight <= 144000) nSubsidy = 512 * COIN;
    else if(nHeight <= 288000) nSubsidy = 256 * COIN;
    else if(nHeight <= 432000) nSubsidy = 128 * COIN;
    else if(nHeight <= 576000) nSubsidy = 64 * COIN;
    else if(nHeight <= 864000) nSubsidy = 32 * COIN;
    else if(nHeight <= 1080000) nSubsidy = 16 * COIN;
    else if (nHeight <= 1584000) nSubsidy = 8 * COIN;
    else if (nHeight <= 2304000) nSubsidy = 4 * COIN;
    else if (nHeight <= 5256000) nSubsidy = 2 * COIN;
    else if (nHeight <= 26280000) nSubsidy = 1 * COIN;

  }

  return nSubsidy + nFees;
}
#endif

/*
 * wormholes modified to end at height 1699157 (12.17)
 */
int64 ltc_GetBlockValue(int nHeight, int64 nFees)
{
  int StartOffset;
  int WormholeStartBlock;
  int mod = nHeight % 36000;
  if (mod != 0) mod = 1;
  int epoch = (nHeight / 36000) + mod;
  long wseed = 5299860 * epoch; /* discovered: 1952, Atomic number: 99 Melting Point: 860 */

  StartOffset = ltc_generateMTRandom(wseed, 35820);
  WormholeStartBlock = StartOffset + ((epoch - 1)  * 36000); // Wormholes start from Epoch 2

  int64 nSubsidy = 0;
  if(epoch > 1 && epoch < 48 && nHeight >= WormholeStartBlock && nHeight < WormholeStartBlock + 180)
  {
    nSubsidy = 2973 * COIN;
  }
  else
  {
    if    (nHeight == 1)        nSubsidy = 10747 * COIN;
    else if (nHeight <= 72000)    nSubsidy = 1024 * COIN;
    else if (nHeight <= 144000)   nSubsidy = 512 * COIN;
    else if (nHeight <= 288000)   nSubsidy = 256 * COIN;
    else if (nHeight <= 432000)   nSubsidy = 128 * COIN;
    else if (nHeight <= 576000)   nSubsidy = 64 * COIN;
    else if (nHeight <= 864000)   nSubsidy = 32 * COIN;
    else if (nHeight <= 1080000)  nSubsidy = 16 * COIN;
    else if (nHeight <= 1584000)  nSubsidy = 8 * COIN;
    else if (nHeight <= 2304000)  nSubsidy = 4 * COIN;
    else if (nHeight <= 5256000)  nSubsidy = 2 * COIN;
    else if (nHeight <= 26280000) nSubsidy = 1 * COIN;
    else nSubsidy = 0;
  }

  return (nSubsidy + nFees);
}

#if 0
namespace LTC_Checkpoints
{
  typedef std::map<int, uint256> MapCheckpoints;

  //
  // What makes a good checkpoint block?
  // + Is surrounded by blocks with reasonable timestamps
  //   (no blocks before with a timestamp after, none after with
  //    timestamp before)
  // + Contains no strange transactions
  //
  static MapCheckpoints mapCheckpoints; 


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

}
#endif




static int64_t ltc_GetTxWeight(const CTransaction& tx)
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(tx, SER_NETWORK, LTC_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (LTC_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(tx, SER_NETWORK, LTC_PROTOCOL_VERSION);
 
  return (weight);
}

 
CBlock* ltc_CreateNewBlock(const CPubKey& rkey)
{
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
  CBlockIndex *pindexPrev = GetBestBlockIndex(iface);

  // Create new block
  //auto_ptr<CBlock> pblock(new CBlock());
  auto_ptr<LTCBlock> pblock(new LTCBlock());
  if (!pblock.get())
    return NULL;

  /* coinbase */
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vin[0].prevout.SetNull();
  txNew.vout.resize(1);
  txNew.vout[0].scriptPubKey << rkey << OP_CHECKSIG;
  pblock->vtx.push_back(txNew);

  /* attributes */
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

  unsigned int nHeight = pindexPrev->nHeight + 1;

  /* assign reward(s) */
  int64 nReward = ltc_GetBlockValue(nHeight, nFees);
  pblock->vtx[0].vout[0].nValue = nReward;

  // Fill in header
  pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
//  pblock->hashMerkleRoot = pblock->BuildMerkleTree();
  pblock->UpdateTime(pindexPrev);
  pblock->nBits          = pblock->GetNextWorkRequired(pindexPrev);
  pblock->nNonce         = 0;

  core_GenerateCoinbaseCommitment(iface, pblock.get(), pindexPrev);

  /* fill coinbase signature (BIP34) */
  core_IncrementExtraNonce(pblock.get(), pindexPrev);

  return pblock.release();
}


bool ltc_CreateGenesisBlock()
{
  blkidx_t *blockIndex = GetBlockTable(LTC_COIN_IFACE);
  bool ret;

  if (blockIndex->count(ltc_hashGenesisBlock) != 0)
    return (true); /* already created */

  /* Genesis block */
  const char* pszTimestamp = "NY Times 19/Feb/2014 North Korea Arrests Christian Missionary From Australia";
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vout.resize(1);
  txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
  txNew.vout[0].nValue = 50 * COIN;
//  txNew.vout[0].scriptPubKey = ...;
  LTCBlock block;
  block.vtx.push_back(txNew);
  block.hashPrevBlock = 0;
  block.hashMerkleRoot = block.BuildMerkleTree();
  block.nVersion = 1;
  block.nTime    = 1392841423;
  block.nBits    = 0x1e0ffff0;
  block.nNonce   = 3236648;


  block.print();
  if (block.GetHash() != ltc_hashGenesisBlock)
    return (false);
  if (block.hashMerkleRoot != uint256("0xb3e47e8776012ee4352acf603e6b9df005445dcba85c606697f422be3cc26f9b")) {
    return (error(SHERR_INVAL, "ltc_CreateGenesisBlock: invalid merkle root generated."));
  }

  if (!block.WriteBlock(0)) {
    return (false);
  }

  ret = block.AddToBlockIndex();
  if (!ret)
    return (false);
  (*blockIndex)[ltc_hashGenesisBlock]->nStatus |= BLOCK_HAVE_DATA;

  return (true);
}




static bool ltc_IsFromMe(CTransaction& tx)
{
  CWallet *pwallet = GetWallet(LTC_COIN_IFACE);

  if (pwallet->IsFromMe(tx))
    return true;

  return false;
}

static void ltc_EraseFromWallets(uint256 hash)
{
  CWallet *pwallet = GetWallet(LTC_COIN_IFACE);

  pwallet->EraseFromWallet(hash);
}

bool ltc_ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(LTC_COIN_IFACE);
  int ifaceIndex = LTC_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
  CBlockIndex *pindexPrev = GetBestBlockIndex(iface);
  shtime_t ts;

  // Check for duplicate
  uint256 hash = pblock->GetHash();

	if (pblock->hashPrevBlock == 0 &&
			hash != ltc_hashGenesisBlock) {
		Debug("(ltc) ProcessBlock: warning: invalid genesis block \"%s\" submitted by \"%s\".", hash.GetHex().c_str(), (pfrom?pfrom->addr.ToString().c_str():"<local>"));
		return (false);
	}


#if 0
  if (blockIndex->count(hash)) {
    return Debug("(ltc) ProcessBlock: already have block %s", hash.GetHex().c_str());
  }
  if (pindexBest && 
      pblock->hashPrevBlock != pindexBest->GetBlockHash() &&
      ltc_IsOrphanBlock(hash)) {
    return Debug("(ltc) ProcessBlock: already have block (orphan) %s", hash.ToString().c_str());
  }
#endif

  if (pblock->vtx.size() != 0 && pblock->vtx[0].wit.IsNull()) {
    if (pindexPrev && IsWitnessEnabled(iface, pindexPrev) &&
        -1 != GetWitnessCommitmentIndex(*pblock)) {
      core_UpdateUncommittedBlockStructures(iface, pblock, pindexPrev);
      Debug("(ltc) ProcessBlock: warning: received block \"%s\" with null witness commitment [height %d].", hash.GetHex().c_str(), (int)pindexPrev->nHeight);
    }
  }

  // Preliminary checks
  if (!pblock->CheckBlock()) {
    return error(SHERR_INVAL, "(ltc) ProcessBlock: failure verifying block '%s'.", hash.GetHex().c_str());
  }


#if 0
  CBlockIndex* pcheckpoint = LTC_Checkpoints::GetLastCheckpoint(*blockIndex);
  if (pcheckpoint && pblock->hashPrevBlock != GetBestBlockChain(iface))
  {
    // Extra checks to prevent "fill up memory by spamming with bogus blocks"
    int64 deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
    if (deltaTime < 0)
    {
      if (pfrom)
        pfrom->Misbehaving(100);
pblock->print();
      return error(SHERR_INVAL, "ProcessBlock() : block with timestamp before last checkpoint");
    }
  }
#endif

  /*
   * LTC: If previous hash and it is unknown.
   */
  if (pblock->hashPrevBlock != 0 &&
      !blockIndex->count(pblock->hashPrevBlock)) {
    Debug("(ltc) ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.GetHex().c_str());
    if (pfrom) {
      ltc_AddOrphanBlock(pblock);
      STAT_BLOCK_ORPHAN(iface)++;

      /* request missing blocks */
      CBlockIndex *pindexBest = GetBestBlockIndex(LTC_COIN_IFACE);
      if (pindexBest) {
        Debug("(ltc) ProcessBlocks: requesting blocks from height %d due to orphan '%s'.\n", pindexBest->nHeight, pblock->GetHash().GetHex().c_str());
        pfrom->PushGetBlocks(GetBestBlockIndex(LTC_COIN_IFACE), ltc_GetOrphanRoot(pblock->GetHash()));
				InitServiceBlockEvent(LTC_COIN_IFACE, pindexBest->nHeight);
      }
    }

    return true;
  }

  /* store to disk */
  timing_init("ProcessBlock/AcceptBlock", &ts);
  bool ok = pblock->AcceptBlock();
  timing_term(LTC_COIN_IFACE, "ProcessBlock/AcceptBlock", &ts);
  if (!ok) {
    iface->net_invalid = time(NULL);
    return error(SHERR_INVAL, "ProcessBlock() : AcceptBlock FAILED");
  }

#if 0
  uint256 nextHash;
  while (ltc_GetOrphanNextHash(hash, nextHash)) {
    hash = nextHash;
    CBlock *block = ltc_GetOrphanBlock(hash);
    if (!block || !block->AcceptBlock())
      break;

    ltc_RemoveOrphanBlock(hash);
    STAT_BLOCK_ORPHAN(iface)--;
  }
#endif

  ServiceBlockEventUpdate(LTC_COIN_IFACE);

  return true;
}

bool ltc_CheckProofOfWork(uint256 hash, unsigned int nBits)
{
  CBigNum bnTarget;
  bnTarget.SetCompact(nBits);

  /* Check range */
  if (bnTarget <= 0 || bnTarget > ltc_bnProofOfWorkLimit)
    return error(SHERR_INVAL, "CheckProofOfWork() : nBits below minimum work");

  /* Check proof of work matches claimed amount */
  if (hash > bnTarget.getuint256())
    return error(SHERR_INVAL, "CheckProofOfWork() : hash doesn't match nBits");

  return true;
}

/**
 * @note These are checks that are independent of context that can be verified before saving an orphan block.
 */
bool LTCBlock::CheckBlock()
{
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
	bool ok;

  if (vtx.empty()) {
    return (trust(-100, "(ltc) CheckBlock: block submitted with zero transactions"));
  }

  int64_t weight = GetBlockWeight(); 
  if (weight > MAX_BLOCK_WEIGHT(iface)) {
    return (trust(-100, "(ltc) CheckBlock: block weight (%d) > max (%d)", weight, MAX_BLOCK_WEIGHT(iface)));
  }

  if (!vtx[0].IsCoinBase()) {
    return (trust(-100, "(ltc) ChecKBlock: first transaction is not coin base"));
  }

	/* verify difficulty match proof-of-work hash. */
	ok = ltc_CheckProofOfWork(GetPoWHash(), nBits);
	if (!ok)
		return error(SHERR_INVAL, "CheckBlock() : proof of work failed");

  // Check timestamp
  if (GetBlockTime() > GetAdjustedTime() + LTC_MAX_DRIFT_TIME) {
    return error(SHERR_INVAL, "CheckBlock() : block timestamp too far in the future");
  }

  // First transaction must be coinbase, the rest must not be
  for (unsigned int i = 1; i < vtx.size(); i++) {
    if (vtx[i].IsCoinBase()) {
      return (trust(-100, "(ltc) CheckBlock: more than one coinbase in transaction"));
    }
  }

#if 0
  if (nVersion >= 2) {
    CBlockIndex* pindexPrev = GetBestBlockIndex(LTC_COIN_IFACE);
    const int nHeight = pindexPrev ? (pindexPrev->nHeight + 1) : 0;
    CScript expect = CScript() << nHeight;
    if (block.vtx[0].vin[0].scriptSig.size() < expect.size() ||
        !std::equal(expect.begin(), expect.end(), block.vtx[0].vin[0].scriptSig.begin())) {
      return (trust(-10, "(ltc) CheckBlock: block \"%s\" height mismatch in coinbase", ));
    }
  }
#endif

  // Check transactions
  BOOST_FOREACH(CTransaction& tx, vtx) {
    if (!tx.CheckTransaction(LTC_COIN_IFACE)) {
      return (trust(-1, "(ltc) ChecKBlock: transaction verification failure"));
    }
  }

  // Check for duplicate txids. This is caught by ConnectInputs(),
  // but catching it earlier avoids a potential DoS attack:
  set<uint256> uniqueTx;
  BOOST_FOREACH(const CTransaction& tx, vtx)
  {
    uniqueTx.insert(tx.GetHash());
  }
  if (uniqueTx.size() != vtx.size()) {
    return (trust(-100, "(ltc) CheckBlock: duplicate transactions"));
  }

  unsigned int nSigOps = 0;
  BOOST_FOREACH(const CTransaction& tx, vtx)
  {
    nSigOps += tx.GetLegacySigOpCount();
  }
  if (nSigOps > MAX_BLOCK_SIGOPS(iface)) {
    return (trust(-100, "(ltc) CheckBlock: out-of-bounds SigOpCount"));
  }

  // Check merkleroot
  if (hashMerkleRoot != BuildMerkleTree()) {
    return (trust(-100, "(emc) CheckBlock: invalid merkle root hash"));
  }

  CBlockIndex *pindexPrev = GetBlockIndexByHash(ifaceIndex, hashPrevBlock);
  if (pindexPrev) {
    if (!core_CheckBlockWitness(iface, (CBlock *)this, pindexPrev))
      return (trust(-10, "(emc) CheckBlock: invalid witness integrity."));
  }

  return true;
}


#if 0
bool static LTC_Reorganize(CTxDB& txdb, CBlockIndex* pindexNew, LTC_CTxMemPool *mempool)
{
  char errbuf[1024];

 // Find the fork
  CBlockIndex* pindexBest = GetBestBlockIndex(LTC_COIN_IFACE);
  CBlockIndex* pfork = pindexBest;
  CBlockIndex* plonger = pindexNew;
  while (pfork != plonger)
  {
    while (plonger->nHeight > pfork->nHeight)
      if (!(plonger = plonger->pprev))
        return error(SHERR_INVAL, "Reorganize() : plonger->pprev is null");
    if (pfork == plonger)
      break;
    if (!pfork->pprev) {
      sprintf(errbuf, "LTC_Reorganize: no previous chain for '%s' height %d\n", pfork->GetBlockHash().GetHex().c_str(), pfork->nHeight); 
      return error(SHERR_INVAL, errbuf);
    }
    pfork = pfork->pprev;
  }


  // List of what to disconnect
  vector<CBlockIndex*> vDisconnect;
  for (CBlockIndex* pindex = GetBestBlockIndex(LTC_COIN_IFACE); pindex != pfork; pindex = pindex->pprev)
    vDisconnect.push_back(pindex);

  // List of what to connect
  vector<CBlockIndex*> vConnect;
  for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
    vConnect.push_back(pindex);
  reverse(vConnect.begin(), vConnect.end());

pindexBest = GetBestBlockIndex(LTC_COIN_IFACE);
Debug("REORGANIZE: Disconnect %i blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
Debug("REORGANIZE: Connect %i blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

  // Disconnect shorter branch
  vector<CTransaction> vResurrect;
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
  {
    LTCBlock block;
    if (!block.ReadFromDisk(pindex)) {
      if (!block.ReadArchBlock(pindex->GetBlockHash()))
        return error(SHERR_IO, "LTC_Reorganize: Disconnect: block hash '%s' [height %d] could not be loaded.", pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight);
    }
    if (!block.DisconnectBlock(txdb, pindex))
      return error(SHERR_INVAL, "Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().c_str());

    // Queue memory transactions to resurrect
    BOOST_FOREACH(const CTransaction& tx, block.vtx)
      if (!tx.IsCoinBase())
        vResurrect.push_back(tx);
  }

  // Connect longer branch
  vector<LTCBlock> vDelete;
  for (unsigned int i = 0; i < vConnect.size(); i++)
  {
    CBlockIndex* pindex = vConnect[i];
    LTCBlock block;
    if (!block.ReadFromDisk(pindex)) {
      if (!block.ReadArchBlock(pindex->GetBlockHash()))
        return error(SHERR_IO, "LTC_Reorganize: Connect: block hash '%s' [height %d] could not be loaded.", pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight);
    }

    if (!block.ConnectBlock(txdb, pindex))
    {
      // Invalid block
      return error(SHERR_INVAL, "Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
    }

    // Queue memory transactions to delete
    vDelete.push_back(block);
  }

  if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
    return error(SHERR_INVAL, "Reorganize() : WriteHashBestChain failed");

  // Make sure it's successfully written to disk before changing memory structure
  if (!txdb.TxnCommit())
    return error(SHERR_INVAL, "Reorganize() : TxnCommit failed");

  // Disconnect shorter branch
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
    if (pindex->pprev)
      pindex->pprev->pnext = NULL;

  // Connect longer branch
  BOOST_FOREACH(CBlockIndex* pindex, vConnect)
    if (pindex->pprev)
      pindex->pprev->pnext = pindex;

  // Resurrect memory transactions that were in the disconnected branch
  BOOST_FOREACH(CTransaction& tx, vResurrect)
    mempool->AddTx(tx);

  // Delete redundant memory transactions that are in the connected branch
  BOOST_FOREACH(CBlock& block, vDelete) {
    mempool->Commit(block);
  }

  return true;
}
#endif

void LTCBlock::InvalidChainFound(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
  ValidIndexSet *setValid = GetValidIndexSet(LTC_COIN_IFACE);

  pindexNew->nStatus |= BLOCK_FAILED_VALID;
  setValid->erase(pindexNew);

  error(SHERR_INVAL, "LTC: InvalidChainFound: invalid block=%s  height=%d  work=%s  date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      pindexNew->bnChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S",
        pindexNew->GetBlockTime()).c_str());

}

#ifdef USE_LEVELDB_TXDB
bool ltc_SetBestChainInner(CBlock *block, CTxDB& txdb, CBlockIndex *pindexNew)
{
  uint256 hash = block->GetHash();

  // Adding to current best branch
  if (!block->ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
  {
    txdb.TxnAbort();
    block->InvalidChainFound(pindexNew);
    return false;
  }
  if (!txdb.TxnCommit())
    return error(SHERR_IO, "SetBestChain() : TxnCommit failed");

  // Add to current best branch
  pindexNew->pprev->pnext = pindexNew;

  // Delete redundant memory transactions
  LTCBlock::mempool.Commit(block);

  return true;
}
#endif

// notify wallets about a new best chain
void static LTC_SetBestChain(const CBlockLocator& loc)
{
  CWallet *pwallet = GetWallet(LTC_COIN_IFACE);

  pwallet->SetBestChain(loc);
}



#ifdef USE_LEVELDB_TXDB
bool LTCBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

  Debug("LTCBlock::SetBestChain: setting best chain to block '%s' @ height %d.", pindexNew->GetBlockHash().GetHex().c_str(), pindexNew->nHeight);

  if (!txdb.TxnBegin())
    return error(SHERR_INVAL, "SetBestChain() : TxnBegin failed");

  if (LTCBlock::pindexGenesisBlock == NULL && hash == ltc_hashGenesisBlock)
  {
    txdb.WriteHashBestChain(hash);
    if (!txdb.TxnCommit())
      return error(SHERR_INVAL, "SetBestChain() : TxnCommit failed");
    LTCBlock::pindexGenesisBlock = pindexNew;
  }
  else if (hashPrevBlock == GetBestBlockChain(iface))
  {
    if (!ltc_SetBestChainInner(this, txdb, pindexNew))
      return error(SHERR_INVAL, "SetBestChain() : SetBestChainInner failed");
  }
  else
  {
/* DEBUG: 060316 - reorg will try to load this block from db. */
    WriteArchBlock();

    ret = LTC_Reorganize(txdb, pindexNew, &mempool);
    if (!ret) {
      txdb.TxnAbort();
      InvalidChainFound(pindexNew);
      return error(SHERR_INVAL, "SetBestChain() : Reorganize failed");
    }
  }

  // Update best block in wallet (so we can detect restored wallets)
  bool fIsInitialDownload = IsInitialBlockDownload(LTC_COIN_IFACE);
  if (!fIsInitialDownload) {
    LTC_SetBestChain(wallet->GetLocator(pindexNew));
  }

  // New best block
//  LTCBlock::hashBestChain = hash;
  SetBestBlockIndex(LTC_COIN_IFACE, pindexNew);
//  SetBestHeight(iface, pindexNew->nHeight);
  wallet->bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();
  STAT_TX_ACCEPTS(iface)++;

  // Check the version of the last 100 blocks to see if we need to upgrade:
  if (!fIsInitialDownload)
  {
    int nUpgraded = 0;
    const CBlockIndex* pindex = GetBestBlockIndex(LTC_COIN_IFACE);
    for (int i = 0; i < 100 && pindex != NULL; i++)
    {
      if (pindex->nVersion > CURRENT_VERSION)
        ++nUpgraded;
      pindex = pindex->pprev;
    }
    if (nUpgraded > 0)
      Debug("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, CURRENT_VERSION);
    //        if (nUpgraded > 100/2)
    // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
    //            strMiscWarning = _("Warning: this version is obsolete, upgrade required");
  }

  std::string strCmd = GetArg("-blocknotify", "");

  if (!fIsInitialDownload && !strCmd.empty())
  {
    boost::replace_all(strCmd, "%s", GetBestBlockChain(iface).GetHex());
    boost::thread t(runCommand, strCmd); // thread runs free
  }

  return true;
}
#endif




bool LTCBlock::IsBestChain()
{
  CBlockIndex *pindexBest = GetBestBlockIndex(LTC_COIN_IFACE);
  return (pindexBest && GetHash() == pindexBest->GetBlockHash());
}

bool LTCBlock::AcceptBlock()
{
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
  CBlockIndex* pindexPrev;

  pindexPrev = GetBlockIndexByHash(ifaceIndex, hashPrevBlock);
  if (!pindexPrev) {
    return error(SHERR_INVAL, "(ltc) AcceptBlock: prev block '%s' not found", hashPrevBlock.GetHex().c_str());
  }
  
  if (GetBlockTime() > GetAdjustedTime() + LTC_MAX_DRIFT_TIME) {
    print();
    return error(SHERR_INVAL, "(ltc) AcceptBlock() : block's timestamp too far in the future.");

  }
  if (GetBlockTime() <= pindexPrev->GetMedianTimePast()) {
    print();
    return error(SHERR_INVAL, "(ltc) AcceptBlock() : block's timestamp too far in the past.");
  }


	/* redundant */
#if 0
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
#endif


  return (core_AcceptBlock(this, pindexPrev));
}

CScript LTCBlock::GetCoinbaseFlags()
{
  return (LTC_COINBASE_FLAGS);
}

static void ltc_UpdatedTransaction(const uint256& hashTx)
{
  CWallet *pwallet = GetWallet(LTC_COIN_IFACE);

  pwallet->UpdatedTransaction(hashTx);
}


bool LTCBlock::ReadBlock(uint64_t nHeight)
{
int ifaceIndex = LTC_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
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

  SetNull();

  /* serialize binary data into block */
  sBlock.write((const char *)sBlockData, sBlockLen);
  sBlock >> *this;
  free(sBlockData);

  uint256 cur_hash = GetHash();
  {
    uint256 db_hash;
    bc_hash_t ret_hash;
    err = bc_get_hash(bc, nHeight, ret_hash);
    if (err) {
      return error(err, "LTCBlock::ReadBlock: error obtaining block-chain height %d.", nHeight);
    }
    db_hash.SetRaw((unsigned int *)ret_hash);

#if 0
    if (!bc_hash_cmp(db_hash.GetRaw(), cur_hash.GetRaw())) {
      sprintf(errbuf, "CBlock::ReadBlock: hash '%s' from loaded block at pos %d has invalid hash of '%s'.", db_hash.GetHex().c_str(), nHeight, cur_hash.GetHex().c_str());
      print();
      SetNull();
      return error(SHERR_INVAL, errbuf);
    }
#endif
  }

#if 0
  if (!CheckBlock()) {
    unet_log(ifaceIndex, "CBlock::ReadBlock: block validation failure.");
    return (false);
  }
#endif

  return (true);
}

bool LTCBlock::ReadArchBlock(uint256 hash)
{
  int ifaceIndex = LTC_COIN_IFACE;
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

if (hash != GetHash()) {
return (false);
}

Debug("ARCH: loaded block '%s'\n", GetHash().GetHex().c_str());
  return (true);
}

bool LTCBlock::IsOrphan()
{
  return (ltc_IsOrphanBlock(GetHash()));
}


#ifdef USE_LEVELDB_COINDB
bool ltc_Truncate(uint256 hash)
{
  blkidx_t *blockIndex = GetBlockTable(LTC_COIN_IFACE);
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  CBlockIndex *pBestIndex;
  CBlockIndex *cur_index;
  CBlockIndex *pindex;
  unsigned int nHeight;
  int err;

  if (!iface || !iface->enabled)
    return (SHERR_OPNOTSUPP);

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
  unsigned int nMinHeight = cur_index->nHeight;

	uint32_t nMaxHeight = 0;
	(void)bc_idx_next(bc, &nMaxHeight);
	nMaxHeight = MAX(1, nMaxHeight) - 1;

  LTCTxDB txdb; /* OPEN */

  for (nHeight = nMaxHeight; nHeight > nMinHeight; nHeight--) {
    LTCBlock block;
    if (block.ReadBlock(nHeight)) {
      uint256 t_hash = block.GetHash();
      if (hash == cur_index->GetBlockHash())
        break; /* bad */

      /* remove from wallet */
      BOOST_FOREACH(CTransaction& tx, block.vtx)
        wallet->EraseFromWallet(tx.GetHash());

      /* remove from block-chain */
      if (blockIndex->count(t_hash) != 0)
        block.DisconnectBlock(txdb, (*blockIndex)[t_hash]);

      /* remove table of hash cache */
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
  wallet->bnBestChainWork = cur_index->bnChainWork;
  InitServiceBlockEvent(LTC_COIN_IFACE, cur_index->nHeight + 1);

  return (true);
}
bool LTCBlock::Truncate()
{
  return (ltc_Truncate(GetHash()));
}
#else
bool LTCBlock::Truncate()
{
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
  return (core_Truncate(iface, GetHash()));
}
#endif

bool LTCBlock::VerifyCheckpoint(int nHeight)
{
	CWallet *wallet = GetWallet(LTC_COIN_IFACE);
	if (!wallet || !wallet->checkpoints) return (true);
  return (wallet->checkpoints->CheckBlock(nHeight, GetHash()));
}

uint64_t LTCBlock::GetTotalBlocksEstimate()
{
	CWallet *wallet = GetWallet(LTC_COIN_IFACE);
	if (!wallet || !wallet->checkpoints) return (true);
  return ((uint64_t)wallet->checkpoints->GetTotalBlocksEstimate());
}

bool LTCBlock::AddToBlockIndex()
{
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(LTC_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  ValidIndexSet *setValid = GetValidIndexSet(LTC_COIN_IFACE);
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

  pindexNew->bnChainWork = (pindexNew->pprev ? pindexNew->pprev->bnChainWork : 0) + pindexNew->GetBlockWork(false);

  if (IsWitnessEnabled(iface, pindexNew->pprev)) {
    pindexNew->nStatus |= BLOCK_OPT_WITNESS;
  }


  if (pindexNew->bnChainWork > wallet->bnBestChainWork) {
#ifdef USE_LEVELDB_COINDB
    LTCTxDB txdb;
    bool ret = SetBestChain(txdb, pindexNew);
    txdb.Close();
    if (!ret)
      return false;
#else
    bool ret = SetBestChain(pindexNew);
    if (!ret)
      return (false);
#endif
  } else {
    WriteArchBlock();
  }

  return true;
}



int64_t LTCBlock::GetBlockWeight()
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(*this, SER_NETWORK, LTC_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (LTC_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(*this, SER_NETWORK, LTC_PROTOCOL_VERSION);

  return (weight);
}




#if 0
bool LTC_CTxMemPool::accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs, bool* pfMissingInputs)
{
  if (pfMissingInputs)
    *pfMissingInputs = false;

  if (!tx.CheckTransaction(LTC_COIN_IFACE))
    return error(SHERR_INVAL, "CTxMemPool::accept() : CheckTransaction failed");

  // Coinbase is only valid in a block, not as a loose transaction
  if (tx.IsCoinBase())
    return error(SHERR_INVAL, "CTxMemPool::accept() : coinbase as individual tx");

  // To help v0.1.5 clients who would see it as a negative number
  if ((int64)tx.nLockTime > std::numeric_limits<int>::max())
    return error(SHERR_INVAL, "CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

  // Rather not work on nonstandard transactions (unless -testnet)
  if (!fTestNet && !tx.IsStandard())
    return error(SHERR_INVAL, "CTxMemPool::accept() : nonstandard transaction type");

  // Do we already have it?
  uint256 hash = tx.GetHash();
  {
    LOCK(cs);
    if (mapTx.count(hash))
      return false;
  }
  if (fCheckInputs)
    if (txdb.ContainsTx(hash))
      return false;

  // Check for conflicts with in-memory transactions
  CTransaction* ptxOld = NULL;
  for (unsigned int i = 0; i < tx.vin.size(); i++)
  {
    COutPoint outpoint = tx.vin[i].prevout;
    if (mapNextTx.count(outpoint))
    {
      // ltc disallow's replacement of previous tx
      error(SHERR_NOTUNIQ, "(ltc) accept: input from tx conflicts with existing pool tx.");
      return (SHERR_NOTUNIQ);
    }
  }

  if (fCheckInputs)
  {
    MapPrevTx mapInputs;
    map<uint256, CTxIndex> mapUnused;
    bool fInvalid = false;
    if (!tx.FetchInputs(txdb, mapUnused, NULL, false, mapInputs, fInvalid))
    {
      if (fInvalid)
        return error(SHERR_INVAL, "CTxMemPool::accept() : FetchInputs found invalid tx %s", hash.GetHex().c_str());
      if (pfMissingInputs)
        *pfMissingInputs = true;
      return error(SHERR_INVAL, "CTxMemPool::accept() : FetchInputs found tx '%s' has missing inputs", hash.GetHex().c_str());
    }

    // Check for non-standard pay-to-script-hash in inputs
    if (!tx.AreInputsStandard(LTC_COIN_IFACE, mapInputs) && !fTestNet)
      return error(SHERR_INVAL, "CTxMemPool::accept() : nonstandard transaction input");

    // Note: if you modify this code to accept non-standard transactions, then
    // you should add code here to check that the transaction does a
    // reasonable number of ECDSA signature verifications.

    int64 nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
    unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, LTC_PROTOCOL_VERSION);

    // Don't accept it if it can't get into a block
    CWallet *pwallet = GetWallet(LTC_COIN_IFACE);
    int64 nMinFee = pwallet->CalculateFee(tx);
    if (nFees < nMinFee)
      return error(SHERR_INVAL, "(ltc) CTxMemPool::accept() : not enough fees");

    // Continuously rate-limit free transactions
    // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
    // be annoying or make other's transactions take longer to confirm.
    if (nFees < LTC_MIN_RELAY_TX_FEE)
    {
      static CCriticalSection cs;
      static double dFreeCount;
      static int64 nLastTime;
      int64 nNow = GetTime();

      {
        LOCK(cs);
        // Use an exponentially decaying ~10-minute window:
        dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
        nLastTime = nNow;
        // -limitfreerelay unit is thousand-bytes-per-minute
        // At default rate it would take over a month to fill 1GB
        if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000 && !ltc_IsFromMe(tx))
          return error(SHERR_INVAL, "CTxMemPool::accept() : free transaction rejected by rate limiter");
        Debug("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
        dFreeCount += nSize;
      }
    }

    // Check against previous transactions
    // This is done last to help prevent CPU exhaustion denial-of-service attacks.

    if (!ltc_ConnectInputs(&tx, mapInputs, mapUnused, CDiskTxPos(0,0,0), GetBestBlockIndex(LTC_COIN_IFACE), false, false))
    {
      return error(SHERR_INVAL, "CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().substr(0,10).c_str());
    }
  }

  // Store transaction in memory
  {
    LOCK(cs);
    if (ptxOld)
    {
      Debug("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
      remove(*ptxOld);
    }
    addUnchecked(hash, tx);
  }

  ///// are we sure this is ok when loading transactions or restoring block txes
  // If updated, erase old tx from wallet
  if (ptxOld)
    ltc_EraseFromWallets(ptxOld->GetHash());

  Debug("(ltc) mempool accepted %s (pool-size %u)\n",
      hash.ToString().c_str(), mapTx.size());
  return true;
}

bool LTC_CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);

  // Add to memory pool without checking anything.  Don't call this directly,
  // call CTxMemPool::accept to properly check the transaction first.
  {
    mapTx[hash] = tx;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
      mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
    STAT_TX_ACCEPTS(iface)++;
  }
  return true;
}


bool LTC_CTxMemPool::remove(CTransaction &tx)
{
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);

  // Remove transaction from memory pool
  {
    LOCK(cs);
    uint256 hash = tx.GetHash();
    if (mapTx.count(hash))
    {
      BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapNextTx.erase(txin.prevout);
      mapTx.erase(hash);
      STAT_TX_ACCEPTS(iface)++;
    }
  }
  return true;
}

void LTC_CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}
#endif

CBlockIndex *ltc_GetLastCheckpoint()
{
	CWallet *wallet = GetWallet(LTC_COIN_IFACE);
	if (!wallet || !wallet->checkpoints) return (NULL);
  return (wallet->checkpoints->GetLastCheckpoint());
}



#ifdef USE_LEVELDB_COINDB

#ifndef USE_LEVELDB_TXDB
bool LTCBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

  if (LTCBlock::pindexGenesisBlock == NULL && hash == ltc_hashGenesisBlock)
  {
    if (!txdb.TxnBegin())
      return error(SHERR_INVAL, "SetBestChain() : TxnBegin failed");
    txdb.WriteHashBestChain(hash);
    if (!txdb.TxnCommit())
      return error(SHERR_INVAL, "SetBestChain() : TxnCommit failed");
    LTCBlock::pindexGenesisBlock = pindexNew;
  } else {
    timing_init("SetBestChain/commit", &ts);
    ret = core_CommitBlock(txdb, this, pindexNew);
    timing_term(LTC_COIN_IFACE, "SetBestChain/commit", &ts);
    if (!ret)
      return (false);
  }

  // Update best block in wallet (so we can detect restored wallets)
  bool fIsInitialDownload = IsInitialBlockDownload(LTC_COIN_IFACE);
  if (!fIsInitialDownload) {
    timing_init("SetBestChain/locator", &ts);
    LTC_SetBestChain(wallet->GetLocator(pindexNew));
    timing_term(LTC_COIN_IFACE, "SetBestChain/locator", &ts);

#ifndef USE_LEVELDB_COINDB
    WriteHashBestChain(hash);
#endif
  }

  // New best block
  SetBestBlockIndex(LTC_COIN_IFACE, pindexNew);
  wallet->bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();

  {
    CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
    if (iface)
      STAT_TX_ACCEPTS(iface)++;
  }

  return true;
}
#endif

bool LTCBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
  char errbuf[1024];

  /* "Check it again in case a previous version let a bad block in" */
#if 1 /* DEBUG: */
  if (!CheckBlock())
    return false;
#endif

  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
  unsigned int nFile = LTC_COIN_IFACE;
  unsigned int nBlockPos = pindex->nHeight;;
  bc_hash_t b_hash;
  int err;

  // Do not allow blocks that contain transactions which 'overwrite' older transactions,
  // unless those are already completely spent.
  // If such overwrites are allowed, coinbases and transactions depending upon those
  // can be duplicated to remove the ability to spend the first instance -- even after
  // being sent to another address.
  // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
  // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
  // already refuses previously-known transaction id's entirely.
  // This rule applies to all blocks whose timestamp is after October 1, 2012, 0:00 UTC.
  int64 nBIP30SwitchTime = 1349049600;
  bool fEnforceBIP30 = (pindex->nTime > nBIP30SwitchTime);

  // BIP16 didn't become active until October 1 2012
  int64 nBIP16SwitchTime = 1349049600;
  bool fStrictPayToScriptHash = (pindex->nTime >= nBIP16SwitchTime);

  map<uint256, CTxIndex> mapQueuedChanges;
  int64 nFees = 0;
  unsigned int nSigOps = 0;
  BOOST_FOREACH(CTransaction& tx, vtx)
  {
    uint256 hashTx = tx.GetHash();
    int nTxPos;

    if (fEnforceBIP30) {
      CTxIndex txindexOld;
      if (txdb.ReadTxIndex(hashTx, txindexOld)) {
        BOOST_FOREACH(CDiskTxPos &pos, txindexOld.vSpent)
          if (tx.IsSpentTx(pos))
            return error(SHERR_INVAL, "LTCBlock::ConnectBlock: BIP30 enforced at height %d\n", pindex->nHeight);
      }
    }

    MapPrevTx mapInputs;
    CDiskTxPos posThisTx(LTC_COIN_IFACE, nBlockPos, nTxPos);
    if (!tx.IsCoinBase()) {
      bool fInvalid;
      if (!tx.FetchInputs(txdb, mapQueuedChanges, this, false, mapInputs, fInvalid)) {
        sprintf(errbuf, "LTC::ConnectBlock: FetchInputs failed for tx '%s' @ height %u\n", tx.GetHash().GetHex().c_str(), (unsigned int)nBlockPos);
        return error(SHERR_INVAL, errbuf);
      }
    }

    nSigOps += tx.GetSigOpCost(mapInputs);
    if (nSigOps > MAX_BLOCK_SIGOP_COST(iface)) {
      return (trust(-100, "(ltc) ConnectBlock: sigop cost exceeded maximum (%d > %d)", nSigOps, MAX_BLOCK_SIGOP_COST(iface)));
    }

    if (!tx.IsCoinBase()) {
      nFees += tx.GetValueIn(mapInputs)-tx.GetValueOut();

      if (!ltc_ConnectInputs(&tx, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fStrictPayToScriptHash)) {
        return error(SHERR_INVAL, "LTCBlock::ConnectBlock: error connecting inputs.");
      }
    }

    mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
  }

  // Write queued txindex changes
  for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
  {
    if (!txdb.UpdateTxIndex((*mi).first, (*mi).second)) {
      return error(SHERR_INVAL, "ConnectBlock() : UpdateTxIndex failed");
    }
  }

#if 0
  if (vtx.size() == 0) {
    return error(SHERR_INVAL, "LTCBlock::ConnectBlock: vtx.size() == 0");
  }
#endif
  
  int64 nValue = ltc_GetBlockValue(pindex->nHeight, 0);
  if (vtx[0].GetValueOut() > (nValue + nFees)) {
    sprintf(errbuf, "LTC_ConnectBlock: coinbase output (%d coins) higher than expected block value @ height %d (%d coins) [block %s].\n", FormatMoney(vtx[0].GetValueOut()).c_str(), pindex->nHeight, FormatMoney(nValue).c_str(), pindex->GetBlockHash().GetHex().c_str());
    return error(SHERR_INVAL, errbuf);
  }

  if (pindex->pprev)
  {
    if (pindex->pprev->nHeight + 1 != pindex->nHeight) {
error(SHERR_INVAL, "warning: ConnectBlock: block-index for hash '%s' height changed from %d to %d.\n", pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight, (pindex->pprev->nHeight + 1));
      pindex->nHeight = pindex->pprev->nHeight + 1;
    }
    if (!WriteBlock(pindex->nHeight)) {
      return (error(SHERR_INVAL, "ConnectBlock: error writing block hash '%s' to height %d\n", GetHash().GetHex().c_str(), pindex->nHeight));
    }

Debug("CONNECT: hash '%s' to height %d\n", GetHash().GetHex().c_str(), pindex->nHeight);
#if 0
    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    CDiskBlockIndex blockindexPrev(pindex->pprev);
    blockindexPrev.hashNext = pindex->GetBlockHash();
    if (!txdb.WriteBlockIndex(blockindexPrev))
      return error(SHERR_INVAL, "ConnectBlock() : WriteBlockIndex failed");
#endif
  }

  BOOST_FOREACH(CTransaction& tx, vtx)
    SyncWithWallets(iface, tx, this);

  return true;
}

bool LTCBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
  return (core_DisconnectBlock(txdb, pindex, this));
}

bool ltc_ConnectInputs(CTransaction *tx, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fStrictPayToScriptHash=true)
{

  if (tx->IsCoinBase())
    return (true);

  // Take over previous transactions' spent pointers
  // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
  // fMiner is true when called from the internal ltc miner
  // ... both are false when called from CTransaction::AcceptToMemoryPool

  int64 nValueIn = 0;
  int64 nFees = 0;
  for (unsigned int i = 0; i < tx->vin.size(); i++)
  {
    COutPoint prevout = tx->vin[i].prevout;
    assert(inputs.count(prevout.hash) > 0);
    CTxIndex& txindex = inputs[prevout.hash].first;
    CTransaction& txPrev = inputs[prevout.hash].second;

    if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
      return error(SHERR_INVAL, "ConnectInputs() : %s prevout.n out of range %d %d %d prev tx %s", tx->GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str());

    // If prev is coinbase, check that it's matured
    if (txPrev.IsCoinBase())
      for (const CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < LTC_COINBASE_MATURITY; pindex = pindex->pprev)
        //if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
        if (pindex->nHeight == txindex.pos.nBlockPos)// && pindex->nFile == txindex.pos.nFile)
          return error(SHERR_INVAL, "ConnectInputs() : tried to spend coinbase at depth %d", pindexBlock->nHeight - pindex->nHeight);

    // Check for negative or overflow input values
    nValueIn += txPrev.vout[prevout.n].nValue;
    if (!MoneyRange(LTC_COIN_IFACE, txPrev.vout[prevout.n].nValue) || !MoneyRange(LTC_COIN_IFACE, nValueIn))
      return error(SHERR_INVAL, "ConnectInputs() : txin values out of range");

  }
  // The first loop above does all the inexpensive checks.
  // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
  // Helps prevent CPU exhaustion attacks.
  for (unsigned int i = 0; i < tx->vin.size(); i++)
  {
    COutPoint prevout = tx->vin[i].prevout;
    assert(inputs.count(prevout.hash) > 0);
    CTxIndex& txindex = inputs[prevout.hash].first;
    CTransaction& txPrev = inputs[prevout.hash].second;

    /* this coin has been marked as spent. ensure this is not a re-write of the same transaction. */
    if (tx->IsSpentTx(txindex.vSpent[prevout.n])) {
      if (fMiner) return false;
      return error(SHERR_INVAL, "(ltc) ConnectInputs: %s prev tx (%s) already used at %s", tx->GetHash().GetHex().c_str(), txPrev.GetHash().GetHex().c_str(), txindex.vSpent[prevout.n].ToString().c_str());
    }

    // Skip ECDSA signature verification when connecting blocks (fBlock=true)
    // before the last blockchain checkpoint. This is safe because block merkle hashes are
    // still computed and checked, and any change will be caught at the next checkpoint.
		CWallet *wallet = GetWallet(LTC_COIN_IFACE);
		int nTotal = 0;
		if (wallet && wallet->checkpoints) nTotal = wallet->checkpoints->GetTotalBlocksEstimate();
    if (!(fBlock && (GetBestHeight(LTC_COIN_IFACE) < nTotal))) {
      // Verify signature
      if (!VerifySignature(LTC_COIN_IFACE, txPrev, *tx, i, fStrictPayToScriptHash, 0))
      {
        // only during transition phase for P2SH: do not invoke anti-DoS code for
        // potentially old clients relaying bad P2SH transactions
        if (fStrictPayToScriptHash && VerifySignature(LTC_COIN_IFACE, txPrev, *tx, i, false, 0))
          return error(SHERR_INVAL, "ConnectInputs() : %s P2SH VerifySignature failed", tx->GetHash().ToString().substr(0,10).c_str());

        return error(SHERR_INVAL, "ConnectInputs() : %s VerifySignature failed", tx->GetHash().ToString().substr(0,10).c_str());
      }
    }

    // Mark outpoints as spent
    txindex.vSpent[prevout.n] = posThisTx;

    // Write back
    if (fBlock || fMiner)
    {
      mapTestPool[prevout.hash] = txindex;
    }
  }

  if (nValueIn < tx->GetValueOut())
    return error(SHERR_INVAL, "ConnectInputs() : %s value in < value out", tx->GetHash().ToString().substr(0,10).c_str());

  // Tally transaction fees
  int64 nTxFee = nValueIn - tx->GetValueOut();
  if (nTxFee < 0)
    return error(SHERR_INVAL, "ConnectInputs() : %s nTxFee < 0", tx->GetHash().ToString().substr(0,10).c_str());
  nFees += nTxFee;
  if (!MoneyRange(LTC_COIN_IFACE, nFees))
    return error(SHERR_INVAL, "ConnectInputs() : nFees out of range");


  return true;
}

#else /* USE_LEVELDB_COINDB */

bool LTCBlock::SetBestChain(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(LTC_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

  if (LTCBlock::pindexGenesisBlock == NULL && hash == ltc_hashGenesisBlock)
  {
    LTCBlock::pindexGenesisBlock = pindexNew;
		WriteHashBestChain(iface, pindexNew->GetBlockHash());
		SetBestBlockIndex(ifaceIndex, pindexNew);
  } else {
    timing_init("SetBestChain/commit", &ts);
    ret = core_CommitBlock(this, pindexNew); 
    timing_term(LTC_COIN_IFACE, "SetBestChain/commit", &ts);
    if (!ret)
      return (false);
  }

  // New best block
  wallet->bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();

  return true;
}

bool LTCBlock::ConnectBlock(CBlockIndex* pindex)
{
  bool ok = core_ConnectBlock(this, pindex); 
  if (ok)
    ltc_RemoveOrphanBlock(pindex->GetBlockHash());
  return (ok);
}

bool LTCBlock::DisconnectBlock(CBlockIndex* pindex)
{
  return (core_DisconnectBlock(pindex, this));
}

#endif /* USE_LEVELDB_COINDB */

bool LTCBlock::CreateCheckpoint()
{ 
  return (false);
}

