
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
#include "emc2_pool.h"
#include "emc2_block.h"
#include "emc2_txidx.h"
#include "emc2_wallet.h"
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

#include <boost/array.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>


using namespace std;
using namespace boost;


#define EMC2_MAJORITY_WINDOW 2500


uint256 emc2_hashGenesisBlock("0x4e56204bb7b8ac06f860ff1c845f03f984303b5b97eb7b42868f714611aed94b");
static CBigNum emc2_bnProofOfWorkLimit(~uint256(0) >> 20);
static const int64 emc2_nTargetTimespan = 3.5 * 24 * 60 * 60; // Einsteinium: 3.5 days
static const int64 emc2_nTargetTimespanNEW = 60;
static const int64 emc2_nTargetSpacing = 60; // Einsteinium: one minute
static const int64 emc2_nInterval = emc2_nTargetTimespan / emc2_nTargetSpacing;
static const int64 emc2_nDiffChangeTarget = 56000; // Patch effective @ block 56000



extern CScript EMC2_CHARITY_SCRIPT;


static unsigned int emc2_KimotoGravityWell(const CBlockIndex* pindexLast, const CBlockHeader *pblock, uint64 TargetBlocksSpacingSeconds, uint64 PastBlocksMin, uint64 PastBlocksMax)
{
  /* current difficulty formula - kimoto gravity well */
  const CBlockIndex *BlockLastSolved                                = pindexLast;
  const CBlockIndex *BlockReading                                = pindexLast;
  const CBlockHeader *BlockCreating                                = pblock;
  BlockCreating                                = BlockCreating;
  uint64                                PastBlocksMass                                = 0;
  int64                                PastRateActualSeconds                = 0;
  int64                                PastRateTargetSeconds                = 0;
  double                                PastRateAdjustmentRatio                = double(1);
  CBigNum                                PastDifficultyAverage;
  CBigNum                                PastDifficultyAveragePrev;
  double                                EventHorizonDeviation;
  double                                EventHorizonDeviationFast;
  double                                EventHorizonDeviationSlow;

  if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64)BlockLastSolved->nHeight < PastBlocksMin) { return emc2_bnProofOfWorkLimit.GetCompact(); }

  for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
    if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
    PastBlocksMass++;

    if (i == 1)        { PastDifficultyAverage.SetCompact(BlockReading->nBits); }
    else                { PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev; }
    PastDifficultyAveragePrev = PastDifficultyAverage;

    PastRateActualSeconds                        = BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
    PastRateTargetSeconds                        = TargetBlocksSpacingSeconds * PastBlocksMass;
    PastRateAdjustmentRatio                        = double(1);
    if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
    if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
      PastRateAdjustmentRatio                        = double(PastRateTargetSeconds) / double(PastRateActualSeconds);
    }
    EventHorizonDeviation                        = 1 + (0.7084 * pow((double(PastBlocksMass)/double(144)), -1.228));
    EventHorizonDeviationFast                = EventHorizonDeviation;
    EventHorizonDeviationSlow                = 1 / EventHorizonDeviation;

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
  if (bnNew > emc2_bnProofOfWorkLimit) { bnNew = emc2_bnProofOfWorkLimit; }

  return bnNew.GetCompact();
}

static unsigned int emc2_DigiShield(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
  int64 retargetTimespan = emc2_nTargetTimespanNEW;
  int64 retargetInterval = emc2_nTargetTimespanNEW / emc2_nTargetSpacing;

  // Only change once per interval
  if ((pindexLast->nHeight+1) % retargetInterval != 0)
  {
    return pindexLast->nBits;
  }

  // Einsteinium: This fixes an issue where a 51% attack can change difficulty at will.
  // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
  int blockstogoback = retargetInterval-1;
  if ((pindexLast->nHeight+1) != retargetInterval)
    blockstogoback = retargetInterval;

  // Go back by what we want to be 14 days worth of blocks
  const CBlockIndex* pindexFirst = pindexLast;
  for (int i = 0; pindexFirst && i < blockstogoback; i++)
    pindexFirst = pindexFirst->pprev;
  assert(pindexFirst);

  // Limit adjustment step
  int64 nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();

  CBigNum bnNew;
  bnNew.SetCompact(pindexLast->nBits);

  //DigiShield implementation - thanks to RealSolid & WDC for this code
  // amplitude filter - thanks to daft27 for this code
  nActualTimespan = retargetTimespan + (nActualTimespan - retargetTimespan)/8;
  if (nActualTimespan < (retargetTimespan - (retargetTimespan/4)) ) nActualTimespan = (retargetTimespan - (retargetTimespan/4));
  if (nActualTimespan > (retargetTimespan + (retargetTimespan/2)) ) nActualTimespan = (retargetTimespan + (retargetTimespan/2));
  // Retarget

  bnNew *= nActualTimespan;
  bnNew /= retargetTimespan;

  if (bnNew > emc2_bnProofOfWorkLimit)
    bnNew = emc2_bnProofOfWorkLimit;

  return bnNew.GetCompact();
}

/* ** BLOCK ORPHANS ** */

typedef map<uint256, uint256> orphan_map;
static orphan_map EMC2_mapOrphanBlocksByPrev;

bool emc2_IsOrphanBlock(const uint256& hash)
{
  CBlockIndex *pindex;
  EMC2Block block;
  uint256 prevHash;
  bool ok;

  if (emc2_GetOrphanPrevHash(hash, prevHash)) {
    /* already mapped. */
    return (true);
  }

#if 0
  pindex = GetBlockIndexByHash(EMC2_COIN_IFACE, hash);
  if (pindex) {
    if (GetBestHeight(EMC2_COIN_IFACE) >= pindex->nHeight &&
        block.ReadFromDisk(pindex))
      return (false); /* present in block-chain */
  }

  if (!block.ReadArchBlock(hash))
    return (false); /* no record in archive db */
  return (true);
#endif

  return (false);
}

void emc2_AddOrphanBlock(CBlock *block)
{

  EMC2_mapOrphanBlocksByPrev.insert(
      make_pair(block->hashPrevBlock, block->GetHash()));
  block->WriteArchBlock();

}

void emc2_RemoveOrphanBlock(const uint256& hash)
{
  bool found;

  orphan_map::iterator it = EMC2_mapOrphanBlocksByPrev.begin(); 
  while (it != EMC2_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found)
      break;
    ++it;
  }
  if (it != EMC2_mapOrphanBlocksByPrev.end()) {
    EMC2_mapOrphanBlocksByPrev.erase(it);
  }
  
}

bool emc2_GetOrphanPrevHash(const uint256& hash, uint256& retPrevHash)
{
  bool found;

  orphan_map::iterator it = EMC2_mapOrphanBlocksByPrev.begin(); 
  while (it != EMC2_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found) {
      retPrevHash = it->first;
      return (true);
    }
    ++it;
  }

  return (false);
}

bool emc2_GetOrphanNextHash(const uint256& hash, uint256& retNextHash)
{
  bool found;

  orphan_map::iterator it = EMC2_mapOrphanBlocksByPrev.find(hash);
  if (it != EMC2_mapOrphanBlocksByPrev.end()) {
    retNextHash = it->second;
    return (true);
  }
  return (false);
}

CBlock *emc2_GetOrphanBlock(const uint256& hash)
{
  EMC2Block block;  

  if (!block.ReadArchBlock(hash))
    return (NULL);

  return (new EMC2Block(block));
}

uint256 emc2_GetOrphanRoot(uint256 hash)
{
  uint256 prevHash;

  while (emc2_GetOrphanPrevHash(hash, prevHash)) {
    hash = prevHash;
  }
  return (hash);
}



unsigned int EMC2Block::GetNextWorkRequired(const CBlockIndex* pindexLast)
{
  int nHeight = pindexLast->nHeight + 1;
  bool fNewDifficultyProtocol = (nHeight >= emc2_nDiffChangeTarget);

  if (fNewDifficultyProtocol) {
    return emc2_DigiShield(pindexLast, this);
  }
  else {

    static const int64           BlocksTargetSpacing       = 60; // 1 minute
    unsigned int                       TimeDaySeconds                                = 60 * 60 * 24;
    int64                                PastSecondsMin                                = TimeDaySeconds * 0.25;
    int64                                PastSecondsMax                                = TimeDaySeconds * 7;
    uint64                                PastBlocksMin                                = PastSecondsMin / BlocksTargetSpacing;
    uint64                                PastBlocksMax                                = PastSecondsMax / BlocksTargetSpacing;

    return emc2_KimotoGravityWell(pindexLast, this, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax);
  }
}



#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>

static int emc2_generateMTRandom(unsigned int s, int range)
{
  boost::mt19937 gen(s);
  boost::uniform_int<> dist(1, range);
  return dist(gen);
}

#if 0
int64 emc2_GetBlockValue(int nHeight, int64 nFees)
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

  StartOffset = emc2_generateMTRandom(wseed, 35820);
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
int64 emc2_GetBlockValue(int nHeight, int64 nFees)
{
  int StartOffset;
  int WormholeStartBlock;
  int mod = nHeight % 36000;
  if (mod != 0) mod = 1;
  int epoch = (nHeight / 36000) + mod;
  long wseed = 5299860 * epoch; /* discovered: 1952, Atomic number: 99 Melting Point: 860 */

  StartOffset = emc2_generateMTRandom(wseed, 35820);
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
namespace EMC2_Checkpoints
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
    (       0, uint256("0x4e56204bb7b8ac06f860ff1c845f03f984303b5b97eb7b42868f714611aed94b"))
    (   14871, uint256("0x5dedc3dd860f008c717d69b8b00f0476de8bc6bdac8d543fb58c946f32f982fa"))
    (   36032, uint256("0xff37468190b2801f2e72eb1762ca4e53cda6c075af48343f28a32b649512e9a8"))
    (   51365, uint256("0x702b407c68091f3c97a587a8d92684666bb622f6821944424b850964b366e42c"))
    (  621000, uint256("0xe2bf6d219cff9d6d7661b7964a05bfea3128265275c3673616ae71fed7072981"))

    /* Feb '17 */
    ( 1290011, uint256("0xb71db4ec1e17678c3f9bd18b04b1fada4134ee0fc84ac21d1fbab02f2ffc181a") )
    ( 1290012, uint256("0xa19aba9e1adb9e9aefff386ec32416394bfc38fc7ff98cc5d7c2f1ab4e001775") )
    ( 1290013, uint256("0x273e013035bf614996f97cf173b0ea5b581a731cb6872fd1f8eda0b2035bf905") )
    ( 1290014, uint256("0x72aa3d5e2cee606343b9c80b89c2fcb3384131236a0aba8e2c22a9118f4f2beb") )

    /* May '17 */
    ( 1315701, uint256("0xd4e1fc80f5d483c12ed9b7358ef3e8b38ad4c89407469108670a3590db2417b1") )
    ( 1315702, uint256("0x1c69f83bcf2e113b7477c4e6f7b2545731db1c43d4d2790d37004348e7dc095a") )
    ( 1315703, uint256("0x8dc088b551c042a92c6b52e14ff83bbe8a39f2a15a66108fc66a5aac12e5721b") )
    ( 1315704, uint256("0x4ffe997b4ab52d56c04a015b0f5f81f7cb0e1aadff63c6d83a5331e06b90804d") )

    /* Dec '17 */
    ( 1410100, uint256("0xf6736ff2a7743014ab1902e442328f5c9928ce7f4edb2b4fd0130010cb4cebc4") )

    /* Nov '18 */
    ( 2137077, uint256("0xc1365bd700afde707f0f173b402b5206eea04a4cc4ea54b2660288fcb55b6292") )
    ( 2137078, uint256("0xc82d89245fb2fe6edeb96f6187a3058e058f71eb6b996a3b4f69cc981f3c74e3") )
    ( 2137079, uint256("0x90af60a1937bfa200eee99710f6c94319ab7c621dc72803c22edd2fb98544045") )
    ( 2137080, uint256("0xa1eefc654694774d00b39e7d15f3b9211e3069e616cdb8df790028d6e8ba3a71") )
    ( 2139040, uint256("0x2e4ce04696259f90e5943ef3e0ce9224c47780e466b4d45521ca6d7b21fcb0dc") )
		( 2152000, uint256("0xa31cadf1a118d78e07df6b337c4d31369033da41098e981a4773841ec2344a69") )
		( 2152015, uint256("0x3590d55a21bf5ca183ab924938abc742eaeb3cbda6f8c1d4f1e25f2f975240ce") )
		( 2152016, uint256("0x7420f5567a41bc15fd2d1946e81687541178655edd9b10ef2538f4af20c2e579") )
		( 2152656, uint256("0xfe6e9d6fbdf12a2a79f68d395521366295e9410f83afb1a7923aaef61529c436") )
		( 2152657, uint256("0x0f60bc1dc69f3d814f9eb65d20bd101ff54631a379761433b9d53a8567bc5d18") )

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

}
#endif




static int64_t emc2_GetTxWeight(const CTransaction& tx)
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(tx, SER_NETWORK, EMC2_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (EMC2_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(tx, SER_NETWORK, EMC2_PROTOCOL_VERSION);
 
  return (weight);
}

 
CBlock* emc2_CreateNewBlock(const CPubKey& rkey)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  CBlockIndex *pindexPrev = GetBestBlockIndex(iface);

  // Create new block
  //auto_ptr<CBlock> pblock(new CBlock());
  auto_ptr<EMC2Block> pblock(new EMC2Block());
  if (!pblock.get())
    return NULL;

  /* coinbase */
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vin[0].prevout.SetNull();
  txNew.vout.resize(2);
  txNew.vout[0].scriptPubKey = EMC2_CHARITY_SCRIPT;
  txNew.vout[1].scriptPubKey << rkey << OP_CHECKSIG;
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
  int64 nReward = emc2_GetBlockValue(nHeight, 0);
  int64 nCharity = nReward * 2.5 / 100;
  pblock->vtx[0].vout[0].nValue = nCharity;
  pblock->vtx[0].vout[1].nValue = (nReward - nCharity) + nFees;


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


bool emc2_CreateGenesisBlock()
{
  blkidx_t *blockIndex = GetBlockTable(EMC2_COIN_IFACE);
  bool ret;

  if (blockIndex->count(emc2_hashGenesisBlock) != 0)
    return (true); /* already created */

  /* Genesis block */
  const char* pszTimestamp = "NY Times 19/Feb/2014 North Korea Arrests Christian Missionary From Australia";
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vout.resize(1);
  txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
  txNew.vout[0].nValue = 50 * COIN;
  txNew.vout[0].scriptPubKey = EMC2_CHARITY_SCRIPT;
  EMC2Block block;
  block.vtx.push_back(txNew);
  block.hashPrevBlock = 0;
  block.hashMerkleRoot = block.BuildMerkleTree();
  block.nVersion = 1;
  block.nTime    = 1392841423;
  block.nBits    = 0x1e0ffff0;
  block.nNonce   = 3236648;


  block.print();
  if (block.GetHash() != emc2_hashGenesisBlock)
    return (false);
  if (block.hashMerkleRoot != uint256("0xb3e47e8776012ee4352acf603e6b9df005445dcba85c606697f422be3cc26f9b")) {
    return (error(SHERR_INVAL, "emc2_CreateGenesisBlock: invalid merkle root generated."));
  }

  if (!block.WriteBlock(0)) {
    return (false);
  }

  ret = block.AddToBlockIndex();
  if (!ret)
    return (false);
  (*blockIndex)[emc2_hashGenesisBlock]->nStatus |= BLOCK_HAVE_DATA;

  return (true);
}




static bool emc2_IsFromMe(CTransaction& tx)
{
  CWallet *pwallet = GetWallet(EMC2_COIN_IFACE);

  if (pwallet->IsFromMe(tx))
    return true;

  return false;
}

static void emc2_EraseFromWallets(uint256 hash)
{
  CWallet *pwallet = GetWallet(EMC2_COIN_IFACE);

  pwallet->EraseFromWallet(hash);
}


#if 0
/** minimum amount of work that could possibly be required nTime after minimum work required was nBase */
unsigned int emc2_ComputeMinWork(unsigned int nBase, int64 nTime)
{
  CBigNum bnResult;
  bnResult.SetCompact(nBase);
  while (nTime > 0 && bnResult < emc2_bnProofOfWorkLimit)
  {
    if(GetBestHeight(EMC2_COIN_IFACE)+1<emc2_nDiffChangeTarget){
      // Maximum 400% adjustment...
      bnResult *= 4;
      // ... in best-case exactly 4-times-normal target time
      nTime -= emc2_nTargetTimespan*4;
    } else {
      // Maximum 10% adjustment...
      bnResult = (bnResult * 110) / 100;
      // ... in best-case exactly 4-times-normal target time
      nTime -= emc2_nTargetTimespanNEW*4;
    }
  }
  if (bnResult > emc2_bnProofOfWorkLimit)
    bnResult = emc2_bnProofOfWorkLimit;
  return bnResult.GetCompact();
}
#endif



static bool emc2_IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned nRequired)
{
  unsigned int nFound = 0;

  for (int i = 0; i < EMC2_MAJORITY_WINDOW &&
      nFound < nRequired && pstart != NULL; i++) {
    if (pstart->nVersion >= minVersion)
      ++nFound;
    pstart = pstart->pprev;
  }

  return (nFound >= nRequired);
}



bool emc2_ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(EMC2_COIN_IFACE);
  int ifaceIndex = EMC2_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
  CBlockIndex *pindexPrev = GetBestBlockIndex(iface);
  shtime_t ts;

  // Check for duplicate
  uint256 hash = pblock->GetHash();

	if (pblock->hashPrevBlock == 0 &&
			hash != emc2_hashGenesisBlock) {
		Debug("(emc2) ProcessBlock: warning: invalid genesis block \"%s\" submitted by \"%s\".", hash.GetHex().c_str(), (pfrom?pfrom->addr.ToString().c_str():"<local>"));
		return (false);
	}


#if 0
  if (blockIndex->count(hash)) {
    return Debug("(emc2) ProcessBlock: already have block %s", hash.GetHex().c_str());
  }
  if (pindexBest && 
      pblock->hashPrevBlock != pindexBest->GetBlockHash() &&
      emc2_IsOrphanBlock(hash)) {
    return Debug("(emc2) ProcessBlock: already have block (orphan) %s", hash.ToString().c_str());
  }
#endif

  if (pblock->vtx.size() != 0 && pblock->vtx[0].wit.IsNull()) {
    if (pindexPrev && IsWitnessEnabled(iface, pindexPrev) &&
        -1 != GetWitnessCommitmentIndex(*pblock)) {
      core_UpdateUncommittedBlockStructures(iface, pblock, pindexPrev);
      Debug("(emc2) ProcessBlock: warning: received block \"%s\" with null witness commitment [height %d].", hash.GetHex().c_str(), (int)pindexPrev->nHeight);
    }
  }

  // Preliminary checks
  if (!pblock->CheckBlock()) {
    return error(SHERR_INVAL, "(emc2) ProcessBlock: failure verifying block '%s'.", hash.GetHex().c_str());
  }


#if 0
  CBlockIndex* pcheckpoint = EMC2_Checkpoints::GetLastCheckpoint(*blockIndex);
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
#if 0
    CBigNum bnNewBlock;
    bnNewBlock.SetCompact(pblock->nBits);
    CBigNum bnRequired;
    bnRequired.SetCompact(emc2_ComputeMinWork(pcheckpoint->nBits, deltaTime));
    if (bnNewBlock > bnRequired)
    {
      if (pfrom)
        pfrom->Misbehaving(100);
      return error(SHERR_INVAL, "ProcessBlock() : block with too little proof-of-work");
    }
#endif
  }
#endif

  /*
   * EMC2: If previous hash and it is unknown.
   */
  if (pblock->hashPrevBlock != 0 &&
      !blockIndex->count(pblock->hashPrevBlock)) {
    Debug("(emc2) ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.GetHex().c_str());
    if (pfrom) {
      emc2_AddOrphanBlock(pblock);
      STAT_BLOCK_ORPHAN(iface)++;

      /* request missing blocks */
      CBlockIndex *pindexBest = GetBestBlockIndex(EMC2_COIN_IFACE);
      if (pindexBest) {
        Debug("(emc2) ProcessBlocks: requesting blocks from height %d due to orphan '%s'.\n", pindexBest->nHeight, pblock->GetHash().GetHex().c_str());
        pfrom->PushGetBlocks(GetBestBlockIndex(EMC2_COIN_IFACE), emc2_GetOrphanRoot(pblock->GetHash()));
				InitServiceBlockEvent(EMC2_COIN_IFACE, pindexBest->nHeight);
      }
    }

    return true;
  }

  /* store to disk */
  timing_init("ProcessBlock/AcceptBlock", &ts);
  bool ok = pblock->AcceptBlock();
  timing_term(EMC2_COIN_IFACE, "ProcessBlock/AcceptBlock", &ts);
  if (!ok) {
    iface->net_invalid = time(NULL);
    return error(SHERR_INVAL, "ProcessBlock() : AcceptBlock FAILED");
  }

#if 0
  uint256 nextHash;
  while (emc2_GetOrphanNextHash(hash, nextHash)) {
    hash = nextHash;
    CBlock *block = emc2_GetOrphanBlock(hash);
    if (!block || !block->AcceptBlock())
      break;

    emc2_RemoveOrphanBlock(hash);
    STAT_BLOCK_ORPHAN(iface)--;
  }
#endif

  ServiceBlockEventUpdate(EMC2_COIN_IFACE);

  return true;
}

bool emc2_CheckProofOfWork(uint256 hash, unsigned int nBits, const CBigNum& bnProofOfWorkLimit)
{
  CBigNum bnTarget;
  bnTarget.SetCompact(nBits);

  /* Check range */
  if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
    return error(SHERR_INVAL, "CheckProofOfWork() : nBits below minimum work");

  /* Check proof of work matches claimed amount */
  if (hash > bnTarget.getuint256())
    return error(SHERR_INVAL, "CheckProofOfWork() : hash doesn't match nBits");

  return true;
}

/**
 * @note These are checks that are independent of context that can be verified before saving an orphan block.
 */
bool EMC2Block::CheckBlock()
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
	bool ok;

  if (vtx.empty()) {
    return (trust(-100, "(emc2) CheckBlock: block submitted with zero transactions"));
  }

  int64_t weight = GetBlockWeight(); 
  if (weight > MAX_BLOCK_WEIGHT(iface)) {
    return (trust(-100, "(emc2) CheckBlock: block weight (%d) > max (%d)", weight, MAX_BLOCK_WEIGHT(iface)));
  }

  if (!vtx[0].IsCoinBase()) {
    return (trust(-100, "(emc2) ChecKBlock: first transaction is not coin base"));
  }

	/* verify difficulty match proof-of-work hash. */
#if 0
	if (GetHash() == emc2_hashGenesisBlock) { /* genesis block */
		ok = emc2_CheckProofOfWork(GetPoWHash(), nBits, EMC2_bnGenesisProofOfWorkLimit);
	} else {
		ok = emc2_CheckProofOfWork(GetPoWHash(), nBits, EMC2_bnProofOfWorkLimit);
	}
#endif
	ok = emc2_CheckProofOfWork(GetPoWHash(), nBits, emc2_bnProofOfWorkLimit);
	if (!ok) {
    return (trust(-50, "(emc2) CheckBlock: proof of work failed"));
	}
#if 0
  // Check proof of work matches claimed amount
  if (!emc2_CheckProofOfWork(GetPoWHash(), nBits)) {
    return (trust(-50, "(emc2) CheckBlock: proof of work failed"));
  }
#endif

  // Check timestamp
  if (GetBlockTime() > GetAdjustedTime() + EMC2_MAX_DRIFT_TIME) {
    return error(SHERR_INVAL, "CheckBlock() : block timestamp too far in the future");
  }
#if 0
  if (GetBlockTime() <= pindexPrev->GetMedianTimePast()) {
    print();
    return error(SHERR_INVAL, "(emc2) AcceptBlock() : block's timestamp too far in the past.");
  }
#endif

  // First transaction must be coinbase, the rest must not be
  for (unsigned int i = 1; i < vtx.size(); i++) {
    if (vtx[i].IsCoinBase()) {
      return (trust(-100, "(emc2) CheckBlock: more than one coinbase in transaction"));
    }
  }

#if 0
  if (nVersion >= 2) {
    CBlockIndex* pindexPrev = GetBestBlockIndex(EMC2_COIN_IFACE);
    const int nHeight = pindexPrev ? (pindexPrev->nHeight + 1) : 0;
    CScript expect = CScript() << nHeight;
    if (block.vtx[0].vin[0].scriptSig.size() < expect.size() ||
        !std::equal(expect.begin(), expect.end(), block.vtx[0].vin[0].scriptSig.begin())) {
      return (trust(-10, "(emc2) CheckBlock: block \"%s\" height mismatch in coinbase", ));
    }
  }
#endif

  // Check transactions
  BOOST_FOREACH(CTransaction& tx, vtx) {
    if (!tx.CheckTransaction(EMC2_COIN_IFACE)) {
      return (trust(-1, "(emc2) ChecKBlock: transaction verification failure"));
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
    return (trust(-100, "(emc2) CheckBlock: duplicate transactions"));
  }

  unsigned int nSigOps = 0;
  BOOST_FOREACH(const CTransaction& tx, vtx)
  {
    nSigOps += tx.GetLegacySigOpCount();
  }
  if (nSigOps > MAX_BLOCK_SIGOPS(iface)) {
    return (trust(-100, "(emc2) CheckBlock: out-of-bounds SigOpCount"));
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
bool static EMC2_Reorganize(CTxDB& txdb, CBlockIndex* pindexNew, EMC2_CTxMemPool *mempool)
{
  char errbuf[1024];

 // Find the fork
  CBlockIndex* pindexBest = GetBestBlockIndex(EMC2_COIN_IFACE);
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
      sprintf(errbuf, "EMC2_Reorganize: no previous chain for '%s' height %d\n", pfork->GetBlockHash().GetHex().c_str(), pfork->nHeight); 
      return error(SHERR_INVAL, errbuf);
    }
    pfork = pfork->pprev;
  }


  // List of what to disconnect
  vector<CBlockIndex*> vDisconnect;
  for (CBlockIndex* pindex = GetBestBlockIndex(EMC2_COIN_IFACE); pindex != pfork; pindex = pindex->pprev)
    vDisconnect.push_back(pindex);

  // List of what to connect
  vector<CBlockIndex*> vConnect;
  for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
    vConnect.push_back(pindex);
  reverse(vConnect.begin(), vConnect.end());

pindexBest = GetBestBlockIndex(EMC2_COIN_IFACE);
Debug("REORGANIZE: Disconnect %i blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
Debug("REORGANIZE: Connect %i blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

  // Disconnect shorter branch
  vector<CTransaction> vResurrect;
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
  {
    EMC2Block block;
    if (!block.ReadFromDisk(pindex)) {
      if (!block.ReadArchBlock(pindex->GetBlockHash()))
        return error(SHERR_IO, "EMC2_Reorganize: Disconnect: block hash '%s' [height %d] could not be loaded.", pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight);
    }
    if (!block.DisconnectBlock(txdb, pindex))
      return error(SHERR_INVAL, "Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().c_str());

    // Queue memory transactions to resurrect
    BOOST_FOREACH(const CTransaction& tx, block.vtx)
      if (!tx.IsCoinBase())
        vResurrect.push_back(tx);
  }

  // Connect longer branch
  vector<EMC2Block> vDelete;
  for (unsigned int i = 0; i < vConnect.size(); i++)
  {
    CBlockIndex* pindex = vConnect[i];
    EMC2Block block;
    if (!block.ReadFromDisk(pindex)) {
      if (!block.ReadArchBlock(pindex->GetBlockHash()))
        return error(SHERR_IO, "EMC2_Reorganize: Connect: block hash '%s' [height %d] could not be loaded.", pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight);
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

void EMC2Block::InvalidChainFound(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  ValidIndexSet *setValid = GetValidIndexSet(EMC2_COIN_IFACE);

  pindexNew->nStatus |= BLOCK_FAILED_VALID;
  setValid->erase(pindexNew);

  error(SHERR_INVAL, "EMC2: InvalidChainFound: invalid block=%s  height=%d  work=%s  date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      pindexNew->bnChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S",
        pindexNew->GetBlockTime()).c_str());

}

#ifdef USE_LEVELDB_TXDB
bool emc2_SetBestChainInner(CBlock *block, CTxDB& txdb, CBlockIndex *pindexNew)
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
  EMC2Block::mempool.Commit(block);

  return true;
}
#endif

// notify wallets about a new best chain
void static EMC2_SetBestChain(const CBlockLocator& loc)
{
  CWallet *pwallet = GetWallet(EMC2_COIN_IFACE);

  pwallet->SetBestChain(loc);
}



#ifdef USE_LEVELDB_TXDB
bool EMC2Block::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

  Debug("EMC2Block::SetBestChain: setting best chain to block '%s' @ height %d.", pindexNew->GetBlockHash().GetHex().c_str(), pindexNew->nHeight);

  if (!txdb.TxnBegin())
    return error(SHERR_INVAL, "SetBestChain() : TxnBegin failed");

  if (EMC2Block::pindexGenesisBlock == NULL && hash == emc2_hashGenesisBlock)
  {
    txdb.WriteHashBestChain(hash);
    if (!txdb.TxnCommit())
      return error(SHERR_INVAL, "SetBestChain() : TxnCommit failed");
    EMC2Block::pindexGenesisBlock = pindexNew;
  }
  else if (hashPrevBlock == GetBestBlockChain(iface))
  {
    if (!emc2_SetBestChainInner(this, txdb, pindexNew))
      return error(SHERR_INVAL, "SetBestChain() : SetBestChainInner failed");
  }
  else
  {
/* DEBUG 060316 - reorg will try to load this block from db. */
    WriteArchBlock();

    ret = EMC2_Reorganize(txdb, pindexNew, &mempool);
    if (!ret) {
      txdb.TxnAbort();
      InvalidChainFound(pindexNew);
      return error(SHERR_INVAL, "SetBestChain() : Reorganize failed");
    }
  }

  // Update best block in wallet (so we can detect restored wallets)
  bool fIsInitialDownload = IsInitialBlockDownload(EMC2_COIN_IFACE);
  if (!fIsInitialDownload) {
    EMC2_SetBestChain(wallet->GetLocator(pindexNew));
  }

  // New best block
//  EMC2Block::hashBestChain = hash;
  SetBestBlockIndex(EMC2_COIN_IFACE, pindexNew);
//  SetBestHeight(iface, pindexNew->nHeight);
  bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();
  STAT_TX_ACCEPTS(iface)++;

  // Check the version of the last 100 blocks to see if we need to upgrade:
  if (!fIsInitialDownload)
  {
    int nUpgraded = 0;
    const CBlockIndex* pindex = GetBestBlockIndex(EMC2_COIN_IFACE);
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




bool EMC2Block::IsBestChain()
{
  CBlockIndex *pindexBest = GetBestBlockIndex(EMC2_COIN_IFACE);
  return (pindexBest && GetHash() == pindexBest->GetBlockHash());
}

bool EMC2Block::AcceptBlock()
{
  CBlockIndex* pindexPrev;

  pindexPrev = GetBlockIndexByHash(ifaceIndex, hashPrevBlock);
  if (!pindexPrev) {
    return error(SHERR_INVAL, "(emc2) AcceptBlock: prev block '%s' not found", hashPrevBlock.GetHex().c_str());
  }
  
  if (GetBlockTime() > GetAdjustedTime() + EMC2_MAX_DRIFT_TIME) {
    print();
    return error(SHERR_INVAL, "(emc2) AcceptBlock() : block's timestamp too far in the future.");

  }
  if (GetBlockTime() <= pindexPrev->GetMedianTimePast()) {
    print();
    return error(SHERR_INVAL, "(emc2) AcceptBlock() : block's timestamp too far in the past.");
  }

	/* redundant */
#if 0
  bool checkHeightMismatch = false;
  if (nVersion >= 2) {
    /* enforce BIP34 with BIP66 */
    if (emc2_IsSuperMajority(3, pindexPrev, 2375))
      checkHeightMismatch = true;
  }
  if (checkHeightMismatch) {
    CScript expect;
    unsigned int nHeight;

    nHeight = pindexPrev ? (pindexPrev->nHeight + 1) : NULL;
    expect << nHeight;

    if (vtx[0].vin[0].scriptSig.size() < expect.size() ||
        !std::equal(expect.begin(), expect.end(),
          vtx[0].vin[0].scriptSig.begin())) {
      if (originPeer) {
        unsigned char rejectCode = 0x10;
        string bad_cb_height = "bad-cb-height";
        string command = "block";
        originPeer->PushMessage("reject", command, rejectCode, bad_cb_height, GetHash());
      }
      return error(SHERR_INVAL, "emc2_AcceptBlock: submit block \"%s\" has invalid commit height (next block height is %u).", GetHash().GetHex().c_str(), nHeight);
    }
  }
#endif

  return (core_AcceptBlock(this, pindexPrev));
}

CScript EMC2Block::GetCoinbaseFlags()
{
  return (EMC2_COINBASE_FLAGS);
}

static void emc2_UpdatedTransaction(const uint256& hashTx)
{
  CWallet *pwallet = GetWallet(EMC2_COIN_IFACE);

  pwallet->UpdatedTransaction(hashTx);
}


bool EMC2Block::ReadBlock(uint64_t nHeight)
{
int ifaceIndex = EMC2_COIN_IFACE;
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
      return error(err, "EMC2Block::ReadBlock: error obtaining block-chain height %d.", nHeight);
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

bool EMC2Block::ReadArchBlock(uint256 hash)
{
  int ifaceIndex = EMC2_COIN_IFACE;
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

bool EMC2Block::IsOrphan()
{
  return (emc2_IsOrphanBlock(GetHash()));
}


#ifdef USE_LEVELDB_COINDB
bool emc2_Truncate(uint256 hash)
{
  blkidx_t *blockIndex = GetBlockTable(EMC2_COIN_IFACE);
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
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
    
  EMC2TxDB txdb; /* OPEN */

  for (nHeight = nMaxHeight; nHeight > nMinHeight; nHeight--) {
    EMC2Block block;
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
  InitServiceBlockEvent(EMC2_COIN_IFACE, cur_index->nHeight + 1);

  return (true);
}
bool EMC2Block::Truncate()
{
  return (emc2_Truncate(GetHash()));
}
#else
bool EMC2Block::Truncate()
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  return (core_Truncate(iface, GetHash()));
}
#endif

bool EMC2Block::VerifyCheckpoint(int nHeight)
{
	CWallet *wallet = GetWallet(EMC2_COIN_IFACE);
	if (!wallet || !wallet->checkpoints)
		return (true);
  return (wallet->checkpoints->CheckBlock(nHeight, GetHash()));
}

uint64_t EMC2Block::GetTotalBlocksEstimate()
{
	CWallet *wallet = GetWallet(EMC2_COIN_IFACE);
	if (!wallet || !wallet->checkpoints)
		return (0);
  return ((uint64_t)wallet->checkpoints->GetTotalBlocksEstimate());
}

bool EMC2Block::AddToBlockIndex()
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(EMC2_COIN_IFACE);
	CWallet *wallet = GetWallet(EMC2_COIN_IFACE);
  ValidIndexSet *setValid = GetValidIndexSet(EMC2_COIN_IFACE);
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
    bool ret = SetBestChain(pindexNew);
    if (!ret)
      return (false);
  } else {
    WriteArchBlock();
  }

  return true;
}



int64_t EMC2Block::GetBlockWeight()
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(*this, SER_NETWORK, EMC2_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (EMC2_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(*this, SER_NETWORK, EMC2_PROTOCOL_VERSION);

  return (weight);
}




#if 0
bool EMC2_CTxMemPool::accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs, bool* pfMissingInputs)
{
  if (pfMissingInputs)
    *pfMissingInputs = false;

  if (!tx.CheckTransaction(EMC2_COIN_IFACE))
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
      // emc2 disallow's replacement of previous tx
      error(SHERR_NOTUNIQ, "(emc2) accept: input from tx conflicts with existing pool tx.");
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
    if (!tx.AreInputsStandard(EMC2_COIN_IFACE, mapInputs) && !fTestNet)
      return error(SHERR_INVAL, "CTxMemPool::accept() : nonstandard transaction input");

    // Note: if you modify this code to accept non-standard transactions, then
    // you should add code here to check that the transaction does a
    // reasonable number of ECDSA signature verifications.

    int64 nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
    unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, EMC2_PROTOCOL_VERSION);

    // Don't accept it if it can't get into a block
    CWallet *pwallet = GetWallet(EMC2_COIN_IFACE);
    int64 nMinFee = pwallet->CalculateFee(tx);
    if (nFees < nMinFee)
      return error(SHERR_INVAL, "(emc2) CTxMemPool::accept() : not enough fees");

    // Continuously rate-limit free transactions
    // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
    // be annoying or make other's transactions take longer to confirm.
    if (nFees < EMC2_MIN_RELAY_TX_FEE)
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
        if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000 && !emc2_IsFromMe(tx))
          return error(SHERR_INVAL, "CTxMemPool::accept() : free transaction rejected by rate limiter");
        Debug("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
        dFreeCount += nSize;
      }
    }

    // Check against previous transactions
    // This is done last to help prevent CPU exhaustion denial-of-service attacks.

    if (!emc2_ConnectInputs(&tx, mapInputs, mapUnused, CDiskTxPos(0,0,0), GetBestBlockIndex(EMC2_COIN_IFACE), false, false))
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
    emc2_EraseFromWallets(ptxOld->GetHash());

  Debug("(emc2) mempool accepted %s (pool-size %u)\n",
      hash.ToString().c_str(), mapTx.size());
  return true;
}

bool EMC2_CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);

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


bool EMC2_CTxMemPool::remove(CTransaction &tx)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);

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

void EMC2_CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}
#endif



#ifdef USE_LEVELDB_COINDB

#ifndef USE_LEVELDB_TXDB
bool EMC2Block::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

  if (EMC2Block::pindexGenesisBlock == NULL && hash == emc2_hashGenesisBlock)
  {
    if (!txdb.TxnBegin())
      return error(SHERR_INVAL, "SetBestChain() : TxnBegin failed");
    txdb.WriteHashBestChain(hash);
    if (!txdb.TxnCommit())
      return error(SHERR_INVAL, "SetBestChain() : TxnCommit failed");
    EMC2Block::pindexGenesisBlock = pindexNew;
  } else {
    timing_init("SetBestChain/commit", &ts);
    ret = core_CommitBlock(txdb, this, pindexNew);
    timing_term(EMC2_COIN_IFACE, "SetBestChain/commit", &ts);
    if (!ret)
      return (false);
  }

  // Update best block in wallet (so we can detect restored wallets)
  bool fIsInitialDownload = IsInitialBlockDownload(EMC2_COIN_IFACE);
  if (!fIsInitialDownload) {
    timing_init("SetBestChain/locator", &ts);
    EMC2_SetBestChain(wallet->GetLocator(pindexNew));
    timing_term(EMC2_COIN_IFACE, "SetBestChain/locator", &ts);

#ifndef USE_LEVELDB_COINDB
    WriteHashBestChain(hash);
#endif
  }

  // New best block
  SetBestBlockIndex(EMC2_COIN_IFACE, pindexNew);
  bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();

  {
    CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
    if (iface)
      STAT_TX_ACCEPTS(iface)++;
  }

  return true;
}
#endif

bool EMC2Block::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
  char errbuf[1024];

  /* "Check it again in case a previous version let a bad block in" */
#if 1 /* DEBUG */
  if (!CheckBlock())
    return false;
#endif

  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  unsigned int nFile = EMC2_COIN_IFACE;
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
            return error(SHERR_INVAL, "EMC2Block::ConnectBlock: BIP30 enforced at height %d\n", pindex->nHeight);
      }
    }

    MapPrevTx mapInputs;
    CDiskTxPos posThisTx(EMC2_COIN_IFACE, nBlockPos, nTxPos);
    if (!tx.IsCoinBase()) {
      bool fInvalid;
      if (!tx.FetchInputs(txdb, mapQueuedChanges, this, false, mapInputs, fInvalid)) {
        sprintf(errbuf, "EMC2::ConnectBlock: FetchInputs failed for tx '%s' @ height %u\n", tx.GetHash().GetHex().c_str(), (unsigned int)nBlockPos);
        return error(SHERR_INVAL, errbuf);
      }
    }

    nSigOps += tx.GetSigOpCost(mapInputs);
    if (nSigOps > MAX_BLOCK_SIGOP_COST(iface)) {
      return (trust(-100, "(emc2) ConnectBlock: sigop cost exceeded maximum (%d > %d)", nSigOps, MAX_BLOCK_SIGOP_COST(iface)));
    }

    if (!tx.IsCoinBase()) {
      nFees += tx.GetValueIn(mapInputs)-tx.GetValueOut();

      if (!emc2_ConnectInputs(&tx, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fStrictPayToScriptHash)) {
        return error(SHERR_INVAL, "EMC2Block::ConnectBlock: error connecting inputs.");
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
    return error(SHERR_INVAL, "EMC2Block::ConnectBlock: vtx.size() == 0");
  }
#endif
  
  int64 nValue = emc2_GetBlockValue(pindex->nHeight, 0);
  if (vtx[0].GetValueOut() > (nValue + nFees)) {
    sprintf(errbuf, "EMC2_ConnectBlock: coinbase output (%d coins) higher than expected block value @ height %d (%d coins) [block %s].\n", FormatMoney(vtx[0].GetValueOut()).c_str(), pindex->nHeight, FormatMoney(nValue).c_str(), pindex->GetBlockHash().GetHex().c_str());
    return error(SHERR_INVAL, errbuf);
  }
  if (vtx[0].vout[0].scriptPubKey != EMC2_CHARITY_SCRIPT) {
    return error(SHERR_INVAL, "EMC2_ConnectBlock() : coinbase does not pay to the charity.");
  }
  int64 nCharity = nValue * 2.5 / 100; 
  if (vtx[0].vout[0].nValue < nCharity) {
    return error(SHERR_INVAL, "EMC2_ConnectBlock() : coinbase does not pay enough to the charity (actual=%llu vs required=%llu)", (unsigned long long)vtx[0].vout[0].nValue, (unsigned long long)nCharity);
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

bool EMC2Block::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
  return (core_DisconnectBlock(txdb, pindex, this));
}

bool emc2_ConnectInputs(CTransaction *tx, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fStrictPayToScriptHash=true)
{

  if (tx->IsCoinBase())
    return (true);

  // Take over previous transactions' spent pointers
  // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
  // fMiner is true when called from the internal emc2 miner
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
      for (const CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < EMC2_COINBASE_MATURITY; pindex = pindex->pprev)
        //if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
        if (pindex->nHeight == txindex.pos.nBlockPos)// && pindex->nFile == txindex.pos.nFile)
          return error(SHERR_INVAL, "ConnectInputs() : tried to spend coinbase at depth %d", pindexBlock->nHeight - pindex->nHeight);

    // Check for negative or overflow input values
    nValueIn += txPrev.vout[prevout.n].nValue;
    if (!MoneyRange(EMC2_COIN_IFACE, txPrev.vout[prevout.n].nValue) || !MoneyRange(EMC2_COIN_IFACE, nValueIn))
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
      return error(SHERR_INVAL, "(emc2) ConnectInputs: %s prev tx (%s) already used at %s", tx->GetHash().GetHex().c_str(), txPrev.GetHash().GetHex().c_str(), txindex.vSpent[prevout.n].ToString().c_str());
    }

    // Skip ECDSA signature verification when connecting blocks (fBlock=true)
    // before the last blockchain checkpoint. This is safe because block merkle hashes are
    // still computed and checked, and any change will be caught at the next checkpoint.
		CWallet *wallet = GetWallet(EMC2_COIN_IFACE);
		int nTotal = 0;
		if (wallet && wallet->checkpoints) nTotal = wallet->checkpoints->GetTotalBlocksEstimate();
    if (!(fBlock && (GetBestHeight(EMC2_COIN_IFACE) < nTotal))) {
      // Verify signature
      if (!VerifySignature(EMC2_COIN_IFACE, txPrev, *tx, i, fStrictPayToScriptHash, 0))
      {
        // only during transition phase for P2SH: do not invoke anti-DoS code for
        // potentially old clients relaying bad P2SH transactions
        if (fStrictPayToScriptHash && VerifySignature(EMC2_COIN_IFACE, txPrev, *tx, i, false, 0))
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
  if (!MoneyRange(EMC2_COIN_IFACE, nFees))
    return error(SHERR_INVAL, "ConnectInputs() : nFees out of range");


  return true;
}

#else /* USE_LEVELDB_COINDB */

bool EMC2Block::SetBestChain(CBlockIndex* pindexNew)
{
  CWallet *wallet = GetWallet(EMC2_COIN_IFACE);
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

  if (EMC2Block::pindexGenesisBlock == NULL && hash == emc2_hashGenesisBlock)
  {
    EMC2Block::pindexGenesisBlock = pindexNew;
		WriteHashBestChain(iface, pindexNew->GetBlockHash());
		SetBestBlockIndex(ifaceIndex, pindexNew);
  } else {
    timing_init("SetBestChain/commit", &ts);
    ret = core_CommitBlock(this, pindexNew); 
    timing_term(EMC2_COIN_IFACE, "SetBestChain/commit", &ts);
    if (!ret)
      return (false);
  }

  // New best block
  wallet->bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();

  return true;
}

bool EMC2Block::ConnectBlock(CBlockIndex* pindex)
{
  bool ok = core_ConnectBlock(this, pindex); 
  if (ok)
    emc2_RemoveOrphanBlock(pindex->GetBlockHash());
  return (ok);
}

bool EMC2Block::DisconnectBlock(CBlockIndex* pindex)
{
  return (core_DisconnectBlock(pindex, this));
}

#endif /* USE_LEVELDB_COINDB */

bool EMC2Block::CreateCheckpoint()
{ 
  return (false);
}

