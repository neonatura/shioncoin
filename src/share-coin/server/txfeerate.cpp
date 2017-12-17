

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
#include "chain.h"
#include "txmempool.h"
#include "block.h"
#include "txfeerate.h"
#include "coin_proto.h"

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


#define ROLLING_FEE_HALFLIFE (60 * 60 * 12)

static CBlockPolicyEstimator *_FeeEstimator[MAX_COIN_IFACE];



CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nBytes_)
{
  //    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
  int64_t nSize = int64_t(nBytes_);

  if (nSize > 0)
    nCoinPerK = nFeePaid * 1000 / nSize;
  else
    nCoinPerK = 0;
}

CAmount CFeeRate::GetFee(size_t nBytes_) const
{
  //    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
  int64_t nSize = int64_t(nBytes_);

  CAmount nFee = nCoinPerK * nSize / 1000;

  if (nFee == 0 && nSize != 0) {
    if (nCoinPerK > 0)
      nFee = CAmount(1);
    if (nCoinPerK < 0)
      nFee = CAmount(-1);
  }

  return nFee;
}

std::string CFeeRate::ToString() const
{
  return strprintf("%d.%08d coins/kB", 
      nCoinPerK / COIN, nCoinPerK % COIN);
}
                                                                               









void TxConfirmStats::Initialize(std::vector<double>& defaultBuckets, unsigned int maxConfirms, double _decay, std::string _dataTypeString)
{

  decay = _decay;
  dataTypeString = _dataTypeString;
  for (unsigned int i = 0; i < defaultBuckets.size(); i++) {
    buckets.push_back(defaultBuckets[i]);
    bucketMap[defaultBuckets[i]] = i;
  }

  confAvg.resize(maxConfirms);
  curBlockConf.resize(maxConfirms);
  unconfTxs.resize(maxConfirms);
  for (unsigned int i = 0; i < maxConfirms; i++) {
    confAvg[i].resize(buckets.size());
    curBlockConf[i].resize(buckets.size());
    unconfTxs[i].resize(buckets.size());
  }

  oldUnconfTxs.resize(buckets.size());
  curBlockTxCt.resize(buckets.size());
  txCtAvg.resize(buckets.size());
  curBlockVal.resize(buckets.size());
  avg.resize(buckets.size());

}

// Zero out the data for the current block
void TxConfirmStats::ClearCurrent(unsigned int nBlockHeight)
{
  for (unsigned int j = 0; j < buckets.size(); j++) {
    oldUnconfTxs[j] += unconfTxs[nBlockHeight%unconfTxs.size()][j];
    unconfTxs[nBlockHeight%unconfTxs.size()][j] = 0;
    for (unsigned int i = 0; i < curBlockConf.size(); i++)
      curBlockConf[i][j] = 0;
    curBlockTxCt[j] = 0;
    curBlockVal[j] = 0;
  }
}


void TxConfirmStats::Record(int blocksToConfirm, double val)
{
  // blocksToConfirm is 1-based
  if (blocksToConfirm < 1)
    return;
  unsigned int bucketindex = bucketMap.lower_bound(val)->second;
  for (size_t i = blocksToConfirm; i <= curBlockConf.size(); i++) {
    curBlockConf[i - 1][bucketindex]++;
  }
  curBlockTxCt[bucketindex]++;
  curBlockVal[bucketindex] += val;
}

void TxConfirmStats::UpdateMovingAverages()
{
  for (unsigned int j = 0; j < buckets.size(); j++) {
    for (unsigned int i = 0; i < confAvg.size(); i++)
      confAvg[i][j] = confAvg[i][j] * decay + curBlockConf[i][j];
    avg[j] = avg[j] * decay + curBlockVal[j];
    txCtAvg[j] = txCtAvg[j] * decay + curBlockTxCt[j];
  }
}

// returns -1 on error conditions
double TxConfirmStats::EstimateMedianVal(int confTarget, double sufficientTxVal,
    double successBreakPoint, bool requireGreater,
    unsigned int nBlockHeight)
{
  // Counters for a bucket (or range of buckets)
  double nConf = 0; // Number of tx's confirmed within the confTarget
  double totalNum = 0; // Total number of tx's that were ever confirmed
  int extraNum = 0;  // Number of tx's still in mempool for confTarget or longer

  int maxbucketindex = buckets.size() - 1;

  // requireGreater means we are looking for the lowest fee/priority such that all higher
  // values pass, so we start at maxbucketindex (highest fee) and look at successively
  // smaller buckets until we reach failure.  Otherwise, we are looking for the highest
  // fee/priority such that all lower values fail, and we go in the opposite direction.
  unsigned int startbucket = requireGreater ? maxbucketindex : 0;
  int step = requireGreater ? -1 : 1;

  // We'll combine buckets until we have enough samples.
  // The near and far variables will define the range we've combined
  // The best variables are the last range we saw which still had a high
  // enough confirmation rate to count as success.
  // The cur variables are the current range we're counting.
  unsigned int curNearBucket = startbucket;
  unsigned int bestNearBucket = startbucket;
  unsigned int curFarBucket = startbucket;
  unsigned int bestFarBucket = startbucket;

  bool foundAnswer = false;
  unsigned int bins = unconfTxs.size();

  // Start counting from highest(default) or lowest fee/pri transactions
  for (int bucket = startbucket; bucket >= 0 && bucket <= maxbucketindex; bucket += step) {
    curFarBucket = bucket;
    nConf += confAvg[confTarget - 1][bucket];
    totalNum += txCtAvg[bucket];
    for (unsigned int confct = confTarget; confct < GetMaxConfirms(); confct++)
      extraNum += unconfTxs[(nBlockHeight - confct)%bins][bucket];
    extraNum += oldUnconfTxs[bucket];
    // If we have enough transaction data points in this range of buckets,
    // we can test for success
    // (Only count the confirmed data points, so that each confirmation count
    // will be looking at the same amount of data and same bucket breaks)
    if (totalNum >= sufficientTxVal / (1 - decay)) {
      double curPct = nConf / (totalNum + extraNum);

      // Check to see if we are no longer getting confirmed at the success rate
      if (requireGreater && curPct < successBreakPoint)
        break;
      if (!requireGreater && curPct > successBreakPoint)
        break;

      // Otherwise update the cumulative stats, and the bucket variables
      // and reset the counters
      else {
        foundAnswer = true;
        nConf = 0;
        totalNum = 0;
        extraNum = 0;
        bestNearBucket = curNearBucket;
        bestFarBucket = curFarBucket;
        curNearBucket = bucket + step;
      }
    }
  }

  double median = -1;
  double txSum = 0;

  // Calculate the "average" fee of the best bucket range that met success conditions
  // Find the bucket with the median transaction and then report the average fee from that bucket
  // This is a compromise between finding the median which we can't since we don't save all tx's
  // and reporting the average which is less accurate
  unsigned int minBucket = bestNearBucket < bestFarBucket ? bestNearBucket : bestFarBucket;
  unsigned int maxBucket = bestNearBucket > bestFarBucket ? bestNearBucket : bestFarBucket;
  for (unsigned int j = minBucket; j <= maxBucket; j++) {
    txSum += txCtAvg[j];
  }
  if (foundAnswer && txSum != 0) {
    txSum = txSum / 2;
    for (unsigned int j = minBucket; j <= maxBucket; j++) {
      if (txCtAvg[j] < txSum)
        txSum -= txCtAvg[j];
      else { // we're in the right bucket
        median = avg[j] / txCtAvg[j];
        break;
      }
    }
  }

//  Debug("TxConfirmStats.EstimateMedianVal: %3d: For conf success %s %4.2f need %s %s: %s from buckets %8g - %8g  Cur Bucket stats %6.2f%%  %8.1f/(%.1f+%d mempool)\n", confTarget, requireGreater ? ">" : "<", successBreakPoint, dataTypeString.c_str(), requireGreater ? ">" : "<", median, buckets[minBucket], buckets[maxBucket], 100 * nConf / (totalNum + extraNum), nConf, totalNum, extraNum);

  return median;
}

#if 0
void TxConfirmStats::Write(CDataStream& fileout)
{

  fileout << decay;
  fileout << buckets;
  fileout << avg;
  fileout << txCtAvg;
  fileout << confAvg;
}

void TxConfirmStats::Read(CDataStream& filein)
{
  // Read data file into temporary variables and do some very basic sanity checking
  std::vector<double> fileBuckets;
  std::vector<double> fileAvg;
  std::vector<std::vector<double> > fileConfAvg;
  std::vector<double> fileTxCtAvg;
  double fileDecay;
  size_t maxConfirms;
  size_t numBuckets;

  filein >> fileDecay;
  if (fileDecay <= 0 || fileDecay >= 1)
    throw std::runtime_error("Corrupt estimates file. Decay must be between 0 and 1 (non-inclusive)");
  filein >> fileBuckets;
  numBuckets = fileBuckets.size();
  if (numBuckets <= 1 || numBuckets > 1000)
    throw std::runtime_error("Corrupt estimates file. Must have between 2 and 1000 fee/pri buckets");
  filein >> fileAvg;
  if (fileAvg.size() != numBuckets)
    throw std::runtime_error("Corrupt estimates file. Mismatch in fee/pri average bucket count");
  filein >> fileTxCtAvg;
  if (fileTxCtAvg.size() != numBuckets)
    throw std::runtime_error("Corrupt estimates file. Mismatch in tx count bucket count");
  filein >> fileConfAvg;
  maxConfirms = fileConfAvg.size();
  if (maxConfirms <= 0 || maxConfirms > 6 * 24 * 7) // one week
    throw std::runtime_error("Corrupt estimates file.  Must maintain estimates for between 1 and 1008 (one week) confirms");
  for (unsigned int i = 0; i < maxConfirms; i++) {
    if (fileConfAvg[i].size() != numBuckets)
      throw std::runtime_error("Corrupt estimates file. Mismatch in fee/pri conf average bucket count");
  }
  // Now that we've processed the entire fee estimate data file and not
  // thrown any errors, we can copy it to our data structures
  decay = fileDecay;
  buckets = fileBuckets;
  avg = fileAvg;
  confAvg = fileConfAvg;
  txCtAvg = fileTxCtAvg;
  bucketMap.clear();

  // Resize the current block variables which aren't stored in the data file
  // to match the number of confirms and buckets
  curBlockConf.resize(maxConfirms);
  for (unsigned int i = 0; i < maxConfirms; i++) {
    curBlockConf[i].resize(buckets.size());
  }
  curBlockTxCt.resize(buckets.size());
  curBlockVal.resize(buckets.size());

  unconfTxs.resize(maxConfirms);
  for (unsigned int i = 0; i < maxConfirms; i++) {
    unconfTxs[i].resize(buckets.size());
  }
  oldUnconfTxs.resize(buckets.size());

  for (unsigned int i = 0; i < buckets.size(); i++)
    bucketMap[buckets[i]] = i;

}
#endif

unsigned int TxConfirmStats::NewTx(unsigned int nBlockHeight, double val)
{
  unsigned int bucketindex = bucketMap.lower_bound(val)->second;
  unsigned int blockIndex = nBlockHeight % unconfTxs.size();
  unconfTxs[blockIndex][bucketindex]++;
  Debug("TxConfirmStats.NewTx: adding to %s", dataTypeString.c_str());
  return bucketindex;
}

void TxConfirmStats::removeTx(unsigned int entryHeight, unsigned int nBestSeenHeight, unsigned int bucketindex)
{
  //nBestSeenHeight is not updated yet for the new block
  int blocksAgo = nBestSeenHeight - entryHeight;
  if (nBestSeenHeight == 0)  // the BlockPolicyEstimator hasn't seen any blocks yet
    blocksAgo = 0;
  if (blocksAgo < 0) {
    Debug("TxConfirmStats.removeTx: Blockpolicy error, blocks ago is negative for mempool tx");
    return;  //This can't happen because we call this with our best seen height, no entries can have higher
  }

  if (blocksAgo >= (int)unconfTxs.size()) {
    if (oldUnconfTxs[bucketindex] > 0)
      oldUnconfTxs[bucketindex]--;
    else
      Debug("TxConfirmStats.removeTx: Blockpolicy error, mempool tx removed from >25 blocks,bucketIndex=%u already\n", bucketindex);
  }
  else {
    unsigned int blockIndex = entryHeight % unconfTxs.size();
    if (unconfTxs[blockIndex][bucketindex] > 0)
      unconfTxs[blockIndex][bucketindex]--;
    else
      Debug("TxConfirmStats.removeTx: Blockpolicy error, mempool tx removed from blockIndex=%u,bucketIndex=%u already\n", blockIndex, bucketindex);
  }
}

void CBlockPolicyEstimator::removeTx(uint256 hash)
{
  std::map<uint256, TxStatsInfo>::iterator pos = mapMemPoolTxs.find(hash);
  if (pos == mapMemPoolTxs.end()) {
    Debug("CBlockPolicyEstimator.removeTx: Blockpolicy error mempool tx %s not found for removeTx\n", hash.ToString().c_str());
    return;
  }
  TxConfirmStats *stats = pos->second.stats;
  unsigned int entryHeight = pos->second.blockHeight;
  unsigned int bucketIndex = pos->second.bucketIndex;

  if (stats != NULL)
    stats->removeTx(entryHeight, nBestSeenHeight, bucketIndex);
  mapMemPoolTxs.erase(hash);
}

CBlockPolicyEstimator::CBlockPolicyEstimator(int ifaceIndexIn, const CFeeRate& _minRelayFee) : nBestSeenHeight(0)
{
  CIface *iface = GetCoinByIndex(ifaceIndexIn);
  CWallet *wallet = GetWallet(iface);

  ifaceIndex = ifaceIndexIn;
  minTrackedFee = _minRelayFee < CFeeRate(MIN_FEERATE) ? CFeeRate(MIN_FEERATE) : _minRelayFee;
  std::vector<double> vfeelist;
  for (double bucketBoundary = minTrackedFee.GetFeePerK(); bucketBoundary <= MAX_FEERATE; bucketBoundary *= FEE_SPACING) {
    vfeelist.push_back(bucketBoundary);
  }
  vfeelist.push_back(INF_FEERATE(iface));
  feeStats.Initialize(vfeelist, MAX_BLOCK_CONFIRMS, DEFAULT_DECAY, "FeeRate");

  double dFreeThreshold = wallet->AllowFreeThreshold();
  minTrackedPriority = dFreeThreshold < MIN_PRIORITY ? MIN_PRIORITY : dFreeThreshold;
  std::vector<double> vprilist;
  for (double bucketBoundary = minTrackedPriority; bucketBoundary <= MAX_PRIORITY; bucketBoundary *= PRI_SPACING) {
    vprilist.push_back(bucketBoundary);
  }
  vprilist.push_back(INF_PRIORITY(iface));
  priStats.Initialize(vprilist, MAX_BLOCK_CONFIRMS, DEFAULT_DECAY, "Priority");

  feeUnlikely = CFeeRate(0);
  feeLikely = CFeeRate(INF_FEERATE(iface));
  priUnlikely = 0;
  priLikely = INF_PRIORITY(iface);
}

bool CBlockPolicyEstimator::isFeeDataPoint(const CFeeRate &fee, double pri)
{
  if ((pri < minTrackedPriority && fee >= minTrackedFee) ||
      (pri < priUnlikely && fee > feeLikely)) {
    return true;
  }
  return false;
}

bool CBlockPolicyEstimator::isPriDataPoint(const CFeeRate &fee, double pri)
{
  if ((fee < minTrackedFee && pri >= minTrackedPriority) ||
      (fee < feeUnlikely && pri > priLikely)) {
    return true;
  }
  return false;
}

void CBlockPolicyEstimator::processTransaction(CPoolTx& entry, bool fCurrentEstimate)
{
  unsigned int txHeight = entry.GetHeight();
  uint256 hash = entry.GetTx().GetHash();
  if (mapMemPoolTxs[hash].stats != NULL) {
    Debug("CBlockPolicyEstimator.processTransaction: Blockpolicy error mempool tx %s already being tracked\n", hash.GetHex().c_str());
    return;
  }

  if (txHeight < nBestSeenHeight) {
    // Ignore side chains and re-orgs; assuming they are random they don't
    // affect the estimate.  We'll potentially double count transactions in 1-block reorgs.
    return;
  }

  // Only want to be updating estimates when our blockchain is synced,
  // otherwise we'll miscalculate how many blocks its taking to get included.
  if (!fCurrentEstimate)
    return;

  if (entry.IsFlag(POOL_DEPENDENCY)) {
    // This transaction depends on other transactions in the mempool to
    // be included in a block before it will be able to be included, so
    // we shouldn't include it in our calculations
    return;
  }

  // Fees are stored and reported as coin-per-kb:
  CFeeRate feeRate(entry.GetFee(), entry.GetTxSize());

  // Want the priority of the tx at confirmation. However we don't know
  // what that will be and its too hard to continue updating it
  // so use starting priority as a proxy
  double curPri = entry.GetPriority(txHeight);
  mapMemPoolTxs[hash].blockHeight = txHeight;

  Debug("CBlockPolicyEstimator.processTransaction: Blockpolicy mempool tx %s ", hash.ToString().substr(0,10).c_str());
  // Record this as a priority estimate
  if (entry.GetFee() == 0 || isPriDataPoint(feeRate, curPri)) {
    mapMemPoolTxs[hash].stats = &priStats;
    mapMemPoolTxs[hash].bucketIndex =  priStats.NewTx(txHeight, curPri);
    Debug("CBlockPolicyEstimator.processTransaction: adding \"%s\" as a priority estimate.", hash.GetHex().c_str());
  }
  // Record this as a fee estimate
  else if (isFeeDataPoint(feeRate, curPri)) {
    mapMemPoolTxs[hash].stats = &feeStats;
    mapMemPoolTxs[hash].bucketIndex = feeStats.NewTx(txHeight, (double)feeRate.GetFeePerK());
    Debug("CBlockPolicyEstimator.processTransaction: adding \"%s\" as a fee estimate.", hash.GetHex().c_str());
  }
  else {
    Debug("CBlockPolicyEstimator.processTransaction: not adding \"%s\".", hash.GetHex().c_str());
  }

}

void CBlockPolicyEstimator::processBlockTx(unsigned int nBlockHeight, CPoolTx& entry)
{

  if (entry.IsFlag(POOL_DEPENDENCY)) {
    // This transaction depended on other transactions in the mempool to
    // be included in a block before it was able to be included, so
    // we shouldn't include it in our calculations
    return;
  }

  // How many blocks did it take for miners to include this transaction?
  // blocksToConfirm is 1-based, so a transaction included in the earliest
  // possible block has confirmation count of 1
  int blocksToConfirm = nBlockHeight - entry.GetHeight();
  if (blocksToConfirm <= 0) {
    // This can't happen because we don't process transactions from a block with a height
    // lower than our greatest seen height
    Debug("CBlockPolicyEstimator.processBlockTx: Blockpolicy error Transaction had negative blocksToConfirm.");
    return;
  }

  // Fees are stored and reported as BTC-per-kb:
  CFeeRate feeRate(entry.GetFee(), entry.GetTxSize());

  // Want the priority of the tx at confirmation.  The priority when it
  // entered the mempool could easily be very small and change quickly
  double curPri = entry.GetPriority(nBlockHeight);

  // Record this as a priority estimate
  if (entry.GetFee() == 0 || isPriDataPoint(feeRate, curPri)) {
    priStats.Record(blocksToConfirm, curPri);
  }
  // Record this as a fee estimate
  else if (isFeeDataPoint(feeRate, curPri)) {
    feeStats.Record(blocksToConfirm, (double)feeRate.GetFeePerK());
  }
}

void CBlockPolicyEstimator::processBlock(unsigned int nBlockHeight,
    std::vector<CPoolTx>& entries, bool fCurrentEstimate)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (nBlockHeight <= nBestSeenHeight) {
    // Ignore side chains and re-orgs; assuming they are random
    // they don't affect the estimate.
    // And if an attacker can re-org the chain at will, then
    // you've got much bigger problems than "attacker can influence
    // transaction fees."
    return;
  }
  nBestSeenHeight = nBlockHeight;

  // Only want to be updating estimates when our blockchain is synced,
  // otherwise we'll miscalculate how many blocks its taking to get included.
  if (!fCurrentEstimate)
    return;

  if (entries.size() == 0)
    return;

  // Update the dynamic cutoffs
  // a fee/priority is "likely" the reason your tx was included in a block if >85% of such tx's
  // were confirmed in 2 blocks and is "unlikely" if <50% were confirmed in 10 blocks
//  Debug("CBlockPolicyEstimator.processBlock: Blockpolicy recalculating dynamic cutoffs:");
  priLikely = priStats.EstimateMedianVal(2, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT, true, nBlockHeight);
  if (priLikely == -1)
    priLikely = INF_PRIORITY(iface);

  double feeLikelyEst = feeStats.EstimateMedianVal(2, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT, true, nBlockHeight);
  if (feeLikelyEst == -1)
    feeLikely = CFeeRate(INF_FEERATE(iface));
  else
    feeLikely = CFeeRate(feeLikelyEst);

  priUnlikely = priStats.EstimateMedianVal(10, SUFFICIENT_PRITXS, UNLIKELY_PCT, false, nBlockHeight);
  if (priUnlikely == -1)
    priUnlikely = 0;

  double feeUnlikelyEst = feeStats.EstimateMedianVal(10, SUFFICIENT_FEETXS, UNLIKELY_PCT, false, nBlockHeight);
  if (feeUnlikelyEst == -1)
    feeUnlikely = CFeeRate(0);
  else
    feeUnlikely = CFeeRate(feeUnlikelyEst);

  // Clear the current block states
  feeStats.ClearCurrent(nBlockHeight);
  priStats.ClearCurrent(nBlockHeight);

  // Repopulate the current block states
  for (unsigned int i = 0; i < entries.size(); i++)
    processBlockTx(nBlockHeight, entries[i]);

  // Update all exponential averages with the current block states
  feeStats.UpdateMovingAverages();
  priStats.UpdateMovingAverages();

  Debug("CBlockPolicyEstimator.processBlock: Blockpolicy after updating estimates for %u confirmed entries, new mempool map size %u", entries.size(), mapMemPoolTxs.size());
}

CFeeRate CBlockPolicyEstimator::estimateFee(int confTarget)
{
  // Return failure if trying to analyze a target we're not tracking
  // It's not possible to get reasonable estimates for confTarget of 1
  if (confTarget <= 1 || (unsigned int)confTarget > feeStats.GetMaxConfirms())
    return CFeeRate(0);

  double median = feeStats.EstimateMedianVal(confTarget, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT, true, nBestSeenHeight);

  if (median < 0)
    return CFeeRate(0);

  return CFeeRate(median);
}

CFeeRate CBlockPolicyEstimator::estimateSmartFee(int confTarget, int *answerFoundAtTarget)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTxMemPool *pool = GetTxMemPool(iface);

  if (answerFoundAtTarget)
    *answerFoundAtTarget = confTarget;
  // Return failure if trying to analyze a target we're not tracking
  if (confTarget <= 0 || (unsigned int)confTarget > feeStats.GetMaxConfirms())
    return CFeeRate(0);

  // It's not possible to get reasonable estimates for confTarget of 1
  if (confTarget == 1)
    confTarget = 2;

  double median = -1;
  while (median < 0 && (unsigned int)confTarget <= feeStats.GetMaxConfirms()) {
    median = feeStats.EstimateMedianVal(confTarget++, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT, true, nBestSeenHeight);
  }

  if (answerFoundAtTarget)
    *answerFoundAtTarget = confTarget - 1;

  // If mempool is limiting txs , return at least the min fee from the mempool
  CAmount minPoolFee = GetMinFee(pool->GetMaxQueueMem()).GetFeePerK();
  if (minPoolFee > 0 && minPoolFee > median)
    return CFeeRate(minPoolFee);

  if (median < 0)
    return CFeeRate(0);

  return CFeeRate(median);
}

double CBlockPolicyEstimator::estimatePriority(int confTarget)
{
  // Return failure if trying to analyze a target we're not tracking
  if (confTarget <= 0 || (unsigned int)confTarget > priStats.GetMaxConfirms())
    return -1;

  return priStats.EstimateMedianVal(confTarget, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT, true, nBestSeenHeight);
}

double CBlockPolicyEstimator::estimateSmartPriority(int confTarget, int *answerFoundAtTarget)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTxMemPool *pool = GetTxMemPool(iface);

  if (answerFoundAtTarget)
    *answerFoundAtTarget = confTarget;
  // Return failure if trying to analyze a target we're not tracking
  if (confTarget <= 0 || (unsigned int)confTarget > priStats.GetMaxConfirms())
    return -1;

  // If mempool is limiting txs, no priority txs are allowed
  CAmount minPoolFee = GetMinFee(pool->GetMaxQueueMem()).GetFeePerK();
  if (minPoolFee > 0)
    return INF_PRIORITY(iface);

  double median = -1;
  while (median < 0 && (unsigned int)confTarget <= priStats.GetMaxConfirms()) {
    median = priStats.EstimateMedianVal(confTarget++, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT, true, nBestSeenHeight);
  }

  if (answerFoundAtTarget)
    *answerFoundAtTarget = confTarget - 1;

  return median;
}

CFeeRate CBlockPolicyEstimator::GetMinFee(size_t sizelimit)
{

  if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0)
    return CFeeRate(rollingMinimumFeeRate);

  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTxMemPool *pool = GetTxMemPool(iface);

  int64_t time = GetTime();
  int64_t nMem = pool->GetOverflowTxSize();
  if (time > lastRollingFeeUpdate + 10) {
    double halflife = ROLLING_FEE_HALFLIFE;
    if (nMem < sizelimit / 4)
      halflife /= 4;
    else if (nMem < sizelimit / 2)
      halflife /= 2;
    rollingMinimumFeeRate = rollingMinimumFeeRate / pow(2.0, (time - lastRollingFeeUpdate) / halflife);
    lastRollingFeeUpdate = time;
    if (rollingMinimumFeeRate < minReasonableRelayFee.GetFeePerK() / 2) {
      rollingMinimumFeeRate = 0;
      return CFeeRate(0);
    }
  }

  return std::max(CFeeRate(rollingMinimumFeeRate), minReasonableRelayFee);
}


#if 0
void CBlockPolicyEstimator::Write(CDataStream& fileout)
{
  fileout << nBestSeenHeight;
  fileout << feeStats;
  fileout << priStats;
}

void CBlockPolicyEstimator::Read(CDataStream& filein)
{
  int nFileBestSeenHeight;
  filein >> nFileBestSeenHeight;
  filein >> feeStats;
  filein >> priStats;
  nBestSeenHeight = nFileBestSeenHeight;
}
#endif

FeeFilterRounder::FeeFilterRounder(const CFeeRate& minIncrementalFee)
{
  CAmount minFeeLimit = minIncrementalFee.GetFeePerK() / 2;
  feeset.insert(0);
  for (double bucketBoundary = minFeeLimit; bucketBoundary <= MAX_FEERATE; bucketBoundary *= FEE_SPACING) {
    feeset.insert(bucketBoundary);
  }
}

CAmount FeeFilterRounder::round(CAmount currentMinFee)
{
  std::set<double>::iterator it = feeset.lower_bound(currentMinFee);
  if ((it != feeset.begin() && rand() % 3 != 0) || it == feeset.end()) {
    it--;
  }
  return *it;
}



CBlockPolicyEstimator *GetFeeEstimator(CIface *iface)
{
  return (GetFeeEstimator(GetCoinIndex(iface)));
}

CBlockPolicyEstimator *GetFeeEstimator(int ifaceIndex)
{

  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);

  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled)
    return (NULL);

  if (_FeeEstimator[ifaceIndex] == NULL) {
    CFeeRate minRelayFee((int64)MIN_RELAY_TX_FEE(iface));
    _FeeEstimator[ifaceIndex] = new CBlockPolicyEstimator(ifaceIndex, minRelayFee); 
  }

  return (_FeeEstimator[ifaceIndex]);
}

