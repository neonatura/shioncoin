
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
#include "block.h"
#include "wallet.h"
#include "txmempool.h"
#include "txsignature.h"
#include "txfeerate.h"

#include <vector>

using namespace std;


typedef vector<unsigned char> valtype;


bool CPool::VerifyTx(CTransaction& tx)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CBlockIndex *pindexPrev;
  bool ok;

  if (tx.IsCoinBase()) {
    return (error(SHERR_INVAL, "CPool.AddTx: rejecting coinbase transaction."));
  }

  if (!tx.CheckTransaction(ifaceIndex)) {
    return (error(SHERR_INVAL, "CPool.AddTx: rejecting transaction after integrity verification failure."));
  }

  if ((int64)tx.nLockTime > std::numeric_limits<int>::max()) {
    return error(SHERR_INVAL, "CPool.VerifyTx: nLockTime exceeds 2038 limit.");
  }

  if (iface) {
    pindexPrev = GetBestBlockIndex(iface);
    if (pindexPrev) {
      bool fWitnessEnabled = IsWitnessEnabled(iface, pindexPrev);
      if (!fWitnessEnabled && !tx.wit.IsNull()) {
        return (error(SHERR_INVAL, "CPool.VerifyTx: warning: rejecting witness transaction due to witness not being enabled."));
      }
    }
  }

  const uint256 hash = tx.GetHash();
  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    const COutPoint& prevout = tx.vin[i].prevout;
    if (prevout.hash == hash) {
      return (error(SHERR_INVAL, "CPool.VerifyTx: rejecting tx \"%s\": an input has the same hash as the transaction.", hash.GetHex().c_str()));
    }
  }

  return (true);
}

bool CPool::AddTx(CTransaction& tx, CNode *pfrom)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  uint256 hash = tx.GetHash();
  bool ok;

  if (inval.count(hash))
    return (false); /* known invalid */

  /* do not re-process mempool transactions */
  if (HaveTx(hash))
    return (false); /* dup */

  /* verify this tx is not in block-chain */
  if (VerifyTxHash(iface, hash))
    return (false); /* dup */

  /* verify core integrity of transaction */
  if (!VerifyTx(tx))
    return (false);

  CPoolTx ptx(tx);
  if (pfrom == NULL)
    ptx.setLocal(true);

  /* retrieve all input transactions */
  bool hasInputs = FillInputs(ptx);

  /* hard limits */
  CalculateLimits(ptx);
  if (!VerifyLimits(ptx)) {
    AddInvalTx(ptx);
    return (false); /* hard limit failure. */
  }

#if 0
  /* redudant check -- happens again before commit */
  if (AreInputsSpent(ptx)) {
    AddInvalTx(ptx);
    return (error(SHERR_INVAL, "CPool.AddTx: rejecting tx \"%s\" with spent input(s).", ptx.GetHash().GetHex().c_str()));
  }
#endif

  /* mark height at which tx entered pool */
  ptx.nHeight = GetBestHeight(iface);

  if (!hasInputs) { /* orphan tx */
    ptx.SetFlag(POOL_NO_INPUT);
    AddPendingTx(ptx);

    /* return as invalid */
    return (false);
  }

  /* individual coin standards */
  if (!VerifyStandards(ptx)) {
    AddInvalTx(ptx);
    return (false);
  }

  /* verify fee */
  CalculateFee(ptx);
  bool fAllowFree = IsFreeRelay(ptx.GetTx(), ptx.GetInputs());
  if (!fAllowFree && ptx.nFee < MIN_RELAY_TX_FEE(iface)) {
    /* invalid fee rate */
    AddInvalTx(ptx);
    return (false);
  }

#if 0
  /* dependent tx's initially start in overflow. */
  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    COutPoint prevout = tx.vin[i].prevout;
    if (exists(prevout.hash)) {
      Debug("CPool.FillInputs: info: tx \"%s\" has input \"%s\" in mempool.", ptx.GetHash().GetHex().c_str(), prevout.hash.GetHex().c_str());
      /* wait until mempool tx is processed. */
      ptx.SetFlag(POOL_DEPENDENCY);
      return (AddOverflowTx(ptx));
    }
  }
#endif

  if (!ptx.IsLocal() && !VerifySoftLimits(ptx)) {
    /* initial breach of soft limits [non-local] starts in overflow queue. */
    Debug("CPool.FillInputs: info: tx \"%s\" breached soft limits.", ptx.GetHash().GetHex().c_str());
    ptx.SetFlag(POOL_SOFT_LIMIT);
    return (AddOverflowTx(ptx));
  }

  /* check for preferred minimum fee on initial pool acceptance */
  if (!fAllowFree) {
    int64 nSoftFee = CalculateSoftFee(ptx.GetTx());
    if (ptx.nFee < nSoftFee) {
      Debug("CPool.FillInputs: info: tx \"%s\" has insufficient soft fee.", ptx.GetHash().GetHex().c_str());

      /* meets minimum requirements -- process as low priority */
      ptx.SetFlag(POOL_FEE_LOW);
      return (AddOverflowTx(ptx));
    }
  }

  if (!tx.IsFinal(ifaceIndex)) {
    /* wait until transaction is finalized. */
    Debug("CPool.AddActiveTx: tx \"%s\" is not finalized.", ptx.GetHash().GetHex().c_str());
    ptx.SetFlag(POOL_NOT_FINAL);

/* DEBUG: TODO: special case -- RelayTransaction so others may queue it as pending. */
    return (AddOverflowTx(ptx));
  }
  ptx.UnsetFlag(POOL_NOT_FINAL);

  PurgeActiveTx();

  return (AddActiveTx(ptx));
}

#if 0
bool CPool::Verify(CPoolTx& ptx)
{

  ptx.CalculateLimits();
  if (!ptx.VerifyLimits(tx))
    return (false); /* hard limit failure. */

  if (!VerifyStandards(tx)) {
    AddInvalTx(ptx);
    return (false);
  }

  if (!VerifyConflict(ptx)) {
    AddInvalTx(ptx);
    return (false); /* referencing already pool'd inputs */
  }

  return (true);
}
#endif

void CPool::CalculateFee(CPoolTx& ptx)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  CTransaction& tx = ptx.GetTx();
  int64 nCredit;

  nCredit = tx.GetValueIn(ptx.GetInputs());

  /* calculate minimum fee */
  //nMinFee = wallet->GetFee(ptx.GetTx(), nCredit, nBytes, dPriority);
  ptx.nMinFee = wallet->CalculateFee(tx);

  /* calculate fee and priority */
  ptx.nFee = nCredit - tx.GetValueOut();
  ptx.dPriority = wallet->GetPriority(tx, ptx.GetInputs());
  ptx.dFeePriority = sqrt(ptx.dPriority) * (double)ptx.nFee; 

}

bool CPool::VerifyStandards(CPoolTx& ptx)
{
  CTransaction& wtx = ptx.GetTx();

  /* verify outputs */
  BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
    vector<valtype> vSolutions;
    txnouttype whichType;

    /* ensure input script is valid */
    if (!Solver(txout.scriptPubKey, whichType, vSolutions)) { 
      return (error(SHERR_INVAL, "CPool.AddTx: rejecting transaction with unresolvable output coin address."));
    }
    if (whichType == TX_NONSTANDARD) {
      return (error(SHERR_INVAL, "CPool.AddTx: rejecting transaction with unknown output coin script."));
    }
  }

  /* verify inputs */
  if (!wtx.IsCoinBase()) {
#if 0
    if (!FillInputs(ptx))
      return false;
#endif

    for (unsigned int i = 0; i < wtx.vin.size(); i++) {
      CTxOut prev;
#if 0
      if (!ptx.GetOutput(wtx.vin[i], prev))
        return false;
#endif
      if (!ptx.GetOutput(wtx.vin[i], prev))
        continue;

      /* ensure output script is valid */
      vector<vector<unsigned char> > vSolutions;
      txnouttype whichType;
      const CScript& prevScript = prev.scriptPubKey;
      if (!Solver(prevScript, whichType, vSolutions))
        return false;
      if (whichType == TX_NONSTANDARD) {
        return (error(SHERR_INVAL, "CPool.AddTx: rejecting transaction with unknown input coin script."));
      }

      /* evaluate signature */
      vector<vector<unsigned char> > stack;
      CSignature sig(ifaceIndex, (CTransaction *)&wtx, i);
      if (!EvalScript(sig, stack, wtx.vin[i].scriptSig, SIGVERSION_BASE, 0)) {
        return (error(SHERR_INVAL, "CPool.VerifyStandards: error evaluating input script."));
      }
    }

    int64 nInputValue = wtx.GetValueIn(ptx.GetInputs());
    int64 nOutputValue = wtx.GetValueOut();
    if (nInputValue < nOutputValue) {
      return (error(SHERR_INVAL, "CPool.VerifyStandards: input value (%f) is lower than output value (%f).", (double)nInputValue/COIN, (double)nOutputValue/COIN));
    }
  }

  if (!VerifyCoinStandards(ptx.GetTx(), ptx.GetInputs()))
    return (error(SHERR_INVAL, "CPool.VerifyStandards: a component of the transaction is not standard."));

  return (true);
}

#if 0
bool VerifyConflict(CPoolTx& ptx)
{
  map<COutPoint, CInPoint> mapNextTx;

  BOOST_FOREACH(PAIRTYPE(uint256, CTransaction tx)& item, active) {
    for (unsigned int i = 0; i < tx.vin.size(); i++)
      mapNextTx[tx.vin[i].prevout] = CInPoint(&tx, i);
  }

  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    COutPoint out = tx.vin[i].prevout;
    if (mapNextTx.count(outpoint))
      return (false); /* disallow replacement */
  }

  return (true);
}
#endif
bool CPool::ResolveConflicts(CPoolTx& ptx)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  bool ok;

  vector<CTransaction> vRemove;
  for (pool_map::iterator it = active.begin(); it != active.end(); ++it) {
    CPoolTx& a_ptx = it->second;
    for (unsigned int i = 0; i < ptx.tx.vin.size(); i++) {
      COutPoint out = ptx.GetTx().vin[i].prevout;
      if (a_ptx.mapNextTx.count(out) != 0) {
        /* found conflict */

        if (a_ptx.GetTx().IsNewerThan(ptx.GetTx())) {
          return (error(SHERR_INVAL, "CPool.ResolveConflicts: warning: rejecting submitted transaction with older time-stamp (%s).", ptx.GetHash()));
        }

        if (ifaceIndex == TEST_COIN_IFACE || ifaceIndex == SHC_COIN_IFACE) {
          if (ptx.GetTx().isFlag(CTransaction::TXF_CHANNEL) ||
              a_ptx.GetTx().isFlag(CTransaction::TXF_CHANNEL)) {
            return (error(SHERR_INVAL, "CPool.ResolveConflicts: warning: rejecting submitted duplicate channel transaction.")); 
          }
        }

        /* replace */
        vRemove.push_back(a_ptx.GetTx());
        break;
      }
    }
  }
  BOOST_FOREACH(CTransaction& tx, vRemove) {
    uint256 tx_hash = tx.GetHash();

    /* remove tx from mempool. */
    if (!RemoveTx(tx)) {
      error(SHERR_INVAL, "CPool.ResolveConflicts: error removing conflicting transaction \"%s\".", tx_hash.GetHex().c_str()); 
    }

    /* abandon invalidated wallet tx [redundant] . */
    wallet->EraseFromWallet(tx_hash);

    CIface *iface = GetCoinByIndex(ifaceIndex);
    Debug("(%s) CPool.ResolveConflict: removed tx \"%s\" from pool due to conflicting input transaction.", iface->name, tx_hash.GetHex().c_str()); 
  }

  /* create mapping for sequential checks */
  CTransaction& tx = ptx.GetTx();
  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    ptx.mapNextTx[tx.vin[i].prevout] = CInPoint(&tx, i);
  }

  return (true);
}

bool CPool::RemoveTx(const uint256& hash)
{

  if (active.count(hash)) {
    CPoolTx& ptx = active[hash];
    revert(ptx.GetTx());

    active.erase(hash);

    CIface *iface = GetCoinByIndex(ifaceIndex);
    if (iface)
      STAT_TX_ACCEPTS(iface)--;

    CBlockPolicyEstimator *fee = GetFeeEstimator(iface);
    if (fee) {
      fee->removeTx(hash);
    }

    return (true);
  }

  if (pending.count(hash)) {
    pending.erase(hash);
    return (true);
  }
  if (overflow.count(hash)) {
    overflow.erase(hash);
    return (true);
  } 
  if (stale.count(hash)) {
    stale.erase(hash);
    return (true);
  } 
  if (inval.find(hash) != inval.end()) {
    inval.erase(hash);
    return (true);
  }

  return (false);
}

void CPool::CalculateLimits(CPoolTx& ptx)
{
  CWallet *wallet = GetWallet(ifaceIndex);

  ptx.nWeight = wallet->GetTransactionWeight(ptx.GetTx());
  ptx.nSigOpCost = ptx.GetTx().GetSigOpCost(ptx.GetInputs());
  ptx.nTxSize = wallet->GetVirtualTransactionSize(ptx.nWeight, ptx.nSigOpCost);


}

bool CPool::VerifyLimits(CPoolTx& ptx)
{
  int64_t nMaxWeight = GetMaxWeight();
  int64_t nMaxCost = GetMaxSigOpCost();

  if (ptx.nWeight > nMaxWeight)
    return (false);

  if (ptx.nSigOpCost > nMaxCost)
    return (false);

  return (true);
}


bool CPool::VerifySoftLimits(CPoolTx& ptx)
{
  int64_t nMaxWeight = GetSoftWeight();
  int64_t nMaxCost = GetSoftSigOpCost();

  if (ptx.nWeight > nMaxWeight)
    return (false);

  if (ptx.nSigOpCost > nMaxCost)
    return (false);

  return (true);
}

int64_t CPool::GetMaxWeight()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  return (MAX_BLOCK_WEIGHT(iface) - 1);
}

int64_t CPool::GetMaxSigOpCost()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  return (MAX_BLOCK_SIGOP_COST(iface) - 1);
}

bool CPool::FillInputs(CPoolTx& ptx)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTransaction& tx = ptx.GetTx();
  bool ok;


  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    COutPoint prevout = tx.vin[i].prevout;
    if (ptx.GetInputs().count(prevout.hash))
      continue; // dup

    CTransaction prevTx;

    prevTx.SetNull();

    ok = GetTx(prevout.hash, prevTx); /* check mempool */
    if (!ok) 
      ok = GetTransaction(iface, prevout.hash, prevTx, NULL);
    if (!ok) {
      /* check for orphan */
      if (pending.count(prevout.hash)) {
        CPoolTx& orphan = pending[prevout.hash];
        /* verify whether inputs are now correct */
        ok = RefillInputs(orphan);
        if (ok) {
          /* ensure integrity of inputs */
          ok = VerifyStandards(orphan);
          if (ok) {
            /* re-accept tx into active pool. */
            CalculateFee(ptx);
            ok = AddActiveTx(orphan);
          }
        }
        if (ok) {
          /* orphan is now an active pool tx */
          prevTx = orphan.GetTx();
          pending.erase(orphan.GetHash());
          Debug("CPool.FillInputs: recovered orphan \"%s\".", orphan.GetHash().GetHex().c_str());
        }
      }
    }
    if (!ok) {
      return (error(SHERR_INVAL, "CPool.FillInputs: unknown input \"%s\" for tx \"%s\".", prevout.hash.GetHex().c_str(), tx.GetHash().GetHex().c_str()));
    }

    ptx.AddInput(prevTx);
  }

  return (true);
}

bool CPool::RefillInputs(CPoolTx& ptx)
{
  bool ok;

  ptx.ClearInputs();

  ok = FillInputs(ptx);
  if (ok)
    CalculateFee(ptx);

  return (ok);
}



/**
 * @note This function permits for tx's with inner-pool dependencies.
 */
bool CPool::AddActiveTx(CPoolTx& ptx)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  const uint256& hash = ptx.GetHash();
  CTransaction& tx = ptx.GetTx();

  if (active.count(hash) != 0)
    return (true); /* false negative */


  /* check if their is room */
  if (GetActiveWeight() + ptx.GetWeight() > GetMaxWeight()) {
    /* tx would exceed block weight, send to overflow */
    Debug("CPool.AddActiveTx: tx \"%s\" would exceed block weight.", ptx.GetHash().GetHex().c_str());
    return (AddOverflowTx(ptx));
  }

#if 0
/* todo: remove this section */
  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    COutPoint prevout = tx.vin[i].prevout;
    if (exists(prevout.hash)) {
      /* bypass issue - wait until dependant tx is cleared. */
      return (AddOverflowTx(ptx));
    }
  }
#endif

  /* for case when overflow is transitioning to active queue. */
  overflow.erase(ptx.GetHash());
  /* for case when stale is transitioning to active queue. */
  stale.erase(ptx.GetHash());

  if (!FillInputs(ptx)) {
    ptx.SetFlag(POOL_NO_INPUT);
    AddPendingTx(ptx);
    return (error(SHERR_INVAL, "CPool.AddActiveTx: tx \"%s\" has unknown inputs specified -- marking as orphan.", ptx.GetHash().GetHex().c_str()));
  }
#if 0
  /* redundant check to ensure inputs are valid. */
  if (!RefillInputs(ptx)) {
    ptx.SetFlag(POOL_NO_INPUT);
    AddPendingTx(ptx);
    return (error(SHERR_INVAL, "CPool.AddActiveTx: tx \"%s\" has unknown inputs specified -- marking as orphan.", ptx.GetHash().GetHex().c_str()));
  }
#endif

  /* remove active transactions referencing same inputs */
  if (!ResolveConflicts(ptx)) {
    AddInvalTx(ptx);
    return (false);
  }

  if (AreInputsSpent(ptx)) {
    AddInvalTx(ptx);
    return (error(SHERR_INVAL, "CPool.AddActiveTx: rejecting tx \"%s\" with spent input(s).", ptx.GetHash().GetHex().c_str()));
  }

//  if (!ptx.IsLocal()) { /* todo: prevents recursive mutex lock on txdb, this is redudant txdb inputs check when called via core_CommitBlock() */
    if (!AcceptTx(ptx.tx)) {
      AddInvalTx(ptx);
      return (error(SHERR_INVAL, "CPool.AddTx: error accepting transaction into memory pool."));
    }
//  }

  active[hash] = ptx;
  STAT_TX_ACCEPTS(iface)++;

  CBlockPolicyEstimator *fee = GetFeeEstimator(iface);
  if (fee) {
    fee->processTransaction(ptx, true);
  }

  Debug("CPool.AddActiveTx: added tx \"%s\" to active queue.",
      ptx.GetHash().GetHex().c_str()); 

  return (true);
}

bool CPool::AddOverflowTx(CPoolTx& ptx)
{
  const uint256& hash = ptx.GetHash();

  if (overflow.count(hash) != 0)
    return (true); /* redundant */

  /* check size breach */
  if (GetOverflowTxSize() + ptx.GetTxSize() > GetMaxQueueMem()) {
    /* reach'd the limit */
    return (error(SHERR_INVAL, "CPool.AddOverflowTx: rejecting tx \"%s\" <%d bytes> due to memory queue limits [max %-3.3fm].", ptx.GetHash().GetHex().c_str(), (int)ptx.GetTxSize(), (double)GetMaxQueueMem()/1000000));
  }

  overflow[hash] = ptx;
  Debug("CPool.AddOverflowTx: added tx \"%s\" to overflow queue.",
      ptx.GetHash().GetHex().c_str()); 

  return (true);
}

bool CPool::AddStaleTx(CPoolTx& ptx)
{
  const uint256& hash = ptx.GetHash();

  if (stale.count(hash) != 0)
    return (true); /* redundant */

  /* check size breach */
  if (GetStaleTxSize() + ptx.GetTxSize() > GetMaxQueueMem()) {
    /* reach'd the limit */
    return (error(SHERR_INVAL, "CPool.AddStaleTx: rejecting tx \"%s\" <%d bytes> due to memory queue limits [max %-3.3fm].", ptx.GetHash().GetHex().c_str(), (int)ptx.GetTxSize(), (double)GetMaxQueueMem()/1000000));
  }

  stale[hash] = ptx;
  Debug("CPool.AddStaleTx: added tx \"%s\" to stale queue.",
      ptx.GetHash().GetHex().c_str()); 

  return (true);
}

bool CPool::AddPendingTx(CPoolTx& ptx)
{
  const uint256& hash = ptx.GetHash();

  if (pending.count(hash) != 0)
    return (true); /* redundant */

  PurgePendingTx();

  Debug("CPool.AddPendingTx: added tx \"%s\" to orphan queue.",
      ptx.GetHash().GetHex().c_str()); 
  
  pending[hash] = ptx;
  return (true);
}

void CPool::AddInvalTx(CPoolTx& ptx)
{
  uint256 hash = ptx.GetHash();
  if (inval.count(hash) == 0)
    inval.insert(inval.begin(), hash);

  while (inval.size() > 1000)
    inval.erase(inval.begin());
}

void CPool::PurgeActiveTx()
{
  vector<CPoolTx> vRemove;

  if (active.size() == 0) {
    if (stale.size() != 0) {
      /* bring back one stale */
      pool_map::iterator it = stale.begin();
      std::advance(it, (shrand() % stale.size()));
      if (it != stale.end()) {
        CPoolTx& o_ptx = it->second;
        AddActiveTx(o_ptx);
      }
    }
    
    /* no active tx's to process. */
    return; 
  }

  for (pool_map::iterator it = active.begin(); it != active.end(); ++it) {
    CPoolTx& o_ptx = it->second;

#if 0
    if (o_ptx.IsLocal())
      continue;
#endif

    if (!o_ptx.IsExpired(MAX_MEMPOOL_ACTIVE_SPAN)) /* 6hr */
      continue;

    vRemove.insert(vRemove.begin(), o_ptx);

    Debug("CPool.ActiveTx: expired tx \"%s\" from active queue.",
        o_ptx.GetHash().GetHex().c_str()); 

    break; /* due to unacceptwallet cpu usage.. do one at a time. */
  }

  /* remove from active queue */
  BOOST_FOREACH(CPoolTx& ptx, vRemove) {
    RemoveTx(ptx.GetHash());
  }

  /* add to stale queue */
  BOOST_FOREACH(CPoolTx& ptx, vRemove) {
    AddStaleTx(ptx);
  }
  
}

void CPool::PurgeOverflowTx()
{
  vector<uint256> vRemove;

  if (overflow.size() == 0)
    return; /* all done */

  /* erase stale entries */
  for (pool_map::iterator it = overflow.begin(); it != overflow.end(); ++it) {
    CPoolTx& o_ptx = it->second;

    if (o_ptx.IsLocal())
      continue;

    if (!o_ptx.IsExpired(MAX_MEMPOOL_OVERFLOW_SPAN))
      continue;

    vRemove.insert(vRemove.begin(), o_ptx.GetHash());
  }
  BOOST_FOREACH(uint256& hash, vRemove) {
    Debug("CPool.PurgeOverflowTx: expired tx \"%s\" from overflow queue.",
        hash.GetHex().c_str()); 
    overflow.erase(hash);
  }

  /* add in overflow items based on priority */
  int64 nWeight = GetActiveWeight();

  vector<CPoolTx> vPoolTx;
  BOOST_FOREACH(PAIRTYPE(const uint256, CPoolTx)& item, overflow) {
    CPoolTx& ptx = item.second;
    if (ptx.GetTx().IsFinal(ifaceIndex))
      vPoolTx.push_back(ptx);
  }
  sort(vPoolTx.begin(), vPoolTx.end());

  BOOST_FOREACH(CPoolTx& ptx, vPoolTx) {
    uint256 hash(ptx.GetHash());
    if (overflow.count(hash) == 0)
      continue; /* erro r*/

    CPoolTx& r_ptx = overflow[hash];
    int64 nTxWeight = r_ptx.GetWeight();
    if ((nWeight + nTxWeight) > GetMaxWeight())
      continue;

    CPoolTx c_ptx = r_ptx;
    AddActiveTx(c_ptx);
    if (active.count(hash) != 0)
      nWeight += nTxWeight;
  }

}

void CPool::PurgePendingTx()
{
  vector<uint256> vRemove;
//  vector<CPoolTx> vPoolTx;

  if (pending.size() == 0)
    return; /* all done */

  /* erase stale entries */
  BOOST_FOREACH(PAIRTYPE(const uint256, CPoolTx)& item, pending) {
    CPoolTx& p_ptx = item.second;
    if (p_ptx.IsExpired(MAX_MEMPOOL_PENDING_SPAN)) {
      vRemove.insert(vRemove.begin(), p_ptx.GetHash());
      continue;
    }

//    vPoolTx.insert(vPoolTx.end(), item.second);
  }
  BOOST_FOREACH(uint256& hash, vRemove) {
    pending.erase(hash);
  }
 

#if 0
  sort(vPoolTx.begin(), vPoolTx.end());

  int64 nWeight = GetActiveWeight();
  BOOST_FOREACH(CPoolTx& ptx, vPoolTx) {
    nWeight += ptx.nWeight;
    if (nWeight > GetMaxWeight())
      break;

    if (!RefillInputs(ptx)) {
      continue;
    }

    if (VerifyTx(ptx)) {
      bool ok = AddActiveTx(ptx);
      if (ok)
        pending.remove(ptx.GetHash());
    }
  }
#endif


}

int CPool::GetActiveTotal()
{
  return (active.size());
}

vector<CTransaction> CPool::GetActiveTx()
{
  vector<CPoolTx> vPoolTx;
  vector<uint256> vRemove;
  vector<CTransaction> vTx;

  for (pool_map::iterator it = active.begin(); it != active.end(); ++it) {
    CPoolTx& ptx = it->second;
#if 0
    if (AreInputsSpent(ptx)) {
      vRemove.push_back(ptx.GetHash());
      continue;
    }
#endif
    vPoolTx.push_back(ptx);
  }
  sort(vPoolTx.begin(), vPoolTx.end()); 

  BOOST_FOREACH(CPoolTx& ptx, vPoolTx) {
    CTransaction& tx = ptx.GetTx();
    vTx.insert(vTx.end(), tx);
  }
  BOOST_FOREACH(uint256& hash, vRemove) {
    RemoveTx(hash);
  }

  return (vTx);
}

vector<uint256> CPool::GetActiveHash()
{
  vector<CPoolTx> vPoolTx;
  vector<uint256> vHash;

  for (pool_map::iterator it = active.begin(); it != active.end(); ++it) {
    const uint256& hash = it->first;
    vHash.push_back(hash);
  }

  return (vHash);
}


bool CPool::PopTx(const CTransaction& tx, CPoolTx& ptx)
{
  const uint256& hash = tx.GetHash();

  if (tx.IsCoinBase())
    return (false);

  if (!exists(hash))
    return (false);

  if (pending.count(hash)) {
    /* orphans */
    ptx = pending[hash];
  }
  if (overflow.count(hash)) {
    /* to-be-accepted */
    ptx = overflow[hash];
  }
  if (active.count(hash)) {
    /* current accepted */
    ptx = active[hash];
  } 

  /* calculations only relevant until after the pool tx is accepted. */
  ptx.CalculateModifiedSize();
  CalculateDependencyMetric(ptx);

#if 0
    if (!ptx) {
      static CPoolTx t_ptx;

      /* create temp pool tx */
      t_ptx = CPoolTx(tx);

      /* calculate the pool tx metrics */
      FillInputs(t_ptx);
      CalculateLimits(t_ptx);
      CalculateFee(t_ptx);
      t_ptx.nHeight = (GetBestHeight(iface) - 1); /* ~ introduced last block */

      ptx = &t_ptx; 
    }
#endif

  inval.erase(hash);
  pending.erase(hash);
  overflow.erase(hash);
  active.erase(hash);

  return (true);
}

static void cpool_RemoveTxWithInput(CPool *pool, const CTxIn& txin)
{
  vector<uint256> vRemove;

  for (pool_map::iterator it = pool->active.begin(); it != pool->active.end(); ++it) {
    CPoolTx& a_ptx = it->second;
    BOOST_FOREACH(const CTxIn& a_txin, a_ptx.GetTx().vin) {
      if (a_txin.prevout == txin.prevout) {
        /* remove mempool tx due to conflict. */
        vRemove.push_back(a_ptx.GetHash());
      }
    }
  }
  for (pool_map::iterator it = pool->overflow.begin(); it != pool->overflow.end(); ++it) {
    CPoolTx& a_ptx = it->second;
    BOOST_FOREACH(const CTxIn& a_txin, a_ptx.GetTx().vin) {
      if (a_txin.prevout == txin.prevout) {
        /* remove mempool tx due to conflict. */
        vRemove.push_back(a_ptx.GetHash());
      }
    }
  }
  for (pool_map::iterator it = pool->pending.begin(); it != pool->pending.end(); ++it) {
    CPoolTx& a_ptx = it->second;
    BOOST_FOREACH(const CTxIn& a_txin, a_ptx.GetTx().vin) {
      if (a_txin.prevout == txin.prevout) {
        /* remove mempool tx due to conflict. */
        vRemove.push_back(a_ptx.GetHash());
      }
    }
  }

  BOOST_FOREACH(uint256& hash, vRemove) {
    pool->RemoveTx(hash);
  }

}

bool CPool::Commit(CBlock& block)
{
  const uint256& hash = block.GetHash();
  vector<CPoolTx> entries;
  CBlockIndex *pindex;

  pindex = GetBlockIndexByHash(ifaceIndex, hash);
  if (!pindex)
    return (false);

  BOOST_FOREACH(const CTransaction& tx, block.vtx) {
    CPoolTx ptx;

    if (tx.IsCoinBase())
      continue;

    if (!PopTx(tx, ptx))
      continue;

    entries.push_back(ptx);
  }

  BOOST_FOREACH(const CTransaction& tx, block.vtx) {
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
      /* remove any tx's from mempool with non-unique inputs */ 
      cpool_RemoveTxWithInput(this, txin);
    }
  }

  CBlockPolicyEstimator *fee = GetFeeEstimator(GetIface());
  if (fee) {
    fee->processBlock(pindex->nHeight, entries, true);
  }

  PurgeOverflowTx();

  return (true);
}

bool CPool::GetFee(uint256 hash, int64& nFee)
{
  pool_map::const_iterator mi;

  mi = active.find(hash); 
  if (mi != active.end()) {
    nFee = active[hash].GetFee();
    return (true);
  }
  mi = overflow.find(hash); 
  if (mi != overflow.end()) {
    nFee = overflow[hash].GetFee();
    return (true);
  }
  mi = pending.find(hash); 
  if (mi != pending.end()) {
    nFee = pending[hash].GetFee();
    return (true);
  }

  nFee = 0;
  return (false);
}


/**
 * @note Function will not return transactions in the 'invalid' pool queue. 
 */
bool CPool::GetTx(uint256 hash, CTransaction& retTx, int flags)
{
  pool_map::const_iterator mi;

  if (flags == 0 || flags & POOL_ACTIVE) {
    mi = active.find(hash); 
    if (mi != active.end()) {
      retTx = active[hash].tx;
      return (true);
    }
  }

  if (flags == 0 || (flags & POOL_PENDING)) {
    mi = pending.find(hash); 
    if (mi != pending.end()) {
      retTx = pending[hash].tx;
      return (true);
    }
  }

  if (flags == 0 || (flags & POOL_OVERFLOW)) {
    mi = overflow.find(hash); 
    if (mi != overflow.end()) {
      retTx = overflow[hash].tx;
      return (true);
    }
  }

  if (flags == 0 || (flags & POOL_STALE)) {
    mi = stale.find(hash); 
    if (mi != stale.end()) {
      retTx = stale[hash].tx;
      return (true);
    }
  }

#if 0
  if (flags == 0 || (flags & POOL_INVAL)) {
    mi = inval.find(hash); 
    if (mi != inval.end()) {
      retTx = inval[hash].tx;
      return (true);
    }
  }
#endif

  retTx = CTransaction();
  return (false);
}

bool CPool::AreInputsSpent(CPoolTx& ptx)
{
  const CTransaction& tx = ptx.GetTx();
  tx_cache& inputs = ptx.GetInputs();
  int i;

  for (i = 0; i < tx.vin.size(); i++) {
    const CTxIn& in = tx.vin[i];
    if (inputs.count(in.prevout.hash) == 0)
      continue;
    CTransaction& prevTx = inputs[in.prevout.hash];
    int nOut = in.prevout.n;
    vector<uint256> vOuts;
  
    if (!prevTx.ReadCoins(ifaceIndex, vOuts)) {
      return (error(SHERR_INVAL, "AreInputsSpent: error obtanining tx \'%s\".", prevTx.GetHash().GetHex().c_str()));
    }

    if (nOut >= vOuts.size()) {
      return (error(SHERR_INVAL, "AreInputsSpent: nOut(%d) >= vOuts.size(%d)\n", nOut, tx.vout.size()));
    }

    if (!vOuts[nOut].IsNull()) {
      /* this is already spent */
      return (true);
    }
  }

  return (false);
}

bool CPool::IsInputTx(const uint256 hash, int nOut)
{

  for (pool_map::iterator it = active.begin(); it != active.end(); ++it) {
    const uint256& a_hash = it->first;
    CPoolTx& a_ptx = it->second;
    BOOST_FOREACH(const CTxIn& a_txin, a_ptx.GetTx().vin) {
      if (a_txin.prevout.hash == hash &&
          a_txin.prevout.n == nOut) {
        return (true);
      }
    }
  }
  for (pool_map::iterator it = overflow.begin(); it != overflow.end(); ++it) {
    const uint256& a_hash = it->first;
    CPoolTx& a_ptx = it->second;
    BOOST_FOREACH(const CTxIn& a_txin, a_ptx.GetTx().vin) {
      if (a_txin.prevout.hash == hash &&
          a_txin.prevout.n == nOut) {
        return (true);
      }
    }
  }
  for (pool_map::iterator it = stale.begin(); it != stale.end(); ++it) {
    const uint256& a_hash = it->first;
    CPoolTx& a_ptx = it->second;
    BOOST_FOREACH(const CTxIn& a_txin, a_ptx.GetTx().vin) {
      if (a_txin.prevout.hash == hash &&
          a_txin.prevout.n == nOut) {
        return (true);
      }
    }
  }

  return (false);
}

void CPoolTx::CalculateModifiedSize()
{
  const CTransaction& tx = GetTx();
  int64 nSize;

  nSize = GetTxSize();
  for (std::vector<CTxIn>::const_iterator it(tx.vin.begin()); it != tx.vin.end(); ++it) {
    unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
    if (nSize > offset)
      nSize -= offset;
  }

  nTxModSize = nSize;
//  return nSize;
}

/* record whether tx was "clear" */
/* calculate incoming chain input value */
void CPool::CalculateDependencyMetric(CPoolTx& ptx)
{
  const CTransaction& tx = ptx.GetTx();

  ptx.nChainInputValue = 0;
  ptx.UnsetFlag(POOL_DEPENDENCY);

  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    COutPoint prevout = tx.vin[i].prevout;
    CTxOut out;

    if (exists(prevout.hash)) {
      ptx.SetFlag(POOL_DEPENDENCY);
    } else if (ptx.GetOutput(tx.vin[i], out)) {
      ptx.nChainInputValue += out.nValue;
    }
  }

}

bool CPoolTx::GetOutput(const CTxIn& input, CTxOut& retOut)
{   
  char errbuf[1024];
    
  tx_cache::const_iterator mi = mapInputs.find(input.prevout.hash);
  if (mi == mapInputs.end())
    return (false); 
    
  const CTransaction& txPrev = (mi->second); 
  if (input.prevout.n >= txPrev.vout.size())
    return (false);

  retOut = txPrev.vout[input.prevout.n];
  return (true);
}

double CPoolTx::GetPriority(unsigned int currentHeight) const
{
  double deltaPriority = ((double)(currentHeight-nHeight)*nChainInputValue)/nTxModSize;
  double dResult = dPriority + deltaPriority;

  if (dResult < 0) /* called with a height below entry height */
    dResult = 0;

  return dResult;
}

CTxMemPool *GetTxMemPool(CIface *iface)
{
  CTxMemPool *pool;
  int err;

  if (!iface->op_tx_pool) {
    int ifaceIndex = GetCoinIndex(iface);
    unet_log(ifaceIndex, "GetTxMemPool: error obtaining tx memory pool: Operation not supported.");
    return (NULL);
  }

  err = iface->op_tx_pool(iface, &pool);
  if (err) {
    int ifaceIndex = GetCoinIndex(iface);
    char errbuf[256];
    sprintf(errbuf, "GetTxMemPool: error obtaining tx memory pool: %s [sherr %d].", sherrstr(err), err);
    unet_log(ifaceIndex, errbuf);
    return (NULL);
  }

  return (pool);
}

