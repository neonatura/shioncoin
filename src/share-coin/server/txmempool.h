
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

#ifndef __SERVER__TXMEMPOOL_H__
#define __SERVER__TXMEMPOOL_H__


#define MAX_MEMPOOL_ACTIVE_SPAN 21600 /* 6hr */ 
#define MAX_MEMPOOL_OVERFLOW_SPAN 43200 /* 12hr */
#define MAX_MEMPOOL_PENDING_SPAN 86400 /* 24hr */
#define MAX_MEMPOOL_INVAL_SPAN 3600 /* 1hr */
#define MAX_MEMPOOL_STALE_SPAN 86400 /* 24hr */


#define POOL_ACTIVE (1 << 0)
#define POOL_PENDING (1 << 1)
#define POOL_OVERFLOW (1 << 2)
#define POOL_INVALID (1 << 3)
#define POOL_STALE (1 << 4)

#define POOL_FEE_LOW (1 << 6)
#define POOL_NOT_FINAL (1 << 7)
#define POOL_PEND_TX (1 << 8)
#define POOL_NO_INPUT (1 << 9)
#define POOL_SOFT_LIMIT (1 << 10)
#define POOL_DEPENDENCY (1 << 10)

class CBlockPolicyEstimator;

class CPoolTx
{
  protected:
    time_t stamp;
    uint256 hash;
    bool fLocal;
    int flags;

    /* a list of all input transactions. */
    tx_cache mapInputs;

  public:
    double dPriority;
    double dFeePriority;
    unsigned int nHeight;
    int64 nTxSize;
    int64 nTxModSize;
    int64 nWeight;
    int64 nSigOpCost;
    int64 nMinFee;
    int64 nFee;
    int64 nChainInputValue;

    /* the underlying transaction being referenced. */
    CTransaction tx;

    /* a mapping between inputs and outputs */
    std::map<COutPoint, CInPoint> mapNextTx;

    CPoolTx()
    {
      SetNull();
    }

    CPoolTx(const CTransaction& txIn)
    {
      SetNull();
      Init(txIn);
    }

    CPoolTx(const CPoolTx& ptxIn)
    {
      SetNull();
      Init(ptxIn);
    }

    void SetNull()
    {
      stamp = time(NULL);
      tx.SetNull();
      hash = uint256(0);

      dPriority = 0;
      dFeePriority = 0;
      nHeight = 0;
      nTxSize = 0;
      nTxModSize = 0;
      nWeight = 0;
      nSigOpCost = 0;
      nMinFee = 0;
      nFee = 0;
      nChainInputValue = 0;
      flags = 0;
      mapInputs.clear();
    }

    time_t GetStamp()
    {
      return (stamp);
    }

    bool IsExpired(time_t span)
    {
      if (GetStamp() + span < time(NULL))
        return (true);
      return (false);
    }

    bool IsLocal()
    {
      return (fLocal);
    }

    const uint256& GetHash() const
    {
      return (hash);
    }

    CTransaction& GetTx()
    {
      return (tx);
    }

    void setLocal(bool val)
    {
      fLocal = val;
    }

    bool isLocal()
    {
      return (true);
    }

    double GetPriority(unsigned int currentHeight) const;

    double GetFeePriority()
    {
      return (dFeePriority);
    }

    int64 GetFee()
    {
      return (nFee);
    }

    int64 GetTxSize()
    {
      return (nTxSize);
    }

    int64 GetModifiedSize()
    {
      return (nTxModSize);
    }

    int64 GetWeight()
    {
      return (nWeight);
    }

    unsigned int GetHeight()
    {
      return (nHeight);
    }

    bool GetOutput(const CTxIn& input, CTxOut& retOut);

#if 0
    CPoolTx& operator = (CPoolTx& b)
    {
      Init(b);
      return *this;
    }
#endif

    bool operator == (const CPoolTx& b) const
    {
      const CPoolTx& a = *this;
      if (GetHash() == 
b.GetHash())
        return (true);
      return (false);
    }

    bool operator < (const CPoolTx& ptx) const
    {
      return (dFeePriority < ptx.dFeePriority);
    }

    bool operator > (const CPoolTx& ptx) const
    {
      return (dFeePriority > ptx.dFeePriority);
    }

    void Init(const CTransaction& txIn)
    {
      tx.Init(txIn);
      hash = tx.GetHash();
    }

    void Init(const CPoolTx& b)
    {
      Init(b.tx);

      stamp = b.stamp;
      hash = b.hash;
      fLocal = b.fLocal;
      flags = b.flags;
      dPriority = b.dPriority;
      dFeePriority = b.dFeePriority;
      nWeight = b.nWeight;
      nTxSize = b.nTxSize;
      nTxModSize = b.nTxModSize;
      nHeight = b.nHeight;
      nSigOpCost = b.nSigOpCost;
      nMinFee = b.nMinFee;
      nFee = b.nFee;        
      nChainInputValue = b.nChainInputValue;
      mapNextTx = b.mapNextTx;

      BOOST_FOREACH(PAIRTYPE(const uint256, CTransaction) item, b.mapInputs) {
        CTransaction tx = item.second;
        uint256 hash = item.first;

        mapInputs[hash] = tx;
      }
    }

    void SetFlag(int flag)
    {
      flags |= flag;
    }

    void UnsetFlag(int flag)
    {
      flags &= ~flag;
    }

    bool IsFlag(int flag)
    {
      if (flags & flag)
        return (true);
      return (false);
    }

    void AddInput(CTransaction prevTx)
    {
      const uint256& hash = prevTx.GetHash();
      CTransaction tx(prevTx);
      uint256 tx_hash(hash);
      
      mapInputs[tx_hash] = tx;
    }

    tx_cache& GetInputs()
    {
      return (mapInputs);
    }

    void ClearInputs()
    {
      mapInputs.clear();
    }


    void CalculateModifiedSize();
};

typedef map<const uint256, CPoolTx> pool_map;
//typedef vector<CPoolTx&> pool_set;

class CTxMemPool
{
  public:

    int size()
    {
      return (GetActiveTotal());
    }

    bool exists(uint256 hash)
    {
      return (HaveTx(hash));
    }

    CTransaction& lookup(uint256 hash)
    {
      static CTransaction tx;
      GetTx(hash, tx);
      return (tx);
    }

    bool accept(CTransaction &tx, CNode *pfrom = NULL)
    {
      return (AddTx(tx, pfrom));
    }

    virtual bool HaveTx(uint256 hash) = 0;

    virtual bool RemoveTx(CTransaction &tx) = 0;

    virtual bool RemoveTx(const uint256& tx_hash) = 0;

    virtual bool GetTx(uint256 hash, CTransaction& retTx, int flags = 0) = 0;

    virtual bool AddTx(CTransaction& tx, CNode *pfrom = NULL) = 0;

    virtual vector<CTransaction> GetActiveTx() = 0;

    virtual bool FetchInputs(uint256 hash, tx_cache& cacheRet) = 0;

    virtual int GetActiveTotal() = 0;

    virtual size_t GetMaxQueueMem() = 0;

    virtual int64 GetOverflowTxSize() = 0;

    virtual bool Commit(CBlock &block) = 0;

    virtual bool GetFee(uint256 hash, int64& nFee) = 0;

    virtual bool IsInvalidTx(const uint256 hash) const = 0;

    virtual bool IsPendingTx(const uint256 hash) const = 0;

    virtual bool IsInputTx(const uint256 hash, int nOut) = 0;

};

class CPool : public CTxMemPool
{

  protected:
    int ifaceIndex;

    /** The maximum preferred size of each memory pool in megabytes. */
    size_t szMemMax;



  public:
    mutable CCriticalSection cs;

    /* the pool where tx's are obtained from to use in new blocks. */
    pool_map active;

    /* the pool where tx's which have an input residing in the mem pool. */
    pool_map pending;

    /* a back-buffer pool when their are too many to put into active pool. */
    pool_map overflow;

    /* active tx's that aren't being processed. */
    pool_map stale;

    /* a list of tx hashes considered invalid for pool acceptance. */
    set<uint256> inval;

    CPool(int ifaceIndexIn)
    {
      ifaceIndex = ifaceIndexIn;
      szMemMax = 5;
    }

    CIface *GetIface()
    {
      return (GetCoinByIndex(ifaceIndex));
    }

    size_t GetMaxQueueMem()
    {
      return (szMemMax * 1000000);
    }

    void queryHashes(std::vector<uint256>& vtxid)
    {
      vtxid.clear();

      {
        LOCK(cs);
        vtxid.reserve(active.size());
        for (map<uint256, CPoolTx>::iterator mi = active.begin(); mi != active.end(); ++mi)
          vtxid.push_back((*mi).first);
      }

    }

    /* remove transaction from mempool referenced by tx hash. */
    bool RemoveTx(const uint256& hash);

    /* remove transaction from mempool. */
    bool RemoveTx(CTransaction &tx)
    {
      uint256 hash = tx.GetHash();
      return (RemoveTx(hash));
    }

    /* Have the tx pool'd in one form or another. */
    bool HaveTx(uint256 hash)
    {
      /* does not consider invalid tx hashes valid. */
      return (active.count(hash) != 0 ||
          pending.count(hash) != 0 ||
          overflow.count(hash) != 0 ||
          stale.count(hash) != 0);
    }

    /* The total weight of all active transactions. */
    int64 GetActiveWeight()
    {
      int64 nWeight = 0;

      BOOST_FOREACH(PAIRTYPE(const uint256, CPoolTx)& item, active) {
        CPoolTx& ptx = item.second;
        nWeight += ptx.GetWeight();
      }
      return (nWeight);
    }

    int64 GetOverflowTxSize()
    {
      int64 nTxSize = 0;

      BOOST_FOREACH(PAIRTYPE(const uint256, CPoolTx)& item, overflow) {
        CPoolTx& ptx = item.second;
        nTxSize += ptx.GetTxSize();
      }

      return (nTxSize);
    }

    int64 GetStaleTxSize()
    {
      int64 nTxSize = 0;

      BOOST_FOREACH(PAIRTYPE(const uint256, CPoolTx)& item, stale) {
        CPoolTx& ptx = item.second;
        nTxSize += ptx.GetTxSize();
      }

      return (nTxSize);
    }

    /** Obtain a pool tx from the active queue. */
    CPoolTx *GetPoolTx(uint256 hash)
    {

      for (map<uint256, CPoolTx>::iterator mi = active.begin(); mi != active.end(); ++mi) {
        CPoolTx& ptx = (*mi).second;
        if (ptx.GetHash() == hash)
          return (&ptx);
      }

      return (NULL);
    }

    /** Obtain the input transactions for a active transaction hash. */
    bool FetchInputs(uint256 hash, tx_cache& cacheRet)
    {
      CPoolTx *ptx;

      ptx = GetPoolTx(hash);
      if (!ptx)
        return (false);
  
      cacheRet = ptx->GetInputs();
      return (true);
    }

    bool IsInvalidTx(const uint256 hash) const
    {

      if (inval.count(hash) != 0)
        return (true);

      return (false);
    }

    bool IsPendingTx(const uint256 hash) const
    {

      if (pending.count(hash) != 0)
        return (true);

      return (false);
    }

    void CalculateDependencyMetric(CPoolTx& ptx);

    void purge();

    bool AddTx(CTransaction& tx, CNode *pfrom = NULL);

    bool AddActiveTx(CPoolTx& tx);

    bool AddOverflowTx(CPoolTx& tx);

    bool AddStaleTx(CPoolTx& tx);

    bool AddPendingTx(CPoolTx& tx);

    void AddInvalTx(CPoolTx& tx);

    bool VerifyTx(CTransaction& tx);

    void CalculateLimits(CPoolTx& ptx);

    bool VerifyLimits(CPoolTx& ptx);

    bool VerifySoftLimits(CPoolTx& ptx);

    int64_t GetMaxWeight();

    int64_t GetMaxSigOpCost();

    bool FillInputs(CPoolTx& ptx);

    bool RefillInputs(CPoolTx& ptx);

    bool VerifyStandards(CPoolTx& ptx);

    void CalculateFee(CPoolTx& ptx);

    vector<CTransaction> GetActiveTx();

    vector<uint256> GetActiveHash();

    bool GetTx(uint256 hash, CTransaction& retTx, int flags = 0);

    bool ResolveConflicts(CPoolTx& ptx);

    int GetActiveTotal();

    void PurgeActiveTx();

    void PurgeOverflowTx();

    void PurgePendingTx();


    /** remove connected block tx's from pool. */
    bool Commit(CBlock &block);

    bool PopTx(const CTransaction& tx, CPoolTx& ptx);

    bool GetFee(uint256 hash, int64& nFee);

    bool AreInputsSpent(CPoolTx& ptx);

    bool IsInputTx(const uint256 hash, int nOut); 

    /* revert transaction from wallet (like tx.purge rpc cmd). */
    virtual bool revert(CTransaction &tx) = 0;

//    virtual bool VerifyAccept(CTransaction &tx) = 0;

    virtual int64_t GetSoftWeight() = 0;

    virtual int64_t GetSoftSigOpCost() = 0;

    virtual bool VerifyCoinStandards(CTransaction& tx, tx_cache& mapInputs) = 0;

    virtual bool AcceptTx(CTransaction& tx) = 0;

    virtual int64 CalculateSoftFee(CTransaction& tx) = 0;

    virtual int64 IsFreeRelay(CTransaction& tx, tx_cache& mapInputs) = 0;


    
/* IncrPriority(uint256 hash) */
/* DecrPriority(uint256 hash) */
/* SetMinFee(double v) */
};






CTxMemPool *GetTxMemPool(CIface *iface);


#endif /* ndef __SERVER__TXMEMPOOL_H__ */



