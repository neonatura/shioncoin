
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
#include "net.h"
#include "strlcpy.h"
#include "ui_interface.h"
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

#include <boost/array.hpp>
#include <share.h>
#include "walletdb.h"
#include "emc2/emc2_pool.h"
#include "emc2/emc2_block.h"
#include "emc2/emc2_wallet.h"
#include "emc2/emc2_txidx.h"
#include "chain.h"
#include "txsignature.h"

using namespace std;
using namespace boost;

EMC2Wallet *emc2Wallet;
CScript EMC2_COINBASE_FLAGS;

static const unsigned int MAX_EMC2_STANDARD_TX_WEIGHT = 400000;



bool emc2_LoadWallet(void)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  std::ostringstream strErrors;

  const char* pszP2SH = "/P2SH/";
  EMC2_COINBASE_FLAGS << std::vector<unsigned char>(pszP2SH, pszP2SH+strlen(pszP2SH));

#if 0
  if (!bitdb.Open(GetDataDir()))
  {
    fprintf(stderr, "error: unable to open data directory.\n");
    return (false);
  }

  if (!LoadBlockIndex(iface)) {
    fprintf(stderr, "error: unable to open load block index.\n");
    return (false);
  }
#endif

  bool fFirstRun = true;
  emc2Wallet->LoadWallet(fFirstRun);

  if (fFirstRun) {
		/* generate default address for system account. */
		string strAccount("");
		emc2Wallet->GetAccount(strAccount);
  }

  //RegisterWallet(emc2Wallet);

#if 0
  CBlockIndex *pindexRescan = GetBestBlockIndex(EMC2_COIN_IFACE);
  if (GetBoolArg("-rescan"))
    pindexRescan = EMC2Block::pindexGenesisBlock;
  else
  {
    CWalletDB walletdb("emc2_wallet.dat");
    CBlockLocator locator(GetCoinIndex(iface));
    if (walletdb.ReadBestBlock(locator))
      pindexRescan = locator.GetBlockIndex();
		walletdb.Close();
  }
  CBlockIndex *pindexBest = GetBestBlockIndex(EMC2_COIN_IFACE);
  if (pindexBest != pindexRescan && pindexBest && pindexRescan && pindexBest->nHeight > pindexRescan->nHeight)
  {
    int64 nStart;

    Debug("(ecm2) LoadWallet: Rescanning last %i blocks (from block %i)...\n", pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
    nStart = GetTimeMillis();
    emc2Wallet->ScanForWalletTransactions(pindexRescan, true);
  }
#endif

  // Add wallet transactions that aren't already in a block to mapTransactions
  emc2Wallet->ReacceptWalletTransactions(); 

  return (true);
}

#ifdef USE_LEVELDB_COINDB
void EMC2Wallet::RelayWalletTransaction(CWalletTx& wtx)
{
  EMC2TxDB txdb;

  BOOST_FOREACH(const CMerkleTx& tx, wtx.vtxPrev) 
  { 
    if (!tx.IsCoinBase())
    {
      uint256 hash = tx.GetHash();
      if (!txdb.ContainsTx(hash))
        RelayMessage(CInv(ifaceIndex, MSG_TX, hash), (CTransaction)tx);
    }
  }

  if (!wtx.IsCoinBase())
  {
    uint256 hash = wtx.GetHash();
    if (!txdb.ContainsTx(hash))
    {
      RelayMessage(CInv(ifaceIndex, MSG_TX, hash), (CTransaction)wtx);
    }
  }

  txdb.Close();
}
#else
void EMC2Wallet::RelayWalletTransaction(CWalletTx& wtx)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);

  BOOST_FOREACH(const CMerkleTx& tx, wtx.vtxPrev) { 
    if (!tx.IsCoinBase() && !tx.vin.empty()) {
      uint256 hash = tx.GetHash();
      if (!VerifyTxHash(iface, hash))
        RelayMessage(CInv(ifaceIndex, MSG_TX, hash), (CTransaction)tx);
    }
  }

  if (!wtx.IsCoinBase()) {
    uint256 hash = wtx.GetHash();
    if (!VerifyTxHash(iface, hash)) {
      RelayMessage(CInv(ifaceIndex, MSG_TX, hash), (CTransaction)wtx);
    }
  }

}
#endif


void EMC2Wallet::ResendWalletTransactions()
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  CTxMemPool *pool = GetTxMemPool(iface);

  // Do this infrequently and randomly to avoid giving away
  // that these are our transactions.
  static int64 nNextTime;
  if (GetTime() < nNextTime)
    return;
  bool fFirst = (nNextTime == 0);
  nNextTime = GetTime() + GetRand(30 * 60);
  if (fFirst)
    return;

  // Only do it if there's been a new block since last time
  static int64 nLastTime;
  if (EMC2Block::nTimeBestReceived < nLastTime)
    return;
  nLastTime = GetTime();

  // Rebroadcast any of our txes that aren't in a block yet
  {
    LOCK(cs_wallet);
    // Sort them in chronological order
    multimap<unsigned int, CWalletTx*> mapSorted;
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
    {
      CWalletTx& wtx = item.second;
      const uint256& tx_hash = item.first;
      if (!pool->exists(tx_hash))
        continue;
      // Don't rebroadcast until it's had plenty of time that
      // it should have gotten in already by now.
      if (EMC2Block::nTimeBestReceived - (int64)wtx.nTimeReceived > 5 * 60)
        mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
    }
    BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
    {
      CWalletTx& wtx = *item.second;
//      wtx.RelayWalletTransaction(txdb);
      RelayWalletTransaction(wtx);
    }
  }
}

void EMC2Wallet::ReacceptWalletTransactions()
{
	{
		LOCK(cs_wallet);
		core_ReacceptWalletTransactions(this);
	}
}

int EMC2Wallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    int ret = 0;

#if 0
    CBlockIndex* pindex = pindexStart;
    {
        LOCK(cs_wallet);
        while (pindex)
        {
            EMC2Block block;
            block.ReadFromDisk(pindex, true);
            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    ret++;
            }
            pindex = pindex->pnext;
        }
    }
#endif

    if (pindexStart)
      InitServiceWalletEvent(this, pindexStart->nHeight);

    return ret;
}

int64 EMC2Wallet::GetTxFee(CTransaction tx)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  CBlock *pblock = GetBlockByTx(iface, tx.GetHash());
  int64 nFees;
  int i;

  if (tx.IsCoinBase()) {
    delete pblock;
    return (0);
  }

  nFees = 0;
#ifdef USE_LEVELDB_COINDB
  bool fInvalid = false;
  map<uint256, CTxIndex> mapQueuedChanges;
  MapPrevTx inputs;
  EMC2TxDB txdb;
  if (tx.FetchInputs(txdb, mapQueuedChanges, pblock, false, inputs, fInvalid))
    nFees += tx.GetValueIn(inputs) - tx.GetValueOut();
  txdb.Close();
#else
  tx_cache inputs;
  if (FillInputs(tx, inputs)) {
    nFees += tx.GetValueIn(inputs) - tx.GetValueOut();
  }
#endif

  if (pblock) delete pblock;
  return (nFees);
}


bool EMC2Wallet::CommitTransaction(CWalletTx& wtxNew)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  CTxMemPool *pool = GetTxMemPool(iface);

  /* perform final checks & submit to pool. */
    if (!pool->AddTx(wtxNew))
      return (false);

  {
    LOCK2(cs_main, cs_wallet);
//    Debug("CommitTransaction:\n%s", wtxNew.ToString().c_str());
    {
      // This is only to keep the database open to defeat the auto-flush for the
      // duration of this scope.  This is the only place where this optimization
      // maybe makes sense; please don't do it anywhere else.
//      CWalletDB* pwalletdb = new CWalletDB(strWalletFile,"r");


      // Add tx to wallet, because if it has change it's also ours,
      // otherwise just for transaction history.
      AddToWallet(wtxNew);

#if 0
      // Mark old coins as spent
      set<CWalletTx*> setCoins;
      BOOST_FOREACH(const CTxIn& txin, wtxNew.vin)
      {
        CWalletTx &coin = mapWallet[txin.prevout.hash];
        coin.BindWallet(this);
        coin.MarkSpent(txin.prevout.n);
        coin.WriteToDisk();
        //NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
      }
#endif

//			delete pwalletdb;
    }

    // Track how many getdata requests our transaction gets
    mapRequestCount[wtxNew.GetHash()] = 0;

#if 0
    // Broadcast
    EMC2TxDB txdb;
    bool ret = wtxNew.AcceptToMemoryPool(txdb);
    if (ret) {
//      wtxNew.RelayWalletTransaction(txdb);
      RelayWalletTransaction(wtxNew);
    }
    txdb.Close();
    if (!ret) {
      // This must not fail. The transaction has already been signed and recorded.
      printf("CommitTransaction() : Error: Transaction not valid");
      return false;
    }
#endif

    RelayWalletTransaction(wtxNew); 
  }

  STAT_TX_SUBMITS(iface)++;

  return true;
}

#if 0
bool EMC2Wallet::CreateTransaction(const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  int64 nValue = 0;

  BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
  {
    if (nValue < 0)
      return false;
    nValue += s.second;
  }
  if (vecSend.empty() || nValue < 0)
    return false;

  wtxNew.BindWallet(this);

  /* set nLockTime to current height in order to disallow this tx from being used in a situation where "the value of the transactions in the best block and the mempool can exceed the cost of deliberately attempting to mine two blocks to orphan the current best". */
  wtxNew.nLockTime = GetBestHeight(iface);

  {
    LOCK2(cs_main, cs_wallet);
    {


      nFeeRet = 0;

      loop
      {
        wtxNew.vin.clear();
        wtxNew.vout.clear();
        wtxNew.wit.SetNull(); 
        wtxNew.fFromMe = true;


        // vouts to the payees
        BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend) {
          if (s.second < MIN_RELAY_TX_FEE(iface))
            return (error(SHERR_INVAL, "Transaction amount too small"));

          wtxNew.vout.push_back(CTxOut(s.second, s.first));
        }

        int64 nTotalValue = nValue + nFeeRet;
        set<pair<const CWalletTx*,unsigned int> > setCoins;
        int64 nValueIn = 0;
        if (!SelectCoins(nTotalValue, setCoins, nValueIn))
          return false;

        double dPriority = 0;
        BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
        {
          int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
          int age = pcoin.first->GetDepthInMainChain(ifaceIndex);
          if (age != 0) age++; /* The coin age after the next block (depth+1) is used instead of the current */
          dPriority += (double)nCredit * age;
        }

        int64 nChange = nValueIn - nValue - nFeeRet;
        // if sub-cent change is required, the fee must be raised to at least MIN_TX_FEE
        // or until nChange becomes zero
        // NOTE: this depends on the exact behaviour of GetMinFee
        if (nFeeRet < EMC2_MIN_TX_FEE && nChange > 0 && nChange < CENT)
        {
          int64 nMoveToFee = min(nChange, EMC2_MIN_TX_FEE - nFeeRet);
          nChange -= nMoveToFee;
          nFeeRet += nMoveToFee;
        }

        if (nChange > 0)
        {
          // Note: We use a new key here to keep it from being obvious which side is the change.
          //  The drawback is that by not reusing a previous key, the change may be lost if a
          //  backup is restored, if the backup doesn't have the new private key for the change.
          //  If we reused the old key, it would be possible to add code to look for and
          //  rediscover unknown transactions that were written with keys of ours to recover
          //  post-backup change.

          // Reserve a new key pair from key pool
          CPubKey vchPubKey = reservekey.GetReservedKey();
          // assert(mapKeys.count(vchPubKey));

          // Fill a vout to ourself
          // TODO: pass in scriptChange instead of reservekey so
          // change transaction isn't always pay-to-bitcoin-address
          CScript scriptChange;
          scriptChange.SetDestination(vchPubKey.GetID());

          // Insert change txn at random position:
          vector<CTxOut>::iterator position = wtxNew.vout.begin()+GetRandInt(wtxNew.vout.size());
          wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
        }
        else
          reservekey.ReturnKey();

        // Fill vin
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
          wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second, 
                CScript(), std::numeric_limits<unsigned int>::max()-1));

        unsigned int nIn = 0;
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
          CSignature sig(EMC2_COIN_IFACE, &wtxNew, nIn);
          if (!sig.SignSignature(*coin.first)) {
            return false;
          }

          nIn++;
        }
#if 0
        // Sign
        int nIn = 0;
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
          if (!SignSignature(*this, *coin.first, wtxNew, nIn++)) {
            return false;
          }
#endif

        /* Ensure transaction does not breach a defined size limitation. */
        unsigned int nWeight = GetTransactionWeight(wtxNew);
        if (nWeight >= MAX_TRANSACTION_WEIGHT(iface)) {
          return (error(SHERR_INVAL, "The transaction size is too large."));
        }

        unsigned int nBytes = GetVirtualTransactionSize(wtxNew);
        dPriority /= nBytes;

        // Check that enough fee is included
        int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
#if 0
        bool fAllowFree = false;
        if (AllowFree(dPriority) && nBytes < 1000)
          fAllowFree = true;
        int64 nMinFee = wtxNew.GetMinFee(EMC2_COIN_IFACE, 1, fAllowFree, GMF_SEND);
#endif
        int64 nMinFee = CalculateFee(wtxNew);

        if (nFeeRet < max(nPayFee, nMinFee))
        {
          nFeeRet = max(nPayFee, nMinFee);
          continue;
        }

        // Fill vtxPrev by copying from previous transactions vtxPrev
        wtxNew.AddSupportingTransactions();
        wtxNew.fTimeReceivedIsTxTime = true;

        break;
      }
    }
  }
  return true;
}
bool EMC2Wallet::CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
    vector< pair<CScript, int64> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet);
}
#endif

void EMC2Wallet::AddSupportingTransactions(CWalletTx& wtx)
{
  wtx.AddSupportingTransactions();
}

#ifdef USE_LEVELDB_COINDB
bool EMC2Wallet::UnacceptWalletTransaction(const CTransaction& tx)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);

  if (!core_UnacceptWalletTransaction(iface, tx))
    return (false);

  {
    EMC2TxDB txdb;

    BOOST_FOREACH(const CTxIn& in, tx.vin) {
      const uint256& prev_hash = in.prevout.hash; 
      int nTxOut = in.prevout.n;

      CTxIndex txindex;
      if (!txdb.ReadTxIndex(prev_hash, txindex))
        continue;

      if (nTxOut >= txindex.vSpent.size())
        continue; /* bad */

      /* set output as unspent */
      txindex.vSpent[nTxOut].SetNull();
      txdb.UpdateTxIndex(prev_hash, txindex);
    }

    /* remove pool tx from db */
    txdb.EraseTxIndex(tx);

    txdb.Close();
  }

  return (true);
}
#else
bool EMC2Wallet::UnacceptWalletTransaction(const CTransaction& tx)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
  return (core_UnacceptWalletTransaction(iface, tx));
}
#endif

int64 EMC2Wallet::GetBlockValue(int nHeight, int64 nFees, uint160 hColor)
{
  return (emc2_GetBlockValue(nHeight, nFees));
}

bool EMC2Wallet::CreateAccountTransaction(string strFromAccount, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, string& strError, int64& nFeeRet)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);

  wtxNew.strFromAccount = strFromAccount;

  int64 nValue = 0;
  BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
  {
    if (nValue < 0)
      return false;
    nValue += s.second;
  }
  if (vecSend.empty() || nValue < 0)
    return false;

  wtxNew.BindWallet(this);

  /* set nLockTime to current height in order to disallow this tx from being used in a situation where "the value of the transactions in the best block and the mempool can exceed the cost of deliberately attempting to mine two blocks to orphan the current best". */
  wtxNew.nLockTime = GetBestHeight(iface) - 1;

  {
    LOCK2(cs_main, cs_wallet);
    {
      nFeeRet = 0;

      loop
      {
        wtxNew.vin.clear();
        wtxNew.vout.clear();
        wtxNew.wit.SetNull(); 
        wtxNew.fFromMe = true;

        int64 nTotalValue = nValue + nFeeRet;
        double dPriority = 0;

        // vouts to the payees
        BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend) {
          if (s.second < MIN_RELAY_TX_FEE(iface))
            return (error(SHERR_INVAL, "Transaction amount too small"));

          wtxNew.vout.push_back(CTxOut(s.second, s.first));
        }

        // Choose coins to use
        set<pair<const CWalletTx*,unsigned int> > setCoins;
        int64 nValueIn = 0;
        if (!SelectAccountCoins(strFromAccount, nTotalValue, setCoins, nValueIn)) {
          strError = "An error occurred obtaining sufficient coins in order perform the transaction. Check the transaction fee cost.";
          return false;
        }
        BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
        {
          int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
          dPriority += (double)nCredit * pcoin.first->GetDepthInMainChain(ifaceIndex);
        }

        int64 nChange = nValueIn - nValue - nFeeRet;
        // if sub-cent change is required, the fee must be raised to at least EMC2_MIN_TX_FEE
        // or until nChange becomes zero
        // NOTE: this depends on the exact behaviour of GetMinFee
        if (nFeeRet < EMC2_MIN_TX_FEE && nChange > 0 && nChange < CENT)
        {
          int64 nMoveToFee = min(nChange, EMC2_MIN_TX_FEE - nFeeRet);
          nChange -= nMoveToFee;
          nFeeRet += nMoveToFee;
        }

				if (nChange > 0)
				{
					CKeyID keyID;
					CCoinAddr addr = GetAccountAddress(this, strFromAccount);
					if (addr.GetKeyID(keyID)) {
						CScript scriptChange;
						scriptChange.SetDestination(keyID);

						// Insert change txn at random position:
						vector<CTxOut>::iterator position = wtxNew.vout.begin()+GetRandInt(wtxNew.vout.size());
						wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
					}
        }

        // Fill vin
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
          wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second,
                CScript(), std::numeric_limits<unsigned int>::max()-1));


        unsigned int nIn = 0;
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
          CSignature sig(EMC2_COIN_IFACE, &wtxNew, nIn);
          const CWalletTx *s_wtx = coin.first;
          if (!sig.SignSignature(*s_wtx)) {

#if 0
            /* failing signing against prevout. mark as spent to prohibit further attempts to use this output. */
            s_wtx->MarkSpent(nIn);
#endif

            strError = strprintf(_("An error occurred signing the transaction [input tx \"%s\", output #%d]."), s_wtx->GetHash().GetHex().c_str(), nIn);
            return false;
          }

          nIn++;
        }
#if 0
        // Sign
        int nIn = 0;
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
          const CWalletTx *s_wtx = coin.first;
          if (!SignSignature(*this, *s_wtx, wtxNew, nIn++)) {

#if 0
            /* failing signing against prevout. mark as spent to prohibit further attempts to use this output. */
            s_wtx->MarkSpent(nIn);
#endif

            strError = strprintf(_("An error occurred signing the transaction [input tx \"%s\", output #%d]."), s_wtx->GetHash().GetHex().c_str(), nIn);
            return false;
          }
        }
#endif

        /* Ensure transaction does not breach a defined size limitation. */
        unsigned int nWeight = GetTransactionWeight(wtxNew);
        if (nWeight >= MAX_TRANSACTION_WEIGHT(iface)) {
          return (error(SHERR_INVAL, "The transaction size is too large."));
        }

        unsigned int nBytes = GetVirtualTransactionSize(wtxNew);
        dPriority /= nBytes;

        // Check that enough fee is included
        int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
#if 0
        bool fAllowFree = false;
        if (AllowFree(dPriority) && nBytes < 1000)
          fAllowFree = true;
       int64 nMinFee = wtxNew.GetMinFee(EMC2_COIN_IFACE, 1, fAllowFree, GMF_SEND);
#endif
        int64 nMinFee = CalculateFee(wtxNew);

        if (nFeeRet < max(nPayFee, nMinFee))
        {
          nFeeRet = max(nPayFee, nMinFee);
          continue;
        }

        // Fill vtxPrev by copying from previous transactions vtxPrev
        wtxNew.AddSupportingTransactions();
        wtxNew.fTimeReceivedIsTxTime = true;

        break;
      }
    }
  }
  return true;
}
bool EMC2Wallet::CreateAccountTransaction(string strFromAccount, CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, string& strError, int64& nFeeRet)
{
  vector< pair<CScript, int64> > vecSend;
  vecSend.push_back(make_pair(scriptPubKey, nValue));
  return CreateAccountTransaction(strFromAccount, vecSend, wtxNew, strError, nFeeRet);
}

unsigned int EMC2Wallet::GetTransactionWeight(const CTransaction& tx)
{

  unsigned int nBytes;

  nBytes = 
    ::GetSerializeSize(tx, SER_NETWORK, EMC2_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (EMC2_WITNESS_SCALE_FACTOR - 1) +
    ::GetSerializeSize(tx, SER_NETWORK, EMC2_PROTOCOL_VERSION);

  return (nBytes);
}

/** Large (in bytes) low-priority (new, small-coin) transactions require fee. */
double EMC2Wallet::AllowFreeThreshold()
{
  return COIN * 144 / 250;
}
#if 0
bool AllowFree() {
  return dPriority > emc2_AllowFreeThreshold();
}
#endif

int64 EMC2Wallet::GetFeeRate(uint160 hColor)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
	return (MIN_TX_FEE_RATE(iface));
}

int EMC2Wallet::GetCoinbaseMaturity(uint160 hColor)
{
  CIface *iface = GetCoinByIndex(EMC2_COIN_IFACE);
	return (iface ? iface->coinbase_maturity : 0);
}

bool EMC2Wallet::IsAlgoSupported(int alg, CBlockIndex *pindexPrev, uint160 hColor)
{
	if (alg == ALGO_SCRYPT)
		return (true);
	return (false);
}
