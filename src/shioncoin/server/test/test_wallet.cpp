
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
#include "net.h"
#include "strlcpy.h"
#include "txcreator.h"

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
#include "test/test_pool.h"
#include "test/test_block.h"
#include "test/test_wallet.h"
#include "test/test_txidx.h"
#include "chain.h"
#include "txsignature.h"
#include "coin.h"

using namespace std;
using namespace boost;

TESTWallet *testWallet;

CScript TEST_COINBASE_FLAGS;


static unsigned int test_nBytesPerSigOp = TEST_DEFAULT_BYTES_PER_SIGOP;


bool test_LoadWallet(void)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  std::ostringstream strErrors;

  const char* pszP2SH = "/P2SH/";
  TEST_COINBASE_FLAGS << std::vector<unsigned char>(pszP2SH, pszP2SH+strlen(pszP2SH));

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
  testWallet->LoadWallet(fFirstRun);

  if (fFirstRun) {
		string strAccount("");
    testWallet->GetAccount(strAccount);
  }

  //RegisterWallet(testWallet);

#if 0
  CBlockIndex *pindexRescan = GetBestBlockIndex(TEST_COIN_IFACE);
  if (GetBoolArg("-rescan"))
    pindexRescan = TESTBlock::pindexGenesisBlock;
  else
  {
    CWalletDB walletdb("test_wallet.dat");
    CBlockLocator locator(GetCoinIndex(iface));
    if (walletdb.ReadBestBlock(locator))
      pindexRescan = locator.GetBlockIndex();
  }
  CBlockIndex *pindexBest = GetBestBlockIndex(TEST_COIN_IFACE);
  if (pindexBest != pindexRescan && pindexBest && pindexRescan && pindexBest->nHeight > pindexRescan->nHeight)
  {
    int64 nStart;

    nStart = GetTimeMillis();
    testWallet->ScanForWalletTransactions(pindexRescan, true);
  }
#endif

  // Add wallet transactions that aren't already in a block to mapTransactions
  testWallet->ReacceptWalletTransactions(); 

  return (true);
}


#ifdef USE_LEVELDB_COINDB
void TESTWallet::RelayWalletTransaction(CWalletTx& wtx)
{

  BOOST_FOREACH(const CMerkleTx& tx, wtx.vtxPrev)
  {
    // Important: versions of bitcoin before 0.8.6 had a bug that inserted
    // empty transactions into the vtxPrev, which will cause the node to be
    // banned when retransmitted, hence the check for !tx.vin.empty()
    if (!tx.IsCoinBase() && !tx.vin.empty())
      if (tx.GetDepthInMainChain(SHC_COIN_IFACE) == 0)
        RelayTransaction(TEST_COIN_IFACE, (CTransaction)tx, tx.GetHash());
  }

  if (!wtx.IsCoinBase())
  {
    if (wtx.GetDepthInMainChain(SHC_COIN_IFACE) == 0) {
      uint256 hash = wtx.GetHash();
      RelayTransaction(TEST_COIN_IFACE, (CTransaction)wtx, hash);
    }
  }

}
#else
void TESTWallet::RelayWalletTransaction(CWalletTx& wtx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);

  BOOST_FOREACH(const CMerkleTx& tx, wtx.vtxPrev)
  {
    // Important: versions of bitcoin before 0.8.6 had a bug that inserted
    // empty transactions into the vtxPrev, which will cause the node to be
    // banned when retransmitted, hence the check for !tx.vin.empty()
    if (!tx.IsCoinBase() && !tx.vin.empty()) {
      uint256 hash = tx.GetHash();
      if (!VerifyTxHash(iface, hash)) { //tx.GetDepthInMainChain(SHC_COIN_IFACE) == 0)
        RelayTransaction(TEST_COIN_IFACE, (CTransaction)tx, tx.GetHash());
      }
    }
  }

  if (!wtx.IsCoinBase()) {
    uint256 hash = wtx.GetHash();
    if (!VerifyTxHash(iface, hash)) { //wtx.GetDepthInMainChain(SHC_COIN_IFACE) == 0) {
      RelayTransaction(TEST_COIN_IFACE, (CTransaction)wtx, hash);
    }
  }

}
#endif


void TESTWallet::ResendWalletTransactions()
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
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
  if (TESTBlock::nTimeBestReceived < nLastTime)
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
      if (TESTBlock::nTimeBestReceived - (int64)wtx.nTimeReceived > 5 * 60)
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

void TESTWallet::ReacceptWalletTransactions()
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  bool fRepeat = true;

  { /* erase previous transactions */
    LOCK(cs_wallet);
    fRepeat = false;
    vector<CDiskTxPos> vMissingTx;
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
    {
      CWalletTx& wtx = item.second;

#ifdef USE_LEVELDB_COINDB
      TESTTxDB txdb;
      txdb.EraseTxIndex(wtx);
      txdb.Close();
#else
      EraseTxCoins(iface, wtx.GetHash());
#endif
    }
  }

}

#if 0
int TESTWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    int ret = 0;

#if 0
    CBlockIndex* pindex = pindexStart;
    {
        LOCK(cs_wallet);
        while (pindex)
        {
            TESTBlock block;
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
#endif

int64 TESTWallet::GetTxFee(CTransaction tx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CBlock *pblock = GetBlockByTx(iface, tx.GetHash());
  int64 nFees;
  int i;

  if (tx.IsCoinBase()) {
    if (pblock) delete pblock;
    return (0);
  }

  nFees = 0;
#ifdef USE_LEVELDB_COINDB
  bool fInvalid = false;
  TESTTxDB txdb;
  map<uint256, CTxIndex> mapQueuedChanges;
  MapPrevTx inputs;
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


bool TESTWallet::CommitTransaction(CWalletTx& wtxNew)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CTxMemPool *pool = GetTxMemPool(iface);

  /* perform final checks & submit to pool. */
  if (!pool->AddTx(wtxNew))
    return (error(SHERR_INVAL, "CommitTransaction: error adding tx \"%s\" to mempool.", wtxNew.GetHash().GetHex().c_str()));

  {
    LOCK2(cs_main, cs_wallet);
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
    TESTTxDB txdb;
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
bool TESTWallet::CreateTransaction(const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  int64 nValue = 0;

  BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
  {
    if (nValue < 0) {
      return false;
}
    nValue += s.second;
  }
  if (vecSend.empty() || nValue < 0) {
    return false;
}

  wtxNew.BindWallet(this);

  {
    LOCK2(cs_main, cs_wallet);
    {
      nFeeRet = nTransactionFee;
      loop
      {
        wtxNew.vin.clear();
        wtxNew.vout.clear();
        wtxNew.fFromMe = true;

        int64 nTotalValue = nValue + nFeeRet;
        double dPriority = 0;
        // vouts to the payees
        BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
          wtxNew.vout.push_back(CTxOut(s.second, s.first));

        // Choose coins to use
        set<pair<const CWalletTx*,unsigned int> > setCoins;
        int64 nValueIn = 0;
        if (!SelectCoins(nTotalValue, setCoins, nValueIn)) {
          return false;
}
        BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
        {
          int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
          dPriority += (double)nCredit * pcoin.first->GetDepthInMainChain(ifaceIndex);
        }

        int64 nChange = nValueIn - nValue - nFeeRet;
        // if sub-cent change is required, the fee must be raised to at least MIN_TX_FEE
        // or until nChange becomes zero
        // NOTE: this depends on the exact behaviour of GetMinFee
        if (nFeeRet < TEST_MIN_TX_FEE && nChange > 0 && nChange < CENT)
        {
          int64 nMoveToFee = min(nChange, TEST_MIN_TX_FEE - nFeeRet);
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
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
          wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));
}

        unsigned int nIn = 0;
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
          CSignature sig(TEST_COIN_IFACE, &wtxNew, nIn);
          const CWalletTx *wtx = coin.first;
          if (!sig.SignSignature(*wtx)) {
            return false;
          }
          nIn++;
        }
wtxNew.print(TEST_COIN_IFACE);
#if 0
        // Sign
        int nIn = 0;
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
          const CWalletTx *wtx = coin.first;
          if (!SignSignature(*this, *wtx, wtxNew, nIn++)) {
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
        bool fAllowFree = AllowFree(dPriority);
        int64 nMinFee = wtxNew.GetMinFee(TEST_COIN_IFACE, 1, fAllowFree, GMF_SEND);
#endif
        int64 nMinFee = CalculateFee(wtxNew);

        if (nFeeRet < max(nPayFee, nMinFee))
        {
          nFeeRet = max(nPayFee, nMinFee);
          continue;
        }

        // Fill vtxPrev by copying from previous transactions vtxPrev
        wtxNew.AddSupportingTransactions();
        break;
      }
    }
  }
  return true;
}
bool TESTWallet::CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
    vector< pair<CScript, int64> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet);
}
#endif


void TESTWallet::AddSupportingTransactions(CWalletTx& wtx)
{
  wtx.AddSupportingTransactions();
}

#ifdef USE_LEVELDB_COINDB
bool TESTWallet::UnacceptWalletTransaction(const CTransaction& tx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);

  if (!core_UnacceptWalletTransaction(iface, tx))
    return (false);

  {
    TESTTxDB txdb;

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
bool TESTWallet::UnacceptWalletTransaction(const CTransaction& tx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  return (core_UnacceptWalletTransaction(iface, tx));
}
#endif

int64 TESTWallet::GetBlockValue(int nHeight, int64 nFees, uint160 hColor)
{
  return (test_GetBlockValue(nHeight, nFees));
}

#if 0
bool TESTWallet::CreateAccountTransaction(string strFromAccount, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, string& strError, int64& nFeeRet)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);

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

  {
    LOCK2(cs_main, cs_wallet);
    {
      nFeeRet = nTransactionFee;
      loop
      {
        wtxNew.vin.clear();
        wtxNew.vout.clear();
        wtxNew.fFromMe = true;

        int64 nTotalValue = nValue + nFeeRet;
        double dPriority = 0;
        // vouts to the payees
        BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
          wtxNew.vout.push_back(CTxOut(s.second, s.first));

        // Choose coins to use
        set<pair<const CWalletTx*,unsigned int> > setCoins;
        int64 nValueIn = 0;
        if (!SelectAccountCoins(strFromAccount, nTotalValue, setCoins, nValueIn))
          return false;
        BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
        {
          int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
          dPriority += (double)nCredit * pcoin.first->GetDepthInMainChain(ifaceIndex);
        }

        int64 nChange = nValueIn - nValue - nFeeRet;
        // if sub-cent change is required, the fee must be raised to at least TEST_MIN_TX_FEE
        // or until nChange becomes zero
        // NOTE: this depends on the exact behaviour of GetMinFee
        if (nFeeRet < TEST_MIN_TX_FEE && nChange > 0 && nChange < CENT)
        {
          int64 nMoveToFee = min(nChange, TEST_MIN_TX_FEE - nFeeRet);
          nChange -= nMoveToFee;
          nFeeRet += nMoveToFee;
        }

				if (nChange > 0) {
					CKeyID keyID;
					CCoinAddr addr = GetAccountAddress(this, strFromAccount, true);
					if (addr.GetKeyID(keyID)) {
						CScript scriptChange;
						scriptChange.SetDestination(keyID);

						// Insert change txn at random position:
						vector<CTxOut>::iterator position = wtxNew.vout.begin()+GetRandInt(wtxNew.vout.size());
						wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
					}
        }

        // Fill vin
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
          wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));
				}


        unsigned int nIn = 0;
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
					const CWalletTx *wtx = coin.first;
          CSignature sig(TEST_COIN_IFACE, &wtxNew, nIn);
          if (!sig.SignSignature(*wtx)) {
						const uint256& in_hash = wtx->GetHash();
						return (error(ERR_ACCESS, "CreateAccountTransaction: !sig.SignSignature[input #%d]: %s\n", (int)nIn, wtxNew.ToString(TEST_COIN_IFACE).c_str())); 
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
        bool fAllowFree = AllowFree(dPriority);
        int64 nMinFee = wtxNew.GetMinFee(TEST_COIN_IFACE, 1, fAllowFree, GMF_SEND);
#endif
        int64 nMinFee = CalculateFee(wtxNew);

        if (nFeeRet < max(nPayFee, nMinFee))
        {
          nFeeRet = max(nPayFee, nMinFee);
          continue;
        }

        // Fill vtxPrev by copying from previous transactions vtxPrev
        wtxNew.AddSupportingTransactions();
        break;
      }
    }
  }
  return true;
}
#endif
bool TESTWallet::CreateAccountTransaction(string strFromAccount, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, string& strError, int64& nFeeRet)
{

	nFeeRet = 0;
	strError = "invalid parameter";

  if (vecSend.empty())
		return (false);

  BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend) {
    if (s.first.size() == 0 || s.second < 0)
      return false;
  }

	wtxNew.vin.clear();
	wtxNew.vout.clear();
	wtxNew.fFromMe = true;

	CTxCreator wtx(this, wtxNew);
	wtx.SetAccount(strFromAccount);
	BOOST_FOREACH(const PAIRTYPE(CScript, int64)& coin, vecSend) {
		wtx.AddOutput(coin.first, coin.second);
	}
	if (!wtx.Generate()) {
		strError = wtx.GetError();
		return (false);
	}

	nFeeRet = wtx.CalculateFee();
//	wtx.nCredit - wtx.nDebit;
	wtxNew = (CWalletTx)wtx;
//	wtxNew.AddSupportingTransactions();
//	wtxNew.fTimeReceivedIsTxTime = true;

	return (true);
}
bool TESTWallet::CreateAccountTransaction(string strFromAccount, CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, string& strError, int64& nFeeRet)
{
  vector< pair<CScript, int64> > vecSend;
  vecSend.push_back(make_pair(scriptPubKey, nValue));
  return CreateAccountTransaction(strFromAccount, vecSend, wtxNew, strError, nFeeRet);
}

unsigned int TESTWallet::GetTransactionWeight(const CTransaction& tx)
{
  unsigned int nBytes;

  nBytes =
    ::GetSerializeSize(tx, SER_NETWORK, TEST_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (TEST_WITNESS_SCALE_FACTOR - 1) +
    ::GetSerializeSize(tx, SER_NETWORK, TEST_PROTOCOL_VERSION);

  return (nBytes);
}

double TESTWallet::AllowFreeThreshold()
{
  static const double block_daily = 360;
  static const double block_bytes = 256;
  return ((double)COIN * block_daily / block_bytes);
}

int64 TESTWallet::GetFeeRate(uint160 hColor)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	return (MIN_TX_FEE_RATE(iface));
}

int TESTWallet::GetCoinbaseMaturity(uint160 hColor)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	return (iface ? iface->coinbase_maturity : 0);
}

bool TESTWallet::IsAlgoSupported(int alg, CBlockIndex *pindexPrev, uint160 hColor)
{
	return (true);
}
