
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
#include "txsignature.h"

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

bool shc_ConnectInputs(CTransaction *tx, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner);


static int64 shc_CalculateFee(const CTransaction& tx)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  CWallet *wallet = GetWallet(SHC_COIN_IFACE);
  int64 nBytes;
  int64 nFee;

  nBytes = wallet->GetVirtualTransactionSize(tx);

  /* base fee */
  nFee = MIN_TX_FEE(iface) * (1 + (nBytes / 1000));

  /* dust penalty */
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    if (out.nValue < CENT)
      nFee += MIN_TX_FEE(iface);
  }

  nFee = MAX(nFee, (int64)MIN_RELAY_TX_FEE(iface));
  nFee = MIN(nFee, (int64)MAX_TRANSACTION_FEE(iface) - 1);

  return (nFee);
}

bool SHC_CTxMemPool::revert(CTransaction &tx)
{
  CWallet *pwallet = GetWallet(SHC_COIN_IFACE);
  pwallet->EraseFromWallet(tx.GetHash());
  return (tx.DisconnectInputs(SHC_COIN_IFACE));
}

#if 0
bool SHC_CTxMemPool::VerifyAccept(CTransaction &tx)
{
return (false);
}
#endif

int64_t SHC_CTxMemPool::GetSoftWeight()
{
  return (SHC_MAX_STANDARD_TX_WEIGHT);
}

int64_t SHC_CTxMemPool::GetSoftSigOpCost()
{
  return (SHC_MAX_STANDARD_TX_SIGOP_COST);
}

bool SHC_CTxMemPool::VerifyCoinStandards(CTransaction& tx, tx_cache& mapInputs)
{
  if (tx.IsCoinBase())
    return (true);

  /* SCRIPT_VERIFY_LOW_S */
  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    CTxOut prev;
    if (!tx.GetOutputFor(tx.vin[i], mapInputs, prev))
      continue; /* only verifying what is currently available */

    /* ensure output script is valid */
    vector<vector<unsigned char> > vSolutions;
    txnouttype whichType;
    const CScript& prevScript = prev.scriptPubKey;
    if (!Solver(prevScript, whichType, vSolutions))
      return false;
    if (whichType == TX_NONSTANDARD)
      return false;

    /* evaluate signature */
    vector<vector<unsigned char> > stack;
    CTransaction *txSig = (CTransaction *)this;
    CSignature sig(SHC_COIN_IFACE, txSig, i);
    if (!EvalScript(sig, stack, tx.vin[i].scriptSig, SIGVERSION_BASE, SCRIPT_VERIFY_LOW_S)) {
      return (error(SHERR_INVAL, "(shc) "
            "CTxMemPool.VerifyCoinStandards: error evaluating signature. [SCRIPT_VERIFY_LOW_S]"));
    }
    //Debug("(shc) CTxMemPool.VerifyCoinStandards: info: (BIP 66) verified DER signature <%d bytes>.", (int)tx.vin[i].scriptSig.size());
  }
  return (true);
}

bool SHC_CTxMemPool::AcceptTx(CTransaction& tx)
{
#ifdef USE_LEVELDB_COINDB
  uint256 hash = tx.GetHash();
  bool fCheckInputs = true;

  if (fCheckInputs) {
    bool fInvalid = false;
    map<uint256, CTxIndex> mapUnused;
    MapPrevTx mapInputs;
    {
      SHCTxDB txdb;

      /* ensure the transaction is unique. */
      if (txdb.ContainsTx(hash)) {
        txdb.Close();
        return false;
      }

      if (!tx.FetchInputs(txdb, mapUnused, NULL, false, mapInputs, fInvalid)) {
        txdb.Close();
        return (error(SHERR_INVAL, "(shc) CTxMemPool.AcceptTx: error retrieiving input transactions for submitted tx \"%s\".", hash.GetHex().c_str()));
      }

      txdb.Close();
    }

    if (!shc_ConnectInputs(&tx, mapInputs, mapUnused, CDiskTxPos(0,0,0), GetBestBlockIndex(SHC_COIN_IFACE), false, false)) {
      return (error(SHERR_INVAL, "(shc) CTxMemPool.AcceptTx: error connecting inputs for submitted tx \"%s\".", hash.GetHex().c_str()));
    }
  }

  Debug("(shc) mempool accepted tx \"%s\".", hash.ToString().c_str());
#endif
  return true;
}


static int64 shc_CalculateSoftFee(CTransaction& tx)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  int64 nBytes;
  int64 nFee;

  nBytes = wallet->GetVirtualTransactionSize(tx);

  /* base fee */
  nFee = wallet->GetFeeRate() * (1 + (nBytes / 1000));

  /* dust penalty */
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    if (out.nValue < CENT)
      nFee += MIN_TX_FEE(iface);
  }

  nFee = MAX(nFee, (int64)MIN_RELAY_TX_FEE(iface));
  nFee = MIN(nFee, (int64)MAX_TRANSACTION_FEE(iface) - 1);

  return (nFee);
}


int64 SHC_CTxMemPool::CalculateSoftFee(CTransaction& tx)
{
  return (shc_CalculateSoftFee(tx));
}

int64 SHC_CTxMemPool::IsFreeRelay(CTransaction& tx, tx_cache& mapInputs)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  unsigned int nBytes;

  nBytes = ::GetSerializeSize(tx, SER_NETWORK, 
      PROTOCOL_VERSION(iface) | SERIALIZE_TRANSACTION_NO_WITNESS);
  if (nBytes < 1500) {
    double dPriority = wallet->GetPriority(tx, mapInputs);
    if (dPriority > wallet->AllowFreeThreshold())
      return (true);
  }

  return (false);
}


