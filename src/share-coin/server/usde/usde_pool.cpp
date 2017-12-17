
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
#include "usde_pool.h"
#include "usde_block.h"
#include "usde_wallet.h"
#include "usde_txidx.h"
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

extern bool usde_ConnectInputs(CTransaction *tx, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fStrictPayToScriptHash=true);


static bool usde_AllowFree(double dPriority)
{
  return dPriority > COIN * 700 / 250;
}

static int64 usde_CalculateFee(const CTransaction& tx)
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  CWallet *wallet = GetWallet(USDE_COIN_IFACE);
  int64 nBaseFee = MIN_TX_FEE(iface);

  unsigned int nBytes = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION(iface));
  int64 nMinFee = (1 + (int64)nBytes / 1000) * nBaseFee;

  tx_cache inputs;
  wallet->FillInputs(tx, inputs);
  double dPriority = wallet->GetPriority(tx, inputs);
  if (usde_AllowFree(dPriority)) {
    if (nBytes < 10000)
      nMinFee = 0;
  }

  /* dust */
  BOOST_FOREACH(const CTxOut& txout, tx.vout) {
    if (txout.nValue < CENT)
      nMinFee += nBaseFee;
  }

  nMinFee = MIN(nMinFee, (int64)MAX_TRANSACTION_FEE(iface) - 1);
  return nMinFee;
}



bool USDE_CTxMemPool::revert(CTransaction &tx)
{
  CWallet *pwallet = GetWallet(USDE_COIN_IFACE);
  pwallet->EraseFromWallet(tx.GetHash());
  return (tx.DisconnectInputs(USDE_COIN_IFACE));
}


#if 0
bool USDE_CTxMemPool::VerifyAccept(CTransaction &tx)
{
return (false);
}
#endif

int64_t USDE_CTxMemPool::GetSoftWeight()
{
  return (USDE_MAX_STANDARD_TX_WEIGHT);
}

int64_t USDE_CTxMemPool::GetSoftSigOpCost()
{
  return (USDE_MAX_STANDARD_TX_SIGOP_COST);
}

bool USDE_CTxMemPool::VerifyCoinStandards(CTransaction& tx, tx_cache& mapInputs)
{
  return (true);
}

bool USDE_CTxMemPool::AcceptTx(CTransaction& tx)
{
#ifdef USE_LEVELDB_COINDB
  uint256 hash = tx.GetHash();
  bool fCheckInputs = true;

  if (fCheckInputs) {
    bool fInvalid = false;
    map<uint256, CTxIndex> mapUnused;
    MapPrevTx mapInputs;
    {
      USDETxDB txdb;

      /* ensure the transaction is unique. */
      if (txdb.ContainsTx(hash)) {
        txdb.Close();
        return false;
      }

      if (!tx.FetchInputs(txdb, mapUnused, NULL, false, mapInputs, fInvalid)) {
        txdb.Close();
        return (error(SHERR_INVAL, "(usde) CTxMemPool.AcceptTx: error retrieiving input transactions for submitted tx \"%s\".", hash.GetHex().c_str()));
      }

      txdb.Close();
    }

    if (!usde_ConnectInputs(&tx, mapInputs, mapUnused, CDiskTxPos(0,0,0), GetBestBlockIndex(USDE_COIN_IFACE), false, false)) {
      return (error(SHERR_INVAL, "(usde) CTxMemPool.AcceptTx: error connecting inputs for submitted tx \"%s\".", hash.GetHex().c_str()));
    }
  }

  Debug("(usde) mempool accepted tx \"%s\".", hash.ToString().c_str());
#endif
  return true;
}

int64 USDE_CTxMemPool::CalculateSoftFee(CTransaction& tx)
{
  return (usde_CalculateFee(tx));
}

int64 USDE_CTxMemPool::IsFreeRelay(CTransaction& tx, tx_cache& mapInputs)
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
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


