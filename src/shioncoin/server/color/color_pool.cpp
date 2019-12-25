
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
#include "color_pool.h"
#include "color_block.h"
#include "color_wallet.h"
#include "color_txidx.h"
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

bool color_ConnectInputs(CTransaction *tx, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner);


static int64 color_CalculateFee(const CTransaction& tx)
{
  CIface *iface = GetCoinByIndex(COLOR_COIN_IFACE);
  CWallet *wallet = GetWallet(COLOR_COIN_IFACE);
  int64 nBytes;
  int64 nFee;

  nBytes = wallet->GetVirtualTransactionSize(tx);

  /* base fee */
	nFee = (int64)MIN_RELAY_TX_FEE(iface);
  nFee = MIN_TX_FEE(iface) * (nBytes / 1000);

  /* dust penalty */
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    if (out.nValue < CENT)
      nFee += MIN_TX_FEE(iface);
  }

  nFee = MIN(nFee, (int64)MAX_TRANSACTION_FEE(iface) - 1);

  return (nFee);
}

bool COLOR_CTxMemPool::revert(CTransaction &tx)
{
  CWallet *pwallet = GetWallet(COLOR_COIN_IFACE);
  pwallet->EraseFromWallet(tx.GetHash());
  return (tx.DisconnectInputs(COLOR_COIN_IFACE));
}

int64_t COLOR_CTxMemPool::GetSoftWeight()
{
  return (COLOR_MAX_STANDARD_TX_WEIGHT);
}

int64_t COLOR_CTxMemPool::GetSoftSigOpCost()
{
  return (COLOR_MAX_STANDARD_TX_SIGOP_COST);
}

bool COLOR_CTxMemPool::VerifyCoinStandards(CTransaction& tx, tx_cache& mapInputs)
{

	if (tx.GetVersion() > 2)
		return (false);

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
    CSignature sig(COLOR_COIN_IFACE, txSig, i);
    if (!EvalScript(sig, stack, tx.vin[i].scriptSig, SIGVERSION_BASE, SCRIPT_VERIFY_LOW_S)) {
      return (error(SHERR_INVAL, "(color) "
            "CTxMemPool.VerifyCoinStandards: error evaluating signature. [SCRIPT_VERIFY_LOW_S]"));
    }
    //Debug("(color) CTxMemPool.VerifyCoinStandards: info: (BIP 66) verified DER signature <%d bytes>.", (int)tx.vin[i].scriptSig.size());
  }
  return (true);
}

bool COLOR_CTxMemPool::AcceptTx(CTransaction& tx)
{
  return true;
}


static int64 color_CalculateSoftFee(CTransaction& tx)
{
	return (0);
}


int64 COLOR_CTxMemPool::CalculateSoftFee(CTransaction& tx)
{
  return (color_CalculateSoftFee(tx));
}

int64 COLOR_CTxMemPool::IsFreeRelay(CTransaction& tx, tx_cache& mapInputs)
{
	return (true);
}

double COLOR_CTxMemPool::CalculateFeePriority(CPoolTx *ptx)
{
	return (sqrt(ptx->dPriority) * (double)ptx->nFee);
}


void COLOR_CTxMemPool::EnforceCoinStandards(CTransaction& tx)
{
}
