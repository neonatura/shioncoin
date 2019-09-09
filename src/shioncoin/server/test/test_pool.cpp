
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
#include "ui_interface.h"
#include "test_pool.h"
#include "test_block.h"
#include "test_wallet.h"
#include "test_txidx.h"
#include "chain.h"
#include "txsignature.h"
#include "bolo/bolo_validation03.h"

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


extern bool test_ConnectInputs(CTransaction *tx, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fStrictPayToScriptHash=true);




bool TEST_CTxMemPool::revert(CTransaction &tx)
{
  CWallet *pwallet = GetWallet(TEST_COIN_IFACE);
  pwallet->EraseFromWallet(tx.GetHash());
  return (tx.DisconnectInputs(TEST_COIN_IFACE));
}

#if 0
bool TEST_CTxMemPool::VerifyAccept(CTransaction &tx)
{
return (false);
}
#endif

int64_t TEST_CTxMemPool::GetSoftWeight()
{
  return (TEST_MAX_STANDARD_TX_WEIGHT);
}

int64_t TEST_CTxMemPool::GetSoftSigOpCost()
{
  return (TEST_MAX_STANDARD_TX_SIGOP_COST);
}

bool TEST_CTxMemPool::VerifyCoinStandards(CTransaction& tx, tx_cache& mapInputs)
{
	CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);

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
    if (!Solver(prevScript, whichType, vSolutions)) {
      return error(ERR_INVAL, "(test) VerifyCoinStandards: unable to solve script: %s", prev.scriptPubKey.ToString().c_str());
		}
    if (whichType == TX_NONSTANDARD) {
      return error(ERR_INVAL, "(test) VerifyCoinStandards: script is non-standard: %s", prev.scriptPubKey.ToString().c_str());
		}

    /* evaluate signature */
    vector<vector<unsigned char> > stack;
    CTransaction *txSig = (CTransaction *)this;
    CSignature sig(TEST_COIN_IFACE, txSig, i);
    if (!EvalScript(sig, stack, tx.vin[i].scriptSig, SIGVERSION_BASE, SCRIPT_VERIFY_LOW_S)) {
      return (error(SHERR_INVAL, "(test) "
            "CTxMemPool.VerifyCoinStandards: error evaluating signature. [SCRIPT_VERIFY_LOW_S]"));
    }
  }

  return (true);
}

void TEST_CTxMemPool::EnforceCoinStandards(CTransaction& tx)
{
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);

	if (tx.IsFinal(TEST_COIN_IFACE))
		return; /* n/a */

	/* detect notary tx */
	const uint256& hPrevTx = tx.vin[0].prevout.hash;
	if (tx.vin.size() == 1 && tx.vout.size() == 1 &&
			std::find(wallet->mapValidateTx.begin(), wallet->mapValidateTx.end(),
				hPrevTx) != wallet->mapValidateTx.end()) {
		CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
		CTransaction prev;

		if (!GetTransaction(iface, hPrevTx, prev, NULL))
			return;

		const CTxOut& out = prev.vout[tx.vin[0].prevout.n];
		if (tx.vout[0].nValue <= MIN_INPUT_VALUE(iface)) 
			UpdateValidateNotaryTx(iface, tx, out.scriptPubKey);
	}

	/* SIP31 */
	bolo_updatetx_master(tx);

}


bool TEST_CTxMemPool::AcceptTx(CTransaction& tx)
{
#ifdef USE_LEVELDB_COINDB
  uint256 hash = tx.GetHash();
  bool fCheckInputs = true;

  if (fCheckInputs) {
    bool fInvalid = false;
    map<uint256, CTxIndex> mapUnused;
    MapPrevTx mapInputs;
    {
      TESTTxDB txdb;

      /* ensure the transaction is unique. */
      if (txdb.ContainsTx(hash)) {
        txdb.Close();
        return false;
      }

      if (!tx.FetchInputs(txdb, mapUnused, NULL, false, mapInputs, fInvalid)) {
        txdb.Close();
        return (error(SHERR_INVAL, "(test) CTxMemPool.AcceptTx: error retrieiving input transactions for submitted tx \"%s\".", hash.GetHex().c_str()));
      }

      txdb.Close();
    }

    if (!test_ConnectInputs(&tx, mapInputs, mapUnused, CDiskTxPos(0,0,0), GetBestBlockIndex(TEST_COIN_IFACE), false, false)) {
      return (error(SHERR_INVAL, "(test) CTxMemPool.AcceptTx: error connecting inputs for submitted tx \"%s\".", hash.GetHex().c_str()));
    }
  }

  Debug("(test) mempool accepted tx \"%s\".", hash.ToString().c_str());
#endif
  return true;
}

static int64 test_CalculateSoftFee(CTransaction& tx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  int64 nBytes;
  int64 nFee;

  nBytes = wallet->GetVirtualTransactionSize(tx);

  /* base fee */
	nFee = (int64)MIN_RELAY_TX_FEE(iface);
  nFee += wallet->GetFeeRate() * (nBytes / 1000);

  /* dust penalty */
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    if (out.nValue < CENT)
      nFee += MIN_TX_FEE(iface);
  }

  nFee = MIN(nFee, (int64)MAX_TRANSACTION_FEE(iface) - 1);

  return (nFee);
}

int64 TEST_CTxMemPool::CalculateSoftFee(CTransaction& tx)
{
  return (test_CalculateSoftFee(tx));
}

int64 TEST_CTxMemPool::IsFreeRelay(CTransaction& tx, tx_cache& mapInputs)
{
	return (true);
}

double TEST_CTxMemPool::CalculateFeePriority(CPoolTx *ptx)
{
	return (sqrt(ptx->dPriority) * (double)ptx->nFee);
}
