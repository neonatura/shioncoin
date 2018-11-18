
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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

#include <vector>

#include "shcoind.h"
#include "block.h"
#include "db.h"
#include "wallet.h"
#include "script.h"
#include "txsignature.h"
#include "txmempool.h"
#include "chain.h"

using namespace std;

static const uint256 _blank_hash = 0;

extern unsigned int color_GetTotalBlocks();


/**
 * Write specific amount of available coins per transaction output.
 */
bool WriteTxCoins(uint256 hash, int ifaceIndex, const vector<uint256>& vOuts)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockCoinChain(iface);
  unsigned char *data;
  char errbuf[1024];
  size_t data_len;
  int txPos;
  int idx;
  int err;

  if (!bc) {
    error(SHERR_IO, "CTransaction::WriteCoinSpent: error opening coin chain.");
    return (false);
  }

  txPos = -1;
  data = NULL;
  data_len = (32 * vOuts.size());
  err = bc_idx_find(bc, hash.GetRaw(), NULL, &txPos);
  if (!err) { /* exists */
    err = bc_get(bc, txPos, (unsigned char **)&data, &data_len);
    if (err) {
      return (error(err, "CTransaction.WriteCoinSpent: error obtaining data for db-index #%u.", (unsigned int)txPos));
    }
    if (data_len < (32 * vOuts.size())) {
      free(data);
      return (error(err, "CTransaction.WriteCoinSpent: data content truncated <%d bytse> for db-index #%u.", data_len, (unsigned int)txPos));
    }
  }

  if (!data) {
    for (idx = 0; idx < vOuts.size(); idx++) {
      if (_blank_hash != vOuts[idx])
        break;
    }
    if (idx == vOuts.size()) {
      /* nothing to save */
      return (true);
    }

    /* fresh */
    data = (unsigned char *)calloc(1, data_len);
    if (!data) {
      return (error(SHERR_NOMEM, "CTransaction.WriteCoinSpent: unable to allocate <%u bytes>", (unsigned int)data_len));
    }
  }

  bool fChanged = false;
  for (idx = 0; idx < vOuts.size(); idx++) {
    cbuff buff(vOuts[idx].begin(), vOuts[idx].end());
    if (0 == memcmp(data + (32 * idx), buff.data(), 32))
      continue;

    memcpy(data + (32 * idx), buff.data(), 32);
    fChanged=true;
  }
  if (!fChanged) {
    free(data);
    return (true);
  }

  /* store new coin outputs */
  if (txPos < 0) {
    err = bc_append(bc, hash.GetRaw(), data, data_len);
  } else {
    err = bc_write(bc, txPos, hash.GetRaw(), data, data_len);
  }
  free(data);
  if (err < 0)
    return (error(err, "WriteTxCoins"));

  return (true);
}

bool CTransaction::WriteCoins(int ifaceIndex, const vector<uint256>& vOuts)
{

  if (vOuts.size() != vout.size()) {
    return (error(SHERR_INVAL, "CTransaction.WriteCoins: tx \"%s\": vOuts.size(%d) != vout.size(%d)\n", GetHash().GetHex().c_str(), vOuts.size(), vout.size()));
  }

  return (WriteTxCoins(GetHash(), ifaceIndex, vOuts));
}

/**
 * Mark a transaction output as being spent.
 * @note Called from the originating (input) transaction.
 */
bool CTransaction::WriteCoins(int ifaceIndex, int nOut, const uint256& hashTxOut)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockCoinChain(iface);
  uint256 hash = GetHash();
  unsigned char *data;
  char errbuf[1024];
  size_t data_len;
  int txPos;
  int idx;
  int err;

  if (!bc) {
    error(SHERR_IO, "CTransaction::WriteCoinSpent: error opening coin chain.");
    return (false);
  }

  if (nOut < 0 || nOut >= vout.size())
    return (false);

  txPos = -1;
  data = NULL;
  data_len = (32 * vout.size());
  err = bc_idx_find(bc, hash.GetRaw(), NULL, &txPos);
  if (!err) { /* exists */
    err = bc_get(bc, txPos, (unsigned char **)&data, &data_len);
    if (err) {
      return (error(err, "CTransaction.WriteCoinSpent: error obtaining data for db-index #%u.", (unsigned int)txPos));
    }
    if (data_len < (32 * vout.size())) {
      free(data);
      return (error(err, "CTransaction.WriteCoinSpent: data content truncated <%d bytse> for db-index #%u.", data_len, (unsigned int)txPos));
    }
  }

  if (!data) {
    if(hashTxOut == _blank_hash)
      return (true); /* nothing changed */

    /* fresh */
    data = (unsigned char *)calloc(1, data_len);
    if (!data) {
      return (error(SHERR_NOMEM, "CTransaction.WriteCoinSpent: unable to allocate <%u bytes>", (unsigned int)data_len));
    }

  }

  cbuff buff(hashTxOut.begin(), hashTxOut.end());
  if (0 == memcmp(data + (32 * nOut), buff.data(), 32)) {
    free(data);
    return (true);
  }

  /* store new coin output */
  memcpy(data + (32 * nOut), buff.data(), 32);
  if (txPos < 0) {
    err = bc_append(bc, hash.GetRaw(), data, data_len);
    if (err) {
      free(data);
      return (false);
    }
  } else {
    err = bc_write(bc, txPos, hash.GetRaw(), data, data_len);
    if (err < 0) {
      free(data);
      return (error(err, "CTransaction.WriteCoinSpent: error writing <%d bytes> to db-index #%u.", data_len, (unsigned int)txPos));
    }
  }

  free(data);
  return (true);
}


/**
 * Obtain all of the established outputs for a transaction.
 * @note Called from the originating (input) transaction.
 */
bool CTransaction::ReadCoins(int ifaceIndex, vector<uint256>& vOuts)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockCoinChain(iface);
  uint256 hash = GetHash();
  unsigned char *data;
  char errbuf[1024];
  size_t data_len;
  int txPos;
  int idx;
  int err;

  if (!bc) {
    unet_log(ifaceIndex, "CTransaction::ReadCoins: error opening coin chain.");
    return (false);
  }

  txPos = -1;
  data_len = 0;
  data = NULL;
  err = bc_idx_find(bc, hash.GetRaw(), NULL, &txPos);
  if (!err) { /* exists */
    err = bc_get(bc, txPos, (unsigned char **)&data, &data_len);
    if (err) {
      return (error(err, "CTransaction.ReadCoins: error obtaining data for db-index #%u.", (unsigned int)txPos));
    }
    if (data_len < (32 * vout.size())) {
      free(data);
      return (error(err, "CTransaction.ReadCoins: data content truncated <%d bytse> for db-index #%u.", data_len, (unsigned int)txPos));
    }
  } else {
    /* all coins are still available. */
  }

  vOuts.clear();
  vOuts.resize(vout.size());

  for (idx = 0; idx < vout.size(); idx++) {
    if (data) {
      cbuff raw(data + (32 * idx), data + ((32 * idx) + 32));
      vOuts[idx] = uint256(raw);
    } else {
      vOuts[idx] = _blank_hash;
    }
  }
  if (data)
    free(data);
  
  return (true);
}

bool HasTxCoins(CIface *iface, uint256 hash)
{
  if (!iface || !iface->enabled) return (false);

  bc_t *bc = GetBlockCoinChain(iface);
  int txPos;
  int err;

  err = bc_idx_find(bc, hash.GetRaw(), NULL, &txPos);
  if (!err)
    return (true);

  return (false);
}


bool EraseTxCoins(CIface *iface, uint256 hash)
{
  bc_t *bc = GetBlockCoinChain(iface);
  char errbuf[1024];
  int txPos;
  int err;

  if (!bc) {
    error(SHERR_IO, "CTransaction::WriteCoinSpent: error opening coin chain.");
    return (false);
  }

  err = bc_idx_find(bc, hash.GetRaw(), NULL, &txPos);
  if (!err) { /* exists */
    err = bc_clear(bc, txPos);
    if (err) {
      return (error(err, "CTransaction.WriteCoinSpent: error clearing data for db-index #%u.", (unsigned int)txPos));
    }
    bc_table_reset(bc, hash.GetRaw());
  }

  return (true);
}

bool CTransaction::EraseCoins(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!iface || !iface->enabled)
    return (false);

  return (EraseTxCoins(iface, GetHash()));
}





typedef map< uint256, vector<uint256> > tx_map;

bool core_VerifyCoinInputs(int ifaceIndex, CTransaction& tx, unsigned int nIn, CTxOut& prev)
{
  CTxIn& in = tx.vin[nIn];
  vector<vector<unsigned char> > vSolutions;
  txnouttype whichType;

  // get the scriptPubKey corresponding to this input:
  const CScript& prevScript = prev.scriptPubKey;
  if (!Solver(prevScript, whichType, vSolutions))
    return false;
  int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
  if (nArgsExpected < 0)
    return false;

  // Transactions with extra stuff in their scriptSigs are
  // non-standard. Note that this EvalScript() call will
  // be quick, because if there are any operations
  // beside "push data" in the scriptSig the
  // IsStandard() call returns false
  vector<vector<unsigned char> > stack;
  CSignature sig(ifaceIndex, &tx, nIn);
  if (!EvalScript(sig, stack, in.scriptSig, 0, 0))
    return false;

  if (whichType == TX_SCRIPTHASH)
  {
    if (stack.empty())
      return false;
    CScript subscript(stack.back().begin(), stack.back().end());
    vector<vector<unsigned char> > vSolutions2;
    txnouttype whichType2;
    if (!Solver(subscript, whichType2, vSolutions2))
      return false;
    if (whichType2 == TX_SCRIPTHASH)
      return false;

    int tmpExpected;
    tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
    if (tmpExpected < 0)
      return false;
    nArgsExpected += tmpExpected;
  }

  if (stack.size() != (unsigned int)nArgsExpected)
    return false;

  return (true);
}

//int core_ConnectCoinInputs(int ifaceIndex, CTransaction *tx, const CBlockIndex* pindexBlock, tx_map& mapOutput, map<uint256, CTransaction> mapTx, int& nSigOps, int64& nFees, bool fVerifySig = true, bool fVerifyInputs = false);

bool core_ConnectCoinInputs(int ifaceIndex, CTransaction *tx, const CBlockIndex* pindexBlock, tx_map& mapOutput, map<uint256, CTransaction>& mapTx, int& nSigOps, int64& nFees, bool fVerifySig, bool fVerifyInputs, bool fRequireInputs, CBlock *pBlock)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  const bool fMiner = false;
  bool fFound;


  if (!iface || !iface->enabled)
    return (false);

  if (tx->IsCoinBase())
    return (true);

	int nVerifyFlags = GetBlockScriptFlags(iface, pindexBlock);

  nSigOps += tx->GetLegacySigOpCount();

  int64 nValueIn = 0;
  uint256 prevblockhash;
  for (unsigned int i = 0; i < tx->vin.size(); i++) {
    COutPoint prevout = tx->vin[i].prevout;
    CTransaction prevtx;

    fFound = false;
    prevblockhash.SetNull();
    if (GetTransaction(iface, prevout.hash, prevtx, &prevblockhash)) {
      /* exists in block-chain */
      fFound = true;
    } else {
      /* check prev tx from single transactions in memory */
      CTxMemPool *mempool = GetTxMemPool(iface);
      if (mempool->exists(prevout.hash)) {
        /* exists in memory pool */
        prevtx = mempool->lookup(prevout.hash);
        fFound = true;
      }
    }
    if (!fFound && pBlock) {
      /* check block itself */
      const CTransaction *inBlockTx = pBlock->GetTx(prevout.hash);
      if (inBlockTx) {
        prevtx.Init(*inBlockTx);
        fFound = true;
      }
    }

    if (!fFound) {
      if (fRequireInputs) {
        return error(SHERR_INVAL, "core_ConnectCoinInputs: input tx \"%s\" is invalid.", prevout.hash.GetHex().c_str());
      }

      /* allow tx orphans */
    }

    if (prevout.n >= prevtx.vout.size()) {
      /* invalid tx param */
      return (error(SHERR_INVAL, "core_ConnectInputs: invalid param"));
    }

    if (!MoneyRange(ifaceIndex, prevtx.vout[prevout.n].nValue)) {
      /* invalid coin value */
      return (error(SHERR_INVAL, "core_ConnectInputs: invalid money range"));
    }

    if (prevtx.IsCoinBase()) {
      if (prevblockhash.IsNull()) {
        return (error(SHERR_INVAL, "core_ConnectInputs: empty block reference"));
      }

      CBlockIndex *previndex = GetBlockIndexByHash(ifaceIndex, prevblockhash);
      if (!previndex) { /* invalid block */
        return (error(SHERR_INVAL, "core_ConnectInputs: invalid block reference"));
      }

			CWallet *wallet = GetWallet(iface);
			unsigned int nDepth = (unsigned int)(pindexBlock->nHeight - previndex->nHeight);
			unsigned int nMaturity = (unsigned int)wallet->GetCoinbaseMaturity(pBlock->hColor);
			if (nDepth < nMaturity) {
				/* immature */
				return (error(SHERR_INVAL, "core_ConnectInputs: immature coinbase [%d < %d]", nDepth, nMaturity));
      }
    }

    vector<uint256> outs;
    if (mapOutput.count(prevout.hash) != 0) {
      outs = mapOutput[prevout.hash];
    } else {
      if (!prevtx.ReadCoins(ifaceIndex, outs)) {
        /* db err */
        return (error(SHERR_IO, "core_ConnectInputs: error obtaining spent coins"));
      }
    }

    if (outs.size() != prevtx.vout.size()) {
      /* internal err */
      return (error(SHERR_IO, "core_ConnectInputs: error obtaining spent coins"));
    }

    if (!outs[prevout.n].IsNull() && /* spent on something */
        outs[prevout.n] != tx->GetHash()) { /* check for repeat */ 
      /* already spent */
      return (error(SHERR_INVAL, "core_ConnectInputs: double spend"));
    }


    nValueIn += prevtx.vout[prevout.n].nValue;


    if (fVerifySig) {
      if (!VerifySignature(ifaceIndex, prevtx, *tx, i, 0, nVerifyFlags)) {
        return (error(SHERR_ACCESS, "core_ConnectCoinInputs: error verifying signature integrity."));
      }
    }

    if (fVerifyInputs &&
        !core_VerifyCoinInputs(ifaceIndex, *tx, i, prevtx.vout[prevout.n])) {
      return (error(SHERR_ACCESS, "core_ConnectCoinInputs: error verifying coin inputs integrity."));
    }

    /* add up output values */
    nValueIn += prevtx.vout[prevout.n].nValue;

    /* cache tx */
    mapTx[prevout.hash] = prevtx;

    /* mark spent */ 
    outs[prevout.n] = tx->GetHash();
    mapOutput[prevout.hash] = outs;

    /* count signature script ops */
    if (prevtx.vout[prevout.n].scriptPubKey.IsPayToScriptHash())
      nSigOps += prevtx.vout[prevout.n].scriptPubKey.GetSigOpCount(tx->vin[i].scriptSig);
  }

  int64 nTxFee = nValueIn - tx->GetValueOut();
  if (!MoneyRange(ifaceIndex, nTxFee)) {
    return error(SHERR_INVAL, "ConnectInputs() : nFees out of range");
  }
  if (!MoneyRange(ifaceIndex, nValueIn)) {
    /* output value exceeds input value or intput value out of range. */
    return error(SHERR_INVAL, "core_ConnectCoinInputs: tx \"%s\": value in < value out", tx->GetHash().ToString().c_str());
  }
  if (nValueIn < tx->GetValueOut()) {
    /* input value out of range. */
    return error(SHERR_INVAL, "core_ConnectCoinInputs: tx \"%s\": invalid input value", tx->GetHash().ToString().c_str());
  }

  nFees += nTxFee;

  return (true);
}

bool CTransaction::ConnectInputs(int ifaceIndex, const CBlockIndex* pindexBlock, tx_map& mapOutput, map<uint256, CTransaction> mapTx, int& nSigOps, int64& nFees, bool fVerifySig, bool fVerifyInputs, bool fRequireInputs)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CBlock *block = NULL;
  bool ok;

  if (pindexBlock) {
    block = GetBlockByHeight(iface, pindexBlock->nHeight);
  }

  ok = core_ConnectCoinInputs(ifaceIndex, this, pindexBlock, mapOutput, mapTx, nSigOps, nFees, fVerifySig, fVerifyInputs, fRequireInputs, block);
  if (block)
    delete block;

  return (ok);
}


bool core_ConnectBlock(CBlock *block, CBlockIndex* pindex)
{
  CIface *iface = GetCoinByIndex(block->ifaceIndex);
  CWallet *wallet = GetWallet(iface);
  shtime_t ts;
  int err;

	unsigned int nHeight = (pindex->pprev ? (pindex->pprev->nHeight+1) : 0);

	/* enforce BIP30 / BIP34 */
	bool fEnforceBIP30 = false;
	bool fEnforceBIP34 = false;
	fEnforceBIP34 = (iface->BIP34Height != -1 && nHeight >= iface->BIP34Height);
	if (!fEnforceBIP34)
		fEnforceBIP30 = (iface->BIP30Height != -1 && nHeight >= iface->BIP30Height);
	if (fEnforceBIP30) {
		BOOST_FOREACH(CTransaction& tx, block->vtx) {
			const uint256& hTx = tx.GetHash();
			CTransaction cmp_tx;
			uint256 hPrevBlock;

			if (GetTransaction(iface, hTx, cmp_tx, &hPrevBlock) == false) {
				continue;
			}
			if (hPrevBlock == block->GetHash()) {
				continue; /* itself */
			}

			int i;
			vector<uint256> vOuts;
			tx.ReadCoins(block->ifaceIndex, vOuts);
			for (i = 0; i < vOuts.size(); i++) {
				if (vOuts[i].IsNull())
					break; /* not spent */
			}
			if (i != vOuts.size()) {
				/* attempting to re-use a tx hash with unspent output(s). */
				return (error(ERR_INVAL, "(%s) core_AcceptBlock: rejecting block \"%s\" with duplicate transaction hash (%s) of block \"%s\" [BIP30].", iface->name, block->GetHash().GetHex().c_str(), hTx.GetHex().c_str(), hPrevBlock.GetHex().c_str()));
			}
		}
	}
	if (block->ifaceIndex != EMC2_COIN_IFACE &&
			block->ifaceIndex != USDE_COIN_IFACE &&
			block->ifaceIndex != LTC_COIN_IFACE) {
		/* non-standard */
		if (fEnforceBIP34) {
			BOOST_FOREACH(CTransaction& tx, block->vtx) {
				CTransaction tmp_tx;
				uint256 hBlock;
				if (GetTransaction(iface, tx.GetHash(), tmp_tx, &hBlock)) {
					if (hBlock != block->GetHash())
						return (error(ERR_INVAL, "(%s) core_AcceptBlock: rejecting block with non-unique transaction hash (%s) [BIP34].", iface->name, tx.GetHash().GetHex().c_str()));
				}
			}
		}
	}

  int64 nFees = 0;
  int nSigOps = 0;
  tx_map mapOutputs;
  map<uint256, CTransaction> mapTx;
  BOOST_FOREACH(CTransaction& tx, block->vtx) {
    uint256 hashTx = tx.GetHash();

    if (!core_ConnectCoinInputs(block->ifaceIndex, &tx, pindex, mapOutputs, mapTx, nSigOps, nFees, true, false, true, block))
      return (false);
  }
  if (nSigOps > MAX_BLOCK_SIGOPS(iface)) /* too many puppies */
    return error(SHERR_INVAL, "ConnectBlock() : too many sigops");
  if (block->vtx[0].GetValueOut() > 
      wallet->GetBlockValue(nHeight, nFees)) {
    return (error(SHERR_INVAL, "core_ConnectBlock: coinbaseValueOut(%f) > BlockValue(%f) @ height %d [fee %llu]\n", ((double)block->vtx[0].GetValueOut()/(double)COIN), ((double)wallet->GetBlockValue(nHeight, nFees)/(double)COIN), nHeight, (unsigned long long)nFees)); 
  }

  /* success */

  /* commit queued spends */
  for (tx_map::iterator mi = mapOutputs.begin(); mi != mapOutputs.end(); ++mi) {
    uint256 prevhash = (*mi).first;
    vector<uint256>& outs = (*mi).second;
    CTransaction& prevtx = mapTx[prevhash];

    if (!prevtx.WriteCoins(block->ifaceIndex, outs)) {
      /* db err */
      return error(SHERR_INVAL, "core_ConnectBlock: error writing to coin chain.");
    }
  }

  if (pindex->pprev)
  {
    timing_init("ConnectBlock/WriteBlock", &ts);
		bool ok = false;
		if (block->ifaceIndex == COLOR_COIN_IFACE) {
			/* multiple chains require manual lookup. */
			uint64_t nCommitHeight = (uint64_t)color_GetTotalBlocks();
			ok = block->WriteBlock(nCommitHeight);
		} else {
			pindex->nHeight = pindex->pprev->nHeight + 1;
			ok = block->WriteBlock(pindex->nHeight);
		}
    timing_term(block->ifaceIndex, "ConnectBlock/WriteBlock", &ts);
    if (!ok) {
      return (error(SHERR_INVAL, "(%s) ConnectBlock: error writing block hash '%s' to height %d\n", iface->name, pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight));
    }
  }

  /* update wallet */
  timing_init("ConnectBlock/AddToWallet", &ts);
  BOOST_FOREACH(CTransaction& tx, block->vtx) {
    wallet->AddToWalletIfInvolvingMe(tx, block, true); 
  }
  timing_term(block->ifaceIndex, "ConnectBlock/AddToWallet", &ts);

  return true;
}

#if 0
bool CBlock::ConnectBlock(CBlockIndex* pindex)
{
  return (core_ConnectBlock(this, pindex));
}
#endif



static bool core_DisconnectCoinInputs(CWallet *wallet, CTransaction& prevTx, const COutPoint& prevout)
{
	if (!wallet) return (false);
  CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	const uint256& prevhash = prevout.hash;
	int nTxOut = prevout.n;
	vector<uint256> vOuts;


	if (!prevTx.ReadCoins(wallet->ifaceIndex, vOuts))
		return (true); /* nothing to do */

	/* sanity */
	if (nTxOut >= vOuts.size())
		return (false); /* invalid */

	if (vOuts[nTxOut].IsNull())
		return (true); /* already marked as unspent. */

	/* set output as unspent */
	vOuts[nTxOut].SetNull();
	if (!prevTx.WriteCoins(wallet->ifaceIndex, vOuts))
		return (false);

	Debug("(%s) DisconnectCoinInputs: marked tx \"%s\" output #%d as unspent in coin-fmap.\n", iface->name, prevhash.GetHex().c_str(), prevout.n); 
	return (true);
}

static bool core_DisconnectWalletInputs(CWallet *wallet, const COutPoint& prevout)
{
	if (!wallet) return (false);
  CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	const uint256& prevhash = prevout.hash;

	if (wallet->mapWallet.count(prevhash) == 0)
		return (true); /* all done */

	CWalletTx& wtx = wallet->mapWallet[prevhash];
	vector<char> vfNewSpent = wtx.vfSpent;
	vfNewSpent.resize(wtx.vout.size());
	if (vfNewSpent[prevout.n] == false)
		return (true); /* already marked as unspent. */

	/* mark output as unspent */
	vfNewSpent[prevout.n] = false;
	wtx.vfSpent = vfNewSpent;
	wtx.fAvailableCreditCached = false;
	if (!wtx.WriteToDisk())
		return (false);

	Debug("(%s) core_DisconnectCoinInputs: marked tx \"%s\" output #%d as unspent in wallet.\n", iface->name, prevhash.GetHex().c_str(), prevout.n); 
	return (true);
}


bool core_DisconnectInputs(int ifaceIndex, CTransaction *tx)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);

	if (!wallet || !tx)
		return (false);

  // Relinquish previous transactions' spent pointers
  uint256 hash = tx->GetHash();
  if (!tx->IsCoinBase())
  {
		tx_cache inputs;
		wallet->FillInputs((const CTransaction)*tx, inputs, true); /* for coin db */

		BOOST_FOREACH(const CTxIn& txin, tx->vin)
    {
      COutPoint prevout = txin.prevout;
			core_DisconnectWalletInputs(wallet, prevout);

			if (inputs.count(prevout.hash) != 0) 
				core_DisconnectCoinInputs(wallet, inputs[prevout.hash], prevout);
    }
  }

  if (IsCertTx(*tx)) {
    if (!DisconnectCertificate(iface, *tx)) {
      error(SHERR_INVAL, "core_DisconnectInputs: error disconnecting certificate tx.");
    }
  }
  if (IsAliasTx(*tx)) {
    if (!DisconnectAliasTx(iface, *tx)) {
      error(SHERR_INVAL, "core_DisconnectInputs: error disconnecting alias tx.");
    }
  }
  if (IsContextTx(*tx)) {
    if (!DisconnectContextTx(iface, *tx)) {
      error(SHERR_INVAL, "core_DisconnectInputs: error disconnecting context tx.");
    }
  }

	int mode;
	if (IsExecTx(*tx, mode)) {
		if (!DisconnectExecTx(iface, *tx, mode)) {
      error(SHERR_INVAL, "core_DisconnectInputs: error disconnecting exec tx [mode %d].", mode);
		}
	}

	if (IsAssetTx(*tx)) {
		if (!DisconnectAssetTx(iface, *tx)) {
      error(SHERR_INVAL, "core_DisconnectInputs: error disconnecting asset tx.");
		}
	}

	if (IsOfferTx(*tx)) {
		DisconnectOfferTx(iface, *tx);
	}

	/* erase from disk/mem wallet tx map */
  wallet->EraseFromWallet(hash);

  /* erase from 'coin' fmap */
  tx->EraseCoins(ifaceIndex);

  /* erase from 'tx' fmap */
  tx->EraseTx(ifaceIndex);

  return (true);
}

bool CTransaction::DisconnectInputs(int ifaceIndex)
{
  return (core_DisconnectInputs(ifaceIndex, this));
}




void WriteHashBestChain(CIface *iface, uint256 hash)
{
  char opt_name[256];
  char buf[256];

  if (!iface || !iface->enabled)
    return;

  memset(buf, 0, sizeof(buf));
  sprintf(buf, "%s", hash.GetHex().c_str());
  sprintf(opt_name, "shcoind.%s.chain", iface->name);
  shpref_set(opt_name, buf);

  Debug("(%s) WriteHashBestChain: stored hash \"%s\".", iface->name, hash.GetHex().c_str());
}

bool ReadHashBestChain(CIface *iface, uint256& ret_hash)
{
  char opt_name[256];
  char buf[256];

  if (!iface || !iface->enabled)
    return (false);

  memset(buf, 0, sizeof(buf));
  sprintf(opt_name, "shcoind.%s.chain", iface->name);
  strncpy(buf, shpref_get(opt_name, ""), sizeof(buf)-1);

  ret_hash = uint256(buf);
  return (!ret_hash.IsNull());
}

/*
 * todo: potentially wipe arch rec. erase pblockindex chain
 */
bool core_Truncate(CIface *iface, uint256 hash)
{
  if (!iface || !iface->enabled) return (false);
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);
  CBlockIndex *pBestIndex;
  CBlockIndex *cur_index;
  CBlockIndex *pindex;
  unsigned int nHeight;
  int err;

  if (!blockIndex || !blockIndex->count(hash))
    return error(SHERR_INVAL, "Erase: block not found in block-index.");

	if (blockIndex->count(hash) == 0)
		return false;
  cur_index = (*blockIndex)[hash];
  if (!cur_index)
    return error(SHERR_INVAL, "Erase: block not found in block-index.");

  pBestIndex = GetBestBlockIndex(iface);
  if (!pBestIndex)
    return error(SHERR_INVAL, "Erase: no block-chain established.");
  if (cur_index->nHeight > pBestIndex->nHeight)
    return error(SHERR_INVAL, "Erase: height is not valid.");

	int nTotal;
	{
		CBlock *block = GetBlockByHash(iface, pBestIndex->GetBlockHash());
		nTotal = block->GetTotalBlocksEstimate();
		delete block;
	}
	if (cur_index->nHeight <= nTotal) {
		return error(SHERR_INVAL, "(%s) Truncate: cannot truncate previous to last checkpoint at height %d.", iface->name, nTotal);
	}

	/* sanity: erase potential blocks higher than our tip */
	bc_t *bc = GetBlockChain(iface);
	unsigned int nMinHeight = pBestIndex->nHeight;
	unsigned int nMaxHeight = 0;
	if (0 == bc_idx_next(bc, &nMaxHeight)) { /* highest disk block index */
		for (int idx = (nMaxHeight-1); idx > nMinHeight; idx--) {
			bc_clear(bc, idx);
			CBlockIndex *tpindex = GetBlockIndexByHeight(ifaceIndex, idx);
			if (tpindex)
				bc_table_reset(bc, tpindex->GetBlockHash().GetRaw());
		}
	}

	/* mem: disconnect blocks from chain. */
	pindex = pBestIndex;
	for(; pindex && pindex != cur_index; pindex = pindex->pprev) {
		CBlock *block = GetBlockByHeight(iface, pindex->nHeight);
		if (block) {
			block->DisconnectBlock(pindex);
			delete block;
		}
	}

	{
		bc_t *bc = GetBlockChain(iface);
		/* disk: remove all blocks from block-chain. */
		pindex = pBestIndex;
		for(; pindex && pindex != cur_index; pindex = pindex->pprev) {
			bc_clear(bc, pindex->nHeight);
			bc_table_reset(bc, pindex->GetBlockHash().GetRaw());
		}
	}
	/* since there may be lingering memory references to the block chain we can not remove it. instead, mark the previous chain as if it were only headers. */
	pindex = pBestIndex;
	for(; pindex && pindex != cur_index; pindex = pindex->pprev) {
		pindex->pnext = NULL;
	}
  cur_index->pnext = NULL;

	/* establish new tip */
	wallet->bnBestChainWork = cur_index->bnChainWork;
  SetBestBlockIndex(iface, cur_index);
  WriteHashBestChain(iface, cur_index->GetBlockHash());

	/* initialize a re-download. */
	iface->blockscan_max = 0;
  InitServiceBlockEvent(ifaceIndex, cur_index->nHeight);

  return (true);
}

bool UpdateBlockCoins(CBlock& block)
{
  CIface *iface = GetCoinByIndex(block.ifaceIndex);
  CWallet *wallet = GetWallet(iface);

  if (!iface || !iface->enabled || !wallet)
    return (false);

  tx_cache inputs;
  BOOST_FOREACH(const CTransaction& tx, block.vtx) {
    if (tx.IsCoinBase()) continue;
    if (!wallet->FillInputs(tx, inputs))
      return (false);
  }

  BOOST_FOREACH(const CTransaction& tx, block.vtx) {
    if (tx.IsCoinBase()) continue;

    const uint256& tx_hash = tx.GetHash();
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
      if (inputs.count(txin.prevout.hash) == 0) continue; /* fail-safe */
      CTransaction& l_tx = inputs[txin.prevout.hash];

      vector<uint256> vOuts;
      int nOut = txin.prevout.n;
      if (l_tx.ReadCoins(block.ifaceIndex, vOuts) &&
          nOut < vOuts.size() && vOuts[nOut] != tx_hash) {
        /* correction */
        vOuts[nOut] = tx_hash;
        if (l_tx.WriteCoins(block.ifaceIndex, vOuts)) {
          Debug("(%s) UpdateBlockCoins: updated tx \"%s\" spent by \"%s\".", iface->name, txin.prevout.hash.GetHex().c_str(), tx_hash.GetHex().c_str());
        }
      }
    }
  }

  return (true);
}

string FormatMoney(CAmount n)
{

	int64_t n_abs = (n > 0 ? n : -n);
	int64_t quotient = n_abs/COIN;
	int64_t remainder = n_abs%COIN;
	std::string str;
	int nTrim = 0;

	str = strprintf("%d.%08d", quotient, remainder);
	for (int i = str.size()-1; (str[i] == '0' && isdigit(str[i-2])); --i)
		++nTrim;
	if (nTrim)
		str.erase(str.size()-nTrim, nTrim);

	if (n < 0)
		str.insert((unsigned int)0, 1, '-');

	return str;
}

bool ParseMoney(const string& str, CAmount& nRet)
{
	return ParseMoney(str.c_str(), nRet);
}

bool ParseMoney(const char* pszIn, CAmount& nRet)
{
	string strWhole;
	CAmount nUnits = 0;
	const char* p;

	p = pszIn;
	while (isspace(*p))
		p++;
	for (; *p; p++) {
		if (*p == '.') {
			p++;
			CAmount nMult = CENT*10;
			while (isdigit(*p) && (nMult > 0))
			{
				nUnits += nMult * (*p++ - '0');
				nMult /= 10;
			}
			break;
		}
		if (isspace(*p))
			break;
		if (!isdigit(*p))
			return false;
		strWhole.insert(strWhole.end(), *p);
	}
	for (; *p; p++)
		if (!isspace(*p))
			return false;
	if (strWhole.size() > 10) // guard against 63 bit overflow
		return false;
	if (nUnits < 0 || nUnits > COIN)
		return false;

	CAmount nWhole = atoi64(strWhole);
	nRet = nWhole*COIN + nUnits;

	return true;
}


static vector<uint160> mapCoinHash;
static void InitCoinHash()
{
	int ifaceIndex;

	if (mapCoinHash.size() == 0) {
		for (ifaceIndex = 0; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
			uint160 hash = 0;

			if (ifaceIndex != COLOR_COIN_IFACE) { /* has no single genesis */
				CIface *iface = GetCoinByIndex(ifaceIndex);
				if (iface && iface->enabled) {
					uint256 hGen = GetGenesisBlockHash(ifaceIndex);
					cbuff raw(hGen.begin(), hGen.end());
					hash = Hash160(raw);
				}
			}

			mapCoinHash.push_back(hash);
		}
	}

}

uint160 GetCoinHash(string name)
{
	int ifaceIndex;

	if (mapCoinHash.size() == 0)
		InitCoinHash();

	ifaceIndex = GetCoinIndex(GetCoin(name.c_str()));
	if (ifaceIndex == -1)
		return (uint160());

	return (mapCoinHash[ifaceIndex]);
}

CIface *GetCoinByHash(uint160 hash)
{
	int ifaceIndex;

	if (mapCoinHash.size() == 0)
		InitCoinHash();

	for (ifaceIndex = 0; ifaceIndex < mapCoinHash.size(); ifaceIndex++) {
		if (mapCoinHash[ifaceIndex] == 0)
			continue;
		if (hash == mapCoinHash[ifaceIndex])
			return (GetCoinByIndex(ifaceIndex));
	}

	return (NULL);
}


