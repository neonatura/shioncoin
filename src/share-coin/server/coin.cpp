
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
    uint256 blank_hash = 0;

    for (idx = 0; idx < vOuts.size(); idx++) {
      if (blank_hash != vOuts[idx])
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
    uint256 blank_hash = 0;

    if(hashTxOut == blank_hash)
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
    txPos = bc_append(bc, hash.GetRaw(), data, data_len);
    if (txPos < 0) {
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

  uint256 blank_hash = 0;
  for (idx = 0; idx < vout.size(); idx++) {
    if (data) {
      cbuff raw(data + (32 * idx), data + ((32 * idx) + 32));
      vOuts[idx] = uint256(raw);
    } else {
      vOuts[idx] = blank_hash;
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

static bool core_ConnectCoinInputs(int ifaceIndex, CTransaction *tx, const CBlockIndex* pindexBlock, tx_map& mapOutput, map<uint256, CTransaction>& mapTx, int& nSigOps, int64& nFees, bool fVerifySig, bool fVerifyInputs, bool fRequireInputs, CBlock *pBlock)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  const bool fStrictPayToScriptHash=true;
  const bool fMiner = false;
  bool fFound;

  if (!iface || !iface->enabled)
    return (false);

  if (tx->IsCoinBase())
    return (true);

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

      if ((pindexBlock->nHeight - previndex->nHeight) < iface->coinbase_maturity) {
        /* immature */
        return (error(SHERR_INVAL, "core_ConnectInputs: immature coinbase"));
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
      if (!VerifySignature(ifaceIndex, prevtx, *tx, i, fStrictPayToScriptHash, 0)) {
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
  bc_t *bc = GetBlockTxChain(iface);
  int err;

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
      wallet->GetBlockValue(pindex->nHeight, nFees)) {
    return (error(SHERR_INVAL, "core_ConnectBlock: coinbaseValueOut(%f) > BlockValue(%f) @ height %d [fee %llu]\n", ((double)block->vtx[0].GetValueOut()/(double)COIN), ((double)wallet->GetBlockValue(pindex->nHeight, nFees)/(double)COIN), pindex->nHeight, (unsigned long long)nFees)); 
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
    pindex->nHeight = pindex->pprev->nHeight + 1;
    if (!block->WriteBlock(pindex->nHeight)) {
      return (error(SHERR_INVAL, "shc_ConnectBlock: error writing block hash '%s' to height %d\n", pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight));
    }
  }

  /* update wallet */
  BOOST_FOREACH(CTransaction& tx, block->vtx) {
    wallet->AddToWalletIfInvolvingMe(tx, block, true); 
  }

  return true;
}

#if 0
bool CBlock::ConnectBlock(CBlockIndex* pindex)
{
  return (core_ConnectBlock(this, pindex));
}
#endif







#ifdef USE_LEVELDB_COINDB

bool CTransaction::DisconnectInputs(CTxDB& txdb)
{
  CIface *iface = GetCoinByIndex(txdb.ifaceIndex);

  // Relinquish previous transactions' spent pointers
  if (!IsCoinBase())
  {
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
      COutPoint prevout = txin.prevout;

      // Get prev txindex from disk
      CTxIndex txindex;
      if (!txdb.ReadTxIndex(prevout.hash, txindex))
        return error(SHERR_INVAL, "DisconnectInputs() : ReadTxIndex failed");

      if (prevout.n >= txindex.vSpent.size())
        return error(SHERR_INVAL, "DisconnectInputs() : prevout.n out of range");

      // Mark outpoint as not spent
      txindex.vSpent[prevout.n].SetNull();

      // Write back
      if (!txdb.UpdateTxIndex(prevout.hash, txindex))
        return error(SHERR_INVAL, "DisconnectInputs() : UpdateTxIndex failed");
    }
  }

  if (IsCertTx(*this)) {
    if (!DisconnectCertificate(iface, *this)) {
      error(SHERR_INVAL, "core_DisconnectInputs: error disconnecting certificate");
    }
  }
  if (IsAliasTx(*this)) {
    if (!DisconnectAliasTx(iface, *this)) {
      error(SHERR_INVAL, "core_DisconnectInputs: error disconnecting alias");
    }
  }
  if (IsContextTx(*this)) {
    if (!DisconnectContextTx(iface, *this)) {
      error(SHERR_INVAL, "core_DisconnectInputs: error disconnecting alias");
    }
  }

  // Remove transaction from index
  // This can fail if a duplicate of this transaction was in a chain that got
  // reorganized away. This is only possible if this transaction was completely
  // spent, so erasing it would be a no-op anway.
  txdb.EraseTxIndex(*this);

  /* erase from bc_tx.idx */
  EraseTx(txdb.ifaceIndex);

  {
    uint256 hash = GetHash();
    CWallet *wallet = GetWallet(iface);
    if (wallet->mapWallet.count(hash) != 0) {
      wallet->mapWallet.erase(hash); 
      Debug("DisconnectInputs: erased mapWallet tx '%s'\n", hash.GetHex().c_str());
    }
  }

  return true;
}

#else

bool core_DisconnectInputs(int ifaceIndex, CTransaction *tx)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);
  uint256 hash = tx->GetHash();
  uint256 blank_hash;

  // Relinquish previous transactions' spent pointers
  if (!tx->IsCoinBase())
  {
    BOOST_FOREACH(const CTxIn& txin, tx->vin)
    {
      COutPoint prevout = txin.prevout;
      vector<uint256> outs;
      CTransaction prevtx;

      if (!GetTransaction(iface, prevout.hash, prevtx, NULL)) {
        error(SHERR_INVAL, "core_DisconnectInputs: invalid input tx \"%s\".", prevout.hash.GetHex().c_str());
        continue;
      }

      prevtx.WriteCoins(ifaceIndex, prevout.n, blank_hash);
    }
  }

  if (IsCertTx(*tx)) {
    if (!DisconnectCertificate(iface, *tx)) {
      error(SHERR_INVAL, "core_DisconnectInputs: error disconnecting certificate");
    }
  }
  if (IsAliasTx(*tx)) {
    if (!DisconnectAliasTx(iface, *tx)) {
      error(SHERR_INVAL, "core_DisconnectInputs: error disconnecting alias");
    }
  }
  if (IsContextTx(*tx)) {
    if (!DisconnectContextTx(iface, *tx)) {
      error(SHERR_INVAL, "core_DisconnectInputs: error disconnecting alias");
    }
  }

  /* erase from 'coin' fmap */
  tx->EraseCoins(ifaceIndex);

  /* erase from 'tx' fmap */
  tx->EraseTx(ifaceIndex);

  wallet->EraseFromWallet(hash);
//  wallet->mapWallet.erase(hash); 

  return true;
}

bool CTransaction::DisconnectInputs(int ifaceIndex)
{
  return (core_DisconnectInputs(ifaceIndex, this));
}

#endif



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


bool core_Truncate(CIface *iface, uint256 hash)
{
  if (!iface || !iface->enabled) return (false);
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);
  CBlockIndex *pBestIndex;
  CBlockIndex *cur_index;
  CBlockIndex *pindex;
  unsigned int nHeight;
  int err;

  if (!blockIndex || !blockIndex->count(hash))
    return error(SHERR_INVAL, "Erase: block not found in block-index.");

  cur_index = (*blockIndex)[hash];
  if (!cur_index)
    return error(SHERR_INVAL, "Erase: block not found in block-index.");

  pBestIndex = GetBestBlockIndex(iface);
  if (!pBestIndex)
    return error(SHERR_INVAL, "Erase: no block-chain established.");
  if (cur_index->nHeight > pBestIndex->nHeight)
    return error(SHERR_INVAL, "Erase: height is not valid.");

  bc_t *bc = GetBlockChain(iface);
  unsigned int nMinHeight = cur_index->nHeight;
  unsigned int nMaxHeight = (bc_idx_next(bc)-1);
    
  for (nHeight = nMaxHeight; nHeight > nMinHeight; nHeight--) {
    CBlock *block = GetBlockByHeight(iface, nHeight);
    if (block) {
      uint256 t_hash = block->GetHash();
      if (hash == cur_index->GetBlockHash()) {
        delete block;
        break; /* bad */
      }

      if (blockIndex->count(t_hash) != 0)
        block->DisconnectBlock((*blockIndex)[t_hash]);
      bc_table_reset(bc, t_hash.GetRaw());

      delete block;
    }
  }
  for (nHeight = nMaxHeight; nHeight > nMinHeight; nHeight--) {
    bc_clear(bc, nHeight);
  }  

  SetBestBlockIndex(iface, cur_index);
  WriteHashBestChain(iface, cur_index->GetBlockHash());

  cur_index->pnext = NULL;
  //TESTBlock::bnBestChainWork = cur_index->bnChainWork;
  InitServiceBlockEvent(ifaceIndex, cur_index->nHeight + 1);

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
