
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
#include "spring.h"
#include "fractal.h"
#include "txsignature.h"
#include "txmempool.h"

#if 0
void CTxMatrix::ClearCells()
{
  int row, col;

  for (row = 0; row < nSize; row++) {
    for (col = 0; col < nSize; col++) {
      SetCell(row, col, 0);
    }
  }
}
#endif


#define MAX_VALIDATE_TX_HISTORY 128


void CTxMatrix::Append(int heightIn, uint256 hash)
{
  nHeight = heightIn;

  int idx = (nHeight / 27) % 9;
  int row = (idx / 3) % 3;
  int col = idx % 3;
  unsigned int crc = (unsigned int)shcrc(hash.GetRaw(), 32);
  AddCell(row, col, crc);
}

void CTxMatrix::Retract(int heightIn, uint256 hash)
{

  if (heightIn > nHeight)
    return;

  nHeight = heightIn - 27;

  int idx = (heightIn / 27) % 9;
  int row = (idx / 3) % 3;
  int col = idx % 3;
  SubCell(row, col, (unsigned int)shcrc(hash.GetRaw(), 32));
}

static unsigned int matrix_GetMinConsensus(int ifaceIndex)
{
	int nMinConsensus = 3;
	if (ifaceIndex == TEST_COIN_IFACE) {
		/* special case for testing. */
		nMinConsensus = 1;
	}
	return (nMinConsensus);
}

bool GetValidateNotaries(CWallet *wallet, vector<CPubKey>& kSend, uint256 hMatrixTx = 0)
{
	int nMinConsensus = matrix_GetMinConsensus(wallet->ifaceIndex);
	int tot;
	int idx;

	kSend.clear();

	if (hMatrixTx == 0) {
		/* tail */
		idx = (wallet->mapValidateTx.size() - 1);
	} else {
		/* find tx */
		for (idx = 0; idx < wallet->mapValidateTx.size(); idx++) {
			if (hMatrixTx == wallet->mapValidateTx[idx])
				break;
		}
		if (idx == wallet->mapValidateTx.size()) {
			return (false);
		}
	}

	tot = 0;
	idx = MAX(0, idx - 9);
	for (; idx < wallet->mapValidateTx.size(); idx++) {
		const uint256& hTx = wallet->mapValidateTx[idx];
		if (wallet->mapValidateNotary.count(hTx) == 0) {
			continue; /* no dest */
		}

		CPubKey pubkey(wallet->mapValidateNotary[hTx]);
		if (std::find(kSend.begin(), kSend.end(), pubkey) != kSend.end())
			continue; /* dup */

		tot++;
		kSend.push_back(pubkey);

		if (tot == nMinConsensus)
			break;
	}

	if (tot != nMinConsensus)
		return (false);

	return (true);
}

/* A redeem script from a OP_MATRIX:GENERATE tx output that is used to trigger a new dynamic checkpoint. */
CScriptID GenerateValidateScript(CWallet *wallet, bool& fConsensus, CScript& script, vector<CPubKey> kSend)
{
	int nMinConsensus = matrix_GetMinConsensus(wallet->ifaceIndex);

	fConsensus = false;
	script.clear();

	if (kSend.size() >= nMinConsensus)
		fConsensus = true;

	if (!fConsensus) {
		script.SetNoDestination();
	} else {
		script << CScript::EncodeOP_N(kSend.size());
		for (int i = 0; i < nMinConsensus; i++) {
			script << kSend[i];
		}
		script << CScript::EncodeOP_N(kSend.size());
		script << OP_CHECKMULTISIG;
	}

	return (CScriptID(script));
}

bool CreateValidateNotaryTx(CIface *iface, const CTransaction& txPrev, int nPrevOut, CTransaction& tx, vector<CPubKey> kSend)
{
	CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	int nMinConsensus = matrix_GetMinConsensus(ifaceIndex);
	const uint256& hPrevTx = txPrev.GetHash();
	CScript scriptSig;
	unsigned int nSeq = 1;

	CBlockIndex *pindexBest = GetBestBlockIndex(iface);
	if (!pindexBest)
		return (false);


	if (nPrevOut >= txPrev.vout.size())
		return (error(ERR_INVAL, "CreateValidateNotaryTx: invalid nPrevOut %d", nPrevOut));

	CScript scriptRedeem;
	bool fConsensus;
	GenerateValidateScript(wallet, fConsensus, scriptRedeem, kSend);
	if (!fConsensus) {
		return (false);
	}

	/* sanity */
	tx.SetNull();

	/* input */
	CTxIn in(hPrevTx, nPrevOut);
	tx.vin.insert(tx.vin.end(), in);

	/* output */
	CScript scriptReturn;
	scriptReturn.SetNoDestination(); /* null output */
	CTxOut out(MIN_INPUT_VALUE(iface), scriptReturn);
	tx.vout.insert(tx.vout.end(), out);
	
	/* sign */
	scriptSig << OP_0;
//	GetValidateNotaries(wallet, kSend);
//	int nUnsolved = 0;
	for (int i = 0; i < nMinConsensus; i++) {

		scriptSig << cbuff(); /* "null" placeholder */
#if 0
		CKey key;
		bool fSolved;

		fSolved = false;
		if (wallet->GetKey(kSend[i].GetID(), key)) {
			CSignature sig(ifaceIndex, &tx, 0);
			cbuff result;

			fSolved = sig.CreateSignature(result,
					kSend[i].GetID(), txPrev.vout[nPrevOut].scriptPubKey, 0); 
			if (fSolved)
				scriptSig << result;
		}
		if (!fSolved) {
			scriptSig << OP_0; /* "null" placeholder */
			nUnsolved++;
		}
#endif

	}
	cbuff raw(scriptRedeem.begin(), scriptRedeem.end());
#if 0
//	scriptSig << OP_PUSHDATA2 << raw;
	scriptSig += scriptRedeem;
#endif
	scriptSig << raw;
	tx.vin[0].scriptSig = scriptSig;

	/* wait for originating matrix-tx to mature. */
//	tx.vin[0].nSequence  = nSeq;
	tx.vin[0].nSequence  = 1;
	tx.nLockTime = pindexBest->nHeight + iface->coinbase_maturity + 1;

	return (true);
}

/* 'zero transactions' penalty. */
bool BlockGenerateValidateMatrix(CIface *iface, CTransaction& tx, int64& nReward, uint64_t nBestHeight, uint64_t nCheckHeight)
{
  int ifaceIndex = GetCoinIndex(iface);
	CWallet *wallet = GetWallet(iface);

  int64 nFee = MAX(0, MIN(COIN, nReward - (int64)iface->min_tx_fee));
  if (nFee < iface->min_tx_fee)
    return (false); /* reward too small */

  CTxMatrix *m = tx.GenerateValidateMatrix(ifaceIndex);
  if (!m)
    return (false); /* not applicable */

	bool fConsensus = false;
	CScript scriptRedeem;
	vector<CPubKey> kSend;
	GetValidateNotaries(wallet, kSend);
	CScriptID hRedeem;
	if (kSend.size() != 0 &&
			(nCheckHeight + iface->coinbase_maturity) < nBestHeight) { 
		hRedeem = GenerateValidateScript(wallet, fConsensus, scriptRedeem, kSend);
	}

  /* define tx op attributes */
  uint160 hashMatrix = m->GetHash();
  CScript scriptMatrix;
  scriptMatrix << OP_EXT_VALIDATE << CScript::EncodeOP_N(OP_MATRIX) << OP_HASH160 << hashMatrix << OP_2DROP;
	if (!fConsensus) {
		scriptMatrix << OP_RETURN << OP_0;
	} else {
		scriptMatrix << OP_HASH160 << hRedeem << OP_EQUAL;
	}
  tx.vout.push_back(CTxOut(nFee, scriptMatrix));

  /* deduct from reward. */
  nReward -= nFee;

//  Debug("BlockGenerateValidateMatrix: validate matrix [hash %s] [consensus %d] proposed: %s\n", hashMatrix.GetHex().c_str(), (int)kSend.size(), m->ToString().c_str());

  return (true);
}

static bool ExtractValidateCoinbaseDestination(CWallet *wallet, const CTransaction& tx, CPubKey& pubkey)
{
	int nExtOut;
	int i;

	nExtOut = IndexOfExtOutput(tx);

	for (i = 0; i < tx.vout.size(); i++) {
		if (i == nExtOut) 
			continue; /* skip matrix */

		if (tx.vout[i].nValue == 0)
			continue; /* n/a */

		vector<cbuff> vSolutions;
		txnouttype whichType; 
		if (!Solver(tx.vout[i].scriptPubKey, whichType, vSolutions)) 
			continue;
		if (whichType != TX_PUBKEY)
			continue;
		pubkey = CPubKey(vSolutions[0]);
		return (true);
	}
	
	return (false);
}

void InsertValidateNotary(CWallet *wallet, const CTransaction& tx)
{
	const uint256& hTx = tx.GetHash();
	int i;

	CPubKey pubkey;
	if (!ExtractValidateCoinbaseDestination(wallet, tx, pubkey)) {
		return;
	}

	/* insert new notary */
	wallet->mapValidateNotary[hTx] = pubkey;

}

static void matrix_PurgeValidateTx(CWallet *wallet)
{
#if 0

	while (wallet->mapValidateTx.size() > MAX_VALIDATE_TX_HISTORY) {
		const uint256& hTx = wallet->mapValidateTx.begin();
		wallet->mapValidateNotary.erase(hTx);
		wallet->mapValidateTx.erase(wallet->mapValidateTx.begin());
	}

#endif
}

extern bool IsMine(const CKeyStore &keystore, const CTxDestination &dest);

bool RelayValidateMatrixNotaryTx(CIface *iface, const CTransaction& txMatrix, CTransaction *txIn)
{
	CWallet *wallet = GetWallet(iface);
	CTxMemPool *pool = GetTxMemPool(iface);
	vector<CPubKey> kSend;
	CBlockIndex *pindex;
	CScript script;
	CTransaction tx;
	int nPrevOut = 0;
	int mode;

	if (!GetExtOutput(txMatrix, OP_MATRIX, mode, nPrevOut, script) ||
			mode != OP_EXT_VALIDATE) {
		return (error(ERR_INVAL, "RelayValidateMatrixTx: tx is not validation matrix."));
	}

	/* check whether validate-tx has usable output. */
	opcodetype opcode;
	if (!RemoveExtOutputPrefix(script)) {
		return (error(ERR_INVAL, "RelayValidateMatrixTx: !RemovePrefix"));
	}
	CScript::const_iterator pc = script.begin();
	if (!script.GetOp(pc, opcode)) {
		return (ERR_INVAL, "RelayValidateMatrixTx: empty script.");
	}
	if (opcode != OP_HASH160) {
		return (false); /* not a CScriptID (multisig) */
	}

	if (!GetValidateNotaries(wallet, kSend, txMatrix.GetHash())) {
		/* not enough notaries */
		return (false);
	}

	bool fLocal = false;
	for (int i = 0; i < kSend.size(); i++) {
		if (IsMine(*wallet, kSend[i].GetID())) {
			fLocal = true;
			break;
		}
	}
	if (fLocal == false) {
		return (false);
	}

	if (!CreateValidateNotaryTx(iface, txMatrix, nPrevOut, tx, kSend))
		return (error(ERR_INVAL, "RelayValidateMatrixTx: !CreateValidateNotaryTx"));

	/* may or may not be finalized. */
	if (pool->AddTx(tx, NULL, 0)) {
		RelayTransaction(wallet->ifaceIndex, tx, tx.GetHash());
	} else {
		error(ERR_INVAL, "warning: RelayValidateMatrixTx: !pool->AddTx: %s", tx.GetHash().GetHex().c_str());
	}

	return (true);
}


bool VerifyValidateMatrixScript(CWallet *wallet, const uint256& hMatrixTx, const CScript& scriptIn)
{
	CScript script(scriptIn);
	opcodetype opcode;
	
	/* remove extended-tx script suffix */
	if (!RemoveExtOutputPrefix(script))
		return (false);

	/* analyze output script for validate matrix tx */
	CScript::const_iterator pc = script.begin();
	if (!script.GetOp(pc, opcode))
		return (false);
	if (opcode != OP_RETURN &&
			opcode != OP_HASH160)
		return (false); /* not p2sh or burn. */
	if (opcode == OP_HASH160) {
		bool fConsensus;

		cbuff vch;
		if (!script.GetOp(pc, opcode, vch))
			return (false);
		uint160 cmp(vch);

		vector<CPubKey> kSend;
		if (!GetValidateNotaries(wallet, kSend, hMatrixTx))
			return (false); /* not enough notaries */

		CScript scriptRedeem;
		CScriptID hRedeem = GenerateValidateScript(wallet, fConsensus, scriptRedeem, kSend);
		if (hRedeem != CScriptID(cmp))
			return (error(ERR_INVAL, "VerifyValidateMatrix: invalid P2SH address: %s", cmp.GetHex().c_str()));
	}

	return (true);
}

bool VerifyValidateMatrixScript(CWallet *wallet, CTransaction& tx)
{
	CScript script;
	int nTxOut;
	int mode;

	if (!GetExtOutput(tx, OP_MATRIX, mode, nTxOut, script))
		return (false);
	if (mode != OP_EXT_VALIDATE)
		return (false);

	return (VerifyValidateMatrixScript(wallet, tx.GetHash(), script));
}

bool BlockAcceptValidateMatrix(CIface *iface, CTransaction& tx, bool& fCheck)
{
  int ifaceIndex = GetCoinIndex(iface);
	CWallet *wallet = GetWallet(iface);
  CTxMatrix matrix;
  bool fMatrix = false;
  int mode;

  if (VerifyMatrixTx(tx, mode) && mode == OP_EXT_VALIDATE) {
    CBlockIndex *pindex = GetBestBlockIndex(ifaceIndex);
    CTxMatrix& matrix = *tx.GetMatrix();
    if (matrix.GetType() == CTxMatrix::M_VALIDATE &&
        matrix.GetHeight() > wallet->matrixValidate.GetHeight()) {
			int nOut;
			int mode;
			CScript script;
			if (!GetExtOutput(tx, OP_MATRIX, mode, nOut, script) ||
      //!VerifyValidateMatrixScript(wallet, tx) ||
					!VerifyValidateMatrixScript(wallet, 0, script) || 
					!tx.VerifyValidateMatrix(ifaceIndex, matrix, pindex)) {
        fCheck = false;
        error(SHERR_INVAL, "BlockAcceptValidateMatrix: invalid matrix received: %s", matrix.ToString().c_str());
      } else {
				/* validate matrix accepted successfully. */
        fCheck = true;

        /* apply new hash to matrix */
        wallet->matrixValidate = matrix;

				/* track matrix tx */
				const uint256& hTx = tx.GetHash();
				wallet->mapValidateTx.push_back(hTx);

				/* track coinbase destinations. */
				InsertValidateNotary(wallet, tx);

				/* free up unused resources. */
				matrix_PurgeValidateTx(wallet);

				/* print debug. */
        Debug("BlockAcceptValidateMatrix: Validate verify success [tx %s] [hash %s]: %s", hTx.GetHex().c_str(), wallet->matrixValidate.ToString().c_str(), matrix.ToString().c_str());
      }

      return (true); /* matrix was found */
    }
  }

  return (false); /* no matrix was present */
}

void BlockRetractValidateMatrix(CIface *iface, const CTransaction& tx, CBlockIndex *pindex)
{
  CWallet *wallet = GetWallet(iface);
	int nTxOut;

	if (!wallet)
		return;
	if (!pindex)
		return;

	/* remove tx from matrix */
	wallet->matrixValidate.Retract(pindex->nHeight, pindex->GetBlockHash());

	if (wallet->mapValidateTx.size() != 0) {
		const uint256& hPrevTx = wallet->mapValidateTx.back();
		if (hPrevTx == tx.GetHash()) {
			wallet->mapValidateTx.pop_back();

#if 0
			CBlockIndex *pindexMatrix;
			pindexMatrix = GetBlockIndexByTx(iface, hPrevTx);
			if (pindexMatrix) {
				/* retract matrix height */
				int height = (pindexMatrix->nHeight - 27);
				height /= 27;
				height *= 27;

				if (height > 27)
					wallet->matrixValidate.nHeight = height;
				else
					wallet->matrixValidate.nHeight = 0;
			}
#endif
		}
	}
	
	wallet->mapValidateNotary.erase(tx.GetHash());
#if 0
	/* the following assumes the chain is being rolled back in reverse order. */
	CPubKey pubkey;
	if (ExtractValidateCoinbaseDestination(wallet, tx, pubkey)) {
		CKeyID keyid;

		/* retract last notary addition. */
		if (wallet->mapValidateNotary.size() != 0 &&
				wallet->mapValidateNotary.back() == pubkey) {
			wallet->mapValidateNotary.pop_back();
		}
	}
#endif
}

/* returns where tx was a valid matrix-notary-tx */
bool ProcessValidateMatrixNotaryTx(CIface *iface, const CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	CBlockIndex *pindex;
	CBlock *pblock;

	if (ifaceIndex != SHC_COIN_IFACE &&
			ifaceIndex != TEST_COIN_IFACE &&
			ifaceIndex != TESTNET_COIN_IFACE)
		return (false);

	if (tx.IsCoinBase())
		return (false);


	/* check whether tx input ref's latest published matrix tx. */
	const CTxIn& txin = tx.vin[0];
	if (std::find(wallet->mapValidateTx.begin(), wallet->mapValidateTx.end(), txin.prevout.hash) == wallet->mapValidateTx.end()) {
		return (false);
	}
	if (tx.vin.size() != 1 || tx.vout.size() != 1)
		return (false);

	if (wallet->matrixValidate.nHeight == 0)
		return (false);

	CTransaction txMatrix;
	uint256 hMatrixBlock;
	if (!GetTransaction(iface, txin.prevout.hash, txMatrix, &hMatrixBlock))
		return (false);

	int mode;
	int nTxOut;
	CScript script;
	if (!GetExtOutput(txMatrix, OP_MATRIX, mode, nTxOut, script))
		return (false);
	if (txin.prevout.n != nTxOut)
		return (false);

	/* output must be OP_RETURN script with MIN_INPUT nValue */
	const CTxOut& txout = tx.vout[0];
	CScript scriptReturn;
	scriptReturn.SetNoDestination(); /* null output */
	if (txout.scriptPubKey != scriptReturn)
		return (error(ERR_INVAL, "ProcessValidateMatrixNotaryTx: invalid output script: %s", txout.scriptPubKey.ToString().c_str()));
	if (txout.nValue > MIN_INPUT_VALUE(iface))
		return (error(ERR_INVAL, "ProcessValidateMatrixNotaryTx: txout.nValue(%f) > MIN_INPUT_VALUE", (double)txout.nValue/COIN));

	/* establish a new dynamic checkpoint at matrix. */
	pblock = GetBlockByHash(iface, hMatrixBlock);
	if (!pblock)
		return (false);
	pblock->CreateCheckpoint();
	delete pblock;

	return (true);
}

void UpdateValidateNotaryTx(CIface *iface, CTransaction& tx, const CScript& scriptPrev)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int nMinConsensus = matrix_GetMinConsensus(ifaceIndex);
	const uint256& hPrevTx = tx.vin[0].prevout.hash;
	vector<CPubKey> kSend;
	bool fLocal = false;

	if (tx.IsFinal(ifaceIndex)) {
		/* already being processed. */
		return;
	}

	/* ensure redeem hash reflects expected notaries. */
	if (!VerifyValidateMatrixScript(wallet, hPrevTx, scriptPrev)) {
		return;
	}

	if (!GetValidateNotaries(wallet, kSend, hPrevTx)) {
		return; /* not enough notaries */
	}

	/* determine whether this is local. */
	for (int i = 0; i < kSend.size(); i++) {
		if (IsMine(*wallet, kSend[i].GetID())) {
			fLocal = true;
			break;
		}
	}
	if (fLocal == false) {
		return;
	}

	CScript script = tx.vin[0].scriptSig;//scriptPrev;
	CScript::const_iterator pc = script.begin();
	vector<cbuff> vsig;
	opcodetype opcode;

	cbuff vch;
	if (!script.GetOp(pc, opcode)) { 
		return;
	}
	if (opcode != OP_0) {
		return;
	}
	for (int i = 0; i < nMinConsensus; i++) {
		if (script.GetOp(pc, opcode, vch))
			break;
		if (vch.size() == 0)
			break;

		vsig.push_back(vch);
	}

	CScript scriptSig;
	scriptSig << OP_0;
	int nUnsolved = 0;
	bool fUpdated = false;
	for (int i = 0; i < nMinConsensus; i++) {
		CKey key;
		bool fSolved;

		if (vsig.size() > i) {
			/* signature has already been gathered. */
			scriptSig << vsig[i];
			continue;
		}

		/* sign local pubkeys */
		fSolved = false;
		if (wallet->GetKey(kSend[i].GetID(), key)) {
			CSignature sig(ifaceIndex, &tx, 0);
			cbuff result;

			fSolved = sig.CreateSignature(result,
					kSend[i].GetID(), scriptPrev, 0); 
			if (fSolved) {
				scriptSig << result;
				fUpdated = true;
			}
		}
		if (!fSolved) {
			scriptSig << OP_0; /* "null" placeholder */
			nUnsolved++;
		}
	}

	if (fUpdated) {
		tx.vin[0].nSequence = tx.vin[0].nSequence + 1;
		if (tx.vin[0].nSequence == CTxIn::SEQUENCE_FINAL)
			tx.vin[0].nSequence = 1;

		CScript scriptSuffix(pc, script.end());
		scriptSig += scriptSuffix;
		tx.vin[0].scriptSig = scriptSig; 

		Debug("(%s) UpdateValidateNotaryTx: updated tx: %s\n", 
				iface->name, tx.ToString(ifaceIndex).c_str());
	}

}


#if 0
void LargeMatrix::compress(CTxMatrix& matrixIn)
{
  int row, col;
  int n_row, n_col;
  double deg;

  matrixIn.ClearCells();

  deg = nSize / matrixIn.nSize; 
  for (row = 0; row < nSize; row++) {
    for (col = 0; col < nSize; col++) {
      n_row = (row / deg); 
      n_col = (col / deg); 
      matrixIn.AddCell(n_row, n_col, GetCell(row, col)); 
    }
  }

}
#endif

/* NOT IMPLEMENTED */
shgeo_t *GetMatrixOrigin(CTransaction& tx)
{
  static shgeo_t geo;
memset(&geo, 0, sizeof(geo));
return (&geo);
}

bool BlockGenerateSpringMatrix(CIface *iface, CTransaction& tx, int64& nReward)
{
  int ifaceIndex = GetCoinIndex(iface);

  int64 nFee = MAX(0, MIN(COIN, nReward - iface->min_tx_fee));
  if (nFee < iface->min_tx_fee)
    return (false); /* reward too small */


  CIdent ident;
  CTxMatrix *m = tx.GenerateSpringMatrix(ifaceIndex, ident);
  if (!m)
    return (false); /* not applicable */

  uint160 hashMatrix = m->GetHash();
  int64 min_tx = (int64)iface->min_tx_fee;

  CScript scriptPubKeyOrig;
  CCoinAddr addr(stringFromVch(ident.vAddr));
  scriptPubKeyOrig.SetDestination(addr.Get());

  CScript scriptMatrix;
  scriptMatrix << OP_EXT_PAY << CScript::EncodeOP_N(OP_MATRIX) << OP_HASH160 << hashMatrix << OP_2DROP;
  scriptMatrix += scriptPubKeyOrig;

  tx.vout.push_back(CTxOut(nFee, scriptMatrix));

  /* deduct from reward. */
  nReward -= nFee;

  Debug("BlockGenerateSpringMatrix: (matrix hash %s) proposed: %s\n", hashMatrix.GetHex().c_str(), m->ToString().c_str());

  return (true);
}

bool BlockAcceptSpringMatrix(CIface *iface, CTransaction& tx, bool& fCheck)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  bool fMatrix = false;
  shnum_t lat, lon;
  int mode = -1;;

  lat = lon = 0;
  if (VerifyMatrixTx(tx, mode) && mode == OP_EXT_PAY) {
    CBlockIndex *pindex = GetBestBlockIndex(ifaceIndex);
    CTxMatrix& matrix = *tx.GetMatrix();
    if (matrix.GetType() == CTxMatrix::M_SPRING) {
      if (!tx.VerifySpringMatrix(ifaceIndex, matrix, &lat, &lon)) {
        fCheck = false;
        Debug("BlockAcceptSpringMatrix: Spring verify failure: (new %s) lat(%f) lon(%f)\n", matrix.ToString().c_str(), lat, lon);
      } else {
        fCheck = true;
        /* remove claim location from spring matrix */
        spring_loc_claim(lat, lon);
        /* erase pending ident tx */
        wallet->mapIdent.erase(matrix.hRef);
Debug("BlockAcceptSpringMatrix: Spring verify success: lat(%Lf) lon(%Lf)\n", lat, lon);
        Debug("BlockAcceptSpringMatrix: Spring verify success: (new %s) lat(%Lf) lon(%Lf)\n", matrix.ToString().c_str(), lat, lon);
      }
      return (true); /* matrix was found */
    }
  }

  return (false); /* no matrix was present */
}

CTxMatrix *CTransaction::GenerateSpringMatrix(int ifaceIndex, CIdent& ident)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  shnum_t lat, lon;
  int height;

  if (!iface || !iface->enabled)
    return (NULL);

  if (nFlag & CTransaction::TXF_MATRIX)
    return (NULL);

  CWallet *wallet = GetWallet(iface);
  if (!wallet)
    return (NULL);

  if (wallet->mapIdent.size() == 0)
    return (NULL);

  const uint160& hashIdent = wallet->mapIdent.begin()->first;

  CTransaction tx;
  bool hasIdent = GetTxOfIdent(iface, hashIdent, tx);
  if (!hasIdent) {
    wallet->mapIdent.erase(hashIdent); /* invalido */
    return (NULL);
  }
  ident = (CIdent&)tx.certificate;

  shgeo_loc(&ident.geo, &lat, &lon, NULL);
  if (!is_spring_loc(lat, lon)) {
    wallet->mapIdent.erase(hashIdent); /* invalido */
    return (NULL);
  }

  nFlag |= CTransaction::TXF_MATRIX;

  matrix = CTxMatrix();
  spring_matrix_compress(matrix.vData);
  matrix.nType = CTxMatrix::M_SPRING;
  matrix.nHeight = GetBestHeight(iface) + 1; 
  matrix.hRef = hashIdent;
 
  return (&matrix);
}

bool CTransaction::VerifySpringMatrix(int ifaceIndex, const CTxMatrix& matrix, shnum_t *lat_p, shnum_t *lon_p)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  
  CTransaction tx;
  if (!GetTxOfIdent(iface, matrix.hRef, tx))
    return error(SHERR_INVAL, "VerifySpringMatrix: invalid ident tx.");

	CCert *cert = tx.GetCertificate();
	if (!cert)
		return (error(SHERR_INVAL, "VerifySptringMatrix: invalid reference hash"));

  CIdent& ident = (CIdent&)(*cert);

  shgeo_loc(&ident.geo, lat_p, lon_p, NULL);
  if (!is_spring_loc(*lat_p, *lon_p))
    return error(SHERR_INVAL, "VerifySpringMatrix: invalid spring location.");

  CTxMatrix cmp_matrix;
  spring_matrix_compress(cmp_matrix.vData);
  cmp_matrix.nType = matrix.nType;
  cmp_matrix.nHeight = matrix.nHeight; 
  cmp_matrix.hRef = matrix.hRef;

  bool ret = (cmp_matrix == matrix);
  if (!ret)
    return error(SHERR_INVAL, "VerifySpringMatrix: matrix integrity failure.");

  return (true);
}


void BlockRetractSpringMatrix(CIface *iface, CTransaction& tx, CBlockIndex *pindex)
{
//  int ifaceIndex = GetCoinIndex(iface);
  const CTxMatrix& matrix = tx.matrix;

  if (pindex->nHeight != matrix.nHeight)
    return;

#if 0
  matrixIn->Retract(matrix.nHeight, tx.GetHash());
#endif

  CTransaction id_tx;
  if (!GetTxOfIdent(iface, matrix.hRef, id_tx))
    return;

#if 0
  if (id_tx.IsInMempool(ifaceIndex))
    return;
#endif

  /* re-establish location bits in spring matrix. */
  CIdent& ident = (CIdent&)id_tx.certificate;
  shnum_t lat, lon;
  shgeo_loc(&ident.geo, &lat, &lon, NULL);
  spring_loc_set(lat, lon);
}


Object CTxMatrix::ToValue()
{
  Object obj;
  char buf[2048];
  int row;
  int col;

  obj.push_back(Pair("hash", GetHash().GetHex()));
  obj.push_back(Pair("type", (int)nType));
  obj.push_back(Pair("ref", hRef.GetHex()));
  if (nHeight != 0)
    obj.push_back(Pair("height", (int)nHeight));

  memset(buf, 0, sizeof(buf));
  for (row = 0; row < 3; row++) {
    if (row != 0) strcat(buf, " ");
    strcat(buf, "(");
    for (col = 0; col < 3; col++) {
      if (col != 0) strcat(buf, " "); 
      sprintf(buf+strlen(buf), "%-8.8x", GetCell(row, col));
    }
    strcat(buf, ")");
  }
  string strMatrix(buf);
  obj.push_back(Pair("data", strMatrix));

  return obj;
}

std::string CTxMatrix::ToString()
{
  return (write_string(Value(ToValue()), false));
}


int cpp_validate_render_fractal(int ifaceIndex, char *img_path, double zoom, double span, double x_of, double y_of)
{
	CWallet *wallet = GetWallet(ifaceIndex);
	CTxMatrix *matrix = &wallet->matrixValidate;
  uint32_t m_seed;
  double seed;
  int y, x;

  m_seed = 0;
  for (y = 0; y < 3; y++) {
    for (x = 0; x < 3; x++) {
      m_seed += matrix->vData[y][x];
    }
  }
  seed = (double)m_seed;

  return (fractal_render(img_path, seed, zoom, span, x_of, y_of));
}

#ifdef __cplusplus
extern "C" {
#endif
int validate_render_fractal(int ifaceIndex, char *img_path, double zoom, double span, double x_of, double y_of)
{
	return (cpp_validate_render_fractal(ifaceIndex, img_path, zoom, span, x_of, y_of));
}
#ifdef __cplusplus
}
#endif



