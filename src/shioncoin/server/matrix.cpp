
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
#include "block.h"
#include "wallet.h"
#include "spring.h"
#include "fractal.h"
#include "txsignature.h"
#include "txmempool.h"

/* The number of notaries required for the multi-sig signature. */
#define MIN_VALIDATE_NOTARY_CONSENSUS 6 /* ~8hr back in block-chain. */ 

#define VALIDATE_NOTARY_DEPTH 18 /* x3 / notary */

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
	int nMinConsensus = MIN_VALIDATE_NOTARY_CONSENSUS;
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
			return (error(ERR_INVAL, "GetValidateNotaries: tx \"%s\" does not contain a matrix.", hMatrixTx.GetHex().c_str()));
		}
		idx--;
	}

	tot = 0;
	idx = MAX(0, idx - VALIDATE_NOTARY_DEPTH);
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

bool VerifyValidateMatrixScript(CWallet *wallet, const uint256& hMatrixTx, const CScript& scriptIn)
{
	CScript script(scriptIn);
	opcodetype opcode;

	/* remove extended-tx script suffix */
	if (!RemoveExtOutputPrefix(script))
		return (error(ERR_INVAL, "VerifyValidateMatrixScript: not an extended transaction."));

	/* analyze output script for validate matrix tx */
	CScript::const_iterator pc = script.begin();
	if (!script.GetOp(pc, opcode))
		return (false);
	if (opcode != OP_RETURN &&
			opcode != OP_HASH160)
		return (error(ERR_INVAL, "VerifyValidateMatrixScript: invalid output script.: %s", script.ToString().c_str())); /* not p2sh or burn */
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
		if (hRedeem != CScriptID(cmp)) {
			return (error(ERR_INVAL, "VerifyValidateMatrix: output has invalid P2SH address: %s", cmp.GetHex().c_str()));
		}
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

static uint32_t matrix_GetNotaryLockTime(CIface *iface)
{
	CBlockIndex *pindexBest = GetBestBlockIndex(iface);
	if (!pindexBest)
		return (0);
	return (pindexBest->nHeight + (iface->coinbase_maturity*2) + 1);
}

bool CreateValidateNotaryTx(CIface *iface, const CTransaction& txPrev, int nPrevOut, CTransaction& tx, vector<CPubKey> kSend)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int nMinConsensus = matrix_GetMinConsensus(ifaceIndex);
	const uint256& hPrevTx = txPrev.GetHash();
	CScript scriptSig;
	unsigned int nSeq = 1;

	if (nPrevOut >= txPrev.vout.size())
		return (error(ERR_INVAL, "CreateValidateNotaryTx: invalid nPrevOut %d", nPrevOut));

	const CScript& scriptPrev = txPrev.vout[nPrevOut].scriptPubKey;
	if (!VerifyValidateMatrixScript(wallet, hPrevTx, scriptPrev)) {
		return (error(ERR_INVAL, "CreateValidateNotaryTx: error verifying validate matrix script [tx %s].", hPrevTx.GetHex().c_str()));
	}

	CScript scriptRedeem;
	bool fConsensus;
	GenerateValidateScript(wallet, fConsensus, scriptRedeem, kSend);
	if (!fConsensus) {
		/* not enough notaries. */
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
	CTxOut out(CTxMatrix::MAX_NOTARY_TX_VALUE, scriptReturn);
	tx.vout.insert(tx.vout.end(), out);

	/* sign */
	scriptSig << OP_0;
	for (int i = 0; i < nMinConsensus; i++) {
		scriptSig << OP_0; /* "null" placeholder */
	}
	cbuff raw(scriptRedeem.begin(), scriptRedeem.end());
	scriptSig << raw;
	tx.vin[0].scriptSig = scriptSig;

	/* wait for originating matrix-tx to mature. */
	tx.vin[0].nSequence  = 1;
	if (tx.GetVersion() >= 2) 
		tx.vin[0].nSequence |= CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG;
	/* establish lock-time */
	tx.nLockTime = matrix_GetNotaryLockTime(iface);

	return (true);
}

/* 'zero transactions' penalty. */
bool BlockGenerateValidateMatrix(CIface *iface, CTransaction& tx, int64& nReward, uint64_t nBestHeight, uint64_t nCheckHeight)
{
	int ifaceIndex = GetCoinIndex(iface);
	CWallet *wallet = GetWallet(iface);

	int64 nFee = MAX(0, MIN(COIN, nReward - (int64)iface->min_tx_fee));
	if (!MoneyRange(iface, nFee) ||
			nFee < iface->min_tx_fee)
		return (false); /* reward too small */

	CTxMatrix *m = tx.GenerateValidateMatrix(ifaceIndex);
	if (!m)
		return (false); /* not applicable */

	bool fConsensus = false;
	CScript scriptRedeem;
	vector<CPubKey> kSend;
	CScriptID hRedeem;
	if (opt_bool(OPT_NOTARY) &&
			(nCheckHeight + iface->coinbase_maturity) < nBestHeight) { 
		GetValidateNotaries(wallet, kSend);
		if (kSend.size() != 0)
			hRedeem = GenerateValidateScript(wallet, fConsensus, scriptRedeem, kSend);
	}

	/* define tx op attributes */
	uint160 hashMatrix = m->GetHash();
	CScript scriptMatrix;
	scriptMatrix << OP_EXT_VALIDATE << CScript::EncodeOP_N(OP_MATRIX) << OP_HASH160 << hashMatrix << OP_2DROP;
	if (!fConsensus) {
		/* null destination */
		scriptMatrix << OP_RETURN << OP_0;
	} else {
		/* P2SH for multi-sig redeem script. */
		scriptMatrix << OP_HASH160 << hRedeem << OP_EQUAL;
	}
	tx.vout.push_back(CTxOut(nFee, scriptMatrix));

	/* deduct from reward. */
	nReward -= nFee;

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

		if (tx.vout[i].scriptPubKey.at(0) == OP_RETURN)
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

/* verifies the integrity of the transaction in relation to the validate matrix. if no validate matrix exists, then the integrity is ok.
 */
bool BlockVerifyValidateMatrix(CIface *iface, CTransaction& tx, CBlockIndex *pindex)
{
	int ifaceIndex = GetCoinIndex(iface);
	CWallet *wallet = GetWallet(iface);
	bool fMatrix = false;
	int mode;

	if (!VerifyMatrixTx(tx, mode))
		return (true); /* n/a */
	if (mode != OP_EXT_VALIDATE)
		return (true); /* n/a */

	if (!pindex)
		pindex = GetBestBlockIndex(ifaceIndex);
	CTxMatrix& matrix = *tx.GetMatrix();
	if (matrix.GetType() != CTxMatrix::M_VALIDATE ||
			matrix.GetHeight() <= wallet->matrixValidate.GetHeight())
		return (true); /* n/a */

	{
		int nOut;
		int mode;
		CScript script;
		if (!GetExtOutput(tx, OP_MATRIX, mode, nOut, script)) {
			return (error(SHERR_INVAL, "BlockVerifyValidateMatrix: GetExtOutput: invalid matrix received: %s [script \"%s\"]", matrix.ToString().c_str(), script.ToString().c_str()));
		}

		if (!VerifyValidateMatrixScript(wallet, 0, script)) {
			return (error(SHERR_INVAL, "BlockVerifyValidateMatrix: VerifyValidateMatrixScript: invalid matrix received: %s", matrix.ToString().c_str()));
		}

		if (!tx.VerifyValidateMatrix(ifaceIndex, matrix, pindex)) {
			return (error(SHERR_INVAL, "BlockVerifyValidateMatrix: VerifyValidateMatrix: invalid matrix received: %s", matrix.ToString().c_str()));
		}
	}

	return (true); /* validate matrix was found */
}

bool BlockAcceptValidateMatrix(CIface *iface, CTransaction& tx, CBlockIndex *pindex, bool& fCheck)
{
	int ifaceIndex = GetCoinIndex(iface);
	CWallet *wallet = GetWallet(iface);
	bool fMatrix = false;
	int mode;

	if (VerifyMatrixTx(tx, mode) && mode == OP_EXT_VALIDATE) {

		if (!pindex)
			pindex = GetBestBlockIndex(ifaceIndex);
		CTxMatrix& matrix = *tx.GetMatrix();
		if (matrix.GetType() == CTxMatrix::M_VALIDATE &&
				matrix.GetHeight() > wallet->matrixValidate.GetHeight()) {
			int nOut;
			int mode;
			CScript script;
			if (!GetExtOutput(tx, OP_MATRIX, mode, nOut, script)) {
				fCheck = false;
				error(SHERR_INVAL, "BlockAcceptValidateMatrix: GetExtOutput: invalid matrix received: %s [script \"%s\"]", matrix.ToString().c_str(), script.ToString().c_str());
			} else if (!VerifyValidateMatrixScript(wallet, 0, script)) {
				fCheck = false;
				error(SHERR_INVAL, "BlockAcceptValidateMatrix: VerifyValidateMatrixScript: invalid matrix received: %s", matrix.ToString().c_str());
			} else if (!tx.VerifyValidateMatrix(ifaceIndex, matrix, pindex)) {
				fCheck = false;
				error(SHERR_INVAL, "BlockAcceptValidateMatrix: VerifyValidateMatrix: invalid matrix received: %s", matrix.ToString().c_str());
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
	int height;

	if (!wallet)
		return;
	if (!pindex)
		return;

	height = (pindex->nHeight - 1 - 27); /* -1 due to it not existing before generation. */
	height /= 27;
	height *= 27;

	if (wallet->matrixValidate.GetHeight() != height) {
		error(SHERR_INVAL, "BlockRetractValidateMatrix: invalid height %d (matrix is %d)", height, wallet->matrixValidate.GetHeight());
		return;
	}
	Debug("(%s) BlockRetractValidateMatrix: retracted matrix from block height %d", iface->name, pindex->nHeight); 

	while (pindex && pindex->pprev && pindex->nHeight > height)
		pindex = pindex->pprev;
	if (pindex) {
		/* remove tx from matrix */
		wallet->matrixValidate.Retract(pindex->nHeight, pindex->GetBlockHash());
	}

	/* remove from archives. */
	if (wallet->mapValidateTx.size() != 0) {
		const uint256& hPrevTx = wallet->mapValidateTx.back();
		if (hPrevTx == tx.GetHash())
			wallet->mapValidateTx.pop_back();
	}

	/* remove from notorary list. */
	wallet->mapValidateNotary.erase(tx.GetHash());
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

	if (tx.vin.size() != 1 || tx.vout.size() != 1)
		return (false);

	/* check whether tx input ref's latest published matrix tx. */
	const CTxIn& txin = tx.vin[0];
	if (std::find(wallet->mapValidateTx.begin(), wallet->mapValidateTx.end(), txin.prevout.hash) == wallet->mapValidateTx.end()) {
		return (false);
	}

	if (wallet->matrixValidate.nHeight == 0)
		return (false);

	CTransaction txMatrix;
	uint256 hMatrixBlock;
	if (!GetTransaction(iface, txin.prevout.hash, txMatrix, &hMatrixBlock)) {
		return (false);
	}

	int mode;
	int nTxOut;
	CScript script;
	if (!GetExtOutput(txMatrix, OP_MATRIX, mode, nTxOut, script)) {
		return (false);
	}
	if (txin.prevout.n != nTxOut) {
		return (false);
	}

	/* output must be OP_RETURN script with MAX_NOTARY_TX_VALUE nValue */
	const CTxOut& txout = tx.vout[0];
	CScript scriptReturn;
	scriptReturn.SetNoDestination(); /* null output */
	if (txout.scriptPubKey != scriptReturn)
		return (error(ERR_INVAL, "ProcessValidateMatrixNotaryTx: invalid output script: %s", txout.scriptPubKey.ToString().c_str()));
	if (txout.nValue > CTxMatrix::MAX_NOTARY_TX_VALUE)
		return (error(ERR_INVAL, "ProcessValidateMatrixNotaryTx: txout.nValue(%f) > MAX_NOTARY_TX_VALUE", (double)txout.nValue/COIN));

	/* is block old enough to match required notary-tx locktime? */
	pindex = GetBlockIndexByHash(ifaceIndex, hMatrixBlock);
	if (!pindex) {
		return (false);
	}

	int nBestHeight = GetBestHeight(iface);
	if ((pindex->nHeight + iface->coinbase_maturity) > nBestHeight) {
		return (false); /* immmature */
	}

	/* verify validate-tx script. */
	if (!txMatrix.IsCoinBase()) {
		return (error(ERR_INVAL, "(%s) ProcessValidateMatrixNotaryTx: transaction \"%s\" is not a coinbase.", iface->name, txin.prevout.hash.GetHex().c_str()));
	}
	if (!VerifyValidateMatrixScript(wallet, txMatrix)) {
		return (error(ERR_INVAL, "(%s) ProcessValidateMatrixNotaryTx: error verifying transaction \"%s\".", iface->name, txin.prevout.hash.GetHex().c_str()));  
	}

	/* verify notary-tx script. */
	CBlockIndex *pindexBest = GetBestBlockIndex(iface);
	if (pindexBest) { /* will be null on startup */
		int nIn = 0;
		int fVerify = GetBlockScriptFlags(iface, pindexBest);
		if (!VerifySignature(ifaceIndex, txMatrix, tx, nIn, 0, fVerify)) {
			return (error(SHERR_ACCESS, "(%s) ProcessValidateMatrixNotaryTx: error verifying transaction \"%s\".", iface->name, tx.GetHash().GetHex().c_str()));
		}
	}

	/* establish a new dynamic checkpoint at matrix. */
	pblock = GetBlockByHash(iface, hMatrixBlock);
	if (!pblock) {
		return (false);
	}
	int nCheck = pblock->GetTotalBlocksEstimate();
	if ((nCheck + iface->coinbase_maturity) < nBestHeight) {
		pblock->CreateCheckpoint();
	} else {
		Debug("(%s) ProcessValidateMatrixNotaryTx: received immature notary tx \"%s\" (min-height %d >= best-height %d)\n", iface->name, tx.GetHash().GetHex().c_str(), (pindex->nHeight + iface->coinbase_maturity), nBestHeight);
	}
	delete pblock;

	return (true);
}

uint256 base_SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);


void UpdateValidateNotaryTx(CIface *iface, CTransaction& tx, const CScript& scriptPrev)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int nMinConsensus = matrix_GetMinConsensus(ifaceIndex);
	const uint256& hPrevTx = tx.vin[0].prevout.hash;
	vector<CPubKey> kSend;
	bool fLocal = false;
	int nUnsolved;
	cbuff vch;
	int i;

	if (tx.IsFinal(ifaceIndex)) {
		/* already being processed. */
		return;
	}

	/* ensure redeem hash reflects expected notaries. */
	if (!VerifyValidateMatrixScript(wallet, hPrevTx, scriptPrev)) {
		return;
	}

	if (tx.vin.size() != 1 || tx.vout.size() != 1)
		return; /* invalid */

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

	/* extract previously applied signatures. */
	CScript script(tx.vin[0].scriptSig);
	CScript::const_iterator pc = script.begin();
	vector<cbuff> vsig;
	opcodetype opcode;
	nUnsolved = 0;
	if (!script.GetOp(pc, opcode) || opcode != OP_0)
		return; /* invalid prefix of notary multi-sig script. */
	for (i = 0; i < nMinConsensus; i++) {
		if (!script.GetOp(pc, opcode, vch))
			break;
		if (vch.size() == 0)
			nUnsolved++;
		vsig.push_back(vch);
	}
	if (nUnsolved == 0) {
		return; /* multi-sig for tx is already signed. */
	}

	CScript scriptRedeem;
	bool fConsensus;
	GenerateValidateScript(wallet, fConsensus, scriptRedeem, kSend);
	if (!fConsensus) {
		return; /* invalid state -- no consensus was formed. */
	}

	/* increment sequence index. */
	uint32_t nSeq = (tx.vin[0].nSequence & 0xFFFF) + 1;
	if (tx.GetVersion() >= 2) 
		nSeq |= CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG;
	/* use final 'locked' sequence for signing. */
	tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;

	CScript scriptSig;
	scriptSig << OP_0;
	nUnsolved = 0;
	bool fUpdated = false;
	for (int i = 0; i < nMinConsensus; i++) {
		ECKey key;
		bool fSolved;

		if (i < vsig.size() && vsig[i].size() != 0) {
			/* signature has already been gathered. */
			scriptSig << vsig[i];
			continue;
		}

		/* sign local pubkeys */
		fSolved = false;
		if (//nUnsolved == 0 && /* notaries fill keys in order */ 
				wallet->GetECKey(kSend[i].GetID(), key)) {
			int nHashType = SIGHASH_ALL;
			cbuff result;

			/* sign redeem script (base sigver) */
			uint256 sighash = base_SignatureHash(scriptRedeem, tx, 0, nHashType);
			fSolved = key.Sign(sighash, result);
			if (fSolved) {
				result.push_back((unsigned char)nHashType);
				scriptSig << result;
				fUpdated = true;
			}
		}
		if (!fSolved) {
			scriptSig << OP_0; /* "null" placeholder */
			nUnsolved++;
		}
	}
	if (nUnsolved == 0) {
		/* tx is ready to be shipped. */
		nSeq = CTxIn::SEQUENCE_FINAL - 1;
	}

	/* over-write transaction with new signature(s). */
	if (fUpdated) {
		/* lock sequence */
		tx.vin[0].nSequence = nSeq;
		if (tx.vin[0].nSequence == CTxIn::SEQUENCE_FINAL)
			return; /* invalid state */

		/* input signature */
		CScript scriptSuffix(pc, script.end());
		scriptSig += scriptSuffix;
		tx.vin[0].scriptSig = scriptSig; 

		Debug("(%s) UpdateValidateNotaryTx: updated tx \"%s\" with %d unsolved signatures.\n", iface->name, tx.GetHash().GetHex().c_str(), nUnsolved);
	}

}

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


	CIdent springIdent;
	CTxMatrix *m = tx.GenerateSpringMatrix(ifaceIndex, springIdent);
	if (!m)
		return (false); /* not applicable */

	uint160 hashMatrix = m->GetHash();
	int64 min_tx = (int64)iface->min_tx_fee;

	CScript scriptPubKeyOrig;
	CCoinAddr addr(ifaceIndex, stringFromVch(springIdent.vAddr));
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

	CTransaction id_tx;
	bool hasIdent = GetTxOfIdent(iface, hashIdent, id_tx);
	if (!hasIdent) {
		wallet->mapIdent.erase(hashIdent); /* invalido */
		return (NULL);
	}

//	ident = (CIdent&)tx.certificate;
	CIdent *springIdent = id_tx.GetIdent();
	if (!springIdent) {
		wallet->mapIdent.erase(hashIdent); /* invalido */
		return (NULL);
	}

	//shgeo_loc(&ident.geo, &lat, &lon, NULL);
	shgeo_loc(&springIdent->geo, &lat, &lon, NULL);
	if (!is_spring_loc(lat, lon)) {
		wallet->mapIdent.erase(hashIdent); /* invalido */
		return (NULL);
	}

// TODO: verify
	ident = *springIdent; 

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

	CTransaction id_tx;
	if (!GetTxOfIdent(iface, matrix.hRef, id_tx)) {
		return error(SHERR_INVAL, "VerifySpringMatrix: invalid ident tx.");
	}

#if 0
	CCert *cert = tx.GetCertificate();
	if (!cert)
		return (error(SHERR_INVAL, "VerifySptringMatrix: invalid reference hash"));

	CIdent& ident = (CIdent&)(*cert);
#endif

	CIdent *springIdent = id_tx.GetIdent();
	if (!springIdent) {
		return (error(SHERR_INVAL, "VerifySptringMatrix: invalid reference hash"));
	}

	shgeo_loc(&springIdent->geo, lat_p, lon_p, NULL);
	if (!is_spring_loc(*lat_p, *lon_p)) {
		return error(SHERR_INVAL, "VerifySpringMatrix: invalid spring location.");
	}

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
	const CTxMatrix& matrix = tx.matrix;

	if (pindex->nHeight != matrix.nHeight)
		return;

	CTransaction id_tx;
	if (!GetTxOfIdent(iface, matrix.hRef, id_tx))
		return;

	/* re-establish location bits in spring matrix. */
//	CIdent& ident = (CIdent&)id_tx.certificate;
	CIdent *springIdent = id_tx.GetIdent();
	if (!springIdent) {
		return;
	}

	shnum_t lat, lon;
	//shgeo_loc(&springIdent.geo, &lat, &lon, NULL);
	shgeo_loc(&springIdent->geo, &lat, &lon, NULL);
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


