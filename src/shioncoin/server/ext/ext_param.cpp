
/*
 * @copyright
 *
 *  Copyright 2018 Brian Burrell
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
#include "json_spirit_reader_template.h"
#include "json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>

using namespace std;
using namespace json_spirit;

#include "block.h"
#include "wallet.h"
#include "versionbits.h"
#include "ext_param.h"

/* The minimum percentage for a parameter setting change. */
#define MIN_PARAM_CONCENSUS_PERCENT 90.0

#define MIN_PARAM_CONCENSUS_TOTAL 10240

bool HasParamConsensus(CIface *iface, CBlockIndex *pindexPrev)
{
	int ifaceIndex = GetCoinIndex(iface);

	if (ifaceIndex != TEST_COIN_IFACE &&
			ifaceIndex != TESTNET_COIN_IFACE &&
			ifaceIndex != SHC_COIN_IFACE)
		return (false);

	if (!pindexPrev)
		pindexPrev = GetBestBlockIndex(iface);
	if (!pindexPrev)
		return (false);
	if (VersionBitsState(pindexPrev, iface, DEPLOYMENT_PARAM) != THRESHOLD_ACTIVE)
		return (false);

	return (true);
}

bool DecodeParamHash(const CScript& script, int& mode, uint160& hash)
{
  CScript::const_iterator pc = script.begin();
  opcodetype opcode;
  int op;

  if (!script.GetOp(pc, opcode)) {
    return false;
  }
  mode = opcode; /* extension mode (new/activate/update) */
  if (mode < 0xf0 || mode > 0xf9)
    return false;

  if (!script.GetOp(pc, opcode)) { 
    return false;
  }
  if (opcode < OP_1 || opcode > OP_16) {
    return false;
  }
  op = CScript::DecodeOP_N(opcode); /* extension type (param) */
  if (op != OP_PARAM) {
    return false;
  }

  vector<unsigned char> vch;
  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  if (opcode != OP_HASH160)
    return (false);

  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  hash = uint160(vch);
  return (true);
}

bool IsParamOp(int op) {
	return (op == OP_PARAM);
}

string paramFromOp(int op) {
	switch (op) {
	case OP_EXT_UPDATE:
		return "paramupdate";
	default:
		return "<unknown param op>";
	}
}

int64 GetParamOpFee(CIface *iface)
{
	return (MIN_RELAY_TX_FEE(iface));
}

bool IsParamTx(const CTransaction& tx)
{
	CScript script;
	int mode;
	int nOut;

  if (!tx.isFlag(CTransaction::TXF_PARAM))
    return (false);

	if (!GetExtOutput(tx, OP_PARAM, mode, nOut, script))
		return (false);

  return (true);
}

/**
 * Verify the integrity of a param transaction.
 */
bool VerifyParamTx(CTransaction& tx, int& mode)
{
	CParam *param;
  uint160 hashParam;
  int nOut;

  param = tx.GetParam();
	if (!param)
		return (false);

  /* verify hash in pub-script matches param hash */
	CScript paramScript;
	if (!GetExtOutput(tx, OP_PARAM, mode, nOut, paramScript))
		return (false);

  if (!DecodeParamHash(tx.vout[nOut].scriptPubKey, mode, hashParam)) {
    return (false); /* no param hash in output */
  }

	const uint160& phash = param->GetHash();
  if (hashParam != phash) {
		/* param hash mismatch */
    return error(SHERR_INVAL, "VerifyParam: param \"%s\" transaction output references invalid param hash: \"%s\" [param: %s].", phash.GetHex().c_str(), tx.vout[nOut].scriptPubKey.ToString().c_str(), param->ToString().c_str());
  }

	/* verify param ext-tx version is appropriate. */
	if (param->GetVersion() < 1) {
    return error(SHERR_INVAL, "VerifyParam: param \"%s\" references invalid version (%d).", phash.GetHex().c_str(), param->GetVersion());
	}
	if (param->GetVersion() == 1 && mode != OP_EXT_UPDATE) {
    return error(SHERR_INVAL, "VerifyParam: param \"%s\" has invalid operation mode (%d).", phash.GetHex().c_str(), mode);
	}

	/* label is used to indicate param mode. */
  if (param->GetMode().size() > CParam::MAX_MODE_LENGTH) {
    return error(SHERR_INVAL, "VerifyParam: param \"%s\" mode exceeds 135 characters (%d).", phash.GetHex().c_str(), param->GetMode().size());
	}

	if (mode == OP_EXT_UPDATE) {
		const CTxOut& txout = tx.vout[nOut];

		/* update operation is constrained to promote inclusion of additional outputs. */
		if (txout.nValue != 0)
			return (error(ERR_INVAL, "VerifyParam: param \"%s\" has invalid output coin value (%f).", phash.GetHex().c_str()), ((double)txout.nValue/COIN));
	}

  return (true);
}

int CParam::VerifyTransaction()
{
  int err;

  err = CExtCore::VerifyTransaction();
  if (err)
    return (err);

  return (0);
}

Object CParam::ToValue()
{
  Object obj = CExtCore::ToValue();

	obj.push_back(Pair("hash", GetHash().GetHex()));
//	obj.push_back(Pair("mode", GetMode()));
	obj.push_back(Pair("value", (int64_t)GetValue()));

  return (obj);
}

const uint160 CParam::GetHash()
{
	uint256 hashOut = SerializeHash(*this);
	unsigned char *raw = (unsigned char *)&hashOut;
	cbuff rawbuf(raw, raw + sizeof(hashOut));
	return Hash160(rawbuf);
}

std::string CParam::ToString()
{
  return (write_string(Value(ToValue()), false));
}

int64_t GetParamTxDefaultValue(CIface *iface, string strName)
{

	if (strName == "blocksize") {
		return (DEFAULT_MAX_BLOCK_SIZE(iface));
	} 

	if (strName == "minfee") {
		return (DEFAULT_MIN_RELAY_TX_FEE(iface));
	}

	return (0);
}

int64_t GetParamTxValue(CIface *iface, string strName)
{

	if (strName == "blocksize") {
		return (MAX_BLOCK_SIZE(iface));
	} 

	if (strName == "minfee") {
		return (MIN_RELAY_TX_FEE(iface));
	}

	return (0);
}

bool IsValidParamTxConsensus(string strMode, int64_t nValue, int64_t nCurrent)
{

	if (nValue == 0)
		return (false);

	/* Propose an alternate block-size maximum. */
	if (strMode == EXTPARAM_BLOCKSIZE) {
		if (nValue != nCurrent &&
				nValue != (nCurrent * 2) &&
				nValue != (nCurrent / 2))
			return (false);
		if (nValue < 1024000 || /* 1m */
				nValue > 131072000) /* 128m */
			return (false);
	}

	/* Propose an alternate tx relay fee. */
	if (strMode == EXTPARAM_MINFEE) {
		if (nValue != nCurrent &&
				nValue != (nCurrent / 10) &&
				nValue != (nCurrent * 10))
			return (false);
		if (nValue < 100 || /* 0.00000100 */
				nValue >= 100000000) /* 1.0 */
			return (false);
	}

	return (true);
}

bool IsValidParamTxConsensus(CIface *iface, CParam *param, int64_t nCurrent)
{
	if (!iface || !param)
		return (false);
	if (nCurrent == 0)
		nCurrent = GetParamTxValue(iface, param->GetMode());
	return (IsValidParamTxConsensus(param->GetMode(), param->GetValue(), nCurrent));
}

bool GetParamTxConsensus(CIface *iface, string strName, int64_t nTime, int64_t& nValue)
{
  CWallet *wallet = GetWallet(iface);
	map<int64_t,unsigned int> mapParam;
	vector<unsigned int> vDel;
	unsigned int nTotal;

	if (strName.size() > CParam::MAX_MODE_LENGTH)
		return (false); /* invalid */

	int64_t nCurrentValue = GetParamTxValue(iface, strName);
	if (nCurrentValue == 0)
		return (error(ERR_INVAL, "(%s) GetParamTxConsensus: unknown parameter \"%s\".", iface->name, strName.c_str()));

	nTotal = 0;
	for (unsigned int i = 0; i < wallet->mapParam.size(); i++) {
		CParam& param = wallet->mapParam[i];
		if (param.GetMode() != strName)
			continue;
		if (!IsValidParamTxConsensus(iface, &param, nCurrentValue))
			continue;

		if (param.IsExpired(nTime)) {
			if (param.GetExpireTime() < (GetTime() - 31536000)) /* 1y */
				vDel.insert(vDel.end(), i);
			continue;
		}

		nTotal++;
		mapParam[param.nValue]++;
	}
	if (nTotal < MIN_PARAM_CONCENSUS_TOTAL)
		return (false); /* not enough tallies */

	int64_t nRetValue = 0;
	unsigned int nMax = 0;
	BOOST_FOREACH(const PAIRTYPE(int64_t, unsigned int)& item, mapParam) {
		if (item.second > nMax) {
			/* return highest consensus */
			nMax = item.second;
			nRetValue = item.first;  
		}
	}
	if (nRetValue == 0)
		return (false);

	if (vDel.size() != 0) {
		/* remove archival tallies */
		for (unsigned int idx = (vDel.size() - 1); idx >= 0; idx--) {
			const unsigned int& p_idx = vDel[idx];
			wallet->mapParam.erase(wallet->mapParam.begin() + p_idx);
		}
	}

	/* no consensus to change current default. */
	if (nRetValue == nCurrentValue)
		return (false);

	/* consensus must be at least 90% */
	double dPer = 100.0 / (double)nTotal * (double)nMax;
	if (dPer < MIN_PARAM_CONCENSUS_PERCENT) {
		return (false);
	}

	nValue = nRetValue;
	return (true);
}

static bool ApplyParam(CIface *iface, string strMode, uint64_t nNewValue)
{

	if (strMode == EXTPARAM_BLOCKSIZE) {
		iface->max_block_size = nNewValue;
	} else if (strMode == EXTPARAM_MINFEE) {
		iface->min_relay_fee = nNewValue;
	}

	return (true);
}

bool ConnectParamTx(CIface *iface, CTransaction *tx, CBlockIndex *pindexPrev)
{
  CWallet *wallet = GetWallet(iface);
	CParam *param;
	int op_mode;

	if (!iface || !tx || !pindexPrev)
		return (false); /* sanity */

	if (!HasParamConsensus(iface, pindexPrev))
		return (false);

	param = tx->GetParam();
	if (!param)
		return (false);

	if (!VerifyParamTx(*tx, op_mode))
		return (error(ERR_INVAL, "ConnectParamTx: unable to verify param."));
	if (op_mode != OP_EXT_UPDATE)
		return (true); /* no-op */

	{
		LOCK(wallet->cs_wallet);

		wallet->mapParam.insert(wallet->mapParam.begin(), *param);

		int64_t nNewValue;
		const string& strMode = param->GetMode();
		if (GetParamTxConsensus(iface, strMode, pindexPrev->nTime, nNewValue) &&
				nNewValue != GetParamTxValue(iface, strMode)) {
			if (!ApplyParam(iface, strMode, nNewValue)) {
				return (error(ERR_INVAL, "(%s) ConnectParamTx: error applying new param \"%s\" value \"%llu\".", iface->name, strMode.c_str(), nNewValue));
			}

			/* record application of param. */
			uint256 hash = tx->GetHash();
			wallet->mapParamArch.insert(wallet->mapParamArch.end(), hash);

			Debug("(%s) ConnectParamTx: set \"%s\" to %lld", iface->name, param->GetMode().c_str(), nNewValue);
		}
	}

	return (true);
}

int64_t GetBestParamValue(CIface *iface, string strName)
{
  CWallet *wallet = GetWallet(iface);

	{
		LOCK(wallet->cs_wallet);

		vector<uint256>::reverse_iterator it = wallet->mapParamArch.rbegin();
		for (; it != wallet->mapParamArch.rend(); ++it) {
			const uint256& hash = *it;
			CTransaction tx;
			if (!GetTransaction(iface, hash, tx, NULL))
				continue;
			CParam *param = tx.GetParam();
			if (!param)
				continue;
			if (param->GetMode() != strName)
				continue;

			/* found last instance registered for mode. */
			return (param->GetValue());
		}
	}

	/* use default */
	return (GetParamTxDefaultValue(iface, strName));
}

bool DisconnectParamTx(CIface *iface, CTransaction *tx)
{
  CWallet *wallet = GetWallet(iface);
	CParam *param;
	int op_mode;

	if (!VerifyParamTx(*tx, op_mode))
		return (false);
	if (op_mode != OP_EXT_UPDATE)
		return (true); /* no-op */

	param = tx->GetParam();
	if (!param)
		return (false); /* not a param extended transaction. */

	if (wallet->mapParam.size() == 0)
		return (false); /* uninitialized */

	CParam& wparam = wallet->mapParam.front();
	if (wparam.GetHash() != param->GetHash())
		return (false); /* out of order */

	/* erase from param vector. */
	wallet->mapParam.erase(wallet->mapParam.begin());

	uint256 hash = tx->GetHash();
	vector<uint256>& l = wallet->mapParamArch;
	vector<uint256>::iterator it = std::find(l.begin(), l.end(), hash);
	if (it != l.end()) {
		/* erase from arch of applied params. */
		l.erase(it);

		/* undo param */
		const string& strName = wparam.GetMode();
		int64_t nNewValue = GetBestParamValue(iface, strName);
		if (!ApplyParam(iface, strName, nNewValue)) {
			return (error(ERR_INVAL, "(%s) DisconnectParamTx: error applying new param \"%s\" value \"%llu\".", iface->name, strName.c_str(), nNewValue));
		}
	}

	return (true);
}

void AddParamIfNeccessary(CIface *iface, CWalletTx& wtx)
{
	if (!opt_bool(OPT_PARAM_TX)) return; /* not configured to vote on params. */
	int64_t nBlockSize = (int64_t)opt_num(OPT_BLOCK_SIZE);
	int64_t nMinFee = (int64_t)opt_num(OPT_MIN_FEE);
	int err;

	if (!HasParamConsensus(iface))
		return;
	
	if (nBlockSize != GetParamTxValue(iface, EXTPARAM_BLOCKSIZE)) {
		/* node affinity is towards a different block size. */
		err = update_param_tx(iface, EXTPARAM_BLOCKSIZE, nBlockSize, wtx);
		if (!err)
			return; /* success */
	}

	if (nMinFee != GetParamTxValue(iface, EXTPARAM_MINFEE)) {
		/* node affinity is towards a different minimum fee. */
		err = update_param_tx(iface, EXTPARAM_MINFEE, nMinFee, wtx);
		if (!err)
			return; /* success */
	}

}

int update_param_tx(CIface *iface, string strParam, int64_t valParam, CWalletTx& wtx)
{
	CWallet *wallet = GetWallet(iface);

	if (!wallet)
		return (ERR_INVAL);

	if (!IsValidParamTxConsensus(strParam, valParam,
				GetParamTxValue(iface, strParam)))
		return (SHERR_INVAL);

	CParam *param = wtx.UpdateParam(strParam, valParam);
	if (!param)
		return (SHERR_INVAL);

	CScript scriptPubKey;
	uint160 paramHash = param->GetHash();
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_PARAM) << OP_HASH160 << paramHash << OP_2DROP << OP_RETURN << OP_0;

	CTxOut paramOut;
	paramOut.nValue = 0;
	paramOut.scriptPubKey = scriptPubKey; 
	wtx.vout.insert(wtx.vout.end(), paramOut);

	Debug("(%s) PARAM-UPDATE: %s", iface->name, param->ToString().c_str());
	return (0);
}


