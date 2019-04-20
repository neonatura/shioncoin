
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>

using namespace std;
using namespace json_spirit;

#include "block.h"
#include "wallet.h"
#include "ext_param.h"

#define EXTPARAM_BLOCKSIZE "blocksize"
#define EXTPARAM_MINFEE "minfee"

/* The minimum percentage for a parameter setting change. */
#define MIN_PARAM_CONCENSUS_PERCENT 90.0

#define MIN_PARAM_CONCENSUS_TOTAL 10240

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
 * Verify the integrity of an param transaction.
 */
bool VerifyParamTx(CTransaction& tx, int& mode)
{
  uint160 hashParam;
  int nOut;

  /* verify hash in pub-script matches param hash */
	CScript paramScript;
	if (!GetExtOutput(tx, OP_PARAM, mode, nOut, paramScript))
		return (false);

  if (!DecodeParamHash(tx.vout[nOut].scriptPubKey, mode, hashParam)) {
    return (false); /* no param hash in output */
  }

  CParam *param = tx.GetParam();
	if (!param)
		return (false);

  if (hashParam != param->GetHash()) {
		/* param hash mismatch */
    return error(SHERR_INVAL, "VerifyParam: transaction references invalid param hash.");
  }

	/* label is not [currently] used, but still restricted in size. */
  if (param->GetLabel().size() > 135)
    return error(SHERR_INVAL, "VerifyParam: label exceeds 135 characters.");

  return (true);
}

Object CParam::ToValue()
{
  Object obj;

	obj.push_back(Pair("hash", GetHash().GetHex()));
	obj.push_back(Pair("mode", GetMode()));
	obj.push_back(Pair("value", GetValue()));

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
		return (MAX_BLOCK_SIZE(iface));
	} 

	if (strName == "minfee") {
		return (MIN_RELAY_TX_FEE(iface));
	}

	return (0);
}

bool IsValidParamTxConcensus(CIface *iface, CParam *param, int64_t nDefault)
{

	/* Propose an alternate block-size maximum. */
	if (param->GetMode() == EXTPARAM_BLOCKSIZE) {
		if (param->nValue != nDefault &&
				param->nValue != (nDefault * 2) &&
				param->nValue != (nDefault / 2))
			return (false);
		if (param->nValue < 4096000 || /* 4m */
				param->nValue > 131072000) /* 128m */
			return (false);
	}

	/* Propose an alternate tx relay fee. */
	if (param->GetMode() == EXTPARAM_MINFEE) {
		if (param->nValue != nDefault &&
				param->nValue != (nDefault / 10) &&
				param->nValue != (nDefault * 10))
			return (false);
		if (param->nValue < 100 || /* 0.00000100 */
				param->nValue > 100000000) /* 1.0 */
			return (false);
	}

	return (true);
}

bool GetParamTxConsensus(CIface *iface, string strName, int64_t& nValue)
{
  CWallet *wallet = GetWallet(iface);
	map<int64_t,unsigned int> mapParam;
	vector<unsigned int> vDel;
	unsigned int nTotal;

	if (strName.length() > MAX_SHARE_NAME_LENGTH)
		return (false);

	int64_t nDefValue = GetParamTxDefaultValue(iface, strName);
	if (nDefValue == 0)
		return (error(ERR_INVAL, "(%s) GetParamTxConcensus: unknown parameter \"%s\".", iface->name, strName.c_str()));

	nTotal = 0;
	for (unsigned int i = 0; i < wallet->mapParam.size(); i++) {
		CParam& param = wallet->mapParam[i];
		if (param.GetMode() != strName)
			continue;
		if (!IsValidParamTxConcensus(iface, &param, nDefValue))
			continue;

		if (param.IsExpired()) {
			vDel.insert(vDel.end(), i);
			continue;
		}

		nTotal++;
		mapParam[param.nValue]++;
	}
	if (nTotal < MIN_PARAM_CONCENSUS_TOTAL)
		return (false); /* not enough tallies */

	/* remove archival tallies */
	for (unsigned int idx = (vDel.size() - 1); idx >= 0; idx--) {
		const unsigned int& p_idx = vDel[idx];
		wallet->mapParam.erase(wallet->mapParam.begin() + p_idx);
	}

	int64_t nRetValue = 0;

	unsigned int nMax = 0;
	unsigned int nLastMax = 0;
	BOOST_FOREACH(const PAIRTYPE(int64_t, unsigned int)& item, mapParam) {
		if (item.second > nMax) {
			nLastMax = nMax;
			nMax = item.second;
			/* return highest consensus */
			nRetValue = item.first;  
		}
	}

	/* consensus must be at least 90% */
	if ((100.0 / (double)nMax * (double)nLastMax) < MIN_PARAM_CONCENSUS_PERCENT) {
		return (false);
	}

	/* no consensus to change current default. */
	if (nRetValue == nDefValue)
		return (false);

	if (nRetValue == 0)
		return (false); /* not permitted */

	nValue = nRetValue;
	return (true);
}

bool ConnectParamTx(CIface *iface, CTransaction *tx)
{
  CWallet *wallet = GetWallet(iface);
	CParam *param;

	param = tx->GetParam();
	if (!param)
		return (false);

	wallet->mapParam.insert(wallet->mapParam.begin(), *param);

	int64_t nNewValue;
	if (GetParamTxConsensus(iface, param->GetMode(), nNewValue)) {
Debug("DEBUG: GetParamTxConsensus: success: \"%s\" = %lld", param->GetMode().c_str(), nNewValue);
	}

	return (true);
}

bool DisconnectParamTx(CIface *iface, CTransaction *tx)
{
  CWallet *wallet = GetWallet(iface);
	CParam *param;

	param = tx->GetParam();
	if (!param)
		return (false); /* not a param extended transaction. */

	if (wallet->mapParam.size() == 0)
		return (false); /* uninitialized */

	CParam& wparam = wallet->mapParam.front();
	if (wparam.GetHash() != param->GetHash())
		return (false); /* out of order */

	wallet->mapParam.erase(wallet->mapParam.begin());
	return (true);
}

int update_param_tx(CIface *iface, string strAccount, string strParam, int64_t valParam, CWalletTx& wtx)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (!wallet)
		return (ERR_INVAL);

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

	Debug("(%s) update_param_tx: strParam(%s) valParam(%lld).",
			iface->name, strParam.c_str(), (long long)valParam);

	return (0);
}

