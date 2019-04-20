
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
#include "sexe.h"
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>
#include "wallet.h"
#include "block.h"
#include "txcreator.h"
#include "exec.h"

using namespace std;
using namespace json_spirit;

#ifdef __cplusplus
extern "C" {
#endif
extern int sexe_compile_pmain(sexe_t *L);
extern sexe_t *sexe_init(void);
extern int sexe_popen(shbuf_t *buff, sexe_t **mod_p);
extern shpeer_t *shcoind_peer(void);
extern int sexe_io_unserialize(sexe_t *S, char *tag, shjson_t **j_p);
extern void sexe_pclose(sexe_t *S);
extern int sexe_pgetdef(sexe_t *S, char *name, shjson_t **arg_p);
extern int sexe_pget(sexe_t *S, char *name, shjson_t **arg_p);
extern int sexe_pset(sexe_t *S, char *name, shjson_t *arg);
extern int sexe_pevent(sexe_t *S, char *event_name, shjson_t *data);
extern void sexe_pushboolean(sexe_t *S, int b);
extern void sexe_event_register(lua_State *L, char *e_name, lua_CFunction f);
extern int sexe_io_serialize(sexe_t *S, char *tag, shjson_t *j);
extern int sexe_prun(sexe_t *S, int argc, char **argv);
extern int sexe_pcall_json(sexe_t *S, char *func, shjson_t *call);



#ifdef __cplusplus
}
#endif


#define MIN_EXEC_FEE 1000

#define MIN_EXEC_CHECKPOINT_HEIGHT(iface) (iface->coinbase_maturity)

static string jsonstr2value(shjson_t *obj, char *var_name)
{
	string ret_val(shjson_str(obj, var_name, ""));
	return (ret_val);
}

static Value json2value(shjson_t *obj, char *var_name)
{
	Value resp;

	if (shjson_type(obj, var_name) == SHJSON_NUMBER) {
		double ret_val = shjson_num(obj, var_name, 0.0);
		if (floor(ret_val) == ret_val) {
			resp = Value((int64_t)ret_val);
		} else {
			resp = Value(ret_val);
		}
	} else if (shjson_type(obj, var_name) == SHJSON_STRING) {
		string ret_val(shjson_str(obj, var_name, ""));
		resp = Value(string(ret_val));
	} else if (shjson_type(obj, var_name) == SHJSON_BOOLEAN) {
		bool ret_val = shjson_bool(obj, var_name, FALSE);
		resp = Value(ret_val ? true : false);
	} else if (shjson_type(obj, var_name) == SHJSON_OBJECT) {
		Object vobj;
		shjson_t *t_obj = shjson_obj(obj, var_name); 
		shjson_t *node;

		for (node = t_obj->child; node; node = node->next) {
			vobj.push_back(Pair(node->string, json2value(t_obj, node->string)));
		}
		resp = vobj;
	} else { //if (shjson_type(obj, var_name) == SHJSON_NULL) {
		resp = Value::null;
	}

	return (resp);
}


static void obj2json(shjson_t *obj, Object valObject)
{
	int i;

	BOOST_FOREACH(const Pair& s, valObject) {
		const string strLabel = s.name_;
		char *var_name = (char *)strLabel.c_str();
		Value val = s.value_;

		if (val.type() == str_type) {
			shjson_str_add(obj, var_name, (char *)val.get_str().c_str());
		} else if (val.type() == int_type) {
			shjson_num_add(obj, var_name, (double)val.get_int());
		} else if (val.type() == bool_type) {
			shjson_bool_add(obj, var_name, (val.get_bool() ? TRUE : FALSE));
		} else if (val.type() == real_type) {
			shjson_num_add(obj, var_name, val.get_real());
		}
	}




}

static vector<string> json2vector(shjson_t *obj, char *var_name)
{
	vector<string> ret;
	shjson_t *j_ar;
	shjson_t *node;

	if (!var_name) {
		j_ar = obj;
	} else {
		j_ar = shjson_obj_get(obj, var_name);
	}

	for (node = j_ar->child; node; node = node->next) {
		ret.push_back(jsonstr2value(node, NULL));
	}

	return (ret);
}

static string StripExtAccountName(string strAccount)
{
  if (strAccount.length() != 0 && strAccount.at(0) == '@')
    strAccount = strAccount.substr(1);
  return (strAccount);
}


#if 0
shpool_t *pool;

void InitExecPool()
{
  if (pool) return;

  unsigned int idx;
  pool = shpool_init();
  (void)shpool_get(pool, &idx);
}

static cbuff GetExecPoolData(uint32_t idx)
{
  unsigned char *raw;
  size_t raw_len;
  shbuf_t *buff;

  InitExecPool();

  buff = shpool_get_index(pool, idx);
  if (!buff)
    return (cbuff());

  raw = shbuf_data(buff);
  raw_len = shbuf_size(buff);
  return (cbuff(raw, raw + raw_len));
}

static unsigned int SetExecPoolData(cbuff vData)
{
  shbuf_t *buff;
  unsigned int indexPool;

  InitExecPool();

  buff = shpool_get(pool, &indexPool);
  shbuf_clear(buff);
  shbuf_cat(buff, vData.data(), vData.size());
  
  return (indexPool);
}

static void ClearExecPoolData(int idx)
{
  unsigned char *raw;
  size_t raw_len;
  shbuf_t *buff;

  if (idx == 0)
    return;

  InitExecPool();

  buff = shpool_get_index(pool, idx);
  if (!buff)
    return;

  shbuf_clear(buff);
}
#endif

static bool AccountFromAddress(int ifaceIndex, CCoinAddr& addr, string& strAccount)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  bool found = false;

	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
	{
		const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
		const string& account = item.second;
		if (address == addr) {
			addr = address;
			strAccount = account;
			found = true;
			break;
		}
	}

	return (found);
}

static int IndexOfExecOutput(const CTransaction& tx)
{
  int idx;

  idx = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {

    const CScript& script = out.scriptPubKey;
    opcodetype opcode;
    CScript::const_iterator pc = script.begin();
    if (script.GetOp(pc, opcode) &&
        opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
			if (script.GetOp(pc, opcode) && 
					opcode == CScript::EncodeOP_N(OP_EXEC))
        break;
    }

    idx++;
  }
  if (idx == tx.vout.size())
    return (-1); /* uh oh */

  return (idx);
}

exec_list *GetExecTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapExec);
}

exec_label_list *GetExecLabelTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapExecLabel);
}

exec_call_list *GetExecCallTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapExecCall);
}
exec_call_list *GetExecCallPendingTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapExecCallPending);
}

/**
 * Obtain the tx that defines this exec.
 */
bool GetTxOfExec(CIface *iface, const uint160& hashExec, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  exec_list *execes = GetExecTable(ifaceIndex);
	int mode;
  bool ret;

  if (execes->count(hashExec) == 0) {
    return false; /* nothing by that name, sir */
  }

	uint256 hTx = (*execes)[hashExec];
	CTransaction txIn;
	if (!::GetTransaction(iface, hTx, txIn, NULL))
		return (false);

  if (!IsExecTx(txIn, mode)) 
    return false; /* inval; not an exec tx */

  if (mode == OP_EXT_NEW) {
		CExec *exec = txIn.GetExec();
		if (exec->IsExpired()) {
			return false;
		}
	}

  tx.Init(txIn);
  return true;
}

bool GetExecByHash(CIface *iface, const uint160& hExec, CExec& execOut)
{
	int mode;

	CTransaction txIn;
	if (!GetTxOfExec(iface, hExec, txIn))
		return false;

  if (!IsExecTx(txIn, mode)) 
    return false; /* inval; not an exec tx */

  if (mode != OP_EXT_NEW)
		return false; /* only returns exec classes */

	execOut = (const CExec&)txIn.exec;
	if (execOut.IsExpired())
		return false;

  return true;
}

bool IsValidExecHash(CIface *iface, const uint160& hExec)
{
	int mode;

	CTransaction txIn;
	if (!GetTxOfExec(iface, hExec, txIn))
		return false;

  if (!IsExecTx(txIn, mode)) 
    return false; /* inval; not an exec tx */

  return true;
}

bool GetCallByHash(CIface *iface, const uint160& hCall, CExecCall& callOut)
{
	int mode;

	CTransaction txIn;
	if (!GetTxOfExec(iface, hCall, txIn))
		return false;

  if (!IsExecTx(txIn, mode)) 
    return false; /* inval; not an exec tx */

  if (mode != OP_EXT_GENERATE)
		return false; /* only returns class method calls */

	callOut = (const CExecCall&)txIn.exec;
	if (callOut.IsExpired())
		return false;

  return true;
}

#if 0
bool GetCheckpointByHash(CIface *iface, const uint160& hCall, CExecCheckpoint& cpOut)
{
	int mode;

	CTransaction txIn;
	if (!GetTxOfExec(iface, hCall, txIn))
		return false;

  if (!IsExecTx(txIn, mode)) 
    return false; /* inval; not an exec tx */

  if (mode != OP_EXT_UPDATE)
		return false; /* only returns class method calls */

	cpOut = (const CExecCheckpoint&)txIn.exec;
	if (cpOut.IsExpired())
		return false;

  return true;
}
#endif

bool GetExecByLabel(CIface *iface, string strLabel, CExec& execIn)
{
	exec_label_list *l_list = GetExecLabelTable(GetCoinIndex(iface));
	CTransaction txIn;

	if (l_list->count(strLabel) == 0)
		return (false);

	uint160& hExec = (*l_list)[strLabel];
	return (GetExecByHash(iface, hExec, execIn));
}

bool InsertExecTable(CIface *iface, const CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
	CBlock *block;
	int mode;

	if (!IsExecTx(tx, mode))
		return (false);
	if (mode != OP_EXT_NEW)
		return (false);

	const uint256& hTx = tx.GetHash();
	CExec *exec = tx.GetExec();
	const uint160& hExec = exec->GetHash();

	/* reference class name to exec hash */
	wallet->mapExecLabel[exec->GetLabel()] = exec->GetHash();

	/* add to exec/call transaction mapping table. */
	wallet->mapExec[hExec] = hTx;
}

bool InsertExecCallTable(CIface *iface, const uint160& hExec, const CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);

	CExecCall *call = tx.GetExecCall();
	const uint160& hCall = call->GetHash();

	/* add to processed exec call table */
	vector<uint160> vCall;
	if (wallet->mapExecCall.count(hExec) != 0)
		vCall = wallet->mapExecCall[hExec];
	vCall.push_back(hCall);
	wallet->mapExecCall[hExec] = vCall;

	/* remove from unprocessed exec call table. */
	if (wallet->mapExecCallPending.count(hExec) != 0) {
		vector<uint160>& l = wallet->mapExecCallPending[hExec];
		vector<uint160>::iterator position = std::find(l.begin(), l.end(), hCall);
		if (position != l.end())
			l.erase(position);
	}

	/* add to exec/call transaction mapping table. */
	wallet->mapExec[hCall] = tx.GetHash();
}

bool InsertExecCallPendingTable(CIface *iface, const uint160& hExec, const CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
	CExecCall *call = tx.GetExecCall();
	const uint160& hCall = call->GetHash();

	/* add to unprocessed exec call table */
	vector<uint160> vCall;
	if (wallet->mapExecCall.count(hExec) != 0)
		vCall = wallet->mapExecCall[hExec];
	vCall.push_back(hCall);
	wallet->mapExecCall[hExec] = vCall;

	/* remove from processed exec call table. */
	if (wallet->mapExecCall.count(hExec) != 0) {
		vector<uint160>& l = wallet->mapExecCall[hExec];
		vector<uint160>::iterator position = std::find(l.begin(), l.end(), hCall);
		if (position != l.end())
			l.erase(position);
	}

	/* add to exec/call transaction mapping table. */
	wallet->mapExec[hCall] = tx.GetHash();
}

bool IsExecPending(CIface *iface, const uint160& hExec)
{
  CWallet *wallet = GetWallet(iface);

#if 0
	if (!GetExecByHash(iface, hExec, execIn))
		return (false);
#endif
	
	if (wallet->mapExecCallPending.count(hExec) != 0)
		return (true);
	
	return (false);
}

/* is a processed exec call hash. */
bool IsExecCallHash(CIface *iface, const uint160& hExec, const uint160& hCall)
{
  CWallet *wallet = GetWallet(iface);

	if (wallet->mapExecCall.count(hExec) == 0) {
		/* nothing known */
		return (false);
	}
	
	vector<uint160>& vCall = wallet->mapExecCall[hExec];
	if (std::find(vCall.begin(), vCall.end(), hCall) != vCall.end())
		return (true);

	return (false);
}

static int ProcessExecGenerateTx(int ifaceIndex, CExec *execIn, CExecCall *exec, shjson_t **param_p, bool bGenerate)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
//  unsigned char *raw = (unsigned char *)exec->vContext.data();
  const uint160& hExec = execIn->GetHash();
  const uint160& hCall = exec->GetHash();
	char func_name[256];
	int64 sendValue = exec->GetSendValue(); 
	shjson_t *param;
	Value resp;

	if (!wallet)
		return (SHERR_INVAL);

  /* verify origin sig of SEXE class */
  if (!execIn->VerifySignature(ifaceIndex))
    return (SHERR_ACCESS);

	if (!bGenerate) {
		/* verify peer sig for function call */
		if (!exec->VerifySignature(ifaceIndex))
			return (SHERR_ACCESS);
	}

	param = *param_p;

	int64 nFee = (int64)(shjson_num(param, "value", 0) * COIN);

  CCoinAddr sendAddr = exec->GetSenderAddr(ifaceIndex);
	if (!execIn->CallStack(ifaceIndex, sendAddr, &param)) {
		char *err_str = shjson_str(param, "error", "n/a");
		error(SHERR_INVAL, "ProcessExecGenerateTx: CallStack: error calling method[%s]: %s", err_str, exec->ToString(ifaceIndex).c_str()); 
		return (SHERR_INVAL);
	}

#if 0
	if (bGenerate) {
/* TODO: create the underlying transactions. */
		shjson_t *p_node = shjson_obj_get(param, "context");
		if (p_node) {
			string strAccount;
			shjson_t *node;
			char *text;
			int err;

			if (!GetCoinAddr(wallet, sendAddr, strAccount)) {
				error(SHERR_REMOTE, "ProcessExecGenerateTx: wallet address \"%s\" not found", sendAddr.ToString().c_str());
				return (SHERR_REMOTE);
			}
			
			for (node = p_node->child; node; node = node->next) {
				string strName(node->string);

				text = shjson_print(shjson_obj_get(param, (char *)strName.c_str()));
				CWalletTx ctx_tx;
				err = init_ctx_tx(iface, ctx_tx, strAccount,
						strName, vchFromString(string(text)), NULL, true);
				free(text);
				if (err) {
					error(err, "ProcessExecGenerateTx: error initializing context \"%s\"", strName.c_str());
					return (err);
				}
			}

		}
	}
#endif

	int64 nSendFee = (int64)(shjson_num(param, "fee", 0) * COIN);
	if (bGenerate) {
		if (nSendFee > nFee)
			return (ERR_FEE);

		exec->SetSendValue(nSendFee);
		exec->SetChecksum(string(shjson_str(param, "checksum", "")));
		exec->SetResultHash(shjson_crc(param, "return"));

#if 0
		/* vContext is now achived via ToString() */
		char *json_str = shjson_print(param);
		exec->vContext = cbuff(json_str, json_str + strlen(json_str));
		free(json_str);
#endif


#if 0
		exec->SetSignContext();
#endif
		exec->InitTxChain();
	} else {
		if (nSendFee != nFee) {
			error(SHERR_INVAL, "ProcessExecGenerateTx: warning: processed fee(%f) does not equal recorded fee(%f)", (double)nSendFee/COIN, (double)nFee/COIN); 
		}

		uint64 hResult = shjson_crc(param, "return");
		if (exec->GetResultHash() != hResult) {
			/* the stored result does not equal what function returned. */
/* DEBUG: at which point should the call chain be reset? */
			return (SHERR_ILSEQ);
		}

#if 0
		/* TODO: verify the underlying transactions. */
		int tot = shjson_array_count(param, "context");
if (tot != 0) error(SHERR_INVAL, "DEBUG: ProcessExecGenerateTx: found x%d context: %s", tot, shjson_print(shjson_obj_get(param, "context")));
#endif
	}

	*param_p = param;

	return (0);
}

static shjson_t *exec_call_param(CIface *iface, CExec *exec, CExecCall *call)
{
  int ifaceIndex = GetCoinIndex(iface);
	shjson_t *param;
	string raw;

	param = shjson_init((char *)call->ToString(ifaceIndex).c_str());
	if (!param) {
		error(SHERR_INVAL, "CallExecChain: JSON conversion error.");
		return (NULL);
	}

	if (exec) {
		CCoinAddr ownAddr = exec->GetSenderAddr(ifaceIndex);
	  shjson_str_add(param, "class", (char *)exec->GetClassName().c_str());
	  shjson_str_add(param, "owner", (char *)ownAddr.ToString().c_str());
		shjson_num_add(param, "version", exec->GetVersion());
	}

//fprintf(stderr, "DEBUG: EXEC_CALL_PARAM: %s\n", shjson_print(param));
	return (param);
}

/**
 * Execute all pending exec generate transactions for a given class.
 */
bool CallExecChain(CIface *iface, CExec& exec, int& nCheckpoint)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	uint160 hExec = exec.GetHash();
	shjson_t *param;
	int err;

	nCheckpoint = 0;
	if (wallet->mapExecCallPending.count(hExec) != 0) {
		int64 nUpdateHeight = exec.GetStackHeight(ifaceIndex);

		vector<uint160> vCall;
		const vector<uint160>& call_list = wallet->mapExecCallPending[hExec];
		BOOST_FOREACH(const uint160& hCall, call_list) {
			vCall.insert(vCall.end(), hCall);
		}
		Debug("(%s) CallExecChain: refreshing run-time (%d calls) for class \"%s\" from block ehight %u.", iface->name, vCall.size(), exec.GetLabel().c_str(), (unsigned int)nUpdateHeight);

		BOOST_FOREACH(const uint160& hCall, vCall) {
			CTransaction tx;
			if (!GetTxOfExec(iface, hCall, tx)) {
				/* skip invalid 'exec call tx' record */
				continue;
			}

			CExecCall *call = tx.GetExecCall();
			if (call->GetCommitHeight() <= nUpdateHeight) {
				/* call has already been processed on local node. */
				continue;
			}

			param = exec_call_param(iface, &exec, call);
			if (!param) {
				/* hard error */
				return (error(SHERR_ILSEQ, "CallExecChain: JSON conversion error [call %s]", call->GetHash().GetHex().c_str()));
			}

			/* execute method call on published sexe class. */
			err = ProcessExecGenerateTx(ifaceIndex, &exec, call, &param, false);
			shjson_free(&param);
			if (!err) {
				nCheckpoint = MAX(nCheckpoint, call->GetCommitHeight());
			} else { /* soft error */
				error(err, "CallExecChain: ProcessExecGenerateTx");
			}

			/* insert new call tx */
			InsertExecCallTable(iface, hExec, tx);
		}

		wallet->mapExecCallPending.erase(hExec);
	}

	return (true);
}

static void _CloseStack(sexe_t *S)
{
	sexe_pclose(S);
}

static void ClearStackData(CIface *iface, CExec *exec)
{
	shjson_t *udata;
	sexe_t *S;
	shbuf_t *buff;
	int err;

	buff = shbuf_init();
	shbuf_cat(buff, exec->vContext.data(), exec->vContext.size());
	err = sexe_popen(buff, &S);
	shbuf_free(&buff);
	if (err)
		return;

	err = sexe_io_serialize(S, iface->name, NULL);
	_CloseStack(S);
}

void ResetExecChain(CIface *iface, const uint160& hExec)
{
  CWallet *wallet = GetWallet(iface);
	vector<uint160> vCall;
	vector<uint160> vEmptyCall;
	CExec exec;

	if (!GetExecByHash(iface, hExec, exec))
		return;

	ClearStackData(iface, &exec);

	vector<uint160>& vActiveCall = wallet->mapExecCall[hExec];
  BOOST_FOREACH(const uint160& hash, vActiveCall) {
		vCall.insert(vCall.end(), hash);
	}

	vector<uint160>& vPendCall = wallet->mapExecCallPending[hExec];
  BOOST_FOREACH(const uint160& hash, vPendCall) {
		vCall.insert(vCall.end(), hash);
	}

	/* move all calls to pending queue. */
	wallet->mapExecCall[hExec] = vEmptyCall;
	wallet->mapExecCallPending[hExec] = vCall;

	Debug("ResetExecChain: class \"%s\" (%d pending calls)", exec.GetClassName().c_str(), vCall.size());
}

bool DecodeExecHash(const CScript& script, int& mode, uint160& hash)
{
  CScript::const_iterator pc = script.begin();
  opcodetype opcode;
  int op;

  if (!script.GetOp(pc, opcode)) {
    return false;
  }
  mode = opcode; /* extension mode (new/update/remove) */
  if (mode < 0xf0 || mode > 0xf9)
    return false;

  if (!script.GetOp(pc, opcode)) { 
    return false;
  }
  if (opcode < OP_1 || opcode > OP_16) {
    return false;
  }
  op = CScript::DecodeOP_N(opcode); /* extension type (exec) */
  if (op != OP_EXEC) {
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



bool IsExecOp(int op) {
	return (op == OP_EXEC);
}


string execFromOp(int op) {
	switch (op) {
	case OP_EXT_NEW:
		return "execnew";
	case OP_EXT_UPDATE:
		return "execupdate";
	case OP_EXT_ACTIVATE:
		return "execactivate";
	case OP_EXT_GENERATE:
		return "execgenerate";
	case OP_EXT_TRANSFER:
		return "exectransfer";
	case OP_EXT_REMOVE:
		return "execremove";
	default:
		return "<unknown exec op>";
	}
}

bool DecodeExecScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) 
{
	opcodetype opcode;
  int mode;

	if (!script.GetOp(pc, opcode))
		return false;
  mode = opcode; /* extension mode (new/update/remove) */

	if (!script.GetOp(pc, opcode))
		return false;
	if (opcode < OP_1 || opcode > OP_16)
		return false;

	op = CScript::DecodeOP_N(opcode); /* extension type (exec) */
  if (op != OP_EXEC)
    return false;

	for (;;) {
		vector<unsigned char> vch;
		if (!script.GetOp(pc, opcode, vch))
			return false;
		if (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP)
			break;
		if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
			return false;
		vvch.push_back(vch);
	}

	// move the pc to after any DROP or NOP
	while (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP) {
		if (!script.GetOp(pc, opcode))
			break;
	}

	pc--;

	if ((mode == OP_EXT_NEW && vvch.size() == 2) ||
      (mode == OP_EXT_UPDATE && vvch.size() == 2) ||
      (mode == OP_EXT_ACTIVATE && vvch.size() == 2) ||
      (mode == OP_EXT_GENERATE && vvch.size() == 2) ||
      (mode == OP_EXT_TRANSFER && vvch.size() == 2) ||
      (mode == OP_EXT_REMOVE && vvch.size() == 2))
    return (true);

	return false;
}

bool DecodeExecScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeExecScript(script, op, vvch, pc);
}

CScript RemoveExecScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeExecScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveExecScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetExecOpFee(CIface *iface, int nHeight, int nSize)
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5040 / base * COIN;
  double nDif = 5000 /base * COIN;
  int64 nFee = (int64)(nRes - nDif);

  /* floor */
  nFee /= 1000;
  nFee *= 1000;

	/* factor in size */
	nSize = MAX(1, nSize);
	nFee = (int64)((double)nFee / (double)MAX_EXEC_SIZE * (double)nSize);

  nFee = MAX(MIN_TX_FEE(iface) * 2, nFee);
  nFee = MIN(MAX_TX_FEE(iface), nFee);

  return (nFee);
}


int64 GetExecReturnFee(const CTransaction& tx) 
{
	int64 nFee = 0;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
			nFee += out.nValue;
	}
	return nFee;
}

bool IsExecTx(const CTransaction& tx, int& mode) /* int& nOut */
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_EXEC)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
		int modeOut;

    if (DecodeExecHash(out.scriptPubKey, modeOut, hash)) {
			mode = modeOut;
      tot++;
    }
  }
  if (tot != 1) {
    return false;
  }

  return (true);
}



bool IsLocalExec(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalExec(CIface *iface, const CTransaction& tx)
{
	int mode;

  if (!IsExecTx(tx, mode))
    return (false); /* not a exec */

  int nOut = IndexOfExecOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalExec(iface, tx.vout[nOut]));
}


bool VerifyExecCall(CExecCall *call)
{
	return (true);
}


/**
 * Verify the integrity of an exec transaction.
 */
bool VerifyExec(CTransaction& tx, int& mode)
{
  uint160 hashExec;
  time_t now;
  int nOut;

  /* core verification */
	mode = 0;
  if (!IsExecTx(tx, mode)) {
		error(SHERR_INVAL, "IsExecTx [VerifyExec]");
    return (false); /* tx not flagged as exec */
  }

  if (mode != OP_EXT_NEW && 
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_GENERATE) {
		error(SHERR_INVAL, "mode %d [VerifyExec]", mode);
    return (false);
	}

  /* verify hash in pub-script matches exec hash */
  nOut = IndexOfExecOutput(tx);
  if (nOut == -1) {
		error(SHERR_INVAL, "IndexOfExecOutput [VerifyExec]");
    return (false); /* no extension output */
	}

  if (!DecodeExecHash(tx.vout[nOut].scriptPubKey, mode, hashExec)) {
		error(SHERR_INVAL, "DecodeExecHash [VerifyExec]");
    return (false); /* no exec hash in output */
	}

	if (mode == OP_EXT_NEW) {
		CExec *exec = tx.GetExec();
		if (hashExec != exec->GetHash()) {
			return error(SHERR_INVAL, "exec hash mismatch[exec-tx %s]: hashed as %s", hashExec.GetHex().c_str(), exec->GetHash().GetHex().c_str());
		}

		now = time(NULL);
		if (exec->tExpire == SHTIME_UNDEFINED ||
				exec->GetExpireTime() > (now + DEFAULT_EXEC_LIFESPAN + 1)) {
			return error(SHERR_INVAL, "invalid exec expiration time");
		}
	} else if (mode == OP_EXT_GENERATE) {
		CExecCall *call = tx.GetExecCall();
		if (hashExec != call->GetHash())
			return error(SHERR_INVAL, "exec call hash mismatch");

		bool ok = VerifyExecCall(call);
		if (!ok)
			return (error(SHERR_INVAL, "VerifyExecTx: exec call verification failure")); 
	}

  return (true);
}

bool IsNewerCheckpoint(CIface *iface, uint160 hExec, CExecCheckpoint *cp)
{
  CWallet *wallet = GetWallet(iface);
	uint160 hCheckpoint;

	if (wallet->mapExecCheckpoint.count(hExec) == 0)
		return (true);

	CTransaction txIn;
	uint256 hCheckpointTx = wallet->mapExecCheckpoint[hExec];
	if (!::GetTransaction(iface, hCheckpointTx, txIn, NULL))
		return (false);

	CExecCheckpoint *t_cp = txIn.GetExecCheckpoint();
	if (t_cp->GetCommitHeight() <= cp->GetCommitHeight())
		return (true);

	return (false);
}

/**
 * Save a new class call as the established checkpoint for the SEXE class.
 */
bool ExecSaveCheckpoint(CIface *iface, CExec *exec, CTransaction *cp_tx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	shjson_t *udata;
	sexe_t *S;
	shbuf_t *buff;
	uint160 hExec;
	uint160 hCheckpoint;
	char fname[PATH_MAX+1];
	int err;

	/* copy current userdata to backup */
	buff = shbuf_init();
	shbuf_cat(buff, exec->vContext.data(), exec->vContext.size());
	err = sexe_popen(buff, &S);
	shbuf_free(&buff);
	if (err) {
		error(err, "CExec.GetStackData: sexe_popen");
		return (false);
	}

	err = sexe_io_unserialize(S, iface->name, &udata);
	if (err) {
		_CloseStack(S);
		return (false);
	}

	sprintf(fname, "%s.checkpoint", iface->name);
	err = sexe_io_serialize(S, fname, udata);
	shjson_free(&udata);
	_CloseStack(S);
	if (err) {
		return (false);
	}

	hExec = exec->GetHash();
	wallet->mapExecCheckpoint[hExec] = cp_tx->GetHash();
	return (true);
}
bool ExecSaveCheckpoint(CIface *iface, uint160 hExec, CTransaction *cp_tx)
{
	CExec exec;

	if (!GetExecByHash(iface, hExec, exec))
		return (false);

	return (ExecSaveCheckpoint(iface, &exec, cp_tx));
}

/**
 * Restores the user-data of a SEXE class to a previously established state.
 */
bool ExecRestoreCheckpoint(CIface *iface, CExec *exec)
{
  CWallet *wallet = GetWallet(iface);
	sexe_t *S;
	shjson_t *udata;
	shbuf_t *buff;
	uint160 hExec;
	char fname[PATH_MAX+1];
	int nHeight;
	int err;

	/* apply backup user-data for class. */
	buff = shbuf_init();
	shbuf_cat(buff, exec->vContext.data(), exec->vContext.size());
	err = sexe_popen(buff, &S);
	shbuf_free(&buff);
	if (err) {
		error(err, "CExec.GetStackData: sexe_popen");
		return (false);
	}

	sprintf(fname, "%s.checkpoint", iface->name);
	err = sexe_io_unserialize(S, fname, &udata);
	if (err) {
		_CloseStack(S);
		return (false);
	}

	nHeight = shjson_num(udata, "height", 0);

	err = sexe_io_serialize(S, iface->name, udata);
	shjson_free(&udata);
	_CloseStack(S);
	if (err) {
		return (false);
	}

	hExec = exec->GetHash();

	vector<uint160> vCall;
	vector<uint160> vIsPend;

	/* move all calls higher than checkpoint to the pending call map */
	vector<uint160>& vActiveCall = wallet->mapExecCall[hExec];
  BOOST_FOREACH(const uint160& hash, vActiveCall) {
		vCall.insert(vCall.end(), hash);
		vIsPend.insert(vIsPend.end(), hash);
	}

	vector<uint160>& vPendCall = wallet->mapExecCallPending[hExec];
  BOOST_FOREACH(const uint160& hash, vPendCall) {
		vCall.insert(vCall.end(), hash);
	}

	vActiveCall.clear();
	vPendCall.clear();
  BOOST_FOREACH(const uint160& hash, vCall) {
		vector<uint160>::iterator position = std::find(vIsPend.begin(), vIsPend.end(), hash);
		if (position != vIsPend.end()) {
			/* was already pending.. */
			vPendCall.insert(vPendCall.end(), hash);
			continue;
		}

		CExecCall call;
		if (!GetCallByHash(iface, hash, call)) {
			/* ?? */
			continue;
		}

		if (call.GetCommitHeight() <= nHeight) {
			vActiveCall.insert(vActiveCall.end(), hash);
		} else {
			vPendCall.insert(vActiveCall.end(), hash);
		}
	}

	return (true);
}

bool ExecRestoreCheckpoint(CIface *iface, const uint160& hExec)
{
	CExec exec;

	if (!GetExecByHash(iface, hExec, exec))
		return (false);

	return (ExecRestoreCheckpoint(iface, &exec));
}

/**
 * Removes a checkpoint at or lower than the specified height.
 */
bool ExecEraseCheckpoint(CIface *iface, uint160 hExec, int nHeight)
{
  CWallet *wallet = GetWallet(iface);

	wallet->mapExecCheckpoint.erase(hExec);
	return (true);
}
bool ExecEraseCheckpoint(CIface *iface, CExec *exec, int nHeight)
{
	return (ExecEraseCheckpoint(iface, exec->GetHash(), nHeight));
}


std::string CExec::ToString(int ifaceIndex)
{
  return (write_string(Value(ToValue(ifaceIndex)), false));
}

Object CExec::ToValue(int ifaceIndex)
{
  Object obj = CExtCore::ToValue();

  CCoinAddr sendAddr = GetSenderAddr(ifaceIndex);
  obj.push_back(Pair("sender", sendAddr.ToString().c_str()));

  obj.push_back(Pair("hash", GetHash().GetHex()));

#if 0
  if (nFlag != 0)
    obj.push_back(Pair("flags", nFlag));
#endif

#if 0
	uint160 keyid(vAddr);
  CCoinAddr addr(ifaceIndex);
  addr.Set(CKeyID(keyid));
  obj.push_back(Pair("sender", addr.ToString().c_str())); 
#endif

  obj.push_back(Pair("signature", signature.GetHash().GetHex()));

	obj.push_back(Pair("stack-size", (int)GetStack().size()));

  return (obj);
}

bool CExecCall::GetExec(int ifaceIndex, CExec& execOut)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
	const uint160& hExec = GetExecHash();
	return (GetExecByHash(iface, hExec, execOut));
}

std::string CExecCall::ToString(int ifaceIndex)
{
  return (write_string(Value(ToValue(ifaceIndex)), false));
}

Object CExecCall::ToValue(int ifaceIndex)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
  CCoinAddr sendAddr = GetSenderAddr(ifaceIndex);
  Object obj;

	Array args;
  BOOST_FOREACH(const cbuff& out, vArg) {
		args.push_back(stringFromVch(out));
	}
	obj.push_back(Pair("argument", args));

//	obj.push_back(Pair("checksum", GetChecksum().GetHex().c_str()));
	obj.push_back(Pair("height", (uint64_t)GetCommitHeight()));
	obj.push_back(Pair("iface", string(iface->name)));
	obj.push_back(Pair("method", GetMethodName()));
	obj.push_back(Pair("timestamp", (uint64_t)GetSendTime()));
	obj.push_back(Pair("value", (double)GetSendValue()/COIN));
  obj.push_back(Pair("sender", sendAddr.ToString().c_str()));

	if (!signature.IsNull())
		obj.push_back(Pair("signature", signature.GetHash().GetHex()));

	if (vTx.size() != 0) {
		Array ar;
		for (int i = 0; i < vTx.size(); i++) {
			ar.push_back(vTx[i].GetHex());
		}
		obj.push_back(Pair("tx-ref", ar));
	}

  return (obj);
}

std::string CExecCheckpoint::ToString(int ifaceIndex)
{
  return (write_string(Value(ToValue(ifaceIndex)), false));
}

Object CExecCheckpoint::ToValue(int ifaceIndex)
{
  Object obj = CExtCore::ToValue();
	obj.push_back(Pair("checksum", GetChecksum().GetHex().c_str()));
	obj.push_back(Pair("height", (uint64_t)GetCommitHeight()));
	obj.push_back(Pair("timestamp", (uint64_t)GetSendTime()));

  return (obj);
}

static bool SetExecLabel(CExec *exec, sexe_mod_t *mod)
{
	char path[PATH_MAX+1];
	char *text;

  if (0 != memcmp(mod->sig, SEXE_SIGNATURE, sizeof(mod->sig)))
    return (false);

	/* skip reserved chars */
	text = mod->name;
	if (*text == '@') text++;

	/* define filename */
	memset(path, 0, sizeof(path));
	strncpy(path, basename(text), sizeof(path)-1);

	/* strip extension */
	text = strrchr(path, '.');
	if (text) *text = '\000';

  exec->SetLabel(string(path));
  return (true);
}

bool CExec::LoadData(string path, cbuff& data)
{
  shbuf_t *buff;
  char exec_path[PATH_MAX+1];
  int err;

  memset(exec_path, 0, sizeof(exec_path));
  strncpy(exec_path, path.c_str(), sizeof(exec_path)-1);

  buff = shbuf_init();
  err = shfs_mem_read(exec_path, buff);
  if (err) {
    shbuf_free(&buff);
    return error(err, "CExec.LoadData: failure loading path \"%s\".", exec_path);
  }
  if (shbuf_size(buff) == 0) {
    return (error(SHERR_INVAL, "CExec.LoadData: no data available."));
  }

  if (!SetExecLabel(this, (sexe_mod_t *)shbuf_data(buff))) {
    shbuf_free(&buff);
    return (error(SHERR_ILSEQ, "SetExecLabel: invalid file format (%s).", exec_path));
  }

  unsigned char *raw = shbuf_data(buff);
  size_t raw_len = shbuf_size(buff);
  data = cbuff(raw, raw + raw_len);

  shbuf_free(&buff);
  return (true);
}

/** 
 * Establish a SEXE process handle.
 */
static int _OpenStack(int ifaceIndex, CExec *exec, CCoinAddr sendAddr, int64_t sendValue, sexe_t **s_p)
{
  uint160 hExec = exec->GetHash();
	cbuff stack = exec->GetStack();
	shjson_t *json;
	shbuf_t *buff;
	sexe_t *S;
	char hash[256];
	char *argv[2];
	int argc;
	int err;

	strcpy(hash, hExec.GetHex().c_str());
	argv[0] = (char *)hash;
	argv[1] = NULL;

	buff = shbuf_init();
	shbuf_cat(buff, stack.data(), stack.size());
	err = sexe_popen(buff, &S);
	if (err) {
		error(err, "sexe_popen [OpenStack]"); 
		return (err);
	}

	err = sexe_prun(S, argc, argv);
  if (err) {
		sexe_pclose(S);
    error(err, "sexe_prun [OpenStack]");
		return (err);
	}

	*s_p = S;
	return (0);
}

static int _CallFunc(sexe_t *S, const char *func, shjson_t *call)
{
	int err;

	err = sexe_pcall_json(S, (char *)func, call);
	if (err) {
		error(err, "_CallFunc: %d = sexe_pcall_json(%s)\n", err, func);
		return (err);
	}
	
	return (0);
}


static int AliasCreateEvent(lua_State *L)
{
	CIface *iface;
  CWallet *wallet;
	shjson_t *param;
	shjson_t *arg;
	int ifaceIndex;
	int err;

	/* skip event name */
	lua_pop(L, 1);

	/* "Alias Create" argument */
	arg = sexe_table_get(L);

	/* runtime parameters */
  param = NULL;
  (void)sexe_pget(L, "param", &param);

	iface = GetCoin(shjson_str(param, "iface", "shc")); 
  ifaceIndex = GetCoinIndex(iface);

  wallet = GetWallet(iface);
	if (!wallet) {
		sexe_pushboolean(L, FALSE); 
		return (1);
	}

	string strAccount("");
	CCoinAddr addr(ifaceIndex, shjson_str(arg, "addr", ""));
	AccountFromAddress(ifaceIndex, addr, strAccount);

	int64 nValue = (int64)(shjson_num(arg, "value", 0) * COIN);
	if (nValue < MIN_INPUT_VALUE(iface)) {
		sexe_pushboolean(L, FALSE); 
		return (1);
	}

	CTransaction txAlias;
	string strTitle(shjson_str(arg, "class", ""));
	CAlias *alias = txAlias.CreateAlias(strTitle);
	if (!alias) {
		sexe_pushboolean(L, FALSE); 
		return (1);
	}

	alias->SetCoinAddr(addr);

	shjson_t *alias_ar = shjson_array_add(param, "alias");
	shjson_t *alias_json = shjson_obj_add(alias_ar, NULL);
	obj2json(alias_json, alias->ToValue(ifaceIndex));

  err = sexe_pset(L, "param", param);
	if (err) {
		sexe_pushboolean(L, FALSE); 
		return (1);
	}

	/* return success */
	sexe_pushboolean(L, TRUE);
	return (1);
}

/* obtains context table data [of JSON] from given label */
static int sexe_ContextGetTable(lua_State *L)
{
	const char *label = lua_tostring(L, 1);	
	CIface *iface;
	CContext *ctx;
	shjson_t *param;
	shjson_t *j;

	/* runtime parameters */
	iface = NULL;
  param = NULL;
  (void)sexe_pget(L, "param", &param);
	if (param) {
		iface = GetCoin(shjson_str(param, "iface", "")); 
		shjson_free(&param);
	}
	if (!iface) {
		lua_pushnil(L);
		return (1);
	}

	CTransaction ctx_tx;
	ctx = GetContextByName(iface, label, ctx_tx); 
	if (!ctx) {
		lua_pushnil(L);
		return (1);
	}

	j = shjson_init((char *)stringFromVch(ctx->vContext).c_str());
	if (!j) {
		lua_pushnil(L);
		return (1);
	}

	/* return JSON as an object table */
	sexe_table_set(L, j);
	shjson_free(&j);
	return (1);
}

static int sexe_ContextCreateEvent(lua_State *L)
{
	CIface *iface;
  CWallet *wallet;
	shjson_t *param;
	shjson_t *arg;
	int ifaceIndex;
	int err;

	/* skip event name */
	lua_pop(L, 1);

	/* "Context Create" argument */
	arg = sexe_table_get(L);

	/* runtime parameters */
  param = NULL;
  (void)sexe_pget(L, "param", &param);

	iface = GetCoin(shjson_str(param, "iface", "shc")); 
  ifaceIndex = GetCoinIndex(iface);

  wallet = GetWallet(iface);
	if (!wallet) {
		error(SHERR_INVAL, "GetWallet [sexe_ContextCreateEvent]");
		sexe_pushboolean(L, FALSE); 
		return (1);
	}

	CTransaction txContext;
	CContext *ctx = txContext.CreateContext();
	if (!ctx) {
		error(SHERR_INVAL, "CreateContext [sexe_ContextCreateEvent]");
		sexe_pushboolean(L, FALSE); 
		return (1);
	}

	string strLabel(shjson_str(arg, "label", ""));
	string strValue(shjson_str(arg, "value", ""));
	if (!ctx->SetValue(strLabel, vchFromString(strValue))) {
		error(SHERR_INVAL, "ctx.SetValue [sexe_ContextCreateEvent]");
		sexe_pushboolean(L, FALSE); 
		return (1);
	}

	if (!ctx->Sign(ifaceIndex)) {
		error(SHERR_INVAL, "ctx.Sign [sexe_ContextCreateEvent]");
		sexe_pushboolean(L, FALSE); 
		return (1);
	}

	/* add context fee. */
	double nFee = shjson_num(param, "fee", 0);
	nFee += (double)GetContextOpFee(iface,
			GetBestHeight(iface), strValue.length()) / COIN;
	shjson_num_add(param, "fee", nFee);

#if 0
	/* add context data to runtime param. */
	shjson_t *ctx_list = shjson_obj_get(param, "context");
	if (!ctx_list) ctx_list = shjson_obj_add(param, "context");
	shjson_t *ctx_json = shjson_obj_add(ctx_list, 
			(char *)ctx->GetHash().GetHex().c_str());
	obj2json(ctx_json, ctx->ToValue());
#endif
	/* add context label/value pair to runtime param. */
	shjson_t *ctx_list = shjson_obj_get(param, "context");
	if (!ctx_list) ctx_list = shjson_obj_add(param, "context");
	if (shjson_type(arg, "value") == SHJSON_OBJECT) {
		shjson_t *ctx_json = shjson_obj_add(ctx_list, (char *)strLabel.c_str()); 
		shjson_obj_append(shjson_obj_get(arg, "value"), ctx_json);
	} else if (shjson_type(arg, "value") == SHJSON_STRING) {
		shjson_str_add(ctx_list, 
				(char *)strLabel.c_str(), shjson_str(arg, "value", "")); 
	}

  err = sexe_pset(L, "param", param);
	if (err) {
		error(SHERR_INVAL, "sexe_pset [sexe_ContextCreateEvent]");
		sexe_pushboolean(L, FALSE); 
		return (1);
	}

	/* return success */
	sexe_pushboolean(L, TRUE);
	return (1);
}

static int ExecUpdateEvent(lua_State *L)
{
	shjson_t *arg;

#if 0
	lua_pop(L, 1); /* event name (second arg) */

	arg = sexe_table_get(L); /* runtime param (first arg) */
	if (arg)
		shjson_free(&arg);
#endif

	sexe_pushboolean(L, TRUE);
	return (1);
}

static int SendTxEvent(lua_State *L)
{
	shjson_t *arg;

	arg = sexe_table_get(L);
	if (arg)
		shjson_free(&arg);

	sexe_pushboolean(L, TRUE);
	return (1);
}

bool CExec::CallStack(int ifaceIndex, CCoinAddr sendAddr, shjson_t **param_p)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);
	shjson_t *paramIn;
	shjson_t *param;
	shjson_t *call;
	shjson_t *args;
	shjson_t *udata;
	sexe_t *S;
	char method[256];
	char checksum[256];
	char *text;
	int jtype;
	int err;

	if (!param_p)
		return (false);

	paramIn = *param_p;
	int64 sendValue = shjson_num(paramIn, "value", 0);
	err = _OpenStack(ifaceIndex, this, sendAddr, sendValue, &S);
	if (err) {
		error(err, "CallStack: OpenStack");
		return (false);
	}

	/* initialize class */
	if (!sexe_pevent(S, "InitEvent", paramIn)) {
		sexe_pclose(S);
		error(SHERR_INVAL, "InitEvent [CallStak]: EXEC: %s", ToString(ifaceIndex).c_str());
		char *str = shjson_print(paramIn);
		error(SHERR_INVAL, "InitEvent [CallStack]: %s", str?str:"");
		if (str) free(str);
		return (false);
	}

	/* obtains a context transaction's JSON information */
	lua_register(S, "shc_context_get", sexe_ContextGetTable);

	sexe_event_register(S, "ExecUpdateEvent", ExecUpdateEvent);
//	sexe_event_register(S, "SentTxEvent", SendTxEvent);
	sexe_event_register(S, "AliasCreateEvent", AliasCreateEvent);

	/* generates a context transaction to be submitted. */
	sexe_event_register(S, "ContextCreateEvent", sexe_ContextCreateEvent);

	memset(method, 0, sizeof(method));
	strcpy(method, shjson_str(paramIn, "class", ""));
	if (*method)
		strcat(method, ".");
	strcat(method, shjson_str(paramIn, "method", ""));

#if 0
	/* handled via CallExecChain */ 
	err = sexe_io_unserialize(S, iface->name, &udata);
	if (!err) {
		int dataHeight = shjson_num(udata, "height", 0);
		int paramHeight = shjson_num(paramIn, "height", 0);
		if (dataHeight > paramHeight) {
			/* this tx has already been processed according to stored user-data. */
			shjson_free(&udata);
			_CloseStack(S);
			return (0);
		}
		shjson_free(&udata);
	}
#endif

	err = _CallFunc(S, method, paramIn);
	if (err) {
		_CloseStack(S);
		error(err, "CallFunc [CallStack]");
		return (false);
	}

	param = NULL;
  err = sexe_pget(S, "param", &param);
	if (err) {
		_CloseStack(S);
		error(err, "sexe_pget [CallStack]");
		return (false);
	}

#if 0 /* because simutanous calls can occur before being committed to block-chain the checkpoint is used to checksum matching instead of each call */
	int64 nFee = shjson_num(param, "fee", 0) * COIN;
	if (nFee > MIN_EXEC_FEE) {
		char buf[256];

		memset(checksum, 0, sizeof(checksum));
		text = shjson_str(param, "checksum", ""); 
		if (text)
			strncpy(checksum, text, sizeof(checksum)-1); 

		memset(buf, 0, sizeof(buf));
		if (*checksum) {
			/* verify checksum integrity of userdata */
			err = sexe_io_unserialize(S, iface->name, &udata); 
			if (!err) {
				text = shjson_print(udata);
				memset(buf, 0, sizeof(buf));
				(void)shsha_hex(SHALG_SHA256, (unsigned char *)buf, (unsigned char *)text, strlen(text));
				shjson_free(&udata);
				free(text);
			}
		}
		if (!*checksum || !*buf || 0 != strcmp(buf, checksum)) {
			shjson_free(&param);
			_CloseStack(S);
/* DEBUG: todo: reset entire exec chain & clear u-data? what if node if josh'n.. checkpoints enuf? */
			return (error(SHERR_ILSEQ, "(%s) CExec.CallStack: checksum error calling \"%s\" [proc-crc: %s].", iface->name, method, checksum));
		}
	}
#endif
	_CloseStack(S);

#if 0
	if (0 != strcmp(shjson_str(param, "class", ""), shjson_str(paramIn, "class", ""))) {
		error(SHERR_INVAL, "CallStack");
		return (false);
	}
	if (0 != strcmp(shjson_str(param, "method", ""), shjson_str(paramIn, "method", ""))) {
		error(SHERR_INVAL, "CallStack");
		return (false);
	}
#endif

	/* transfer return variable to new params. */
	jtype = shjson_type(paramIn, "return");
	switch (jtype) {
		case SHJSON_NUMBER:
			shjson_num_add(param, "return", shjson_num(paramIn, "return", 0));
			break;
		case SHJSON_STRING:
			shjson_str_add(param, "return", shjson_str(paramIn, "return", ""));
			break;
		case SHJSON_BOOLEAN:
			shjson_bool_add(param, "return", shjson_bool(paramIn, "return", FALSE));
			break;
		case SHJSON_OBJECT:
			shjson_obj_append(shjson_obj(paramIn, "return"),
					shjson_obj_add(param, "return"));
			break;
		default:
			shjson_null_add(param, "return");
			break;
	}

	*param_p = param;
	shjson_free(&paramIn);

	return (true);
}

void CExecCheckpoint::SetCommitHeight(int ifaceIndex)
{
	SetCommitHeight((int64)GetBestHeight(ifaceIndex));
}

void CExecCheckpoint::SetSendTime()
{
	nTime = (int64)time(NULL);
}

bool CExecCheckpoint::VerifyChecksum(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
	CExec exec;
	shjson_t *udata;
	char *text;
	char buf[256];
	int height;

	if (!GetExecByHash(iface, hExec, exec))
		return (false);

	if (!exec.GetStackData(ifaceIndex, &udata))
		return (false);

	height = shjson_num(udata, "height", 0);
	if (GetCommitHeight() <= height)
		return (true); /* checkpoint came later than last update */

	text = shjson_print(udata);
	memset(buf, 0, sizeof(buf));
	(void)shsha_hex(SHALG_SHA256, (unsigned char *)buf, 
		(unsigned char *)text, strlen(text));
	shjson_free(&udata);
	free(text);

	string hex(buf);
	return (GetChecksum() == uint256(hex));
}

bool CExec::VerifyStack(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);
	shjson_t *param;
	sexe_t *S;
	char method[256];
	int err;

  /* establish 'sender' coin addr */
	int64 sendValue = 0;
  CCoinAddr sendAddr = GetSenderAddr(ifaceIndex);
	err = _OpenStack(ifaceIndex, this, sendAddr, sendValue, &S);
	if (err) {
		error(err, "OpenStack [VerifyStack]");
		return (false);
	}

	/* call parameters */
	param = shjson_init(NULL);
	shjson_str_add(param, "sender", (char *)sendAddr.ToString().c_str());
	shjson_str_add(param, "iface", iface->name);
	shjson_num_add(param, "value", 0);
	shjson_str_add(param, "class", (char *)GetLabel().c_str());
	shjson_str_add(param, "method", "verify");
	shjson_num_add(param, "timestamp", GetExpireTime());
	shjson_num_add(param, "height", GetBestHeight(iface));

	memset(method, 0, sizeof(method));
	snprintf(method, sizeof(method)-1, "%s.verify", GetLabel().c_str());
	err = _CallFunc(S, method, param);
	_CloseStack(S);
	if (err) {
		error(err, "CallFunc \"%s\" [VerifyStack]", method);
		return (false);
	}


	bool ok = shjson_bool(param, "return", FALSE);
	shjson_free(&param);

	return (ok);
}

bool CExec::GetStackData(int ifaceIndex, shjson_t **j_p)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
	shjson_t *udata;
	sexe_t *S;
	shbuf_t *buff;
	int err;

	buff = shbuf_init();
	shbuf_cat(buff, vContext.data(), vContext.size());
	err = sexe_popen(buff, &S);
	shbuf_free(&buff);
	if (err) {
		error(err, "CExec.GetStackData: sexe_popen");
		return (false);
	}

	err = sexe_io_unserialize(S, iface->name, &udata);
	_CloseStack(S);
	if (err) {
//fprintf(stderr, "DEBUG: GetStackData: %d = sexe_io_unserialize()\n", err);
		return (false);
	}

	*j_p = udata;
	return (true);
}

int64 CExec::GetStackHeight(int ifaceIndex)
{
	shjson_t *udata;
	int64 nHeight;
	
	if (!GetStackData(ifaceIndex, &udata))
		return (0);

	nHeight = (int64)shjson_num(udata, "height", 0);
	shjson_free(&udata);

	return (nHeight);
}


/* process a new exec-tx on the block-chain. */
int ProcessExecTx(CIface *iface, CNode *pfrom, CTransaction& tx, int64 nHeight)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CKeyID inkey;
  CKeyID key;
	shjson_t *param;
  int err;

  /* validate */
  int tx_mode;
  if (!VerifyExec(tx, tx_mode)) {
    error(SHERR_INVAL, "ProcessExecTx: error verifying exec tx: %s", tx.ToString(ifaceIndex).c_str());
    return (SHERR_INVAL);
  }

	switch (tx_mode) {
		case OP_EXT_NEW:
			{
				CExec *exec = tx.GetExec();
				uint160 hExec = exec->GetHash();

				if (IsValidExecHash(iface, hExec))
					return (SHERR_EXIST);

				int64 nFee = GetExecOpFee(iface, nHeight, exec->vContext.size());
				int nOut = IndexOfExecOutput(tx);
				int64 nOutValue = tx.vout[nOut].nValue;
				if (nOutValue < nFee) {
					error(ERR_FEE, "ProcessExecTx: OP_EXT_NEW: insufficient fee.");
					return (ERR_FEE);
				}

				/* verify integrity of sexe class */
				if (!exec->VerifyStack(ifaceIndex)) {
					error(SHERR_IO, "ProcessExecTx: OP_EXT_NEW: error verifying class executable.");
					return (SHERR_IO);
				}

				InsertExecTable(iface, tx);

				/* mark exec as pending by default */
				if (wallet->mapExecCallPending.count(hExec) == 0) {
					vector<uint160> vCall;
					wallet->mapExecCallPending[hExec] = vCall;
				}
			}
			break;

		case OP_EXT_UPDATE:
			{
				CExecCheckpoint *cp = tx.GetExecCheckpoint();

				if (IsNewerCheckpoint(iface, cp->hExec, cp) && /* check for redundancy */
						cp->VerifyChecksum(ifaceIndex)) { /* user-data sync */
					ExecSaveCheckpoint(iface, cp->hExec, &tx);
				}
			}
			break;

		case OP_EXT_GENERATE:
			{
				CExecCall *call = tx.GetExecCall();
				const uint160& hCall = call->GetHash();

				CExec exec;
				if (!call->GetExec(ifaceIndex, exec)) {
					error(SHERR_NOENT, "ProcessExecTx: exec '%s' not registered.", call->GetExecHash().GetHex().c_str());
					return (SHERR_NOENT);
				}
				const uint160& hExec = exec.GetHash();

				if (IsExecCallHash(iface, hExec, hCall)) {
					/* already processed. */
					break; 
				}

				if (IsExecPending(iface, hExec)) {
					/* no ongoing run-time processing required. */
					InsertExecCallPendingTable(iface, hExec, tx);
					return (0);
				}

#if 0
				unsigned char *raw = (unsigned char *)call->vContext.data();
				shjson_t *param = shjson_init((char *)raw);
				if (!param)
					return (SHERR_INVAL);
#endif
#if 0
				string raw = write_string(Value(call->ToValue(ifaceIndex)), false);
				shjson_t *param = shjson_init((char *)raw.c_str());
				if (!param) {
					error(SHERR_INVAL, "ProcessExecTx: JSON conversion error.");
					return (SHERR_INVAL);
				}
#endif
				param = exec_call_param(iface, &exec, call);
				if (!param) {
					error(SHERR_INVAL, "ProcessExecTx: JSON conversion error.");
					return (SHERR_INVAL);
				}
	
				err = ProcessExecGenerateTx(ifaceIndex, &exec, call, &param, false);
				shjson_free(&param);
				if (err) {
					error(err, "ProcessExecTx: ProcessExecGenerateTx error");
					return (err);
				}

				/* insert new call tx */
				InsertExecCallTable(iface, hExec, tx);
			}
			break;

		default:
			return (SHERR_OPNOTSUPP);
	}

  return (0);
}

int DisconnectExecTx(CIface *iface, CTransaction& tx, int mode)
{
  CWallet *wallet = GetWallet(iface);
	uint256 hTx = tx.GetHash();
	int err;

	err = 0;
	if (mode == OP_EXT_NEW) {
		CExec *exec = tx.GetExec();
		uint160 hExec = exec->GetHash();

		/* remove class's userdata */
		ClearStackData(iface, exec);

		/* delete all class references. */
		wallet->mapExecCall.erase(hExec);
		wallet->mapExecCallPending.erase(hExec);
		wallet->mapExecCheckpoint.erase(hExec);
		/* remove from global exec tx reference map */
		wallet->mapExec.erase(hExec);
	} else if (mode == OP_EXT_UPDATE) {
		CExecCheckpoint *cp = tx.GetExecCheckpoint();
		if (wallet->mapExecCheckpoint.count(cp->hExec) != 0) {
			uint256 hCheckpointTx = wallet->mapExecCheckpoint[cp->hExec];
			if (hCheckpointTx == hTx) {
				wallet->mapExecCheckpoint.erase(cp->hExec);
			}
		}
	} else if (mode == OP_EXT_GENERATE) {
		CExecCall *call = tx.GetExecCall();
		uint160 hCall = call->GetHash();

		if (wallet->mapExecCall.count(call->hExec) != 0) {
			vector<uint160>& l = wallet->mapExecCall[call->hExec];
			vector<uint160>::iterator position = std::find(l.begin(), l.end(), hCall);
			if (position != l.end()) {
				/* call is active, revert call chain.. */
				if (!ExecRestoreCheckpoint(iface, call->hExec)) {
					ResetExecChain(iface, call->hExec);
				}
			}
		}

		/* remove from unprocessed exec call table. */
		if (wallet->mapExecCallPending.count(call->hExec) != 0) {
			/* call has not been processed and can simply be removed. */
			vector<uint160>& l = wallet->mapExecCallPending[call->hExec];
			vector<uint160>::iterator position = std::find(l.begin(), l.end(), hCall);
			if (position != l.end()) {
				l.erase(position);
			}
		}

		/* remove from global exec tx reference map */
		wallet->mapExec.erase(hCall);
	}

	return (0);
}

int init_exec_tx(CIface *iface, string strAccount, string strPath, CWalletTx& wtx)
{
#ifdef USE_SEXE
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	struct stat st;
	char class_buf[PATH_MAX+1];
  CExec *exec;
	int exec_size;
	int err;

	err = stat(strPath.c_str(), &st);
	if (err) {
		err = errno2sherr();
		error(err, "stat [init_exec_tx]");
		return (err);
	}

  int64 nFee = GetExecOpFee(iface, GetBestHeight(iface), (int)st.st_size);
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
		error(SHERR_INVAL, "init_exec_tx: insufficient balance (%llu) .. %llu required\n", bal, nFee);
    return (ERR_FEE);
  }

  /* establish 'sender' coin addr */
  CCoinAddr sendAddr = wallet->GetExecAddr(strAccount);
#if 0
  CCoinAddr sendAddr(ifaceIndex);
  if (!wallet->GetMergedAddress(strAccount, "exec", sendAddr)) {
    error(SHERR_INVAL, "init_exec_tx: error generating merged address.");
    return (false);
  }
#endif

  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */

  /* embed exec content into transaction */
  exec = wtx.CreateExec();
	exec->SetSenderAddr(sendAddr);

	cbuff data;
  if (!exec->LoadData(strPath, data)) {
    error(SHERR_INVAL, "init_exec_tx: error loading sexe bytecode.");
    return (SHERR_NOENT);
  }

	/* instill executable code */
  if (!exec->SetStack(data)) {
    error(SHERR_INVAL, "init_exec_tx: error initializing sexe bytecode.");
    return (SHERR_INVAL);
  }

	strcpy(class_buf, basename(strPath.c_str()));
	strtok(class_buf, ".");
	exec->SetLabel(string(class_buf));

	/* call "verify" method of class */
	if (!exec->VerifyStack(ifaceIndex)) {
		error(SHERR_INVAL, "init_exec_tx: sexe class validation error.");
		return (SHERR_INVAL);
	}

	/* sign against owner address. */
  if (!exec->Sign(ifaceIndex, sendAddr)) {
    error(SHERR_INVAL, "init_exec_tx: error signing sexe bytecode.");
    return (SHERR_INVAL);
  }

  /* off off and away */
  CScript scriptPubKey;
  uint160 hExec = exec->GetHash();
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << hExec << OP_2DROP << OP_RETURN;
  string strError = wallet->SendMoney(strAccount, scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, "init_exec_tx: %s", strError.c_str());
    return (SHERR_INVAL);
  }

	/* note: class will not be available until processed onto the block-chain. */

  Debug("(%s) INIT EXEC TX[%s]: %s", iface->name, hExec.GetHex().c_str(), exec->ToString(ifaceIndex).c_str());

  return (0);
#else
	/* SEXE not enabled in runtime */
  return (SHERR_OPNOTSUPP);
#endif
}

/* checkpoint */
int update_exec_tx(CIface *iface, string strAccount, const uint160& hExec, CWalletTx& wtx)
{
#ifdef USE_SEXE
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
	CExecCheckpoint *cp;
	CExec *exec;
	char *text;
	shjson_t *udata;
	char buf[256];

  /* verify original exec */
  CTransaction tx;
  if (!GetTxOfExec(iface, hExec, tx)) {
    return (SHERR_NOENT);
	}
	exec = tx.GetExec();

  /* define "sender" address. */
  const CCoinAddr& sendAddr = wallet->GetExecAddr(strAccount);
#if 0
  CCoinAddr sendAddr(ifaceIndex);
  if (!wallet->GetMergedAddress(strAccount, "exec", sendAddr)) {
    error(SHERR_INVAL, "generate_exec_tx: invalid sender exec coin addr."); 
    return (SHERR_INVAL);
  }
#endif

	if (!exec->GetStackData(ifaceIndex, &udata))
		return (0); /* no data avail */

	int64 nFee = MIN_TX_FEE(iface);
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
		shjson_free(&udata);
    return (ERR_FEE);
  }

  /* exec update tx */
	CTxCreator s_wtx(wallet, strAccount);
  cp = s_wtx.UpdateExec(*exec);
	cp->hExec = hExec;
	cp->SetSendTime();
	cp->SetCommitHeight(ifaceIndex);

	/* generate checksum from class's current user-data */
	text = shjson_print(udata);
	shjson_free(&udata);
	memset(buf, 0, sizeof(buf));
	(void)shsha_hex(SHALG_SHA256, (unsigned char *)buf, 
			(unsigned char *)text, strlen(text));
	cp->SetChecksum(string(buf));
	free(text);

  /* generate output script */
	CScript scriptPubKey;
  uint160 hCheckpoint = cp->GetHash();
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << hCheckpoint << OP_2DROP << OP_RETURN;
	s_wtx.AddOutput(scriptPubKey, MIN_TX_FEE(iface));

	/* send transaction */
	if (!s_wtx.Send()) {
		error(SHERR_INVAL, "update_exec_tx: error committing transaction");
		return (SHERR_INVAL);
	}

	Debug("(%s) UPDATE EXEC TX[%s]: checkpoint %s", iface->name, hExec.GetHex().c_str(), cp->GetHash().GetHex().c_str());
	return (0);
#else
  return (SHERR_OPNOTSUPP);
#endif
}

/**
 * Call a function for a class published on the block-chain.
 * @param hExec The hash of the SEXE class.
 * @param strFunc The name of the function inside the class to call.
 * @param args A string array, ending with NULL, specifying the function call arguments.
 * @param wtx The wallet transaction generated, if a transaction is generated. 
 */
int generate_exec_tx(CIface *iface, string strAccount, string strClass, int64 nFee, string strFunc, char **args, Value& resp, CWalletTx& wtx)
{
#ifdef USE_SEXE
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	uint160 hExec;
	shjson_t *param;
  char buf[256];
	int err;
	int i;

  /* obtain class's exec tx */
	CExec execIn;
	if (!GetExecByLabel(iface, strClass, execIn)) {
		error(SHERR_NOENT, "generate_exec_tx: invalid class \"%s\"", strClass.c_str());
		return (SHERR_NOENT);
	}

  /* ensure sufficient funds are available to invoke call */
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < (nFee + (int64)iface->min_tx_fee)) {
    error(ERR_FEE, "generate_exec_tx: insufficient funds.");
    return (ERR_FEE);
  }

  /* define "sender" address. */
  CCoinAddr sendAddr = wallet->GetExecAddr(strAccount);
#if 0
  CCoinAddr sendAddr(ifaceIndex);
  if (!wallet->GetMergedAddress(strAccount, "exec", sendAddr)) {
    error(SHERR_INVAL, "generate_exec_tx: invalid sender exec coin addr."); 
    return (SHERR_INVAL);
  }
#endif

  /* define "execution" address. */
  CCoinAddr recvAddr = execIn.GetSenderAddr(ifaceIndex);
  if (!recvAddr.IsValid()) {
    error(SHERR_INVAL, "generate_exec_tx: invalid receive exec coin addr: \"%s\".", recvAddr.ToString().c_str());
    return (SHERR_INVAL);
  }

	/* catch up on pending calls for class. */
	int nCheckpoint;
	if (!CallExecChain(iface, execIn, nCheckpoint)) {
    error(SHERR_INVAL, "generate_exec_tx: error processing pending calls for class \"%s\".", strClass.c_str());
    return (SHERR_INVAL);
	}

	hExec = execIn.GetHash();
	if (nCheckpoint != 0 && 
			nCheckpoint <= (GetBestHeight(iface) - MIN_EXEC_CHECKPOINT_HEIGHT(iface))) {// && exec->GetCheckpointHeight() < nCheckpoint) {
		CTxCreator cp_wtx(wallet, strAccount);
		err = update_exec_tx(iface, strAccount, hExec, cp_wtx);
		if (err) {
			error(err, "generate_exec_tx: unable to create checkpoint for class \"%s\".", strClass.c_str());
			/* soft error.. */
		}
	}

  /* init tx */
	CTxCreator s_wtx(wallet, strAccount);

  CExecCall *call = s_wtx.GenerateExec(execIn);
	if (!call)
		return (SHERR_INVAL);

	call->hExec = hExec;
	call->SetSendTime();
	call->SetCommitHeight(ifaceIndex);
	call->SetMethodName(strFunc.c_str());
	call->SetSenderAddr(sendAddr);

	/* set again below */
	call->SetSendValue(nFee);

	/* method arguments */
	call->vArg.clear();
	if (args) {
		for (i = 0; args[i]; i++) {
			call->vArg.insert(call->vArg.end(), vchFromString(string(args[i])));
		}
	}

	/* calling parameters */
	param = exec_call_param(iface, &execIn, call);

/* todo: move "class" -> "exec.label" */

#if 0
	shjson_str_add(param, "iface", iface->name);
	shjson_str_add(param, "sender", (char *)sendAddr.ToString().c_str());
	shjson_num_add(param, "value", (double)nFee/COIN); 
	shjson_str_add(param, "class", (char *)call->GetClassName().c_str());
	shjson_str_add(param, "method", (char *)strFunc.c_str());
	shjson_num_add(param, "timestamp", call->GetSendTime());
	shjson_num_add(param, "height", GetBestHeight(iface));
	shjson_t *jargs;
	jargs = shjson_array_add(param, "argument");	
	if (args) {
		for (i = 0; args[i]; i++) {
			shjson_str_add(jargs, NULL, args[i]);
		}
	}
#endif

	/* call class function */
	err = ProcessExecGenerateTx(ifaceIndex, &execIn, call, &param, true);
	if (err) {
			error(err, "ProcessExecGenerateTx");
#if 0
		char *err_str = shjson_str(param, "error", "");
		if (*err_str) {
			error(err, "ProcessExecGenerateTx: %s", err_str);
		} else {
			error(err, "ProcessExecGenerateTx");
		}
#endif
		return (err);
	}

	{ /* create context */
		shjson_t *p_node = shjson_obj_get(param, "context");
		if (p_node) {
			shjson_t *node;
			char *text;
			int err;

			for (node = p_node->child; node; node = node->next) {
				string strName(node->string);

				if (shjson_type(node, NULL) == SHJSON_STRING) {
					text = strdup(shjson_str(node, NULL, ""));
				} else if (shjson_type(node, NULL) == SHJSON_OBJECT) {
					text = shjson_print(shjson_obj_get(p_node, (char *)strName.c_str()));
				} else {
					/* DEBUG: TODO .. */
				}

				if (text) {
					CWalletTx ctx_tx;

//fprintf(stderr, "DEBUG: generate_exec_tx: CONTEXT[%s]: %s\n", node->string, text);
					err = init_ctx_tx(iface, ctx_tx, strAccount,
							strName, vchFromString(string(text)), NULL, true);
					free(text);
					if (err) {
						error(err, "generate_exec_tx: error initializing context \"%s\"", strName.c_str());
					//	return (err); /* soft? */
					}
				}
			}

		}
	}

	resp = json2value(param, "return");

	if (call->GetSendValue() >= MIN_EXEC_FEE) {
		/* sign "sender" addr */
		if (!call->Sign(ifaceIndex, sendAddr)) {
/* DEBUG: TODO: reset chain */
			return (SHERR_NOKEY);
		}

		hExec = call->GetHash();

		/* send to "owner" */
		CScript scriptPubKeyDest;
		scriptPubKeyDest.SetDestination(execIn.GetSenderAddr(ifaceIndex).Get());
		CScript scriptPubKey;
		scriptPubKey << OP_EXT_GENERATE << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << hExec << OP_2DROP;
		scriptPubKey += scriptPubKeyDest;
		s_wtx.AddOutput(scriptPubKey, call->GetSendValue());

		/* send transaction */
		if (!s_wtx.Send()) {
/* DEBUG: TODO: reset chain */
			error(SHERR_INVAL, "generate_exec_tx: error committing transaction");
			return (SHERR_INVAL);
		}

		/* call has been performed locally, record as processed. */
		InsertExecCallTable(iface, call->hExec, s_wtx);
		Debug("(%s) GENERATE EXEC TX[%s]: %s", iface->name, hExec.GetHex().c_str(), call->ToString(ifaceIndex).c_str());
	}
	wtx = s_wtx;

  return (0);
#else
  return (SHERR_OPNOTSUPP);
#endif
}

#if 0
  /* post tx commit */
  vector<pair<CScript, int64> > vecSend;
  BOOST_FOREACH(CTxOut& out, wallet->mapExecCommit) {
    vecSend.push_back(make_pair(out.scriptPubKey, out.nValue));
  }

  if (vecSend.size() != 0) {
    CWalletTx wtx;
    int64 nFeeRet = 0;
    CReserveKey rkey(wallet);
    wtx.strFromAccount = strExtAccount;
    if (!wallet->CreateTransaction(vecSend, wtx, rkey, nFeeRet)) 
      return (SHERR_CANCELED);

    if (!wallet->CommitTransaction(wtx))
      return (SHERR_CANCELED);
  }
#endif

#if 0
/**
 * Certify an application.
 */
int activate_exec_tx(CIface *iface, uint160 hExec, string hCert, CWalletTx& wtx)
{
  return (SHERR_OPNOTSUPP);
}
#endif

#if 0
int transfer_exec_tx(CIface *iface, uint160 hExec, string strAccount, CWalletTx& wtx)
{
  return (SHERR_OPNOTSUPP);
}
#endif


/**
 * Removes a pre-existing exec on the block-chain. 
 * @param hashExec The exec ident hash from it's initial tx op.
 * @param strAccount The account that has ownership over the exec.
 * @param wtx The new transaction to be filled in.
 * @note The previous exec tx fee is returned to the account, and the current fee is burned.
 * @todo call "term" method (w/out recognition of return code) on app
 */
int remove_exec_tx(CIface *iface, const uint160& hashExec, CWalletTx& wtx)
{
  return (SHERR_OPNOTSUPP);
#if 0
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  /* verify original exec */
  CTransaction tx;
  if (!GetTxOfExec(iface, hashExec, tx)) {
//fprintf(stderr, "DEBUG: update_exec_tx: !GetTxOfExec\n");
    return (SHERR_NOENT);
  }

  if(!IsLocalExec(iface, tx)) {
//fprintf(stderr, "DEBUG: update_exec_tx: !IsLocalExec\n");
    return (SHERR_REMOTE);
  }

  /* establish user account */
  string strExtAccount;
  CExec& execIn = (CExec&)tx.certificate;
  CCoinAddr extAddr = execIn.GetSenderAddr();
  if (!GetCoinAddr(wallet, extAddr, strExtAccount))
    return (SHERR_NOENT);

  string strAccount = StripExtAccountName(strExtAccount);
  int64 nNetFee = GetExecOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }

  /* establish user address. */
  const CCoinAddr& recvAddr = wallet->GetExecAddr(strAccount);
#if 0
  CCoinAddr recvAddr(ifaceIndex);
  if (!wallet->GetMergedAddress(strAccount, "exec", recvAddr)) {
    error(SHERR_NOENT, "remove_exec_tx: error obtaining user coin address.");
    return (SHERR_NOENT);
  }
#endif

  /* generate tx */
  CExec *exec;
  wtx.SetNull();
  exec = wtx.RemoveExec(CExec(tx.certificate));

	CScript scriptPubKeyDest;
  scriptPubKeyDest.SetDestination(recvAddr.Get()); /* back to origin */

	CScript scriptExt;
  uint160 execHash = exec->GetHash();
	scriptExt << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << execHash << OP_2DROP << OP_RETURN;

  vector<pair<CScript, int64> > vecSend;
  uint256 wtxInHash = tx.GetHash();
  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];
  vecSend.push_back(make_pair(scriptExt, (int64)iface->min_tx_fee));
  if (!SendRemitMoneyTx(iface, extAddr, &wtxIn, wtx, vecSend, scriptPubKeyDest)) {
    return (SHERR_CANCELED);
  }

	return (0);
#endif
}

bool CExec::Sign(int ifaceIndex, CCoinAddr& addr)
{

  if (!signature.SignAddress(ifaceIndex, addr, vContext.data(), vContext.size())) {
		error(SHERR_ACCESS, "CExec.Sign: error signing context with sender address.");
    return (false);
  }

	return (true);
//	return (SetSenderAddr(addr));
}

bool CExec::VerifySignature(int ifaceIndex)
{
  CCoinAddr addr(ifaceIndex);

  addr.Set(GetSenderKey());
  if (!signature.VerifyAddress(addr, vContext.data(), vContext.size()))
    return (false);

  return (true);
}


bool CExecCall::Sign(int ifaceIndex, CCoinAddr& addr)
{
	uint256 hash;
	cbuff msg;

	hash = GetTxChainHash(); 
	unsigned char *raw = (unsigned char *)&hash;
	msg = cbuff(raw, raw + sizeof(uint256));
  if (!signature.SignAddress(ifaceIndex, addr, msg.data(), msg.size())) {
		error(SHERR_ACCESS, "CExecCall.Sign: sign address failure");
    return (false);
  }

	return (true);
}

static uint256 GenerateChainCoinbase(CExecCall *call)
{
	unsigned char *raw = (unsigned char *)&call->hResult;
	cbuff vchResult(raw, raw + sizeof(uint64_t));
	uint256 hContext = Hash(
			vchResult.begin(), vchResult.end(), /* method call result */ 
			call->hData.begin(), call->hData.end()); /* persistent data hash */
	return (hContext);
}

bool CExecCall::VerifySignature(int ifaceIndex)
{
  CCoinAddr addr(ifaceIndex);
	uint256 hash;
	cbuff msg;

	if (vTx.size() == 0) {
		error(SHERR_INVAL, "CExecCall.VerifySignature: invalid exec call tx chain");
		return (false); /* invalid */
	}

	if (vTx[0] != GenerateChainCoinbase(this)) {
		/* invalid exec tx-list coinbase */
		error(SHERR_ACCESS, "CExecCall.VerifySignature: invalid exec call coinbase");
		return (false);
	}

	hash = GetTxChainHash(); 
	unsigned char *raw = (unsigned char *)&hash;
	msg = cbuff(raw, raw + sizeof(uint256));

  addr.Set(GetSenderKey());
  if (!signature.VerifyAddress(addr, msg.data(), msg.size())) {
		error(SHERR_ACCESS, "CExecCall.VerifySignature: invalid exec call signature");
    return (false);
	}

  return (true);
}

bool CExec::SetSenderAddr(CCoinAddr& addr)
{
  CKeyID k;

  if (!addr.GetKeyID(k))
    return (false);

	kSender = k;
	return (true);
}

CCoinAddr CExecCore::GetSenderAddr(int ifaceIndex)
{
  CCoinAddr addr(ifaceIndex);
  addr.Set(CKeyID(kSender));
	return (addr);
}

void CExecCall::SetCommitHeight(int ifaceIndex)
{
	SetCommitHeight((int64)GetBestHeight(ifaceIndex));
}
void CExecCall::SetSendTime()
{
	nTime = (int64)time(NULL);
}


void CExecCall::InitTxChain()
{
	vTx.clear();
	AddTxChain(GenerateChainCoinbase(this));
}



static int writer(lua_State* L, const void* p, size_t size, void* u)
{
	return (fwrite(p,size,1,(FILE*)u)!=1) && (size!=0);
}


int rpc_sexe_compile(char *path_out, char *path_fname, char *path_dir, int *exec_size)
{
	struct stat st;
	sexe_t *L;
	int argc;
	char *argv[256];
	int err;

	argc = 2;
	argv[0] = path_out;
	argv[1] = path_fname;
	argv[2] = NULL;

	L = sexe_init();
	if (L==NULL)
		return (SHERR_NOMEM);

	lua_pushcfunction(L, &sexe_compile_pmain);
	lua_pushinteger(L,argc);
	lua_pushlightuserdata(L,argv);
	if (lua_pcall(L,2,0,0)!=LUA_OK)
		return (SHERR_ILSEQ);
	lua_close(L);

	err = stat(path_out, &st);
	if (err)
		return (errno2sherr());

	*exec_size = (int)st.st_size;
	return (0);
}

void exec_write_base_object(char *path)
{
	static const char *text =
		"--\n"
		"-- The \"Base Object\" class used to derive compatible SEXE classes on\n"
		"-- the ShionCoin (SHC) virtual currency block-chain.\n"
		"--\n"
		"\n"
		"require 'math'\n"
		"require 'io'\n"
		"require 'crypt'\n"
		"\n"
		"event ExecUpdateEvent\n"
		"\n"
		"BaseObject = {}\n"
		"BaseObject._VERSION = 3\n"
		"\n"
		"param = { }\n"
		"\n"
		"-- permissions\n"
		"local PERM_ADMIN = \"admin\"\n"
		"\n"
		"local function enablePerm(level)\n"
		"	local vname = \"map_\" .. crypt.crc(level)\n"
		"  if (BaseObject.data[vname] == nil) then\n"
		"		BaseObject.data[vname] = { }\n"
		"	end\n"
		"end\n"
		"\n"
		"\n"
		"function printvar(var)\n"
		"	if (type(var) == \"string\") then\n"
		"		println(var .. \" [str]\")\n"
		"	elseif (type(var) == \"number\") then\n"
		"		println (var .. \" [num]\")\n"
		"	elseif (type(var) == \"boolean\") then\n"
		"		println (var .. \" [bool]\")\n"
		"	elseif (type(var) == \"function\") then\n"
		"		println (\"[func]\")\n"
		"	elseif (type(var) == \"table\") then\n"
		"		println (\"{\")\n"
		"		for k,v in pairs(var) do\n"
		"			print(k .. \"=\")\n"
		"			printvar(v)\n"
		"		end\n"
		"		println (\"}\")\n"
		"	end\n"
		"end\n"
		"\n"
		"function BaseObject:New(template)\n"
		"    -- The new instance of the BaseObject needs an index table.\n"
		"    -- This next statement prefers to use \"template\" as the\n"
		"    -- index table, but will fall back to self.\n"
		"    -- Without the proper index table, your new BaseObject will\n"
		"    -- not have the proper behavior.\n"
		"    --\n"
		"    template = template or self\n"
		"    \n"
		"    -- This call to setmetatable does 3 things:\n"
		"    -- 1. Makes a new table.\n"
		"    -- 2. Sets its metatable to the \"index\" table\n"
		"    -- 3. Returns that table.\n"
		"    --\n"
		"    local newObject = setmetatable ({}, template)\n"
		"    \n"
		"    --\n"
		"    -- Obtain the metatable of the newly instantiated table.\n"
		"    -- Make sure that if the user attempts to access newObject[key]\n"
		"    -- and newObject[key] is nil, that it will actually fall\n"
		"    -- back to looking up template[key]...and so on, because template\n"
		"    -- should also have a metatable with the correct __index metamethod.\n"
		"    --\n"
		"    local mt = getmetatable (newObject)\n"
		"    mt.__index = template\n"
		"    \n"
		"    return newObject\n"
		"end\n"
		"\n"
		"function BaseObject:Subclass()\n"
		"    --\n"
		"    -- This is just a convenience function/semantic extension\n"
		"    -- so that BaseObjects which need to inherit from a base BaseObject\n"
		"    -- use a clearer function name to describe what they are doing.\n"
		"    --\n"
		"    return setmetatable({}, {__index = self})\n"
		"end\n"
		"\n"
		"function BaseObject.MultiSubclass(...)\n"
		"    local parentClasses = {...}\n"
		"    return setmetatable({}, \n"
		"    {\n"
		"        __index = function(table, key)\n"
		"            for _, parentClassTable in ipairs(parentClasses) do\n"
		"                local value = parentClassTable[key]\n"
		"                if value ~= nil then\n"
		"                    return value\n"
		"                end\n"
		"            end\n"
		"        end\n"
		"    })\n"
		"end\n"
		"\n"
		"function BaseObject.getSentTime()\n"
		"	return (param[\"timestamp\"])\n"
		"end\n"
		"\n"
		"-- the address of the entity who initiated execution \n"
		"function BaseObject.getSentAddress()\n"
		"	return (param[\"sender\"])\n"
		"end\n"
		"\n"
		"function BaseObject.getUpdateTime()\n"
		"	return (BaseObject.data[\"timestamp\"])\n"
		"end\n"
		"\n"
		"-- the value sent by the entity who intiated execution\n"
		"function BaseObject.getSentValue()\n"
		"	local value = param[\"value\"]\n"
		"	return (value)\n"
		"end\n"
		"\n"
		"function BaseObject.getOwner()\n"
		"	return (BaseObject.data[\"owner\"])\n"
		"end\n"
		"\n"
		"function BaseObject.isOwner()\n"
		"	if (BaseObject.getSentAddress() == BaseObject.getOwner()) then\n"
		"		return (true)\n"
		"	end\n"
		"	return (false)\n"
		"end\n"
		"\n"
		"function BaseObject.getBlockHeight()\n"
		"	return (param[\"height\"])\n"
		"end\n"
		"\n"
		"-- the class's version\n"
		"function BaseObject.getVersion()\n"
		"	return BaseObject._VERSION\n"
		"end\n"
		"\n"
		"-- the name of the underlying script\n"
		"function BaseObject.getClassName()\n"
		"	return (param[\"class\"])\n"
		"end\n"
		"\n"
		"-- callback to verify BaseObject is available.\n"
		"function BaseObject.verify()\n"
		"	if (BaseObject.getVersion() >= 3) then\n"
		"		return (true)\n"
		"	end\n"
		"	return (false)\n"
		"end\n"
		"\n"
		"function BaseObject.incrFee(val)\n"
		"	param[\"fee\"] = math.max(0, param[\"fee\"] + tonumber(val))\n"
		"	if (param[\"fee\"] > param[\"value\"]) then\n"
		"		BaseObject.setError(\"insufficient funds\")\n"
		"		return (false)\n"
		"	end\n"
		"	return (true)\n"
		"end\n"
		"\n"
		"function BaseObject.setFee(val)\n"
		"	param[\"fee\"] = math.max(0, tonumber(val))\n"
		"	if (param[\"fee\"] > param[\"value\"]) then\n"
		"		BaseObject.setError(\"insufficient funds\")\n"
		"		return (false)\n"
		"	end\n"
		"	return (true)\n"
		"end\n"
		"\n"
		"-- called when a data variable has changed\n"
		"function BaseObject.update()\n"
		"	if (BaseObject.data == nil) then\n"
		"		-- not initialized\n"
		"		return (false)\n"
		"	end\n"
		"\n"
		"	-- last updated time-stamp\n"
		"	BaseObject.data[\"timestamp\"] = param[\"timestamp\"]\n"
		"	BaseObject.data[\"height\"] = param[\"height\"]\n"
		"\n"
		"	-- checksum for validation in block-chain\n"
		"	local last_checksum = param[\"checksum\"]\n"
		"	param[\"checksum\"] = crypt.sha2(BaseObject.data)\n"
		"	if (last_checksum == param[\"checksum\"]) then\n"
		"		-- no changes have occurred.\n"
		"		return (true)\n"
		"	end\n"
		"\n"
		"	-- tack on fee so that tx is stored on block-chain\n"
		"	if (BaseObject.incrFee(0.0001) == false) then\n"
		"		-- unable to afford fee\n"
		"		return (false)\n"
		"	end\n"
		"\n"
		"	if (ExecUpdateEvent(param) == false) then\n"
		"		-- unable to update userdata\n"
		"		return (false)\n"
		"	end\n"
		"\n"
		"	-- persistently write any changed user-data variables\n"
		"	io.serialize(param[\"iface\"], BaseObject.data)\n"
		"	return (true)\n"
		"end\n"
		"\n"
		"function BaseObject.setError(msg)\n"
		"	BaseObject.setFee(0)\n"
		"	param[\"error\"] = msg\n"
		"end\n"
		"\n"
		"function BaseObject.isPerm(level)\n"
		"	local vname = \"map_\" .. crypt.crc(level)\n"
		"	local plist = BaseObject.data[vname]\n"
		"	return (plist ~= nil)\n"
		"end\n"
		"\n"
		"function BaseObject.setPerm(level, addr, code)\n"
		"	if (BaseObject.isOwner() == false) then\n"
		"		return false\n"
		"	end\n"
		"\n"
		"	local vname = \"map_\" .. crypt.crc(level)\n"
		"	local plist = BaseObject.data[vname]\n"
		"	if (plist == nil) then\n"
		"		return false\n"
		"	end\n"
		"\n"
		"	-- only ADMIN may set permissions\n"
		"	local acc_vname = \"map_\" .. crypt.crc(PERM_ADMIN)\n"
		"	if (plist[acc_vname] ~= true) then\n"
		"		return false\n"
		"	end\n"
		"\n"
		"	if (code == nil) then code = true end\n"
		"	plist[addr] = code\n"
		"	return (BaseObject.update())\n"
		"end\n"
		"\n"
		"function BaseObject.unsetPerm(level, addr)\n"
		"	if (BaseObject.isOwner() == false) then\n"
		"		return false\n"
		"	end\n"
		"\n"
		"	local vname = \"map_\" .. crypt.crc(level)\n"
		"	local plist = BaseObject.data[vname]\n"
		"	if (plist == nil) then\n"
		"		BaseObject.setError(\"invalid permission level\")\n"
		"		return false\n"
		"	end\n"
		"\n"
		"	-- only ADMIN may set permissions\n"
		"	local acc_vname = \"map_\" .. crypt.crc(PERM_ADMIN)\n"
		"	if (plist[acc_vname] ~= true) then\n"
		"		return false\n"
		"	end\n"
		"\n"
		"	plist[addr] = nil\n"
		"	return (BaseObject.update())\n"
		"end\n"
		"\n"
		"function BaseObject.isAdmin()\n"
		"	if (BaseObject.isOwner() == true) then\n"
		"		return (true)\n"
		"	end\n"
		"	return (BaseObject.hasPerm(PERM_ADMIN))\n"
		"end\n"
		"\n"
		"function BaseObject.hasPerm(level)\n"
		"	local vname = \"map_\" .. crypt.crc(level)\n"
		"\n"
		"	local plist = BaseObject.data[vname]\n"
		"	if (plist == nil) then\n"
		"		-- access level has no permission requirements\n"
		"		return true\n"
		"	end\n"
		"\n"
		"	local sender = BaseObject.getSentAddress()\n"
		"	if (plist[sender] == nil) then\n"
		"		return false\n"
		"	end\n"
		"\n"
		"	return (plist[sender])\n"
		"end\n"
		"\n"
		"local function BaseObject_Initialize(arg, event_name)\n"
		"	-- parameters\n"
		"	param = arg\n"
		"\n"
		"	if (arg[\"iface\"] == nil) then\n"
		"		return (false)\n"
		"	end\n"
		"\n"
		"	-- param\n"
		"	param[\"iface\"] = tostring(arg[\"iface\"])\n"
		"	param[\"sender\"] = tostring(arg[\"sender\"])\n"
		"	param[\"class\"] = tostring(arg[\"class\"])\n"
		"	param[\"timestamp\"] = tonumber(arg[\"timestamp\"])\n"
		"	param[\"value\"] = tonumber(arg[\"value\"])\n"
		"	param[\"height\"] = tonumber(arg[\"height\"])\n"
		"	param[\"version\"] = tonumber(arg[\"version\"])\n"
		"\n"
		"	if (param[\"version\"] < BaseObject.getVersion()) then\n"
		"		return (false)\n"
		"	end\n"
		"\n"
		"	-- runtime\n"
		"	param[\"fee\"] = 0.0\n"
		"	param[\"checksum\"] = \"\"\n"
		"\n"
		"	BaseObject.data = io.unserialize(param[\"iface\"])\n"
		"\n"
		"	-- first time\n"
		"	if (BaseObject.data == nil) then\n"
		"		BaseObject.data = { }\n"
		"		BaseObject.data[\"owner\"] = tostring(arg[\"owner\"])\n"
		"\n"
		"		enablePerm(PERM_ADMIN)\n"
		"	end\n"
		"\n"
		"	return (true)\n"
		"end\n"
		"os.register(\"InitEvent\", BaseObject_Initialize)\n";

	shfs_write_mem(path, (char *)text, strlen(text));
}


