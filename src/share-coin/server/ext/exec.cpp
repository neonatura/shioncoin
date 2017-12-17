
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
#include "sexe.h"
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>
#include "wallet.h"
#include "exec.h"

using namespace std;
using namespace json_spirit;

#ifdef __cplusplus
extern "C" {
#endif
extern shpeer_t *shcoind_peer(void);

#ifdef __cplusplus
}
#endif



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

exec_list *GetExecTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapExec);
}

static string StripExtAccountName(string strAccount)
{
  if (strAccount.length() != 0 && strAccount.at(0) == '@')
    strAccount = strAccount.substr(1);
  return (strAccount);
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

int64 GetExecOpFee(CIface *iface, int nHeight) 
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5040 / base * COIN;
  double nDif = 5000 /base * COIN;
  int64 nFee = (int64)(nRes - nDif);

  /* floor */
  nFee /= 1000;
  nFee *= 1000;

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

bool IsExecTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_EXEC)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeExecHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

/**
 * Obtain the tx that defines this exec.
 */
bool GetTxOfExec(CIface *iface, const uint160& hashExec, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  exec_list *execes = GetExecTable(ifaceIndex);
  bool ret;

  if (execes->count(hashExec) == 0) {
    return false; /* nothing by that name, sir */
  }

  CTransaction& txIn = (*execes)[hashExec];
  if (!IsExecTx(txIn)) 
    return false; /* inval; not an exec tx */

#if 0
  if (txIn.exec.IsExpired()) {
    return false;
  }
#endif

  tx.Init(txIn);
  return true;
}

bool IsLocalExec(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalExec(CIface *iface, const CTransaction& tx)
{
  if (!IsExecTx(tx))
    return (false); /* not a exec */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalExec(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an exec transaction.
 */
bool VerifyExec(CTransaction& tx, int& mode)
{
  uint160 hashExec;
  int nOut;

  /* core verification */
  if (!IsExecTx(tx)) {
    return (false); /* tx not flagged as exec */
  }

  /* verify hash in pub-script matches exec hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* no extension output */

  if (!DecodeExecHash(tx.vout[nOut].scriptPubKey, mode, hashExec))
    return (false); /* no exec hash in output */

  if (mode != OP_EXT_NEW && 
      mode != OP_EXT_ACTIVATE &&
      mode != OP_EXT_GENERATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_REMOVE)
    return (false);

  CExec exec(tx.certificate);
  if (hashExec != exec.GetHash())
    return error(SHERR_INVAL, "exec hash mismatch");

  return (true);
}

std::string CExec::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CExec::ToValue()
{
  Object obj = CIdent::ToValue();

  if (GetStack().size() != 0) {
    string str((const char *)GetStack().data());
    obj.push_back(Pair("stack", stringFromVch(GetStack())));
  }

  if (nFlag != 0)
    obj.push_back(Pair("flags", nFlag));

  obj.push_back(Pair("signature", signature.GetHash().GetHex()));

  obj.push_back(Pair("app", GetIdentHash().GetHex()));
  obj.push_back(Pair("hash", GetHash().GetHex()));
  return (obj);
}

std::string CExecCall::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CExecCall::ToValue()
{
  Object obj = CIdent::ToValue();

  if (GetStack().size() != 0) {
    string str((const char *)GetStack().data());
    obj.push_back(Pair("stack", str));
  }

  if (nFlag != 0)
    obj.push_back(Pair("flags", nFlag));

  obj.push_back(Pair("signature", signature.GetHash().GetHex()));

#if 0
  CCoinAddr addr(ifaceIndex);
  addr.Set(CKeyID(hashIssuer));
  obj.push_back(Pair("sender", addr.ToString().c_str())); 
#endif

  obj.push_back(Pair("app", GetIdentHash().GetHex()));
  obj.push_back(Pair("hash", GetHash().GetHex()));

  return (obj);
}

/**
 * Sign an app's "bytecode hash" using the extended coin address responsible.
 * @param addr The extended coin address responsible for this app instance.
 */
bool CExec::Sign(int ifaceIndex, CCoinAddr& addr)
{
  cbuff hbuff(hashIssuer.begin(), hashIssuer.end());
  return (CCert::Sign(ifaceIndex, addr, hbuff));
}

/* @todo ensure pubkey in compact sig matches ext coin addr */
bool CExec::VerifySignature()
{
  bool ret;

  cbuff hbuff(hashIssuer.begin(), hashIssuer.end());
  ret = CCert::VerifySignature(hbuff);
  if (!ret) {
    error(SHERR_ACCESS, "CExec.VerifySignature: verification failure: %s", ToString().c_str());
    return (false); 
  }

  return (true);
}

bool CExec::VerifyData(const cbuff& data)
{

  if (data.size() == 0)
    return (false);

  uint160 hData = Hash160(data);
  return (hData == hashIssuer);
}

static bool SetExecLabel(CExec *exec, sexe_mod_t *mod)
{
  if (0 != memcmp(mod->sig, SEXE_SIGNATURE, sizeof(mod->sig)))
    return (false);
  exec->SetLabel(string(mod->name));
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

/* run program and call 'init' event to gather external decl var/func. */
bool CExec::SetStack(const cbuff& data, const CCoinAddr& sendAddr)
{
  shjson_t *json;
  shjson_t *def_json;
  shjson_t *u_json;
  shjson_t *jret;
  shbuf_t *buff;
  sexe_t *S;
  char *str;
  int err;

#if 0
  data = GetExecPoolData(indexPool);
  if (data.size() == 0) {
    error(SHERR_NOENT, "CExec.SetStack: pool index #%d has no content.", indexPool);
    return (false);
  }
#endif

  /* prepare args */
//json = shjson_init(NULL);
//shjson_str_add(json, "version", PACKAGE_STRING); 

  /* prepare runtime */
  buff = shbuf_init();
  unsigned char *raw = (unsigned char *)data.data();
  size_t raw_len = (size_t)data.size();
  shbuf_cat(buff, raw, raw_len);
//err = sexe_exec_popen(buff, json, &S);
  err = sexe_exec_popen(buff, NULL, &S);
  shbuf_free(&buff);
//  shjson_free(&json);
  if (err) {
    return error(err, "CExec.SetStack: error executing code <%d bytes>.", raw_len);
  }

  /* load stack */
  err = sexe_exec_prun(S);
  if (err) {
    error(err, "CExec.SetStack: sexe_exec_prun");
    return (false);
  }

  /* prep args */
  int64 sendValue = 0;
  json = shjson_init(NULL);
  shjson_str_add(json, "sender", (char *)sendAddr.ToString().c_str());
  shjson_num_add(json, "value", ((double)sendValue / (double)COIN));

  /* execute method */
  err = sexe_exec_pcall(S, "init", json);
  shjson_free(&json);
  if (err) {
    error(err, "CExec.SetStack: sexe_exec_pcall");
    return (false);
  }

#if 0
  /* persistent user data */
  u_json = NULL;
  err = sexe_exec_pget(S, "userdata", &u_json);
  if (err) {
    return error(err, "CExec.SetStack: error obtaining user-data.");
  }
fprintf(stderr, "DEBUG: EXEC: USRDATA: \"%s\"\n", shjson_print(u_json));
  shjson_free(&u_json);
#endif

  def_json = NULL;
  err = sexe_exec_pgetdef(S, "userdata", &def_json);
  sexe_exec_pclose(S);
  if (err) {
    return error(err, "CExec.SetStack: error obtaining user-data.");
  }

  str = shjson_print(def_json);
  shjson_free(&def_json);
  if (!str)
    return error(SHERR_INVAL, "CExec.SetStack: error parsing json");
  SetStack(cbuff(str, str + strlen(str)));
  free(str);

  /* non-generate exec tx defines hashIssuer as 20byte hash of exec code. */
  hashIssuer = Hash160(data);

  return (true);
}

static int _sexe_shc_tx_commit(sexe_t *S)
{
  const char *coin_addr = sexe_checkstring(S, 1);
  double coin_val = sexe_checknumber(S, 2);
  int64 nValue = (int64)(coin_val * (double)COIN);

  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);

  CCoinAddr addr(coin_addr);
  CScript scriptPub;
  scriptPub.SetDestination(addr.Get());

  wallet->mapExecCommit.push_back(CTxOut(nValue, scriptPub));

  lua_pushnil(S);
  return (1); /* 1 nil */
}
static int _sexe_test_tx_commit(sexe_t *S)
{
  const char *coin_addr = sexe_checkstring(S, 1);
  double coin_val = sexe_checknumber(S, 2);
  int64 nValue = (int64)(coin_val * (double)COIN);

  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);

  CCoinAddr addr(coin_addr);
  CScript scriptPub;
  scriptPub.SetDestination(addr.Get());

  wallet->mapExecCommit.push_back(CTxOut(nValue, scriptPub));

  lua_pushnil(S);
  return (1); /* 1 nil */
}

int ProcessExecGenerateTx(CIface *iface, CExec *execIn, CExecCall *exec)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  shjson_t *json;
  shbuf_t *buff;
  sexe_t *S;
  char method[256];
  char *str;
  int err;

#if 0
  /* establish coin addr */
  string strAccount;
  CCoinAddr addr = exec->GetCoinAddr();
  if (!GetCoinAddr(wallet, addr, strAccount))
    return (SHERR_NOENT);
#endif

  /* establish ext coin addr */
  string strExtAccount;
  CCoinAddr extAddr = exec->GetExecAddr();
  if (!GetCoinAddr(wallet, extAddr, strExtAccount))
    return (SHERR_INVAL);

  /* verify origin sig */
  if (!execIn->VerifySignature())
    return (SHERR_ACCESS);

  /* verify peer sig */
  if (!exec->VerifySignature(ifaceIndex))
    return (SHERR_ACCESS);

  /* load sexe code */
  cbuff data;
  if (!execIn->LoadPersistentData(data)) {
    error(SHERR_INVAL, "ProcessExecGenerateTx: error loading sexe bytecode.");
    return (SHERR_INVAL);
  }

  /* prepare args */
//  json = shjson_init(NULL);
//  shjson_str_add(json, "version", PACKAGE_STRING); 
  /* prepare runtime */
  buff = shbuf_init();
  shbuf_cat(buff, data.data(), data.size());
//err = sexe_exec_popen(buff, json, &S);
  err = sexe_exec_popen(buff, NULL, &S);
  shbuf_free(&buff);
//  shjson_free(&json);
  if (err) {
    return error(err, "CExec.SetStack: error executing code.");
  }


  switch (ifaceIndex) {
    case TEST_COIN_IFACE:
      lua_pushcfunction(S, _sexe_test_tx_commit);
      lua_setglobal(S, "commit");
      break;
    case SHC_COIN_IFACE:
      lua_pushcfunction(S, _sexe_shc_tx_commit);
      lua_setglobal(S, "commit");
      break;
  }


  /* load runtime */
  err = sexe_exec_prun(S);
  if (err) {
    error(err, "CExec.SetStack: sexe_exec_prun");
    return (false);
  }


  /* prep args */
  str = strchr((char *)exec->vContext.data(), ' ');
  json = shjson_init(str ? str + 1 : NULL);
  shjson_str_add(json, "sender", (char *)exec->GetSendAddr(ifaceIndex).ToString().c_str());
  shjson_num_add(json, "value", ((double)exec->GetSendValue() / (double)COIN));

  memset(method, 0, sizeof(method));
  strncpy(method, (char *)exec->vContext.data(), sizeof(method)-1);
  strtok(method, " ");

//fprintf(stderr, "DEBUG: ProcessExecGenerateTx: SEXE_EXEC_CALL[%s]: %s\n", method, shjson_print(json));

  /* execute method */
  err = sexe_exec_pcall(S, method, json);
  shjson_free(&json);
  if (err) {
fprintf(stderr, "DEBUG: ProcessExecGenerateTx: %d = sexe_exec_pcall('%s')\n", err, method);

#if 0
{
shjson_t *u_json = NULL;
err = sexe_exec_pget(S, "userdata", &u_json);
if (err) {
  error(err, "CExec.SetStack: error obtaining user-data.");
} else {
  fprintf(stderr, "DEBUG: GEN-EXEC: USRDATA: \"%s\"\n", shjson_print(u_json));
  shjson_free(&u_json);
}
}
#endif

    sexe_exec_pclose(S);
    return (false);
  }


  sexe_exec_pclose(S);

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
//fprintf(stderr, "DEBUG: ProcessExecGenerateTx: COMMIT: %s\n", wtx.ToString().c_str()); 
  }

  return (0);
}

/* @todo make extern in header */
int ProcessExecTx(CIface *iface, CNode *pfrom, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CExec& exec = (CExec&)tx.certificate;
  uint160 hExec = exec.GetIdentHash();
  CKeyID inkey;
  CKeyID key;
  int err;


  /* validate */
  int tx_mode;
  if (!VerifyExec(tx, tx_mode)) {
    error(SHERR_INVAL, "ProcessExecTx: error verifying exec tx.");
    return (SHERR_INVAL);
  }

/* .. metric .. */

  if (tx_mode == OP_EXT_UPDATE ||
      tx_mode == OP_EXT_ACTIVATE ||
      tx_mode == OP_EXT_TRANSFER) {
    /* only applies to local server */
    if (!IsLocalExec(iface, tx))
      return (SHERR_REMOTE);
  }

  if (wallet->mapExec.count(hExec) == 0) {
    if (tx_mode != OP_EXT_NEW)
      return (SHERR_NOENT);
  } else {
    /* obtain 'primary' exec tx */
    CTransaction txIn;
    if (!GetTxOfExec(iface, hExec, txIn)) {
      error(SHERR_NOENT, "ProcessExecTx: exec '%s' not registered.", hExec.GetHex().c_str());
      return (SHERR_NOENT);
    }
    CExec& execIn = (CExec&)txIn.certificate;

    if (tx_mode != OP_EXT_NEW &&
        tx_mode != OP_EXT_UPDATE) {
      execIn.GetExecAddr().GetKeyID(inkey);
      exec.GetExecAddr().GetKeyID(key);
      if (inkey != key) {
        error(SHERR_INVAL, "ProcessExecTx: exec coin addr mismatch.");
        return (SHERR_INVAL);
      }
    }

    if (tx_mode == OP_EXT_GENERATE) {
      CExecCall& call = (CExecCall&)tx.certificate;
      err = ProcessExecGenerateTx(iface, &execIn, &call);
      if (err)
        return (err);
    }

#if 0
    if (tx_mode == OP_EXT_REMOVE) {
      ClearExecPoolData(exec.indexPool);
    }
#endif
  }

  if (tx_mode == OP_EXT_NEW || 
      tx_mode == OP_EXT_ACTIVATE ||
      tx_mode == OP_EXT_UPDATE ||
      tx_mode == OP_EXT_TRANSFER) {
    /* [re]insert into ExecTable */
    wallet->mapExec[hExec] = tx;
  } else if (tx_mode == OP_EXT_REMOVE) {
    /* remove from ExecTable */
    wallet->mapExec.erase(hExec);
  }

  return (0);
}

bool CExec::VerifyStack()
{
  return (true);
}

bool CExec::LoadPersistentData(cbuff& data)
{
  SHFL *fl;
  shfs_t *fs;
  char path[PATH_MAX+1];
  shbuf_t *buff;
  int err;

  sprintf(path, "/exec/%s.sx", GetIdentHash().GetHex().c_str());
  fs = shfs_init(shcoind_peer());
  fl = shfs_file_find(fs, path);

  buff = shbuf_init();
  err = shfs_read(fl, buff);
  shfs_free(&fs);
  if (err) {
    shbuf_free(&buff);
    return (error(err, "CExec.LoadPersistentData: error loading bytecode '%s'.", path));
  }
  if (shbuf_size(buff) == 0) {
    shbuf_free(&buff);
    return (SHERR_INVAL);
  }

  unsigned char *raw = shbuf_data(buff);
  unsigned int raw_len = shbuf_size(buff);
  data = cbuff(raw, raw + raw_len);
  shbuf_free(&buff);

  return (true);
}

bool CExec::SavePersistentData(const cbuff& data)
{
  SHFL *fl;
  char path[PATH_MAX+1];
  shbuf_t *buff;
  shfs_t *fs;
  unsigned char *raw;
  size_t raw_len;
  int err;

  if (data.size() == 0)
      return (false);

  buff = shbuf_init();
  raw = (unsigned char *)data.data();
  raw_len = (size_t)data.size();
  shbuf_cat(buff, raw, raw_len);

  sprintf(path, "/exec/%s.sx", GetIdentHash().GetHex().c_str());
  fs = shfs_init(shcoind_peer());
  fl = shfs_file_find(fs, path);
  err = shfs_write(fl, buff);
  shfs_free(&fs);
  shbuf_free(&buff);
  if (err) {
    return (error(err, "CExec.SavePersistentData: error saving bytecode."));
  }

  return (true);
}

bool CExec::RemovePersistentData()
{
  return (true);
}

/* rid of */
bool CExec::SetAccount(int ifaceIndex, string& strAccount)
{
  CWallet *wallet = GetWallet(ifaceIndex);

  strAccount = StripExtAccountName(strAccount);
//  return (wallet->GetMergedAddress(strAccount, "exec", sendaddr));
  return (true);
}

int init_exec_tx(CIface *iface, string strAccount, string strPath, int64 nExecFee, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CExec *exec;

  int64 nFee = GetExecOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
fprintf(stderr, "DEBUG: init_exec_tx: insufficient balance (%llu) .. %llu required\n", bal, nFee);
    return (SHERR_AGAIN);
  }

  CCoinAddr sendAddr(ifaceIndex);
  if (!wallet->GetMergedAddress(strAccount, "exec", sendAddr)) {
    error(SHERR_INVAL, "init_exec_tx: error generating merged address.");
    return (false);
  }

  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */

  /* embed exec content into transaction */
  exec = wtx.CreateExec();
//  exec->SetAccount(ifaceIndex, strAccount);
  exec->SetFee(MAX(iface->min_tx_fee, nExecFee));

cbuff data;
  if (!exec->LoadData(strPath, data)) {
    error(SHERR_INVAL, "init_exec_tx: error loading sexe bytecode.");
    return (SHERR_NOENT);
  }

  if (!exec->SetStack(data, sendAddr)) {
    error(SHERR_INVAL, "init_exec_tx: error initializing sexe bytecode.");
    return (SHERR_INVAL);
  }

  if (!exec->Sign(ifaceIndex, extAddr)) {
    error(SHERR_INVAL, "init_exec_tx: error signing sexe bytecode.");
    return (SHERR_INVAL);
  }

  /* after "IdentHash" has been established. */
  if (!exec->SavePersistentData(data))
    return (SHERR_IO);


  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());

  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << exec->GetHash() << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  // send transaction
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, "init_exec_tx: %s", strError.c_str());
    return (SHERR_INVAL);
  }


#if 0
  /* temporary allocation. */
  ClearExecPoolData(exec->indexPool);
#endif

  uint160 hExec = exec->GetHash();
#if 0
  /* stow away to retain pool index of data allocated */
  wallet->mapExec[hExec] = wtx;
#endif

  Debug("SENT:EXECNEW : title=%s, exechash=%s, tx=%s\n", exec->GetLabel().c_str(), hExec.GetHex().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}


/* prob should require removal of original first to update */
int update_exec_tx(CIface *iface, const uint160& hashExec, string strPath, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  /* verify original exec */
  CTransaction tx;
  if (!GetTxOfExec(iface, hashExec, tx)) {
fprintf(stderr, "DEBUG: update_exec_tx: !GetTxOfExec\n");
    return (SHERR_NOENT);
}
  if(!IsLocalExec(iface, tx)) {
fprintf(stderr, "DEBUG: update_exec_tx: !IsLocalExec\n");
    return (SHERR_REMOTE);
}

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0) {
    return (SHERR_REMOTE);
}

  CExec& execIn = (CExec&)tx.certificate;

  /* establish account */
  string strExtAccount;
  CCoinAddr extAddr = execIn.GetExecAddr();
  if (!GetCoinAddr(wallet, extAddr, strExtAccount))
    return (SHERR_NOENT);

  string strAccount = StripExtAccountName(strExtAccount);
  int64 nNetFee = GetExecOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }

  /* generate tx */
  CExec *exec;
	CScript scriptPubKey;
  wtx.SetNull();
  wtx.strFromAccount = strAccount;

  exec = wtx.UpdateExec(execIn);

  /* establish 'sender' coin addr */
  CCoinAddr sendAddr(ifaceIndex);
  if (!wallet->GetMergedAddress(strAccount, "exec", sendAddr))
    return (SHERR_INVAL);

  /* generate new ext addr */
  extAddr = GetAccountAddress(wallet, strExtAccount, true);

  /* load new sexe code */
  cbuff data;
  if (!exec->LoadData(strPath, data))
    return (SHERR_INVAL);

  /* initialize code */
  if (!exec->SetStack(data, sendAddr))
    return (SHERR_INVAL);

  /* sign code */
  if (!exec->Sign(ifaceIndex, extAddr))
    return (SHERR_NOKEY);

  /* after "IdentHash" has been established. */
  if (!exec->SavePersistentData(data))
    return (SHERR_IO);


  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << exec->GetHash() << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  vector<pair<CScript, int64> > vecSend;
  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend)) {
    fprintf(stderr, "DEBUG: update_exec_tx: !SendMoneyWithExtTx\n"); 
    return (SHERR_INVAL);
  }

  uint160 execHash = exec->GetIdentHash();
//  wallet->mapExec[execHash] = wtx;
  Debug("SENT:EXECUPDATE : title=%s, exechash=%s, tx=%s\n", exec->GetLabel().c_str(), execHash.ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

/**
 * @todo ensure that called method has been declared in primary exec tx's context definitions
 */
int generate_exec_tx(CIface *iface, string strAccount, uint160 hExec, string strFunc, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  char buf[256];

  /* obtain primary exec tx */
  CTransaction tx;
  if (!GetTxOfExec(iface, hExec, tx))
    return (SHERR_NOENT);
  CExec& execIn = (CExec&)tx.certificate;

  /* ensure sufficient funds are available to invoke call */
  int64 nFee = MAX(iface->min_tx_fee, execIn.GetFee() - iface->min_tx_fee);
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < (nFee + (int64)iface->min_tx_fee)) {
fprintf(stderr, "DEBUG: generate_exec_tx: insufficient balance (%llu) .. %llu required\n", bal, nFee);
    return (SHERR_AGAIN);
  }

  /* define "sender" address. */
  CCoinAddr sendAddr(ifaceIndex);
  if (!wallet->GetMergedAddress(strAccount, "exec", sendAddr)) {
    error(SHERR_INVAL, "generate_exec_tx: invalid sender exec coin addr."); 
    return (SHERR_INVAL);
  }

  /* define "execution" address. */
  CCoinAddr recvAddr = execIn.GetExecAddr();
  if (!recvAddr.IsValid()) {
    error(SHERR_INVAL, "generate_exec_tx: invalid receive exec coin addr: \"%s\".", execIn.vAddr.data());
    return (SHERR_INVAL);
  }

  /* init tx */
  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */
  CExecCall *exec = wtx.GenerateExec(execIn, sendAddr);

  /* set fee */
  exec->SetSendValue(execIn.GetFee());

  /* set "stack" */
  memset(buf, 0, sizeof(buf));
  sprintf(buf, "%s {\"sender\":\"%s\",\"value\":%-8.8f}", strFunc.c_str(), sendAddr.ToString().c_str(), ((double)nFee / (double)COIN));
  cbuff sbuff(buf, buf + strlen(buf));
  if (!exec->SetStack(sbuff)) {
    return (SHERR_INVAL);
  }

  /* sign "sender" addr */
  if (!exec->Sign(ifaceIndex, sendAddr))
    return (SHERR_NOKEY);

  CScript scriptPubKey;
  scriptPubKey << OP_EXT_GENERATE << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << exec->GetHash() << OP_2DROP << OP_RETURN;

  /* send to extended tx storage account as non-ext tx output */
  CScript scriptPubKeyDest;
  scriptPubKeyDest.SetDestination(execIn.GetExecAddr().Get());

  vector<pair<CScript, int64> > vecSend;
  vecSend.push_back(make_pair(scriptPubKey, (int64)iface->min_tx_fee));
  vecSend.push_back(make_pair(scriptPubKeyDest, nFee));

  // send transaction
  int64 nFeeRet = 0;
  CReserveKey rkey(wallet);
  if (!wallet->CreateTransaction(vecSend, wtx, rkey, nFeeRet))
    return (SHERR_CANCELED);
//const std::vector<std::pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet))

  if (!wallet->CommitTransaction(wtx))
    return (SHERR_CANCELED);

#if 0
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }
#endif

  /* identify tx using hash that does not take into account context */
  uint160 execHash = exec->GetIdentHash();
  uint256 txHash = wtx.GetHash();
  Debug("SENT:EXECGENERATE : title=%s, exechash=%s, tx=%s\n", exec->GetLabel().c_str(), execHash.ToString().c_str(), txHash.GetHex().c_str());
//  wallet->mapExec[execHash] = wtx;

  return (0);
}

/**
 * Certify an application.
 */
int activate_exec_tx(CIface *iface, uint160 hExec, string hCert, CWalletTx& wtx)
{
  return (SHERR_OPNOTSUPP);
}

int transfer_exec_tx(CIface *iface, uint160 hExec, string strAccount, CWalletTx& wtx)
{
  return (SHERR_OPNOTSUPP);
}


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
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  /* verify original exec */
  CTransaction tx;
  if (!GetTxOfExec(iface, hashExec, tx)) {
    fprintf(stderr, "DEBUG: update_exec_tx: !GetTxOfExec\n");
    return (SHERR_NOENT);
  }

  if(!IsLocalExec(iface, tx)) {
    fprintf(stderr, "DEBUG: update_exec_tx: !IsLocalExec\n");
    return (SHERR_REMOTE);
  }

  /* establish user account */
  string strExtAccount;
  CExec& execIn = (CExec&)tx.certificate;
  CCoinAddr extAddr = execIn.GetExecAddr();
  if (!GetCoinAddr(wallet, extAddr, strExtAccount))
    return (SHERR_NOENT);

  string strAccount = StripExtAccountName(strExtAccount);
  int64 nNetFee = GetExecOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }

  /* establish user address. */
  CCoinAddr recvAddr(ifaceIndex);
  if (!wallet->GetMergedAddress(strAccount, "exec", recvAddr)) {
    error(SHERR_NOENT, "remove_exec_tx: error obtaining user coin address.");
    return (SHERR_NOENT);
  }

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
}


bool CExecCall::Sign(int ifaceIndex, CCoinAddr& addr)
{

  if (!signature.SignAddress(ifaceIndex, addr, vContext.data(), vContext.size())) {
    return (false);
  }

  CKeyID k;
  if (!addr.GetKeyID(k))
    return (false);

  hashIssuer = k;
  return (true);
}

bool CExecCall::VerifySignature(int ifaceIndex)
{
  CCoinAddr addr(ifaceIndex);

  addr.Set(CKeyID(hashIssuer));
  if (!signature.VerifyAddress(addr, vContext.data(), vContext.size())) {
    return (false);
  }

  return (true);
}

