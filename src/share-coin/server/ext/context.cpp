

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
#include "context.h"

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

void InitContextPool()
{
  if (pool) return;

  unsigned int idx;
  pool = shpool_init();
  (void)shpool_get(pool, &idx);
}

static cbuff GetContextPoolData(uint32_t idx)
{
  unsigned char *raw;
  size_t raw_len;
  shbuf_t *buff;

  InitContextPool();

  buff = shpool_get_index(pool, idx);
  if (!buff)
    return (cbuff());

  raw = shbuf_data(buff);
  raw_len = shbuf_size(buff);
  return (cbuff(raw, raw + raw_len));
}

static unsigned int SetContextPoolData(cbuff vData)
{
  shbuf_t *buff;
  unsigned int indexPool;

  InitContextPool();

  buff = shpool_get(pool, &indexPool);
  shbuf_clear(buff);
  shbuf_cat(buff, vData.data(), vData.size());
  
  return (indexPool);
}

static void ClearContextPoolData(int idx)
{
  unsigned char *raw;
  size_t raw_len;
  shbuf_t *buff;

  if (idx == 0)
    return;

  InitContextPool();

  buff = shpool_get_index(pool, idx);
  if (!buff)
    return;

  shbuf_clear(buff);
}
#endif

ctx_list *GetContextTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapContext);
}

static string StripExtAccountName(string strAccount)
{
  if (strAccount.length() != 0 && strAccount.at(0) == '@')
    strAccount = strAccount.substr(1);
  return (strAccount);
}

bool DecodeContextHash(const CScript& script, int& mode, uint160& hash)
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
  op = CScript::DecodeOP_N(opcode); /* extension type (ctx) */
  if (op != OP_CONTEXT) {
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



bool IsContextOp(int op) {
	return (op == OP_CONTEXT);
}


string ctxFromOp(int op) {
	switch (op) {
	case OP_EXT_NEW:
		return "ctxnew";
	case OP_EXT_UPDATE:
		return "ctxupdate";
	case OP_EXT_ACTIVATE:
		return "ctxactivate";
	case OP_EXT_GENERATE:
		return "ctxgenerate";
	case OP_EXT_TRANSFER:
		return "ctxtransfer";
	case OP_EXT_REMOVE:
		return "ctxremove";
	default:
		return "<unknown ctx op>";
	}
}

bool DecodeContextScript(const CScript& script, int& op,
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

	op = CScript::DecodeOP_N(opcode); /* extension type (ctx) */
  if (op != OP_CONTEXT)
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
      (mode == OP_EXT_REMOVE && vvch.size() == 2))
    return (true);

	return false;
}

bool DecodeContextScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeContextScript(script, op, vvch, pc);
}

CScript RemoveContextScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeContextScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveContextScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetContextOpFee(CIface *iface, int nHeight, int nSize) 
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5200 / base * COIN;
  double nDif = 5000 /base * COIN;
  int64 nFee = (int64)(nRes - nDif);
  double nFact;

  nFact = 4096 / (double)MIN(4096, MAX(32, nSize));
  nFee = (int64)((double)nFee / nFact);

  /* floor */
  nFee /= 100000;
  nFee *= 100000;

  nFee = MAX(100000, nFee);
  nFee = MAX(MIN_TX_FEE(iface), nFee);
  nFee = MIN(MAX_TX_FEE(iface), nFee);
  return (nFee);
}


int64 GetContextReturnFee(const CTransaction& tx) 
{
	int64 nFee = 0;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
			nFee += out.nValue;
	}
	return nFee;
}

bool IsContextTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_CONTEXT)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeContextHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

/**
 * Obtain the tx that defines this ctx.
 */
bool GetTxOfContext(CIface *iface, const uint160& hashContext, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  ctx_list *ctxes = GetContextTable(ifaceIndex);
  bool ret;

  if (ctxes->count(hashContext) == 0) {
    return false; /* nothing by that name, sir */
  }

  CTransaction txIn;
  uint256 hTx = (*ctxes)[hashContext];
  ret = GetTransaction(iface, hTx, txIn, NULL);
  if (!ret)
    return (error(SHERR_NOENT, "invalid tx hash reference."));

  if (!IsContextTx(txIn)) 
    return false; /* inval; not an ctx tx */

  tx.Init(txIn);
  return true;
}

bool IsLocalContext(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalContext(CIface *iface, const CTransaction& tx)
{
  if (!IsContextTx(tx))
    return (false); /* not a ctx */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalContext(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an ctx transaction.
 */
bool VerifyContextTx(CIface *iface, CTransaction& tx, int& mode)
{
  uint160 hashContext;
  time_t now;
  int nOut;

  /* core verification */
  if (!IsContextTx(tx)) {
    return (false); /* tx not flagged as ctx */
  }

  /* verify hash in pub-script matches ctx hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* no extension output */

  if (!DecodeContextHash(tx.vout[nOut].scriptPubKey, mode, hashContext))
    return (false); /* no ctx hash in output */

  if (mode != OP_EXT_NEW && 
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_REMOVE)
    return (false);

  CContext ctx(tx.certificate);
  if (hashContext != ctx.GetHash())
    return error(SHERR_INVAL, "ctx hash mismatch");

  int64 nFee = GetContextOpFee(iface, GetBestHeight(iface), ctx.vContext.size());
  if (tx.vout[nOut].nValue < nFee)
    return error(SHERR_INVAL, "insufficient funds in coin output");

  now = time(NULL);
  if (ctx.GetExpireTime() > (now + DEFAULT_CONTEXT_LIFESPAN))
    return error(SHERR_INVAL, "invalid expiration time");

  return (true);
}

std::string CContext::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CContext::ToValue()
{
  static char buf[256];
  Object obj = CIdent::ToValue();
  uint64_t crc;

  memset(buf, 0, sizeof(buf));
  crc = shcrc(vContext.data(), vContext.size());
  strncpy(buf, shcrcstr(crc), sizeof(buf)-1);
  string strChecksum(buf);
  
  if (nFlag != 0)
    obj.push_back(Pair("flags", nFlag));
  obj.push_back(Pair("signature", signature.GetHash().GetHex()));
  obj.push_back(Pair("hash", GetHash().GetHex()));
  obj.push_back(Pair("valuesize", (int)vContext.size()));
  obj.push_back(Pair("valuecrc", strChecksum));

  return (obj);
}


/**
 * Sign an app's "bytecode hash" using the extended coin address responsible.
 * @param addr The extended coin address responsible for this app instance.
 */
bool CContext::Sign(int ifaceIndex)
{

  if (vContext.size() == 0)
    return (false);

  return (signature.SignContext(vContext));
}

/* @todo ensure pubkey in compact sig matches ext coin addr */
bool CContext::VerifySignature()
{
  bool ret;

  if (vContext.size() == 0)
    return (false);

  ret = signature.VerifyContext(vContext.data(), vContext.size());

  if (!ret) {
    error(SHERR_ACCESS, "CContext.VerifySignature: verification failure: %s", ToString().c_str());
    return (false); 
  }

  return (true);
}






/* @todo make extern in header */
int CommitContextTx(CIface *iface, CTransaction& tx, unsigned int nHeight)
{
  CWallet *wallet = GetWallet(iface);
  CContext& ctx = (CContext&)tx.certificate;
  uint160 hContext = ctx.GetHash();
  int err;

  /* validate */
  int tx_mode;
  if (!VerifyContextTx(iface, tx, tx_mode)) {
    error(SHERR_INVAL, "CommitContextTx: error verifying ctx tx.");
    return (SHERR_INVAL);
  }

  if (wallet->mapContext.count(hContext) != 0) {
    /* already exists. */
    if (tx_mode == OP_EXT_NEW)
      return (SHERR_NOTUNIQ);

    const uint256& hOrig = wallet->mapContext[hContext];
    wallet->mapContextArch[hOrig] = hContext;
  }

  /* assign context to internal map */
  wallet->mapContext[hContext] = tx.GetHash();

  /* propagate via share runtime library */
  shctx_set_key(ctx.hashIssuer.GetKey(), 
      ctx.vContext.data(), ctx.vContext.size());
#if 0
/* DEBUG: */ /* record in libshare runtime */
  ctx.NotifySharenet(GetCoinIndex(iface));
#endif

  return (0);
}

bool DisconnectContextTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  CContext *ctx = (CContext *)&tx.certificate;
  const uint160& hContext = ctx->GetHash();

  if (wallet->mapContext.count(hContext) == 0)
    return (false);

  const uint256& o_tx = wallet->mapContext[hContext];
  if (o_tx != tx.GetHash())
    return (false);

  /* NOTE: order matters here. last = best */
  uint256 n_tx;
  bool found = false;
  for(map<uint256,uint160>::iterator it = wallet->mapContextArch.begin(); it != wallet->mapContextArch.end(); ++it) {
    const uint256& hash2 = (*it).first;
    const uint160& hash1 = (*it).second;
    if (hash1 == hContext) {
      n_tx = hash2;
      found = true;
    }
  }

  if (found) {
    /* transition current entry to archive */
    wallet->mapContextArch[o_tx] = hContext;

    wallet->mapContext[hContext] = n_tx;
  } else {
    wallet->mapContext.erase(hContext);
  }

}


CContext *GetContextByHash(CIface *iface, uint160 hashName, CTransaction& ctx_tx)
{
  CContext *ctx;

  if (!GetTxOfContext(iface, hashName, ctx_tx))
    return (NULL);

  ctx = (CContext *)&ctx_tx.certificate;

  if (ctx->IsExpired())
    return (NULL);

  return (ctx);
}


#include <algorithm>
#include <string>

uint160 GetContextHash(string strName)
{

  std::transform(strName.begin(), strName.end(), strName.begin(), ::tolower);
  cbuff vchName(strName.begin(), strName.end());

  if (vchName.size() < 16)
    vchName.resize(16);

  return (Hash160(vchName));
}

CContext *GetContextByName(CIface *iface, string strName, CTransaction& ctx_tx)
{
  return (GetContextByHash(iface, GetContextHash(strName), ctx_tx));
}

bool IsContextName(CIface *iface, string strName)
{
  CTransaction t_tx;

  if (GetContextByName(iface, strName, t_tx) != NULL) {
    return (true);
  }

  return (false);
}


/**
 * Set the context value.
 * @param name The name of the context (at least 3 characters).
 * @param value The contents of the context value (4096 max bytes).
 */
bool CContext::SetValue(string name, cbuff value)
{

  if (name.size() < 3)
    return (false);

  if (value.size() == 0 || value.size() > 4096)
    return (false);

  hashIssuer = GetContextHash(name);

  /* set context value */
  vContext = value;

  {
    char buf[256];
    uint64_t crc = shcrc(vContext.data(), vContext.size());
    sprintf(buf, "%s %-24.24s (%s)",
        hashIssuer.GetHex().c_str(), name.c_str(), shcrcstr(crc)); 
    string sLabel(buf);
    SetLabel(sLabel);
  }

  return (true);
}

static string GetObjectValue(Object obj, string cmp_name)
{
  for( Object::size_type i = 0; i != obj.size(); ++i )
  {
    const Pair& pair = obj[i];
    const string& name = pair.name_;

    if (cmp_name == name) {
      const Value& value = pair.value_;
      return (value.get_str());
    }
  }

  return (string());
}

void CContext::NotifySharenet(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  shkey_t key;
  unsigned char *data;
  size_t data_len;
  uint32_t val;

  if (!iface || !iface->enabled) {
    return;
  }

  if (ifaceIndex != SHC_COIN_IFACE) {
    return;
  }

  data = (unsigned char *)calloc(vContext.size() + 256, sizeof(char));
  if (!data)
    return; /* NOMEM */

  /* context name */
  memcpy(&key, hashIssuer.GetKey(), sizeof(shkey_t));
  memcpy(data, &key, sizeof(shkey_t)); 
  data_len += sizeof(shkey_t); 

  /* context size */
  val = htonl((uint32_t)vContext.size());
  memcpy(data + data_len, &val, sizeof(uint32_t));
  data_len += sizeof(uint32_t);

  /* context payload */
  memcpy(data + data_len, vContext.data(), vContext.size());
fprintf(stderr, "DEBUG: CContext:NotifySharenet: key '%s' = '%s'\n", shkey_print(&key), (data + data_len));
  data_len += vContext.size();

  shnet_inform(iface, TX_CONTEXT, data, data_len);

  free(data);


}

bool FormatGeoContext(CIface *iface, string& strGeo, shnum_t& lat, shnum_t& lon)
{
  static char buf[256];

  if (strGeo.size() < 3)
    return (false);

  if (strGeo.substr(0, 4) != "geo:") {
    string strLoc = "loc:" + strGeo;

    CTransaction t_tx;
    CContext *ctx = GetContextByName(iface, strLoc, t_tx);
    if (!ctx)
      return (false);

    strGeo = stringFromVch(ctx->vContext); /* geo:-f,f */
  }

  sscanf(strGeo.c_str(), "geo:%Lf,%Lf", &lat, &lon);
  if (lat == 0.00000 || lon == 0.00000)
    return (false);

  lat = fabsl(lat);
  lon = fabsl(lon);
  sprintf(buf, "geo:%-5.5Lf,%-5.5Lf", lat, lon);
  strGeo = string(buf);

fprintf(stderr, "DEBUG: FormatGeoContext: lat(%Lf) lon(%Lf)\n", lat, lon);

  return (true);
}

void share_geo_save(CContext *ctx, string label)
{
  shloc_t loc;
  int err;
  shnum_t lat, lon;

  if (0 != strncmp(label.c_str(), "geo:", 4))
    return;

  memset(&loc, 0, sizeof(loc));

  shgeo_loc(&ctx->geo, &lat, &lon, NULL);

  Value val;
  if (!read_string(stringFromVch(ctx->vContext), val))
    return;

  (void)shgeodb_loc_unset(&ctx->geo);

  Object ret_obj = val.get_obj();
  string strPlaceName = GetObjectValue(ret_obj, "name");
  string strPlaceType = GetObjectValue(ret_obj, "code");
  string strPlaceLocale = GetObjectValue(ret_obj, "country");
  string strPlaceSummary = GetObjectValue(ret_obj, "summary");


  if (strPlaceName.length() != 0)
    strncpy(loc.loc_name, strPlaceName.c_str(), sizeof(loc.loc_name)-1);

  if (strPlaceType.length() != 0)
    strncpy(loc.loc_type, strPlaceType.c_str(), sizeof(loc.loc_type)-1);

  if (strPlaceLocale.length() == 2)
    strncpy(loc.loc_locale, strPlaceLocale.c_str(), sizeof(loc.loc_locale)-1);

  if (strPlaceSummary.length() != 0)
    strncpy(loc.loc_summary, strPlaceSummary.c_str(), sizeof(loc.loc_summary)-1);

  err = shgeodb_loc_set(&ctx->geo, &loc);    
  if (err) {
fprintf(stderr, "DEBUG: %d = shgeodb_loc_set(%Lf,%Lf)\n", err, lat, lon);
  }

}

int init_ctx_tx(CIface *iface, CWalletTx& wtx, string strAccount, string strName, cbuff vchValue, shgeo_t *loc, bool fAddr)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CContext *ctx;

  if (strName.length() < 3) {
    return (SHERR_INVAL);
  }
  if (vchValue.size() == 0) {
    return (SHERR_INVAL);
  }
  if (vchValue.size() > CContext::MAX_VALUE_SIZE) {
    return (SHERR_INVAL);
  }

  int64 nFee = GetContextOpFee(iface, GetBestHeight(iface), vchValue.size());
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (SHERR_AGAIN);
  }

  if (IsContextName(iface, strName)) {
    error(SHERR_INVAL, "init_ctx_tx: duplicate context name.");
    return (SHERR_NOTUNIQ);
  }

  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */

  /* embed ctx content into transaction */
  ctx = wtx.CreateContext();
  if (!ctx) {
    error(SHERR_INVAL, "init_ctx_tx: error initializing context transaction.");
    return (SHERR_INVAL);
  }

  if (loc) {
    memcpy(&ctx->geo, loc, sizeof(shgeo_t));
  }

  if (fAddr) {
    CCoinAddr addr(ifaceIndex);
    if (wallet->GetMergedAddress(strAccount, "context", addr)) {
      ctx->vAddr = vchFromString(addr.ToString());
    }
  }

  if (!ctx->SetValue(strName, vchValue)) {
    error(SHERR_INVAL, "init_ctx_tx: error setting context value.");
    return (SHERR_INVAL);
  }

  if (!ctx->Sign(ifaceIndex)) {
    error(SHERR_INVAL, "init_ctx_tx: error signing context.");
    return (SHERR_INVAL);
  }

  uint160 hContext = ctx->GetHash();


  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_CONTEXT) << OP_HASH160 << hContext << OP_2DROP;

  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);
  CScript destPubKey;
  destPubKey.SetDestination(extAddr.Get());
  scriptPubKey += destPubKey;

  // send transaction
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, "init_ctx_tx: %s", strError.c_str());
    return (SHERR_INVAL);
  }

  Debug("SENT:CONTEXTNEW : title=%s, ctxhash=%s, tx=%s\n", ctx->GetLabel().c_str(), hContext.GetHex().c_str(), wtx.GetHash().GetHex().c_str());

  if (GetCoinIndex(iface) == SHC_COIN_IFACE) {
    share_geo_save(ctx, strName);
  }

  return (0);
}

int update_ctx_tx(CIface *iface, CWalletTx& wtx, string strAccount, string strName, cbuff vchValue, shgeo_t *loc, bool fAddr)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CContext *ctx;

  if (strName.length() < 3) {
    return (SHERR_INVAL);
  }
  if (vchValue.size() == 0) {
    return (SHERR_INVAL);
  }
  if (vchValue.size() > CContext::MAX_VALUE_SIZE) {
    return (SHERR_INVAL);
  }

  CTransaction txIn;
  CContext *ctxIn = GetContextByName(iface, strName, txIn);
  if (!ctxIn)
    return (SHERR_NOENT);

  const uint256& wtxInHash = txIn.GetHash();

  int nOut = IndexOfExtOutput(txIn);
  if (nOut == -1)
    return (SHERR_INVAL);

  int64 nFee = GetContextOpFee(iface, GetBestHeight(iface), vchValue.size());
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee)
    return (SHERR_AGAIN);

  if (wallet->mapWallet.count(wtxInHash) == 0)
    return (SHERR_REMOTE);

/* DEBUG: TODO: ensure is same account */


  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */

  /* embed ctx content into transaction */
  ctx = wtx.CreateContext();
  if (!ctx) {
    error(SHERR_INVAL, "init_ctx_tx: error initializing context transaction.");
    return (SHERR_INVAL);
  }

  if (loc) {
    memcpy(&ctx->geo, loc, sizeof(shgeo_t));
  }

  if (fAddr) {
    CCoinAddr addr(ifaceIndex);
    if (wallet->GetMergedAddress(strAccount, "context", addr)) {
      ctx->vAddr = vchFromString(addr.ToString());
    }
  }

  if (!ctx->SetValue(strName, vchValue)) {
    error(SHERR_INVAL, "init_ctx_tx: error setting context value.");
    return (SHERR_INVAL);
  }

  if (!ctx->Sign(ifaceIndex)) {
    error(SHERR_INVAL, "init_ctx_tx: error signing context.");
    return (SHERR_INVAL);
  }

  uint160 hContext = ctx->GetHash();


  CScript scriptPubKey;
  scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_CONTEXT) << OP_HASH160 << hContext << OP_2DROP;

  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);
  CScript destPubKey;
  destPubKey.SetDestination(extAddr.Get());
  scriptPubKey += destPubKey;

  vector<pair<CScript, int64> > vecSend;
  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend)) {
    return (SHERR_CANCELED);
  }

  Debug("SENT:CONTEXTUPDATE : title=%s, ctxhash=%s, tx=%s\n", ctx->GetLabel().c_str(), hContext.GetHex().c_str(), wtx.GetHash().GetHex().c_str());

  if (GetCoinIndex(iface) == SHC_COIN_IFACE) {
    share_geo_save(ctx, strName);
  }

  return (0);
}








