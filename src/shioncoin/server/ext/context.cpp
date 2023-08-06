

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
#include "sexe.h"
#include "json_spirit_reader_template.h"
#include "json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>
#include "wallet.h"
#include "context.h"
#include "txcreator.h"

using namespace std;
using namespace json_spirit;

#ifdef __cplusplus
extern "C" {
#endif
extern shpeer_t *shcoind_peer(void);

#ifdef __cplusplus
}
#endif

static bool is_numeric(const std::string& s)
{
    return( strspn( s.c_str(), "0123456789" ) == s.size() );
}


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
  if (strAccount.length() != 0 && 
			strAccount.substr(0, 1) == CWallet::EXT_ACCOUNT_PREFIX)
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

int64 GetContextOpFee(CIface *iface, int nHeight, int nSize, time_t nLifespan)
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5200 / base * COIN;
  double nDif = 5000 /base * COIN;
  int64 nFee = (int64)(nRes - nDif);
  double nFact;

  /* content fee */
  nFact = 4096 / (double)MIN(4096, MAX(32, nSize));
  nFee = (int64)((double)nFee / nFact);

  /* lifespan */
  if (nLifespan > 0) {
    nLifespan = MAX(nLifespan, CContext::MIN_CONTEXT_LIFESPAN);
    nLifespan = MIN(nLifespan, CContext::MAX_CONTEXT_LIFESPAN);
    nFee = (int64)((double)nFee / (double)CContext::MIN_CONTEXT_LIFESPAN * (double)nLifespan);
  }

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

#if 0
/**
 * Verify the integrity of an ctx transaction.
 */
bool VerifyContextTx(CIface *iface, CTransaction& tx, int& mode)
{
  uint160 hashContext;
  time_t now;
  int nOut;
	int err;

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

	err = ctx_context_verify(ctx.vContext);
	if (err)
		return (error(err, "context verification failure"));

  int64 nFee = GetContextOpFee(iface, GetBestHeight(iface), ctx.vContext.size());
  if (tx.vout[nOut].nValue < nFee)
    return error(SHERR_INVAL, "insufficient funds in coin output");

  now = time(NULL);
  if (ctx.GetExpireTime() > (now + DEFAULT_CONTEXT_LIFESPAN))
    return error(SHERR_INVAL, "invalid expiration time");

	if (!ctx.VerifySignature()) {
		return (error(SHERR_ACCESS, "VerifyContextTx: invalid signature."));
	}

  return (true);
}
#endif

std::string CContext::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CContext::ToValue()
{
  static char buf[256];
  Object obj = CEntity::ToValue();
  uint64_t crc;

  memset(buf, 0, sizeof(buf));
  crc = shcrc(vContext.data(), vContext.size());
  strncpy(buf, shcrcstr(crc), sizeof(buf)-1);
  string strChecksum(buf);
  
#if 0
  if (nFlag != 0)
    obj.push_back(Pair("flags", nFlag));
#endif
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
	shkey_t *key;
	const char *hex_str;
	bool ok;

  if (vContext.size() == 0) {
		error(SHERR_INVAL, "CContext.Sign: vContext is empty.");
    return (false);
	}

	key = hashIssuer.GetKey();
	hex_str = shkey_hex(key);
	string hex_seed(hex_str, hex_str+strlen(hex_str)); 
  ok = signature.SignContext(vContext, hex_seed);
	if (!ok) {
		error(SHERR_INVAL, "CContext.Sign: vContext<%d bytes>, hex_seed(%s)\n", vContext.size(), hex_seed.c_str());
	}

	return (ok);
}

/* @todo ensure pubkey in compact sig matches hashIsser */
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
	CContext *ctx;
	uint160 hContext;
  int err;

	ctx = tx.GetContext();
	if (!ctx)
		return (ERR_INVAL);
	hContext = ctx->GetHash();

  /* validate */
	if (!tx.VerifyContext(GetCoinIndex(iface))) {
		return (ERR_INVAL);
	}
#if 0
  int tx_mode;
  if (!VerifyContextTx(iface, tx, tx_mode)) {
    error(SHERR_INVAL, "CommitContextTx: error verifying ctx tx.");
    return (SHERR_INVAL);
  }
#endif
	int tx_mode;
	int nOut = IndexOfContextOutput(tx);
  if (nOut == -1)
    return (SHERR_INVAL);//error(SHERR_INVAL, "no contxt output script"));

  uint160 hashContext;
  if (!DecodeContextHash(tx.vout[nOut].scriptPubKey, tx_mode, hashContext))
    return (SHERR_INVAL);//error(SHERR_INVAL, "no context hash in output"));

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
  shctx_set_key(ctx->hashIssuer.GetKey(), 
      ctx->vContext.data(), ctx->vContext.size());
#if 0
/* DEBUG */ /* record in libshare runtime */
  ctx.NotifySharenet(GetCoinIndex(iface));
#endif

  return (0);
}

bool DisconnectContextTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
	CContext *ctx;
	uint160 hContext;

	ctx = tx.GetContext();
	if (!ctx)
		return (false);
	hContext = ctx->GetHash();

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

	return (true);
}


CContext *GetContextByHash(CIface *iface, uint160 hashName, CTransaction& ctx_tx)
{
  CContext *ctx;

  if (!GetTxOfContext(iface, hashName, ctx_tx))
    return (NULL);

  ctx = (CContext *)ctx_tx.GetContext();
	if (!ctx)
		return (NULL);

  if (ctx->IsExpired()) {
    return (NULL);
	}

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

int ctx_context_verify(cbuff vchValue)
{
	static const unsigned char *gzip = (unsigned char *)"\037\213";
	static const unsigned char *bz2 = (unsigned char *)"\102\132\150\071\061\101\131\046";
	static const unsigned char *rar = (unsigned char *)"Rar!";
	static const unsigned char *jpeg = (unsigned char *)"\377\330\377\341";
	static const unsigned char *zip = (unsigned char *)"\120\113\003\004";
	static const unsigned char *xz = (unsigned char *)"\xFD" "7zXZ";
	static const unsigned char *shz = (unsigned char *)"\132\123\042\042";
	static const unsigned char *gif = (unsigned char *)"GIF89a";
	static const unsigned char *png = (unsigned char *)"\211PNG\015\012\032\012";
	static const unsigned char *winexe = (unsigned char *)"MZ";

	if (vchValue.size() <= 8)
		return (0);

	if (std::equal(vchValue.begin(), vchValue.begin()+2, gzip) ||
			std::equal(vchValue.begin(), vchValue.begin()+8, bz2) ||
			std::equal(vchValue.begin(), vchValue.begin()+4, rar) ||
			std::equal(vchValue.begin(), vchValue.begin()+4, jpeg) || 
			std::equal(vchValue.begin(), vchValue.begin()+4, zip) ||
			std::equal(vchValue.begin(), vchValue.begin()+5, xz) ||
			std::equal(vchValue.begin(), vchValue.begin()+4, shz) ||
			std::equal(vchValue.begin(), vchValue.begin()+6, gif) ||
			std::equal(vchValue.begin(), vchValue.begin()+8, png) ||
			std::equal(vchValue.begin(), vchValue.begin()+2, winexe)) {
		/* suppress common images, executables, and archives. */
		return (SHERR_ILSEQ);
	}

	/* context permitted */
	return (0);
}


/**
 * Set the context value.
 * @param name The name of the context (at least 3 characters).
 * @param value The contents of the context value (4096 max bytes).
 */
bool CContext::SetValue(string name, cbuff value)
{
	int err;

  if (name.size() < 3)
    return (false);

  if (value.size() == 0 || 
			value.size() > CContext::MAX_VALUE_SIZE) {
    return (false);
	}

	err = ctx_context_verify(value);
	if (err)
		return (false);

  hashIssuer = GetContextHash(name);

  /* set context value */
  vContext = value;

#if 0
  {
    char buf[256];
    uint64_t crc = shcrc(vContext.data(), vContext.size());
    sprintf(buf, "%s %-24.24s (%s)",
        hashIssuer.GetHex().c_str(), name.c_str(), shcrcstr(crc)); 
    string sLabel(buf);
    SetLabel(sLabel);
  }
#endif
  {
    char buf[256];
		memset(buf, 0, sizeof(buf));
		strncpy(buf, name.c_str(), MAX_SHARE_NAME_LENGTH-1);
    string sLabel(buf);
    SetLabel(sLabel);
  }

  return (true);
}

int64 CContext::CalculateFee(CIface *iface, int nHeight)
{
  return (GetContextOpFee(iface, nHeight, GetContentSize(), GetLifespan()));
}

time_t CContext::CalculateLifespan(CIface *iface, int64 nFee)
{
  nFee = MAX(nFee, MIN_TX_FEE(iface));
  nFee = MIN(nFee, MAX_TX_FEE(iface));

  int nHeight = GetBestHeight(iface);
  int64 nBaseFee = GetContextOpFee(iface, nHeight, GetContentSize(), 0);
  double fact = 1 / (double)nBaseFee * (double)nFee;

  time_t lifespan = (time_t)(GetMinimumLifespan() * fact);
  lifespan = MAX(lifespan, GetMinimumLifespan());
  lifespan = MIN(lifespan, GetMaximumLifespan());

  return (lifespan);
}

int CContext::VerifyTransaction()
{
	int err;

	err = CEntity::VerifyTransaction();
	if (err)
		return (err);

	/* ensure context payload is sane. */
	if (GetContentSize() > MAX_CONTEXT_CONTENT_LENGTH) {
		return (ERR_2BIG);
	}

	err = ctx_context_verify(vContext);
	if (err)
		return (error(err, "context verification failure"));

	if (!VerifySignature()) {
		return (error(SHERR_ACCESS, "VerifyTransaction: invalid context signature."));
	}

	return (0);
}

void CContext::ResetExpireTime(CIface *iface, int64 nFee)
{
	SetExpireSpan(CalculateLifespan(iface, nFee));
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

#if 0
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
  data_len = sizeof(shkey_t); 

  /* context size */
  val = htonl((uint32_t)vContext.size());
  memcpy(data + data_len, &val, sizeof(uint32_t));
  data_len += sizeof(uint32_t);

  /* context payload */
  memcpy(data + data_len, vContext.data(), vContext.size());
  data_len += vContext.size();

  shnet_inform(iface, TX_CONTEXT, data, data_len);

  free(data);


}
#endif

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
//fprintf(stderr, "DEBUG: %d = shgeodb_loc_set(%Lf,%Lf)\n", err, lat, lon);
  }

}

string create_shionid_id(string strEmail)
{
	string strId;

	uint256 hash;
	SHA256((unsigned char *)strEmail.c_str(), strEmail.size(), (unsigned char *)&hash); /* single SHA256 hash */
	strId = "id:" + EncodeBase64((unsigned char *)&hash, sizeof(hash));

	return (strId);
}

int IndexOfContextOutput(const CTransaction& tx)
{
  CScript script;
  int nTxOut;
  int mode;

  if (!GetExtOutput(tx, OP_CONTEXT, mode, nTxOut, script))
    return (-1);

  return (nTxOut);
}

int init_ctx_tx(CIface *iface, CWalletTx& wtx, string strAccount, string strName, cbuff vchValue, shgeo_t *loc, bool fTest)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	CContext *ctx;
	int err;

	if (strName.length() < 3) {
		error(SHERR_INVAL, "init_ctx_tx: name less than three characters.");
		return (SHERR_INVAL);
	}
	if (vchValue.size() == 0) {
		error(SHERR_INVAL, "init_ctx_tx: blank value");
		return (SHERR_INVAL);
	}
	if (vchValue.size() > CContext::MAX_VALUE_SIZE) {
		error(SHERR_INVAL, "init_ctx_tx: value exceeds maximum context size.");
		return (SHERR_INVAL);
	}

	err = ctx_context_verify(vchValue);
	if (err) {
		error(err, "init_ctx_tx: invalid context value.");
		return (err);
	}

	int64 nFee = GetContextOpFee(iface, GetBestHeight(iface), 
			vchValue.size(), CContext::MAX_CONTEXT_LIFESPAN);
	int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
	if (bal < nFee) {
		return (ERR_FEE);
	}

	if (IsContextName(iface, strName)) {
		error(SHERR_INVAL, "init_ctx_tx: duplicate context name.");
		return (SHERR_NOTUNIQ);
	}

	CTxCreator s_wtx(wallet, strAccount);

	/* embed ctx content into transaction */
	ctx = s_wtx.CreateContext();
	if (!ctx) {
		error(SHERR_INVAL, "init_ctx_tx: error initializing context transaction.");
		return (SHERR_INVAL);
	}

	if (loc) {
		memcpy(&ctx->geo, loc, sizeof(shgeo_t));
	}

#if 0
	if (fAddr) {
		CCoinAddr addr(ifaceIndex);
		if (wallet->GetMergedAddress(strAccount, "context", addr)) {
			ctx->vAddr = vchFromString(addr.ToString());
		}
	}
#endif

	if (!ctx->SetValue(strName, vchValue)) {
		error(SHERR_INVAL, "init_ctx_tx: error setting context value.");
		return (SHERR_INVAL);
	}

	ctx->ResetExpireTime(iface, nFee);

	if (!ctx->Sign(ifaceIndex)) {
		error(SHERR_INVAL, "init_ctx_tx: error signing context.");
		return (SHERR_INVAL);
	}

	uint160 hContext = ctx->GetHash();

	CScript destPubKey;
	CCoinAddr extAddr = wallet->GetExtAddr(strAccount);
	destPubKey.SetDestination(extAddr.Get());

	CScript scriptPubKey;
	scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_CONTEXT) << OP_HASH160 << hContext << OP_2DROP;
	scriptPubKey += destPubKey;
	if (!s_wtx.AddOutput(scriptPubKey, nFee, true))
		return (SHERR_INVAL);

	if (!fTest) {
		/* commit transaction. */
		if (!s_wtx.Send())
			return (SHERR_CANCELED);

		Debug("SENT:CONTEXTNEW : title=%s, ctxhash=%s, tx=%s\n", ctx->GetLabel().c_str(), hContext.GetHex().c_str(), s_wtx.GetHash().GetHex().c_str());

		if (GetCoinIndex(iface) == SHC_COIN_IFACE) {
			share_geo_save(ctx, strName);
		}
	} else {
		if (!s_wtx.Generate())
			return (SHERR_CANCELED);
	}
	wtx = (CWalletTx)s_wtx;

	return (0);
}

int update_ctx_tx(CIface *iface, CWalletTx& wtx, string strAccount, string strName, cbuff vchValue, shgeo_t *loc, bool fTest)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strExtAccount = CWallet::EXT_ACCOUNT_PREFIX + strAccount;
  CContext *ctx;
	int err;

  if (strName.length() < 3) {
    return (SHERR_INVAL);
  }
  if (vchValue.size() == 0) {
    return (SHERR_INVAL);
  }
  if (vchValue.size() > CContext::MAX_VALUE_SIZE) {
    return (SHERR_INVAL);
  }

	err = ctx_context_verify(vchValue);
	if (err)
		return (err);

  CTransaction txIn;
  CContext *ctxIn = GetContextByName(iface, strName, txIn);
  if (!ctxIn)
    return (SHERR_NOENT);

  const uint256& wtxInHash = txIn.GetHash();

  int nOut = IndexOfExtOutput(txIn);
  if (nOut == -1)
    return (SHERR_INVAL);

	int64 nValue = GetContextOpFee(iface, GetBestHeight(iface),
			vchValue.size(), CContext::MAX_CONTEXT_LIFESPAN);
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nValue)
    return (ERR_FEE);

  if (!wallet->HasTx(wtxInHash))
    return (SHERR_REMOTE);
  CWalletTx& wtxIn = wallet->GetTx(wtxInHash); // wallet->mapWallet[wtxInHash];

  /* embed ctx content into transaction */
	CTxCreator s_wtx(wallet, strAccount);
  ctx = s_wtx.CreateContext();
  if (!ctx) {
    error(SHERR_INVAL, "update_ctx_tx: error initializing context transaction.");
    return (SHERR_INVAL);
  }

  if (loc) {
    memcpy(&ctx->geo, loc, sizeof(shgeo_t));
  }

#if 0
  if (fAddr) {
    CCoinAddr addr(ifaceIndex);
    if (wallet->GetMergedAddress(strAccount, "context", addr)) {
      ctx->vAddr = vchFromString(addr.ToString());
    }
  }
#endif

  if (!ctx->SetValue(strName, vchValue)) {
    error(SHERR_INVAL, "update_ctx_tx: error setting context value.");
    return (SHERR_INVAL);
  }

	ctx->ResetExpireTime(iface, nValue); 

  if (!ctx->Sign(ifaceIndex)) {
    error(SHERR_INVAL, "update_ctx_tx: error signing context.");
    return (SHERR_INVAL);
  }

  uint160 hContext = ctx->GetHash();

	CCoinAddr extAddr = wallet->GetExtAddr(strAccount);
  CScript destPubKey;
  destPubKey.SetDestination(extAddr.Get());

  CScript scriptPubKey;
  scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_CONTEXT) << OP_HASH160 << hContext << OP_2DROP;
  scriptPubKey += destPubKey;
	if (!s_wtx.AddExtTx(&wtxIn, scriptPubKey, 0, nValue))
    return (SHERR_INVAL);

	if (!fTest) {
		/* commit transaction. */
		if (!s_wtx.Send())
			return (SHERR_CANCELED);

		Debug("SENT:CONTEXTUPDATE : title=%s, ctxhash=%s, tx=%s\n", ctx->GetLabel().c_str(), hContext.GetHex().c_str(), s_wtx.GetHash().GetHex().c_str());

		if (GetCoinIndex(iface) == SHC_COIN_IFACE)
			share_geo_save(ctx, strName);
	} else {
		if (!s_wtx.Generate())
			return (SHERR_CANCELED);
	}
	wtx = (CWalletTx)s_wtx;

  return (0);
}

int create_shionid_tx(CIface *iface, CWalletTx& wtx, string strAccount, map<string,string> mapParam, bool fTest)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	shjson_t *node;
	string strGeo;
	string strId;
	int err;

	if (mapParam.count("id") == 0)
		return (ERR_INVAL);

	strId = create_shionid_id(mapParam["id"]);

	node = shjson_init(NULL);
	if (!node)
		return (ERR_NOMEM);

	if (mapParam.count("password") != 0) {
		string strPassphrase = mapParam["password"];

		/* PBKDF2_SHA256 */
		unsigned char cr_salt[64];
		unsigned char cr_pass[64];

		memset(cr_salt, 0, sizeof(cr_salt));
		memset(cr_pass, 0, sizeof(cr_pass));

		for (int i = 0; i < 24; i++)
			cr_salt[i] = rand() % 256;

		string salt = EncodeBase64(cr_salt, 24);
		PBKDF2_SHA256((const unsigned char *)strPassphrase.c_str(), strPassphrase.size(),
				(const unsigned char *)salt.c_str(), salt.size(),
				1000, cr_pass, 24);

		char *param_label = "crypted_password";
		string val = "sha256:1000:" + salt + ":" + EncodeBase64(cr_pass, 24);
		shjson_str_add(node, param_label, (char *)val.c_str());
	}

	strGeo = "";
	if (mapParam.count("geo") != 0)
		strGeo = mapParam["geo"];
	shgeo_t *geo = NULL;
	shnum_t lat = 0;
	shnum_t lon = 0;
	{
		shgeo_t loc;
		memset(&loc, 0, sizeof(loc));

		if (strGeo.size() != 0) {
			if (strGeo.size() == 5 && is_numeric(strGeo)) {
				/* zip-code */
				mapParam["zipcode"] = strGeo;

				err = shgeodb_place(strGeo.c_str(), &loc);
				if (err) {
					/* unknown .. keep zipcode but bail on lat/lon assoc. */
					strGeo = string();
				} else {
					char buf[256];
					shgeo_loc(&loc, &lat, &lon, NULL);
					sprintf(buf, "geo:%-5.5Lf,%-5.5Lf", lat, lon);
					strGeo = string(buf);
				}
			}
		}
		if (strGeo.size() != 0) {
			if (!FormatGeoContext(iface, strGeo, lat, lon)) {
				strGeo = "";
			} else {
				/* set context geo-location */
				shgeo_set(&loc, lat, lon, 0);
				geo = &loc;
			}
		}
	}
	if (geo) {
		char buf[256];
		sprintf(buf, "%-5.5Lf,%-5.5Lf", lat, lon);
		mapParam["geo"] = string(buf);
	} else {
		if (mapParam.size() != 0 || strGeo.size() != 0)
			mapParam["geo"] = strGeo;
	}

	if (ifaceIndex == SHC_COIN_IFACE || 
			ifaceIndex == TESTNET_COIN_IFACE) {
		/* tag on a shioncoin address for receiving funds. */
		CCoinAddr addr = wallet->GetRecvAddr(strAccount);
		mapParam["shioncoin"] = addr.ToString();
	}

	map<string,string>::const_iterator it = mapParam.begin();
	for (; (it != mapParam.end()); it++) {
		const string& name = it->first;
		const string& value = it->second;

		if (name == "id" ||
				name == "password")
			continue; /* skip context name */

		if (name.size() < 5 || name.size() > 32 || value.size() > 135)
			continue; /* soft error "invalid parameter name length" */

		shjson_str_add(node, (char *)name.c_str(), (char *)value.c_str());
	}

	string strValue = shjson_print(node);
	cbuff vchValue(strValue.begin(), strValue.end());
	shjson_free(&node);

	if (!IsContextName(iface, strId)) { 
		err = init_ctx_tx(iface, wtx, strAccount, 
				strId, vchValue, geo, fTest);
	} else {
		err = update_ctx_tx(iface, wtx, strAccount, 
				strId, vchValue, geo, fTest);
	}
	if (err)
		return (err);

	return (0);
}

