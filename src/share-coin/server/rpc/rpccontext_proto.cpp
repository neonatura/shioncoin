
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

#undef GNULIB_NAMESPACE
#include "shcoind.h"
#include "init.h"
#include "ui_interface.h"
#include "base58.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "context.h"
#include "spring.h"
#include "rpc_proto.h"

using namespace std;
using namespace boost;
using namespace json_spirit;


extern json_spirit::Value ValueFromAmount(int64 amount);

extern string AccountFromValue(const Value& value);

bool FormatGeoContext(CIface *iface, string& strGeo, shnum_t& lat, shnum_t& lon);


static bool is_numeric(const std::string& s)
{
    return( strspn( s.c_str(), "0123456789" ) == s.size() );
}


Value rpc_ctx_fee(CIface *iface, const Array& params, bool fStratum)
{
  int nBestHeight = GetBestHeight(iface); 
  int nSize;

  nSize = 4096;
  if (params.size() != 0)
    nSize = params[0].get_int(); 

  return ValueFromAmount(GetContextOpFee(iface, nBestHeight, nSize));
}

Value rpc_ctx_info(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *wallet = GetWallet(iface);
  int nBestHeight = GetBestHeight(iface); 

  Object ret_obj;
  ret_obj.push_back(Pair("fee", ValueFromAmount(GetContextOpFee(iface, nBestHeight))));
  ret_obj.push_back(Pair("total", (int)wallet->mapContext.size()));

  return (ret_obj);
}

static void GetAccountAddresses(CWallet *wallet, string strAccount, set<CTxDestination>& setAddress)
{
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CTxDestination& address = item.first;
    const string& strName = item.second;
    if (strName == strAccount)
      setAddress.insert(address);
  }
}
Value rpc_ctx_list(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *wallet = GetWallet(iface);
  Array ret;
  string strAllAccount = "*";
  string strAccount;

  set<CTxDestination> setAddress;
  if (params.size() == 0) {
    if (fStratum)
      throw JSONRPCError(-5, string("account name required"));

    strAccount = "*";
  } else {
    strAccount = AccountFromValue(params[0]);

    /* get set of pub keys assigned to extended account. */
    string strExtAccount = "@" + strAccount;
    GetAccountAddresses(wallet, strExtAccount, setAddress);
    if (setAddress.size() == 0) {
      return (ret);
    }
  }

  BOOST_FOREACH(const PAIRTYPE(uint160, uint256)& r, wallet->mapContext) {
    const uint160& hContext = r.first;
    const uint256& hTx = r.second;
    CTransaction tx;

    if (!GetTransaction(iface, hTx, tx, NULL))
      continue;

    if (setAddress.size() != 0) {
      /* filter by account name. */
      int nOut = IndexOfExtOutput(tx);
      if (nOut == -1)
        continue;
      
      CTxDestination dest;
      const CTxOut& txout = tx.vout[nOut];
      if (!ExtractDestination(txout.scriptPubKey, dest))
        continue;

      if (setAddress.count(dest) == 0)
        continue;
    }

    ret.push_back(hContext.GetHex());
  }
 
  return (ret);
}

Value rpc_ctx_get(CIface *iface, const Array& params, bool fStratum)
{
  CContext *ctx;
  CTransaction tx;

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  uint160 hContext(params[0].get_str());
  ctx = GetContextByHash(iface, hContext, tx);
  if (!ctx) {
    throw JSONRPCError(-5, string("unknown context hash"));
  }

  Object obj = ctx->ToValue();
  obj.push_back(Pair("tx", tx.GetHash().GetHex()));

  return (obj);
}

Value rpc_ctx_setstr(CIface *iface, const Array& params, bool fStratum)
{
  CContext *ctx;
  CTransaction tx;
  CWalletTx wtx;
  int err;

  if (params.size() != 3)
    throw runtime_error("invalid parameters");

  string strAccount = params[0].get_str();
  string strName = params[1].get_str();
  string strValue = params[2].get_str();
  cbuff vchValue(strValue.begin(), strValue.end());

  err = init_ctx_tx(iface, wtx, strAccount, strName, vchValue);
  if (err)
    throw JSONRPCError(err, string(sherrstr(err)));

  ctx = (CContext *)&wtx.certificate;
  Object obj = ctx->ToValue();
  obj.push_back(Pair("tx", wtx.GetHash().GetHex()));

  return (obj);
}

Value rpc_ctx_setbin(CIface *iface, const Array& params, bool fStratum)
{
  CContext *ctx;
  CTransaction tx;
  CWalletTx wtx;
  int err;

  if (params.size() != 3)
    throw runtime_error("invalid parameters");

  string strAccount = params[0].get_str();
  string strName = params[1].get_str();
  string strHex = params[2].get_str();

  cbuff vchValue = ParseHex(strHex);
  if (vchValue.size() == 0)
    throw JSONRPCError(-5, string("invalid hexadecimal format"));

  err = init_ctx_tx(iface, wtx, strAccount, strName, vchValue);
  if (err)
    throw JSONRPCError(err, string(sherrstr(err)));

  ctx = (CContext *)&wtx.certificate;
  Object obj = ctx->ToValue();
  obj.push_back(Pair("tx", wtx.GetHash().GetHex()));

  return (obj);
}

Value rpc_ctx_setfile(CIface *iface, const Array& params, bool fStratum)
{
  CContext *ctx;
  CTransaction tx;
  CWalletTx wtx;
  int err;

  if (params.size() != 3)
    throw runtime_error("invalid parameters");

  string strAccount = params[0].get_str();
  string strName = params[1].get_str();
  string strPath = params[2].get_str();

  /* load 'er up */
  shbuf_t *buff = shbuf_init();
  err = shfs_mem_read((char *)strPath.c_str(), buff);
  if (err) {
    shbuf_free(&buff);
    throw JSONRPCError(err, string("invalid path specification"));
  }
  if (shbuf_size(buff) == 0) {
    shbuf_free(&buff);
    throw JSONRPCError(err, string("empty file"));
  }
  if (shbuf_size(buff) > 4096) {
    shbuf_free(&buff);
    throw JSONRPCError(err, string("file exceeds 4096 byte limitation"));
  }

  /* and ship 'er through.. */
  const char *raw = (const char *)shbuf_data(buff);
  unsigned int raw_len = shbuf_size(buff);
  cbuff vchValue(raw, raw + raw_len);
  err = init_ctx_tx(iface, wtx, strAccount, strName, vchValue);
  shbuf_free(&buff);
  if (err)
    throw JSONRPCError(err, string(sherrstr(err)));

  /* report back to boss */
  ctx = (CContext *)&wtx.certificate;
  Object obj = ctx->ToValue();
  obj.push_back(Pair("tx", wtx.GetHash().GetHex()));

  return (obj);
}

Value rpc_ctx_getstr(CIface *iface, const Array& params, bool fStratum)
{
  CContext *ctx;
  CTransaction tx;

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  ctx = GetContextByName(iface, params[0].get_str(), tx);
  if (!ctx) {
    throw JSONRPCError(-5, string("unknown context hash"));
  }

  return (stringFromVch(ctx->vContext));
}

Value rpc_ctx_getbin(CIface *iface, const Array& params, bool fStratum)
{
  CContext *ctx;
  CTransaction tx;

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  ctx = GetContextByName(iface, params[0].get_str(), tx);
  if (!ctx) {
    throw JSONRPCError(-5, string("unknown context hash"));
  }

  return (HexStr(ctx->vContext));
}

Value rpc_ctx_getfile(CIface *iface, const Array& params, bool fStratum)
{
  CContext *ctx;
  CTransaction tx;
  int err;

  if (params.size() != 2)
    throw runtime_error("invalid parameters");

  string strName = params[0].get_str();
  string strPath = params[1].get_str();

  ctx = GetContextByName(iface, strName, tx);
  if (!ctx) {
    throw JSONRPCError(-5, string("unknown context hash"));
  }

  shbuf_t *buff = shbuf_init();
  shbuf_cat(buff, ctx->vContext.data(), ctx->vContext.size());
  err = shfs_mem_write((char *)strPath.c_str(), buff);
  shbuf_free(&buff);
  if (err) 
    throw JSONRPCError(err, string("invalid path specification"));

  Object obj;
  obj.push_back(Pair("path", strPath));
  obj.push_back(Pair("size", (int)ctx->vContext.size()));

  return (obj);
}

Value rpc_ctx_getid(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *wallet = GetWallet(iface);
  CContext *ctx;
  string strId;

  if (params.size() != 1)
    throw runtime_error("invalid parmeters");

  CTransaction tx;
  strId = "id:" + params[0].get_str();
  ctx = GetContextByName(iface, strId, tx);
  if (!ctx)
    throw JSONRPCError(-5, string("unknown id"));

  Value val;
  if (!read_string(stringFromVch(ctx->vContext), val))
    throw JSONRPCError(-5, string("invalid json format"));

  return (val);
}

Value rpc_ctx_setid(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strAccount = AccountFromValue(params[0]);
  string strName;
  string strEmail;
  string strCountry;
  string strZip;
  string strUrl;
  string strGeo;
  string strId;
  char buf[256];
  int err;

  if (params.size() < 3)
    throw runtime_error("invalid parameters");

  string strLiteralId = params[1].get_str();
  strId = "id:" + strLiteralId;

  if (params.size() > 2) {
    strName = params[2].get_str();
    if (strName.size() > 135)
      throw JSONRPCError(-5, string("real name exceeds 135 character maximum"));
  }
  if (params.size() > 3) {
    strEmail = params[3].get_str();
    if (strEmail.size() > 135)
      throw JSONRPCError(-5, string("email exceeds 135 character maximum"));
  }
  if (params.size() > 4)
    strCountry = params[4].get_str();
  if (params.size() > 5)
    strGeo = params[5].get_str();
  if (params.size() > 6) {
    strUrl = params[6].get_str();
    if (strUrl.size() > 135)
      throw JSONRPCError(-5, string("url exceeds 135 character maximum"));
  }

  if (strCountry.size() > 5)
    throw JSONRPCError(-5, string("invalid country code"));

  shgeo_t *geo = NULL;
  shgeo_t loc;
  memset(&loc, 0, sizeof(loc));

  shnum_t lat = 0;
  shnum_t lon = 0;
  if (strGeo.size() != 0) {
    if (strGeo.size() == 5 && is_numeric(strGeo)) {
      /* zip-code */
      strZip = strGeo;

      err = shgeodb_place(strGeo.c_str(), &loc);
      if (err) {
        /* unknown .. keep zipcode but bail on lat/lon assoc. */
        strGeo = string();
      } else {
        shgeo_loc(&loc, &lat, &lon, NULL);
        sprintf(buf, "geo:%-5.5Lf,%-5.5Lf", lat, lon);
        strGeo = string(buf);
      }
    }
  }
  if (strGeo.size() != 0) {
    if (!FormatGeoContext(iface, strGeo, lat, lon))
      throw JSONRPCError(-5, string("invalid location"));

    /* set context geo-location */
    shgeo_set(&loc, lat, lon, 0);
    geo = &loc;
  }

  CCoinAddr addr(ifaceIndex);
  if (!wallet->GetMergedAddress(strAccount, "context", addr))
    throw JSONRPCError(-5, string("invalid account name"));

#if 0
  if (strName.length() == 0) {
    const char *def_name = shpref_get(SHPREF_USER_NAME, "");
    strName = string(def_name);
  }
  if (strEmail.length() == 0) {
    const char *def_email = shpref_get(SHPREF_USER_EMAIL, "");
    strEmail = string(def_email);
  }
#endif

  if (strLiteralId.size() > 135)
    strLiteralId.resize(135);

  Object obj;
  obj.push_back(Pair("id", strLiteralId));
  obj.push_back(Pair("name", strName));
  obj.push_back(Pair("email", strEmail));
  obj.push_back(Pair("country", strCountry));
  if (strUrl.size() != 0)
    obj.push_back(Pair("weblog", strUrl));
  if (strZip.size() != 0)
    obj.push_back(Pair("zipcode", strZip));
  obj.push_back(Pair("sharecoin", addr.ToString()));

  if (geo) {
    sprintf(buf, "%-5.5Lf,%-5.5Lf", lat, lon);
    obj.push_back(Pair("geo", string(buf)));
  }

  string jsonValue = write_string(Value(obj), false);
  cbuff vchValue = vchFromString(jsonValue);
  if (vchValue.size() > 4096)
    throw JSONRPCError(-5, string("context too large"));

  CWalletTx wtx;
  err = init_ctx_tx(iface, wtx, strAccount, strId, vchValue, geo, true);
  if (err)
    throw JSONRPCError(err, string(sherrstr(err)));

  CContext *ctx = (CContext *)&wtx.certificate;
  Object ret_obj = ctx->ToValue();
  ret_obj.push_back(Pair("txhash", wtx.GetHash().GetHex()));
  ret_obj.push_back(Pair("id", obj));

  return (ret_obj);
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

Value rpc_ctx_getloc(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *wallet = GetWallet(iface);
  CTransaction tx;
  CContext *ctx;
  shnum_t lat, lon;
  char buf[256];

  if (params.size() != 1)
    throw runtime_error("invalid parmeters");

  string strName;
  string strId = params[0].get_str();
  if (strId.substr(0, 4) != "geo:") {
    strName = strId; 
    strId = "loc:" + strId;
    ctx = GetContextByName(iface, strId, tx);
    if (!ctx)
      throw JSONRPCError(-5, string("unknown location"));
      
    strId = stringFromVch(ctx->vContext); /* geo:XX,XX */
  }

  if (!FormatGeoContext(iface, strId, lat, lon))
    throw JSONRPCError(-5, string("unknown location"));

  /* geo:XX,XX -> JSON */
  ctx = GetContextByName(iface, strId, tx);
  if (!ctx)
    throw JSONRPCError(-5, string("unknown geodetic location"));

  Value val;
  if (!read_string(stringFromVch(ctx->vContext), val))
    throw JSONRPCError(-5, string("invalid json format"));

  Object ret_obj = val.get_obj();
  if (strName.size() != 0)
    ret_obj.push_back(Pair("name", strName));
  ret_obj.push_back(Pair("txhash", tx.GetHash().GetHex()));
  ret_obj.push_back(Pair("ctxhash", ctx->GetHash().GetHex()));

  string strPlaceType = GetObjectValue(ret_obj, "code"); 
  if (strPlaceType.length() != 0) {
    ret_obj.push_back(Pair("type", 
          string(shgeo_place_desc((char *)strPlaceType.c_str()))));
  }

  if (is_spring_loc(lat, lon)) {
    ret_obj.push_back(Pair("springable", "true"));
  } else {
    ret_obj.push_back(Pair("springable", "false"));
  }

  return (ret_obj);
}


Value rpc_ctx_setloc(CIface *iface, const Array& params, bool fStratum)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strName;
  string strEmail;
  string strCountry;
  string strUrl;
  string strValue;
  Object loc_obj; 
  shnum_t lat, lon;
  shgeo_t geo;
  shgeo_t loc;
  char buf[256];
  int err;

  if (params.size() < 3)
    throw runtime_error("invalid parameters");

  string strAccount = params[0].get_str();
  string strId = params[1].get_str();

  if (strId.substr(0, 4) != "geo:") { /* loc:XX */
    string strZip;

    if (shgeodb_place(strId.c_str(), &geo) == 0) {
      /* reserved name */
      throw JSONRPCError(SHERR_EXIST, string("duplicate location name"));
    }

    CTransaction t_tx;
    string strLoc = "loc:" + strId;
    if (GetContextByName(iface, strLoc, t_tx)) {
      /* already registered name */
      throw JSONRPCError(SHERR_EXIST, string("duplicate location name"));
    }

    strValue = params[2].get_str();
    if (strValue.size() == 5 && is_numeric(strValue)) {
      strZip = strValue;

      /* zip code */
      memset(&geo, 0, sizeof(geo));
      err = shgeodb_place(strValue.c_str(), &geo);
      if (err)
        throw JSONRPCError(err, string("unknown zip-code"));

      shgeo_loc(&geo, &lat, &lon, NULL);
      sprintf(buf, "geo:%-5.5Lf,%-5.5Lf", lat, lon);
      strValue = string(buf);
    }
    if (!FormatGeoContext(iface, strValue, lat, lon))
      throw JSONRPCError(-5, string("invalid geodetic format [context value]"));

    strId = strLoc;
    loc_obj.push_back(Pair("name", strId));
    loc_obj.push_back(Pair("latitude", (double)lat));
    loc_obj.push_back(Pair("longitude", (double)lon));
    if (strZip.size() != 0)
      loc_obj.push_back(Pair("zipcode", strZip));
  } else {
#if 0
    if (strId.size() == 5 && is_numeric(strId)) {
      /* zip code */
      memset(&geo, 0, sizeof(geo));
      err = shgeodb_place(strId.c_str(), &geo);
      if (err)
        throw JSONRPCError(err, string("unknown zip-code"));

      shgeo_loc(&geo, lat, lon);
      sprintf(buf, "geo:%-5.5Lf,%-5.5Lf", lat, lon);
      strId = string(buf);
    }
#endif
    if (!FormatGeoContext(iface, strId, lat, lon))
      throw JSONRPCError(-5, string("invalid geodetic format [context name]"));

    if (params.size() > 2) {
      string strSummary = params[2].get_str();
//      if (strSummary.size() > 135) throw JSONRPCError(-5, string("summary exceeds maximum length (135 characters)"));
      loc_obj.push_back(Pair("summary", strSummary));
    }

    /* define regional boundary */
    string strPlaceType = "AREA";
    if (params.size() > 3)
      strPlaceType = params[3].get_str();
    loc_obj.push_back(Pair("code", strPlaceType));
#if 0
    /* reduce precision to match location type */
    memset(&geo, 0, sizeof(geo));
    shgeo_set(&geo, lat, lon, 0);
    shgeo_dim(&geo, shgeo_place_prec((char *)strPlaceType.c_str()));
    shgeo_loc(&geo, &lat, &lon, NULL);
#endif

    if (params.size() > 4) {
      string strLocale = params[4].get_str();
      if (strLocale.size() > 5)
        throw JSONRPCError(-5, string("locale exceeds maximum length (5 characters)"));
      loc_obj.push_back(Pair("country", strLocale));
    }
    if (params.size() > 5) {
      string strUrl = params[5].get_str();
      if (strUrl.size() > 135)
        throw JSONRPCError(-5, string("url exceeds maximum length (135 characters)"));
      loc_obj.push_back(Pair("weblog", strUrl));
    }

    /* redundant */
    sprintf(buf, "%-5.5Lf,%-5.5Lf", lat, lon);
    string ret_geo(buf);
    loc_obj.push_back(Pair("geo", ret_geo));

    strValue = write_string(Value(loc_obj), false);
  }

  if (strValue.size() == 0)
    throw JSONRPCError(-5, string("empty context value"));
  if (strValue.size() > 4096)
    throw JSONRPCError(-5, string("context too large"));

  CWalletTx wtx;
  memset(&loc, 0, sizeof(loc));
  shgeo_set(&loc, lat, lon, 0);
  cbuff vchValue = vchFromString(strValue);
  err = init_ctx_tx(iface, wtx, strAccount, strId, vchValue, &loc);
  if (err)
    throw JSONRPCError(err, string(sherrstr(err)));

  CContext *ctx = (CContext *)&wtx.certificate;
  Object ret_obj = ctx->ToValue();
  ret_obj.push_back(Pair("tx", wtx.GetHash().GetHex()));
  ret_obj.push_back(Pair("geo", loc_obj));

  return (ret_obj);
}

static Object ConvertLocationToObject(shgeo_t *geo, shloc_t *loc)
{
  Object ret_obj;
  shnum_t lat, lon;
  char buf[256];
  char *ptr;

  ret_obj.push_back(Pair("name", string(loc->loc_name)));
  ret_obj.push_back(Pair("summary", string(loc->loc_summary)));
  ret_obj.push_back(Pair("zone", string(loc->loc_zone)));

  if (*loc->loc_type) {
    ret_obj.push_back(Pair("code", string(loc->loc_type)));
//    ret_obj.push_back(Pair("type", string(shgeo_place_desc(loc->loc_type))));
  }

  ptr = strchr(loc->loc_locale, '_');
  if (ptr && strlen(loc->loc_locale) > 4)
    ret_obj.push_back(Pair("country", string(loc->loc_locale).substr(3, 2)));
  else
    ret_obj.push_back(Pair("country", string("US"))); /* default */

  shgeo_loc(geo, &lat, &lon, NULL);
  sprintf(buf, "%-5.5Lf,%-5.5Lf", lat, lon);
  string ret_geo(buf);
  ret_obj.push_back(Pair("geo", ret_geo));

  return (ret_obj);
}

Value rpc_ctx_findloc(CIface *iface, const Array& params, bool fStratum)
{
  Object ret_obj;
  CContext *ctx;
  shnum_t lat, lon;
  shgeo_t geo;
  shloc_t loc;
  int err;

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  string strId = params[0].get_str();

  bool fScan = true;
  if (strId.substr(0, 4) != "geo:") { /* find geodetic cordinates */
    /* search block-chain by name. */
    CTransaction tx;
    string idstr = "loc:" + strId;
    ctx = GetContextByName(iface, idstr, tx);
    if (ctx) {
      strId = stringFromVch(ctx->vContext); /* geo:XX,XX */
    } else {
      /* search libshare by name. */
      err = shgeodb_place(strId.c_str(), &geo);
      if (err)
        throw JSONRPCError(err, string("unknown location"));

      { /* jic */
        static char buf[256];

        shgeo_loc(&geo, &lat, &lon, NULL);
        sprintf(buf, "%-5.5Lf,%-5.5Lf", lat, lon);
        strId = string(buf);
      }
    }
    fScan = false;
  }

  if (!FormatGeoContext(iface, strId, lat, lon))
    throw JSONRPCError(err, string("invalid geodetic format"));

  CTransaction tx;
  ctx = GetContextByName(iface, strId, tx);
  if (ctx) { /* SHC */
    Value val;
    if (read_string(stringFromVch(ctx->vContext), val)) {
      ret_obj = val.get_obj();
      shgeo_loc(&ctx->geo, &lat, &lon, NULL);
    }
  } else { /* libshare */
    if (fScan) {
      /* scan area */
      err = shgeodb_scan(lat, lon, 0.5, &geo);
      if (err)
        throw JSONRPCError(err, string("unknown location"));
    } else {
      shgeo_set(&geo, lat, lon, 0);
    }

    /* welp, we found a reference to a spot at least */
    err = shgeodb_loc(&geo, &loc);
    if (!err) {
      ret_obj = ConvertLocationToObject(&geo, &loc);
    }
  }

#if 0
  if (strId.substr(0, 4) == "geo:") {
    bool bFound = false;

    /* search via scan for lat/lon */
    if (!FormatGeoContext(iface, strId, lat, lon))
      throw JSONRPCError(err, string("invalid geodetic format"));

    /* check block-chain */
    string strGeo;
    CTransaction tx;
    ctx = GetContextByName(iface, strId, tx);
    if (ctx) {
      strGeo = stringFromVch(ctx->vContext);
      ctx = GetContextByName(iface, strGeo, tx);
      if (ctx) {
        Value val;
        if (read_string(stringFromVch(ctx->vContext), val)) {
          ret_obj = val.get_obj();
          shgeo_loc(&ctx->geo, &lat, &lon, NULL);
          bFound = true;
        }
      }
    } 

    /* check libshare */
    if (!bFound) {
      err = shgeodb_scan(lat, lon, 0.5, &geo);
      if (err)
        throw JSONRPCError(err, string("unknown location"));

      err = shgeodb_loc(&geo, &loc);
      if (err)
        throw JSONRPCError(err, string("unknown location"));

      ret_obj = ConvertLocationToObject(&geo, &loc);
      shgeo_loc(&geo, &lat, &lon, NULL);
    }
  } else {
    /* search block-chain by name. */
    string idstr = "loc:" + strId;
    CTransaction tx;
    bool bFound = false;

    ctx = GetContextByName(iface, idstr, tx);
    if (ctx) {
      Value val;
      if (read_string(stringFromVch(ctx->vContext), val)) {
        ret_obj = val.get_obj();
        shgeo_loc(&ctx->geo, &lat, &lon, NULL);
        bFound = true;
      }
    }

    if (!bFound) {
      /* search libshare by name. */
      err = shgeodb_place(strId.c_str(), &geo);
      if (err)
        throw JSONRPCError(err, string("unknown location"));

      err = shgeodb_loc(&geo, &loc);
      if (err)
        throw JSONRPCError(err, string("unknown location"));

      ret_obj = ConvertLocationToObject(&geo, &loc);
      shgeo_loc(&geo, &lat, &lon, NULL);
    }
  }
#endif

  string strGeo = GetObjectValue(ret_obj, "geo");
  if (strGeo.length() == 0) {
    char buf[256];

    sprintf(buf, "%-5.5Lf,%-5.5Lf", lat, lon);
    string ret_geo(buf);
    ret_obj.push_back(Pair("geo", ret_geo));
  }

  string strPlaceType = GetObjectValue(ret_obj, "code"); 
  if (strPlaceType.length() != 0) {
    ret_obj.push_back(Pair("type", 
          string(shgeo_place_desc((char *)strPlaceType.c_str()))));
  }

  if (is_spring_loc(lat, lon)) {
    ret_obj.push_back(Pair("springable", "true"));
  } else {
    ret_obj.push_back(Pair("springable", "false"));
  }

  return (ret_obj);
}

Value rpc_ctx_loctypes(CIface *iface, const Array& params, bool fStratum)
{
  const char **place_codes = shgeo_place_codes();
  int err;
  int i;

  if (params.size() != 0)
    throw runtime_error("invalid parameters");

  Array ret_ar;
  for (i = 0; place_codes[i]; i++) {
    char *code = (char *)place_codes[i];

    Object obj;
    obj.push_back(Pair("name", string(place_codes[i])));
    obj.push_back(Pair("desc", string(shgeo_place_desc(code))));
    obj.push_back(Pair("prec", shgeo_place_prec(code)));

    ret_ar.push_back(obj);
  }

  return (ret_ar);
}

