
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

#undef GNULIB_NAMESPACE
#include "shcoind.h"

#include "init.h"
#include "ui_interface.h"
#include "base58.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "rpc_proto.h"
#include "txmempool.h"
#include "wallet.h"
#include "color/color_pool.h"
#include "color/color_block.h"

using namespace std;
using namespace boost;
using namespace json_spirit;

extern int64 AmountFromValue(const Value& value);
extern string AccountFromValue(const Value& value);


static uint160 rpc_alt_key_from_value(CIface *iface, Value val)
{
	string text = val.get_str();
	string strDesc;
	uint160 hColor;

	hColor = 0;
	if (text.size() == 40) {
		hColor = uint160(text);
	}
	if (hColor == 0) {
		hColor = GetAltColorHash(iface, text, strDesc);
	}

	return (hColor);
}

static uint160 rpc_offer_key_from_value(CIface *iface, Value val)
{
	string text = val.get_str();
	return (uint160(text));
}



Value rpc_offer_new(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	string strAccount;
	uint160 hColor;
	int64 nMinValue;
	int64 nMaxValue;
	double dRate;
	int err;

  if (params.size() < 5)
    throw runtime_error("rpc_offer_new");

	strAccount = AccountFromValue(params[0]);
	hColor = rpc_alt_key_from_value(iface, params[1]);
	nMinValue = AmountFromValue(params[2]);
	nMaxValue = AmountFromValue(params[3]);
	dRate = params[4].get_real();

	CWalletTx wtx(wallet);
	err = init_offer_tx(iface, strAccount, COLOR_COIN_IFACE,
			nMinValue, nMaxValue, dRate, wtx, hColor); 
	if (err)
    throw JSONRPCError(err, "init_offer_tx");

	COffer *offer = wtx.GetOffer();
	if (!offer) return (Value::null);
	Object obj = offer->ToValue();
	obj.push_back(Pair("txhash", wtx.GetHash().GetHex()));
	return (obj);
}


Value rpc_offer_accept(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	string strAccount;
	uint160 hOffer;
	int64 nValue;
	int err;

  if (params.size() != 3)
    throw runtime_error("rpc_offer_accept");

	strAccount = AccountFromValue(params[0]);
	hOffer = rpc_offer_key_from_value(iface, params[1]);
	nValue = AmountFromValue(params[2]);

	CTransaction tx;
	if (!GetTxOfOffer(iface, hOffer, tx))
    throw JSONRPCError(ERR_NOENT, "invalid offer hash");
	COffer *offer = tx.GetOffer();
	if (!offer)
    throw JSONRPCError(ERR_NOENT, "invalid offer hash");

	CWalletTx wtx(wallet);
	err = accept_offer_tx(iface, strAccount, hOffer, nValue, wtx);
	if (err)
    throw JSONRPCError(err, "accept_offer_tx");

	COffer *acc = wtx.GetOffer();
	if (!acc) return (Value::null);
	Object obj = acc->ToValue();
	obj.push_back(Pair("txhash", wtx.GetHash().GetHex()));
	obj.push_back(Pair("offerhash", offer->GetHash().GetHex()));
	return (obj);

	return (Value::null);
}

Value rpc_offer_commit(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	string strAccount;
	uint160 hOffer;
	int err;

  if (params.size() != 2)
    throw runtime_error("rpc_offer_commit");

	strAccount = AccountFromValue(params[0]);
	hOffer = rpc_offer_key_from_value(iface, params[1]);

	CTransaction tx;
	if (!GetTxOfOffer(iface, hOffer, tx))
    throw JSONRPCError(ERR_NOENT, "invalid offer hash");
	COffer *offer = tx.GetOffer();
	if (!offer)
    throw JSONRPCError(ERR_NOENT, "invalid offer hash");

	CWalletTx wtx(wallet);
	err = generate_offer_tx(iface, strAccount, hOffer, wtx);
	if (err)
    throw JSONRPCError(err, "generate_offer_tx");

	COffer *gen = wtx.GetOffer();
	if (!gen) return (Value::null);
	Object obj = gen->ToValue();
	obj.push_back(Pair("txhash", wtx.GetHash().GetHex()));
	obj.push_back(Pair("offerhash", offer->GetHash().GetHex()));
	return (obj);
}

Value rpc_offer_cancel(CIface *iface, const Array& params, bool fStratum)
{
	string strAccount;
	uint160 hOffer;

  if (params.size() != 2)
    throw runtime_error("rpc_offer_cancel");

	strAccount = AccountFromValue(params[0]);
	hOffer = rpc_offer_key_from_value(iface, params[1]);


	return (Value::null);
}

Value rpc_offer_info(CIface *iface, const Array& params, bool fStratum)
{
	double dFee;

  if (params.size() != 0)
    throw runtime_error("rpc_offer_info");

	Object obj;

	dFee = (double)GetOfferOpFee(iface) / COIN;
	obj.push_back(Pair("fee", dFee));

	return (obj);
}

Value rpc_offer_list(CIface *iface, const Array& params, bool fStratum)
{
	string strAccount;
	uint160 hColor;

  if (params.size() != 2)
    throw runtime_error("rpc_offer_list");

	strAccount = AccountFromValue(params[0]);
	hColor = rpc_alt_key_from_value(iface, params[1]);

	Array ar;
	
	/* .. */

	return (ar);
}

Value rpc_offer_status(CIface *iface, const Array& params, bool fStratum)
{
	string strAccount;

  if (params.size() != 1)
    throw runtime_error("rpc_offer_status");

	strAccount = AccountFromValue(params[0]);

	return (Value::null);
}
