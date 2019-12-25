
/*
 * @copyright
 *
 *  Copyright 2019 Neo Natura
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
#include "base58.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "rpc_proto.h"
#include "txmempool.h"
#include "wallet.h"
#include "ext/ext_param.h"

using namespace std;
using namespace boost;

Value rpc_param_list(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	bool fVerbose = false;
	int err;

  if (params.size() > 1)
    throw runtime_error("rpc_param_list");
	if (params.size() == 1)
		fVerbose = params[0].get_bool();

	Array ret;
	BOOST_FOREACH(CParam& param, wallet->mapParam) {
		ret.push_back(param.ToValue());
	}

	return (ret);
}

Value rpc_param_value(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	map<int64_t,int> vTalley;
	char buf[256];
	char buf2[256];
	string strMode;
	int64_t nCurrentValue;
	int nTotal;
	int err;

  if (params.size() != 1)
    throw runtime_error("rpc_param_value");

	strMode = params[0].get_str();
	nCurrentValue = GetParamTxValue(iface, strMode);

	nTotal = 0;
	BOOST_FOREACH(CParam& param, wallet->mapParam) {
		if (param.GetMode() != strMode)
			continue;
		if (param.IsExpired())
			continue;
		if (!IsValidParamTxConsensus(iface, &param, nCurrentValue))
			continue;

		if (vTalley.count(param.GetValue()) == 0) {
			vTalley[param.GetValue()] = 1;
		} else {
			vTalley[param.GetValue()] = vTalley[param.GetValue()] + 1;
		}
		nTotal++;
	}

	Object ret;
	if (nTotal != 0) {
		BOOST_FOREACH(const PAIRTYPE(int64_t, int)& a, vTalley) {
			sprintf(buf, "%lld", a.first);
			sprintf(buf2, "%-1.1f%%", 100 / (double)nTotal * (double)a.second);
			ret.push_back(Pair(string(buf), string(buf2)));
		}
	}
	ret.push_back(Pair("total", nTotal));

	return (ret);
}

Value rpc_param_get(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	bool fVerbose = false;
	int err;

  if (params.size() != 1)
    throw runtime_error("rpc_param_get");
	uint160 hParam(params[0].get_str());

	Array ret;
	BOOST_FOREACH(CParam& param, wallet->mapParam) {
		if (param.IsExpired())
			continue;
		if (param.GetHash() == hParam)
			return (param.ToValue());
	}

	throw JSONRPCError(ERR_NOENT, "unknown param");
}

