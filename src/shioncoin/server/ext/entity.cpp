
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
#include "json_spirit_reader_template.h"
#include "json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>
#include "wallet.h"
#include "account.h"
#include "txcreator.h"

using namespace std;
using namespace json_spirit;

uint160 CEntity::GetHash()
{
	uint256 hash = SerializeHash(*this);
	unsigned char *raw = (unsigned char *)&hash;
	cbuff rawbuf(raw, raw + sizeof(hash));
	return Hash160(rawbuf);
}

Object CEntity::ToValue()
{
  Object obj = CExtCore::ToValue();
  char sig[256];
  char loc[256];
  shnum_t lat, lon;

  shgeo_loc(&geo, &lat, &lon, NULL);
  if (lat != 0.0000 || lon != 0.0000) {
    sprintf(loc, "%Lf,%Lf", lat, lon);
    string strGeo(loc);
    obj.push_back(Pair("geo", strGeo));
  }

  if (nType != 0) {
    obj.push_back(Pair("type", (int64_t)nType));
  }

  if (vAddr.size() != 0)
    obj.push_back(Pair("address", stringFromVch(vAddr)));

  return (obj);
}

std::string CEntity::ToString()
{
  return (write_string(Value(ToValue()), false));
}

bool CEntity::IsLocalRegion()
{
	shgeo_t lcl_geo;
	bool ret = false;

	memset(&lcl_geo, 0, sizeof(lcl_geo));
	shgeo_local(&lcl_geo, SHGEO_PREC_REGION);
	if (shgeo_cmp(&geo, &lcl_geo, SHGEO_PREC_REGION))
		ret = true;

	return (ret);
}

int CEntity::VerifyTransaction()
{
	int err;

	err = CExtCore::VerifyTransaction();
	if (err)
		return (err);

	if (//GetLabelSize() == 0 ||
			GetLabelSize() > GetMaximumLabelSize()) {
		return (ERR_INVAL);
	}

	if (GetContentSize() > GetMaximumContentSize()) {
		return (ERR_2BIG);
	}

	return (0);
}

bool IsLocalEntity(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

