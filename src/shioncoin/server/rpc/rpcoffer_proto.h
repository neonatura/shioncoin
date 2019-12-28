
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

#ifndef __SERVER__RPCOFFER_PROTO_H__
#define __SERVER__RPCOFFER_PROTO_H__

#include <string>
#include <list>
#include <map>

#include "json_spirit_reader_template.h"
#include "json_spirit_writer_template.h"
#include "json_spirit_utils.h"


Value rpc_offer_new(CIface *iface, const Array& params, bool fStratum); 

Value rpc_offer_accept(CIface *iface, const Array& params, bool fStratum); 

Value rpc_offer_commit(CIface *iface, const Array& params, bool fStratum); 

Value rpc_offer_cancel(CIface *iface, const Array& params, bool fStratum); 

Value rpc_offer_info(CIface *iface, const Array& params, bool fStratum); 

Value rpc_offer_list(CIface *iface, const Array& params, bool fStratum); 

Value rpc_offer_status(CIface *iface, const Array& params, bool fStratum); 


#endif /* ndef __SERVER__RPCOFFER_PROTO_H__ */

