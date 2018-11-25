
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

#ifndef __SERVER__RPCCONTEXT_PROTO_H__
#define __SERVER__RPCCONTEXT_PROTO_H__


#if 0
#include "shcoind.h"
#include "coin_proto.h"
#endif

#include <string>
#include <list>
#include <map>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"



Value rpc_ctx_fee(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_info(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_list(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_get(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_setstr(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_setbin(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_setfile(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_getstr(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_getbin(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_getfile(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_setid(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_getid(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_getloc(CIface *iface, const Array& params, bool fStratum);

Value rpc_ctx_setloc(CIface *iface, const Array& params, bool fStratum);

/**
 * Search the block-chain and libshare for a geodetic location or place.
 * @note Accessible via the stratum or RPC service.
 */
Value rpc_ctx_findloc(CIface *iface, const Array& params, bool fStratum);

/**
 * Display the internal table of short and long names for location types.
 */
Value rpc_ctx_loctypes(CIface *iface, const Array& params, bool fStratum);

/* not implem'd */
Value rpc_ctx_setevent(CIface *iface, const Array& params, bool fStratum);
Value rpc_ctx_getevent(CIface *iface, const Array& params, bool fStratum);
Value rpc_ctx_setval(CIface *iface, const Array& params, bool fStratum);
Value rpc_ctx_getval(CIface *iface, const Array& params, bool fStratum);



#endif /* ndef __SERVER__RPCCONTEXT_PROTO_H__ */

