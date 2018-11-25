
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

#ifndef __SERVER__RPCEXEC_PROTO_H__
#define __SERVER__RPCEXEC_PROTO_H__

#include <string>
#include <list>
#include <map>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"




Value rpc_exec_compile(CIface *iface, const Array& params, bool fStratum);

Value rpc_exec_fee(CIface *iface, const Array& params, bool fStratum);

Value rpc_exec_get(CIface *iface, const Array& params, bool fStratum);

Value rpc_exec_info(CIface *iface, const Array& params, bool fStratum);

Value rpc_exec_list(CIface *iface, const Array& params, bool fStratum);

Value rpc_exec_new(CIface *iface, const Array& params, bool fStratum);

Value rpc_exec_run(CIface *iface, const Array& params, bool fStratum);

Value rpc_exec_renew(CIface *iface, const Array& params, bool fStratum); 

Value rpc_exec_transfer(CIface *iface, const Array& params, bool fStratum); 

Value rpc_exec_history(CIface *iface, const Array& params, bool fStratum); 

Value rpc_exec_reset(CIface *iface, const Array& params, bool fStratum); 


#endif /* ndef __SERVER__RPCEXEC_PROTO_H__ */

