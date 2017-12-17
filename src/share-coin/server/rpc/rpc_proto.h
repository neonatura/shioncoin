
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

#ifndef __RPC__RPC_PROTO_H__
#define __RPC__RPC_PROTO_H__

#ifdef __cplusplus
#include <string>
#include <list>
#include <map>
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"
#endif

#include "coin_proto.h"

#define MAX_RPC_ARGS 32

#define RPC_NULL 0
#define RPC_STRING 1
#define RPC_INT 2 
#define RPC_INT64 3 
#define RPC_DOUBLE 4 
#define RPC_BOOL 5
#define RPC_ARRAY 6
#define RPC_OBJECT 7
#define RPC_ACCOUNT 8
#define RPC_COINADDR 9
#define MAX_RPC_ARG_TYPES 10


#ifdef __cplusplus

json_spirit::Object JSONRPCError(int code, const std::string& message);

void ThreadRPCServer(void* parg);
int CommandLineRPC(int argc, char *argv[]);

/** Convert parameter values for RPC call from strings to command-specific JSON objects. */
json_spirit::Array RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams);

/*
  Type-check arguments; throws JSONRPCError if wrong type given. Does not check that
  the right number of arguments are passed, just that any passed are the correct type.
  Use like:  RPCTypeCheck(params, boost::assign::list_of(str_type)(int_type)(obj_type));
*/
void RPCTypeCheck(const json_spirit::Array& params,
                  const std::list<json_spirit::Value_type>& typesExpected);
/*
  Check for expected keys/value types in an Object.
  Use like: RPCTypeCheck(object, boost::assign::map_list_of("name", str_type)("value", int_type));
*/
void RPCTypeCheck(const json_spirit::Object& o,
                  const std::map<std::string, json_spirit::Value_type>& typesExpected);

typedef json_spirit::Value(*rpcfn_type)(CIface *iface, const json_spirit::Array& params, bool fHelp);

typedef int rpcfn_arg[MAX_RPC_ARGS];
class RPCOp
{
public:
  rpcfn_type actor;
  int min_arg;
  rpcfn_arg arg;
  string usage;
};

inline vector<unsigned char> vchFromValue(const json_spirit::Value& value) {
  string strName = value.get_str();
  unsigned char *strbeg = (unsigned char*) strName.c_str();
  return vector<unsigned char>(strbeg, strbeg + strName.size());
}


void RegisterRPCOp(int ifaceIndex, string name, const RPCOp& op);

#endif /* def __cplusplus */


void RegisterRPCOpDefaults(int ifaceIndex);


#ifdef __cplusplus
extern "C" {
#endif
int ExecuteRPC(int ifaceIndex, shjson_t *json, shbuf_t *buff);
int ExecuteStratumRPC(int ifaceIndex, shjson_t *json, shbuf_t *buff);
#ifdef __cplusplus
}
#endif





#endif /* ndef __RPC__RPC_PROTO_H__ */


