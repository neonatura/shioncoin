
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
#include <libgen.h>

#include "init.h"
#include "ui_interface.h"
#include "base58.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "exec.h"
#include "rpc_proto.h"

using namespace std;
using namespace boost;
//using namespace boost::asio;
using namespace json_spirit;
//using namespace boost::assign;


static bool fHelp = false;


extern exec_list *GetExecTable(int ifaceIndex);

extern string AccountFromValue(const Value& value);

extern int rpc_sexe_compile(char *path_out, char *path_fname, char *path_dir, int *exec_size);

extern int64 AmountFromValue(const Value& value);

extern json_spirit::Value ValueFromAmount(int64 amount);



static const char *get_exec_path(CIface *iface, char *fname)
{
	static char ret_buf[PATH_MAX+1];

	memset(ret_buf, 0, sizeof(ret_buf));

	/* program data dir */
	strncpy(ret_buf, get_shioncoin_path(), sizeof(ret_buf)-1);

	/* SX executables dir */
#ifdef WINDOWS
	if (*ret_buf && ret_buf[strlen(ret_buf)-1] != '\\')
		strcat(ret_buf, "\\");
	strncat(ret_buf, "blockchain\\exec\\", sizeof(ret_buf)-strlen(ret_buf)-1);
#else
	if (*ret_buf && ret_buf[strlen(ret_buf)-1] != '/')
		strcat(ret_buf, "/");
	strncat(ret_buf, "blockchain/exec/", sizeof(ret_buf)-strlen(ret_buf)-1);
#endif
	mkdir(ret_buf, 0770);

	/* network service */
	strncat(ret_buf, iface->name, sizeof(ret_buf)-strlen(ret_buf)-2);
#ifdef WINDOWS
	strcat(ret_buf, "\\"); 
#else
	strcat(ret_buf, "/"); 
#endif
	mkdir(ret_buf, 0770);

	strcat(ret_buf, fname);
	return ((const char *)ret_buf);
}

Value rpc_exec_compile(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
	int exec_size = 0;
	char path_dir[PATH_MAX+1];
	char path_fname[PATH_MAX+1];
		string pathStr;
	char fname[PATH_MAX+1];
	char path_out[PATH_MAX+1];
	int err;
	char pathbuf[PATH_MAX+1];

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (1 != params.size())
    throw runtime_error("invalid parameters");

	pathStr = params[0].get_str();

	memset(pathbuf, 0, sizeof(pathbuf));
	strncpy(pathbuf, pathStr.c_str(), sizeof(pathbuf)-1);
	memset(path_dir, 0, sizeof(path_dir));
	strncpy(path_dir, dirname(pathbuf), sizeof(path_dir)-1);

	memset(pathbuf, 0, sizeof(pathbuf));
	strncpy(pathbuf, pathStr.c_str(), sizeof(pathbuf)-1);
	memset(path_fname, 0, sizeof(path_fname));
	strncpy(path_fname, basename(pathbuf), sizeof(path_fname)-1);

	/* output filename */
	memset(fname, 0, sizeof(fname));
	strcpy(fname, path_fname);
	strtok(fname, ".");
	strcat(fname, ".sx");

	/* compile into SX output file */
	strcpy(path_out, get_exec_path(iface, fname));
	err = rpc_sexe_compile(path_out, pathbuf, path_dir, &exec_size);
	if (err) {
		throw JSONRPCError(err, "compile executable");
	}

	/* return info */
  Object obj;
  int nBestHeight = GetBestHeight(iface); 
	obj.push_back(Pair("fee", 
				ValueFromAmount(GetExecOpFee(iface, nBestHeight, exec_size))));
  obj.push_back(Pair("size", exec_size));
  obj.push_back(Pair("path", string(path_out)));

  return (obj);
}

Value rpc_exec_fee(CIface *iface, const Array& params, bool fStratum) 
{

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (params.size() > 1)
    throw runtime_error("invalid parameters");

	int64 nSize = MAX_EXEC_SIZE;
  if (params.size() > 0)
		nSize = params[0].get_int();

  int nBestHeight = GetBestHeight(iface); 
  return ValueFromAmount(GetExecOpFee(iface, nBestHeight, nSize));
}

Value rpc_exec_get(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
  CExec *exec;
  exec_list *list;

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

  uint160 hash(params[0].get_str());

  list = GetExecTable(ifaceIndex);
  BOOST_FOREACH(PAIRTYPE(const uint160, uint256)& r, *list) {
    const uint160& hExec = r.first;
    if (hExec != hash)
			continue; /* no match */

    const uint256& hTx = r.second;
    CTransaction tx;
		if (!GetTransaction(iface, hTx, tx, NULL))
			break; /* soft error */

		int mode;
		if (!IsExecTx(tx, mode))
			continue;

		if (mode != OP_EXT_NEW) {
			return (tx.ToValue(ifaceIndex));
		}

		CExec *exec = tx.GetExec();
		Object obj = exec->ToValue(ifaceIndex);

		Array calls;
		exec_call_list *c_list = GetExecCallTable(ifaceIndex);
		if (c_list->count(hExec) != 0) {
			const vector<uint160>& e_list = (*c_list)[hExec];
			BOOST_FOREACH(const uint160& hash, e_list) {
				calls.push_back(hash.GetHex());
			}
		}
		exec_call_list *p_list = GetExecCallPendingTable(ifaceIndex);
		if (p_list->count(hExec) != 0) {
			const vector<uint160>& e_list = (*p_list)[hExec];
			BOOST_FOREACH(const uint160& hash, e_list) {
				calls.push_back(hash.GetHex());
			}
		}
		obj.push_back(Pair("calls", calls));
		return (obj);
  }

  throw JSONRPCError(-5, "invalid hash specified");
}

Value rpc_exec_info(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
  exec_list *list;

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (0 != params.size())
    throw runtime_error("invalid parameters");

  Object obj;

  int nBestHeight = GetBestHeight(iface); 
  obj.push_back(Pair("max-fee", ValueFromAmount(GetExecOpFee(iface, nBestHeight))));
  obj.push_back(Pair("min-fee", ValueFromAmount(GetExecOpFee(iface, nBestHeight, 20))));

  list = GetExecTable(ifaceIndex);
  obj.push_back(Pair("total", (int)list->size()));

  return (obj);
}

Value rpc_exec_list(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
  exec_label_list *list;

  if (params.size() > 1)
    throw runtime_error("invalid parameters");

  string keyword;
  if (params.size() != 0)
    keyword = params[0].get_str();

  Object result;
  list = GetExecLabelTable(ifaceIndex);
  BOOST_FOREACH(PAIRTYPE(const string, uint160)& r, *list) {
		const string& label = r.first;
    if (keyword.length() != 0 &&
        label.find(keyword) == std::string::npos)
      continue;

    result.push_back(Pair(label, r.second.GetHex()));
  }

  return (result);
}


Value rpc_exec_new(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
	CWalletTx wtx;
  CExec *exec;
  exec_list *list;
  string strPath;
	string strAccount;
	char label[256];
	int err;

  if (params.size() != 2)
    throw runtime_error("invalid parameters");

	strAccount = AccountFromValue(params[0]);
	strPath = string(get_exec_path(iface, 
				(char *)params[1].get_str().c_str()));

	err = init_exec_tx(iface, strAccount, strPath, wtx);
	if (err)
		throw JSONRPCError(err, "initialize executable");

	return (wtx.ToValue(ifaceIndex));
}

#if 0
static Value rpc_exec_call(CIface *iface, string strAccount, int64 nFee, string strClass, string strFunc, vector<string> vArg)
{
	Value resp;
	size_t pos;
	int err;
	int i;

	if (strClass.length() == 0 || strFunc.length() == 0) {
		throw JSONRPCError(SHERR_INVAL, "invalid class/function reference");
	}

	CExec exec;
	if (!GetExecByLabel(iface, strClass, exec)) {
		throw JSONRPCError(SHERR_INVAL, "invalid class name");
	}

	resp = Value::null;
	if (!exec.CallStack(GetCoinIndex(iface), strAccount, nFee, strFunc, vArg, resp)) {
		throw JSONRPCError(SHERR_INVAL, "invalid function syntax");
	}

	return (resp);
}
#endif

Value rpc_exec_run(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
	CWalletTx wtx;
	string strAccount;
	string strClass;
	string strFunc;
	char **args;
	size_t pos;
	int64 nFee;
	int err;
	int i;

  if (params.size() < 3)
    throw runtime_error("invalid parameters");

	string s = params[2].get_str();
	pos = s.find(".");
	if (pos == std::string::npos) {
		throw JSONRPCError(SHERR_INVAL, "invalid class/function reference");
	}

	strAccount = AccountFromValue(params[0]);
	nFee = (int64)(params[1].get_real() * COIN);
	strClass = s.substr(0, pos);
	strFunc = s.substr(pos + 1);

	/* generate execution of class method */
	args = (char **)calloc(params.size(), sizeof(char *));
	for (i = 3; i < params.size(); i++)
		args[i-3] = strdup(params[i].get_str().c_str());
	Value ret_val;
	err = generate_exec_tx(iface, strAccount, strClass, nFee, strFunc, args, ret_val, wtx);
	for (i = 3; i < params.size(); i++)
		free(args[i-3]);
	free(args);
	if (err)
		throw JSONRPCError(err, "call class method");

#if 0
	/* return JSON context */
	CExecCall *call = wtx.GetExecCall();
	string strContext = call->ToString(ifaceIndex);
	Value resp = Value::null;
	read_string(strContext, resp);
	resp.push_back(Pair("return", ret_val));
	return (resp);
#endif
	Object resp;
	resp.push_back(Pair("return", ret_val));

	return (resp);
}

Value rpc_exec_history(CIface *iface, const Array& params, bool fStratum) 
{

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

	string strClass  = params[0].get_str();
	CExec exec;

	if (!GetExecByLabel(iface, strClass, exec)) {
		throw JSONRPCError(SHERR_NOENT, "invalid class/function reference");
	}

	Object ret;

	/* .. */

	return (ret);
}

Value rpc_exec_reset(CIface *iface, const Array& params, bool fStratum) 
{

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

	string strClass  = params[0].get_str();
	CExec exec;

	if (!GetExecByLabel(iface, strClass, exec)) {
		throw JSONRPCError(SHERR_NOENT, "invalid class/function reference");
	}

	uint160 hExec = exec.GetHash();
	ResetExecChain(iface, hExec);

	Object ret;

	/* .. */

	return (ret);
}

static inline string ToValue_date_format(time_t t)
{
  char buf[256];

  memset(buf, 0, sizeof(buf));
  strftime(buf, sizeof(buf)-1, "%x %T", localtime(&t));

  return (string(buf));
}

#if 0
Value rpc_exec_renew(CIface *iface, const Array& params, bool fStratum) 
{
	static const int nMinDepth = 1;
  int ifaceIndex = GetCoinIndex(iface);
	string strClass;
	string strAccount;
	int64 nBalance;
	int64 nFee;
	int err;

  if (params.size() != 1)
    throw runtime_error("invalid parameters");

	strClass = params[0].get_str();

	CExec execIn;
	if (!GetExecByLabel(iface, strClass, execIn)) {
		throw JSONRPCError(SHERR_INVAL, "invalid class name");
	}

	CWalletTx wtx;
	err = update_exec_tx(iface, execIn.GetHash(), wtx);
	if (err)
		throw JSONRPCError(err, "initialize executable class");

	/* updated executable */
	CExec& exec = (CExec&)wtx.certificate;

	/* return info */
  Object obj;
  int nBestHeight = GetBestHeight(iface); 
	obj.push_back(Pair("class", exec.GetLabel()));
	obj.push_back(Pair("hash", exec.GetHash().GetHex()));
	obj.push_back(Pair("fee", ValueFromAmount(nFee))); 
	obj.push_back(Pair("expire", ToValue_date_format(exec.GetExpireTime())));
	obj.push_back(Pair("owner", exec.GetExecAddr(ifaceIndex).ToString()));

	return (obj);
}
#endif

#if 0
Value rpc_exec_transfer(CIface *iface, const Array& params, bool fStratum) 
{
	static const int nMinDepth = 1;
  int ifaceIndex = GetCoinIndex(iface);
	string strClass;
	string strAccount;
	int64 nBalance;
	int64 nFee;

  if (params.size() != 2)
    throw runtime_error("invalid parameters");

	strClass = params[0].get_str();

	return (SHERR_OPNOTSUPP);
}
#endif


