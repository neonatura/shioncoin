
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

#include <list>

#include "shcoind.h"
#include "main.h"
#include "util.h"
#include "ui_interface.h"
#include "clientrpc_iface.h"
#include "netbase.h"

#include <boost/asio.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/shared_ptr.hpp>

using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace json_spirit;

#if 0
#include "SSLIOStreamDevice.h"
#endif

static std::string strRPCUserColonPass;

static int64 nWalletUnlockTime;


string rfc1123Time()
{
  char buffer[64];
  time_t now;
  time(&now);
  struct tm* now_gmt = gmtime(&now);
  string locale(setlocale(LC_TIME, NULL));
  setlocale(LC_TIME, "C"); // we want posix (aka "C") weekday/month strings
  strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S +0000", now_gmt);
  setlocale(LC_TIME, locale.c_str());
  return string(buffer);
}

static string HTTPReply(int nStatus, const string& strMsg, bool keepalive)
{
  if (nStatus == 401)
    return strprintf("HTTP/1.0 401 Authorization Required\r\n"
        "Date: %s\r\n"
        "Server: usde-json-rpc/%s\r\n"
        "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 296\r\n"
        "\r\n"
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
        "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
        "<HTML>\r\n"
        "<HEAD>\r\n"
        "<TITLE>Error</TITLE>\r\n"
        "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
        "</HEAD>\r\n"
        "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
        "</HTML>\r\n", rfc1123Time().c_str(), FormatFullVersion().c_str());
  const char *cStatus;
  if (nStatus == 200) cStatus = "OK";
  else if (nStatus == 400) cStatus = "Bad Request";
  else if (nStatus == 403) cStatus = "Forbidden";
  else if (nStatus == 404) cStatus = "Not Found";
  else if (nStatus == 500) cStatus = "Internal Server Error";
  else cStatus = "";
  return strprintf(
      "HTTP/1.1 %d %s\r\n"
      "Date: %s\r\n"
      "Connection: %s\r\n"
      "Content-Length: %d\r\n"
      "Content-Type: application/json\r\n"
      "Server: usde-json-rpc/%s\r\n"
      "\r\n"
      "%s",
      nStatus,
      cStatus,
      rfc1123Time().c_str(),
      keepalive ? "keep-alive" : "close",
      strMsg.size(),
      FormatFullVersion().c_str(),
      strMsg.c_str());
}

int ReadHTTPStatus(std::basic_istream<char>& stream, int &proto)
{
  string str;
  getline(stream, str);
  vector<string> vWords;
  boost::split(vWords, str, boost::is_any_of(" "));
  if (vWords.size() < 2)
    return 500;
  proto = 0;
  const char *ver = strstr(str.c_str(), "HTTP/1.");
  if (ver != NULL)
    proto = atoi(ver+7);
  return atoi(vWords[1].c_str());
}

int ReadHTTPHeader(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet)
{
  int nLen = 0;
  loop
  {
    string str;
    std::getline(stream, str);
    if (str.empty() || str == "\r")
      break;
    string::size_type nColon = str.find(":");
    if (nColon != string::npos)
    {
      string strHeader = str.substr(0, nColon);
      boost::trim(strHeader);
      boost::to_lower(strHeader);
      string strValue = str.substr(nColon+1);
      boost::trim(strValue);
      mapHeadersRet[strHeader] = strValue;
      if (strHeader == "content-length")
        nLen = atoi(strValue.c_str());
    }
  }
  return nLen;
}

int ReadHTTP(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet, string& strMessageRet)
{
  mapHeadersRet.clear();
  strMessageRet = "";

  // Read status
  int nProto = 0;
  int nStatus = ReadHTTPStatus(stream, nProto);

  // Read header
  int nLen = ReadHTTPHeader(stream, mapHeadersRet);
  if (nLen < 0 || nLen > (int)MAX_SIZE)
    return 500;

  // Read message
  if (nLen > 0)
  {
    vector<char> vch(nLen);
    stream.read(&vch[0], nLen);
    strMessageRet = string(vch.begin(), vch.end());
  }

  string sConHdr = mapHeadersRet["connection"];

  if ((sConHdr != "close") && (sConHdr != "keep-alive"))
  {
    if (nProto >= 1)
      mapHeadersRet["connection"] = "keep-alive";
    else
      mapHeadersRet["connection"] = "close";
  }

  return nStatus;
}

bool HTTPAuthorized(map<string, string>& mapHeaders)
{
  string strAuth = mapHeaders["authorization"];
  if (strAuth.substr(0,6) != "Basic ")
    return false;
  string strUserPass64 = strAuth.substr(6); boost::trim(strUserPass64);
  string strUserPass = DecodeBase64(strUserPass64);
  return strUserPass == strRPCUserColonPass;
}

string HTTPPost(const string& strMsg, const map<string,string>& mapRequestHeaders)
{
  ostringstream s;
  s << "POST / HTTP/1.1\r\n"
    << "User-Agent: usde-json-rpc/" << FormatFullVersion() << "\r\n"
    << "Host: 127.0.0.1\r\n"
    << "Content-Type: application/json\r\n"
    << "Content-Length: " << strMsg.size() << "\r\n"
    << "Connection: close\r\n"
    << "Accept: application/json\r\n";
  BOOST_FOREACH(const PAIRTYPE(string, string)& item, mapRequestHeaders)
    s << item.first << ": " << item.second << "\r\n";
  s << "\r\n" << strMsg;

  return s.str();
}

string JSONRPCRequest(const char *iface, const string& strMethod, const Array& params, const Value& id)
{
  Object request;
  string iface_name(iface);

  request.push_back(Pair("method", strMethod));
  request.push_back(Pair("params", params));
  request.push_back(Pair("id", id));
  request.push_back(Pair("iface", iface_name));

  return write_string(Value(request), false) + "\n";
}

#if 0
Object CallRPC(const char *iface, const string& strMethod, const Array& params)
{
  char port_str[64];

  if (mapArgs["-rpcuser"] == "" && mapArgs["-rpcpassword"] == "")
    throw runtime_error(strprintf(
          _("You must set rpcpassword=<password> in the configuration file:\n%s\n"
            "If the file does not exist, create it with owner-readable-only file permissions."),
          GetConfigFile().string().c_str()));

  // Connect to localhost
  bool fUseSSL = GetBoolArg("-rpcssl");
  asio::io_service io_service;
  ssl::context context(io_service, ssl::context::sslv23);
  context.set_options(ssl::context::no_sslv2);
  asio::ssl::stream<asio::ip::tcp::socket> sslStream(io_service, context);
  SSLIOStreamDevice<asio::ip::tcp> d(sslStream, fUseSSL);
  iostreams::stream< SSLIOStreamDevice<asio::ip::tcp> > stream(d);

  string host_str("127.0.0.1");
  sprintf(port_str, "%u", (unsigned int)opt_num(OPT_RPC_PORT));
  if (!d.connect(host_str, string(port_str)))
    throw runtime_error("couldn't connect to server");

  // HTTP basic authentication
  string strUserPass64 = EncodeBase64(mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"]);
  map<string, string> mapRequestHeaders;
  mapRequestHeaders["Authorization"] = string("Basic ") + strUserPass64;

  // Send request
  string strRequest = JSONRPCRequest(iface, strMethod, params, 1);
  string strPost = HTTPPost(strRequest, mapRequestHeaders);
  stream << strPost << std::flush;

  // Receive reply
  map<string, string> mapHeaders;
  string strReply;
  int nStatus = ReadHTTP(stream, mapHeaders, strReply);
  if (nStatus == 401)
    throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
  else if (nStatus >= 400 && nStatus != 400 && nStatus != 404 && nStatus != 500)
    throw runtime_error(strprintf("server returned HTTP error %d", nStatus));
  else if (strReply.empty())
    throw runtime_error("no response from server");

  // Parse reply
  Value valReply;
  if (!read_string(strReply, valReply)) {
fprintf(stderr, "DEBUG: strReply: %s\n", strReply.c_str());
    throw runtime_error("couldn't parse reply from server");
}
  const Object& reply = valReply.get_obj();
  if (reply.empty())
    throw runtime_error("expected reply to have result, error and id properties");

  return reply;
}
#endif

#if 0
template<typename T>
void ConvertTo(Value& value)
{
  if (value.type() == str_type)
  {
    // reinterpret string as unquoted json value
    Value value2;
    string strJSON = value.get_str();
    if (!read_string(strJSON, value2))
      throw runtime_error(string("Error parsing JSON:")+strJSON);
    value = value2.get_value<T>();
  }
  else
  {
    value = value.get_value<T>();
  }
}
#endif


#if 0
// Convert strings to command-specific RPC representation
Array RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
  Array params;
  BOOST_FOREACH(const std::string &param, strParams)
    params.push_back(param);

  int n = params.size();

  //
  // Special case non-string parameter types
  //
  if (strMethod == "sendtoaddress"          && n > 1) ConvertTo<double>(params[1]);
  if (strMethod == "settxfee"               && n > 0) ConvertTo<double>(params[0]);
  if (strMethod == "setmininput"            && n > 0) ConvertTo<double>(params[0]);
  if (strMethod == "getreceivedbyaddress"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "wallet.recvbyaddr"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "getreceivedbyaccount"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "wallet.recvbyaccount"   && n > 1) ConvertTo<boost::int64_t>(params[1]);

  if (strMethod == "listreceivedbyaddress"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
  if (strMethod == "listreceivedbyaddress"  && n > 1) ConvertTo<bool>(params[1]);
  if (strMethod == "listreceivedbyaccount"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
  if (strMethod == "listreceivedbyaccount"  && n > 1) ConvertTo<bool>(params[1]);
  if (strMethod == "wallet.listbyaddr"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
  if (strMethod == "wallet.listbyaddr"  && n > 1) ConvertTo<bool>(params[1]);
  if (strMethod == "wallet.listbyaccount"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
  if (strMethod == "wallet.listbyaccount"  && n > 1) ConvertTo<bool>(params[1]);

  if (strMethod == "getbalance"             && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "wallet.balance"             && n > 1) ConvertTo<boost::int64_t>(params[1]);

  if (strMethod == "getblockhash"           && n > 0) ConvertTo<boost::int64_t>(params[0]);
  if (strMethod == "block.hash"           && n > 0) ConvertTo<boost::int64_t>(params[0]);

  if (strMethod == "block.import"           && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "block.export"           && n > 1) ConvertTo<boost::int64_t>(params[1]);

  if (strMethod == "block.purge"           && n > 0) ConvertTo<boost::int64_t>(params[0]);

  if (strMethod == "block.verify"           && n > 0) ConvertTo<boost::int64_t>(params[0]);

  if (strMethod == "move"                   && n > 2) ConvertTo<double>(params[2]);
  if (strMethod == "move"                   && n > 3) ConvertTo<boost::int64_t>(params[3]);
  if (strMethod == "wallet.move"                   && n > 2) ConvertTo<double>(params[2]);
  if (strMethod == "wallet.move"                   && n > 3) ConvertTo<boost::int64_t>(params[3]);

  if (strMethod == "sendfrom"               && n > 2) ConvertTo<double>(params[2]);
  if (strMethod == "sendfrom"               && n > 3) ConvertTo<boost::int64_t>(params[3]);
  if (strMethod == "wallet.send"            && n > 2) ConvertTo<double>(params[2]);
  if (strMethod == "wallet.send"            && n > 3) ConvertTo<boost::int64_t>(params[3]);

  if (strMethod == "cert.new"               && n > 3) ConvertTo<double>(params[3]); /* nFee */
  if (strMethod == "wallet.donate"          && n > 1) ConvertTo<double>(params[1]); /* nValue */
  if (strMethod == "wallet.csend"           && n > 2) ConvertTo<double>(params[2]); /* nValue */

  if (strMethod == "listtransactions"       && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "listtransactions"       && n > 2) ConvertTo<boost::int64_t>(params[2]);

  if (strMethod == "tx.list"       && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "tx.list"       && n > 2) ConvertTo<boost::int64_t>(params[2]);

  if (strMethod == "listaccounts"           && n > 0) ConvertTo<boost::int64_t>(params[0]);
  if (strMethod == "wallet.accounts"           && n > 0) ConvertTo<boost::int64_t>(params[0]);
  if (strMethod == "walletpassphrase"       && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "getblocktemplate"       && n > 0) ConvertTo<Object>(params[0]);
  if (strMethod == "block.template"       && n > 0) ConvertTo<Object>(params[0]);
  if (strMethod == "listsinceblock"         && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "block.listsince"         && n > 1) ConvertTo<boost::int64_t>(params[1]);

  if (strMethod == "sendmany"               && n > 1) ConvertTo<Object>(params[1]);
  if (strMethod == "sendmany"               && n > 2) ConvertTo<boost::int64_t>(params[2]);
  if (strMethod == "wallet.multisend"               && n > 1) ConvertTo<Object>(params[1]);
  if (strMethod == "wallet.multisend"               && n > 2) ConvertTo<boost::int64_t>(params[2]);

  if (strMethod == "addmultisigaddress"     && n > 0) ConvertTo<boost::int64_t>(params[0]);
  if (strMethod == "addmultisigaddress"     && n > 1) ConvertTo<Array>(params[1]);

  if (strMethod == "listunspent"            && n > 0) ConvertTo<boost::int64_t>(params[0]);
  if (strMethod == "listunspent"            && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "wallet.unspent"            && n > 0) ConvertTo<boost::int64_t>(params[0]);
  if (strMethod == "wallet.unspent"            && n > 1) ConvertTo<boost::int64_t>(params[1]);

  if (strMethod == "getrawtransaction"      && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "tx.getraw"      && n > 1) ConvertTo<boost::int64_t>(params[1]);
  if (strMethod == "createrawtransaction"   && n > 0) ConvertTo<Array>(params[0]);
  if (strMethod == "createrawtransaction"   && n > 1) ConvertTo<Object>(params[1]);
  if (strMethod == "signrawtransaction"     && n > 1) ConvertTo<Array>(params[1]);
  if (strMethod == "signrawtransaction"     && n > 2) ConvertTo<Array>(params[2]);
  if (strMethod == "tx.signraw"     && n > 1) ConvertTo<Array>(params[1]);
  if (strMethod == "tx.signraw"     && n > 2) ConvertTo<Array>(params[2]);

  return params;
}
#endif

Array RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
  Array params;

  BOOST_FOREACH(const std::string &param, strParams)
    params.push_back(param);

  return (params);
}

int CommandLineRPC(int argc, char *argv[])
{
  string strPrint;
  const char *iface;
  char prog_name[4096];
  char *ptr;
  int nRet = 0;

  iface = NULL;
  memset(prog_name, 0, sizeof(prog_name));
  strncpy(prog_name, argv[0], sizeof(prog_name));
  ptr = strrchr(prog_name, '/'); /* from end */
#ifdef _WIN32
  if (!ptr)
    ptr = strrchr(prog_name, '\\'); /* from end */
#endif
  if (!ptr)
    ptr = prog_name;
  else
    ptr++;
  strtok(ptr, ".");
  if (!*ptr) ptr = "shc"; /* default */
  iface = (const char *)ptr;

  try
  {
    // Skip switches
    while (argc > 1 && IsSwitchChar(argv[1][0]))
    {
      argc--;
      argv++;
    }

    // Method
    if (argc < 2)
      throw runtime_error("too few parameters");
    string strMethod = argv[1];

    // Parameters default to strings
    std::vector<std::string> strParams(&argv[2], &argv[argc]);
    Array params = RPCConvertValues(strMethod, strParams);

    // Execute
    Object reply = CallRPC(iface, strMethod, params);

    // Parse reply
    const Value& result = find_value(reply, "result");
    const Value& error  = find_value(reply, "error");

    if (error.type() != null_type)
    {
      // Error
      strPrint = "error: " + write_string(error, false);
      int code = find_value(error.get_obj(), "code").get_int();
      nRet = abs(code);
    }
    else
    {
      // Result
      if (result.type() == null_type)
        strPrint = "";
      else if (result.type() == str_type)
        strPrint = result.get_str();
      else
        strPrint = write_string(result, true);
    }
  }
  catch (std::exception& e)
  {
    strPrint = string("error: ") + e.what();
    nRet = 87;
  }
  catch (...)
  {
    PrintException(NULL, "CommandLineRPC()");
  }

  if (strPrint != "")
  {
    fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
  }
  return nRet;
}

