
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
        "Server: shc-json-rpc/%s\r\n"
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
      "Server: shc-json-rpc/%s\r\n"
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
    << "User-Agent: shc-json-rpc/" << FormatFullVersion() << "\r\n"
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

