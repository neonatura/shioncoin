
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

#include "shcoind.h"
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "chain.h"
#include "certificate.h"
#include "rpc_proto.h"
#include "rpccert_proto.h"
#include "rpcalias_proto.h"
#include "rpccontext_proto.h"


using namespace std;
using namespace boost;

extern Value rpc_wallet_keyphrase(CIface *iface, const Array& params, bool fHelp);
extern Value rpc_wallet_setkeyphrase(CIface *iface, const Array& params, bool fHelp);

const RPCOp WALLET_CSEND = {
  &rpc_wallet_csend, 4, {RPC_ACCOUNT, RPC_COINADDR, RPC_DOUBLE, RPC_STRING},
  "Syntax: <account> <address> <value> <cert-hash>\n"
  "Summary: Send a certified coin transaction."
};

const RPCOp WALLET_DONATE = {
  &rpc_wallet_donate, 2, {RPC_ACCOUNT, RPC_DOUBLE, RPC_STRING},
  "Syntax: <account> <value> [<cert-hash>]\n"
  "Summary: Donate coins as a block transaction fee identified by the specified certificate.\n"
  "Params: [ <account> The coin account name., <value> The coin value to donate, <cert-hash> The associated certificate's hash. ]\n"
  "\n"
  "Donated coins are added to the upcoming block reward. Donations may be optionally associated with a certificate. The maximum donation value in a single transaction is 500 coins."
};

const RPCOp WALLET_KEYPHRASE = {
  &rpc_wallet_keyphrase, 1, {RPC_COINADDR},
  "Syntax: <address>\n"
    "Summary: Reveals the private key corresponding to a public coin address as a phrase of common words..\n"
    "Params: [ <address> The coin address. ]\n"
    "\n"
    "The 'wallet.key' command provides a method to obtain the private key associated\n"
    "with a particular coin address.\n"
    "\n"
    "The coin address must be available in the local wallet in order to print it's pr\n"
    "ivate address.\n"
    "\n"
    "The private coin address can be imported into another system via the 'wallet.setkey' command.\n"
    "\n"
    "The entire wallet can be exported to a file via the 'wallet.export' command."
};

const RPCOp WALLET_SETKEYPHRASE = {
  &rpc_wallet_setkeyphrase, 2, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: \"<phrase>\" <account>\n"
    "Adds a private key to your wallet from a key phrase."
};

const RPCOp WALLET_STAMP = {
  &rpc_wallet_stamp, 2, {RPC_ACCOUNT, RPC_STRING},
  "Syntax: <account> \"<comment>\"\n"
    "Summary: Create a 'ident stamp' transaction which optionally references a particular geodetic location.\n"
    "Params: [ <account> The coin account name., <comment> Use the format \"geo:<lat>,<lon>\" to specify a location. ]\n"
    "\n"
    "A single coin reward can be achieved by creating an ident stamp transaction on a location present in the \"spring matrix\". The reward will be given, at most, once per location. A minimum transaction fee will apply and is sub-sequently returned once the transaction has been processed."
};


/* ext tx: alias */
const RPCOp ALIAS_INFO = {
  &rpc_alias_info, 0, {},
  "Get general information on aliases."
};
const RPCOp ALIAS_FEE = {
  &rpc_alias_fee, 0, {},
  "Get current service fee to perform an alias operation."
};
const RPCOp ALIAS_PUBADDR = {
  &rpc_alias_pubaddr, 1, {RPC_STRING, RPC_STRING},
  "Syntax: <name> [<coin-address>]\n"
  "Summary: Generate, transfer, or obtain a published coin-address alias.\n"
  "Params: [ <name> The alias's label, <coin-address> The alias's referenced coin address. ]\n"
  "When a coin address is specified the alias label will be published onto the block chain in reference. If the alias label already exists, then a transfer will occur providing you are the original owner.\n"
  "The assigned coin address, if one exists, is printed if a specific coin address is not specified."
};
const RPCOp ALIAS_REMOVE = {
  &rpc_alias_remove, 1, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: <name> [<account>]\n"
  "Summary: Removed a published alias.\n"
  "Params: [ <name> The alias's label, <account> the account of the referenced coin address. ]\n"
  "Removes a published alias from the block-chain. The alias owner's account is verified [when an account specification is warranted]."
};
const RPCOp ALIAS_GET = {
  &rpc_alias_get, 1, {RPC_STRING},
  "Syntax: <alias-hash>\n"
  "Summary: Obtain specific information about an alias.\n"
  "Params: [ <alias-hash> The alias hash being referenced. ]\n"
  "\n"
  "Print indepth information about a particular alias based on it's hash."
};
const RPCOp ALIAS_GETADDR = {
  &rpc_alias_getaddr, 1, {RPC_STRING},
  "Syntax: <name>\n"
  "Summary: Obtain specific information about an alias.\n"
  "Params: [ <name> The alias label being referenced. ]\n"
  "\n"
  "Print indepth information about a particular alias based on it's label."
};
const RPCOp ALIAS_LIST = {
  &rpc_alias_listaddr, 0, {RPC_STRING},
  "Syntax: [<keyword>]\n"
  "List all published aliases with optional keyword filter."
};



/* ext tx; certificate */
const RPCOp CERT_EXPORT = {
  &rpc_cert_export, 1, {RPC_STRING, RPC_STRING},
  "Syntax: <cert-hash> [<path>]\n"
  "Summary: Export the credentials neccessary to own a certificate.\n"
  "Params: [ <cert-hash> The certificate's reference hash. ]\n"
  "\n"
  "Ownership and management of a certificate depends on having specific coin address key(s) in the coin wallet. Exporting a certificate provides JSON formatted content which can be used with \"wallet.import\" command to attain ownership of a certificate."
};
const RPCOp CERT_INFO = {
  &rpc_cert_info, 0, {},
  "Print general certificate related information."
};
const RPCOp CERT_GET = {
  &rpc_cert_get, 1, {RPC_STRING},
  "Syntax: <cert-hash>\n"
  "Print information about a certificate."
};
const RPCOp CERT_LIST = {
  &rpc_cert_list, 0, {RPC_STRING},
  "Syntax: [<keyword>]\n"
  "List all certificates with an optional keyword."
};
const RPCOp CERT_NEW = {
  &rpc_cert_new, 2, {RPC_ACCOUNT, RPC_STRING, RPC_INT64, RPC_STRING},
  "Syntax: <account> <name> [<fee>] [<hex-seed>]\n"
  "Summary: Creates a new certificate suitable for authorizing another certificate or license.\n"
  "Params: [ <account> The coin account name., <name> The title or the certificate, <hex-seed> A hexadecimal string to create the private key from, <fee> the coin value to license or have issued. ]\n"
  "\n"
  "A certificate can either be designated for issueing other certificates or granting licenses, but not both. Either form of the certificate may be used in order to donate or send a certified coin transfer."
};
const RPCOp CERT_DERIVE = {
  &rpc_cert_derive, 3, {RPC_ACCOUNT, RPC_STRING, RPC_STRING, RPC_INT64},
  "Syntax: <account> <name> <cert-hash> [<fee>]\n"
  "Derive a certificate from another certificate."
};
const RPCOp CERT_LICENSE = {
  &rpc_cert_license, 2, {RPC_ACCOUNT, RPC_STRING, RPC_STRING},
  "Syntax: <account> <cert-hash> [<hex seed>]\n"
  "Generate a license from a certificate."
};


/* context */
const RPCOp CTX_INFO = {
  &rpc_ctx_info, 0, {},
  "Display a summary of context transactions."
};

const RPCOp CTX_FEE = {
  &rpc_ctx_fee, 0, {RPC_INT},
  "Syntax: [<ctx-size>]\n"
  "Summary: Obtain the coin fee to perform a context transaction operation."
  "Params: [ <ctx-size> The size of the proposed context value. ]\n"
  "\n"
  "A context transaction essentially consists of a hashed name, a binary segment value, and an expiration date.\n"
  "The context operation fee is based on the current block-chain height and the size of the underlying context value.\n"
  "When a context size is not specified, the maximum size \"4096\" will be used."
};


const RPCOp CTX_GET = {
  &rpc_ctx_get, 1, {RPC_STRING},
  "Syntax: <ctx-hash>\n"
  "Summary: Obtain verbose information about a specific context transaction.\n"
  "Params: [ <ctx-hash> The hash of the context name. ]\n"
  "\n"
  "Prints detailed information relating to the specified context transaction."
};

const RPCOp CTX_LIST = {
  &rpc_ctx_list, 1, {RPC_ACCOUNT},
  "Syntax: <account>\n"
  "List all of the context transactions generated by the specified account name."
};

const RPCOp CTX_GETSTR = {
  &rpc_ctx_getstr, 1, {RPC_STRING},
  "Syntax: <name>\n"
  "Summary: Display a context value in ASCII.\n"
  "Params: [ <name> The literal string name of the context. ]\n"
  "\n"
  "Prints the ASCII value associated with a particular context name."
};

const RPCOp CTX_GETBIN = {
  &rpc_ctx_getbin, 1, {RPC_STRING},
  "Syntax: <name>\n"
  "Summary: Display a context value in hexadecimal representation.\n"
  "Params: [ <name> The literal string name of the context. ]\n"
  "\n"
  "Prints a hexadecimal version of the binary segment value associated with a particular context name."
};

const RPCOp CTX_GETFILE = {
  &rpc_ctx_getfile, 2, {RPC_STRING, RPC_STRING},
  "Syntax: <name> <path>\n"
  "\n"
  "Write the binary contents of a given context to the path specified."
};

const RPCOp CTX_SETSTR = {
  &rpc_ctx_setstr, 3, {RPC_ACCOUNT, RPC_STRING, RPC_STRING},
  "Syntax: <account> <name> <value>\n"
  "Summary: Create a new contex using the specified ASCII value."
  "Params: [ <account> The account to associate with the context, <name> A literal string name, <value> A string value to store. ]\n"
  "\n"
  "Context transaction consist of a name and a value. The context name is stored as a 160-bit hash key, and a summary (including the first 24 characters of the context name) is stored as the label. A context transaction's hash is equivelant to the 160-bit hash key generated from the context name.\n" 
  "\n"
  "The name must be at least 3 characters.\n"
  "The value is limited to a maximum of 4096 characters."
  "A context with expire after two years from it's original creation.\n"
  "The original owner account may update a context with the same name, and sub-sequentially refresh the expiration date."
};

const RPCOp CTX_SETBIN = {
  &rpc_ctx_setbin, 3, {RPC_ACCOUNT, RPC_STRING, RPC_STRING},
  "Syntax: <account> <name> <hex>\n"
  "Summary: Create a new binary context.\n"
  "Params: [ <account> The account to associate with the context, <name> A literal string name, <hex> A hexadecimal representation of the value. ]\n"
  "Create a new context using the hexadecimal string as the value.\n"
  "\n"
  "All context transaction expire after two years from there creation.\n"
  "The name must be at least 3 characters.\n"
  "The value is limited to a maximum of 4096 characters.\n"
  "The original owner account may update a context with the same name, and sub-sequentially refresh the expiration date."
};

const RPCOp CTX_SETFILE = {
  &rpc_ctx_setfile, 3, {RPC_ACCOUNT, RPC_STRING, RPC_STRING},
  "Syntax: <account> <name> <path>\n"
  "Summary: Create a binary context from a file.\n"
  "Params: [ <account> The account to associate with the context, <name> A literal string name, <path> A local file path. ]\n"
  "Create a new context using the contents of the path specified."
  "\n"
  "All context transaction expire after two years from there creation.\n"
  "The name must be at least 3 characters.\n"
  "The value is limited to a maximum of 4096 characters."
};

const RPCOp CTX_GETID = {
  &rpc_ctx_getid, 1, {RPC_STRING},
  "Syntax: <name>\n"
  "Print profile information for a given ID name."
};
const RPCOp CTX_SETID = {
  &rpc_ctx_setid, 3, {RPC_ACCOUNT, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING},
  "Syntax: <account> <id-name> <real-name> <email> [<country>] [\"geo:<lat>,<lon>\" | <zipcode>] [<url>]\n"
  "Params: [ <account> The account to associate with the context, <id-name> The name of the entity, <real-name> An organization or real person name, <email> An email address, <country> A country in \"en_US\" or \"US\" style format, <zipcode> A five-digit numeric zip-code, <url> An associated web reference. ]\n"
  "\n"
  "Set profile information for a given ID name."
};

const RPCOp CTX_GETLOC = {
  &rpc_ctx_getloc, 1, {RPC_STRING},
  "Syntax: (<name> | \"geo:<lat>,<lon>)\"\n"
  "Summary: Obtain information about a given place or specific geodetic location.\n"
  "Params: [ <account> The account to associate with the context, <name> The name of the location. ]\n"
  "\n"
  "Obtains specific geodetic location (latitude and longitude) for a registered location name.\n"
  "Use the \"geo:<lat>,<lon>\" style format to obtain detailed information about a specific location.\n"
  "\n"
  "Example: shc getloc \"Missoula, MT\"\n"
  "Example: shc getloc geo:46.8787,113.9966\n"
  "Note: This command is restricted to block-chain based context transactions."
};
const RPCOp CTX_SETLOC = {
  &rpc_ctx_setloc, 3, {RPC_ACCOUNT, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING},
  "Syntax: account \"geo:<lat>,<lon>\" <summary> [<type>] [<country>] [<web-url>]\n"
  "Syntax: <account> <name> (\"geo:<lat>,<lon>\" | <zipcode>)\n"
  "Summary: Create contextual information about a specific place.\n"
  "Params: [ <account> The account to associate with the context, <zipcode> A 5-digit numeric zipcode, <name> The name of the location, <summary> A textual description of the location, <type> A location type code, <country> The two-letter country code, <zipcode> A zipcode for the given country, <web-url> A url providing additional information about the place. ]\n"
  "\n"
  "This dual-purpose command allows for locations to be given contextual information and specific geodetic locations to be given names.\n"
  "\n"
  "Note: Use the \"ctx.loctypes\" command to list supported location type codes.\n"
  "Note: The \"springable\" value denotes whether the geodetic location can be claimed in the SHC spring matrix (see \"wallet.stamp\")."
};

const RPCOp CTX_FINDLOC = {
  &rpc_ctx_findloc, 1, {RPC_STRING},
  "Syntax: \"<name>\"\n"
  "Syntax: geo:<lat>,<lon>\n"
  "Params: [ <name> The name of the location or a five-digit zip-code. ]\n"
  "\n"
  "Search for a place given a name or geodetic location.\n"
  "\n"
  "Example: ctx.findloc \"Missoula, MT\"\n"
  "Example: ctx.findloc \"geo:46.9,114.2\"\n"
  "Note: All city names are in the format \"<city>, <state-abrev>\".\n"
  "Note: An internal database will be searched if the location cannot be found in the block-chain."
  "Note: The \"springable\" value denotes whether the geodetic location can be claimed in the SHC spring matrix (see \"wallet.stamp\")."
};

const RPCOp CTX_LOCTYPES = {
  &rpc_ctx_loctypes, 0, {},
  "List all of the supported location type codes and their respective descriptions.\n"
  "\n"
  "name: The location type code.\n"
  "desc: A printable label describing the location type.\n"
  "prec: The precision associated with the location type."
};



void shc_RegisterRPCOp()
{
  int ifaceIndex = SHC_COIN_IFACE;

  RegisterRPCOpDefaults(ifaceIndex);

  RegisterRPCOp(ifaceIndex, "alias.fee", ALIAS_FEE);
//  RegisterRPCOp(ifaceIndex, "alias.get", ALIAS_GET);
  RegisterRPCOp(ifaceIndex, "alias.getaddr", ALIAS_GETADDR);
  RegisterRPCOp(ifaceIndex, "alias.info", ALIAS_INFO);
  RegisterRPCOp(ifaceIndex, "alias.list", ALIAS_LIST);
  RegisterRPCOp(ifaceIndex, "alias.pubaddr", ALIAS_PUBADDR);
  RegisterRPCOp(ifaceIndex, "alias.remove", ALIAS_REMOVE);

  RegisterRPCOp(ifaceIndex, "cert.export", CERT_EXPORT);
  RegisterRPCOp(ifaceIndex, "cert.info", CERT_INFO);
  RegisterRPCOp(ifaceIndex, "cert.get", CERT_GET);
  RegisterRPCOp(ifaceIndex, "cert.list", CERT_LIST);
  RegisterRPCOp(ifaceIndex, "cert.new", CERT_NEW);
  RegisterRPCOp(ifaceIndex, "cert.derive", CERT_DERIVE);
  RegisterRPCOp(ifaceIndex, "cert.license", CERT_LICENSE);

  RegisterRPCOp(ifaceIndex, "ctx.fee", CTX_FEE);
  RegisterRPCOp(ifaceIndex, "ctx.info", CTX_INFO);
  RegisterRPCOp(ifaceIndex, "ctx.list", CTX_LIST);
  RegisterRPCOp(ifaceIndex, "ctx.get", CTX_GET);
  RegisterRPCOp(ifaceIndex, "ctx.setstr", CTX_SETSTR);
  RegisterRPCOp(ifaceIndex, "ctx.setbin", CTX_SETBIN);
  RegisterRPCOp(ifaceIndex, "ctx.setfile", CTX_SETFILE);
  RegisterRPCOp(ifaceIndex, "ctx.getstr", CTX_GETSTR);
  RegisterRPCOp(ifaceIndex, "ctx.getbin", CTX_GETBIN);
  RegisterRPCOp(ifaceIndex, "ctx.getfile", CTX_GETFILE);
  RegisterRPCOp(ifaceIndex, "ctx.getid", CTX_GETID);
  RegisterRPCOp(ifaceIndex, "ctx.setid", CTX_SETID);
  RegisterRPCOp(ifaceIndex, "ctx.getloc", CTX_GETLOC);
  RegisterRPCOp(ifaceIndex, "ctx.setloc", CTX_SETLOC);
  RegisterRPCOp(ifaceIndex, "ctx.findloc", CTX_FINDLOC);
  RegisterRPCOp(ifaceIndex, "ctx.loctypes", CTX_LOCTYPES);

  RegisterRPCOp(ifaceIndex, "wallet.csend", WALLET_CSEND);
  RegisterRPCOp(ifaceIndex, "wallet.donate", WALLET_DONATE);
  RegisterRPCOp(ifaceIndex, "wallet.keyphrase", WALLET_KEYPHRASE);
  RegisterRPCOp(ifaceIndex, "wallet.setkeyphrase", WALLET_SETKEYPHRASE);
  RegisterRPCOp(ifaceIndex, "wallet.stamp", WALLET_STAMP);
}

