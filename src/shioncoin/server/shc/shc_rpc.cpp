
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
#include "net.h"
#include "strlcpy.h"
#include "chain.h"
#include "certificate.h"
#include "asset.h"
#include "rpc_proto.h"
#include "rpccert_proto.h"
#include "rpcasset_proto.h"
#include "rpcalias_proto.h"
#include "rpccontext_proto.h"
#include "rpcexec_proto.h"
#include "rpcoffer_proto.h"
#include "rpcparam_proto.h"

using namespace std;
using namespace boost;

extern void RegisterRPCAlias(int ifaceIndex, string name, const RPCOp& op);
extern Value rpc_wallet_keyphrase(CIface *iface, const Array& params, bool fHelp);
extern Value rpc_wallet_setkeyphrase(CIface *iface, const Array& params, bool fHelp);
extern Value rpc_wallet_burn(CIface *iface, const Array& params, bool fStratum); 

const RPCOp WALLET_CSEND = {
  &rpc_wallet_csend, 4, {RPC_ACCOUNT, RPC_COINADDR, RPC_DOUBLE, RPC_STRING},
  "Syntax: <account> <address> <value> <cert-hash>\n"
  "Summary: Send a certified coin transaction."
};

const RPCOp WALLET_BURN = {
  &rpc_wallet_burn, 2, {RPC_ACCOUNT, RPC_DOUBLE},
  "Syntax: <account> <value>\n"
  "Summary: Send coins to a null destination.\n"
  "Params: [ <account> The coin account name., <value> The coin value to burn. ]\n"
  "\n"
  "Burnt coins are no longer accessible on the blockchain once sent. The maximum burn value in a single transaction is 1000 coins."
};

const RPCOp WALLET_DONATE = {
  &rpc_wallet_donate, 2, {RPC_ACCOUNT, RPC_DOUBLE, RPC_STRING},
  "Syntax: <account> <value> [<cert-hash>]\n"
  "Summary: Donate coins as a block transaction fee identified by the specified certificate.\n"
  "Params: [ <account> The coin account name., <value> The coin value to donate, <cert-hash> The associated certificate's hash. ]\n"
  "\n"
  "Donated coins are added to the upcoming block reward. Donations may be optionally associated with a certificate. The maximum donation value in a single transaction is 1000 coins."
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

const RPCOp WALLET_GETACCALIAS = {
  &rpc_wallet_getaccalias, 1, {RPC_ACCOUNT},
  "Syntax: <account>\n"
	"Get the default certificate for the given account name."
};

const RPCOp WALLET_SETACCALIAS = {
  &rpc_wallet_setaccalias, 2, {RPC_ACCOUNT, RPC_STRING},
  "Syntax: <account> <cert-hash>\n"
	"Set the default certificate for the given account name."
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
const RPCOp ALIAS_SETADDR = {
  &rpc_alias_pubaddr, 1, {RPC_STRING, RPC_STRING},
  "Syntax: <name> [<coin-address>]\n"
  "Summary: Generate, transfer, or obtain a published coin-address alias.\n"
  "Params: [ <name> The alias's label, <coin-address> The alias's referenced coin address. ]\n"
  "When a coin address is specified the alias label will be published onto the block chain in reference. If the alias label already exists, then a transfer will occur providing you are the original owner.\n"
	"If the coin-address is not specified for an existing alias, then the alias will be regenerated and the expiration time will be refreshed."
};
const RPCOp ALIAS_REMOVE = {
  &rpc_alias_remove, 1, {RPC_STRING},//, RPC_ACCOUNT},
  "Syntax: <name>\n"
  "Summary: Removed a published alias.\n"
  "Params: [ <name> The alias's label. ]\n"
  "Removes a published alias from the block-chain."
//	The alias owner's account is verified [when an account specification is warranted]."
};
const RPCOp ALIAS_GET = {
  &rpc_alias_get, 1, {RPC_STRING},
  "Syntax: <alias-hash>\n"
  "Summary: Obtain specific information about an alias.\n"
  "Params: [ <alias-hash> The alias hash being referenced. ]\n"
  "\n"
  "Print indepth information about a particular alias."
};
const RPCOp ALIAS_GETADDR = {
  &rpc_alias_getaddr, 1, {RPC_STRING},
  "Syntax: <name>\n"
  "Summary: Obtain specific information about an alias.\n"
  "Params: [ <name> The alias label being referenced. ]\n"
  "\n"
  "Print indepth information about a particular alias based on it's label."
};
const RPCOp ALIAS_LISTADDR = {
  &rpc_alias_listaddr, 0, {RPC_STRING},
  "Syntax: [<keyword>]\n"
  "List all published aliases with optional keyword filter."
};
const RPCOp ALIAS_EXPORT = {
  &rpc_alias_export, 1, {RPC_ACCOUNT},
  "Syntax: <account>\n"
  "Summary: Export an account's published alias(es).\n"
  "Params: [ <account> the account to export from. ]\n"
  "Exports neccessary walet keys for published aliases(es) associated with an account."
};



/* ext tx; certificate */
const RPCOp CERT_EXPORTHASH = {
  &rpc_cert_export_hash, 1, {RPC_STRING},
  "Syntax: <cert-hash>\n"
  "Summary: Export the credentials neccessary to own a certificate.\n"
  "Params: [ <cert-hash> The certificate's reference hash. ]\n"
  "\n"
  "Ownership and management of a certificate depends on having specific coin address key(s) in the coin wallet. Exporting a certificate provides JSON formatted content which can be used with \"wallet.import\" command to attain ownership of a certificate."
};
const RPCOp CERT_EXPORT = {
  &rpc_cert_export, 1, {RPC_ACCOUNT},
  "Syntax: <account>\n"
  "Summary: Export the certificate credentials associated with an account.\n"
  "Params: [ <acount> The account to export certificate(s) for. ]\n"
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
  "Write the specified context's data to the path specified."
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
  "Syntax: <email>\n"
  "Print profile information for a given email ID."
};

const RPCOp CTX_SETID = {
  &rpc_ctx_setid, 3, {RPC_ACCOUNT, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING},
  "Syntax: <account> <email> <password> [<param>=<value>]\n"
  "Params: [ <account> The account to associate with the context, <email> An email address, <password> A unique passphrase, [<param>] One or more of the parameters specified below. ]\n"
  "\n"
  "Set profile information for a given email address ID.\n"
	"\n"
	"Parameters: (optional)\n"
	"\tbirthdate\tYear of birth.\n"
	"\tcountry\t\tA country code (\"US\") referencing residence.\n"
	"\tgender\t\tA 'M' for male or 'F' for female.\n"
	"\tgeo\t\tA \"<lat>,<lon>\" referencing a general location.\n"
	"\tname\t\tAn organization or real person name.\n"
	"\tnickname\tAn alternate personal name.\n"
	"\twebsite\t\tAn associated web site.\n"
	"\tzipcode\t\tA postal zipcode.\n"
	"\tzoneinfo\tA timezone locale (\"America/Denver\")\n"
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

const RPCOp EXEC_COMPILE = {
	&rpc_exec_compile, 1, {RPC_STRING},
  "Syntax: <path>]\n"
  "Params: [ <path> The file path of a main LUA file. ]\n"
//  "Params: [ <exec-hash> A pre-existing execution script dependency. ]\n"
	"\n"
	" Compile a SEXE executable class from source code.\n"
//	"	Specifying a LUA file will result in the all \"*.lua\" files in the same directory being compiled into a SEXE executable.\n"
//	"\n"
//	"	Note: An pre-existing executable can be added as a depdency.\n"
};

const RPCOp EXEC_FEE = {
  &rpc_exec_fee, 0, {RPC_INT},
  "Syntax: [<exec-size>]\n"
  "Summary: Obtain the coin fee to create a executable transaction.\n"
  "Params: [ <exec-size> The size of the proposed executable. ]\n"
  "\n"
  "A context transaction essentially consists of a hashed name, a binary segment value, and an expiration date.\n"
  "The context operation fee is based on the current block-chain height and the size of the underlying context value.\n"
  "When a executable size is not specified, the maximum size \"780000\" will be used."
};

const RPCOp EXEC_GET = {
  &rpc_exec_get, 1, {RPC_STRING},
  "Syntax: <exec-hash>\n"
  "Summary: Obtain information about a particular executable on the block-chain.\n"
  "\n"
  "Obtains detailed information, and the user data associated with, a SEXE executable stored on the block chain.\n"
};

const RPCOp EXEC_INFO = {
  &rpc_exec_info, 0, {},
  "Summary: Obtain general information about all executables.\n"
  "\n"
  "Obtains general information about all executable stored on the block-chain."
};

const RPCOp EXEC_LIST = {
  &rpc_exec_list, 1, {RPC_STRING},
  "Syntax: <keyword>\n"
  "Summary: Obtain general information about executables.\n"
  "\n"
  "Obtains general information about all executable names that match the given keyword."
};

const RPCOp EXEC_NEW = {
	&rpc_exec_new, 2, {RPC_ACCOUNT, RPC_STRING},
  "Syntax: <account> <path>\n"
  "Params: [ <path> The file path of a SX file. ]\n"
	"\n"
	" Create a new executable class on the block-chain.\n"
	"\n"
	"	Note: See https://sharelib.net/sexe/ for more information on creating SEXE executable classes.\n"
};

const RPCOp EXEC_RUN = {
  &rpc_exec_run, 3, {RPC_ACCOUNT, RPC_DOUBLE, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING},
  "Syntax: <account> <fee> <class>.<func> [<arg>, [..]]\n"
  "Summary: Run a method in a published SEXE class.\n"
  "\n"
  "Run a method from a published SEXE class with the specified fee."
	"\n"
	"Note: A minimum transaction fee is required for all methods which result in writing to the block-chain.\n"
};

const RPCOp EXEC_RESET = {
  &rpc_exec_reset, 1, {RPC_STRING},
  "Syntax: <class>\n"
  "Summary: Reset the local run-time of a published executable.\n"
  "\n"
  "Rewews an call execution chain for a particular sexe class."
};

const RPCOp EXEC_HISTORY = {
  &rpc_exec_history, 1, {RPC_STRING},
  "Syntax: <class>\n"
  "Summary: Display the call execution chain for a particular sexe class.\n"
  "\n"
  "Rewews an call execution chain for a particular sexe class."
};

#if 0
const RPCOp EXEC_RENEW = {
  &rpc_exec_renew, 1, {RPC_STRING},
  "Syntax: <class>\n"
  "Summary: Rewew a published executable.\n"
  "\n"
  "Rewews an existing class's expiration date. A renewed executable class will expire after 5 years.\n"
	"\n"
  "Note: Only the current owner may renew a SEXE class."
};
#endif

#if 0
const RPCOp EXEC_TRANSFER = {
  &rpc_exec_transfer, 2, {RPC_STRING, RPC_COINADDR},
  "Syntax: <class> <addr>\n"
  "Summary: Transfer ownership of a executable class.\n"
  "\n"
  "Transfers ownership to a new address.\n"
	"\n"
  "Note: Only the current owner may renew a SEXE class."
};
#endif


const RPCOp ASSET_FEE = {
  &rpc_asset_fee, 0, {RPC_INT},
  "Summary: Display fee information for generating an asset.\n"
  "\n"
  "Print fee information for an asset."
};
const RPCOp ASSET_GET = {
  &rpc_asset_get, 1, {RPC_STRING},
  "Summary: Display information about an asset.\n"
  "\n"
  "Print detailed information about a particular asset."
};
const RPCOp ASSET_INFO = {
  &rpc_asset_info, 0, {},
  "Summary: Display information about asset transactions.\n"
  "\n"
  "Show general information about certified assets."
};
const RPCOp ASSET_LIST = {
  &rpc_asset_list, 0, {RPC_STRING},
  "Syntax: [<kwd>]\n"
  "Summary: List assets information.\n"
  "\n"
  "List all assets on blockchain with keyword substring match."
};
const RPCOp ASSET_LISTACC = {
  &rpc_asset_list, 1, {RPC_ACCOUNT},
  "Syntax: <account>\n"
  "Summary: List assets information for account.\n"
  "\n"
  "List all assets on blockchain with with account association."
};
const RPCOp ASSET_LISTCERT = {
  &rpc_asset_listcert, 1, {RPC_STRING},
  "Syntax: <cert>\n"
  "Summary: List assets information for certificate.\n"
  "\n"
  "List all assets on blockchain certified by specified certificate hash."
};
const RPCOp ASSET_NEW = {
  &rpc_asset_new, 5, {RPC_ACCOUNT, RPC_STRING, RPC_INT, RPC_INT, RPC_STRING, RPC_INT64},
  "Syntax: <account> <cert> <type> <subtype> <data> [<fee>]\n"
  "Summary: Create a certified asset.\n"
  "\n"
	"Generate a certified digital asset.\n"
	"\n"
	"Note: See commands 'asset.type' and 'asset.subtype' for applicable <type> and <subtype> parameter values."
};
const RPCOp ASSET_NEWCERT = {
  &rpc_asset_newcert, 2, {RPC_ACCOUNT, RPC_STRING, RPC_STRING},
  "Syntax: <account> <label> [<cert>]\n"
  "Summary: Create a certified asset.\n"
  "\n"
  "Submit a new asset transaction onto the blockchain."
};
const RPCOp ASSET_REMOVE = {
  &rpc_asset_remove, 2, {RPC_ACCOUNT, RPC_STRING},
  "Syntax: <account> <asset>\n"
  "Summary: Remove a certified asset.\n"
  "\n"
  "Remove an asset from the blockchain."
};
const RPCOp ASSET_ACTIVATE = { /* asset.renew */
  &rpc_asset_activate, 2, {RPC_ACCOUNT, RPC_STRING},
  "Syntax: <account> <asset>\n"
  "Summary: Renew an existing asset.\n"
  "\n"
  "Renew the expiration time-span of an asset on the blockchain."
};
const RPCOp ASSET_TRANSFER = {
  &rpc_asset_transfer, 3, {RPC_ACCOUNT, RPC_STRING, RPC_COINADDR},
  "Syntax: <account> <asset> <address>\n"
  "Summary: Transfer an existing asset to a destination extended transaction address.\n"
  "\n"
  "Transfer an asset on the blockchain."
};
const RPCOp ASSET_UPDATE = {
  &rpc_asset_update, 4, {RPC_ACCOUNT, RPC_STRING, RPC_STRING},
  "Syntax: <account> <asset> <data>\n"
  "Summary: Update an existing asset.\n"
  "\n"
  "Update information for an asset on the blockchain."
};
const RPCOp ASSET_EXPORT = {
  &rpc_asset_export, 1, {RPC_ACCOUNT},
  "Syntax: <account>\n"
  "Summary: Export an account's published asset(es).\n"
  "Params: [ <account> the account to export from. ]\n"
  "Exports neccessary walet keys for published asset(es) associated with an account."
};

const RPCOp OFFER_NEW = {
  &rpc_offer_new, 2, {RPC_ACCOUNT, RPC_STRING},
  "Syntax: <account> <color> <min-value> <max-value> <rate>\n"
  "Summary: Create a new exchange offer.\n"
  "\n"
  "Offer to send between <min-value> and <max-value> SHC in exchange for that value multiplied by <rate> of the specified color coins."
};
const RPCOp OFFER_ACCEPT = {
  &rpc_offer_accept, 3, {RPC_ACCOUNT, RPC_STRING, RPC_DOUBLE},
  "Syntax: <account> <offer> <value>\n"
  "Summary: Accept an exchange offer.\n"
  "\n"
  "Accept an offer to receive <value> SHC in exchange for sending a pre-determined <rate> of color coins."
};
const RPCOp OFFER_COMMIT = {
  &rpc_offer_commit, 2, {RPC_ACCOUNT, RPC_STRING},
  "Syntax: <account> <offer>\n"
  "Summary: Complete an offer exchange.\n"
  "\n"
  "Confirm a offer that has been accepted."
};
const RPCOp OFFER_CANCEL = {
  &rpc_offer_cancel, 2, {RPC_ACCOUNT, RPC_STRING},
  "Syntax: <account> <offer>\n"
  "Summary: Cancel an offer exchange.\n"
  "\n"
  "Cancel an active offer before it is accepted."
};
const RPCOp OFFER_INFO = {
  &rpc_offer_info, 0, {},
  "Summary: General offer exchange transaction information."
};
const RPCOp OFFER_LIST = {
  &rpc_offer_list, 2, {RPC_ACCOUNT, RPC_STRING},
  "Syntax: <account> <color>\n"
  "Summary: List available exchange offers that have not been accepted."
};
const RPCOp OFFER_STATUS = {
  &rpc_offer_status, 1, {RPC_ACCOUNT, RPC_INT64},
  "Syntax: <account> [<start-time>]\n"
  "Summary: List the pending and completed exchanges for an account.\n"
};

const RPCOp PARAM_LIST = {
	&rpc_param_list, 0, {RPC_BOOL},
  "Syntax: [<verbose>]\n"
	"Summary: List all active dynamic blockchain param transactions."
};

const RPCOp PARAM_VALUE = {
	&rpc_param_value, 1, {RPC_STRING},
	"Summary: Get info about a particular dynamic blockchain parameter mode.\n"
	"Valid modes are: \"blocksize\" or \"minfee\"."
};

const RPCOp PARAM_GET = {
	&rpc_param_get, 1, {RPC_STRING},
  "Syntax: <param-hash>\n"
	"Summary: Get info about a particular param transaction."
};

void shc_RegisterRPCOp(int ifaceIndex)
{

  RegisterRPCOpDefaults(ifaceIndex);

//  Note: Alias hash is not currently shown to user or used as input param.

  RegisterRPCOp(ifaceIndex, "alias.export", ALIAS_EXPORT);
  RegisterRPCOp(ifaceIndex, "alias.fee", ALIAS_FEE);
  RegisterRPCOp(ifaceIndex, "alias.get", ALIAS_GET);
  RegisterRPCOp(ifaceIndex, "alias.getaddr", ALIAS_GETADDR);
  RegisterRPCOp(ifaceIndex, "alias.info", ALIAS_INFO);
  RegisterRPCOp(ifaceIndex, "alias.listaddr", ALIAS_LISTADDR);
  RegisterRPCOp(ifaceIndex, "alias.setaddr", ALIAS_SETADDR);
  RegisterRPCOp(ifaceIndex, "alias.remove", ALIAS_REMOVE);

	RegisterRPCOp(ifaceIndex, "asset.fee", ASSET_FEE);
	RegisterRPCOp(ifaceIndex, "asset.get", ASSET_GET);
	RegisterRPCOp(ifaceIndex, "asset.export", ASSET_EXPORT);
	RegisterRPCOp(ifaceIndex, "asset.info", ASSET_INFO);
	RegisterRPCOp(ifaceIndex, "asset.list", ASSET_LIST);
	RegisterRPCOp(ifaceIndex, "asset.listacc", ASSET_LISTACC);
	RegisterRPCOp(ifaceIndex, "asset.listcert", ASSET_LISTCERT);
	RegisterRPCOp(ifaceIndex, "asset.new", ASSET_NEW);
	RegisterRPCOp(ifaceIndex, "asset.newcert", ASSET_NEWCERT);
	RegisterRPCOp(ifaceIndex, "asset.remove", ASSET_REMOVE);
	RegisterRPCOp(ifaceIndex, "asset.renew", ASSET_ACTIVATE);
	RegisterRPCOp(ifaceIndex, "asset.send", ASSET_TRANSFER);
	RegisterRPCOp(ifaceIndex, "asset.update", ASSET_UPDATE);

  RegisterRPCOp(ifaceIndex, "cert.export", CERT_EXPORT);
  RegisterRPCOp(ifaceIndex, "cert.exporthash", CERT_EXPORTHASH);
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
//  RegisterRPCOp(ifaceIndex, "ctx.export", CTX_EXPORT);

#ifdef USE_SEXE
  RegisterRPCOp(ifaceIndex, "exec.compile", EXEC_COMPILE);
  RegisterRPCOp(ifaceIndex, "exec.fee", EXEC_FEE);
  RegisterRPCOp(ifaceIndex, "exec.get", EXEC_GET);
  RegisterRPCOp(ifaceIndex, "exec.info", EXEC_INFO);
  RegisterRPCOp(ifaceIndex, "exec.list", EXEC_LIST);
//  RegisterRPCOp(ifaceIndex, "exec.pay", EXEC_PAY);
  RegisterRPCOp(ifaceIndex, "exec.new", EXEC_NEW);
//  RegisterRPCOp(ifaceIndex, "exec.renew", EXEC_RENEW);
  RegisterRPCOp(ifaceIndex, "exec.reset", EXEC_RESET);
  RegisterRPCOp(ifaceIndex, "exec.run", EXEC_RUN);
//  RegisterRPCOp(ifaceIndex, "exec.transfer", EXEC_TRANSFER);

//  RegisterRPCOp(ifaceIndex, "exec.export", EXEC_EXPORT);
#endif

	RegisterRPCOp(ifaceIndex, "offer.new", OFFER_NEW);
	RegisterRPCOp(ifaceIndex, "offer.accept", OFFER_ACCEPT);
	RegisterRPCOp(ifaceIndex, "offer.commit", OFFER_COMMIT);
	RegisterRPCOp(ifaceIndex, "offer.cancel", OFFER_CANCEL);
	RegisterRPCOp(ifaceIndex, "offer.info", OFFER_INFO);
	RegisterRPCOp(ifaceIndex, "offer.list", OFFER_LIST);
	RegisterRPCOp(ifaceIndex, "offer.status", OFFER_STATUS);

	RegisterRPCOp(ifaceIndex, "param.list", PARAM_LIST);
	RegisterRPCOp(ifaceIndex, "param.value", PARAM_VALUE);
	RegisterRPCOp(ifaceIndex, "param.get", PARAM_GET);

	RegisterRPCOp(ifaceIndex, "wallet.burn", WALLET_BURN);
  RegisterRPCOp(ifaceIndex, "wallet.csend", WALLET_CSEND);
  RegisterRPCOp(ifaceIndex, "wallet.donate", WALLET_DONATE);
  RegisterRPCOp(ifaceIndex, "wallet.keyphrase", WALLET_KEYPHRASE);
  RegisterRPCOp(ifaceIndex, "wallet.setkeyphrase", WALLET_SETKEYPHRASE);
  RegisterRPCOp(ifaceIndex, "wallet.stamp", WALLET_STAMP);


#if 0
	/* no supporting functionality to utilize 'default cert for account'. */
  RegisterRPCOp(ifaceIndex, "wallet.getaccalias", WALLET_GETACCALIAS);
  RegisterRPCOp(ifaceIndex, "wallet.setaccalias", WALLET_SETACCALIAS);
#endif

}

