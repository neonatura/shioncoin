
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

#include "shcoind.h"
#include "net.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "chain.h"
#include "certificate.h"
#include "rpc_proto.h"
#include "rpccolor_proto.h"


using namespace std;
using namespace boost;


const RPCOp ALT_ADDR = {
  &rpc_alt_addr, 1, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: <name|color-hex> [<account>]\n"
  "Summary: Obtain a alt-chain coin address.\n"
  "\n"
  "Create a new coin address suitable for receiving coins on an alternate block-chain."
};

const RPCOp ALT_ADDRLIST = {
  &rpc_alt_addrlist, 1, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: <name|color-hex> [<account>]\n"
  "Summary: Obtain a list of alt-chain coin addresses.\n"
  "\n"
  "List all local coin addresses associated with a alternate block-chain."
};

const RPCOp ALT_SEND = {
  &rpc_alt_send, 3, {RPC_STRING, RPC_STRING, RPC_DOUBLE, RPC_ACCOUNT},
  "Syntax: <name|color-hex> <dest addr> <value> [<account>]\n"
  "Summary: Sends coins to a destination on an alternate block-chain.\n"
  "\n"
  "Transfers coins to a destination address of a particular alternate block-chain.\n"
	"\n"
	"Note: Each color is a seperate chain, and therefore coins can not be sent from one color to another with this command.\n"
	"Note: A 0.001 tx-fee will be charged [on the main block-chain] in order to create an alt-chain block."
};

const RPCOp ALT_INFO = {
  &rpc_alt_info, 1, {RPC_STRING},
  "Syntax: <name|color-hex>\n"
  "Summary: General information about an alternate block-chain.\n"
  "\n"
  "Obtain general information about the state of a colored alternate block-chain."
};

const RPCOp ALT_COLOR = {
  &rpc_alt_color, 1, {RPC_STRING},
  "Syntax: <name>\n"
  "Summary: Information about a colored alternate block-chain."
  "\n"
  "Obtains the color hex code and color description for a given alternate block-chain name."
};

const RPCOp ALT_COMMIT = {
  &rpc_alt_color, 1, {RPC_STRING, RPC_STRING},
  "Syntax: <block data> [<coinbase>]\n"
  "Summary: Process a pre-formed block onto an alternate block-chain.\n"
  "\n"
  "Create a block on an alternate block chain with the specified block content."
};

const RPCOp ALT_BALANCE = {
  &rpc_alt_balance, 0, {RPC_STRING, RPC_ACCOUNT, RPC_INT},
  "Syntax: [<name|color-hex>] [<account>] [<depth>]\n"
  "Summary: The coin balance on an alternate block-chain.\n"
  "\n"
  "Calculate the total balance available for a particular alternate block-chain."
};

const RPCOp ALT_MINE = {
  &rpc_alt_mine, 1, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: <name|color-hex> [<account>]\n"
  "Summary: Generate a coinbase block on an alternate block-chain.\n"
  "\n"
  "Uses the built-in CPU miner in order to generate a block on an alternate block-chain. A genesis block will be created for the first block of each color.\n"
	"\n"
	"Note: A minimal tx-fee will be charged [on the main block-chain] in order to create an alt-chain block."
};
const RPCOp ALT_NEW = {
  &rpc_alt_new, 1, {RPC_STRING, RPC_ACCOUNT, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING, RPC_STRING},
  "Syntax: <name|color-hex> [<account>] [option=value]..\n"
  "Summary: Generate a genesis block for a new alternate block-chain.\n"
	"Options:\n"
	"\tdifficulty=<1-8>\n"
	"\t\tA lower number indicates a lower minimum block difficulty.\n"
	"\tblocktarget=<1-15>\n"
	"\t\tThe number of minutes to set the block difficulty target.\n"
	"\tmaturity=<1-8>\n"
	"\t\tThe number of blocks for a coinbase to mature in 60-block intervals.\n"
	"\t\tFor example: A 7 value would indicate (7*60=) 420 block maturity.\n" 
	"\trewardbase=<1-10>\n"
	"\t\tThe base value for calculating a block reward (2 ^ <value>).\n"
	"\t\tFor example: A 7 value would indicate (2^7=) 128 coins.\n"
	"\trewardhalf=<1-10>\n"
	"\t\tThe number of blocks to half the reward in 1000 increments.\n"
	"\ttxfee=<1-8>\n"
	"\t\tThe txfee of X, where X is (10 ^ (X+1)) / COIN.\n"
	"\t\tFor example: A 7 value would indicate ((10^7)/COIN=) 1 coins.\n"
  "\n"
	"Note: A minimal tx-fee will be charged [on the main block-chain] in order to create an alt-chain block."
};

const RPCOp ALT_BLOCK = {
  &rpc_alt_block, 1, {RPC_STRING},
  "Syntax: <block-hash>\n"
  "Summary: Print information about an alt-chain block."
};

const RPCOp ALT_TX = {
  &rpc_alt_tx, 1, {RPC_STRING},
  "Syntax: <tx-hash>\n"
  "Summary: Print information about an alt-chain transaction."
};

const RPCOp ALT_KEY = {
  &rpc_alt_key, 1, {RPC_COINADDR},
  "Syntax: <coin-addr>\n"
  "Summary: Print the private key of a colored coin address."
};

const RPCOp ALT_SETKEY = {
  &rpc_alt_setkey, 1, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: <coin-addr> [<account>]\n"
  "Summary: Print the private key of a colored coin address."
};

const RPCOp ALT_UNSPENT = {
  &rpc_alt_unspent, 1, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: <color> [<account>]\n"
  "Summary: Print the unspent transaction associated with a colored alt-chain."
};


void color_RegisterRPCOp(int ifaceIndex)
{

  RegisterRPCOp(ifaceIndex, "alt.addr", ALT_ADDR);
  RegisterRPCOp(ifaceIndex, "alt.addrlist", ALT_ADDRLIST);
  RegisterRPCOp(ifaceIndex, "alt.balance", ALT_BALANCE);
  RegisterRPCOp(ifaceIndex, "alt.block", ALT_BLOCK);
  RegisterRPCOp(ifaceIndex, "alt.color", ALT_COLOR);
	/* add "alt.work" to dispense block template and coinbase (first tx) hex 
  RegisterRPCOp(ifaceIndex, "alt.commit", ALT_COMMIT);
	 */
  RegisterRPCOp(ifaceIndex, "alt.info", ALT_INFO);
  RegisterRPCOp(ifaceIndex, "alt.key", ALT_KEY);
  RegisterRPCOp(ifaceIndex, "alt.mine", ALT_MINE);
  RegisterRPCOp(ifaceIndex, "alt.new", ALT_NEW);
  RegisterRPCOp(ifaceIndex, "alt.send", ALT_SEND);
  RegisterRPCOp(ifaceIndex, "alt.setkey", ALT_SETKEY);
  RegisterRPCOp(ifaceIndex, "alt.tx", ALT_TX);
  RegisterRPCOp(ifaceIndex, "alt.unspent", ALT_UNSPENT);

}

