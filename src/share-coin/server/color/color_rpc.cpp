
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
#include "rpccolor_proto.h"


using namespace std;
using namespace boost;


const RPCOp ALT_ADDR = {
  &rpc_alt_addr, 1, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: <name|color-hex> [account]\n"
  "Summary: Obtain a alt-chain coin address.\n"
  "\n"
  "Create a new coin address suitable for receiving coins on an alternate block-chain."
};

const RPCOp ALT_ADDRLIST = {
  &rpc_alt_addrlist, 1, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: <name|color-hex> [account]\n"
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
  &rpc_alt_balance, 1, {RPC_STRING},
  "Syntax: <name|color-hex>\n"
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
	"Note: A 0.001 tx-fee will be charged [on the main block-chain] in order to create an alt-chain block."
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
  RegisterRPCOp(ifaceIndex, "alt.mine", ALT_MINE);
  RegisterRPCOp(ifaceIndex, "alt.send", ALT_SEND);
  RegisterRPCOp(ifaceIndex, "alt.tx", ALT_TX);

}

