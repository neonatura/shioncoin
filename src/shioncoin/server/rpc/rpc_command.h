
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

#ifndef __SERVER__RPCCOMMAND_PROTO_H__
#define __SERVER__RPCCOMMAND_PROTO_H__



#include <string>
#include <list>
#include <map>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

Object JSONRPCError(int code, const string& message);
void RPCTypeCheck(const Array& params, const list<Value_type>& typesExpected);
void RPCTypeCheck(const Object& o, const map<string, Value_type>& typesExpected);
void WalletTxToJSON(int ifaceIndex, const CWalletTx& wtx, Object& entry);
void GetAccountAddresses(CWallet *wallet, string strAccount, set<CTxDestination>& setAddress);
Value GetNetworkHashPS(int ifaceIndex, int lookup);
void ListTransactions(int ifaceIndex, const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret);
double GetDifficulty(int ifaceIndex, const CBlockIndex* blockindex = NULL);
int64 AmountFromValue(const Value& value);

Value rpc_sys_shutdown(CIface *iface, const Array& params, bool fStratum);
Value rpc_sys_info(CIface *iface, const Array& params, bool fStratum);
Value rpc_sys_echo(CIface *iface, const Array& params, bool fStratum);
Value rpc_sys_config(CIface *iface, const Array& params, bool fStratum);
Value rpc_sys_url(CIface *iface, const Array& params, bool fStratum);

Value rpc_block_info(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_count(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_difficulty(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_export(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_free(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_get(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_hash(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_import(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_listsince(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_purge(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_verify(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_mine(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_work(CIface *iface, const Array& params, bool fStratum);
Value rpc_block_workex(CIface *iface, const Array& params, bool fStratum);

Value rpc_msg_sign(CIface *iface, const Array& params, bool fStratum);
Value rpc_msg_verify(CIface *iface, const Array& params, bool fStratum);
Value rpc_msg_info(CIface *iface, const Array& params, bool fStratum);

Value rpc_peer_info(CIface *iface, const Array& params, bool fStratum);
Value rpc_peer_hashps(CIface *iface, const Array& params, bool fStratum);
Value rpc_peer_add(CIface *iface, const Array& params, bool fStratum);
Value rpc_peer_count(CIface *iface, const Array& params, bool fStratum);
Value rpc_peer_import(CIface *iface, const Array& params, bool fStratum);
Value rpc_peer_importdat(CIface *iface, const Array& params, bool fStratum);
Value rpc_peer_list(CIface *iface, const Array& params, bool fStratum);
Value rpc_peer_export(CIface *iface, const Array& params, bool fStratum);
Value rpc_peer_remove(CIface *iface, const Array& params, bool fStratum);

Value rpc_stratum_keyadd(CIface *iface, const Array& params, bool fStratum);
Value rpc_stratum_info(CIface *iface, const Array& params, bool fStratum);
Value rpc_stratum_list(CIface *iface, const Array& params, bool fStratum);
Value rpc_stratum_key(CIface *iface, const Array& params, bool fStratum);
Value rpc_stratum_keyremove(CIface *iface, const Array& params, bool fStratum);

Value rpc_tx_decode(CIface *iface, const Array& params, bool fStratum);
Value rpc_tx_get(CIface *iface, const Array& params, bool fStratum);
Value rpc_tx_list(CIface *iface, const Array& params, bool fStratum);
Value rpc_tx_pool(CIface *iface, const Array& params, bool fStratum);
Value rpc_tx_prune(CIface *iface, const Array& params, bool fStratum);
Value rpc_tx_purge(CIface *iface, const Array& params, bool fStratum);
Value rpc_tx_validate(CIface *iface, const Array& params, bool fStratum);

Value rpc_wallet_addr(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_witaddr(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_addrlist(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_balance(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_export(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_exportdat(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_get(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_info(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_cscript(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_import(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_key(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_list(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_listbyaccount(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_listbyaddr(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_move(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_multisend(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_new(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_derive(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_recvbyaccount(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_recvbyaddr(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_verify(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_send(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_bsend(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_tsend(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_set(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_setkey(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_tx(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_unconfirm(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_unspent(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_spent(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_select(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_validate(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_keyadd(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_info(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_list(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_key(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_keyremove(CIface *iface, const Array& params, bool fStratum);
Value rpc_wallet_fee(CIface *iface, const Array& params, bool fStratum);



#endif /* ndef __SERVER__RPCCOMMAND_PROTO_H__ */

