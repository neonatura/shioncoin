
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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
#include "block.h"
#include "main.h"
#include "wallet.h"
#include "coin_proto.h"
#include "testnet/testnet_netmsg.h"
#include "testnet/testnet_pool.h"
#include "testnet/testnet_block.h"
#include "testnet/testnet_wallet.h"
#include "testnet/testnet_txidx.h"

TESTNET_CTxMemPool TESTNETBlock::mempool;
CBlockIndex *TESTNETBlock::pindexGenesisBlock = NULL;
int64 TESTNETBlock::nTimeBestReceived;
CBigNum TESTNETBlock::bnBestChainWork;
CBigNum TESTNETBlock::bnBestInvalidWork;




extern void shc_RegisterRPCOp(int ifaceIndex);


static int testnet_init(CIface *iface, void *_unused_)
{
  int ifaceIndex = GetCoinIndex(iface);
  int err;

  iface->nRuleChangeActivationThreshold = 9072;
  iface->nMinerConfirmationWindow = 12096;

	iface->vDeployments[DEPLOYMENT_TESTDUMMY].bit = 28;
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nStartTime = 1524960000; /* 04/29/18 */
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nTimeout = 1530230400; /* 06/29/18 */ 

	/* BIP68, BIP112, and BIP113 */
	iface->vDeployments[DEPLOYMENT_CSV].bit = 0;
	iface->vDeployments[DEPLOYMENT_CSV].nStartTime = 1530403200; /* 07/01/18 */
	iface->vDeployments[DEPLOYMENT_CSV].nTimeout = 1535760000; /* 09/01/18 */

	/* BIP141, BIP143, and BIP147 */
	iface->vDeployments[DEPLOYMENT_SEGWIT].bit = 1;
	iface->vDeployments[DEPLOYMENT_SEGWIT].nStartTime = 1538352000; /* 10/01/18 */
	iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout = 1546300800; /* 01/01/19 */ 


  shc_RegisterRPCOp(TESTNET_COIN_IFACE);

  testnetWallet = new TESTNETWallet();
  SetWallet(TESTNET_COIN_IFACE, testnetWallet);


	/* normal startup */
	if (!testnet_InitBlockIndex()) {
		error(SHERR_INVAL, "testnet_proto: unable to initialize block index table.");
		return (SHERR_INVAL);
	}

  if (!testnet_LoadWallet()) {
    error(SHERR_INVAL, "testnet_proto: unable to open load wallet.");
    return (SHERR_INVAL);
  }

  Debug("initialized TESTNET block-chain.");

  return (0);
}

static int testnet_bind(CIface *iface, void *_unused_)
{
  int err;

  err = unet_bind(UNET_TESTNET, opt_num(OPT_TESTNET_PORT), NULL);
  if (err) {
    error(err, "error binding TESTNET socket port");
    return (err);
  }

  unet_timer_set(UNET_TESTNET, testnet_server_timer); /* x10/s */
  unet_connop_set(UNET_TESTNET, testnet_server_accept);
  unet_disconnop_set(UNET_TESTNET, testnet_server_close);

  /* automatically connect to peers of 'testnet' service. */
  unet_bind_flag_set(UNET_TESTNET, UNETF_PEER_SCAN);

  Debug("initialized TESTNET service on port %d.", (int)iface->port);

  return (0);
}

static int testnet_term(CIface *iface, void *_unused_)
{
#if 0
  CWallet *wallet = GetWallet(iface);
  if (wallet) {
    UnregisterWallet(wallet);
   }
#endif
  SetWallet(iface, NULL);
}
static int testnet_msg_recv(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!testnet_ProcessMessages(iface, pnode)) {
    /* log */
  }

return (0);
}
static int testnet_msg_send(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!testnet_SendMessages(iface, pnode, false)) {
    /* log */
  }

return (0);
}
static int testnet_peer_add(CIface *iface, void *arg)
{
return (0);
}
static int testnet_peer_recv(CIface *iface, void *arg)
{
return (0);
}

static int testnet_block_new(CIface *iface, CBlock **block_p)
{
  *block_p = new TESTNETBlock();
  return (0);
}

static int testnet_block_process(CIface *iface, CBlock *block)
{

  if (!testnet_ProcessBlock(block->originPeer, block))
    return (SHERR_INVAL);

  return (0);
}

static CPubKey testnet_GetMainAccountPubKey(CWallet *wallet)
{
  static CPubKey ret_key;

  if (!ret_key.IsValid()) {
    string strAccount("");
    GetAccountAddress(wallet, strAccount, false);

    ret_key = GetAccountPubKey(wallet, strAccount);
    if (!ret_key.IsValid()) {
      error(SHERR_INVAL, "(testnet) GetMainAccountPubKey: error obtaining main account pubkey.");
      CReserveKey reservekey(wallet);
      ret_key = reservekey.GetReservedKey();
      reservekey.KeepKey();
    } else {
      CCoinAddr addr(wallet->ifaceIndex, ret_key.GetID()); 
      Debug("(testnet) GetMainAccountPubKey: using '%s' for mining address.",
          addr.ToString().c_str()); 
    }

    /* mining pool fees */
    string strBankAccount("bank");
    GetAccountAddress(wallet, strBankAccount, false);
    /* cpu miner */
    string strSystemAccount("system");
    GetAccountAddress(wallet, strSystemAccount, false);
  }

  return (ret_key);
}

static int testnet_block_templ(CIface *iface, CBlock **block_p)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CBlock* pblock;
  string strAccount("");
  unsigned int median;
  int reset;
    
  if (!wallet) {
    unet_log(ifaceIndex, "GetBlocKTemplate: Wallet not initialized.");
    return (NULL);
  }

  CBlockIndex *pindexBest = GetBestBlockIndex(TESTNET_COIN_IFACE);
  median = pindexBest->GetMedianTimePast() + 1;

  const CPubKey& pubkey = testnet_GetMainAccountPubKey(wallet);
  if (!pubkey.IsValid()) {
error(SHERR_INVAL, "testnet_block_templ: error obtaining main pubkey.\n");
    return (NULL);
  }

  pblock = testnet_CreateNewBlock(pubkey);
  if (!pblock)
    return (NULL);

  pblock->nTime = MAX(median, GetAdjustedTime());
  pblock->nNonce = 0;

  *block_p = pblock;

  return (0);
}

#if 0
static int testnet_block_submit(CIface *iface, CBlock *block)
{
  blkidx_t *blockIndex;

  blockIndex = GetBlockTable(TESTNET_COIN_IFACE);
  if (!blockIndex)
    return (STERR_INVAL);

  // Check for duplicate
  uint256 hash = block->GetHash();
  if (blockIndex->count(hash))// || mapOrphanBlocks.count(hash))
    return (BLKERR_DUPLICATE_BLOCK);

  // Preliminary checks
  if (!block->CheckBlock()) {
    testnetoind_log("c_processblock: !CheckBlock()");
    return (BLKERR_CHECKPOINT);
  }

  // Store to disk
  if (!block->AcceptBlock()) {
    testnetoind_log("c_processblock: !AcceptBlock()");
    return (BLKERR_INVALID_BLOCK);
  }

  block->print();

return (0);
}
#endif

static int testnet_tx_new(CIface *iface, void *arg)
{
return (0);
}

static int testnet_tx_pool(CIface *iface, CTxMemPool **pool_p)
{
  *pool_p = &TESTNETBlock::mempool;
  return (0);
}








#ifdef __cplusplus
extern "C" {
#endif

coin_iface_t testnet_coin_iface = {
  "testnet",
  TRUE, /* enable */
  COIN_IFACE_VERSION(TESTNET_VERSION_MAJOR, TESTNET_VERSION_MINOR,
      TESTNET_VERSION_REVISION, TESTNET_VERSION_BUILD), /* cli ver */
  2, /* block version */
  TESTNET_PROTOCOL_VERSION, /* network proto ver */
  TESTNET_COIN_DAEMON_PORT,
  { 0x09, 0xd9, 0xf9, 0xbd },
  NODE_NETWORK | NODE_BLOOM,
  TESTNET_MIN_INPUT,
  TESTNET_MAX_BLOCK_SIZE,
  TESTNET_MAX_ORPHAN_TRANSACTIONS,
  TESTNET_MAX_TRANSACTION_WEIGHT,
  TESTNET_MIN_TX_FEE,
  TESTNET_MAX_TX_FEE,
  TESTNET_MAX_FREE_TX_SIZE,
  TESTNET_MAX_MONEY,
  TESTNET_COINBASE_MATURITY, 
  TESTNET_MAX_SIGOPS,
  COINF(testnet_init),
  COINF(testnet_bind),
  COINF(testnet_term),
  COINF(testnet_msg_recv),
  COINF(testnet_msg_send),
  COINF(testnet_peer_add),
  COINF(testnet_peer_recv),
  COINF(testnet_block_new),
  COINF(testnet_block_process),
  COINF(testnet_block_templ),
  COINF(testnet_tx_new),
  COINF(testnet_tx_pool)
};


#ifdef __cplusplus
}
#endif
