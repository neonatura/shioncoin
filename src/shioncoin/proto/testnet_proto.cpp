
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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
#include "block.h"
#include "main.h"
#include "wallet.h"
#include "account.h"
#include "coin_proto.h"
#include "testnet/testnet_netmsg.h"
#include "testnet/testnet_pool.h"
#include "testnet/testnet_block.h"
#include "testnet/testnet_wallet.h"
#include "testnet/testnet_txidx.h"

#ifdef TESTNET_SERVICE
TESTNET_CTxMemPool TESTNETBlock::mempool;

CBlockIndex *TESTNETBlock::pindexGenesisBlock = NULL;

int64 TESTNETBlock::nTimeBestReceived;

extern void shc_RegisterRPCOp(int ifaceIndex);

extern void color_RegisterRPCOp(int ifaceIndex);
#endif

static int testnet_init(CIface *iface, void *_unused_)
{
#ifdef TESTNET_SERVICE
  int ifaceIndex = GetCoinIndex(iface);
  int err;

	/* P2SH */
	iface->BIP16Height = 1; 
	/* v2.0 block (height in coinbase) */
	iface->BIP30Height = 1;
	iface->BIP34Height = 1;
	/* OP_CHECLOCKTIMEVERIFY */
	iface->BIP65Height = 1;
	/* strict DER signature */
	iface->BIP66Height = 1;

	/* 75% of 1209 blocks. */ 
	iface->nRuleChangeActivationThreshold = 907;
	iface->nMinerConfirmationWindow = 1209;

	/* ACTIVE: BIP9 */
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].bit = 28;
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nStartTime = 1546300800; /* 01/01/19 */
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nTimeout = 1577836800; /* 01/01/20 */

	/* ACTIVE: BIP68, BIP112, and BIP113 */
	iface->vDeployments[DEPLOYMENT_CSV].bit = 0;
	iface->vDeployments[DEPLOYMENT_CSV].nStartTime = 1546300800; /* 01/01/19 */
	iface->vDeployments[DEPLOYMENT_CSV].nTimeout = 1577836800; /* 01/01/20 */

	/* ACTIVE: BIP141, BIP143, and BIP147 */
	iface->vDeployments[DEPLOYMENT_SEGWIT].bit = 1;
	iface->vDeployments[DEPLOYMENT_SEGWIT].nStartTime = 1546300800; /* 01/01/19 */
	iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout = 1577836800; /* 01/01/20 */

	/* ACTIVE: SIP32 */
	iface->vDeployments[DEPLOYMENT_ALGO].bit = 5;
	iface->vDeployments[DEPLOYMENT_ALGO].nStartTime = 1556409600; /* 04/27/19 */
	iface->vDeployments[DEPLOYMENT_ALGO].nTimeout = 1577836800; /* 01/01/20 */

	iface->vDeployments[DEPLOYMENT_PARAM].bit = 6;
	iface->vDeployments[DEPLOYMENT_PARAM].nStartTime = 1577836800; /* 01/01/20 */
	iface->vDeployments[DEPLOYMENT_PARAM].nTimeout = 1609459200; /* 01/01/21 */ 

  shc_RegisterRPCOp(TESTNET_COIN_IFACE);

	/* alternate block-chain rpc operations. */
  color_RegisterRPCOp(TESTNET_COIN_IFACE);

  testnetWallet = new TESTNETWallet();
	testnetWallet->checkpoints = new CCheckpoints(TESTNET_COIN_IFACE);
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
#endif

  return (0);
}

static int testnet_bind(CIface *iface, void *_unused_)
{
  int err;

	iface->port = opt_num(OPT_TESTNET_PORT);

  err = unet_bind(UNET_TESTNET, iface->port, NULL);
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
#ifdef TESTNET_SERVICE
  if (!pnode)
    return (0);

  if (!testnet_ProcessMessages(iface, pnode)) {
    /* log */
  }
#endif

	return (0);
}

static int testnet_msg_send(CIface *iface, CNode *pnode)
{
#ifdef TESTNET_SERVICE
  if (!pnode)
    return (0);

  if (!testnet_SendMessages(iface, pnode, false)) {
    /* log */
  }
#endif
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
#ifdef TESTNET_SERVICE
  *block_p = new TESTNETBlock();
  return (0);
#else
	return (ERR_OPNOTSUPP);
#endif
}

static int testnet_block_process(CIface *iface, CBlock *block)
{
#ifdef TESTNET_SERVICE
  if (!testnet_ProcessBlock(block->originPeer, block))
    return (SHERR_INVAL);
  return (0);
#else
	return (ERR_OPNOTSUPP);
#endif
}

static CPubKey testnet_GetMainAccountPubKey(CWallet *wallet)
{
#if 0
  static CPubKey ret_key;
	string strAccount("");

  if (!ret_key.IsValid()) {
		ret_key = GetAccountPubKey(wallet, strAccount, false);
    if (!ret_key.IsValid()) { /* fallback. */
			ret_key = wallet->GenerateNewECKey(true);
			wallet->SetAddressBookName(ret_key.GetID(), strAccount);
    }

		/* debug */
		CCoinAddr addr(wallet->ifaceIndex, ret_key.GetID()); 
		Debug("(testnet) getmainaccountpubkey: using '%s' for mining address.",
				addr.ToString().c_str()); 

    /* mining pool fees */
    string strBankAccount("bank");
    GetAccountAddress(wallet, strBankAccount, false);
    /* cpu miner */
    string strSystemAccount("system");
    GetAccountAddress(wallet, strSystemAccount, false);
	}

  return (ret_key);
#endif

  static CPubKey pubkey;
  if (!pubkey.IsValid()) {
    CAccountCache *account = wallet->GetAccount("");
    account->GetPrimaryPubKey(ACCADDR_MINER, pubkey);
    /* miner fee */
		wallet->GetAccount("bank");
    /* cpu miner */
		wallet->GetAccount("system");
  }
  return (pubkey);
}

static int testnet_block_templ(CIface *iface, CBlock **block_p)
{
#ifdef TESTNET_SERVICE
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
    return (-1);
  }

  pblock = testnet_CreateNewBlock(pubkey);
  if (!pblock)
    return (-1);

  pblock->nTime = MAX(median, GetAdjustedTime());
  pblock->nNonce = 0;

  *block_p = pblock;

  return (0);
#else
	return (ERR_OPNOTSUPP);
#endif
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
#ifdef TESTNET_SERVICE
  *pool_p = &TESTNETBlock::mempool;
  return (0);
#else
	return (ERR_OPNOTSUPP);
#endif
}








#ifdef __cplusplus
extern "C" {
#endif

coin_iface_t testnet_coin_iface = {
  "testnet",
  TRUE, /* enable */
  COIN_IFACE_VERSION(TESTNET_VERSION_MAJOR, TESTNET_VERSION_MINOR,
      TESTNET_VERSION_REVISION, TESTNET_VERSION_BUILD), /* cli ver */
  4, /* block version */
  TESTNET_PROTOCOL_VERSION, /* network proto ver */
  TESTNET_COIN_DAEMON_PORT,
	{ 0x09, 0xd9, 0xf9, 0xbd },
	65, /* T */
	5, /* 3 */
	25, /* A */
	193,
	{0x04, 0x88, 0xB2, 0x1E},
	{0x04, 0x88, 0xAD, 0xE4},
	NODE_NETWORK | NODE_BLOOM | NODE_WITNESS,
  TESTNET_MIN_INPUT,
  TESTNET_MAX_BLOCK_SIZE,
  TESTNET_MAX_ORPHAN_TRANSACTIONS,
  TESTNET_MAX_TRANSACTION_WEIGHT,
  TESTNET_MIN_TX_FEE,
  TESTNET_MIN_RELAY_TX_FEE,
  TESTNET_MAX_TX_FEE,
  TESTNET_MAX_FREE_TX_SIZE,
  TESTNET_MAX_MONEY,
  TESTNET_COINBASE_MATURITY, 
  TESTNET_MAX_SIGOPS,
	TESTNET_MAX_SCRIPT_SIZE,
	TESTNET_MAX_SCRIPT_ELEMENT_SIZE,
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
