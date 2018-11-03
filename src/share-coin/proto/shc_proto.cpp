
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
#include "shc/shc_netmsg.h"
#include "shc/shc_pool.h"
#include "shc/shc_block.h"
#include "shc/shc_wallet.h"
#include "shc/shc_txidx.h"

SHC_CTxMemPool SHCBlock::mempool;
CBlockIndex *SHCBlock::pindexGenesisBlock = NULL;
int64 SHCBlock::nTimeBestReceived;
CBigNum SHCBlock::bnBestChainWork;
CBigNum SHCBlock::bnBestInvalidWork;




extern void shc_RegisterRPCOp(int ifaceIndex);
extern void color_RegisterRPCOp(int ifaceIndex);


static int shc_init(CIface *iface, void *_unused_)
{
  int ifaceIndex = GetCoinIndex(iface);
  int err;

	/* P2SH */
	iface->BIP16Height = 1; /* always enabled */
	/* v2.0 block (height in coinbase) */
	iface->BIP34Height = 59128; /* f19bc1a7e3416751daf8ea6ca116aded43b0f541ac4576ccd99a7c494fb50f20 */
	/* OP_CHECLOCKTIMEVERIFY */
	iface->BIP65Height = 59128; /* f19bc1a7e3416751daf8ea6ca116aded43b0f541ac4576ccd99a7c494fb50f20 */
	/* strict DER signature */
	iface->BIP66Height = 59128; /* f19bc1a7e3416751daf8ea6ca116aded43b0f541ac4576ccd99a7c494fb50f20 */

  iface->nRuleChangeActivationThreshold = 9072;
  iface->nMinerConfirmationWindow = 12096;

	iface->vDeployments[DEPLOYMENT_TESTDUMMY].bit = 28;
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nStartTime = 1524960000; /* 04/29/18 */
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nTimeout = 1530230400; /* 06/29/18 */ 

	/* BIP68, BIP112, and BIP113 */
	iface->vDeployments[DEPLOYMENT_CSV].bit = 0;
	iface->vDeployments[DEPLOYMENT_CSV].nStartTime = 1543622400; /* 12/01/2018 UTC */
	iface->vDeployments[DEPLOYMENT_CSV].nTimeout = 1544745600; /* 12/14/2018 UTC */

	/* BIP141, BIP143, and BIP147 */
	iface->vDeployments[DEPLOYMENT_SEGWIT].bit = 1;
	iface->vDeployments[DEPLOYMENT_SEGWIT].nStartTime = 1577836800; /* 01/01/20 */
	iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout = 1609459200; /* 01/01/21 */ 

  shc_RegisterRPCOp(SHC_COIN_IFACE);

	/* alternate block-chain rpc operations. */
  color_RegisterRPCOp(SHC_COIN_IFACE);

  shcWallet = new SHCWallet();
  SetWallet(SHC_COIN_IFACE, shcWallet);


  if (!opt_bool((char *)OPT_SHC_BACKUP_RESTORE)) {
    /* normal startup */
    if (!shc_InitBlockIndex()) {
      error(SHERR_INVAL, "shc_proto: unable to initialize block index table.");
      return (SHERR_INVAL);
    }
  } else {
    /* over-write block-chain with pre-existing backup records */
    if (!shc_RestoreBlockIndex()) {
      error(SHERR_INVAL, "shc_proto: unable to initialize block index table.");
      return (SHERR_INVAL);
    }
  }

  if (!shc_LoadWallet()) {
    error(SHERR_INVAL, "shc_proto: unable to open load wallet.");
    return (SHERR_INVAL);
  }

  Debug("initialized SHC block-chain.");

  return (0);
}

static int shc_bind(CIface *iface, void *_unused_)
{
  int err;

	/* set configured port */
	iface->port = opt_num(OPT_SHC_PORT);

  err = unet_bind(UNET_SHC, iface->port, NULL);
  if (err) {
    error(err, "error binding SHC socket port");
    return (err);
  }

  unet_timer_set(UNET_SHC, shc_server_timer); /* x10/s */
  unet_connop_set(UNET_SHC, shc_server_accept);
  unet_disconnop_set(UNET_SHC, shc_server_close);

  /* automatically connect to peers of 'shc' service. */
  unet_bind_flag_set(UNET_SHC, UNETF_PEER_SCAN);

  Debug("initialized SHC service on port %d.", (int)iface->port);

  return (0);
}

static int shc_term(CIface *iface, void *_unused_)
{
#if 0
  CWallet *wallet = GetWallet(iface);
  if (wallet) {
    UnregisterWallet(wallet);
   }
#endif
  SetWallet(iface, NULL);
}
static int shc_msg_recv(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!shc_ProcessMessages(iface, pnode)) {
    /* log */
  }

return (0);
}
static int shc_msg_send(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!shc_SendMessages(iface, pnode, false)) {
    /* log */
  }

return (0);
}
static int shc_peer_add(CIface *iface, void *arg)
{
return (0);
}
static int shc_peer_recv(CIface *iface, void *arg)
{
return (0);
}

static int shc_block_new(CIface *iface, CBlock **block_p)
{
  *block_p = new SHCBlock();
  return (0);
}

static int shc_block_process(CIface *iface, CBlock *block)
{

  if (!shc_ProcessBlock(block->originPeer, block))
    return (SHERR_INVAL);

  return (0);
}

static CPubKey shc_GetMainAccountPubKey(CWallet *wallet)
{
  static CPubKey ret_key;
	string strAccount("");

  if (!ret_key.IsValid()) {
		/* main account. */
		GetAccountAddress(wallet, strAccount, false);

    /* mining pool fees */
    string strBankAccount("bank");
    GetAccountAddress(wallet, strBankAccount, false);

    /* cpu miner */
    string strSystemAccount("system");
    GetAccountAddress(wallet, strSystemAccount, false);

		/* use main account's primary address. */
    ret_key = GetAccountPubKey(wallet, strAccount, false);
		CCoinAddr addr(wallet->ifaceIndex, ret_key.GetID()); 
		Debug("(shc) GetMainAccountPubKey: using '%s' for mining address.",
				addr.ToString().c_str()); 
	}

	/* check if this pubkey has been used in coinbase. */
	CScript scriptPubKey;
	bool bKeyUsed = false;
	scriptPubKey << ret_key << OP_CHECKSIG;
	for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin();
			it != wallet->mapWallet.end(); ++it) {
		const CWalletTx& wtx = (*it).second;
		if (!wtx.IsCoinBase())
			continue;
		BOOST_FOREACH(const CTxOut& txout, wtx.vout)
			if (txout.scriptPubKey == scriptPubKey)
				bKeyUsed = true;
	}
	if (bKeyUsed) {
		/* create new pubkey */
		ret_key = GetAccountPubKey(wallet, strAccount, true);
	}

  return (ret_key);
}

static int shc_block_templ(CIface *iface, CBlock **block_p)
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

  CBlockIndex *pindexBest = GetBestBlockIndex(SHC_COIN_IFACE);
  median = pindexBest->GetMedianTimePast() + 1;

  const CPubKey& pubkey = shc_GetMainAccountPubKey(wallet);
  if (!pubkey.IsValid()) {
error(SHERR_INVAL, "shc_block_templ: error obtaining main pubkey.\n");
    return (NULL);
  }

  pblock = shc_CreateNewBlock(pubkey);
  if (!pblock)
    return (NULL);

  pblock->nTime = MAX(median, GetAdjustedTime());
  pblock->nNonce = 0;

  *block_p = pblock;

  return (0);
}

#if 0
static int shc_block_submit(CIface *iface, CBlock *block)
{
  blkidx_t *blockIndex;

  blockIndex = GetBlockTable(SHC_COIN_IFACE);
  if (!blockIndex)
    return (STERR_INVAL);

  // Check for duplicate
  uint256 hash = block->GetHash();
  if (blockIndex->count(hash))// || mapOrphanBlocks.count(hash))
    return (BLKERR_DUPLICATE_BLOCK);

  // Preliminary checks
  if (!block->CheckBlock()) {
    shcoind_log("c_processblock: !CheckBlock()");
    return (BLKERR_CHECKPOINT);
  }

  // Store to disk
  if (!block->AcceptBlock()) {
    shcoind_log("c_processblock: !AcceptBlock()");
    return (BLKERR_INVALID_BLOCK);
  }

  block->print();

return (0);
}
#endif

static int shc_tx_new(CIface *iface, void *arg)
{
return (0);
}

static int shc_tx_pool(CIface *iface, CTxMemPool **pool_p)
{
  *pool_p = &SHCBlock::mempool;
  return (0);
}








#ifdef __cplusplus
extern "C" {
#endif

coin_iface_t shc_coin_iface = {
  "shc",
  TRUE, /* enabled */
  COIN_IFACE_VERSION(SHC_VERSION_MAJOR, SHC_VERSION_MINOR,
      SHC_VERSION_REVISION, SHC_VERSION_BUILD), /* cli ver */
  2, /* block version */
  SHC_PROTOCOL_VERSION, /* network proto ver */
  SHC_COIN_DAEMON_PORT,
  { 0xd9, 0xd9, 0xf9, 0xbd },
	62, /* S*/
	5, /* 3 */
	25, /* A */
	190,
	{0x04, 0x88, 0xB2, 0x1E},
	{0x04, 0x88, 0xAD, 0xE4},
  NODE_NETWORK | NODE_BLOOM,
  SHC_MIN_INPUT,
  SHC_MAX_BLOCK_SIZE,
  SHC_MAX_ORPHAN_TRANSACTIONS,
  SHC_MAX_TRANSACTION_WEIGHT,
  SHC_MIN_TX_FEE,
  SHC_MIN_RELAY_TX_FEE,
  SHC_MAX_TX_FEE,
  SHC_MAX_FREE_TX_SIZE,
  SHC_MAX_MONEY,
  SHC_COINBASE_MATURITY, 
  SHC_MAX_SIGOPS,
  COINF(shc_init),
  COINF(shc_bind),
  COINF(shc_term),
  COINF(shc_msg_recv),
  COINF(shc_msg_send),
  COINF(shc_peer_add),
  COINF(shc_peer_recv),
  COINF(shc_block_new),
  COINF(shc_block_process),
  COINF(shc_block_templ),
  COINF(shc_tx_new),
  COINF(shc_tx_pool)
};


#ifdef __cplusplus
}
#endif
