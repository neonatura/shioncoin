
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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
#include "coin_proto.h"
#include "ltc/ltc_netmsg.h"
#include "ltc/ltc_pool.h"
#include "ltc/ltc_block.h"
#include "ltc/ltc_wallet.h"
#include "ltc/ltc_txidx.h"

LTC_CTxMemPool LTCBlock::mempool;
CBlockIndex *LTCBlock::pindexGenesisBlock = NULL;
int64 LTCBlock::nTimeBestReceived;





extern void RegisterRPCOpDefaults(int ifaceIndex);


static int ltc_init(CIface *iface, void *_unused_)
{
  int ifaceIndex = GetCoinIndex(iface);
  int err;

	/* P2SH */
	iface->BIP16Height = 218579; // 87afb798a3ad9378fcd56123c81fb31cfd9a8df4719b9774d71730c16315a092 - October 1, 2012
	/* v2.0 block (height in coinbase) */ 
	iface->BIP30Height = 1; /* always enabled */
	iface->BIP34Height = 710000; /* fa09d204a83a768ed5a7c8d441fa62f2043abf420cff1226c7b4329aeb9d51cf */
	/* OP_CHECLOCKTIMEVERIFY */
	iface->BIP65Height = 918684; /* bab3041e8977e0dc3eeff63fe707b92bde1dd449d8efafb248c27c8264cc311a */
	/* strict DER signature */
	iface->BIP66Height = 811879; /* 7aceee012833fa8952f8835d8b1b3ae233cd6ab08fdb27a771d2bd7bdc491894 */ 

  iface->nRuleChangeActivationThreshold = 6048;
	iface->nMinerConfirmationWindow = 8064;

	iface->vDeployments[DEPLOYMENT_TESTDUMMY].bit = 28;
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

	iface->vDeployments[DEPLOYMENT_CSV].bit = 0;
	iface->vDeployments[DEPLOYMENT_CSV].nStartTime = 1485561600; // January 28, 2017
	iface->vDeployments[DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

	iface->vDeployments[DEPLOYMENT_SEGWIT].bit = 1;
	iface->vDeployments[DEPLOYMENT_SEGWIT].nStartTime = 1485561600; // January 28, 2017
	iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018


  RegisterRPCOpDefaults(LTC_COIN_IFACE);

  ltcWallet = new LTCWallet();
	ltcWallet->checkpoints = new CCheckpoints(LTC_COIN_IFACE);
  SetWallet(LTC_COIN_IFACE, ltcWallet);


	/* normal startup */
	if (!ltc_InitBlockIndex()) {
		error(SHERR_INVAL, "ltc_proto: unable to initialize block index table.");
		return (SHERR_INVAL);
	}

  if (!ltc_LoadWallet()) {
    error(SHERR_INVAL, "ltc_proto: unable to open load wallet.");
    return (SHERR_INVAL);
  }

  Debug("initialized LTC block-chain.");

  return (0);
}

static int ltc_bind(CIface *iface, void *_unused_)
{
  int err;

  err = unet_bind(UNET_LTC, LTC_COIN_DAEMON_PORT, NULL);
  if (err) {
    error(err, "error binding LTC socket port");
    return (err);
  }

  unet_timer_set(UNET_LTC, ltc_server_timer); /* x10/s */
  unet_connop_set(UNET_LTC, ltc_server_accept);
  unet_disconnop_set(UNET_LTC, ltc_server_close);

  /* automatically connect to peers of 'ltc' service. */
  unet_bind_flag_set(UNET_LTC, UNETF_PEER_SCAN);

  Debug("initialized LTC service on port %d.", (int)iface->port);

  return (0);
}

static int ltc_term(CIface *iface, void *_unused_)
{
#if 0
  CWallet *wallet = GetWallet(iface);
  if (wallet) {
    UnregisterWallet(wallet);
   }
#endif
  SetWallet(iface, NULL);
}
static int ltc_msg_recv(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!ltc_ProcessMessages(iface, pnode)) {
    /* log */
  }

return (0);
}
static int ltc_msg_send(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!ltc_SendMessages(iface, pnode, false)) {
    /* log */
  }

return (0);
}
static int ltc_peer_add(CIface *iface, void *arg)
{
return (0);
}
static int ltc_peer_recv(CIface *iface, void *arg)
{
return (0);
}

static int ltc_block_new(CIface *iface, CBlock **block_p)
{
  *block_p = new LTCBlock();
  return (0);
}

static int ltc_block_process(CIface *iface, CBlock *block)
{

  if (!ltc_ProcessBlock(block->originPeer, block))
    return (SHERR_INVAL);

  return (0);
}

static CPubKey ltc_GetMainAccountPubKey(CWallet *wallet)
{
  static CPubKey ret_key;
	string strAccount("");

  if (!ret_key.IsValid()) {
    GetAccountAddress(wallet, strAccount, false);

    ret_key = GetAccountPubKey(wallet, strAccount);
    if (!ret_key.IsValid()) {
      error(SHERR_INVAL, "(ltc) GetMainAccountPubKey: error obtaining main account pubkey.");
#if 0
      CReserveKey reservekey(wallet);
      ret_key = reservekey.GetReservedKey();
      reservekey.KeepKey();
#endif
			ret_key = wallet->GenerateNewKey();
    } else {
      CCoinAddr addr(wallet->ifaceIndex, ret_key.GetID()); 
      Debug("(ltc) GetMainAccountPubKey: using '%s' for mining address.",
          addr.ToString().c_str()); 
    }

    /* mining pool fees */
    string strBankAccount("bank");
    GetAccountAddress(wallet, strBankAccount, false);
    /* cpu miner */
    string strSystemAccount("system");
    GetAccountAddress(wallet, strSystemAccount, false);
  }

#if 0
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
#endif

  return (ret_key);
}

static int ltc_block_templ(CIface *iface, CBlock **block_p)
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

  CBlockIndex *pindexBest = GetBestBlockIndex(LTC_COIN_IFACE);
  median = pindexBest->GetMedianTimePast() + 1;

  const CPubKey& pubkey = ltc_GetMainAccountPubKey(wallet);
  if (!pubkey.IsValid()) {
error(SHERR_INVAL, "ltc_block_templ: error obtaining main pubkey.\n");
    return (NULL);
  }

  pblock = ltc_CreateNewBlock(pubkey);
  if (!pblock)
    return (NULL);

  pblock->nTime = MAX(median, GetAdjustedTime());
  pblock->nNonce = 0;

  *block_p = pblock;

  return (0);
}

#if 0
static int ltc_block_submit(CIface *iface, CBlock *block)
{
  blkidx_t *blockIndex;

  blockIndex = GetBlockTable(LTC_COIN_IFACE);
  if (!blockIndex)
    return (STERR_INVAL);

  // Check for duplicate
  uint256 hash = block->GetHash();
  if (blockIndex->count(hash))// || mapOrphanBlocks.count(hash))
    return (BLKERR_DUPLICATE_BLOCK);

  // Preliminary checks
  if (!block->CheckBlock()) {
    ltcoind_log("c_processblock: !CheckBlock()");
    return (BLKERR_CHECKPOINT);
  }

  // Store to disk
  if (!block->AcceptBlock()) {
    ltcoind_log("c_processblock: !AcceptBlock()");
    return (BLKERR_INVALID_BLOCK);
  }

  block->print();

return (0);
}
#endif

static int ltc_tx_new(CIface *iface, void *arg)
{
return (0);
}

static int ltc_tx_pool(CIface *iface, CTxMemPool **pool_p)
{
  *pool_p = &LTCBlock::mempool;
  return (0);
}








#ifdef __cplusplus
extern "C" {
#endif

/**
 * A "LTC Compatible" external interface being designed to be able to perform remote SSL RPC (bitcoin style) commands against a remote coin service.
 *
 * The point is meant as a way to provide multi-pool mining against a selectable scrpt-based virtual currency, and to provide a potential method to perform a decentralized coin exchange between two currencies via the "TX_EXCHANGE" transaction.
 */
coin_iface_t ltc_coin_iface = {
  "ltc",
  FALSE, /* disabled */
  COIN_IFACE_VERSION(LTC_VERSION_MAJOR, LTC_VERSION_MINOR,
      LTC_VERSION_REVISION, LTC_VERSION_BUILD), /* cli ver */
  4, /* block version */
  LTC_PROTOCOL_VERSION, /* network proto ver */
  LTC_COIN_DAEMON_PORT,
  { 0xfb, 0xc0, 0xb6, 0xdb },
	48, /* L */
	5,
	50,
	176,
	{0x04, 0x88, 0xB2, 0x1E},
	{0x04, 0x88, 0xAD, 0xE4},
  NODE_NETWORK | NODE_BLOOM,
  LTC_MIN_INPUT,
  LTC_MAX_BLOCK_SIZE,
  LTC_MAX_ORPHAN_TRANSACTIONS,
  LTC_MAX_TRANSACTION_WEIGHT,
  LTC_MIN_TX_FEE,
  LTC_MIN_RELAY_TX_FEE,
  LTC_MAX_TX_FEE,
  LTC_MAX_FREE_TX_SIZE,
  LTC_MAX_MONEY,
  LTC_COINBASE_MATURITY, 
  LTC_MAX_SIGOPS,
	LTC_MAX_SCRIPT_SIZE,
	LTC_MAX_SCRIPT_ELEMENT_SIZE,
  COINF(ltc_init),
  COINF(ltc_bind),
  COINF(ltc_term),
  COINF(ltc_msg_recv),
  COINF(ltc_msg_send),
  COINF(ltc_peer_add),
  COINF(ltc_peer_recv),
  COINF(ltc_block_new),
  COINF(ltc_block_process),
  COINF(ltc_block_templ),
  COINF(ltc_tx_new),
  COINF(ltc_tx_pool)
};


#ifdef __cplusplus
}
#endif
