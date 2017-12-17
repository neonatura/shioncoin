
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
#include "emc2/emc2_netmsg.h"
#include "emc2/emc2_pool.h"
#include "emc2/emc2_block.h"
#include "emc2/emc2_wallet.h"
#include "emc2/emc2_txidx.h"

EMC2_CTxMemPool EMC2Block::mempool;
CBlockIndex *EMC2Block::pindexGenesisBlock = NULL;
int64 EMC2Block::nTimeBestReceived;
CBigNum EMC2Block::bnBestChainWork;
CBigNum EMC2Block::bnBestInvalidWork;

extern void RegisterRPCOpDefaults(int ifaceIndex);


#if 0
int64 EMC2Block::nTargetTimespan = 14400; /* four hours */
int64 EMC2Block::nTargetSpacing = 180; /* three minutes */
#endif


static int emc2_init(CIface *iface, void *_unused_)
{
  int ifaceIndex = GetCoinIndex(iface);
  int err;

  iface->nRuleChangeActivationThreshold = 15120; // 75% of 20160
  iface->nMinerConfirmationWindow = 20160; /* aprox */

  iface->vDeployments[DEPLOYMENT_TESTDUMMY].bit = 28;
  iface->vDeployments[DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; /* Jan 1, 2008 */
  iface->vDeployments[DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; /* Dec 31, 2008 */

  iface->vDeployments[DEPLOYMENT_CSV].bit = 0;
  iface->vDeployments[DEPLOYMENT_CSV].nStartTime = 1485561600; /* Jan 28, 2017 */
  iface->vDeployments[DEPLOYMENT_CSV].nTimeout = 1517356801; /* Jan 31, 2018 */

  iface->vDeployments[DEPLOYMENT_SEGWIT].bit = 1;
  iface->vDeployments[DEPLOYMENT_SEGWIT].nStartTime = 1485561600; /* Jan 28, 2017 */
  iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout = 1517356801; /* Jan 31, 2018 */

  RegisterRPCOpDefaults(EMC2_COIN_IFACE);

  emc2Wallet = new EMC2Wallet();
  SetWallet(EMC2_COIN_IFACE, emc2Wallet);



#if 0
  if (!bitdb.Open(GetDataDir())) /* DEBUG: */
  {
    fprintf(stderr, "error: unable to open data directory.\n");
    return (SHERR_INVAL);
  }
#endif

  if (!opt_bool(OPT_EMC2_BACKUP_RESTORE)) {
    /* normal startup */
    if (!emc2_InitBlockIndex()) {
      error(SHERR_INVAL, "emc2_proto: unable to initialize block index table.");
      return (SHERR_INVAL);
    }
  } else {
    /* over-write block-chain with pre-existing backup records */
    if (!emc2_RestoreBlockIndex()) {
      error(SHERR_INVAL, "emc2_proto: unable to initialize block index table.");
      return (SHERR_INVAL);
    }
  }

  if (!emc2_LoadWallet()) {
    fprintf(stderr, "error: emc2_proto: unable to load wallet.\n");
    return (SHERR_INVAL);
  }

  Debug("initialized EMC2 block-chain.");

  return (0);
}

static int emc2_bind(CIface *iface, void *_unused_)
{
  int err;

  err = unet_bind(UNET_EMC2, EMC2_COIN_DAEMON_PORT, 0);
  if (err) { 
    error(err, "error binding EMC2 socket port");
    return (err);
  }

  unet_timer_set(UNET_EMC2, emc2_server_timer); /* x10/s */
  unet_connop_set(UNET_EMC2, emc2_server_accept);
  unet_disconnop_set(UNET_EMC2, emc2_server_close);

  /* automatically connect to peers of 'emc2' service. */
  unet_bind_flag_set(UNET_EMC2, UNETF_PEER_SCAN);

  Debug("initialized EMC2 service on port %d.", (int)iface->port);

  return (0);
}
static int emc2_term(CIface *iface, void *_unused_)
{
#if 0
  CWallet *wallet = GetWallet(iface);
  if (wallet)
    UnregisterWallet(wallet);
#endif
  SetWallet(iface, NULL);
}

static int emc2_msg_recv(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!emc2_ProcessMessages(iface, pnode)) {
    /* log */
  }

return (0);
}
static int emc2_msg_send(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!emc2_SendMessages(iface, pnode, false)) {
    /* log */
  }

return (0);
}
static int emc2_peer_add(CIface *iface, void *arg)
{
return (0);
}
static int emc2_peer_recv(CIface *iface, void *arg)
{
return (0);
}
static int emc2_block_new(CIface *iface, CBlock **block_p)
{
  *block_p = new EMC2Block();
return (0);
}

static int emc2_block_process(CIface *iface, CBlock *block)
{

  if (!emc2_ProcessBlock(block->originPeer, block))
    return (SHERR_INVAL);

  return (0);
}

static CPubKey emc2_GetMainAccountPubKey(CWallet *wallet)
{
  static CPubKey ret_key; 

  if (!ret_key.IsValid()) {
    string strAccount("");

    ret_key = GetAccountPubKey(wallet, strAccount);
    if (!ret_key.IsValid()) {
      error(SHERR_INVAL, "GetMainAccountPubKey: emc2: error obtaining main account pubkey.");
      CReserveKey reservekey(wallet);
      ret_key = reservekey.GetReservedKey();
      reservekey.KeepKey();
    } else {
      CCoinAddr addr(wallet->ifaceIndex, ret_key.GetID()); 
      Debug("(emc2) GetMainAccountPubKey: using '%s' for mining address", 
          addr.ToString().c_str()); 
    }

    string strBankAccount("bank");
    GetAccountAddress(wallet, strBankAccount, false);
  }

  return (ret_key);
}

static int emc2_block_templ(CIface *iface, CBlock **block_p)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CBlock* pblock;
  unsigned int median;
  int reset;
    
  if (!wallet) {
    unet_log(ifaceIndex, "GetBlocKTemplate: Wallet not initialized.");
    return (NULL);
  }

  CBlockIndex *pindexBest = GetBestBlockIndex(EMC2_COIN_IFACE);
  median = pindexBest->GetMedianTimePast() + 1;

  const CPubKey& pubkey = emc2_GetMainAccountPubKey(wallet);
  if (!pubkey.IsValid()) {
fprintf(stderr, "DEBUG: emc2_block_templ: error obtaining main pubkey.\n"); 
    return (NULL);
  }

  pblock = emc2_CreateNewBlock(pubkey);
  if (!pblock)
    return (NULL);

  pblock->nTime = MAX(median, GetAdjustedTime());
  pblock->nNonce = 0;

  *block_p = pblock;

  return (0);
}

#if 0
static int emc2_block_submit(CIface *iface, CBlock *block)
{
  blkidx_t *blockIndex;

  blockIndex = GetBlockTable(EMC2_COIN_IFACE);
  if (!blockIndex) {
fprintf(stderr, "DEBUG: emc2_block_submit: error obtaining tableBlockIndex[EMC2}\n"); 
    return (STERR_INVAL);
}

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

static int emc2_tx_new(CIface *iface, void *arg)
{
return (0);
}

static int emc2_tx_pool(CIface *iface, CTxMemPool **pool_p)
{
  *pool_p = &EMC2Block::mempool;
  return (0);
}

#ifdef __cplusplus
extern "C" {
#endif



coin_iface_t emc2_coin_iface = {
  "emc2",
  TRUE,
  COIN_IFACE_VERSION(EMC2_VERSION_MAJOR, EMC2_VERSION_MINOR,
      EMC2_VERSION_REVISION, EMC2_VERSION_BUILD), /* cli ver */
  2, /* block version */
  EMC2_PROTOCOL_VERSION, /* network protocol version */ 
  EMC2_COIN_DAEMON_PORT,
  { 0xe8, 0xf1, 0xc4, 0xac },
  NODE_NETWORK | NODE_BLOOM | NODE_WITNESS,
  EMC2_MIN_INPUT,
  EMC2_MAX_BLOCK_SIZE,
  EMC2_MAX_ORPHAN_TRANSACTIONS,
  EMC2_MAX_TRANSACTION_WEIGHT,
  EMC2_MIN_TX_FEE,
  EMC2_MAX_TX_FEE,
  EMC2_MAX_FREE_TX_SIZE,
  EMC2_MAX_MONEY,
  EMC2_COINBASE_MATURITY, 
  EMC2_MAX_SIGOPS,
  COINF(emc2_init),
  COINF(emc2_bind),
  COINF(emc2_term),
  COINF(emc2_msg_recv),
  COINF(emc2_msg_send),
  COINF(emc2_peer_add),
  COINF(emc2_peer_recv),
  COINF(emc2_block_new),
  COINF(emc2_block_process),
  COINF(emc2_block_templ),
  COINF(emc2_tx_new),
  COINF(emc2_tx_pool)
};


#ifdef __cplusplus
}
#endif
