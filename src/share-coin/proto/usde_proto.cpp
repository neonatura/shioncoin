
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
#include "usde/usde_netmsg.h"
#include "usde/usde_pool.h"
#include "usde/usde_block.h"
#include "usde/usde_wallet.h"
#include "usde/usde_txidx.h"

USDE_CTxMemPool USDEBlock::mempool;
CBlockIndex *USDEBlock::pindexGenesisBlock = NULL;
int64 USDEBlock::nTimeBestReceived;
CBigNum USDEBlock::bnBestChainWork;
CBigNum USDEBlock::bnBestInvalidWork;

int64 USDEBlock::nTargetTimespan = 7200; /* two hours */
int64 USDEBlock::nTargetSpacing = 60; /* one minute */

extern void RegisterRPCOpDefaults(int ifaceIndex);

static int usde_init(CIface *iface, void *_unused_)
{
  int ifaceIndex = GetCoinIndex(iface);
  int err;

  iface->nRuleChangeActivationThreshold = 15120; // 75% of 20160
  iface->nMinerConfirmationWindow = 20160; /* aprox */

  RegisterRPCOpDefaults(USDE_COIN_IFACE);

  usdeWallet = new USDEWallet();
  SetWallet(USDE_COIN_IFACE, usdeWallet);



#if 0
  if (!bitdb.Open(GetDataDir())) /* DEBUG: */
  {
    fprintf(stderr, "error: unable to open data directory.\n");
    return (SHERR_INVAL);
  }
#endif

  if (!opt_bool(OPT_USDE_BACKUP_RESTORE)) {
    /* normal startup */
    if (!usde_InitBlockIndex()) {
      error(SHERR_INVAL, "usde_proto: unable to initialize block index table.");
      return (SHERR_INVAL);
    }
  } else {
    /* over-write block-chain with pre-existing backup records */
    if (!usde_RestoreBlockIndex()) {
      error(SHERR_INVAL, "usde_proto: unable to initialize block index table.");
      return (SHERR_INVAL);
    }
  }

  if (!usde_LoadWallet()) {
    fprintf(stderr, "error: usde_proto: unable to load wallet.\n");
    return (SHERR_INVAL);
  }

  Debug("initialized USDE block-chain.");

  return (0);
}

static int usde_bind(CIface *iface, void *_unused_)
{
  int err;

  err = unet_bind(UNET_USDE, USDE_COIN_DAEMON_PORT, 0);
  if (err) { 
    error(err, "error binding USDE socket port");
    return (err);
  }

  unet_timer_set(UNET_USDE, usde_server_timer); /* x10/s */
  unet_connop_set(UNET_USDE, usde_server_accept);
  unet_disconnop_set(UNET_USDE, usde_server_close);

  /* automatically connect to peers of 'usde' service. */
  unet_bind_flag_set(UNET_USDE, UNETF_PEER_SCAN);

  Debug("initialized USDE service on port %d.", (int)iface->port);

  return (0);
}
static int usde_term(CIface *iface, void *_unused_)
{
#if 0 
  CWallet *wallet = GetWallet(iface);
  if (wallet)
    UnregisterWallet(wallet);
#endif
  SetWallet(iface, NULL);
}

static int usde_msg_recv(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!usde_ProcessMessages(iface, pnode)) {
    /* log */
  }

return (0);
}
static int usde_msg_send(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!usde_SendMessages(iface, pnode, false)) {
    /* log */
  }

return (0);
}
static int usde_peer_add(CIface *iface, void *arg)
{
return (0);
}
static int usde_peer_recv(CIface *iface, void *arg)
{
return (0);
}
static int usde_block_new(CIface *iface, CBlock **block_p)
{
  *block_p = new USDEBlock();
return (0);
}

static int usde_block_process(CIface *iface, CBlock *block)
{

  if (!usde_ProcessBlock(block->originPeer, block))
    return (SHERR_INVAL);

  return (0);
}

static CPubKey usde_GetMainAccountPubKey(CWallet *wallet)
{
  static CPubKey ret_key;

  if (!ret_key.IsValid()) {
    string strAccount("");

    ret_key = GetAccountPubKey(wallet, strAccount);
    if (!ret_key.IsValid()) {
      error(SHERR_INVAL, "(usde) GetMainAccountPubKey: error obtaining main account pubkey.");
      CReserveKey reservekey(wallet);
      ret_key = reservekey.GetReservedKey();
      reservekey.KeepKey();
    } else {
      CCoinAddr addr(wallet->ifaceIndex, ret_key.GetID()); 
      Debug("(usde) GetMainAccountPubKey: using '%s' for mining address.",
          addr.ToString().c_str()); 
    }

    string strBankAccount("bank");
    GetAccountAddress(wallet, strBankAccount, false);
  }

  return (ret_key);
}

static int usde_block_templ(CIface *iface, CBlock **block_p)
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

  CBlockIndex *pindexBest = GetBestBlockIndex(USDE_COIN_IFACE);
  median = pindexBest->GetMedianTimePast() + 1;

  const CPubKey& pubkey = usde_GetMainAccountPubKey(wallet);
  if (!pubkey.IsValid()) {
fprintf(stderr, "DEBUG: usde_block_templ: error obtaining main pubkey.\n");
    return (NULL);
  }

  pblock = usde_CreateNewBlock(pubkey);
  if (!pblock)
    return (NULL);

  pblock->nTime = MAX(median, GetAdjustedTime());
  pblock->nNonce = 0;

  *block_p = pblock;

  return (0);
}

#if 0
static int usde_block_submit(CIface *iface, CBlock *block)
{
  blkidx_t *blockIndex;

  blockIndex = GetBlockTable(USDE_COIN_IFACE);
  if (!blockIndex) {
fprintf(stderr, "DEBUG: usde_block_submit: error obtaining tableBlockIndex[USDE}\n"); 
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

static int usde_tx_new(CIface *iface, void *arg)
{
return (0);
}

static int usde_tx_pool(CIface *iface, CTxMemPool **pool_p)
{
  *pool_p = &USDEBlock::mempool;
  return (0);
}

#ifdef __cplusplus
extern "C" {
#endif



coin_iface_t usde_coin_iface = {
  "usde",
  TRUE, /* enabled */
  COIN_IFACE_VERSION(USDE_VERSION_MAJOR, USDE_VERSION_MINOR,
      USDE_VERSION_REVISION, USDE_VERSION_BUILD), /* cli ver */
  1, /* block version */
  USDE_PROTOCOL_VERSION, /* network protocol version */ 
  USDE_COIN_DAEMON_PORT,
  { 0xd9, 0xd9, 0xf9, 0xbd },
  NODE_NETWORK,
  USDE_MIN_INPUT,
  USDE_MAX_BLOCK_SIZE,
  USDE_MAX_ORPHAN_TRANSACTIONS,
  USDE_MAX_TRANSACTION_WEIGHT,
  USDE_MIN_TX_FEE,
  USDE_MAX_TX_FEE,
  USDE_MAX_FREE_TX_SIZE,
  USDE_MAX_MONEY,
  USDE_COINBASE_MATURITY, 
  USDE_MAX_SIGOPS,
  COINF(usde_init),
  COINF(usde_bind),
  COINF(usde_term),
  COINF(usde_msg_recv),
  COINF(usde_msg_send),
  COINF(usde_peer_add),
  COINF(usde_peer_recv),
  COINF(usde_block_new),
  COINF(usde_block_process),
  COINF(usde_block_templ),
  COINF(usde_tx_new),
  COINF(usde_tx_pool)
};


#ifdef __cplusplus
}
#endif
