
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
//#include "test/test_netmsg.h"
#include "test/test_pool.h"
#include "test/test_block.h"
#include "test/test_wallet.h"
#include "test/test_txidx.h"

TEST_CTxMemPool TESTBlock::mempool;
CBlockIndex *TESTBlock::pindexGenesisBlock = NULL;
int64 TESTBlock::nTimeBestReceived;
CBigNum TESTBlock::bnBestChainWork;
CBigNum TESTBlock::bnBestInvalidWork;

int64 TESTBlock::nTargetTimespan = 7200; /* two hours */
int64 TESTBlock::nTargetSpacing = 60; /* one minute */


static int test_init(CIface *iface, void *_unused_)
{

  iface->nRuleChangeActivationThreshold = 9072;
  iface->nMinerConfirmationWindow = 12096;

  SetWallet(TEST_COIN_IFACE, testWallet);
  return (0);
}


static int test_bind(CIface *iface, void *_unused_)
{
  return (0);
}

static int test_term(CIface *iface, void *_unused_)
{
#if 0
  CWallet *wallet = GetWallet(iface);
  if (wallet)
    UnregisterWallet(wallet);
#endif
  SetWallet(iface, NULL);
}

static int test_peer_add(CIface *iface, void *arg)
{
return (0);
}
static int test_peer_recv(CIface *iface, void *arg)
{
return (0);
}
static int test_block_new(CIface *iface, CBlock **block_p)
{
  *block_p = new TESTBlock();
return (0);
}

static int test_block_process(CIface *iface, CBlock *block)
{

  if (!test_ProcessBlock(block->originPeer, block))
    return (SHERR_INVAL);

  return (0);
}

static CPubKey test_GetMainAccountPubKey(CWallet *wallet)
{
  static CPubKey ret_key;

  if (!ret_key.IsValid()) {
    string strAccount("");

    ret_key = GetAccountPubKey(wallet, strAccount);
    if (!ret_key.IsValid()) {
      CReserveKey reservekey(wallet);
      ret_key = reservekey.GetReservedKey();
      reservekey.KeepKey();
    }
  }

  return (ret_key);
}

static int test_block_templ(CIface *iface, CBlock **block_p)
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

  CBlockIndex *pindexBest = GetBestBlockIndex(TEST_COIN_IFACE);
  median = pindexBest->GetMedianTimePast() + 1;

  const CPubKey& pubkey = test_GetMainAccountPubKey(wallet);
  if (!pubkey.IsValid())
    return (NULL);

  pblock = test_CreateNewBlock(pubkey);
  if (!pblock)
    return (NULL);

  pblock->nTime = MAX(median, GetAdjustedTime());
  pblock->nNonce = 0;

  *block_p = pblock;

  return (0);
}

#if 0
static int test_block_submit(CIface *iface, CBlock *block)
{
  blkidx_t *blockIndex;

  blockIndex = GetBlockTable(TEST_COIN_IFACE);
  if (!blockIndex) {
fprintf(stderr, "DEBUG: test_block_submit: error obtaining tableBlockIndex[TEST}\n"); 
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

static int test_tx_new(CIface *iface, void *arg)
{
return (0);
}

static int test_tx_pool(CIface *iface, CTxMemPool **pool_p)
{
  *pool_p = &TESTBlock::mempool;
  return (0);
}

#ifdef __cplusplus
extern "C" {
#endif



coin_iface_t test_coin_iface = {
  "test",
  TRUE, /* enabled */
  COIN_IFACE_VERSION(TEST_VERSION_MAJOR, TEST_VERSION_MINOR,
      TEST_VERSION_REVISION, TEST_VERSION_BUILD), /* cli ver */
  1, /* block version */
  TEST_PROTOCOL_VERSION, /* network protocol version */ 
  TEST_COIN_DAEMON_PORT,
  { 0xd9, 0xd9, 0xf8, 0xbd },
  0,
  TEST_MIN_INPUT,
  TEST_MAX_BLOCK_SIZE,
  TEST_MAX_ORPHAN_TRANSACTIONS,
  TEST_MAX_TRANSACTION_WEIGHT,
  TEST_MIN_TX_FEE,
  TEST_MAX_TX_FEE,
  TEST_MAX_FREE_TX_SIZE,
  TEST_MAX_MONEY,
  TEST_COINBASE_MATURITY, 
  TEST_MAX_SIGOPS,
  COINF(test_init),
  COINF(test_bind),
  COINF(test_term),
  NULL, /* test_msg_recv() */
  NULL, /* test_msg_send() */
  COINF(test_peer_add),
  COINF(test_peer_recv),
  COINF(test_block_new),
  COINF(test_block_process),
  COINF(test_block_templ),
  COINF(test_tx_new),
  COINF(test_tx_pool)
};


#ifdef __cplusplus
}
#endif
