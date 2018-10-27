
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

	/* P2SH */
	iface->BIP16Height = 1; 
	/* v2.0 block (height in coinbase) */
	iface->BIP34Height = 1;
	/* OP_CHECLOCKTIMEVERIFY */
	iface->BIP65Height = 1;
	/* strict DER signature */
	iface->BIP66Height = 1;

  iface->nRuleChangeActivationThreshold = 4;
  iface->nMinerConfirmationWindow = 5;

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
	static int renew_index;

	renew_index++;
	if ((0 == (renew_index % 50)) || !ret_key.IsValid()) {
		string strAccount("");
		GetAccountAddress(wallet, strAccount, false);

		ret_key = wallet->GenerateNewKey(true);
		if (!ret_key.IsValid()) {
			ret_key = GetAccountPubKey(wallet, strAccount);
		} else {
			wallet->SetAddressBookName(ret_key.GetID(), strAccount);
		}
		CCoinAddr addr(wallet->ifaceIndex, ret_key.GetID());
		Debug("(testnet) GetMainAccountPubKey: using '%s' for mining address.",
				addr.ToString().c_str());

		/* mining pool fees */
		string strBankAccount("bank");
		GetAccountAddress(wallet, strBankAccount, false);
		/* cpu miner */
		string strSystemAccount("system");
		GetAccountAddress(wallet, strSystemAccount, false);
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
	38, /* G */
	5, /* 3 */
	25, /* A */
	190,
	{0x04, 0x88, 0xB2, 0x1E},
	{0x04, 0x88, 0xAD, 0xE4},
  0,
  TEST_MIN_INPUT,
  TEST_MAX_BLOCK_SIZE,
  TEST_MAX_ORPHAN_TRANSACTIONS,
  TEST_MAX_TRANSACTION_WEIGHT,
  TEST_MIN_TX_FEE,
  TEST_MIN_RELAY_TX_FEE,
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
