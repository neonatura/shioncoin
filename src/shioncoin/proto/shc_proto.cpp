
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
#include "coin_proto.h"
#include "shc/shc_netmsg.h"
#include "shc/shc_pool.h"
#include "shc/shc_block.h"
#include "shc/shc_wallet.h"
#include "shc/shc_txidx.h"

SHC_CTxMemPool SHCBlock::mempool;
CBlockIndex *SHCBlock::pindexGenesisBlock = NULL;
int64 SHCBlock::nTimeBestReceived;




extern void shc_RegisterRPCOp(int ifaceIndex);
extern void color_RegisterRPCOp(int ifaceIndex);


static int shc_init(CIface *iface, void *_unused_)
{
  int ifaceIndex = GetCoinIndex(iface);
  int err;

	/* P2SH */
	iface->BIP16Height = 1; /* always enabled */
	/* v2.0 block (height in coinbase) */
	iface->BIP30Height = 1; /* super-ceded by BIP30 */
	iface->BIP34Height = 50001;
	/* OP_CHECLOCKTIMEVERIFY */
	iface->BIP65Height = 78001;
	/* strict DER signature */
	iface->BIP66Height = 50001;

	/* 75% of 12096 blocks */
  iface->nRuleChangeActivationThreshold = 9072;
  iface->nMinerConfirmationWindow = 12096;

	/* DEFINED: BIP9 */
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].bit = 28;
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nStartTime = 1577836800; /* 01/01/20 */
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nTimeout = 1609459200; /* 01/01/21 */ 

	/* ACTIVE: BIP68, BIP112, and BIP113 */
	iface->vDeployments[DEPLOYMENT_CSV].bit = 0;
	iface->vDeployments[DEPLOYMENT_CSV].nStartTime = 1555781815;
	iface->vDeployments[DEPLOYMENT_CSV].nTimeout = 1577836800;

	/* DEFINED: BIP141, BIP143, and BIP147 */
	iface->vDeployments[DEPLOYMENT_SEGWIT].bit = 1;
	iface->vDeployments[DEPLOYMENT_SEGWIT].nStartTime = 1577836800; /* 01/01/20 */
	iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout = 1609459200; /* 01/01/21 */ 

  shc_RegisterRPCOp(SHC_COIN_IFACE);

	/* alternate block-chain rpc operations. */
  color_RegisterRPCOp(SHC_COIN_IFACE);

  MapCheckpoints shc_mapCheckpoints =
    boost::assign::map_list_of
    ( 0, uint256("0xf4319e4e89b35b5f26ec0363a09d29703402f120cf1bf8e6f535548d5ec3c5cc") )

    /* Feb '17 */
    ( 29011, uint256("0x860e1b1ed3ebb78822d9e1c99dfa34ac1066c6eee17753f95b4ae0d354e61e5d") )
    ( 29012, uint256("0x82fe60a87c9f3a71e3edd897871a03d2f7ffb8d3eb8f2526a79f5630a50f9411") )
    ( 29013, uint256("0x7e2a6b592d7316bf137d7591298ae597057b16616d7df3ca4407d0ace6d8855e") )
    ( 29014, uint256("0x9c9e871541ced1c418e1ec483e0827bf812274e55596d5585f525410fee74b42") )

    /* May '17 */
    ( 49123, uint256("0x685651fb79d40cb8f53378e424bd4b3bc865de1554590c930d04801b8a7ecdfe") )
    ( 49124, uint256("0xda1e2aefb75b5c218e1e86abc89a913347cdf1e1dd81dd210a5fd33f09808009") )
    ( 49125, uint256("0x5e4a101dae9f04d9a28d54d0bfc742ac8c2c6887c53fd7063a3c3b73087a9c53") )
    ( 49126, uint256("0xe1e089319ca2bbdb036a462361560e130009f17bb7fdb030d5056069e96b92f1") )
    ( 49127, uint256("0x31cd03e68bc0ff6cc0ab98eef2574dfcc30f8815501f9ccdf02accc41598352c") )
    ( 49128, uint256("0x20ef53261360002ad1eddd2c5bf7c2166aecedad236be0efd636085cd8111440") )

    /* Feb '18 */
    ( 59123, uint256("0x47c8bce54da6e3412e8b27092cd9ece71dc942b47c4a9c133df0058f0a111488") )
    ( 59124, uint256("0xf68049663a540964b730fe7cbc2200ecefedf94fab7adcdfb60b6f31af9e737a") )
    ( 59125, uint256("0x84750f65256d837e6742372a4257a0ce65f721248ae4adcb185173b113589f75") )
    ( 59126, uint256("0x587a174683903a3f255a1784508a15b4bcfbaaae9b371fae4c9f1a18c060f54c") )
    ( 59127, uint256("0x7ddbb72740b40ff434717d5938fc1fedd1e9173d25d30e5554eef3b10743515d") )
    ( 59128, uint256("0xf19bc1a7e3416751daf8ea6ca116aded43b0f541ac4576ccd99a7c494fb50f20") )

    /* Nov '18 */
    ( 78003, uint256("0x8759db8220ea122999cfdfcb8a2a3a332cf9189947955bd12bc9ed2c2ac71403") )
    ( 78004, uint256("0x9194d30c93aebd46d538a65f3962aced87c18a530ee947ca0200524c48fa67c6") )
    ( 78005, uint256("0x191d1b362ec5c04d80731a2f782bccefebdb4b976c19dfcc400e8eb1fd6b172a") )
    ( 78006, uint256("0x780128527b837c3456a111341d9e0b135c7afe335f0cfcfd8664efccfa1d577e") )
    ( 78007, uint256("0xcbb3bc5241bf4d528214b5bad95bc17e92d047db85a1d68587d505de60e76189") )

		/* Feb '19 */
		( 200000, uint256("0xb4bb61f7cbe02b48ced1c5af6c8f95df3768d021f595d26e7e2d4d0a59f930b3") )
		( 200001, uint256("0x82954d9ed5ce7326df6b94f874c0ae0d3fefbec3627f4883b759b8bd6f15fb20") )
		( 200002, uint256("0xb507dd690d87a3fbec5acb18e5866a406177eaf23ef16ae50c8ecd6b3faa3a3b") )
		( 200003, uint256("0x233baac43596d3b71fd02c2910abe128b3cf89c058ca675272394833dbb7ca4e") )
		( 200004, uint256("0x0df2e80407cf97f48f3311758c8e36f6b7dec4b9846875b8af898aec9a32cbd7") )
    ;

  shcWallet = new SHCWallet();
	shcWallet->checkpoints = new CCheckpoints(SHC_COIN_IFACE, shc_mapCheckpoints);
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
	return (0);
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
	static int _index = 0;
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

	_index++;
	if (0 == (_index % 1000)) {
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
    return (ERR_INVAL);
  }

  CBlockIndex *pindexBest = GetBestBlockIndex(SHC_COIN_IFACE);
  median = pindexBest->GetMedianTimePast() + 1;

  const CPubKey& pubkey = shc_GetMainAccountPubKey(wallet);
  if (!pubkey.IsValid()) {
error(SHERR_INVAL, "shc_block_templ: error obtaining main pubkey.\n");
    return (ERR_INVAL);
  }

  pblock = shc_CreateNewBlock(pubkey);
  if (!pblock)
    return (ERR_INVAL);

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
  4, /* block version */
  SHC_PROTOCOL_VERSION, /* network proto ver */
  SHC_COIN_DAEMON_PORT,
  { 0xb9, 0xb9, 0xf9, 0xbb },
	62, /* S*/
	5, /* 3 */
	25, /* A */
	190,
	{0x04, 0x88, 0xB2, 0x1E},
	{0x04, 0x88, 0xAD, 0xE4},
	NODE_NETWORK | NODE_BLOOM | NODE_WITNESS,
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
