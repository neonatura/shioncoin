
/*
 * @copyright
 *
 *  Copyright 2016 Brian Burrell
 *
 *  This file is part of Shioncoin.
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
	iface->BIP34Height = 1;
	/* OP_CHECLOCKTIMEVERIFY */
	iface->BIP65Height = 1;
	/* strict DER signature */
	iface->BIP66Height = 1;

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

	/* DEFINED: SIP32 */
	iface->vDeployments[DEPLOYMENT_ALGO].bit = 5;
	iface->vDeployments[DEPLOYMENT_ALGO].nStartTime = 1559347200; /* 06/01/19 */
	iface->vDeployments[DEPLOYMENT_ALGO].nTimeout = 1590969600; /* 06/01/20 */

	iface->vDeployments[DEPLOYMENT_PARAM].bit = 6;
	iface->vDeployments[DEPLOYMENT_PARAM].nStartTime =  1609459200; /* 01/01/21 */
	iface->vDeployments[DEPLOYMENT_PARAM].nTimeout = 1640995200; /* 01/01/22 */ 

	iface->vDeployments[DEPLOYMENT_BOLO].bit = 7;
	iface->vDeployments[DEPLOYMENT_BOLO].nStartTime =  1609459200; /* 01/01/21 */
	iface->vDeployments[DEPLOYMENT_BOLO].nTimeout = 1640995200; /* 01/01/22 */ 

  shc_RegisterRPCOp(SHC_COIN_IFACE);

	/* alternate block-chain rpc operations. */
  color_RegisterRPCOp(SHC_COIN_IFACE);

  MapCheckpoints shc_mapCheckpoints =
    boost::assign::map_list_of
		( 0, uint256("a2128a434c48ff41bfb911857639fa24b69012aebf690b12e6dfa799cd5d914e") )
		( 19900, uint256("9acf29e637ceaeefc820b47b87acde5ea57380d59f36ddd3a05692196691be91") )
		( 19901, uint256("949f60599254173425aa2d25c7bd39783aee5fba13016eb8dc15e079ab928888") )
		( 19902, uint256("341b2416086cdf9c9e4ba9c843c31a646a96141614ec702f65255bfbd76d6ec8") )
		( 170000, uint256("56922c13c4e420b7da7b36651c63e22906d453e3ccd0ffbc28fb91fbf0a494da") )
		( 170001, uint256("3017b8b9eaa6ae3795bbad2eca000df21c946862e60ea32127b39fd8d7acc36b") )
		( 170002, uint256("0a5b5aef267804884d567b7714c1a790b0bde6589a563857b1b897ea8f5eebec") )
		( 170003, uint256("fd83b7e175bd75ec2be1f00fd642c11b2db9d3558d97c537cbdd2c5f6ed6d0f7") )
		( 170004, uint256("c0e59e4cb0ea0fb92ec27d23b2987dca3bddc64145cecfb9b44c882125f8acc5") )
		( 170005, uint256("9a3f7ef2ffcd44c227df7e3703559949e837ec0bfc53e38f69b59e0e8ca2e45f") )
		( 170006, uint256("Aea7339237b6d1eb5237aa03b5fc50ad2c245e16d4bff5b723393a056062945c2") )
		( 170007, uint256("be18cce78552b2b7dd0205be59d57962a884cc9552a6b05b5cb8762a40aee613") )
		( 170034, uint256("c26119229d19e51051513a45b423dbf733759716c6fe6166ac2e6213033efaaa") )
		( 170035, uint256("b898b7a0fccc3498fecb4b17815bda8418cbb019084ee070df43774f37b1cfec") )
		( 170036, uint256("007393aba9fba9877bdda1afcf6f4c5ef1fc21d8d7b1a64b34d973e7731c6a67") )
		( 170037, uint256("75364720669a6b1e19b3dc7d8cc778c9e288b1d1440f65a7dca47990f26d46a6") )
		( 170038, uint256("63ece1279c4ca01af87fd2e46e22b2b87c4ec46734fa2f66a05d7af39ad9331e") )
		( 170039, uint256("b2a063a8d7e2f779ad134f48f32480d23e227be3ac723abb795f8c4dd861c2e5") )
		( 170040, uint256("833391ed739c9cd28ab1616c99e92a68a197b7b4fac64b68e2f0d4e294ba02e8") )
		( 170067, uint256("2ed09c38123f8ad5d800fea26e1a2ee8a1e1b3d6f7db18a855e8731f4d8fc9ff") )
		( 170068, uint256("61e21899ec6d28a4d052d35825efa2a0663fd9185a7bf3ce102e6fefa7080ca8") )
		( 170069, uint256("f5d2cb0f760fd32123914607cc7907614d968f39d106e61f84cfb3c97199ed57") )
		( 170070, uint256("d03d79e50d4273b1e15e37bbe87d8a0ab425c1a1b120e6f8924e7404d25582cd") )
		( 170071, uint256("b95cfc336e2dfbca6b9422d7402551a74bc93af827ec3cf14ab7e926f8e55246") )
		( 170072, uint256("952951e5c939c6faf6a14d37130f070e37094c3ea1d1b798fd2f67de018756e4") )
		( 170073, uint256("6ba051f9abc46ca85819b5419755d79570a5ae77c5a5de81c68b7a6f77ddef28") )
		( 299998, uint256("85563cf18c096f6fa43952b965c3e3f3fa69ce0459af18c7ae1716a085433179") )
		( 599995, uint256("337ddb5b6d5bbd4e513d2a7767c35b1a9ba5c27422ff20c3ac60eeef058b43ca") )
		( 810001, uint256("00000000008bbddcafcdd19153fbd376dd952d14df270c0cea8276797eae5c39") )
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
#if 0
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

#if 0
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
#endif

  return (ret_key);
#endif

  static CPubKey pubkey;
  if (!pubkey.IsValid()) {
    CAccountCache *account = wallet->GetAccount("");
    //account->GetPrimaryPubKey(ACCADDR_MINER, pubkey);
		account->GetCoinbasePubKey(pubkey);
    /* cpu miner */
		wallet->GetAccount("system");
  }
  return (pubkey);
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
	{0x04, 0x80, 0xB2, 0x1E},
	{0x04, 0x80, 0xAD, 0xE4},
	NODE_NETWORK | NODE_BLOOM | NODE_WITNESS,
  SHC_MIN_INPUT,
  SHC_MAX_BLOCK_SIZE,
  SHC_MAX_BLOCK_SIZE,
  SHC_MAX_ORPHAN_TRANSACTIONS,
  SHC_MAX_TRANSACTION_WEIGHT,
  SHC_MIN_TX_FEE,
  SHC_MIN_RELAY_TX_FEE,
  SHC_MIN_RELAY_TX_FEE,
  SHC_MAX_TX_FEE,
  SHC_MAX_FREE_TX_SIZE,
  SHC_MAX_MONEY,
  SHC_COINBASE_MATURITY, 
  SHC_MAX_SIGOPS,
	SHC_MAX_SCRIPT_SIZE,
	SHC_MAX_SCRIPT_ELEMENT_SIZE,
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
