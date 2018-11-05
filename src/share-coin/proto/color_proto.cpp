
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
#include "txmempool.h"
#include "color/color_pool.h"
#include "color/color_block.h"
#include "color/color_wallet.h"
#include "color/color_txidx.h"

COLOR_CTxMemPool COLORBlock::mempool;
CBlockIndex *COLORBlock::pindexGenesisBlock = NULL;
int64 COLORBlock::nTimeBestReceived;
CBigNum COLORBlock::bnBestChainWork;
CBigNum COLORBlock::bnBestInvalidWork;




#if 0
extern void color_RegisterRPCOp(int ifaceIndex);
#endif


static int color_init(CIface *iface, void *_unused_)
{
  int ifaceIndex = GetCoinIndex(iface);
  int err;

	/* P2SH */
	iface->BIP16Height = 0; /* always enabled */
	/* v2.0 block (height in coinbase) */
	iface->BIP30Height = 0; /* always enabled */
	iface->BIP34Height = 0; /* always enabled */
	/* OP_CHECLOCKTIMEVERIFY */
	iface->BIP65Height = 0; /* always enabled */
	/* strict DER signature */
	iface->BIP66Height = 0; /* always enabled */


  iface->nRuleChangeActivationThreshold = 9072;
  iface->nMinerConfirmationWindow = 12096;

	iface->vDeployments[DEPLOYMENT_TESTDUMMY].bit = 28;
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nStartTime = 0;
	iface->vDeployments[DEPLOYMENT_TESTDUMMY].nTimeout = 0;

	/* BIP68, BIP112, and BIP113 */
	iface->vDeployments[DEPLOYMENT_CSV].bit = 0;
	iface->vDeployments[DEPLOYMENT_CSV].nStartTime = 0;
	iface->vDeployments[DEPLOYMENT_CSV].nTimeout = 0;

	/* BIP141, BIP143, and BIP147 */
	iface->vDeployments[DEPLOYMENT_SEGWIT].bit = 1;
	iface->vDeployments[DEPLOYMENT_SEGWIT].nStartTime = 0;
	iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout = 0;

#if 0
  color_RegisterRPCOp(COLOR_COIN_IFACE);
#endif

  colorWallet = new COLORWallet();
  SetWallet(COLOR_COIN_IFACE, colorWallet);

	if (!color_InitBlockIndex()) {
		error(SHERR_INVAL, "color_proto: unable to initialize block index table.");
		return (SHERR_INVAL);
	}
#if 0
  if (!opt_bool((char *)OPT_COLOR_BACKUP_RESTORE)) {
    /* normal startup */
    if (!color_InitBlockIndex()) {
      error(SHERR_INVAL, "color_proto: unable to initialize block index table.");
      return (SHERR_INVAL);
    }
  } else {
    /* over-write block-chain with pre-existing backup records */
    if (!color_RestoreBlockIndex()) {
      error(SHERR_INVAL, "color_proto: unable to initialize block index table.");
      return (SHERR_INVAL);
    }
  }
#endif

  if (!color_LoadWallet()) {
    error(SHERR_INVAL, "color_proto: unable to open load wallet.");
    return (SHERR_INVAL);
  }

  Debug("initialized COLOR block-chain.");

  return (0);
}

static int color_bind(CIface *iface, void *_unused_)
{
#if 0
  int err;

  err = unet_bind(UNET_COLOR, opt_num(OPT_COLOR_PORT), NULL);
  if (err) {
    error(err, "error binding COLOR socket port");
    return (err);
  }

  unet_timer_set(UNET_COLOR, color_server_timer); /* x10/s */
  unet_connop_set(UNET_COLOR, color_server_accept);
  unet_disconnop_set(UNET_COLOR, color_server_close);

  /* automatically connect to peers of 'color' service. */
  unet_bind_flag_set(UNET_COLOR, UNETF_PEER_SCAN);

  Debug("initialized COLOR service on port %d.", (int)iface->port);

#endif
  Debug("color_bind: initialized COLOR alternate block-chain.");
  return (0);
}

static int color_term(CIface *iface, void *_unused_)
{
  SetWallet(iface, NULL);
}
static int color_msg_recv(CIface *iface, CNode *pnode)
{
#if 0
  if (!pnode)
    return (0);

  if (!color_ProcessMessages(iface, pnode)) {
    /* log */
  }

#endif
return (0);
}
static int color_msg_send(CIface *iface, CNode *pnode)
{
#if 0

  if (!pnode)
    return (0);

  if (!color_SendMessages(iface, pnode, false)) {
    /* log */
  }
#endif

return (0);
}
static int color_peer_add(CIface *iface, void *arg)
{
return (0);
}
static int color_peer_recv(CIface *iface, void *arg)
{
return (0);
}

static int color_block_new(CIface *iface, CBlock **block_p)
{
  *block_p = new COLORBlock();
  return (0);
}

static int color_block_process(CIface *iface, CBlock *block)
{

  if (!color_ProcessBlock(block->originPeer, block))
    return (SHERR_INVAL);

  return (0);
}

static CPubKey color_GetMainAccountPubKey(CWallet *wallet)
{
  static CPubKey ret_key;
	static int _index;
	string strAccount("");

  if (!ret_key.IsValid()) {
    GetAccountAddress(wallet, strAccount, false);

    ret_key = GetAccountPubKey(wallet, strAccount);
    if (!ret_key.IsValid()) {
      error(SHERR_INVAL, "(color) GetMainAccountPubKey: error obtaining main account pubkey.");
#if 0
      CReserveKey reservekey(wallet);
      ret_key = reservekey.GetReservedKey();
      reservekey.KeepKey();
#endif
			ret_key = wallet->GenerateNewKey();
    } else {
      CCoinAddr addr(wallet->ifaceIndex, ret_key.GetID()); 
      Debug("(color) GetMainAccountPubKey: using '%s' for mining address.",
          addr.ToString().c_str()); 
    }

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

static int color_block_templ(CIface *iface, CBlock **block_p)
{
#if 0
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

  CBlockIndex *pindexBest = GetBestBlockIndex(COLOR_COIN_IFACE);
  median = pindexBest->GetMedianTimePast() + 1;

  const CPubKey& pubkey = color_GetMainAccountPubKey(wallet);
  if (!pubkey.IsValid()) {
error(SHERR_INVAL, "color_block_templ: error obtaining main pubkey.\n");
    return (NULL);
  }

	uint160 hColor = 0;
  pblock = color_CreateNewBlock(hColor, NULL, pubkey);
  if (!pblock)
    return (NULL);

  pblock->nTime = MAX(median, GetAdjustedTime());
  pblock->nNonce = 0;

  *block_p = pblock;

  return (0);
#endif
	*block_p = NULL;
	return (SHERR_OPNOTSUPP);
}


static int color_tx_new(CIface *iface, void *arg)
{
return (0);
}

static int color_tx_pool(CIface *iface, CTxMemPool **pool_p)
{
  *pool_p = &COLORBlock::mempool;
  return (0);
}








#ifdef __cplusplus
extern "C" {
#endif

coin_iface_t color_coin_iface = {
  "color",
  TRUE, /* enabled */
  COIN_IFACE_VERSION(COLOR_VERSION_MAJOR, COLOR_VERSION_MINOR,
      COLOR_VERSION_REVISION, COLOR_VERSION_BUILD), /* cli ver */
  2, /* block version */
  COLOR_PROTOCOL_VERSION, /* network proto ver */
  0, //COLOR_COIN_DAEMON_PORT,
  { 0xd9, 0xd9, 0xf9, 0xbd },
	29, /* C */
	5, /* 3 */
	25, /* A */
	157,
	{0x04, 0x88, 0xB2, 0x1E},
	{0x04, 0x88, 0xAD, 0xE4},
  0, //NODE_NETWORK | NODE_BLOOM,
  COLOR_MIN_INPUT,
  COLOR_MAX_BLOCK_SIZE,
  COLOR_MAX_ORPHAN_TRANSACTIONS,
  COLOR_MAX_TRANSACTION_WEIGHT,
  COLOR_MIN_TX_FEE,
  COLOR_MIN_RELAY_TX_FEE,
  COLOR_MAX_TX_FEE,
  COLOR_MAX_FREE_TX_SIZE,
  COLOR_MAX_MONEY,
  COLOR_COINBASE_MATURITY, 
  COLOR_MAX_SIGOPS,
  COINF(color_init),
  COINF(color_bind),
  COINF(color_term),
  COINF(color_msg_recv),
  COINF(color_msg_send),
  COINF(color_peer_add),
  COINF(color_peer_recv),
  COINF(color_block_new),
  COINF(color_block_process),
  COINF(color_block_templ),
  COINF(color_tx_new),
  COINF(color_tx_pool)
};


#ifdef __cplusplus
}
#endif
