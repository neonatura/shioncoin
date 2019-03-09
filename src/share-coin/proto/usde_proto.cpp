
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

int64 USDEBlock::nTargetTimespan = 7200; /* two hours */
int64 USDEBlock::nTargetSpacing = 60; /* one minute */

extern void RegisterRPCOpDefaults(int ifaceIndex);

static int usde_init(CIface *iface, void *_unused_)
{
  int ifaceIndex = GetCoinIndex(iface);
  int err;

	/* P2SH */
	iface->BIP16Height = 1; 
	/* v2.0 block (height in coinbase) */
	iface->BIP30Height = 0; /* always enabled. */
	iface->BIP34Height = -1; /* never enabled */
	/* OP_CHECLOCKTIMEVERIFY */
	iface->BIP65Height = -1; /* never enabled */
	/* strict DER signature */
	iface->BIP66Height = -1; /* never enabled */

  iface->nRuleChangeActivationThreshold = 15120; // 75% of 20160
  iface->nMinerConfirmationWindow = 20160; /* aprox */

  RegisterRPCOpDefaults(USDE_COIN_IFACE);


  MapCheckpoints usde_mapCheckpoints =
    boost::assign::map_list_of
    ( 0, uint256("0x33abc26f9a026f1279cb49600efdd63f42e7c2d3a15463ad8090505d3e967752"))
    ( 1, uint256("0xec9c4d88a04ede4cd777234ac504084c36cb25080c45b4741e2cfc0d5994359a"))
    ( 50, uint256("0x253e145aae6b516ac47b9f6855675bea6f589922b74195cee77b31df1ebbc8c7"))
    ( 3000, uint256("0xb0bf45beaad4446c666158baee04488267e622fabc49e6686b798ccd122018fe"))
    ( 8000, uint256("0xde808d01865606385726824fd9f1466aacb94f233cd9713dc989333bcea15312"))
    ( 10000, uint256("0xb5bab4cfa3e92985302a95afeb1b42755d6c240e73af61deb2599cb72aba991e"))
    ( 20000, uint256("0x2f35019fbf04de7287aaa18b4010d2317779aac0a875183ff52934b8a3fee685"))
    ( 135798, uint256("0xbd8423b7e21e1422953008db6ab7197b71b4cfabb9d9e69cc0cbcdcd7dd86b30"))
    ( 1000, uint256("0xa59b03d739edd29c98cf563a1f7b57e7da8306abcae4e18397bd1e320fa79007"))
    ( 100000, uint256("0x9376d399b8b3f34549d05b6858f4cba534e78cba2306c414117dcaa057c23081"))
    ( 250000, uint256("0x7e86b4d451fcfdf4c59e7f0a8081b33366a50a82b276073c55b758d7769333bf"))
    ( 444444, uint256("0xd4b76e38fe481aef65e4dcc52703f34187aff8dcd037b1ab7abe7b7429af7d95"))
    ( 500000, uint256("0x17a3060325e40e311b42763d44574b3f63a3525f1f7644588fe00ca824c7b21e"))
    ( 750000, uint256("0xa3b1c4f90225299fef3a43851be960b49ca70e8500d1891612e2836cfbeed188"))
    ( 888888, uint256("0x96d7bf79871c8d6d887e098c444071cfda4548e502d1965e255b1b0e71c93c7a"))
    ( 1000000, uint256("0xd444bebec6a7f1345e6bee094d913bdfff0b7ae833c3e3f17b90c98fdc899aa4"))
    ( 1047382, uint256("0x7489d8515228bc90bf43ca09af944e5b3e13f43f1a15f80ae5f211533a26e791"))
    ( 1084324, uint256("0x59e7296adef10db8f517c1e05cc10b1d83925ebe53d81608a5f929ca3b98d94b"))
    ( 1087716, uint256("0xfd322ca21f75bb01a92d903fd435a48a70fc416b2f439d3eadfbd4385138b5b7"))
    ( 1087717, uint256("0x23fad9f5b12079dea9362a51d77e70f49a4d484ad93ca3b0e97fac38fd0addc5"))
    ( 1087718, uint256("0xa5c0965a380a1a5f99065472da29f5a3f1fc4c9713072597e63e402f87f1812e"))
    ( 1387912, uint256("0xb64a82f874dc048cf85d0058949561f679b6e21720e29d309949cbb60fd2345a"))
    ( 1387913, uint256("0x672b6e14296aafd712bfcb40bd58bc7f267b91a9af5bb5516e023629b8f14c96"))

    /* Feb '17 */
    ( 1500011, uint256("0xc64be1f5f3fc10e70436282448af92412bb0085107b9e0fd587484f73951571f") )
    ( 1500012, uint256("0x559ddd79cc6b2448e8f9b349f672a674181c251216b1d53c21aec74dd231ae19") )
    ( 1500013, uint256("0xf6b327bffa001480d5c9fe6cf1ff52f3f6169ea3b2fb3dfd7bee317d46673142") )
    ( 1500014, uint256("0xe112576e56fd471a4dd9aea6fed40888dfc2d6f4fdeb5c6bedb6d808c9a5c92d") )

    /* May '17 */
    ( 1512101, uint256("0x0b350aa230e612a7f2fd8c45a9f39063c1b99cdde344ee571a19cdccc097c7f6") )
    ( 1512102, uint256("0x393998ccc586374862d45f2f6effa67b27d89acab6eed8034c7d159ee3eb1a26") )
    ( 1512103, uint256("0x19750648e7d11b345f74d466af91da58f19a8d3026793e27568a7b7544f68764") )
    ( 1512104, uint256("0x94194d4819e6b47ff380c86056c50ff738b43e483e0439d5b0192296fb5f63bc") )
    ;

  usdeWallet = new USDEWallet();
	usdeWallet->checkpoints = new CCheckpoints(USDE_COIN_IFACE, usde_mapCheckpoints);
  SetWallet(USDE_COIN_IFACE, usdeWallet);


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
error(SHERR_INVAL, "usde_proto: unable to load wallet.\n");
    return (SHERR_INVAL);
  }

  Debug("initialized USDE block-chain.");

  return (0);
}

static int usde_bind(CIface *iface, void *_unused_)
{
  int err;

	/* set configured usde peer port for listening for new sockets. */
	iface->port = opt_num(OPT_USDE_PORT);

  err = unet_bind(UNET_USDE, iface->port, NULL);
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
	string strAccount("");

  if (!ret_key.IsValid()) {
    GetAccountAddress(wallet, strAccount, false);

    ret_key = GetAccountPubKey(wallet, strAccount);
    if (!ret_key.IsValid()) {
      error(SHERR_INVAL, "(usde) GetMainAccountPubKey: error obtaining main account pubkey.");
#if 0
      CReserveKey reservekey(wallet);
      ret_key = reservekey.GetReservedKey();
      reservekey.KeepKey();
#endif
			ret_key = wallet->GenerateNewKey();
    } else {
      CCoinAddr addr(wallet->ifaceIndex, ret_key.GetID()); 
      Debug("(usde) GetMainAccountPubKey: using '%s' for mining address.",
          addr.ToString().c_str()); 
    }

    /* mining pool fees */
    string strBankAccount("bank");
    GetAccountAddress(wallet, strBankAccount, false);
    /* cpu miner */
    string strSystemAccount("system");
    GetAccountAddress(wallet, strSystemAccount, false);
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
error(SHERR_INVAL, "usde_block_templ: error obtaining main pubkey.\n");
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
	38, /* G */
	5,
	0, /* not supported */
	166, /* 38 + 128 */
	{0x0, 0x0, 0x0, 0x0}, /* not supported */
	{0x0, 0x0, 0x0, 0x0}, /* not supported */
  NODE_NETWORK,
  USDE_MIN_INPUT,
  USDE_MAX_BLOCK_SIZE,
  USDE_MAX_ORPHAN_TRANSACTIONS,
  USDE_MAX_TRANSACTION_WEIGHT,
  USDE_MIN_TX_FEE,
  USDE_MIN_RELAY_TX_FEE,
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
