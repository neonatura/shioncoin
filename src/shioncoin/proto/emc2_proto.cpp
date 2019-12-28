
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
#include "checkpoints.h"
#include "emc2/emc2_netmsg.h"
#include "emc2/emc2_pool.h"
#include "emc2/emc2_block.h"
#include "emc2/emc2_wallet.h"
#include "emc2/emc2_txidx.h"

#ifdef EMC2_SERVICE
EMC2_CTxMemPool EMC2Block::mempool;

CBlockIndex *EMC2Block::pindexGenesisBlock = NULL;

int64 EMC2Block::nTimeBestReceived;

extern void RegisterRPCOpDefaults(int ifaceIndex);
#endif

static int emc2_init(CIface *iface, void *_unused_)
{
#ifdef EMC2_SERVICE
  int ifaceIndex = GetCoinIndex(iface);
  int err;

	/* P2SH */
	iface->BIP16Height = 1; /* always enabled */
	/* v2.0 block (height in coinbase) */
	iface->BIP30Height = 1; /* always enabled */
	iface->BIP34Height = 1500000;
	/* OP_CHECLOCKTIMEVERIFY */
	iface->BIP65Height = 1; /* always enabled */
	/* strict DER signature */
	iface->BIP66Height = 1; /* always enabled */

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


	MapCheckpoints emc2_mapCheckpoints =
		boost::assign::map_list_of
		(       0, uint256("0x4e56204bb7b8ac06f860ff1c845f03f984303b5b97eb7b42868f714611aed94b"))
		(   14871, uint256("0x5dedc3dd860f008c717d69b8b00f0476de8bc6bdac8d543fb58c946f32f982fa"))
		(   36032, uint256("0xff37468190b2801f2e72eb1762ca4e53cda6c075af48343f28a32b649512e9a8"))
		(   51365, uint256("0x702b407c68091f3c97a587a8d92684666bb622f6821944424b850964b366e42c"))
		(  621000, uint256("0xe2bf6d219cff9d6d7661b7964a05bfea3128265275c3673616ae71fed7072981"))

		/* Feb '17 */
		( 1290011, uint256("0xb71db4ec1e17678c3f9bd18b04b1fada4134ee0fc84ac21d1fbab02f2ffc181a") )
		( 1290012, uint256("0xa19aba9e1adb9e9aefff386ec32416394bfc38fc7ff98cc5d7c2f1ab4e001775") )
		( 1290013, uint256("0x273e013035bf614996f97cf173b0ea5b581a731cb6872fd1f8eda0b2035bf905") )
		( 1290014, uint256("0x72aa3d5e2cee606343b9c80b89c2fcb3384131236a0aba8e2c22a9118f4f2beb") )

		/* May '17 */
		( 1315701, uint256("0xd4e1fc80f5d483c12ed9b7358ef3e8b38ad4c89407469108670a3590db2417b1") )
		( 1315702, uint256("0x1c69f83bcf2e113b7477c4e6f7b2545731db1c43d4d2790d37004348e7dc095a") )
		( 1315703, uint256("0x8dc088b551c042a92c6b52e14ff83bbe8a39f2a15a66108fc66a5aac12e5721b") )
		( 1315704, uint256("0x4ffe997b4ab52d56c04a015b0f5f81f7cb0e1aadff63c6d83a5331e06b90804d") )

		/* Dec '17 */
		( 1410100, uint256("0xf6736ff2a7743014ab1902e442328f5c9928ce7f4edb2b4fd0130010cb4cebc4") )

		/* Nov '18 */
		( 2137077, uint256("0xc1365bd700afde707f0f173b402b5206eea04a4cc4ea54b2660288fcb55b6292") )
		( 2137078, uint256("0xc82d89245fb2fe6edeb96f6187a3058e058f71eb6b996a3b4f69cc981f3c74e3") )
		( 2137079, uint256("0x90af60a1937bfa200eee99710f6c94319ab7c621dc72803c22edd2fb98544045") )
		( 2137080, uint256("0xa1eefc654694774d00b39e7d15f3b9211e3069e616cdb8df790028d6e8ba3a71") )
		( 2139040, uint256("0x2e4ce04696259f90e5943ef3e0ce9224c47780e466b4d45521ca6d7b21fcb0dc") )
		( 2152000, uint256("0xa31cadf1a118d78e07df6b337c4d31369033da41098e981a4773841ec2344a69") )
		( 2152015, uint256("0x3590d55a21bf5ca183ab924938abc742eaeb3cbda6f8c1d4f1e25f2f975240ce") )
		( 2152016, uint256("0x7420f5567a41bc15fd2d1946e81687541178655edd9b10ef2538f4af20c2e579") )
		( 2152656, uint256("0xfe6e9d6fbdf12a2a79f68d395521366295e9410f83afb1a7923aaef61529c436") )
		( 2152657, uint256("0x0f60bc1dc69f3d814f9eb65d20bd101ff54631a379761433b9d53a8567bc5d18") )
		;

  emc2Wallet = new EMC2Wallet();
	emc2Wallet->checkpoints = new CCheckpoints(EMC2_COIN_IFACE, emc2_mapCheckpoints);
  SetWallet(EMC2_COIN_IFACE, emc2Wallet);



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
    error(SHERR_INVAL, "emc2_proto: unable to load wallet.\n");
    return (SHERR_INVAL);
  }

  Debug("initialized EMC2 block-chain.");
#endif

  return (0);
}

int get_emc2_bind_port(void)
{
	return ((int)opt_num(OPT_EMC2_PORT));
}

static int emc2_bind(CIface *iface, void *_unused_)
{
  int err;

	iface->port = get_emc2_bind_port();

  err = unet_bind(UNET_EMC2, iface->port, NULL);
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
#ifdef EMC2_SERVICE
  if (!pnode)
    return (0);

  if (!emc2_ProcessMessages(iface, pnode)) {
    /* log */
  }
#endif
return (0);
}
static int emc2_msg_send(CIface *iface, CNode *pnode)
{
#ifdef EMC2_SERVICE
  if (!pnode)
    return (0);

  if (!emc2_SendMessages(iface, pnode, false)) {
    /* log */
  }
#endif
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
#ifdef EMC2_SERVICE
  *block_p = new EMC2Block();
	return (0);
#else
	return (ERR_OPNOTSUPP);
#endif
}

static int emc2_block_process(CIface *iface, CBlock *block)
{
#ifdef EMC2_SERVICE
  if (!emc2_ProcessBlock(block->originPeer, block))
    return (SHERR_INVAL);

  return (0);
#else
	return (ERR_OPNOTSUPP);
#endif
}

static CPubKey emc2_GetMainAccountPubKey(CWallet *wallet)
{
#if 0
  static CPubKey ret_key; 
	string strAccount("");

  if (!ret_key.IsValid()) {
    GetAccountAddress(wallet, strAccount, false);

    ret_key = GetAccountPubKey(wallet, strAccount);
    if (!ret_key.IsValid()) {
      error(SHERR_INVAL, "GetMainAccountPubKey: emc2: error obtaining main account pubkey.");
#if 0
      CReserveKey reservekey(wallet);
      ret_key = reservekey.GetReservedKey();
      reservekey.KeepKey();
#endif
    } else {
      CCoinAddr addr(wallet->ifaceIndex, ret_key.GetID()); 
      Debug("(emc2) GetMainAccountPubKey: using '%s' for mining address", 
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
#endif

  static CPubKey pubkey;
  if (!pubkey.IsValid()) {
    CAccountCache *account = wallet->GetAccount("");
    account->GetPrimaryPubKey(ACCADDR_MINER, pubkey);
    /* miner fee */
		wallet->GetAccount("bank");
    /* cpu miner */
		wallet->GetAccount("system");
  }
  return (pubkey);
}

static int emc2_block_templ(CIface *iface, CBlock **block_p)
{
#ifdef EMC2_SERVICE
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CBlock* pblock;
  unsigned int median;
  int reset;
    
  if (!wallet) {
    unet_log(ifaceIndex, "GetBlocKTemplate: Wallet not initialized.");
    return (ERR_INVAL);
  }

  CBlockIndex *pindexBest = GetBestBlockIndex(EMC2_COIN_IFACE);
  median = pindexBest->GetMedianTimePast() + 1;

  const CPubKey& pubkey = emc2_GetMainAccountPubKey(wallet);
  if (!pubkey.IsValid()) {
    error(SHERR_INVAL, "emc2_block_templ: error obtaining main pubkey.\n"); 
    return (ERR_INVAL);
  }

  pblock = emc2_CreateNewBlock(pubkey);
  if (!pblock)
    return (ERR_INVAL);

  pblock->nTime = MAX(median, GetAdjustedTime());
  pblock->nNonce = 0;

  *block_p = pblock;

  return (0);
#else
	return (ERR_OPNOTSUPP);
#endif
}

static int emc2_tx_new(CIface *iface, void *arg)
{
return (0);
}

static int emc2_tx_pool(CIface *iface, CTxMemPool **pool_p)
{
#ifdef EMC2_SERVICE
  *pool_p = &EMC2Block::mempool;
  return (0);
#else
	return (ERR_OPNOTSUPP);
#endif
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
	33, /* E */
	5,
	55,
	176,/* !+128 */
	{ 0x04, 0x88, 0xb2, 0x1e },
	{ 0x04, 0x88, 0xad, 0xe4 },
  NODE_NETWORK | NODE_BLOOM | NODE_WITNESS,
  EMC2_MIN_INPUT,
  EMC2_MAX_BLOCK_SIZE,
  EMC2_MAX_BLOCK_SIZE,
  EMC2_MAX_ORPHAN_TRANSACTIONS,
  EMC2_MAX_TRANSACTION_WEIGHT,
  EMC2_MIN_TX_FEE,
  EMC2_MIN_RELAY_TX_FEE,
  EMC2_MIN_RELAY_TX_FEE,
  EMC2_MAX_TX_FEE,
  EMC2_MAX_FREE_TX_SIZE,
  EMC2_MAX_MONEY,
  EMC2_COINBASE_MATURITY, 
  EMC2_MAX_SIGOPS,
	EMC2_MAX_SCRIPT_SIZE,
	EMC2_MAX_SCRIPT_ELEMENT_SIZE,
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
