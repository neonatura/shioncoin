

#include "test_shcoind.h"
#include "server/wallet.h"
#include "server/test/test_pool.h"
#include "server/test/test_block.h"
#include "server/test/test_wallet.h"
#include "server/test/test_txidx.h"
#include "server/eckey.h"

#ifdef __cplusplus
extern "C" {
#endif


void test_shcoind_init(void)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  uint256 thash;

  /* initialize configuration options */
  opt_init();

  INIT_SECP256K1();

  /* initialize chains */
  bc_t *tx_bc = GetBlockTxChain(iface);
  bc_t *bc = GetBlockChain(iface);

  /* load wallet */
  testWallet = new TESTWallet();
  SetWallet(TEST_COIN_IFACE, testWallet);
  //RegisterWallet(testWallet);
  //RandAddSeedPerfmon();

	GetCoinByIndex(EMC2_COIN_IFACE)->enabled = FALSE;
	GetCoinByIndex(TESTNET_COIN_IFACE)->enabled = FALSE;

  iface->op_init(iface, NULL);


#ifdef USE_LEVELDB_COINDB
  /* initialize chain */
  {
    TESTTxDB txdb("cr");
 //   txdb.ReadHashBestChain(thash);
    txdb.Close();
  }
#endif
  test_CreateGenesisBlock();


  /* initialize wallet */
  test_LoadWallet();


	iface->vDeployments[DEPLOYMENT_CSV].bit = 0;
  iface->vDeployments[DEPLOYMENT_CSV].nStartTime = time(NULL) + 3600;
  iface->vDeployments[DEPLOYMENT_CSV].nTimeout = time(NULL) + 7200;
  iface->vDeployments[DEPLOYMENT_SEGWIT].bit = 1;
  iface->vDeployments[DEPLOYMENT_SEGWIT].nStartTime = time(NULL) + 3600;
  iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout = time(NULL) + 7200; 
  iface->vDeployments[DEPLOYMENT_PARAM].bit = 6;
  iface->vDeployments[DEPLOYMENT_PARAM].nStartTime = time(NULL) + 3600;
  iface->vDeployments[DEPLOYMENT_PARAM].nTimeout = time(NULL) + 7200;

#if 0
  iface->nRuleChangeActivationThreshold = 3;
  iface->nMinerConfirmationWindow = 10;
#endif

}


#ifdef __cplusplus
}
#endif
