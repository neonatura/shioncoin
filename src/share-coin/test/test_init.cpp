

#include "test_shcoind.h"
#include "server/wallet.h"
#include "server/test/test_pool.h"
#include "server/test/test_block.h"
#include "server/test/test_wallet.h"
#include "server/test/test_txidx.h"
#include "server/derkey.h"

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
  RandAddSeedPerfmon();

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


  iface->nRuleChangeActivationThreshold = 5;
  iface->nMinerConfirmationWindow = 5;

//CBlock *test_block = test_GenerateBlock(); /* DEBUG: */

}


#ifdef __cplusplus
}
#endif
