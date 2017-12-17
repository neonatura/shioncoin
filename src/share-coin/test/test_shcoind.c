

#include "test_shcoind.h"
#include "coin_proto.h"
#include "test_proto.h"
#include "stratum/stratum.h"


user_t *client_list;

extern TEST_jsonencap(CuTest*);
extern TEST_coin_key(CuTest*);
extern TEST_coin_key_phrase(CuTest*);
extern TEST_wallet(CuTest*);
extern TEST_coinaddr(CuTest*);
extern TEST_bignum(CuTest*);
extern TEST_sha256transform(CuTest*);
extern TEST_blockchain(CuTest*);
extern TEST_truncate(CuTest*);
extern TEST_reorganize(CuTest*);
extern TEST_serializetx(CuTest*);
extern TEST_matrix(CuTest*);
extern TEST_matrixtx(CuTest*);
extern TEST_signtx(CuTest*);
extern TEST_cointx(CuTest*);
extern TEST_offertx(CuTest*);
extern TEST_aliastx(CuTest*);
extern TEST_assettx(CuTest*);
extern TEST_certtx(CuTest*);
extern TEST_identtx(CuTest*);
extern TEST_bloom_create_insert_key(CuTest*);
extern TEST_bloom_match(CuTest*);
extern TEST_coin_hdkey(CuTest*);
extern TEST_channeltx(CuTest*);
extern TEST_hdtx(CuTest*);
extern TEST_exectx(CuTest*);
extern TEST_coin_table(CuTest*);
extern TEST_coin_spendall(CuTest*);
extern TEST_ctxtx(CuTest*);
extern TEST_scriptid(CuTest*);
extern TEST_segwit(CuTest*);
extern TEST_segwit_serializetx(CuTest*);
extern TEST_txmempool_pending(CuTest*);
extern TEST_txmempool_inval(CuTest*);
extern TEST_respend(CuTest*);
extern TEST_txmempool_depend(CuTest*);
extern TEST_chainwork(CuTest*);



extern void test_shcoind_init(void);

shpeer_t *serv_peer;

shpeer_t *shcoind_peer(void)
{
  return (serv_peer);
}

shtime_t server_start_t;

int main(int argc, char *argv[])
{
  CuString *output = CuStringNew();
  CuSuite* suite = CuSuiteNew();
  int fails;

  server_start_t = shtime();

  serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

  test_shcoind_init();

  /* core tests */
  SUITE_ADD_TEST(suite, TEST_coinaddr);
  SUITE_ADD_TEST(suite, TEST_bloom_create_insert_key);
  SUITE_ADD_TEST(suite, TEST_bloom_match);
  SUITE_ADD_TEST(suite, TEST_jsonencap);
  SUITE_ADD_TEST(suite, TEST_coin_key);
  SUITE_ADD_TEST(suite, TEST_coin_key_phrase);
  SUITE_ADD_TEST(suite, TEST_coin_hdkey);
  SUITE_ADD_TEST(suite, TEST_wallet);
  SUITE_ADD_TEST(suite, TEST_bignum);
  SUITE_ADD_TEST(suite, TEST_sha256transform);
  SUITE_ADD_TEST(suite, TEST_blockchain);
  SUITE_ADD_TEST(suite, TEST_matrix);
  SUITE_ADD_TEST(suite, TEST_serializetx);

  /* block-chain transaction tests */
  SUITE_ADD_TEST(suite, TEST_reorganize);
  SUITE_ADD_TEST(suite, TEST_matrixtx);
  SUITE_ADD_TEST(suite, TEST_identtx);
//  SUITE_ADD_TEST(suite, TEST_truncate);
  SUITE_ADD_TEST(suite, TEST_hdtx);
  SUITE_ADD_TEST(suite, TEST_signtx);
  SUITE_ADD_TEST(suite, TEST_cointx);
  SUITE_ADD_TEST(suite, TEST_aliastx);
  SUITE_ADD_TEST(suite, TEST_certtx);
  SUITE_ADD_TEST(suite, TEST_assettx);
  SUITE_ADD_TEST(suite, TEST_exectx);
  SUITE_ADD_TEST(suite, TEST_ctxtx);
//  SUITE_ADD_TEST(suite, TEST_channeltx);
//  SUITE_ADD_TEST(suite, TEST_offertx);
  SUITE_ADD_TEST(suite, TEST_scriptid);
  SUITE_ADD_TEST(suite, TEST_chainwork);

  /* tx memory pool */
  SUITE_ADD_TEST(suite, TEST_txmempool_pending);
  SUITE_ADD_TEST(suite, TEST_txmempool_inval);
  SUITE_ADD_TEST(suite, TEST_txmempool_depend);
  SUITE_ADD_TEST(suite, TEST_respend);

  /* segwit tests */
  SUITE_ADD_TEST(suite, TEST_segwit);
  SUITE_ADD_TEST(suite, TEST_segwit_serializetx);

  /* finale */
  SUITE_ADD_TEST(suite, TEST_coin_table);
  SUITE_ADD_TEST(suite, TEST_coin_spendall);

  CuSuiteRun(suite);
  CuSuiteSummary(suite, output);
  CuSuiteDetails(suite, output);
  printf("%s\n", output->buffer);
  CuStringDelete(output);
  fails = suite->failCount;
  CuSuiteDelete(suite);


  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  iface->op_term(iface, NULL);

  TERM_SECP256K1();

  shpeer_free(&serv_peer);

  return (fails);
}


