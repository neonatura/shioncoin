
/*
 * @copyright
 *
 *  Copyright 2015 Brian Burrell
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
extern TEST_reorganize(CuTest*);
extern TEST_serializetx(CuTest*);
extern TEST_matrix(CuTest*);
extern TEST_matrixtx(CuTest*);
extern TEST_signtx(CuTest*);
extern TEST_cointx(CuTest*);
extern TEST_offertx(CuTest*);
extern TEST_sip6_aliastx(CuTest*);
extern TEST_sip6_di_aliastx(CuTest*);
extern TEST_sip22_altblock(CuTest*);
extern TEST_sip25_assettx(CuTest*);
extern TEST_sip25_di_assettx(CuTest*);
extern TEST_sip5_certtx(CuTest*);
extern TEST_sip5_di_certtx(CuTest*);
extern TEST_sip12_consensus(CuTest*);
extern TEST_identtx(CuTest*);
extern TEST_bloom_create_insert_key(CuTest*);
extern TEST_bloom_match(CuTest*);
extern TEST_exectx(CuTest*);
extern TEST_coin_spendall(CuTest*);
extern TEST_coin_spendall_segwit(CuTest*);
extern TEST_sip10_ctxtx(CuTest*);
extern TEST_sip10_di_ctxtx(CuTest*);
extern TEST_sip10_geo_ctxtx(CuTest*);
extern TEST_scriptid(CuTest*);
extern TEST_segwit(CuTest*);
extern TEST_segwit_serializetx(CuTest*);
extern TEST_seqlocktx(CuTest*);
extern TEST_bech32(CuTest*);
extern TEST_bolo(CuTest*);
extern TEST_txmempool_pending(CuTest*);
extern TEST_txmempool_inval(CuTest*);
extern TEST_respend(CuTest*);
extern TEST_txmempool_depend(CuTest*);
extern TEST_chainwork(CuTest*);
extern TEST_orphan_block(CuTest*);
extern TEST_algo_sha256d(CuTest*);
extern TEST_txmempool_conflict(CuTest *);
extern TEST_bip32_hdkey(CuTest *);
extern TEST_sip33_hdkey(CuTest *);
extern TEST_sip33_tx(CuTest*);
extern TEST_account_cache(CuTest*);
extern TEST_account_addr(CuTest*);


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
  SUITE_ADD_TEST(suite, TEST_bip32_hdkey);
  SUITE_ADD_TEST(suite, TEST_sip33_hdkey);
  SUITE_ADD_TEST(suite, TEST_coinaddr);
  SUITE_ADD_TEST(suite, TEST_bloom_create_insert_key);
  SUITE_ADD_TEST(suite, TEST_bloom_match);
  SUITE_ADD_TEST(suite, TEST_jsonencap);
  SUITE_ADD_TEST(suite, TEST_coin_key);
  SUITE_ADD_TEST(suite, TEST_coin_key_phrase);

  SUITE_ADD_TEST(suite, TEST_wallet);
  SUITE_ADD_TEST(suite, TEST_bignum);
  SUITE_ADD_TEST(suite, TEST_sha256transform);
  SUITE_ADD_TEST(suite, TEST_blockchain);
  SUITE_ADD_TEST(suite, TEST_matrix);
  SUITE_ADD_TEST(suite, TEST_serializetx);

  /* block-chain transaction tests */
  SUITE_ADD_TEST(suite, TEST_reorganize);
	SUITE_ADD_TEST(suite, TEST_algo_sha256d);
  SUITE_ADD_TEST(suite, TEST_identtx);
  SUITE_ADD_TEST(suite, TEST_matrixtx);
  SUITE_ADD_TEST(suite, TEST_signtx);
  SUITE_ADD_TEST(suite, TEST_cointx);
  SUITE_ADD_TEST(suite, TEST_sip6_aliastx);
  SUITE_ADD_TEST(suite, TEST_sip5_certtx);
  SUITE_ADD_TEST(suite, TEST_sip22_altblock);
  SUITE_ADD_TEST(suite, TEST_sip25_assettx);
#ifdef USE_SEXE
  SUITE_ADD_TEST(suite, TEST_exectx);
#endif
  SUITE_ADD_TEST(suite, TEST_sip10_ctxtx);
  SUITE_ADD_TEST(suite, TEST_sip10_geo_ctxtx);
  SUITE_ADD_TEST(suite, TEST_scriptid);
  SUITE_ADD_TEST(suite, TEST_chainwork);
  SUITE_ADD_TEST(suite, TEST_offertx);

  /* tx memory pool */
  SUITE_ADD_TEST(suite, TEST_txmempool_pending);
  SUITE_ADD_TEST(suite, TEST_txmempool_inval);
  SUITE_ADD_TEST(suite, TEST_txmempool_depend);
  SUITE_ADD_TEST(suite, TEST_txmempool_conflict);

  SUITE_ADD_TEST(suite, TEST_respend);
  SUITE_ADD_TEST(suite, TEST_orphan_block);

  /* pre-finale */
  SUITE_ADD_TEST(suite, TEST_coin_spendall);

  SUITE_ADD_TEST(suite, TEST_bolo); /* SIP31 */

  /* segwit tests */
  SUITE_ADD_TEST(suite, TEST_segwit);
  SUITE_ADD_TEST(suite, TEST_segwit_serializetx);
  SUITE_ADD_TEST(suite, TEST_seqlocktx); /* BIP68+ */
  SUITE_ADD_TEST(suite, TEST_bech32); /* BIP173 */
  SUITE_ADD_TEST(suite, TEST_sip33_tx); /* SIP33 */
  SUITE_ADD_TEST(suite, TEST_account_cache);
  SUITE_ADD_TEST(suite, TEST_account_addr);

	/* dilithium SIP33 */
  SUITE_ADD_TEST(suite, TEST_sip6_di_aliastx);
  SUITE_ADD_TEST(suite, TEST_sip10_di_ctxtx);
  SUITE_ADD_TEST(suite, TEST_sip25_di_assettx);
  SUITE_ADD_TEST(suite, TEST_sip5_di_certtx);
  SUITE_ADD_TEST(suite, TEST_sip12_consensus);

	/* finale */
  SUITE_ADD_TEST(suite, TEST_coin_spendall_segwit);

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


