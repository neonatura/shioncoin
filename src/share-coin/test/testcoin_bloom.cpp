
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

#include "test_shcoind.h"
#include <string>
#include <vector>
#include "wallet.h"
#include "test/test_pool.h"
#include "test/test_block.h"
#include "test/test_txidx.h"




#ifdef __cplusplus
extern "C" {
#endif


_TEST(bloom_create_insert_key)
{
  string strSecret = string("6afmzdRwDThTdg9L8XYbvUsvMcLK2KpNkpuDr5gfuSBzTtebVjy");
  CCoinSecret vchSecret;
  _TRUE(vchSecret.SetString(strSecret) == true);

  CKey key;
  bool fCompress;
  key.SetSecret(vchSecret.GetSecret(fCompress));
  CPubKey pubkey = key.GetPubKey();

  CBloomFilter filter(TEST_COIN_IFACE, 2, 0.001, 0, BLOOM_UPDATE_ALL);
  filter.insert(pubkey.Raw());
  uint160 hash = pubkey.GetID();
  filter.insert(hash);

  string hex("21d792");
  _TRUE(filter.ToString() == hex);

}

_TEST(bloom_match)
{
  /* origin */
  CTransaction tx;
  CDataStream stream(ParseHex("01000000010b26e9b7735eb6aabdf358bab62f9816a21ba9ebdb719d5299e88607d722c190000000008b4830450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a0141046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339ffffffff021bff3d11000000001976a91404943fdd508053c75000106d3bc6e2754dbcff1988ac2f15de00000000001976a914a266436d2965547608b9e15d9032a7b9d64fa43188ac00000000"), SER_DISK, CLIENT_VERSION);
  stream >> tx;
//  fprintf(stderr, "DEBUG: bloom_match: %s\n", tx.ToString().c_str());

  /* spent */
  unsigned char ch[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0xff, 0x7f, 0xcd, 0x4f, 0x85, 0x65, 0xef, 0x40, 0x6d, 0xd5, 0xd6, 0x3d, 0x4f, 0xf9, 0x4f, 0x31, 0x8f, 0xe8, 0x20, 0x27, 0xfd, 0x4d, 0xc4, 0x51, 0xb0, 0x44, 0x74, 0x01, 0x9f, 0x74, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00, 0xda, 0x0d, 0xc6, 0xae, 0xce, 0xfe, 0x1e, 0x06, 0xef, 0xdf, 0x05, 0x77, 0x37, 0x57, 0xde, 0xb1, 0x68, 0x82, 0x09, 0x30, 0xe3, 0xb0, 0xd0, 0x3f, 0x46, 0xf5, 0xfc, 0xf1, 0x50, 0xbf, 0x99, 0x0c, 0x02, 0x21, 0x00, 0xd2, 0x5b, 0x5c, 0x87, 0x04, 0x00, 0x76, 0xe4, 0xf2, 0x53, 0xf8, 0x26, 0x2e, 0x76, 0x3e, 0x2d, 0xd5, 0x1e, 0x7f, 0xf0, 0xbe, 0x15, 0x77, 0x27, 0xc4, 0xbc, 0x42, 0x80, 0x7f, 0x17, 0xbd, 0x39, 0x01, 0x41, 0x04, 0xe6, 0xc2, 0x6e, 0xf6, 0x7d, 0xc6, 0x10, 0xd2, 0xcd, 0x19, 0x24, 0x84, 0x78, 0x9a, 0x6c, 0xf9, 0xae, 0xa9, 0x93, 0x0b, 0x94, 0x4b, 0x7e, 0x2d, 0xb5, 0x34, 0x2b, 0x9d, 0x9e, 0x5b, 0x9f, 0xf7, 0x9a, 0xff, 0x9a, 0x2e, 0xe1, 0x97, 0x8d, 0xd7, 0xfd, 0x01, 0xdf, 0xc5, 0x22, 0xee, 0x02, 0x28, 0x3d, 0x3b, 0x06, 0xa9, 0xd0, 0x3a, 0xcf, 0x80, 0x96, 0x96, 0x8d, 0x7d, 0xbb, 0x0f, 0x91, 0x78, 0xff, 0xff, 0xff, 0xff, 0x02, 0x8b, 0xa7, 0x94, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xba, 0xde, 0xec, 0xfd, 0xef, 0x05, 0x07, 0x24, 0x7f, 0xc8, 0xf7, 0x42, 0x41, 0xd7, 0x3b, 0xc0, 0x39, 0x97, 0x2d, 0x7b, 0x88, 0xac, 0x40, 0x94, 0xa8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xc1, 0x09, 0x32, 0x48, 0x3f, 0xec, 0x93, 0xed, 0x51, 0xf5, 0xfe, 0x95, 0xe7, 0x25, 0x59, 0xf2, 0xcc, 0x70, 0x43, 0xf9, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00};
  vector<unsigned char> vch(ch, ch + sizeof(ch) -1);
  CDataStream spendStream(vch, SER_DISK, CLIENT_VERSION);
  CTransaction spendingTx;
  spendStream >> spendingTx;



  CBloomFilter filter(TEST_COIN_IFACE, 10, 0.000001, 0, BLOOM_UPDATE_ALL);
  filter.insert(uint256("0xb4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b"));
  _TRUE(true == filter.IsRelevantAndUpdate(tx, tx.GetHash()));

  filter = CBloomFilter(TEST_COIN_IFACE, 10, 0.000001, 0, BLOOM_UPDATE_ALL);
  // byte-reversed tx hash
  filter.insert(ParseHex("6bff7fcd4f8565ef406dd5d63d4ff94f318fe82027fd4dc451b04474019f74b4"));
  _TRUE(true == filter.IsRelevantAndUpdate(tx, tx.GetHash()));

  filter = CBloomFilter(TEST_COIN_IFACE, 10, 0.000001, 0, BLOOM_UPDATE_ALL);
  filter.insert(ParseHex("30450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a01"));
  _TRUE(true == filter.IsRelevantAndUpdate(tx, tx.GetHash()));

  filter = CBloomFilter(TEST_COIN_IFACE, 10, 0.000001, 0, BLOOM_UPDATE_ALL);
  filter.insert(ParseHex("046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339"));
  _TRUE(true == filter.IsRelevantAndUpdate(tx, tx.GetHash()));

  filter = CBloomFilter(TEST_COIN_IFACE, 10, 0.000001, 0, BLOOM_UPDATE_ALL);
  filter.insert(ParseHex("04943fdd508053c75000106d3bc6e2754dbcff19"));
  _TRUE(true == filter.IsRelevantAndUpdate(tx, tx.GetHash()));
  _TRUE(true == filter.IsRelevantAndUpdate(spendingTx, spendingTx.GetHash()));

  filter = CBloomFilter(TEST_COIN_IFACE, 10, 0.000001, 0, BLOOM_UPDATE_ALL);
  filter.insert(ParseHex("a266436d2965547608b9e15d9032a7b9d64fa431"));
  _TRUE(true == filter.IsRelevantAndUpdate(tx, tx.GetHash()));

  filter = CBloomFilter(TEST_COIN_IFACE, 10, 0.000001, 0, BLOOM_UPDATE_ALL);
  filter.insert(COutPoint(uint256("0x90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 0));
  _TRUE(true == filter.IsRelevantAndUpdate(tx, tx.GetHash()));

}

#ifdef __cplusplus
}
#endif
