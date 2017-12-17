
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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
#include <limits>
#include "bignum.h"
#include "util.h"
#include <boost/foreach.hpp>
#include "init.h"
#include "wallet.h"
#include "walletdb.h"
#include "serialize.h"


extern void SHA256Transform(void* pstate, void* pinput, const void* pinit);

#ifdef __cplusplus
extern "C" {
#endif



_TEST(sha256transform)
{
  unsigned int pSHA256InitState[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  // unsigned char pstate[32];
  unsigned char pinput[64];

  int i;

  for (i = 0; i < 32; i++) {
    pinput[i] = i;
    pinput[i+32] = 0;
  }

  uint256 hash;

  SHA256Transform(&hash, pinput, pSHA256InitState);

//  BOOST_TEST_MESSAGE(hash.GetHex());

  uint256 hash_reference("0x2df5e1c65ef9f8cde240d23cae2ec036d31a15ec64bc68f64be242b1da6631f3");

  _TRUE(hash == hash_reference);
}





#ifdef __cplusplus
}
#endif

