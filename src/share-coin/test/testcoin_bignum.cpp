
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


#ifdef __cplusplus
extern "C" {
#endif


static void mysetint64(CBigNum& num, int64 n)
{
    num.setint64(n);
}

// For each number, we do 2 tests: one with inline code, then we reset the
// value to 0, then the second one with a non-inlined function.
_TEST(bignum)
{
    int64 n;

    {
        n = 0;
        CBigNum num(n);
        _TRUE(num.ToString() == "0");
        num.setulong(0);
        _TRUE(num.ToString() == "0");
        mysetint64(num, n);
        _TRUE(num.ToString() == "0");
    }
    {
        n = 1;
        CBigNum num(n);
        _TRUE(num.ToString() == "1");
        num.setulong(0);
        _TRUE(num.ToString() == "0");
        mysetint64(num, n);
        _TRUE(num.ToString() == "1");
    }
    {
        n = -1;
        CBigNum num(n);
        _TRUE(num.ToString() == "-1");
        num.setulong(0);
        _TRUE(num.ToString() == "0");
        mysetint64(num, n);
        _TRUE(num.ToString() == "-1");
    }
    {
        n = 5;
        CBigNum num(n);
        _TRUE(num.ToString() == "5");
        num.setulong(0);
        _TRUE(num.ToString() == "0");
        mysetint64(num, n);
        _TRUE(num.ToString() == "5");
    }
    {
        n = -5;
        CBigNum num(n);
        _TRUE(num.ToString() == "-5");
        num.setulong(0);
        _TRUE(num.ToString() == "0");
        mysetint64(num, n);
        _TRUE(num.ToString() == "-5");
    }
    {
        n = std::numeric_limits<int64>::min();
        CBigNum num(n);
        _TRUE(num.ToString() == "-9223372036854775808");
        num.setulong(0);
        _TRUE(num.ToString() == "0");
        mysetint64(num, n);
        _TRUE(num.ToString() == "-9223372036854775808");
    }
    {
        n = std::numeric_limits<int64>::max();
        CBigNum num(n);
        _TRUE(num.ToString() == "9223372036854775807");
        num.setulong(0);
        _TRUE(num.ToString() == "0");
        mysetint64(num, n);
        _TRUE(num.ToString() == "9223372036854775807");
    }
}


#ifdef __cplusplus
}
#endif

