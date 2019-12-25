
/*
 * @copyright
 *
 *  Copyright 2019 Neo Natura
 *
 *  This file is part of ShionCoin.
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

#ifndef ALGO___HMAC_SHA512_H
#define ALGO___HMAC_SHA512_H

#include "sha512.h"

#include <stdint.h>
#include <stdlib.h>

/** A hasher class for HMAC-SHA-512. */
class CHMAC_SHA512
{
private:
    CSHA512 outer;
    CSHA512 inner;

public:
    static const size_t OUTPUT_SIZE = 64;

    CHMAC_SHA512(const unsigned char* key, size_t keylen);
    CHMAC_SHA512& Write(const unsigned char* data, size_t len)
    {
        inner.Write(data, len);
        return *this;
    }
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
};

#endif // ALGO___HMAC_SHA512_H
