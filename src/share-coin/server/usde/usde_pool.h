
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

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2013 shc Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef __USDE_POOL_H__
#define __USDE_POOL_H__


/**
 * @ingroup sharecoin_shc
 * @{
 */

#include <boost/assign/list_of.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>

#include "txmempool.h"



class USDE_CTxMemPool : public CPool
{

  public:

    bool revert(CTransaction &tx) ;
//    bool VerifyAccept(CTransaction &tx) ;
    int64_t GetSoftWeight() ;
    int64_t GetSoftSigOpCost() ;
    bool VerifyCoinStandards(CTransaction& tx, tx_cache& mapInputs) ;
    bool AcceptTx(CTransaction& tx);
    int64 CalculateSoftFee(CTransaction& tx);
    int64 IsFreeRelay(CTransaction& tx, tx_cache& mapInputs);

    USDE_CTxMemPool() : CPool(USDE_COIN_IFACE) { };
};



/**
 * @}
 */

#endif /* ndef __USDE_POOL_H__ */
