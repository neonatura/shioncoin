
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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

#ifndef __TESTNET_POOL_H__
#define __TESTNET_POOL_H__


/**
 * @ingroup sharecoin_testnet
 * @{
 */

#include <boost/assign/list_of.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>

#include "txmempool.h"


#ifdef TESTNET_SERVICE
class TESTNET_CTxMemPool : public CPool
{

  public:

    bool revert(CTransaction &tx) ;
    int64_t GetSoftWeight() ;
    int64_t GetSoftSigOpCost() ;
    bool VerifyCoinStandards(CTransaction& tx, tx_cache& mapInputs) ;
    bool AcceptTx(CTransaction& tx);
    int64 CalculateSoftFee(CTransaction& tx);
    int64 IsFreeRelay(CTransaction& tx, tx_cache& mapInputs);

		double CalculateFeePriority(CPoolTx *ptx);

		void EnforceCoinStandards(CTransaction& tx);

    TESTNET_CTxMemPool() : CPool(TESTNET_COIN_IFACE) { };
};
#endif


/**
 * @}
 */

#endif /* ndef __TESTNET_POOL_H__ */
