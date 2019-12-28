
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
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

#ifndef __SHC_POOL_H__
#define __SHC_POOL_H__

/**
 * @ingroup sharecoin_shc
 * @{
 */

#include <boost/assign/list_of.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>

#include "txmempool.h"

class SHC_CTxMemPool : public CPool
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

		SHC_CTxMemPool() : CPool(SHC_COIN_IFACE) { };
};

/**
 * @}
 */

#endif /* ndef __SHC_POOL_H__ */

