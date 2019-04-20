
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#ifndef __SERVER__CHECKPOINTS_H__
#define __SERVER__CHECKPOINTS_H__

#include <string>
#include <vector>
#include <map>

#include <boost/foreach.hpp>
#include <boost/variant.hpp>


typedef std::map<int, uint256> MapCheckpoints;

/** 
 * Block-chain checkpoints is a hard-coded validation check against already established blocks. Additional checkpoints may be added dynamically.
 */
class CCheckpoints
{
	protected:
		MapCheckpoints mapCheckpoints;
		uint32_t hNotaryHeight;
		uint256 hNotaryBlock;
		int ifaceIndex;

	public:
		CCheckpoints(int ifaceIndexIn)
		{
			ifaceIndex = ifaceIndexIn;
			mapCheckpoints.clear();
			hNotaryHeight = 0;
			hNotaryBlock = 0;
		}

		CCheckpoints(int ifaceIndexIn, MapCheckpoints mapIn)
		{
			ifaceIndex = ifaceIndexIn;
			mapCheckpoints = mapIn;
			hNotaryHeight = 0;
			hNotaryBlock = 0;
		}

    // Returns true if block passes checkpoint checks
    bool CheckBlock(int nHeight, const uint256& hash);

    // Return conservative estimate of total number of blocks, 0 if unknown
    int GetTotalBlocksEstimate();

    // Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
    CBlockIndex* GetLastCheckpoint();

		/* Add a dynamic block-chain checkpoint. */
		bool AddCheckpoint(CBlockIndex *pindex);
		bool AddCheckpoint(int height, uint256 hash);

		/* Remove all checkpoints at height and above. */
		bool RemoveCheckpoint(int nHeight);

		/* The last notorized block height. */
		const unsigned int GetNotorizedBlockHeight()
		{
			return (hNotaryHeight);
		}

		/* The last notorized block hash. */
		const uint256 GetNotorizedBlockHash()
		{
			return (hNotaryBlock);
		}

		void ResetNotorizedBlock();

};


#endif /* ndef __SERVER__CHECKPOINTS_H__ */

