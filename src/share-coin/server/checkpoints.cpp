
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

#include "shcoind.h"
#include "block.h"
#include "main.h"
#include "checkpoints.h"
#include "uint256.h"
#include "wallet.h"

#include <boost/assign/list_of.hpp> // for 'map_list_of()'


bool CCheckpoints::CheckBlock(int nHeight, const uint256& hash)
{
	MapCheckpoints::const_iterator i = mapCheckpoints.find(nHeight);
	if (i == mapCheckpoints.end()) return true;
	return hash == i->second;
}

int CCheckpoints::GetTotalBlocksEstimate()
{
	if (mapCheckpoints.size() == 0)
		return (0);
	return mapCheckpoints.rbegin()->first;
}

CBlockIndex* CCheckpoints::GetLastCheckpoint()
{
	CBlockIndex *pindex;

	BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, mapCheckpoints)
	{
		const uint256& hash = i.second;
		pindex = GetBlockIndexByHash(ifaceIndex, hash);
		if (pindex)
			return (pindex);
	}
	return NULL;
}

bool CCheckpoints::AddCheckpoint(CBlockIndex *pindex)
{
	const int height = pindex->nHeight;
	const uint256& hash = pindex->GetBlockHash();
	CBlockIndex *prevIndex;

	if (pindex->nStatus & BLOCK_FAILED_MASK) {
		/* block is marked as invalid. */
		CIface *iface = GetCoinByIndex(ifaceIndex);
		if (iface) Debug("(%s) CreateCheckpoint: warning: disregarding an invalid block \"%s\" at height %d (last checkpoint height is %d).", iface->name, hash.GetHex().c_str(), height, prevIndex->nHeight);
		return (false);
	}

	/* ensure that checkpoint has not already been established for height. */
	prevIndex = GetLastCheckpoint();
	if (prevIndex && pindex->nHeight <= prevIndex->nHeight) {
		CIface *iface = GetCoinByIndex(ifaceIndex);
		if (iface) Debug("(%s) CreateCheckpoint: warning: disregarding stale block \"%s\" at height %d (last checkpoint height is %d).", iface->name, hash.GetHex().c_str(), height, prevIndex->nHeight);
		return (false); /* stale */
	}

	/* insert new record at end of checkpoint list. */
	mapCheckpoints.insert(mapCheckpoints.end(), make_pair(height, hash));

	/* record last dynamic checkpoint as notorized. */
  hNotaryHeight = height;
	hNotaryBlock = hash;

	/* debug */
	CIface *iface = GetCoinByIndex(ifaceIndex);
	if (iface) Debug("(%s) AddCheckpoint: new dynamic checkpoint (height %d): %s",iface->name, height, hash.GetHex().c_str());

	return (true);
}

bool CCheckpoints::AddCheckpoint(int height, uint256 hash)
{
	CBlockIndex *pindex;
	
	pindex = GetBlockIndexByHash(ifaceIndex, hash);
	if (!pindex || pindex->nHeight != height)
		return (false);

	return (AddCheckpoint(pindex));
}

/* Remove all checkpoints at height and above. */
bool CCheckpoints::RemoveCheckpoint(int nHeight)
{
	vector<int> vHeight;

	BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, mapCheckpoints) {
		const int height = i.first;
		if (height >= nHeight) {
			vHeight.push_back(height);
			continue;
		}

		/* too low of height */
		break;
	}
	if (vHeight.size() == 0)
		return (false);

	for (unsigned int i = 0; i < vHeight.size(); i++) {
		mapCheckpoints.erase(vHeight[i]);
	}

	ResetNotorizedBlock();

	return (true);
}

void CCheckpoints::ResetNotorizedBlock()
{
	CBlockIndex *pindex = GetLastCheckpoint();

	if (!pindex) {
		hNotaryHeight = 0;
		hNotaryBlock = 0;
	}

	hNotaryHeight = pindex->nHeight;
	hNotaryBlock = pindex->GetBlockHash();
}

