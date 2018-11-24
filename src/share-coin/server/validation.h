
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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

#ifndef __SERVER__VALIDATION_H__
#define __SERVER__VALIDATION_H__


bool CheckBlockHeader(CBlockHeader *pblock);

bool ContextualCheckBlockHeader(CIface *iface, const CBlockHeader& block, CBlockIndex *pindexPrev);

bool CheckBlock(CBlock *pblock);

bool ContextualCheckBlock(CBlock *pblock, CBlockIndex *pindexPrev);

CBlockIndex *CreateBlockIndex(CIface *iface, CBlockHeader& block);

uint256 GetGenesisBlockHash(CIface *iface, CBlockIndex *pindex = NULL);

bool core_AcceptBlockHeader(CIface *iface, CBlockHeader& block, CBlockIndex **pindex_p);

bool ProcessNewBlockHeaders(CIface *iface, std::vector<CBlockHeader>& headers, CBlockIndex** ppindex);

bool core_AcceptBlock(CBlock *pblock, CBlockIndex *pindexPrev);


#endif /* ndef __SERVER__VALIDATION_H__ */
