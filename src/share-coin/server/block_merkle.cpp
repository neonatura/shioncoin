
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


/** 
 * Traditional scrypt-based merkle standard. The 'merkle root' is a hash which uniquely represents the underlying transactions associated with the block.
 */
uint256 CBlock::BuildMerkleTree() const
{
  uint256 merkleHash = 0;

  vMerkleTree.clear();
  BOOST_FOREACH(const CTransaction& tx, vtx)
    vMerkleTree.push_back(tx.GetHash());
  int j = 0;
  for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
  {
    for (int i = 0; i < nSize; i += 2)
    {
      int i2 = std::min(i+1, nSize-1);
      vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
            BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
    }
    j += nSize;
  }

  if (!vMerkleTree.empty())
    merkleHash = vMerkleTree.back();
  return (merkleHash);
}


std::vector<uint256> CBlock::GetMerkleBranch(int nIndex) const
{

  if (vMerkleTree.empty()) {
    BuildMerkleTree();
  }

  std::vector<uint256> vMerkleBranch;
  int j = 0;
  for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
  {
    int i = std::min(nIndex^1, nSize-1);
    vMerkleBranch.push_back(vMerkleTree[j+i]);
    nIndex >>= 1;
    j += nSize;
  }

  return vMerkleBranch;
}

uint256 CBlock::CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
{
  if (nIndex == -1)
    return 0;
  BOOST_FOREACH(const uint256& otherside, vMerkleBranch)
  {
    if (nIndex & 1)
      hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
    else
      hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
    nIndex >>= 1;
  }
  return hash;
}


