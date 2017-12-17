
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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

#include "checkpoints.h"
#include "db.h"

using namespace std;
using namespace boost;


#if 0
/*
   int nVersion;
   uint256 hashPrevBlock;
   uint256 hashMerkleRoot;
   unsigned int nTime;
   unsigned int nBits;
   unsigned int nNonce;
   std::vector<CTransaction> vtx;
   */
void bc_stream_write(bc_t *bc, CBlock block)
{
  uint256 hash;

  /* block */
  hash = Hash(BEGIN(block.nVersion), END(block.nNonce));
  bc_write(bc, (void *)&hash, 32);
  bc_write_int(bc, block.nVersion);
  bc_write(bc, (void *)&block.hashPrevBlock, 32);
  bc_write(bc, (void *)&block.hashMerkleRoot, 32);
  bc_write_int(bc, block.nTime);
  bc_write_int(bc, block.nBits);
  bc_write_int(bc, block.nNonce);
  bc_write_int(bc, block.nTime);

  /* tx index */
  bc_write_int(bc, (unsigned int)block.vtx.size());
  BOOST_FOREACH(CTransaction& tx, block.vtx) {
    uint256 tx_hash = tx.GetHash();
    bc_write(bc, (void *)&tx_hash, 32);
/*
    BOOST_FOREACH(CTransaction& tx, block.vin) {
    }
    BOOST_FOREACH(CTransaction& tx, block.vout) {
    }
*/
  }

}

void bc_stream_read(bc_t *bc, CBlock block)
{

}
#endif


