
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

#ifndef __EMC2__EMC2_TXIDX_H__ 
#define __EMC2__EMC2_TXIDX_H__ 




#ifdef USE_LEVELDB_COINDB

class EMC2TxDB : public CTxDB
{
  public:
    EMC2TxDB(const char *fileMode = "r+") : CTxDB("emc2_tx.dat", EMC2_COIN_IFACE, fileMode) { }
    bool ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(uint256 hash, CTransaction& tx);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx);
    bool LoadBlockIndex();

    bool WriteFlag(const std::string &name, bool fValue);
    bool ReadFlag(const std::string &name, bool &fValue);

  private:
    EMC2TxDB(const EMC2TxDB&);
    void operator=(const EMC2TxDB&);
    bool LoadBlockIndexGuts();
};

#endif


static bool IsChainFile(std::string strFile)
{
    if (strFile == "emc2_tx.dat")
        return true;

    return false;
}

bool emc2_InitBlockIndex();

bool emc2_RestoreBlockIndex();



#endif /** __EMC2__EMC2_TXIDX_H__ */
