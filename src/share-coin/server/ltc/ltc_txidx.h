
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

#ifndef __LTC__LTC_TXIDX_H__ 
#define __LTC__LTC_TXIDX_H__ 




#ifdef USE_LEVELDB_COINDB

class LTCTxDB : public CTxDB
{
  public:
    LTCTxDB(const char *fileMode = "r+") : CTxDB("ltc_tx.dat", LTC_COIN_IFACE, fileMode) { }
    bool ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(uint256 hash, CTransaction& tx);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx);
    bool LoadBlockIndex();

    bool WriteFlag(const std::string &name, bool fValue);
    bool ReadFlag(const std::string &name, bool &fValue);

  private:
    LTCTxDB(const LTCTxDB&);
    void operator=(const LTCTxDB&);
    bool LoadBlockIndexGuts();
};

#endif


static bool IsChainFile(std::string strFile)
{
    if (strFile == "ltc_tx.dat")
        return true;

    return false;
}

bool ltc_InitBlockIndex();

bool ltc_RestoreBlockIndex();



#endif /** __LTC__LTC_TXIDX_H__ */
