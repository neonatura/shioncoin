
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

#ifndef __COLOR_TXIDX_H__
#define __COLOR_TXIDX_H__

/**
 * @ingroup sharecoin_color
 * @{
 */


#ifdef USE_LEVELDB_COINDB

class COLORTxDB : public CTxDB
{
  public:
    COLORTxDB(const char *fileMode = "r+") : CTxDB("color_tx.dat", COLOR_COIN_IFACE, fileMode) { }
  private:
    COLORTxDB(const COLORTxDB&);
    void operator=(const COLORTxDB&);
  public:

    bool ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(uint256 hash, CTransaction& tx);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx);

    bool LoadBlockIndex();

  private:
    bool LoadBlockIndexGuts();
};

#endif


static bool IsChainFile(std::string strFile)
{
    if (strFile == "color_tx.dat")
        return true;

    return false;
}

bool color_InitBlockIndex();

bool color_RestoreBlockIndex();


/**
 * @}
 */

#endif /* ndef __COLOR_TXIDX_H__ */
