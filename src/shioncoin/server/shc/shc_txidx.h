
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

#ifndef __SHC_TXIDX_H__
#define __SHC_TXIDX_H__

/**
 * @ingroup sharecoin_shc
 * @{
 */


#ifdef USE_LEVELDB_COINDB

class SHCTxDB : public CTxDB
{
  public:
    SHCTxDB(const char *fileMode = "r+") : CTxDB("shc_tx.dat", SHC_COIN_IFACE, fileMode) { }
  private:
    SHCTxDB(const SHCTxDB&);
    void operator=(const SHCTxDB&);
  public:
#if 0
    bool ReadTxIndex(uint256 hash, CTxIndex& txindex);
    bool UpdateTxIndex(uint256 hash, const CTxIndex& txindex);
    bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight);
    bool EraseTxIndex(const CTransaction& tx);
    bool ContainsTx(uint256 hash);
#endif

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
    if (strFile == "shc_tx.dat")
        return true;

    return false;
}

bool shc_InitBlockIndex();

bool shc_RestoreBlockIndex();


/**
 * @}
 */

#endif /* ndef __SHC_TXIDX_H__ */
