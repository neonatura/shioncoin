

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

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2013 color Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


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
