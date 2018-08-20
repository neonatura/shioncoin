
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


#if 0
/** CCoinsView backed by the LevelDB coin database (chainstate/) */
class CCoinsViewDB : public CCoinsView
{
protected:
    CLevelDB db;
public:
    CCoinsViewDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool GetCoins(const uint256 &txid, CCoins &coins);
    bool SetCoins(const uint256 &txid, const CCoins &coins);
    bool HaveCoins(const uint256 &txid);
    CBlockIndex *GetBestBlock();
    bool SetBestBlock(CBlockIndex *pindex);
    bool BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex);
    bool GetStats(CCoinsStats &stats);
};

/** Access to the block database (blocks/index/) */
class LTCTxDB : public CLevelDB
{
public:
    LTCTxDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
private:
    LTCTxDB(const LTCTxDB&);
    void operator=(const LTCTxDB&);
public:
    bool WriteBlockIndex(const CDiskBlockIndex& blockindex);
    bool ReadBestInvalidWork(CBigNum& bnBestInvalidWork);
    bool WriteBestInvalidWork(const CBigNum& bnBestInvalidWork);
    bool ReadBlockFileInfo(int nFile, CBlockFileInfo &fileinfo);
    bool WriteBlockFileInfo(int nFile, const CBlockFileInfo &fileinfo);
    bool ReadLastBlockFile(int &nFile);
    bool WriteLastBlockFile(int nFile);
    bool WriteReindexing(bool fReindex);
    bool ReadReindexing(bool &fReindex);
    bool ReadTxIndex(const uint256 &txid, CDiskTxPos &pos);
    bool WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> > &list);
    bool WriteFlag(const std::string &name, bool fValue);
    bool ReadFlag(const std::string &name, bool &fValue);
    bool LoadBlockIndexGuts();
};

#endif


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
