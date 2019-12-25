
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

extern "C"
{
#ifdef GNULIB_NAMESPACE
#undef GNULIB_NAMESPACE
#endif
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
}

#ifndef SERVER__MAIN_H
#define SERVER__MAIN_H


#include "bignum.h"
#include "net.h"
#include "key.h"
#include "script.h"
#include "scrypt.h"
#include "shcoind.h"
#include "block.h"

#include <list>

class CWallet;
class CBlock;
class CBlockIndex;
class CKeyItem;
class CReserveKey;

class CAddress;
class CInv;
class CRequestTracker;
class CNode;

// Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp.
#ifdef USE_UPNP
static const int fHaveUPnP = true;
#else
static const int fHaveUPnP = false;
#endif


//extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_mapAlerts;



extern CCriticalSection cs_main;
extern uint64 nLastBlockTx;
extern uint64 nLastBlockSize;
extern const std::string strMessageMagic;
extern double dHashesPerSec;
extern int64 nHPSTimerStart;
extern int64 nTimeBestReceived;

// Settings
extern int64 nTransactionFee;
//extern int64 nMinimumInputValue;

// Minimum disk space required - used in CheckDiskSpace()
static const uint64 nMinDiskSpace = 52428800;


class CReserveKey;
#ifdef USE_LEVELDB_COINDB
class CTxDB;
class CTxIndex;
#endif

bool ProcessBlock(CNode* pfrom, CBlock* pblock);
bool CheckDiskSpace(uint64 nAdditionalBytes=0);
//FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");
//FILE* AppendBlockFile(unsigned int& nFileRet);
bool LoadBlockIndex(bool fAllowNew=true);
void PrintBlockTree();
bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto, bool fSendTrickle);
bool LoadExternalBlockFile(FILE* fileIn);
void GenerateBitcoins(bool fGenerate, CWallet* pwallet);
CBlock* CreateNewBlock(CReserveKey& reservekey);
void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1);
bool CheckWork(CBlock* pblock, CWallet& wallet);
bool CheckProofOfWork(uint256 hash, unsigned int nBits);
unsigned int ComputeMinWork(unsigned int nBase, int64 nTime);
int GetNumBlocksOfPeers();
bool IsInitialBlockDownload();
std::string GetWarnings(int ifaceIndex, std::string strFor);











bool GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);












/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx : public CTransaction
{
public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    // memory only
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }


    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        nVersion = 1;//this->nFlag;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )


    bool IsInMainChain(int ifaceIndex) const { return GetDepthInMainChain(ifaceIndex) > 0; }

#if 0
    bool AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs=true);
    bool AcceptToMemoryPool(int ifaceIndex);
#endif

    int GetBlocksToMaturity(int ifaceIndex) const;
    int SetMerkleBranch(const CBlock* pblock);
    int SetMerkleBranch(int ifaceIndex);

    int GetDepthInMainChain(int ifaceIndex, CBlockIndex* &pindexRet) const;

    int GetDepthInMainChain(int ifaceIndex) const {
      CBlockIndex *pindexRet;
      return GetDepthInMainChain(ifaceIndex, pindexRet);
    }

};

#endif /* ndef SERVER__MAIN_H */
