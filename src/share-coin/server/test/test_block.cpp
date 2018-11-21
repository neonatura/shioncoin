
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
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "test_pool.h"
#include "test_block.h"
#include "test_txidx.h"
#include "test_wallet.h"
#include "chain.h"
#include "coin.h"
#include "versionbits.h"

#ifdef WIN32
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef fcntl
#undef fcntl
#endif

#include <boost/array.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>


using namespace std;
using namespace boost;


uint256 test_hashGenesisBlock("0xf4e533069fcce5b4a3488b4363caa24e9f3265b260868794881c0164e286394b");
uint256 test_hashGenesisMerkle("0x96f34a50bdbe2f2f50308b52ee2a5fd9dba09824d95df16798fabad0de3a7f67");
static CBigNum TEST_bnProofOfWorkLimit(~uint256(0) >> 9);


#define TEST_MAJORITY_WINDOW 2500


/* ** BLOCK ORPHANS ** */

typedef map<uint256, uint256> orphan_map;
static orphan_map TEST_mapOrphanBlocksByPrev;

bool test_IsOrphanBlock(const uint256& hash)
{
  CBlockIndex *pindex;
  TESTBlock block;
  uint256 prevHash;
  bool ok;

  if (test_GetOrphanPrevHash(hash, prevHash)) {
    /* already mapped. */
    return (true);
  }

#if 0
  pindex = GetBlockIndexByHash(TEST_COIN_IFACE, hash);
  if (pindex) {
    if (GetBestHeight(TEST_COIN_IFACE) >= pindex->nHeight &&
        block.ReadFromDisk(pindex))
      return (false); /* present in block-chain */
  }

  if (!block.ReadArchBlock(hash))
    return (false); /* no record in archive db */

  return (true);
#endif
  return (false);
}

void test_AddOrphanBlock(CBlock *block)
{

  TEST_mapOrphanBlocksByPrev.insert(
      make_pair(block->hashPrevBlock, block->GetHash()));
  block->WriteArchBlock();

}

void test_RemoveOrphanBlock(const uint256& hash)
{
  bool found;

  orphan_map::iterator it = TEST_mapOrphanBlocksByPrev.begin(); 
  while (it != TEST_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found)
      break;
    ++it;
  }
  if (it != TEST_mapOrphanBlocksByPrev.end()) {
    TEST_mapOrphanBlocksByPrev.erase(it);
  }
  
}

bool test_GetOrphanPrevHash(const uint256& hash, uint256& retPrevHash)
{
  bool found;

  orphan_map::iterator it = TEST_mapOrphanBlocksByPrev.begin(); 
  while (it != TEST_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found) {
      retPrevHash = it->first;
      return (true);
    }
    ++it;
  }

  return (false);
}

bool test_GetOrphanNextHash(const uint256& hash, uint256& retNextHash)
{
  bool found;

  orphan_map::iterator it = TEST_mapOrphanBlocksByPrev.find(hash);
  if (it != TEST_mapOrphanBlocksByPrev.end()) {
    retNextHash = it->second;
    return (true);
  }
  return (false);
}

CBlock *test_GetOrphanBlock(const uint256& hash)
{
  TESTBlock block;  

  if (!block.ReadArchBlock(hash))
    return (NULL);

  return (new TESTBlock(block));
}

uint256 test_GetOrphanRoot(uint256 hash)
{
  uint256 prevHash;

  while (test_GetOrphanPrevHash(hash, prevHash)) {
    hash = prevHash;
  }
  return (hash);
}

/** TestNet : difficulty level is always lowest possible per protocol. */
unsigned int TESTBlock::GetNextWorkRequired(const CBlockIndex* pindexLast)
{
  unsigned int nProofOfWorkLimit = TEST_bnProofOfWorkLimit.GetCompact();
  return nProofOfWorkLimit;
}

int64 test_GetBlockValue(int nHeight, int64 nFees)
{
  int64 nSubsidy = (nHeight+1) * COIN;
  return nSubsidy + nFees;
}

namespace TEST_Checkpoints
{
  typedef std::map<int, uint256> MapCheckpoints;

  //
  // What makes a good checkpoint block?
  // + Is surrounded by blocks with reasonable timestamps
  //   (no blocks before with a timestamp after, none after with
  //    timestamp before)
  // + Contains no strange transactions
  //
  static MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    ( 0, uint256("0x0xf4e533069fcce5b4a3488b4363caa24e9f3265b260868794881c0164e286394b") )
    ;


  bool CheckBlock(int nHeight, const uint256& hash)
  {
    if (fTestNet) return true; // Testnet has no checkpoints

    MapCheckpoints::const_iterator i = mapCheckpoints.find(nHeight);
    if (i == mapCheckpoints.end()) return true;
    return hash == i->second;
  }

  int GetTotalBlocksEstimate()
  {
    if (fTestNet) return 0;
    return mapCheckpoints.rbegin()->first;
  }

  CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
  {
    if (fTestNet) return NULL;

    BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, mapCheckpoints)
    {
      const uint256& hash = i.second;
      std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
      if (t != mapBlockIndex.end())
        return t->second;
    }
    return NULL;
  }

  void AddCheckpoint(int height, uint256 hash)
  {
    mapCheckpoints.insert(mapCheckpoints.end(), make_pair(height, hash));
		Debug("(test) AddCheckpoint: new dynamic checkpoint (height %d): %s",height, hash.GetHex().c_str());
  }


}

static int64_t test_GetTxWeight(const CTransaction& tx)
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(tx, SER_NETWORK, TEST_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (TEST_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(tx, SER_NETWORK, TEST_PROTOCOL_VERSION);

  return (weight);
}



CBlock* test_CreateNewBlock(const CPubKey& rkey, CBlockIndex *pindexPrev)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  bool fWitnessEnabled;

  if (!pindexPrev)
    pindexPrev = GetBestBlockIndex(iface);

  // Create new block
  //auto_ptr<CBlock> pblock(new CBlock());
  auto_ptr<TESTBlock> pblock(new TESTBlock());
  if (!pblock.get())
    return NULL;

  fWitnessEnabled = IsWitnessEnabled(iface, pindexPrev);

  // Create coinbase tx
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vin[0].prevout.SetNull();
  txNew.vout.resize(1);
  txNew.vout[0].scriptPubKey << rkey << OP_CHECKSIG;

  // Add our coinbase tx as first transaction
  pblock->vtx.push_back(txNew);

  pblock->nVersion = core_ComputeBlockVersion(iface, pindexPrev);

  /* insert active transactions */
  int64 nFees = 0;
  CTxMemPool *pool = GetTxMemPool(iface); 
  vector<CTransaction> vPriority = pool->GetActiveTx(); 
  BOOST_FOREACH(CTransaction tx, vPriority) {
    const uint256& hash = tx.GetHash();
    int64 nTxFee;
    
    if (!pool->GetFee(hash, nTxFee))
      continue; /* 'should' never happen */

    if (nTxFee != 0 && nTxFee < MIN_RELAY_TX_FEE(iface)) {
      error(SHERR_INVAL, "test_CreateBlock: warning: tx \"%s\" has invalid fee (%f).", hash.GetHex().c_str(), (double)nTxFee/COIN);
      continue; 
    }

    nFees += nTxFee;
    pblock->vtx.push_back(tx);
  }

  /* calculate reward */
  bool ret = false;
  int64 reward = test_GetBlockValue(pindexPrev->nHeight+1, nFees);
  if (pblock->vtx.size() == 1)
    ret = BlockGenerateValidateMatrix(iface, pblock->vtx[0], reward, pindexPrev->nHeight + 1, pblock->GetTotalBlocksEstimate());
  if (!ret)
    ret = BlockGenerateSpringMatrix(iface, pblock->vtx[0], reward);
  pblock->vtx[0].vout[0].nValue = reward; 

  /* define core header */
  pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
  pblock->hashMerkleRoot = pblock->BuildMerkleTree();
  pblock->UpdateTime(pindexPrev);
  pblock->nBits          = pblock->GetNextWorkRequired(pindexPrev);
  pblock->nNonce         = 0;

  /* declare consensus attributes. */
  core_GenerateCoinbaseCommitment(iface, pblock.get(), pindexPrev);

  /* set default coinbase sig-script */
  core_IncrementExtraNonce(pblock.get(), pindexPrev);

  return pblock.release();
}


bool test_CreateGenesisBlock()
{
  blkidx_t *blockIndex = GetBlockTable(TEST_COIN_IFACE);
  bool ret;

  if (blockIndex->count(test_hashGenesisBlock) != 0) {
    return (true); /* already created */

}

  // Genesis block
  const char* pszTimestamp = "Neo Natura (share-coin) 2016";
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vout.resize(1);
  txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
  txNew.vout[0].nValue = 1 * COIN;
  txNew.vout[0].scriptPubKey = CScript() << ParseHex("04a5814813115273a109cff99907ba4a05d951873dae7acb6c973d0c9e7c88911a3dbc9aa600deac241b91707e7b4ffb30ad91c8e56e695a1ddf318592988afe0a") << OP_CHECKSIG;
  TESTBlock block;
  block.vtx.push_back(txNew);
  block.hashPrevBlock = 0;
  block.hashMerkleRoot = block.BuildMerkleTree();
  block.nVersion = 1;
  block.nTime    = 1365048244;
  block.nBits    = 0x1f7fffff; 
  block.nNonce   = 299;

  if (block.GetHash() != test_hashGenesisBlock)
    return (false);
  if (block.hashMerkleRoot != test_hashGenesisMerkle)
    return (false);

  if (!block.WriteBlock(0)) {
    return (false);
  }

  ret = block.AddToBlockIndex();
  if (!ret)
    return (false);

  return (true);
}

CBlock *test_GenerateBlock(CBlockIndex *pindexPrev)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  static unsigned int nNonceIndex = 0xF2222222;
//  static unsigned int nXIndex = 0xf0000000;
//  CBlockIndex *bestIndex = GetBestBlockIndex(TEST_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(TEST_COIN_IFACE);
  char xn_hex[128];

  if (blockIndex->empty())
    return (NULL);

  CWallet *wallet = GetWallet(iface);

  string sysAccount("");
  CPubKey pubkey = GetAccountPubKey(wallet, sysAccount);
//  CReserveKey reservekey(wallet);
  CBlock *block = test_CreateNewBlock(pubkey, pindexPrev);
  if (!block)
    return (NULL);
//reservekey.KeepKey();
//wallet->SetAddressBookName(reservekey.GetReservedKey().GetID(), sysAccount); 


//  block->vtx.push_back(txNew);
// if (bestIndex) block->hashPrevBlock = bestIndex->GetBlockHash();
//  block->hashMerkleRoot = block->BuildMerkleTree();
//  block->nVersion = TESTBlock::CURRENT_VERSION;
//  block->nTime    = time(NULL);
//  block->nBits    = block->GetNextWorkRequired(bestIndex);
  block->nNonce   = ++nNonceIndex;

  block->hashMerkleRoot = block->BuildMerkleTree();

  {
    uint256 hashTarget = CBigNum().SetCompact(block->nBits).getuint256();
    uint256 thash;
    char scratchpad[SCRYPT_SCRATCHPAD_SIZE];

    loop
    {
      scrypt_1024_1_1_256_sp(BEGIN(block->nVersion), BEGIN(thash), scratchpad);
      if (thash <= hashTarget)
        break;
      if ((block->nNonce & 0xFFF) == 0)
      {
//        printf("nonce %08X: hash = %s (target = %s)\n", block->nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
      }
      ++block->nNonce;
      if (block->nNonce == 0)
      {
//        printf("NONCE WRAPPED, incrementing time\n");
        ++block->nTime;
      }
    }
  }
  nNonceIndex = block->nNonce;

  return (block);
}











static bool test_IsFromMe(CTransaction& tx)
{
  CWallet *pwallet = GetWallet(TEST_COIN_IFACE);

  if (pwallet->IsFromMe(tx))
    return true;

  return false;
}

static void test_EraseFromWallets(uint256 hash)
{
  CWallet *pwallet = GetWallet(TEST_COIN_IFACE);

  pwallet->EraseFromWallet(hash);
}


bool test_ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  int ifaceIndex = TEST_COIN_IFACE;
  CBlockIndex *pindexBest = GetBestBlockIndex(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
  shtime_t ts;

  // Check for duplicate
  uint256 hash = pblock->GetHash();

	if (pblock->hashPrevBlock == 0 &&
			hash != test_hashGenesisBlock) {
		Debug("(test) ProcessBlock: warning: invalid genesis block \"%s\" submitted by \"%s\".", hash.GetHex().c_str(), (pfrom?pfrom->addr.ToString().c_str():"<local>"));
		return (false);
	}


#if 0
  if (blockIndex->count(hash)) {
    return Debug("(test) ProcessBlock: already have block %s", hash.GetHex().c_str());
  }
  if (pindexBest && 
      pblock->hashPrevBlock != pindexBest->GetBlockHash() && 
      test_IsOrphanBlock(hash)) {
    return Debug("(test) ProcessBlock: already have block (orphan) %s", hash.ToString().substr(0,20).c_str());
  }
#endif

  // Preliminary checks
  if (!pblock->CheckBlock()) {
    iface->net_invalid = time(NULL);
    return error(SHERR_INVAL, "ProcessBlock() : CheckBlock FAILED");
  }

#if 0
  CBlockIndex* pcheckpoint = TEST_Checkpoints::GetLastCheckpoint(*blockIndex);
  if (pcheckpoint && pblock->hashPrevBlock != GetBestBlockChain(iface))
  {
    // Extra checks to prevent "fill up memory by spamming with bogus blocks"
    int64 deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
    if (deltaTime < 0)
    {
      if (pfrom)
        pfrom->Misbehaving(100);
      return error(SHERR_INVAL, "ProcessBlock() : block with timestamp before last checkpoint");
    }
  }
#endif

  /* block is considered orphan when previous block or one of the transaction's input hashes is unknown. */
  if (pblock->hashPrevBlock != 0 && 
      !blockIndex->count(pblock->hashPrevBlock)) {
    Debug("(test) ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.GetHex().c_str());
    if (pfrom) {
      test_AddOrphanBlock(pblock);
      STAT_BLOCK_ORPHAN(iface)++;

      /* request missing blocks */
      CBlockIndex *pindexBest = GetBestBlockIndex(TEST_COIN_IFACE);
      if (pindexBest) {
        Debug("(test) ProcessBlocks: requesting blocks from height %d due to orphan '%s'.\n", pindexBest->nHeight, pblock->GetHash().GetHex().c_str());
        pfrom->PushGetBlocks(GetBestBlockIndex(TEST_COIN_IFACE), test_GetOrphanRoot(pblock->GetHash()));
				InitServiceBlockEvent(TEST_COIN_IFACE, pindexBest->nHeight);
      }
    }
    return true;
  }

#if 0 /* redundant */
  if (!pblock->CheckTransactionInputs(TEST_COIN_IFACE)) {
    error(SHERR_INVAL, "(test) ProcessBlock: check transaction input failure [prev %s]", pblock->hashPrevBlock.GetHex().c_str());
    return (true);
  }
#endif

  if (!pblock->AcceptBlock()) {
    iface->net_invalid = time(NULL);
    return error(SHERR_IO, "TESTBlock::AcceptBlock: error adding block '%s'.", pblock->GetHash().GetHex().c_str());
  }

  uint256 nextHash;
  while (test_GetOrphanNextHash(hash, nextHash)) {
    hash = nextHash;
    CBlock *block = test_GetOrphanBlock(hash);
    if (!block || !block->AcceptBlock())
      break;

    test_RemoveOrphanBlock(hash);
    STAT_BLOCK_ORPHAN(iface)--;
  }

  ServiceBlockEventUpdate(TEST_COIN_IFACE);

	/* initiate notary tx, if needed. */
	int mode;
	const CTransaction& tx = pblock->vtx[0];
	if ((tx.GetFlags() & CTransaction::TXF_MATRIX) &&
			GetExtOutputMode(tx, OP_MATRIX, mode) &&
			mode == OP_EXT_VALIDATE) {
		RelayValidateMatrixNotaryTx(iface, tx);
	}

  return true;
}

bool test_CheckProofOfWork(uint256 hash, unsigned int nBits)
{
  CBigNum TEST_bnTarget;
  TEST_bnTarget.SetCompact(nBits);

  // Check range
  if (TEST_bnTarget <= 0 || TEST_bnTarget > TEST_bnProofOfWorkLimit)
    return error(SHERR_INVAL, "CheckProofOfWork() : nBits below minimum work");

  // Check proof of work matches claimed amount
  if (hash > TEST_bnTarget.getuint256())
    return error(SHERR_INVAL, "CheckProofOfWork() : hash doesn't match nBits");

  return true;
}

/**
 * @note These are checks that are independent of context that can be verified before saving an orphan block.
 */
bool TESTBlock::CheckBlock()
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);

  if (vtx.empty()) {
    return (trust(-100, "(test) CheckBlock: block submitted with zero transactions"));
  }

  int64_t weight = GetBlockWeight();
  if (weight > MAX_BLOCK_WEIGHT(iface)) {
    return (trust(-100, "(test) CheckBlock: block weight (%d) > max (%d)", weight, MAX_BLOCK_WEIGHT(iface)));
  }

  if (!vtx[0].IsCoinBase()) {
    return (trust(-100, "(test) ChecKBlock: first transaction is not coin base"));
  }

  if (!vtx[0].IsCoinBase())
    return error(SHERR_INVAL, "(test) CheckBlock: first tx is not coinbase.");

  // Check proof of work matches claimed amount
  if (!test_CheckProofOfWork(GetPoWHash(), nBits)) {
    return error(SHERR_INVAL, "(test) CheckBlock : proof of work failed");
  }

  // Check timestamp
  if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60) {
    return error(SHERR_INVAL, "CheckBlock() : block timestamp too far in the future");
  }

  // First transaction must be coinbase, the rest must not be
  for (unsigned int i = 1; i < vtx.size(); i++)
    if (vtx[i].IsCoinBase()) {
      return error(SHERR_INVAL, "CheckBlock() : more than one coinbase");
    }

  // Check transactions
  BOOST_FOREACH(CTransaction& tx, vtx) {
    if (!tx.CheckTransaction(TEST_COIN_IFACE)) {
      return error(SHERR_INVAL, "TestBlock.CheckBlock: transaction integrity failure [CheckTransaction failed]: %s", ToString().c_str());
    }
  }

  // Check for duplicate txids. This is caught by ConnectInputs(),
  // but catching it earlier avoids a potential DoS attack:
  set<uint256> uniqueTx;
  BOOST_FOREACH(const CTransaction& tx, vtx)
  {
    uniqueTx.insert(tx.GetHash());
  }
  if (uniqueTx.size() != vtx.size()) {
    return error(SHERR_INVAL, "CheckBlock() : duplicate transaction");
  }

  unsigned int nSigOps = 0;
  BOOST_FOREACH(const CTransaction& tx, vtx)
  {
    nSigOps += tx.GetLegacySigOpCount();
  }
  if (nSigOps > MAX_BLOCK_SIGOPS(iface)) {
    return error(SHERR_INVAL, "CheckBlock() : out-of-bounds SigOpCount");
  }

  // Check merkleroot
  if (hashMerkleRoot != BuildMerkleTree()) {
    return error(SHERR_INVAL, "CheckBlock() : hashMerkleRoot mismatch");
  }

  blkidx_t *blockIndex = GetBlockTable(TEST_COIN_IFACE);
  map<uint256, CBlockIndex*>::iterator miPrev = blockIndex->find(hashPrevBlock);
  if (miPrev != blockIndex->end()) {
    CBlockIndex *pindexPrev = (*miPrev).second;
    if (!core_CheckBlockWitness(iface, (CBlock *)this, pindexPrev))
      return (trust(-10, "(test) CheckBlock: invalid witness integrity."));
  }

  return true;
}



#ifdef USE_LEVELDB_TXDB
bool static test_Reorganize(CTxDB& txdb, CBlockIndex* pindexNew, TEST_CTxMemPool *mempool)
{
  char errbuf[1024];

  /* find the fork */
  CBlockIndex* pindexBest = GetBestBlockIndex(TEST_COIN_IFACE);
  CBlockIndex* pfork = pindexBest;
  CBlockIndex* plonger = pindexNew;
  while (pfork != plonger)
  {
    while (plonger->nHeight > pfork->nHeight)
      if (!(plonger = plonger->pprev))
        return error(SHERR_INVAL, "Reorganize() : plonger->pprev is null");
    if (pfork == plonger)
      break;
    if (!pfork->pprev) {
      sprintf(errbuf, "test_Reorganize: no previous chain for '%s' height %d\n", pfork->GetBlockHash().GetHex().c_str(), pfork->nHeight); 
      return error(SHERR_INVAL, errbuf);
    }
    pfork = pfork->pprev;
  }


  // List of what to disconnect
  vector<CBlockIndex*> vDisconnect;
  for (CBlockIndex* pindex = GetBestBlockIndex(TEST_COIN_IFACE); pindex != pfork; pindex = pindex->pprev)
    vDisconnect.push_back(pindex);

  // List of what to connect
  vector<CBlockIndex*> vConnect;
  for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
    vConnect.push_back(pindex);
  reverse(vConnect.begin(), vConnect.end());

  pindexBest = GetBestBlockIndex(TEST_COIN_IFACE);

  // Disconnect shorter branch
  vector<CTransaction> vResurrect;
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
  {
    TESTBlock block;
    if (!block.ReadFromDisk(pindex)) {
      if (!block.ReadArchBlock(pindex->GetBlockHash()))
        return error(SHERR_IO, "Reorganize() : ReadFromDisk for disconnect failed");
    }
    if (!block.DisconnectBlock(txdb, pindex))
      return error(SHERR_INVAL, "Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());

    // Queue memory transactions to resurrect
    BOOST_FOREACH(const CTransaction& tx, block.vtx)
      if (!tx.IsCoinBase())
        vResurrect.push_back(tx);
  }

  // Connect longer branch
  vector<TESTBlock> vDelete;
  for (unsigned int i = 0; i < vConnect.size(); i++)
  {
    CBlockIndex* pindex = vConnect[i];
    TESTBlock block;
    if (!block.ReadFromDisk(pindex)) {
      if (!block.ReadArchBlock(pindex->GetBlockHash()))
        return error(SHERR_INVAL, "Reorganize() : ReadFromDisk for connect failed for hash '%s' [height %d]", pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight);
    }
    if (!block.ConnectBlock(txdb, pindex))
    {
      // Invalid block
      return error(SHERR_INVAL, "Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
    }

    // Queue memory transactions to delete
    vDelete.push_back(block);
  }
  if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
    return error(SHERR_INVAL, "Reorganize() : WriteHashBestChain failed");

  // Make sure it's successfully written to disk before changing memory structure
  if (!txdb.TxnCommit())
    return error(SHERR_INVAL, "Reorganize() : TxnCommit failed");

  // Disconnect shorter branch
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
    if (pindex->pprev)
      pindex->pprev->pnext = NULL;

  // Connect longer branch
  BOOST_FOREACH(CBlockIndex* pindex, vConnect)
    if (pindex->pprev)
      pindex->pprev->pnext = pindex;

  // Resurrect memory transactions that were in the disconnected branch
  BOOST_FOREACH(CTransaction& tx, vResurrect)
    mempool->AddTx(tx);

#if 0
  BOOST_FOREACH(CTransaction& tx, vDelete)
    mempool->CommitTx(tx);
#endif
  // Delete redundant memory transactions that are in the connected branch
  BOOST_FOREACH(CBlock& block, vDelete) {
    mempool->Commit(block);
  }

  return true;
}
#endif

void TESTBlock::InvalidChainFound(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  ValidIndexSet *setValid = GetValidIndexSet(TEST_COIN_IFACE);

  pindexNew->nStatus |= BLOCK_FAILED_VALID;
  setValid->erase(pindexNew);


  error(SHERR_INVAL, "TEST: InvalidChainFound: invalid block=%s  height=%d  work=%s  date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      pindexNew->bnChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S",
        pindexNew->GetBlockTime()).c_str());
}

#ifdef USE_LEVELDB_TXDB
bool test_SetBestChainInner(CTxDB& txdb, CBlock *block, CBlockIndex *pindexNew)
{
  uint256 hash = block->GetHash();
  shtime_t ts;
  bool ret;

  timing_init("SetBestChainInner:ConnectBlock", &ts);
  ret = block->ConnectBlock(txdb, pindexNew);
  timing_term(TEST_COIN_IFACE, "SetBestChainInner:ConnectBlock", &ts);
  if (!ret) {
    txdb.TxnAbort();
    block->InvalidChainFound(pindexNew);
    return error(SHERR_INVAL, "connect block failure");
  }

  timing_init("SetBestChainInner:WriteHashBestChain", &ts);
  ret = txdb.WriteHashBestChain(hash);
  timing_term(TEST_COIN_IFACE, "SetBestChainInner:WriteHashBestChain", &ts);
  if (!ret) {
    txdb.TxnAbort();
    block->InvalidChainFound(pindexNew);
    return error(SHERR_INVAL, "error writing best hash chain");
  }

  timing_init("SetBestChainInner:TxnCommit", &ts);
  if (!txdb.TxnCommit())
    return error(SHERR_IO, "SetBestChain() : TxnCommit failed");
  timing_term(TEST_COIN_IFACE, "SetBestChainInner:TxnCommit", &ts);

  // Add to current best branch
  pindexNew->pprev->pnext = pindexNew;

  // Delete redundant memory transactions
  BOOST_FOREACH(CTransaction& tx, block->vtx)
    TESTBlock::mempool.CommitTx(tx);

  return true;
}
#endif

// notify wallets about a new best chain
void static TEST_SetBestChain(const CBlockLocator& loc)
{
  CWallet *pwallet = GetWallet(TEST_COIN_IFACE);

  pwallet->SetBestChain(loc);
}

bool TESTBlock::IsBestChain()
{
  CBlockIndex *pindexBest = GetBestBlockIndex(TEST_COIN_IFACE);
  return (pindexBest && GetHash() == pindexBest->GetBlockHash());
}

bool TESTBlock::AcceptBlock()
{
  blkidx_t *blockIndex = GetBlockTable(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  int mode;

  map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hashPrevBlock);
  if (mi == blockIndex->end()) {
    return error(SHERR_INVAL, "(usde) AcceptBlock: prev block '%s' not found", hashPrevBlock.GetHex().c_str());
  }
  CBlockIndex* pindexPrev = (*mi).second;

  if (GetBlockTime() > GetAdjustedTime() + TEST_MAX_DRIFT_TIME) {
    print();
    return error(SHERR_INVAL, "(test) AcceptBlock: block's timestamp too new.");

  }
	if (GetBlockTime() <= pindexPrev->GetMedianTimePast() ||
			GetBlockTime() < pindexPrev->GetBlockTime()) {
    print();
    return error(SHERR_INVAL, "(test) AcceptBlock: block's timestamp too old.");
  }

	/* redundant */
#if 0
	uint32_t nHeight = (pindexPrev ? (pindexPrev->nHeight+1) : 0);
	if (iface->BIP34Height != -1 && nHeight >= iface->BIP34Height) {
		/* check for obsolete blocks. */
		if (nVersion < 2)
			return (error(SHERR_INVAL, "(%s) AcceptBlock: rejecting obsolete block (ver: %u) (hash: %s) [BIP34].", iface->name, (unsigned int)nVersion, GetHash().GetHex().c_str()));

		/* verify height inclusion. */
		CScript expect = CScript() << nHeight;
		if (vtx[0].vin[0].scriptSig.size() < expect.size() ||
				!std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
			return error(SHERR_INVAL, "(%s) AcceptBlock: submit block \"%s\" has invalid commit height (next block height is %u): %s", iface->name, GetHash().GetHex().c_str(), nHeight, vtx[0].vin[0].scriptSig.ToString().c_str());
	}
	if (iface->BIP66Height != -1 && nVersion < 3 && 
			nHeight >= iface->BIP66Height) {
		return (error(SHERR_INVAL, "(%s) AcceptBlock: rejecting obsolete block (ver: %u) (hash: %s) [BIP66].", iface->name, (unsigned int)nVersion, GetHash().GetHex().c_str()));
	}
	if (iface->BIP65Height != -1 && nVersion < 4 && 
			nHeight >= iface->BIP65Height) {
		return (error(SHERR_INVAL, "(%s) AcceptBlock: rejecting obsolete block (ver: %u) (hash: %s) [BIP65].", iface->name, (unsigned int)nVersion, GetHash().GetHex().c_str()));
	}
	if (nVersion < VERSIONBITS_TOP_BITS &&
			IsWitnessEnabled(iface, pindexPrev)) {
		return (error(SHERR_INVAL, "(%s) AcceptBlock: rejecting obsolete block (ver: %u) (hash: %s) [segwit].", iface->name, (unsigned int)nVersion, GetHash().GetHex().c_str()));
	}
#endif

  if (vtx.size() != 0 && VerifyMatrixTx(vtx[0], mode)) {
    bool fCheck = false;
    if (mode == OP_EXT_VALIDATE) {
      bool fHasValMatrix = BlockAcceptValidateMatrix(iface, vtx[0], NULL, fCheck);
      if (fHasValMatrix && !fCheck)
        return error(SHERR_ILSEQ, "AcceptBlock: test_Validate failure");
    } else if (mode == OP_EXT_PAY) {
      bool fHasSprMatrix = BlockAcceptSpringMatrix(iface, vtx[0], fCheck);
      if (fHasSprMatrix && !fCheck)
        return error(SHERR_ILSEQ, "AcceptBlock: test_Spring failure");
    }
  }

  return (core_AcceptBlock(this, pindexPrev));
}

CScript TESTBlock::GetCoinbaseFlags()
{
  return (TEST_COINBASE_FLAGS);
}

static void test_UpdatedTransaction(const uint256& hashTx)
{
  CWallet *pwallet = GetWallet(TEST_COIN_IFACE);

  pwallet->UpdatedTransaction(hashTx);
}

bool TESTBlock::AddToBlockIndex()
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(TEST_COIN_IFACE);
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  ValidIndexSet *setValid = GetValidIndexSet(TEST_COIN_IFACE);
  CBlockIndex *pindexNew;
  shtime_t ts;

  uint256 hash = GetHash();

  // Check for duplicate
  if (blockIndex->count(hash)) 
    return error(SHERR_INVAL, "AddToBlockIndex() : %s already exists", hash.GetHex().c_str());

  /* create new index */
  pindexNew = new CBlockIndex(*this);
  if (!pindexNew)
    return error(SHERR_INVAL, "AddToBlockIndex() : new CBlockIndex failed");

  map<uint256, CBlockIndex*>::iterator mi = blockIndex->insert(make_pair(hash, pindexNew)).first;
  pindexNew->phashBlock = &((*mi).first);
  map<uint256, CBlockIndex*>::iterator miPrev = blockIndex->find(hashPrevBlock);
  if (miPrev != blockIndex->end())
  {
    pindexNew->pprev = (*miPrev).second;
    pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    pindexNew->BuildSkip();
  }

  pindexNew->bnChainWork = (pindexNew->pprev ? pindexNew->pprev->bnChainWork : 0) + pindexNew->GetBlockWork();

  if (IsWitnessEnabled(iface, pindexNew->pprev)) {
    pindexNew->nStatus |= BLOCK_OPT_WITNESS;
  }

  if (pindexNew->bnChainWork > wallet->bnBestChainWork) {
    bool ret = SetBestChain(pindexNew);
    if (!ret)
      return (false);
  } else {
    WriteArchBlock();
  }

  return true;
}

bool TESTBlock::ReadBlock(uint64_t nHeight)
{
int ifaceIndex = TEST_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
  size_t sBlockLen;
  unsigned char *sBlockData;
  char errbuf[1024];
  bc_t *bc;
  int err;

  bc = GetBlockChain(iface);
  if (!bc)
    return (false);

  err = bc_get(bc, nHeight, &sBlockData, &sBlockLen);
  if (err) {
    sprintf(errbuf, "CBlock::ReadBlock[height %d]: %s (sherr %d).",
      (int)nHeight, sherrstr(err), err);
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

  SetNull();

  /* serialize binary data into block */
  sBlock.write((const char *)sBlockData, sBlockLen);
  sBlock >> *this;
  free(sBlockData);

  return (true);
}

bool TESTBlock::ReadArchBlock(uint256 hash)
{
  int ifaceIndex = TEST_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
  size_t sBlockLen;
  unsigned char *sBlockData;
  char errbuf[1024];
  bcsize_t nPos;
  bc_t *bc;
  int err;

  bc = GetBlockChain(iface);
  if (!bc)
    return (false);

  err = bc_arch_find(bc, hash.GetRaw(), NULL, &nPos);
  if (err)
    return false;

  err = bc_arch(bc, nPos, &sBlockData, &sBlockLen);
  if (err) {
    sprintf(errbuf, "CBlock::ReadBlock[arch-idx %d]: %s (sherr %d).",
      (int)nPos, sherrstr(err), err);
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

  SetNull();

  /* serialize binary data into block */
  sBlock.write((const char *)sBlockData, sBlockLen);
  sBlock >> *this;
  free(sBlockData);

  return (true);
}

bool TESTBlock::IsOrphan()
{
  return (test_IsOrphanBlock(GetHash()));
}

#ifdef USE_LEVELDB_COINDB
bool test_Truncate(uint256 hash)
{
  blkidx_t *blockIndex = GetBlockTable(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CBlockIndex *pBestIndex;
  CBlockIndex *cur_index;
  CBlockIndex *pindex;
  bcpos_t nHeight;
  int err;

  if (!blockIndex || !blockIndex->count(hash))
    return error(SHERR_INVAL, "Erase: block not found in block-index.");

  cur_index = (*blockIndex)[hash];
  if (!cur_index)
    return error(SHERR_INVAL, "Erase: block not found in block-index.");

  pBestIndex = GetBestBlockIndex(iface);
  if (!pBestIndex)
    return error(SHERR_INVAL, "Erase: no block-chain established.");
  if (cur_index->nHeight > pBestIndex->nHeight)
    return error(SHERR_INVAL, "Erase: height is not valid.");

  bc_t *bc = GetBlockChain(iface);
  unsigned int nMinHeight = MAX(1, cur_index->nHeight);

	uint32_t nMaxHeight = 0;
	(void)bc_idx_next(bc, &nMaxHeight);
	nMaxHeight = MAX(1, nMaxHeight) - 1;

  TESTTxDB txdb; /* OPEN */

  for (nHeight = nMaxHeight; nHeight > nMinHeight; nHeight--) {
    TESTBlock block;
    if (block.ReadBlock(nHeight)) {
      uint256 t_hash = block.GetHash();
      if (hash == cur_index->GetBlockHash())
        break; /* bad */
      if (blockIndex->count(t_hash) != 0)
        block.DisconnectBlock(txdb, (*blockIndex)[t_hash]);
      bc_table_reset(bc, t_hash.GetRaw());
    }
  }
  for (nHeight = nMaxHeight; nHeight > nMinHeight; nHeight--) {
    bc_clear(bc, nHeight);
  }  

  SetBestBlockIndex(iface, cur_index);
  bool ret = txdb.WriteHashBestChain(cur_index->GetBlockHash());

  txdb.Close(); /* CLOSE */

  if (!ret)
    return error(SHERR_INVAL, "Truncate: WriteHashBestChain '%s' failed", hash.GetHex().c_str());

  cur_index->pnext = NULL;
  wallet->bnBestChainWork = cur_index->bnChainWork;
  InitServiceBlockEvent(TEST_COIN_IFACE, cur_index->nHeight + 1);

  return (true);
}
bool TESTBlock::Truncate()
{
  return (test_Truncate(GetHash()));
}
#else
bool TESTBlock::Truncate()
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  return (core_Truncate(iface, GetHash()));
}
#endif


bool TESTBlock::VerifyCheckpoint(int nHeight)
{
  return (TEST_Checkpoints::CheckBlock(nHeight, GetHash()));
}   
uint64_t TESTBlock::GetTotalBlocksEstimate()
{   
  return ((uint64_t)TEST_Checkpoints::GetTotalBlocksEstimate());
}

#if 0
/* TEST: coin.cpp */
bool TESTBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);

  if (!core_DisconnectBlock(pindex, this))
    return (false);

  if (pindex->pprev) {
    BOOST_FOREACH(CTransaction& tx, vtx) {
      if (tx.IsCoinBase()) {
        if (tx.isFlag(CTransaction::TXF_MATRIX)) {
          CTxMatrix& matrix = tx.matrix;
          if (matrix.GetType() == CTxMatrix::M_VALIDATE) {
            /* retract block hash from Validate matrix */
            matrixValidate.Retract(matrix.nHeight, pindex->GetBlockHash());
          } else if (matrix.GetType() == CTxMatrix::M_SPRING) {
            BlockRetractSpringMatrix(iface, tx, pindex);
          }
        }
      } else {
        if (tx.isFlag(CTransaction::TXF_CERTIFICATE)) {
          DisconnectCertificate(iface, tx);
        }
      }
    }
  }

  return true;
}
#endif

int64_t TESTBlock::GetBlockWeight()
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(*this, SER_NETWORK, TEST_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (TEST_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(*this, SER_NETWORK, TEST_PROTOCOL_VERSION);

  return (weight);
}




#if 0
bool TEST_CTxMemPool::accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs, bool* pfMissingInputs)
{
  if (pfMissingInputs)
    *pfMissingInputs = false;

  if (!tx.CheckTransaction(TEST_COIN_IFACE))
    return error(SHERR_INVAL, "CTxMemPool::accept() : CheckTransaction failed");

  // Coinbase is only valid in a block, not as a loose transaction
  if (tx.IsCoinBase()) {
    return error(SHERR_INVAL, "CTxMemPool::accept() : coinbase as individual tx");
}

  // To help v0.1.5 clients who would see it as a negative number
  if ((int64)tx.nLockTime > std::numeric_limits<int>::max())
    return error(SHERR_INVAL, "CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

  // Rather not work on nonstandard transactions (unless -testnet)
  if (!fTestNet && !tx.IsStandard())
    return error(SHERR_INVAL, "CTxMemPool::accept() : nonstandard transaction type");

  // Do we already have it?
  uint256 hash = tx.GetHash();
  {
    LOCK(cs);
    if (mapTx.count(hash))
      return false;
  }
  if (fCheckInputs)
    if (txdb.ContainsTx(hash))
      return false;

  // Check for conflicts with in-memory transactions
  CTransaction* ptxOld = NULL;
  for (unsigned int i = 0; i < tx.vin.size(); i++)
  {
    COutPoint outpoint = tx.vin[i].prevout;
    if (mapNextTx.count(outpoint))
    {
      if (!tx.isFlag(CTransaction::TXF_CHANNEL)) {
        return false;
      }

      // Allow replacing with a newer version of the same transaction
      if (i != 0)
        return false;
      ptxOld = mapNextTx[outpoint].ptx;
      if (ptxOld->IsFinal(TEST_COIN_IFACE))
        return false;
      if (!tx.IsNewerThan(*ptxOld))
        return false;
      for (unsigned int i = 0; i < tx.vin.size(); i++)
      {
        COutPoint outpoint = tx.vin[i].prevout;
        if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
          return false;
      }

      break;
    }
  }

  if (fCheckInputs)
  {
    MapPrevTx mapInputs;
    map<uint256, CTxIndex> mapUnused;
    bool fInvalid = false;
    if (!tx.FetchInputs(txdb, mapUnused, NULL, false, mapInputs, fInvalid))
    {
      if (fInvalid)
        return error(SHERR_INVAL, "CTxMemPool::accept() : FetchInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
      if (pfMissingInputs)
        *pfMissingInputs = true;
      return false;
    }

    // Check for non-standard pay-to-script-hash in inputs
    if (!tx.AreInputsStandard(TEST_COIN_IFACE, mapInputs) && !fTestNet) {
      tx.print(TEST_COIN_IFACE);
      return error(SHERR_INVAL, "CTxMemPool::accept() : nonstandard transaction input");
    }

    // Note: if you modify this code to accept non-standard transactions, then
    // you should add code here to check that the transaction does a
    // reasonable number of ECDSA signature verifications.

    int64 nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
    unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, TEST_PROTOCOL_VERSION);

#if 0
    // Don't accept it if it can't get into a block
    if (nFees < tx.GetMinFee(1000, true, GMF_RELAY))
      return error(SHERR_INVAL, "CTxMemPool::accept() : not enough fees");
#endif
    CWallet *pwallet = GetWallet(TEST_COIN_IFACE);
    if (!pwallet->AllowFree(pwallet->GetPriority(tx, mapInputs))) {
      if (nFees < pwallet->CalculateFee(tx))
        return error(SHERR_INVAL, "CTxMemPool::accept() : not enough fees");
    }

    // Continuously rate-limit free transactions
    // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
    // be annoying or make other's transactions take longer to confirm.
    if (nFees < TEST_MIN_RELAY_TX_FEE)
    {
      static CCriticalSection cs;
      static double dFreeCount;
      static int64 nLastTime;
      int64 nNow = GetTime();

      {
        LOCK(cs);
        // Use an exponentially decaying ~10-minute window:
        dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
        nLastTime = nNow;
        // -limitfreerelay unit is thousand-bytes-per-minute
        // At default rate it would take over a month to fill 1GB
        if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000 && !test_IsFromMe(tx))
          return error(SHERR_INVAL, "CTxMemPool::accept() : free transaction rejected by rate limiter");
        Debug("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
        dFreeCount += nSize;
      }
    }

    // Check against previous transactions
    // This is done last to help prevent CPU exhaustion denial-of-service attacks.

    if (!test_ConnectInputs(&tx, mapInputs, mapUnused, CDiskTxPos(0,0,0), GetBestBlockIndex(TEST_COIN_IFACE), false, false))
    {
      return error(SHERR_INVAL, "CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().substr(0,10).c_str());
    }
  }

  // Store transaction in memory
  {
    LOCK(cs);
    if (ptxOld)
    {
      Debug("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
      remove(*ptxOld);
    }
    addUnchecked(hash, tx);
  }

  ///// are we sure this is ok when loading transactions or restoring block txes
  // If updated, erase old tx from wallet
  if (ptxOld)
    test_EraseFromWallets(ptxOld->GetHash());

//  Debug("(test) mempool accepted %s (pool-size %u)\n", hash.ToString().c_str(), mapTx.size());
  return true;
}

bool TEST_CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);

  // Add to memory pool without checking anything.  Don't call this directly,
  // call CTxMemPool::accept to properly check the transaction first.
  {
    mapTx[hash] = tx;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
      mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
    STAT_TX_ACCEPTS(iface)++;
  }
  return true;
}


bool TEST_CTxMemPool::remove(CTransaction &tx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);

  // Remove transaction from memory pool
  {
    LOCK(cs);
    uint256 hash = tx.GetHash();
    if (mapTx.count(hash))
    {
      BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapNextTx.erase(txin.prevout);
      mapTx.erase(hash);
      STAT_TX_ACCEPTS(iface)++;
    }
  }
  return true;
}

void TEST_CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}
#endif



#ifdef USE_LEVELDB_COINDB

#ifndef USE_LEVELDB_TXDB
bool TESTBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

  if (TESTBlock::pindexGenesisBlock == NULL && hash == test_hashGenesisBlock)
  {
    if (!txdb.TxnBegin())
      return error(SHERR_INVAL, "SetBestChain() : TxnBegin failed");
    txdb.WriteHashBestChain(hash);
    if (!txdb.TxnCommit())
      return error(SHERR_INVAL, "SetBestChain() : TxnCommit failed");
    TESTBlock::pindexGenesisBlock = pindexNew;
  } else {
    timing_init("SetBestChain/commit", &ts);
    ret = core_CommitBlock(txdb, this, pindexNew); 
    timing_term(TEST_COIN_IFACE, "SetBestChain/commit", &ts);
    if (!ret)
      return (false);
  }

  // Update best block in wallet (so we can detect restored wallets)
  bool fIsInitialDownload = IsInitialBlockDownload(TEST_COIN_IFACE);
  if (!fIsInitialDownload) {
    const CBlockLocator locator(TEST_COIN_IFACE, pindexNew);
    timing_init("SetBestChain/locator", &ts);
    TEST_SetBestChain(locator);
    timing_term(TEST_COIN_IFACE, "SetBestChain/locator", &ts);
  }

  // New best block
  SetBestBlockIndex(TEST_COIN_IFACE, pindexNew);
  bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();

  {
    CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
    if (iface)
      STAT_TX_ACCEPTS(iface)++;
  }

  return true;
}
#endif

bool TESTBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
  shtime_t ts;
  char errbuf[1024];

  /* redundant */
  if (!CheckBlock())
    return false;

  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  unsigned int nFile = TEST_COIN_IFACE;
  unsigned int nBlockPos = pindex->nHeight;;
  bc_hash_t b_hash;
  int err;

  // BIP16 didn't become active until October 1 2012
  int64 nBIP16SwitchTime = 1349049600;
  bool fStrictPayToScriptHash = (pindex->nTime >= nBIP16SwitchTime);

  map<uint256, CTxIndex> mapQueuedChanges;
  int64 nFees = 0;
  unsigned int nSigOps = 0;
  BOOST_FOREACH(CTransaction& tx, vtx)
  {
    uint256 hashTx = tx.GetHash();
    int nTxPos;

    { /* BIP30 */
      CTxIndex txindexOld;
      if (txdb.ReadTxIndex(hashTx, txindexOld)) {
        BOOST_FOREACH(CDiskTxPos &pos, txindexOld.vSpent) {
          if (tx.IsSpentTx(pos))
            return error(SHERR_INVAL, "TESTBlock::ConnectBlock: BIP30 enforced at height %d (block %s) (tx %s)\n", pindex->nHeight, pindex->GetBlockHash().GetHex().c_str(), tx.GetHash().GetHex().c_str());
        }
      }
    }

    MapPrevTx mapInputs;
    CDiskTxPos posThisTx(TEST_COIN_IFACE, nBlockPos, nTxPos);
    if (!tx.IsCoinBase()) {
      bool fInvalid;
      if (!tx.FetchInputs(txdb, mapQueuedChanges, this, false, mapInputs, fInvalid)) {
        sprintf(errbuf, "TEST::ConnectBlock: FetchInputs failed for tx '%s' @ height %u\n", tx.GetHash().GetHex().c_str(), (unsigned int)nBlockPos);
        return error(SHERR_INVAL, errbuf);
      }
    }

    nSigOps += tx.GetSigOpCost(mapInputs);
    if (nSigOps > MAX_BLOCK_SIGOP_COST(iface)) {
      return (trust(-100, "(test) ConnectBlock: sigop cost exceeded maximum (%d > %d)", nSigOps, MAX_BLOCK_SIGOP_COST(iface)));
    }

    if (!tx.IsCoinBase()) {
      nFees += tx.GetValueIn(mapInputs)-tx.GetValueOut();

      if (!test_ConnectInputs(&tx, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fStrictPayToScriptHash))
        return false;
    }

    mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
  }

  // Write queued txindex changes
  for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
  {
    if (!txdb.UpdateTxIndex((*mi).first, (*mi).second)) {
      return error(SHERR_INVAL, "ConnectBlock() : UpdateTxIndex failed");
    }
  }

#if 0
if (vtx.size() == 0) {
return false;
}
#endif
  
  int64 nValue = test_GetBlockValue(pindex->nHeight, nFees);
  if (vtx[0].GetValueOut() > test_GetBlockValue(pindex->nHeight, nFees)) {
    sprintf(errbuf, "TEST::ConnectBlock: coinbase output (%d coins) higher than expected block value @ height %d (%d coins) [block %s].\n", FormatMoney(vtx[0].GetValueOut()).c_str(), pindex->nHeight, FormatMoney(nValue).c_str(), pindex->GetBlockHash().GetHex().c_str());
    return error(SHERR_INVAL, errbuf);
  }


  if (pindex->pprev)
  {
    if (pindex->pprev->nHeight + 1 != pindex->nHeight) {
      pindex->nHeight = pindex->pprev->nHeight + 1;
    }
    timing_init("WriteBlock", &ts);
    if (!WriteBlock(pindex->nHeight)) {
      return (error(SHERR_INVAL, "test_ConnectBlock: error writing block hash '%s' to height %d\n", GetHash().GetHex().c_str(), pindex->nHeight));
    }
    timing_term(TEST_COIN_IFACE, "WriteBlock", &ts);
  }

  timing_init("SyncWithWallets", &ts);
  BOOST_FOREACH(CTransaction& tx, vtx)
    SyncWithWallets(iface, tx, this);
  timing_term(TEST_COIN_IFACE, "SyncWithWallets", &ts);

  return true;
}

bool TESTBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
  CIface *iface = GetCoinByIndex(txdb.ifaceIndex);
	CWallet *wallet = GetCoinByIndex(txdb.ifaceIndex);


  if (pindex->pprev) {
    if (txdb.ifaceIndex == TEST_COIN_IFACE ||
        txdb.ifaceIndex == SHC_COIN_IFACE) {
      BOOST_FOREACH(CTransaction& tx, vtx) {
        if (tx.IsCoinBase()) {
          if (tx.isFlag(CTransaction::TXF_MATRIX)) {
            CTxMatrix& matrix = tx.matrix;
            if (matrix.GetType() == CTxMatrix::M_VALIDATE) {
              /* retract block hash from Validate matrix */
							BlockRetractValidateMatrix(iface, tx, pindex);
            } else if (matrix.GetType() == CTxMatrix::M_SPRING) {
              BlockRetractSpringMatrix(iface, tx, pindex);
            }
          }
        }
      }
    }
  }

  if (!core_DisconnectBlock(txdb, pindex, this))
    return (false);

  return true;
}


bool test_ConnectInputs(CTransaction *tx, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fStrictPayToScriptHash=true)
{

  if (tx->IsCoinBase())
    return (true);

  // Take over previous transactions' spent pointers
  // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
  // fMiner is true when called from the internal test miner
  // ... both are false when called from CTransaction::AcceptToMemoryPool

  int64 nValueIn = 0;
  int64 nFees = 0;
  for (unsigned int i = 0; i < tx->vin.size(); i++)
  {
    COutPoint prevout = tx->vin[i].prevout;
    assert(inputs.count(prevout.hash) > 0);
    CTxIndex& txindex = inputs[prevout.hash].first;
    CTransaction& txPrev = inputs[prevout.hash].second;

    if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
      return error(SHERR_INVAL, "ConnectInputs() : %s prevout.n out of range %d %d %d prev tx %s\n", tx->GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str());

    // If prev is coinbase, check that it's matured
    if (txPrev.IsCoinBase())
      for (const CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < TEST_COINBASE_MATURITY; pindex = pindex->pprev)
        //if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
        if (pindex->nHeight == txindex.pos.nBlockPos)// && pindex->nFile == txindex.pos.nFile)
          return error(SHERR_INVAL, "TEST: ConnectInputs() : tried to spend coinbase at depth %d", pindexBlock->nHeight - pindex->nHeight);

    // Check for negative or overflow input values
    nValueIn += txPrev.vout[prevout.n].nValue;
    if (!MoneyRange(TEST_COIN_IFACE, txPrev.vout[prevout.n].nValue) || !MoneyRange(TEST_COIN_IFACE, nValueIn))
      return error(SHERR_INVAL, "ConnectInputs() : txin values out of range");

  }
  // The first loop above does all the inexpensive checks.
  // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
  // Helps prevent CPU exhaustion attacks.
  for (unsigned int i = 0; i < tx->vin.size(); i++)
  {
    COutPoint prevout = tx->vin[i].prevout;
    assert(inputs.count(prevout.hash) > 0);
    CTxIndex& txindex = inputs[prevout.hash].first;
    CTransaction& txPrev = inputs[prevout.hash].second;

    /* this coin has been marked as spent. ensure this is not a re-write of the same transaction. */
    if (tx->IsSpentTx(txindex.vSpent[prevout.n])) {
      if (fMiner) return false;
      return error(SHERR_INVAL, "(test) ConnectInputs: %s prev tx (%s) already used at %s", tx->GetHash().GetHex().c_str(), txPrev.GetHash().GetHex().c_str(), txindex.vSpent[prevout.n].ToString().c_str());
    }

    // Check for conflicts (double-spend)
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    if (!txindex.vSpent[prevout.n].IsNull()) {
      if (txindex.vSpent[prevout.n].nBlockPos != pindexBlock->nHeight) {
        return fMiner ? false : error(SHERR_INVAL, "ConnectInputs() : %s prev tx already used at %s", tx->GetHash().ToString().substr(0,10).c_str(), txindex.vSpent[prevout.n].ToString().c_str());
      }
  }

    // Skip ECDSA signature verification when connecting blocks (fBlock=true)
    // before the last blockchain checkpoint. This is safe because block merkle hashes are
    // still computed and checked, and any change will be caught at the next checkpoint.
    if (!(fBlock && (GetBestHeight(TEST_COIN_IFACE < TEST_Checkpoints::GetTotalBlocksEstimate()))))
    {
      // Verify signature
      if (!VerifySignature(TEST_COIN_IFACE, txPrev, *tx, i, fStrictPayToScriptHash, 0))
      {
        // only during transition phase for P2SH: do not invoke anti-DoS code for
        // potentially old clients relaying bad P2SH transactions
        if (fStrictPayToScriptHash && VerifySignature(TEST_COIN_IFACE, txPrev, *tx, i, false, 0))
          return error(SHERR_INVAL, "ConnectInputs() : %s P2SH VerifySignature failed", tx->GetHash().ToString().substr(0,10).c_str());

        return error(SHERR_INVAL, "ConnectInputs() : %s VerifySignature failed", tx->GetHash().ToString().substr(0,10).c_str());
      }
    }

    // Mark outpoints as spent
    txindex.vSpent[prevout.n] = posThisTx;

    // Write back
    if (fBlock || fMiner)
    {
      mapTestPool[prevout.hash] = txindex;
    }
  }

  if (nValueIn < tx->GetValueOut())
    return error(SHERR_INVAL, "ConnectInputs() : %s value in < value out", tx->GetHash().ToString().substr(0,10).c_str());

  // Tally transaction fees
  int64 nTxFee = nValueIn - tx->GetValueOut();
  if (nTxFee < 0)
    return error(SHERR_INVAL, "ConnectInputs() : %s nTxFee < 0", tx->GetHash().ToString().substr(0,10).c_str());
  nFees += nTxFee;
  if (!MoneyRange(TEST_COIN_IFACE, nFees))
    return error(SHERR_INVAL, "ConnectInputs() : nFees out of range");

  return true;
}





#else

bool TESTBlock::SetBestChain(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

  if (TESTBlock::pindexGenesisBlock == NULL && hash == test_hashGenesisBlock)
  {
    TESTBlock::pindexGenesisBlock = pindexNew;
  } else {
    timing_init("SetBestChain/commit", &ts);
    ret = core_CommitBlock(this, pindexNew); 
    timing_term(TEST_COIN_IFACE, "SetBestChain/commit", &ts);
    if (!ret)
      return (false);
  }

  // Update best block in wallet (so we can detect restored wallets)
  bool fIsInitialDownload = IsInitialBlockDownload(TEST_COIN_IFACE);
  if (!fIsInitialDownload) {
    const CBlockLocator locator(TEST_COIN_IFACE, pindexNew);
    timing_init("SetBestChain/locator", &ts);
    TEST_SetBestChain(locator);
    timing_term(TEST_COIN_IFACE, "SetBestChain/locator", &ts);

#ifdef USE_LEVELDB_COINDB
    {
      TESTTxDB txdb;
      txdb.WriteHashBestChain(hash);
      txdb.Close();
    }
#else
    WriteHashBestChain(iface, hash); 
#endif
  }

  // New best block
  SetBestBlockIndex(TEST_COIN_IFACE, pindexNew);
  wallet->bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();

  return true;
}

bool TESTBlock::ConnectBlock(CBlockIndex* pindex)
{
  bool ok = core_ConnectBlock(this, pindex);
  if (ok)
    test_RemoveOrphanBlock(pindex->GetBlockHash());
  return (ok);
}

bool TESTBlock::DisconnectBlock(CBlockIndex* pindex)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
	CWallet *wallet = GetWallet(TEST_COIN_IFACE);


  if (pindex->pprev) {
    BOOST_FOREACH(CTransaction& tx, vtx) {
      if (tx.IsCoinBase()) {
        if (tx.isFlag(CTransaction::TXF_MATRIX)) {
          CTxMatrix& matrix = tx.matrix;
          if (matrix.GetType() == CTxMatrix::M_VALIDATE) {
            /* retract block hash from Validate matrix */
            wallet->matrixValidate.Retract(matrix.nHeight, pindex->GetBlockHash());
          } else if (matrix.GetType() == CTxMatrix::M_SPRING) {
            BlockRetractSpringMatrix(iface, tx, pindex);
          }
        }
      } else {
        if (tx.isFlag(CTransaction::TXF_CERTIFICATE)) {
          DisconnectCertificate(iface, tx);
        }
      }
    }
  }

  if (!core_DisconnectBlock(pindex, this))
    return (false);

  return (true);
}


#endif


bool TESTBlock::CreateCheckpoint()
{
	blkidx_t *blockIndex = GetBlockTable(TEST_COIN_IFACE);
	const uint256& hBlock = GetHash();
	CBlockIndex *prevIndex;
	CBlockIndex *pindex;

	if (blockIndex->count(hBlock) == 0)
		return (false);
	pindex = (*blockIndex)[hBlock];

	prevIndex = TEST_Checkpoints::GetLastCheckpoint(*blockIndex);
	if (prevIndex && pindex->nHeight <= prevIndex->nHeight)
		return (false); /* stale */

	TEST_Checkpoints::AddCheckpoint(pindex->nHeight, hBlock);
	return (true);
}

