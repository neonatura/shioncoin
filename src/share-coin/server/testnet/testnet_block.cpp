
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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
#include "testnet_pool.h"
#include "testnet_block.h"
#include "testnet_wallet.h"
#include "testnet_txidx.h"
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


using namespace std;
using namespace boost;


uint256 testnet_hashGenesisBlock("0xf4319e4e89b35b5f26ec0363a09d29703402f120cf1bf8e6f535548d5ec3c5cc");
static uint256 testnet_hashGenesisMerkle("0xd3f4bbe7fe61bda819369b4cd3a828f3ad98d971dda0c20a466a9ce64846c321");
static CBigNum TESTNET_bnGenesisProofOfWorkLimit(~uint256(0) >> 20);
static CBigNum TESTNET_bnProofOfWorkLimit(~uint256(0) >> 12);


/* ** BLOCK ORPHANS ** */

typedef map<uint256, uint256> orphan_map;
static orphan_map TESTNET_mapOrphanBlocksByPrev;

bool testnet_IsOrphanBlock(const uint256& hash)
{
  CBlockIndex *pindex;
  TESTNETBlock block;
  uint256 prevHash;
  bool ok;

  if (testnet_GetOrphanPrevHash(hash, prevHash)) {
    /* already mapped. */
    return (true);
  }

  return (false); 
}

void testnet_AddOrphanBlock(CBlock *block)
{

  TESTNET_mapOrphanBlocksByPrev.insert(
      make_pair(block->hashPrevBlock, block->GetHash()));
  block->WriteArchBlock();

}

void testnet_RemoveOrphanBlock(const uint256& hash)
{
  bool found;

  orphan_map::iterator it = TESTNET_mapOrphanBlocksByPrev.begin(); 
  while (it != TESTNET_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found)
      break;
    ++it;
  }
  if (it != TESTNET_mapOrphanBlocksByPrev.end()) {
    TESTNET_mapOrphanBlocksByPrev.erase(it);
  }
  
}

bool testnet_GetOrphanPrevHash(const uint256& hash, uint256& retPrevHash)
{
  bool found;

  orphan_map::iterator it = TESTNET_mapOrphanBlocksByPrev.begin(); 
  while (it != TESTNET_mapOrphanBlocksByPrev.end()) {
    found = (it->second == hash);
    if (found) {
      retPrevHash = it->first;
      return (true);
    }
    ++it;
  }

  return (false);
}

bool testnet_GetOrphanNextHash(const uint256& hash, uint256& retNextHash)
{
  bool found;

  orphan_map::iterator it = TESTNET_mapOrphanBlocksByPrev.find(hash);
  if (it != TESTNET_mapOrphanBlocksByPrev.end()) {
    retNextHash = it->second;
    return (true);
  }
  return (false);
}

CBlock *testnet_GetOrphanBlock(const uint256& hash)
{
  TESTNETBlock block;  

  if (!block.ReadArchBlock(hash))
    return (NULL);

  return (new TESTNETBlock(block));
}

uint256 testnet_GetOrphanRoot(uint256 hash)
{
  uint256 prevHash;

  while (testnet_GetOrphanPrevHash(hash, prevHash)) {
    hash = prevHash;
  }
  return (hash);
}




/** TestNet : difficulty level is always lowest possible per protocol. */
unsigned int TESTNETBlock::GetNextWorkRequired(const CBlockIndex* pindexLast)
{
	if (pindexLast == NULL)
		    return (TESTNET_bnGenesisProofOfWorkLimit.GetCompact());

	return ((unsigned int)TESTNET_bnProofOfWorkLimit.GetCompact());
}


int64 testnet_GetBlockValue(int nHeight, int64 nFees)
{
  if (nHeight == 0) return (800 * COIN);

  int64 nSubsidy = COIN; /* one coin */
  return ((int64)nSubsidy + nFees);
}


namespace TESTNET_Checkpoints
{
  typedef std::map<int, uint256> MapCheckpoints;

  static MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    ( 0, uint256("0xf4319e4e89b35b5f26ec0363a09d29703402f120cf1bf8e6f535548d5ec3c5cc") )


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
		Debug("(testnet) AddCheckpoint: new dynamic checkpoint (height %d): %s",height, hash.GetHex().c_str());
  }

}

static int64_t testnet_GetTxWeight(const CTransaction& tx)
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(tx, SER_NETWORK, TESTNET_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (TESTNET_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(tx, SER_NETWORK, TESTNET_PROTOCOL_VERSION);

  return (weight);
}

CBlock* testnet_CreateNewBlock(const CPubKey& rkey)
{
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);
  CBlockIndex *pindexPrev = GetBestBlockIndex(iface);

  auto_ptr<TESTNETBlock> pblock(new TESTNETBlock());
  if (!pblock.get())
    return NULL;

  /* coinbase */
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vin[0].prevout.SetNull();
  txNew.vout.resize(1);
  txNew.vout[0].scriptPubKey << rkey << OP_CHECKSIG;
  pblock->vtx.push_back(txNew);

  pblock->nVersion = core_ComputeBlockVersion(iface, pindexPrev);

  int64 nFees = 0;
  CTxMemPool *pool = GetTxMemPool(iface); 
  vector<CTransaction> vPriority = pool->GetActiveTx(); 
  BOOST_FOREACH(CTransaction tx, vPriority) {
    const uint256& hash = tx.GetHash();
    tx_cache mapInputs;

    if (pool->FetchInputs(hash, mapInputs)) {
      int64 nTxFee = tx.GetValueIn(mapInputs)-tx.GetValueOut();
      nFees += nTxFee;
      pblock->vtx.push_back(tx);
    }
  }

  /* calculate reward */
  bool ret = false;
  int64 reward = testnet_GetBlockValue(pindexPrev->nHeight+1, nFees);
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

  /* fill coinbase signature (BIP34) */
  core_IncrementExtraNonce(pblock.get(), pindexPrev);

  return pblock.release();
}

bool testnet_CreateGenesisBlock()
{
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(TESTNET_COIN_IFACE);
  bool ret;

  if (blockIndex->count(testnet_hashGenesisBlock) != 0)
    return (true); /* already created */

  // Genesis block
  const char* pszTimestamp = "Neo Natura (share-coin) 2016";
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vout.resize(1);
  txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
  txNew.vout[0].nValue = testnet_GetBlockValue(0, 0);
  txNew.vout[0].scriptPubKey = CScript() << ParseHex("04a5814813115273a109cff99907ba4a05d951873dae7acb6c973d0c9e7c88911a3dbc9aa600deac241b91707e7b4ffb30ad91c8e56e695a1ddf318592988afe0a") << OP_CHECKSIG;
  TESTNETBlock block;
  block.vtx.push_back(txNew);
  block.hashPrevBlock = 0;
  block.hashMerkleRoot = block.BuildMerkleTree();
  block.nVersion = 2;
  block.nTime    = 1461974400; /* 04/30/16 12:00am */
  block.nBits    = 0x1e0ffff0;
  block.nNonce   = 3293840;


  if (block.GetHash() != testnet_hashGenesisBlock) {
fprintf(stderr, "DEBUG: Genesis fail: %s\n", block.ToString().c_str());
    return (error(ERR_INVAL, "testnet_CreateGenesisBlock: !hash"));
	}
  if (block.hashMerkleRoot != testnet_hashGenesisMerkle)
    return (false);

  if (!block.WriteBlock(0)) {
    return (error(ERR_INVAL, "testnet_CreateGenesisBlock: !WriteBlock"));
  }

  ret = block.AddToBlockIndex();
  if (!ret) {
		return (error(ERR_INVAL, "testnet_CreateGenesisBlock: !AddToBlockIndex"));
  }

  return (true);
}

static bool testnet_IsFromMe(CTransaction& tx)
{
  CWallet *pwallet = GetWallet(TESTNET_COIN_IFACE);

  if (pwallet->IsFromMe(tx))
    return true;

  return false;
}

static void testnet_EraseFromWallets(uint256 hash)
{
  CWallet *pwallet = GetWallet(TESTNET_COIN_IFACE);

  pwallet->EraseFromWallet(hash);
}


bool testnet_ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(TESTNET_COIN_IFACE);
  int ifaceIndex = TESTNET_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
  shtime_t ts;

  // Check for duplicate
  uint256 hash = pblock->GetHash();

	if (pblock->hashPrevBlock == 0 &&
			hash != testnet_hashGenesisBlock) {
		Debug("(testnet) ProcessBlock: warning: invalid genesis block \"%s\" submitted by \"%s\".", hash.GetHex().c_str(), (pfrom?pfrom->addr.ToString().c_str():"<local>"));
		return (false);
	}


  // Preliminary checks
  if (!pblock->CheckBlock()) {
    return error(SHERR_INVAL, "ProcessBlock() : CheckBlock FAILED");
  }

#if 0
  CBlockIndex* pcheckpoint = TESTNET_Checkpoints::GetLastCheckpoint(*blockIndex);
  if (pcheckpoint && pblock->hashPrevBlock != GetBestBlockChain(iface)) {
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

  /*
   * TESTNET: If previous hash and it is unknown.
   */ 
  if (pblock->hashPrevBlock != 0 &&
      !blockIndex->count(pblock->hashPrevBlock)) {
    Debug("(testnet) ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.GetHex().c_str());
    if (pfrom) {
      testnet_AddOrphanBlock(pblock);
      STAT_BLOCK_ORPHAN(iface)++;

      /* request missing blocks */
      CBlockIndex *pindexBest = GetBestBlockIndex(TESTNET_COIN_IFACE);
      if (pindexBest) {
        Debug("(testnet) ProcessBlocks: requesting blocks from height %d due to orphan '%s'.\n", pindexBest->nHeight, pblock->GetHash().GetHex().c_str()); 
        pfrom->PushGetBlocks(GetBestBlockIndex(TESTNET_COIN_IFACE), testnet_GetOrphanRoot(pblock->GetHash()));
				InitServiceBlockEvent(TESTNET_COIN_IFACE, pindexBest->nHeight);
      }
    }
    return true;
  }

#if 0 /* redundant */
  if (!pblock->CheckTransactionInputs(TESTNET_COIN_IFACE)) {
    Debug("(testnet) ProcessBlock: invalid input transaction [prev %s].", pblock->hashPrevBlock.GetHex().c_str());
    return (true);
  }
#endif

  /* store to disk */
  if (!pblock->AcceptBlock()) {
    iface->net_invalid = time(NULL);
    return error(SHERR_IO, "TESTNETBlock::AcceptBlock: error adding block '%s'.", pblock->GetHash().GetHex().c_str());
  }

  uint256 nextHash;
  while (testnet_GetOrphanNextHash(hash, nextHash)) {
    hash = nextHash;
    CBlock *block = testnet_GetOrphanBlock(hash);
    if (!block || !block->AcceptBlock())
      break;
    testnet_RemoveOrphanBlock(hash);
    STAT_BLOCK_ORPHAN(iface)--;
  }

  ServiceBlockEventUpdate(TESTNET_COIN_IFACE);

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

CBlockIndex *testnet_GetLastCheckpoint()
{
  blkidx_t *blockIndex = GetBlockTable(TESTNET_COIN_IFACE);
  return (TESTNET_Checkpoints::GetLastCheckpoint(*blockIndex));
}

bool testnet_CheckProofOfWork(uint256 hash, unsigned int nBits)
{
  CBigNum bnTarget;
  bnTarget.SetCompact(nBits);

  // Check range
  if (bnTarget <= 0 || bnTarget > TESTNET_bnProofOfWorkLimit)
    return error(SHERR_INVAL, "CheckProofOfWork() : nBits below minimum work");

  // Check proof of work matches claimed amount
  if (hash > bnTarget.getuint256())
    return error(SHERR_INVAL, "CheckProofOfWork() : hash doesn't match nBits");

  return true;
}

/**
 * @note These are checks that are independent of context that can be verified before saving an orphan block.
 */
bool TESTNETBlock::CheckBlock()
{
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);

  if (vtx.empty()) { 
    return (trust(-80, "(testnet) CheckBlock: block submitted with zero transactions"));
  }

  int64_t weight = GetBlockWeight();
  if (weight > MAX_BLOCK_WEIGHT(iface)) {
    return (trust(-80, "(testnet) CheckBlock: block weight (%d) > max (%d)", weight, MAX_BLOCK_WEIGHT(iface)));
  }


  if (vtx.empty() || !vtx[0].IsCoinBase())
    return error(SHERR_INVAL, "CheckBlock() : first tx is not coinbase");

  // Check proof of work matches claimed amount
  if (!testnet_CheckProofOfWork(GetPoWHash(), nBits)) {
    return error(SHERR_INVAL, "CheckBlock() : proof of work failed");
  }

  // Check timestamp
  if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60) {
    return error(SHERR_INVAL, "CheckBlock() : block timestamp too far in the future");
  }

  for (unsigned int i = 1; i < vtx.size(); i++)
    if (vtx[i].IsCoinBase()) {
      return error(SHERR_INVAL, "CheckBlock() : more than one coinbase");
    }

  // Check transactions
  BOOST_FOREACH(CTransaction& tx, vtx)
    if (!tx.CheckTransaction(TESTNET_COIN_IFACE)) {
      return error(SHERR_INVAL, "CheckBlock() : CheckTransaction failed");
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

  blkidx_t *blockIndex = GetBlockTable(TESTNET_COIN_IFACE);
  map<uint256, CBlockIndex*>::iterator miPrev = blockIndex->find(hashPrevBlock);
  if (miPrev != blockIndex->end()) {
    CBlockIndex *pindexPrev = (*miPrev).second;
    if (!core_CheckBlockWitness(iface, (CBlock *)this, pindexPrev))
      return (trust(-10, "(testnet) CheckBlock: invalid witness integrity."));
  }


/* DEBUG: TODO: */
/* addition verification.. 
 * ensure genesis block has higher payout in coinbase
 * ensure genesis block has lower difficulty (nbits)
 * ensure genesis block has earlier block time
 */


  return true;
}

void TESTNETBlock::InvalidChainFound(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);
  char errbuf[1024];

  sprintf(errbuf, "TESTNET: InvalidChainFound: invalid block=%s  height=%d  work=%s  date=%s\n", pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight, pindexNew->bnChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
  unet_log(TESTNET_COIN_IFACE, errbuf);

}

// notify wallets about a new best chain
void static TESTNET_SetBestChain(const CBlockLocator& loc)
{
  CWallet *pwallet = GetWallet(TESTNET_COIN_IFACE);

  pwallet->SetBestChain(loc);
}

bool TESTNETBlock::IsBestChain()
{
  CBlockIndex *pindexBest = GetBestBlockIndex(TESTNET_COIN_IFACE);
  return (pindexBest && GetHash() == pindexBest->GetBlockHash());
}


bool TESTNETBlock::AcceptBlock()
{
  blkidx_t *blockIndex = GetBlockTable(TESTNET_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);
  int mode;

  map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hashPrevBlock);
  if (mi == blockIndex->end()) {
    return error(SHERR_INVAL, "(testnet) AcceptBlock: prev block '%s' not found", hashPrevBlock.GetHex().c_str());
  }
  CBlockIndex* pindexPrev = (*mi).second;

  if (GetBlockTime() > GetAdjustedTime() + TESTNET_MAX_DRIFT_TIME) {
    print();
    return error(SHERR_INVAL, "(testnet) AcceptBlock: block's timestamp too new.");

  }
	if (GetBlockTime() <= pindexPrev->GetMedianTimePast() ||
			(GetBlockTime() < pindexPrev->GetBlockTime())) {
    print();
    return error(SHERR_INVAL, "(testnet) AcceptBlock: block's timestamp too old.");
  }

	/* redundant */
#if 0
	int nHeight = (pindexPrev ? (pindexPrev->nHeight+1) : 0);
	if (iface->BIP34Height != -1 && nHeight >= iface->BIP34Height) {
		/* check for obsolete blocks. */
		if (nVersion < 2)
			return (error(SHERR_INVAL, "(%s) AcceptBlock: rejecting obsolete block (ver: %u) (hash: %s) [BIP34].", iface->name, (unsigned int)nVersion, GetHash().GetHex().c_str()));

		/* verify height inclusion. */
		CScript expect = CScript() << nHeight;
		if (vtx[0].vin[0].scriptSig.size() < expect.size() ||
				!std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
			return error(SHERR_INVAL, "(%s) AcceptBlock: submit block \"%s\" has invalid commit height (next block height is %u).", iface->name, GetHash().GetHex().c_str(), nHeight);
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
      bool fValMatrix = false;
      fValMatrix = BlockAcceptValidateMatrix(iface, vtx[0], fCheck);
      if (fValMatrix && !fCheck)
        return error(SHERR_ILSEQ, "(testnet) AcceptBlock: ValidateMatrix verification failure.");
    } else if (mode == OP_EXT_PAY) {
      bool fHasSprMatrix = BlockAcceptSpringMatrix(iface, vtx[0], fCheck);
      if (fHasSprMatrix && !fCheck)
        return error(SHERR_ILSEQ, "(testnet) AcceptBlock: SpringMatrix verification failure.");
    }
  }

  return (core_AcceptBlock(this, pindexPrev));
}

/* remove me */
CScript TESTNETBlock::GetCoinbaseFlags()
{
  return (TESTNET_COINBASE_FLAGS);
}

static void testnet_UpdatedTransaction(const uint256& hashTx)
{
  CWallet *pwallet = GetWallet(TESTNET_COIN_IFACE);

  pwallet->UpdatedTransaction(hashTx);
}

bool TESTNETBlock::ReadBlock(uint64_t nHeight)
{
int ifaceIndex = TESTNET_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
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

  /* serialize binary data into block */
  {
    CDataStream sBlock(SER_DISK, CLIENT_VERSION);
    sBlock.write((const char *)sBlockData, sBlockLen);
    sBlock >> *this;
  }
  free(sBlockData);

  return (true);
}

bool TESTNETBlock::ReadArchBlock(uint256 hash)
{
  int ifaceIndex = TESTNET_COIN_IFACE;
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

bool TESTNETBlock::IsOrphan()
{
  return (testnet_IsOrphanBlock(GetHash()));
}

bool TESTNETBlock::Truncate()
{
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);
  return (core_Truncate(iface, GetHash()));
}

bool TESTNETBlock::VerifyCheckpoint(int nHeight)
{
  return (TESTNET_Checkpoints::CheckBlock(nHeight, GetHash()));
}
uint64_t TESTNETBlock::GetTotalBlocksEstimate()
{
  return ((uint64_t)TESTNET_Checkpoints::GetTotalBlocksEstimate());
}

bool TESTNETBlock::AddToBlockIndex()
{
  blkidx_t *blockIndex = GetBlockTable(TESTNET_COIN_IFACE);
	CWallet *wallet = GetWallet(TESTNET_COIN_IFACE);
  uint256 hash = GetHash();
  CBlockIndex *pindexNew;
  shtime_t ts;

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

  if (IsWitnessEnabled(GetCoinByIndex(TESTNET_COIN_IFACE), pindexNew->pprev)) {
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

int64_t TESTNETBlock::GetBlockWeight()
{
  int64_t weight = 0;

  weight += ::GetSerializeSize(*this, SER_NETWORK, TESTNET_PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (TESTNET_WITNESS_SCALE_FACTOR - 1);
  weight += ::GetSerializeSize(*this, SER_NETWORK, TESTNET_PROTOCOL_VERSION);

  return (weight);
}



bool TESTNETBlock::SetBestChain(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);
	CWallet *wallet = GetWallet(TESTNET_COIN_IFACE);
  uint256 hash = GetHash();
  shtime_t ts;
  bool ret;

  if (TESTNETBlock::pindexGenesisBlock == NULL && hash == testnet_hashGenesisBlock)
  {
    TESTNETBlock::pindexGenesisBlock = pindexNew;
  } else {
    timing_init("SetBestChain/commit", &ts);
    ret = core_CommitBlock(this, pindexNew); 
    timing_term(TESTNET_COIN_IFACE, "SetBestChain/commit", &ts);
    if (!ret)
      return (false);
  }

  // Update best block in wallet (so we can detect restored wallets)
  bool fIsInitialDownload = IsInitialBlockDownload(TESTNET_COIN_IFACE);
  if (!fIsInitialDownload) {
    const CBlockLocator locator(TESTNET_COIN_IFACE, pindexNew);
    timing_init("SetBestChain/locator", &ts);
    TESTNET_SetBestChain(locator);
    timing_term(TESTNET_COIN_IFACE, "SetBestChain/locator", &ts);

    WriteHashBestChain(iface, hash);
  }

  // New best block
  SetBestBlockIndex(TESTNET_COIN_IFACE, pindexNew);
  wallet->bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();

  return true;
}

bool TESTNETBlock::ConnectBlock(CBlockIndex* pindex)
{
  bool ok = core_ConnectBlock(this, pindex);
  if (ok)
    testnet_RemoveOrphanBlock(pindex->GetBlockHash());
  return (ok);
}

bool TESTNETBlock::DisconnectBlock(CBlockIndex* pindex)
{
  CIface *iface = GetCoinByIndex(TESTNET_COIN_IFACE);
	CWallet *wallet = GetWallet(TESTNET_COIN_IFACE);
  CBlock *block = (CBlock *)this;


  if (pindex->pprev) {
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

  if (!core_DisconnectBlock(pindex, block))
    return (false);

  return (true);
}


bool TESTNETBlock::CreateCheckpoint()
{
  blkidx_t *blockIndex = GetBlockTable(TESTNET_COIN_IFACE);
  const uint256& hBlock = GetHash();
  CBlockIndex *prevIndex;
  CBlockIndex *pindex;

  if (blockIndex->count(hBlock) == 0)
    return (false);
  pindex = (*blockIndex)[hBlock];

  prevIndex = TESTNET_Checkpoints::GetLastCheckpoint(*blockIndex);
  if (prevIndex && pindex->nHeight <= prevIndex->nHeight)
    return (false); /* stale */

  TESTNET_Checkpoints::AddCheckpoint(pindex->nHeight, hBlock);
	return (true);
}




