
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

#include <vector>

#include "shcoind.h"
#include "block.h"
#include "db.h"
#include "script.h"
#include "bloom.h"

#define LN2SQUARED 0.4804530139182014246671025263266649717305529515945455
#define LN2 0.6931471805599453094172321214581765680755001343602552

using namespace std;

static const unsigned char bit_mask[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

CBloomFilter::CBloomFilter(int ifaceIndexIn, unsigned int nElements, double nFPRate, unsigned int nTweakIn, unsigned char nFlagsIn) :
  // The ideal size for a bloom filter with a given number of elements and false positive rate is: - nElements * log(fp rate) / ln(2)^2 We ignore filter parameters which will create a bloom filter larger than the protocol limits
  vData(min((unsigned int)(-1  / LN2SQUARED * nElements * log(nFPRate)), MAX_BLOOM_FILTER_SIZE * 8) / 8),
  // The ideal number of hash functions is filter size * ln(2) / number of elements Again, we ignore filter parameters which will create a bloom filter with more hash functions than the protocol limits See http://en.wikipedia.org/wiki/Bloom_filter for an explanation of these formulas
  isFull(false),
  isEmpty(false),
  nHashFuncs(min((unsigned int)(vData.size() * 8 / nElements * LN2), MAX_HASH_FUNCS)),
  nTweak(nTweakIn),
  nFlags(nFlagsIn)
{
  ifaceIndex = ifaceIndexIn;
}

inline uint32_t ROTL32 ( uint32_t x, int8_t r )
{
    return (x << r) | (x >> (32 - r));
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash)
{
  // The following is MurmurHash3 (x86_32), see http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
  uint32_t h1 = nHashSeed;
  const uint32_t c1 = 0xcc9e2d51;
  const uint32_t c2 = 0x1b873593;

  const int nblocks = vDataToHash.size() / 4;

  //----------
  // body
  const uint32_t * blocks = (const uint32_t *)(&vDataToHash[0] + nblocks*4);

  for(int i = -nblocks; i; i++)
  {
    uint32_t k1 = blocks[i];

    k1 *= c1;
    k1 = ROTL32(k1,15);
    k1 *= c2;

    h1 ^= k1;
    h1 = ROTL32(h1,13);
    h1 = h1*5+0xe6546b64;
  }

  //----------
  // tail
  const uint8_t * tail = (const uint8_t*)(&vDataToHash[0] + nblocks*4);

  uint32_t k1 = 0;

  switch(vDataToHash.size() & 3)
  {
    case 3: k1 ^= tail[2] << 16;
    case 2: k1 ^= tail[1] << 8;
    case 1: k1 ^= tail[0];
            k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
  };

  //----------
  // finalization
  h1 ^= vDataToHash.size();
  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return h1;
}

class CPartialMerkleTree;

inline unsigned int CBloomFilter::Hash(unsigned int nHashNum, const std::vector<unsigned char>& vDataToHash) const
{
  // 0xFBA4C795 chosen as it guarantees a reasonable bit difference between nHashNum values.
  return MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash) % (vData.size() * 8);
}

void CBloomFilter::insert(const vector<unsigned char>& vKey)
{
  if (isFull)
    return;
  for (unsigned int i = 0; i < nHashFuncs; i++)
  {
    unsigned int nIndex = Hash(i, vKey);
    // Sets bit nIndex of vData
    vData[nIndex >> 3] |= bit_mask[7 & nIndex];
  }
  isEmpty = false;
}

void CBloomFilter::insert(const COutPoint& outpoint)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CDataStream stream(SER_NETWORK, PROTOCOL_VERSION(iface));
  stream << outpoint;
  vector<unsigned char> data(stream.begin(), stream.end());
  insert(data);
}

void CBloomFilter::insert(const uint256& hash)
{
  vector<unsigned char> data(hash.begin(), hash.end());
  insert(data);
}

void CBloomFilter::insert(const uint160& hash)
{
  vector<unsigned char> data(hash.begin(), hash.end());
  insert(data);
}

bool CBloomFilter::contains(const vector<unsigned char>& vKey) const
{
  if (isFull)
    return true;
  if (isEmpty)
    return false;
  for (unsigned int i = 0; i < nHashFuncs; i++)
  {
    unsigned int nIndex = Hash(i, vKey);
    // Checks bit nIndex of vData
    if (!(vData[nIndex >> 3] & bit_mask[7 & nIndex]))
      return false;
  }
  return true;
}

bool CBloomFilter::contains(const COutPoint& outpoint) const
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CDataStream stream(SER_NETWORK, PROTOCOL_VERSION(iface));
  stream << outpoint;
  vector<unsigned char> data(stream.begin(), stream.end());
  return contains(data);
}

bool CBloomFilter::contains(const uint256& hash) const
{
  vector<unsigned char> data(hash.begin(), hash.end());
  return contains(data);
}

bool CBloomFilter::contains(const uint160& hash) const
{
  vector<unsigned char> data(hash.begin(), hash.end());
  return contains(data);
}

bool CBloomFilter::IsWithinSizeConstraints() const
{
  return vData.size() <= MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS;
}

bool CBloomFilter::IsRelevant(const CTransaction& tx, const uint256& hash, bool fUpdate)
{
  bool fFound = false;
  // Match if the filter contains the hash of tx
  //  for finding tx when they appear in a block
  if (isFull)
    return true;
  if (isEmpty)
    return false;
  if (contains(hash))
    fFound = true;

  for (unsigned int i = 0; i < tx.vout.size(); i++)
  {
    const CTxOut& txout = tx.vout[i];
    // Match if the filter contains any arbitrary script data element in any scriptPubKey in tx
    // If this matches, also add the specific output that was matched.
    // This means clients don't have to update the filter themselves when a new relevant tx 
    // is discovered in order to find spending transactions, which avoids round-tripping and race conditions.
    CScript::const_iterator pc = txout.scriptPubKey.begin();
    vector<unsigned char> data;
    while (pc < txout.scriptPubKey.end())
    {
      opcodetype opcode;
      if (!txout.scriptPubKey.GetOp(pc, opcode, data))
        break;
      if (data.size() != 0 && contains(data))
      {
        fFound = true;
        if (fUpdate) {
          if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)
            insert(COutPoint(hash, i));
          else if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_P2PUBKEY_ONLY)
          {
            txnouttype type;
            vector<vector<unsigned char> > vSolutions;
            if (Solver(txout.scriptPubKey, type, vSolutions) &&
                (type == TX_PUBKEY || type == TX_MULTISIG))
              insert(COutPoint(hash, i));
          }
        }
        break;
      }
    }
  }

  if (fFound)
    return (true);

  BOOST_FOREACH(const CTxIn& txin, tx.vin)
  {
    // Match if the filter contains an outpoint tx spends
    if (contains(txin.prevout))
      return true;

    // Match if the filter contains any arbitrary script data element in any scriptSig in tx
    CScript::const_iterator pc = txin.scriptSig.begin();
    vector<unsigned char> data;
    while (pc < txin.scriptSig.end())
    {
      opcodetype opcode;
      if (!txin.scriptSig.GetOp(pc, opcode, data))
        break;
      if (data.size() != 0 && contains(data))
        return true;
    }
  }

  return (false);
}

bool CBloomFilter::IsRelevantAndUpdate(const CTransaction& tx, const uint256& hash)
{
#if 0
  bool fFound = false;
  // Match if the filter contains the hash of tx
  //  for finding tx when they appear in a block
  if (isFull)
    return true;
  if (isEmpty)
    return false;
  if (contains(hash))
    fFound = true;

  for (unsigned int i = 0; i < tx.vout.size(); i++)
  {
    const CTxOut& txout = tx.vout[i];
    // Match if the filter contains any arbitrary script data element in any scriptPubKey in tx
    // If this matches, also add the specific output that was matched.
    // This means clients don't have to update the filter themselves when a new relevant tx 
    // is discovered in order to find spending transactions, which avoids round-tripping and race conditions.
    CScript::const_iterator pc = txout.scriptPubKey.begin();
    vector<unsigned char> data;
    while (pc < txout.scriptPubKey.end())
    {
      opcodetype opcode;
      if (!txout.scriptPubKey.GetOp(pc, opcode, data))
        break;
      if (data.size() != 0 && contains(data))
      {
        fFound = true;
        if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)
          insert(COutPoint(hash, i));
        else if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_P2PUBKEY_ONLY)
        {
          txnouttype type;
          vector<vector<unsigned char> > vSolutions;
          if (Solver(txout.scriptPubKey, type, vSolutions) &&
              (type == TX_PUBKEY || type == TX_MULTISIG))
            insert(COutPoint(hash, i));
        }
        break;
      }
    }
  }
#endif

  bool fFound = IsRelevant(tx, hash, true);
  if (IsTest()) {
    Debug("BloomFilter/IsRelevantAndUpdate: TEST: tx hash '%s' %s considered relevant.", hash.GetHex().c_str(), (fFound ? "is" : "is not")); 
    return (true);
  }
  if (fFound)
    return (true); /* winner chicken dinner */

  return false;
}

void CBloomFilter::UpdateEmptyFull()
{
  bool full = true;
  bool empty = true;
  for (unsigned int i = 0; i < vData.size(); i++)
  {
    full &= vData[i] == 0xff;
    empty &= vData[i] == 0;
  }
  isFull = full;
  isEmpty = empty;
}


CMerkleBlock::CMerkleBlock(const CBlock& block, CBloomFilter& filter)
{
  header = block.GetBlockHeader();

  vector<bool> vMatch;
  vector<uint256> vHashes;

  vMatch.reserve(block.vtx.size());
  vHashes.reserve(block.vtx.size());

  for (unsigned int i = 0; i < block.vtx.size(); i++)
  {
    uint256 hash = block.vtx[i].GetHash();
    if (filter.IsRelevantAndUpdate(block.vtx[i], hash))
    {
      vMatch.push_back(true);
      vMatchedTxn.push_back(make_pair(i, hash));
    }
    else
      vMatch.push_back(false);
    vHashes.push_back(hash);
  }

  txn = CPartialMerkleTree(vHashes, vMatch);
}

uint256 CPartialMerkleTree::CalcHash(int height, unsigned int pos, const std::vector<uint256> &vTxid) {
    if (height == 0) {
        // hash at height 0 is the txids themself
        return vTxid[pos];
    } else {
        // calculate left hash
        uint256 left = CalcHash(height-1, pos*2, vTxid), right;
        // calculate right hash if not beyong the end of the array - copy left hash otherwise1
        if (pos*2+1 < CalcTreeWidth(height-1))
            right = CalcHash(height-1, pos*2+1, vTxid);
        else
            right = left;
        // combine subhashes
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}


uint256 CPartialMerkleTree::TraverseAndExtract(int height, unsigned int pos, unsigned int &nBitsUsed, unsigned int &nHashUsed, std::vector<uint256> &vMatch) {
    if (nBitsUsed >= vBits.size()) {
        // overflowed the bits array - failure
        fBad = true;
        return 0;
    }
    bool fParentOfMatch = vBits[nBitsUsed++];
    if (height==0 || !fParentOfMatch) {
        // if at height 0, or nothing interesting below, use stored hash and do not descend
        if (nHashUsed >= vHash.size()) {
            // overflowed the hash array - failure
            fBad = true;
            return 0;
        }
        const uint256 &hash = vHash[nHashUsed++];
        if (height==0 && fParentOfMatch) // in case of height 0, we have a matched txid
            vMatch.push_back(hash);
        return hash;
    } else {
        // otherwise, descend into the subtrees to extract matched txids and hashes
        uint256 left = TraverseAndExtract(height-1, pos*2, nBitsUsed, nHashUsed, vMatch), right;
        if (pos*2+1 < CalcTreeWidth(height-1))
            right = TraverseAndExtract(height-1, pos*2+1, nBitsUsed, nHashUsed, vMatch);
        else
            right = left;
        // and combine them before returning
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}
CPartialMerkleTree::CPartialMerkleTree(const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) : nTransactions(vTxid.size()), fBad(false) {
    // reset state
    vBits.clear();
    vHash.clear();

    // calculate height of tree
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1)
        nHeight++;

    // traverse the partial tree
    TraverseAndBuild(nHeight, 0, vTxid, vMatch);
}

CPartialMerkleTree::CPartialMerkleTree() : nTransactions(0), fBad(true) {}


uint256 CPartialMerkleTree::ExtractMatches(std::vector<uint256> &vMatch)
{

  vMatch.clear();
  // An empty set will not work
  if (nTransactions == 0)
    return 0;
  // check for excessively high numbers of transactions
  if (nTransactions > 16666) //  60 is the lower bound for the size of a serialized CTransaction (16666 * 60 = 1meg)
    return 0;
  // there can never be more hashes provided than one for every txid
  if (vHash.size() > nTransactions)
    return 0;
  // there must be at least one bit per node in the partial tree, and at least one node per hash
  if (vBits.size() < vHash.size())
    return 0;
  // calculate height of tree
  int nHeight = 0;
  while (CalcTreeWidth(nHeight) > 1)
    nHeight++;
  // traverse the partial tree
  unsigned int nBitsUsed = 0, nHashUsed = 0;
  uint256 hashMerkleRoot = TraverseAndExtract(nHeight, 0, nBitsUsed, nHashUsed, vMatch);
  // verify that no problems occured during the tree traversal
  if (fBad)
    return 0;
  // verify that all bits were consumed (except for the padding caused by serializing it as a byte sequence)
  if ((nBitsUsed+7)/8 != (vBits.size()+7)/8)
    return 0;
  // verify that all hashes were consumed
  if (nHashUsed != vHash.size())
    return 0;
  return hashMerkleRoot;
}


void CPartialMerkleTree::TraverseAndBuild(int height, unsigned int pos, const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) 
{
  // determine whether this node is the parent of at least one matched txid
  bool fParentOfMatch = false;
  for (unsigned int p = pos << height; p < (pos+1) << height && p < nTransactions; p++)
    fParentOfMatch |= vMatch[p];
  // store as flag bit
  vBits.push_back(fParentOfMatch);
  if (height==0 || !fParentOfMatch) {
    // if at height 0, or nothing interesting below, store hash and stop
    vHash.push_back(CalcHash(height, pos, vTxid));
  } else {
    // otherwise, don't store any hash, but descend into the subtrees
    TraverseAndBuild(height-1, pos*2, vTxid, vMatch);
    if (pos*2+1 < CalcTreeWidth(height-1))
      TraverseAndBuild(height-1, pos*2+1, vTxid, vMatch);
  }
}

std::string CBloomFilter::ToString()
{
  unsigned char *pn;
  char *str;
  int i;

  pn = (unsigned char *)vData.data();
  if (!pn)
    return (std::string());

  str = (char *)calloc(vData.size() * 2 + 1, sizeof(char));
  if (!str)
    return (std::string());

  for (int i = 0; i < vData.size(); i++)
    sprintf(str + i*2, "%02x", pn[vData.size() - i - 1]);

  string ret_str(str);
  free(str);
  return (ret_str);
}



