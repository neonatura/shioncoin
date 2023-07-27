
/*
 * @copyright
 *
 *  Copyright 2016 Brian Burrell
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

#ifndef __SERVER__CHAIN_H__
#define __SERVER__CHAIN_H__

#ifdef __cplusplus
extern "C" {
#endif

#define BCOP_NONE 0
#define BCOP_IMPORT 1
#define BCOP_EXPORT 2
#define BCOP_DOWNLOAD 3
#define BCOP_VALIDATE 4
#define BCOP_MINER 5

#include <stdio.h>

typedef struct ChainOp
{
  char path[PATH_MAX+1];
  int mode;
  int ifaceIndex;
  int pos;
  unsigned int max;
  unsigned int total;
} ChainOp;

enum BlockFilterState {
	BLOCKFILTER_NONE,
	BLOCKFILTER_SCAN,
	BLOCKFILTER_PROCESS,
	BLOCKFILTER_SYNC
};

class CBlockFilter
{

	protected:
		int ifaceIndex;
		string label;

		/* result */
		shjson_t *stream;
		vector<CBlockIndex> vBlock;
		vector<uint256> vTx;

  public:
		/* config */
		time_t nMinTime;

		int blockStart;

		int blockEnd;

		/* working vars */
		int blockTotal;

		int txTotal;

		CBlockIndex *blockIndex;

		BlockFilterState state;

		CBlockFilter(int ifaceIndexIn, string labelIn)
		{
			SetNull();
			this->ifaceIndex = ifaceIndexIn;
			this->label = labelIn;
		}

		void SetNull();

		string GetLabel() { return label; }

		void SetMinimumTime(time_t minTime) { nMinTime = minTime; }

		time_t GetMinimumTime() { return (nMinTime); }

		int GetBlockTotal() { return (blockTotal); }

		int GetTxTotal() { return (txTotal); }

		CBlockIndex *GetBlockIndex() { return (blockIndex); }

		uint256 GetBlockHash() { return (blockIndex ? blockIndex->GetBlockHash() : 0); }

		int64 GetBlockHeight() { return (blockIndex ? blockIndex->nHeight : 0); }

		time_t GetBlockTime() { return (blockIndex ? (time_t)blockIndex->GetBlockTime() : 0); }

		void filter();

		void filterAll();

		void initialize();

		void terminate();

		bool IsFinished();

		bool IsRunning();

		void setMinTime(time_t nMinTime);

		CIface *GetIface();

		int GetIfaceIndex();

		CWallet *GetWallet();

		virtual bool BlockIndexFilter()
		{
			return (false);
		}

		virtual bool BlockFilter(CBlock *block)
		{
			return (false);
		}

		virtual bool TransactionFilter(CBlock *block, CTransaction *tx)
		{
			return (false);
		}

		virtual void BlockTask(CBlock *block)
		{
		}

		virtual void TransactionTask(CBlock *block, CTransaction *tx)
		{
		}

};

class CBlockValidateFilter : public CBlockFilter
{

	public:

		CBlockValidateFilter(int ifaceIndexIn) : CBlockFilter(ifaceIndexIn, "block-validate")
		{
			SetNull();
		}

		void SetNull();

		bool BlockFilter(CBlock *block);

		bool TransactionFilter(CBlock *block, CTransaction *tx);

		void BlockTask(CBlock *block);

		void TransactionTask(CBlock *block, CTransaction *tx);

};

#if 0
class CBlockDownloadFilter : public CBlockFilter
{

	const string FILTER_NAME = "block-download";

	public:

		CNode *pNode;

		CBlockDownloadFilter(int ifaceIndex) : CBlockFilter(ifaceIndex, FILTER_NAME)
		{
			SetNull();
		}

		void SetNull();

		bool BlockIndexFilter();

		bool BlockFilter(CBlock *block);

		bool TransactionFilter(CBlock *block, CTransaction *tx);

		void BlockTask(CBlock *block);

		void TransactionTask(CBlock *block, CTransaction *tx);

		void SetNode(CNode *pNodeIn) {
			pNode = pNodeIn;
		}

		CNode *GetNode() {
			return (pNode);
		}

};
#endif

class CWalletUpdateFilter : public CBlockFilter
{

	public:
		vector<CTxDestination> vDestination;

		CWalletUpdateFilter(int ifaceIndexIn, time_t nMinTime = 0) : CBlockFilter(ifaceIndexIn, "wallet-update")
		{
			SetNull();
			SetMinimumTime(nMinTime);
		}

		CWalletUpdateFilter(int ifaceIndexIn, vector<CTxDestination>& vDestinationIn, time_t nMinTime = 0) : CBlockFilter(ifaceIndexIn, "wallet-update")
		{
			SetNull();
			vDestination.insert(vDestination.end(), vDestinationIn.begin(), vDestinationIn.end());
			SetMinimumTime(nMinTime);
		}

		void SetNull();

		bool TransactionFilter(CBlock *block, CTransaction *tx);

		bool AddressFilter(CScript& script);

		void BlockTask(CBlock *block) { }

		void TransactionTask(CBlock *block, CTransaction *tx);

};


class CWalletValidateFilter : public CBlockFilter
{

	public:

		CWalletValidateFilter(int ifaceIndexIn) : CBlockFilter(ifaceIndexIn, "wallet-validate")
		{
			SetNull();
		}

		void SetNull();

		bool BlockIndexFilter();

		bool TransactionFilter(CBlock *block, CTransaction *tx);

		bool AddressFilter(CScript& script);

		void BlockTask(CBlock *block) { }

		void TransactionTask(CBlock *block, CTransaction *tx);

};


int InitChainImport(int ifaceIndex, const char *path, int offset);

int InitChainExport(int ifaceIndex, const char *path, int min, int max);

void event_cycle_chain(int ifaceIndex);

void ServiceWalletEventUpdate(CWallet *wallet, const CBlock *pblock);

void InitServiceValidateEvent(CWallet *wallet, uint64_t nHeight);

int InitServiceBlockEvent(int ifaceIndex, uint64_t nHeight);

void UpdateServiceBlockEvent(int ifaceIndex);

void ServiceBlockEventUpdate(int ifaceIndex);

void ResetServiceWalletEvent(CWallet *wallet);

void ResetServiceValidateEvent(CWallet *wallet);

int InitServiceMinerEvent(int ifaceIndex, uint64_t nHeight);

bool UpdateServiceMinerEvent(int ifaceIndex);

void ProcessBlockAvailability(int ifaceIndex, CNode *pfrom);

void UpdateBlockAvailability(int ifaceIndex, CNode *pfrom, const uint256& hash);

double GetDifficulty(unsigned int nBits, unsigned int nVersion);

bool HasAlgoConsensus(CIface *iface, CBlockIndex *pindexLast);

void InitChainFilter(CBlockFilter *filter);

#ifdef __cplusplus
}
#endif


void InitServiceWalletEvent(int ifaceIndex, CBlockIndex *pindex);

void InitServiceWalletEvent(int ifaceIndex, uint64_t nHeight);


#endif /* ndef __SERVER__CHAIN_H__ */
