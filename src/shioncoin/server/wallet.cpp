
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

#include "shcoind.h"
#include "wallet.h"
#include "wallettx.h"
#include "walletdb.h"
#include "crypter.h"
#include "base58.h"
#include "chain.h"
#include "txsignature.h"
#include "txmempool.h"
#include "txfeerate.h"
#include "txcreator.h"
#include "coinaddr.h"
#include "account.h"

using namespace std;

CWallet* pwalletMaster[MAX_COIN_IFACE];

const string NULL_ACCOUNT = "*";

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static const unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);
/** Use GetMedianTimePast() instead of nTime for end point timestamp. */
static const unsigned int LOCKTIME_MEDIAN_TIME_PAST = (1 << 1);

static const unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS = 
		LOCKTIME_VERIFY_SEQUENCE |
		LOCKTIME_MEDIAN_TIME_PAST;

static const char *ExtendedDefaultKeyTag = "ext-default";

CWallet *GetWallet(int iface_idx)
{
#ifndef TEST_SHCOIND
	if (iface_idx == 0)
		return (NULL);
#endif

	if (iface_idx < 0 || iface_idx >= MAX_COIN_IFACE)
		return (NULL);

	return (pwalletMaster[iface_idx]); 
}

CWallet *GetWallet(CIface *iface)
{
	return (GetWallet(GetCoinIndex(iface)));
}

void SetWallet(int iface_idx, CWallet *wallet)
{
#ifndef TEST_SHCOIND
	if (iface_idx == 0)
		return;
#endif

	if (iface_idx < 0 || iface_idx >= MAX_COIN_IFACE)
		return;

	pwalletMaster[iface_idx] = wallet;
}

void SetWallet(CIface *iface, CWallet *wallet)
{
	return (SetWallet(GetCoinIndex(iface), wallet));
}

struct CompareValueOnly
{
	bool operator()(const pair<int64, pair<const CWalletTx*, unsigned int> >& t1,
			const pair<int64, pair<const CWalletTx*, unsigned int> >& t2) const
	{
		return t1.first < t2.first;
	}
};

void CWallet::GenerateNewECKey(ECKey& key, bool fCompressed, int nFlag)
{
	LOCK(cs_wallet);
	key.MakeNewKey(fCompressed);
	key.nFlag |= nFlag;
}

void CWallet::GenerateNewDIKey(DIKey& key, int nFlag)
{
	LOCK(cs_wallet);
	key.MakeNewKey();
	key.nFlag |= nFlag;
}

bool CWallet::AddKey(ECKey& key)
{

	if (!CBasicKeyStore::AddKey(key))
		return (error(SHERR_INVAL, "CWallet.AddKey: error adding key to crypto key-store."));

	{
		bool ret = false;
		{
			LOCK(cs_wallet);
			CWalletDB db(strWalletFile);

			const CPubKey& pubkey = key.GetPubKey();
			ret = db.WriteKey(key, pubkey);

			db.Close();
		}
		if (!ret)
			return (error(SHERR_INVAL, "CWallet.AddKey: error writing key to wallet."));
	}

	return true;
}

bool CWallet::AddKey(DIKey& key)
{

	if (!CBasicKeyStore::AddKey(key))
		return (error(SHERR_INVAL, "CWallet.AddKey: error adding key to crypto key-store."));

	{
		bool ret = false;
		{
			LOCK(cs_wallet);
			CWalletDB db(strWalletFile);

			const CPubKey& pubkey = key.GetPubKey();
			ret = db.WriteKey(key, pubkey);

			db.Close();
		}
		if (!ret)
			return (error(SHERR_INVAL, "CWallet.AddKey: error writing key to wallet."));
	}

	return true;
}

bool CWallet::AddCScript(const CScript& redeemScript)
{

	if (!CBasicKeyStore::AddCScript(redeemScript))
		return false;

	uint160 sid = Hash160(redeemScript);
	bool ok;

	{
		LOCK(cs_wallet);

		CWalletDB db(strWalletFile);
		ok = db.WriteCScript(sid, redeemScript);
		db.Close();
	}

	return (ok);
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
	LOCK(cs_wallet);

	CWalletDB walletdb(strWalletFile);
	walletdb.WriteBestBlock(loc);
	walletdb.Close();
}

void CWallet::MarkDirty()
{
	{
		LOCK(cs_wallet);
		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
			item.second.MarkDirty();
	}
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn)
{
	return (AddTx(wtxIn));
}

/* Add a transaction to the wallet, or update it. pblock is optional, but should be provided if the transaction is known to be in a block. If fUpdate is true, existing transactions will be updated. */
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fFindBlock)
{
	uint256 hash = tx.GetHash();
	{
		LOCK(cs_wallet);
		bool fExisted = (mapWallet.count(hash) || HasArchTx(hash));
		if (fExisted && !fUpdate) return false;
		if (fExisted || IsFromMe(tx) || IsMine(tx)) {
			CWalletTx wtx(this,tx);
			// Get merkle branch if transaction was found in a block
			if (pblock) {
				wtx.SetMerkleBranch(pblock);
			}
			return AddToWallet(wtx);
		}
		else {
			WalletUpdateSpent(tx);
		}
	}
	return false;
}

bool CWallet::EraseFromWallet(uint256 hash)
{
	RemoveTx(hash);
	return true;
}


bool CWallet::IsMine(const CTxIn &txin)
{
	{
		LOCK(cs_wallet);

		if (HasTx(txin.prevout.hash)) {
			const CWalletTx& prev = GetTx(txin.prevout.hash);
			if (txin.prevout.n < prev.vout.size()) {
				if (IsMine(prev.vout[txin.prevout.n]))
					return true;
			}
		}
	}
	return false;
}

int64 CWallet::GetDebit(const CTxIn &txin)
{
	{
		LOCK(cs_wallet);

		if (HasTx(txin.prevout.hash)) {
			const CWalletTx& prev = GetTx(txin.prevout.hash);
			if (txin.prevout.n < prev.vout.size()) {
				if (IsMine(prev.vout[txin.prevout.n]))
					return prev.vout[txin.prevout.n].nValue;
			}
		}
	}
	return 0;
}

bool CWallet::IsChange(const CTxOut& txout) const
{
	CTxDestination address;

	if (ExtractDestination(txout.scriptPubKey, address) && ::IsMine(*this, address))
	{
		LOCK(cs_wallet);
		if (!mapAddressBook.count(address))
			return true;
	}
	return false;
}

int64 CWalletTx::GetTxTime() const
{
	return nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
	// Returns -1 if it wasn't being tracked
	int nRequests = -1;
	{
		LOCK(pwallet->cs_wallet);
		if (IsCoinBase())
		{
			// Generated block
			if (hashBlock != 0)
			{
				map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
				if (mi != pwallet->mapRequestCount.end())
					nRequests = (*mi).second;
			}
		}
		else
		{
			// Did anyone request this transaction?
			map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
			if (mi != pwallet->mapRequestCount.end())
			{
				nRequests = (*mi).second;

				// How about the block it's in?
				if (nRequests == 0 && hashBlock != 0)
				{
					map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
					if (mi != pwallet->mapRequestCount.end())
						nRequests = (*mi).second;
					else
						nRequests = 1; // If it's in someone else's block it must have got out
				}
			}
		}
	}
	return nRequests;
}

void CWalletTx::GetAmounts(list<pair<CTxDestination, int64> >& listReceived, list<pair<CTxDestination, int64> >& listSent, int64& nFee, string& strSentAccount) const
{
	int ifaceIndex = pwallet->ifaceIndex;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	//  int64 minValue = (int64)MIN_INPUT_VALUE(iface);

	nFee = 0;
	listReceived.clear();
	listSent.clear();
	strSentAccount = strFromAccount;

	int64 nDebit = 0;
	if (!IsCoinBase()) {
		nDebit = GetDebit();

		// Compute fee:
		if (nDebit > 0) // debit>0 means we signed/sent this transaction
		{
			int64 nValueOut = 0;
			BOOST_FOREACH(const CTxOut& txout, vout) {
				nValueOut += txout.nValue;
			}

			nFee = MAX(0.0, nDebit - nValueOut);
		}
	}

	// Sent/received.
	int idx = -1;
	BOOST_FOREACH(const CTxOut& txout, vout)
	{
		int64 nValue = txout.nValue;

		idx++;
		if (nValue < 0) {
			Debug("GetAmounts: invalid transaction '%s' coin value for output (#%d) [coin value (%f)].", GetHash().GetHex().c_str(), idx, ((double)nValue / (double)COIN));
			continue;
		}

		CTxDestination address;
		if (!ExtractDestination(txout.scriptPubKey, address)) {
			error(SHERR_INVAL,
					"CWalletTx::GetAmounts: Unknown transaction type found, txid %s: %s\n",
					this->GetHash().ToString().c_str(), txout.scriptPubKey.ToString().c_str());
		}

		if (nDebit > 0)
			listSent.push_back(make_pair(address, nValue));

		if (pwallet->IsMine(txout))
			listReceived.push_back(make_pair(address, nValue));
	}

}

void CWalletTx::GetAmounts(int ifaceIndex, int64& nGeneratedImmature, int64& nGeneratedMature) const
{

	nGeneratedImmature = nGeneratedMature = 0;

	if (!IsCoinBase())
		return;

	if (GetBlocksToMaturity(ifaceIndex) > 0) {
		nGeneratedImmature = pwallet->GetCredit(*this);
	} else {
		/* base reward */
		nGeneratedMature = GetCredit();

		if (ifaceIndex == TEST_COIN_IFACE ||
				ifaceIndex == SHC_COIN_IFACE) {
			if (vout.size() > 1) {
				int64 nFee = 0;
				/* do not count >0 coinbase outputs as part of miner 'reward' */
				for (int idx = 1; idx < vout.size(); idx++) {
					const CTxOut& txout = vout[idx];
					if (pwallet->IsMine(txout)) {
						CTxDestination address;
						if (ExtractDestination(txout.scriptPubKey, address)) {
							nFee += txout.nValue;
							//listReceived.push_back(make_pair(address, txout.nValue));
						}
					}
				}
				nGeneratedMature -= nFee;
			}
		} else if (ifaceIndex == EMC2_COIN_IFACE) {
			if (vout.size() > 0) {
				/* subtract donation output */
				nGeneratedMature -= vout[0].nValue;
			}
		}
	}

}

int CWallet::ScanForWalletTransaction(const uint256& hashTx)
{
	CTransaction tx;

	if (!tx.ReadTx(ifaceIndex, hashTx)) {
		error(SHERR_INVAL, "ScanForWalletTransaction: unknown tx '%s'\n", hashTx.GetHex().c_str());
		return (0);
	}

	//    tx.ReadFromDisk(COutPoint(hashTx, 0));
	if (AddToWalletIfInvolvingMe(tx, NULL, true, true))
		return 1;
	return 0;
}

int64 CWallet::GetBalance() const
{
	int64 nTotal = 0;
	{
		LOCK(cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx* pcoin = &(*it).second;
			if (!pcoin->IsFinal(ifaceIndex)) {
				continue;
			}
			if (!pcoin->IsConfirmed()) {
				continue;
			}
			nTotal += pcoin->GetAvailableCredit();
		}
	}

	return nTotal;
}

int64 CWallet::GetUnconfirmedBalance() const
{
	int64 nTotal = 0;
	{
		LOCK(cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx* pcoin = &(*it).second;
			if (!pcoin->IsFinal(ifaceIndex) || !pcoin->IsConfirmed())
				nTotal += pcoin->GetAvailableCredit();
		}
	}
	return nTotal;
}

int64 CWallet::GetImmatureBalance()
{
	int64 nTotal = 0;
	{
		LOCK(cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx& pcoin = (*it).second;
			if (pcoin.IsCoinBase() && pcoin.GetBlocksToMaturity(ifaceIndex) > 0 && pcoin.GetDepthInMainChain(ifaceIndex) >= 2)
				nTotal += GetCredit(pcoin);
		}
	}
	return nTotal;
}

/* populate vCoins with vector of spendable COutputs. */
void CWallet::AvailableCoins(vector<COutput>& vCoins, bool fOnlyConfirmed)
{
	vCoins.clear();

	{
		LOCK(cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx* pcoin = &(*it).second;

			if (!pcoin->IsFinal(ifaceIndex))
				continue;

			if (fOnlyConfirmed && !pcoin->IsConfirmed())
				continue;

			if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity(ifaceIndex) > 0)
				continue;

			// If output is less than minimum value, then don't include transaction.
			// This is to help deal with dust spam clogging up create transactions.
			for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
				opcodetype opcode;
				const CScript& script = pcoin->vout[i].scriptPubKey;
				CScript::const_iterator pc = script.begin();
				if (script.GetOp(pc, opcode) &&
						opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
					continue; /* not avail */
				}

				CIface *iface = GetCoinByIndex(ifaceIndex);
				int64 nMinimumInputValue = MIN_INPUT_VALUE(iface);
				if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) && pcoin->vout[i].nValue >= nMinimumInputValue)
					vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(ifaceIndex)));
			}
		}
	}
}

void CWallet::AvailableAccountCoins(string strAccount, vector<COutput>& vCoins, bool fOnlyConfirmed, uint160 hColor) const
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CTxMemPool *pool = GetTxMemPool(iface);
	int64 nMinValue = MIN_INPUT_VALUE(iface);
	vector<CTxDestination> vDest;

	vCoins.clear();

	{
		LOCK(cs_wallet);

		BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, mapAddressBook) {
			const string& account = item.second;
			if (account != strAccount)
				continue;
			//    const CCoinAddr& address = CCoinAddr(wallet->ifaceIndex, item.first);
			vDest.push_back(item.first);
		}
	}

	if (strAccount == "") {
		/* include coinbase (non-mapped) pub-keys */
		std::set<CKeyID> keys;

		GetECKeys(keys);
		BOOST_FOREACH(const CKeyID& key, keys) {
			if (mapAddressBook.count(key) == 0) { /* loner */
				GetAddrDestination(ifaceIndex, key, vDest, ACCADDRF_WITNESS); 
			}
		}

		GetDIKeys(keys);
		BOOST_FOREACH(const CKeyID& key, keys) {
			if (mapAddressBook.count(key) == 0) { /* loner */
				GetAddrDestination(ifaceIndex, key, vDest, ACCADDRF_WITNESS | ACCADDRF_DILITHIUM); 
			}
		}
	}

	{
		LOCK(cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx* pcoin = &(*it).second;

			if (hColor != 0 && pcoin->GetColor() != hColor)
				continue;

			if (!CheckFinalTx(iface, *pcoin, NULL))
				continue; /* not finalized */
			if (pcoin->GetVersion() >= 2) {
				/* tx v2 lock/sequence test */
				if (!CheckSequenceLocks(iface, *pcoin, STANDARD_LOCKTIME_VERIFY_FLAGS))
					continue;
			}

			if (fOnlyConfirmed) {
				if (!pcoin->IsConfirmed()) {
					continue;
				}
				int mat;
				if (pcoin->IsCoinBase() && 
						(mat=pcoin->GetBlocksToMaturity(ifaceIndex)) > 0) {
					continue;
				}
			}

			uint256 pcoinHash = pcoin->GetHash();
			for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
				/* If output is less than minimum value, then don't include transaction. */
				if (pcoin->vout[i].nValue < nMinValue)
					continue;

				/* check whether this output has already been used */
				if (pcoin->IsSpent(i))
					continue;

				/* check mempool for conflict */ 
				if (pool->IsInputTx(pcoinHash, i))
					continue;

				/* filter via account */
				CTxDestination dest;
				if (!ExtractDestination(pcoin->vout[i].scriptPubKey, dest)) {
					continue;
				}

				if ( std::find(vDest.begin(), vDest.end(), dest) != vDest.end() ) {
					vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(ifaceIndex)));
				} 
			}
		}
	}
}

static void ApproximateBestSubset(vector<pair<int64, pair<const CWalletTx*,unsigned int> > >vValue, int64 nTotalLower, int64 nTargetValue,
		vector<char>& vfBest, int64& nBest, int iterations = 1000)
{
	vector<char> vfIncluded;

	vfBest.assign(vValue.size(), true);
	nBest = nTotalLower;

	for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
	{
		vfIncluded.assign(vValue.size(), false);
		int64 nTotal = 0;
		bool fReachedTarget = false;
		for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
		{
			for (unsigned int i = 0; i < vValue.size(); i++)
			{
				if (nPass == 0 ? rand() % 2 : !vfIncluded[i])
				{
					nTotal += vValue[i].first;
					vfIncluded[i] = true;
					if (nTotal >= nTargetValue)
					{
						fReachedTarget = true;
						if (nTotal < nBest)
						{
							nBest = nTotal;
							vfBest = vfIncluded;
						}
						nTotal -= vValue[i].first;
						vfIncluded[i] = false;
					}
				}
			}
		}
	}
}

bool CWallet::SelectCoinsMinConf(int64 nTargetValue, int nConfMine, int nConfTheirs, vector<COutput> vCoins, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const
{
	setCoinsRet.clear();
	nValueRet = 0;

	// List of values less than target
	pair<int64, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
	coinLowestLarger.first = std::numeric_limits<int64>::max();
	coinLowestLarger.second.first = NULL;
	vector<pair<int64, pair<const CWalletTx*,unsigned int> > > vValue;
	int64 nTotalLower = 0;

	random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

	BOOST_FOREACH(COutput output, vCoins)
	{
		const CWalletTx *pcoin = output.tx;

		if (output.nDepth < (pcoin->IsFromMe() ? nConfMine : nConfTheirs))
			continue;

		int i = output.i;
		int64 n = pcoin->vout[i].nValue;

		pair<int64,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

		if (n == nTargetValue)
		{
			setCoinsRet.insert(coin.second);
			nValueRet += coin.first;
			return true;
		}
		else if (n < nTargetValue + CENT)
		{
			vValue.push_back(coin);
			nTotalLower += n;
		}
		else if (n < coinLowestLarger.first)
		{
			coinLowestLarger = coin;
		}
	}

	if (nTotalLower == nTargetValue)
	{
		for (unsigned int i = 0; i < vValue.size(); ++i)
		{
			setCoinsRet.insert(vValue[i].second);
			nValueRet += vValue[i].first;
		}
		return true;
	}

	if (nTotalLower < nTargetValue)
	{
		if (coinLowestLarger.second.first == NULL)
			return false;
		setCoinsRet.insert(coinLowestLarger.second);
		nValueRet += coinLowestLarger.first;
		return true;
	}

	// Solve subset sum by stochastic approximation
	sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
	vector<char> vfBest;
	int64 nBest;

	ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
	if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
		ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

	// If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
	//                                   or the next bigger coin is closer), return the bigger coin
	if (coinLowestLarger.second.first &&
			((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger.first <= nBest))
	{
		setCoinsRet.insert(coinLowestLarger.second);
		nValueRet += coinLowestLarger.first;
	}
	else {
		for (unsigned int i = 0; i < vValue.size(); i++)
			if (vfBest[i])
			{
				setCoinsRet.insert(vValue[i].second);
				nValueRet += vValue[i].first;
			}

	}

	return true;
}

bool CWallet::SelectCoins(int64 nTargetValue, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet)
{
	vector<COutput> vCoins;
	AvailableCoins(vCoins);

	return (SelectCoinsMinConf(nTargetValue, 1, 6, vCoins, setCoinsRet, nValueRet) ||
			SelectCoinsMinConf(nTargetValue, 1, 1, vCoins, setCoinsRet, nValueRet) ||
			SelectCoinsMinConf(nTargetValue, 0, 1, vCoins, setCoinsRet, nValueRet));
}

bool SelectCoins_Avg(int64 nTargetValue, vector<COutput>& vCoins, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet)
{
	setCoinsRet.clear();
	nValueRet = 0;
	vector<pair<int64, pair<const CWalletTx*,unsigned int> > > vValue;
	int64 nTotalLower = 0;

	random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

	int low_cnt = 0;
	int64 low_tot = 0;
	int64 max_val = 0;
	int64 avg_val = nTargetValue;
	BOOST_FOREACH(COutput output, vCoins) {
		const CWalletTx *pcoin = output.tx;
		int i = output.i;
		int64 n = pcoin->vout[i].nValue;

		if (n == nTargetValue)
		{
			/* found an exact value */
			setCoinsRet.insert(make_pair(pcoin, i));
			nValueRet += n;
			return true;
		}

		if (n > nTargetValue) {
			if (max_val == 0)
				max_val = n;
			else
				max_val = MIN(max_val, n);
		} else {
			low_tot += n;
			low_cnt++;
		}
	}
	if (low_cnt)
		avg_val = (low_tot / low_cnt);
	avg_val = MIN(avg_val, nTargetValue / 4);

	int64 nTotalValue = 0;

	BOOST_FOREACH(COutput output, vCoins) {
		const CWalletTx *pcoin = output.tx;
		int i = output.i;
		int64 n = pcoin->vout[i].nValue;

		if (max_val != 0 && n > max_val) {
			continue; /* beyond what is needed */
		}

		if ((nTotalValue - CENT) > nTargetValue && n < avg_val) {
			continue; /* skip relative lower values */ 
		}

		nTotalValue += n;

		pair<int64,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));
		vValue.push_back(coin);
	}

	sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());

	nValueRet = 0;
	int idx;
	for (idx = 0; idx < vValue.size(); idx++) {
		int64 nCredit = vValue[idx].first;
		//    pair<const CWalletTx*,unsigned int>& val = vValue[idx].second;
		//    const CWalletTx *wtx = val.first;
		//    int nOut = val.second;


		nTotalValue -= nCredit;
		if (nCredit > avg_val && 
				nTotalValue > (nTargetValue - nValueRet)) {
			continue; /* remainder will be sufficient */
		}

		setCoinsRet.insert(vValue[idx].second);
		nValueRet += nCredit;

		if (nValueRet >= nTargetValue)
			break;
	}

	/* insufficient funds */
	if (nValueRet < nTargetValue)
		return (false); 

	return true;
}

bool CWallet::SelectAccountCoins(string strAccount, int64 nTargetValue, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet, uint160 hColor) const
{
	vector<COutput> vCoins;
	AvailableAccountCoins(strAccount, vCoins);

	return (SelectCoins_Avg(nTargetValue, vCoins, setCoinsRet, nValueRet));  
}

#if 0
string CWallet::SendMoneyToDestination(string strAccount, const CTxDestination& address, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
	// Check amount
	if (nValue <= 0)
		return _("Invalid amount");
	if (nValue + nTransactionFee > GetBalance())
		return _("Insufficient funds");

	// Parse Bitcoin address
	CScript scriptPubKey;
	scriptPubKey.SetDestination(address);

	return SendMoney(strAccount, scriptPubKey, nValue, wtxNew, fAskFee);
}
string CWallet::SendMoney(string strFromAccount, CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
	int64 nFeeRequired;

	string strError;
	int nMinDepth = 1;
	int64 nBalance = GetAccountBalance(ifaceIndex, strFromAccount, nMinDepth);

	wtxNew.vin.clear();
	wtxNew.vout.clear();

	CTxCreator wtx(this, wtxNew);
	wtx.SetAccount(strFromAccount);
	wtx.AddOutput(scriptPubKey, nValue);
	if (fAskFee) {
		if (!wtx.Generate()) {
			error(SHERR_INVAL, "SendMoney: error commiting tx (fAskFee=true): %s", wtx.GetError().c_str());
			return (wtx.GetError());
		}
		int64 nFeeRequired = wtx.CalculateFee();
		if ((nValue + nFeeRequired) > nBalance) {
			string strError;
			strError = strprintf(_("Account \"%s\" has insufficient funds to initiate transaction [fee %f, balance %f]."), strFromAccount.c_str(), ((double)nFeeRequired/(double)COIN), ((double)nBalance/(double)COIN));
			return (strError);
		}
		return ("ABORTED");
	}
	if (!wtx.Send()) {
		error(SHERR_INVAL, "SendMoney: error commiting tx: %s", wtx.GetError().c_str());
		return (wtx.GetError());
	}

	wtxNew = wtx;

	return "";
}
string CWallet::SendMoney(string strFromAccount, const CTxDestination& address, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
	// Check amount
	if (nValue <= 0)
		return _("Invalid amount");
	if (nValue + nTransactionFee > GetBalance())
		return _("Insufficient funds");

	// Parse Bitcoin address
	CScript scriptPubKey;
	scriptPubKey.SetDestination(address);

	return SendMoney(strFromAccount, scriptPubKey, nValue, wtxNew, fAskFee);
}
#endif




int CWallet::LoadWallet(bool& fFirstRunRet)
{
	int nLoadWalletRet;

	fFirstRunRet = false;

	{
		LOCK(cs_wallet);

		CWalletDB db(strWalletFile,"cr+");
		nLoadWalletRet = db.LoadWallet(this);
		db.Close();
	}

	if (nLoadWalletRet != DB_LOAD_OK)
		return nLoadWalletRet;

	fFirstRunRet = !vchDefaultKey.IsValid();

	return DB_LOAD_OK;
}


bool CWallet::SetAddressBookName(const CTxDestination& address, const string& strName)
{
	bool ok;

	{
		LOCK(cs_wallet);

		std::map<CTxDestination, std::string>::iterator mi = mapAddressBook.find(address);
		mapAddressBook[address] = strName;
	}

	{
		LOCK(cs_wallet);

		string strAddr = CCoinAddr(ifaceIndex, address).ToString();

		CWalletDB db(strWalletFile);
		ok = db.WriteName(strAddr, strName);
		db.Close();
	}

	return (ok);
}

bool CWallet::DelAddressBookName(const CTxDestination& address)
{
	bool ok;

	{
		LOCK(cs_wallet);

		mapAddressBook.erase(address);
		CWalletDB db(strWalletFile);
		ok = db.EraseName(CCoinAddr(ifaceIndex, address).ToString());
		db.Close();
	}

	return (ok);
}

void CWallet::PrintWallet(const CBlock& block)
{
}

bool CWallet::GetTransaction(const uint256 &hashTx, CWalletTx& wtx)
{
	if (!HasTx(hashTx))
		return (false);

	wtx = GetTx(hashTx);
	return (true);
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
	bool ok;

	{
		LOCK(cs_wallet);

		CWalletDB db(strWalletFile);
		ok = db.WriteDefaultKey(vchPubKey);
		db.Close();
	}

	if (ok)
		vchDefaultKey = vchPubKey;

	return (ok);
}

bool GetWalletFile(CWallet* pwallet, string &strWalletFileOut)
{
	{
		LOCK(pwallet->cs_wallet);

		strWalletFileOut = pwallet->strWalletFile;
	}

	return true;
}

void CWallet::UpdatedTransaction(const uint256 &hashTx)
{
}

int64 GetTxFee(int ifaceIndex, CTransaction tx)
{
	CWallet *wallet;

	wallet = GetWallet(ifaceIndex);
	if (!wallet)
		return (0);

	return (wallet->GetTxFee(tx));
}

int64 GetAccountBalance(int ifaceIndex, const string& strAccount, int nMinDepth)
{
	CWallet *pwalletMain = GetWallet(ifaceIndex);
	int64 nBalance = 0;

	vector <COutput> vCoins;
	pwalletMain->AvailableAccountCoins(strAccount, vCoins, nMinDepth == 0 ? false : true);
	BOOST_FOREACH(const COutput& out, vCoins) {
		nBalance += out.tx->vout[out.i].nValue;
	}

	return nBalance;
}

bool SyncWithWallets(CIface *iface, CTransaction& tx, CBlock *pblock)
{
	CWallet *pwallet;

	pwallet = GetWallet(iface);
	if (!pwallet)
		return (false);

	return (pwallet->AddToWalletIfInvolvingMe(tx, pblock, true));
}

int CMerkleTx::GetBlocksToMaturity(int ifaceIndex) const
{
	CWallet *wallet = GetWallet(ifaceIndex);
	if (!wallet)
		return (0);
	CIface *iface = GetCoinByIndex(ifaceIndex);
	if (!iface)
		return 0;

	int nMaturity = wallet->GetCoinbaseMaturity();
	if (!IsCoinBase())
		return 0;

	int depth = GetDepthInMainChain(ifaceIndex);
	return max(0, (nMaturity + 1) - depth);
}

int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{

	if (!pblock)
		return (0);

	blkidx_t *mapBlockIndex = GetBlockTable(pblock->ifaceIndex);
	if (!mapBlockIndex)
		return 0;

	// Update the tx's hashBlock
	hashBlock = pblock->GetHash();

	// Locate the transaction
	for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
		if (pblock->vtx[nIndex] == *(CTransaction*)this)
			break;
	if (nIndex == (int)pblock->vtx.size())
	{
		nIndex = -1;
		//printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
		return 0;
	}

	// Is the tx in a block that's in the main chain
	map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex->find(hashBlock);
	if (mi == mapBlockIndex->end())
		return (0);

	CBlockIndex* pindex = (*mi).second;
	if (!pindex || !pindex->IsInMainChain(pblock->ifaceIndex))
		return (0);

	CBlockIndex *pindexBest = GetBestBlockIndex(pblock->ifaceIndex);
	if (!pindexBest)
		return (0);

	return (pindexBest->nHeight - pindex->nHeight + 1);
}

int CMerkleTx::SetMerkleBranch(int ifaceIndex)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	if (!iface)
		return (0);

	CBlock *pblock = GetBlockByTx(iface, GetHash()); 
	if (!pblock)
		return (0);

	int ret = SetMerkleBranch(pblock);
	delete pblock;
	return (ret);
}

CCoinAddr GetAccountAddress(CWallet *wallet, string strAccount)
{
	return (wallet->GetRecvAddr(strAccount));
}

bool CWallet::GetMergedPubKey(string strAccount, const char *tag, CPubKey& pubkey)
{
	CAccountCache *acc = GetAccount(strAccount);
	return (acc->GetMergedPubKey(tag, pubkey));
}

bool CWallet::GetMergedAddress(string strAccount, const char *tag, CCoinAddr& addrRet)
{

	{
		CPubKey pubkey;
		bool fRet = GetMergedPubKey(strAccount, tag, pubkey);
		if (!fRet)
			return (false);

		addrRet = CCoinAddr(ifaceIndex, pubkey.GetID());
		if (!addrRet.IsValid()) {
			return (error(SHERR_INVAL, "CWallet.GetMergedAddress: error generating coin addr from pubkey"));
		}
	}

	return (true);
}


/** Generate a transaction with includes a specific input tx. */
bool CreateTransactionWithInputTx(CIface *iface, string strAccount, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxIn, int nTxOut, CWalletTx& wtxNew, int64 nTxFee)
{
	int ifaceIndex = GetCoinIndex(iface);
	CWallet *pwalletMain = GetWallet(iface);
	int64 nMinValue = MIN_INPUT_VALUE(iface);
	int64 nValue = 0;
	int64 nFeeRet;

	if (wtxIn.IsSpent(nTxOut)) {
		return error(ifaceIndex, "CreateTransactionWithInputTx: previous ext tx '%s' is already spent.", wtxIn.GetHash().GetHex().c_str());
	}

	BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
		if (s.second < 0) {
			return error(SHERR_INVAL, "CreateTransactionWIthInputTx: send-value(%f) < min-value(%f)", ((double)s.second/(double)COIN), ((double)nMinValue/(double)COIN));
		}
		nValue += s.second;
	}
	if (vecSend.empty() || nValue < 0) {
		return error(SHERR_INVAL, "CreateTransactionWIthInputTx: vecSend.empty()\n");
	}

	wtxNew.BindWallet(pwalletMain);
	wtxNew.strFromAccount = strAccount;

	{
		nFeeRet = nTransactionFee;
		loop {
			wtxNew.vin.clear();
			wtxNew.vout.clear();
			wtxNew.fFromMe = true;

			int64 nTotalValue = nValue + nFeeRet;
			double dPriority = 0;

			// vouts to the payees
			BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
				wtxNew.vout.push_back(CTxOut(s.second, s.first));

			int64 nWtxinCredit = wtxIn.vout[nTxOut].nValue;

			// Choose coins to use
			set<pair<const CWalletTx*, unsigned int> > setCoins;
			int64 nValueIn = 0;
			if (nTotalValue - nWtxinCredit > 0) {
				if (!pwalletMain->SelectCoins(nTotalValue - nWtxinCredit,
							setCoins, nValueIn)) {
					return error(SHERR_INVAL, "CreateTransactionWithInputTx: error selecting coins\n"); 
				}
			}

			vector<pair<const CWalletTx*, unsigned int> > vecCoins(
					setCoins.begin(), setCoins.end());

			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
				int64 nCredit = coin.first->vout[coin.second].nValue;
				dPriority += (double) nCredit
					* coin.first->GetDepthInMainChain(ifaceIndex);
			}

			// Input tx always at first position
			vecCoins.insert(vecCoins.begin(), make_pair(&wtxIn, nTxOut));

			nValueIn += nWtxinCredit;
			dPriority += (double) nWtxinCredit * wtxIn.GetDepthInMainChain(ifaceIndex);

			// Fill a vout back to self (new addr) with any change
			int64 nChange = MAX(0, nValueIn - nTotalValue - nTxFee);
			if (nChange >= CENT) {
				CCoinAddr returnAddr = GetAccountAddress(pwalletMain, wtxNew.strFromAccount);
				CScript scriptChange;

				if (returnAddr.IsValid()) {
					/* return change to sender */
					scriptChange.SetDestination(returnAddr.Get());

					/* include as first transaction. */
					vector<CTxOut>::iterator position = wtxNew.vout.begin();
					wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
				}
			}

			// Fill vin
			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
				wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

			unsigned int nIn = 0;
			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
				CSignature sig(ifaceIndex, &wtxNew, nIn);
				if (!sig.SignSignature(*coin.first)) {
					return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
				}
				nIn++;
			}

			/* Ensure transaction does not breach a defined size limitation. */
			unsigned int nWeight = pwalletMain->GetTransactionWeight(wtxNew);
			if (nWeight >= MAX_TRANSACTION_WEIGHT(iface)) {
				return error(SHERR_INVAL, "CreateTransactionWithInputTx: the transaction is too large.");
			}

			unsigned int nBytes = pwalletMain->GetVirtualTransactionSize(wtxNew);
			dPriority /= nBytes;

			// Check that enough fee is included
			int64 nPayFee = nTransactionFee * (1 + (int64) nBytes / 1000);
			int64 nMinFee = pwalletMain->CalculateFee(wtxNew);

			if (nFeeRet < max(nPayFee, nMinFee)) {
				nFeeRet = max(nPayFee, nMinFee);
				Debug("TEST: CreateTransactionWithInputTx: re-iterating (nFreeRet = %s)\n", FormatMoney(nFeeRet).c_str());
				continue;
			}

			// Fill vtxPrev by copying from previous transactions vtxPrev
			pwalletMain->AddSupportingTransactions(wtxNew);
			break;
		}

	}

	return true;
}

int IndexOfExtOutput(const CTransaction& tx)
{
	int idx;

	idx = 0;
	BOOST_FOREACH(const CTxOut& out, tx.vout) {

		const CScript& script = out.scriptPubKey;
		opcodetype opcode;
		CScript::const_iterator pc = script.begin();
		if (script.GetOp(pc, opcode) &&
				opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
			break;
		}

		idx++;
	}
	if (idx == tx.vout.size())
		return (-1); /* uh oh */

	return (idx);
}

#if 0
/** Commit a transaction with includes a specific input tx. */
bool SendMoneyWithExtTx(CIface *iface, string strAccount, CWalletTx& wtxIn, CWalletTx& wtxNew, const CScript& scriptPubKey, vector<pair<CScript, int64> > vecSend, int64 txFee)
{
	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int nTxOut;

	nTxOut = IndexOfExtOutput(wtxIn);
	if (nTxOut == -1) {
		return error(ifaceIndex, "SendMoneyWithExtTx: error obtaining previous tx.");
	}

	/* insert as initial position. this is 'primary' operation. */
	int64 tx_val = wtxIn.vout[nTxOut].nValue;
	txFee = MAX(0, MIN(tx_val - iface->min_tx_fee, txFee));
	int64 nValue = tx_val - txFee;
	vecSend.insert(vecSend.begin(), make_pair(scriptPubKey, nValue));

	if (!CreateTransactionWithInputTx(iface, strAccount,
				vecSend, wtxIn, nTxOut, wtxNew, txFee)) {
		return error(ifaceIndex, "SendMoneyWithExtTx: error creating transaction.");
	}

	if (!pwalletMain->CommitTransaction(wtxNew)) {
		return error(ifaceIndex, "error commiting transaction.");
	}

	return (true);
}
#endif

bool GetCoinAddr(CWallet *wallet, CCoinAddr& addrAccount, string& strAccount)
{
	bool fIsScript = addrAccount.IsScript();

	if (!addrAccount.IsValid())
		return (error(SHERR_INVAL, "GetCoinAddr: invalid address \"%s\" specified for account \"%s\".", addrAccount.ToString().c_str(), strAccount.c_str()));

	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
	{
		const CCoinAddr& address = CCoinAddr(wallet->ifaceIndex, item.first);
		const string& account = item.second;

		if (fIsScript && !address.IsScript())
			continue;

		/* NOTE: does not compare coinaddr version */
		if (address.Get() == addrAccount.Get()) {
			addrAccount = address;
			strAccount = account;
			return (true);
		}
	}

	error(ERR_INVAL, "GetCoinAddr: mapAddressBook missing address \"%s\"\n", addrAccount.ToString().c_str());
	return (false);
}

bool GetCoinAddrAlias(CWallet *wallet, string strAlias, CCoinAddr& addrAccount)
{
	CIface *iface = GetCoinByIndex(wallet->ifaceIndex); 
	CTransaction tx;
	CAlias *alias;

	alias = GetAliasByName(iface, strAlias, tx); 
	if (!alias)
		return (false);

	return (alias->GetCoinAddr(wallet->ifaceIndex, addrAccount));
}

bool GetCoinAddr(CWallet *wallet, string strAddress, CCoinAddr& addrAccount)
{

	if (strAddress.length() == 0)
		return (false);

	if (strAddress.substr(0, 1) == CWallet::EXT_ACCOUNT_PREFIX) {
		return (GetCoinAddrAlias(wallet, strAddress.substr(1), addrAccount));
	}

	addrAccount = CCoinAddr(wallet->ifaceIndex, strAddress);
	if (!addrAccount.IsValid())
		return (false);

	return (true);
}

bool DecodeMatrixHash(const CScript& script, int& mode, uint160& hash)
{
	CScript::const_iterator pc = script.begin();
	opcodetype opcode;
	int op;

	if (!script.GetOp(pc, opcode)) {
		return false;
	}
	mode = opcode; /* extension mode (new/activate/update) */
	if (mode < 0xf0 || mode > 0xf9)
		return false;

	if (!script.GetOp(pc, opcode)) {
		return false;
	}
	if (opcode < OP_1 || opcode > OP_16) {
		return false;
	}
	op = CScript::DecodeOP_N(opcode); /* extension type */
	if (op != OP_MATRIX) {
		return false;
	}

	vector<unsigned char> vch;
	if (!script.GetOp(pc, opcode, vch)) {
		return false;
	}
	if (opcode != OP_HASH160)
		return (false);

	if (!script.GetOp(pc, opcode, vch)) {
		return false;
	}
	hash = uint160(vch);
	return (true);
}

bool VerifyMatrixTx(CTransaction& tx, int& mode)
{
	uint160 hashMatrix;
	int nOut;

	/* core verification */
	if (!tx.isFlag(CTransaction::TXF_MATRIX))
		return (false); /* tx not flagged as matrix */

	/* verify hash in pub-script matches matrix hash */
	nOut = IndexOfExtOutput(tx);
	if (nOut == -1)
		return error(SHERR_INVAL, "no extension output");

	if (!DecodeMatrixHash(tx.vout[nOut].scriptPubKey, mode, hashMatrix))
		return error(SHERR_INVAL, "no matrix hash in output");

	CTxMatrix *matrix = (CTxMatrix *)&tx.matrix;
	if (hashMatrix != matrix->GetHash())
		return error(SHERR_INVAL, "matrix hash mismatch");

	return (true);
}

bool IsAccountValid(CIface *iface, std::string strAccount)
{
	int ifaceIndex = GetCoinIndex(iface);
	CWallet *wallet;
	int total;

	wallet = GetWallet(iface);
	if (!wallet)
		return (false);

	if (strAccount.length() == 0)
		return (true);

	total = 0;
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
	{
		const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
		const string& strName = item.second;
		if (strName == strAccount)
			total++;
	}

	return (total != 0);
}

void RelayTransaction(int ifaceIndex, const CTransaction& tx, const uint256& hash)
{
	CInv inv(ifaceIndex, MSG_TX, hash);

	LOCK(cs_vNodes);
	NodeList &vNodes = GetNodeList(ifaceIndex);
	BOOST_FOREACH(CNode* pnode, vNodes)
	{
		if(!pnode->fRelayTxes) {
			Debug("RelayTransaction[iface #%d]: tx (%s) [suppress]", ifaceIndex, hash.GetHex().c_str());
			continue;
		}

		LOCK(pnode->cs_filter);
		CBloomFilter *filter = pnode->GetBloomFilter();
		if (filter) {
			if (filter->IsRelevantAndUpdate(tx, hash)) {
				pnode->PushInventory(inv);
				Debug("RelayTransaction[iface #%d]: tx (%s) [bloom]", ifaceIndex, hash.GetHex().c_str());
			} else {
				Debug("RelayTransaction[iface #%d]: tx (%s) [suppress/bloom]", ifaceIndex, hash.GetHex().c_str());
			}
		} else {
			pnode->PushInventory(inv);
			Debug("RelayTransaction[iface #%d]: tx (%s)", ifaceIndex, hash.GetHex().c_str());
		}
	}

}

int CMerkleTx::GetDepthInMainChain(int ifaceIndex, CBlockIndex* &pindexRet) const
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CBlockIndex *pindexBest;
	CBlockIndex *pindex;

	if (hashBlock == 0 || nIndex == -1) {
		return 0;
	}

	pindex = GetBlockIndexByHash(ifaceIndex, hashBlock);
	if (!pindex || !pindex->IsInMainChain(ifaceIndex)) {
		return 0;
	}
	pindexRet = pindex;

	if (ifaceIndex == COLOR_COIN_IFACE)  {
		int nDepth = 1;

		pindexBest = pindex;
		while (pindexBest->pnext) {
			nDepth++;
			pindexBest = pindexBest->pnext;
		}

		return (nDepth);
	}

	pindexBest = GetBestBlockIndex(ifaceIndex);
	if (!pindexBest)
		return (0);
	return pindexBest->nHeight - pindex->nHeight + 1;
}


void CWallet::AvailableAddrCoins(vector<COutput>& vCoins, const CCoinAddr& filterAddr, int64& nTotalValue, bool fOnlyConfirmed) const
{

	vCoins.clear();
	nTotalValue = 0;

	{
		LOCK(cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx* pcoin = &(*it).second;

			if (!pcoin->IsFinal(ifaceIndex))
				continue;

			if (fOnlyConfirmed && !pcoin->IsConfirmed())
				continue;

			if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity(ifaceIndex) > 0)
				continue;

			// If output is less than minimum value, then don't include transaction.
			// This is to help deal with dust spam clogging up create transactions.
			for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
				opcodetype opcode;
				const CScript& script = pcoin->vout[i].scriptPubKey;
				CScript::const_iterator pc = script.begin();
				if (script.GetOp(pc, opcode) &&
						opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
					continue; /* not avail */
				}

				CIface *iface = GetCoinByIndex(ifaceIndex);
				int64 nMinValue = MIN_INPUT_VALUE(iface);
				if (pcoin->vout[i].nValue < nMinValue)
					continue; /* weird */

				if (pcoin->IsSpent(i))
					continue;

				CTxDestination dest;
				if (!ExtractDestination(pcoin->vout[i].scriptPubKey, dest))
					continue;
				CKeyID k1;
				CKeyID k2;
				if (!CCoinAddr(ifaceIndex, dest).GetKeyID(k1) || 
						!filterAddr.GetKeyID(k2) || 
						k1 != k2)
					continue; /* wrong coin address */

				vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(ifaceIndex)));
				nTotalValue += pcoin->vout[i].nValue;
			}
		}
	}
}

bool CreateMoneyTx(CIface *iface, CWalletTx& wtxNew, vector<COutput>& vecRecv, vector<CTxOut>& vecSend, CScript scriptPubKey)
{
	CWallet *wallet = GetWallet(iface);
	int64 nTotalValue = 0;
	int64 nTxFee = 0;

	wtxNew.BindWallet(wallet);
	{
		wtxNew.vin.clear();
		wtxNew.vout.clear();

		BOOST_FOREACH(const COutput& out, vecRecv) {
			wtxNew.vin.push_back(CTxIn(out.tx->GetHash(), (unsigned int)out.i));
			nTotalValue += out.tx->vout[out.i].nValue; 
		}

		BOOST_FOREACH(const CTxOut& out, vecSend) {
			wtxNew.vout.push_back(out);
		}

		/* calculate fee */
		unsigned int nBytes = ::GetSerializeSize(wtxNew, SER_NETWORK, PROTOCOL_VERSION(iface));
		nBytes += 66 * vecRecv.size(); /* ~ 66b / sig */
		nTxFee = (1 + (int64)nBytes / 1000) * (int64)iface->min_tx_fee;
		/* add final destination addr */
		wtxNew.vout.push_back(CTxOut(nTotalValue - nTxFee, scriptPubKey));

		unsigned int nIn = 0;
		BOOST_FOREACH(const COutput& out, vecRecv) {
			CSignature sig(wallet->ifaceIndex, &wtxNew, nIn);
			if (!sig.SignSignature(*out.tx)) {
				return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
			}

			nIn++;
		}

		wallet->AddSupportingTransactions(wtxNew);
	}

	return (true);
}

/**
 * @param wtxIn An extended tx input to remit coins from.
 * @param scriptPubKey The destination coin address.
 */ 
bool SendRemitMoneyTx(CIface *iface, const CCoinAddr& addrFrom, CWalletTx *wtxIn, CWalletTx& wtxNew, vector<pair<CScript, int64> >& vecSend, CScript scriptPubKey)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	vector<COutput> vCoins;
	int64 nTotalValue = 0;
	wallet->AvailableAddrCoins(vCoins, addrFrom, nTotalValue, true);

	if (wtxIn) {
		/* append primary exec tx */
		int nTxOut = IndexOfExtOutput(*wtxIn);
		if (nTxOut == -1) return (false);
		vCoins.push_back(COutput(wtxIn, nTxOut, wtxIn->GetDepthInMainChain(ifaceIndex)));
	}

	vector <CTxOut> vecOut;
	BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
		vecOut.push_back(CTxOut(s.second, s.first));
	}

	if (!CreateMoneyTx(iface, wtxNew, vCoins, vecOut, scriptPubKey)) {
		return (error(SHERR_CANCELED, "SendRemitMoneyExtTx: error sending money tx: %s.", scriptPubKey.ToString().c_str()));
	}

	if (!wallet->CommitTransaction(wtxNew)) {
		return error(SHERR_CANCELED, "SendRemitMoneyExtTx: error commiting transaction.");
	}

	return (true);
}

/**
 * @note: This functionality is designed to rid of rejected transactions. This does not permit the 'canceling' of already relayed transactions.
 */
bool core_UnacceptWalletTransaction(CIface *iface, const CTransaction& tx)
{
	int ifaceIndex = GetCoinIndex(iface);
	const uint256& tx_hash = tx.GetHash();
	CTxMemPool *pool = GetTxMemPool(iface);
	CWallet *wallet = GetWallet(iface);
	vector<CTxIn> vIn;
	tx_cache inputs;

	if (VerifyTxHash(iface, tx_hash)) {
		Debug("(%s) core_UnacceptWalletTransaction: unable to unaccept tx \"%s\" from wallet as it is already in block-chain.", iface->name, tx_hash.GetHex().c_str());
		return (false);
	}

	/* remove from wallet */
	wallet->EraseFromWallet(tx_hash);

	/* remove from mem-pool */
	if (pool->exists(tx_hash)) {
		pool->RemoveTx(tx_hash);
	}

	{
		CTransaction *tx_p = (CTransaction *)&tx;

		/* erase from 'coin' fmap */
		tx_p->EraseCoins(ifaceIndex);
	}

	/* mark inputs unspent */
	BOOST_FOREACH(const CTxIn& in, vIn) {
		const uint256& prevhash = in.prevout.hash;

		if (wallet->HasTx(prevhash)) {
			CWalletTx& wtx = wallet->GetTx(prevhash);

			/* mark output as unspent */
			vector<char> vfNewSpent = wtx.vfSpent;
			if (in.prevout.n >= wtx.vout.size()) {
				error(SHERR_INVAL, "(%s) core_UnacceptWalletTransaction: in.prevout.n (%d) >= wtx.vout.size(%d)", iface->name, in.prevout.n, wtx.vout.size());
				continue;    
			}
			vfNewSpent.resize(wtx.vout.size());
			vfNewSpent[in.prevout.n] = false;
			wtx.vfSpent = vfNewSpent;
			wtx.fAvailableCreditCached = false;
			/* -> active */
			wallet->WriteWalletTx(wtx);
			wallet->mapWallet[prevhash] = wtx;
			wallet->EraseArchTx(prevhash);

			Debug("(%s) core_UnacceptWalletTransaction: marked tx \"%s\" output #%d as unspent in wallet.\n", iface->name, prevhash.GetHex().c_str(), in.prevout.n); 
		}
	}

	return (true);
}

int64 CWallet::CalculateFee(CWalletTx& tx, int64 nMinFee, int confTarget)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CWallet *wallet = GetWallet(ifaceIndex);
	int64 nBytes;
	int64 nFee;

	nBytes = (int64)GetVirtualTransactionSize(tx); 

	/* base fee */
	nFee = (int64)MIN_RELAY_TX_FEE(iface);
	if (ifaceIndex == COLOR_COIN_IFACE) {
		nFee += GetFeeRate(tx.GetColor()) * (nBytes / 1000);
	} else {
		nFee += GetFeeRate() * (nBytes / 1000);
	}
	/* dust penalty */
	BOOST_FOREACH(const CTxOut& out, tx.vout) {
		if (out.nValue < CENT)
			nFee += MIN_TX_FEE(iface);
	}
	nFee = MAX(nFee, nMinFee);

	if (confTarget != 0) {
		int64 nEstFee = 0;
		CBlockPolicyEstimator *est = GetFeeEstimator(iface);
		if (est) {
			nEstFee = est->estimateSmartFee(confTarget, NULL).GetFee(nBytes);
			if (nEstFee > nFee) {
				nFee = nEstFee;
			}
		}
	}

	/* limit fee */
	nFee = MIN(nFee, (int64)MAX_TRANSACTION_FEE(iface) - 1);

	return (nFee);
}


bool CWallet::FillInputs(const CTransaction& tx, tx_cache& inputs, bool fAllowSpent)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);

	if (!iface || !iface->enabled)
		return (false);

	{
		LOCK(cs_wallet);

		for (unsigned int i = 0; i < tx.vin.size(); i++) {
			COutPoint prevout = tx.vin[i].prevout;

			if (inputs.count(prevout.hash))
				continue;

			CTransaction prevTx;
			const uint256& prev_hash = prevout.hash;
			if (!::GetTransaction(iface, prev_hash, prevTx, NULL)) {
				CTxMemPool *pool = GetTxMemPool(iface);
				if (!pool->GetTx(prev_hash, prevTx, POOL_ACTIVE)) {
					return (error(SHERR_INVAL, "(%s) FillInputs: unknown tx hash \"%s\" [tx: %s].", iface->name, prev_hash.GetHex().c_str(), tx.GetHash().GetHex().c_str()));
				}
			}

			if (!fAllowSpent) {
				vector<uint256> vOuts;
				if (!prevTx.ReadCoins(ifaceIndex, vOuts)) {
					return (error(SHERR_INVAL, "FillInputs: error reading tx from coin database."));
				}
				if (prevout.n >= vOuts.size()) {
					return (error(SHERR_INVAL, "FillInputs: error reading tx from coin database [invalid index]."));
				}
				if (!vOuts[prevout.n].IsNull()) {
					/* already spent */
					return (error(SHERR_ALREADY, "FillInputs: transaction has spent coins."));
				}
			}

			inputs[prev_hash] = prevTx;
		}
	}

	return (true);
}

double CWallet::GetPriority(const CTransaction& tx, tx_cache& inputs)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	double dPriority = 0;

	for (unsigned int i = 0; i < tx.vin.size(); i++) {
		const CTxIn& input = tx.vin[i];
		tx_cache::const_iterator mi = inputs.find(input.prevout.hash);
		if (mi == inputs.end()) continue;

		const CTransaction& txPrev = (mi->second);
		if (input.prevout.n >= txPrev.vout.size()) continue;

		const CTxOut& out = txPrev.vout[input.prevout.n];
		dPriority += out.nValue * txPrev.GetDepthInMainChain(ifaceIndex);
	}
	int64 nBytes = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION(iface));
	dPriority /= nBytes;

	return (dPriority);
}

void CWalletTx::AddSupportingTransactions()
{
	int ifaceIndex = pwallet->ifaceIndex;

	vtxPrev.clear();

	const int COPY_DEPTH = 3;
	if (SetMerkleBranch(ifaceIndex) < COPY_DEPTH)
	{
		vector<uint256> vWorkQueue;
		BOOST_FOREACH(const CTxIn& txin, vin) {
			vWorkQueue.push_back(txin.prevout.hash);
		}

		{
			LOCK(pwallet->cs_wallet);
			map<uint256, const CMerkleTx*> mapWalletPrev;
			set<uint256> setAlreadyDone;
			for (unsigned int i = 0; i < vWorkQueue.size(); i++)
			{
				uint256 hash = vWorkQueue[i];
				if (setAlreadyDone.count(hash))
					continue;
				setAlreadyDone.insert(hash);

				CMerkleTx tx;
				map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(hash);
				if (mi != pwallet->mapWallet.end())
				{
					tx = (*mi).second;
					BOOST_FOREACH(const CMerkleTx& txWalletPrev, (*mi).second.vtxPrev)
						mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
				}
				else if (mapWalletPrev.count(hash))
				{
					tx = *mapWalletPrev[hash];
				}
				else if (!fClient && tx.ReadTx(ifaceIndex, hash))
				{
					;
				}
				else
				{
					error(SHERR_INVAL, "AddSupportingTransactions: unsupported transaction: %s", hash.GetHex().c_str());
					continue;
				}

				if (tx.IsCoinBase())
					continue;

				int nDepth = tx.SetMerkleBranch(ifaceIndex);
				vtxPrev.push_back(tx);

				if (nDepth < COPY_DEPTH)
				{
					BOOST_FOREACH(const CTxIn& txin, tx.vin) {
						vWorkQueue.push_back(txin.prevout.hash);
					}
				}
			}
		}
	}

	reverse(vtxPrev.begin(), vtxPrev.end());
}

bool CWalletTx::AcceptWalletTransaction()
{
	CIface *iface = GetCoinByIndex(pwallet->ifaceIndex);
	CTxMemPool *pool;

	pool = GetTxMemPool(iface);
	if (!pool) {
		unet_log(pwallet->ifaceIndex, "error obtaining tx memory pool");
		return (false);
	}

	/* Add previous supporting transactions first */
	BOOST_FOREACH(CMerkleTx& tx, vtxPrev) {
		pool->AddTx(tx);
	}

	return pool->AddTx(*this);
}

void core_ReacceptWalletTransactions(CWallet *wallet)
{
	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	blkidx_t *blockIndex = GetBlockTable(wallet->ifaceIndex);
	CBlockIndex *min_pindex;
	CBlockIndex *pindex;
	int i;

	if (!iface || !iface->enabled)
		return;

	min_pindex = NULL;

	vector<uint256> vErase;

	std::map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin();
	for (; it != wallet->mapWallet.end(); it++) {
		const uint256& tx_hash = it->first;
		CWalletTx *wtx = &it->second;

		if (!wtx->hashBlock.IsNull()) {
			continue; /* already commited to blockchain. */
		}

		if (wtx->IsCoinBase())
			continue; /* not applicable */

		/* need to be careful here to still add supporting tx's */
		for (i = 0; i < wtx->vfSpent.size(); i++) {
			if (wtx->vfSpent[i])
				break;
		}
		if (i != wtx->vfSpent.size())
			continue; /* already [at least partially] spent. */

		pindex = GetBlockIndexByTx(iface, tx_hash);
		if (!pindex) {
			/* reaccept into mempool. */
			if (!wtx->AcceptWalletTransaction()) {
				Debug("(%s) ReacceptWalletTransactions: warning: unresolvable tx \"%s\".", iface->name, wtx->GetHash().GetHex().c_str());
				vErase.push_back(tx_hash);
			}
		} else {
			/* reference highest block with stored wallet tx */
			if (!min_pindex || min_pindex->nHeight < pindex->nHeight)
				min_pindex = pindex;
		}
	}

#if 0
	/* rescan from height of newest wallet tx */
	if (min_pindex)
		wallet->ScanForWalletTransactions(min_pindex);
#endif

	if (min_pindex) {
		Debug("Last wallet transaction @ height %d (block %s).", min_pindex->nHeight, min_pindex->GetBlockHash().GetHex().c_str());
	}

}

static bool GenerateExtendedDefaultKey(CWallet *wallet, CKeyID masterKeyID, CPubKey& pubkeyRet)
{
	cbuff tagbuf(ExtendedDefaultKeyTag, ExtendedDefaultKeyTag + strlen(ExtendedDefaultKeyTag));
	CKey *eckey;
  CKey *pkey;

  pkey = wallet->GetKey(masterKeyID);
  if (!pkey)
    return (false);

#if 0
	eckey = wallet->toECKey(pkey);
	if (!eckey)
		return (false);
#endif

  ECKey key;
  key.MergeKey(pkey, tagbuf);
  key.nFlag |= ACCADDRF_MASTER;

  pubkeyRet = key.GetPubKey();
  if (!pubkeyRet.IsValid())
    return (false);

  const CKeyID& keyid = pubkeyRet.GetID();
  if (!wallet->HaveKey(keyid)) {
    /* add key to address book */
    if (!wallet->AddKey(key))
      return (false);
  }

  return (true);
}

CAccountCache *CWallet::GetAccount(string strAccount, uint160 hColor)
{

	CAccountCache *ca;

  ca = NULL;
  if (mapAddrCache.count(strAccount) != 0) {
    ca = mapAddrCache[strAccount];
  }
  if (ca && ca->hColor != hColor) {
    ca = NULL;
  }

	if (ca == NULL) {
		ca = new CAccountCache(this, hColor);
		CPubKey pubkey;
		bool fUpdate;

		fUpdate = false;
		ca->strAccount = strAccount;
		ca->account.SetNull();

		{
			LOCK(cs_wallet);

			/* load from wallet */
			CWalletDB walletdb(strWalletFile);
			walletdb.ReadAccount(strAccount, ca->account);
			walletdb.Close();
		}

		/* initial extended account primary key creation. */
		if (!ca->account.vchPubKey.IsValid() &&
				strAccount.substr(0, 1) == CWallet::EXT_ACCOUNT_PREFIX) {
			/* derive from non-extended account. */
			string strMasterAccount = strAccount.substr(1);

			CAccount masterAccount;
			{
				LOCK(cs_wallet);

				/* load from wallet */
				CWalletDB walletdb(strWalletFile);
				walletdb.ReadAccount(strMasterAccount, masterAccount);
				walletdb.Close();
			}

			if (masterAccount.vchPubKey.IsValid()) {
				CPubKey pubkey;
				CKeyID keyid;

				if (GenerateExtendedDefaultKey(this, masterAccount.vchPubKey.GetID(), pubkey)) {
					ca->account.vchPubKey = pubkey;
					fUpdate = true;
				}
			}
		}

		/* initial regular account master key creation. */
		if (!ca->account.vchPubKey.IsValid()) {
#if 0
			CPubKey pubkey;
			bool fOk;

			if (opt_bool(OPT_DILITHIUM) &&
					(ifaceIndex == SHC_COIN_IFACE ||
					 ifaceIndex == TEST_COIN_IFACE ||
					 ifaceIndex == TESTNET_COIN_IFACE)) {
				/* uses dilithium key as master to increase entropy (seed) of derived hd-keys. */
				fOk = ca->GenerateNewDIKey(pubkey, ACCADDRF_MASTER);
			} else {
				/* standard ecdsa key */
				fOk = ca->GenerateNewECKey(pubkey, ACCADDRF_MASTER);
			}
			if (fOk) {
				ca->account.vchPubKey = pubkey;
        fUpdate = true; 
			}
#endif
			fUpdate = ca->GenerateDefaultKey();
		}

		if (fUpdate) {
			ca->UpdateAccount();
		}

		mapAddrCache[strAccount] = ca;
	}

	return (ca);
}


CPubKey CWallet::GetPrimaryPubKey(string strAccount)
{
	return (GetAccount(strAccount)->account.vchPubKey);
}

CCoinAddr CWallet::GetChangeAddr(string strAccount)
{
	return (GetAccount(strAccount)->GetAddr(ACCADDR_CHANGE));
}

CCoinAddr CWallet::GetExecAddr(string strAccount)
{
	return (GetAccount(strAccount)->GetAddr(ACCADDR_EXEC));
}

CCoinAddr CWallet::GetExtAddr(string strAccount)
{
	return (GetAccount(EXT_ACCOUNT_PREFIX + strAccount)->GetAddr(ACCADDR_EXT));
}

CCoinAddr CWallet::GetNotaryAddr(string strAccount)
{
	return (GetAccount(strAccount)->GetAddr(ACCADDR_NOTARY));
}

CCoinAddr CWallet::GetRecvAddr(string strAccount)
{
	return (GetAccount(strAccount)->GetAddr(ACCADDR_RECV));
}

CCoinAddr CWallet::GetPrimaryAddr(string strAccount)
{
	const CPubKey& pubkey = GetPrimaryPubKey(strAccount);
	return CCoinAddr(ifaceIndex, pubkey.GetID());
}

static const char *wallet_wtx_filename(CWallet *wallet)
{
	static char ret_buf[PATH_MAX+1];

	if (!*ret_buf) {
		CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
		if (!iface)
			return ("null.dat");
		sprintf(ret_buf, "%s_wtx.dat", iface->name);
	}

	return (ret_buf);
}

CBlockLocator CWallet::GetLocator(CBlockIndex *pindex)
{
	std::vector<uint256> vHave;
	int nStep = 1;

	vHave.clear();
	vHave.reserve(32);

	if (!pindex)
		pindex = GetBestBlockIndex(ifaceIndex);

	while (pindex) {
		vHave.push_back(pindex->GetBlockHash());

		/* stop when we have added the genesis block. */
		if (pindex->nHeight == 0)
			break;

		/* exponentially larger steps back, plus the genesis block. */
		int nHeight = std::max(pindex->nHeight - nStep, 0);
		while (pindex->nHeight > nHeight)
			pindex = pindex->pprev;

		if (vHave.size() > 10)
			nStep *= 2;
	}

	return CBlockLocator(vHave);
}

CBlockIndex *CWallet::GetLocatorIndex(const CBlockLocator& loc)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CBlockIndex *pindex;

	/* find the first block the caller has in the main chain. */
	BOOST_FOREACH(const uint256& hash, loc.vHave) {
		pindex = GetBlockIndexByHash(ifaceIndex, hash);
		if (pindex && pindex->IsInMainChain(ifaceIndex))
			return pindex;
	}

	if (loc.vHave.empty()) {
		Debug("(%s) GetLocatorIndex: warning: empty block hierarchy.", iface->name);
	} else {
		Debug("(%s) GetLocatorIndex: unable to find block \"%s\" hierarchy in chain.", iface->name, loc.vHave.front().GetHex().c_str());
	}

	return (GetGenesisBlockIndex(iface));
}

bool CWallet::DeriveNewECKey(CKey *key, CAccount *hdChain, ECKey& secret, int nType)
{
	// for now we use a fixed keypath scheme of m/0'/0'/k
//	ECExtKey masterKey;             //hd master key
//	ECExtKey accountKey;            //key at m/0'
	ECExtKey chainChildKey;         //key at m/0'/0' (external) or m/0'/1' (internal)
	ECExtKey childKey;              //key at m/0'/0'/<n>'
	string hdKeypath;

	if (!hdChain)
		return (false);

	if (!key)
		return (false);

#if 0
	CKey *key = GetKey(hdChain->masterKeyID);
	if (!key)
		return (false);

	masterKey.SetMaster(key->begin(), key->size());

	// derive m/0'
	// use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
	masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

	// derive "m/0'/<nType>'"
	accountKey.Derive(chainChildKey, BIP32_HARDENED_KEY_LIMIT + nType);
#endif

	if (!DerivePrimaryECExtKey(key, chainChildKey, nType))
		return (false);

	// derive child key at next index, skip keys already known to the wallet
	do {
		// always derive hardened keys
		// childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
		// example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
		uint nIndex = hdChain->GetHDIndex(nType, SIGN_ALG_ECDSA);
		chainChildKey.Derive(childKey, nIndex | BIP32_HARDENED_KEY_LIMIT);
		hdKeypath = "m/0'/" + std::to_string(nType) + "'/" + std::to_string(nIndex) + "'";
		hdChain->IncrementHDIndex(nType, SIGN_ALG_ECDSA); 	
	} while (HaveKey(childKey.key.GetPubKey().GetID()));

	secret = childKey.key;
	secret.nFlag |= ACCADDRF_DERIVE;
	secret.hdMasterKeyID = key->GetPubKey().GetID();
	secret.hdKeypath = hdKeypath;

	return (true);
}

bool CWallet::DerivePrimaryECExtKey(CKey *key, ECExtKey& chainChildKey, int nType)
{
	ECExtKey masterKey;             //hd master key
	ECExtKey accountKey;            //key at m/0'
//	ECExtKey chainChildKey;         //key at m/0'/<nType>'

	if (!key)
		return (false);

#if 0
	CKey *key = GetKey(hdChain->GetMasterKeyID());
	if (!key) {
		return (false);
	}
#endif

	masterKey.SetMaster(key->begin(), key->size());

	// derive m/0'
	// use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
	masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

	// derive m/0'/X' based on type.
	accountKey.Derive(chainChildKey, BIP32_HARDENED_KEY_LIMIT + nType);

	return (true);
}

bool CWallet::DerivePrimaryECKey(CKey *key, ECKey& secret, int nType)
{
	ECExtKey chainChildKey;

	if (!DerivePrimaryECExtKey(key, chainChildKey, nType))
		return (false); 

	secret = chainChildKey.key;
	secret.nFlag |= CKeyMetadata::META_HD_KEY;
	secret.hdMasterKeyID = key->GetPubKey().GetID();
	secret.hdKeypath = "m/0'/" + std::to_string(nType) + "'";
	return (true);
}

bool CWallet::DeriveNewDIKey(CKey *key, CAccount *hdChain, DIKey& secret, int nType)
{
	// for now we use a fixed keypath scheme of m/0'/0'/k
//	DIExtKey masterKey;             //hd master key
//	DIExtKey accountKey;            //key at m/0'
	DIExtKey chainChildKey;         //key at m/0'/0' (external) or m/0'/1' (internal)
	DIExtKey childKey;              //key at m/0'/0'/<n>'
	string hdKeypath;

	if (!hdChain)
		return (false);

	if (!key)
		return (false);

#if 0
	CKey *key = GetKey(hdChain->masterKeyID);
	if (!key)
		return (false);

	masterKey.SetMaster(key->begin(), key->size());

	// derive m/0'
	// use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
	masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

	// derive "m/0'/<nType>'"
	accountKey.Derive(chainChildKey, BIP32_HARDENED_KEY_LIMIT + nType);
#endif
	if (!DerivePrimaryDIExtKey(key, chainChildKey, nType))
		return (false);

	// derive child key at next index, skip keys already known to the wallet
	do {
		// always derive hardened keys
		// childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
		// example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
		uint nIndex = hdChain->GetHDIndex(nType, SIGN_ALG_DILITHIUM);
		chainChildKey.Derive(childKey, nIndex | BIP32_HARDENED_KEY_LIMIT);
		hdKeypath = "m/0'/" + std::to_string(nType) + "'/" + std::to_string(nIndex) + "'";
		hdChain->IncrementHDIndex(nType, SIGN_ALG_DILITHIUM);
	} while (HaveKey(childKey.key.GetPubKey().GetID()));

	secret = childKey.key;
	secret.nFlag |= ACCADDRF_DERIVE;
	secret.nFlag |= ACCADDRF_DILITHIUM;
	secret.hdMasterKeyID = key->GetPubKey().GetID();
	secret.hdKeypath = hdKeypath;

	return (true);
}

bool CWallet::DerivePrimaryDIExtKey(CKey *key, DIExtKey& chainChildKey, int nType)
{
	DIExtKey masterKey;             //hd master key
	DIExtKey accountKey;            //key at "m/0'"
//	DIExtKey chainChildKey;         //key at "m/0'/<nType>'"

	if (!key)
		return (false);

#if 0
	CKey *key = GetKey(hdChain->GetMasterKeyID());
	if (!key)
		return (false);
#endif

	masterKey.SetMaster(key->begin(), key->size());

	// derive m/0'
	// use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
	masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

	// derive m/0'/X' based on type.
	accountKey.Derive(chainChildKey, BIP32_HARDENED_KEY_LIMIT + nType);

	return (true);
}

bool CWallet::DerivePrimaryDIKey(CKey *key, DIKey& secret, int nType)
{
	DIExtKey chainChildKey;

	if (!DerivePrimaryDIExtKey(key, chainChildKey, nType))
		return (false); 

	secret = chainChildKey.key;
	secret.nFlag |= CKeyMetadata::META_HD_KEY;
	secret.nFlag |= ACCADDRF_DILITHIUM;
	secret.hdMasterKeyID = key->GetPubKey().GetID();
	secret.hdKeypath = "m/0'/" + std::to_string(nType) + "'";
	return (true);
}

const cbuff& CWallet::Base58Prefix(int type) const
{
	static cbuff vchVersion;
	static cbuff empty_buff;
	CIface *iface = GetCoinByIndex(ifaceIndex);
	uint8_t *raw;

	if (!iface || !iface->enabled)
		return (empty_buff);

	vchVersion.clear();

	switch (type) {
		case CCoinAddr::BASE58_PUBKEY_ADDRESS:
			raw = &iface->base58_pubkey_address;
			vchVersion = cbuff(raw, raw+1);
			break;
		case CCoinAddr::BASE58_SCRIPT_ADDRESS:
			raw = &iface->base58_script_address;
			vchVersion = cbuff(raw, raw+1);
			break;
		case CCoinAddr::BASE58_SCRIPT_ADDRESS2:
			raw = &iface->base58_script_address2;
			vchVersion = cbuff(raw, raw+1);
			break;
		case CCoinAddr::BASE58_SECRET_KEY:
			raw = &iface->base58_secret_key;
			vchVersion = cbuff(raw, raw+1);
			break;
		case CCoinAddr::BASE58_EXT_PUBLIC_KEY:
			raw = (uint8_t *)iface->base58_ext_public_key;
			vchVersion = cbuff(raw, raw+4);
			break;
		case CCoinAddr::BASE58_EXT_SECRET_KEY:
			raw = (uint8_t *)iface->base58_ext_secret_key;
			vchVersion = cbuff(raw, raw+4);
			break;
	}

	return (vchVersion);
}

bool ExtractDestinationKey(CWallet *wallet, const CTxDestination& dest, CKeyID& keyid)
{
	CScript scriptPubKey;
	vector<cbuff> vSolutions;
	txnouttype whichType;

	/* reset key */
	keyid.SetNull();

	scriptPubKey.SetDestination(dest);
	if (!Solver(scriptPubKey, whichType, vSolutions))
		return (false);

	if (whichType == TX_SCRIPTHASH) {
		CScriptID scriptid;
		scriptid = CScriptID(uint160(vSolutions[0]));
		CScript subscript;
		if (!wallet->GetCScript(scriptid, subscript))
			return (false);
		vSolutions.clear();
		if (!Solver(subscript, whichType, vSolutions))
			return (false);
	} else if (whichType == TX_WITNESS_V0_SCRIPTHASH ||
			whichType == TX_WITNESS_V14_SCRIPTHASH) {
		uint160 hash2;
		const cbuff vch(vSolutions[0].begin(), vSolutions[0].end());
		cbuff vchHash;
		uint160 hash160;
		RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
		memcpy(&hash160, &vchHash[0], sizeof(hash160));

		CScriptID scriptID = CScriptID(hash160);
		CScript subscript;
		if (!wallet->GetCScript(scriptID, subscript))
			return (false);
		if (!Solver(subscript, whichType, vSolutions))
			return (false);
	}

	switch (whichType) {
		case TX_PUBKEY:
			keyid = CPubKey(vSolutions[0]).GetID();
			break;
		case TX_PUBKEYHASH:
			keyid = CKeyID(uint160(vSolutions[0]));
			break;
		case TX_WITNESS_V0_KEYHASH:
		case TX_WITNESS_V14_KEYHASH:
			keyid = CKeyID(uint160(vSolutions[0]));
			break;
	}	
	if (keyid == 0)
		return (false);

	return (true);
}

bool CWalletTx::IsConfirmed() const
{

	// Quick answer in most cases
	if (!IsFinal(pwallet->ifaceIndex)) {
		return false;
	}

	int nDepth = GetDepthInMainChain(pwallet->ifaceIndex);
	if (nDepth >= 1) {
		return true;
	}

	if (!IsFromMe()) { // using wtx's cached debit
		return false;
	}

	{
		CIface *iface = GetCoinByIndex(pwallet->ifaceIndex);
		CTxMemPool *pool = GetTxMemPool(iface);
		const uint256& hash = GetHash();
		CTransaction tmpTx;
		if (!pool || !pool->GetTx(hash, tmpTx, POOL_ACTIVE)) {
			/* must be in active pool in order to use as input [when not confirmed]. */
			return (false);
		}
	}

	// If no confirmations but it's from us, we can still
	// consider it confirmed if all dependencies are confirmed
	std::map<uint256, const CMerkleTx*> mapPrev;
	std::vector<const CMerkleTx*> vWorkQueue;
	vWorkQueue.reserve(vtxPrev.size()+1);
	vWorkQueue.push_back(this);
	for (unsigned int i = 0; i < vWorkQueue.size(); i++)
	{
		const CMerkleTx* ptx = vWorkQueue[i];

		if (!ptx->IsFinal(pwallet->ifaceIndex))
			return false;
		if (ptx->GetDepthInMainChain(pwallet->ifaceIndex) >= 1)
			continue;
		if (!pwallet->IsFromMe(*ptx))
			return false;

		if (mapPrev.empty())
		{
			BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
				mapPrev[tx.GetHash()] = &tx;
		}

		BOOST_FOREACH(const CTxIn& txin, ptx->vin)
		{
			if (!mapPrev.count(txin.prevout.hash))
				return false;
			vWorkQueue.push_back(mapPrev[txin.prevout.hash]);
		}
	}
	return true;
}


void CWallet::InitSpent(CWalletTx& wtx)
{
	vector<uint256> vout; /* out */
	int i;

	if (!wtx.ReadCoins(ifaceIndex, vout))
		return;

	wtx.vfSpent.resize(vout.size());
	for (i = 0; i < vout.size(); i++) {
		if (vout[i].IsNull())
			wtx.vfSpent[i] = false;
		else
			wtx.vfSpent[i] = true;
	}
}

#if 0
CKey *CWallet::toECKey(CKey *key)
{
	static const uint8_t version = DILITHIUM_VERSION;

	bool fCompressed = false;
  uint8_t buf[128];
	uint8_t seed[128];
	size_t seed_len;

	if (key->GetMethod() == SIGN_ALG_ECDSA) {
		return (key);
	} 

	const CSecret& keySecret = key->GetSecret(fCompressed);
	if (keySecret.size() > 128) {
		return (NULL);
	}

	cbuff keyBuff(keySecret.begin(), keySecret.end());
	memcpy(seed, keyBuff.begin(), keyBuff.size());
	seed_len = keyBuff.size(); 

  {
    shake256incctx state;

		memset(buf, 0, sizeof(buf));
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, (const uint8_t *)seed, seed_len);
    shake256_inc_absorb(&state, (const uint8_t *)&version, 1);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(buf, ECKey::ECDSA_SECRET_SIZE, &state);
  }

	ECKey eckey;
  if (!eckey.SetSecret(CSecret(buf, buf + ECKey::ECDSA_SECRET_SIZE)), true) {
		return (NULL);
	}

  if (!wallet->HaveKey(keyid)) {
		if (!wallet->AddKey(eckey)) {
			return (NULL);
		}

    SetAddressBookName(CTxDestination(keyid), 
const CTxDestination& address, const std::string& strName);
	}

	const CPubKey& pubkey = eckey.GetPubKey();
	return (GetKey(pubkey.GetID()));
}
#endif

