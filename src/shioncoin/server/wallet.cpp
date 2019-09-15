
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

#include "shcoind.h"
#include "wallet.h"
#include "wallettx.h"
#include "walletdb.h"
#include "crypter.h"
#include "ui_interface.h"
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

bool CWallet::GenerateNewECKey(CPubKey& pubkeyRet, bool fCompressed, int nFlag)
{
	ECKey key;

	{
		LOCK(cs_wallet);
		key.MakeNewKey(fCompressed);

	}

	key.meta.nFlag |= nFlag;
	if (!AddKey(key))
		return (false);

	pubkeyRet = key.GetPubKey();
	return (true);
}

bool CWallet::GenerateNewDIKey(CPubKey& pubkeyRet, int nFlag)
{
	DIKey key;

	{
		LOCK(cs_wallet);
		key.MakeNewKey();
	}

	key.meta.nFlag |= nFlag;
	if (!AddKey(key))
		return (false);

	pubkeyRet = key.GetPubKey();
	return (true);
}

bool CWallet::AddKey(const ECKey& key)
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

bool CWallet::AddKey(const DIKey& key)
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

#if 0
HDPubKey CWallet::GenerateNewHDKey(bool fCompressed)
{
	HDMasterPrivKey key;

	{
		LOCK(cs_wallet);

		key.MakeNewKey(fCompressed);

#if 0
		// Compressed public keys were introduced in version 0.6.0
		if (fCompressed)
			SetMinVersion(FEATURE_COMPRPUBKEY);
#endif

		if (!AddKey(key))
			throw std::runtime_error("CWallet::GenerateNewKey() : AddKey failed");
	}

	HDPubKey pubkey = key.GetMasterPubKey();
	return pubkey;
}
#endif

#if 0
bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
	if (!CBasicKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
		return false;
	{
		LOCK(cs_wallet);

		if (pwalletdbEncryption)
			return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret);

		CWalletDB db(strWalletFile);
		db.WriteCryptedKey(vchPubKey, vchCryptedSecret);
		db.Close();
	}

	return false;
}
#endif

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

#if 0
/**
 * Anytime a signature is successfully verified, it's proof the outpoint is spent.
 * Update the wallet spent flag if it doesn't know due to wallet.dat being
 * restored from backup or the user making copies of wallet.dat.
 */
void CWallet::WalletUpdateSpent(const CTransaction &tx)
{
	{
		LOCK(cs_wallet);
		BOOST_FOREACH(const CTxIn& txin, tx.vin)
		{
			map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
			if (mi != mapWallet.end())
			{
				CWalletTx& wtx = (*mi).second;
				if (txin.prevout.n >= wtx.vout.size()) {
					/* mis-match */
					error(SHERR_INVAL, "WalletUpdateSpent: tx '%s' has prevout-n >= vout-size.", wtx.GetHash().GetHex().c_str());
					continue;
				}

				if (!wtx.IsSpent(txin.prevout.n) && IsMine(wtx.vout[txin.prevout.n]))
				{
					//          Debug("WalletUpdateSpent found spent coin %sbc %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
					wtx.MarkSpent(txin.prevout.n);
					wtx.WriteToDisk();
					//NotifyTransactionChanged(this, txin.prevout.hash, CT_UPDATED);
				}
			}
		}
	}
}
#endif

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
#if 0
	uint256 hash = wtxIn.GetHash();
	{
		LOCK(cs_wallet);
		// Inserts only if not already there, returns tx inserted or tx found
		pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
		CWalletTx& wtx = (*ret.first).second;
		wtx.BindWallet(this);
		bool fInsertedNew = ret.second;
		if (fInsertedNew)
			wtx.nTimeReceived = GetAdjustedTime();

		bool fUpdated = false;
		if (!fInsertedNew)
		{
			// Merge
			if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
			{
				wtx.hashBlock = wtxIn.hashBlock;
				fUpdated = true;
			}
			if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
			{
				wtx.vMerkleBranch = wtxIn.vMerkleBranch;
				wtx.nIndex = wtxIn.nIndex;
				fUpdated = true;
			}
			if (wtxIn.strFromAccount != wtx.strFromAccount) {
				wtx.strFromAccount = wtxIn.strFromAccount;
				fUpdated = true;
			}
			if (wtxIn.hColor != 0 && wtx.hColor == 0) {
				wtx.hColor = wtxIn.hColor;
				fUpdated = true;
			}
			if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
			{
				wtx.fFromMe = wtxIn.fFromMe;
				fUpdated = true;
			}
			fUpdated |= wtx.UpdateSpent(wtxIn.vfSpent);
		}

		Debug("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString().substr(0,10).c_str(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

		// Write to disk
		if (fInsertedNew || fUpdated) {
#if 0
			if (!wtx.WriteToDisk())
				return false;
#endif
			WriteWalletTx(wtx);
		}

		// since AddToWallet is called directly for self-originating transactions, check for consumption of own coins
		WalletUpdateSpent(wtx);

		// Notify UI of new or updated transaction
		//NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);
	}
	return true;
#endif
	return (AddTx(wtxIn));
}

// Add a transaction to the wallet, or update it.
// pblock is optional, but should be provided if the transaction is known to be in a block.
// If fUpdate is true, existing transactions will be updated.
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
				// TODO: wtx.fCommit = true;
				wtx.SetMerkleBranch(pblock);
			}
			return AddToWallet(wtx);
		}
		else {
			WalletUpdateSpent(tx);
		}
	}
	return false;
#if 0
	return (AddTx(tx, pblock));
#endif
}

bool CWallet::EraseFromWallet(uint256 hash)
{
#if 0
	{
		LOCK(cs_wallet);
		if (mapWallet.erase(hash)) {
			CWalletDB db(strWalletFile);
			db.EraseTx(hash);
			db.Close();
		}
	}
#endif
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
#if 0
		map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
		if (mi != mapWallet.end())
		{
			const CWalletTx& prev = (*mi).second;
			if (txin.prevout.n < prev.vout.size())
				if (IsMine(prev.vout[txin.prevout.n]))
					return true;
		}
#endif
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
#if 0
		map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
		if (mi != mapWallet.end())
		{
			const CWalletTx& prev = (*mi).second;
			if (txin.prevout.n < prev.vout.size())
				if (IsMine(prev.vout[txin.prevout.n]))
					return prev.vout[txin.prevout.n].nValue;
		}
#endif
	}
	return 0;
}

bool CWallet::IsChange(const CTxOut& txout) const
{
	CTxDestination address;

	// TODO: fix handling of 'change' outputs. The assumption is that any
	// payment to a TX_PUBKEYHASH that is mine but isn't in the address book
	// is change. That assumption is likely to break when we implement multisignature
	// wallets that return change back into a multi-signature-protected address;
	// a better way of identifying which outputs are 'the send' and which are
	// 'the change' will need to be implemented (maybe extend CWalletTx to remember
	// which output, if any, was change).
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

#if 0
		if (nDebit > 0 && pwallet->IsChange(txout)) /* skip change */
			continue;
#endif

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


#if 0
void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
	BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
	{
		if (!tx.IsCoinBase())
		{
			uint256 hash = tx.GetHash();
			if (!txdb.ContainsTx(hash))
				RelayMessage(CInv(txdb.ifaceIndex, MSG_TX, hash), (CTransaction)tx);
		}
	}
	if (!IsCoinBase())
	{
		uint256 hash = GetHash();
		if (!txdb.ContainsTx(hash))
		{
			//printf("Relaying wtx %s\n", hash.ToString().substr(0,10).c_str());
			RelayMessage(CInv(txdb.ifaceIndex, MSG_TX, hash), (CTransaction)*this);
		}
	}
}
#endif






//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


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

// populate vCoins with vector of spendable COutputs
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

	if (strAccount.length() == 0) {
		/* include coinbase (non-mapped) pub-keys */
		std::set<CKeyID> keys;
		GetKeys(keys);
		BOOST_FOREACH(const CKeyID& key, keys) {
			if (mapAddressBook.count(key) == 0) { /* loner */
				vDest.push_back(CTxDestination(key));
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
//if (!pcoin->IsFinal(ifaceIndex)) continue;

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
#if 0
				opcodetype opcode;
				const CScript& script = pcoin->vout[i].scriptPubKey;
				CScript::const_iterator pc = script.begin();
				if (script.GetOp(pc, opcode) &&
						opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
					continue; /* not avail */
				}
#endif

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
#if 0
				else if (pcoin->strFromAccount == strAccount && 
						0 == mapAddressBook.count(dest)) {
					if (::IsMine(*this, dest)) {
						vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(ifaceIndex)));
					}
				}
#endif

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

#if 0
	// List of values less than target
	pair<int64, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
	coinLowestLarger.first = std::numeric_limits<int64>::max();
	coinLowestLarger.second.first = NULL;
#endif
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
#if 0
	return (SelectCoinsMinConf(nTargetValue, 1, 6, vCoins, setCoinsRet, nValueRet) ||
			SelectCoinsMinConf(nTargetValue, 1, 1, vCoins, setCoinsRet, nValueRet) ||
			SelectCoinsMinConf(nTargetValue, 0, 1, vCoins, setCoinsRet, nValueRet));
#endif
}

#if 0
string CWallet::SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
	CReserveKey reservekey(this);
	int64 nFeeRequired;

	if (!CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired))
	{
		string strError;
		if (nValue + nFeeRequired > GetBalance())
			strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds  "), FormatMoney(nFeeRequired).c_str());
		else
			strError = _("Error: Transaction creation failed  ");
		printf("SendMoney() : %s", strError.c_str());
		return strError;
	}

	if (fAskFee)
		return "ABORTED";

	if (!CommitTransaction(wtxNew)) {
		return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
	}

	return "";
}
#endif

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
#if 0
	CReserveKey reservekey(this);
#endif
	int64 nFeeRequired;

#if 0
	if (IsLocked())
	{
		string strError = _("Error: Wallet locked, unable to create transaction  ");
		printf("SendMoney() : %s", strError.c_str());
		return strError;
	}
#endif

	string strError;
	int nMinDepth = 1;
	int64 nBalance = GetAccountBalance(ifaceIndex, strFromAccount, nMinDepth);

#if 0
	if (!CreateAccountTransaction(strFromAccount, scriptPubKey, nValue, wtxNew, strError, nFeeRequired))
	{
		if (strError.length() == 0) {
			if (//nValue + nFeeRequired > GetBalance() ||
					nValue + nFeeRequired > nBalance) {
				strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds  "), FormatMoney(nFeeRequired).c_str());
			} else {
				strError = _("Error: Transaction creation failed  ");
			}
		}
		return strError;
	}

	if ((nValue + nFeeRequired) > nBalance) {
		string strError;
		strError = strprintf(_("Account \"%s\" has insufficient funds to initiate transaction [fee %f, balance %f]."), strFromAccount.c_str(), ((double)nFeeRequired/(double)COIN), ((double)nBalance/(double)COIN));
		return (strError);
	}

	if (fAskFee)
		return "ABORTED";

	if (!CommitTransaction(wtxNew)) {
		return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
	}
#endif

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

		CWalletDB db(strWalletFile);
		ok = db.WriteName(CCoinAddr(ifaceIndex, address).ToString(), strName);
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
#if 0
	{
		LOCK(cs_wallet);
		if (mapWallet.count(block.vtx[0].GetHash()))
		{
			CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
			printf("    mine:  %d  %d  %d", wtx.GetDepthInMainChain(ifaceIndex), wtx.GetBlocksToMaturity(ifaceIndex), wtx.GetCredit());
		}
	}
	printf("\n");
#endif
}

bool CWallet::GetTransaction(const uint256 &hashTx, CWalletTx& wtx)
{
#if 0
	{
		LOCK(cs_wallet);
		map<uint256, CWalletTx>::iterator mi = mapWallet.find(hashTx);
		if (mi != mapWallet.end())
		{
			wtx = (*mi).second;
			return true;
		}
	}
	return false;
#endif

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
#if 0
		vMerkleBranch.clear();
#endif
		nIndex = -1;
		//printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
		return 0;
	}

#if 0
	// Fill in merkle branch
	vMerkleBranch = pblock->GetMerkleBranch(nIndex);
#endif

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

CPubKey GetAccountPubKey(CWallet *wallet, string strAccount, bool bForceNew)
{
	bool bKeyUsed = false;
	bool bValid = false;
	bool bNew = false;
	CAccount account;
	CPubKey pubkey;

	{
		LOCK(wallet->cs_wallet);

		CWalletDB walletdb(wallet->strWalletFile);
		/* load from wallet */
		walletdb.ReadAccount(strAccount, account);
		bValid = account.vchPubKey.IsValid();
		walletdb.Close();
	}

	if (bForceNew && bValid) {
		/* check if the current key has been used */
		CScript scriptPubKey;
		scriptPubKey.SetDestination(account.vchPubKey.GetID());
		for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin();
				it != wallet->mapWallet.end() && account.vchPubKey.IsValid();
				++it)
		{
			const CWalletTx& wtx = (*it).second;
			BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
				if (txout.scriptPubKey == scriptPubKey) {
					bKeyUsed = true;
					break;
				}
			}
		}
	}

	if (!bValid) {
		/* first time -- generate primary key for account */
		bNew = true;
		account.vchPubKey = wallet->GenerateNewECKey(true);

		{
			LOCK(wallet->cs_wallet);

			CWalletDB walletdb(wallet->strWalletFile);
			walletdb.WriteAccount(strAccount, account);
			walletdb.Close();
		}

		pubkey = account.vchPubKey;
	} else if (bForceNew && bKeyUsed) {
		/* generate a new key */
		bNew = true;
		pubkey = wallet->GenerateNewECKey(true);
	} else {
		pubkey = account.vchPubKey;
	}

	if (bNew) {
		/* retain pubkey in addressbook in order to identify. */
		CKeyID keyID = pubkey.GetID();
		wallet->SetAddressBookName(keyID, strAccount);

		/* generate a standard CScriptID destination. */
		CScript scriptPubKey;
		scriptPubKey.SetDestination(keyID);
		wallet->AddCScript(scriptPubKey);
		CScriptID scriptID(scriptPubKey); 
		wallet->SetAddressBookName(scriptID, strAccount);

		CIface *iface = GetCoinByIndex(wallet->ifaceIndex); 
		if (iface && IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
			CCoinAddr addr(wallet->ifaceIndex, pubkey.GetID());

			/* generate "program 0" p2sh-segwit address. */
			CTxDestination sh_dest = addr.GetWitness(OUTPUT_TYPE_P2SH_SEGWIT);
			wallet->SetAddressBookName(sh_dest, strAccount);

			/* config option more controls whether bech32 will be dispensed then supported or not. */
//			if (opt_bool(OPT_BECH32)) {
				/* bech32 destination address. */
				CTxDestination be_dest = addr.GetWitness(OUTPUT_TYPE_BECH32);
				wallet->SetAddressBookName(be_dest, strAccount);
//			}
		}
	}

	return (pubkey);
}

CCoinAddr GetAccountAddress(CWallet *wallet, string strAccount, bool bForceNew)
{
	const CPubKey& pubkey = GetAccountPubKey(wallet, strAccount, bForceNew);
	return CCoinAddr(wallet->ifaceIndex, pubkey.GetID());
}

bool CWallet::GetMergedPubKey(string strAccount, const char *tag, CPubKey& pubkey)
{

	{
		LOCK(cs_wallet);

		CAccount account;
		ECKey pkey;

		CWalletDB walletdb(strWalletFile);
		walletdb.ReadAccount(strAccount, account);
		walletdb.Close();

		if (!account.vchPubKey.IsValid()) {
			account.vchPubKey = GenerateNewECKey(true);

			SetAddressBookName(account.vchPubKey.GetID(), strAccount);
			{
				CWalletDB walletdb(strWalletFile);
				walletdb.WriteAccount(strAccount, account);
				walletdb.Close();
			}
		}

		if (!GetECKey(account.vchPubKey.GetID(), pkey)) {
			return error(SHERR_INVAL, "CWallet::GetMergedAddress: account '%s' has no primary key.", strAccount.c_str());
		}

		cbuff tagbuff(tag, tag + strlen(tag)); 
		ECKey key;
		pkey.MergeKey(key, tagbuff);

		pubkey = key.GetPubKey();
		if (!pubkey.IsValid()) {
			return error(SHERR_INVAL, "CWallet.GetMergedAddress: generated pubkey is invalid.");
		}

		if (!HaveKey(pubkey.GetID())) {
			/* add key to address book */
			if (!AddKey(key)) {
				return error(SHERR_INVAL, "CWallet.GetMergedAddress: error adding generated key to wallet.");
			}

			SetAddressBookName(pubkey.GetID(), strAccount);
		}
	}

	return (true);
}

bool CWallet::GetMergedAddress(string strAccount, const char *tag, CCoinAddr& addrRet)
{

	{
		LOCK(cs_wallet);

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
				CCoinAddr returnAddr = GetAccountAddress(pwalletMain, wtxNew.strFromAccount, true);
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
#if 0
			// Sign
			int nIn = 0;
			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
				if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nIn++)) {
					return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
				}
			}
#endif

			/* Ensure transaction does not breach a defined size limitation. */
			unsigned int nWeight = pwalletMain->GetTransactionWeight(wtxNew);
			if (nWeight >= MAX_TRANSACTION_WEIGHT(iface)) {
				return error(SHERR_INVAL, "CreateTransactionWithInputTx: the transaction is too large.");
			}

			unsigned int nBytes = pwalletMain->GetVirtualTransactionSize(wtxNew);
			dPriority /= nBytes;

			// Check that enough fee is included
			int64 nPayFee = nTransactionFee * (1 + (int64) nBytes / 1000);
#if 0
			bool fAllowFree = pwalletMain->AllowFree(dPriority);
			int64 nMinFee = wtxNew.GetMinFee(ifaceIndex, 1, fAllowFree);
#endif
			int64 nMinFee = pwalletMain->CalculateFee(wtxNew);

			if (nFeeRet < max(nPayFee, nMinFee)) {
				nFeeRet = max(nPayFee, nMinFee);
				Debug("TEST: CreateTransactionWithInputTx: re-iterating (nFreeRet = %s)\n", FormatMoney(nFeeRet).c_str());
				continue;
			}

			// Fill vtxPrev by copying from previous transactions vtxPrev
			pwalletMain->AddSupportingTransactions(wtxNew);
			wtxNew.fTimeReceivedIsTxTime = true;
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
#if 0
			if (script.GetOp(pc, opcode) && /* ext type */
					script.GetOp(pc, opcode) && /* content */
					opcode == OP_HASH160)
#endif
				break;
		}

		idx++;
	}
	if (idx == tx.vout.size())
		return (-1); /* uh oh */

	return (idx);
}

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


bool GetCoinAddr(CWallet *wallet, CCoinAddr& addrAccount, string& strAccount)
{
	bool fIsScript = addrAccount.IsScript();

	if (!addrAccount.IsValid())
		return (false);

	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
	{
		const CCoinAddr& address = CCoinAddr(wallet->ifaceIndex, item.first);
		const string& account = item.second;

		if (fIsScript && !address.IsScript())
			continue;

		/* TODO: does not compare coinaddr version */
		if (address.Get() == addrAccount.Get()) {
			addrAccount = address;
			strAccount = account;
			return (true);
		}
	}

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

	if (strAddress.at(0) == '@') {
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

#if 0
bool CMerkleTx::AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs)
{
	if (fClient)
	{
		if (!IsInMainChain(txdb.ifaceIndex) && !ClientConnectInputs(txdb.ifaceIndex))
			return false;
		return CTransaction::AcceptToMemoryPool(txdb, false);
	}
	else
	{
		return CTransaction::AcceptToMemoryPool(txdb, fCheckInputs);
	}
}
#endif


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
	CBlockIndex *pindex;

	if (hashBlock == 0 || nIndex == -1)
		return 0;

	pindex = GetBlockIndexByHash(ifaceIndex, hashBlock);
	if (!pindex || !pindex->IsInMainChain(ifaceIndex))
		return 0;

#if 0
	// Make sure the merkle branch connects to this block
	if (!fMerkleVerified)
	{
		CBlock *block;
		if (ifaceIndex == COLOR_COIN_IFACE) {
			block = GetBlockByHash(iface, pindex->GetBlockHash());
		} else {
			block = GetBlockByHeight(iface, pindex->nHeight);
		}
		if (!block)
			return 0;
		if (block->CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot) {
			delete block;
			return 0;
		}
		fMerkleVerified = true;
		delete block;
	}
#endif

	pindexRet = pindex;

	CBlockIndex *pindexBest = NULL;
	if (ifaceIndex == COLOR_COIN_IFACE)  {
		/* count manually as each color has it's own 'best block index'. */
		pindexBest = pindex;
		
		while (pindexBest && pindexBest->pnext) {
			pindexBest = pindexBest->pnext;
		}
	} else {
		pindexBest = GetBestBlockIndex(ifaceIndex);
		if (!pindexBest)
			return (0);
	}

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
#if 0
				CIface *iface = GetCoinByIndex(ifaceIndex);
				int64 nMinimumInputValue = MIN_INPUT_VALUE(iface);
				if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) && pcoin->vout[i].nValue >= nMinimumInputValue)
					vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(ifaceIndex)));
#endif

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
#if 0
		int nIn = 0;
		BOOST_FOREACH(const COutput& out, vecRecv) {
			if (!SignSignature(*wallet, *out.tx, wtxNew, nIn++)) {
				return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
			}
		}
#endif

		wallet->AddSupportingTransactions(wtxNew);
		wtxNew.fTimeReceivedIsTxTime = true;
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


#if 0
bool CreateExtTransactionFromAddrTx(CIface *iface, 
		const CCoinAddr& sendAddr, const CTransaction& wtxIn,
		CWalletTx& wtxNew, CReserveKey& reservekey)
{
	int ifaceIndex = GetCoinIndex(iface);
	CWallet *wallet = GetWallet(iface);
	int64 nFee = 0;

#if 0
	BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
		if (nValue < 0) {
			return error(SHERR_INVAL, "CreateTransactionWIthInputTx: nValue < 0\n");
		}
		nValue += s.second;
	}
	if (vecSend.empty() || nValue < 0) {
		return error(SHERR_INVAL, "CreateTransactionWIthInputTx: vecSend.empty()\n");
	}
#endif

	wtxNew.BindWallet(wallet);

	{
		vector<COutput> vCoins;
		int64 nTotalValue = 0;
		int64 nValue;

		wallet->AvailableAddrCoins(vCoins, sendAddr, nTotalValue, true); 

		nFee = iface->min_tx_fee;
		/* rought estimate ~ 200b per input */
		nFee += (vCoins.size() * 20);

		loop {
			wtxNew.vin.clear();
			wtxNew.vout.clear();
			wtxNew.fFromMe = true;

			int64 nValue = nTotalValue - nFee;
			if (nValue < iface->min_input)
				return error(SHERR_INVAL, "transaction too large."); /* remove/limit vCoins? */

			//      int64 nTotalValue = nValue + nFee;
			//      double dPriority = 0;

			CScript scriptPub;
			scriptPub.SetDestination(sendAddr.Get());
			wtxNew.vout.push_back(CTxOut(nTotalValue - nFee, scriptPub));

#if 0
			// vouts to the payees
			BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
				wtxNew.vout.push_back(CTxOut(s.second, s.first));

			int64 nWtxinCredit = wtxIn.vout[nTxOut].nValue;

			// Choose coins to use
			set<pair<const CWalletTx*, unsigned int> > setCoins;
			int64 nValueIn = 0;
			if (nTotalValue - nWtxinCredit > 0) {
				if (!wallet->SelectCoins(nTotalValue - nWtxinCredit,
							setCoins, nValueIn)) {
					return error(SHERR_INVAL, "CreateTransactionWithInputTx: error selecting coins\n"); 
				}
			}
#endif

#if 0
			vector<pair<const CWalletTx*, unsigned int> > vecCoins(
					setCoins.begin(), setCoins.end());

			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
				int64 nCredit = coin.first->vout[coin.second].nValue;
				dPriority += (double) nCredit
					* coin.first->GetDepthInMainChain(ifaceIndex);
			}
#endif

#if 0
			// Input tx always at first position
			vecCoins.insert(vecCoins.begin(), make_pair(&wtxIn, nTxOut));
#endif

#if 0
			nValueIn += nWtxinCredit;
			dPriority += (double) nWtxinCredit * wtxIn.GetDepthInMainChain(ifaceIndex);
#endif

#if 0
			// Fill a vout back to self (new addr) with any change
			int64 nChange = MAX(0, nValueIn - nTotalValue - nTxFee);
			if (nChange >= CENT) {
				CCoinAddr returnAddr = GetAccountAddress(wallet, wtxNew.strFromAccount, true);
				CScript scriptChange;

				if (returnAddr.IsValid()) {
					/* return change to sender */
					scriptChange.SetDestination(returnAddr.Get());
				} else {
					/* use supplied addr */
					CPubKey pubkey = reservekey.GetReservedKey();
					scriptChange.SetDestination(pubkey.GetID());
				}

				/* include as first transaction. */
				vector<CTxOut>::iterator position = wtxNew.vout.begin();
				wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
			}
#endif

			BOOST_FOREACH(const COutput& out, vCoins) {
				wtxNew.vin.push_back(CTxIn(out.tx->GetHash(), (unsigned int)out.i));
			}
#if 0
			// Fill vin
			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
				wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));
#endif

			int nIn = 0;
			BOOST_FOREACH(const COutput& out, vCoins) {
				if (!SignSignature(*wallet, *out.tx, wtxNew, nIn++)) {
					return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
				}
			}
#if 0
			// Sign
			int nIn = 0;
			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
				if (!SignSignature(*wallet, *coin.first, wtxNew, nIn++)) {
					return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
				}
			}
#endif

			unsigned int nBytes = ::GetSerializeSize(*(CTransaction*) &wtxNew,
					SER_NETWORK, PROTOCOL_VERSION(iface));
			if (nBytes >= MAX_BLOCK_SIZE_GEN(iface)) {
				return error(SHERR_INVAL, "CreateTransactionWithInputTx: tx too big");
			}
#if 0
			dPriority /= nBytes;
			// Check that enough fee is included
			int64 nPayFee = nTransactionFee * (1 + (int64) nBytes / 1000);
#endif

			int64 nMinFee = wtxNew.GetMinFee(ifaceIndex, 1, false);
			if (nFee < nMinFee) {
				nFee = nMinFee;
				Debug("TEST: CreateTransactionWithInputTx: re-iterating (nFreeRet = %s)\n", FormatMoney(nFee).c_str());
				continue;
			}

			// Fill vtxPrev by copying from previous transactions vtxPrev
			wallet->AddSupportingTransactions(wtxNew);
			wtxNew.fTimeReceivedIsTxTime = true;
			break;
		}

	}

	Debug("CreateTransactionFromAddrTx: commit '%s'", wtxNew.ToString().c_str());
	return true;
}
#endif

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

#if 0
	if (!wallet->FillInputs(tx, inputs, true))
		return (error(ERR_INVAL, "(%s) core_UnacceptWalletTranasction: error retrieving inputs for tx \"%s\".", tx_hash.GetHex().c_str()));
	BOOST_FOREACH(const CTxIn& in, tx.vin) {
		vIn.insert(vIn.end(), in);
	}
#endif

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

#if 0 /* we check above to ensure it's not in tx fmap */
		/* erase from 'tx' fmap */
		tx_p->EraseTx(ifaceIndex);
#endif
	}

	/* mark inputs unspent */
	BOOST_FOREACH(const CTxIn& in, vIn) {
		const uint256& prevhash = in.prevout.hash;
		
		if (wallet->HasTx(prevhash)) {
			CWalletTx& wtx = wallet->GetTx(prevhash);
#if 0
		if (wallet->mapWallet.count(prevhash) != 0) {
			CWalletTx& wtx = wallet->mapWallet[prevhash];
#endif

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
//			wtx.MarkDirty();
#if 0
			wtx.WriteToDisk();
#endif
			/* -> active */
			wallet->WriteWalletTx(wtx);
			wallet->mapWallet[prevhash] = wtx;
			wallet->EraseArchTx(prevhash);

			Debug("(%s) core_UnacceptWalletTransaction: marked tx \"%s\" output #%d as unspent in wallet.\n", iface->name, prevhash.GetHex().c_str(), in.prevout.n); 
		}

#if 0 /* the coin fmap is not filled until tx is confirmed. */
		if (inputs.count(prevhash) != 0) {
			CTransaction& prevTx = inputs[prevhash]; 
			int nTxOut = in.prevout.n;
			vector<uint256> vOuts;

			if (prevTx.ReadCoins(ifaceIndex, vOuts))
				continue;

			/* sanity */
			if (nTxOut >= vOuts.size())
				continue;

			if (vOuts[nTxOut].IsNull())
				continue;

			/* set output as unspent */
			vOuts[nTxOut].SetNull();
			prevTx.WriteCoins(ifaceIndex, vOuts);
		} else {
			Debug("(%s) core_UnacceptWalletTransaction: warning: unknown input tx \"%s\".", iface->name, prevhash.GetHex().c_str());
		}
#endif
	}

	return (true);
}


#if 0
/* not used, intended as generic interface */
bool core_CreateWalletAccountTransaction(CWallet *wallet, string strFromAccount, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, string& strError, int64& nFeeRet)
{
	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);

	wtxNew.strFromAccount = strFromAccount;

	int64 nValue = 0;
	BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
	{
		if (nValue < 0) {
			strError = "invalid output coin value";
			return false;
		}
		nValue += s.second;
	}
	if (vecSend.empty() || nValue < 0) {
		strError = "incomplete output specified";
		return false;
	}

	wtxNew.BindWallet(wallet);

	{
		//LOCK2(cs_main, cs_wallet);
		{
			nFeeRet = 0;

			loop
			{
				wtxNew.vin.clear();
				wtxNew.vout.clear();
				wtxNew.wit.SetNull();
				wtxNew.fFromMe = true;

				int64 nTotalValue = nValue + nFeeRet;
				double dPriority = 0;
				// vouts to the payees
				BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
					wtxNew.vout.push_back(CTxOut(s.second, s.first));

				// Choose coins to use
				set<pair<const CWalletTx*,unsigned int> > setCoins;
				int64 nValueIn = 0;
				if (!wallet->SelectAccountCoins(strFromAccount, nTotalValue, setCoins, nValueIn)) {
					strError = "An error occurred obtaining sufficient coins in order perform the transaction. Check the transaction fee cost.";
					return false;
				}
				BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
				{
					int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
					dPriority += (double)nCredit * pcoin.first->GetDepthInMainChain(wallet->ifaceIndex);
				}

				int64 nChange = nValueIn - nValue - nFeeRet;
				// if sub-cent change is required, the fee must be raised to at least SHC_MIN_TX_FEE
				// or until nChange becomes zero
				// NOTE: this depends on the exact behaviour of GetMinFee
				if (nFeeRet < MIN_TX_FEE(iface) && nChange > 0 && nChange < CENT)
				{
					int64 nMoveToFee = min(nChange, MIN_TX_FEE(iface) - nFeeRet);
					nChange -= nMoveToFee;
					nFeeRet += nMoveToFee;
				}

				int64 minValue = (int64)MIN_INPUT_VALUE(iface);
				if (nChange >= minValue) {
					CPubKey vchPubKey = GetAccountPubKey(wallet, strFromAccount, true);

					CScript scriptChange;
					scriptChange.SetDestination(vchPubKey.GetID());

					// Insert change txn at random position:
					vector<CTxOut>::iterator position = wtxNew.vout.begin()+GetRandInt(wtxNew.vout.size());
					wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
				}

				// Fill vin
				BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
					wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

				unsigned int nIn = 0;
				BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
					CSignature sig(wallet->ifaceIndex, &wtxNew, nIn);
					const CWalletTx *s_wtx = coin.first;
					if (!sig.SignSignature(*s_wtx)) {
						return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
					}

					nIn++;
				}
#if 0
				// Sign
				int nIn = 0;
				BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
					const CWalletTx *s_wtx = coin.first;
					if (!SignSignature(*wallet, *s_wtx, wtxNew, nIn)) {

#if 0
						/* failing signing against prevout. mark as spent to prohibit further attempts to use this output. */
						s_wtx->MarkSpent(nIn);
#endif

						strError = strprintf(_("An error occurred signing the transaction [input tx \"%s\", output #%d]."), s_wtx->GetHash().GetHex().c_str(), nIn);
						return false;
					}
					nIn++;
				}
#endif

				/* Ensure transaction does not breach a defined size limitation. */
				unsigned int nWeight = wallet->GetTransactionWeight(wtxNew);
				if (nWeight >= MAX_TRANSACTION_WEIGHT(iface)) {
					strError = "The transaction is too large.";
					return false;
				}

				unsigned int nBytes = wallet->GetVirtualTransactionSize(wtxNew);
				dPriority /= nBytes;

				// Check that enough fee is included
				int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
#if 0
				bool fAllowFree = wallet->AllowFree(dPriority);
				int64 nMinFee = wtxNew.GetMinFee(wallet->ifaceIndex, 1, fAllowFree, GMF_SEND);
#endif
				int64 nMinFee = wallet->CalculateFee(wtxNew);

				if (nFeeRet < max(nPayFee, nMinFee))
				{
					nFeeRet = max(nPayFee, nMinFee);
					continue;
				}

				/* established acceptable parameters */
				break;
			}
		}
	}

	return true;
}
#endif

	template <typename T>
std::vector<unsigned char> ToByteVector(const T& in)
{       
	return std::vector<unsigned char>(in.begin(), in.end());
}   

#if 0
CScript GetScriptForWitness(const CScript& redeemscript)
{
	CScript ret;

	txnouttype typ;
	std::vector<std::vector<unsigned char> > vSolutions;
	if (Solver(redeemscript, typ, vSolutions)) {
		if (typ == TX_PUBKEY) {
			/*
				 unsigned char h160[20];
				 CHash160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(h160);
				 ret << OP_0 << std::vector<unsigned char>(&h160[0], &h160[20]);
			 *
			 */
			cbuff vch(vSolutions[0].begin(), vSolutions[0].end());
			uint160 h160 = Hash160(vch);
			ret << OP_0 << h160;
			return ret;
		} else if (typ == TX_PUBKEYHASH) {
			ret << OP_0 << vSolutions[0];
			return ret;
		}
	}

	uint256 hash;
	//  CSHA256().Write(&redeemscript[0], redeemscript.size()).Finalize(hash.begin());
	hash = Hash(redeemscript.begin(), redeemscript.end());
	ret << OP_0 << ToByteVector(hash);

	return ret;
}
#endif

#if 0
bool CWallet::GetWitnessAddress(CCoinAddr& addr, CCoinAddr& witAddr)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	string strAccount;
	CTxDestination result; 

	{
		LOCK(cs_wallet);

		if (!addr.IsValid())
			return error(SHERR_INVAL, "GetWitnessAddress: invalid address specified.");

		if (!IsWitnessEnabled(iface, GetBestBlockIndex(iface)))
			return error(SHERR_INVAL, "GetWitnessAddress: seg-wit not enabled.");

		if (!GetCoinAddr((CWallet *)this, addr, strAccount))
			return error(SHERR_ACCESS, "GetWitnessAddress: cannot generate witness address from a non-local coin address.");

		bool fBech = false;
		if (GetCoinIndex(iface) != EMC2_COIN_IFACE &&
				opt_bool(OPT_BECH32))
			fBech = true;

		CKeyID keyID;
		CScriptID scriptID;
		if (addr.GetKeyID(keyID)) {
			CKey key;
			if (!GetKey(keyID, key)) {
				return (error(SHERR_ACCESS, "GetWitnessAddress: cannot generate witness address from a non-local coin address."));
			}

			// Signing with uncompressed keys is disabled in witness scripts
			if (!key.IsCompressed()) {
				return (error(SHERR_INVAL, "GetWitnessAddress: generating witness program signature unsupportd for non-compressed key."));
			}


			CScript basescript = GetScriptForDestination(keyID);

#if 0
			if (!::IsMine(*this, basescript, true))
				return error(SHERR_ACCESS, "GetWitnessAddress: cannot create witness address from non-local pub-key address.");
#endif
	//  CSHA256().Write(&redeemscript[0], redeemscript.size()).Finalize(hash.begin());

			/* witness program for p2wsh */
			CScript witscript = GetScriptForWitness(basescript);
			this->AddCScript(witscript);

			if (!fBech) {
				result = CScriptID(witscript);
			} else {
				WitnessV0KeyHash hash(keyID);
				result = hash;
			}
		} else if (addr.GetScriptID(scriptID)) {
			CScript subscript;
			if (this->GetCScript(scriptID, subscript)) {
				int witnessversion;
				std::vector<unsigned char> witprog;
				if (subscript.IsWitnessProgram(witnessversion, witprog)) {
					/* ID is already for a witness program script */
					result = scriptID;
				} else {
#if 0
					//isminetype typ;
					//typ = IsMine(*pthisMain, subscript, SIGVERSION_WITNESS_V0);
					//if (typ != ISMINE_SPENDABLE && typ != ISMINE_WATCH_SOLVABLE)
					if (!::IsMine(*this, subscript, true))
						return error(SHERR_ACCESS, "GetWitnessAddress: cannot create witness address from non-local script address.");
#endif

					CScript witscript = GetScriptForWitness(subscript);
					this->AddCScript(witscript);
					
					if (!fBech) {
						result = CScriptID(witscript);
					} else {
						WitnessV0ScriptHash hash;
						SHA256((unsigned char *)&subscript[0], subscript.size(), (unsigned char *)&hash);
						result = hash;
					}
				}
			}
		} else {
			return error(SHERR_ACCESS, "GetWitnessAddress: cannot create witness address from non-standard address.");
		}

		/* retain in addressbook in order to identify */
		this->SetAddressBookName(result, strAccount);

		/* fill in return variable */
		witAddr = CCoinAddr(ifaceIndex, result);
	}

	return (true);
}
#endif

bool CWallet::GetWitnessAddress(CCoinAddr& addr, CCoinAddr& witAddr)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	CTxDestination dest;
	string strAccount;

	if (!iface || !iface->enabled)
		return (false);

	if (!addr.IsValid())
		return error(SHERR_INVAL, "GetWitnessAddress: invalid address specified.");

	if (!IsWitnessEnabled(iface, GetBestBlockIndex(iface)))
		return error(SHERR_INVAL, "GetWitnessAddress: seg-wit not enabled.");

	if (!GetCoinAddr((CWallet *)this, addr, strAccount))
		return error(SHERR_ACCESS, "GetWitnessAddress: cannot generate witness address from a non-local coin address.");

	/* convert to segwit addr. */
	dest = addr.GetWitness();
	if (dest == CTxDestination(CNoDestination())) {
		return error(SHERR_ACCESS, "GetWitnessAddress: error converting address into a segwit program.");
		return (false);
	}

	{ /* retain in addressbook in order to identify */
		LOCK(cs_wallet);
		this->SetAddressBookName(dest, strAccount);
	}

	/* fill in return variable */
	witAddr = CCoinAddr(ifaceIndex, dest);

	return (true);
}

int64 CWallet::CalculateFee(CWalletTx& tx, int64 nMinFee)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	int64 nBytes;
	int64 nFee;

	nBytes = (int64)GetVirtualTransactionSize(tx); 
	//nBytes = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION(iface));

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

	int64 nEstFee = 0;
	CBlockPolicyEstimator *est = GetFeeEstimator(iface);
	if (est) {
		static const unsigned int confTarget = 2;
		nEstFee = est->estimateSmartFee(confTarget, NULL).GetFee(nBytes);
		if (nEstFee > nFee) {
			nFee = nEstFee;
//			Debug("CWallet.CalculateFee: using estimated fee %f.", (double)nFee/COIN);
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
				return (error(SHERR_INVAL, "FillInputs: unknown tx hash \"%s\".", prev_hash.GetHex().c_str()));
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
	BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, wallet->mapWallet) {
		const uint256& tx_hash = item.first;
		CWalletTx& wtx = item.second;
		vector<uint256> vOuts;

		if (wtx.IsCoinBase())
			continue; /* not applicable */

		/* need to be careful here to still add supporting tx's */
		for (i = 0; i < wtx.vfSpent.size(); i++) {
			if (wtx.vfSpent[i])
				break;
		}
		if (i != wtx.vfSpent.size())
			continue; /* already [at least partially] spent. */

		pindex = GetBlockIndexByTx(iface, tx_hash);
		if (!pindex) {
			/* reaccept into mempool. */
			if (!wtx.AcceptWalletTransaction()) {
				Debug("(%s) ReacceptWalletTransactions: warning: unresolvable tx \"%s\".", iface->name, wtx.GetHash().GetHex().c_str());
				vErase.push_back(tx_hash);
			}
		} else {
			/* reference highest block with stored wallet tx */
			if (!min_pindex || min_pindex->nHeight < pindex->nHeight)
				min_pindex = pindex;
		}
	}
#if 0
	BOOST_FOREACH(const uint256& tx_hash, vErase) {
		wallet->EraseFromWallet(tx_hash);
	}
#endif

	/* rescan from height of newest wallet tx */
	if (min_pindex)
		wallet->ScanForWalletTransactions(min_pindex);

}


#if 0
bool CWallet::ReadTx(uint256 hash, CWalletTx& wtx)
{
	CIface *iface;
	bc_t *bc;
	unsigned char *data;
	size_t data_len;
	bcpos_t posTx;
	int err;

	iface = GetCoinByIndex(ifaceIndex);
	if (!iface)
		return (false);

	bc = GetWalletTxChain(iface);
	if (!bc)
		return (false);

	err = bc_find(bc, hash.GetRaw(), &posTx);
	if (err)
		return (false);

	err = bc_get(bc, posTx, &data, &data_len);
	if (err)
		return (error(err, "bc_get [CWallet.ReadTx]"));

	CDataStream sBlock(SER_DISK, CLIENT_VERSION);
	sBlock.write((const char *)data, data_len);
	sBlock >> wtx;
	free(data);

	return (true);
}
bool CWallet::WriteTx(uint256 hash, const CWalletTx& wtx)
{
	CDataStream sBlock(SER_DISK, CLIENT_VERSION);
	CIface *iface = GetCoinByIndex(ifaceIndex);
	bc_t *bc = GetWalletTxChain(iface);
	char *sBlockData;
	size_t sBlockLen;
	bcpos_t posTx;
	int err;

	err = bc_find(bc, hash.GetRaw(), &posTx);
	if (!err)
		return (true); /* already written. */

	sBlock << wtx;
	sBlockLen = sBlock.size();
	sBlockData = (char *)calloc(sBlockLen, sizeof(char));
	if (!sBlockData)
		return (false);

	sBlock.read(sBlockData, sBlockLen);
	err = bc_append(bc, hash.GetRaw(), sBlockData, sBlockLen); 
	if (err < 0)
		return (error(err, "bc_append [CWallet.WriteTx]"));

	return (true);
}
bool CWallet::EraseTx(uint256 hash)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	bc_t *bc = GetBlockTxChain(iface);
	bcpos_t posTx;
	int err;

	err = bc_find(bc, hash.GetRaw(), &posTx);
	if (err)
		return (false);

	bc_table_reset(bc, hash.GetRaw());
	err = bc_idx_clear(bc, posTx);
	if (err)
		return (error(err, "bc_idx_clear [CWallet.EraseTx]"));

	return (true);
}
#endif

CAccountCache *CWallet::GetAccount(string strAccount)
{
	if (mapAddrCache.count(strAccount) == 0) {
		CAccountCache *ca = new CAccountCache(this);
		CPubKey pubkey;

		ca->strAccount = strAccount;
		ca->account.SetNull();

		{
			LOCK(cs_wallet);

			/* load from wallet */
			CWalletDB walletdb(strWalletFile);
			walletdb.ReadAccount(strAccount, ca->account);
			walletdb.Close();
		}

		bool bValid = ca->account.vchPubKey.IsValid();
		if (!bValid) {
			ca->CreateNewPubKey(ca->account.vchPubKey, 0);
		}

		mapAddrCache[strAccount] = ca;
	}

	return (mapAddrCache[strAccount]);
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
	return (GetAccount("@"+strAccount)->GetAddr(ACCADDR_EXT));
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

#if 0
static void wallet_UpdateSpent(CWallet *wallet, const CTransaction &tx)
{

	BOOST_FOREACH(const CTxIn& txin, tx.vin) {
		map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(txin.prevout.hash);
		if (mi != wallet->mapWallet.end()) {
			CWalletTx& wtx = (*mi).second;
			if (txin.prevout.n >= wtx.vout.size()) {
				/* mis-match */
				continue;
			}

			if (!wtx.IsSpent(txin.prevout.n)) {
				wtx.MarkSpent(txin.prevout.n);
			}
		}
	}

}
bool CWallet::AddWalletTx(CWalletTx& wtx)
{
	const uint256& hash = wtx.GetHash();
	bool ok;

	if (!IsFromMe(wtx) && !IsMine(wtx))
		return (true);

	{ /* mark any spent not already */
		LOCK(cs_wallet);
		wallet_UpdateSpent(this, wtx);
	}
	
	/* check whether all outputs have been spent. */
	bool fArch = true;
	unsigned int idx;
	for (idx = 0; idx < wtx.vout.size(); idx++) {
		if (!wtx.IsSpent(idx)) {
			fArch = false;
			break;
		}
	}

	if (!fArch) { /* active local wallet transaction database. */
		LOCK(cs_wallet);

		/* write to actively tracked storage. */
		CWalletDB wtx_db(wallet_wtx_filename(this), "cr+");
		ok = wtx_db.WriteTx(hash, wtx);
		wtx_db.Close();
	} else { /* archived wallet transaction database. */
		/* write to arch wtx db */
		ok = WriteTx(hash, wtx);
		if (ok) {
			LOCK(cs_wallet);

			/* remove from actively tracked transactions. */
			CWalletDB wtx_db(wallet_wtx_filename(this), "cr+");
			wtx_db.EraseTx(hash);
			wtx_db.Close();
		}
	}

	return (ok);
}
bool CWallet::RemoveWalletTx(CWalletTx& wtx)
{
	const uint256& hash = wtx.GetHash();

	/* remove from active storage. no records are removed from arch. */
	{
		LOCK(cs_wallet);
		CWalletDB wtx_db(wallet_wtx_filename(this), "cr+");
		wtx_db.EraseTx(hash);
		wtx_db.Close();
	}

	return (true);
}
#endif


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

bool CWallet::DeriveNewECKey(CHDChain *hdChain, ECKey& secret, bool internal)
{
	// for now we use a fixed keypath scheme of m/0'/0'/k
	ECExtKey masterKey;             //hd master key
	ECExtKey accountKey;            //key at m/0'
	ECExtKey chainChildKey;         //key at m/0'/0' (external) or m/0'/1' (internal)
	ECExtKey childKey;              //key at m/0'/0'/<n>'
	string hdKeypath;

	if (!hdChain)
		return (false);

	CKey *key = GetKey(hdChain->masterKeyID);
	if (!key)
		return (false);

	masterKey.SetMaster(key->begin(), key->size());

	// derive m/0'
	// use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
	masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

	// derive m/0'/0' (external chain) OR m/0'/1' (internal chain)
//	assert(internal ? CanSupportFeature(FEATURE_HD_SPLIT) : true);
	accountKey.Derive(chainChildKey, BIP32_HARDENED_KEY_LIMIT+(internal ? 1 : 0));

	// derive child key at next index, skip keys already known to the wallet
	do {
		// always derive hardened keys
		// childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
		// example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
		if (internal) {
			chainChildKey.Derive(childKey, hdChain->nInternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
			hdKeypath = "m/0'/1'/" + std::to_string(hdChain->nInternalChainCounter) + "'";
			hdChain->nInternalChainCounter++;
		}
		else {
			chainChildKey.Derive(childKey, hdChain->nExternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
			hdKeypath = "m/0'/0'/" + std::to_string(hdChain->nExternalChainCounter) + "'";
			hdChain->nExternalChainCounter++;
		}
	} while (HaveKey(childKey.key.GetPubKey().GetID()));

	secret = childKey.key;
	secret.meta.hdMasterKeyID = hdChain->masterKeyID;
	secret.meta.hdKeypath = hdKeypath;

//	acc->UpdateHDChain();
#if 0
	{
		LOCK(cs_wallet);

		CWalletDB walletdb(strWalletFile);
		walletdb.WriteHDChain(hdChain);
		walletdb.Close();
	}
#endif

	return (true);
}

bool CWallet::DeriveNewDIKey(CHDChain *hdChain, DIKey& secret, bool internal)
{
	// for now we use a fixed keypath scheme of m/0'/0'/k
	DIExtKey masterKey;             //hd master key
	DIExtKey accountKey;            //key at m/0'
	DIExtKey chainChildKey;         //key at m/0'/0' (external) or m/0'/1' (internal)
	DIExtKey childKey;              //key at m/0'/0'/<n>'
	string hdKeypath;

	if (!hdChain)
		return (false);

	CKey *key = GetKey(hdChain->masterKeyID);
	if (!key)
		return (false);

	masterKey.SetMaster(key->begin(), key->size());

	// derive m/0'
	// use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
	masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

	// derive m/0'/0' (external chain) OR m/0'/1' (internal chain)
//	assert(internal ? CanSupportFeature(FEATURE_HD_SPLIT) : true);
	accountKey.Derive(chainChildKey, BIP32_HARDENED_KEY_LIMIT+(internal ? 1 : 0));

	// derive child key at next index, skip keys already known to the wallet
	do {
		// always derive hardened keys
		// childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
		// example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
		if (internal) {
			chainChildKey.Derive(childKey, hdChain->nInternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
			hdKeypath = "m/0'/1'/" + std::to_string(hdChain->nInternalChainCounter) + "'";
			hdChain->nInternalChainCounter++;
		}
		else {
			chainChildKey.Derive(childKey, hdChain->nExternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
			hdKeypath = "m/0'/0'/" + std::to_string(hdChain->nExternalChainCounter) + "'";
			hdChain->nExternalChainCounter++;
		}
	} while (HaveKey(childKey.key.GetPubKey().GetID()));

	secret = childKey.key;
	secret.meta.hdMasterKeyID = hdChain->masterKeyID;
	secret.meta.hdKeypath = hdKeypath;

	return (true);
}

bool CWallet::LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata &meta)
{
	LOCK(cs_wallet);
	//UpdateTimeFirstKey(meta.nCreateTime);
	mapKeyMetadata[keyID] = meta;
	return true;
}

bool CWallet::LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata &meta)
{
	LOCK(cs_wallet);
	//UpdateTimeFirstKey(meta.nCreateTime);
	mapScriptMetadata[script_id] = meta;
	return true;
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

