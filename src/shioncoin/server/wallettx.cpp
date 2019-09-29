
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

static bool wallet_MergeTx(CWallet *wallet, const uint256& hash, const CWalletTx& wtxIn, CWalletTx& wtx)
{
	bool fUpdated = false;

	if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock) {
		wtx.hashBlock = wtxIn.hashBlock;
		fUpdated = true;
	}
	if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex)) {
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

	return (fUpdated);
}

void CWallet::WalletUpdateSpent(const CTransaction &tx)
{

	{
		LOCK(cs_wallet);

		vector<uint256> vSave;
		BOOST_FOREACH(const CTxIn& txin, tx.vin) {
			map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
			if (mi == mapWallet.end())
				continue;

			const uint256& hash = (*mi).first;
			CWalletTx& wtx = (*mi).second;

			if (txin.prevout.n >= wtx.vout.size())
				continue;

			if (!wtx.IsSpent(txin.prevout.n)) {
				wtx.MarkSpent(txin.prevout.n);

				if (std::find(vSave.begin(), vSave.end(), hash) == vSave.end()) {
					vSave.push_back(hash);
				}
			}
		}

		for (unsigned int i = 0; i < vSave.size(); i++) {
			const uint256& hash = vSave[i];
			map<uint256, CWalletTx>::iterator mi = mapWallet.find(hash);
			if (mi == mapWallet.end()) continue;
			CWalletTx& wtx = (*mi).second;

			/* archive wallet transaction if all outputs are spent. */
			bool fArch = true;
			unsigned int idx;
			for (idx = 0; idx < wtx.vout.size(); idx++) {
				if (!wtx.IsSpent(idx)) {
					fArch = false;
					break;
				}
			}
			if (fArch) {
				WriteArchTx(wtx);
				EraseWalletTx(hash);
			} else {
				WriteWalletTx(wtx);
			}
		}
	}

}

bool CWallet::HasTx(const uint256 hTx) const
{
	if (mapWallet.count(hTx) != 0)
		return (true);

	return (HasArchTx(hTx));
}

CWalletTx& CWallet::GetTx(const uint256& hTx)
{

	map<uint256, CWalletTx>::iterator mi = mapWallet.find(hTx);
	if (mi != mapWallet.end())
		return (*mi).second;

	if (HasArchTx(hTx)) {
		CWalletTx& wtxArch = mapWallet[hTx];
		if (ReadArchTx(hTx, wtxArch)) {
			wtxArch.BindWallet(this);
			for (int i = 0; i < wtxArch.vout.size(); i++)
				wtxArch.MarkSpent(i); /* redundant */
			return (wtxArch);
		}
	}

	Debug("CWallet::GetTx: warning: no transaction found '%s'.", hTx.GetHex().c_str()); 
	/* empty */
	static CWalletTx wtx;
	wtx = CWalletTx();
	return (wtx);
}

bool CWallet::AddTx(const uint256& hTx, const CBlock *pblock)
{
	CTransaction tx;

	if (!tx.ReadTx(ifaceIndex, hTx))
		return (false);

	return (AddTx(hTx, pblock));
}

bool CWallet::AddTx(const CTransaction& tx, const CBlock* pblock)
{
	CWalletTx wtx(this, tx);

	if (pblock) {
		wtx.SetMerkleBranch(pblock);
	}

	return (AddTx(wtx));
}

bool CWallet::AddTx(const CWalletTx& wtxIn)
{
#if 0

//	if (IsFromMe(wtxIn) || IsMine(wtxIn)) 
	{
		const uint256& hash = wtxIn.GetHash();

		{
			LOCK(cs_wallet);

			pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
			CWalletTx& wtx = (*ret.first).second;
			wtx.BindWallet(this);
			bool fInsertedNew = ret.second;
			if (fInsertedNew)
				wtx.nTimeReceived = GetAdjustedTime();

			bool fUpdated = false;
			if (!fInsertedNew) { // Merge
				if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock) {
					wtx.hashBlock = wtxIn.hashBlock;
					fUpdated = true;
				}
				if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex)) {
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
				if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe) {
					wtx.fFromMe = wtxIn.fFromMe;
					fUpdated = true;
				}
				fUpdated |= wtx.UpdateSpent(wtxIn.vfSpent);
			}

			Debug("AddToWallet %s  %s%s\n", wtxIn.GetHash().GetHex().c_str(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

#if 0
			pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
			CWalletTx& wtx = (*ret.first).second;
			bool fInsertedNew = ret.second;

			wtx.BindWallet(this);
			if (fInsertedNew)
				wtx.nTimeReceived = GetAdjustedTime();

			if (!fInsertedNew)
				fUpdate = wallet_MergeTx(this, hash, wtxIn, wtx);
#endif

#if 0
			/* check whether all outputs have been spent. */
			bool fArch = true;
			unsigned int idx;
			for (idx = 0; idx < wtx.vout.size(); idx++) {
				if (!wtx.IsSpent(idx)) {
					fArch = false;
					break;
				}
			}
#endif
			bool fArch = false;
			if (!fArch) {
				if (fInsertedNew || fUpdated) {
					WriteWalletTx(wtx);
				}
			} else {
				/* remove from active */
				if (mapWallet.erase(hash))
					EraseWalletTx(hash);
				/* write to arch */
				WriteArchTx(wtx);
			}

			WalletUpdateSpent(wtx);
		}
	}

	return (true);
#endif

  uint256 hash = wtxIn.GetHash();
#if 0
	if (HasArchTx(hash)) {
		CWalletTx& wtx = GetTx(hash);
		EraseWalletTx(hash); /* redundant */
	}
#endif

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
      if (wtxIn.strFromAccount != "" && 
					wtxIn.strFromAccount != wtx.strFromAccount) {
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
			bool fArch = true;
			unsigned int idx;
			for (idx = 0; idx < wtx.vout.size(); idx++) {
				if (!wtx.IsSpent(idx)) {
					fArch = false;
					break;
				}
			}
			if (fArch) {
				WriteArchTx(wtx);
				EraseWalletTx(hash);
			} else {
				WriteWalletTx(wtx);
			}
    }

		// since AddToWallet is called directly for self-originating transactions, check for consumption of own coins
		WalletUpdateSpent(wtx);
	}

  return true;
}

void CWallet::RemoveTx(uint256 hash)
{

	{
		LOCK(cs_wallet);

		EraseWalletTx(hash); /* active wtx db */
		mapWallet.erase(hash); /* active mem */
		EraseArchTx(hash); /* remove from arch wtx db. */
	}

}

void CWallet::WriteWalletTx(const CWalletTx& wtx) const
{

	{
		LOCK(cs_wallet);

		CWalletDB db(strWalletFile);
		db.WriteTx(wtx.GetHash(), wtx);
		db.Close();
	}

}

void CWallet::EraseWalletTx(const uint256& hash) const
{

	{
		LOCK(cs_wallet);

		/* remove from actively tracked transactions. */
		CWalletDB wtx_db(strWalletFile, "cr+");
		wtx_db.EraseTx(hash);
		wtx_db.Close();
	}

}

bool CWallet::ReadArchTx(uint256 hash, CWalletTx& wtx) const
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

bool CWallet::WriteArchTx(const CWalletTx& wtx) const
{
	CDataStream sBlock(SER_DISK, CLIENT_VERSION);
	CIface *iface = GetCoinByIndex(ifaceIndex);
	bc_t *bc = GetWalletTxChain(iface);
	uint256 hash = wtx.GetHash();
	char *sBlockData;
	size_t sBlockLen;
	bcpos_t posTx;
	int err;

	err = bc_find(bc, hash.GetRaw(), &posTx);
	if (!err) {
		return (true); /* already written. */
	}

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

bool CWallet::EraseArchTx(uint256 hash) const
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	bc_t *bc = GetWalletTxChain(iface);
	bcpos_t posTx;
	int err;

	err = bc_find(bc, hash.GetRaw(), &posTx);
	if (err)
		return (false);

	err = bc_idx_clear(bc, posTx);
	if (err)
		return (error(err, "bc_idx_clear [CWallet.EraseArchTx]"));

	/* clear ".tmp" b-tree lookup table. */
	bc_table_reset(bc, hash.GetRaw());

	Debug("EraseArchTx: removed tx \"%s\".", hash.GetHex().c_str());
	return (true);
}

bool CWallet::HasArchTx(uint256 hash) const
{
	CIface *iface;
	bc_t *bc;
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

	return (true);
}

