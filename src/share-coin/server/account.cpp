
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
#include "account.h"


static const char *_pubkey_tag_table[] = {
	"recieve",
	"change",
	"exec",
	"hdkey",
	"segwit",
	"ext",
	"mine"
};


static const char *GetPubKeyTag(int type)
{

	if (type < 0 || type >= MAX_ACCADDR)
		return (_pubkey_tag_table[ACCADDR_RECV]);

	return (_pubkey_tag_table[type]);
}

CPubKey CAccountCache::CreateAddr(int type)
{
	CPubKey pubkey;

	if (!wallet)
		return (CPubKey());

	wallet->GetMergedPubKey(strAccount, GetPubKeyTag(type), pubkey);
	AddAddr(pubkey, type);
	return (pubkey);
}

CPubKey CAccountCache::CreateNewAddr(int type)
{
	if (!wallet)
		return (CPubKey());
	CPubKey pubkey = GetAccountPubKey(wallet, strAccount, true);
	AddAddr(pubkey, type);
	return (pubkey);
}

void CAccountCache::AddAddr(CPubKey pubkey, int type)
{
	CAccountAddr addr;

	if (type < 0 || type >= MAX_ACCADDR)
		return;

	if (!pubkey.IsValid())
		return;

	vAddr[type].nCreateTime = time(NULL);
	vAddr[type].vchPubKey = pubkey.Raw();
}

CPubKey CAccountCache::GetAddr(int type)
{
	static CPubKey null_key;

	if (type < 0 || type >= MAX_ACCADDR)
		return (null_key);
	
	vAddr[type].nAccessTime = time(NULL);
	return (CPubKey(vAddr[type].vchPubKey));
}

CPubKey CAccountCache::GetDefaultAddr()
{
	return (account.vchPubKey);
}

CPubKey CAccountCache::GetDynamicAddr(int type)
{
	CPubKey pubkey;

	pubkey = GetAddr(type);
	if (!pubkey.IsValid()) {
		pubkey = CreateAddr(ACCADDR_CHANGE);
	} else if (IsAddrUsed(pubkey)) {
		pubkey = CreateNewAddr(type);
	}

	SetFlag(type, ACCADDRF_DYNAMIC);
	return (pubkey);
}

CPubKey CAccountCache::GetStaticAddr(int type)
{
	CPubKey pubkey;

	pubkey = GetAddr(type);
	if (!pubkey.IsValid()) {
		pubkey = GetDefaultAddr();
	}

	UnsetFlag(type, ACCADDRF_DYNAMIC);
	return (pubkey);
}

bool CAccountCache::IsAddrUsed(const CPubKey& vchPubKey)
{
	bool bKeyUsed = false;

	if (!wallet)
		return (false);

	/* check if the current key has been used */
	CScript scriptPubKey;
	scriptPubKey.SetDestination(vchPubKey.GetID());
	CScript cbPubKey;
	cbPubKey << vchPubKey << OP_CHECKSIG;

	for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin();
			it != wallet->mapWallet.end() && vchPubKey.IsValid();
			++it)
	{
		const CWalletTx& wtx = (*it).second;
		BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
			if (txout.scriptPubKey == scriptPubKey ||
					txout.scriptPubKey == cbPubKey) {
				bKeyUsed = true;
				break;
			}
		}
	}

	return (bKeyUsed);
}
