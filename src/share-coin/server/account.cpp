
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


static const char *_pubkey_tag_table[MAX_ACCADDR] = {
	"recieve",
	"change",
	"exec",
	"hdkey",
	"segwit",
	"ext",
	"notary"
};

static int _account_address_flags[MAX_ACCADDR] = {
	ACCADDRF_WITNESS | ACCADDRF_DERIVE, /* Recv */
	ACCADDRF_WITNESS | ACCADDRF_DERIVE, /* Change */
	ACCADDRF_STATIC | ACCADDRF_DERIVE, /* Exec */
	ACCADDRF_STATIC, /* HDKey (master) */
	ACCADDRF_WITNESS, /* SegWit (Recv) */
	ACCADDRF_DERIVE, /* Ext */
	ACCADDRF_STATIC, /* Notary */
};
#define IS_ACCOUNT(type, flag) \
	(_account_address_flags[(type)] & (flag))


static const char *GetPubKeyTag(int type)
{

	if (type < 0 || type >= MAX_ACCADDR)
		return (_pubkey_tag_table[ACCADDR_RECV]);

	return (_pubkey_tag_table[type]);
}

CCoinAddr CAccountCache::CreateAddr(int type)
{
	CCoinAddr addr(wallet->ifaceIndex, CNoDestination());

	if (!wallet)
		return (addr);

	CPubKey pubkey;
	wallet->GetMergedPubKey(strAccount, GetPubKeyTag(type), pubkey);

	addr = CCoinAddr(wallet->ifaceIndex, pubkey.GetID());
	AddAddr(addr, type);

	return (addr);
}

CCoinAddr CAccountCache::CreateNewAddr(int type)
{
	CCoinAddr addr(wallet->ifaceIndex, CNoDestination());

	if (!wallet)
		return (addr);

	CPubKey pubkey = GetAccountPubKey(wallet, strAccount, true);
	addr = CCoinAddr(wallet->ifaceIndex, pubkey.GetID());
	AddAddr(addr, type);

	return (addr);
}

void CAccountCache::AddAddr(CCoinAddr addr, int type)
{

	if (type < 0 || type >= MAX_ACCADDR)
		return;

	if (!addr.IsValid())
		return;

	vAddr[type] = addr;
}

CCoinAddr CAccountCache::GetAddr(int type)
{
	static CPubKey null_key;
	CCoinAddr addr(wallet->ifaceIndex);

	if (type >= 0 && type < MAX_ACCADDR)
		addr = vAddr[type];
	
	if (addr.IsValid()) {
		vAddr[type].nAccessTime = time(NULL);
		if (IS_ACCOUNT(type, ACCADDRF_STATIC))
			return (addr);
		if (!IsAddrUsed(addr))
			return (addr);
	}

	/* create new address. */
	CPubKey pubkey =
		GetAccountPubKey(wallet, strAccount, !IS_ACCOUNT(type, ACCADDRF_STATIC));
	addr = CCoinAddr(wallet->ifaceIndex, pubkey.GetID());
	if (!addr.IsValid())
		return (addr);

	/* retain */
	vAddr[type] = addr;
	vAddr[type].nAccessTime = time(NULL);
	return (addr);
}

CCoinAddr CAccountCache::GetDefaultAddr()
{
	return (CCoinAddr(wallet->ifaceIndex, account.vchPubKey.GetID()));
}

CCoinAddr CAccountCache::GetDynamicAddr(int type)
{
	CCoinAddr addr;

	if (type >= 0 && type < MAX_ACCADDR)
		addr = vAddr[type];

	if (!addr.IsValid()) {
		addr = CreateAddr(ACCADDR_CHANGE);
	} else if (IsAddrUsed(addr)) {
		addr = CreateNewAddr(type);
	}
	
	return (addr);
}

CCoinAddr CAccountCache::GetStaticAddr(int type)
{
	CCoinAddr addr;

	if (type >= 0 && type < MAX_ACCADDR)
		addr = vAddr[type];

	if (!addr.IsValid()) {
		addr = GetDefaultAddr();
	}

	return (addr);
}

bool CAccountCache::IsAddrUsed(const CCoinAddr& addr)
{
	bool bKeyUsed = false;

	if (!wallet)
		return (false);

	/* check if the current key has been used */
	CKeyID keyID;
	if (!addr.GetKeyID(keyID))
		return (false);

	CScript scriptPubKey;
	scriptPubKey.SetDestination(keyID);

	for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin();
			it != wallet->mapWallet.end();
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

	return (bKeyUsed);
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

//bool CAccountCache::CreateHDKey(const CPubKey& vchPubKey)
