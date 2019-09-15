
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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
#include "account.h"


static const char *_pubkey_tag_table[MAX_ACCADDR] = {
	"receive",
	"change",
	"exec",
	"hdkey",
	"ext",
	"notary",
	"miner"
};

static int _account_address_flags[MAX_ACCADDR] = {
	ACCADDRF_WITNESS | ACCADDRF_DERIVE | ACCADDRF_DILITHIUM, /* Recv */
	ACCADDRF_WITNESS | ACCADDRF_DERIVE, /* Change */
	ACCADDRF_STATIC, /* Exec */
	ACCADDRF_STATIC, /* HDKey (master) */
	ACCADDRF_DERIVE, /* Ext */
	ACCADDRF_STATIC, /* Notary */
	ACCADDRF_STATIC, /* Miner */
};
#define IS_ACCOUNT(type, flag) \
	(_account_address_flags[(type)] & (flag))

static bool CAccountCache_GenerateAddress(CWallet *wallet, const string& strAccount, CPubKey& pubkey, const char *tag)
{
	ECKey pkey;

	if (!wallet->GetECKey(pubkey.GetID(), pkey))
		return (false);

	cbuff tagbuff(tag, tag + strlen(tag));
	ECKey key;
	pkey.MergeKey(key, tagbuff);

	CPubKey mrg_pubkey = key.GetPubKey();
	if (!mrg_pubkey.IsValid())
		return (false);

	if (!wallet->HaveKey(mrg_pubkey.GetID())) {
		/* add key to address book */
		if (!wallet->AddKey(key))
			return (false);

		wallet->SetAddressBookName(mrg_pubkey.GetID(), strAccount);
	}

	pubkey = mrg_pubkey; 
	return (true);
}

static const char *GetPubKeyTag(int type)
{

	if (type < 0 || type >= MAX_ACCADDR)
		return (_pubkey_tag_table[ACCADDR_RECV]);

	return (_pubkey_tag_table[type]);
}

int GetPubKeyMode(const char *tag)
{
	int i;

	for (i = 0; i < MAX_ACCADDR; i++) {
		if (0 == strcasecmp(tag, _pubkey_tag_table[i]))
			return (i);
	}

	return (-1);
}

#if 0
CCoinAddr CAccountCache::CreateAddr(int type)
{
	CCoinAddr addr(wallet->ifaceIndex, CNoDestination());

	if (!wallet)
		return (addr);

	CPubKey pubkey;
	wallet->GetMergedPubKey(strAccount, GetPubKeyTag(type), pubkey);

	addr = CCoinAddr(wallet->ifaceIndex, pubkey.GetID());
	SetAddr(type, addr);

	return (addr);
}
#endif

#if 0
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
#endif

void CAccountCache::SetAddr(int type, CCoinAddr addr)
{

	if (type < 0 || type >= MAX_ACCADDR)
		return;

	if (!addr.IsValid())
		return;

	vAddr[type] = addr;
}

void CAccountCache::ResetAddr(int type)
{
	CCoinAddr null_addr(wallet->ifaceIndex);

	if (type < 0 || type >= MAX_ACCADDR)
		return;

	vAddr[type] = null_addr;
}

CCoinAddr CAccountCache::GetAddr(int type)
{
	static CPubKey null_key;
	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	CCoinAddr addr(wallet->ifaceIndex);

	if (type < 0 || type >= MAX_ACCADDR)
		return (addr); /* invalid */

	addr = vAddr[type];
	if (addr.IsValid()) {
		/* last addr */
		if (IS_ACCOUNT(type, ACCADDRF_STATIC)) {
			/* only dispences a single coin address. */
			return (addr);
		}
		int flags = 0;
		CKeyID keyid;
		if (addr.GetKeyID(keyid)) {
			CKeyMetadata *meta = wallet->GetKeyMetadata(keyid);
			flags = meta->nFlag;
		}
		if (!(flags & ACCADDRF_INTERNAL) && !IsAddrUsed(addr)) {
			/* this is not an internal use address and it has not been used yet. */
			return (addr);
		}
	}

	if (IS_ACCOUNT(type, ACCADDRF_STATIC)) {
		CTxDestination dest;
		/* primary address for type. */
		if (GetPrimaryAddr(type, dest))
			addr = CCoinAddr(wallet->ifaceIndex, dest); 
	} else {
		CTxDestination dest;
		/* derived/generated address. */
		if (CreateNewAddr(dest, type, 0))
			addr = CCoinAddr(wallet->ifaceIndex, dest);
	}
	if (addr.IsValid()) {
		SetAddr(type, addr);
		vAddr[type].nAccessTime = time(NULL);
	}


	return (addr);


#if 0
	bool fOk = false;
	bool fWitness = true;
	addr = vAddr[type];
	if (addr.IsValid()) {
		vAddr[type].nAccessTime = time(NULL);
		if (IS_ACCOUNT(type, ACCADDRF_STATIC))
			return (addr);
		fOk = true;
		fWitness = false;
	} else {
		CPubKey pubkey = wallet->GetPrimaryPubKey(strAccount);
		fOk = CAccountCache_GenerateAddress(wallet, strAccount, pubkey, _pubkey_tag_table[type]);
		if (fOk) {
			/* an address unique for mode has been generated. */
			addr = CCoinAddr(wallet->ifaceIndex, pubkey.GetID());
		}
	}

	if (!fOk || (!IS_ACCOUNT(type, ACCADDRF_STATIC) && IsAddrUsed(addr))) {
		/* create new address. */
		CPubKey pubkey = GetAccountPubKey(wallet, strAccount, true);
		if (pubkey.IsValid()) {
			addr = CCoinAddr(wallet->ifaceIndex, pubkey.GetID());
			fOk = true;
		}
	}

	if (!addr.IsValid()) {
		error(ERR_INVAL, "CAccountCache.GetAddr: error generating coin address.");
		return (addr);
	}

	if (fWitness &&
			IS_ACCOUNT(type, ACCADDRF_WITNESS) &&
			IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		CTxDestination result = addr.GetWitness();
		wallet->SetAddressBookName(result, strAccount);
		addr = CCoinAddr(wallet->ifaceIndex, result); 
	}

	/* retain */
	vAddr[type] = addr;
	vAddr[type].nAccessTime = time(NULL);
	return (addr);
#endif
}

CCoinAddr CAccountCache::GetDefaultAddr()
{
	return (CCoinAddr(wallet->ifaceIndex, account.vchPubKey.GetID()));
}

void CAccountCache::SetDefaultAddr(const CPubKey& pubkey)
{

	if (!pubkey.IsValid())
		return; /* nerp */

	if (pubkey == account.vchPubKey)
		return; /* done */

	account.vchPubKey = pubkey;

	{ /* save to wallet */
		LOCK(wallet->cs_wallet);
		CWalletDB walletdb(wallet->strWalletFile);
		walletdb.WriteAccount(strAccount, account);
		walletdb.Close();
	}

}


#if 0
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
#endif

bool CAccountCache::IsAddrUsed(const CCoinAddr& addr)
{
	bool bKeyUsed = false;

	if (!wallet)
		return (false);

	CScript script;
	script.SetDestination(addr.Get());
	for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin();
			it != wallet->mapWallet.end();
			++it) {
		const CWalletTx& wtx = (*it).second;
		BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
			if (txout.scriptPubKey == script) {
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
	CKey *key = wallet->GetKey(vchPubKey.GetID());
	if (!key)
		return (false); /* unknown */

	const CKeyID& keyid = vchPubKey.GetID();
	vector<CTxDestination> vDest;
	GetAddrDestination(keyid, vDest, key->meta.nFlag);

	vector<CScript> vScript;
	BOOST_FOREACH(const CTxDestination& dest, vDest) {
		CScript script;
		script.SetDestination(dest);
		vScript.push_back(script);
	}

	for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin();
			it != wallet->mapWallet.end();
			++it)
	{
		const CWalletTx& wtx = (*it).second;
		BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
			BOOST_FOREACH(const CScript& scriptPubKey, vScript) {
				if (txout.scriptPubKey == scriptPubKey) {
					bKeyUsed = true;
					break;
				}
			}
			if (bKeyUsed)
				break;
		}
	}

	return (bKeyUsed);
}

//bool CAccountCache::CreateHDKey(const CPubKey& vchPubKey)


CHDChain *CAccountCache::GetHDChain()
{

#if 0
	if (!account.vchPubKey.IsValid()) {
		LOCK(wallet->cs_wallet);

		/* load from wallet */
		CWalletDB walletdb(wallet->strWalletFile);
		walletdb.ReadAccount(strAccount, account);
		walletdb.Close();
	}
#endif

	if (account.chain.masterKeyID == 0) {
		/* intialize chain attributes. */
		const CCoinAddr& m_addr = GetAddr(ACCADDR_HDKEY);

		account.chain.nVersion = CHDChain::VERSION_HD_CHAIN_SPLIT;
		m_addr.GetKeyID(account.chain.masterKeyID);

		{
			LOCK(wallet->cs_wallet);

			/* save to wallet */
			CWalletDB walletdb(wallet->strWalletFile);
			walletdb.WriteAccount(strAccount, account);
			walletdb.Close();
		}
	}

	return (&account.chain);
}

#if 0
CPubKey CAccountCache::GetMasterPubKey()
{
	CPubKey pubkey = account.vchPubKey;
	bool bValid;
	
	bValid = pubkey.IsValid();
	if (!bValid) {
		LOCK(wallet->cs_wallet);

		/* load from wallet */
		CWalletDB walletdb(wallet->strWalletFile);
		walletdb.ReadAccount(strAccount, account);
		bValid = account.vchPubKey.IsValid();
		walletdb.Close();
	}
	if (!bValid) {
		account.vchPubKey = wallet->GenerateNewKey(true);
		{
			LOCK(wallet->cs_wallet);

			/* save to wallet */
			CWalletDB walletdb(wallet->strWalletFile);
			walletdb.WriteAccount(strAccount, account);
			walletdb.Close();
		}
	}

	return (account.vchPubKey);
}
#endif

void CAccountCache::UpdateAccount()
{

	{
		LOCK(wallet->cs_wallet);

		/* save to wallet */
		CWalletDB walletdb(wallet->strWalletFile);
		walletdb.WriteAccount(strAccount, account);
		walletdb.Close();
	}

}

bool CAccountCache::GetPrimaryAddr(int type, CTxDestination& addrRet)
{
	CPubKey pubkey;
	if (!GetPrimaryPubKey(type, pubkey))
		return (false);

	addrRet = pubkey.GetID();
	return (true);
}

bool CAccountCache::GetPrimaryPubKey(int type, CPubKey& pubkeyRet)
{
	CKey *pkey;
	const char *tag = GetPubKeyTag(type);
	cbuff tagbuff(tag, tag + strlen(tag));

	pkey = wallet->GetKey(account.vchPubKey.GetID());
	if (!pkey)
		return (false);

	ECKey key;
	pkey->MergeKey(key, tagbuff);
	key.meta.nFlag |= ACCADDRF_INTERNAL;

	pubkeyRet = key.GetPubKey();
	if (!pubkeyRet.IsValid())
		return (false);

	const CKeyID& keyid = pubkeyRet.GetID();
	if (!wallet->HaveKey(keyid)) {
		/* add key to address book */
		if (!wallet->AddKey(key))
			return (false);
		
		/* add all the address variants to the wallet's address book. */
		SetAddrDestinations(keyid);
	}

	return (true);
}

bool CAccountCache::CreateNewAddr(CTxDestination& addrRet, int type, int flags)
{
	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	bool fWitness = IsWitnessEnabled(iface, GetBestBlockIndex(iface));
	bool fDilithium = opt_bool(OPT_DILITHIUM);
	bool fHDKey = opt_bool(OPT_HDKEY);
	bool fBech32 = opt_bool(OPT_BECH32);
	CPubKey pubkey;

	if (type < 0 || type >= MAX_ACCADDR)
		return (false);

	flags |= _account_address_flags[type];
	if (!fWitness)
		flags &= ~ACCADDRF_WITNESS;
	if (!(flags & ACCADDRF_WITNESS))
		fBech32 = false;
	if (!fBech32 || !fDilithium) {
		flags &= ~ACCADDRF_DILITHIUM;
	}
	if (!fHDKey)
		flags &= ~ACCADDRF_DERIVE;

	if (!CreateNewPubKey(pubkey, flags))
		return (false);

	if ((flags & ACCADDRF_WITNESS)) {
		if (!fBech32) {
			CCoinAddr addr(wallet->ifaceIndex, pubkey.GetID());
			addrRet = addr.GetWitness(OUTPUT_TYPE_P2SH_SEGWIT);
		} else {
			CCoinAddr addr(wallet->ifaceIndex, pubkey.GetID());
			addrRet = addr.GetWitness(OUTPUT_TYPE_BECH32);
		}
	} else {
		/* regular */
		addrRet = pubkey.GetID();
	}
	if (addrRet == CTxDestination(CNoDestination()))
		return (false);

	return (true);
}

bool CAccountCache::CreateNewPubKey(CPubKey& addrRet, int flags)
{
	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	bool fWitness = IsWitnessEnabled(iface, GetBestBlockIndex(iface));
	bool fDilithium = opt_bool(OPT_DILITHIUM);
	bool fHDKey = opt_bool(OPT_HDKEY);
	bool fBech32 = opt_bool(OPT_BECH32);
	CPubKey pubkey;

	if (!fWitness || !fBech32 || !fDilithium)
		flags &= ~ACCADDRF_DILITHIUM;

	if (flags & ACCADDRF_DILITHIUM) {
		if (!(flags & ACCADDRF_DERIVE)) {
			if (!wallet->GenerateNewDIKey(pubkey, flags))
				flags &= ~ACCADDRF_DILITHIUM;
		} else {
			DIKey key;
			CHDChain *hdChain = GetHDChain();
			if (!wallet->DeriveNewDIKey(hdChain, key, false)) {
				flags &= ~ACCADDRF_DILITHIUM;
			} else {
				key.meta.nFlag = flags;
				if (!wallet->AddKey(key)) {
					error(SHERR_INVAL, "CreateNewPubKey: error adding derived dilithium key to wallet.");
					return (false);
				}
				pubkey = key.GetPubKey();
			}
		}
	}
	if (!(flags & ACCADDRF_DILITHIUM)) {
		if (!(flags & ACCADDRF_DERIVE)) {
			if (!wallet->GenerateNewECKey(pubkey, true, flags)) {
				error(SHERR_INVAL, "CreateNewPubKey: error generating key.");
				return (false);
			}
		} else {
			ECKey key;
			CHDChain *hdChain = GetHDChain();
			if (!wallet->DeriveNewECKey(hdChain, key, false)) {
				error(SHERR_INVAL, "CreateNewPubKey: error deriving key.");
				return (false);
			}
			key.meta.nFlag = flags;
			if (!wallet->AddKey(key)) {
				error(SHERR_INVAL, "CreateNewPubKey: error adding derived ecdsa key to wallet.");
				return (false);
			}
			pubkey = key.GetPubKey();
		}
	}

	/* add all the address variants to the wallet's address book. */
	SetAddrDestinations(pubkey.GetID(), flags);

	addrRet = pubkey;
	return (true);
}

void CAccountCache::GetAddrDestination(const CKeyID& keyid, vector<CTxDestination>& vDest, int nFlag)
{

	vDest.clear();

	if (keyid == 0)
		return;

	/* pubkey coin address */
	if (wallet->mapAddressBook.count(keyid) == 0) {
		wallet->SetAddressBookName(keyid, strAccount);
	}
	if (!(nFlag & ACCADDRF_DILITHIUM))
		vDest.push_back(keyid);

	/* CScriptID destination to pubkey. */
	CScript scriptPubKey;
	scriptPubKey.SetDestination(keyid);
	wallet->AddCScript(scriptPubKey);
	CScriptID scriptID(scriptPubKey);
	if (wallet->mapAddressBook.count(scriptID) == 0) {
		wallet->SetAddressBookName(scriptID, strAccount);
	}
	if (!(nFlag & ACCADDRF_DILITHIUM))
		vDest.push_back(keyid);

	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	if (iface && IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		CCoinAddr addr(wallet->ifaceIndex, keyid);

		/* generate "program 0" p2sh-segwit address. */
		CTxDestination sh_dest = addr.GetWitness(OUTPUT_TYPE_P2SH_SEGWIT);
		if (wallet->mapAddressBook.count(sh_dest) == 0) {
			wallet->SetAddressBookName(sh_dest, strAccount);
		}
		if (!(nFlag & ACCADDRF_DILITHIUM))
			vDest.push_back(sh_dest);

		/* bech32 destination address. */
		CTxDestination be_dest = addr.GetWitness(OUTPUT_TYPE_BECH32);
		if (wallet->mapAddressBook.count(be_dest) == 0) {
			wallet->SetAddressBookName(be_dest, strAccount);
		}
		vDest.push_back(be_dest);
	}

}

void CAccountCache::SetAddrDestinations(const CKeyID& keyid, int nFlag)
{
	vector<CTxDestination> vDest;
	GetAddrDestination(keyid, vDest, nFlag);
}

