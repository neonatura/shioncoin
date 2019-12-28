
/*
 * @copyright
 *
 *  Copyright 2018 Brian Burrell
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
#include "walletdb.h"
#include "crypter.h"
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
	ACCADDRF_WITNESS | ACCADDRF_DERIVE | ACCADDRF_DILITHIUM, /* Ext */
	ACCADDRF_STATIC, /* Notary */
	ACCADDRF_STATIC, /* Miner */
};
#define IS_ACCOUNT(type, flag) \
	(_account_address_flags[(type)] & (flag))


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

void GetAddrDestination(int ifaceIndex, const CKeyID& keyid, vector<CTxDestination>& vDest, int nFlag)
{

	vDest.clear();

	if (keyid == 0)
		return;

	if (!(nFlag & ACCADDRF_DILITHIUM)) {
		/* pubkey coin address */
		vDest.push_back(keyid);

		/* CScriptID destination to pubkey. */
		CScript scriptPubKey;
		scriptPubKey.SetDestination(keyid);
		CScriptID scriptID(scriptPubKey);
		vDest.push_back(scriptID);
	}

	CIface *iface = GetCoinByIndex(ifaceIndex);
	if (iface && IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		CCoinAddr addr(ifaceIndex, keyid);

		if (!(nFlag & ACCADDRF_DILITHIUM)) {
			/* generate "program 0" p2sh-segwit address. */
			CTxDestination sh_dest = addr.GetWitness(OUTPUT_TYPE_P2SH_SEGWIT);
			vDest.push_back(sh_dest);

			/* bech32 destination address. */
			CTxDestination be_dest = addr.GetWitness(OUTPUT_TYPE_BECH32);
			vDest.push_back(be_dest);
		} else {
			/* bech32 destination address. */
			CTxDestination be_dest = addr.GetWitness(OUTPUT_TYPE_DILITHIUM);
			vDest.push_back(be_dest);
		}
	}

}

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
		if (!IsAddrUsed(addr)) {
			/* has not been used yet */
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
			const CScript& scriptPubKey = txout.scriptPubKey; 
			opcodetype opcode;
			CScript::const_iterator pc = scriptPubKey.begin();
			if (scriptPubKey.GetOp(pc, opcode) &&
					opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
				CScript scriptPubKeyTmp(scriptPubKey);
				RemoveExtOutputPrefix(scriptPubKeyTmp);
				if (scriptPubKeyTmp == script) {
					bKeyUsed = true;
					break;
				}
			} else if (scriptPubKey == script) {
				bKeyUsed = true;
				break;
			}
		}
		if (bKeyUsed)
			break;
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
	GetAddrDestination(keyid, vDest);

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
	key.nFlag |= CKey::META_INTERNAL;

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
		CCoinAddr addr(wallet->ifaceIndex, pubkey.GetID());
		if (pubkey.IsDilithium()) {
			addrRet = addr.GetWitness(OUTPUT_TYPE_DILITHIUM);
		} else if (!fBech32) {
			addrRet = addr.GetWitness(OUTPUT_TYPE_P2SH_SEGWIT);
		} else {
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
	CPubKey pubkey;

	if (!fWitness)
		flags &= ~ACCADDRF_DILITHIUM;

	if (flags & ACCADDRF_DILITHIUM) {
		if (!(flags & ACCADDRF_DERIVE)) {
			bool fOk = wallet->GenerateNewDIKey(pubkey, flags);
			if (!fOk)
				flags &= ~ACCADDRF_DILITHIUM;
		} else {
			DIKey key;
			CAccount *hdChain = &account;
			bool fOk = wallet->DeriveNewDIKey(hdChain, key, false);
			if (!fOk) {
				flags &= ~ACCADDRF_DILITHIUM;
			} else {
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
			CAccount *hdChain = &account;
			if (!wallet->DeriveNewECKey(hdChain, key, false)) {
				error(SHERR_INVAL, "CreateNewPubKey: error deriving key.");
				return (false);
			}
			if (!wallet->AddKey(key)) {
				error(SHERR_INVAL, "CreateNewPubKey: error adding derived ecdsa key to wallet.");
				return (false);
			}
			pubkey = key.GetPubKey();
		}
	}

	/* add all the address variants to the wallet's address book. */
	SetAddrDestinations(pubkey.GetID());

	addrRet = pubkey;
	return (true);
}

void CAccountCache::SetAddrDestinations(const CKeyID& keyid)
{

	if (keyid == 0)
		return;

	/* pubkey coin address */
	if (wallet->mapAddressBook.count(keyid) == 0) {
		wallet->SetAddressBookName(keyid, strAccount);
	}

	/* CScriptID destination to pubkey. */
	CScript scriptPubKey;
	scriptPubKey.SetDestination(keyid);
	CScriptID scriptID(scriptPubKey);
	if (wallet->mapAddressBook.count(scriptID) == 0) {
		wallet->AddCScript(scriptPubKey);
		wallet->SetAddressBookName(scriptID, strAccount);
	}

	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	if (iface && IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		CCoinAddr addr(wallet->ifaceIndex, keyid);

		/* generate "program 0" p2sh-segwit address. */
		CTxDestination sh_dest = addr.GetWitness(OUTPUT_TYPE_P2SH_SEGWIT);
		if (wallet->mapAddressBook.count(sh_dest) == 0) {
			wallet->SetAddressBookName(sh_dest, strAccount);
		}

		/* bech32 destination address. */
		CTxDestination be_dest = addr.GetWitness(OUTPUT_TYPE_BECH32);
		if (wallet->mapAddressBook.count(be_dest) == 0) {
			wallet->SetAddressBookName(be_dest, strAccount);
		}
	}

}

bool CAccountCache::GetMergedPubKey(cbuff tag, CPubKey& pubkey)
{

	{
    LOCK(wallet->cs_wallet);

		CKey *pkey = wallet->GetKey(account.vchPubKey.GetID());
		if (!pkey)
			return (false);

		if (pkey->IsDilithium()) {
			DIKey ckey;
			pkey->MergeKey(ckey, tag);
			pubkey = ckey.GetPubKey();
		} else /* ECDSA */ {
			ECKey ckey;
			pkey->MergeKey(ckey, tag);
			pubkey = ckey.GetPubKey();
		}
		if (!pubkey.IsValid())
			return (false);

		SetAddrDestinations(pubkey.GetID());
	}

	return (true);
}

bool CAccountCache::GetMergedAddr(cbuff tag, CCoinAddr& addr)
{
	CPubKey pubkey;

	if (!GetMergedPubKey(tag, pubkey))
		return (false);

	addr = CCoinAddr(wallet->ifaceIndex, pubkey.GetID());
	return (true);
}

bool CAccountCache::SetCertHash(const uint160& hCert)
{

	if (hCert == 0)
		return (false); /* sanity */

	if (wallet->mapCert.count(hCert) == 0)
		return (false); /* unknown */

	/* assign new default certificate for account. */
	account.hCert = hCert;
	UpdateAccount();
	return (true);
}

uint160 CAccountCache::GetCertHash() const
{
	return (account.hCert);
}

