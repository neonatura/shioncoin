
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
#include "key.h"
#include "rpc/rpc_proto.h"
#include "account.h"


static const char *_pubkey_tag_table[MAX_ACCADDR] = {
	"receive",
	"change",
	"ext",
	"exec",
	"notary",
	"miner"
};

static int _account_address_flags[MAX_ACCADDR] = {
	ACCADDRF_WITNESS | ACCADDRF_DERIVE | ACCADDRF_DILITHIUM, /* Recv */
	ACCADDRF_WITNESS | ACCADDRF_DERIVE | ACCADDRF_DILITHIUM, /* Change */
	ACCADDRF_WITNESS | ACCADDRF_DERIVE | ACCADDRF_DILITHIUM | ACCADDRF_INTERNAL, /* Ext */
	ACCADDRF_STATIC, /* Exec */
	ACCADDRF_STATIC, /* Notary */
	ACCADDRF_STATIC, /* Miner */
};
#define IS_ACCOUNT(type, flag) \
	(_account_address_flags[(type)] & (flag))

const char *GetPubKeyTag(int type)
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

	/* pubkey coin address */
	CTxDestination destPubKey(keyid);
	if (find(vDest.begin(), vDest.end(), destPubKey) == vDest.end()) {
		vDest.push_back(destPubKey);
	}

	if (!(nFlag & ACCADDRF_DILITHIUM)) {
    /* CScriptID destination to pubkey. */
    CScript scriptPubKey;
    scriptPubKey.SetDestination(keyid);
    CScriptID scriptID(scriptPubKey);
    CTxDestination destScriptID(scriptID);
    if (find(vDest.begin(), vDest.end(), destScriptID) == vDest.end()) {
      vDest.push_back(destScriptID);
    }
  }

	if (nFlag & ACCADDRF_WITNESS) {
//  CIface *iface = GetCoinByIndex(ifaceIndex);
//  if (iface && IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
    CCoinAddr addr(ifaceIndex, keyid);

    if (!(nFlag & ACCADDRF_DILITHIUM)) {
      /* generate "program 0" p2sh-segwit address. */
      CTxDestination sh_dest = addr.GetWitness(OUTPUT_TYPE_P2SH_SEGWIT);
      if (find(vDest.begin(), vDest.end(), sh_dest) == vDest.end()) {
        vDest.push_back(sh_dest);
      }

      /* bech32 destination address. */
      CTxDestination be_dest = addr.GetWitness(OUTPUT_TYPE_BECH32);
      if (find(vDest.begin(), vDest.end(), be_dest) == vDest.end()) {
        vDest.push_back(be_dest);
      }
    } else {
      /* bech32 destination address. */
      CTxDestination be_dest = addr.GetWitness(OUTPUT_TYPE_DILITHIUM);
      if (find(vDest.begin(), vDest.end(), be_dest) == vDest.end()) {
        vDest.push_back(be_dest);
      }
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
//		vAddr[type].nAccessTime = time(NULL);
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

	/* reset primary modes */
	for (int i = 0; i < MAX_ACCADDR; i++) {
		/* reset primary addr. */
		ResetAddr(i);

	}

	/* reset hd-index. */
	ResetHDIndex();

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
	CalcAddressBook(key, vDest);
//	GetAddrDestination(keyid, vDest, (key->IsDilithium() ? ACCADDR_DILITHIUM : 0));

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

CKey *CAccountCache::GetPrimaryKey(int nMode, int nAlg)
{
	CKeyID keyid;
	CPubKey pubkey;

	if (nAlg == SIGN_ALG_DILITHIUM) {
		DIKey secret;

		if (!wallet->DerivePrimaryDIKey(&account, secret, nMode)) {
			error(ERR_INVAL, "GetPrimaryKey: error deriving primary di-key");
			return (NULL);
		}

		pubkey = secret.GetPubKey();
		if (!pubkey.IsValid())
			return (NULL);

		keyid = pubkey.GetID();
		AddKey(secret);
#if 0
		if (!wallet->HaveKey(keyid)) {
			/* add di3 key to wallet. */
			if (!wallet->AddKey(secret))
				return (NULL);

			/* add all the address variants to the wallet's address book. */
			SetAddrDestinations(keyid);
		}
#endif
	} else {
		ECKey secret;

		if (!wallet->DerivePrimaryECKey(&account, secret, nMode)) {
			error(ERR_INVAL, "GetPrimaryKey: error deriving primary ec-key");
			return (NULL);
		}

		pubkey = secret.GetPubKey();
		if (!pubkey.IsValid())
			return (NULL);

		keyid = pubkey.GetID();
		AddKey(secret);
#if 0
		if (!wallet->HaveKey(keyid)) {
			/* add ecdsa key to wallet. */
			if (!wallet->AddKey(secret))
				return (NULL);

			/* add all the address variants to the wallet's address book. */
			SetAddrDestinations(keyid);
		}
#endif
	}
	if (keyid == 0) {
		error(ERR_INVAL, "GetPrimaryKey: error deriving primary keyid");
		return (NULL);
	}

	return (wallet->GetKey(keyid));
}

bool CAccountCache::GetPrimaryAddr(int type, CTxDestination& addrRet)
{
	CPubKey pubkey;
	if (!GetPrimaryPubKey(type, pubkey))
		return (false);

	addrRet = pubkey.GetID();
	return (true);
}

bool CAccountCache::GetPrimaryPubKey(int nType, CPubKey& pubkeyRet)
{
	bool fHDKey = opt_bool(OPT_HDKEY);
	bool fValid = false;

	if (nType < MAX_HD_ACCADDR && fHDKey) {
		fValid = DerivePrimaryKey(pubkeyRet, nType);
	} else {
		fValid = GeneratePrimaryKey(pubkeyRet, nType); 
	}

	return (fValid);
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
	if (wallet->ifaceIndex != SHC_COIN_IFACE &&
			wallet->ifaceIndex != TEST_COIN_IFACE &&
			wallet->ifaceIndex != TESTNET_COIN_IFACE) {
		flags &= ~ACCADDRF_DILITHIUM;
	} else if (!fDilithium || !fWitness || !fBech32) {
		flags &= ~ACCADDRF_DILITHIUM;
	}
	if (!fHDKey)
		flags &= ~ACCADDRF_DERIVE;

	if (!CreateNewPubKey(pubkey, type, flags))
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

bool CAccountCache::CreateNewPubKey(CPubKey& addrRet, int type, int flags)
{
	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
#if 0
	bool fWitness = IsWitnessEnabled(iface, GetBestBlockIndex(iface));

	if (!fWitness)
		flags &= ~ACCADDRF_DILITHIUM;
#endif

	if (flags & ACCADDRF_DILITHIUM) {
		if (!(flags & ACCADDRF_DERIVE)) {
			if (!GenerateNewDIKey(addrRet, flags)) {
				error(SHERR_INVAL, "CreateNewPubKey: error generating new dikey.");
				return (false);
			}
		} else {
			DIKey key;
			CAccount *hdChain = &account;
			bool fOk = wallet->DeriveNewDIKey(hdChain, key, type);
			if (!fOk) {
				error(SHERR_INVAL, "CreateNewPubKey: error deriving new dikey.");
				return (false);
			}

			if (!AddKey(key)) {
				return (error(SHERR_INVAL, "CreateNewPubKey: error adding derived dilithium key to wallet."));
			}

			addrRet = key.GetPubKey();
		}
	} else {
		if (!(flags & ACCADDRF_DERIVE)) {
			if (!GenerateNewECKey(addrRet, true, flags)) {
				error(SHERR_INVAL, "CreateNewPubKey: error generating new eckey.");
				return (false);
			}
		} else {
			ECKey key;
			CAccount *hdChain = &account;
			if (!wallet->DeriveNewECKey(hdChain, key, type)) {
				error(SHERR_INVAL, "CreateNewPubKey: error deriving new eckey.");
				return (false);
			}

			if (!AddKey(key)) {
				error(SHERR_INVAL, "CreateNewPubKey: error adding derived ecdsa key to wallet.");
				return (false);
			}

			addrRet = key.GetPubKey();
		}
	}

	/* update hd-index counter. */
	if (flags & ACCADDRF_DERIVE) {
		UpdateAccount();
	}

	return (true);
}

#if 0
void CAccountCache::GetAddrDestinations(const CKeyID& keyid, vector<CTxDestination>& retDest)
{

	if (keyid == 0)
		return;

	/* pubkey coin address */
	if (wallet->mapAddressBook.count(keyid) == 0) {
		wallet->SetAddressBookName(keyid, strAccount);
	}
	CTxDestination pubDest(keyid);
  if (find(retDest.begin(), retDest.end(), pubDest) == retDest.end()) {
		retDest.push_back(pubDest);
	}

	/* CScriptID destination to pubkey. */
	CScript scriptPubKey;
	scriptPubKey.SetDestination(keyid);
	CScriptID scriptID(scriptPubKey);
	if (wallet->mapAddressBook.count(scriptID) == 0) {
		wallet->AddCScript(scriptPubKey);
		wallet->SetAddressBookName(scriptID, strAccount);
	}
	CTxDestination scriptDest(scriptID);
  if (find(retDest.begin(), retDest.end(), scriptDest) == retDest.end()) {
		retDest.push_back(scriptDest);
	}

	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	if (iface && IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		CCoinAddr addr(wallet->ifaceIndex, keyid);

		/* generate "program 0" p2sh-segwit address. */
		CTxDestination sh_dest = addr.GetWitness(OUTPUT_TYPE_P2SH_SEGWIT);
		if (wallet->mapAddressBook.count(sh_dest) == 0) {
			wallet->SetAddressBookName(sh_dest, strAccount);
		}
		if (find(retDest.begin(), retDest.end(), sh_dest) == retDest.end()) {
			retDest.push_back(sh_dest);
		}

		/* bech32 destination address. */
		CTxDestination be_dest = addr.GetWitness(OUTPUT_TYPE_BECH32);
		if (wallet->mapAddressBook.count(be_dest) == 0) {
			wallet->SetAddressBookName(be_dest, strAccount);
		}
		if (find(retDest.begin(), retDest.end(), be_dest) == retDest.end()) {
			retDest.push_back(be_dest);
		}
	}

}
void CAccountCache::SetAddrDestinations(const CKeyID& keyid)
{
	vector<CTxDestination> dest;

	if (keyid == 0)
		return;

	GetAddrDestinations(keyid, dest);
}
#endif

bool CAccountCache::GetMergedPubKey(CKey *pkey, int nAlg, cbuff tag, CPubKey& pubkey)
{
	LOCK(wallet->cs_wallet);

	pubkey.SetNull();
	if (nAlg == SIGN_ALG_ECDSA) {
		ECKey ckey;
		ckey.MergeKey(pkey, tag);

		pubkey = ckey.GetPubKey();
		if (!pubkey.IsValid())
			return (false);

		if (!AddKey(ckey))
			return (false);
	} else if (nAlg == SIGN_ALG_DILITHIUM) {
		DIKey ckey;
		ckey.MergeKey(pkey, tag);

		pubkey = ckey.GetPubKey();
		if (!pubkey.IsValid())
			return (false);

		if (!AddKey(ckey))
			return (false);
	} 

#if 0
	SetAddrDestinations(pubkey.GetID());
#endif

	return (true);
}

bool CAccountCache::GetMergedPubKey(int nMode, int nAlg, cbuff tag, CPubKey& pubkey)
{
//    bool DerivePrimaryKey(CPubKey& pubkeyRet, int nType = 0);
	CKey *pkey = GetPrimaryKey(nMode, nAlg);
	if (!pkey)
		return (false);

	return (GetMergedPubKey(pkey, nAlg, tag, pubkey));
}

bool CAccountCache::GetMergedPubKey(cbuff tag, CPubKey& pubkey)
{
#if 0
	{
    LOCK(wallet->cs_wallet);

		CKey *pkey = wallet->GetKey(account.vchPubKey.GetID());
		if (!pkey)
			return (false);

		if (pkey->IsDilithium()) {
			DIKey ckey;
			ckey.MergeKey(pkey, tag);
			pubkey = ckey.GetPubKey();
		} else /* ECDSA */ {
			ECKey ckey;
			ckey.MergeKey(pkey, tag);
			pubkey = ckey.GetPubKey();
		}
		if (!pubkey.IsValid())
			return (false);

		SetAddrDestinations(pubkey.GetID());
	}

	return (true);
#endif

	CKey *pkey = wallet->GetKey(account.vchPubKey.GetID());
	if (!pkey)
		return (false);

	return (GetMergedPubKey(pkey, SIGN_ALG_ECDSA, tag, pubkey));
}

bool CAccountCache::GetMergedAddr(cbuff tag, CCoinAddr& addr)
{
	CPubKey pubkey;

	if (!GetMergedPubKey(tag, pubkey))
		return (false);

	addr = CCoinAddr(wallet->ifaceIndex, pubkey.GetID());
	return (true);
}

bool CAccountCache::SetAliasHash(const uint160& hAlias)
{

	if (hAlias == 0)
		return (false); /* sanity */

	if (wallet->mapCert.count(hAlias) == 0)
		return (false); /* unknown */

	/* assign new default certificate for account. */
	account.hAlias = hAlias;
	UpdateAccount();
	return (true);
}

uint160 CAccountCache::GetAliasHash() const
{
	return (account.hAlias);
}

int CAccountCache::GetAddrMode(const CTxDestination& addr)
{

	for (int nMode = 0; nMode < MAX_ACCADDR; nMode++) {
		CTxDestination accAddr;

		if (!GetPrimaryAddr(nMode, accAddr)) {
			continue;
		}

		if (accAddr == addr) {
			return (nMode);
		}
	}

	return (-1);
}

uint CAccountCache::GetHDIndex(int nMode, int nAlg)
{
	return ((uint)account.GetHDIndex(nMode, nAlg));
}

void CAccountCache::IncrementHDIndex(int nMode, int nAlg)
{
	account.IncrementHDIndex(nMode, nAlg);

	/* save to wallet */
	if (nMode == ACCADDR_RECV || nMode == ACCADDR_CHANGE) {
		LOCK(wallet->cs_wallet);
		CWalletDB walletdb(wallet->strWalletFile);
		walletdb.WriteAccount(strAccount, account);
		walletdb.Close();
	}
}

void CAccountCache::ResetHDIndex()
{
	account.ResetHDIndex();

	{ /* save to wallet */
		LOCK(wallet->cs_wallet);
		CWalletDB walletdb(wallet->strWalletFile);
		walletdb.WriteAccount(strAccount, account);
		walletdb.Close();
	}
}

bool CAccountCache::DerivePrimaryKey(CPubKey& pubkeyRet, int nType)
{
	bool fDilithium = opt_bool(OPT_DILITHIUM);

	if (fDilithium) {
		DIKey secret;
		if (!wallet->DerivePrimaryDIKey(&account, secret, nType))
			return (false);

		pubkeyRet = secret.GetPubKey();
		if (!pubkeyRet.IsValid())
			return (false);

		/* add dikey to wallet. */
		if (!AddKey(secret)) {
			return (false);
		}
	} else {
		ECKey secret;
		if (!wallet->DerivePrimaryECKey(&account, secret, nType))
			return (false);

		pubkeyRet = secret.GetPubKey();
		if (!pubkeyRet.IsValid())
			return (false);

		/* add eckey to wallet. */
		if (!AddKey(secret)) {
			return (false);
		}
	}

	return (true);
}

/* Generate ecdsa primary keys for misc tasks. */
bool CAccountCache::GeneratePrimaryKey(CPubKey& pubkeyRet, int nType)
{
	CKey *pkey;
	CKey *eckey;
	const char *tag = GetPubKeyTag(nType);
	cbuff tagbuff(tag, tag + strlen(tag));

	pkey = wallet->GetKey(account.GetMasterKeyID());
	if (!pkey) {
		return (false);
	}

	ECKey key;
	key.MergeKey(pkey, tagbuff);
	key.nFlag |= CKey::META_PRIMARY;

	pubkeyRet = key.GetPubKey();
	if (!pubkeyRet.IsValid()) {
		return (false);
	}

#if 0
	const CKeyID& keyid = pubkeyRet.GetID();
	if (wallet->HaveKey(keyid)) {
		return (true);
	}

	/* add key to address book */
	if (!wallet->AddKey(key)) {
		return (false);
	}

	/* add all the address variants to the wallet's address book. */
	SetAddrDestinations(keyid);
#endif
	if (!AddKey(key)) {
		return (false);
	}

	return (true);
}

void CAccountAddress::SetNull()
{

//	account = NULL;
	keyid = CKeyID();

//	scriptPubKey = CScript();
//	addresses.clear();
	nOutputType = TX_NONSTANDARD;
//	nRequired = 0;

	fWitness = 0;
	nWitnessVersion = 0;
	nWitnessSize = 0;

//	fScript = false;
//	scriptID = CScriptID();
	script = CScript();

}

void CAccountAddress::Init()
{

	wallet = GetWallet(ifaceIndex);
	if (!wallet)
		return;

	if (script.size() == 0) {
		CScriptID scriptID;
		if (GetScriptID(scriptID)) {
			/* obtain script being referenced. */
			wallet->GetCScript(scriptID, script);
		}
	}

	if (keyid.size() == 0) {
		if (GetKeyID(keyid)) {
			/* unable to obtain key-id being referenced. */
			return;
		}
	}

	{
		CScript scriptPubKey = GetScriptPubKey();
		vector<unsigned char> witnessprogram;
		int witnessversion;

		if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
			fWitness = true;
			nWitnessVersion = witnessversion;
			nWitnessSize = (int)witnessprogram.size();
		}
	}

	/* attempt to derive an underlying keyid */
	ExtractDestinationKey(wallet, Get(), keyid);

}

CScript CAccountAddress::GetScriptPubKey()
{
	CTxDestination destination = GetDestination();

	CScript scriptPubKey;
	scriptPubKey.SetDestination(destination);

	return (scriptPubKey);
}

#if 0
bool CAccountAddress::IsMaster()
{
	return (account && account->account.masterKeyID == keyid);
}
#endif

bool CAccountAddress::IsDefault()
{
	const CPubKey& pubkeyDefault = wallet->GetPrimaryPubKey(GetAccountName());
	const CKeyID& keyidDefault = pubkeyDefault.GetID();
	return (keyidDefault == keyid);
}

#if 0
string CAccountAddress::GetAccountName()
{
	if (!account)
		return ("");
	return (account->strAccount);
}
#endif

bool CAccountAddress::IsMine()
{
	CTxDestination destination = GetDestination();
	return (::IsMine(*wallet, destination));
}

CAccountCache *CAccountAddress::GetAccountCache()
{
	return (wallet->GetAccount(GetAccountName()));
}

CAccount *CAccountAddress::GetAccount()
{
	CAccountCache *account;

	account = GetAccountCache();
	if (!account)
		return (NULL);

	return (&account->account);
}

string CAccountAddress::GetAccountName()
{
	const CTxDestination& destination = GetDestination();
	string strAccount = "";

	map<CTxDestination, string>::iterator mi = wallet->mapAddressBook.find(destination);
	if (mi != wallet->mapAddressBook.end() && !(*mi).second.empty())
		strAccount = (*mi).second;

	return (strAccount);
}

void CAccountAddress::SetAccountName(string strAccount)
{
	const CTxDestination& destination = GetDestination();
	wallet->SetAddressBookName(destination, strAccount);
}

CTxDestination CAccountAddress::GetDestination()
{
	return (Get());
}

bool CAccountAddress::GetScriptID(CScriptID& scriptID)
{

	if (script.size() == 0) {
		return (false);
	}

	scriptID = CScriptID(script);
	return (true);
}

bool CAccountAddress::HaveKey()
{
	return (wallet ? wallet->HaveKey(keyid) : false);
}

Object CAccountAddress::ToValue()
{
	Object obj;

  obj.push_back(Pair("origin", GetAccountName()));

	if (keyid != 0) {
		obj.push_back(Pair("keyid", keyid.GetHex()));
#if 0
		if (GetAccount()->masterKeyID == keyid) { // IsMaster
			obj.push_back(Pair("master", true));
		}
#endif
	}

	obj.push_back(Pair("addr", ToString()));

	CScript scriptPubKey = GetScriptPubKey();
	if (scriptPubKey.size() != 0) {
		txnouttype type;
		int nRequired;
		vector<CTxDestination> addresses;

		obj.push_back(Pair("pubkey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

		if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
			obj.push_back(Pair("kind", GetTxnOutputType(TX_NONSTANDARD)));
		} else {
			obj.push_back(Pair("kind", GetTxnOutputType(type)));
		}

		if (type == TX_MULTISIG) {
			Array addr_list;

			BOOST_FOREACH(const CTxDestination& destTmp, addresses) {
				CCoinAddr t_addr(ifaceIndex, destTmp);
				addr_list.push_back(t_addr.ToString());
			}
			if (addr_list.size() != 0) {
				obj.push_back(Pair("multisig", addr_list));
			}
		}
	}

#if 0
	obj.push_back(Pair("output-type", GetTxnOutputType(nOutputType)));
#endif

	if (fWitness) {
		obj.push_back(Pair("witness", true));
		obj.push_back(Pair("witness-version", nWitnessVersion));
		obj.push_back(Pair("witness-size", nWitnessSize));
	}

	if (script.size() != 0) {
		obj.push_back(Pair("script", HexStr(script)));

		CScriptID scriptID;
		GetScriptID(scriptID);
		obj.push_back(Pair("scriptid", scriptID.GetHex()));
	}

	if (IsDefault()) {
		obj.push_back(Pair("default", true));
	}

	return (obj);
}

void CAccountAddressKey::SetNull()
{
	CAccountAddress::SetNull();
	key = NULL;
	pubkey = CPubKey();
}

void CAccountAddressKey::Init()
{

	CAccountAddress::Init();

	if (wallet && key == NULL && keyid.size() != 0) {
		key = wallet->GetKey(keyid); 
		if (key) {
			pubkey = key->GetPubKey();
		}
	}

}

Object CAccountAddressKey::ToValue()
{
	Object obj = CAccountAddress::ToValue();
	CAccountCache *account = GetAccountCache();
	bool fDilithium = false;
	bool fCompressed = false;

	obj.push_back(Pair("type", "key"));

	if (key) {
		fDilithium = key->IsDilithium();

		CSecret vchSecret = key->GetSecret(fCompressed);;
		CCoinSecret csec(ifaceIndex, vchSecret, fCompressed);
		obj.push_back(Pair("ref", csec.ToString()));

		if (key->nCreateTime != 0) {
			obj.push_back(Pair("create", (boost::uint64_t)key->nCreateTime));
		}

		if (!fDilithium) {
			obj.push_back(Pair("alg", string("ecdsa")));
		} else {
			obj.push_back(Pair("alg", string("dilithium")));
		}

		if (key->nFlag != 0) {
			obj.push_back(Pair("flag", (boost::uint64_t)key->nFlag));
//			obj.push_back(Pair("flags", key->GetFlagString()));
		}

		if (key->nFlag & ACCADDRF_DERIVE) {
			obj.push_back(Pair("keypath", key->hdKeypath));
			obj.push_back(Pair("masterkeyid", key->hdMasterKeyID.GetHex()));
		}

		if (account) {
			vector<CTxDestination> vDest;
			account->CalcAddressBook(key, vDest); 

			Array addr_list;
			CTxDestination destination = GetDestination();
			BOOST_FOREACH(const CTxDestination& destTmp, vDest) {
				if (destTmp == destination) continue; /* already reported on. */
				CCoinAddr t_addr(wallet->ifaceIndex, destTmp);
				addr_list.push_back(t_addr.ToString());
			}
			if (addr_list.size() != 0) {
				obj.push_back(Pair("alias", addr_list));
			}
		}
	}

	if (account && IsDefault()) {
		Array echdindex;
		for (int nMode = 0; nMode < MAX_HD_ACCADDR; nMode++) {
			echdindex.push_back(Value((uint64_t)account->GetHDIndex(nMode, SIGN_ALG_ECDSA)));
		}
		obj.push_back(Pair("echdi", echdindex));

		Array dihdindex;
		for (int nMode = 0; nMode < MAX_HD_ACCADDR; nMode++) {
			dihdindex.push_back(Value((uint64_t)account->GetHDIndex(nMode, SIGN_ALG_DILITHIUM)));
		}
		obj.push_back(Pair("dihdi", dihdindex));
	}
#if 0
	/* list all aliases of the pubkey address. */
  if (account && keyid != 0) {
		CTxDestination destination = GetDestination();
    vector<CTxDestination> vDest;
    Array addr_list;

    account->GetAddrDestination(keyid, vDest, (fDilithium ? ACCADDRF_DILITHIUM : 0));
    BOOST_FOREACH(const CTxDestination& destTmp, vDest) {
      if (destTmp == destination) continue; /* already reported on. */
      CCoinAddr t_addr(wallet->ifaceIndex, destTmp);
      addr_list.push_back(t_addr.ToString());
    }
    if (addr_list.size() != 0) {
      obj.push_back(Pair("alias", addr_list));
		}
	}
#endif

	if (!fDilithium && fCompressed) {
		obj.push_back(Pair("compressed", true));
	}

	return (obj);
}

bool CAccountAddressKey::FromValue(Object obj)
{
	bool fImport = false;

	if (!wallet) {
		/* invalid chain */
		return (false);
	}

	string strType = strFromObject(obj, "type");
	if (strType != "" && strType != "key") {
		/* not applicable. */
		return (false);
	}

#if 0
	boolean fDilithium = false;
	string strAlg = GetObjectString(obj, "alg");
	if (strAlg == "") {
		if (secret.size() == 96)
			fDilithium = true;
	} else {
		if (strAlg == "dilithium") {
			fDilithium = true;
		} else if (strAlg != "ecdsa") {
			// unsupported algorithm
			return (error(SHERR_OPNOTSUPP, "[CAccountAddressKey::FromValue] key algorithm \"" + strAlg + "\" not supported."));
		}
	}
#endif

	int nFlag = numFromObject(obj, "flag");

	time_t nCreateTime = numFromObject(obj, "create"); 

	string strAccount = strFromObject(obj, "origin");
	if (strAccount.size() == 0)
		strAccount = strFromObject(obj, "label"); // bc

	string strScript = strFromObject(obj, "script");

	string strKey = strFromObject(obj, "ref");
	if (strKey.size() == 0)
		strKey = strFromObject(obj, "key"); // bc

	string strAddress = strFromObject(obj, "addr");

	CAccountCache *account = wallet->GetAccount(strAccount);
	if (!account) {
		return (error(ERR_INVAL, "account not available."));
	}

	if (strScript.size() != 0) {
		/* an alias which references another coin address. */
		script = CScript(ParseHex(strScript));
		if (script.size() == 0) {
			/* invalid format */
			return (false);
		}

		/* add script to wallet. */
		CScriptID scriptID = CScriptID(script);
		fImport = !wallet->HaveCScript(scriptID);
		if (fImport) {
			wallet->AddCScript(script);
			wallet->SetAddressBookName(scriptID, strAccount);
		}

		/* initialize as script-id coin addr. */
		Set(scriptID);
	} else if (strKey.size() != 0) {
		CCoinSecret vchSecret;
		if (!vchSecret.SetString(strKey)) {
			/* invalid key specified. */
			return (error(ERR_INVAL, "[CAccountAddressKey::FromValue] Invalid coin secret specified."));
		}

		{
			LOCK2(cs_main, wallet->cs_wallet);

			bool fCompressed = false;
			CSecret secret = vchSecret.GetSecret(fCompressed);

			if (secret.size() == 96) { // dilithium
				DIKey dikey;
				dikey.SetNull();
				dikey.SetSecret(secret, fCompressed);
				dikey.nFlag |= nFlag;
				dikey.nCreateTime = nCreateTime;

				string strMasterKeyID = strFromObject(obj, "masterkeyid");
				if (strMasterKeyID.size() > 2) {
					dikey.hdMasterKeyID = CKeyID(uint160(strMasterKeyID));
					dikey.hdKeypath = strFromObject(obj, "keypath");
					dikey.nFlag |= ACCADDRF_DERIVE;
				}

				keyid = dikey.GetPubKey().GetID();
				fImport = !wallet->HaveKey(keyid);
				if (fImport) {
#if 0
					wallet->AddKey(dikey);
					wallet->SetAddressBookName(keyid, strAccount);
#endif
					account->AddKey(dikey);
				}
			} else { /* ECDSA */
				ECKey eckey;
				eckey.SetNull();
				eckey.SetSecret(secret, fCompressed);
				eckey.nFlag |= nFlag;
				eckey.nCreateTime = nCreateTime;

				string strMasterKeyID = strFromObject(obj, "masterkeyid");
				if (strMasterKeyID.size() > 2) {
					eckey.hdMasterKeyID = CKeyID(uint160(strMasterKeyID));
					eckey.hdKeypath = strFromObject(obj, "keypath");
					eckey.nFlag |= ACCADDRF_DERIVE;
				}

				keyid = eckey.GetPubKey().GetID();
				fImport = !wallet->HaveKey(keyid);
				if (fImport) {
#if 0
					wallet->AddKey(eckey);
					wallet->SetAddressBookName(keyid, strAccount);
#endif
					account->AddKey(eckey);
				}
			}
		}

		Set(keyid);
	} else if (strAddress.size() != 0) { 
		/* no key was specified. */
		SetString(strAddress);
	}

	/* initialize internal variables. */
	Init();

	if (!IsValid()) {
		return (error(SHERR_INVAL, "[CAccountAddressKey::FromValue] imported coin address is not valid."));
	}

#if 0
	if (fImport) {
		CAccountCache *account = GetAccountCache();
		if (account) {
			/* generate variant versions of coin address. */
			account->SetAddrDestinations(keyid);
			// todo: do above in wallet.import instead

			bool fDefault = boolFromObject(obj, "default"); 
			bool fMaster = boolFromObject(obj, "master");
			if (fDefault) {
				account->SetDefaultAddr(pubkey);
//				account->UpdateAccount();
			} else if (fMaster) {
				int hdindex = numFromObject(obj, "hdindex");
				int ihdindex = numFromObject(obj, "ihdindex");
				if (account->account.masterKeyID != keyid) {
					account->account.masterKeyID = keyid;
					if (key->IsDilithium()) {
						account->account.nInternalDIChainCounter = ihdindex;
						account->account.nExternalDIChainCounter = hdindex;
					} else {
						account->account.nInternalECChainCounter = ihdindex;
						account->account.nExternalECChainCounter = hdindex;
					}
				}
				account->UpdateAccount();

				/* TODO: Need to utilize "hdindex" more intelligently. After import is completed perform an additional sweep up to "hdindex" to ensure all addresses are created even if they are not included in export JSON file. Their nCreateTime CAN be rewinded to the parent (master) key. */
			}
		}
	}
#endif

	return (fImport);
}

/* Generates a ECDSA hd-key chain until an address cannot be identified. */
void CAccountCache::CalculateECKeyChain(vector<CTxDestination>& vAddr, int nType, int nMinCount)
{
	CAccount *hdChain = &account;
	ECExtKey chainChildKey;         //key at m/0'/0' (external) or m/0'/1' (internal)
	ECExtKey childKey;              //key at m/0'/0'/<n>'
	string hdKeypath;

	if (!hdChain)
		return;

	if (!wallet->DerivePrimaryECExtKey(hdChain, chainChildKey, nType))
		return;

	// derive child key at next index, skip keys already known to the wallet
	do {
		// always derive hardened keys
		// childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
		// example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
		uint nIndex = hdChain->GetHDIndex(nType, SIGN_ALG_ECDSA);
		chainChildKey.Derive(childKey, nIndex | BIP32_HARDENED_KEY_LIMIT);
		hdKeypath = "m/0'/" + std::to_string(nType) + "'/" + std::to_string(nIndex) + "'";

		bool fFound = false;
		bool fImport = true;
		const CKeyID& keyid = childKey.key.GetPubKey().GetID();
		if (wallet->HaveKey(keyid)) {
			fFound = true;
			fImport = false;
		} else if (nIndex < nMinCount) {
			fFound = true;
		} else if (find(vAddr.begin(), vAddr.end(), CTxDestination(keyid)) != vAddr.end()) {
			fFound = true;	
		}
		if (!fFound)
			break;

		hdChain->IncrementHDIndex(nType, SIGN_ALG_ECDSA); 	

		if (fImport) {
			ECKey secret;
			secret = childKey.key;
			secret.nFlag |= ACCADDRF_DERIVE;
			secret.hdMasterKeyID = hdChain->GetMasterKeyID();
			secret.hdKeypath = hdKeypath;

#if 0
			wallet->AddKey(secret);
			GetAddrDestinations(keyid, vAddr);
#endif
			AddKey(secret);
		}
	} while (1);

}

/* Generates a Dilithium hd-key chain until an address cannot be identified. */
void CAccountCache::CalculateDIKeyChain(vector<CTxDestination>& vAddr, int nMode, int nMinCount)
{
	CAccount *hdChain = &account;
	DIExtKey chainChildKey;         //key at m/0'/0' (external) or m/0'/1' (internal)
	DIExtKey childKey;              //key at m/0'/0'/<n>'
	string hdKeypath;

	if (!hdChain)
		return;

	if (!wallet->DerivePrimaryDIExtKey(hdChain, chainChildKey, nMode))
		return;

	// derive child key at next index, skip keys already known to the wallet
	do {
		// always derive hardened keys
		// childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
		// example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
		uint nIndex = hdChain->GetHDIndex(nMode, SIGN_ALG_DILITHIUM);
		chainChildKey.Derive(childKey, nIndex | BIP32_HARDENED_KEY_LIMIT);
		hdKeypath = "m/0'/" + std::to_string(nMode) + "'/" + std::to_string(nIndex) + "'";

		bool fImport = false;
		bool fFound = false;
		const CKeyID& keyid = childKey.key.GetPubKey().GetID();
		if (wallet->HaveKey(keyid)) {
			fFound = true;
			fImport = false;
		} else if (nIndex < nMinCount) {
			fFound = true;
		} else if (find(vAddr.begin(), vAddr.end(), CTxDestination(keyid)) != vAddr.end()) {
			fFound = true;
		}
		if (!fFound)
			break;

		hdChain->IncrementHDIndex(nMode, SIGN_ALG_DILITHIUM);

		if (fImport) {
			DIKey secret;
			secret = childKey.key;
			secret.nFlag |= ACCADDRF_DERIVE;
			secret.nFlag |= ACCADDRF_DILITHIUM;
			secret.hdMasterKeyID = hdChain->GetMasterKeyID();
			secret.hdKeypath = hdKeypath;

#if 0
			wallet->AddKey(secret);
			GetAddrDestinations(keyid, vAddr);
#endif
			AddKey(secret);
		}
	} while (1);

}

bool CAccountCache::GetCoinbasePubKey(CPubKey& pubkeyRet)
{
	const char *tagstr = "coinbase";
	cbuff tag(tagstr, tagstr + strlen(tagstr));
	return (GetMergedPubKey(ACCADDR_MINER, SIGN_ALG_ECDSA, tag, pubkeyRet));
}

CCoinAddr CAccountCache::GetCoinbaseAddr()
{
	CCoinAddr addrRet(wallet->ifaceIndex);
	CPubKey pubkey;

	if (GetCoinbasePubKey(pubkey)) {
		addrRet = CCoinAddr(wallet->ifaceIndex, CTxDestination(pubkey.GetID()));
	}

	return (addrRet);
}

bool CAccountCache::AddKey(ECKey& key)
{
	const CPubKey& pubkey = key.GetPubKey();
	const CKeyID& keyid = pubkey.GetID();

	if (keyid == 0) {
		return (false);
	}

	if (wallet->HaveKey(keyid)) {
		/* redundant */
		return (true);
	}

	if (!wallet->AddKey(key)) {
		return (false);
	}

	vector<CTxDestination> vAddr;
	SetAddressBook(&key, vAddr);
	return (true);
}

bool CAccountCache::AddKey(DIKey& key)
{
	const CPubKey& pubkey = key.GetPubKey();
	const CKeyID& keyid = pubkey.GetID();

	if (keyid == 0) {
		return (false);
	}

	if (wallet->HaveKey(keyid)) {
		/* redundant */
		return (true);
	}

	key.nFlag |= ACCADDRF_DILITHIUM;
	key.nFlag |= ACCADDRF_WITNESS;
	if (!wallet->AddKey(key)) {
		return (false);
	}

	vector<CTxDestination> vAddr;
	SetAddressBook(&key, vAddr);
	return (true);
}

void CAccountCache::CalcAddressBook(const CKeyID& keyid, vector<CTxDestination>& vDest, bool fDilithium)
{
	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	int nFlag = 0;

	if (fDilithium) {
		nFlag |= ACCADDRF_DILITHIUM;
		nFlag |= ACCADDRF_WITNESS;
	} else if (IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		nFlag |= ACCADDRF_WITNESS;
	}

	return (GetAddrDestination(wallet->ifaceIndex, keyid, vDest, nFlag));
}

void CAccountCache::CalcAddressBook(CKey *key, vector<CTxDestination>& vDest)
{
	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	bool fDilithium = key->IsDilithium();
	int nFlag = key->nFlag;

	if (fDilithium) {
		nFlag |= ACCADDRF_DILITHIUM;
		nFlag |= ACCADDRF_WITNESS;
	} else if (IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		nFlag |= ACCADDRF_WITNESS;
	}

	const CKeyID& keyid = key->GetPubKey().GetID();
	return (GetAddrDestination(wallet->ifaceIndex, keyid, vDest, nFlag));

#if 0
	if (!fDilithium) {
		/* pubkey coin address */
		CTxDestination destPubKey(keyid);
		if (find(vDest.begin(), vDest.end(), destPubKey) == vDest.end()) {
			vDest.push_back(destPubKey);
		}

		/* CScriptID destination to pubkey. */
		CScript scriptPubKey;
		scriptPubKey.SetDestination(keyid);
		CScriptID scriptID(scriptPubKey);
		CTxDestination destScriptID(scriptID);
		if (find(vDest.begin(), vDest.end(), destScriptID) == vDest.end()) {
			vDest.push_back(destScriptID);
		}
	}

	CIface *iface = GetCoinByIndex(ifaceIndex);
	if (iface && IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		CCoinAddr addr(ifaceIndex, keyid);

		if (!fDilithium) {
			/* generate "program 0" p2sh-segwit address. */
			CTxDestination sh_dest = addr.GetWitness(OUTPUT_TYPE_P2SH_SEGWIT);
			if (find(vDest.begin(), vDest.end(), sh_dest) == vDest.end()) {
				vDest.push_back(sh_dest);
			}

			/* bech32 destination address. */
			CTxDestination be_dest = addr.GetWitness(OUTPUT_TYPE_BECH32);
			if (find(vDest.begin(), vDest.end(), be_dest) == vDest.end()) {
				vDest.push_back(be_dest);
			}
		} else {
			/* bech32 destination address. */
			CTxDestination be_dest = addr.GetWitness(OUTPUT_TYPE_DILITHIUM);
			if (find(vDest.begin(), vDest.end(), be_dest) == vDest.end()) {
				vDest.push_back(be_dest);
			}
		}
	}
#endif
}

void CAccountCache::SetAddressBook(const CKeyID& keyid, vector<CTxDestination>& vDest, bool fDilithium)
{
	vector<CTxDestination> vCalcDest;

	CalcAddressBook(keyid, vCalcDest, fDilithium);

	if (!fDilithium) {
		CScript scriptPubKey;
		scriptPubKey.SetDestination(keyid);
		wallet->AddCScript(scriptPubKey);
	}

	BOOST_FOREACH(const CTxDestination& dest, vCalcDest) {
		wallet->SetAddressBookName(dest, strAccount);
		if (find(vDest.begin(), vDest.end(), dest) == vDest.end()) {
			vDest.push_back(dest);
		}
	}
}

void CAccountCache::SetAddressBook(CKey *key, vector<CTxDestination>& vDest)
{
	vector<CTxDestination> vCalcDest;

	CalcAddressBook(key, vCalcDest);

	if (!key->IsDilithium()) {
		const CKeyID keyid = key->GetPubKey().GetID();

		CScript scriptPubKey;
		scriptPubKey.SetDestination(keyid);
		wallet->AddCScript(scriptPubKey);
	}

	BOOST_FOREACH(const CTxDestination& dest, vCalcDest) {
		wallet->SetAddressBookName(dest, strAccount);
		if (find(vDest.begin(), vDest.end(), dest) == vDest.end()) {
			vDest.push_back(dest);
		}
	}
}

CTxDestination CAccountCache::GetDestination(const CKeyID& keyid, int nFlag)
{
  bool fBech32 = opt_bool(OPT_BECH32);
	CTxDestination addrRet;

	if (nFlag & ACCADDRF_WITNESS) {
		CCoinAddr addr(wallet->ifaceIndex, keyid);
		if (nFlag & ACCADDRF_DILITHIUM) {
			addrRet = addr.GetWitness(OUTPUT_TYPE_DILITHIUM);
		} else if (!fBech32) {
			addrRet = addr.GetWitness(OUTPUT_TYPE_P2SH_SEGWIT);
		} else {
			addrRet = addr.GetWitness(OUTPUT_TYPE_BECH32);
		}
	} else {
		/* regular */
    addrRet = CTxDestination(keyid);
	}

	return (addrRet);
}

CTxDestination CAccountCache::GetDestination(CKey *key)
{
	CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
	bool fDilithium = key->IsDilithium();
	int nFlag = key->nFlag;

	if (fDilithium) {
		nFlag |= ACCADDRF_DILITHIUM;
		nFlag |= ACCADDRF_WITNESS;
	} else if (!IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		nFlag &= ~ACCADDRF_WITNESS;
	}

	const CKeyID& keyid = key->GetPubKey().GetID();
	return (GetDestination(keyid, nFlag)); 
}

bool CAccountCache::GenerateNewECKey(CPubKey& pubkeyRet, bool fCompressed, int nFlag)
{
	ECKey ckey;
	wallet->GenerateNewECKey(ckey, fCompressed, nFlag);

	if (!AddKey(ckey))
		return (false);

	pubkeyRet = ckey.GetPubKey(); 
	return (true);
}

bool CAccountCache::GenerateNewDIKey(CPubKey& pubkeyRet, int nFlag)
{
	DIKey ckey;
	nFlag |= ACCADDRF_DILITHIUM;
	nFlag |= ACCADDRF_WITNESS;
	wallet->GenerateNewDIKey(ckey, nFlag);

	if (!AddKey(ckey))
		return (false);

	pubkeyRet = ckey.GetPubKey(); 
	return (true);
}

