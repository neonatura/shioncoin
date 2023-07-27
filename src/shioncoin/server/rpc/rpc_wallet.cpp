
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
#include <unistd.h>
using namespace std;
#include "main.h"
#include "wallet.h"
#include "txcreator.h"
#include "db.h"
#include "walletdb.h"
#include "net.h"
#include "base58.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "mnemonic.h"
#include "txmempool.h"
#include "txfeerate.h"
#include "rpc_proto.h"
#include "rpc_command.h"
#include "rpccert_proto.h"
#include "account.h"
#include "stratum/stratum.h"

#include <boost/assign/list_of.hpp>

using namespace boost;
using namespace json_spirit;
using namespace boost::assign;

extern json_spirit::Value ValueFromAmount(int64 amount);
extern bool IsAccountValid(CIface *iface, std::string strAccount);
extern string AccountFromValue(const Value& value);
extern int GetPubKeyMode(const char *tag);
extern string ToValue_date_format(time_t t);

Value rpc_wallet_balance(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() > 2)
		throw runtime_error(
				"wallet.balance [account] [minconf=1]\n"
				"If [account] is not specified, returns the server's total available balance.\n"
				"If [account] is specified, returns the balance in the account.");

	if (params.size() == 0)
		return  ValueFromAmount(pwalletMain->GetBalance());

	int nMinDepth = 1;
	if (params.size() > 1)
		nMinDepth = params[1].get_int();

	if (params[0].get_str() == "*") {
		// Calculate total balance a different way from GetBalance()
		// (GetBalance() sums up all unspent TxOuts)
		// getbalance and getbalance '*' should always return the same number.
		int64 nBalance = 0;
		for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
		{
			const CWalletTx& wtx = (*it).second;
			if (!wtx.IsFinal(ifaceIndex))
				continue;

			int64 allGeneratedImmature, allGeneratedMature, allFee;
			allGeneratedImmature = allGeneratedMature = allFee = 0;
			string strSentAccount;
			list<pair<CTxDestination, int64> > listReceived;
			list<pair<CTxDestination, int64> > listSent;
			wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount);
			//wtx.GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount);
			if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
			{
				BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listReceived)
					nBalance += r.second;
			}
			BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listSent)
				nBalance -= r.second;
			nBalance -= allFee;
			//      nBalance += allGeneratedMature;
		}
		return  ValueFromAmount(nBalance);
	}

	string strAccount = AccountFromValue(params[0]);

	int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);

	return ValueFromAmount(nBalance);
}

void rpcwallet_GetWalletAddr(CWallet *wallet, shjson_t *tree, string strLabel, const CKeyID& keyID)
{
	CKey *key;
	shjson_t *node;
	bool fCompressed;

	key = wallet->GetKey(keyID);
	if (!key)
		return;

	CSecret vchSecret = key->GetSecret(fCompressed);;
	CCoinSecret csec(wallet->ifaceIndex, vchSecret, fCompressed);
	CCoinAddr addr(wallet->ifaceIndex, keyID);

	node = shjson_obj_add(tree, NULL);
	shjson_str_add(node, "key", (char *)csec.ToString().c_str()); 
	shjson_str_add(node, "label", (char *)strLabel.c_str());
	shjson_str_add(node, "addr", (char *)addr.ToString().c_str());

	CAccountCache *acc = wallet->GetAccount(strLabel);
	if (!acc)
		return;

	const CPubKey& pubkey = key->GetPubKey();

	if (key->nCreateTime != 0)
		shjson_num_add(node, "create", (double)key->nCreateTime);
	if (key->nFlag != 0)
		shjson_num_add(node, "flag", (double)key->nFlag);
	if (acc->account.vchPubKey == pubkey)
		shjson_bool_add(node, "default", TRUE);

#if 0
	CAccount *chain = &acc->account;
	if (chain->masterKeyID == pubkey.GetID()) {
		shjson_bool_add(node, "master", TRUE);
		if (pubkey.IsDilithium()) {
			shjson_num_add(node, "hdindex", chain->nExternalDIChainCounter);
		} else {
			shjson_num_add(node, "hdindex", chain->nExternalECChainCounter);
		}
	}
#endif

}

#if 0
Value rpc_wallet_export(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() != 1)
		throw runtime_error("wallet.export");

	std::string strPath = params[0].get_str();
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	shjson_t *json = shjson_init(NULL);
	shjson_t *tree = shjson_array_add(json, iface->name);
	string strSystemLabel("coinbase");
	vector<CScriptID> vSkip;
	FILE *fl;
	char *text;

	/* handle loner keys. */
	std::set<CKeyID> keys;
	wallet->GetKeys(keys);
	BOOST_FOREACH(const CKeyID& keyid, keys) {
		if (wallet->mapAddressBook.count(keyid) == 0) 
			rpcwallet_GetWalletAddr(wallet, tree, strSystemLabel, keyid);
	}

	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
		CTxDestination dest = entry.first;
		string strLabel = entry.second;

		CCoinAddr addr(ifaceIndex, dest);
		CKeyID keyID;
		if (addr.GetKeyID(keyID)) {
			rpcwallet_GetWalletAddr(wallet, tree, strLabel, keyID);

			/* retain script derivatives. */
			CScriptID scriptID;
			vector<CTxDestination> vDestTmp;
			GetAddrDestination(wallet->ifaceIndex, keyID, vDestTmp);
			BOOST_FOREACH(const CTxDestination& dest, vDestTmp) {
				CCoinAddr addrTmp(wallet->ifaceIndex, dest);
				if (addrTmp.GetScriptID(scriptID))
					vSkip.push_back(scriptID);
			}
		}
	}

	/* handle scripts not directly derived from regular pubkey (witness, etc) */
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
		CTxDestination dest = entry.first;
		string strLabel = entry.second;

		CScriptID scriptID;
		CCoinAddr addr(wallet->ifaceIndex, dest);
		if (addr.GetScriptID(scriptID)) {
			if (find(vSkip.begin(), vSkip.end(), scriptID) != vSkip.end())
				continue; /* will be regenerated. */

			CScript script;
			if (!wallet->GetCScript(scriptID, script))
				continue;

			shjson_t *node = shjson_obj_add(tree, NULL);
			shjson_str_add(node, "script", (char *)HexStr(script).c_str());
			shjson_str_add(node, "label", (char *)strLabel.c_str());
			shjson_str_add(node, "addr", (char *)addr.ToString().c_str());
		}
	}

	text = shjson_print(json);
	shjson_free(&json);

	fl = fopen(strPath.c_str(), "wb");
	if (fl) {
		fwrite(text, sizeof(char), strlen(text), fl);
		fclose(fl);
	}
	free(text);

	return Value::null;
}
#endif

/** removes from address book only -- does not remove from keystore */
Value rpc_wallet_prune(CIface *iface, const Array& params, bool fStratum)
{
	int ifaceIndex = GetCoinIndex(iface);
	CWallet *pwalletMain = GetWallet(iface);

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() != 1)
		throw runtime_error("wallet.prune");

	string strAccount = AccountFromValue(params[0]);

	vector<CTxDestination> vRemove;
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
		CTxDestination book_dest = entry.first;
		string strLabel = entry.second;

		if (!IsMine(*pwalletMain, book_dest))
			continue;

		CKeyID key;
		CCoinAddr(ifaceIndex, book_dest).GetKeyID(key);

		/* was this key ever used. */
		int nTxInput = 0;
		int nTxSpent = 0;
		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
			const CWalletTx& tx = item.second;
			int i;
			for (i = 0; i < tx.vout.size(); i++) {
				CTxDestination dest;
				if (!ExtractDestination(tx.vout[i].scriptPubKey, dest))
					continue;
				CKeyID k1;
				CCoinAddr(ifaceIndex, dest).GetKeyID(k1);
				if (k1 == key) {
					if (tx.IsSpent(i)) {
						nTxSpent++;
					}
					nTxInput++;
				}
			}
		}

		if (nTxInput == 0 || (nTxSpent >= nTxInput)) {
			/* never used or spent */
			vRemove.push_back(book_dest);
		}

	}

	BOOST_FOREACH(const CTxDestination& dest, vRemove) {
		pwalletMain->mapAddressBook.erase(dest);  
	}

	return Value::null;
}

Value rpc_wallet_get(CIface *iface, const Array& params, bool fStratum)
{
	int ifaceIndex = GetCoinIndex(iface);

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *pwalletMain = GetWallet(iface);
	if (params.size() != 1)
		throw runtime_error("wallet.get");

	CAccountAddress address(ifaceIndex, params[0].get_str());
	if (!address.IsValid()) {
		throw JSONRPCError(-5, "Invalid coin address");
	}

#if 0
	string strAccount = "";
	map<CTxDestination, string>::iterator mi = pwalletMain->mapAddressBook.find(address.Get());
	if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.empty())
		strAccount = (*mi).second;
	return strAccount;
#endif

	return (address.ToValue());
}

Value rpc_wallet_key(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	bool fVerbose;

	if (fStratum)
		throw runtime_error("unsupported operation");

	string strAddress = params[0].get_str();

	fVerbose = false;
	if (params.size() == 2)
		fVerbose = params[1].get_bool();

	CCoinAddr address(ifaceIndex, strAddress);
	if (!address.IsValid())
		throw JSONRPCError(ERR_INVAL, "Invalid address");

	CKeyID keyid;
	if (!ExtractDestinationKey(wallet, address.Get(), keyid)) {
		if (!address.GetKeyID(keyid)) {
			throw JSONRPCError(ERR_NOKEY, "Invalid address destination");
		}
	}

	if (fVerbose) {
		CAccountAddressKey addr(ifaceIndex, CTxDestination(keyid));
		if (!addr.IsValid())
			throw JSONRPCError(ERR_NOKEY, "Private key for address " + strAddress + " is not known");
		return (addr.ToValue());
	}

	/* private key only */
	CSecret vchSecret;
	bool fCompressed = true;
	if (!wallet->GetSecret(keyid, vchSecret, fCompressed))
		throw JSONRPCError(ERR_NOKEY, "Private key for address " + strAddress + " is not known");

	return CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString();
}

Value rpc_wallet_hdkey(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	string strAddress = params[0].get_str();

	bool fVerbose = false;
	if (params.size() == 2)
		fVerbose = params[1].get_bool();

	if (fVerbose) {
		CAccountAddressKey address(ifaceIndex, strAddress);
		return (address.ToValue());
	}

	CCoinAddr address(ifaceIndex, strAddress);
	if (!address.IsValid())
		throw JSONRPCError(ERR_INVAL, "Invalid address");

	CKeyID keyid;
	if (!ExtractDestinationKey(wallet, address.Get(), keyid)) {
		if (!address.GetKeyID(keyid)) {
			throw JSONRPCError(ERR_NOKEY, "Invalid address");
		}
	}

	while (keyid != 0) {
		CKey *key = wallet->GetKey(keyid);
		if (!key)
			break;

		if (key->hdMasterKeyID == 0)
			break;

		keyid = key->hdMasterKeyID;
	};
	if (keyid == 0) {
		throw JSONRPCError(ERR_NOKEY, "Private hd-key for address " + strAddress + " is not known");
	}

#if 0
	bool fCompressed = false;
	CSecret vchSecret = key->GetSecret(fCompressed);
	return CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString();
#endif
	CAccountAddressKey addr(ifaceIndex, CTxDestination(keyid));
	return (addr.ToValue());
}

Value rpc_wallet_info(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() != 0)
		throw runtime_error("invalid parameters specified");

	Object obj;
	obj.push_back(Pair("version",       (int)CLIENT_VERSION));

	obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance())));

	return obj;
}

Value rpc_wallet_cscript(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	string strAccount;
	CScript script;
	CScriptID cid;

	if (params.size() > 1)
		throw runtime_error("invalid parameters specified");

	CCoinAddr address(ifaceIndex, params[0].get_str());
	if (!address.IsValid())
		throw JSONRPCError(-5, "Invalid coin address specified.");
	if (!GetCoinAddr(wallet, address, strAccount))
		throw JSONRPCError(-5, "No account associated with coin address.");

	script = address.GetScript();
	if (script.empty())
		throw JSONRPCError(-5, "Unable to generate script from coin address.");

	/* generate a Script ID referencing the output destination script. */
	cid = script.GetID();
	CCoinAddr script_addr(ifaceIndex, cid);
	/* retain */
	wallet->AddCScript(script);
	wallet->SetAddressBookName(cid, strAccount);

	return (Value(script_addr.ToString()));
}

#if 0
Value rpc_wallet_import(CIface *iface, const Array& params, bool fStratum)
{
	int nTotal = 0;
	int nRecs = 0;

	if (fStratum)
		throw runtime_error("unsupported operation");
	if (params.size() != 1)
		throw runtime_error("wallet.import");

	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	std::string strPath = params[0].get_str();
	char *script_hex;
	time_t nMinTime = 0;

	wallet->MarkDirty();

	{
		shjson_t *json;
		shjson_t *tree;
		shjson_t *node;
		char *text;
		struct stat st;
		FILE *fl;
		char label[256];
		char addr[256];
		char key[256];
		uint32_t nFlag;
		time_t nCreateTime;

		memset(label, 0, sizeof(label));
		memset(addr, 0, sizeof(addr));
		memset(key, 0, sizeof(key));

		fl = fopen(strPath.c_str(), "rb");
		if (!fl)
			throw runtime_error("error opening file.");

		memset(&st, 0, sizeof(st));
		fstat(fileno(fl), &st);
		if (st.st_size == 0)
			throw runtime_error("file is not in JSON format.");

		text = (char *)calloc(st.st_size + 1, sizeof(char));
		if (!text)
			throw runtime_error("not enough memory to allocate file.");

		fread(text, sizeof(char), st.st_size, fl);
		fclose(fl);

		//    serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

		json = shjson_init(text);
		free(text);
		if (!json) {
			throw runtime_error("file is not is JSON format.");
		}

		tree = json->child;
		if (tree && tree->string) {
			if (0 != strcmp(tree->string, iface->name))
				throw runtime_error("wallet file references incorrect coin service.");

			for (node = tree->child; node; node = node->next) {
				strncpy(label, shjson_astr(node, "label", ""), sizeof(label)-1);
				strncpy(addr, shjson_astr(node, "addr", ""), sizeof(addr)-1);
				strncpy(key, shjson_astr(node, "key", ""), sizeof(key)-1);
				nFlag = (uint32_t)shjson_num(node, "flag", 0);
				nCreateTime = (time_t)shjson_num(node, "create", 0);
				script_hex = shjson_str(node, "script", NULL);

				nRecs++;

				if (script_hex && strlen(script_hex) != 0) {
					CScript scriptPubKey(ParseHex(script_hex));
					CScriptID scriptID(scriptPubKey);
					if (!wallet->HaveCScript(scriptID)) {
						string strLabel(label);

						/* add script to wallet. */
						wallet->AddCScript(scriptPubKey);
						wallet->SetAddressBookName(scriptID, strLabel);
						nTotal++;
					}

				/* DEBUG: TODO: handle nMinTime */

					free(script_hex);
					continue;
				}

				if (!*key) continue;

				string strSecret(key);
				string strLabel(label);

				CCoinSecret vchSecret;
				bool fGood = vchSecret.SetString(strSecret);
				if (!fGood) {
					error(ERR_INVAL, "rpc_wallet_import: invalid secret \"%s\"\n", strSecret.c_str()); 
					continue;
				}

				bool fCompressed = false;
				CSecret secret = vchSecret.GetSecret(fCompressed);

				{
					LOCK2(cs_main, wallet->cs_wallet);

					CKey *key = NULL;
					CKeyID vchAddress;

					if (secret.size() == 96) {
						/* dilithium */
						static DIKey dikey;

						dikey.SetNull();
						dikey.SetSecret(secret, fCompressed);

						vchAddress = dikey.GetPubKey().GetID();
#if 0
						key = wallet->GetKey(vchAddress);
						if (key) {
							if (nCreateTime == 0 || nCreateTime >= key->nCreateTime)
								continue;
						}
#endif
						if (wallet->HaveKey(vchAddress)) continue;

						dikey.nFlag |= nFlag;
//						dikey.nFlag |= CKeyMetadata::META_DILITHIUM;
						if (nCreateTime != 0)
							dikey.nCreateTime = nCreateTime;
						if (!wallet->AddKey(dikey))
							continue; 

						key = &dikey;
					} else {
						/* ecdsa */
						static ECKey eckey;

						eckey.SetNull();
						eckey.SetSecret(secret, fCompressed);

						vchAddress = eckey.GetPubKey().GetID();
#if 0
						key = wallet->GetKey(vchAddress);
						if (key) {
							if (nCreateTime == 0 || nCreateTime >= key->nCreateTime)
								continue;
						}
#endif
						if (wallet->HaveKey(vchAddress)) continue;

						eckey.nFlag |= nFlag;
						if (nCreateTime != 0)
							eckey.nCreateTime = nCreateTime;
						if (!wallet->AddKey(eckey))
							continue; 

						key = &eckey;
					}

					if (nMinTime == 0 || nMinTime > nCreateTime)
						nMinTime = (time_t)nCreateTime;

					nTotal++;

					/* redundant */
					wallet->SetAddressBookName(vchAddress, strLabel);

					CAccountCache *acc = wallet->GetAccount(strLabel); 
					if (!acc)
						continue;

					/* generate all the coin address variants for this pubkey addr. */
					acc->SetAddrDestinations(vchAddress);

					if (shjson_bool(node, "default", FALSE)) {
						acc->SetDefaultAddr(key->GetPubKey());
					} else if (shjson_bool(node, "master", FALSE)) {
						int hdindex = shjson_num(node, "hdindex", 0);
						if (acc->account.masterKeyID != vchAddress) {
							acc->account.masterKeyID = vchAddress;
							if (key->IsDilithium()) {
								acc->account.nInternalDIChainCounter = 0;
								acc->account.nExternalDIChainCounter = hdindex;
							} else {
								acc->account.nInternalECChainCounter = 0;
								acc->account.nExternalECChainCounter = hdindex;
							}
							acc->UpdateAccount();

/* TODO: Need to utilize "hdindex" more intelligently. After import is completed perform an additional sweep up to "hdindex" to ensure all addresses are created even if they are not included in export JSON file. Their nCreateTime CAN be rewinded to the parent (master) key. */

						}
					}
				}

			} /* for(node) */
		}

		shjson_free(&json);
	}

	CBlockIndex *pindexStart = NULL;
	if (nTotal != 0) {
		if (nMinTime == 0) {
			/* scan from beginning of chain */
			pindexStart = GetGenesisBlockIndex(iface);
		} else {
			/* rewind to minimum time */
			pindexStart = GetBestBlockIndex(iface);
			while (pindexStart && pindexStart->pprev &&
					pindexStart->nTime > nMinTime)
				pindexStart = pindexStart->pprev;
		}

		/* re-scan for spendable outputs. */
		ResetServiceWalletEvent(wallet);
		wallet->ScanForWalletTransactions(pindexStart, true);
		wallet->ReacceptWalletTransactions();
	}

	Object ret;
	if (pindexStart)
		ret.push_back(Pair("mincreate", (uint64_t)pindexStart->nTime));
	ret.push_back(Pair("total", (uint64_t)nTotal));
	ret.push_back(Pair("scanned", (uint64_t)nRecs));

	return ret;
}
#endif
static const Value& GetObjectValue(Object obj, string cmp_name)
{

  for( Object::size_type i = 0; i != obj.size(); ++i )
  {
    const Pair& pair = obj[i];
    const string& name = pair.name_;

    if (cmp_name == name) {
      const Value& value = pair.value_;
      return (value);
    }
  }

	throw runtime_error("unknown json value");
}

Value rpc_wallet_import(CIface *iface, const Array& params, bool fStratum)
{
	int ifaceIndex = GetCoinIndex(iface);
	CWallet *wallet;
	Array ret_obj;
	vector<CTxDestination> vAddr;
	char *text;
	struct stat st;
	FILE *fl;

	if (fStratum) {
		throw runtime_error("unsupported operation");
	}
	if (params.size() != 1) {
		throw runtime_error("wallet.import");
	}
	wallet = GetWallet(iface);
	if (!wallet) {
		throw runtime_error("wallet.import: invalid chain");
	}

	std::string strPath = params[0].get_str();
	fl = fopen(strPath.c_str(), "rb");
	if (!fl)
		throw runtime_error("error opening file.");

	memset(&st, 0, sizeof(st));
	fstat(fileno(fl), &st);
	if (st.st_size == 0)
		throw runtime_error("file is not in JSON format.");

	text = (char *)calloc(st.st_size + 1, sizeof(char));
	if (!text)
		throw runtime_error("not enough memory to allocate file.");

	fread(text, sizeof(char), st.st_size, fl);
	fclose(fl);

	Value objWalletValue;
	const string strWallet(text);
	if (!read_string(strWallet, objWalletValue)) {
		throw runtime_error("file is not is JSON format.");
	}

	time_t nCreateTime = time(NULL);
	Object objWallet = objWalletValue.get_obj();
	Array arWallet = GetObjectValue(objWallet, iface->name).get_array();
	for (Array::size_type i = 0; i != arWallet.size(); ++i) {
		Value& value = arWallet[i];
		uint32_t nECChainCounter[7];
		Object& objAddr = value.get_obj();

		CAccountAddressKey addr(ifaceIndex);
		//	todo:			addr << value.get_obj();
		bool fImport = addr.FromValue(objAddr);

		if (fImport) {
			/* retain earliest import time. */
			nCreateTime = MIN(addr.GetCreateTime(), nCreateTime); 

			/* retain addr for wallet tx scan. */
			CAccountCache *account = addr.GetAccountCache();
			if (addr.keyid == 0 || !account) {
				const CTxDestination& destination = addr.GetDestination();
				if (find(vAddr.begin(), vAddr.end(), destination) == vAddr.end()) {
					vAddr.push_back(destination);
				}
			} else {
				if (addr.GetKey() != NULL) {
					/* append all variations to tx-scan list */
#if 0
					int nFlag = (addr.GetKey()->IsDilithium() ? ACCADDRF_DILITHIUM : 0);
					account->GetAddrDestinations(addr.keyid, vAddr, nFlag);
#endif
					account->CalcAddressBook(addr.GetKey(), vAddr);
				}

				bool bDefault = boolFromObject(objAddr, "default");
				if (bDefault) {
					account->SetDefaultAddr(addr.GetPubKey());

					for (int nMode = 0; nMode < MAX_ACCADDR; nMode++) {
						CTxDestination dest;
						account->GetPrimaryAddr(nMode, dest);
						if (find(vAddr.begin(), vAddr.end(), dest) == vAddr.end()) {
							vAddr.push_back(dest);
						}
					}

					Array echdi = GetObjectValue(objAddr, "echdi").get_array();
					for (Array::size_type nMode = 0; nMode != echdi.size(); ++nMode) {
						int nCount = echdi[nMode].get_int();
						account->CalculateECKeyChain(vAddr, nMode, nCount); 
					}

					Array dihdi = GetObjectValue(objAddr, "dihdi").get_array();
					for (Array::size_type nMode = 0; nMode != dihdi.size(); ++nMode) {
						int nCount = dihdi[nMode].get_int();
						account->CalculateDIKeyChain(vAddr, nMode, nCount); 
					}
				}

#if 0
				bool bMaster = boolFromObject(objAddr, "master");
				if (bMaster) {
					int nMode = account->GetAddrMode(CKeyID(addr.keyid));
					if (nMode != -1) {
						int hdindex = numFromObject(objAddr, "hdindex");

						/* derive new hd-keys until hdindex is reached. */ 
						while (account->GetHDIndex(nMode) < hdindex) {
							CPubKey hdPubKey;

							if (!account->CreateNewPubKey(hdPubKey, /*nMode,*/
										addr.GetKey()->nFlag | CKeyMetadata::META_HD_KEY)) {
								break;
							}

							const CKeyID& hdKeyid = hdPubKey.GetID();
							account->GetAddrDestinations(hdKeyid, vAddr);
						}
					}
				}
#endif
			}

			Debug("Imported new coin address \"%s\".",  addr.ToString().c_str());
		}

		if (addr.IsValid()) {
			/* return json version with general address info. */
			CAccountAddress *retAddr = (CAccountAddress *)&addr;
			Object obj = retAddr->ToValue(); 
			obj.push_back(Pair("import", fImport));
			ret_obj.push_back(obj);
		}
	}

	if (vAddr.size() != 0) {
		/* update wallet */
		CWalletUpdateFilter *filter =
			new CWalletUpdateFilter(ifaceIndex, vAddr, nCreateTime);
		InitChainFilter(filter);
	}

	/* clear cache to reflect new addresses. */
	wallet->MarkDirty();

	return (ret_obj);
}

Value rpc_wallet_list(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() > 1)
		throw runtime_error(
				"wallet.list [minconf=1]\n"
				"Returns Object that has account names as keys, account balances as values.");

	int nMinDepth = 1;
	if (params.size() > 0)
		nMinDepth = params[0].get_int();


	vector<string> vAcc;
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
		const string& strAccount = entry.second;

		if (strAccount.length() != 0 &&
				strAccount.substr(0, 1) == CWallet::EXT_ACCOUNT_PREFIX) {
			continue; /* ext account */
		}

		if (find(vAcc.begin(), vAcc.end(), strAccount) != vAcc.end())
			continue; /* already established account name */

		if (IsMine(*wallet, entry.first)) { // This address belongs to me
			vAcc.push_back(strAccount);
		}
	}

	map<string, int64> mapAccountBalances;
	BOOST_FOREACH(const string& strAccount, vAcc) {
		int64 nTotal = 0;

		vector<COutput> vCoins;
		wallet->AvailableAccountCoins(strAccount, vCoins, 
				(nMinDepth == 0 ? false : true));
		BOOST_FOREACH(const COutput& out, vCoins) {
			nTotal += out.tx->vout[out.i].nValue;
		}

		mapAccountBalances[strAccount] = nTotal;
	}

#if 0
	/* ?? */
	list<CAccountingEntry> acentries;
	CWalletDB(wallet->strWalletFile).ListAccountCreditDebit("*", acentries);
	BOOST_FOREACH(const CAccountingEntry& entry, acentries) {
		mapAccountBalances[entry.strAccount] += entry.nCreditDebit;
	}
#endif

	Object ret;
	BOOST_FOREACH(const PAIRTYPE(string, int64)& accountBalance, mapAccountBalances) {
		ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
	}

	return ret;
}



void ResetServiceWalletEvent(CWallet *wallet);

Value rpc_wallet_verify(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	Object ret;
	int ifaceIndex = GetCoinIndex(iface);
	vector<uint256> hash_list;
	tx_cache inputs;
	uint256 bhash;
	uint64_t bestHeight;
	uint64_t minTime;
	uint64_t minHeight;
	int64 nDepth = 0;

	if (fStratum)
		throw runtime_error("unsupported operation");
	if (params.size() > 1)
		throw runtime_error("wallet.verify [<depth>]\nRescan coin inputs associated with local wallet transactions.\n");

	if (params.size() == 1)
		nDepth = params[0].get_int();

	bestHeight = GetBestHeight(iface);
	minHeight = bestHeight + 1;
	minTime = time(NULL) + 1;

	if (nDepth == 0) {
		/* scan wallet's 'previous hiearchy' */
		for (map<uint256, CWalletTx>::const_iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
		{
			const CWalletTx& pcoin = (*it).second;
			const uint256& pcoin_hash = pcoin.GetHash();
			uint256 bhash = 0;

			const CTransaction& pcoin_tx = (CTransaction)pcoin;
			inputs[pcoin_hash] = pcoin_tx;

#if 0
			BOOST_FOREACH(const CTxIn& txin, pcoin.vin) {
				CTransaction tx;
				if (inputs.count(txin.prevout.hash) != 0) {
					tx = inputs[txin.prevout.hash];
				} else if (::GetTransaction(iface, txin.prevout.hash, tx, &bhash)) {
					inputs[txin.prevout.hash] = tx;
				} else {
					/* unknown */
					continue;
				}

				wallet->FillInputs(tx, inputs);
			}
#endif

			if (bhash != 0 && 
					find(hash_list.begin(), hash_list.end(), bhash) != hash_list.end()) {
				hash_list.insert(hash_list.end(), bhash);
			}
		}

		/* scan wallet's 'next hiearchy' */
		for (tx_cache::iterator it = inputs.begin(); it != inputs.end(); ++it) {
			CTransaction& tx = (*it).second;
			vector<uint256> vOuts;

			if (!tx.ReadCoins(ifaceIndex, vOuts))
				continue; /* unknown */
			if (tx.vout.size() > vOuts.size())
				continue; /* invalid */


			BOOST_FOREACH(const uint256& tx_hash, vOuts) {
				if (find(hash_list.begin(), hash_list.end(), bhash) != hash_list.end())
					continue; /* dup */

				uint256 bhash;
				if (!::GetTransaction(iface, tx_hash, tx, &bhash)) 
					continue;

				if (inputs.count(tx_hash) == 0)
					inputs[tx_hash] = tx;
				//if (find(hash_list.begin(), hash_list.end(), bhash) != hash_list.end())
				hash_list.insert(hash_list.end(), bhash);

#if 0
				wallet->FillInputs(tx, inputs);
#endif
			}
		}

		/* add any missing wallet tx's */
		for (tx_cache::const_iterator it = inputs.begin(); it != inputs.end(); ++it) {
			const uint256& tx_hash = (*it).first;
			if (wallet->mapWallet.count(tx_hash))
				continue;

			const CTransaction& tx = (*it).second;
			wallet->AddToWalletIfInvolvingMe(tx, NULL, true);
		}

		/* find earliest block inovolved. */
		BOOST_FOREACH(const uint256& bhash, hash_list) {
			CBlockIndex *pindex = GetBlockIndexByHash(ifaceIndex, bhash);
			if (!pindex) continue; /* unknown */ 

			if (pindex->nHeight < minHeight)
				minHeight = pindex->nHeight;
			if (pindex->nTime < minTime)
				minTime = pindex->nTime;
		}
		ret.push_back(Pair("prescan-tx", (int)inputs.size()));
		ret.push_back(Pair("wallet-tx", (int)wallet->mapWallet.size()));
	} else {
		minHeight = MAX(0, bestHeight - nDepth);
	}

	minHeight = MIN(bestHeight, minHeight);
	if (minHeight != bestHeight) {
		/* reset wallet-scan event state */
		ResetServiceWalletEvent(wallet);
		/* scan entire chain for corrections to wallet & coin-db. */
		InitServiceWalletEvent(ifaceIndex, minHeight);
	}

	ret.push_back(Pair("start-height", minHeight));
	ret.push_back(Pair("end-height", bestHeight));
#if 0
	if (minHeight != bestHeight) {
		ret.push_back(Pair("min-stamp", ToValue_date_format((time_t)minTime)));
		ret.push_back(Pair("min-time", minTime));
	}
#endif

	return (ret);
}

Value rpc_wallet_send(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() > 4)
		throw runtime_error("wallet.send");

	/* originating account  */
	string strAccount = AccountFromValue(params[0]);

	/* destination coin address */
	CCoinAddr address(ifaceIndex, params[1].get_str());
	if (!address.IsValid())
		throw JSONRPCError(-5, "Invalid coin address");
#if 0
	if (address.GetVersion() != CCoinAddr::GetCoinAddrVersion(ifaceIndex))
		throw JSONRPCError(-5, "Invalid address for coin service.");
#endif

	int64 nAmount = AmountFromValue(params[2]);
	int nMinDepth = 1;

	//CWalletTx wtx;
	//wtx.strFromAccount = strAccount;
#if 0
	if (params.size() > 3)
		nMinDepth = params[3].get_int();
	if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
		wtx.mapValue["comment"] = params[4].get_str();
	if (params.size() > 5 && params[5].type() != null_type && !params[5].get_str().empty())
		wtx.mapValue["to"]      = params[5].get_str();
#endif
	int64 nFee = 0;
	if (params.size() == 4)
		nFee = params[3].get_real();

	if (nFee >= MAX_TRANSACTION_FEE(iface)) {
		throw JSONRPCError(ERR_INVAL, "The fee exceeds the maximum permitted.");
	}

	CTxCreator wtx(wallet, strAccount);
	wtx.SetMinFee(nFee);
#if 0
	if (feeRate.length() != 0) {
		if (feeRate.substring(0, 1) == "l") { /* low */
			wtx.setLowFeeRate();
		} else if (feeRate.substring(0, 1) == "h") { /* high */
			wtx.setHighFeeRate();
		}
	}
#endif

	// Check funds
	int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
	if (nAmount > nBalance)
		throw JSONRPCError(-6, "Account has insufficient funds");

	if (!wtx.AddOutput(address.Get(), nAmount))
		throw JSONRPCError(-5, "Invalid destination address specified.");

	if (!wtx.Send())
		throw JSONRPCError(-5, wtx.GetError());
#if 0
	//string strError = wallet->SendMoneyToDestination(address.Get(), nAmount, wtx);
	string strError = wallet->SendMoney(strAccount, address.Get(), nAmount, wtx);
	if (strError != "")
		throw JSONRPCError(-4, strError);
#endif

	return wtx.GetHash().GetHex();
}

Value rpc_wallet_tsend(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() < 3)
		throw runtime_error("invalid parameters");

	/* originating account  */
	string strAccount = AccountFromValue(params[0]);

	/* destination coin address */
	CCoinAddr address(ifaceIndex, params[1].get_str());
	if (!address.IsValid())
		throw JSONRPCError(-5, "Invalid coin address");
#if 0
	if (address.GetVersion() != CCoinAddr::GetCoinAddrVersion(ifaceIndex))
		throw JSONRPCError(-5, "Invalid address for coin service.");
#endif

	int64 nAmount = AmountFromValue(params[2]);
	int nMinDepth = 1;
	if (params.size() > 3)
		nMinDepth = params[3].get_int();

	int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
	if (nAmount > nBalance)
		throw JSONRPCError(-6, "Account has insufficient funds");

	CTxCreator wtx(wallet, strAccount);
	/*
		 string strError = wallet->SendMoney(strAccount, address.Get(), nAmount, wtx, true);
		 if (strError != "" && strError != "ABORTED")
		 throw JSONRPCError(-4, strError);
		 */

	wtx.AddOutput(address.Get(), nAmount);
	if (!wtx.Generate())
		throw JSONRPCError(-4, wtx.GetError());

	unsigned int nBytes = ::GetSerializeSize(wtx, SER_NETWORK, 
			PROTOCOL_VERSION(iface) | SERIALIZE_TRANSACTION_NO_WITNESS);
	int64 nFee = wallet->GetTxFee(wtx);

	tx_cache inputs;
	if (!wallet->FillInputs(wtx, inputs))
		throw JSONRPCError(-4, "error filling inputs");
	double dPriority = wallet->GetPriority(wtx, inputs);

	int64 nVirtSize = wallet->GetVirtualTransactionSize(wtx);

	Object ret_obj;
	ret_obj.push_back(Pair("amount", ValueFromAmount(nAmount)));
	ret_obj.push_back(Pair("tx-amount", ValueFromAmount(wtx.GetValueOut())));
	ret_obj.push_back(Pair("size", (int)nBytes));
	ret_obj.push_back(Pair("virt-size", (int)nVirtSize));
	//ret_obj.push_back(Pair("maxsize", (int)nMaxBytes));
	ret_obj.push_back(Pair("fee", ValueFromAmount(nFee)));
	ret_obj.push_back(Pair("inputs", inputs.size()));
	ret_obj.push_back(Pair("priority", dPriority));

	return ret_obj;
}

Value rpc_wallet_bsend(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	const int nMinDepth = 1;
	int64 nSent;
	int64 nValue;
	int nBytes;
	int nInputs;

	if (params.size() < 3)
		throw runtime_error("invalid parameters");

	/* originating account  */
	string strAccount = AccountFromValue(params[0]);

	/* destination coin address */
	CCoinAddr address(ifaceIndex, params[1].get_str());
	if (!address.IsValid())
		throw JSONRPCError(-5, "Invalid coin address");
#if 0
	if (address.GetVersion() != CCoinAddr::GetCoinAddrVersion(ifaceIndex))
		throw JSONRPCError(-5, "Invalid address for coin service.");
#endif

	int64 nAmount = AmountFromValue(params[2]);

	int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
	if (nAmount > nBalance)
		throw JSONRPCError(-6, "Account has insufficient funds");

	/* init batch tx creator */
	CScript scriptPub;
	scriptPub.SetDestination(address.Get());
	CTxBatchCreator b_tx(wallet, strAccount, scriptPub, nAmount); 

	if (!b_tx.Generate()) {
		string strError = b_tx.GetError();
		if (strError == "")
			strError = "An unknown error occurred while generating the transactions.";
		throw JSONRPCError(-6, strError);
	} 

	if (!b_tx.Send()) {
		string strError = b_tx.GetError();
		if (strError == "")
			strError = "An unknown error occurred while commiting the batch transaction operation.";
		throw JSONRPCError(-6, strError);
	}

	int64 nValueOut = 0;
	int64 nChangeOut = 0;
	int64 nValueIn = 0;
	int64 nTxSize = 0;
	int nInputTotal = 0;
	int64 nSigTotal = 0;

	vector<CWalletTx>& tx_list = b_tx.GetTxList();

	tx_cache inputs;
	BOOST_FOREACH(CWalletTx& wtx, tx_list) {
		nInputTotal += wtx.vin.size();
		nSigTotal += wtx.GetLegacySigOpCount();

		wallet->FillInputs(wtx, inputs);
		nTxSize += wallet->GetVirtualTransactionSize(wtx);
	}
	BOOST_FOREACH(CWalletTx& wtx, tx_list) {
		BOOST_FOREACH(const CTxIn& txin, wtx.vin) {
			CTxOut out;
			if (!wtx.GetOutputFor(txin, inputs, out)) {
				continue;
			}

			nValueIn += out.nValue;
		}
	}

	BOOST_FOREACH(CWalletTx& wtx, tx_list) {
		BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
			if (txout.scriptPubKey == scriptPub) {
				nValueOut += txout.nValue;
			} else {
				nChangeOut += txout.nValue;
			}
		}
	}


	Object ret;
	int64 nFee = nValueIn - nValueOut - nChangeOut;
	nBalance = MAX(0, nBalance - (nValueOut + nFee));

	ret.push_back(Pair("fee", ValueFromAmount(nFee)));
	ret.push_back(Pair("input-value", ValueFromAmount(nValueIn)));
	ret.push_back(Pair("total-tx", (int)tx_list.size()));
	ret.push_back(Pair("total-inputs", (int)nInputTotal));
	ret.push_back(Pair("total-sigops", (int)nSigTotal));
	ret.push_back(Pair("total-size", (int)nTxSize));

	Object ret_out;
	ret_out.push_back(Pair("account", strAccount));
	ret_out.push_back(Pair("balance", ValueFromAmount(nBalance)));
	ret_out.push_back(Pair("output-value", ValueFromAmount(nValueOut)));
	ret_out.push_back(Pair("change-value", ValueFromAmount(nChangeOut)));
	ret_out.push_back(Pair("target-value", ValueFromAmount(nAmount)));
	ret.push_back(Pair("out", ret_out));

	Array ar;
	BOOST_FOREACH(CWalletTx& wtx, tx_list) {
		ar.push_back(wtx.GetHash().GetHex());
	}
	ret.push_back(Pair("txid", ar));

	return (ret);
}

#if 0
Value rpc_wallet_set(CIface *iface, const Array& params, bool fStratum)
{
	int ifaceIndex = GetCoinIndex(iface);

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *pwalletMain = GetWallet(iface);
	if (params.size() < 1 || params.size() > 2)
		throw runtime_error(
				"wallet.set <coin-address> <account>\n"
				"Sets the account associated with the given address.");

	CCoinAddr address(ifaceIndex, params[0].get_str());
	if (!address.IsValid())
		throw JSONRPCError(-5, "Invalid coin address");


	string strAccount;
	if (params.size() > 1)
		strAccount = AccountFromValue(params[1]);

#if 0
	// Detect when changing the account of an address that is the 'unused current key' of another account:
	if (pwalletMain->mapAddressBook.count(address.Get()))
	{
		string strOldAccount = pwalletMain->mapAddressBook[address.Get()];
		if (address == GetAccountAddress(GetWallet(iface), strOldAccount))
			GetAccountAddress(GetWallet(iface), strOldAccount, true);
	}
#endif

	pwalletMain->SetAddressBookName(address.Get(), strAccount);

	/* TODO: */

	return Value::null;
}
#endif

Value rpc_wallet_unspent(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	string strAccount;

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() == 0 || params.size() > 2)
		throw runtime_error("unsupported operation");

	strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_NOENT, "unknown account");

	int nMinDepth = 1;
	if (params.size() > 1)
		nMinDepth = params[1].get_int();

	Array results;
	vector<COutput> vecOutputs;
	pwalletMain->AvailableAccountCoins(strAccount, vecOutputs, 
			(nMinDepth == 0 ? false : true));
	BOOST_FOREACH(const COutput& out, vecOutputs) {
		if (out.nDepth < nMinDepth)
			continue;

		int64 nValue = out.tx->vout[out.i].nValue;
		const CScript& pk = out.tx->vout[out.i].scriptPubKey;
		Object entry;

		entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
//		entry.push_back(Pair("hash", out.tx->GetWitnessHash().GetHex()));
		entry.push_back(Pair("vout", out.i));
		entry.push_back(Pair("script", pk.ToString()));
		entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
		entry.push_back(Pair("amount",ValueFromAmount(nValue)));
		entry.push_back(Pair("confirmations",out.nDepth));
		results.push_back(entry);
	}

	return results;
}

Value rpc_wallet_spent(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	bc_t *bc = GetWalletTxChain(iface);
	string strSysAccount("*");
	string strAccount;
	bcpos_t nArch = 0;
	bcpos_t posTx;
	bool fVerbose;
	int i;

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() > 2)
		throw runtime_error("unsupported operation");

	strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_NOENT, "unknown account");

	fVerbose = false;
	if (params.size() == 2)
		fVerbose = params[1].get_bool();

	bc_idx_next(bc, &nArch);

	Array results;
	for (posTx = 0; posTx < nArch; posTx++) {
		CWalletTx pcoin;
		unsigned char *data;
		size_t data_len;
		int err;

		err = bc_get(bc, posTx, &data, &data_len);
		if (err)
			continue;

		CDataStream sBlock(SER_DISK, CLIENT_VERSION);
		sBlock.write((const char *)data, data_len);
		sBlock >> pcoin;
		free(data);

		if (strAccount != strSysAccount &&
				pcoin.strFromAccount != strAccount)
			continue;

		if (!fVerbose) {
			results.push_back(pcoin.GetHash().GetHex());
		} else {
			results.push_back(pcoin.ToValue(ifaceIndex));
		}
	}

	return (results);
}

Value rpc_wallet_select(CIface *iface, const Array& params, bool fStratum)
{

	if (params.size() != 2)
		throw runtime_error("unsupported operation");

	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	string strAccount = params[0].get_str();
	int64 nAmount = AmountFromValue(params[1]);

	Array results;
	vector<COutput> vecOutputs;
	pwalletMain->AvailableAccountCoins(strAccount, vecOutputs, false);

	int64 nValueRet;
	set<pair<const CWalletTx*,unsigned int> > setCoins;
	if (!pwalletMain->SelectAccountCoins(strAccount, nAmount, setCoins, nValueRet))
		throw JSONRPCError(-6, "Insufficient funds for account.");

	BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins) {
		const CWalletTx *wtx = pcoin.first; 
		int nOut = pcoin.second;
		int64 nCredit = wtx->vout[nOut].nValue;
		const CScript& pk = wtx->vout[nOut].scriptPubKey;

		Object entry;
		entry.push_back(Pair("txid", wtx->GetHash().GetHex()));
		entry.push_back(Pair("hash", wtx->GetWitnessHash().GetHex()));
		entry.push_back(Pair("vout", nOut));
		entry.push_back(Pair("script", pk.ToString()));
		entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
		entry.push_back(Pair("amount",ValueFromAmount(nCredit)));
		results.push_back(entry);
	}

	return results;
}

Value rpc_wallet_unconfirm(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() != 0)
		throw runtime_error(
				"wallet.unconfirm\n"
				"Display a list of all unconfirmed transactions.\n");

	Array results;
	{
		LOCK(pwalletMain->cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
		{
			const CWalletTx& pcoin = (*it).second;
			if (!pcoin.IsCoinBase()) continue;
			int depth = pcoin.GetBlocksToMaturity(ifaceIndex);
			if (depth > 0 && pcoin.GetDepthInMainChain(ifaceIndex) >= 2) {
				CTransaction& tx = (CTransaction&)pcoin;
				results.push_back(tx.ToValue(ifaceIndex));
			}
		}
	}

	return results;
} 

Value rpc_wallet_multisend(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() < 2 || params.size() > 4)
		throw runtime_error(
				"wallet.multisend <fromaccount> {address:amount,...} [minconf=1] [comment]\n"
				"amounts are double-precision floating point numbers");

	string strAccount = AccountFromValue(params[0]);
	Object sendTo = params[1].get_obj();
	int nMinDepth = 1;
	if (params.size() > 2)
		nMinDepth = params[2].get_int();

	CWalletTx wtx;
	wtx.strFromAccount = strAccount;
	if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
		wtx.mapValue["comment"] = params[3].get_str();

	set<CCoinAddr> setAddress;
	vector<pair<CScript, int64> > vecSend;

	int64 totalAmount = 0;
	BOOST_FOREACH(const Pair& s, sendTo)
	{
		CCoinAddr address(ifaceIndex, s.name_);
		if (!address.IsValid())
			throw JSONRPCError(-5, string("Invalid coin address:")+s.name_);

		if (setAddress.count(address))
			throw JSONRPCError(-8, string("Invalid parameter, duplicated address: ")+s.name_);
		setAddress.insert(address);

		CScript scriptPubKey;
		scriptPubKey.SetDestination(address.Get());
		int64 nAmount = AmountFromValue(s.value_);
		totalAmount += nAmount;

		vecSend.push_back(make_pair(scriptPubKey, nAmount));
	}

	// Check funds
	int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
	if (totalAmount > nBalance)
		throw JSONRPCError(-6, "Account has insufficient funds");

	// Send
	int64 nFeeRequired = 0;
	string strError;
	bool fCreated = pwalletMain->CreateAccountTransaction(strAccount, vecSend, wtx, strError, nFeeRequired);
	if (!fCreated)
	{
		if (totalAmount + nFeeRequired > pwalletMain->GetBalance())
			throw JSONRPCError(-6, "Insufficient funds");
		throw JSONRPCError(-4, "Transaction creation failed");
	}
	if (!pwalletMain->CommitTransaction(wtx))
		throw JSONRPCError(-4, "Transaction commit failed");

	return wtx.GetHash().GetHex();
}

Value rpc_wallet_tx(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() != 1)
		throw runtime_error(
				"wallet.tx <txid>\n"
				"Get detailed information about in-wallet transaction <txid>");

	uint256 hash;
	hash.SetHex(params[0].get_str());

	Object entry;

	if (pwalletMain->mapWallet.count(hash))
		throw JSONRPCError(-5, "Invalid transaction id");

	const CWalletTx& wtx = pwalletMain->mapWallet[hash];

	int64 nCredit = wtx.GetCredit();
	int64 nDebit = wtx.GetDebit();
	int64 nNet = nCredit - nDebit;
	int64 nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);

	entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
	if (wtx.IsFromMe())
		entry.push_back(Pair("fee", ValueFromAmount(nFee)));

	WalletTxToJSON(ifaceIndex, wtx, entry);

	Array details;
	ListTransactions(ifaceIndex, wtx, "*", 0, true, details);
	entry.push_back(Pair("details", details));

	return entry;
}

Value rpc_wallet_keyphrase(CIface *iface, const Array& params, bool fStratum)
{
	bool fVerbose;

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() != 1)
		throw runtime_error("wallet.keyphrase");

	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	string strAddress = params[0].get_str();
	CCoinAddr address(ifaceIndex);
	if (!address.SetString(strAddress))
		throw JSONRPCError(-5, "Invalid address");

	fVerbose = false;
	if (params.size() >= 2)
		fVerbose = params[1].get_bool();

	CKeyID keyid;
	if (!ExtractDestinationKey(wallet, address.Get(), keyid))
		throw JSONRPCError(ERR_REMOTE, "unknown address: " + strAddress);

#if 0
	{
		CScript scriptPubKey;
		vector<cbuff> vSolutions;
		txnouttype whichType;

		scriptPubKey.SetDestination(address.Get());
		if (!Solver(scriptPubKey, whichType, vSolutions))
			throw JSONRPCError(ERR_REMOTE, "unknown address");

		if (whichType == TX_SCRIPTHASH) {
			CScriptID scriptid;
			scriptid = CScriptID(uint160(vSolutions[0]));
			CScript subscript;
			if (!wallet->GetCScript(scriptid, subscript))
				throw JSONRPCError(ERR_REMOTE, "unknown script ID");
			vSolutions.clear();
			if (!Solver(subscript, whichType, vSolutions))
				throw JSONRPCError(ERR_REMOTE, "unknown script ID");

#if 0
			if (whichType != TX_PUBKEYHASH)
				throw JSONRPCError(ERR_INVAL, "invalid script ID");
			keyid = CKeyID(uint160(vSolutions[0]));
#endif
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
#if 0
			case TX_WITNESS_V0_SCRIPTHASH:
			case TX_WITNESS_V14_SCRIPTHASH:
				{
					uint160 hash2;
					const cbuff vch(vSolutions[0].begin(), vSolutions[0].end());
					cbuff vchHash;
					uint160 hash160;
					RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
					memcpy(&hash160, &vchHash[0], sizeof(hash160));

					CScriptID scriptID = CScriptID(hash160);
					CScript subscript;
					if (!wallet->GetCScript(scriptID, subscript))
						throw JSONRPCError(ERR_REMOTE, "unknown script ID");
					if (!Solver(subscript, whichType, vSolutions))
						throw JSONRPCError(ERR_REMOTE, "unknown script ID");
					if (whichType != TX_PUBKEYHASH)
						throw JSONRPCError(ERR_INVAL, "invalid script ID");
					keyid = CKeyID(uint160(vSolutions[0]));
				}
				break;
#endif
		}	
	}
	if (keyid == 0)
		throw JSONRPCError(ERR_INVAL, "incompatible address " + strAddress);
#endif

	CKey *key = wallet->GetKey(keyid);
	if (!key)
		throw JSONRPCError(ERR_REMOTE, "Private key for address " + strAddress + " is not known");

	bool fCompressed = false;
	CSecret vchSecret = key->GetSecret(fCompressed);
	if (!fCompressed) {
		throw JSONRPCError(ERR_OPNOTSUPP, "Uncompressed key phrase export not supported.");
	}

	CCoinSecret secret(ifaceIndex, vchSecret, fCompressed);
	string phrase = EncodeMnemonicSecret(secret);

// TODO: fVerbose

	return (phrase);
}

Value rpc_wallet_fee(CIface *iface, const Array& params, bool fStratum)
{
	int64 nFeeRate;
	int nDepth;
	bool fEco;

	nDepth = 2; /* minimum */
	if (params.size() >= 1)
		nDepth = MAX(1, params[0].get_int());

	fEco = false; /* default */
	if (params.size() >= 2 && params[1].get_str() == "ECONOMICAL")
		fEco = true;

	CBlockPolicyEstimator *est = GetFeeEstimator(iface);
	nFeeRate = est->estimateSmartFee(nDepth, NULL).GetFeePerK();
	if (!fEco) {
		/* TODO: not standard, but similar.. */
		nFeeRate = MAX(nFeeRate, 
			(est->estimateSmartFee(nDepth * 2, NULL).GetFeePerK() + nFeeRate) / 2);
	}
	nFeeRate = MAX(nFeeRate, MIN_TX_FEE(iface));

	Object obj;
	obj.push_back(Pair("feerate", (double)nFeeRate / COIN));
	obj.push_back(Pair("blocks", nDepth));
	return (obj);
}

Value rpc_wallet_getaccalias(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	string strAccount;

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() != 1)
		throw runtime_error("invalid parameter");

	strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_NOENT, "unknown account");

	CAccountCache *acc = wallet->GetAccount(strAccount);
	if (!acc)
		throw JSONRPCError(ERR_INVAL, "invalid account");
	const uint160& hAlias = acc->GetAliasHash();

	Value ret;
	if (hAlias != 0) {
		ret = hAlias.GetHex();
	}
	return (ret);
}

Value rpc_wallet_setaccalias(CIface *iface, const Array& params, bool fStratum)
{
	throw runtime_error("unsupported operation");
#if 0
	CWallet *wallet = GetWallet(iface);

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() != 2)
		throw runtime_error("invalid parameters");

	string strAccount;
	strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(ERR_NOENT, "unknown account");

	string hCertStr = params[1].get_str();
	uint160 hCert(hCertStr);
	if (hCert == 0)
		throw JSONRPCError(ERR_INVAL, "invalid certificate hash specified");

	CTransaction tx;
	if (!GetTxOfCert(iface, hCert, tx))
		throw JSONRPCError(ERR_NOENT, "unknown certificate");
	CCert *cert = (CCert *)&tx.certificate;

	CAccountCache *acc = wallet->GetAccount(strAccount);
	if (!acc)
		throw JSONRPCError(ERR_INVAL, "invalid account");
	if (!acc->SetCertHash(hCert))
		throw JSONRPCError(ERR_INVAL, "error setting account certificate");

	Object ret;
	ret.push_back(Pair("account", strAccount));
	ret.push_back(Pair("hash", hCert.GetHex()));
	ret.push_back(Pair("label", cert->GetLabel()));
	return (ret);
#endif
}

Value rpc_wallet_export(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	vector<CTxDestination> vSkip;
	CAccountCache *account;
	Array result;

	if (fStratum)
		throw runtime_error("unsupported operation");

	/* coinaddr destinations with no address book entry. */
	std::set<CKeyID> keys;
	wallet->GetKeys(keys);
	account = wallet->GetAccount("");
	BOOST_FOREACH(const CKeyID& keyid, keys) {
		if (wallet->mapAddressBook.count(keyid) != 0)
			continue;

		CKey *key = wallet->GetKey(keyid);
		if (!key)
			continue;

		CTxDestination ckeyid(keyid);
		CAccountAddressKey addr(ifaceIndex, ckeyid);
		result.push_back(addr.ToValue());
		account->CalcAddressBook(key, vSkip);
	}

	/* pubkey coinaddr destinations from address book. */
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
		CTxDestination dest = entry.first;
		string strLabel = entry.second;

		if (find(vSkip.begin(), vSkip.end(), dest) != vSkip.end()) {
			continue;
		}

		CKeyID keyid;
		CCoinAddr tAddr(ifaceIndex, dest);
		if (!tAddr.GetKeyID(keyid)) {
			continue; // not keyid kind
		}

		CKey *key = wallet->GetKey(keyid);
		if (!key) {
			continue;
		}

		account = wallet->GetAccount(strLabel);

		CAccountAddressKey addr(ifaceIndex, CTxDestination(keyid));
		result.push_back(addr.ToValue());
		account->CalcAddressBook(key, vSkip);
	}

	/* script/misc coinaddr destinations from address book. */
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
		CTxDestination dest = entry.first;
		string strLabel = entry.second;

		if (find(vSkip.begin(), vSkip.end(), dest) != vSkip.end())
			continue;

		account = wallet->GetAccount(strLabel);

		CAccountAddressKey addr(ifaceIndex, dest);
		result.push_back(addr.ToValue());
	}

	Object ret;
	ret.push_back(Pair(iface->name, result));
	return (ret);
}

Value rpc_wallet_export_account(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	vector<CScriptID> vSkip;
	Array result;
	string strExtAccount;
	string strAccount;

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() != 1)
		throw runtime_error("wallet.export");

	strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount)) {
		throw JSONRPCError(ERR_NOENT, "unknown account");
	}
	strExtAccount = CWallet::EXT_ACCOUNT_PREFIX + strAccount;

	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
		CTxDestination dest = entry.first;
		string strLabel = entry.second;

		if (strLabel != strAccount &&
				strLabel != strExtAccount) {
			continue;
		}

		CAccountAddressKey addr(ifaceIndex, dest);
		CKeyID keyID;
		if (addr.GetKeyID(keyID)) {
			result.push_back(addr.ToValue());
//			rpcwallet_GetWalletAddr(wallet, tree, strLabel, keyID);

			vector<CTxDestination> vDestTmp;
			CAccountCache *account = wallet->GetAccount(strLabel);
			account->CalcAddressBook(addr.GetKey(), vDestTmp);

			/* retain script derivatives. */
			CScriptID scriptID;
//			GetAddrDestination(wallet->ifaceIndex, keyID, vDestTmp);
			BOOST_FOREACH(const CTxDestination& dest, vDestTmp) {
				CCoinAddr addrTmp(wallet->ifaceIndex, dest);
				if (addrTmp.GetScriptID(scriptID))
					vSkip.push_back(scriptID);
			}
		}
	}

	/* handle scripts not directly derived from regular pubkey (witness, etc) */
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
		CTxDestination dest = entry.first;
		string strLabel = entry.second;

		if (strLabel != strAccount &&
				strLabel != strExtAccount) {
			continue;
		}

		CScriptID scriptID;
		CAccountAddressKey addr(wallet->ifaceIndex, dest);
		if (addr.GetScriptID(scriptID)) {
			if (find(vSkip.begin(), vSkip.end(), scriptID) != vSkip.end())
				continue; /* will be regenerated. */

#if 0
			CScript script;
			if (!wallet->GetCScript(scriptID, script))
				continue;

			shjson_t *node = shjson_obj_add(tree, NULL);
			shjson_str_add(node, "script", (char *)HexStr(script).c_str());
			shjson_str_add(node, "label", (char *)strLabel.c_str());
			shjson_str_add(node, "addr", (char *)addr.ToString().c_str());
#endif
			result.push_back(addr.ToValue());
		}
	}

	Object ret;
	ret.push_back(Pair(iface->name, result));
	return (ret);
}

/**
 * Burn coins by sending to a null coin address.
 */
Value rpc_wallet_burn(CIface *iface, const Array& params, bool fStratum) 
{
	CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  int64 nBalance;
  int err;

	if (params.size() != 2) {
    throw runtime_error("invalid parameters");
	}

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != TESTNET_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE) {
    throw runtime_error("Unsupported operation for coin service.");
	}

  string strAccount = AccountFromValue(params[0]);
  if (!IsAccountValid(iface, strAccount)) {
    throw JSONRPCError(SHERR_INVAL, "Invalid account name specified.");
	}

  int64 nValue = AmountFromValue(params[1]);
  if (nValue < iface->min_tx_fee || 
			nValue > MAX_TRANSACTION_FEE(iface)) {
    throw JSONRPCError(SHERR_INVAL, "Invalid coin value specified.");
	}

  nBalance = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (nBalance < nValue) {
    throw JSONRPCError(ERR_FEE, "Insufficient funds available for amount specified.");
	}

	int64 nFee = nValue - iface->min_tx_fee;
	if (nFee < iface->min_input) {
    throw JSONRPCError(ERR_FEE, "Insufficient coin value specified.");
	}

	/* generate script for null destination */
	CScript scriptPubKey;
	scriptPubKey << OP_RETURN << OP_0;

	CTxCreator s_wtx(wallet, strAccount);
	if (!s_wtx.AddOutput(scriptPubKey, nFee)) {
    throw JSONRPCError(ERR_CANCELED, "Invalid coin destination.");
	}
	if (!s_wtx.Send()) {
    throw JSONRPCError(ERR_CANCELED, "Unable to generate transaction.");
	}

	return (s_wtx.ToValue(ifaceIndex));
}

