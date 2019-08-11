
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
#include <unistd.h>
using namespace std;

#include "main.h"
#include "wallet.h"
#include "txcreator.h"
#include "db.h"
#include "walletdb.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
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


struct tallyitem
{
    int64 nAmount;
    int nConf;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
    }
};
static Value ListReceived(CWallet *wallet, const Array& params, bool fByAccounts)
{
  int ifaceIndex = wallet->ifaceIndex;

  // Minimum confirmations
  int nMinDepth = 1;
  if (params.size() > 0)
    nMinDepth = params[0].get_int();

  // Whether to include empty accounts
  bool fIncludeEmpty = false;
  if (params.size() > 1)
    fIncludeEmpty = params[1].get_bool();

  // Tally
  map<CCoinAddr, tallyitem> mapTally;
  for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
  {
    const CWalletTx& wtx = (*it).second;

    if (wtx.IsCoinBase()) {
      if (wtx.vout.size() == 1)
      continue;
      nMinDepth = 1;
    } else {
      nMinDepth = 1;
    }
    if (!wtx.IsFinal(wallet->ifaceIndex))
      continue;
#if 0
    if (wtx.IsCoinBase() || !wtx.IsFinal(wallet->ifaceIndex))
      continue;
#endif

    int nDepth = wtx.GetDepthInMainChain(ifaceIndex);
    if (nDepth < nMinDepth)
      continue;

    BOOST_FOREACH(const CTxOut& txout, wtx.vout)
    {
      CTxDestination address;
      if (!ExtractDestination(txout.scriptPubKey, address) || !IsMine(*wallet, address))
        continue;

      CCoinAddr c_addr(wallet->ifaceIndex, address);
      tallyitem& item = mapTally[c_addr];
      item.nAmount += txout.nValue;
      item.nConf = min(item.nConf, nDepth);
    }
  }

  // Reply
  Array ret;
  map<string, tallyitem> mapAccountTally;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
    const string& strAccount = item.second;
    map<CCoinAddr, tallyitem>::iterator it = mapTally.find(address);
    if (it == mapTally.end() && !fIncludeEmpty)
      continue;

    int64 nAmount = 0;
    int nConf = std::numeric_limits<int>::max();
    if (it != mapTally.end())
    {
      nAmount = (*it).second.nAmount;
      nConf = (*it).second.nConf;
    }

    if (fByAccounts)
    {
      tallyitem& item = mapAccountTally[strAccount];
      item.nAmount += nAmount;
      item.nConf = min(item.nConf, nConf);
    }
    else
    {
      Object obj;
      obj.push_back(Pair("address",       address.ToString()));
      obj.push_back(Pair("account",       strAccount));
      obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
      obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
      ret.push_back(obj);
    }
  }

  if (fByAccounts)
  {
    for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
    {
      int64 nAmount = (*it).second.nAmount;
      int nConf = (*it).second.nConf;
      Object obj;
      obj.push_back(Pair("account",       (*it).first));
      obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
      obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
      ret.push_back(obj);
    }
  }

  return ret;
}


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

Value rpc_wallet_export(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() != 1)
		throw runtime_error("wallet.export");

	std::string strPath = params[0].get_str();

	int ifaceIndex = GetCoinIndex(iface);
	shjson_t *json = shjson_init(NULL);
	shjson_t *tree = shjson_array_add(json, iface->name);
	shjson_t *node;
	FILE *fl;
	char *text;

	CWallet *pwalletMain = GetWallet(iface);

	std::set<CKeyID> keys;
	pwalletMain->GetKeys(keys);
	BOOST_FOREACH(const CKeyID& key, keys) {
		if (pwalletMain->mapAddressBook.count(key) == 0) { /* loner */

			/* todo: try again w/ txdb removed */
#if 0
			/* TODO: commented out; takes too long with large wallet */
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
			if (nTxInput == 0 || (nTxSpent >= nTxInput))
				continue; /* never used or spent */
#endif

			/* pub key */
			CCoinAddr addr(ifaceIndex, key);

			/* priv key */
			CSecret vchSecret;
			bool fCompressed;
			if (!pwalletMain->GetSecret(key, vchSecret, fCompressed))
				continue;
			CCoinSecret csec(ifaceIndex, vchSecret, fCompressed);
			string strKey = csec.ToString();

			node = shjson_obj_add(tree, NULL);
			shjson_str_add(node, "key", (char *)strKey.c_str()); 
			shjson_str_add(node, "label", "coinbase");
			shjson_str_add(node, "addr", (char *)addr.ToString().c_str());
			//      shjson_str_add(node, "phrase", (char *)EncodeMnemonicSecret(csec).c_str());
			//      shjson_num_add(node, "inputs", (nTxInput - nTxSpent));
		}
	}


	map<string, int64> mapAccountBalances;
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
		CTxDestination dest = entry.first;
		string strLabel = entry.second;

		if (!IsMine(*pwalletMain, dest))
			continue;

#if 0
		CCoinAddr address;
		if (!address.SetString(strLabel))
			continue;//throw JSONRPCError(-5, "Invalid address");
#endif

		CCoinAddr addr(ifaceIndex, dest);
		CKeyID keyID;
		if (!addr.GetKeyID(keyID))
			continue;//throw JSONRPCError(-3, "Address does not refer to a key");

		CSecret vchSecret;
		bool fCompressed;
		if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
			continue;//throw JSONRPCError(-4,"Private key for address " + strLabel + " is not known");
		CCoinSecret csec(ifaceIndex, vchSecret, fCompressed);
		string strKey = csec.ToString();

		node = shjson_obj_add(tree, NULL);
		shjson_str_add(node, "key", (char *)strKey.c_str()); 
		shjson_str_add(node, "label", (char *)strLabel.c_str());
		shjson_str_add(node, "addr", (char *)addr.ToString().c_str());
		//    shjson_str_add(node, "phrase", (char *)EncodeMnemonicSecret(csec).c_str());
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

#if 0
bool BackupWallet(const CWallet& wallet, const string& strDest)
{
	while (!fShutdown)
	{
		{
			LOCK(bitdb.cs_db);
			if (!bitdb.mapFileUseCount.count(wallet.strWalletFile) || bitdb.mapFileUseCount[wallet.strWalletFile] == 0)
			{
				// Flush log data to the dat file
				bitdb.CloseDb(wallet.strWalletFile);
				bitdb.CheckpointLSN(wallet.strWalletFile);
				bitdb.mapFileUseCount.erase(wallet.strWalletFile);

				// Copy wallet.dat
				filesystem::path pathSrc = GetDataDir() / wallet.strWalletFile;
				filesystem::path pathDest(strDest);
				if (filesystem::is_directory(pathDest))
					pathDest /= wallet.strWalletFile;

				try {
#if 0
#if BOOST_VERSION >= 104000
					filesystem::copy_file(pathSrc, pathDest, filesystem::copy_option::overwrite_if_exists);
#else
					filesystem::copy_file(pathSrc, pathDest);
#endif
#endif
					filesystem::copy_file(pathSrc, pathDest);
					printf("copied wallet.dat to %s\n", pathDest.string().c_str());
					return true;
				} catch(const filesystem::filesystem_error &e) {
					printf("error copying wallet.dat to %s - %s\n", pathDest.string().c_str(), e.what());
					return false;
				}
			}
		}
		//    Sleep(100);
	}
	return false;
}
#endif

#if 0
Value rpc_wallet_exportdat(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() != 1)
		throw runtime_error("wallet.exportdat");

	CWallet *wallet = GetWallet(iface);
	if (!wallet)
		throw runtime_error("Wallet not available.");

	string strDest = params[0].get_str();
	if (!BackupWallet(*wallet, strDest))
		throw runtime_error("Failure writing wallet datafile.");

	return Value::null;
}
#endif

Value rpc_wallet_get(CIface *iface, const Array& params, bool fStratum)
{
	int ifaceIndex = GetCoinIndex(iface);

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *pwalletMain = GetWallet(iface);
	if (params.size() != 1)
		throw runtime_error("wallet.get");

	CCoinAddr address(ifaceIndex, params[0].get_str());
	if (!address.IsValid())
		throw JSONRPCError(-5, "Invalid coin address");

	string strAccount;
	map<CTxDestination, string>::iterator mi = pwalletMain->mapAddressBook.find(address.Get());
	if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.empty())
		strAccount = (*mi).second;
	return strAccount;
}

Value rpc_wallet_key(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() != 1)
		throw runtime_error(
				"wallet.key <address>\n"
				"Summary: Reveals the private key corresponding to a public coin address.\n"
				"Params: [ <address> The coin address. ]\n"
				"\n"
				"The 'wallet.key' command provides a method to obtain the private key associated\n"
				"with a particular coin address.\n"
				"\n"
				"The coin address must be available in the local wallet in order to print it's pr\n"
				"ivate address.\n"
				"\n"
				"The private coin address can be imported into another system via the 'wallet.setkey' command.\n"
				"\n"
				"The entire wallet can be exported to a file via the 'wallet.export' command.\n"
				);

	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	string strAddress = params[0].get_str();
	CCoinAddr address(ifaceIndex, strAddress);
	if (!address.IsValid())
		throw JSONRPCError(-5, "Invalid address");
	CKeyID keyID;
	if (!address.GetKeyID(keyID))
		throw JSONRPCError(-3, "Address does not refer to a key");
	CSecret vchSecret;
	bool fCompressed;
	if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
		throw JSONRPCError(-4,"Private key for address " + strAddress + " is not known");
	return CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString();
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

#if 0
	obj.push_back(Pair("keypoololdest", (boost::int64_t)pwalletMain->GetOldestKeyPoolTime()));
	obj.push_back(Pair("keypoolsize",   pwalletMain->GetKeyPoolSize()));
#endif

	//  obj.push_back(Pair("txcachecount",   (int)pwalletMain->mapWallet.size()));
	//  obj.push_back(Pair("errors",        GetWarnings(ifaceIndex, "statusbar")));

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

Value rpc_wallet_import(CIface *iface, const Array& params, bool fStratum)
{
	if (fStratum)
		throw runtime_error("unsupported operation");
	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() != 1) {
		throw runtime_error(
				"wallet.import <path>\n"
				"Import a JSON wallet file.");
	}

	std::string strPath = params[0].get_str();

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
				if (!*key) continue;

				string strSecret(key);
				string strLabel(label);

				CCoinSecret vchSecret;
				bool fGood = vchSecret.SetString(strSecret);
				if (!fGood) {
					continue;// throw JSONRPCError(-5,"Invalid private key");
				}

				CKey key;
				bool fCompressed;
				CSecret secret = vchSecret.GetSecret(fCompressed);
				key.SetSecret(secret, fCompressed);
				CKeyID vchAddress = key.GetPubKey().GetID();


				{
					LOCK2(cs_main, pwalletMain->cs_wallet);

					if (pwalletMain->HaveKey(vchAddress)) {
						/* pubkey has already been assigned to an account. */
						continue;
					}

					if (!pwalletMain->AddKey(key)) {
						//JSONRPCError(-4,"Error adding key to wallet"); 
						continue; 
					}

					pwalletMain->MarkDirty();
					pwalletMain->SetAddressBookName(vchAddress, strLabel);
				}
			}
		}

		shjson_free(&json);
	}
	pwalletMain->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
	pwalletMain->ReacceptWalletTransactions();

#if 0
	string strSecret = params[0].get_str();
	string strLabel = "";
	//  if (params.size() > 1)
	strLabel = params[1].get_str();
	CCoinSecret vchSecret;
	bool fGood = vchSecret.SetString(strSecret);

	if (!fGood) throw JSONRPCError(-5,"Invalid private key");

	CKey key;
	bool fCompressed;
	CSecret secret = vchSecret.GetSecret(fCompressed);
	key.SetSecret(secret, fCompressed);
	CKeyID vchAddress = key.GetPubKey().GetID();
	{
		LOCK2(cs_main, pwalletMain->cs_wallet);

		pwalletMain->MarkDirty();
		pwalletMain->SetAddressBookName(vchAddress, strLabel);

		if (!pwalletMain->AddKey(key))
			throw JSONRPCError(-4,"Error adding key to wallet");

		pwalletMain->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
		pwalletMain->ReacceptWalletTransactions();
	}
#endif

	return Value::null;
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

		if (strAccount.length() != 0 && strAccount.at(0) == '@')
			continue; /* ext account */

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


Value rpc_wallet_addr(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() > 2)
		throw runtime_error("invalid parameters");

	CWallet *wallet = GetWallet(iface);

	// Parse the account first so we don't generate a key if there's an error
	string strAccount = AccountFromValue(params[0]);
	int mode = 0;
	if (params.size() > 1) {
		string strMode = params[1].get_str();
		mode = GetPubKeyMode(strMode.c_str());
		if (mode == -1)
			throw JSONRPCError(ERR_INVAL, "Invalid coin address mode specified.");
	}

	Value ret;
	ret = wallet->GetAccount(strAccount)->GetAddr(mode).ToString();

	return ret;
}

Value rpc_wallet_witaddr(CIface *iface, const Array& params, bool fStratum)
{
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() == 0 || params.size() > 2) {
		throw runtime_error(
				"wallet.witaddr <addr> [<type>]\n"
				"Returns a witness program which references the coin address specified.");
	}

	CWallet *wallet = GetWallet(iface);
	string strAccount;

	// Parse the account first so we don't generate a key if there's an error
	CCoinAddr address(ifaceIndex, params[0].get_str());
	if (!address.IsValid())
		throw JSONRPCError(-5, "Invalid coin address specified.");

	int output_mode = OUTPUT_TYPE_NONE;
	if (params.size() > 1) {
		string strMode = params[1].get_str();
		if (strMode == "bech32")
			output_mode = OUTPUT_TYPE_BECH32;
		else if (strMode == "p2sh" ||
				strMode == "p2sh-segwit")
			output_mode = OUTPUT_TYPE_P2SH_SEGWIT;
		else if (strMode == "default")
			output_mode = OUTPUT_TYPE_NONE;
		else
			throw JSONRPCError(ERR_INVAL, "invalid type parameter");
	}

	if (!IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
		throw JSONRPCError(-4, "Segregated witness is not enabled on the network.");
	}

	if (!GetCoinAddr(wallet, address, strAccount)) {
		throw JSONRPCError(-5, "No account associated with coin address.");
	}

	/* convert into witness program. */
	CTxDestination result = address.GetWitness(output_mode); 
	wallet->SetAddressBookName(result, strAccount);
	return (CCoinAddr(ifaceIndex, result).ToString());
}

Value rpc_wallet_recvbyaccount(CIface *iface, const Array& params, bool fStratum)
{
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() < 1 || params.size() > 2)
		throw runtime_error(
				"wallet.recvbyaccount <account> [minconf=1]\n"
				"Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.");

	CWallet *wallet = GetWallet(iface);

	// Minimum confirmations
	int nMinDepth = 1;
	if (params.size() > 1)
		nMinDepth = params[1].get_int();

	// Get the set of pub keys assigned to account
	string strAccount = AccountFromValue(params[0]);
	set<CTxDestination> setAddress;
	GetAccountAddresses(wallet, strAccount, setAddress);

	// Tally
	int64 nAmount = 0;
	for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
	{
		const CWalletTx& wtx = (*it).second;
		if (wtx.IsCoinBase() || !wtx.IsFinal(ifaceIndex))
			continue;

		BOOST_FOREACH(const CTxOut& txout, wtx.vout)
		{
			CTxDestination address;
			if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*wallet, address) && setAddress.count(address))
				if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
					nAmount += txout.nValue;
		}
	}

	return (double)nAmount / (double)COIN;
}

Value rpc_wallet_recvbyaddr(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);

	if (params.size() < 1 || params.size() > 2)
		throw runtime_error(
				"wallet.recvbyaddr <coin-address> [minconf=1]\n"
				"Returns the total amount received by <coin-address> in transactions with at least [minconf] confirmations.");

	CCoinAddr address = CCoinAddr(ifaceIndex, params[0].get_str());
	if (!address.IsValid())
		throw JSONRPCError(-5, "Invalid coin address");

	CScript scriptPubKey;
	scriptPubKey.SetDestination(address.Get());
	if (!IsMine(*pwalletMain,scriptPubKey))
		return (double)0.0;

	// Minimum confirmations
	int nMinDepth = 1;
	if (params.size() > 1)
		nMinDepth = params[1].get_int();

	// Tally
	int64 nAmount = 0;
	for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
	{
		const CWalletTx& wtx = (*it).second;
		if (wtx.IsCoinBase() && wtx.vout.size() == 1)
			continue;
		if (!wtx.IsFinal(ifaceIndex))
			continue;


		BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
			CTxDestination out_addr;
			ExtractDestination(txout.scriptPubKey, out_addr);
			if (address.Get() == out_addr)
				if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
					nAmount += txout.nValue;
#if 0
			if (txout.scriptPubKey == scriptPubKey)
				if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
					nAmount += txout.nValue;
#endif
		}
	}

	return  ValueFromAmount(nAmount);
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
		InitServiceWalletEvent(wallet, minHeight);
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

	if (params.size() < 3 || params.size() > 6)
		throw runtime_error(
				"wallet.send <fromaccount> <toaddress> <amount> [minconf=1] [comment] [comment-to]\n"
				"<amount> is a real and is rounded to the nearest 0.00000001");

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

	CTxCreator wtx(wallet, strAccount);
	//CWalletTx wtx;
	//wtx.strFromAccount = strAccount;
	if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
		wtx.mapValue["comment"] = params[4].get_str();
	if (params.size() > 5 && params[5].type() != null_type && !params[5].get_str().empty())
		wtx.mapValue["to"]      = params[5].get_str();

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

	// Detect when changing the account of an address that is the 'unused current key' of another account:
	if (pwalletMain->mapAddressBook.count(address.Get()))
	{
		string strOldAccount = pwalletMain->mapAddressBook[address.Get()];
		if (address == GetAccountAddress(GetWallet(iface), strOldAccount))
			GetAccountAddress(GetWallet(iface), strOldAccount, true);
	}

	pwalletMain->SetAddressBookName(address.Get(), strAccount);

	return Value::null;
}

Value rpc_wallet_setkey(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");
	if (params.size() != 2) {
		throw runtime_error(
				"wallet.setkey <priv-key> <account>\n"
				"Adds a private key (as returned by wallet.key) to your wallet.");
	}

	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	CCoinSecret vchSecret;
	string strSecret = params[0].get_str();
	string strLabel = params[1].get_str();

	bool fGood = vchSecret.SetString(strSecret);
	if (!fGood) {
		/* invalid private key 'string' for particular coin interface. */
		throw JSONRPCError(SHERR_ILSEQ, "private-key");
	}

	CKey key;
	bool fCompressed = true;
	CSecret secret = vchSecret.GetSecret(fCompressed); /* set's fCompressed */
	key.SetSecret(secret, fCompressed);
	CKeyID vchAddress = key.GetPubKey().GetID();

	{
		LOCK2(cs_main, pwalletMain->cs_wallet);

		if (pwalletMain->HaveKey(vchAddress)) {
			/* pubkey has already been assigned to an account. */
			throw JSONRPCError(-8, "Private key already exists.");
		}

		if (!pwalletMain->AddKey(key)) {
			/* error adding key to wallet */
			throw JSONRPCError(-4, "Error adding key to wallet."); 
		}

		/* create a link between account and coin address. */ 
		pwalletMain->SetAddressBookName(vchAddress, strLabel);
		pwalletMain->MarkDirty();

		/* rescan entire block-chain for unspent coins */
		pwalletMain->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
		pwalletMain->ReacceptWalletTransactions();
	}

	return Value::null;
}

Value rpc_wallet_setkeyphrase(CIface *iface, const Array& params, bool fStratum)
{

	if (params.size() != 2) {
		throw runtime_error(
				"wallet.setkeyphrase \"<phrase>\" <account>\n"
				"Adds a private key to your wallet from a key phrase..");
	}

	CCoinSecret vchSecret;
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	bool ret = DecodeMnemonicSecret(ifaceIndex, params[0].get_str(), vchSecret);
	if (!ret)
		throw JSONRPCError(-5, "Invalid private key");

	string strLabel = params[1].get_str();
	bool fGood = vchSecret.IsValid();
	if (!fGood) throw JSONRPCError(-5,"Invalid private key");

	CKey key;
	bool fCompressed;
	CSecret secret = vchSecret.GetSecret(fCompressed);
	key.SetSecret(secret, fCompressed);
	CKeyID vchAddress = key.GetPubKey().GetID();
	{
		LOCK2(cs_main, wallet->cs_wallet);

		std::map<CTxDestination, std::string>::iterator mi = wallet->mapAddressBook.find(vchAddress);
		if (mi != wallet->mapAddressBook.end()) {
			throw JSONRPCError(SHERR_NOTUNIQ, "Address already exists in wallet.");
		}

		wallet->MarkDirty();
		wallet->SetAddressBookName(vchAddress, strLabel);

		if (!wallet->AddKey(key))
			throw JSONRPCError(-4,"Error adding key to wallet");

		wallet->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
		wallet->ReacceptWalletTransactions();
	}

	return Value::null;
}


Value rpc_wallet_unspent(CIface *iface, const Array& params, bool fStratum)
{

	if (params.size() == 0 || params.size() > 2)
		throw runtime_error("unsupported operation");

	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	string strAccount = AccountFromValue(params[0]);

	int nMinDepth = 1;
	if (params.size() > 1)
		nMinDepth = params[1].get_int();

	Array results;
	vector<COutput> vecOutputs;
	pwalletMain->AvailableAccountCoins(strAccount, vecOutputs, 
			(nMinDepth == 0 ? false : true));
	BOOST_FOREACH(const COutput& out, vecOutputs)
	{
		if (out.nDepth < nMinDepth)
			continue;

		int64 nValue = out.tx->vout[out.i].nValue;
		const CScript& pk = out.tx->vout[out.i].scriptPubKey;
		Object entry;
		entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
		entry.push_back(Pair("hash", out.tx->GetWitnessHash().GetHex()));
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
	string strAccount = params[0].get_str();
	bc_t *bc = GetWalletTxChain(iface);
	string strSysAccount("*");
	bcpos_t nArch = 0;
	bcpos_t posTx;
	bool fVerbose = false;
	int i;

	if (params.size() > 2)
		throw runtime_error("unsupported operation");

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

Value rpc_wallet_validate(CIface *iface, const Array& params, bool fStratum)
{
	int ifaceIndex = GetCoinIndex(iface);

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *wallet = GetWallet(iface);

	if (params.size() != 1)
		throw runtime_error(
				"wallet.validate <coin-address>\n"
				"Return information about <coin-address>.");

	CCoinAddr address(ifaceIndex, params[0].get_str());
	bool isValid = true;//address.IsValid();

	Object ret;
	ret.push_back(Pair("isvalid", isValid));
	if (isValid)
	{
		CTxDestination dest = address.Get();
		string currentAddress = address.ToString();
		ret.push_back(Pair("address", currentAddress));
		bool fMine = IsMine(*wallet, dest);
		ret.push_back(Pair("ismine", fMine));
#if 0
		if (fMine) {
			Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
			ret.insert(ret.end(), detail.begin(), detail.end());
		}
#endif
		if (wallet->mapAddressBook.count(dest))
			ret.push_back(Pair("account", wallet->mapAddressBook[dest]));
	}
	return ret;
}

Value rpc_wallet_addrlist(CIface *iface, const Array& params, bool fStratum)
{

	if (params.size() != 1)
		throw runtime_error("wallet.addrlist <account>\nReturns the list of coin addresses for the given account.");

	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	string strAccount = AccountFromValue(params[0]);
	if (!IsAccountValid(iface, strAccount))
		throw JSONRPCError(SHERR_NOENT, "Invalid account name specified.");

	// Find all addresses that have the given account
	Array ret;
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
	{
		const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
		const string& strName = item.second;
		if (strName == strAccount)
			ret.push_back(address.ToString());
	}

	if (strAccount.length() == 0) {
		std::set<CKeyID> keys;
		pwalletMain->GetKeys(keys);
		BOOST_FOREACH(const CKeyID& key, keys) {
			if (pwalletMain->mapAddressBook.count(key) == 0) { /* loner */
				CCoinAddr addr(ifaceIndex, key);
				ret.push_back(addr.ToString());
			}
		}
	}

	return ret;
}

Value rpc_wallet_listbyaddr(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() > 2)
		throw runtime_error(
				"wallet.listbyaddr [minconf=1] [includeempty=false]\n"
				"[minconf] is the minimum number of confirmations before payments are included.\n"
				"[includeempty] whether to include addresses that haven't received any payments.\n"
				"Returns an array of objects containing:\n"
				"  \"address\" : receiving address\n"
				"  \"account\" : the account of the receiving address\n"
				"  \"amount\" : total amount received by the address\n"
				"  \"confirmations\" : number of confirmations of the most recent transaction included");

	return ListReceived(GetWallet(iface), params, false);
}

Value rpc_wallet_listbyaccount(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() > 2)
		throw runtime_error(
				"wallet.listbyaccount [minconf=1] [includeempty=false]\n"
				"[minconf] is the minimum number of confirmations before payments are included.\n"
				"[includeempty] whether to include accounts that haven't received any payments.\n"
				"Returns an array of objects containing:\n"
				"  \"account\" : the account of the receiving addresses\n"
				"  \"amount\" : total amount received by addresses with this account\n"
				"  \"confirmations\" : number of confirmations of the most recent transaction included");

	return ListReceived(GetWallet(iface), params, true);
}

#if 0
Value rpc_wallet_move(CIface *iface, const Array& params, bool fStratum)
{

	if (fStratum)
		throw runtime_error("unsupported operation");

	CWallet *pwalletMain = GetWallet(iface);

	if (params.size() < 3 || params.size() > 5)
		throw runtime_error(
				"wallet.move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
				"Move from one account in your wallet to another.");

	string strFrom = AccountFromValue(params[0]);
	string strTo = AccountFromValue(params[1]);
	int64 nAmount = AmountFromValue(params[2]);
	if (params.size() > 3)
		// unused parameter, used to be nMinDepth, keep type-checking it though
		(void)params[3].get_int();
	string strComment;
	if (params.size() > 4)
		strComment = params[4].get_str();

	CWalletDB walletdb(pwalletMain->strWalletFile);
	if (!walletdb.TxnBegin())
		throw JSONRPCError(-20, "database error");

	int64 nNow = GetAdjustedTime();

	// Debit
	CAccountingEntry debit;
	debit.strAccount = strFrom;
	debit.nCreditDebit = -nAmount;
	debit.nTime = nNow;
	debit.strOtherAccount = strTo;
	debit.strComment = strComment;
	walletdb.WriteAccountingEntry(debit);

	// Credit
	CAccountingEntry credit;
	credit.strAccount = strTo;
	credit.nCreditDebit = nAmount;
	credit.nTime = nNow;
	credit.strOtherAccount = strFrom;
	credit.strComment = strComment;
	walletdb.WriteAccountingEntry(credit);

	if (!walletdb.TxnCommit())
		throw JSONRPCError(-20, "database error");

	return true;
}
#endif

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

/** create a new coin address for the account specified. */
Value rpc_wallet_new(CIface *iface, const Array& params, bool fStratum)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int output_mode = OUTPUT_TYPE_NONE;

	if (params.size() == 0)
		throw runtime_error("invalid parameters");

	Value ret;
	string strAccount = params[0].get_str();
	
	if (params.size() > 1) {
		string strMode = params[1].get_str();
		if (strMode == "bech32")
			output_mode = OUTPUT_TYPE_BECH32;
		else if (strMode == "p2sh-segwit" ||
				strMode == "segwit")
			output_mode = OUTPUT_TYPE_P2SH_SEGWIT;
		else if (strMode == "legacy")
			output_mode = OUTPUT_TYPE_LEGACY;
		else
			throw JSONRPCError(ERR_INVAL, "invalid type parameter");
	}

	/* obtain legacy pubkey address. */
	CCoinAddr addr = GetAccountAddress(GetWallet(iface), strAccount, true);

	if (output_mode == OUTPUT_TYPE_NONE ||
			output_mode == OUTPUT_TYPE_P2SH_SEGWIT ||
			output_mode == OUTPUT_TYPE_BECH32) {
		if (IsWitnessEnabled(iface, GetBestBlockIndex(iface))) {
			/* convert to wit-addr program. */
			CTxDestination dest = addr.GetWitness(output_mode); 
			wallet->SetAddressBookName(dest, strAccount);
			addr = CCoinAddr(ifaceIndex, dest);
		}
	}

	return (addr.ToString());
}

Value rpc_wallet_derive(CIface *iface, const Array& params, bool fStratum)
{

	if (params.size() != 2)
		throw runtime_error("invalid parameters");

	int ifaceIndex = GetCoinIndex(iface);
	CWallet *wallet = GetWallet(iface);
	string strAccount = params[0].get_str();
	string strSeed = params[1].get_str();

	CCoinAddr raddr = GetAccountAddress(GetWallet(iface), strAccount, false);
	if (!raddr.IsValid())
		throw JSONRPCError(-5, "Unknown account name.");

	CCoinAddr addr(ifaceIndex);
	if (!wallet->GetMergedAddress(strAccount, strSeed.c_str(), addr))
		throw JSONRPCError(-5, "Error obtaining merged coin address.");


	Object ret;
	ret.push_back(Pair("seed", strSeed));
	ret.push_back(Pair("origin", raddr.ToString()));
	ret.push_back(Pair("addr", addr.ToString()));

	return (ret);
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

	if (fStratum)
		throw runtime_error("unsupported operation");

	if (params.size() != 1)
		throw runtime_error("wallet.keyphrase");

	CWallet *pwalletMain = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	string strAddress = params[0].get_str();
	CCoinAddr address(ifaceIndex);
	if (!address.SetString(strAddress))
		throw JSONRPCError(-5, "Invalid address");
	CKeyID keyID;
	if (!address.GetKeyID(keyID))
		throw JSONRPCError(-3, "Address does not refer to a key");
	CSecret vchSecret;
	bool fCompressed;
	if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
		throw JSONRPCError(-4,"Private key for address " + strAddress + " is not known");

	CCoinSecret secret(ifaceIndex, vchSecret, fCompressed);
	string phrase = EncodeMnemonicSecret(secret);

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

