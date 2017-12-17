
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura
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
#include "db.h"
#include "walletdb.h"
#include "net.h"
#include "init.h"
#include "util.h"
#include "ui_interface.h"
#include "rpc_proto.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/convenience.hpp>
#ifndef WIN32
#include <signal.h>
#endif

#define WALLET_FILENAME_SUFFIX "wallet"

using namespace std;
using namespace boost;
using namespace json_spirit;


extern Value ValueFromAmount(int64 amount);



extern void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Array& ret);

extern string JSONRPCReply(const Value& result, const Value& error, const Value& id);


#if 0
class DescribeAddressVisitor : public boost::static_visitor<Object>
{
public:
    Object operator()(const CNoDestination &dest) const { return Object(); }

    Object operator()(CWallet *pwalletMain, const CKeyID &keyID) const {
        Object obj;
        CPubKey vchPubKey;
        pwalletMain->GetPubKey(keyID, vchPubKey);
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("pubkey", HexStr(vchPubKey.Raw())));
        obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        return obj;
    }

    Object operator()(CWallet *pwalletMain, const CScriptID &scriptID) const {
        Object obj;
        obj.push_back(Pair("isscript", true));
        CScript subscript;
        pwalletMain->GetCScript(scriptID, subscript);
        std::vector<CTxDestination> addresses;
        txnouttype whichType;
        int nRequired;
        ExtractDestinations(subscript, whichType, addresses, nRequired);
        obj.push_back(Pair("script", GetTxnOutputType(whichType)));
        Array a;
        BOOST_FOREACH(const CTxDestination& addr, addresses)
            a.push_back(CCoinAddr(addr).ToString());
        obj.push_back(Pair("addresses", a));
        if (whichType == TX_MULTISIG)
            obj.push_back(Pair("sigsrequired", nRequired));
        return obj;
    }
};
#endif


string address;

Object stratumerror_obj;
void SetStratumError(Object error)
{
  stratumerror_obj = error;
}
Object GetStratumError(void)
{
  return (stratumerror_obj);
}

static uint256 get_private_key_hash(CWallet *wallet, CKeyID keyId)
{
  CSecret vchSecret;
  bool fCompressed;
  uint256 phash;

  if (!wallet->GetSecret(keyId, vchSecret, fCompressed))
    return (phash);

  CCoinSecret sec(wallet->ifaceIndex, vchSecret, fCompressed);
  if (!sec.IsValid()) {
    error(SHERR_INVAL, "get_private_key_hash: invalid secret for keyid '%s'.", keyId.ToString().c_str());
    return (phash);
  }

  string secret = sec.ToString();
  unsigned char *secret_str = (unsigned char *)secret.c_str();
  size_t secret_len = secret.length();
  SHA256(secret_str, secret_len, (unsigned char*)&phash);

  return (phash);
}


Object JSONAddressInfo(int ifaceIndex, CCoinAddr address, bool show_priv)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  CTxDestination dest = address.Get();
  string currentAddress = address.ToString();
  Object result;

  result.push_back(Pair("address", currentAddress));

  if (iface)
    result.push_back(Pair("coin", iface->name));

  if (show_priv) {
    CKeyID keyID;
    bool fCompressed;
    CSecret vchSecret;
    uint256 pkey;

    if (!address.GetKeyID(keyID)) {
      throw JSONRPCError(STERR_ACCESS_UNAVAIL,
          "Private key for address " + currentAddress + " is not known");
    }

    pkey = get_private_key_hash(pwalletMain, keyID);
    result.push_back(Pair("pkey", pkey.GetHex()));

    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
      throw JSONRPCError(STERR_ACCESS_UNAVAIL,
          "Private key for address " + currentAddress + " is not known");
    }
    result.push_back(Pair("secret", CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString()));
  }

//    bool fMine = IsMine(*pwalletMain, dest);
#if 0
  Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
  result.insert(result.end(), detail.begin(), detail.end());
#endif
  if (pwalletMain->mapAddressBook.count(dest))
    result.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));

  return (result);
}

#if 0
int cxx_UpgradeWallet(void)
{
  int nMaxVersion = 0;//GetArg("-upgradewallet", 0);
  if (nMaxVersion == 0) // the -upgradewallet without argument case
  {
    nMaxVersion = CLIENT_VERSION;
    pwalletMain->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
    Debug("using wallet version %d", FEATURE_LATEST);
  }
  else
    printf("Allowing wallet upgrade up to %i\n", nMaxVersion);

  if (nMaxVersion > pwalletMain->GetVersion()) {
    pwalletMain->SetMaxVersion(nMaxVersion);
  }

}
int c_LoadWallet(void)
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  std::ostringstream strErrors;

  const char* pszP2SH = "/P2SH/";
  COINBASE_FLAGS << std::vector<unsigned char>(pszP2SH, pszP2SH+strlen(pszP2SH));

  if (!bitdb.Open(GetDataDir()))
  {
    fprintf(stderr, "error: unable to open data directory.\n");
    return (-1);
  }

  if (!LoadBlockIndex(iface)) {
    fprintf(stderr, "error: unable to open load block index.\n");
    return (-1);
  }

  bool fFirstRun = true;
  pwalletMain = new CWallet("wallet.dat");
  SetWallet(USDE_COIN_IFACE, pwalletMain);
  pwalletMain->LoadWallet(fFirstRun);

  if (fFirstRun)
  {

    // Create new keyUser and set as default key
    RandAddSeedPerfmon();

    CPubKey newDefaultKey;
    if (!pwalletMain->GetKeyFromPool(newDefaultKey, false))
      strErrors << _("Cannot initialize keypool") << "\n";
    pwalletMain->SetDefaultKey(newDefaultKey);
    if (!pwalletMain->SetAddressBookName(pwalletMain->vchDefaultKey.GetID(), ""))
      strErrors << _("Cannot write default address") << "\n";
  }

  printf("%s", strErrors.str().c_str());

  RegisterWallet(pwalletMain);

  CBlockIndex *pindexRescan = pindexBest;
  if (GetBoolArg("-rescan"))
    pindexRescan = pindexGenesisBlock;
  else
  {
    CWalletDB walletdb("wallet.dat");
    CBlockLocator locator(GetCoinIndex(iface));
    if (walletdb.ReadBestBlock(locator))
      pindexRescan = locator.GetBlockIndex();
  }
  if (pindexBest != pindexRescan && pindexBest && pindexRescan && pindexBest->nHeight > pindexRescan->nHeight)
  {
    int64 nStart;

    printf("Rescanning last %i blocks (from block %i)...\n", pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
    nStart = GetTimeMillis();
    pwalletMain->ScanForWalletTransactions(pindexRescan, true);
    printf(" rescan      %15"PRI64d"ms\n", GetTimeMillis() - nStart);
  }

}
#endif

#if 0
/** load peers */
int c_LoadPeers(void)
{
  int64 nStart;

  nStart = GetTimeMillis();
#if 0
  {
    CAddrDB adb;
    if (!adb.Read(addrman))
      printf("Invalid or missing peers.dat; recreating\n");
  }
  printf("Loaded %i addresses from peers.dat  %"PRI64d"ms\n",
      addrman.size(), GetTimeMillis() - nStart);
#endif

  RandAddSeedPerfmon();
//  pwalletMain->ReacceptWalletTransactions();
}
#endif

CCoinAddr GetNewAddress(CWallet *wallet, string strAccount)
{
  if (!wallet->IsLocked())
    wallet->TopUpKeyPool();

  // Generate a new key that is added to wallet
  CPubKey newKey;
  if (!wallet->GetKeyFromPool(newKey, false)) {
    throw JSONRPCError(-12, "Error: Keypool ran out, please call keypoolrefill first");
  }
  CKeyID keyID = newKey.GetID();

  wallet->SetAddressBookName(keyID, strAccount);

  return CCoinAddr(keyID);
}

string getnewaddr_str;
const char *json_getnewaddress(int ifaceIndex, const char *account)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strAccount(account);

  if (!wallet)
    return (NULL);

  if (!wallet->IsLocked())
    wallet->TopUpKeyPool();

  // Generate a new key that is added to wallet
  CPubKey newKey;
  if (!wallet->GetKeyFromPool(newKey, false)) {
    return (NULL);
  }
  CKeyID keyID = newKey.GetID();
  wallet->SetAddressBookName(keyID, strAccount);
  getnewaddr_str = CCoinAddr(keyID).ToString();

  return (getnewaddr_str.c_str());
}




static CCoinAddr GetAddressByAccount(CWallet *wallet, const char *accountName, bool& found)
{
  CCoinAddr address(wallet->ifaceIndex);
  string strAccount(accountName);
  Array ret;

  // Find all addresses that have the given account
  found = false;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const string& strName = item.second;
    if (strName == strAccount) {
      address = CCoinAddr(wallet->ifaceIndex, item.first);
      if (!address.IsValid()) {
        error(SHERR_INVAL, "GetAddressByAccount: account \"%s\" has invalid coin address.", accountName); 
        continue;
      }

      found = true;
      break;
    }
  }

  return (address);
}

const char *c_getaddressbyaccount(int ifaceIndex, const char *accountName)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  bool found = false;

  if (!wallet)
    return (NULL);

  CCoinAddr addr = GetAddressByAccount(wallet, accountName, found);
  if (!found || !addr.IsValid())
     return (NULL);
  return (addr.ToString().c_str());
}

static string walletkeylist_json;
static const char *cpp_stratum_walletkeylist(int ifaceIndex, const char *acc_name)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);
  string strAccount(acc_name);
  Object ret;

  if (!iface || !wallet || !iface->enabled)
    return (NULL);

  ret.push_back(Pair("account", strAccount));

  Array ar;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook) {
    const string& strName = item.second;
    if (strName == strAccount) {
      CCoinAddr address = CCoinAddr(wallet->ifaceIndex, item.first);
      bool fComp;
      CSecret secret;
      CKeyID keyID;
      CKey key;

      if (!address.IsValid())
        continue;
      if (!address.GetKeyID(keyID))
        continue;
      if (!wallet->GetKey(keyID, key))
        continue;

      secret = key.GetSecret(fComp); 
      //cbuff buff(secret.begin(), secret.end());
      ar.push_back(CCoinSecret(ifaceIndex, secret, fComp).ToString());
     // ar.push_back(HexStr(buff.begin(), buff.end()));
    }
  }
  ret.push_back(Pair("key", ar));

  walletkeylist_json = JSONRPCReply(ret, Value::null, Value::null);
  return (walletkeylist_json.c_str());
}

/**
 * Sends a reward to a particular address.
 */
int c_setblockreward(int ifaceIndex, const char *accountName, double dAmount)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  CWalletDB walletdb(pwalletMain->strWalletFile);
  string strMainAccount("");
  string strAccount(accountName);
  string strComment("sharenet");
  int64 nAmount;
  Array ret;
  int nMinDepth = 1; /* single confirmation requirement */
  int nMinConfirmDepth = 1; /* single confirmation requirement */
  bool found = false;
  int64 nBalance;

  if (pwalletMain->IsLocked()) {
fprintf(stderr, "DEBUG: c_setblockreward: wallet is locked\n");
    return (-13);
  }

  if (dAmount <= 0)
    return (SHERR_INVAL);

  const CCoinAddr address = GetAddressByAccount(pwalletMain, accountName, found);
  if (!found) {
fprintf(stderr, "DEBUG: c_setblockreward[iface #%d]: account '%s' not found\n", ifaceIndex, accountName);
    return (-5);
  }
  if (!address.IsValid()) {
    char errbuf[1024];
    sprintf(errbuf, "setblockreward: account '%s' has invalid %s address.", accountName, iface->name);
    shcoind_log(errbuf);
    //throw JSONRPCError(-5, "Invalid usde address");
    return (-5);
  }


  if (dAmount <= 0.0 || dAmount > 84000000.0) {
    return (-3);
  }

  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount)) {
    return (-3);
  }

  nBalance  = GetAccountBalance(ifaceIndex, walletdb, strMainAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
    shcoind_log("c_setblockreward: warning: main account has insufficient funds for block reward distribution.");
    return (-6);
  }

  CWalletTx wtx;
  wtx.strFromAccount = strMainAccount;
  wtx.mapValue["comment"] = strComment;
  string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
  if (strError != "") {
fprintf(stderr, "DEBUG: '%s' = SendMoneyTo: amount %d\n", strError.c_str(), (int)nAmount);
    //throw JSONRPCError(-4, strError);
    return (-4);
  }

  return (0);
}

vector< pair<CScript, int64> > vecRewardSend;
#if 0
int64 nBankFee = 0;
#endif

int c_addblockreward(int ifaceIndex, const char *accountName, double dAmount)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  CWalletDB walletdb(pwalletMain->strWalletFile);
  string strAccount(accountName);
  string strMainAccount("");
  int64 nAmount;
  Array ret;
  int nMinDepth = 1; /* single confirmation requirement */
  int nMinConfirmDepth = 1; /* single confirmation requirement */
  int64 nBalance;

  if (pwalletMain->IsLocked()) {
fprintf(stderr, "DEBUG: c_setblockreward: wallet is locked\n");
    return (-13);
  }

  if (dAmount <= 0)
    return (-3);

#if 0
  CCoinAddr address;
  if (!wallet->GetMergedAddress(accountName, "miner", address))
    return (-5);
#endif
  bool found = false;
  CCoinAddr address = GetAddressByAccount(pwalletMain, accountName, found);
  if (!found || !address.IsValid()) {
//    error(SHERR_NOENT, "setblockreward: account '%s' has invalid %s coin address.", accountName, iface->name);
    return (-5);
  }


  if (dAmount <= 0.0 || dAmount > 84000000.0) {
    return (-3);
  }

  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount)) {
    return (-3);
  }

  nBalance  = GetAccountBalance(ifaceIndex, walletdb, strMainAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
    shcoind_log("c_setblockreward: warning: main account has insufficient funds for block reward distribution.");
    return (-6);
  }

  /* add to list */
  CScript scriptPubKey;
  scriptPubKey.SetDestination(address.Get());
  vecRewardSend.push_back(make_pair(scriptPubKey, nAmount));

  return (0);
}

int c_sendblockreward(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *wallet = GetWallet(ifaceIndex);
  string strMainAccount("");
  int64 nFeeRet;
  int nMinConfirmDepth = 1; /* single confirmation requirement */
  bool fRet;

  if (vecRewardSend.size() == 0)
    return (0); /* all done */

  /* calculate already-subtracted fee */
  int64 nTotValue = 0;
  int64 nValue = 0;
  BOOST_FOREACH(const PAIRTYPE(CScript, int64)& item, vecRewardSend) {
#if 0
    nValue += item.second + (item.second / 1000);
#endif
    nTotValue += item.second;
  }

#if 0
  nBankFee += nValue / 1000;

  /* add in residual bank fee */
  if (nBankFee > (MIN_TX_FEE(iface) * 10)) {
    CCoinAddr address(ifaceIndex);
    if (wallet->GetMergedAddress(strMainAccount, "bank", address)) {
      CScript scriptPubKey;
      scriptPubKey.SetDestination(address.Get());
      vecRewardSend.push_back(make_pair(scriptPubKey, nBankFee));
    }
    nBankFee = 0;
  }
#endif


#if 0
  /* double-check balance */
  nBalance  = GetAccountBalance(ifaceIndex, walletdb, strMainAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
    shcoind_log("c_setblockreward: warning: main account has insufficient funds for block reward distribution.");
    return (-6);
  }
#endif

  CWalletTx wtx;
  wtx.strFromAccount = strMainAccount;

  string strError;
  fRet = wallet->CreateAccountTransaction(strMainAccount, vecRewardSend, wtx, strError, nFeeRet);
  vecRewardSend.clear();
  if (!fRet)
    return (-4);

  fRet = wallet->CommitTransaction(wtx);
  if (!fRet)
    return (-4);

  Debug("sendblockreward: sent %f coins for stratum reward(s) [tx-fee %f].", (double)nTotValue/(double)COIN, (double)nFeeRet/(double)COIN);

#if 0
  /* bank pays for all transaction fees */
  nBankFee -= nFeeRet;
#endif

  return (0);
}


/**
 * Transfer currency between two accounts.
 */
static int c_wallet_account_transfer(int ifaceIndex, const char *sourceAccountName, const char *accountName, const char *comment, double dAmount)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);

  if (0 == strcmp(sourceAccountName, ""))
    return (-14);

  CWalletDB walletdb(pwalletMain->strWalletFile);
  string strMainAccount(sourceAccountName);
  string strAccount(accountName);
  string strComment(comment);
  int64 nAmount;
  Array ret;
  int nMinDepth = 1; /* single confirmation requirement */
  int nMinConfirmDepth = 1; /* single confirmation requirement */
  bool found = false;
  int64 nBalance;

  if (pwalletMain->IsLocked()) {
    shcoind_log("c_wallet_account_transfer: wallet is locked.");
    return (-13);
  }

  // Find all addresses that have the given account
  CCoinAddr address(ifaceIndex);
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
  {
    const CCoinAddr& acc_address = CCoinAddr(ifaceIndex, item.first);
    const string& strName = item.second;
    if (strName == strAccount) {
      address = acc_address;
      found = true;
    }
  }
  if (!found) {
    return (-7);
  }

  if (dAmount <= 0.0 || dAmount > 84000000.0) {
    fprintf(stderr, "DEBUG: invalid amount (%f)\n", dAmount);
    //throw JSONRPCError(-3, "Invalid amount");
    return (-3);
  }

  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(ifaceIndex, nAmount)) {
    fprintf(stderr, "DEBUG: invalid amount: !MoneyRange(%d)\n", (int)nAmount);
    //throw JSONRPCError(-3, "Invalid amount");
    return (-3);
  }


  nBalance  = GetAccountBalance(ifaceIndex, walletdb, strMainAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
    fprintf(stderr, "DEBUG: account has insufficient funds\n");
    //throw JSONRPCError(-6, "Account has insufficient funds");
    return (-6);
  }

  //address = GetAddressByAccount(accountName);
  if (!address.IsValid()) {
    fprintf(stderr, "DEBUG: invalid usde address destination\n");
    //throw JSONRPCError(-5, "Invalid usde address");
    return (-5);
  }

  CWalletTx wtx;
  wtx.strFromAccount = strMainAccount;
  wtx.mapValue["comment"] = strComment;
  string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
  if (strError != "") {
    fprintf(stderr, "DEBUG: '%s' = SendMoneyTo: amount %d\n", strError.c_str(), (int)nAmount);
    return (-4);
  }

  return (0);
}

double c_getaccountbalance(int ifaceIndex, const char *accountName)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  CWalletDB walletdb(pwalletMain->strWalletFile);
  string strAccount(accountName);

  int nMinDepth = 1;
  int64 nBalance = GetAccountBalance(ifaceIndex, walletdb, strAccount, nMinDepth);

  return ((double)nBalance / (double)COIN);
}

static bool valid_pkey_hash(string strAccount, uint256 in_pkey)
{
  CWallet *wallet;
  uint256 acc_pkey;
  int ifaceIndex;
  int valid;

  valid = 0;
  for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
    wallet = GetWallet(ifaceIndex);
    if (!wallet) 
      continue;

    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
    {
      const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
      const string& strName = item.second;
      CKeyID keyID;

      if (strName != strAccount)
        continue;
      if (!address.GetKeyID(keyID))
        continue;

      acc_pkey = get_private_key_hash(wallet, keyID);
      if (acc_pkey == in_pkey)
        valid++;
    }
  }

  if (valid > 0)
    return (true);
  return (false);
}

bool GetStratumKeyAccount(uint256 in_pkey, string& strAccount)
{
  static uint256 local_site_key;
  CWallet *wallet;
  uint256 acc_pkey;
  int ifaceIndex;
  int valid;


  valid = 0;
  for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
    wallet = GetWallet(ifaceIndex);
    if (!wallet) 
      continue;

    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
    {
      const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
      const string& strName = item.second;
      CKeyID keyID;

      if (!address.GetKeyID(keyID))
        continue;

      acc_pkey = get_private_key_hash(wallet, keyID);
      if (acc_pkey == in_pkey) {
        strAccount = strName;
        return (true);
      }
    }
  }

  return (false);
}

/**
 * local up to 100 transactions associated with account name.
 * @param duration The range in the past to search for account transactions (in seconds).
 * @returns json string format 
 */
string accounttransactioninfo_json;
void ListTransactions(int ifaceIndex, const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret);
static const char *json_getaccounttransactioninfo(int ifaceIndex, const char *tx_account, const char *pkey_str, int duration)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  string strAccount(tx_account);
  uint256 in_pkey = 0;
  Array result;
  int64 min_t;
  int max = 100;
  int idx;

  try {
    in_pkey.SetHex(pkey_str);
    if (!valid_pkey_hash(strAccount, in_pkey)) {
      throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
    }

    min_t = time(NULL) - duration;
    CWalletDB walletdb(pwalletMain->strWalletFile);
    //for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.end(); it != pwalletMain->mapWallet.begin(); --it) {
      CWalletTx* wtx = &((*it).second);

      if (wtx->GetTxTime() < min_t)
        continue;

      ListTransactions(ifaceIndex, *wtx, strAccount, 0, true, result);

      idx++;
      if (idx > max)
        break;
    }
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  accounttransactioninfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (accounttransactioninfo_json.c_str());
}

string addressinfo_json;
const char *json_getaddressinfo(int ifaceIndex, const char *addr_hash, const char *pkey_str)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strAddr(addr_hash);
  Object result;

  try {
    CCoinAddr address(strAddr);
    CKeyID keyID;

    if (!address.IsValid()) {
      throw JSONRPCError(STERR_INVAL, "Invalid coin destination address");
    }

    if (pkey_str && strlen(pkey_str) > 1) {
      uint256 in_pkey = 0;
      uint256 acc_pkey;

      if (!address.GetKeyID(keyID)) {
        throw JSONRPCError(STERR_ACCESS, "Address does not refer to a key.");
      }

      in_pkey.SetHex(pkey_str);
      acc_pkey = get_private_key_hash(wallet, keyID);
      if (acc_pkey != in_pkey) {
        throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
      }
    }

#if 0
    if (pkey_str) { /* optional */
      uint256 in_pkey = 0;
      uint256 acc_pkey;

      if (!address.GetKeyID(keyID)) {
        throw JSONRPCError(STERR_ACCESS, "Address does not refer to a key.");
      }

      in_pkey.SetHex(pkey_str);
      acc_pkey = get_private_key_hash(keyID);
      if (acc_pkey != in_pkey) {
        throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
      }
    }

    CTxDestination dest = address.Get();
    string currentAddress = address.ToString();
    result.push_back(Pair("address", currentAddress));
    if (pkey_str) {
      bool fCompressed;
      CSecret vchSecret;
      if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
        throw JSONRPCError(STERR_ACCESS_UNAVAIL,
            "Private key for address " + currentAddress + " is not known");
      }
      result.push_back(Pair("secret", CCoinSecret(vchSecret, fCompressed).ToString()));
    }

//    bool fMine = IsMine(*pwalletMain, dest);
    Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
    result.insert(result.end(), detail.begin(), detail.end());
    if (pwalletMain->mapAddressBook.count(dest))
      result.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));
#endif
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  if (pkey_str && strlen(pkey_str) > 1) {
    result = JSONAddressInfo(ifaceIndex, addr_hash, true);
  } else {
    result = JSONAddressInfo(ifaceIndex, addr_hash, false);
  }

  addressinfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (addressinfo_json.c_str());
}

bool VerifyLocalAddress(CWallet *wallet, CKeyID vchAddress)
{
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(wallet->ifaceIndex, item.first);
    const string& strName = item.second;
    CKeyID keyID;
    address.GetKeyID(keyID);
    if (keyID == vchAddress)
      return (true);
  }

  return (false);
}

string createaccount_json;
static const char *json_stratum_create_account(int ifaceIndex, const char *acc_name)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  string strAccount(acc_name);
  string coinAddr = "";
  uint256 phash = 0;
  CPubKey newKey;
  bool found;
  int idx;

  try {
    if (strAccount == "" || strAccount == "*") {
      throw JSONRPCError(STERR_INVAL_PARAM, "The account name specified is invalid.");
    }

    /* check for duplicate against all coin services. */
    for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
      CWallet *wallet = GetWallet(idx); 
      if (!wallet)
        continue;

      found = false;
      CCoinAddr address = GetAddressByAccount(wallet, acc_name, found);
      if (found && address.IsValid()) {
        throw JSONRPCError(STERR_INVAL_PARAM, "Account name is not unique.");
      }

    }

    /* generate new account for all coin services. */
    for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
      CWallet *wallet = GetWallet(idx); 
      if (!wallet)
        continue;

      /* Generate a new key that is added to wallet. */
      if (!wallet->GetKeyFromPool(newKey, false)) {
        if (!wallet->IsLocked())
          wallet->TopUpKeyPool();
        if (!wallet->GetKeyFromPool(newKey, false)) {
          throw JSONRPCError(STERR_INTERNAL_MAP, "No new keys currently available.");
          return (NULL);
        }
      }

      CKeyID keyId = newKey.GetID();
      wallet->SetAddressBookName(keyId, strAccount);
      if (ifaceIndex == idx) {
        coinAddr = CCoinAddr(keyId).ToString();
        phash = get_private_key_hash(pwalletMain, keyId);
      }
    }
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  Object result;
  result.push_back(Pair("address", coinAddr));
  result.push_back(Pair("key", phash.GetHex()));
  createaccount_json = JSONRPCReply(result, Value::null, Value::null);
  return (createaccount_json.c_str());
}

/**
 * Creates an coin transaction for a single user account. 
 * @note charges 0.1 coins per each transaction to "bank" account.
 */
string transferaccount_json;
static const char *c_stratum_account_transfer(int ifaceIndex, char *account, char *pkey_str, char *dest, double amount)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  CWalletDB walletdb(pwalletMain->strWalletFile);
  string strAccount(account);
  string strDestAddress(dest);
  CWalletTx wtx;
  int64 nAmount;
  string strAddress;
  CKeyID keyID;
  CSecret vchSecret;
  bool fCompressed;
  uint256 acc_pkey;
  uint256 in_pkey;
  int nMinDepth;
  int64 nBalance;
  int64 nFee = COIN / 10;
  int64 nTxFee = 0;

  try {
    in_pkey = 0;
    nMinDepth = 1;

    if (pwalletMain->IsLocked()) {
      throw JSONRPCError(STERR_ACCESS_NOKEY, "Account transactions are not currently available.");
    }

    CCoinAddr dest_address(strDestAddress);
    if (!dest_address.IsValid()) {
      throw JSONRPCError(STERR_INVAL, "invalid coin address");
    }

    in_pkey.SetHex(pkey_str);
    if (!valid_pkey_hash(strAccount, in_pkey)) {
      throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
    }

    nAmount = roundint64(amount * COIN);
    if (!MoneyRange(ifaceIndex, nAmount) || nAmount <= nFee) {
      throw JSONRPCError(STERR_INVAL_AMOUNT, "Invalid coin amount.");
    }

    nBalance = GetAccountBalance(ifaceIndex, walletdb, strAccount, nMinDepth);
    if (nAmount > nBalance) {
      throw JSONRPCError(STERR_FUND_UNAVAIL, "Account has insufficient funds.");
    }

    vector<pair<CScript, int64> > vecSend;
    bool bankAddressFound = false;
    CScript scriptPubKey;

    /* send fee to main account */
    CCoinAddr bankAddress = GetAddressByAccount(pwalletMain, "", bankAddressFound);
    if (!bankAddressFound || !bankAddress.IsValid()) {
      nFee = 0;
    }

    wtx.strFromAccount = strAccount;
    wtx.mapValue["comment"] = "sharelib.net";
    /* bank */
    if (nFee) {
      scriptPubKey.SetDestination(bankAddress.Get());
      vecSend.push_back(make_pair(scriptPubKey, nFee));
    }
    /* user */
    string strError;
    scriptPubKey.SetDestination(dest_address.Get());
    vecSend.push_back(make_pair(scriptPubKey, nAmount - nFee));
    if (!pwalletMain->CreateAccountTransaction(strAccount, vecSend, wtx, strError, nTxFee)) {
      if (nAmount + nTxFee > pwalletMain->GetBalance())
        throw JSONRPCError(STERR_FUND_UNAVAIL, "Insufficient funds for transaction.");
      throw JSONRPCError(STERR_ACCESS_UNAVAIL, "Transaction creation failure.");
    }

    if (!pwalletMain->CommitTransaction(wtx)) {
      throw JSONRPCError(STERR_ACCESS_UNAVAIL, "Transaction commit failed.");
    }
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  Object result;
  result.push_back(Pair("txid", wtx.GetHash().GetHex()));
  result.push_back(Pair("fee", ValueFromAmount(nFee + nTxFee)));
  result.push_back(Pair("amount", ValueFromAmount(nAmount - nFee - nTxFee)));
  transferaccount_json = JSONRPCReply(result, Value::null, Value::null);
  return (transferaccount_json.c_str());
}

string accountinfo_json;
static const char *c_stratum_account_info(int ifaceIndex, const char *acc_name, const char *pkey_str)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWalletDB walletdb(pwalletMain->strWalletFile);
  string strAccount(acc_name);
  int64 nConfirm;
  int64 nUnconfirm;
  int nMinDepth = 1;
  Object result;
  Array addr_list;
  uint256 phash;

  try {
    if (strAccount == "" || strAccount == "*") {
      throw JSONRPCError(STERR_INVAL_PARAM, "The account name specified is invalid.");
    }

    if (pkey_str) {
      uint256 in_pkey;

      in_pkey.SetHex(pkey_str);
      if (!valid_pkey_hash(strAccount, in_pkey)) {
        throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified for account.");
      }
    }

    nConfirm = GetAccountBalance(ifaceIndex, walletdb, strAccount, nMinDepth);
    nUnconfirm = GetAccountBalance(ifaceIndex, walletdb, strAccount, 0) - nConfirm;
    result.push_back(Pair("confirmed", ValueFromAmount(nConfirm)));
    result.push_back(Pair("unconfirmed", ValueFromAmount(nUnconfirm)));

    // Find all addresses that have the given account
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
    {
      const CCoinAddr& acc_address = CCoinAddr(ifaceIndex, item.first);
      const string& strName = item.second;
      if (strName == strAccount) {
        addr_list.push_back(JSONAddressInfo(ifaceIndex, acc_address, false));
      }
    }
    result.push_back(Pair("addresses", addr_list));
#if 0
    BOOST_FOREACH(const PAIRTYPE(CCoinAddr, string)& item, pwalletMain->mapAddressBook)
    {
      const CCoinAddr& acc_address = item.first;
      const string& strName = item.second;
      if (strName == strAccount) {
        addr_list.push_back(acc_address.ToString());

        CKeyID keyID;
        acc_address.GetKeyID(keyID);
        phash = get_private_key_hash(keyID);
      }
    }
    result.push_back(Pair("addresses", addr_list));
#endif
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  accountinfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (accountinfo_json.c_str());
}

string account_import_json;
static const char *json_stratum_account_import(int ifaceIndex, const char *acc_name, const char *privaddr_str)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CWallet *pwalletMain = GetWallet(iface);
  string strLabel(acc_name);
  string strSecret(privaddr_str);
  CCoinSecret vchSecret;
  CKeyID vchAddress;
  bool ok;

  try {
    ok = vchSecret.SetString(strSecret);
    if (!ok) {
      throw JSONRPCError(STERR_INVAL, "Invalid private key specified.");
    }

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    vchAddress = key.GetPubKey().GetID();

    if (VerifyLocalAddress(pwalletMain, vchAddress)) {
      throw JSONRPCError(STERR_INVAL_PARAM, "Address already registered to local account.");
    }

    {
      LOCK2(cs_main, pwalletMain->cs_wallet);

      pwalletMain->MarkDirty();
      pwalletMain->SetAddressBookName(vchAddress, strLabel);

      if (pwalletMain->AddKey(key)) {
        /* key did not previously exist in wallet db */
        pwalletMain->ScanForWalletTransactions(GetGenesisBlockIndex(iface));
        pwalletMain->ReacceptWalletTransactions();
      }
    }
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  Object result;
  CCoinAddr addr(vchAddress);

  result.push_back(Pair("address", addr.ToString()));
  account_import_json = JSONRPCReply(result, Value::null, Value::null);
  return (account_import_json.c_str());
}

string stratumerror_json;
const char *c_stratum_error_get(int req_id)
{
  Object error;
  Object reply;
  Value id = req_id;

  error = GetStratumError();
  stratumerror_json = JSONRPCReply(Value::null, error, id);
  return (stratumerror_json.c_str());
}

#if 0
static const char *cpp_stratum_call_rpc(int ifaceIndex, const char *account, const char *pkey_str, shjson_t *json)
{
  string strAccount(account);
  uint256 in_pkey;

  if (account && pkey_str && *pkey_str) { 
    in_pkey.SetHex(pkey_str);
    if (!valid_pkey_hash(strAccount, in_pkey)) {
      error(SHERR_ACCESS, "Invalid private key hash specified.");
      return (NULL);
    }
  } else {
    account = NULL;
  }

  return (ExecuteStratumRPC(ifaceIndex, account, json));
}
#endif



#ifdef __cplusplus
extern "C" {
#endif

#if 0
int load_wallet(void)
{
  return (c_LoadWallet());
}

int upgrade_wallet(void)
{
  return (cxx_UpgradeWallet());
}
#endif

#if 0
int load_peers(void)
{
  return (c_LoadPeers());
}
#endif

const char *getaddressbyaccount(int ifaceIndex, const char *accountName)
{
  if (accountName || !*accountName)
    return (NULL);
  return (c_getaddressbyaccount(ifaceIndex, accountName));
}

double getaccountbalance(int ifaceIndex, const char *accountName)
{
  return (c_getaccountbalance(ifaceIndex, accountName));
}

int setblockreward(int ifaceIndex, const char *accountName, double amount)
{
  if (!*accountName)
    return (-5); /* invalid coin address */
  return (c_setblockreward(ifaceIndex, accountName, amount));
}

int addblockreward(int ifaceIndex, const char *accountName, double amount)
{
  if (!*accountName)
    return (-5); /* invalid coin address */
  return (c_addblockreward(ifaceIndex, accountName, amount));
}

int sendblockreward(int ifaceIndex)
{
  return (c_sendblockreward(ifaceIndex));
}

int wallet_account_transfer(int ifaceIndex, const char *sourceAccountName, const char *accountName, const char *comment, double amount)
{
  if (!accountName || !*accountName)
    return (-5); /* invalid usde address */
  return (c_wallet_account_transfer(ifaceIndex, sourceAccountName, accountName, comment, amount));
}

const char *getaccounttransactioninfo(int ifaceIndex, const char *account, const char *pkey_str, int duration)
{
  if (!account)
    return (NULL);
  return (json_getaccounttransactioninfo(ifaceIndex, account, pkey_str, duration));
}

const char *stratum_getaddressinfo(int ifaceIndex, const char *addr_hash)
{
  if (!addr_hash)
    return (NULL);
  return (json_getaddressinfo(ifaceIndex, addr_hash, NULL));
}
const char *stratum_getaddresssecret(int ifaceIndex, const char *addr_hash, const char *pkey_str)
{
  if (!addr_hash)
    return (NULL);
  return (json_getaddressinfo(ifaceIndex, addr_hash, pkey_str));
}

const char *stratum_create_account(int ifaceIndex, const char *acc_name)
{
  if (!acc_name)
    return (NULL);
  return (json_stratum_create_account(ifaceIndex, acc_name));
}

const char *stratum_create_transaction(int ifaceIndex, char *account, char *pkey_str, char *dest, double amount)
{
  if (!account || !pkey_str || !dest)
    return (NULL);
  return (c_stratum_account_transfer(ifaceIndex, account, pkey_str, dest, amount));
}

const char *stratum_getaccountinfo(int ifaceIndex, const char *account, const char *pkey_str)
{
  if (!account)
    return (NULL);
  return (c_stratum_account_info(ifaceIndex, account, pkey_str));
}

const char *stratum_error_get(int req_id)
{
  return (c_stratum_error_get(req_id));
}

const char *stratum_importaddress(int ifaceIndex, const char *account, const char *privaddr_str)
{
  if (!account || !privaddr_str)
    return (NULL);
  return (json_stratum_account_import(ifaceIndex, account, privaddr_str));
}

const char *getnewaddress(int ifaceIndex, const char *account)
{
  return (json_getnewaddress(ifaceIndex, account));
}

static uint32_t generate_addrlist_crc(int ifaceIndex, const char *acc_name) 
{
  CIface *iface;
  CWallet *wallet;
  string strAccount;
  char buf[1024];
  uint32_t ret_crc;

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled) return (0);
  wallet = GetWallet(iface);
  if (!wallet) return (0);
  if (!acc_name) return (0);
  strAccount = acc_name;

  ret_crc = 0;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook) {
    const string& strName = item.second;
    if (strName == strAccount) {
      const CCoinAddr& acc_address = CCoinAddr(ifaceIndex, item.first);
      string strAddr = acc_address.ToString();

      memset(buf, 0, sizeof(buf));
      strncpy(buf, strAddr.c_str(), sizeof(buf)-1);
      ret_crc += shcrc32(buf, strlen(buf));
    }
  }

  return (ret_crc);
}

uint32_t stratum_addr_crc(int ifaceIndex, char *worker)
{
  char *addr;
  char acc_name[256];

  memset(acc_name, 0, sizeof(acc_name));
  strncpy(acc_name, worker, sizeof(acc_name)-1);
  strtok(acc_name, ".");

  return (generate_addrlist_crc(ifaceIndex, acc_name));
}

uint32_t stratum_ext_addr_crc(int ifaceIndex, char *worker)
{
  char *addr;
  char acc_name[256];

  memset(acc_name, 0, sizeof(acc_name));
  strcpy(acc_name, "@");
  strncat(acc_name+1, worker, sizeof(acc_name)-2);
  strtok(acc_name, ".");

  return (generate_addrlist_crc(ifaceIndex, acc_name));
}

const char *stratum_walletkeylist(int ifaceIndex, char *acc_name)
{
  return (cpp_stratum_walletkeylist(ifaceIndex, (const char *)acc_name));
}

string stratumRetAddr;
const char *stratum_getaccountaddress(int ifaceIndex, char *account)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strAccount(account); 
  const CCoinAddr& addr = GetAccountAddress(wallet, strAccount, false);
  if (!addr.IsValid())
    return (NULL);

  stratumRetAddr = addr.ToString();
  return (stratumRetAddr.c_str());
}

void stratum_listaddrkey(int ifaceIndex, char *account, shjson_t *obj)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strListAccount(account);
  string strListExtAccount = "@" + strListAccount;

  vector<string> vAcc;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
    const string& strAccount = entry.second;
    CKey pkey;

    if (strAccount != strListAccount &&
        strAccount != strListExtAccount)
      continue;

    const CCoinAddr& address = CCoinAddr(ifaceIndex, entry.first);
    if (!address.IsValid())
      throw JSONRPCError(-5, "Invalid address");

    CKeyID keyID;
    if (!address.GetKeyID(keyID))
      throw JSONRPCError(-3, "Address does not refer to a key");

    CSecret vchSecret;
    bool fCompressed;
    if (!wallet->GetSecret(keyID, vchSecret, fCompressed))
      throw JSONRPCError(-4,"Private key for address is not known");

    string priv_str = CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString();
    shjson_str_add(obj, NULL, (char *)priv_str.c_str());
#if 0
    string pub_str = address.ToString(); 
    string priv_str = CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString();

    node = shjson_obj_add(obj, (char *)strAccount.c_str());
    shjson_str_add(node, (char *)pub_str.c_str(), (char *)priv_str.c_str());
#endif
  }

}

int stratum_getaddrkey(int ifaceIndex, char *account, char *pubkey, char *ret_pkey)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strListAccount(account);
  string strListExtAccount = "@" + strListAccount;

  if (ret_pkey)
    *ret_pkey = '\000';

  vector<string> vAcc;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
    const string& strAccount = entry.second;
    CKey pkey;

    if (strAccount != strListAccount &&
        strAccount != strListExtAccount)
      continue;

    const CCoinAddr& address = CCoinAddr(ifaceIndex, entry.first);
    if (!address.IsValid())
      throw JSONRPCError(-5, "Invalid address");

    string addrStr = address.ToString();
    if (pubkey) {
      if (0 != strcmp(pubkey, addrStr.c_str()))
        continue;
    }

    if (ret_pkey) {
      CKeyID keyID;
      if (!address.GetKeyID(keyID))
        return (SHERR_ACCESS);

      CSecret vchSecret;
      bool fCompressed;
      if (!wallet->GetSecret(keyID, vchSecret, fCompressed))
        return (SHERR_ACCESS);

      string priv_str = CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString();
      strcpy(ret_pkey, priv_str.c_str());
    }

    return (0);
  }

  return (SHERR_NOENT);
}


int stratum_setdefaultkey(int ifaceIndex, char *account, char *pub_key)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  string strAccount(account);

  if (!wallet)
    return (SHERR_INVAL);

  CCoinAddr address(pub_key);
  if (!address.IsValid())
    return (SHERR_INVAL);

  if (wallet->mapAddressBook.count(address.Get()))
  {
    string strOldAccount = wallet->mapAddressBook[address.Get()];
    if (address == GetAccountAddress(wallet, strOldAccount))
      GetAccountAddress(wallet, strOldAccount, true);
  }

  wallet->SetAddressBookName(address.Get(), strAccount);

  return (0);
}

  

#if 0
const char *stratum_call_rpc(int ifaceIndex, const char *account, const char *pkey_str, shjson_t *json)
{
  return (cpp_stratum_call_rpc(ifaceIndex, account, pkey_str, json));
}
#endif

#ifdef __cplusplus
}
#endif


