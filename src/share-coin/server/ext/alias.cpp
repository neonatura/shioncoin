
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>

using namespace std;
using namespace json_spirit;

#include "block.h"
#include "wallet.h"
#include "txcreator.h"
#include "certificate.h"
#include "alias.h"


alias_list *GetAliasTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapAlias);
}

#if 0
alias_list *GetAliasPendingTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapAlias);
}
#endif

bool DecodeAliasHash(const CScript& script, int& mode, uint160& hash)
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
  op = CScript::DecodeOP_N(opcode); /* extension type (alias) */
  if (op != OP_ALIAS) {
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





bool IsAliasOp(int op) {
	return (op == OP_ALIAS);
}


string aliasFromOp(int op) {
	switch (op) {
	case OP_EXT_ACTIVATE:
		return "aliasactivate";
	case OP_EXT_UPDATE:
		return "aliasupdate";
	case OP_EXT_TRANSFER:
		return "aliastransfer";
	case OP_EXT_REMOVE:
		return "aliasremove";
	default:
		return "<unknown alias op>";
	}
}

bool DecodeAliasScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) 
{
	opcodetype opcode;
  int mode;

	if (!script.GetOp(pc, opcode))
		return false;
  mode = opcode; /* extension mode (new/activate/update) */

	if (!script.GetOp(pc, opcode))
		return false;
	if (opcode < OP_1 || opcode > OP_16)
		return false;

	op = CScript::DecodeOP_N(opcode); /* extension type (alias) */
  if (op != OP_ALIAS)
    return false;

	for (;;) {
		vector<unsigned char> vch;
		if (!script.GetOp(pc, opcode, vch))
			return false;
		if (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP)
			break;
		if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
			return false;
		vvch.push_back(vch);
	}

	// move the pc to after any DROP or NOP
	while (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP) {
		if (!script.GetOp(pc, opcode))
			break;
	}

	pc--;

	if ((mode == OP_EXT_ACTIVATE && vvch.size() == 2) ||
      (mode == OP_EXT_UPDATE && vvch.size() == 2) ||
      (mode == OP_EXT_TRANSFER && vvch.size() == 2) ||
      (mode == OP_EXT_REMOVE && vvch.size() == 2))
    return (true);

	return false;
}

bool DecodeAliasScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeAliasScript(script, op, vvch, pc);
}

CScript RemoveAliasScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeAliasScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveAliasScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetAliasOpFee(CIface *iface, int nHeight) 
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5000 / base * COIN;
  double nDif = 4750 /base * COIN;
  int64 nFee = (int64)(nRes - nDif);
  nFee = MAX(MIN_TX_FEE(iface), nFee);
  nFee = MIN(MAX_TX_FEE(iface), nFee);
  return (nFee);
}


int64 GetAliasReturnFee(const CTransaction& tx) 
{
	int64 nFee = 0;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
			nFee += out.nValue;
	}
	return nFee;
}

bool IsAliasTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_ALIAS)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeAliasHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}


bool IsLocalAlias(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalAlias(CIface *iface, const CTransaction& tx)
{
  if (!IsAliasTx(tx))
    return (false); /* not a alias */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalAlias(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an alias transaction.
 */
bool VerifyAlias(CTransaction& tx)
{
  uint160 hashAlias;
  time_t now;
  int nOut;

  /* core verification */
  if (!IsAliasTx(tx))
    return (error(SHERR_INVAL, "VerifyAlias: not an alias tx"));

  /* verify hash in pub-script matches alias hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1) {
    return (false); /* no extension output */
  }

  int mode;
  if (!DecodeAliasHash(tx.vout[nOut].scriptPubKey, mode, hashAlias)) {
    return (false); /* no alias hash in output */
  }

  if (mode != OP_EXT_ACTIVATE && 
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_REMOVE) {
    return (false);
  }

  CAlias *alias = tx.GetAlias();

  if (hashAlias != alias->GetHash()) {
    return error(SHERR_INVAL, "VerifyAlias: transaction references invalid alias hash.");
    return (false); /* alias hash mismatch */
  }

  now = time(NULL);
  if (alias->GetExpireTime() > (now + DEFAULT_ALIAS_LIFESPAN))
    return error(SHERR_INVAL, "VerifyAlias: expiration exceeds %d years.", (DEFAULT_ALIAS_LIFESPAN/31536000));

  if (alias->GetLabel().size() > 135)
    return error(SHERR_INVAL, "VerifyAlias: label exceeds 135 characters.");

  return (true);
}

bool IsValidAliasName(CIface *iface, string label)
{
#if 0
  CWallet *wallet = GetWallet(iface);
  uint256 hTx;

  if (wallet->mapAlias.count(label) == 0)
    return (false);

  hTx = wallet->mapAlias[label];
  if (hTx.IsNull())
    return (false);

  return (true);
#endif
  CTransaction tx;
  if (GetAliasByName(iface, label, tx))
    return (true);

  return (false); 
}

bool GetTxOfAlias(CIface *iface, const std::string strTitle, CTransaction& tx) 
{
  CWallet *wallet = GetWallet(iface);
  uint256 hTx;

  if (wallet->mapAlias.count(strTitle) == 0)
    return (false);

  hTx = wallet->mapAlias[strTitle];
  if (hTx.IsNull())
    return (false);

  if (!GetTransaction(iface, hTx, tx, NULL))
    return (false);

  return (true);
}

/**
 * @note Performs an additional expiration check.
 */
CAlias *GetAliasByName(CIface *iface, string label, CTransaction& tx)
{
  CAlias *alias;

  if (!GetTxOfAlias(iface, label, tx))
    return (NULL);

  alias = &tx.alias;
  if (alias->IsExpired())
    return (NULL);

  return (alias);
}

bool CAlias::GetCoinAddr(CCoinAddr& addrRet)
{

  if (vAddr.size() == 0)
    return (false);
  addrRet = CCoinAddr(stringFromVch(vAddr));
  if (!addrRet.IsValid())
    return (false);

#if 0
  uint160 hash(vAddr);
  CKeyID keyid(hash);
  addrRet.Set(keyid);
  if (!addrRet.IsValid())
    return (false);
#endif

  return (true);
}

void CAlias::SetCoinAddr(CCoinAddr& addr)
{

  vAddr = vchFromString(addr.ToString());

#if 0
  CKeyID key_id;
  if (!addr.GetKeyID(key_id))
    return;

  char hstr[256];
  memset(hstr, 0, sizeof(hstr));
  strncpy(hstr, key_id.GetHex().c_str(), sizeof(hstr)-1);
  vAddr = cbuff(hstr, hstr + strlen(hstr));
#endif

}


bool ConnectAliasTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  CAlias *alias = (CAlias *)&tx.alias;
  string strTitle = alias->GetLabel();

  if (wallet->mapAlias.count(strTitle) != 0) {
    const uint256& hash = wallet->mapAlias[strTitle];
    wallet->mapAliasArch[hash] = strTitle;
  }
  wallet->mapAlias[strTitle] = tx.GetHash();

  return (true);
}

bool DisconnectAliasTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  CAlias *alias = (CAlias *)&tx.alias;
  string strTitle = alias->GetLabel();

  if (wallet->mapAlias.count(strTitle) == 0)
    return (false);

  const uint256& o_tx = wallet->mapAlias[strTitle];
  if (o_tx != tx.GetHash())
    return (false);

  /* NOTE: order matters here. last = best */
  uint256 n_tx;
  bool found = false;
  for(map<uint256,string>::iterator it = wallet->mapAliasArch.begin(); it != wallet->mapAliasArch.end(); ++it) {
    const uint256& hash2 = (*it).first;
    const string& hash1 = (*it).second;
    if (hash1 == strTitle) {
      n_tx = hash2;
      found = true;
    }
  }

  if (found) {
    /* transition current entry to archive */
    wallet->mapAliasArch[o_tx] = strTitle;

    wallet->mapAlias[strTitle] = n_tx;
  } else {
    wallet->mapAlias.erase(strTitle);
  }

}

bool RemoveAliasTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  CAlias *alias = (CAlias *)&tx.alias;
  string strTitle = alias->GetLabel();

  if (wallet->mapAlias.count(strTitle) == 0)
    return (false);

  /* transition current into archive */
  const uint256& cur_tx = wallet->mapAlias[strTitle];
  wallet->mapAliasArch[cur_tx] = strTitle;

  /* erase current */
  uint256 blank_hash;
  wallet->mapAlias[strTitle] = blank_hash;

  return (true);
}

/**
 * Verify that the preceding input is the currently established alias tx.
 */
bool VerifyAliasChain(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  CAlias *alias = &tx.alias;
  string strLabel = alias->GetLabel();
  CTransaction in_tx;

  if (wallet->mapAlias.count(strLabel) == 0)
    return (false);

  const uint256& prev_hash = wallet->mapAlias[strLabel];
  BOOST_FOREACH(const CTxIn& in, tx.vin) {
    const uint256& in_hash = in.prevout.hash;

    if (in_hash == prev_hash)
      return (true);

#if 0
    if (!GetTransaction(iface, in_hash, in_tx))
      return (false);

    if (!IsAliasTx(in_tx))
      return (false);

    int nOut = IndexOfExtOutput(in_tx);
    if (nOut == -1)
      return (false);

    CAlias *in_alias = &in_tx.alias;
    if (in_alias->GetLabel() != alias->GetLabel())
      return (false);
#endif

  }

  return (false);
}

bool CommitAliasTx(CIface *iface, CTransaction& tx, int nHeight)
{

  if (!VerifyAlias(tx))
    return (false);

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false);

  int mode;
  uint160 hashAlias;
  if (!DecodeAliasHash(tx.vout[nOut].scriptPubKey, mode, hashAlias)) {
    return (false); /* no alias hash in output */
  }

  switch (mode) {
    case OP_EXT_ACTIVATE:
      /* Verify that the correct fee was paid for an alias creation operation.  */
      if (tx.vout[nOut].nValue < GetAliasOpFee(iface, nHeight)) 
        return (error(SHERR_INVAL, "CommitAliasTx: insufficient coin fee spent for transaction operation."));
      if (!ConnectAliasTx(iface, tx))
        return (false);
      break;
    case OP_EXT_UPDATE:
      if (!VerifyAliasChain(iface, tx))
        return error(SHERR_INVAL, "CommitAliasTx: error verifying alias chain on tx '%s' for update.", tx.GetHash().GetHex().c_str());
(false);
      if (!ConnectAliasTx(iface, tx))
        return error(SHERR_INVAL, "CommitAliasTx: error updating alias on tx '%s'.", tx.GetHash().GetHex().c_str());
      break;
    case OP_EXT_REMOVE:
      if (!VerifyAliasChain(iface, tx))
        return (false);
      if (!RemoveAliasTx(iface, tx))
        return (false);
      break;
  }

  return (true);
}

void CAlias::FillReference(SHAlias *ref)
{
  memset(ref, 0, sizeof(SHAlias));
  std::string strLabel = GetLabel();
  strncpy(ref->ref_name,
      (const char *)strLabel.c_str(), 
      MIN(strLabel.size(), sizeof(ref->ref_name)-1));
  if (vAddr.data()) {
    strncpy(ref->ref_hash,
        (const char *)vAddr.data(),
        MIN(vAddr.size(), sizeof(ref->ref_hash)-1));
  }
  ref->ref_expire = tExpire;
  ref->ref_type = nType;
}

void CAlias::NotifySharenet(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled) return;

  SHAlias ref;
  FillReference(&ref);
  shnet_inform(iface, TX_REFERENCE, &ref, sizeof(ref));
}

int init_alias_addr_tx(CIface *iface, const char *title, CCoinAddr& addr, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strTitle(title);

  if(strlen(title) == 0)
    return (SHERR_INVAL);
  if(strlen(title) > 135)
    return (SHERR_INVAL);

  if (IsValidAliasName(iface, strTitle))
    return (SHERR_NOTUNIQ);

  bool found = false;
  string strAccount;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
    const string& account = item.second;
    if (address == addr) {
      addr = address;
      strAccount = account;
      found = true;
      break;
    }
  }
  if (!found) {
    return (SHERR_NOENT);
  }

  int64 nFee = GetAliasOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (SHERR_AGAIN);
  }

#if 0
  /* embed alias content into transaction */
  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */
#endif
  CTxCreator s_wtx(wallet, strAccount);

  uint160 deprec_hash;
  CAlias *alias = s_wtx.CreateAlias(strTitle, deprec_hash);
  if (!alias)
    return (SHERR_INVAL);

  alias->SetCoinAddr(addr);

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  uint160 aliasHash = alias->GetHash();
  CScript scriptPubKey;

  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);
  if (!extAddr.IsValid())
    return (error(SHERR_INVAL, "init_alias_addr_tx: error obtaining address for '%s'\n", strExtAccount.c_str()));

  scriptPubKeyOrig.SetDestination(extAddr.Get());
  scriptPubKey << OP_EXT_ACTIVATE << CScript::EncodeOP_N(OP_ALIAS) << OP_HASH160 << aliasHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

#if 0
  // send transaction
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }
#endif
  if (!s_wtx.AddOutput(scriptPubKey, nFee))
    return (false);

  if (!s_wtx.Send())
    return (false);

  wtx = s_wtx;
  Debug("(%s) SENT:ALIASNEW : title=%s, aliashash=%s, tx=%s\n", 
      iface->name, title, alias->GetHash().ToString().c_str(), 
      s_wtx.GetHash().GetHex().c_str());

  return (0);
}

int update_alias_addr_tx(CIface *iface, const char *title, CCoinAddr& addr, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
  string strTitle(title);

  if (strlen(title) > MAX_SHARE_NAME_LENGTH)
    return (SHERR_INVAL);

  if (!IsValidAliasName(iface, strTitle))
    return (SHERR_NOENT);

  /* verify original alias */
  CTransaction tx;
  if (!GetTxOfAlias(iface, strTitle, tx))
    return (SHERR_NOENT);
  if(!IsLocalAlias(iface, tx))
    return (SHERR_REMOTE);

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0)
    return (SHERR_REMOTE);

  /* establish account */
  string strAccount;
  if (!GetCoinAddr(wallet, addr, strAccount)) 
    return (SHERR_NOENT);

  int64 nNetFee = (int64)MIN_TX_FEE(iface);
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }

  string strAccountIn;
  CCoinAddr addrIn(ifaceIndex);
  if (!tx.alias.GetCoinAddr(addrIn))
    return (SHERR_INVAL);
  if (!GetCoinAddr(wallet, addrIn, strAccountIn))
    return (SHERR_REMOTE);
#if 0
  if (strAccountIn != strAccount)
    return (SHERR_ACCESS);
#endif

  /* generate new coin address */
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  /* generate tx */
  CAlias *alias;
	CScript scriptPubKey;

  CTxCreator s_wtx(wallet, strAccount);

  uint160 deprec_hash;
  alias = s_wtx.UpdateAlias(strTitle, deprec_hash);
  alias->SetType(tx.alias.GetType());
  alias->SetCoinAddr(addr);

  uint160 aliasHash = alias->GetHash();
  vector<pair<CScript, int64> > vecSend;
  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_ALIAS) << OP_HASH160 << aliasHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  if (!s_wtx.AddExtTx(&wtxIn, scriptPubKey))
    return (SHERR_CANCELED);

  if (!s_wtx.Send())
    return (SHERR_CANCELED);
#if 0
  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend))
    return (SHERR_INVAL);
#endif

  wtx = (CWalletTx)s_wtx;

  Debug("SENT:ALIASUPDATE : title=%s, aliashash=%s, tx=%s\n", title, alias->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

int remove_alias_addr_tx(CIface *iface, string strAccount, string strTitle, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  if (strTitle.length() == 0 ||
      strTitle.length() > MAX_SHARE_NAME_LENGTH)
    return (SHERR_INVAL);

  if (!IsValidAliasName(iface, strTitle))
    return (SHERR_NOENT);

  /* verify original alias */
  CTransaction in_tx;
  CAlias *in_alias = GetAliasByName(iface, strTitle, in_tx);
  if (!in_alias)
    return (SHERR_NOENT);

  if(!IsLocalAlias(iface, in_tx))
    return (SHERR_REMOTE);

  /* establish original tx */
  uint256 wtxInHash = in_tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0)
    return (SHERR_REMOTE);

  /* generate tx */
  CAlias *alias;
	CScript scriptPubKey;

  CTxCreator s_wtx(wallet, strAccount);
  alias = s_wtx.RemoveAlias(strTitle);
  uint160 aliasHash = alias->GetHash();

  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	scriptPubKey << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_ALIAS) << OP_HASH160 << aliasHash << OP_2DROP << OP_RETURN;

  int64 nNetFee = (int64)MIN_TX_FEE(iface);
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }

  if (!s_wtx.AddExtTx(&wtxIn, scriptPubKey))
    return (SHERR_CANCELED);

  if (!s_wtx.Send())
    return (SHERR_CANCELED);

#if 0
  vector<pair<CScript, int64> > vecSend;
  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend))
    return (SHERR_INVAL);
#endif

  wtx = (CWalletTx)s_wtx;

  Debug("(%s) SENT:ALIASREMOVE : title \"%s\", aliashash \"%s\", tx \"%s\"", 
      iface->name, strTitle.c_str(), 
      alias->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}


std::string CAlias::ToString(int ifaceIndex)
{
  return (write_string(Value(ToValue(ifaceIndex)), false));
}

Object CAlias::ToValue(int ifaceIndex)
{
  Object obj = CIdent::ToValue();

/* DEBUG: TODO: custimize CIDent::TOValue */
  if (GetType() == ALIAS_COINADDR) {
    obj.push_back(Pair("type-name", "pubkey"));

#if 0
    CCoinAddr addr(ifaceIndex);
    if (GetCoinAddr(addr))
      obj.push_back(Pair("address", addr.ToString().c_str()));
    else
      obj.push_back(Pair("valid", "false"));
#endif
  }

  return (obj);
}


