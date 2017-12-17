
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
#include "wallet.h"
#include "txcreator.h"
#include "asset.h"

using namespace std;
using namespace json_spirit;



asset_list *GetAssetTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapAsset);
}

asset_list *GetAssetPendingTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapAsset);
}

bool DecodeAssetHash(const CScript& script, int& mode, uint160& hash)
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
  op = CScript::DecodeOP_N(opcode); /* extension type (asset) */
  if (op != OP_ASSET) {
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



bool IsAssetOp(int op) {
	return (op == OP_ASSET);
}


string assetFromOp(int op) {
	switch (op) {
	case OP_EXT_NEW:
		return "assetnew";
	case OP_EXT_UPDATE:
		return "assetupdate";
	case OP_EXT_ACTIVATE:
		return "assetactivate";
	default:
		return "<unknown asset op>";
	}
}

bool DecodeAssetScript(const CScript& script, int& op,
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

	op = CScript::DecodeOP_N(opcode); /* extension type (asset) */
  if (op != OP_ASSET)
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

	if ((mode == OP_EXT_NEW && vvch.size() == 2) ||
      (mode == OP_EXT_ACTIVATE && vvch.size() == 2) ||
      (mode == OP_EXT_UPDATE && vvch.size() == 2) ||
      (mode == OP_EXT_TRANSFER && vvch.size() == 2) ||
      (mode == OP_EXT_REMOVE && vvch.size() == 2))
    return (true);

	return false;
}

bool DecodeAssetScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeAssetScript(script, op, vvch, pc);
}

CScript RemoveAssetScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeAssetScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveAssetScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetAssetOpFee(CIface *iface, int nHeight) 
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5140 / base * COIN;
  double nDif = 4982 /base * COIN;
  int64 nFee = (int64)(nRes - nDif);
  nFee = MAX(MIN_TX_FEE(iface), nFee);
  nFee = MIN(MAX_TX_FEE(iface), nFee);
  return (nFee);
}


int64 GetAssetReturnFee(const CTransaction& tx) 
{
	int64 nFee = 0;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
			nFee += out.nValue;
	}
	return nFee;
}

bool IsAssetTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_ASSET)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeAssetHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

/**
 * Obtain the tx that defines this asset.
 */
bool GetTxOfAsset(CIface *iface, const uint160& hashAsset, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  asset_list *assetes = GetAssetTable(ifaceIndex);
  bool ret;

  if (assetes->count(hashAsset) == 0) {
    return false; /* nothing by that name, sir */
  }

  uint256 hashBlock;
  uint256 hashTx = (*assetes)[hashAsset];
  CTransaction txIn;
  ret = GetTransaction(iface, hashTx, txIn, NULL);
  if (!ret) {
    return false;
  }

  if (!IsAssetTx(txIn)) 
    return false; /* inval; not an asset tx */

#if 0
  if (txIn.asset.IsExpired()) {
    return false;
  }
#endif

  tx.Init(txIn);
  return true;
}

bool IsLocalAsset(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalAsset(CIface *iface, const CTransaction& tx)
{
  if (!IsAssetTx(tx))
    return (false); /* not a asset */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalAsset(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an asset transaction.
 */
bool VerifyAsset(CTransaction& tx)
{
  uint160 hashAsset;
  int nOut;

  /* core verification */
  if (!IsAssetTx(tx)) {
    return (false); /* tx not flagged as asset */
}

  /* verify hash in pub-script matches asset hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* no extension output */

  int mode;
  if (!DecodeAssetHash(tx.vout[nOut].scriptPubKey, mode, hashAsset))
    return (false); /* no asset hash in output */

  if (mode != OP_EXT_NEW && 
      mode != OP_EXT_ACTIVATE &&
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_REMOVE)
    return (false);

  CAsset asset(tx.certificate);
  if (hashAsset != asset.GetHash())
    return error(SHERR_INVAL, "asset hash mismatch");

  return (true);
}



int init_asset_tx(CIface *iface, string strAccount, string strTitle, string strHash, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if(strTitle.length() == 0 || strTitle.length() > 135)
    return (SHERR_INVAL);
  if(strHash.length() == 0 || strHash.length() > 135)
    return (SHERR_INVAL);

  CCert *asset;
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  /* embed asset content into transaction */
#if 0
  wtx.SetNull();
  asset = wtx.CreateAsset(strTitle, strHash);
  wtx.strFromAccount = strAccount; /* originating account for payment */
#endif
  CTxCreator s_wtx(wallet, strAccount);
  asset = s_wtx.CreateAsset(strTitle, strHash);

  int64 nFee = GetAssetOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (SHERR_AGAIN);
  }

  uint160 assetHash = asset->GetHash();

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());

  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  if (!s_wtx.AddOutput(scriptPubKey, nFee))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (SHERR_CANCELED);

#if 0
  // send transaction
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }
#endif

  wtx = (CWalletTx)s_wtx; 
  wallet->mapAsset[assetHash] = wtx.GetHash(); /* todo:add to pending instead */
  Debug("(%s) SENT:ASSETNEW : title=%s, ref=%s, assethash=%s, tx=%s\n",
      iface->name, strTitle.c_str(), strHash.c_str(), 
      assetHash.ToString().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}


int update_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, string strTitle, string strHash, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  if(strTitle.length() == 0 || strTitle.length() > 135) {
    return (SHERR_INVAL);
  }

  if(strHash.length() == 0 || strHash.length() > 135) {
    return (SHERR_INVAL);
  }

  /* verify original asset */
  CTransaction tx;
  if (!GetTxOfAsset(iface, hashAsset, tx)) {
    return (SHERR_NOENT);
  }
  if(!IsLocalAsset(iface, tx)) {
    return (SHERR_REMOTE);
  }

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0) {
    return (SHERR_REMOTE);
  }

  /* establish account */
  CCoinAddr addr = GetAccountAddress(wallet, strAccount, false);

  if (!addr.IsValid()) {
    fprintf(stderr, "DEBUG: update_asset_tx: !addr.IsValid\n");
    return (SHERR_NOENT);
  }

  /* generate new coin address */
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);
  if (!extAddr.IsValid()) {
    fprintf(stderr, "DEBUG: update_asset_tx: !extAddr.IsValid\n");
    return (SHERR_INVAL);
  }

  /* generate tx */
  CCert *asset;
	CScript scriptPubKey;

  CTxCreator s_wtx(wallet, strAccount);
  asset = s_wtx.UpdateAsset(CAsset(tx.certificate), strTitle, strHash);
  uint160 assetHash = asset->GetHash();

  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  int64 nNetFee = GetAssetOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }

  /* activation fee */
  CScript scriptFee;
  scriptFee << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP << OP_RETURN;
  if (!s_wtx.AddOutput(scriptFee, nNetFee))
    return (SHERR_INVAL);

  /* link previous asset input */
  if (!s_wtx.AddExtTx(&wtxIn, scriptPubKey))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (SHERR_CANCELED);

#if 0
  /* supplemental tx payment */
  vector<pair<CScript, int64> > vecSend;
  vecSend.push_back(make_pair(scriptFee, nNetFee));

  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend)) {
fprintf(stderr, "DEBUG: update_asset_tx: !SendMoneyWithExtTx\n"); 
    return (SHERR_INVAL);
}
#endif

  wtx = (CWalletTx)s_wtx;
  wallet->mapAsset[assetHash] = wtx.GetHash();
  Debug("SENT:ASSETUPDATE : assethash=%s, tx=%s", asset->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

int activate_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, const uint160& hashCert, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  /* verify original asset */
  CTransaction tx;
  if (!GetTxOfAsset(iface, hashAsset, tx)) {
    fprintf(stderr, "DEBUG: update_asset_tx: !GetTxOfAsset\n");
    return (SHERR_NOENT);
  }
  if(!IsLocalAsset(iface, tx)) {
    fprintf(stderr, "DEBUG: update_asset_tx: !IsLocalAsset\n");
    return (SHERR_REMOTE);
  }

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0) {
    return (SHERR_REMOTE);
  }

  /* establish account */
  CCoinAddr addr = GetAccountAddress(wallet, strAccount, false);
  if (!addr.IsValid()) {
    fprintf(stderr, "DEBUG: update_asset_tx: !addr.IsValid\n");
    return (SHERR_NOENT);
  }

  /* generate new coin address */
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);
  if (!extAddr.IsValid()) {
    fprintf(stderr, "DEBUG: update_asset_tx: !extAddr.IsValid\n");
    return (SHERR_INVAL);
  }

  CTransaction cert_tx;
  if (!GetTxOfCert(iface, hashCert, cert_tx))
    return (SHERR_NOENT);

  /* generate tx */
  CCert *asset;
	CScript scriptPubKey;

  CTxCreator s_wtx(wallet, strAccount);
  asset = s_wtx.SignAsset(CAsset(tx.certificate), &cert_tx.certificate);
  uint160 assetHash = asset->GetHash();

  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_ACTIVATE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  int64 nNetFee = GetAssetOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }

  /* activation fee */
  CScript scriptFee;
  scriptFee << OP_EXT_ACTIVATE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP << OP_RETURN;
  if (!s_wtx.AddOutput(scriptFee, nNetFee))
    return (SHERR_INVAL);

  /* link asset input */
  if (!s_wtx.AddExtTx(&wtxIn, scriptPubKey))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (SHERR_CANCELED);

#if 0
  /* supplemental tx payment */
  vector<pair<CScript, int64> > vecSend;
  vecSend.push_back(make_pair(scriptFee, nNetFee));

  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend)) {
fprintf(stderr, "DEBUG: update_asset_tx: !SendMoneyWithExtTx\n"); 
    return (SHERR_INVAL);
}
#endif

  wtx = (CWalletTx)s_wtx;
  wallet->mapAsset[assetHash] = wtx.GetHash();
  Debug("(%s) SENT:ASSETACTIVATE : assethash=%s, tx=%s", iface->name, asset->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

/**
 * Removes a pre-existing asset on the block-chain. 
 * @param hashAsset The asset hash from it's last tx op.
 * @param strAccount The account that has ownership over the asset.
 * @param wtx The new transaction to be filled in.
 * @note The previous asset tx fee is returned to the account, and the current fee is burned.
 */
int remove_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  /* verify original asset */
  CTransaction tx;
  if (!GetTxOfAsset(iface, hashAsset, tx)) {
    fprintf(stderr, "DEBUG: update_asset_tx: !GetTxOfAsset\n");
    return (SHERR_NOENT);
  }
  if(!IsLocalAsset(iface, tx)) {
    fprintf(stderr, "DEBUG: update_asset_tx: !IsLocalAsset\n");
    return (SHERR_REMOTE);
  }

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0) {
    return (SHERR_REMOTE);
  }

  /* establish account */
  CCoinAddr addr = GetAccountAddress(wallet, strAccount, false);
  if (!addr.IsValid()) {
    fprintf(stderr, "DEBUG: update_asset_tx: !addr.IsValid\n");
    return (SHERR_NOENT);
  }

  /* generate tx */
  CCert *asset;
	CScript scriptPubKey;

  CTxCreator s_wtx(wallet, strAccount);
  asset = s_wtx.RemoveAsset(CAsset(tx.certificate));
  uint160 assetHash = asset->GetHash();

  vector<pair<CScript, int64> > vecSend;
  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(addr.Get()); /* back to origin */
	scriptPubKey << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  int64 nNetFee = GetAssetOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }

  /* removal fee */
  CScript scriptFee;
  scriptFee << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP << OP_RETURN;
  if (!s_wtx.AddOutput(scriptFee, nNetFee))
    return (SHERR_INVAL);

  /* link asset */
  if (!s_wtx.AddExtTx(&wtxIn, scriptPubKey))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (SHERR_CANCELED);
  

#if 0
  if (nNetFee) { /* supplemental tx payment */
    vecSend.push_back(make_pair(scriptFee, nNetFee));
  }

  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend)) {
fprintf(stderr, "DEBUG: update_asset_tx: !SendMoneyWithExtTx\n"); 
    return (SHERR_INVAL);
}
#endif


  wtx = (CWalletTx)s_wtx;
  wallet->mapAsset[assetHash] = wtx.GetHash();
  Debug("(%s) SENT:ASSETACTIVATE : assethash=%s, tx=%s", iface->name, asset->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

std::string CAsset::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CAsset::ToValue()
{
  Object obj = CCert::ToValue();
  obj.push_back(Pair("hash", GetHash().GetHex()));
  return (obj);
}

bool CAsset::Sign(CCert *cert)
{
  string hexContext = stringFromVch(cert->signature.vPubKey);
  cbuff vchContext = ParseHex(hexContext);
  return (signature.SignContext(vchContext));
}
bool CAsset::Sign(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTransaction cert_tx;

  if (!GetTxOfCert(iface, hashIssuer, cert_tx))
    return (false);

  return (Sign(&cert_tx.certificate));
}

bool CAsset::VerifySignature(CCert *cert)
{
  string hexContext = stringFromVch(cert->signature.vPubKey);
  cbuff vchContext = ParseHex(hexContext);
  return (signature.VerifyContext(vchContext.data(), vchContext.size()));
}

bool CAsset::VerifySignature(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTransaction cert_tx;

  if (!GetTxOfCert(iface, hashIssuer, cert_tx))
    return (false);

  return (VerifySignature(&cert_tx.certificate));
}



#if 0
bool CAsset::Sign(uint160 sigCertIn)
{
  hashIssuer = sigCertIn;
  signature.SignContext(hashIssuer);
  return true;
}

bool CAsset::VerifySignature()
{
  return (signature.VerifyContext(hashIssuer));
}
#endif


