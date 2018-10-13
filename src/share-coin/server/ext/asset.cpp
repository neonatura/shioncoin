
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


extern bool GetExtOutput(const CTransaction& tx, int ext_mode, int& nOut, CScript& scriptOut);


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

  tx.Init(txIn);
  return true;
}

#if 0
static int IndexOfAssetOutput(const CTransaction& tx)
{
	int idx;

	idx = 0;
	BOOST_FOREACH(const CTxOut& out, tx.vout) {
		const CScript& script = out.scriptPubKey;
		opcodetype opcode;
		CScript::const_iterator pc = script.begin();
		if (script.GetOp(pc, opcode) &&
				opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
			if (script.GetOp(pc, opcode) &&
					CScript::DecodeOP_N(opcode) == OP_ASSET)
				break;
		}

		idx++;
	}
	if (idx == tx.vout.size())
		return (-1); /* uh oh */

	return (idx);
}
#endif
static int IndexOfAssetOutput(const CTransaction& tx)
{
	CScript script;
	int nTxOut;

	if (!GetExtOutput(tx, OP_ASSET, nTxOut, script))
		return (-1);

	return (nTxOut);
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

  int nOut = IndexOfAssetOutput(tx);
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
  nOut = IndexOfAssetOutput(tx);
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

bool VerifyAssetAccount(CWallet *wallet, const CTxOut& outAsset, string strAccount)
{
	bool fIsScript;

	strAccount = "@" + strAccount;

	/* extract "extended account" tx-destination. */
	CTxDestination dest;
	if (!ExtractDestination(outAsset.scriptPubKey, dest))
		return (false);
	CCoinAddr addrAsset = CCoinAddr(wallet->ifaceIndex, dest);
	if (!addrAsset.IsValid())
		return (false);
	fIsScript = addrAsset.IsScript();

	/* search for matching output and account name. */
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
	{
		const CCoinAddr& address = CCoinAddr(wallet->ifaceIndex, item.first);
		const string& account = item.second;

		if (fIsScript && !address.IsScript())
			continue;

		if (strAccount != account)
			continue;

		if (address.Get() == addrAsset.Get())
			return (true);
	}

	return (false);
}


int init_asset_tx(CIface *iface, string strAccount, uint160 hashCert, string strTitle, string strHash, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if(strTitle.length() == 0 || strTitle.length() > 135)
    return (SHERR_INVAL);
  if(strHash.length() == 0 || strHash.length() > 135)
    return (SHERR_INVAL);

  int64 nFee = GetAssetOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (ERR_FEE);
  }

  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  CTxCreator s_wtx(wallet, strAccount);
  CAsset *asset = s_wtx.CreateAsset(strTitle, strHash);

	/* sign cert */
  asset->vAddr = cbuff(hashCert.begin(), hashCert.end());
  if (!asset->Sign(ifaceIndex))
		return (ERR_ACCESS);

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

  wtx = (CWalletTx)s_wtx; 
  Debug("(%s) SENT:ASSETNEW : title=%s, ref=%s, assethash=%s, tx=%s\n",
      iface->name, strTitle.c_str(), strHash.c_str(), 
      assetHash.ToString().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}

int update_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, string strTitle, string strHash, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
	int nOut;

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
	nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (false);
#if 0
  if(!IsLocalAsset(iface, tx)) {
    return (SHERR_REMOTE);
  }
#endif
	if (!VerifyAssetAccount(wallet, tx.vout[nOut], strAccount)) {
		return (SHERR_ACCESS); /* invalid account specified. */
	}

  /* establish original tx */
  uint256 hTxIn = tx.GetHash();

  /* generate new coin address */
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);
  if (!extAddr.IsValid()) {
    return (SHERR_INVAL);
  }

	/* establish fee for asset update. */
	int64 nTxFee = (MIN_TX_FEE(iface) * 2);
	int64 nCredit = wallet->GetCredit(tx.vout[nOut]);
  int64 nNetFee = MAX(nTxFee, nCredit - nTxFee);

	/* verify account has balance for tx fee. */
	if (nNetFee > nCredit) {
		int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
		if (bal < (nNetFee - nCredit)) {
			return (ERR_FEE);
		}
	}

  /* generate tx */
  CAsset *asset;

	/* create asset */
  CTxCreator s_wtx(wallet, strAccount);
  asset = s_wtx.UpdateAsset(CAsset(tx.certificate), strTitle, strHash);

	/* original asset hash */
	asset->hashIssuer = hashAsset;

  uint160 assetHash = asset->GetHash();

	if (nCredit > nNetFee) {
		s_wtx.SetMinFee(nCredit - nNetFee);
	}

	if (!s_wtx.AddInput(hTxIn, nOut))
		return (false);

  /* generate output script */
	CScript scriptPubKey;
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
  if (!s_wtx.AddOutput(scriptPubKey, nNetFee))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (error(SHERR_CANCELED, "update_asset_tx: %s", s_wtx.GetError().c_str()));

  wtx = (CWalletTx)s_wtx;
  Debug("SENT:ASSETUPDATE : assethash=%s, tx=%s", asset->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

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
    return (SHERR_NOENT);
  }
	int nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (false);
#if 0
  if(!IsLocalAsset(iface, tx)) {
    return (SHERR_REMOTE);
  }
#endif
	if (!VerifyAssetAccount(wallet, tx.vout[nOut], strAccount)) {
		return (SHERR_ACCESS); /* invalid account specified. */
	}

  /* establish original tx */
  uint256 hTxIn = tx.GetHash();

	/* establish fee for asset update. */
	int64 nCredit = wallet->GetCredit(tx.vout[nOut]);
  int64 nNetFee = MIN_TX_FEE(iface);
	int64 nTxFee = nCredit - nNetFee;
	int64 nDebit = nNetFee + nTxFee;

	/* establish fee for asset removal. */
	if (nDebit > nCredit) {
		int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
		if (bal < (nDebit - nCredit)) {
			return (ERR_FEE);
		}
	}

  /* generate tx */
  CCert *asset;
	CScript scriptPubKey;

  CTxCreator s_wtx(wallet, strAccount);
  asset = s_wtx.RemoveAsset(CAsset(tx.certificate));

	/* original asset hash */
	asset->hashIssuer = hashAsset;

  uint160 assetHash = asset->GetHash();

	s_wtx.SetMinFee(nTxFee);

  /* link previous asset as input */
	if (!s_wtx.AddInput(hTxIn, nOut))
		return (false);

  /* generate output script */
	scriptPubKey << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP << OP_RETURN;
  if (!s_wtx.AddOutput(scriptPubKey, nNetFee))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (SHERR_CANCELED);
  
  wtx = (CWalletTx)s_wtx;
  Debug("(%s) SENT:ASSETREMOVE : assethash=%s, tx=%s", iface->name, asset->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

std::string CAsset::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CAsset::ToValue()
{
  Object obj;
	uint160 hCert(vAddr);

	obj.push_back(Pair("certhash", hCert.GetHex())); 
	obj.push_back(Pair("data", stringFromVch(vContext)));
  obj.push_back(Pair("hash", GetHash().GetHex()));
	obj.push_back(Pair("title", GetLabel()));

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

	uint160 hCert(vAddr);
  if (!GetTxOfCert(iface, hCert, cert_tx))
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

	uint160 hCert(vAddr);
  if (!GetTxOfCert(iface, hCert, cert_tx))
    return (false);

  return (VerifySignature(&cert_tx.certificate));
}



bool VerifyAssetChainOrigin(CIface *iface, const CTransaction& tx, uint160 hIssuer, uint256& hPrevAssetTx)
{
	CAsset *asset;
	int i;

	CTransaction asset_tx;
	if (!GetTxOfAsset(iface, hIssuer, asset_tx))
		return (false);

	/* cycle through inputs and find previous asset. */
	const uint256& hTx = asset_tx.GetHash();
	for (i = 0; i < tx.vin.size(); i++) {
		const CTxIn& in = tx.vin[i];
		if (in.prevout.hash == hTx) {
			hPrevAssetTx = hTx;
			return (true);
		}
	}

	return (false);
}

bool ProcessNewAssetTx(CIface *iface, CTransaction& tx)
{
	CWallet *wallet = GetWallet(iface);
	CAsset *asset = tx.GetAsset();
	const uint160& hAsset = asset->GetHash();

	if (wallet->mapAsset.count(hAsset) != 0)
		return (false); /* dup */

	/* verify certificate signature */
	if (!asset->VerifySignature(GetCoinIndex(iface))) {
		return (false);
	}

	wallet->mapAsset[hAsset] = tx.GetHash();
	return (true);
}

bool ProcessUpdateAssetTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CTransaction cert_tx;
	uint256 hPrevAssetTx;
	CCert cert;

	CAsset *asset = tx.GetAsset();
	if (!asset)
		return (false);

	const uint160& hIssuer = asset->GetIssuerHash();
	if (!VerifyAssetChainOrigin(iface, tx, hIssuer, hPrevAssetTx)) {
		return (false);
	}

	wallet->mapAsset[hIssuer] = tx.GetHash();
	return (true);
}

bool ProcessRemoveAssetTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
	uint256 hPrevAssetTx;
	CCert cert;

	CAsset *asset = tx.GetAsset();
	if (!asset)
		return (false);

	const uint160& hIssuer = asset->GetIssuerHash();
	if (!VerifyAssetChainOrigin(iface, tx, hIssuer, hPrevAssetTx)) {
		return (false);
	}

	wallet->mapAsset.erase(hIssuer);
	return (true);
}

bool ProcessAssetTx(CIface *iface, CTransaction& tx, int nHeight)
{
  CWallet *wallet = GetWallet(iface);

	if (!VerifyAsset(tx)) {
		return (false);
	}

	int nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (false);

	int mode;
	uint160 hashAsset;
	if (!DecodeAssetHash(tx.vout[nOut].scriptPubKey, mode, hashAsset))
		return (false); /* no alias hash in output */

	switch (mode) {
		case OP_EXT_NEW:
			if (!ProcessNewAssetTx(iface, tx))
				return (false);
			break;
		case OP_EXT_UPDATE:
			if (!ProcessUpdateAssetTx(iface, tx))
				return (false);
			break;
		case OP_EXT_REMOVE:
			if (!ProcessRemoveAssetTx(iface, tx))
				return (false);
			break;
	}

	return (true);
}

/* obtain all previous assets in sequence associated with "tx". */
bool GetAssetChain(CIface *iface, const CTransaction& txIn, vector<CTransaction>& vTx)
{
	CAsset *asset = (CAsset *)&txIn.certificate;
	CTransaction tx;
	uint160 l_hashIssuer = 0;
	uint160 hashAsset;
	int nOut;
	int mode;
	int i;

	vTx.clear();

	nOut = IndexOfAssetOutput(txIn);
	if (nOut == -1)
		return (false);
	if (!DecodeAssetHash(txIn.vout[nOut].scriptPubKey, mode, hashAsset))
		return (false);

	if (mode == OP_EXT_NEW)
		return (true); /* all done */

	tx = txIn;
	mode = OP_EXT_UPDATE;
	l_hashIssuer = tx.GetAsset()->hashIssuer;
	while (mode == OP_EXT_UPDATE) {
		for (i = 0; i < tx.vin.size(); i++) {
			const CTxIn& in = tx.vin[i];
			const uint256& hashPrevTx = in.prevout.hash;
			int nPrevOut = in.prevout.n;
			CTransaction p_tx;

			if (!GetTransaction(iface, in.prevout.hash, p_tx, NULL)) {
fprintf(stderr, "GetAssetChain: invalid input tx \"%s\"\n", p_tx.GetHash().GetHex().c_str());
				continue; /* soft error */
			}

			const CTxOut& out = p_tx.vout[nPrevOut];
			if (!DecodeAssetHash(out.scriptPubKey, mode, hashAsset)) {
fprintf(stderr, "GetAssetChain: !DecodeAssetHash\n");
				continue; /* onto next tx */
			}

			CAsset *p_asset = p_tx.GetAsset();
			if (!p_asset) {
				continue;
			}
			if (mode == OP_EXT_NEW) {
				if (hashAsset != l_hashIssuer) {
fprintf(stderr, "GetAssetChain: !DecodeAssetHash: hashAsset != l_hashIssuer\n");
					continue; /* wrong chain */
				}
			} else {
				if (p_asset->hashIssuer != l_hashIssuer) {
fprintf(stderr, "GetAssetChain: !DecodeAssetHash: p_asset->hashIssuer != l_hashIssuer\n");
					continue; /* wrong chain */
				}
			}

			tx = p_tx;
			vTx.insert(vTx.begin(), tx);
			l_hashIssuer = p_asset->hashIssuer;
			break;
		}
		if (i == tx.vin.size())
			return (error(ERR_INVAL, "GetAssetChain: invalid chain"));
	}

	return (true);
}

bool DisconnectAssetTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
	CAsset *asset;
	
	asset = tx.GetAsset();
	if (!asset)
		return (error(ERR_INVAL, "DisconnectAssetTx: !Asset"));

	int nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (error(ERR_INVAL, "DisconnectAssetTx: !ExtOutput"));

	int mode;
	uint160 hAsset;
	if (!DecodeAssetHash(tx.vout[nOut].scriptPubKey, mode, hAsset))
		return (error(SHERR_INVAL, "DisconnectAssetTx: no alias hash in output"));

	if (mode == OP_EXT_NEW) {
		/* scrub clean */
		wallet->mapAsset.erase(hAsset);
//		wallet->mapAssetArch.erase(hAsset);
		return (true);
	}

	/* load entire asset hierarchy. */
	vector<CTransaction> vTx;
	if (!GetAssetChain(iface, tx, vTx))
		return (error(ERR_INVAL, "DisconnectAssetTx: !GetAssetChain"));

	/* set previous asset as primary */
	hAsset = vTx[0].GetAsset()->GetHash();
	uint256 hTx = vTx.back().GetHash();
	wallet->mapAsset[hAsset] = hTx;
	return (true);
}


