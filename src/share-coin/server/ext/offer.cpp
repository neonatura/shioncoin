
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
#include <boost/xpressive/xpressive_dynamic.hpp>
#include "wallet.h"
#include "offer.h"
#include "txcreator.h"
#include "txmempool.h"


extern json_spirit::Value ValueFromAmount(int64 amount);


offer_list *GetOfferTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapOffer);
}

bool InsertOfferTable(int ifaceIndex, uint256 hTx, uint160 hOffer)
{
	offer_list *offer_list = GetOfferTable(ifaceIndex);

	if (!offer_list)
		return (false);

	if (offer_list->count(hOffer) != 0)
		return (false); /* dup */

	(*offer_list)[hOffer] = hTx;
	return (true);
}

void RemoveOfferTable(int ifaceIndex, uint160 hOffer)
{
	offer_list *offer_list = GetOfferTable(ifaceIndex);

	if (!offer_list)
		return;

	offer_list->erase(hOffer);
}

offer_list *GetOfferPendingTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapOfferAccept);
}

bool InsertPendingTable(int ifaceIndex, uint256 hTx, uint160 hAccept)
{
	offer_list *offer_list = GetOfferPendingTable(ifaceIndex);

	if (!offer_list)
		return (false);

	if (offer_list->count(hAccept) != 0)
		return (false); /* dup */

	(*offer_list)[hAccept] = hTx;
	return (true);
}

void RemovePendingTable(int ifaceIndex, uint160 hAccept)
{
	offer_list *offer_list = GetOfferPendingTable(ifaceIndex);

	if (!offer_list)
		return;

	offer_list->erase(hAccept);
}

bool DecodeOfferHash(const CScript& script, int& mode, uint160& hash)
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
  op = CScript::DecodeOP_N(opcode); /* extension type (offer) */
  if (op != OP_OFFER)
    return false;

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


bool IsOfferOp(int op) {
	return (op == OP_OFFER);
}


string offerFromOp(int op) {
	switch (op) {
	case OP_EXT_NEW:
		return "offernew";
	case OP_EXT_ACTIVATE:
		return "offeractivate";
	case OP_EXT_GENERATE:
		return "offergenerate";
	case OP_EXT_PAY:
		return "offerpay";
	case OP_EXT_REMOVE:
		return "offerremove";
	default:
		return "<unknown offer op>";
	}
}

bool DecodeOfferScript(const CScript& script, int& op,
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

	op = CScript::DecodeOP_N(opcode); /* extension type (offer) */
  if (op != OP_OFFER)
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

	if ((mode == OP_EXT_NEW && vvch.size() >= 1) ||
      (mode == OP_EXT_ACTIVATE && vvch.size() >= 1) ||
      (mode == OP_EXT_TRANSFER && vvch.size() >= 1) ||
      (mode == OP_EXT_GENERATE && vvch.size() >= 1) ||
      (mode == OP_EXT_PAY && vvch.size() >= 1) ||
      (mode == OP_EXT_REMOVE && vvch.size() >= 1))
    return (true);

	return false;
}

bool DecodeOfferScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeOfferScript(script, op, vvch, pc);
}

CScript RemoveOfferScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeOfferScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveOfferScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetOfferOpFee(CIface *iface)
{
  return (iface->min_tx_fee * 2);
}

bool IsOfferTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_OFFER)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeOfferHash(out.scriptPubKey, mode, hash)) {
      tot++;
		}

  }
  if (tot != 1) {
		/* only single offer per transaction. */
    return false;
  }

  return (true);
}

/**
 * Obtain the tx that defines this offer.
 */
bool GetTxOfOffer(CIface *iface, const uint160& hashOffer, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  offer_list *offeres = GetOfferTable(ifaceIndex);
  bool ret;

  if (offeres->count(hashOffer) == 0) {
fprintf(stderr, "DEBUG: GetTxOfOffer: invalid offer \"%s\".\n", hashOffer.GetHex().c_str());
    return false; /* nothing by that name, sir */
  }

  uint256 hashTx = (*offeres)[hashOffer];
  ret = GetTransaction(iface, hashTx, tx, NULL);
  if (!ret) {
fprintf(stderr, "DEBUG: GetTxOfOffer: invalid tx\n");
    return false;
  }

  if (!IsOfferTx(tx)) { 
fprintf(stderr, "DEBUG: GetTxOfOffer: not offer\n");
    return false; /* inval; not an offer tx */
  }

  return true;
}

bool GetTxOfAcceptOffer(CIface *iface, const uint160& hashOffer, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  offer_list *accepts = GetOfferPendingTable(ifaceIndex);
  bool ret;

  if (accepts->count(hashOffer) == 0) {
    return false; /* nothing by that name, sir */
  }

  uint256 hashTx = (*accepts)[hashOffer];
  ret = GetTransaction(iface, hashTx, tx, NULL);
  if (!ret) {
    return false;
  }

  if (!IsOfferTx(tx)) 
    return false; /* inval; not an offer tx */

/* expired */
  return true;
}

bool IsLocalOffer(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalOffer(CIface *iface, const CTransaction& tx)
{
  if (!IsOfferTx(tx))
    return (false); /* not a offer */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalOffer(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an offer transaction.
 */
bool VerifyOffer(const CTransaction& tx, int& mode)
{
  uint160 hashOffer;
  int nOut;

  /* core verification */
  if (!IsOfferTx(tx)) {
fprintf(stderr, "DEBUG: VerifyOffer: !IsOfferTx()\n");
    return (false); /* tx not flagged as offer */
}

  /* verify hash in pub-script matches offer hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1) {
fprintf(stderr, "DEBUG: VerifyOffer: nOut == -1\n");
    return (false); /* no extension output */
}

  if (!DecodeOfferHash(tx.vout[nOut].scriptPubKey, mode, hashOffer)) {
		fprintf(stderr, "DEBUG: VerifyOffer: DecodeOfferHash: no offer hash in output.\n"); 
    return (false); /* no offer hash in output */
	}

  if (mode != OP_EXT_NEW &&
      mode != OP_EXT_ACTIVATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_GENERATE &&
      mode != OP_EXT_PAY &&
      mode != OP_EXT_REMOVE)
    return (false);

  COffer *offer = tx.GetOffer();
  if (hashOffer != offer->GetHash()) {
fprintf(stderr, "DEBUG: VerifyOffer: hashOffer != GetHash\n");
    return (false); /* offer hash mismatch */
	}

  return (true);
}

#if 0
bool AcceptOffer(CIface *iface, COffer *offer, COffer& accept)
{
  int64 payValue = 0;//abs(offer->nXferValue);
  int64 xferValue = 0;//abs(offer->nPayValue);

  BOOST_FOREACH(const COffer& t_accept, offer->accepts) {
    payValue += abs(t_accept.nPayValue); 
    xferValue += abs(t_accept.nXferValue); 
  }

//fprintf(stderr, "DEBUG: accept.nXferValue(%llu) xferValue(%llu) <= offer->nPayValue(%llu)\n", accept.nXferValue, xferValue, offer->nPayValue); fprintf(stderr, "DEBUG: accept.nPayValue(%llu) xferValue(%llu) <= offer->nPayValue(%llu)\n", accept.nPayValue, payValue, offer->nXferValue);

  /* verify limits */
  if (abs(accept.nXferValue) + xferValue > abs(offer->nPayValue))
    return (false);
  if (abs(accept.nPayValue) + payValue > abs(offer->nXferValue))
    return (false);

  /* verify ratio */
  double srate = abs(offer->nPayValue / accept.nXferValue);
  double drate = abs(offer->nXferValue / accept.nPayValue);
//fprintf(stderr, "DEBUG: srate(%f) drate(%f)\n", srate, drate);
  if (srate != drate) {
    /* invalid offer */
    return error(SHERR_INVAL, "AcceptOffer: offer has invalid exchange ratio.");
  }

  offer->accepts.push_back(accept);
  return (true);
}

/* DEBUG: TODO: verify their offer-accept alt->holding transaction */

bool GenerateOffers(CIface *iface, COffer *offer)
{
  int ifaceIndex = GetCoinIndex(iface);
  offer_list *offers = GetOfferPendingTable(ifaceIndex);
  uint160 hashOffer = offer->GetHash();
  bool ret;

  map<uint160, uint256>::iterator mi = offers->begin(); 
  while (mi != offers->end()) {
    const uint160& hashAccept = (*mi).first;
    const uint256& hashTx = (*mi).second;
    mi++;

//fprintf(stderr, "DEBUG: found accept offer '%s'\n", hashAccept.GetHex().c_str());

    CTransaction tx;
    ret = GetTransaction(iface, hashTx, tx, NULL);
    if (!ret)
      return false;

    COffer& accept = ((COffer&) tx.offer);
    if (accept.hashOffer != hashOffer) {
//fprintf(stderr, "DEBUG: wrong offer '%s' for accept '%s'\n", accept.hashOffer.GetHex().c_str(), hashAccept.GetHex().c_str());
      continue; /* wrong offer */
}

    AcceptOffer(iface, offer, accept);
  }

  if (offer->accepts.size() == 0)
    return (false);

  return (true);
}
#endif

bool COffer::GetPayAddr(int ifaceIndex, CCoinAddr& addr)
{
  CWallet *wallet = GetWallet(ifaceIndex);

	CPubKey keyid(vchPayAddr);
	addr = CCoinAddr(ifaceIndex, keyid.GetID()); /* CKeyId */
  if (!addr.IsValid())
    return (false);

  return (true);
}

bool COffer::GetPayAccount(int ifaceIndex, CCoinAddr& addr, std::string& account)
{
  CWallet *wallet = GetWallet(ifaceIndex);

	CPubKey keyid(vchPayAddr);
	addr = CCoinAddr(ifaceIndex, keyid.GetID()); /* CKeyId */
  if (!addr.IsValid())
    return (false);

  if (!GetCoinAddr(wallet, addr, account))
    return error(SHERR_INVAL, "COffeAccept:GetPayAccount: !GetCoinAddr()");

  return (true);
}

bool COffer::GetXferAddr(int ifaceIndex, CCoinAddr& addr)
{
  CWallet *wallet = GetWallet(ifaceIndex);

	CPubKey keyid(vchXferAddr);
	addr = CCoinAddr(ifaceIndex, keyid.GetID()); /* CKeyId */
  if (!addr.IsValid())
    return error(SHERR_INVAL, "COffer:GetXferAddr: iface #%d: addr '%s' invalid'.", ifaceIndex, addr.ToString().c_str());

  return (true);
}

bool COffer::GetXferAccount(int ifaceIndex, CCoinAddr& addr, std::string& account)
{
  CWallet *wallet = GetWallet(ifaceIndex);

	CPubKey keyid(vchXferAddr);
	addr = CCoinAddr(ifaceIndex, keyid.GetID()); /* CKeyId */
  if (!addr.IsValid()) {
    return error(SHERR_INVAL, "COffer:GetXferAddr: iface #%d: addr '%s' invalid'.", ifaceIndex, addr.ToString().c_str());
	}

  if (!GetCoinAddr(wallet, addr, account)) {
    return error(SHERR_INVAL, "COffeAccept:GetXferAddr; !GetCoinAddr()");
  }

  return (true);
}

static bool GetExtTxOut(int ifaceIndex, CWalletTx& wtxIn, int64& retValue, string& strAccount, unsigned int& nTxOut)
{
	CWallet *wallet = GetWallet(ifaceIndex);

	nTxOut = IndexOfExtOutput(wtxIn);
	if (nTxOut == -1)
		return (false);

	retValue = wtxIn.vout[nTxOut].nValue;

	CTxDestination extDest;
	if (!ExtractDestination(wtxIn.vout[nTxOut].scriptPubKey, extDest))
		return (false);

	CCoinAddr addrDest(ifaceIndex, extDest);
	if (!GetCoinAddr(wallet, addrDest, strAccount))
		return (false);

	return (true);
}

Object COffer::ToValue()
{
  Object obj;

	CIface *payIface = GetPayIface();
	if (payIface && payIface->enabled) {
		int payIndex = GetCoinIndex(payIface);
		CCoinAddr payAddr(payIndex);
		GetPayAddr(payIndex, payAddr);
		obj.push_back(Pair("payaddr", payAddr.ToString().c_str()));
	}

	CIface *xferIface = GetXferIface();
	if (xferIface && xferIface->enabled) {
		int xferIndex = GetCoinIndex(xferIface);
		CCoinAddr xferAddr(xferIndex);
		GetPayAddr(xferIndex, xferAddr);
		obj.push_back(Pair("xferaddr", xferAddr.ToString().c_str()));
	}

  if (hPayTx != 0)
    obj.push_back(Pair("xfertx", (char *)hPayTx.GetHex().c_str()));
  if (hSinkTx != 0) {
    obj.push_back(Pair("sinktx", (char *)hSinkTx.GetHex().c_str()));
    obj.push_back(Pair("sinkout", (int)hSinkOut));
	}
 
	if (nValue != 0)
		obj.push_back(Pair("value", ValueFromAmount(nValue)));
  obj.push_back(Pair("minvalue", ValueFromAmount(nMinValue)));
  obj.push_back(Pair("maxvalue", ValueFromAmount(nMaxValue)));

  if (hashOffer.size() != 0)
    obj.push_back(Pair("offerhash", (char *)hashOffer.GetHex().c_str()));

	obj.push_back(Pair("paycoin", stringFromVch(vchPayCoin)));
	obj.push_back(Pair("xfercoin", stringFromVch(vchXferCoin)));
 
  return (obj);
}

std::string COffer::ToString()
{
  return (write_string(Value(ToValue()), false));
}

void COffer::SetPayAddr(const CPubKey& payAddr)
{
	vchPayAddr = payAddr.Raw();
}

void COffer::SetXferAddr(const CPubKey& xferAddr)
{
	vchXferAddr = xferAddr.Raw();
}

std::string OfferHoldAltCoin(CIface *iface, string strAccount, COffer *offer, int64 nValue)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  char errbuf[1024];

fprintf(stderr, "DEBUG: OfferHoldaltCoin: nValue %f\n", (double)nValue/COIN);

  if (nValue < iface->min_tx_fee) {
    sprintf(errbuf, "insufficient funds (%s) specified for transaction [offer hold alt coin].", FormatMoney(nValue).c_str());
    return string(errbuf);
  }

  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nValue)
    return string("insufficient funds to perform transaction.");

	CCoinAddr xferAddr(ifaceIndex);
	if (ifaceIndex == COLOR_COIN_IFACE) {
		string strExtAccount = "@" + offer->hashColor.GetHex();
		xferAddr = GetAccountAddress(wallet, strExtAccount, true);
		if (!xferAddr.IsValid())
			return string("error generating holding account");
	} else {
		string strExtAccount = "@" + strAccount;
		xferAddr = GetAccountAddress(wallet, strExtAccount, true);
		if (!xferAddr.IsValid())
			return string("error generating holding account");
	}

  CScript scriptPubKey;
  scriptPubKey.SetDestination(xferAddr.Get());

	CTxCreator s_wtx(wallet, strAccount);
	/* we must supply an extra tx fee for "GetAltTx" commit. */
	if (!s_wtx.AddOutput(scriptPubKey, nValue + GetOfferOpFee(iface))) {
		string strError = s_wtx.GetError();	
    return (strError);
	}
fprintf(stderr, "DEBUG: OfferHoldAltCoin: s_wtx: %s\n", s_wtx.ToString(ifaceIndex).c_str());
	if (!s_wtx.Send()) {
		string strError = s_wtx.GetError();	
    return (strError);
	}

	/* success */
	offer->hSinkTx = s_wtx.GetHash();
	for (offer->hSinkOut = 0; offer->hSinkOut < s_wtx.vout.size(); offer->hSinkOut++) {
		if (s_wtx.vout[offer->hSinkOut].scriptPubKey == scriptPubKey)
			break;
	}
fprintf(stderr, "DEBUG: OfferHoldAltCoin: hSinkTx (out: %d) \"%s\".\n", offer->hSinkOut, s_wtx.GetHash().GetHex().c_str());
  return string("");
}

/* create the transaction for sending alt-coin to origin. */
bool GetAltTx(CTransaction& tx, COffer *offer)
{
	CIface *alt_iface = offer->GetXferIface();
	CWallet *wallet = GetWallet(alt_iface);
	string strAccount;
	int altIndex;

	if (!alt_iface || !alt_iface->enabled)
		return (error(ERR_INVAL, "GetAltTx: no coin interface available."));

	altIndex = GetCoinIndex(alt_iface);
	CCoinAddr xferAddr(altIndex);
	if (!offer->GetXferAccount(altIndex, xferAddr, strAccount))
		return (error(SHERR_INVAL, "GetAltTx: !GetXferAddr"));

	double dRate = (double)offer->nRate / COIN;
  int64 nAltValue = (int64)((double)offer->nValue * dRate);

#if 0
	/* temporary alt-coin holding tx */
  if (wallet->mapWallet.count(offer->hSinkTx) == 0)
		return (error(SHERR_INVAL, "GetAlTx: no wallet entry for hSinkTx \"%s\".", offer->hSinkTx.GetHex().c_str()));
	const CWalletTx& wtx = wallet->mapWallet[offer->hSinkTx];
#endif

	/* generate transaction sending alt-currency to receiver. */
	CTxCreator s_wtx(wallet, strAccount);
	
	/* add temp tx as input */
	if (!s_wtx.AddInput(offer->hSinkTx, offer->hSinkOut))
		return (error(ERR_ALREADY, "GetAltTx: input tx (out: %d) \"%s\" cannot be input.", offer->hSinkOut, offer->hSinkTx.GetHex().c_str()));

	/* send to alt-coin receiving address. */
//	int nAltValue = wallet->GetCredit(wtx);
	CTxCreator(wallet, strAccount);
	CPubKey pubkey(offer->vchXferAddr);
fprintf(stderr, "DEBUG: GetAlTx: s_wtx.AddOutput: nAltValue %f\n", (double)nAltValue/COIN); 
	if (!s_wtx.AddOutput(pubkey, nAltValue))// - MIN_TX_FEE(alt_iface)))
		return (false);

	if (!s_wtx.Generate())
		return (error(SHERR_CANCELED, "GetAltTx: %s", s_wtx.GetError().c_str()));
	// if (vin>1) .. not ok

	tx = (CTransaction)s_wtx;
	return (true);
}

static bool offer_IsCompatibleIface(CIface *iface)
{
	int ifaceIndex = GetCoinIndex(iface);

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != TESTNET_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
		return (false);

	return (true);
}

#if 0
int ProcessOfferTx(CIface *iface, CNode *pfrom, const CTransaction& tx, int64 nHeight)
{
  CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int tx_mode;

	 /* validate */
	if (!VerifyOffer(tx, tx_mode)) {
		error(SHERR_INVAL, "ProcessOfferTx: error verifying offer tx.");
		return (SHERR_INVAL);
	}

	COffer *off = tx.GetOffer();
	if (!off)
		return (SHERR_INVAL);

	uint160 hOffer = off->GetHash();
	switch (tx_mode) {
		case OP_EXT_NEW:
			/*
			if (!VerifyNewOffer(iface, off))
				return (SHERR_INVAL);
				*/
			wallet->mapOffer[hOffer] = tx.GetHash();
			break;
		case OP_EXT_ACTIVATE:
			/*
			if (wallet->mapOfferAccept.count(hOffer) != 0)
				return (ERR_STALE);
			if (!VerifyActivateOffer(iface, off))
				return (SHERR_INVAL);
			*/
			wallet->mapOfferAccept[hOffer] = tx.GetHash();
			break;
		case OP_EXT_GENERATE:
			/*
			if (!CommitGenerateOffer(iface, off))
				return (SHERR_INVAL);
				*/
			break;
		case OP_EXT_PAY:
			/*
			if (!CommitPayOffer(iface, off))
				return (SHERR_INVAL);
				*/

			/* erase after completion. */
			wallet->mapOffer.erase(off->hashOffer);
			wallet->mapOfferAccept.erase(off->hashOffer);
			break;
		case OP_EXT_REMOVE:
			/*
			if (!CommitRemoveOffer(iface, off))
				return (SHERR_INVAL);
				*/

			/* erase after cancel. */
			wallet->mapOffer.erase(off->hashOffer);
			wallet->mapOfferAccept.erase(off->hashOffer);
			break;
	}
}
#endif

/**
 * If a particular transaction exists, then send to primary destination.
 * If not, then after offer expires it may be returned to sender. 
 */
CScript offer_CheckAltProofScript(CIface *iface, COffer *offer, const CPubKey& retAddr)
{
	int ifaceIndex = GetCoinIndex(iface);
	CPubKey destAddr(offer->vchPayAddr);

fprintf(stderr, "DEBUG: offer_CheckAltProofScript: %s\n", offer->ToString().c_str());

	CScriptNum nWaitTime(offer->GetExpireTime());
	CScript script;

	script << OP_CHECKALTPROOF << offer->hXferTx;
	if (ifaceIndex == COLOR_COIN_IFACE) {
		script << offer->hashColor;
	} else {
		script << GetCoinHash(stringFromVch(offer->vchXferCoin));
	}

	/* first condition: if <tx> exists then allow send. */ 
	script << OP_IF << destAddr << OP_CHECKSIG <<
	/* second condition: if <tx> does not exist, then allow coins to be returned after offer expires. */ 
		//OP_ELSE << nWaitTime << OP_CHECKLOCKTIMEVERIFY << OP_DROP <<
		OP_ELSE << retAddr << OP_CHECKSIG << OP_ENDIF;

	return (script);
}

/**
 * When a GENERATE OFFER TX is processed the receiver will submit the prepared alternate-coin tx if they have a matching key. Since the TX hash is pre-computed it is safe for multiple nodes to attempt to commit the transaction. If no nodes commit the transaction then the offer is cancelled and coins are returned to the original sender.
 */
bool CommitGenerateOffer(CIface *iface, COffer *offer)
{
	CIface *alt_iface = offer->GetXferIface();
	CWallet *alt_wallet = GetWallet(alt_iface);
  int ifaceIndex = GetCoinIndex(iface);
	CTransaction alt_tx;

fprintf(stderr, "DEBUG: CommitGenerateOffer()\n");

	if (!alt_iface || !alt_wallet) {
		/* since we cannot process this we will consider our work done. */
fprintf(stderr, "DEBUG: CommitGenerateOffer(): uknown iface\n");
		return (true);
	}

	/* retrieve the alt-coin intermediate transaction. */
	CTransaction txSink;
	if (!GetTransaction(alt_iface, offer->hSinkTx, txSink, NULL)) {
		/* check for pending transaction. */
		CTxMemPool *pool = GetTxMemPool(iface);
		if (!pool)
			return (false);
		if (!pool->GetTx(offer->hSinkTx, txSink))
			return (error(ERR_NOENT, "(%s) CommitGenerateOffer: unknown alt-coin (%s) tx \"%s\".", iface->name, stringFromVch(offer->vchXferCoin).c_str(), offer->hSinkTx.GetHex().c_str()));
	}
	if (txSink.vout.size() < 1 ||
			!alt_wallet->IsMine(txSink)) {
fprintf(stderr, "DEBUG: CommitGenerateOffer: !IsLocalOffer()\n"); 
		return (true); /* not our problem */
	}

	/* retrieve prepared alt-coin tx [with sink as input] */
	if (!GetAltTx(alt_tx, offer))
		return (error(ERR_INVAL, "CommitGenerateOffer: !GetAltTx: hSinkTx %s\n", offer->hSinkTx.GetHex().c_str()));

	CWalletTx alt_wtx(alt_wallet, alt_tx); 

	/* verify intermediate tx has minimum value to perform offer. */
	double dRate = (double)offer->nRate / COIN;
  int64 nAltFee = (int64)((double)offer->nValue * dRate);
	int64 nDebit = alt_wtx.GetDebit();
	if (nDebit < nAltFee) {
		return (error(ERR_FEE, "(%s) CommitGenerateOffer: insufficient alt-coin (%f < %f).", iface->name, ((double)nDebit/COIN), ((double)nAltFee/COIN)));
	}

	/* commit alt-coin transaction. */
	if (alt_wtx.GetHash() != offer->hXferTx) {
		/* transaction contents mismatch. */
fprintf(stderr, "DEBUG: CommitGenerateOffer: alt tx mismatch.\n");
		return (SHERR_INVAL);
	}
	if (!alt_wallet->CommitTransaction(alt_wtx)) {
fprintf(stderr, "DEBUG: CommitGEnerateOffer: !CommitTrans\n");
		return (SHERR_CANCELED);
	}

fprintf(stderr, "DEBUG: CommitGenerateOffer(): %s\n", alt_wtx.ToString(GetCoinIndex(alt_iface)).c_str());

	return (true);
}

int CommitOfferTx(CIface *iface, CTransaction& tx, unsigned int nHeight)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  COffer& ctx = (COffer&)tx.certificate;
  uint160 hOffer = ctx.GetHash();
  int err;

  /* validate */
  int tx_mode;
  if (!VerifyOffer(tx, tx_mode)) {
    error(SHERR_INVAL, "CommitOfferTx: error verifying offer tx.");
    return (SHERR_INVAL);
  }

	COffer *offer = tx.GetOffer();
	if (!offer) {
    error(SHERR_INVAL, "CommitOfferTx: transaction is not an offer.");
		return (ERR_INVAL);
	}

fprintf(stderr, "DEBUG: COmmitOfferTx: tx_mode %d\n", tx_mode); 
	switch (tx_mode) {
		case OP_EXT_NEW:
			if (!InsertOfferTable(ifaceIndex, tx.GetHash(), offer->GetHash()))
				return (ERR_NOTUNIQ);
			break;
		case OP_EXT_ACTIVATE:
			if (wallet->mapOffer.count(offer->hashOffer) == 0)
				return (ERR_NOENT);
			if (!InsertPendingTable(ifaceIndex, tx.GetHash(), offer->hashOffer))
				return (ERR_NOTUNIQ);
			break;
		case OP_EXT_GENERATE:
			if (wallet->mapOffer.count(offer->hashOffer) == 0)
				return (ERR_NOENT);
			if (wallet->mapOfferAccept.count(offer->hashOffer) == 0)
				return (ERR_NOENT);

			if (!CommitGenerateOffer(iface, offer))
				return (SHERR_INVAL);

			/* erase after completion. */
			RemoveOfferTable(ifaceIndex, offer->hashOffer);
			RemovePendingTable(ifaceIndex, offer->hashOffer);
			break;
	}

  return (0);
}

/**
 * Create an offer to send SHC in exchange for an alternate currency.
 */
int init_offer_tx(CIface *iface, std::string strAccount, int altIndex, int64 nMinValue, int64 nMaxValue, double dRate, CWalletTx& wtx, uint160 hColor)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  char errbuf[1024];

	if (!offer_IsCompatibleIface(iface))
		return (SHERR_OPNOTSUPP);

  if (ifaceIndex != TEST_COIN_IFACE && 
      (ifaceIndex == altIndex))
    return (SHERR_INVAL);
	CIface *alt_iface = GetCoinByIndex(altIndex);
	if (!alt_iface)
		return (SHERR_OPNOTSUPP);
  CWallet *altWallet = GetWallet(altIndex);
	if (!altWallet)
		return (SHERR_OPNOTSUPP);

  if (nMinValue <= 0 || nMaxValue <= 0 || 
			dRate <= 0.0000 || nMinValue > nMaxValue) {
    return (SHERR_INVAL);
  }

	/* check account balance to ensure "offer fee" can be paid. */
  int64 nFee = GetOfferOpFee(iface) + nMaxValue;
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    sprintf(errbuf, "init_offer_tx: account '%s' balance %llu < nFee %llu\n", strAccount.c_str(), (unsigned long long)bal, (unsigned long long)nFee);
    return (ERR_FEE);
  }

#if 0
  int64 nAltFee = nMaxValue;
	int64 bal;
	if (altIndex == COLOR_COIN_IFACE) {
		bal = GetAccountBalance(altIndex, hColor.GetHex(), 1);
	} else {
		bal = GetAccountBalance(altIndex, strAccount, 1);
	}
  if (bal < nAltFee) {
    sprintf(errbuf, "init_offer_tx: alt account balance %llu < nFee %llu\n", (unsigned long long)bal, (unsigned long long)nAltFee);
    return (ERR_FEE);
  }
#endif

	CTxCreator s_wtx(wallet, strAccount);
  COffer *offer = s_wtx.CreateOffer();

	offer->vchPayCoin = vchFromString(string(iface->name));
	offer->hashColor = hColor;
	offer->nMinValue = nMinValue;
	offer->nMaxValue = nMaxValue;
	offer->nRate = (int64)(dRate * COIN);

  string strExtAccount = "@" + strAccount;
	CPubKey extAddr = GetAccountPubKey(wallet, strExtAccount, true);

	CPubKey payAddr = GetAccountPubKey(wallet, strAccount, true);
	offer->SetPayAddr(payAddr);

	string sXferCoin(alt_iface->name);
	offer->vchXferCoin = cbuff(sXferCoin.begin(), sXferCoin.end());

	string strError;

#if 0
	/* send alt-coin to temp holding addr. */
	CPubKey sinkAddr;
	strError = OfferHoldAltCoin(alt_iface, strAccount, offer, nAltFee);
	if (strError != "") {
		error(SHERR_CANCELED, "(%s) init_offer_tx: OfferHoldAltCoin: %s", iface->name, strError.c_str());
		return (SHERR_CANCELED);
  }
#endif

  uint160 offerHash = offer->GetHash();

  /* add output to ext tx for offer fee + max SHC offer */
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.GetID());
  CScript scriptPubKey;
	scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_OFFER) << OP_HASH160 << offerHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
	s_wtx.AddOutput(scriptPubKey, nFee);

	if (!s_wtx.Send()) {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  Debug("(%s) SENT:OFFERNEW : offerhash=%s, tx=%s, coin=%s\n", 
			iface->name, offer->GetHash().ToString().c_str(),
			s_wtx.GetHash().GetHex().c_str(), alt_iface->name);

	wtx = (CWalletTx)s_wtx;
  return (0);
}

int accept_offer_tx(CIface *iface, std::string strAccount, uint160 hashOffer, int64 nValue, CWalletTx& wtx, uint160 hColor)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

	if (!offer_IsCompatibleIface(iface))
		return (SHERR_OPNOTSUPP);

  /* establish offer tx */
  CTransaction tx;
  if (!GetTxOfOffer(iface, hashOffer, tx))
    return (SHERR_NOENT);

  COffer *offer = tx.GetOffer();
	if (!offer)
		return (SHERR_NOENT);

  if (nValue <= 0 || nValue < offer->nMinValue || nValue > offer->nMaxValue) {
    return (SHERR_INVAL);
  }

	CIface *alt_iface = offer->GetXferIface();
	if (!alt_iface)
		return (SHERR_OPNOTSUPP);
  CWallet *alt_wallet = GetWallet(alt_iface);
	if (!alt_wallet)
		return (SHERR_OPNOTSUPP);
	int destIndex = GetCoinIndex(alt_iface);

	/* establish alt-coin fee */
	double dRate = (double)offer->nRate / COIN;
  int64 nAltFee = (int64)((double)nValue * dRate);
  int64 bal = GetAccountBalance(destIndex, strAccount, 1);
  if (nAltFee >= bal) {
    return (error(ERR_FEE, "accept_offer_tx"));
  }

	CTxCreator s_wtx(wallet, strAccount);

	/* offer -> accept */
  COffer *accept = s_wtx.AcceptOffer(offer);
	accept->hashOffer = hashOffer; 
	accept->nValue = nValue;
	accept->hPayTx = tx.GetHash();

	/* establish destination alt-coin address. */
	if (destIndex == COLOR_COIN_IFACE) {
		string strColorAccount = hColor.GetHex();
		CPubKey xferAddr = GetAccountPubKey(alt_wallet, strColorAccount, true);
		accept->SetXferAddr(xferAddr);
	} else {
		CPubKey xferAddr = GetAccountPubKey(alt_wallet, strAccount, true);
		accept->SetXferAddr(xferAddr);
	}

	/* send alt-coin to temp holding addr. */
	string strError = OfferHoldAltCoin(alt_iface, strAccount, accept, nAltFee);
	if (strError != "") {
		error(SHERR_CANCELED, "(%s) init_offer_tx: OfferHoldAltCoin: %s", iface->name, strError.c_str());
		return (SHERR_CANCELED);
  }

  uint160 hashAccept = accept->GetHash();

  int64 minTxFee = MIN_TX_FEE(iface);
	/* "offer" extended transaction */
  CScript scriptPubKey;
	scriptPubKey << OP_EXT_ACTIVATE << CScript::EncodeOP_N(OP_OFFER) << OP_HASH160 << hashAccept << OP_2DROP << OP_RETURN << OP_0; /* null destination */
	/* 'if alt-tx then send else return funds' script */
//	CPubKey retAddr = GetAccountPubKey(wallet, strAccount, true);
  //scriptPubKey += offer_CheckAltProofScript(iface, offer, retAddr, nFee); 
	s_wtx.AddOutput(scriptPubKey, minTxFee);

	if (!s_wtx.Send()) {
    error(ifaceIndex, s_wtx.GetError().c_str());
    return (SHERR_CANCELED);
  }

fprintf(stderr, "DEBUG: OFFER: ACCEPT: %s\n", s_wtx.ToString(TEST_COIN_IFACE).c_str());

  Debug("(%s) SENT:OFFERACCEPT : accepthash=%s, tx=%s\n", 
			iface->name, accept->GetHash().ToString().c_str(),
			hashAccept.GetHex().c_str());

	wtx = (CWalletTx)s_wtx;
  return (0);
}

/* original offer sends SHC with alt-tx condition. */
int generate_offer_tx(CIface *iface, uint160 hashOffer, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
  int64 minTxFee = MIN_TX_FEE(iface);
  char errbuf[1024];
  bool ret;

	if (!offer_IsCompatibleIface(iface))
		return (SHERR_OPNOTSUPP);

  /* verify original offer */
  CTransaction tx;
  if (!GetTxOfOffer(iface, hashOffer, tx))
    return (SHERR_NOENT);
  if(!IsLocalOffer(iface, tx))
    return (SHERR_REMOTE);

  CTransaction txAccept;
  if (!GetTxOfAcceptOffer(iface, hashOffer, txAccept)) {
    error(SHERR_NOENT, "pay_offer_tx: unknown offer accept hash '%s'\n", hashOffer.GetHex().c_str());
    return (SHERR_NOENT);
  }

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
	if (wallet->mapWallet.count(wtxInHash) == 0)
		return (false);

	int64 nFeeValue;
	string strAccount;
	unsigned int nTxOut;
	CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];
	if (!GetExtTxOut(ifaceIndex, wtxIn, nFeeValue, strAccount, nTxOut))
		return (SHERR_REMOTE);

	CTxCreator s_wtx(wallet, strAccount);

	/* accept -> generate */
	COffer *offer = s_wtx.GenerateOffer(txAccept.GetOffer());
	if (!offer) {
		error(SHERR_NOENT, "generate_offer_tx: !wtx.GenerateOffer()\n"); 
		return (SHERR_NOENT);
	}

	{
		CTransaction alt_tx;
		if (!GetAltTx(alt_tx, offer))
			return (error(ERR_INVAL, "generate_offer_tx: error creating alt-tx"));
		offer->hXferTx = alt_tx.GetHash();
	}

  uint160 offerHash = offer->GetHash();

	/* original offer tx is input */
	s_wtx.AddInput(&wtxIn, nTxOut);

  /* ext output - remainder of input is left to block tx fee */
  CScript scriptFee;
  scriptFee << OP_EXT_GENERATE << CScript::EncodeOP_N(OP_OFFER) << OP_HASH160 << offerHash << OP_2DROP;
	/* send nFeeValue to OP_CHECKALTPROOF */
	CPubKey retAddr = GetAccountPubKey(wallet, strAccount, true);
	scriptFee += offer_CheckAltProofScript(iface, offer, retAddr);
	s_wtx.AddOutput(scriptFee, minTxFee);

	/* commit transaction */
	if (!s_wtx.Send()) {
    error(ifaceIndex, s_wtx.GetError().c_str());
    return (SHERR_CANCELED);
  }

  Debug("(%s) SENT:OFFERGENERATE : offerhash=%s\n", 
			iface->name, offer->GetHash().ToString().c_str());

	wtx = (CWalletTx)s_wtx;
  return (0);
}

#if 0
int pay_offer_tx(CIface *iface, uint160 hashAccept, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
	string strExtAccount;
	string strAccount;
  char errbuf[1024];
  bool ret;

	if (!offer_IsCompatibleIface(iface))
		return (SHERR_OPNOTSUPP);

  /* verify original offer */
  CTransaction tx;
  if (!GetTxOfAcceptOffer(iface, hashAccept, tx)) {
    error(SHERR_NOENT, "pay_offer_tx: unknown offer accept hash '%s'\n", hashAccept.GetHex().c_str());
    return (SHERR_NOENT);
  }
  if(!IsLocalOffer(iface, tx))
    return (SHERR_REMOTE);

  COffer *accept = tx.GetOffer();

  int nAltTxOut = IndexOfExtOutput(tx);
	CScript& pubKey = tx.vout[nAltTxOut].scriptPubKey;
	CTxDestination extDest;
	if (!ExtractDestination(pubKey, extDest))
		return (SHERR_INVAL);
	CCoinAddr extAddr(ifaceIndex, extDest);
	if (!GetCoinAddr(wallet, extAddr, strExtAccount))
		return (SHERR_NOENT);
	strAccount = strExtAccount.substr(1);
  int64 nFeeValue = tx.vout[nAltTxOut].nValue;

  CTransaction off_tx;
  if (!GetTxOfOffer(iface, accept->hashOffer, off_tx)) {
    error(SHERR_NOENT, "pay_offer_tx: unknown offer hash '%s'\n", accept->hashOffer.GetHex().c_str());
    return (SHERR_NOENT);
  }

  COffer *offer = off_tx.GetOffer();
	CIface *xferIface = offer->GetXferIface();
	int altIndex = GetCoinIndex(xferIface);
	CWallet *alt_wallet = GetWallet(xferIface);

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0) {
    return (SHERR_REMOTE);
  }
  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  int nTxOut = IndexOfExtOutput(wtxIn);
  if (nTxOut == -1)
    return (SHERR_INVAL);
  int64 nValue = wtxIn.vout[nTxOut].nValue;


#if 0
  CCoinAddr payAddr(ifaceIndex);
  string strPayAccount;
  vector<pair<CScript, int64> > vecSend;
  if (stringFromVch(offer->vchPayCoin) == string(iface->name)) {
    nFeeValue -= iface->min_tx_fee; /* for GEN op script */

    /* accept sending shc */
    if (!accept.GetXferAddr(ifaceIndex, payAddr, strPayAccount))
      return (SHERR_INVAL);

    int64 nValue = MAX(0, accept.nXferValue);
if (nValue <= iface->min_tx_fee) return (SHERR_INVAL); /* DEBUG: redundant */


    /* output - send SHC to accept addr */
    CCoinAddr destAddr(ifaceIndex);
    if (!accept.GetPayAddr(ifaceIndex, destAddr)) {
      /* print error */
      return (SHERR_INVAL);
    }

    CScript destPubKey;
    destPubKey.SetDestination(destAddr.Get());
    vecSend.insert(vecSend.begin(), make_pair(destPubKey, nValue));

    nFeeValue -= nValue;
    
    if (nFeeValue < 0) {
      error(SHERR_CANCELED, "pay_offer_tx: "
          "miscalculation on accept offer payments:");
      wtx.print(ifaceIndex); 
      return (SHERR_CANCELED);
    }

    wtx.strFromAccount = strPayAccount;
  } else {
    CIface *altIface = offer->GetPayIface();
    if (!altIface || !altIface->enabled)
      return (SHERR_OPNOTSUPP);
		int altIndex = GetCoinIndex(altIface);

    /* offer sending alt */
    if (!accept.GetXferAddr(altIndex, payAddr, strPayAccount)) {
      error(SHERR_INVAL, "generate_offer_tx: !offer->GetXferAddr()\n"); 
      return (SHERR_INVAL);
    }

    CWalletTx alt_wtx;
    CWalletTx alt_wtxIn;
    int nTxOut = FindOfferTxOut(altIndex, accept.hXferTx, alt_wtxIn, payAddr);
    if (nTxOut < 0) {
      error(SHERR_INVAL, "generate_offer_tx: nTxOut 'tx %s' error (%d)\n", accept.hXferTx.GetHex().c_str(), nTxOut);
      return (SHERR_INVAL);
    }

int nAltFeeValue = alt_wtxIn.vout[nTxOut].nValue;
    vector<pair<CScript, int64> > alt_vecSend;
    int nValue = accept.nXferValue;
//fprintf(stderr, "DEBUG: pay_tx_fee: accept sending alt-coin: nValue %lld\n", (long long)nValue);

    /* output - send alt-coin to accept addr */
    CCoinAddr destAddr(ifaceIndex);
    if (!accept.GetPayAddr(altIndex, destAddr)) {
      error(SHERR_INVAL, "pay_tx_fee: !GetPayAddr '%s'.", destAddr.ToString().c_str());
      return (SHERR_INVAL);
    }

    CScript destPubKey;
    destPubKey.SetDestination(destAddr.Get());
    vecSend.insert(vecSend.begin(), make_pair(destPubKey, nValue));

    nAltFeeValue -= nValue;
    
    if (nAltFeeValue < 0) {
      error(SHERR_CANCELED, "pay_offer_tx: "
          "miscalculation on accept offer payments:");
      wtx.print(ifaceIndex); 
      return (SHERR_CANCELED);
    }

    CWallet *altWallet = GetWallet(altIface);
    //CReserveKey reservekey(altWallet);
    ret = CreateTransactionWithInputTx(altIface, strAccount, alt_vecSend, alt_wtxIn, nTxOut, alt_wtx, 0);//reservekey);
    if (!ret) {
      error(SHERR_CANCELED, "error creating alt-coin transaction.");
      return (SHERR_CANCELED);
    }
    if (!altWallet->CommitTransaction(alt_wtx)) {
      error(SHERR_CANCELED, "error commiting alt-coin transaction.");
      return (SHERR_CANCELED);
    }
  }
#endif
	/* prepare ext tx */
	CCoinAddr destAddr(ifaceIndex);
	if (!accept->GetXferAddr(altIndex, destAddr)) {
		error(SHERR_INVAL, "pay_tx_fee: !GetPayAddr '%s'.", destAddr.ToString().c_str());
		return (SHERR_INVAL);
	}

	CTxCreator s_wtx(wallet, strExtAccount);
  COffer *pay = s_wtx.PayOffer(accept);
  if (!pay) {
    error(SHERR_INVAL, "generate_offer_tx: !wtx.PayOffer()\n"); 
    return (SHERR_INVAL);
  }

	/* add accept tx as input */
	s_wtx.AddInput(&wtxIn, nTxOut);

	/* add proof tx as input */
  int nProofTxOut = IndexOfExtOutput(wtxIn);
	s_wtx.AddInput(accept->hPayTx, nProofTxOut); 

  /* output - remainder of input is left to block tx fee */
  CScript scriptFee;
  uint160 hashPay = pay->GetHash();
  int64 minTxFee = MIN_TX_FEE(iface);
  scriptFee << OP_EXT_PAY << CScript::EncodeOP_N(OP_OFFER) << OP_HASH160 << hashPay << OP_2DROP;
	CScript destPubKey;
	destPubKey.SetDestination(destAddr.Get());
	scriptFee += destPubKey;
	s_wtx.AddOutput(scriptFee, accept->nValue);

	/* send alt-coins (commit prepared tx) */
	CTransaction alt_tx;
	if (!GetAltTx(alt_tx, accept)) {
		return (SHERR_INVAL);
	}
	CWalletTx alt_wtx(alt_wallet, alt_tx); 
	if (alt_wtx.GetHash() != accept->hXferTx) {
		/* transaction contents mismatch. */
fprintf(stderr, "DEBUG: pay_offer_tx: alg tx mismatch\n");
		return (SHERR_INVAL);
	}
	/* commit alt-coin transaction. */
	if (!alt_wallet->CommitTransaction(alt_wtx))
		return (SHERR_CANCELED);

	/* commit SHC transaction */
	if (!s_wtx.Send()) {
		/* user still owns received SHC if this fails.. */
    error(ifaceIndex, "pay_offer_tx: !s_wtx.Send", s_wtx.GetError().c_str());
//    return (SHERR_CANCELED);
  }

  Debug("(%s) SENT:OFFERPAY : accepthash=%s, payhash=%s\n",
			iface->name, accept->GetHash().GetHex().c_str(),
			pay->GetHash().GetHex().c_str());

	wtx = (CWalletTx)s_wtx;
  return (0);
}
#endif

