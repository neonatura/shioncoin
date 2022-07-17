
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
#include "json_spirit_reader_template.h"
#include "json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>
#include "wallet.h"
#include "account.h"
#include "txcreator.h"

using namespace std;
using namespace json_spirit;

cert_list *GetIdentTable(int ifaceIndex)
{
	if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
		return (NULL);
	CWallet *wallet = GetWallet(ifaceIndex);
	if (!wallet)
		return (NULL);
	return (&wallet->mapIdent);
}

bool InsertIdentTable(CIface *iface, CTransaction& tx)
{
	CWallet *wallet = GetWallet(iface);
	int mode;

	if (!wallet)
		return (false);

	if (!VerifyIdent(tx, mode))
		return (false);

	if (mode == OP_EXT_NEW) { /* ident stamp */
		//CIdent& ident = (CIdent&)tx.certificate;
		CIdent& ident = (CIdent&)tx.ident;
		const uint160& hIdent = ident.GetHash();
		wallet->mapIdent[hIdent] = tx.GetHash();
	}

	return (true);
}

bool DecodeIdentHash(const CScript& script, int& mode, uint160& hash)
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
	op = CScript::DecodeOP_N(opcode); /* extension type (cert) */
	if (op != OP_IDENT) {
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

bool IsIdentTx(const CTransaction& tx)
{
	int tot;

	if (!tx.isFlag(CTransaction::TXF_IDENT)) {
		return (false);
	}

	tot = 0;
	BOOST_FOREACH(const CTxOut& out, tx.vout) {
		uint160 hash;
		int mode;

		/* todo: check mode */
		if (DecodeIdentHash(out.scriptPubKey, mode, hash)) {
			tot++;
		}
	}
	if (tot == 0) {
		return false;
	}

	return (true);
}

bool IsLocalIdent(CIface *iface, const CTransaction& tx)
{
	if (!IsIdentTx(tx))
		return (false); /* not a cert */

	int nOut = IndexOfExtOutput(tx);
	if (nOut == -1)
		return (false); /* invalid state */

	return (IsLocalEntity(iface, tx.vout[nOut]));
}

bool VerifyIdent(CTransaction& tx, int& mode)
{
	uint160 hashIdent;
	int nOut;

	/* core verification */
	if (!IsIdentTx(tx))
		return (false); /* tx not flagged as ident */

	/* verify hash in pub-script matches ident hash */
	nOut = IndexOfExtOutput(tx);
	if (nOut == -1)
		return (false); /* no extension output */

	if (!DecodeIdentHash(tx.vout[nOut].scriptPubKey, mode, hashIdent))
		return (false); /* no ident hash in output */

	if (mode != OP_EXT_NEW &&
			mode != OP_EXT_ACTIVATE &&
			mode != OP_EXT_GENERATE &&
			mode != OP_EXT_PAY) {
		return (false);
	}

	//CIdent *ident = (CIdent *)&tx.certificate;
	CIdent *ident = (CIdent *)&tx.ident;
	if (hashIdent != ident->GetHash()) {
		return (false); /* ident hash mismatch */
	}

	return (true);
}

bool GetTxOfIdent(CIface *iface, const uint160& hash, CTransaction& tx)
{
	int ifaceIndex = GetCoinIndex(iface);
	cert_list *idents = GetIdentTable(ifaceIndex);

	if (idents->count(hash) == 0)
		return (false);

	uint256 hashTx = (*idents)[hash];
	bool ret = GetTransaction(iface, hashTx, tx, NULL);
	if (!ret)
		return (false);

	if (!IsIdentTx(tx)) {
		return (false);
	}

	return (true);
}

std::string CIdent::ToString()
{
	return (write_string(Value(ToValue()), false));
}

Object CIdent::ToValue()
{
	Object obj = CExtCore::ToValue();
	char sig[256];
	char loc[256];
	shnum_t lat, lon;

	//  obj.push_back(Pair("identhash", GetHash().GetHex()));

	shgeo_loc(&geo, &lat, &lon, NULL);
	if (lat != 0.0000 || lon != 0.0000) {
		sprintf(loc, "%Lf,%Lf", lat, lon);
		string strGeo(loc);
		obj.push_back(Pair("geo", strGeo));
	}

	if (nType != 0) {
		obj.push_back(Pair("type", (int64_t)nType));
	}

	if (vAddr.size() != 0)
		obj.push_back(Pair("address", stringFromVch(vAddr)));

	return (obj);
}

uint160 CIdent::GetHash()
{
	uint256 hash = SerializeHash(*this);
	unsigned char *raw = (unsigned char *)&hash;
	cbuff rawbuf(raw, raw + sizeof(hash));
	return Hash160(rawbuf);
}

int CIdent::VerifyTransaction()
{
  int err;

  err = CEntity::VerifyTransaction();
  if (err)
    return (err);
  
  return (0);
}

/**
 * Submits an amount of coins as a transaction fee.
 * @param strAccount The account to donate funds from.
 * @param nValue A coin amount more than 0.0000101.
 * @param hashCert An optional certificate reference to associate with the donation.
 * @note A block depth of two must be reached before donation occurs.
 */
int init_ident_donate_tx(CIface *iface, string strAccount, uint64_t nValue, uint160 hashCert, CWalletTx& wtx)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	CIdent *ident;

	if (ifaceIndex != TEST_COIN_IFACE && ifaceIndex != SHC_COIN_IFACE)
		return (SHERR_OPNOTSUPP);

	if (!wallet || !iface->enabled)
		return (SHERR_OPNOTSUPP);

	int64 nFee = nValue - iface->min_tx_fee;
	if (nFee < iface->min_input) {
		return (SHERR_INVAL);
	}

	CTransaction tx;
	bool hasCert = GetTxOfCert(iface, hashCert, tx);

	CTxDestination dest;
	wallet->GetAccount(strAccount)->GetPrimaryAddr(ACCADDR_EXT, dest);
	CCoinAddr addr(wallet->ifaceIndex, dest);
	//  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);
	if (!addr.IsValid())
		return (SHERR_INVAL);

	CTxCreator t_wtx(wallet, strAccount); /* first tx */
	if (hasCert) {
		if (!IsCertAccount(iface, tx, strAccount)) { 
			error(SHERR_ACCESS, "init_ident_donate_tx: certificate is not local.");
			return (SHERR_ACCESS);
		}

		CIdent& c_ident = (CIdent&)tx.certificate;
		ident = t_wtx.CreateIdent(&c_ident);
	} else {
		ident = t_wtx.CreateIdent(ifaceIndex, addr);
	}
	if (!ident)
		return (SHERR_INVAL);

	uint160 hashIdent = ident->GetHash();

	/* OP_IDENT: OPT_EXT_NEW */
	CScript scriptPubKeyOrig;
	scriptPubKeyOrig.SetDestination(addr.Get());
	CScript scriptPubKey;
	scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_IDENT) << OP_HASH160 << hashIdent << OP_2DROP;
	scriptPubKey += scriptPubKeyOrig;
	if (!t_wtx.AddOutput(scriptPubKey, nValue, true))
		return SHERR_CANCELED;
	if (!t_wtx.Send()) {
		return (SHERR_CANCELED);
	}

	/* OP_IDENT: OPT_EXT_GENERATE */
	CTxCreator s_wtx(wallet, strAccount);

	/* deduct intermediate tx fee */
#if 0
	nFee -= nFeeRequired;
#endif
	nFee = MAX(iface->min_tx_fee, nFee);

	/* send from intermediate as tx fee */
#if 0
	s_wtx.SetNull();
	s_wtx.strFromAccount = strAccount;
#endif
	CIdent *gen_ident = s_wtx.CreateIdent(ident);
	if (!gen_ident) {
		return (SHERR_INVAL);
	}

	CScript feePubKey;
	s_wtx.strFromAccount = strAccount;
	feePubKey << OP_EXT_GENERATE << CScript::EncodeOP_N(OP_IDENT) << OP_HASH160 << hashIdent << OP_2DROP << OP_RETURN;

#if 0
	vector<pair<CScript, int64> > vecSend;
	if (!SendMoneyWithExtTx(iface, t_wtx, s_wtx, feePubKey, vecSend, nFee))
		return (error(SHERR_INVAL, "init_ident_donate_tx:: !SendMoneyWithExtTx"));
#endif
	if (!s_wtx.AddExtTx(&t_wtx, feePubKey, nFee))
		return (SHERR_CANCELED);

	if (!s_wtx.Send()) {
		return (SHERR_CANCELED);
	}

	wtx = s_wtx;

	return (0);
}

/**
 * Submits a geodetic trackable time-stamp.
 */
int init_ident_stamp_tx(CIface *iface, std::string strAccount, std::string strComment, CWalletTx& wtx)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	CIdent *ident;

	if (ifaceIndex != TEST_COIN_IFACE && ifaceIndex != SHC_COIN_IFACE)
		return (SHERR_OPNOTSUPP);

	if (!wallet || !iface->enabled)
		return (SHERR_OPNOTSUPP);

	if (strComment.length() > 135)
		return (SHERR_INVAL);

	int64 nFee = iface->min_tx_fee;

	CTxDestination dest;
	wallet->GetAccount(strAccount)->GetPrimaryAddr(ACCADDR_EXT, dest);
	CCoinAddr addr(wallet->ifaceIndex, dest);
	//  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);
	if (!addr.IsValid())
		return (SHERR_INVAL);

	ident = wtx.CreateIdent(ifaceIndex, addr);
	if (!ident)
		return (SHERR_INVAL);

	if (strComment.substr(0, 4) == "geo:") { /* geodetic uri */
		shnum_t lat, lon;
		int n = sscanf(strComment.c_str(), "geo:%Lf,%Lf", &lat, &lon);
		if (n == 2 &&
				(lat >= -90 && lat <= 90) &&
				(lon >= -180 && lon <= 180))
			shgeo_set(&ident->geo, lat, lon, 0);
	}
	ident->SetLabel(strComment);

	const uint160 hashIdent = ident->GetHash();

	/* sent to intermediate account. */
	//  CReserveKey rkey(wallet);
	wtx.strFromAccount = strAccount;

	CScript scriptPubKey;
	scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_IDENT) << OP_HASH160 << hashIdent << OP_2DROP << OP_RETURN;
	int64 nFeeRequired;
	string strError;
	if (!wallet->CreateAccountTransaction(strAccount, scriptPubKey, nFee, wtx, strError, nFeeRequired)) {
		return (SHERR_CANCELED);
	}

	if (!wallet->CommitTransaction(wtx)) {
		return (SHERR_CANCELED);
	}

	return (0);
}

int init_ident_certcoin_tx(CIface *iface, string strAccount, uint64_t nValue, uint160 hashCert, CCoinAddr addrDest, CWalletTx& wtx)
{
	CWallet *wallet = GetWallet(iface);
	int ifaceIndex = GetCoinIndex(iface);
	int64 nMinValue = MIN_TX_FEE(iface); 
	int64 nMinInput = MIN_INPUT_VALUE(iface); 

	if (ifaceIndex != TEST_COIN_IFACE && 
			ifaceIndex != TESTNET_COIN_IFACE && 
			ifaceIndex != SHC_COIN_IFACE)
		return (SHERR_OPNOTSUPP);

	if (!wallet || !iface->enabled)
		return (SHERR_OPNOTSUPP);

	if (!addrDest.IsValid())
		return (SHERR_INVAL);

	if (nValue < MIN_RELAY_TX_FEE(iface))
		return (ERR_INVAL); /* output value is too small. */

	int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
	if (bal < (nValue + MIN_RELAY_TX_FEE(iface)))
		return (ERR_FEE); /* account has insufficient funds. */

	CTransaction tx;
	bool hasCert = GetTxOfCert(iface, hashCert, tx);
	if (!hasCert) {
		error(SHERR_INVAL, "init_ident_certcoin_tx: invalid certificate specified.");
		return (SHERR_INVAL);
	}

	if (!IsCertAccount(iface, tx, strAccount)) { 
		error(SHERR_ACCESS, "init_ident_certcoin_tx: account '%s' is not owner of cert '%s'.", strAccount.c_str(), hashCert.GetHex().c_str());
		return (SHERR_ACCESS);
	}

	CTxCreator s_wtx(wallet, strAccount);
	CIdent& s_cert = (CIdent&)tx.certificate;
	CIdent *ident = s_wtx.CreateIdent(&s_cert);
	if (!ident)
		return (ERR_INVAL);

	CScript scriptPubKey;
	scriptPubKey.SetDestination(addrDest.Get());

	CScript scriptExt;
	const uint160& hashIdent = ident->GetHash();
	scriptExt << OP_EXT_PAY << CScript::EncodeOP_N(OP_IDENT) << OP_HASH160 << hashIdent << OP_2DROP;
	scriptExt += scriptPubKey;
	s_wtx.AddOutput(scriptExt, nValue, true);

	if (!s_wtx.Send())
		return (SHERR_CANCELED);

	wtx = (CWalletTx)s_wtx;

#if 0
	CTxDestination dest;
	if (!wallet->GetAccount(strAccount)->GetPrimaryAddr(ACCADDR_EXT, dest))
		return (ERR_INVAL);

	/* set destination address. */
	CScript scriptPubKeyOrig;
	scriptPubKeyOrig.SetDestination(dest);

	CScript scriptPubKey;
	scriptPubKey << OP_EXT_PAY << CScript::EncodeOP_N(OP_IDENT) << OP_HASH160 << hashIdent << OP_2DROP;

	scriptPubKey += scriptPubKeyOrig;
	int64 nFeeRequired;
	string strError;
	if (!wallet->CreateAccountTransaction(strAccount, scriptPubKey, nValue, wtx, strError, nFeeRequired)) {
		CTransaction& pr_tx = (CTransaction&)wtx;
		return (SHERR_CANCELED);
	}
	if (!wallet->CommitTransaction(wtx)) {
		CTransaction *tx = (CTransaction *)&wtx;
		return (SHERR_CANCELED);
	}

	nValue -= nFeeRequired;
	nValue = MAX(iface->min_tx_fee, nValue);

	/* send from intermediate to desination specified */
	CWalletTx t_wtx;
	t_wtx.SetNull();
	t_wtx.strFromAccount = strAccount;
	t_wtx.CreateIdent(ident);

	vector<pair<CScript, int64> > vecSend;
	CScript destPubKey;
	destPubKey.SetDestination(addrDest.Get());

	if (!SendMoneyWithExtTx(iface, strAccount, wtx, t_wtx, destPubKey, vecSend, nMinValue)) { 
		return (SHERR_INVAL);
	}

	Debug("CERT-TX: sent certified payment of %f [fee %f]\n", ((double)nValue/(double)COIN), ((double)(nMinValue+nFeeRequired)/(double)COIN)); 
#endif

	return (0);
}

