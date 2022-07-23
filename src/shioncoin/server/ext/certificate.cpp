
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


extern json_spirit::Value ValueFromAmount(int64 amount);


cert_list *GetCertTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapCert);
}

#if 0
cert_list *GetIdentTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapIdent);
}
#endif

cert_list *GetLicenseTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapLicense);
}

int GetTotalCertificates(int ifaceIndex)
{
  cert_list *certs = GetCertTable(ifaceIndex);
  return (certs->size());
}

bool VerifyCertChain(CIface *iface, CTransaction& tx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CCert *cert = (CCert *)&tx.certificate;
  uint160 &cert_hash = cert->hashIssuer;
  CTransaction ptx;
  int idx;
  
  if (!cert_hash.IsNull()) {
    if (!GetTxOfCert(iface, cert_hash, ptx))
      return error(SHERR_INVAL, "VerifyCertChain: unknown originating certificate.");

    CCert *pcert = (CCert *)&ptx.certificate;
    if (!pcert->VerifySignature(ifaceIndex))
      return error(SHERR_INVAL, "VerifyCertChain: signature integrity error");
  }

  if (!cert->VerifySignature(ifaceIndex))
    return error(SHERR_INVAL, "VerifyCertChain: signature integrity error");

#if 0
  CCert *pcert = &ptx.certificate;
  if (pcert->nFee > (int64)iface->min_tx_fee) {
    const string cert_addr = stringFromVch(pcert->vAddr);

    bool bFound = false;
    for (idx = 0; idx < tx.vout.size(); idx++) {
      CTxDestination dest;
      if (!ExtractDestination(tx.vout[idx].scriptPubKey, dest))
        return error(SHERR_INVAL, "VerifyCertChain: no output destination.");
      CCoinAddr addr(ifaceIndex);
      addr.Set(dest);
      if (addr.ToString() != cert_addr)
        continue; /* wrong output */

      /* verify fee has been paid by license */
      if (tx.vout[idx].nValue < pcert->nFee)
        return (SHERR_INVAL, "VerifyCertChain: insufficent license fee.");

      bFound = true;
      break;
    }
    if (!bFound)
      return error(SHERR_INVAL, "VerifyCertChain: invalid output destination.");
  }
#endif

  return (true);
}

bool InsertCertTable(CIface *iface, CTransaction& tx, unsigned int nHeight, bool fUpdate)
{
  CWallet *wallet = GetWallet(iface);

  if (!wallet)
    return (false);

  if (!VerifyCert(iface, tx, nHeight))
    return error(SHERR_INVAL, "CommitCertTx: error verifying certificate.");

  if (!VerifyCertChain(iface, tx))
    return error(SHERR_INVAL, "CommitCertTx: chain verification failure [tx %s].", tx.GetHash().GetHex().c_str());

  CCert *cert = (CCert *)&tx.certificate;

  string strCertLabel = cert->GetLabel();
  int count = wallet->mapCertLabel.count(strCertLabel);
  if (count != 0) {
    return (error(SHERR_NOTUNIQ, "CommitCertTx: non-unique certificate name '%s' rejected.", strCertLabel.c_str()));
  }

  const uint160& hCert = cert->GetHash();
  count = wallet->mapCert.count(hCert);
  if (count) {
    const uint256& o_tx = wallet->mapCert[hCert]; 
    if (o_tx == tx.GetHash())
      return (true); /* already assigned */
  }

  if (!fUpdate) {
    int ifaceIndex = GetCoinIndex(iface);
    cert_list *certs = GetCertTable(ifaceIndex);
    if (count) {
      wallet->mapCertArch[tx.GetHash()] = hCert;
      return (false); /* suppress overwrite */
    }
  }

  /* reassign previous */
  if (count) {
    const uint256& o_tx = wallet->mapCert[hCert]; 
    wallet->mapCertArch[o_tx] = hCert;
  }

  wallet->mapCert[hCert] = tx.GetHash();
  wallet->mapCertLabel[strCertLabel] = hCert;

#if 0
  /* save to sharefs sub-system. */
  cert.NotifySharenet(GetCoinIndex(iface));
#endif

  return (true);
}

#if 0
bool InsertIdentTable(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  int mode;

  if (!wallet)
    return (false);

  if (!VerifyIdent(tx, mode))
    return (false);

  if (mode == OP_EXT_NEW) { /* ident stamp */
    CIdent& ident = (CIdent&)tx.certificate;
    const uint160& hIdent = ident.GetHash();
    wallet->mapIdent[hIdent] = tx.GetHash();
  }

  return (true);
}
#endif

static bool GetOutDestination(int ifaceIndex, const CTransaction& tx, CCoinAddr addr, int& nOut)
{
  const string& addr_str = addr.ToString();
  int idx;

  for (idx = 0; idx < tx.vout.size(); idx++) {
    CTxDestination dest;
    if (!ExtractDestination(tx.vout[idx].scriptPubKey, dest))
      return error(SHERR_INVAL, "VerifyCertChain: no output destination.");

    CCoinAddr addr(ifaceIndex);
    addr.Set(dest);
    if (addr.ToString() != addr_str)
      continue; /* wrong output */

    nOut = idx;
    return (true);
  }

  return (false);
}

bool CommitLicenseTx(CIface *iface, CTransaction& tx, int nHeight)
{
  CWallet *wallet = GetWallet(iface);
  CTransaction cert_tx;
  bool fUpdate = true;

  if (!wallet)
    return (false);

  if (!VerifyLicense(tx))
    return error(SHERR_INVAL, "CommitLicenseTx: !VerifyLicense\n");

	CLicense *lic = tx.GetLicense();
	if (!lic)
		return (false);

  if (!VerifyLicenseChain(iface, tx))
    return error(SHERR_INVAL, "CommitLicenseTx: chain verification failure.");

  const uint160& hashCert = lic->hashIssuer;

  if (!GetTxOfCert(iface, hashCert, cert_tx))
    return error(SHERR_INVAL, "CommitLicenseTx: unknown certificate \"%s\".", hashCert.GetHex().c_str());

  CCert *cert = (CCert *)&cert_tx.certificate;

  if (!(cert->nFlag & SHCERT_CERT_DIGITAL)) {
    return error(SHERR_INVAL, "CommitLicenseTx: license certificate is not sufficient to grant digital license.");
  }
  if (!(cert->nFlag & SHCERT_CERT_CHAIN)) {
    return error(SHERR_INVAL, "CommitLicenseTx: license certificate cannot be a certificate authority (must be derived)");
  }

#if 0
  int64 nFee = cert->nFee;
  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false);
  if (tx.vout[nOut].nValue < nFee) {
    return error(SHERR_AGAIN, "CommitLicenseTx: license fee is insufficient (%llu/%llu) [nout %d, tx %s]", tx.vout[nOut].nValue, nFee, nOut, tx.GetHash().GetHex().c_str());
  }
#endif

  const uint160& hLic = lic->GetHash();
  if (wallet->mapLicense.count(hLic) != 0)
    return error(SHERR_AGAIN, "CommitLicenseTx: license duplicate.");

  wallet->mapLicense[hLic] = tx.GetHash();

#if 0
  /* save to sharefs sub-system. */
  lic.NotifySharenet(GetCoinIndex(iface));
#endif

  return (true);
}

bool GetCertByName(CIface *iface, string name, CCert& cert)
{
  CWallet *wallet = GetWallet(iface);

  if (wallet->mapCertLabel.count(name) == 0)
    return (false);

  CTransaction tx;
  const uint160& hash = wallet->mapCertLabel[name];
  bool ret = GetTxOfCert(iface, hash, tx);
  if (!ret)
    return (false);

  cert = tx.certificate;
  return (true);
}

#if 0
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
#endif

bool DecodeCertHash(const CScript& script, int& mode, uint160& hash)
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
  if (op != OP_CERT) {
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

bool DecodeLicenseHash(const CScript& script, int& mode, uint160& hash)
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
  if (op != OP_LICENSE) {
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


bool IsCertOp(int op) {
	return (op == OP_CERT);
}


string certFromOp(int op) {
	switch (op) {
	case OP_EXT_NEW:
		return "certnew";
	case OP_EXT_ACTIVATE:
		return "certactivate";
	case OP_EXT_UPDATE:
		return "certupdate";
	case OP_EXT_TRANSFER:
		return "certtransfer";
	case OP_EXT_REMOVE:
		return "certremove";
	case OP_EXT_GENERATE:
		return "certgenerate";
	case OP_EXT_PAY:
		return "certpay";
	default:
		return "<unknown cert op>";
	}
}

bool DecodeCertScript(const CScript& script, int& op,
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

	op = CScript::DecodeOP_N(opcode); /* extension type (cert) */
  if (op != OP_CERT)
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

bool DecodeCertScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeCertScript(script, op, vvch, pc);
}

CScript RemoveCertScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeCertScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveCertScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetCertOpFee(CIface *iface, int nHeight) 
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5100 / base * COIN;
  double nDif = 4982 /base * COIN;
  int64 nFee = (int64)(nRes - nDif);

  /* round down */
  nFee /= 1000;
  nFee *= 1000;

  nFee = MAX(MIN_TX_FEE(iface), nFee);
  nFee = MIN(MAX_TX_FEE(iface), nFee);
  return (nFee);
}


int64 GetCertReturnFee(const CTransaction& tx) 
{
	int64 nFee = 0;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
			nFee += out.nValue;
	}
	return nFee;
}

#if 0
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

    if (DecodeIdentHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}
#endif

bool IsCertTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_CERTIFICATE)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeCertHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

bool IsLicenseTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_LICENSE)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeLicenseHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

#if 0
bool IsCertEntTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_ENTITY)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeCertHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}
#endif

bool GetCertAccount(CIface *iface, CTransaction& tx, string& strAccount)
{
  CWallet *wallet = GetWallet(iface);

  if (!IsCertTx(tx))
    return (false); /* not a cert */

	const CCert *cert = tx.GetCertificate();
	if (!cert)
		return (false);

  CCoinAddr addr(GetCoinIndex(iface), stringFromVch(cert->vAddr));
  return (GetCoinAddr(wallet, addr, strAccount));
}

bool IsCertAccount(CIface *iface, CTransaction& tx, string strAccount)
{
  bool ret;
  string strCertAccount;

  ret = GetCertAccount(iface, tx, strCertAccount);
  if (!ret)
    return (false);

  if (strCertAccount.length() > 0 && strCertAccount.at(0) == '@')
    strCertAccount.erase(0, 1);

  return (strAccount == strCertAccount);
}

bool IsLocalCert(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalCert(CIface *iface, const CTransaction& tx)
{
  if (!IsCertTx(tx))
    return (false); /* not a cert */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalCert(iface, tx.vout[nOut]));
}

#if 0
bool IsLocalIdent(CIface *iface, const CTransaction& tx)
{
  if (!IsIdentTx(tx))
    return (false); /* not a cert */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalCert(iface, tx.vout[nOut]));
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

  CIdent *ident = (CIdent *)&tx.certificate;
  if (hashIdent != ident->GetHash()) {
    return (false); /* ident hash mismatch */
}

  return (true);
}
#endif

/**
 * Verify the integrity of an certificate.
 */
bool VerifyCert(CIface *iface, CTransaction& tx, int nHeight)
{
  uint160 hashCert;
  time_t now;
  int nOut;

  /* core verification */
  if (!IsCertTx(tx)) {
    return (error(SHERR_INVAL, "VerifyCert: transaction does not contain a certificate: %s", tx.ToString(GetCoinIndex(iface)).c_str()));
	}

  /* verify hash in pub-script matches cert hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (error(SHERR_INVAL, "VerifyCert: no extension output"));

  int mode;
  if (!DecodeCertHash(tx.vout[nOut].scriptPubKey, mode, hashCert))
    return (error(SHERR_INVAL, "VerifyCert: no cert hash in output"));

  if (mode != OP_EXT_NEW &&
      mode != OP_EXT_ACTIVATE &&
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_REMOVE)
    return (error(SHERR_INVAL, "VerifyCert: invalid operational mode."));

  if (tx.vout[nOut].nValue < GetCertOpFee(iface, nHeight))
    return error(SHERR_INVAL, "VerifyCert: insufficient fee (%f) for block accepted at height %d.", (double)tx.vout[nOut].nValue/COIN, (int)nHeight);

  CCert *cert = (CCert *)tx.GetCertificate();
	if (!cert)
		return (false);
  if (hashCert != cert->GetHash())
    return (error(SHERR_INVAL, "VerifyCert: invalid cert hash"));

  if (cert->hashIssuer.IsNull() &&
      (cert->nFlag & SHCERT_CERT_CHAIN))
    return error(SHERR_INVAL, "VerifyCert: error: cert has no issuer and is also marked chained.");

  now = time(NULL);
  if (cert->GetExpireTime() > (now + SHARE_DEFAULT_EXPIRE_TIME))
    return error(SHERR_INVAL, "VerifyCert: invalid expiration time");

  return (true);
}

/**
 * Verify the integrity of a license
 */
bool VerifyLicense(CTransaction& tx)
{
  uint160 hashLicense;
  int nOut;

  /* core verification */
  if (!IsLicenseTx(tx)) {
    return (false); /* tx not flagged as cert */
  }

  /* verify hash in pub-script matches cert hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1) {
    return (false); /* no extension output */
  }

  int mode;
  if (!DecodeLicenseHash(tx.vout[nOut].scriptPubKey, mode, hashLicense)) {
    return (false); /* no cert hash in output */
  }

  if (mode != OP_EXT_ACTIVATE)
    return (false);

  CLicense *lic = tx.GetLicense();
	if (!lic)
		return (false);
  if (hashLicense != lic->GetHash())
    return error(SHERR_INVAL, "license certificate hash mismatch");

  return (true);
}


bool VerifyLicenseChain(CIface *iface, CTransaction& tx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CLicense *lic;
  uint160 cert_hash;

  lic = tx.GetLicense();
	if (!lic)
		return (false);
	cert_hash = lic->hashIssuer;

  CTransaction cert_tx; 
  if (!GetTxOfCert(iface, cert_hash, cert_tx)) {
    return error(SHERR_INVAL, "VerifyLicenseChain: uknown certificate issuer '%s'", cert_hash.GetHex().c_str());
  }

  CCert *cert = cert_tx.GetCertificate();
	if (!cert)
		return (false);
  if (!cert->VerifySignature(ifaceIndex))
    return error(SHERR_INVAL, "VerifyLicenseChain: signature integrity error with chained certificated.");

  if (!lic->VerifySignature(ifaceIndex, cert))
    return error(SHERR_INVAL, "VerifyLicenseChain: signature integrity error with license.");

  if (cert->nFee > (int64)iface->min_tx_fee) {
    const CCoinAddr addr(ifaceIndex, stringFromVch(cert->vAddr));
    int nOut;

    if (!GetOutDestination(ifaceIndex, tx, addr, nOut)) {
      return error(SHERR_INVAL, "VerifyCertChain: invalid output destination.");
    //  return false;
    }

    /* verify fee has been paid by license */
    if (tx.vout[nOut].nValue < cert->nFee)
      return (SHERR_INVAL, "VerifyCertChain: insufficent license fee.");
  }

  return (true);
}

#if 0
bool GetCertEntByHash(CIface *iface, uint160 hash, CIdent& issuer)
{
  int ifaceIndex = GetCoinIndex(iface);
  cert_list *certs = GetCertTable(ifaceIndex);

  if (certs->count(hash) == 0)
    return (false);

  uint256 hashTx = (*certs)[hash];
  CTransaction tx;
  bool ret = GetTransaction(iface, hashTx, tx, NULL);
  if (!ret)
    return (false);

  if (!IsCertEntTx(tx))
    return (false);

  issuer = tx.entity;
  return (true);
}
#endif

/**
 * Obtain the block-chain tx that encapsulates a certificate
 * @param hash The certificate hash.
 */
bool GetTxOfCert(CIface *iface, const uint160& hash, CTransaction& tx)
{
  int ifaceIndex = GetCoinIndex(iface);
  cert_list *certs = GetCertTable(ifaceIndex);

  if (certs->count(hash) == 0)
    return (false);

  uint256 hashTx = (*certs)[hash];
  bool ret = GetTransaction(iface, hashTx, tx, NULL);
  if (!ret)
    return (false);

  if (!IsCertTx(tx)) {
    return (false);
}

  return (true);
}

#if 0
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
#endif

bool VerifyCertHash(CIface *iface, const uint160& hash)
{
  int ifaceIndex = GetCoinIndex(iface);
  cert_list *certs = GetCertTable(ifaceIndex);

  if (certs->count(hash) == 0)
    return (false);

  return (true);
}

/**
 * Obtain the block-chain tx that encapsulates a license.
 * @param hash The license hash.
 */
bool GetTxOfLicense(CIface *iface, const uint160& hash, CTransaction& tx)
{
  int ifaceIndex = GetCoinIndex(iface);
  cert_list *licenses = GetLicenseTable(ifaceIndex);

  if (licenses->count(hash) == 0)
    return (false);

  uint256 hashTx = (*licenses)[hash];
  bool ret = GetTransaction(iface, hashTx, tx, NULL);
  if (!ret)
    return (false);

  if (!IsLicenseTx(tx)) {
    return (false);
}

  return (true);
}

int init_cert_tx(CIface *iface, CWalletTx& wtx, string strAccount, string strTitle, string hexSeed, int64 nLicenseFee)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CCert *cert;

  if(strTitle.length() == 0)
    return (SHERR_INVAL);
  if(strTitle.length() > 135)
    return (SHERR_INVAL);

  int count = wallet->mapCertLabel.count(strTitle);
  if (count != 0)
    return (SHERR_NOTUNIQ);

	CTxDestination dest;
	wallet->GetAccount(strAccount)->GetPrimaryAddr(ACCADDR_EXT, dest);
	CCoinAddr addr(wallet->ifaceIndex, dest);
//  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);
  if (!addr.IsValid())
    return (SHERR_INVAL);

	CCoinAddr extAddr = wallet->GetExtAddr(strAccount);
  if (!extAddr.IsValid())
    return (SHERR_INVAL);

  /* embed cert content into transaction */
	CTxCreator s_wtx(wallet, strAccount);
  cert = s_wtx.CreateCert(ifaceIndex, strTitle.c_str(), addr, hexSeed, nLicenseFee);

  int64 nFee = GetCertOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (ERR_FEE);
  }

  uint160 certHash = cert->GetHash();

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());

  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_CERT) << OP_HASH160 << certHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
	s_wtx.AddOutput(scriptPubKey, nFee);

  /* send certificate transaction */
	if (!s_wtx.Send()) {
    error(ifaceIndex, s_wtx.GetError().c_str());
    return (SHERR_CANCELED);
  }

#if 0
  /* add as direct const reference */
  const uint160& mapHash = cert->GetHash();
  wallet->mapCert[certHash] = s_wtx.GetHash();
  wallet->mapCertLabel[cert->GetLabel()] = certHash;
#endif

	wtx = (CWalletTx)s_wtx;
  Debug("SENT:CERTNEW : title=%s, certhash=%s, tx=%s\n", strTitle.c_str(), cert->GetHash().ToString().c_str(), s_wtx.GetHash().GetHex().c_str());

  return (0);
}

int derive_cert_tx(CIface *iface, CWalletTx& wtx, const uint160& hChainCert, string strAccount, string strTitle, string hexSeed, int64 nLicenseFee)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CCert *cert;

  if(strTitle.length() == 0)
    return (SHERR_INVAL);
  if(strTitle.length() > 135)
    return (SHERR_INVAL);

  int count = wallet->mapCertLabel.count(strTitle);
  if (count != 0)
    return (SHERR_NOTUNIQ);

  CTransaction chain_tx;

  if (!GetTxOfCert(iface, hChainCert, chain_tx))
    return (SHERR_NOENT);

  CCert *chain = (CCert *)chain_tx.GetCertificate();//&chain_tx.certificate;
	if (!chain)
		return (SHERR_INVAL);

  if (!(chain->nFlag & SHCERT_CERT_SIGN)) {
    return (SHERR_INVAL);
  }

  CCoinAddr extAddr(ifaceIndex);
  if ((chain->nFlag & SHCERT_CERT_NONREPUDIATION)) {
    string strValAccount;

    extAddr = CCoinAddr(ifaceIndex, stringFromVch(chain->vAddr));
    if (!GetCoinAddr(wallet, extAddr, strValAccount)) {
      return error(SHERR_ACCESS, "derive_cert_tx: private entity warning: invalid chain certificate coin address.");
    }

		string strExtAccount = "@" + strAccount;
    if (strValAccount != strExtAccount) {
      return error(SHERR_ACCESS, "derive_cert_tx: must be certificate owner to derive 'private entity' certificate."); 
    }
  } else {
		extAddr = wallet->GetExtAddr(strAccount);
  }

  if (!chain->VerifySignature(ifaceIndex))
    return error(SHERR_INVAL, "derive_cert_tx: signature integrity error.");

	CTxDestination dest;
	wallet->GetAccount(strAccount)->GetPrimaryAddr(ACCADDR_EXT, dest);
	CCoinAddr addr(wallet->ifaceIndex, dest);
//  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);
  if (!addr.IsValid())
    return (SHERR_INVAL);


  /* embed cert content into transaction */
	CTxCreator s_wtx(wallet, strAccount);
  cert = s_wtx.DeriveCert(ifaceIndex, strTitle.c_str(), addr, chain, hexSeed, nLicenseFee);
  cert->tExpire = chain->tExpire;

  int64 nFee = GetCertOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (ERR_FEE);
  }

  uint160 certHash = cert->GetHash();

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());

  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_CERT) << OP_HASH160 << certHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
	s_wtx.AddOutput(scriptPubKey, nFee);

  /* send certificate transaction */
	if (!s_wtx.Send()) {
    error(ifaceIndex, s_wtx.GetError().c_str());
    return (SHERR_INVAL);
  }

	wtx = (CWalletTx)s_wtx;
  Debug("SENT:CERTDERIVE : title=%s, certhash=%s, tx=%s\n", strTitle.c_str(), cert->GetHash().ToString().c_str(), s_wtx.GetHash().GetHex().c_str());

  return (0);
}

/**
 * A license tranaction pays back it's fee to the address which certifies it. 
 * @param iface The coin service interface.
 * @param strAccount The coin account name to conduct the transaction with.
 * @param vchSecret Private data which is
 * @note A license is not modifable after it has been issued.
 */
int init_license_tx(CIface *iface, string strAccount, uint160 hashCert, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  CTransaction tx;
  bool hasCert = GetTxOfCert(iface, hashCert, tx);
  if (!hasCert) {
    return (SHERR_NOENT);
  }

  CCert *cert = (CCert *)tx.GetCertificate();//&tx.certificate;
	if (!cert)
		return (SHERR_INVAL);

  if (!(cert->nFlag & SHCERT_CERT_SIGN)) {
    error(SHERR_INVAL, "init_license_tx: error: origin certificate is not capable of signing.");
    return (SHERR_INVAL);
  }
  if (!(cert->nFlag & SHCERT_CERT_DIGITAL)) {
    error(SHERR_INVAL, "init_license_tx: error: origin certificate is not sufficient to grant a digital license.");
    return (SHERR_INVAL);
  }

  if (!cert->VerifySignature(ifaceIndex)) {
    error(SHERR_INVAL, "init_license_tx: error: origin certificate has invalid signature.");
    return (SHERR_INVAL);
  }

  /* destination (certificate owner) */
  CCoinAddr certAddr(ifaceIndex, stringFromVch(cert->vAddr));
  if (!certAddr.IsValid())
    return (error(SHERR_INVAL, "init_license_tx: certAddr '%s' is invalid: %s\n", certAddr.ToString().c_str(), cert->ToString().c_str()));
  
	CCoinAddr extAddr = wallet->GetExtAddr(strAccount);
  if (!extAddr.IsValid())
    return (error(SHERR_INVAL, "error generating ext account addr"));

  /* intermediate tx */
	CTxCreator int_wtx(wallet, strAccount);

  int64 nCertFee = (int64)cert->nFee;
  int64 nFee = ((int64)iface->min_tx_fee * 2) + nCertFee;

  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee)
    return (ERR_FEE);

  /* create a single [known] input to derive license from */
  CScript scriptPubKeyDest;
  scriptPubKeyDest.SetDestination(extAddr.Get());
	int_wtx.AddOutput(scriptPubKeyDest, nFee);

	if (!int_wtx.Send()) {
    error(ifaceIndex, int_wtx.GetError().c_str());
    return (SHERR_CANCELED);
  }

  /* lic tx */

  int nOut;
  if (!GetOutDestination(ifaceIndex, int_wtx, extAddr, nOut))
    return error(SHERR_INVAL, "intermediate tx lacks proper output.");

  int64 nRetFee = int_wtx.vout[nOut].nValue - (int64)iface->min_tx_fee;
  if (nRetFee < nCertFee)
    return error(SHERR_INVAL, "intermediate tx output is insufficient.");

  vector<pair<CScript, int64> > vecSend;
//  CReserveKey rkey(wallet);

  /* initialize wallet transaction */
	CTxCreator s_wtx(wallet, strAccount);

  /* initialize license */
#if 0
	CCert *cert = tx.GetCertificate();
	if (!cert)
		return (SHERR_INVAL);
#endif
  //CLicense *lic = s_wtx.CreateLicense((CCert *)&tx.certificate);
  CLicense *lic = s_wtx.CreateLicense(cert);
  if (!lic)
    return (SHERR_INVAL);
  lic->tExpire = cert->tExpire;
  lic->SetLabel(cert->GetLabel()); /* inherit title from cert */
  uint160 licHash = lic->GetHash();

	/* the intermediate tx previously created. */
	s_wtx.AddInput((CWalletTx *)&int_wtx, nOut);

  /* declare ext tx */
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_ACTIVATE << CScript::EncodeOP_N(OP_LICENSE) << OP_HASH160 << licHash << OP_2DROP << OP_RETURN;
	/* the license fee tx */
	s_wtx.AddOutput(scriptPubKey, (int64)iface->min_tx_fee, true);

  /* add licensing payment, when required */
  if (nCertFee >= (int64)iface->min_tx_fee) {
		/* this will appear first in vtx list */
    CScript scriptPubKeyFee;
    scriptPubKeyFee.SetDestination(certAddr.Get());
		s_wtx.AddOutput(scriptPubKeyFee, nCertFee, true);
//    nRetFee -= nCertFee;
  }


  /* ship 'er off */
	if (!s_wtx.Send()) {
    error(SHERR_CANCELED, "error paying certificate owner the license fee.");
    return (SHERR_CANCELED);
  }

	wtx = (CWalletTx)s_wtx;
  Debug("SENT:LICENSENEW : lichash=%s, tx=%s\n", lic->GetHash().ToString().c_str(), s_wtx.GetHash().GetHex().c_str());

  return (0);
}
#if 0
int init_license_tx(CIface *iface, string strAccount, uint160 hashCert, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  CTransaction tx;
  bool hasCert = GetTxOfCert(iface, hashCert, tx);
  if (!hasCert) {
    return (SHERR_NOENT);
  }

  CCert *cert = &tx.certificate;

  if (!(cert->nFlag & SHCERT_CERT_SIGN)) {
    error(SHERR_INVAL, "init_license_tx: error: origin certificate is not capable of signing.");
    return (SHERR_INVAL);
  }
  if (!(cert->nFlag & SHCERT_CERT_DIGITAL)) {
    error(SHERR_INVAL, "init_license_tx: error: origin certificate is not sufficient to grant a digital license.");
    return (SHERR_INVAL);
  }
#if 0
  if (!(cert->nFlag & SHCERT_CERT_CHAIN)) {
    error(SHERR_INVAL, "init_license_tx: error: origin certificate is certificate authority (must be derived).");
    return (SHERR_INVAL);
  }
#endif

  if (!cert->VerifySignature(ifaceIndex)) {
    error(SHERR_INVAL, "init_license_tx: error: origin certificate has invalid signature.");
    return (SHERR_INVAL);
  }

  /* destination (certificate owner) */
  CCoinAddr certAddr(stringFromVch(tx.certificate.vAddr));
  if (!certAddr.IsValid())
    return (error(SHERR_INVAL, "init_license_tx: certAddr '%s' is invalid: %s\n", certAddr.ToString().c_str(), tx.certificate.ToString().c_str()));
  
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);
  if (!extAddr.IsValid())
    return (error(SHERR_INVAL, "error generating ext account addr"));

  /* embed cert content into transaction */
  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */

  CCert *lic = wtx.CreateLicense(&tx.certificate);
  if (!lic) {
    return (SHERR_INVAL);
  }

  lic->tExpire = cert->tExpire;

  /* inherit title from cert */
  lic->SetLabel(cert->GetLabel());

  int64 nCertFee = lic->nFee;
  int64 nOpFee = MAX(iface->min_tx_fee, 
      GetCertOpFee(iface, GetBestHeight(iface)));
  int64 nTxFee =  nOpFee + nCertFee;
  nTxFee = MAX(iface->min_tx_fee, nTxFee);

  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nTxFee)
    return (SHERR_AGAIN);

  /* send to extended tx storage account */
  uint160 licHash = lic->GetHash();

  /* send license tx to intermediate address */
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_ACTIVATE << CScript::EncodeOP_N(OP_LICENSE) << OP_HASH160 << licHash << OP_2DROP;
  if (nCertFee >= (int64)iface->min_tx_fee) {
    CScript scriptPubKeyDest;
    scriptPubKeyDest.SetDestination(extAddr.Get());
    scriptPubKey += scriptPubKeyDest;
  } else {
    /* no fee required */
    scriptPubKey << OP_RETURN;
  }

  string certStrError = wallet->SendMoney(scriptPubKey, nTxFee, wtx, false);
  if (certStrError != "") {
    error(ifaceIndex, certStrError.c_str());
    return (SHERR_CANCELED);
  }

  if (nCertFee >= (int64)iface->min_tx_fee) {
    int nTxOut = 0; /* tx only had one output */
    CWalletTx l_wtx;
    vector<pair<CScript, int64> > vecSend;

    l_wtx.SetNull();
    l_wtx.strFromAccount = strAccount;
    CScript scriptPubKeyFee;
    scriptPubKeyFee.SetDestination(certAddr.Get());
    vecSend.push_back(make_pair(scriptPubKeyFee, nCertFee));

//    CReserveKey rkey(wallet);
    int64 nRetFee = MAX(iface->min_tx_fee, wtx.vout[0].nValue - nCertFee);
    if (!CreateTransactionWithInputTx(iface, strAccount,
          vecSend, wtx, nTxOut, l_wtx, nRetFee) ||
        !wallet->CommitTransaction(l_wtx)) {
      error(SHERR_CANCELED, "error paying certificate owner the license fee.");
      return (SHERR_CANCELED);
    }
  }

  Debug("SENT:LICENSENEW : lichash=%s, tx=%s\n", lic->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}
#endif


static void FillSharenetCertificate(SHCert *cert, CCert *c_cert, CCert *iss)
{
  int err;

  memset(cert, 0, sizeof(SHCert));

  /* core attributes */
  if (iss) {
    err = shesig_init(cert, (char *)c_cert->GetLabel().c_str(), SHALG_ECDSA160R, c_cert->nFlag);
  } else {
    err = shesig_ca_init(cert, (char *)c_cert->GetLabel().c_str(), SHALG_ECDSA160R, c_cert->nFlag);
  }
  if (err) {
    shcoind_err(err, "shesig_init", (char *)c_cert->GetLabel().c_str());
    return;
  }

  /* certificate version */
  shesig_version_set(cert, c_cert->GetVersion());

  /* serial number */
  shesig_serial_set(cert, c_cert->vContext.data(), c_cert->vContext.size()); 

  /* expiration time-stamp */
  shesig_expire_set(cert, c_cert->tExpire); 

  /* prepare public key */
  const string& pubkey_str = stringFromVch(c_cert->signature.vPubKey);
  cbuff vchContext = ParseHex(pubkey_str);
  memcpy(cert->pub, vchContext.data(), vchContext.size());
  shalg_size(cert->pub) = vchContext.size();

  {
    /* prepare signature */
    memset(cert->data_sig, 0, sizeof(cert->data_sig));
    const string& sig_r_str = stringFromVch(c_cert->signature.vSig[0]);
    const string& sig_s_str = stringFromVch(c_cert->signature.vSig[1]);
    cbuff vchContext_r = ParseHex(sig_r_str);
    cbuff vchContext_s = ParseHex(sig_s_str);
    memcpy(cert->data_sig, vchContext_r.data(), vchContext_r.size());
    memcpy((unsigned char *)cert->data_sig + vchContext_r.size(), vchContext_s.data(), vchContext_s.size());
    shalg_size(cert->data_sig) = vchContext_r.size() + vchContext_s.size();
  }

  shtime_t now = shtime();
  if (!shtime_after(now, cert->stamp)) { 
}



  shalg_t iss_pub;
  memset(iss_pub, 0, sizeof(iss_pub));
  if (iss) {
    const string& iss_label = iss->GetLabel();

    const string& pubkey_str = stringFromVch(iss->signature.vPubKey);
    shhex_bin((char *)pubkey_str.c_str(), (unsigned char *)iss_pub, pubkey_str.size()/2);
    shalg_size(iss_pub) = pubkey_str.size()/2;
    
    err = shesig_import(cert, (char *)iss_label.c_str(), iss_pub);
  } else {
    err = shesig_import(cert, NULL, iss_pub);
  }
  if (err) {
    shcoind_err(err, "shesig_import", c_cert->GetLabel().c_str());
    return;
  }

}

int CCertCore::VerifyTransaction()
{
  int err;

  err = CEntity::VerifyTransaction();
  if (err)
    return (err);

  return (0);
}

std::string CCertCore::ToString()
{
  return (write_string(Value(ToValue()), false));
}

#if 0
void CCert::NotifySharenet(int ifaceIndex)
{
  SHCert cert;
  char tag[SHFS_PATH_MAX];
  shbuf_t *buff;
  int err;

  /* only applies to ShionCoin block-chain transaction */
  if (ifaceIndex != SHC_COIN_IFACE)
    return;

  CCert *iss = NULL;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTransaction tx;
  if (GetTxOfCert(iface, hashIssuer, tx)) {
    iss = &tx.certificate;
  }


  memset(&cert, 0, sizeof(shesig_t));
  FillSharenetCertificate(&cert, this, iss);

#if 0
  sprintf(tag, "alias/%s", GetLabel().c_str());
  err = shfs_cert_save(&cert, tag);
  if (err) {
    error(SHERR_INVAL, "error saving cert '%s'", tag);
  }
#endif

}
void CLicense::NotifySharenet(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled) return;
  shbuf_t *buff;
  char tag[SHFS_PATH_MAX];
  char sig_r[256];
  char sig_s[256];
  int err;
  int i;

#if 0
/* DEBUG: */
  /* only applies to ShionCoin block-chain transaction */
  if (ifaceIndex != SHC_COIN_IFACE)
    return;
#endif

  uint160 hLic = GetHash();
  shkey_t *pubkey;
  SHLicense lic;
  SHCert cert;
  SHCert pcert;

  memset(&lic, 0, sizeof(lic));


  /* relay license to sharenet */
  CCert *iss = NULL;
  CTransaction tx;
  if (GetTxOfCert(iface, hashIssuer, tx))
    iss = &tx.certificate;


  memset(&cert, 0, sizeof(cert));
  FillSharenetCertificate(&cert, this, iss);


#if 0
  memset(&pcert, 0, sizeof(pcert));
  FillSharenetCertificate(&pcert, iss, NULL);

  buff = shbuf_init();
  shbuf_cat(buff, &cert, sizeof(shesig_t));
  err = shesig_save(&cert, buff);
  shbuf_free(&buff);
#endif

#if 0
  memset(&lic, 0, sizeof(lic));
  memcpy(&lic.lic_ctx, hLic.GetKey(), sizeof(lic.lic_ctx));
  lic.lic_expire = tExpire; 

  shnet_inform(iface, TX_LICENSE, (char *)&lic, sizeof(shlic_t));
#endif

}
#endif

#if 0
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

#if 0
  /* sent to intermediate account. */
  CReserveKey rkey(wallet);
  t_wtx.strFromAccount = strAccount;
#endif

  //CPubKey vchPubKey = rkey.GetReservedKey();
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(addr.Get());
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_IDENT) << OP_HASH160 << hashIdent << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
//  string strError = wallet->SendMoney(scriptPubKey, nValue, t_wtx, false);

#if 0
  int64 nFeeRequired = 0;
  if (!wallet->CreateTransaction(scriptPubKey, nValue, t_wtx, rkey, nFeeRequired)) {
    return (SHERR_CANCELED);
}

  if (!wallet->CommitTransaction(t_wtx)) {
    return (SHERR_CANCELED);
}
#endif
  if (!t_wtx.AddOutput(scriptPubKey, nValue, true))
    return SHERR_CANCELED;
  if (!t_wtx.Send())
    return (SHERR_CANCELED);

  /* second tx */
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
  s_wtx.CreateIdent(ident);
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

  if (!s_wtx.Send())
    return (SHERR_CANCELED);

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
  CCert *s_cert = tx.GetCertificate();
  CIdent *ident = s_wtx.CreateIdent(s_cert);
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
#endif

/**
 * Generate a signature unique to this identify in relation to an external context. Only call after the "origin" signature has been generated.
 * @param vchSecret The external context that the signature was generated from.
 * @note In contrast to the CExtCore.origin field; this signature is meant specifically to reference external information as opposed to internally generated context.
 * @see CExtCore.origin
 */
bool CCert::Sign(int ifaceIndex, CCoinAddr& addr, cbuff vchContext, string hexSeed) 
{
  shkey_t *kpriv;
  bool ret;

  if (!hashIssuer.IsNull())
    nFlag |= SHCERT_CERT_CHAIN; 

  if (!signature.Sign(ifaceIndex, addr, vchContext, hexSeed))
    return error(SHERR_INVAL, "CSign::Sign: error signing with addr '%s'\n", addr.ToString().c_str());
;

  vAddr = vchFromString(addr.ToString());
  return (true);
}

#if 0
bool CCert::Sign(int ifaceIndex, CCoinAddr& addr)
{
  cbuff vchSecret(hashIssuer.begin(), hashIssuer.end());
  return (Sign(ifaceIndex, addr, vchSecret));
}
#endif

/**
 * Verify an identity's signature.
 * @param vchSecret The external context that the signature was generated from.
 */
bool CCert::VerifySignature(int ifaceIndex, cbuff vchContext)
{
  unsigned char *raw = (unsigned char *)vchContext.data();
  size_t raw_len = vchContext.size();
  CCoinAddr addr(ifaceIndex, stringFromVch(vAddr));

  if (GetVersion() == 1 && hashIssuer.IsNull())
    return (true);

  return (signature.Verify(addr, vchContext.data(), vchContext.size()));
}

bool CCert::VerifySignature(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTransaction cert_tx;
  
  cbuff vchContext;
  if (!hashIssuer.IsNull()) {
    if (!GetTxOfCert(iface, hashIssuer, cert_tx))
      return error(SHERR_INVAL, "CCert.VerifySignature: unknown hashissuer cert '%s'.", hashIssuer.GetHex().c_str());

    string hexContext = stringFromVch(cert_tx.certificate.signature.vPubKey);
    vchContext = ParseHex(hexContext);
  }

  return (VerifySignature(ifaceIndex, vchContext));
}


#if 0
bool CCert::VerifySignature()
{
  cbuff vchSecret(hashIssuer.begin(), hashIssuer.end());
  return (VerifySignature(vchSecret));
}
#endif

/**
 * verify whether ext account used to generate certificate tx is owned by us.
 * @param strAccount optionally restrict the condition to a specific account name.
 */
bool CCert::IsSignatureOwner(string strAccount)
{
//  bool IsLocalCert(CIface *iface, const CTxOut& txout) 
/* TODO: */
return (false);
}

/**
 * Verifies whether a particular private key seed is valid.
 */ 
bool CCert::VerifySignatureSeed(string hexSeed)
{
  return (signature.VerifySeed(hexSeed));
}

#if 0
std::string CIdent::ToString()
{
  return (write_string(Value(ToValue()), false));
}
#endif

std::string CCert::ToString()
{
  return (write_string(Value(ToValue()), false));
}

std::string CLicense::ToString()
{
  return (write_string(Value(ToValue()), false));
}

#if 0
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
#endif

int CCert::VerifyTransaction()
{
  int err;

  err = CCertCore::VerifyTransaction();
  if (err)
    return (err);

  return (0);
}

Object CCertCore::ToValue()
{
  Object obj = CEntity::ToValue();

  return (obj);
}

Object CCert::ToValue()
{
  Object obj = CCertCore::ToValue();

  obj.push_back(Pair("certhash", GetHash().GetHex()));
  if (hashIssuer.size() != 0)
    obj.push_back(Pair("issuer", hashIssuer.GetHex()));
  if (vContext.size() != 0)
    obj.push_back(Pair("serialno", GetSerialNumber().c_str()));
  if (nFee != 0)
    obj.push_back(Pair("fee", ValueFromAmount(nFee)));
  if (nFlag != 0)
    obj.push_back(Pair("flags", nFlag));

  obj.push_back(Pair("signature", signature.GetHash().GetHex()));
  if (signature.vPubKey.size() != 0)
    obj.push_back(Pair("sigpubkey", stringFromVch(signature.vPubKey)));
  
  return (obj);
}

Object CLicense::ToValue()
{
  Object obj = CCertCore::ToValue();
  obj.push_back(Pair("hash", GetHash().GetHex()));
  return (obj);
}

bool CLicense::Sign(CCert *cert)
{
	if (!cert) return (false);
  string hexContext = stringFromVch(cert->signature.vPubKey);
  cbuff vchContext = ParseHex(hexContext);

  nFlag |= SHCERT_CERT_CHAIN; 
  return (signature.SignContext(vchContext));
}

bool CLicense::Sign(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTransaction cert_tx;

  if (!GetTxOfCert(iface, hashIssuer, cert_tx))
    return (false);

  return (Sign(cert_tx.GetCertificate()));
}

bool CLicense::VerifySignature(int ifaceIndex, CCert *cert)
{
  string hexContext = stringFromVch(cert->signature.vPubKey);
  cbuff vchContext = ParseHex(hexContext);
  return (signature.VerifyContext(vchContext.data(), vchContext.size()));
}

bool CLicense::VerifySignature(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTransaction cert_tx;

  if (!GetTxOfCert(iface, hashIssuer, cert_tx))
    return error(SHERR_INVAL, "VerifySIgnature");

  return (VerifySignature(ifaceIndex, (CCert *)&cert_tx.certificate));
}

bool DisconnectCertificate(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  CCert *cert = (CCert *)&tx.certificate;
  const uint160 hCert = cert->GetHash();

  if (wallet->mapCert.count(hCert) == 0)
    return (false);

  const uint256& o_tx = wallet->mapCert[hCert];
  if (o_tx != tx.GetHash())
    return (false);

/* NOTE: order matters here. last = best */
  uint256 n_tx;
  bool found = false;
  for(map<uint256,uint160>::iterator it = wallet->mapCertArch.begin(); it != wallet->mapCertArch.end(); ++it) {
    const uint256& hash2 = (*it).first;
    const uint160& hash1 = (*it).second;
    if (hash1 == hCert) {
      n_tx = hash2;
      found = true;
    }
  }
  
  if (found) {
    /* transition current entry to archive */
    const uint160& o_cert = hCert;
    wallet->mapCertArch[o_tx] = o_cert;

    wallet->mapCert[hCert] = n_tx; 
    wallet->mapCertLabel[cert->GetLabel()] = hCert;
  } else {
    wallet->mapCert.erase(hCert);
    wallet->mapCertLabel.erase(cert->GetLabel());
  }

  return (true);
}


