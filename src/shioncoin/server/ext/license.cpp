
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

cert_list *GetLicenseTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapLicense);
}

bool CommitLicenseTx(CIface *iface, CTransaction& tx, int nHeight)
{
  CWallet *wallet = GetWallet(iface);
  CTransaction cert_tx;
  bool fUpdate = true;

  if (!wallet)
    return (false);

  if (!tx.VerifyLicense(iface))
    return error(SHERR_INVAL, "CommitLicenseTx: !VerifyLicense\n");

	CLicense *lic = tx.GetLicense();
	if (!lic)
		return (false);

#if 0
  if (!VerifyLicenseChain(iface, tx))
    return error(SHERR_INVAL, "CommitLicenseTx: chain verification failure.");
#endif

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

int64 GetLicenseOpFee(CIface *iface)
{
	CTransaction tx;
	uint160 hCert;

	bool hasCert = GetTxOfCert(iface, hCert, tx);
	if (!hasCert) {
		return (0); /* error */
	}

	CCert *cert = (CCert *)tx.GetCertificate();
	if (!cert)
		return (0); /* error */

	int64 nCertFee = (int64)cert->nFee;
  int64 nFee = ((int64)MIN_TX_FEE(iface) * 2) + nCertFee;

	return (nFee);
}

std::string CLicense::ToString()
{
  return (write_string(Value(ToValue()), false));
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

int64 CLicense::CalculateFee(CIface *iface)
{
	return (GetLicenseOpFee(iface));
}

int CLicense::VerifyTransaction()
{
	int err;

  err = CCertCore::VerifyTransaction();
  if (err)
    return (err);

	if (!(nFlag & SHCERT_CERT_CHAIN)) {
		return (ERR_ACCESS);
	}

	return (0);
}

#if 0
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
#endif

#if 0
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
