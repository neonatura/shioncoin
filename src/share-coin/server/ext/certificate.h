
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

#ifndef __SERVER__CERTIFICATE_H__
#define __SERVER__CERTIFICATE_H__






class CIdent : public CExtCore
{
  public:
    shgeo_t geo;
    cbuff vAddr;
    unsigned int nType;

//    cbuff vChain;

    CIdent()
    {
      SetNull();
    }

    CIdent(const CIdent& ent)
    {
      SetNull();
      Init(ent);
    }

    CIdent(string labelIn)
    {
      SetNull();
      SetLabel(labelIn);
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(*(CExtCore *)this);
        READWRITE(FLATDATA(geo));
        READWRITE(this->vAddr);
        READWRITE(this->nType);
    )

    friend bool operator==(const CIdent &a, const CIdent &b)
    {
      return (
          ((CExtCore&) a) == ((CExtCore&) b) &&
          0 == memcmp(&a.geo, &b.geo, sizeof(shgeo_t)) &&
          a.nType == b.nType &&
          a.vAddr == b.vAddr
          );
    }

    CIdent operator=(const CIdent &b)
    {
      SetNull();
      Init(b);
      return *this;
    }

    void SetNull()
    {
      CExtCore::SetNull();
      memset(&geo, 0, sizeof(geo));
      vAddr.clear();
      nType = 0;
    }

    void Init(const CIdent& b)
    {
      CExtCore::Init(b);
      memcpy(&geo, &b.geo, sizeof(geo));
      vAddr = b.vAddr;
      nType = b.nType;
    }


/*
    uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }
*/



    bool IsLocalRegion()
    {
      shgeo_t lcl_geo;
      bool ret = false;

      memset(&lcl_geo, 0, sizeof(lcl_geo));
      shgeo_local(&lcl_geo, SHGEO_PREC_REGION);
      if (shgeo_cmp(&geo, &lcl_geo, SHGEO_PREC_REGION))
        ret = true;

      return (ret);
    }

    void SetType(int nTypeIn)
    {
      nType = nTypeIn;
    }

    unsigned int GetType()
    {
      return (nType);
    }

    uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    std::string ToString();

    Object ToValue();

};

class CCert : public CIdent
{
  public:
    static const int CERTF_CHAIN = SHCERT_CERT_CHAIN;

    uint160 hashIssuer;
    CSign signature;
    cbuff vContext;
    int64 nFee;
    int nFlag;

    CCert()
    {
      SetNull();
    }

    CCert(const CIdent& identIn)
    {
      SetNull();
      CIdent::Init(identIn);
    }

    CCert(const CCert& certIn)
    {
      SetNull();
      Init(certIn);
    }

    /**
     * Create a certificate authority.
     * @param hashEntity The entity being issued a certificate.
     * @param vSer A 16-byte (128-bit) serial number.
     */
    CCert(string strTitle)
    {
      SetNull();
      SetLabel(strTitle);
    }

    bool SetIssuer(CCert& issuer)
    {

      if (issuer.nFlag & CERTF_CHAIN)
        return (false); /* cannot chain a chain'd cert */

      nFlag |= CERTF_CHAIN;
      hashIssuer = issuer.GetHash();
      return (true);
    }

    void SetFee(int64 nFeeIn)
    {
      nFee = (uint64_t)nFeeIn; 
    }

    void SetSerialNumber()
    {
      SetSerialNumber(GenerateSerialNumber());
    }

    void SetSerialNumber(cbuff vSerialIn)
    {
      vContext = vSerialIn;
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(*(CIdent *)this);
        READWRITE(this->hashIssuer);
        READWRITE(this->signature);
        READWRITE(this->vContext);
        READWRITE(this->nFee);
        READWRITE(this->nFlag);
    )

    void Init(const CCert& b)
    {
      CIdent::Init(b);
      hashIssuer = b.hashIssuer;
      signature = b.signature;
      vContext = b.vContext;
      nFee = b.nFee;
      nFlag = b.nFlag;
    }

    friend bool operator==(const CCert &a, const CCert &b) {
      return (
          ((CIdent&) a) == ((CIdent&) b) &&
          a.hashIssuer == b.hashIssuer &&
          a.signature == b.signature &&
          a.vContext == b.vContext &&
          a.nFee == b.nFee &&
          a.nFlag == b.nFlag
          );
    }

    CCert operator=(const CCert &b) {
      Init(b);
      return *this;
    }

    friend bool operator!=(const CCert &a, const CCert &b) {
      return !(a == b);
    }

    void SetNull()
    {
      CIdent::SetNull();
      signature.SetNull();
      vContext.clear();

      nVersion = 3;
      nFee = 0;

      /* x509 prep */
      nFlag = SHCERT_ENT_ORGANIZATION | SHCERT_CERT_DIGITAL | SHCERT_CERT_SIGN;
    }

    int GetFlags()
    {
      return (nFlag);
    }

    int64 GetFee()
    {
      return (nFee);
    }

    /* a 128-bit binary context converted into a 160bit hexadecimal number. */
    std::string GetSerialNumber()
    {
      return (HexStr(vContext));
    }

    uint160 GetIssuerHash()
    {
      return (hashIssuer);
    }

    uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    /**
     * @note The signature does not take into account the geo-detic address (although the underlying certificate hash does).
     */
    bool Sign(int ifaceIndex, CCoinAddr& addr, cbuff vchContext, string hexSeed = string());

    bool Sign(int ifaceIndex, CCoinAddr& addr, CCert *cert, string hexSeed = string())
    {
      string hexContext = stringFromVch(cert->signature.vPubKey);
      return (Sign(ifaceIndex, addr, ParseHex(hexContext), hexSeed));
    }


    /**
     * Verify the integrity of a signature against some context.
     */
    bool VerifySignature(cbuff vchContext);

    /**
     * Verify the integrity of a signature against the pubkey of specific cert.
     */
    bool VerifySignature(CCert *cert)
    {
      return (VerifySignature(cert->signature.vPubKey));
    }

    /**
     * Verify the integrity of a signature against the pubkey of chained cert.
     */
    bool VerifySignature(int ifaceIndex);

    bool IsSignatureOwner(string strAccount = string());

    bool VerifySignatureSeed(string hexSeed);

    /**
     * Create a randomized serial number suitable for a certificate.
     */
    static cbuff GenerateSerialNumber()
    {
      static unsigned char raw[32];
      uint64_t *v = (uint64_t *)raw;

      v[0] = shrand();
      v[1] = shrand();

      return (cbuff(raw, raw+16));
    }

    void NotifySharenet(int ifaceIndex);

    std::string ToString();

    Object ToValue();

};

/**
 * A license is a specific type of certification.
 * @note A license is not capable of having contextual data.
 */
class CLicense : public CCert
{
  public:
    CLicense()
    {
      SetNull();
    }

    CLicense(const CLicense& lic)
    {
      SetNull();
      Init(lic);
    }

    CLicense(const CCert& cert)
    {
      SetNull();
      CCert::Init(cert);
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(*(CCert *)this);
    )

    void SetNull()
    {
      CCert::SetNull();
      nFlag |= SHCERT_CERT_LICENSE;
    }

    friend bool operator==(const CLicense &a, const CLicense &b) {
      return (
          ((CCert&) a) == ((CCert&) b)
          );
    }

    CLicense operator=(const CLicense &b) 
    {
      Init(b);
      return *this;
    }

    friend bool operator!=(const CLicense &a, const CLicense &b) {
      return !(a == b);
    }

    void Init(const CLicense& b)
    {
      CCert::Init(b);
    }

    bool Sign(CCert *cert);

    bool Sign(int ifaceIndex);

    bool VerifySignature(CCert *cert);

    bool VerifySignature(int ifaceIndex);


    const uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    void NotifySharenet(int ifaceIndex);

    std::string ToString();

    Object ToValue();

};

class CWalletTx;


bool VerifyCert(CIface *iface, CTransaction& tx, int nHeight);

int64 GetCertOpFee(CIface *iface, int nHeight);

int init_cert_tx(CIface *iface, CWalletTx& wtx, string strAccount, string strTitle, string hexSeed = string(), int64 nLicenseFee = 0);

int derive_cert_tx(CIface *iface, CWalletTx& wtx, const uint160& hChainCert, string strAccount, string strTitle, string hexSeed = string(), int64 nLicenseFee = 0);

int init_ident_stamp_tx(CIface *iface, string strAccount, string strComment, CWalletTx& wtx);

int init_license_tx(CIface *iface, string strAccount, uint160 hashCert, CWalletTx& wtx);


bool VerifyLicense(CTransaction& tx);

bool VerifyCertHash(CIface *iface, const uint160& hash);

extern bool GetTxOfCert(CIface *iface, const uint160& hash, CTransaction& tx);

extern bool GetTxOfLicense(CIface *iface, const uint160& hash, CTransaction& tx);

extern int init_ident_donate_tx(CIface *iface, string strAccount, uint64_t nValue, uint160 hashCert, CWalletTx& wtx);

extern int init_ident_certcoin_tx(CIface *iface, string strAccount, uint64_t nValue, uint160 hashCert, CCoinAddr addrDest, CWalletTx& wtx);

extern bool VerifyIdent(CTransaction& tx, int& mode);

int GetTotalCertificates(int ifaceIndex);

cert_list *GetCertTable(int ifaceIndex);

cert_list *GetIdentTable(int ifaceIndex);

cert_list *GetLicenseTable(int ifaceIndex);

bool IsCertTx(const CTransaction& tx);

bool IsLicenseTx(const CTransaction& tx);

bool InsertCertTable(CIface *iface, CTransaction& tx, unsigned int nHeight, bool fUpdate = true);

bool GetCertAccount(CIface *iface, const CTransaction& tx, string& strAccount);

bool IsCertAccount(CIface *iface, CTransaction& tx, string strAccount);

bool DisconnectCertificate(CIface *iface, CTransaction& tx);

bool GetCertByName(CIface *iface, string name, CCert& cert);

bool GetTxOfIdent(CIface *iface, const uint160& hash, CTransaction& tx);

bool InsertIdentTable(CIface *iface, CTransaction& tx);

bool CommitLicenseTx(CIface *iface, CTransaction& tx, int nHeight);

bool VerifyLicenseChain(CIface *iface, CTransaction& tx);





#endif /* ndef __SERVER__CERTIFICATE_H__ */


