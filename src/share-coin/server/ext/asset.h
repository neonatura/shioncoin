
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

#ifndef __ASSET_H__
#define __ASSET_H__




/**
 * An asset is treated as a specific type of certification.
 * @note An asset is not capable of additional context data being stored.
 */
class CAsset : public CCert
{

  public:
    CAsset()
    {
      SetNull();
    }

    CAsset(const CCert& certIn)
    {
      SetNull();
      CCert::Init(certIn);
    }

    CAsset(const CAsset& assetIn)
    {
      SetNull();
      Init(assetIn);
    }

    CAsset(string labelIn)
    {
      SetNull();
      SetLabel(labelIn);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(*(CCert *)this);
    )

    void SetNull()
    {
      CCert::SetNull();
    }

    void Init(const CAsset& assetIn)
    {
      CCert::Init(assetIn);
    }

    friend bool operator==(const CAsset &a, const CAsset &b)
    {
      return (
        ((CCert&) a) == ((CCert&) b)
      );
    }

    CAsset operator=(const CAsset &b)
    {
      Init(b);
      return (*this);
    }

    bool Sign(CCert *cert);

    bool Sign(int ifaceIndex);

    bool VerifySignature(CCert *cert);

    bool VerifySignature(int ifaceIndex);

    bool Sign(uint160 sigCertIn);

    bool VerifySignature();

    const uint160 GetHash()
    {
      uint256 hashOut = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hashOut;
      cbuff rawbuf(raw, raw + sizeof(hashOut));
      return Hash160(rawbuf);
    }

    std::string ToString();

    Object ToValue();

};

bool VerifyAsset(CTransaction& tx);


int init_asset_tx(CIface *iface, string strAccount, string strTitle, string strHash, CWalletTx& wtx);

int update_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, string strTitle, string strHash, CWalletTx& wtx);

int activate_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, const uint160& hashCert, CWalletTx& wtx);

int remove_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, CWalletTx& wtx);




#endif /* ndef __ASSET_H__ */


