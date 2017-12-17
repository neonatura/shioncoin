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


#ifndef __SERVER__BASE58_H__
#define __SERVER__BASE58_H__

#include <string>
#include <vector>
#include "bignum.h"
#include "key.h"
#include "script.h"


// Encode a byte sequence as a base58-encoded string
std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend);



// Decode a base58-encoded string psz into byte vector vchRet
// returns true if decoding is successful
bool DecodeBase58(const char* psz, std::vector<unsigned char>& vchRet);


// Decode a base58-encoded string str into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}

// Encode a byte vector as a base58-encoded string
inline std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}



// Encode a byte vector to a base58-encoded string, including checksum
inline std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

// Decode a base58-encoded string psz that includes a checksum, into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet))
        return false;
    if (vchRet.size() < 4)
    {
        vchRet.clear();
        return false;
    }
    uint256 hash = Hash(vchRet.begin(), vchRet.end()-4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0)
    {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size()-4);
    return true;
}

// Decode a base58-encoded string str that includes a checksum, into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}





/** Base class for all base58-encoded data */
class CBase58Data
{
protected:
    // the version byte
    unsigned char nVersion;

    // the actually encoded data
    std::vector<unsigned char> vchData;

    CBase58Data()
    {
        nVersion = 0;
        vchData.clear();
    }

    ~CBase58Data()
    {
        // zero the memory, as it may contain sensitive data
        if (!vchData.empty())
            memset(&vchData[0], 0, vchData.size());
    }

    void SetData(int nVersionIn, const void* pdata, size_t nSize)
    {
        nVersion = nVersionIn;
        vchData.resize(nSize);
        if (!vchData.empty())
            memcpy(&vchData[0], pdata, nSize);
    }

    void SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend)
    {
        SetData(nVersionIn, (void*)pbegin, pend - pbegin);
    }

public:
    bool SetString(const char* psz)
    {
        std::vector<unsigned char> vchTemp;
        DecodeBase58Check(psz, vchTemp);
        if (vchTemp.empty())
        {
            vchData.clear();
            nVersion = 0;
            return (error(SHERR_INVAL, "CBase58Data.SetString: failure decoding \"%s\".", psz));
        }
        nVersion = vchTemp[0];
        vchData.resize(vchTemp.size() - 1);
        if (!vchData.empty())
            memcpy(&vchData[0], &vchTemp[1], vchData.size());

        /* wipe physical memory. note OPENSSL_cleanse() is an alternative. */
        memset(&vchTemp[0], 0, vchTemp.size());
        return true;
    }

    bool SetString(const std::string& str)
    {
        return SetString(str.c_str());
    }

    int GetVersion() const
    {
      return (nVersion);
    }

    std::string ToString() const
    {
        std::vector<unsigned char> vch(1, nVersion);
        vch.insert(vch.end(), vchData.begin(), vchData.end());
        return EncodeBase58Check(vch);
    }

    int CompareTo(const CBase58Data& b58) const
    {
        if (nVersion < b58.nVersion) return -1;
        if (nVersion > b58.nVersion) return  1;
        if (vchData < b58.vchData)   return -1;
        if (vchData > b58.vchData)   return  1;
        return 0;
    }

    bool operator==(const CBase58Data& b58) const { return CompareTo(b58) == 0; }
    bool operator<=(const CBase58Data& b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const CBase58Data& b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const CBase58Data& b58) const { return CompareTo(b58) <  0; }
    bool operator> (const CBase58Data& b58) const { return CompareTo(b58) >  0; }
};

class CCoinAddr;

class CCoinAddrVisitor : public boost::static_visitor<bool>
{
private:
    CCoinAddr *addr;
public:
    CCoinAddrVisitor(CCoinAddr *addrIn) : addr(addrIn) { }
    bool operator()(const CKeyID &id) const;
    bool operator()(const CScriptID &id) const;
    bool operator()(const CNoDestination &no) const;
};

/** base58-encoded coin addresses.
 * Public-key-hash-addresses have various versions per coin.
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 for all coin services.
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 */
class CCoinAddr : public CBase58Data
{
public:
    enum
    {
        PUBKEY_ADDRESS = 38,
        PUBKEY_E_ADDRESS = 33,
        PUBKEY_S_ADDRESS = 62,
        SCRIPT_ADDRESS = 5,
        PUBKEY_ADDRESS_TEST = 111,
        SCRIPT_ADDRESS_TEST = 196,
    };

    mutable int ifaceIndex;

    static int GetCoinAddrVersion(int ifaceIndex)
    {

      switch (ifaceIndex) {
        case SHC_COIN_IFACE:
          return (PUBKEY_S_ADDRESS);
        case EMC2_COIN_IFACE:
          return (PUBKEY_E_ADDRESS);
      }

      return (PUBKEY_ADDRESS);
    }

    bool Set(const CKeyID &id) {
        int ver = PUBKEY_ADDRESS;
        if (ifaceIndex != 0) ver = GetCoinAddrVersion(ifaceIndex);
        SetData(ver, &id, 20);
        //SetData(GetCoinAddrVersion(ifaceIndex), &id, 20);
        //SetData(fTestNet ? PUBKEY_ADDRESS_TEST : PUBKEY_ADDRESS, &id, 20);
        return true;
    }

    bool Set(const CScriptID &id) {
        SetData(SCRIPT_ADDRESS, &id, 20);
        return true;
    }

    bool Set(const CTxDestination &dest)
    {
        return boost::apply_visitor(CCoinAddrVisitor(this), dest);
    }

    bool IsValid() const;

    CCoinAddr(int ifaceIndexIn)
    {
      ifaceIndex = ifaceIndexIn;
    }

    CCoinAddr(int ifaceIndexIn, const CTxDestination &dest)
    {
      ifaceIndex = ifaceIndexIn;
      Set(dest);
    }

    CCoinAddr(const CScriptID& scriptIn)
    {
      ifaceIndex = 0;
      Set(scriptIn);
    }

    CCoinAddr(const std::string& strAddress)
    {
      ifaceIndex = 0;
      SetString(strAddress);
    }

    CCoinAddr(const char* pszAddress)
    {
      ifaceIndex = 0;
      SetString(pszAddress);
    }

    CTxDestination Get() const;
    bool GetKeyID(CKeyID &keyID) const;
    bool GetScriptID(CScriptID &scriptID) const;

    bool IsScript() const 
    {
      if (!IsValid())
        return false;
      switch (nVersion) {
        case SCRIPT_ADDRESS:
        case SCRIPT_ADDRESS_TEST: {
                                    return true;
                                  }
        default: return false;
      }
    }

};

bool inline CCoinAddrVisitor::operator()(const CKeyID &id) const         { return addr->Set(id); }
bool inline CCoinAddrVisitor::operator()(const CScriptID &id) const      { return addr->Set(id); }
bool inline CCoinAddrVisitor::operator()(const CNoDestination &id) const { return false; }

class EMC2CoinAddr : public CCoinAddr
{
  public:
    EMC2CoinAddr() : CCoinAddr(EMC2_COIN_IFACE)
    {
    }

    EMC2CoinAddr(const CTxDestination &dest) : CCoinAddr(EMC2_COIN_IFACE)
    {
      Set(dest);
    }
};
class SHCCoinAddr : public CCoinAddr
{
  public:
    SHCCoinAddr() : CCoinAddr(SHC_COIN_IFACE)
    {
    }

    SHCCoinAddr(const CTxDestination &dest) : CCoinAddr(SHC_COIN_IFACE)
    {
      Set(dest);
    }
};
class USDECoinAddr : public CCoinAddr
{
  public:
    USDECoinAddr() : CCoinAddr(USDE_COIN_IFACE)
    {
    }

    USDECoinAddr(const CTxDestination &dest) : CCoinAddr(USDE_COIN_IFACE)
    {
      Set(dest);
    }
};

/** A base58-encoded secret key */
class CCoinSecret : public CBase58Data
{
public:
#if 0
    enum
    {
        PRIVKEY_ADDRESS = CCoinAddr::PUBKEY_ADDRESS + 128,
        PRIVKEY_ADDRESS_TEST = CCoinAddr::PUBKEY_ADDRESS_TEST + 128,
    };
#endif

    void SetSecret(int ifaceIndex, const CSecret& vchSecret, bool fCompressed)
    { 
      int PRIVKEY_ADDRESS = (CCoinAddr::GetCoinAddrVersion(ifaceIndex) + 128);
      assert(vchSecret.size() == 32);
      SetData(PRIVKEY_ADDRESS, &vchSecret[0], vchSecret.size());
      //SetData(fTestNet ? PRIVKEY_ADDRESS_TEST : PRIVKEY_ADDRESS, &vchSecret[0], vchSecret.size());
      if (fCompressed)
        vchData.push_back(1);
    }

    CSecret GetSecret(bool &fCompressedOut)
    {
        CSecret vchSecret;
        vchSecret.resize(32);
        memcpy(&vchSecret[0], &vchData[0], 32);
        fCompressedOut = vchData.size() == 33;
        return vchSecret;
    }

    bool SetString(const char* pszSecret);

    bool SetString(const std::string& strSecret);

    bool IsValid() const
    {
#if 0
        bool fExpectTestNet = false;
        switch(nVersion)
        {
            case PRIVKEY_ADDRESS:
                break;

            case PRIVKEY_ADDRESS_TEST:
                fExpectTestNet = true;
                break;

            default:
                return false;
        }
#endif

        if (nVersion <= 128)
          return (false);
        return (vchData.size() == 32 || (vchData.size() == 33 && vchData[32] == 1));

        //return fExpectTestNet == fTestNet && (vchData.size() == 32 || (vchData.size() == 33 && vchData[32] == 1));
    }


    CCoinSecret(int ifaceIndex, const CSecret& vchSecret, bool fCompressed)
    {
        SetSecret(ifaceIndex, vchSecret, fCompressed);
    }

    CCoinSecret()
    {
    }
};

#endif /* ndef __SERVER__BASE58_H__ */
