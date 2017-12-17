
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
#include "block.h"
#include "db.h"
#include <vector>
#include "base58.h"

using namespace std;

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


bool CCoinSecret::SetString(const char* pszSecret)
{
  bool ret;

  ret = CBase58Data::SetString(pszSecret);
  if (!ret) {
    return error(SHERR_INVAL, "error setting base58 data '%s'.", pszSecret);
  }

  ret = IsValid();
  if (!ret)
    return (false);

  return (true);
}

bool CCoinSecret::SetString(const std::string& strSecret)
{
  return SetString(strSecret.c_str());
}




bool CCoinAddr::IsValid() const
{
  unsigned int nExpectedSize = 20;
  bool fExpectTestNet = false;
  switch(nVersion)
  {
    case PUBKEY_ADDRESS:
    case PUBKEY_E_ADDRESS:
    case PUBKEY_S_ADDRESS:
      nExpectedSize = 20; // Hash of public key
      fExpectTestNet = false;
      break;
    case SCRIPT_ADDRESS:
      nExpectedSize = 20; // Hash of CScript
      fExpectTestNet = false;
      break;
#if 0
    case PUBKEY_ADDRESS_TEST:
      nExpectedSize = 20;
      fExpectTestNet = true;
      break;
    case SCRIPT_ADDRESS_TEST:
      nExpectedSize = 20;
      fExpectTestNet = true;
      break;
#endif
    default:
      return false;
  }
  if (vchData.size() != nExpectedSize) {
    Debug("CCoinSecret: vchData.size() %d, nExpectedSize %d\n", vchData.size(), nExpectedSize);
  }
  return vchData.size() == nExpectedSize;
  //return fExpectTestNet == fTestNet && vchData.size() == nExpectedSize;
}

CTxDestination CCoinAddr::Get() const 
{
  if (!IsValid())
    return CNoDestination();
  switch (nVersion) {
    case PUBKEY_ADDRESS:
    case PUBKEY_E_ADDRESS:
    case PUBKEY_S_ADDRESS:
    case PUBKEY_ADDRESS_TEST: 
      {
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        return CKeyID(id);
      }
    case SCRIPT_ADDRESS:
    case SCRIPT_ADDRESS_TEST: 
      {
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        return CScriptID(id);
      }
  }
  return CNoDestination();
}

bool CCoinAddr::GetKeyID(CKeyID &keyID) const
{
  if (!IsValid())
    return false;
  switch (nVersion) {
    case PUBKEY_ADDRESS:
    case PUBKEY_E_ADDRESS:
    case PUBKEY_S_ADDRESS:
    case PUBKEY_ADDRESS_TEST:
      {
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        keyID = CKeyID(id);
        return true;
      }
  }
  return (false);
}

bool CCoinAddr::GetScriptID(CScriptID& scriptID) const 
{
  if (!IsValid())
    return false;
  if (nVersion != SCRIPT_ADDRESS &&
      nVersion != SCRIPT_ADDRESS_TEST)
    return false;

  uint160 id;
  memcpy(&id, &vchData[0], 20);
  scriptID = CScriptID(id);
  return (true);
}


std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    CAutoBN_CTX pctx;
    CBigNum bn58 = 58;
    CBigNum bn0 = 0;

    // Convert big endian data to little endian
    // Extra zero at the end make sure bignum will interpret as a positive number
    std::vector<unsigned char> vchTmp(pend-pbegin+1, 0);
    reverse_copy(pbegin, pend, vchTmp.begin());

    // Convert little endian data to bignum
    CBigNum bn;
    bn.setvch(vchTmp);

    // Convert bignum to std::string
    std::string str;
    // Expected size increase from base58 conversion is approximately 137%
    // use 138% to be safe
    str.reserve((pend - pbegin) * 138 / 100 + 1);
    CBigNum dv;
    CBigNum rem;
    while (bn > bn0)
    {
        if (!BN_div(&dv, &rem, &bn, &bn58, pctx))
            throw bignum_error("EncodeBase58 : BN_div failed");
        bn = dv;
        unsigned int c = rem.getulong();
        str += pszBase58[c];
    }

    // Leading zeroes encoded as base58 zeros
    for (const unsigned char* p = pbegin; p < pend && *p == 0; p++)
        str += pszBase58[0];

    // Convert little endian std::string to big endian
    reverse(str.begin(), str.end());
    return str;
}

bool DecodeBase58(const char* psz, std::vector<unsigned char>& vchRet)
{
    CAutoBN_CTX pctx;
    vchRet.clear();
    CBigNum bn58 = 58;
    CBigNum bn = 0;
    CBigNum bnChar;
    while (isspace(*psz))
        psz++;

    // Convert big endian string to bignum
    for (const char* p = psz; *p; p++)
    {
        const char* p1 = strchr(pszBase58, *p);
        if (p1 == NULL)
        {
            while (isspace(*p))
                p++;
            if (*p != '\0')
                return false;
            break;
        }
        bnChar.setulong(p1 - pszBase58);
        if (!BN_mul(&bn, &bn, &bn58, pctx))
            throw bignum_error("DecodeBase58 : BN_mul failed");
        bn += bnChar;
    }

    // Get bignum as little endian data
    std::vector<unsigned char> vchTmp = bn.getvch();

    // Trim off sign byte if present
    if (vchTmp.size() >= 2 && vchTmp.end()[-1] == 0 && vchTmp.end()[-2] >= 0x80)
        vchTmp.erase(vchTmp.end()-1);

    // Restore leading zeros
    int nLeadingZeros = 0;
    for (const char* p = psz; *p == pszBase58[0]; p++)
        nLeadingZeros++;
    vchRet.assign(nLeadingZeros + vchTmp.size(), 0);

    // Convert little endian data to big endian
    reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
    return true;
}


