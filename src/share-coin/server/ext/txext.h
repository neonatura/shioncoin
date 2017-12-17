
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

#ifndef __SERVER__TXEXT_H__
#define __SERVER__TXEXT_H__

#include "shcoind.h"
#include "base58.h"
#include <vector>
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"

using namespace std;
using namespace json_spirit;

inline bool arrcasecmp(cbuff v1, cbuff v2)
{
  int idx;

  if (v1.size() != v2.size())
    return (false);

  size_t len = v1.size();
  unsigned char *p1 = &*v1.begin();
  unsigned char *p2 = &*v2.begin();
  for (idx = 0; idx < len; idx++) {
    if (tolower(p1[idx]) != tolower(p2[idx]))
      return (false);
  }

  return (true);
}

inline std::string stringFromVch(const std::vector<unsigned char> &vch) 
{
  std::string res;
  if (vch.size() != 0) {
    std::vector<unsigned char>::const_iterator vi = vch.begin();
    while (vi != vch.end()) {
      res += (char) (*vi);
      vi++;
    }
  }
  return res;
}

inline shpeer_t *sharenet_peer(void)
{
  static shpeer_t *ret_peer;
  if (!ret_peer)
    ret_peer = shpeer_init(NULL, NULL);
  return (ret_peer);
}


class CSign
{
  public:
    static const int ALG_ECDSA = SHALG_ECDSA; // SHKEY_ALG_ECDSA
    static const int ALG_U160 = SHALG_SHR; // SHKEY_ALG_U160

    unsigned int nAlg;
    cbuff vPubKey;
    cbuff vAddrKey;
    std::vector<cbuff> vSig;

    CSign()
    {
      SetNull();
    }

    CSign(uint160 hash, string hexSeed = string())
    {
      SetNull();
      SignContext(hash, hexSeed);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(this->nAlg);
      READWRITE(this->vPubKey);
      READWRITE(this->vAddrKey);
      READWRITE(this->vSig);
    )

    void SetNull()
    {
      nAlg = 0;
      vPubKey.clear();
      vAddrKey.clear();
      vSig.clear();
    }

    bool IsNull()
    {
      return (nAlg == 0);
    }

    void Init(const CSign& b)
    {
      nAlg = b.nAlg;
      vPubKey = b.vPubKey;
      vAddrKey = b.vAddrKey;
      vSig = b.vSig;
    }

    friend bool operator==(const CSign &a, const CSign &b)
    {
      return (
          a.nAlg == b.nAlg &&
          a.vPubKey == b.vPubKey &&
          a.vAddrKey == b.vAddrKey &&
          a.vSig == b.vSig
          );
    }

    CSign operator=(const CSign &b)
    {
      Init(b);
      return *this;
    }


    bool SignContext(cbuff& vchContext, string hexSeed = string());

    bool SignContext(uint160 hash, string hexSeed = string())
    {
      cbuff vchContext(hash.begin(), hash.end());
      return (SignContext(vchContext, hexSeed));
    }

    bool SignContext(string hexContext, string hexSeed = string())
    {
      cbuff vchContext = ParseHex(hexContext);
      return (SignContext(vchContext, hexSeed)); 
    }

    bool VerifyContext(unsigned char *data, size_t data_len);


    bool SignAddress(int ifaceIndex, CCoinAddr& addr, unsigned char *data, size_t data_len);

    bool VerifyAddress(CCoinAddr& addr, unsigned char *data, size_t data_len);

    bool SignOrigin(int ifaceIndex, CCoinAddr& addr);

    bool VerifyOrigin(CCoinAddr& addr);




    bool VerifyContext(uint160 hash);

    //bool Sign(int ifaceIndex, CCoinAddr& addr, unsigned char *data, size_t data_len);
    bool Sign(int ifaceIndex, CCoinAddr& addr, cbuff& vchContext, string hexSeed = string());

    bool Sign(int ifaceIndex, CCoinAddr& addr, string hexContext, string hexSeed = string());

    bool Verify(CCoinAddr& addr, unsigned char *data, size_t data_len);

    bool VerifySeed(string hexSeed);


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


class CExtCore
{
  static const int PROTO_EXT_VERSION = 1;

  public:
    unsigned int nVersion;
    shtime_t tExpire;
    cbuff vchLabel;
//    CSign signature;

    CExtCore() {
      SetNull();
    }
    CExtCore(std::string labelIn) {
      SetNull();
      SetLabel(labelIn);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(this->nVersion);
      READWRITE(this->tExpire);
      READWRITE(this->vchLabel);
//      READWRITE(this->signature);
    )

    void SetNull()
    {
      nVersion = PROTO_EXT_VERSION;
      tExpire = SHTIME_UNDEFINED;
//      tExpire = shtime_adj(shtime(), SHARE_DEFAULT_EXPIRE_TIME);
      vchLabel.clear();
//      signature.SetNull();
    }

    /** Obtain the expiration time in unix-seconds. */
    time_t GetExpireTime()
    {
      return (shutime(tExpire));
    }

    /** Set's the expiration time. */
    void SetExpireTime(shtime_t tExpireIn)
    {
      tExpire = tExpireIn;
    }

    /** Set's the expiration to the specified seconds into the future. */
    void SetExpireSpan(double sec)
    {
      tExpire = shtime_adj(shtime(), sec);
    }

    void SetExpireTime()
    {
      double dSpan = (double)SHARE_DEFAULT_EXPIRE_TIME;
      SetExpireSpan(dSpan);
    }

    bool IsExpired()
    {
      if (tExpire == SHTIME_UNDEFINED)
        return (false);
      return (shtime_after(shtime(), tExpire));
    }

    void Init(const CExtCore& b)
    {
      nVersion = b.nVersion;
      tExpire = b.tExpire;
      vchLabel = b.vchLabel;
//      signature = b.signature;
    }

    friend bool operator==(const CExtCore &a, const CExtCore &b)
    {
      return (a.nVersion == b.nVersion &&
          a.tExpire == b.tExpire &&
          a.vchLabel == b.vchLabel
//          a.signature == b.signature
          );
    }

    CExtCore operator=(const CExtCore &b)
    {
      Init(b);
      return *this;
    }

    void SetLabel(std::string labelIn)
    {
      vchLabel = vchFromString(labelIn);
    }
    std::string GetLabel()
    {
      return (stringFromVch(vchLabel)); 
    }

    int GetVersion()
    {
      return (nVersion);
    }

    void SetVersion(int ver)
    {
      nVersion = ver;
    }

    std::string ToString();

    Object ToValue();

};


typedef std::map<std::string, uint256> alias_list;
typedef std::map<uint160, uint256> asset_list;
typedef std::map<uint160, uint256> cert_list;
typedef std::map<uint160, CTransaction> exec_list;
typedef std::map<uint160, uint256> offer_list;
typedef std::map<uint160, CTransaction> channel_list;
typedef std::map<uint160, uint256> ctx_list;


#include "certificate.h"
#include "offer.h"
#include "asset.h"
#include "exec.h"
#include "alias.h"
#include "channel.h"
#include "context.h"


#endif /* ndef __SERVER_TXEXT_H__ */




