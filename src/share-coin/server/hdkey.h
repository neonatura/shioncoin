
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

#ifndef __SERVER__HDKEY_H__
#define __SERVER__HDKEY_H__


#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_value.h"
//#include <boost/xpressive/xpressive_dynamic.hpp>



class HDPubKey : public CPubKey
{
  public:
  
    unsigned int depth;
    unsigned int index;
    cbuff vchChain;

    HDPubKey()
    {
      SetNull();
    }

    HDPubKey(const HDPubKey& b)
    {
      SetNull();
      Init(b);
    }

    HDPubKey(cbuff vchPubKeyIn)
    {
      SetNull();
      
      vchPubKey = vchPubKeyIn;
/* cannot be derived due to lacking chain*/
    }

    HDPubKey(cbuff vchPubKeyIn, cbuff vchChainIn)
    {
      SetNull();
      
      vchPubKey = vchPubKeyIn;
      vchChain = vchChainIn;
    }

    HDPubKey(cbuff vchPubKeyIn, cbuff vchChainIn, int depthIn, int indexIn)
    {
      SetNull();
      
      vchPubKey = vchPubKeyIn;
      vchChain = vchChainIn;
      depth = depthIn;
      index = indexIn;
    }

    void SetNull()
    {
      depth = 0;
      index = 0;
      vchPubKey.clear();
      vchChain.clear();
      vchChain.resize(32);
    }

    friend bool operator==(const HDPubKey &a, const HDPubKey &b) 
    {
      return (
          a.vchPubKey == b.vchPubKey &&
          a.vchChain == b.vchChain
          );
    }

    friend bool operator!=(const HDPubKey &a, const HDPubKey &b) {
      return ( 
          a.vchPubKey != b.vchPubKey ||
          a.vchChain != b.vchChain
          );
    }

    HDPubKey operator=(const HDPubKey &b)
    {
      Init(b);
      return *this;
    }

    void Init(const HDPubKey& b)
    {
      vchPubKey = b.vchPubKey;
      depth = b.depth;
      index = b.index;
      vchChain = b.vchChain;
    }

    bool derive(HDPubKey& pubkey, unsigned int i);

    bool Verify(uint256 hash, const std::vector<unsigned char>& vchSig);


    std::string ToString();

    Object ToValue();

};

class HDPrivKey : public CKey
{
  public:
    unsigned int depth;
    unsigned int index;
    cbuff vchChain;

    HDPrivKey()
    {
      SetNull();
    }

    HDPrivKey(const HDPrivKey& b)
    {
      SetNull();
      Init(b);
    }

/*
    HDPrivKey(cbuff vchKeyIn, cbuff vchChainIn)
    {
      bool ret;

      SetNull();
      CKey::Reset();

      vchKey = vchKeyIn;
      CSecret secret(vchKey.begin(), vchKey.end());
      ret = SetSecret(secret, false);
      if (!ret)
        error(SHERR_INVAL, "HDPrivKey: error setting secret key.");

      vchChain = vchChainIn;
    }

    HDPrivKey(CSecret secretIn, cbuff vchChainIn)
    {
      bool ret;

      SetNull();
      CKey::Reset();

      vchKey = cbuff(secretIn.begin(), secretIn.end());
      ret = SetSecret(secretIn, false);
      if (!ret)
        error(SHERR_INVAL, "HDPrivKey: error setting secret key.");

      vchChain = vchChainIn;
    }
*/

    HDPrivKey(CSecret secret, bool fCompressed)
    {
      /* cannot derive */
      bool ret;

      SetNull();
      SetSecret(secret, fCompressed);
    }

    HDPrivKey(const HDPrivKey& parent, cbuff vchKeyIn, cbuff vchChainIn, int indexIn)
    {

      SetNull();
      vchChain = vchChainIn;

      CSecret secret(vchKeyIn.begin(), vchKeyIn.end());
      SetSecret(secret, false);

      depth = parent.depth + 1;
      index = indexIn;
    }

/*
    HDPrivKey(CKey key)
    {
      SetNull();

      bool fCompressed = false;
      CSecret buff = key.GetSecret(fCompressed);
      cbuff seed = cbuff(buff.begin(), buff.end()); 
      SetSeed(seed);
    }
*/

    void SetNull()
    {
      //pkey = NULL;
      CKey::Reset();

      depth = 0;
      index = 0;

      vchChain.clear();
    }

    friend bool operator==(const HDPrivKey &a, const HDPrivKey &b) 
    {
      bool fc1, fc2;
      return (
          a.Raw() == b.Raw() &&
          a.vchChain == b.vchChain
          );
    }

    friend bool operator!=(const HDPrivKey &a, const HDPrivKey &b) {
      return ( 
          a.Raw() != b.Raw() ||
          a.vchChain != b.vchChain
          );
    }

    HDPrivKey operator=(const HDPrivKey &b)
    {
      Init(b);
      return *this;
    }

    void Init(const HDPrivKey& b)
    {
      /* CKey */
      bool fCompressed = false;
      CSecret secret = b.GetSecret(fCompressed);
      SetSecret(secret, fCompressed);

      /* HDPrivKey */      
      depth = b.depth;
      index = b.index;
      vchChain = b.vchChain;
    }

    cbuff Raw() const
    {
      bool fCompr;
      CSecret secret = GetSecret(fCompr);
      return (cbuff(secret.begin(), secret.end()));
    }

    bool IsValid();

    bool IsValidKey();

    CPubKey GetPubKey() const;

    HDPubKey GetMasterPubKey() const;

    void MakeNewKey(bool fCompressed);

    bool derive(HDPrivKey& privkey, cbuff pubkey, uint32_t i);

    bool SetSeed(cbuff seed);

    bool SetSeed(CSecret seed)
    {
      cbuff buff(seed.begin(), seed.end());
      return (SetSeed(buff));
    }

    bool Sign(uint256 hash, std::vector<unsigned char>& vchSig);

    bool SignCompact(uint256 hash, std::vector<unsigned char>& vchSig);

    bool VerifyCompact(uint256 hash, const std::vector<unsigned char>& vchSig);

    bool Verify(uint256 hash, const std::vector<unsigned char>& vchSig)
    {
      return (GetMasterPubKey().Verify(hash, vchSig));
    }

    bool SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig);

    cbuff GetChain() const;

    string GetChainHex();

    string GetHex();

    bool SetChain(cbuff vchChainIn);

    bool SetChain(string hexChain);

    std::string ToString();

    Object ToValue();

};


class HDMasterPrivKey : public HDPrivKey
{
  public:

    HDMasterPrivKey() : HDPrivKey()
    {
    }

    HDMasterPrivKey(HDMasterPrivKey& b)
    {
      SetNull();
      Init(b);
    }

    /* Supply a seed to generate a key. */
    HDMasterPrivKey(cbuff seedIn)
    {
      SetNull();
      SetSeed(seedIn);
    }

    /* provide a previously created key and chain */
    HDMasterPrivKey(cbuff vchKeyIn, cbuff vchChainIn)
    {
      bool ret;

      SetNull();
      CKey::Reset();

      CSecret secret(vchKeyIn.begin(), vchKeyIn.end());
      ret = SetSecret(secret, false);
      if (!ret)
        error(SHERR_INVAL, "HDPrivKey: error setting secret key.");

      vchChain = vchChainIn;
    }

    HDMasterPrivKey(CSecret secretIn, cbuff vchChainIn)
    {
      bool ret;

      SetNull();
      CKey::Reset();

      ret = SetSecret(secretIn, false);
      if (!ret)
        error(SHERR_INVAL, "HDPrivKey: error setting secret key.");

      vchChain = vchChainIn;
    }

    HDMasterPrivKey(CKey seed_key)
    {
      SetNull();

      bool fCompressed;
      CSecret seed_secret = seed_key.GetSecret(fCompressed);
      cbuff seedIn = cbuff(seed_secret.begin(), seed_secret.end());
      SetSeed(seedIn);
    }

    void SetNull()
    {
      HDPrivKey::SetNull();
    }

    friend bool operator==(const HDMasterPrivKey &a, const HDMasterPrivKey &b) 
    {
      return (
          (HDPrivKey&)a == (HDPrivKey&)b
          );
    }

    friend bool operator!=(const HDMasterPrivKey &a, const HDMasterPrivKey &b) {
      return ( 
          (HDPrivKey&)a != (HDPrivKey&)b
          );
    }

    HDMasterPrivKey operator=(const HDMasterPrivKey &b)
    {
      Init(b);
      return *this;
    }

    void Init(const HDMasterPrivKey& b)
    {
      HDPrivKey::Init((HDPrivKey&)b);
    }

    cbuff GetChain() const
    {
      return (vchChain);
    }

    void MakeNewKey()
    {
      MakeNewKey(true);
    }

    bool IsValidKey();

    void MakeNewKey(bool fCompressed);


};



#endif /* ndef __SERVER__HDKEY_H__ */

