
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

#include <sys/select.h>
#include "share.h"
#include "shcoind.h"
#include "wallet.h"

using namespace std;
using namespace boost;

#define BLANK_HASH_SIZE 21

#if 0

/**
 * Apply a signature that is unique for the local machine and specified coin address.
 */
bool CExtCore::SignOrigin(int ifaceIndex, CCoinAddr& addr)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (false);

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    return error(SHERR_INVAL, "Address does not refer to key");

  CKey key;
  if (!wallet->GetKey(keyID, key))
    return error(SHERR_INVAL, "Private key not available");

  shpeer_t *peer = sharenet_peer();
  shkey_t s_key;
  memcpy(&s_key, shpeer_kpriv(peer), sizeof(s_key));
  unsigned char *raw = (unsigned char *)&s_key;
  cbuff vchPeer(raw, raw + sizeof(shkey_t));
  uint256 hashPeer = uint256(vchPeer);

  vector<unsigned char> vchSig;
  if (!key.SignCompact(hashPeer, vchSig))
    return error(SHERR_INVAL, "Sign failed");

  origin = vchSig;
  return (true);
}

/**
 * Verify whether a particular extended transaction originated from the local machine.
 * @note addr The original address used to sign the extended transaction.
 */
bool CExtCore::VerifyOrigin(int ifaceIndex, CCoinAddr& addr)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (false);

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    return error(SHERR_INVAL, "Address does not refer to key");

  shpeer_t *peer = sharenet_peer();
  shkey_t s_key;
  memcpy(&s_key, shpeer_kpriv(peer), sizeof(s_key));
  unsigned char *raw = (unsigned char *)&s_key;
  cbuff vchPeer(raw, raw + sizeof(shkey_t));
  uint256 hashPeer = uint256(vchPeer);

  CKey key;
  if (!key.SetCompactSignature(hashPeer, origin))
    return error(SHERR_INVAL, "Sign failed");

  return (key.GetPubKey().GetID() == keyID);
}

/**
 * Obtains a 256-bit hash representation of the origin signature.
 */
const uint256 CExtCore::GetOrigin()
{
  return (Hash(origin.begin(), origin.end()));
}
#endif


std::string CExtCore::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CExtCore::ToValue()
{
  Object obj;
  char tbuf[256];

  obj.push_back(Pair("version", (int64_t)nVersion));

  if (vchLabel.size() != 0)
    obj.push_back(Pair("label", stringFromVch(vchLabel)));

  sprintf(tbuf, "%-20.20s", shctime(tExpire)+4);
  obj.push_back(Pair("expire", string(tbuf)));

  return (obj);
}


bool CSign::SignContext(cbuff& vchContext, string hexSeed)
{
  shkey_t *priv_key;
  shkey_t *pub_key;
  shkey_t *kpriv;
  char pub_key_hex[1024];
  char priv_key_hex[1024];
  char sig_r[1024];
  char sig_s[1024];

  if (nAlg & ALG_ECDSA) {
    return error(SHERR_INVAL, 
        "CSign:SignContext: certificate is already signed.");
  }

  if (vchContext.size() == 0) { /* use blank message */
    static unsigned char blank_hash[BLANK_HASH_SIZE];
    vchContext = cbuff(blank_hash, blank_hash + sizeof(blank_hash));
  }


  if (hexSeed.size() == 0) { /* use machine's unique "priveleged key" */
    char priv_key_hex[256];
    shkey_t *kpriv;

    kpriv = shpeer_kpriv(sharenet_peer());
    memset(priv_key_hex, 0, sizeof(priv_key_hex));
    strncpy(priv_key_hex, shkey_hex(kpriv), sizeof(priv_key_hex)-1);
    hexSeed = string(priv_key_hex);
  }

  char *seed_hex = (char *)hexSeed.c_str();
  unsigned char *data = (unsigned char *)vchContext.data();
  size_t data_len = vchContext.size();

  nAlg = ALG_ECDSA; 

  /* generate private key */
  priv_key = shecdsa_key_priv((char *)seed_hex);
  if (!priv_key) {
    return error(SHERR_INVAL, "CSign::SignContenxt: error generating private key.");
  }

  /* generate public key */
  pub_key = shecdsa_key_pub(priv_key);
  if (!pub_key) {
    shkey_free(&priv_key);
    return error(SHERR_INVAL, "CSign::SignContenxt: error generating public key.");
  }

  /* stow pub-key into sign object */
  memset(pub_key_hex, 0, sizeof(pub_key_hex));
  strncpy(pub_key_hex, shkey_hex(pub_key), sizeof(pub_key_hex)-1);
  string strPubKey(pub_key_hex);
  vPubKey = vchFromString(strPubKey); 

  /* sign content */
  shecdsa_sign(priv_key, sig_r, sig_s, data, data_len);

  vSig.push_back(vchFromString(string(sig_r)));
  vSig.push_back(vchFromString(string(sig_s)));
  
  shkey_free(&priv_key);
  shkey_free(&pub_key);

  return (true);
}


bool CSign::VerifyContext(unsigned char *data, size_t data_len)
{
  shkey_t *pub_key;
  char sig_r[256];
  char sig_s[256];
  char pub_key_hex[256];
  int err;

  if (!(nAlg & ALG_ECDSA))
    return error(SHERR_INVAL, "CSign:VerifyContext: empty ecdsa signature.");

  if (vPubKey.size() == 0) {
    return (error(SHERR_INVAL, "CSign::Verify: no public key established."));
  }

  if (data_len == 0) {
    static unsigned char blank_hash[BLANK_HASH_SIZE];
    data = blank_hash;
    data_len = sizeof(blank_hash);
  }

  /* verify content */
  memset(pub_key_hex, 0, sizeof(pub_key_hex));
  strncpy(pub_key_hex, stringFromVch(vPubKey).c_str(), sizeof(pub_key_hex)-1);
  pub_key = shecdsa_key(pub_key_hex);

  strncpy(sig_r, stringFromVch(vSig[0]).c_str(), sizeof(sig_r)-1);
  strncpy(sig_s, stringFromVch(vSig[1]).c_str(), sizeof(sig_s)-1);
  err = shecdsa_verify(pub_key, sig_r, sig_s, data, data_len);
  shkey_free(&pub_key);
  if (err)
    return (error(err, "CSign::Verify"));

  return (true);
}

bool CSign::SignAddress(int ifaceIndex, CCoinAddr& addr, unsigned char *data, size_t data_len)
{

  if (nAlg & ALG_U160)
    return error(SHERR_INVAL, "CSign:SignAddress: address signature is already signed.");

  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (false);

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    return error(SHERR_INVAL, "Address does not refer to key");

  CKey key;
  if (!wallet->GetKey(keyID, key))
    return error(SHERR_INVAL, "Private key not available");

  cbuff vchData(data, data + data_len);
  uint256 hashData = uint256(vchData);

  vector<unsigned char> vchSig;
  if (!key.SignCompact(hashData, vchSig))
    return error(SHERR_INVAL, "Sign failed");

  nAlg |= ALG_U160;
  vAddrKey = vchSig;

  return (true);
}

bool CSign::VerifyAddress(CCoinAddr& addr, unsigned char *data, size_t data_len)
{

  if (!(nAlg & ALG_U160))
    return error(SHERR_INVAL, "CSign:VerifyAddress: empty address signature.");

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    return error(SHERR_INVAL, "Address does not refer to key");

  cbuff vchData(data, data + data_len);
  uint256 hashData = uint256(vchData);

  CKey key;
  if (!key.SetCompactSignature(hashData, vAddrKey))
    return error(SHERR_INVAL, "Sign failed");

  return (key.GetPubKey().GetID() == keyID);
}

bool CSign::SignOrigin(int ifaceIndex, CCoinAddr& addr)
{

  shpeer_t *peer = sharenet_peer();
  shkey_t s_key;
  memcpy(&s_key, shpeer_kpriv(peer), sizeof(s_key));
  unsigned char *raw = (unsigned char *)&s_key;

  return (SignAddress(ifaceIndex, addr, raw, sizeof(shkey_t)));
}

bool CSign::VerifyOrigin(CCoinAddr& addr)
{
  shpeer_t *peer = sharenet_peer();
  shkey_t s_key;

  memcpy(&s_key, shpeer_kpriv(peer), sizeof(s_key));
  unsigned char *raw = (unsigned char *)&s_key;
  
  return (VerifyAddress(addr, raw, sizeof(shkey_t)));
}



bool CSign::VerifyContext(uint160 hash)
{
  cbuff vchContext(hash.begin(), hash.end());
  return (VerifyContext((unsigned char *)vchContext.data(), vchContext.size()));
}

#if 0
bool CSign::Sign(int ifaceIndex, CCoinAddr& addr, unsigned char *data, size_t data_len)
{
  bool ret;

  ret = SignContext(data, data_len);
  if (!ret) {
    return error(SHERR_INVAL, "CSign.Sign: Error signing context.");
  }
    
  ret = SignAddress(ifaceIndex, addr, data, data_len);
  if (!ret) { 
    return error(SHERR_INVAL, "CSign.Sign: Error signing addr '%s'.", addr.ToString().c_str());
  }
 
  return true;
}
#endif

bool CSign::Sign(int ifaceIndex, CCoinAddr& addr, cbuff& vchContext, string hexSeed)
{
  bool ret;

  ret = SignContext(vchContext, hexSeed);
  if (!ret) {
    return error(SHERR_INVAL, "CSign.Sign: Error signing context.");
  }
   
  if (addr.IsValid()) {
    ret = SignAddress(ifaceIndex, addr, vchContext.data(), vchContext.size());
    if (!ret) { 
      return error(SHERR_INVAL, "CSign.Sign: Error signing addr '%s'.", addr.ToString().c_str());
    }
  }
 
  return true;
}

bool CSign::Sign(int ifaceIndex, CCoinAddr& addr, string hexContext, string hexSeed)
{
  cbuff vchContext = ParseHex(hexContext);
  return (Sign(ifaceIndex, addr, vchContext, hexSeed));
}

bool CSign::Verify(CCoinAddr& addr, unsigned char *data, size_t data_len)
{
  bool ret;

  if (data_len == 0) {
    static unsigned char blank_hash[BLANK_HASH_SIZE];
    data = blank_hash;
    data_len = sizeof(blank_hash);
  }

  ret = VerifyContext(data, data_len);
  if (!ret)
    return error(SHERR_INVAL, "CSign.Verify: context integrity failure.");

  ret = VerifyAddress(addr, data, data_len);
  if (!ret)
    return error(SHERR_INVAL, "CSign.Verify: origin integrity failure.");

  return (true);
}

std::string CSign::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CSign::ToValue()
{
  Object obj;
  return (obj);
}


bool CSign::VerifySeed(string hexSeed)
{
  char pub_key_hex[256];
  shkey_t *priv_key;
  shkey_t *pub_key;

  if (!(nAlg & ALG_ECDSA))
    return false; /* seed is only related to context ECDSA signature */

  if (hexSeed.size() == 0) { /* use machine's unique "priveleged key" */
    static char priv_key_hex[256];
    shkey_t *kpriv;

    kpriv = shpeer_kpriv(sharenet_peer());
    memset(priv_key_hex, 0, sizeof(priv_key_hex));
    strncpy(priv_key_hex, shkey_hex(kpriv), sizeof(priv_key_hex)-1);
    hexSeed = string(priv_key_hex);
  }

  priv_key = shecdsa_key_priv((char *)hexSeed.c_str());
  if (!priv_key)
    return error(SHERR_INVAL, "VerifySignatureSeed: error generating private key.");

  /* generate public key */
  pub_key = shecdsa_key_pub(priv_key);
  shkey_free(&priv_key);
  if (!pub_key)
    return error(SHERR_INVAL, "VerifySignatureSeed: error generating public key.");

  memset(pub_key_hex, 0, sizeof(pub_key_hex));
  strncpy(pub_key_hex, shkey_hex(pub_key), sizeof(pub_key_hex)-1);
  string strPubKey(pub_key_hex);

  return (strPubKey == stringFromVch(vPubKey));
}
