
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

#include <string>
#include <vector>
#include <map>
//#include <array>
#include <cstddef>
//#include <cstdint>
//#include <initializer_list>
#include <queue>
#include <vector>

#include "key.h"
#include "base58.h"
#include "uint256.h"
#include "util.h"
#include "mnemonic.h"

//#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include "hdkey.h"

#define MAX_HD_SEED_INDEX 0xfffffff

using namespace std;


void HDPrivKey::MakeNewKey(bool fCompressed)
{
  /* not supported */
}

bool HDPrivKey::SetSeed(cbuff seed)
{
  char secret_hex[256];
  char m_chain[256];

  string master_seed = Hash(seed.begin(), seed.end()).GetHex();
  while (master_seed.length() < 64)
    master_seed = "0" + master_seed;

  strcpy(secret_hex, shecdsa_hd_seed((char *)master_seed.c_str(), m_chain));

  cbuff vchKey = ParseHex(secret_hex);
  CSecret secret(vchKey.begin(), vchKey.end());
  SetSecret(secret, false);

  vchChain = ParseHex(m_chain);

  fSet = true;

  return (true);
}

bool HDPrivKey::derive(HDPrivKey& privkey, cbuff pubkey, uint32_t i)
{
  char privkey_hex[256];
  char chain_hex[256];
  char pubkey_hex[256];
  char secret_hex[256];

  if (i > MAX_HD_SEED_INDEX)
    return (false);

#if 0
  if (!IsValid())
    return (false);
#endif

  string hex = HexStr(vchChain);
  memset(chain_hex, 0, sizeof(chain_hex));
  strcpy(chain_hex, hex.c_str());

  strcpy(secret_hex, HexStr(Raw()).c_str());

  strcpy(pubkey_hex, HexStr(pubkey).c_str());

  strcpy(privkey_hex, shecdsa_hd_privkey(secret_hex, chain_hex, i));

  cbuff secret = ParseHex(privkey_hex); 
if (secret.size() != 32) fprintf(stderr, "DEBUG: HDPrivKey.derive: derived secret key is not 32 bytes\n");
  privkey = HDPrivKey(*this, secret, ParseHex(chain_hex), i);

  if (!privkey.IsValid())
    return (false);

  return (true);
}

CPubKey HDPrivKey::GetPubKey() const
{
  char secret_hex[256];
  char pubkey_hex[256];

  memset(secret_hex, 0, sizeof(secret_hex));
  memset(pubkey_hex, 0, sizeof(pubkey_hex));

  strcpy(secret_hex, HexStr(Raw()).c_str());
  char *hex = shecdsa_hd_recover_pub(secret_hex);
  if (hex)
    strcpy(pubkey_hex, hex); 

  cbuff buff = ParseHex(pubkey_hex);
  CPubKey pubkey(buff);

  return (pubkey);
}

HDPubKey HDPrivKey::GetMasterPubKey() const
{
  bool fCompr = false;
  char *hex;

  hex = shecdsa_hd_recover_pub((char *)HexStr(Raw()).c_str());
  if (!hex) {
    error(SHERR_INVAL, "GetMasterPubKey: failure recovering pubkey.");
    return (HDPubKey());
  }

  cbuff buff = ParseHex(hex);
  HDPubKey pubkey(buff, vchChain, depth, index);

  return (pubkey);
}

bool HDPrivKey::IsValid()
{

  if (!fSet) {
    error(SHERR_INVAL, "HDPrivKey.IsValid: fSet == false");
    return (false);
  }

  if (Raw().size() != 32) {
    return error(SHERR_INVAL, "HDPrivKey.IsValid: vchKey.size() != 32");
  }

  if (vchChain.size() != 0 && vchChain.size() != 32) {
    error(SHERR_INVAL, "HDPrivKey.IsValid: vchChain.size() = %d", vchChain.size());
    return (false);
  }

  if (!IsValidKey()) {
    return error(SHERR_INVAL, "HDPrivKey.IsValid: key is invalid.");
  }

  return (true);
}

bool HDPrivKey::IsValidKey()
{
  bool fCompr;
  HDPrivKey key2;

  /* generate clone of this key */
  key2.Init(*this);

  /* verify secret key integrity */
  CSecret secret = GetSecret(fCompr);
  cbuff buff(secret.begin(), secret.end());
  if (buff != key2.Raw())
    return error(SHERR_INVAL, "HDPrivKey.IsValidKey: secret encapsulation failure.");

  /* verify pub-key derivative */
  return GetPubKey() == key2.GetPubKey();
}

bool HDPrivKey::Sign(uint256 hash, std::vector<unsigned char>& vchSig)
{
  char sig_r[256];
  char sig_s[256];
  int err;

  string privkey = HexStr(Raw());
  string hash_hex = HexStr(hash.begin(), hash.end());

memset(sig_r, 0, sizeof(sig_r));
memset(sig_s, 0, sizeof(sig_s));
  err = shecdsa_hd_sign((char *)privkey.c_str(), sig_r, sig_s, (char *)hash_hex.c_str());
  if (err)
    return (false);

  cbuff bin_r = ParseHex(string(sig_r));
  cbuff bin_s = ParseHex(string(sig_s));

  if (bin_r.size() != 32 || bin_s.size() != 32)
    return error(SHERR_INVAL, "HDPrivKey.Sign: invalid signature size.");

  vchSig.clear();
  vchSig.insert(vchSig.begin(), bin_r.begin(), bin_r.end());
  vchSig.insert(vchSig.end(), bin_s.begin(), bin_s.end());


  return (true);
}

bool HDPrivKey::SignCompact(uint256 hash, std::vector<unsigned char>& vchSig)
{
  return (CKey::SignCompact(hash, vchSig));
}


bool HDPrivKey::SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig)
{
  return (false);
}


bool HDPubKey::derive(HDPubKey& pubkey, unsigned int i)
{
  char m_chain[256];
  char m_pubkey[256];
  char *pubkey_hex;

  if (i > MAX_HD_SEED_INDEX)
    return (false);

  if (!IsValid())
    return (false);

  if (vchChain.size() == 0)
    return (false);

  strcpy(m_chain, HexStr(vchChain).c_str());
  strcpy(m_pubkey, HexStr(vchPubKey).c_str());
  pubkey_hex = shecdsa_hd_pubkey(m_pubkey, m_chain, i);

  pubkey = HDPubKey(ParseHex(pubkey_hex), ParseHex(m_chain), (depth + 1), i);
  if (!pubkey.IsValid())
    return (false);

  return (true);
}

bool HDPrivKey::VerifyCompact(uint256 hash, const std::vector<unsigned char>& vchSig)
{
  return (CKey::VerifyCompact(hash, vchSig));
}

bool HDPubKey::Verify(uint256 hash, const std::vector<unsigned char>& vchSig)
{
  string sig_r = HexStr(vchSig.begin(), vchSig.begin() + 32);
  string sig_s = HexStr(vchSig.begin() + 32, vchSig.end());
  string pubkey = HexStr(vchPubKey);
  string hash_hex = HexStr(hash.begin(), hash.end());
  int err;

  err = shecdsa_hd_verify((char *)pubkey.c_str(), 
      (char *)sig_r.c_str(), (char *)sig_s.c_str(), (char *)hash_hex.c_str());
  if (err)
    return (false);

  return (true);
}

void HDMasterPrivKey::MakeNewKey(bool fCompressed)
{

  RandAddSeedPerfmon();

  CKey t_key;
  t_key.MakeNewKey(fCompressed);
  CSecret secret = t_key.GetSecret(fCompressed);
  SetSeed(secret);

  if (fCompressed)
    SetCompressedPubKey();
}

std::string HDPrivKey::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object HDPrivKey::ToValue()
{
  Object obj;

  obj.push_back(Pair("depth", (int)depth));
  obj.push_back(Pair("index", (int)index));
  obj.push_back(Pair("chain", HexStr(vchChain)));
  obj.push_back(Pair("keylen", (int)Raw().size()));

  return (obj);
}

std::string HDPubKey::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object HDPubKey::ToValue()
{
  Object obj;

  obj.push_back(Pair("depth", (int)depth));
  obj.push_back(Pair("index", (int)index));
  obj.push_back(Pair("chain", HexStr(vchChain)));
  obj.push_back(Pair("pubkey", HexStr(vchPubKey)));

#if 0
  CCoinAddr addr;
  addr.Set(GetID());
  obj.push_back(Pair("addr", addr.ToString()));
#endif

  return (obj);
}

bool HDMasterPrivKey::IsValidKey()
{

  /* generate clone of key */
  HDMasterPrivKey key2;
  key2.Init(*this);

  /* verify secret key integrity */
  bool fCompr;
  CSecret secret = GetSecret(fCompr);
  cbuff buff(secret.begin(), secret.end());
  if (buff != key2.Raw())
    return error(SHERR_INVAL, "HDPrivKey.IsValidKey: secret encapsulation failure.");

  /* verify pub-key derivative */
  return GetPubKey() == key2.GetPubKey();
}


cbuff HDPrivKey::GetChain() const
{
  return (vchChain);
}

string HDPrivKey::GetChainHex()
{
  return (HexStr(GetChain()));
}

string HDPrivKey::GetHex()
{
  return (HexStr(Raw()));
}

bool HDPrivKey::SetChain(cbuff vchChainIn)
{
  if (vchChainIn.size() != 32)
    return error(SHERR_INVAL, "SetChain: invalid size specification.");
  vchChain = vchChainIn;
}

bool HDPrivKey::SetChain(string hexChain)
{
  SetChain(ParseHex(hexChain));
}

#if 0
string HDPrivKey::encode()
{
  CDataStream key;
  char ver[4] = { 0x73, 0x68, 0x68, 0x64 };
  cbuff verbuff(ver, ver + 4);

  key << verbuff; /* 4b */
  key << index; /* 4b */
  key << depth; /* 4b */
  key << Raw(); /* 32b */
  key << GetChain(); /* 32b */

  cbuff buff(key.begin(), key.end()); /* 76 bytes */
  return (EncodeBase58(buff));
}
#endif
