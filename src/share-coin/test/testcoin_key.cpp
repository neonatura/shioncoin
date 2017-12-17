
#include "test_shcoind.h"
#include <string>
#include <vector>

#include "key.h"
#include "base58.h"
#include "uint256.h"
#include "util.h"
#include "mnemonic.h"





#include <cstddef>
#include <vector>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include "secp256k1.h"
#include "secp256k1_recovery.h"

#include "hdkey.h"






using namespace std;


extern CKey MergeKey(const CKey& pkey, cbuff tag);


#ifdef __cplusplus
extern "C" {
#endif



static const string strSecret3     ("6bMUHP9bBRR5dQcnrAzyoB3nsYTK69LC5LEgzUBiPz9Fqwe4vry");
static const string strSecret3C    ("RgdMRJkurzmHRhEyN38ugoMKU5q8qhmht7uRWezHiTDSWyVT7kMu");
static const string strSecret4     ("6bRCArv9Htu4oLMdTsHhyE4jKHUYo46HKSbHiBRT8itJWQuyN34");
static const string strSecret4C    ("RgunJXKZba4omWS3waxjqAfTmhibLGeK2PxLkkzvM5sSGYZA3piX");

static const CCoinAddr addr3 ("GLduwFUxWvKSotSgqhNwKFcU58wQjPwtfV");
static const CCoinAddr addr4 ("GSFFyXXYHNTtDk8W8M4LcZMcyG4fJuqjoo");
static const CCoinAddr addr3C ("GczsCEv6UXUByQTmsSnFoLWG3KWD7yV9zp");
static const CCoinAddr addr4C ("GJgcXeqegX3BW2AihD6q1gbetgYqpAkrxD");


static const string strAddressBad("1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF");


bool static _IsValidSignatureEncoding(const std::vector<unsigned char> &sig) 
{
  // Minimum and maximum size constraints.
  if (sig.size() < 9) return false;
  if (sig.size() > 73) return false;

  // A signature is of type 0x30 (compound).
  if (sig[0] != 0x30) return false;

  // Make sure the length covers the entire signature.
  if (sig[1] != sig.size() - 3) return false;

  // Extract the length of the R element.
  unsigned int lenR = sig[3];

  // Make sure the length of the S element is still inside the signature.
  if (5 + lenR >= sig.size()) return false;

  // Extract the length of the S element.
  unsigned int lenS = sig[5 + lenR];

  // Verify that the length of the signature matches the sum of the length
  // of the elements.
  if ((size_t)(lenR + lenS + 7) != sig.size()) return false;

  // Check whether the R element is an integer.
  if (sig[2] != 0x02) return false;

  // Zero-length integers are not allowed for R.
  if (lenR == 0) return false;

  // Negative numbers are not allowed for R.
  if (sig[4] & 0x80) return false;

  // Null bytes at the start of R are not allowed, unless R would
  // otherwise be interpreted as a negative number.
  if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;

  // Check whether the S element is an integer.
  if (sig[lenR + 4] != 0x02) return false;

  // Zero-length integers are not allowed for S.
  if (lenS == 0) return false;

  // Negative numbers are not allowed for S.
  if (sig[lenR + 6] & 0x80) return false;

  // Null bytes at the start of S are not allowed, unless S would otherwise be
  // interpreted as a negative number.
  if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;

  return true;
}

bool static _CheckLowS(const std::vector<unsigned char>& vchSig) 
{
  secp256k1_context *secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  secp256k1_ecdsa_signature sig;
  bool ok;

  memset(&sig, 0, sizeof(sig));
  if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig, &vchSig[0], vchSig.size())) {
    secp256k1_context_destroy(secp256k1_context_verify);
    return false;
  }

  if (!secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, NULL, &sig)) {
    secp256k1_context_destroy(secp256k1_context_verify);
    return false;
  };

  secp256k1_context_destroy(secp256k1_context_verify);
  return (true);
}

bool static _IsLowDERSignature(const cbuff& vchSig)
{
  std::vector<unsigned char> vchSigCopy(vchSig.begin(), vchSig.begin() + vchSig.size() - 1);
  if (!_CheckLowS(vchSigCopy))
    return false;
  return true;
}


_TEST(coin_key)
{
  CCoinSecret bsecret3, bsecret4;
  CCoinSecret bsecret3C, bsecret4C;
  CCoinSecret baddress1;

  _TRUE( bsecret3.SetString (strSecret3) );
  _TRUE( bsecret4.SetString (strSecret4) );
  _TRUE( bsecret3C.SetString(strSecret3C));
  _TRUE( bsecret4C.SetString(strSecret4C));
  _TRUE(!baddress1.SetString(strAddressBad));

  bool fCompressed;
  CSecret secret3  = bsecret3.GetSecret (fCompressed);
  _TRUE(fCompressed == false);
  CSecret secret4  = bsecret4.GetSecret (fCompressed);
  _TRUE(fCompressed == false);
  bsecret3C.SetSecret(TEST_COIN_IFACE, secret3, true);
  bsecret4C.SetSecret(TEST_COIN_IFACE, secret4, true);
  CSecret secret3C = bsecret3C.GetSecret(fCompressed);
  _TRUE(fCompressed == true);
  CSecret secret4C = bsecret4C.GetSecret(fCompressed);
  _TRUE(fCompressed == true);
  _TRUE(secret3 == secret3C);
  _TRUE(secret4 == secret4C);

  CKey key3, key4;
  key3.SetSecret(secret3, false);
  key4.SetSecret(secret4, false);
  CKey key3C, key4C;
  _TRUE(true == key3C.SetSecret(secret3, true));
  _TRUE(true == key4C.SetSecret(secret4, true));

  _TRUE(addr3.Get()  == CTxDestination(key3.GetPubKey().GetID()));
  _TRUE(addr4.Get()  == CTxDestination(key4.GetPubKey().GetID()));
  _TRUE(addr3C.Get() == CTxDestination(key3C.GetPubKey().GetID()));
  _TRUE(addr4C.Get() == CTxDestination(key4C.GetPubKey().GetID()));


  for (int n=0; n<16; n++)
  {
    string strMsg = strprintf("Very secret message %i: 11", n);
    uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

    // normal signatures

    vector<unsigned char> sign3, sign4;
    _TRUE(key3.Sign (hashMsg, sign3));
    _TRUE(key4.Sign (hashMsg, sign4));
    vector<unsigned char> sign3C, sign4C;
    _TRUE(key3C.Sign(hashMsg, sign3C));
    _TRUE(key4C.Sign(hashMsg, sign4C));

    _TRUE( key3.Verify(hashMsg, sign3));
    _TRUE(!key3.Verify(hashMsg, sign4));
    _TRUE( key3.Verify(hashMsg, sign3C));
    _TRUE(!key3.Verify(hashMsg, sign4C));

    _TRUE(!key4.Verify(hashMsg, sign3));
    _TRUE( key4.Verify(hashMsg, sign4));
    _TRUE(!key4.Verify(hashMsg, sign3C));
    _TRUE( key4.Verify(hashMsg, sign4C));

    _TRUE( key3C.Verify(hashMsg, sign3));
    _TRUE(!key3C.Verify(hashMsg, sign4));
    _TRUE( key3C.Verify(hashMsg, sign3C));
    _TRUE(!key3C.Verify(hashMsg, sign4C));

    _TRUE(!key4C.Verify(hashMsg, sign3));
    _TRUE( key4C.Verify(hashMsg, sign4));
    _TRUE(!key4C.Verify(hashMsg, sign3C));
    _TRUE( key4C.Verify(hashMsg, sign4C));

//    _TRUE(true == _IsValidSignatureEncoding(sign3C));
//    _TRUE(true == _IsLowDERSignature(sign3C));

    // compact signatures (with key recovery)

    vector<unsigned char> csign3, csign4;
    _TRUE(key3.SignCompact (hashMsg, csign3));
    _TRUE(key4.SignCompact (hashMsg, csign4));
    vector<unsigned char> csign3C, csign4C;
    _TRUE(key3C.SignCompact(hashMsg, csign3C));
    _TRUE(key4C.SignCompact(hashMsg, csign4C));


    CKey rkey3, rkey4;
    CKey rkey3C, rkey4C;
    _TRUE(rkey3.SetCompactSignature (hashMsg, csign3));
    _TRUE(rkey4.SetCompactSignature (hashMsg, csign4));
    _TRUE(rkey3C.SetCompactSignature(hashMsg, csign3C));
    _TRUE(rkey4C.SetCompactSignature(hashMsg, csign4C));

    _TRUE(rkey3.GetPubKey()  == key3.GetPubKey());
    _TRUE(rkey4.GetPubKey()  == key4.GetPubKey());
    _TRUE(rkey3C.GetPubKey() == key3C.GetPubKey());
    _TRUE(rkey4C.GetPubKey() == key4C.GetPubKey());

//    _TRUE(true == _IsValidSignatureEncoding(sign3C));
  }

  char teststr[64];
  strcpy(teststr, "test");
  cbuff tag(teststr, teststr + strlen(teststr));
  bool fCompr = true;
  CKey pkey;
  pkey.MakeNewKey(fCompr);
  CKey key1 = pkey.MergeKey(tag);
  CKey key2 = pkey.MergeKey(tag);
  _TRUE(key1.GetPubKey().GetID() == key2.GetPubKey().GetID());
  _TRUE(pkey.GetPubKey().GetID() != key2.GetPubKey().GetID());

  strcpy(teststr, "test2");
  cbuff tag2(teststr, teststr + strlen(teststr));
  key2 = pkey.MergeKey(tag2);
  _TRUE(key1.GetPubKey().GetID() != key2.GetPubKey().GetID());

}



_TEST(coin_key_phrase)
{
  bool fCompressed = false;

  /* generate new coin address key */
  CKey key;
  key.MakeNewKey(false);
  CCoinSecret secret(TEST_COIN_IFACE, key.GetSecret(fCompressed), false); 
  _TRUE(secret.IsValid() == true);

  /* convert to a 'phrase' */
  string phrase = EncodeMnemonicSecret(secret);

  CCoinSecret cmp_secret;
  bool ret = DecodeMnemonicSecret(TEST_COIN_IFACE, phrase, cmp_secret);
  _TRUE(ret == true);
  _TRUE(cmp_secret.IsValid() == true);
  
  _TRUE(cmp_secret.GetSecret(fCompressed) == secret.GetSecret(fCompressed));
}



#ifdef __cplusplus
}
#endif









extern CCoinAddr GetAccountAddress(CWallet *wallet, string strAccount, bool bForceNew);
extern CWallet *GetWallet(CIface *iface);

#ifdef __cplusplus
extern "C" {
#endif

  _TEST(coin_hdkey)
  {
    CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
    CWallet *wallet = GetWallet(iface);
    string strAccount("");
    char master_pubkey[256];
    char buf[32];
    bool ret;
    int idx2;
    int idx;

    HDMasterPrivKey privkey;
    privkey.MakeNewKey();
    cbuff sec_buff;
    {
      bool fCompressed = false;
      CSecret seed_secret = privkey.GetSecret(fCompressed);
      sec_buff = cbuff(seed_secret.begin(), seed_secret.end());
      _TRUE(sec_buff == privkey.Raw());
    }

/* x2check */
    HDMasterPrivKey m_privkey(sec_buff, privkey.GetChain());
    _TRUE(m_privkey == privkey);

    string master_secret = HexStr(privkey.Raw());
    strcpy(master_pubkey, shecdsa_hd_recover_pub((char *)master_secret.c_str()));

    HDPubKey key(ParseHex(master_pubkey),
        privkey.vchChain, privkey.depth, privkey.index);
    _TRUE(key.IsValid() == true);

/* x2check */
    HDPubKey m_pubkey = m_privkey.GetMasterPubKey();
    _TRUE(m_pubkey == key);

/* -- */

    for (idx = 1; idx < 8; idx++) {
      /* extract child pub key */
      HDPubKey t_pubkey;
      ret = key.derive(t_pubkey, idx);
      _TRUE(ret == true);

      /* extract child priv key */
      HDPrivKey t_privkey;
      ret = privkey.derive(t_privkey, key.Raw(), idx);
      _TRUE(ret == true);

    /* -- */

      CPubKey t_pubkey2 = t_privkey.GetPubKey();
  if (t_pubkey.Raw().size() != 33 || t_pubkey2.Raw().size() != 33) {
    fprintf(stderr, "DEBUG: TEST_coin_hdkey: t_pubkey2.Raw().size() = %d\n", t_pubkey2.Raw().size()); 
    fprintf(stderr, "DEBUG: TEST_coin_hdkey: t_pubkey.Raw().size() = %d\n", t_pubkey.Raw().size()); 
  }
      _TRUE(t_pubkey2.Raw() == t_pubkey.Raw());



  /* .. coin compatibility  .. */

      CPubKey b_pubkey(t_pubkey.Raw());

      /* test variant derivatives */
      for (idx2 = 5; idx2 < 7; idx2++) {
        HDPubKey d_pubkey;
        _TRUE(key.derive(d_pubkey, idx2) == true);

        HDPrivKey d_privkey;
        _TRUE(privkey.derive(d_privkey, key.Raw(), idx2) == true);

        /* TODO: check for dups.. */
      }


      /* test hash signing */
      uint256 hash("0xf4319e4e89b35b5f26ec0363a09d29703402f120cf1bf8e6f535548d5ec3c5cc");
      uint256 inval_hash("0x54bac4474b4d5e3cef2d38dda11fed32e4459a97fbddf43ff9543b0f31b587fd");
      cbuff sig;
      _TRUE(t_privkey.Sign(hash, sig) == true);
      _TRUE(t_pubkey.Verify(hash, sig) == true);
      _TRUE(t_privkey.Verify(hash, sig) == true);
      _TRUE(t_privkey.Verify(inval_hash, sig) == false);
      cbuff csig;
      _TRUE(t_privkey.SignCompact(hash, csig) == true);
      _TRUE(t_privkey.VerifyCompact(hash, csig) == true);

      /* test pub-key hash verification */
      CKey pk;
      _TRUE(pk.SetCompactSignature(hash, csig) == true);
      _TRUE(pk.VerifyCompact(hash, csig) == true);
      _TRUE(pk.VerifyCompact(inval_hash, csig) == false);

      /* this won't eval since pubkey is variant derivative */
      CKey pk2;
      pk2.SetPubKey(t_privkey.GetPubKey());
      _TRUE(pk2.Verify(hash, csig) == false);
      _TRUE(pk2.VerifyCompact(hash, csig) == false);
    }

  }



#ifdef __cplusplus
}
#endif



