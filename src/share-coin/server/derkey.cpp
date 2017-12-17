
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
#include "main.h"
#include <map>
#include "key.h"
#include "derkey.h"

static secp256k1_context* secp256k1_context_sign = NULL;
static secp256k1_context* secp256k1_context_verify = NULL;

#ifdef __cplusplus
extern "C" {
#endif
void INIT_SECP256K1(void)
{

  if (!secp256k1_context_sign)
    secp256k1_context_sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

  if (!secp256k1_context_verify)
    secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

}
secp256k1_context *SECP256K1_VERIFY_CONTEXT(void)
{
  return (secp256k1_context_verify);
}
secp256k1_context *SECP256K1_SIGN_CONTEXT(void)
{
  return (secp256k1_context_sign);
}
void TERM_SECP256K1(void)
{

  if (secp256k1_context_sign)
    secp256k1_context_destroy(secp256k1_context_sign);
  secp256k1_context_sign = NULL;

  if (secp256k1_context_verify)
    secp256k1_context_destroy(secp256k1_context_verify);
  secp256k1_context_verify = NULL;
}
#ifdef __cplusplus
};
#endif

void CKey::SetCompressedPubKey()
{
  fCompressedPubKey = true;
}

void CKey::Reset()
{
  fCompressedPubKey = false;
  fPubSet = false;
  fSet = false;

  memset(vch, '\000', sizeof(vch));
  vchPub.clear();
}

CKey::CKey()
{
  Reset();
}

CKey::CKey(const CKey& b)
{
  memcpy(vch, b.vch, sizeof(vch));
  vchPub = b.vchPub;
  fSet = b.fSet;
  fCompressedPubKey = b.fCompressedPubKey; /* 12.17 */
}

CKey& CKey::operator=(const CKey& b)
{
  memcpy(vch, b.vch, sizeof(vch));
  vchPub = b.vchPub;
  fSet = b.fSet;
  fCompressedPubKey = b.fCompressedPubKey;
  return (*this);
}

bool CKey::IsNull() const
{
    return !fSet;
}

bool CKey::IsCompressed() const
{
  return fCompressedPubKey;
}

void CKey::MakeNewKey(bool fCompressed)
{
  int i;

  do {
    uint64_t *v_ptr = (uint64_t *)vch;
    for (i = 0; i < 4; i++) { /* 4 * 8 = 32b */
      v_ptr[i] = shrand();
    } 
  } while (!secp256k1_ec_seckey_verify(secp256k1_context_sign, vch));

  if (fCompressed)
    SetCompressedPubKey();

  fSet = true;
  fPubSet = false;

}

bool CKey::SetPrivKey(const CPrivKey& vchPrivKey, bool fCompressed)
{

  if (!ec_privkey_import_der(secp256k1_context_sign, (unsigned char*)vch, vchPrivKey.data(), vchPrivKey.size()))
    return (false);

  fSet = true;

  if (fCompressed || fCompressedPubKey)
    SetCompressedPubKey();

  return true;


}

bool CKey::SetSecret(const CSecret& vchSecret, bool fCompressed)
{
  unsigned char buf[32];

  if (vchSecret.size() != 32) {
    return (error(SHERR_INVAL, "CKey.SetSecret: invalid secret size (%d) specified.", vchSecret.size()));
  }

  cbuff vchIn(vchSecret.begin(), vchSecret.end());
  memcpy(buf, vchIn.data(), 32);
  if (!secp256k1_ec_seckey_verify(secp256k1_context_sign, buf)) {
    return (error(SHERR_INVAL, "CKey.SetSecret: invalid secret specified."));
  }

  memcpy(vch, buf, 32);
  fSet = true;

  if (fCompressed || fCompressedPubKey)
    SetCompressedPubKey();

  return true;
}

/**
 * @note Requires the pkey to be defined before-hand 
*/
CSecret CKey::GetSecret(bool &fCompressed) const
{
  CSecret ret_secret(vch, vch + 32);
  fCompressed = fCompressedPubKey;
  return (ret_secret);
}

CPrivKey CKey::GetPrivKey() const
{
//  CPrivKey privkey;
  int ret;

  if (!fSet)
    return (CPrivKey());

  unsigned char privkey_buf[280];
  size_t privkeylen;
//  privkey.resize(279);

  memset(privkey_buf, 0, sizeof(privkey_buf));
  privkeylen = 279;

  ret = ec_privkey_export_der(secp256k1_context_sign, privkey_buf, &privkeylen, (unsigned char *)vch, fCompressedPubKey ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
//  assert(ret);
  if (!ret)
    return (CPrivKey());

  //privkey.resize(privkeylen);
  return (CPrivKey(privkey_buf, privkey_buf + privkeylen));
}

bool CKey::SetPubKey(const CPubKey& vchPubKey)
{
  const unsigned char* pbegin = &vchPubKey.vchPubKey[0];
  size_t psize = vchPubKey.vchPubKey.size();

  /* verify integrity */
  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, pbegin, psize)) {
    return (error(SHERR_INVAL, "CKey.SetPubKey: invalid pubkey specified."));
  }

  /* stoe for later */
  vchPub = cbuff(vchPubKey.vchPubKey);

  if (psize == 33)
    SetCompressedPubKey();

  fPubSet = true;

  return true;
}

CPubKey CKey::GetPubKey() const
{

  if (!fSet) {
    if (fPubSet) {
      /* key is carring a public key */
      return (CPubKey(vchPub));
    }

    return (CPubKey());
  }
//  assert(fValid);

  secp256k1_pubkey pubkey;
  unsigned char result[65];
  size_t clen = 65;
  int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, (unsigned char *)vch);
  if (!ret) {
    error(SHERR_INVAL, "CKey.GetPubKey: error creating public key.");
    return (CPubKey());
  }
//  assert(ret);

  secp256k1_ec_pubkey_serialize(secp256k1_context_sign, result, &clen, &pubkey, fCompressedPubKey ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
//  assert(result.size() == clen);
//  assert(result.IsValid());

  CPubKey ret_pubkey(cbuff(result, result + clen));
  if (!ret_pubkey.IsValid()) {
    error(SHERR_INVAL, "CKey.GetPubKey: error serializing public key.");
    return (CPubKey());
  }

  return (ret_pubkey);
}

bool CKey::Sign(uint256 hash, std::vector<unsigned char>& vchSig)
{

  if (!fSet)
    return false;

  vchSig.resize(72);
  size_t nSigLen = 72;

  secp256k1_ecdsa_signature sig;
  int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), (unsigned char *)vch, secp256k1_nonce_function_rfc6979, NULL);
  if (!ret)
    return (false);
//  assert(ret);

  unsigned char sig_buf[128];
  memset(sig_buf, 0, sizeof(sig_buf));
  secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, sig_buf, &nSigLen, &sig);
//  vchSig.resize(nSigLen);
  vchSig = cbuff(sig_buf, sig_buf + nSigLen);

  return true;
}

bool CKey::SignCompact(uint256 hash, std::vector<unsigned char>& vchSig)
{
  secp256k1_ecdsa_recoverable_signature sig;
  int rec;
  int ret;

  if (!fSet) {
    return (error(SHERR_INVAL, "CKey.SignCompact: error signing unitialized key."));
  }

  vchSig.resize(65);

  ret = secp256k1_ecdsa_sign_recoverable(secp256k1_context_sign, &sig, hash.begin(), (unsigned char *)vch, secp256k1_nonce_function_rfc6979, NULL);
  if (!ret) {
    return (error(SHERR_INVAL, "CKey.SignCompact: error signing compact signature."));
  }

  rec = -1;
  ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_sign, (unsigned char*)&vchSig[1], &rec, &sig);
  if (!ret || rec == -1) {
    return (error(SHERR_INVAL, "CKey.SignCompact: error serializing compact signature."));
  }
  //assert(ret);
  //assert(rec != -1);
 
  vchSig[0] = 27 + rec + (fCompressedPubKey ? 4 : 0);

  return (true);
}


#if 0
static int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
{
  if (!eckey) return 0;

  int ret = 0;
  BN_CTX *ctx = NULL;

  BIGNUM *x = NULL;
  BIGNUM *e = NULL;
  BIGNUM *order = NULL;
  BIGNUM *sor = NULL;
  BIGNUM *eor = NULL;
  BIGNUM *field = NULL;
  EC_POINT *R = NULL;
  EC_POINT *O = NULL;
  EC_POINT *Q = NULL;
  BIGNUM *rr = NULL;
  BIGNUM *zero = NULL;
  int n = 0;
  int i = recid / 2;

  const EC_GROUP *group = EC_KEY_get0_group(eckey);
  if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
  BN_CTX_start(ctx);
  order = BN_CTX_get(ctx);
  if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
  x = BN_CTX_get(ctx);
  if (!BN_copy(x, order)) { ret=-1; goto err; }
  if (!BN_mul_word(x, i)) { ret=-1; goto err; }
  if (!BN_add(x, x, ecsig->r)) { ret=-1; goto err; }
  field = BN_CTX_get(ctx);
  if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
  if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
  if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
  if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
  if (check)
  {
    if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
    if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
  }
  if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
  n = EC_GROUP_get_degree(group);
  e = BN_CTX_get(ctx);
  if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
  if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
  zero = BN_CTX_get(ctx);
  if (!BN_zero(zero)) { ret=-1; goto err; }
  if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
  rr = BN_CTX_get(ctx);
  if (!BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret=-1; goto err; }
  sor = BN_CTX_get(ctx);
  if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret=-1; goto err; }
  eor = BN_CTX_get(ctx);
  if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
  if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
  if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

  ret = 1;

err:
  if (ctx) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (R != NULL) EC_POINT_free(R);
  if (O != NULL) EC_POINT_free(O);
  if (Q != NULL) EC_POINT_free(Q);
  return ret;
}
#endif

bool CKey::SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig)
{

  if (vchSig.size() != 65)
      return false;

  int recid = (vchSig[0] - 27) & 3;
  bool fComp = ((vchSig[0] - 27) & 4) != 0;

  secp256k1_pubkey pubkey;
  secp256k1_ecdsa_recoverable_signature sig;
  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_context_verify, &sig, &vchSig[1], recid)) {
      return false;
  }
  if (!secp256k1_ecdsa_recover(secp256k1_context_verify, &pubkey, &sig, hash.begin())) {
      return false;
  }

  unsigned char pub[65];
  size_t publen = 65;
  memset(pub, 0, sizeof(pub));
  secp256k1_ec_pubkey_serialize(secp256k1_context_verify, pub, &publen, &pubkey, fComp ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  if (fComp)
    SetCompressedPubKey();

  vchPub = cbuff(pub, pub + publen);
  fPubSet = true;

  return true;
}

bool CKey::Verify(uint256 hash, const std::vector<unsigned char>& vchSig)
{
  secp256k1_ecdsa_signature sig;
  secp256k1_pubkey pubkey;

  if (vchSig.size() == 0) {
    return (error(SHERR_INVAL, "CKey.Verify: empty signature specified."));
  }

  memset(&pubkey, 0, sizeof(pubkey));
  if (!fSet && fPubSet) {
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pubkey, vchPub.data(), vchPub.size())) {
      return (error(SHERR_INVAL, "CKey.Verify: error parsing public key.")); 
    }
  } else { 
    if (!IsValid())
      return false;
    if (!secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, (unsigned char *)vch)) {
      return (error(SHERR_INVAL, "CKey.Verify: error generating public key.")); 
    }
  }

  memset(&sig, 0, sizeof(sig));
  if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig, vchSig.data(), vchSig.size())) {
    return false;
  }

  /* libsecp256k1's ECDSA verification requires lower-S signatures, which have
   * not historically been enforced in coins, so normalize them first. */
  secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, &sig, &sig);

  return (secp256k1_ecdsa_verify(secp256k1_context_verify, 
      &sig, hash.begin(), &pubkey));
}

bool CKey::VerifyCompact(uint256 hash, const std::vector<unsigned char>& vchSig)
{
  CKey key;
  if (!key.SetCompactSignature(hash, vchSig))
    return false;
  if (GetPubKey() != key.GetPubKey())
    return false;

  return true;
}

bool CKey::IsValid()
{

  if (!fSet)
    return (false);

  return secp256k1_ec_seckey_verify(secp256k1_context_sign, vch);
}

static void _keyxor(unsigned char *buf, unsigned char *alt, size_t size)
{
  int i;

  for (i = 0; i < size; i++) {
    buf[i] = buf[i] ^ alt[i];
  }

}

static cbuff ckey_MergeKey(cbuff secret, cbuff tag)
{
  bool fCompr;
  uint256 pkey;
  uint256 mkey;
  unsigned char raw[32];

  /* hash input values */
  pkey = Hash(secret.begin(), secret.end());
  mkey = Hash(tag.begin(), tag.end());
  cbuff pbuff(pkey.begin(), pkey.end());
  cbuff mbuff(mkey.begin(), mkey.end());

  /* calculate new key */
  memset(raw, 0, sizeof(raw));
  memcpy(raw, pbuff.data(), MIN(32, pbuff.size()));
  _keyxor(raw, mbuff.data(), MIN(32, mbuff.size()));

  /* create a key secret */
  return (cbuff(raw, raw + 32));
}

/**
 * Create a new derived key given a "tag" context.
 * @param tag A salt to purturb the calculation.
 */ 
CKey CKey::MergeKey(cbuff tag)
{
  cbuff secret(vch, vch + 32);
  cbuff kbuff;
  unsigned char test_vch[32];

  kbuff = secret;
  do {
    kbuff = ckey_MergeKey(kbuff, tag); 
    memcpy(test_vch, kbuff.data(), sizeof(test_vch));
  } while (!secp256k1_ec_seckey_verify(secp256k1_context_sign, test_vch));

  /* create a key to return */
  CKey key;
  CSecret ksec(kbuff.begin(), kbuff.end());
  key.SetSecret(ksec, fCompressedPubKey);

  return (key);
}

CKey::~CKey()
{
}
