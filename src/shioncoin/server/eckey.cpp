
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
 *
 *  This file is part of ShionCoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcoind.h"
#include "main.h"
#include <map>
#include "key.h"
#include "eckey.h"
#include "hmac_sha512.h"

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

#if 0
void ECKey::Reset()
{
  fCompressedPubKey = false;
  fPubSet = false;
  fSet = false;

  memset(vch, '\000', sizeof(vch));
  vchPub.clear();
}
#endif

#if 0
ECKey::ECKey(const ECKey& b)
{
  memcpy(vch, b.vch, sizeof(vch));
  vchPub = b.vchPub;
  fSet = b.fSet;
  fCompressedPubKey = b.fCompressedPubKey; /* 12.17 */
}

ECKey& ECKey::operator=(const ECKey& b)
{
  memcpy(vch, b.vch, sizeof(vch));
  vchPub = b.vchPub;
  fSet = b.fSet;
  fCompressedPubKey = b.fCompressedPubKey;
  return (*this);
}
#endif

void ECKey::MakeNewKey(bool fCompressed)
{
	unsigned char secret[32];
  int i;

  do {
    uint64_t *v_ptr = (uint64_t *)secret;//(uint64_t *)vch.data();
    for (i = 0; i < 4; i++) { /* 4 * 8 = 32b */
      v_ptr[i] = shrand();
    } 
  } while (!secp256k1_ec_seckey_verify(secp256k1_context_sign, secret));//vch.data()));

	SetSecret(CSecret(secret, secret+32), fCompressed);
#if 0
	vch = CSecret(cbuff(secret, secret+32));
  if (fCompressed)
    SetCompressedPubKey();
#endif

//  fSet = true;
  fPubSet = false;

}

bool ECKey::SetPrivKey(const CPrivKey& vchPrivKey, bool fCompressed)
{
	unsigned char secret[32];

	memset(secret, 0, sizeof(secret));
  if (!ec_privkey_import_der(secp256k1_context_sign, secret, vchPrivKey.data(), vchPrivKey.size()))
    return (false);

//  fSet = true;
	SetSecret(CSecret(secret, secret+32), (fCompressed || fCompressedPubKey));
#if 0
  if (fCompressed || fCompressedPubKey)
    SetCompressedPubKey();
#endif

  return true;
}

bool ECKey::SetSecret(const CSecret& vchSecret, bool fCompressed)
{
  unsigned char buf[32];

  if (vchSecret.size() != 32) {
    return (error(SHERR_INVAL, "ECKey.SetSecret: invalid secret size (%d) specified.", vchSecret.size()));
  }

  cbuff vchIn(vchSecret.begin(), vchSecret.end());
  memcpy(buf, vchIn.data(), 32);
  if (!secp256k1_ec_seckey_verify(secp256k1_context_sign, buf)) {
    return (error(SHERR_INVAL, "ECKey.SetSecret: invalid secret specified."));
  }

	vch = vchSecret;
  //fSet = true;
  if (fCompressed || fCompressedPubKey)
    SetCompressedPubKey();

	if (nCreateTime == 0)
		nCreateTime = GetTime();

	fPubSet = false;

  return true;
}

CPrivKey ECKey::GetPrivKey() const
{
//  CPrivKey privkey;
  int ret;

  if (IsNull())
    return (CPrivKey());

  unsigned char privkey_buf[280];
  size_t privkeylen;
//  privkey.resize(279);

  memset(privkey_buf, 0, sizeof(privkey_buf));
  privkeylen = 279;

  ret = ec_privkey_export_der(secp256k1_context_sign, privkey_buf, &privkeylen, (unsigned char *)vch.data(), fCompressedPubKey ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
//  assert(ret);
  if (!ret)
    return (CPrivKey());

  //privkey.resize(privkeylen);
  return (CPrivKey(privkey_buf, privkey_buf + privkeylen));
}

bool ECKey::SetPubKey(const CPubKey& vchPubKey)
{
  const unsigned char* pbegin = vchPubKey.begin();
  size_t psize = vchPubKey.size();

  /* verify integrity */
  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, pbegin, psize)) {
    return (error(SHERR_INVAL, "ECKey.SetPubKey: invalid pubkey specified."));
  }

  /* stoe for later */
  vchPub = cbuff(vchPubKey.begin(), vchPubKey.end());

  if (psize == 33)
    SetCompressedPubKey();

  fPubSet = true;

  return true;
}

CPubKey ECKey::GetPubKey() const
{

  if (IsNull()) {
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
  int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, (unsigned char *)vch.data());
  if (!ret) {
    error(SHERR_INVAL, "ECKey.GetPubKey: error creating public key.");
    return (CPubKey());
  }
//  assert(ret);

  secp256k1_ec_pubkey_serialize(secp256k1_context_sign, result, &clen, &pubkey, fCompressedPubKey ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
//  assert(result.size() == clen);
//  assert(result.IsValid());

  CPubKey ret_pubkey(cbuff(result, result + clen));
  if (!ret_pubkey.IsValid()) {
    error(SHERR_INVAL, "ECKey.GetPubKey: error serializing public key.");
    return (CPubKey());
  }

  return (ret_pubkey);
}

bool ECKey::Sign(uint256 hash, std::vector<unsigned char>& vchSig)
{

  if (IsNull())
    return false;

  vchSig.resize(72);
  size_t nSigLen = 72;

  secp256k1_ecdsa_signature sig;
  int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), (unsigned char *)vch.data(), secp256k1_nonce_function_rfc6979, NULL);
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

bool ECKey::SignCompact(uint256 hash, std::vector<unsigned char>& vchSig)
{
  secp256k1_ecdsa_recoverable_signature sig;
  int rec;
  int ret;

  if (IsNull()) {
    return (error(SHERR_INVAL, "ECKey.SignCompact: error signing unitialized key."));
  }

  vchSig.resize(65);

  ret = secp256k1_ecdsa_sign_recoverable(secp256k1_context_sign, &sig, hash.begin(), (unsigned char *)vch.data(), secp256k1_nonce_function_rfc6979, NULL);
  if (!ret) {
    return (error(SHERR_INVAL, "ECKey.SignCompact: error signing compact signature."));
  }

  rec = -1;
  ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_sign, (unsigned char*)&vchSig[1], &rec, &sig);
  if (!ret || rec == -1) {
    return (error(SHERR_INVAL, "ECKey.SignCompact: error serializing compact signature."));
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

bool ECKey::SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig)
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

bool ECKey::Verify(uint256 hash, const std::vector<unsigned char>& vchSig)
{
  secp256k1_ecdsa_signature sig;
  secp256k1_pubkey pubkey;

  if (vchSig.size() == 0) {
    return (error(SHERR_INVAL, "ECKey.Verify: empty signature specified."));
  }

  memset(&pubkey, 0, sizeof(pubkey));
  if (IsNull() && fPubSet) {
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pubkey, vchPub.data(), vchPub.size())) {
      return (error(SHERR_INVAL, "ECKey.Verify: error parsing public key.")); 
    }
  } else { 
    if (!IsValid())
      return false;
    if (!secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, (unsigned char *)vch.data())) {
      return (error(SHERR_INVAL, "ECKey.Verify: error generating public key.")); 
    }
  }

  memset(&sig, 0, sizeof(sig));
  if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig, vchSig.data(), vchSig.size())) {
    return false;
  }

  /* libsecp256k1's ECDSA verification requires lower-S signatures, which have
   * not historically been enforced in coins, so normalize them first. */
  secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, &sig, &sig);

bool ok =
  secp256k1_ecdsa_verify(secp256k1_context_verify, 
      &sig, hash.begin(), &pubkey);
return (ok);
}

bool ECKey::VerifyCompact(uint256 hash, const std::vector<unsigned char>& vchSig)
{
  ECKey key;
  if (!key.SetCompactSignature(hash, vchSig))
    return false;
  if (GetPubKey() != key.GetPubKey())
    return false;

  return true;
}

bool ECKey::IsValid()
{

  if (IsNull())
    return (false);

  return secp256k1_ec_seckey_verify(secp256k1_context_sign, vch.data());
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
void ECKey::MergeKey(CKey& childKey, cbuff tag)
{
  cbuff secret(vch.begin(), vch.end());
  cbuff kbuff;
  unsigned char test_vch[32];

  kbuff = secret;
  do {
    kbuff = ckey_MergeKey(kbuff, tag); 
    memcpy(test_vch, kbuff.data(), sizeof(test_vch));
  } while (!secp256k1_ec_seckey_verify(secp256k1_context_sign, test_vch));

  /* create a key to return */
  ECKey key;
  CSecret ksec(kbuff.begin(), kbuff.end());
  key.SetSecret(ksec, fCompressedPubKey);

	childKey = key;
//  return (key);
}

void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64])
{
	unsigned char num[4];
	num[0] = (nChild >> 24) & 0xFF;
	num[1] = (nChild >> 16) & 0xFF;
	num[2] = (nChild >>  8) & 0xFF;
	num[3] = (nChild >>  0) & 0xFF;
	CHMAC_SHA512(chainCode.begin(), sizeof(ChainCode)).Write(&header, 1).Write(data, 32).Write(num, 4).Finalize(output);
}

bool ECKey::Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const 
{
	unsigned char vch[32];

	std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
	if ((nChild >> 31) == 0) {
		CPubKey pubkey = GetPubKey();
		BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, vout.data());
	} else {
		BIP32Hash(cc, nChild, 0, begin(), vout.data());
	}

	memcpy(ccChild.begin(), vout.data()+32, 32);
	memcpy(vch, begin(), 32);
//	memcpy((unsigned char*)keyChild.begin(), begin(), 32);

	//bool ret = secp256k1_ec_privkey_tweak_add(secp256k1_context_sign, (unsigned char*)keyChild.begin(), vout.data());
	//keyChild.fCompressed = true;
	//keyChild.fValid = ret;
	bool ret = secp256k1_ec_privkey_tweak_add(secp256k1_context_sign, (unsigned char*)vch, vout.data());
	if (ret)
		keyChild = ECKey(CSecret(vch, vch+32), true);

	return (ret);
}

bool ECExtKey::Derive(ECExtKey &out, unsigned int _nChild) const 
{
	out.nDepth = nDepth + 1;
	CKeyID id = key.GetPubKey().GetID();
	memcpy(&out.vchFingerprint[0], &id, 4);
	out.nChild = _nChild;
	return key.Derive(out.key, out.chaincode, _nChild, chaincode);
}

void ECExtKey::SetMaster(const unsigned char *seed, unsigned int nSeedLen) 
{
	static const unsigned char hashkey[] = {'S','h','i','o','n','c','o','i','n'};
	std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
	CHMAC_SHA512(hashkey, sizeof(hashkey)).Write(seed, nSeedLen).Finalize(vout.data());
	key.SetSecret(CSecret(vout.data(), vout.data() + 32), true);
	memcpy(chaincode.begin(), vout.data() + 32, 32);
	nDepth = 0;
	nChild = 0;
	memset(vchFingerprint, 0, sizeof(vchFingerprint));
}

ECExtPubKey ECExtKey::Neuter() const 
{
	ECExtPubKey ret;
	ret.nDepth = nDepth;
	memcpy(&ret.vchFingerprint[0], &vchFingerprint[0], 4);
	ret.nChild = nChild;
	ret.pubkey = key.GetPubKey();
	ret.chaincode = chaincode;
	return ret;
}

static const unsigned int COMPRESSED_PUBLIC_KEY_SIZE  = 33;

bool ECExtPubKey::Derive(ECExtPubKey& outPubKey, unsigned int nChild) const
{
	outPubKey.nDepth = nDepth + 1;
	CKeyID id = pubkey.GetID();
	memcpy(&outPubKey.vchFingerprint[0], &id, 4);
	outPubKey.nChild = nChild;

	CPubKey& pubkeyChild = outPubKey.pubkey;
	ChainCode& ccChild = outPubKey.chaincode;
	const ChainCode& cc = chaincode;
	{
    unsigned char out[64];
		const unsigned char *raw = pubkey.begin();
    BIP32Hash(cc, nChild, raw[0], raw+1, out);
    memcpy(ccChild.begin(), out+32, 32);
    secp256k1_pubkey pubkey_new;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey_new, pubkey.begin(), pubkey.size())) {
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_context_verify, &pubkey_new, out)) {
        return false;
    }
    unsigned char pub[COMPRESSED_PUBLIC_KEY_SIZE];
    size_t publen = COMPRESSED_PUBLIC_KEY_SIZE;
    secp256k1_ec_pubkey_serialize(secp256k1_context_verify, pub, &publen, &pubkey_new, SECP256K1_EC_COMPRESSED);
    //pubkeyChild.Set(pub, pub + publen);
    pubkeyChild = CPubKey(cbuff(pub, pub + publen));
	}
	return true;
}

void ECExtKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const 
{

	memset(code, '\000', BIP32_EXTKEY_SIZE);

	code[0] = nDepth;
	memcpy(code+1, vchFingerprint, 4);
	code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
	code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
	memcpy(code+9, chaincode.begin(), 32);
	code[41] = 0;
	memcpy(code+42, key.begin(), MIN(32, key.size()));
}

void ECExtKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE])
{

//	SetNull();

	nDepth = code[0];
	memcpy(vchFingerprint, code+1, 4);
	nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
	memcpy(chaincode.begin(), code+9, 32);
	key.SetSecret(CSecret(code+42, code+BIP32_EXTKEY_SIZE), true);

}

void ECExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const 
{

	memset(code, '\000', BIP32_EXTKEY_SIZE);

	code[0] = nDepth;
	memcpy(code+1, vchFingerprint, 4);
	code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
	code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
	memcpy(code+9, chaincode.begin(), 32);
	memcpy(code+41, pubkey.begin(), COMPRESSED_PUBLIC_KEY_SIZE);
}

void ECExtPubKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE])
{

//	SetNull();

	nDepth = code[0];
	memcpy(vchFingerprint, code+1, 4); 
	nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
	memcpy(chaincode.begin(), code+9, 32);
	pubkey = CPubKey(cbuff(code+41, code+BIP32_EXTKEY_SIZE));
}

bool ECKey::IsNull() const
{
	return (CKey::IsNull());
}
