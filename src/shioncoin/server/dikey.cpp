
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
#include "wallet.h"
#include "main.h"
#include <map>
#include "dikey.h"
#include "pqclean_dilithium3_clean/sha3.h"
#include "pqclean_dilithium3_clean/fips202.h"
#include "di3.h"

#define SIP33_EXTKEY_SIZE 

void DIKey::MakeNewKey()
{
	unsigned char secret[DILITHIUM_SECRET_SIZE];
  int i;

  {
    uint64_t *v_ptr = (uint64_t *)secret;
    for (i = 0; i < 4; i++) { /* 12 * 8 = DILITHIUM_SECRET_SIZEb */
      v_ptr[i] = shrand();
    } 
  }

	SetSecret(CSecret(secret, secret+DILITHIUM_SECRET_SIZE));
  fPubSet = false;

}

bool DIKey::SetPrivKey(const CPrivKey& vchPrivKey, bool fCompressed)
{
	return (false);
}

bool DIKey::SetSecret(const CSecret& vchSecret)
{

  if (vchSecret.size() != DILITHIUM_SECRET_SIZE) {
    return (error(SHERR_INVAL, "DIKey.SetSecret: invalid secret size (%d) specified.", vchSecret.size()));
  }

	vch = vchSecret;

	if (meta.nCreateTime == 0)
		meta.nCreateTime = GetTime();

	meta.nFlag |= CKeyMetadata::META_DILITHIUM;

	/* always considered 'compressed'. */
	SetCompressedPubKey();

	fPubSet = false;

  return (true);
}

CPrivKey DIKey::GetPrivKey() const
{
	uint8_t sk[DILITHIUM_PRIVATE_KEY_SIZE];
	uint8_t pk[DILITHIUM_PUBLIC_KEY_SIZE];
	int err;

  if (IsNull())
    return (CPrivKey());

	memset(sk, 0, sizeof(sk));
	err = di3_keypair(pk, sk, (uint8_t *)vch.data());
	if (err) {
		error(err, "DIKey.GetPrivKey: error generating di3 keypair");
    return (CPrivKey());
	}

  return (CPrivKey(sk, sk + DILITHIUM_PRIVATE_KEY_SIZE));
}

bool DIKey::SetPubKey(const CPubKey& vchPubKey)
{

	if (vchPubKey.size() != (DILITHIUM_PUBLIC_KEY_SIZE + 1))
		return (false);

  /* stoe for later */
  vchPub = cbuff(vchPubKey.begin(), vchPubKey.end());
  fPubSet = true;

  return (true);
}

CPubKey DIKey::GetPubKey() const
{

  if (IsNull()) {
    if (fPubSet) {
      /* key is carring a public key */
      return (CPubKey(vchPub));
    }

    return (CPubKey());
  }

	static const uint8_t ver = DILITHIUM_VERSION;
	uint8_t pk[DILITHIUM_PUBLIC_KEY_SIZE];
	uint8_t sk[DILITHIUM_PRIVATE_KEY_SIZE];
	int err;

  if (IsNull()) {
    return (CPubKey());
	}

	err = di3_keypair(pk, sk, (uint8_t *)vch.data());
	if (err) {
		error(err, "DIKey.GetPrivKey: error generating di3 keypair");
    return (CPubKey());
	}

	cbuff pubkey_buf(&ver, &ver + 1);
	pubkey_buf.insert(pubkey_buf.end(), pk, pk + DILITHIUM_PUBLIC_KEY_SIZE);
  CPubKey ret_pubkey(pubkey_buf);
  if (!ret_pubkey.IsValid()) {
    error(SHERR_INVAL, "DIKey.GetPubKey: error serializing public key.");
    return (CPubKey());
  }

  return (ret_pubkey);
}

bool DIKey::Sign(uint256 hash, std::vector<unsigned char>& vchSig)
{
	uint8_t pk[DILITHIUM_PUBLIC_KEY_SIZE];
	uint8_t sk[DILITHIUM_PRIVATE_KEY_SIZE];
	uint8_t sig_buf[DILITHIUM_SIGNATURE_SIZE];
	int err;

  if (IsNull())
    return false;

  vchSig.clear();

	err = di3_keypair(pk, sk, vch.data());
	if (err)
		return (error(err, "DIKey.GetPrivKey: error generating di3 keypair"));

	size_t sig_len = DILITHIUM_SIGNATURE_SIZE;
	err = di3_sign(sig_buf, &sig_len,
			hash.begin(), sizeof(uint256), sk);
	if (err) {
    error(err, "ECKey.Sign: di3_sign error");
		return (false);
	}

  vchSig = cbuff(sig_buf, sig_buf + DILITHIUM_SIGNATURE_SIZE);
  return (true);
}

bool DIKey::SignCompact(uint256 hash, std::vector<unsigned char>& vchSig)
{
	static const uint8_t ver = DILITHIUM_VERSION;
	uint8_t sig_buf[DILITHIUM_SIGNATURE_SIZE];
	uint8_t pk[DILITHIUM_PUBLIC_KEY_SIZE];
	uint8_t sk[DILITHIUM_PRIVATE_KEY_SIZE];
	int err;

  if (IsNull()) {
    return (error(SHERR_INVAL, "DIKey.SignCompact: error signing unitialized key."));
  }

  vchSig.clear();

	err = di3_keypair(pk, sk, vch.data());
	if (err) {
		error(err, "DIKey.GetPrivKey: error generating di3 keypair");
    return (false);
	}

	size_t sig_len = DILITHIUM_SIGNATURE_SIZE;
	err = di3_sign(sig_buf, &sig_len, hash.begin(), sizeof(uint256), sk);
	if (err) {
    error(err, "ECKey.Sign: di3_sign error");
		return (false);
	}

	vchSig = cbuff(&ver, &ver + 1);
	vchSig.insert(vchSig.end(), pk, pk + DILITHIUM_PUBLIC_KEY_SIZE);
	vchSig.insert(vchSig.end(), sig_buf, sig_buf + DILITHIUM_SIGNATURE_SIZE);

  return (true);
}

bool DIKey::SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig)
{
	cbuff sig;

  if (vchSig.size() != 4174) {
		error(ERR_INVAL, "DIKey.SetCompactSignature: invalid compact signature size (%d).\n", vchSig.size());
		return (false);
	}

	vchPub = cbuff(vchSig.begin(),
			vchSig.begin() + (DILITHIUM_PUBLIC_KEY_SIZE + 1));
  fPubSet = true;

	sig = cbuff(vchSig.begin() + vchPub.size(), vchSig.end());
	return (Verify(hash, sig));
}

bool DIKey::Verify(uint256 hash, const std::vector<unsigned char>& vchSig)
{
	int err;

  if (vchSig.size() != DILITHIUM_SIGNATURE_SIZE) {
    return (error(SHERR_INVAL, "DIKey.Verify: invalid signature size (%d).", (int)vchSig.size()));
  }

	uint8_t pk[DILITHIUM_PUBLIC_KEY_SIZE];
  if (IsNull() && fPubSet) {
		if ((vchPub.size() -1) != DILITHIUM_PUBLIC_KEY_SIZE)
			return (error(SHERR_INVAL, "DIKey.Verify: invalid pubkey size (%d).", (int)vchPub.size()));
		memcpy(pk, vchPub.data() + 1, vchPub.size() - 1);
  } else { 
		uint8_t _unused[DILITHIUM_PRIVATE_KEY_SIZE];

    if (!IsValid())
      return (false);

		err = di3_keypair(pk, _unused, vch.data());
		memset(_unused, 0, sizeof(_unused));
		if (err)
      return (error(SHERR_INVAL, "DIKey.Verify: error generating public key."));
  }

	err = di3_verify(vchSig.data(), vchSig.size(), 
			hash.begin(), sizeof(uint256), pk); 
	if (err)
		return (false);

	return (true);
}

bool DIKey::VerifyCompact(uint256 hash, const std::vector<unsigned char>& vchSig)
{

  DIKey key;
  if (!key.SetCompactSignature(hash, vchSig))
    return (false);

  if (GetPubKey() != key.GetPubKey()) {
		error(ERR_INVAL, "DIKey.VerifyCompact: invalid public key generated.");
    return (false);
	}

  return (true);
}

bool DIKey::IsValid()
{
	uint8_t pk[DILITHIUM_PUBLIC_KEY_SIZE];
	uint8_t sk[DILITHIUM_PRIVATE_KEY_SIZE];
	int err;

  if (IsNull())
    return (false);

	if (vch.size() != DILITHIUM_SECRET_SIZE)
		return (false);

	err = di3_keypair(pk, sk, (uint8_t *)vch.data());
	if (err)
		return (false);

	return (true);
}

static void _memxor(unsigned char *buf, unsigned char *alt, size_t size)
{
  int i;

  for (i = 0; i < size; i++) {
    buf[i] = buf[i] ^ alt[i];
  }

}

static cbuff dikey_MergeKey(cbuff secret, cbuff tag)
{
	static const uint8_t version = DILITHIUM_VERSION;
  unsigned char output[DIKey::DILITHIUM_SECRET_SIZE];

	memset(output, 0, sizeof(output));

	{
		shake256incctx state;
		shake256_inc_init(&state);
		shake256_inc_absorb(&state, (const uint8_t *)secret.data(), (size_t)secret.size());
		shake256_inc_absorb(&state, (const uint8_t *)&version, 1);
		shake256_inc_absorb(&state, (const uint8_t *)tag.data(), (size_t)tag.size());
		shake256_inc_finalize(&state);
		shake256_inc_squeeze(output, DIKey::DILITHIUM_SECRET_SIZE, &state);
	}

  /* create a key secret */
  return (cbuff(output, output + DIKey::DILITHIUM_SECRET_SIZE));
}

/**
 * Create a new derived key given a "tag" context.
 * @param tag A salt to purturb the calculation.
 */ 
void DIKey::MergeKey(CKey& childKey, cbuff tag)
{
  cbuff secret(vch.begin(), vch.end());
  cbuff kbuff = dikey_MergeKey(secret, tag); 

  /* create a key to return */
  DIKey key;
  CSecret ksec(kbuff.begin(), kbuff.end());
  key.SetSecret(ksec);

	childKey = key;
}

static void SIP33Hash(const ChainCode &chainCode, unsigned int nChild, uint16_t header, uint8_t *data, size_t data_len, unsigned char *output/*[128]*/)
{
	
	memset(output, 0, 128);
	(void)di3_derive_hash(output, 128, 
			data, data_len, (uint8_t *)&chainCode, 
			nChild, header);

}

bool DIKey::Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const 
{
	std::vector<unsigned char, secure_allocator<unsigned char>> vout(128);
	unsigned char vchKey[DILITHIUM_SECRET_SIZE];

	if ((nChild >> 31) == 0) {
		CPubKey pubkey = GetPubKey();
		uint8_t header;

		if (!pubkey.IsValid()) {
			error(ERR_INVAL, "DIKey.Derive: error generating pubkey.");
			return (false);
		}

		memcpy(&header, pubkey.begin(), 1);
		if (header != DILITHIUM_VERSION) {
			return (error(ERR_OPNOTSUPP, "DIKey.Derive: invalid pubkey header (%u)\n", (unsigned int)header));
		}
		SIP33Hash(cc, nChild, header, /* uses pubkey */ 
				(uint8_t *)pubkey.begin()+1, DILITHIUM_PUBLIC_KEY_SIZE, vout.data());
	} else {
		SIP33Hash(cc, nChild, 0, /* uses secret data */ 
				(uint8_t *)begin(), DILITHIUM_SECRET_SIZE, vout.data());
	}

	memcpy(ccChild.begin(), vout.data()+DILITHIUM_SECRET_SIZE, 32);
	memcpy(vchKey, vout.data(), DILITHIUM_SECRET_SIZE);

	keyChild = DIKey(CSecret(vchKey, vchKey+DILITHIUM_SECRET_SIZE));
	return (true);
}

bool DIExtKey::Derive(DIExtKey &out, unsigned int _nChild) const 
{
	out.nDepth = nDepth + 1;
	CKeyID id = key.GetPubKey().GetID();
	memcpy(&out.vchFingerprint[0], &id, 4);
	out.nChild = _nChild;
	return key.Derive(out.key, out.chaincode, _nChild, chaincode);
}

void DIExtKey::SetMaster(const unsigned char *seed, unsigned int nSeedLen) 
{
	static const unsigned char header[32] = 
		{'S','h','i','o','n','c','o','i','n',' ','D','i','l','i','t','h','i','u','m',' ','M','a','s','t','e','r',' ','S','e','e','d','.'};
	static const uint8_t version = DILITHIUM_VERSION;
	uint8_t buf[128];
	int err;

	nDepth = 0;
	nChild = 0;
	memset(vchFingerprint, 0, sizeof(vchFingerprint));

	memset(buf, 0, sizeof(buf));
	{
		shake256incctx state;
		shake256_inc_init(&state);
		shake256_inc_absorb(&state, (const uint8_t *)header, sizeof(header));
		shake256_inc_absorb(&state, (const uint8_t *)&version, 1);
		shake256_inc_absorb(&state, (const uint8_t *)seed, (size_t)nSeedLen);
		shake256_inc_finalize(&state);
		shake256_inc_squeeze(buf, DIKey::DILITHIUM_SECRET_SIZE + sizeof(chaincode), &state);
	}

	key.SetSecret(CSecret(buf, buf + DIKey::DILITHIUM_SECRET_SIZE));
	memcpy(&chaincode, buf + DIKey::DILITHIUM_SECRET_SIZE, sizeof(chaincode));
}

DIExtPubKey DIExtKey::Neuter() const 
{
	DIExtPubKey ret;
	ret.nDepth = nDepth;
	memcpy(&ret.vchFingerprint[0], &vchFingerprint[0], 4);
	ret.nChild = nChild;
	ret.pubkey = key.GetPubKey();
	ret.chaincode = chaincode;
	return ret;
}

bool DIExtPubKey::Derive(DIExtPubKey& outPubKey, unsigned int nChild) const
{
	return (false);
}

bool DIKey::IsNull() const
{
	return (CKey::IsNull());
}

