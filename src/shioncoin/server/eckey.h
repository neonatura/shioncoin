
/*
 * @copyright
 *
 *  Copyright 2017 Brian Burrell
 *
 *  This file is part of Shioncoin.
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

#ifndef __SERVER__ECKEY_H__
#define __SERVER__ECKEY_H__

/* libsecp256k1 */
#include "secp256k1.h"
#include "secp256k1_recovery.h"

#ifdef __cplusplus
#include "key.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif
void INIT_SECP256K1(void);

secp256k1_context *SECP256K1_VERIFY_CONTEXT(void);

secp256k1_context *SECP256K1_SIGN_CONTEXT(void);

void TERM_SECP256K1(void);
#ifdef __cplusplus
};
#endif


#ifdef __cplusplus
#include <stdexcept>
#include <vector>

#include "allocators.h"
#include "serialize.h"
#include "uint256.h"
#include "util.h"

const unsigned int BIP32_EXTKEY_SIZE = 74;

/** An encapsulated Elliptic Curve key (public and/or private) */
class ECKey : public CKey
{

	public:

    ECKey()
		{
			SetNull();
		}

    ECKey(CSecret secret, bool fCompressed = true)
		{
			SetNull();
			SetSecret(secret, fCompressed);
		}

    ECKey(const ECKey& b)
		{
			SetNull();
			Init(b);
		}

    ECKey& operator=(const ECKey& b)
		{
			Init(b);
			return (*this);
		}

		friend bool operator==(const ECKey &a, const ECKey &b) { return a.vch == b.vch; }

    bool IsNull() const;

    bool SetPrivKey(const CPrivKey& vchPrivKey, bool fCompressed = false);

    bool SetSecret(const CSecret& vchSecret, bool fCompressed = false);

    CPrivKey GetPrivKey() const;

    bool SetPubKey(const CPubKey& vchPubKey);

    CPubKey GetPubKey(); /* CKey */

    bool Sign(uint256 hash, std::vector<unsigned char>& vchSig); /* CKey */

    // create a compact signature (65 bytes), which allows reconstructing the used public key
    // The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
    // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
    //                  0x1D = second key with even y, 0x1E = second key with odd y
    bool SignCompact(uint256 hash, std::vector<unsigned char>& vchSig); /* CKey */

    // reconstruct public key from a compact signature
    // This is only slightly more CPU intensive than just verifying it.
    // If this function succeeds, the recovered public key is guaranteed to be valid
    // (the signature is a valid signature of the given data for that key)
    bool SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig); /* CKey */

    bool Verify(uint256 hash, const std::vector<unsigned char>& vchSig); /* CKey */

    // Verify a compact signature
    bool VerifyCompact(uint256 hash, const std::vector<unsigned char>& vchSig); /* CKey */

    void MakeNewKey(bool fCompressed); /* CKey */

    bool IsValid(); /* CKey */

    void MergeKey(CKey& childKey, cbuff tag);

		bool Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc);

		void SetCompressedPubKey();

};

struct ECExtPubKey 
{
	uint8_t nDepth;
	uint8_t vchFingerprint[4];
	uint32_t nChild;
	ChainCode chaincode;
	CPubKey pubkey;

	friend bool operator==(const ECExtPubKey &a, const ECExtPubKey &b)
	{
		return a.nDepth == b.nDepth &&
			memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], sizeof(vchFingerprint)) == 0 &&
			a.nChild == b.nChild &&
			a.chaincode == b.chaincode &&
			a.pubkey == b.pubkey;
	}

	bool Derive(ECExtPubKey& out, unsigned int nChild);

	void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;

	void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);

	IMPLEMENT_SERIALIZE
	(
		unsigned char code[BIP32_EXTKEY_SIZE];
		uint8_t code_size = BIP32_EXTKEY_SIZE;
		if (fWrite) {
			Encode(code);
		}
		READWRITE(FLATDATA(code_size));
		READWRITE(FLATDATA(code));
		if (fRead) {
			ECExtPubKey *_self = (ECExtPubKey *)this;
			_self->nDepth = code[0];
			memcpy(_self->vchFingerprint, code+1, 4); 
			_self->nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
			memcpy(_self->chaincode.begin(), code+9, 32);
			_self->pubkey = CPubKey(cbuff(code+41, code+BIP32_EXTKEY_SIZE));
		} 
	)

};

struct ECExtKey
{
	uint8_t nDepth;
	uint8_t vchFingerprint[4];
	uint32_t nChild;
	ChainCode chaincode;
	ECKey key;

	friend bool operator==(const ECExtKey& a, const ECExtKey& b)
	{
		return a.nDepth == b.nDepth &&
			memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], sizeof(vchFingerprint)) == 0 &&
			a.nChild == b.nChild &&
			a.chaincode == b.chaincode &&
			a.key == b.key;
	}

	bool Derive(ECExtKey& out, unsigned int nChild);

	ECExtPubKey Neuter();

	void SetMaster(const unsigned char* seed, unsigned int nSeedLen);

	void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;

	void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);

	IMPLEMENT_SERIALIZE
	(
		unsigned char code[BIP32_EXTKEY_SIZE];
		uint8_t code_size = BIP32_EXTKEY_SIZE;

		if (fWrite) {
			Encode(code);
		}
		READWRITE(FLATDATA(code_size));
		READWRITE(FLATDATA(code));
		if (fRead) {
			ECExtKey *_self = (ECExtKey *)this;

			_self->nDepth = code[0];
			memcpy(_self->vchFingerprint, code+1, 4);
			_self->nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
			memcpy(_self->chaincode.begin(), code+9, 32);
			_self->key.SetSecret(CSecret(code+42, code+BIP32_EXTKEY_SIZE), true);
		}
	)

};

#endif /* __cplusplus */


#endif /* ndef __SERVER__ECKEY_H__ */
