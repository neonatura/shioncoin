
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

#ifndef __SERVER__DIKEY_H__
#define __SERVER__DIKEY_H__


#ifdef __cplusplus
extern "C" {
#endif

/* libdi3 */
#include "di3.h"

#ifdef __cplusplus
#include "key.h"
};
#endif


#ifdef __cplusplus
#include <stdexcept>
#include <vector>

#include "allocators.h"
#include "serialize.h"
#include "uint256.h"
#include "util.h"

#define DILITHIUM_VERSION 0x3

/** Dilithium-3 */
class DIKey : public CKey
{

	public:
		static const unsigned int DILITHIUM_PUBLIC_KEY_SIZE = 1472; 
		static const unsigned int DILITHIUM_PRIVATE_KEY_SIZE = 3504;
		static const unsigned int DILITHIUM_SIGNATURE_SIZE = 2701;
		static const unsigned int DILITHIUM_SECRET_SIZE = 96; 

    DIKey()
		{
			SetNull();
		}

    DIKey(CSecret secret)
		{
			SetNull();
			SetSecret(secret);
		}

    DIKey(const DIKey& b)
		{
			SetNull();
			Init(b);
		}

    DIKey& operator=(const DIKey& b)
		{
			Init(b);
			return (*this);
		}

		friend bool operator==(const DIKey &a, const DIKey &b) { return a.vch == b.vch; }

    bool IsNull() const;

    bool SetPrivKey(const CPrivKey& vchPrivKey, bool fCompressed = false);

    bool SetSecret(const CSecret& vchSecret, bool fCompressed)
		{
			return SetSecret(vchSecret);
		}

    bool SetSecret(const CSecret& vchSecret);

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

    void MakeNewKey(bool fCompressed) /* CKey */
		{
			MakeNewKey();
		}

    void MakeNewKey(); /* CKey */

    bool IsValid(); /* CKey */

    void MergeKey(CKey& childKey, cbuff tag);

		bool Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc);

		void SetCompressedPubKey();

};

struct DIExtPubKey 
{
	uint8_t nDepth;
	uint8_t vchFingerprint[4];
	uint32_t nChild;
	ChainCode chaincode;
	CPubKey pubkey;

	friend bool operator==(const DIExtPubKey &a, const DIExtPubKey &b)
	{
		return a.nDepth == b.nDepth &&
			memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], sizeof(vchFingerprint)) == 0 &&
			a.nChild == b.nChild &&
			a.chaincode == b.chaincode &&
			a.pubkey == b.pubkey;
	}

	bool Derive(DIExtPubKey& out, unsigned int nChild);

	IMPLEMENT_SERIALIZE (
			READWRITE(nDepth);
			READWRITE(FLATDATA(vchFingerprint));
			READWRITE(nChild);
			READWRITE(chaincode);
			READWRITE(pubkey);
	)

};

struct DIExtKey
{
	uint8_t nDepth;
	uint8_t vchFingerprint[4];
	uint32_t nChild;
	ChainCode chaincode;
	DIKey key;

	friend bool operator==(const DIExtKey& a, const DIExtKey& b)
	{
		return a.nDepth == b.nDepth &&
			memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], sizeof(vchFingerprint)) == 0 &&
			a.nChild == b.nChild &&
			a.chaincode == b.chaincode &&
			a.key == b.key;
	}

	bool Derive(DIExtKey& out, unsigned int nChild);

	DIExtPubKey Neuter();

	void SetMaster(const unsigned char* seed, unsigned int nSeedLen);

	IMPLEMENT_SERIALIZE (
			READWRITE(nDepth);
			READWRITE(FLATDATA(vchFingerprint));
			READWRITE(nChild);
			READWRITE(chaincode);
			READWRITE(key);
	)

};

#endif /* __cplusplus */


#endif /* ndef __SERVER__DIKEY_H__ */
