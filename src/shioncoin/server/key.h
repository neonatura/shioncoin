
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
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

#ifndef __SERVER__KEY_H__
#define __SERVER__KEY_H__

#include "shcoind.h"

#include <stdexcept>
#include <vector>

#include "allocators.h"
#include "serialize.h"
#include "uint256.h"
#include "util.h"

#define SIGN_ALG_NONE 0
#define SIGN_ALG_ECDSA 1
#define SIGN_ALG_DILITHIUM 2

/* use segwit program, if available. */
#define ACCADDRF_WITNESS (1 << 0)
/* hdkey derived. */
#define ACCADDRF_DERIVE (1 << 1)
/* always the same address returned */
#define ACCADDRF_STATIC (1 << 2)
/* permit dilithium signature */
#define ACCADDRF_DILITHIUM (1 << 3)
/* extended transaction (internal) */
#define ACCADDRF_INTERNAL (1 << 4)
/* the 'default' key for an account. */
#define ACCADDRF_MASTER (1 << 5)

typedef uint256 ChainCode;

// secure_allocator is defined in serialize.h
// CPrivKey is a serialized private key, with all parameters included (279 bytes)
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;
// CSecret is a serialization of just the secret parameter (32 bytes)
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CSecret;

// script supports up to 75 for single byte push

class key_error : public std::runtime_error
{
	public:
    explicit key_error(const std::string& str) : std::runtime_error(str) {}
};

/**
 * The public key of a coin address referenced as a 160-bit hash.
 * @see CCoinAddr
 */
class CKeyID : public uint160
{
	public:
    CKeyID() : uint160(0) { }
    CKeyID(const uint160 &in) : uint160(in) { }
};

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
	public:
    CScriptID() : uint160(0) { }
    CScriptID(const uint160 &in) : uint160(in) { }
    CScriptID(const CScript& in);
};

/** An encapsulated public key. */
class CPubKey 
{

	protected:
		std::vector<unsigned char> vchPubKey;
		friend class CKey;

	public:
		CPubKey()
		{
			SetNull();
		}

		CPubKey(const std::vector<unsigned char> &vchPubKeyIn) : vchPubKey(vchPubKeyIn) { }

		friend bool operator==(const CPubKey &a, const CPubKey &b) { return a.vchPubKey == b.vchPubKey; }
		friend bool operator!=(const CPubKey &a, const CPubKey &b) { return a.vchPubKey != b.vchPubKey; }
		friend bool operator<(const CPubKey &a, const CPubKey &b) { return a.vchPubKey < b.vchPubKey; }

		IMPLEMENT_SERIALIZE(
				READWRITE(vchPubKey);
				)

			CKeyID GetID() const {
				return CKeyID(Hash160(vchPubKey));
			}

		uint256 GetHash() const {
			return Hash(vchPubKey.begin(), vchPubKey.end());
		}

		void SetNull()
		{
			vchPubKey.clear();
		}

		std::vector<unsigned char> Raw() const 
		{
			return vchPubKey;
		}

		void Invalidate()
		{
			SetNull();
		}

		bool IsValid() const
		{
			return (
					GetMethod() == SIGN_ALG_ECDSA || 
					GetMethod() == SIGN_ALG_DILITHIUM
					);
		}

		bool IsCompressed() const
		{
			return (vchPubKey.size() == 33 || IsDilithium());
		}

		int GetMethod() const
		{
			switch (vchPubKey.size()) {
				case 1473: return SIGN_ALG_DILITHIUM; /* DILITHIUM-3 */
				case 33: case 65: return SIGN_ALG_ECDSA; /* ECDSA 256k1 */
			}
			return (SIGN_ALG_NONE);
		}

		bool IsDilithium() const
		{
			return (GetMethod() == SIGN_ALG_DILITHIUM);
		}

		unsigned int size() const { return vchPubKey.size(); }

		const unsigned char* begin() const { return vchPubKey.data(); }

		const unsigned char* end() const { return vchPubKey.data() + size(); }

};

class CKeyMetadata
{
	public:
		static const int META_SEGWIT = ACCADDRF_WITNESS;
		static const int META_HD_KEY = ACCADDRF_DERIVE;
		static const int META_PRIMARY = ACCADDRF_STATIC;

		unsigned int nFlag;
		int64_t nCreateTime; // 0 means unknown
		std::string hdKeypath; //optional HD/bip32 keypath
		CKeyID hdMasterKeyID; //id of the HD masterkey used to derive this key

		CKeyMetadata()
		{
			SetNull();
		}

		explicit CKeyMetadata(int64_t nCreateTime_)
		{
			SetNull();
			nCreateTime = nCreateTime_;
		}

		void SetNull()
		{
			nFlag = 0;
			nCreateTime = 0;
			hdKeypath.clear();
			hdMasterKeyID.SetNull();
		}

		void Init(const CKeyMetadata& b)
		{
			nFlag = b.nFlag;
			nCreateTime = b.nCreateTime;
			hdKeypath = b.hdKeypath;
			hdMasterKeyID = b.hdMasterKeyID;
		}

		IMPLEMENT_SERIALIZE
		(
			READWRITE(nFlag);
			READWRITE(nCreateTime);
			if (nFlag & CKeyMetadata::META_HD_KEY) {
				READWRITE(hdKeypath);
				READWRITE(hdMasterKeyID);
			}
		)

		const string GetFlagString() const
		{
			string ret_str;
			if (nFlag & META_HD_KEY)
				ret_str += "hd ";
			if (nFlag & META_SEGWIT)
				ret_str += "wit ";
			if (nFlag & META_PRIMARY)
				ret_str += "pri ";
			if (ret_str.size() != 0)
				ret_str = ret_str.substr(0, ret_str.size()-1);
			return (ret_str);
		}

};

class CKey : public CKeyMetadata
{
	protected:
    CSecret vch;
    bool fPubSet;
    bool fCompressedPubKey;
    cbuff vchPub;

		void Init(const CKey& b)
		{
			CKeyMetadata::Init(b);
			vch = b.vch;
			vchPub = b.vchPub;
			fPubSet = b.fPubSet;
			fCompressedPubKey = b.fCompressedPubKey;
		}

public:


    CKey()
		{
			SetNull();
		}

    CKey(const CKey& b)
		{
			Init(b);
		}

    CKey& operator=(const CKey& b)
		{
			Init(b);
			return (*this);
		}

    IMPLEMENT_SERIALIZE(
			READWRITE(*(CKeyMetadata *)this);
			READWRITE(vch);
			READWRITE(fCompressedPubKey);
		)

    void SetNull()
		{
			CKeyMetadata::SetNull();
			fCompressedPubKey = false;
			fPubSet = false;
			vch.clear();
			vchPub.clear();
		}

		void Reset()
		{
			SetNull();
		}

    bool IsNull() const
		{
			return (vch.size() == 0);
		}

    bool IsCompressed() const
		{
			return fCompressedPubKey;
		}

    CSecret GetSecret(bool &fCompressed) const
		{
			CSecret ret_secret(vch);
			fCompressed = fCompressedPubKey;
			return (ret_secret);
		}

		int GetMethod() const
		{
			switch (vch.size()) {
				case 96: return SIGN_ALG_DILITHIUM;
				case 32: return SIGN_ALG_ECDSA;
			}
			return SIGN_ALG_NONE;
		}

		bool IsDilithium() const
		{
			return (GetMethod() == SIGN_ALG_DILITHIUM);
		}

		unsigned int size() const { return (vch.size()); }

		const unsigned char* begin() const { return vch.data(); }

		const unsigned char* end() const { return vch.data() + size(); }

    virtual void MakeNewKey(bool fCompressed) = 0;

    virtual bool SetPrivKey(const CPrivKey& vchPrivKey, bool fCompressed = false) = 0;

    virtual bool SetSecret(const CSecret& vchSecret, bool fCompressed = false) = 0;

    virtual CPrivKey GetPrivKey() const = 0;

    virtual bool SetPubKey(const CPubKey& vchPubKey) = 0;

    virtual CPubKey GetPubKey() = 0;

    virtual bool Sign(uint256 hash, std::vector<unsigned char>& vchSig) = 0;

    // create a compact signature (65 bytes), which allows reconstructing the used public key
    // The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
    // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
    //                  0x1D = second key with even y, 0x1E = second key with odd y
    virtual bool SignCompact(uint256 hash, std::vector<unsigned char>& vchSig) =0 ;

    // reconstruct public key from a compact signature
    // This is only slightly more CPU intensive than just verifying it.
    // If this function succeeds, the recovered public key is guaranteed to be valid
    // (the signature is a valid signature of the given data for that key)
    virtual bool SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig) = 0;

    virtual bool Verify(uint256 hash, const std::vector<unsigned char>& vchSig) = 0;

    // Verify a compact signature
    virtual bool VerifyCompact(uint256 hash, const std::vector<unsigned char>& vchSig) = 0;

    virtual bool IsValid() = 0;

    virtual void MergeKey(CKey *masterKey, cbuff tag) = 0;

		virtual bool Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) = 0;
		
		virtual void SetCompressedPubKey() = 0;

};

#endif /* ndef __SERVER__KEY_H__ */

