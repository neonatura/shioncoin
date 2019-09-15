
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

#ifndef __SERVER__KEY_H__
#define __SERVER__KEY_H__

#include "shcoind.h"

#include <stdexcept>
#include <vector>

#include "allocators.h"
#include "serialize.h"
#include "uint256.h"
#include "util.h"

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
			return 
				vchPubKey.size() == 33 || vchPubKey.size() == 65 || /* ECDSA */ 
				vchPubKey.size() == 1473; /* DILITHIUM-3 */
		}

    bool IsCompressed() const
		{
			return vchPubKey.size() == 33;
		}

		unsigned int size() const { return vchPubKey.size(); }

		const unsigned char* begin() const { return vchPubKey.data(); }

		const unsigned char* end() const { return vchPubKey.data() + size(); }

};

class CKeyMetadata
{
	public:
		static const int META_HD_ENABLED = (1 << 0);
		static const int META_HD_KEY = (1 << 1);
		static const int META_SEGWIT = (1 << 2);
		static const int META_DILITHIUM = (1 << 3);
		static const int META_STATIC = (1 << 4);
		static const int META_INTERNAL = (1 << 5);

		static const int STANDARD_META_FLAGS = META_HD_ENABLED;

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
			nFlag = CKeyMetadata::STANDARD_META_FLAGS;
			nCreateTime = 0;
			hdKeypath.clear();
			hdMasterKeyID.SetNull();
		}

		IMPLEMENT_SERIALIZE
		(
			READWRITE(nFlag);
			READWRITE(nCreateTime);
			if (nFlag & CKeyMetadata::META_HD_ENABLED) {
				READWRITE(hdKeypath);
				READWRITE(hdMasterKeyID);
			}
		)

		const string GetFlagString() const
		{
			string ret_str;
			if (nFlag & META_HD_KEY)
				ret_str += "hdkey ";
			if (ret_str.size() != 0)
				ret_str.substr(0, ret_str.size()-1);
			return (ret_str);
		}

};

class CKey
{
	protected:
    CSecret vch;
    bool fPubSet;
    bool fCompressedPubKey;
    cbuff vchPub;

    void SetCompressedPubKey()
		{
			fCompressedPubKey = true;
		}

		void Init(const CKey& b)
		{
			vch = b.vch;
			vchPub = b.vchPub;
			fPubSet = b.fPubSet;
			fCompressedPubKey = b.fCompressedPubKey;
			meta = b.meta;
		}

public:
		CKeyMetadata meta;

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
			READWRITE(meta);
			READWRITE(vch);
			READWRITE(fCompressedPubKey);
		)

    void SetNull()
		{
			fCompressedPubKey = false;
			fPubSet = false;

			vch.clear();
			vchPub.clear();

			meta.SetNull();
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

		unsigned int size() const { return (vch.size()); }

		const unsigned char* begin() const { return vch.data(); }

		const unsigned char* end() const { return vch.data() + size(); }

    virtual void MakeNewKey(bool fCompressed) = 0;

    virtual bool SetPrivKey(const CPrivKey& vchPrivKey, bool fCompressed = false) = 0;

    virtual bool SetSecret(const CSecret& vchSecret, bool fCompressed = false) = 0;

    virtual CPrivKey GetPrivKey() const = 0;

    virtual bool SetPubKey(const CPubKey& vchPubKey) = 0;

    virtual CPubKey GetPubKey() const = 0;

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

    virtual void MergeKey(CKey& keyChild, cbuff tag) = 0;

		virtual bool Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const = 0;

};

#endif /* ndef __SERVER__KEY_H__ */

