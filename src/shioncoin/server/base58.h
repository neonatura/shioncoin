
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

#ifndef __SERVER__BASE58_H__
#define __SERVER__BASE58_H__

#include <string>
#include <vector>
#include "bignum.h"
#include "key.h"
#include "script.h"

#ifndef BASE58_DEFAULT_SCRIPT_ADDRESS
#define BASE58_DEFAULT_SCRIPT_ADDRESS 5
#endif

// Encode a byte sequence as a base58-encoded string
std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend);

// Decode a base58-encoded string psz into byte vector vchRet
// returns true if decoding is successful
bool DecodeBase58(const char* psz, std::vector<unsigned char>& vchRet);


// Decode a base58-encoded string str into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet)
{
	return DecodeBase58(str.c_str(), vchRet);
}

// Encode a byte vector as a base58-encoded string
inline std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
	return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

// Encode a byte vector to a base58-encoded string, including checksum
inline std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
	// add 4-byte hash check to the end
	std::vector<unsigned char> vch(vchIn);
	uint256 hash = Hash(vch.begin(), vch.end());
	vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
	return EncodeBase58(vch);
}

// Decode a base58-encoded string psz that includes a checksum, into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet))
        return false;
    if (vchRet.size() < 4)
    {
        vchRet.clear();
        return false;
    }
    uint256 hash = Hash(vchRet.begin(), vchRet.end()-4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0)
    {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size()-4);
    return true;
}

// Decode a base58-encoded string str that includes a checksum, into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}

/** Base class for all base58-encoded data */
class CBase58Data
{
	protected:
		// the version byte(s)
		cbuff vchVersion;
		// the actually encoded data
		cbuff vchData;

		CBase58Data()
		{
			vchVersion.clear();
			vchData.clear();
		}

		~CBase58Data()
		{
			// zero the memory, as it may contain sensitive data
			if (!vchData.empty())
				memset(&vchData[0], 0, vchData.size());
		}

		void SetData(int nVersionIn, const void* pdata, size_t nSize)
		{
			unsigned char raw[4];

			memset(raw, 0, sizeof(raw));
			raw[0] = (unsigned char)nVersionIn;
			vchVersion = cbuff(raw, raw + 1);

			vchData.resize(nSize);
			if (!vchData.empty())
				memcpy(&vchData[0], pdata, nSize);
		}

		void SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend)
		{
			SetData(nVersionIn, (void*)pbegin, pend - pbegin);
		}

		void SetData(const cbuff& vchVersionIn, const void* pdata, size_t nSize)
		{

			vchVersion = vchVersionIn;

			vchData.resize(nSize);
			if (!vchData.empty())
				memcpy(&vchData[0], pdata, nSize);
		}

		void SetData(const cbuff& vchVersionIn, const unsigned char *pbegin, const unsigned char *pend)
		{
			SetData(vchVersionIn, (void*)pbegin, pend - pbegin);
		}


	public:
		bool SetString(const char *psz, size_t nVersionSize = 1);

		bool SetString(const std::string& str, size_t nVersionSize = 1)
		{
			return SetString(str.c_str(), nVersionSize);
		}

		const cbuff& GetVersion() const
		{
			return (vchVersion);
		}

		std::string ToString(int output_type = 0) const;

		int CompareTo(const CBase58Data& b58) const
		{
			if (vchVersion < b58.vchVersion) return -1;
			if (vchVersion > b58.vchVersion) return  1;
			if (vchData < b58.vchData)   return -1;
			if (vchData > b58.vchData)   return  1;
			return 0;
		}

		bool operator==(const CBase58Data& b58) const { return CompareTo(b58) == 0; }
		bool operator<=(const CBase58Data& b58) const { return CompareTo(b58) <= 0; }
		bool operator>=(const CBase58Data& b58) const { return CompareTo(b58) >= 0; }
		bool operator< (const CBase58Data& b58) const { return CompareTo(b58) <  0; }
		bool operator> (const CBase58Data& b58) const { return CompareTo(b58) >  0; }
};

/** A base58-encoded secret key */
class CCoinSecret : public CBase58Data
{
	public:
#if 0
		enum
		{
			PRIVKEY_ADDRESS = CCoinAddr::PUBKEY_ADDRESS + 128,
			PRIVKEY_ADDRESS_TEST = CCoinAddr::PUBKEY_ADDRESS_TEST + 128,
		};
#endif

		void SetSecret(int ifaceIndex, const CSecret& vchSecret, bool fCompressed)
		{ 
//			int PRIVKEY_ADDRESS = (CCoinAddr::GetCoinAddrVersion(ifaceIndex) + 128);
			int PRIVKEY_ADDRESS = (BASE58_PUBKEY_ADDRESS(GetCoinByIndex(ifaceIndex)) + 128);
			assert(vchSecret.size() == 32);
			SetData(PRIVKEY_ADDRESS, &vchSecret[0], vchSecret.size());
			//SetData(fTestNet ? PRIVKEY_ADDRESS_TEST : PRIVKEY_ADDRESS, &vchSecret[0], vchSecret.size());
			if (fCompressed)
				vchData.push_back(1);
		}

		CSecret GetSecret(bool &fCompressedOut)
		{
			CSecret vchSecret;
			vchSecret.resize(32);
			memcpy(&vchSecret[0], &vchData[0], 32);
			fCompressedOut = vchData.size() == 33;
			return vchSecret;
		}

		bool SetString(const char* pszSecret);

		bool SetString(const std::string& strSecret);

		bool IsValid() const
		{
#if 0
			bool fExpectTestNet = false;
			switch(nVersion)
			{
				case PRIVKEY_ADDRESS:
					break;

				case PRIVKEY_ADDRESS_TEST:
					fExpectTestNet = true;
					break;

				default:
					return false;
			}
#endif

			if (vchVersion.size() != 4) {
				if (vchVersion.size() != 1)
					return (false);

				const unsigned char *raw = vchVersion.data();
				if (raw[0] <= 128)
					return (false);
			}

			return (vchData.size() == 32 || (vchData.size() == 33 && vchData[32] == 1));

			//return fExpectTestNet == fTestNet && (vchData.size() == 32 || (vchData.size() == 33 && vchData[32] == 1));
		}


		CCoinSecret(int ifaceIndex, const CSecret& vchSecret, bool fCompressed)
		{
			SetSecret(ifaceIndex, vchSecret, fCompressed);
		}

		CCoinSecret()
		{
		}
};

#endif /* ndef __SERVER__BASE58_H__ */
