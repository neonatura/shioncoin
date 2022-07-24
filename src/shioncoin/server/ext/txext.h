
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

#ifndef __SERVER__TXEXT_H__
#define __SERVER__TXEXT_H__

#include "shcoind.h"
#include "base58.h"
#include "coinaddr.h"
#include <vector>
#include "json_spirit_reader_template.h"
#include "json_spirit_writer_template.h"

using namespace std;
using namespace json_spirit;

int GetBestHeight(CIface *iface);

inline bool arrcasecmp(cbuff v1, cbuff v2)
{
	int idx;

	if (v1.size() != v2.size())
		return (false);

	size_t len = v1.size();
	unsigned char *p1 = &*v1.begin();
	unsigned char *p2 = &*v2.begin();
	for (idx = 0; idx < len; idx++) {
		if (tolower(p1[idx]) != tolower(p2[idx]))
			return (false);
	}

	return (true);
}

inline std::string stringFromVch(const std::vector<unsigned char> &vch) 
{
	std::string res;
	if (vch.size() != 0) {
		std::vector<unsigned char>::const_iterator vi = vch.begin();
		while (vi != vch.end()) {
			res += (char) (*vi);
			vi++;
		}
	}
	return res;
}

inline shpeer_t *sharenet_peer(void)
{
	static shpeer_t *ret_peer;
	if (!ret_peer)
		ret_peer = shpeer_init(NULL, NULL);
	return (ret_peer);
}

class CSign
{
	public:
		static const int ALG_ECDSA = SHALG_ECDSA; // SHKEY_ALG_ECDSA
		static const int ALG_U160 = SHALG_SHR; // SHKEY_ALG_U160

		unsigned int nAlg;
		cbuff vPubKey;
		cbuff vAddrKey;
		std::vector<cbuff> vSig;

		CSign()
		{
			SetNull();
		}

		CSign(uint160 hash, string hexSeed = string())
		{
			SetNull();
			SignContext(hash, hexSeed);
		}

		IMPLEMENT_SERIALIZE (
				READWRITE(this->nAlg);
				READWRITE(this->vPubKey);
				READWRITE(this->vAddrKey);
				READWRITE(this->vSig);
		)

		void SetNull()
		{
			nAlg = 0;
			vPubKey.clear();
			vAddrKey.clear();
			vSig.clear();
		}

		bool IsNull()
		{
			return (nAlg == 0);
		}

		void Init(const CSign& b)
		{
			nAlg = b.nAlg;
			vPubKey = b.vPubKey;
			vAddrKey = b.vAddrKey;
			vSig = b.vSig;
		}

		friend bool operator==(const CSign &a, const CSign &b)
		{
			return (
					a.nAlg == b.nAlg &&
					a.vPubKey == b.vPubKey &&
					a.vAddrKey == b.vAddrKey &&
					a.vSig == b.vSig
					);
		}

		CSign operator=(const CSign &b)
		{
			Init(b);
			return *this;
		}


		bool SignContext(cbuff& vchContext, string hexSeed = string());

		bool SignContext(uint160 hash, string hexSeed = string())
		{
			cbuff vchContext(hash.begin(), hash.end());
			return (SignContext(vchContext, hexSeed));
		}

		bool SignContext(string hexContext, string hexSeed = string())
		{
			cbuff vchContext = ParseHex(hexContext);
			return (SignContext(vchContext, hexSeed)); 
		}

		bool VerifyContext(unsigned char *data, size_t data_len);


		bool SignAddress(int ifaceIndex, CCoinAddr& addr, unsigned char *data, size_t data_len);

		bool VerifyAddress(CCoinAddr& addr, unsigned char *data, size_t data_len);

		bool SignOrigin(int ifaceIndex, CCoinAddr& addr);

		bool VerifyOrigin(CCoinAddr& addr);




		bool VerifyContext(uint160 hash);

		//bool Sign(int ifaceIndex, CCoinAddr& addr, unsigned char *data, size_t data_len);
		bool Sign(int ifaceIndex, CCoinAddr& addr, cbuff& vchContext, string hexSeed = string());

		bool Sign(int ifaceIndex, CCoinAddr& addr, string hexContext, string hexSeed = string());

		bool Verify(CCoinAddr& addr, unsigned char *data, size_t data_len);

		bool VerifySeed(string hexSeed);


		const uint160 GetHash()
		{
			uint256 hashOut = SerializeHash(*this);
			unsigned char *raw = (unsigned char *)&hashOut;
			cbuff rawbuf(raw, raw + sizeof(hashOut));
			return Hash160(rawbuf);
		}

		std::string ToString();

		Object ToValue();

};


class CExtCore
{

	static const int PROTO_EXT_VERSION = 1;

	public:

	static const int MAX_EXT_LIFESPAN = 1514743200; // ~48y

	unsigned int nVersion;
	shtime_t tExpire;
	cbuff vchLabel;

	CExtCore() {
		SetNull();
	}
	CExtCore(std::string labelIn) {
		SetNull();
		SetLabel(labelIn);
	}

	IMPLEMENT_SERIALIZE (
			READWRITE(this->nVersion);
			READWRITE(this->tExpire);
			READWRITE(this->vchLabel);
	)

	void SetNull()
	{
		nVersion = GetDefaultVersion();
		tExpire = SHTIME_UNDEFINED;
		vchLabel.clear();
	}

	/** Obtain the expiration time in unix-seconds. */
	time_t GetExpireTime()
	{
		return (shutime(tExpire));
	}

	/** Set's the expiration time. */
	void SetExpireTime(shtime_t tExpireIn)
	{
		tExpire = tExpireIn;
	}

	/** Set's the expiration to the specified seconds into the future. */
	void SetExpireSpan(double sec)
	{
		tExpire = shtime_adj(shtime(), sec);
	}

	/* DEBUG: REMOVE ME: */
	void SetExpireTime()
	{
		double dSpan = (double)SHARE_DEFAULT_EXPIRE_TIME;
		SetExpireSpan(dSpan);
	}

	virtual void ResetExpireTime(CIface *iface, int64 nFee)
	{
		SetExpireSpan((double)GetMinimumLifespan());
	}

	bool IsExpired()
	{
		if (tExpire == SHTIME_UNDEFINED)
			return (false);
		return (shtime_after(shtime(), tExpire));
	}

	bool IsExpired(int64_t nTime)
	{
		if (tExpire == SHTIME_UNDEFINED)
			return (false);
		shtime_t t = shtimeu((time_t)nTime);
		return (shtime_after(t, tExpire));
	}

	void Init(const CExtCore& b)
	{
		nVersion = b.nVersion;
		tExpire = b.tExpire;
		vchLabel = b.vchLabel;
	}

	friend bool operator==(const CExtCore &a, const CExtCore &b)
	{
		return (a.nVersion == b.nVersion &&
				a.tExpire == b.tExpire &&
				a.vchLabel == b.vchLabel
				);
	}

	CExtCore operator=(const CExtCore &b)
	{
		Init(b);
		return *this;
	}

	void SetLabel(std::string labelIn)
	{
		vchLabel = vchFromString(labelIn);
	}

	std::string GetLabel()
	{
		return (stringFromVch(vchLabel)); 
	}

	int GetVersion()
	{
		return (nVersion);
	}

	void SetVersion(int ver)
	{
		nVersion = ver;
	}

	virtual int GetMinimumVersion() 
	{
		return (PROTO_EXT_VERSION);
	}

	virtual int GetMaximumVersion()
	{
		return (SHC_VERSION_MAJOR);
	}

	virtual int GetDefaultVersion()
	{
		return (GetMinimumVersion());
	}

	bool VerifyVersion()
	{
		if (GetVersion() < GetMinimumVersion()) {
			return (false);
		}
		if (GetVersion() > GetMaximumVersion()) {
			return (false);
		}
		return (true);
	}

	int GetLabelSize()
	{
		return (GetLabel().length());
	}

	virtual int GetContentSize()
	{
		return (0);
	}

	virtual int GetMaximumContentSize()
	{
		return (0);
	}

#if 0
	virtual int64 CalculateFee(CIface *iface, int nHeight, int nContentSize = -1, time_t nLifespan = -1)
	{
		return (MIN_TX_FEE(iface));
	}

	virtual int64 GetMinimumFee(CIface *iface, int nHeight = -1)
	{
		if (nHeight == -1) {
			nHeight = GetBestHeight(iface); 
		}
		return (CalculateFee(iface, nHeight, 0, 0));
	}

	virtual int64 GetMaximumFee(CIface *iface, int nHeight = -1)
	{
		if (nHeight == -1) {
			nHeight = GetBestHeight(iface); 
		}
		return (CalculateFee(iface, nHeight, 
					GetMaximumContentSize(), GetMaximumLifespan()));
	}
#endif

	virtual time_t GetMinimumLifespan()
	{
		return (SHTIME_UNDEFINED);
	}

	virtual time_t GetMaximumLifespan()
	{
		return (MAX_EXT_LIFESPAN);
	}

	virtual time_t CalculateLifespan(CIface *iface, int64 nFee)
	{
		return (GetMinimumLifespan());
	}

#if 0
	virtual time_t GetDefaultLifespan()
	{
		return (GetMinimumLifespan());
	}

	virtual time_t CalculateLifespan(int64 nBaseFee, int64 nFee)
	{
		double base = (double)GetMinimumLifespan();

		base = (base / nBaseFee * nFee);
		base = MIN(base, GetMaximumLifespan());

		return ((time_t)base);
	}
#endif

	time_t GetLifespan()
	{
		time_t nExpireTime = GetExpireTime();
		time_t now = time(NULL);

		if (nExpireTime == SHTIME_UNDEFINED)
			return (0);

		if (now >= nExpireTime)
			return (0);

		return (nExpireTime - time(NULL));
	}

	bool VerifyLifespan(CIface *iface, int64 nCredit)
	{
		if (GetExpireTime() == SHTIME_UNDEFINED)
			return (true);

		time_t lifespan = CalculateLifespan(iface, nCredit);
		if ((GetExpireTime() - time(NULL)) > lifespan) {
			return (false);
		}

		return (true);
	}

#if 0
	bool VerifyLifespan(int64 nBaseFee, int64 nFee)
	{
		time_t lifespan = CalculateLifespan(nBaseFee, nFee);
		double diff = shtime_diff(shtime(), tExpire);
		if (diff > lifespan)
			return (false);
		return (true);
	}
#endif

	int VerifyTransaction();

	std::string ToString();

	Object ToValue();

	static string GetOpLabel(int op) {
		switch (op) {
			case OP_EXT_NEW:
				return "new";
			case OP_EXT_UPDATE:
				return "update";
			case OP_EXT_ACTIVATE:
				return "activate";
			case OP_EXT_TRANSFER:
				return "transfer";
			case OP_EXT_REMOVE:
				return "remove";
			default:
				return "unknown";
		}
	}

};


typedef std::map<std::string, uint256> alias_list;
typedef std::map<uint160, uint256> asset_list;
typedef std::map<uint160, uint256> cert_list;
typedef std::map<uint160, uint256> exec_list;
typedef std::map<std::string, uint160> exec_label_list;
typedef std::map< uint160, vector<uint160> > exec_call_list;
typedef std::map<uint160, uint256> offer_list;
typedef std::map<uint160, CTransaction> channel_list;
typedef std::map<uint160, uint256> ctx_list;
typedef std::map<uint160, uint256> altchain_list;


#include "entity.h"
#include "certificate.h"
#include "license.h"
#include "ident.h"
#include "offer.h"
#include "asset.h"
#include "exec.h"
#include "alias.h"
#include "channel.h"
#include "context.h"
#include "altchain.h"


bool GetExtOutput(const CScript& script, int ext_mode, int& mode, CScript& scriptOut);

bool GetExtOutput(const CTransaction& tx, int ext_mode, int& mode, int& nOut, CScript& scriptOut);

bool GetExtOutputMode(const CTransaction& tx, int ext_mode, int& mode);

bool RemoveExtOutputPrefix(CScript& script);


#endif /* ndef __SERVER_TXEXT_H__ */




