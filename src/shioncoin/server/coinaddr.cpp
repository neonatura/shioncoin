
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

#include "shcoind.h"
#include "block.h"
#include "db.h"
#include <vector>
#include "bech32.h"
#include "base58.h"
#include "coinaddr.h"
#include "wallet.h"
#include "script.h"

using namespace std;

typedef vector<unsigned char> valtype;

/** Convert from one power-of-2 number base to another. */
template<int frombits, int tobits, bool pad, typename O, typename I>
bool ConvertBits(O& out, I it, I end) 
{
	size_t acc = 0;
	size_t bits = 0;
	constexpr size_t maxv = (1 << tobits) - 1;
	constexpr size_t max_acc = (1 << (frombits + tobits - 1)) - 1;
	while (it != end) {
		acc = ((acc << frombits) | *it) & max_acc;
		bits += frombits;
		while (bits >= tobits) {
			bits -= tobits;
			out.push_back((acc >> bits) & maxv);
		}
		++it;
	}
	if (pad) { 
		if (bits) out.push_back((acc << (tobits - bits)) & maxv);
	} else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
		return false;
	}
	return true;
}

template <typename T>
std::vector<unsigned char> ToByteVector(const T& in)
{       
    return std::vector<unsigned char>(in.begin(), in.end());
}   

bool CCoinAddr::Set(const CKeyID &id) 
{
	nType = ADDR_BASE58;
	int ver = GetPubKeyVersion();
	SetData(ver, &id, 20);
	return true;
}

bool CCoinAddr::Set(const CScriptID &id) 
{
	nType = ADDR_BASE58;
	int ver = GetScriptVersion();
	SetData(ver, &id, 20);
	return true;
}

bool CCoinAddr::Set(const WitnessV0KeyHash& id)
{
	nType = ADDR_BECH32;
	SetData(0, &id, 20);
	return (true);
}

bool CCoinAddr::Set(const WitnessV0ScriptHash& id)
{
	nType = ADDR_BECH32;
	SetData(0, &id, 32);
	return (true);
}

bool CCoinAddr::Set(const WitnessV14KeyHash& id)
{
	nType = ADDR_BECH32;
	SetData(14, &id, 20);
	return (true);
}

bool CCoinAddr::Set(const WitnessV14ScriptHash& id)
{
	nType = ADDR_BECH32;
	SetData(14, &id, 32);
	return (true);
}

bool CCoinAddr::Set(const WitnessUnknown& id)
{
	nType = ADDR_BECH32;
	/* TODO: */
	SetData(id.version, id.program, id.length);  
	return (true);
}

bool CCoinAddr::Set(const CTxDestination &dest)
{
	return boost::apply_visitor(CCoinAddrVisitor(this), dest);
}

bool CCoinAddr::IsValid() const
{

	if (vchVersion.size() == 0)
		return (false);

	const unsigned char *raw = vchVersion.data();
	unsigned int nVersion = (unsigned int)raw[0];

	if (nType != ADDR_BECH32) {
		if (vchVersion.size() == 1) {
			unsigned int nExpectedSize = 20;
			switch(nVersion) {
				case PUBKEY_G_ADDRESS:
				case PUBKEY_C_ADDRESS:
				case PUBKEY_E_ADDRESS:
				case PUBKEY_L_ADDRESS:
				case PUBKEY_S_ADDRESS:
				case PUBKEY_T_ADDRESS:
					nExpectedSize = 20; // Hash of public key
					break;
				case SCRIPT_ADDRESS:
				case SCRIPT_ADDRESS_2:
				case SCRIPT_ADDRESS_2S:
				case SCRIPT_ADDRESS_2G:
					nExpectedSize = 20; // Hash of CScript
					break;
				default:
					return false;
			}
			if (vchData.size() != nExpectedSize)
				return (false);

			CIface *iface = GetCoinByIndex(ifaceIndex);
			if (iface) {
				if (nVersion != BASE58_PUBKEY_ADDRESS(iface) &&
						nVersion != BASE58_SCRIPT_ADDRESS(iface) &&
						nVersion != BASE58_SCRIPT_ADDRESS_2(iface)) {
					return (false);
				}
			}
		}
	} else {
		if (nVersion < 0 || nVersion >= 16)
			return (false);
		if (nVersion == 0) {
			if (vchData.size() != 20 && vchData.size() != 32)
				return (false);
		}
	}

	return (true);
}

CTxDestination CCoinAddr::Get() const 
{
	
	if (nType == ADDR_BECH32) {
		unsigned int nVersion = 0;
		if (vchVersion.size() != 0) {
			const unsigned char *raw = vchVersion.data();
			nVersion = (unsigned int)raw[0];
		}
		switch (nVersion) {
			case 0:
				{
					if (vchData.size() == sizeof(WitnessV0KeyHash)) {
						WitnessV0KeyHash id;
						memcpy(&id, &vchData[0], vchData.size());
						return (id);
					}
					if (vchData.size() == sizeof(WitnessV0ScriptHash)) {
						WitnessV0ScriptHash id;
						memcpy(&id, &vchData[0], vchData.size());
						return (id);
					}
				}
				break;
			case 14:
				{
					if (vchData.size() == sizeof(WitnessV14KeyHash)) {
						WitnessV14KeyHash id;
						memcpy(&id, &vchData[0], vchData.size());
						return (id);
					}
					if (vchData.size() == sizeof(WitnessV14ScriptHash)) {
						WitnessV14ScriptHash id;
						memcpy(&id, &vchData[0], vchData.size());
						return (id);
					}
				}
				break;
		}
	}

  if (!IsValid())
    return CNoDestination();

#if 0
	CIface *iface = GetCoinByIndex(ifaceIndex);
	if (nVersion == BASE58_PUBKEY_ADDRESS(iface)) {
		uint160 id;
		memcpy(&id, &vchData[0], 20);
		return CKeyID(id);
	}
	if (nVersion == BASE58_SCRIPT_ADDRESS(iface)) {
		uint160 id;
		memcpy(&id, &vchData[0], 20);
		return CScriptID(id);
	}
#endif

	if (vchVersion.size() == 1) {
		const unsigned char *raw = vchVersion.data();
		unsigned int nVersion = (unsigned int)raw[0];

		switch (nVersion) {
			case PUBKEY_G_ADDRESS:
			case PUBKEY_C_ADDRESS:
			case PUBKEY_E_ADDRESS:
			case PUBKEY_L_ADDRESS:
			case PUBKEY_S_ADDRESS:
			case PUBKEY_T_ADDRESS:
				{
					uint160 id;
					memcpy(&id, &vchData[0], 20);
					return CKeyID(id);
				}
			case SCRIPT_ADDRESS:
			case SCRIPT_ADDRESS_2:
			case SCRIPT_ADDRESS_2S:
			case SCRIPT_ADDRESS_2G:
				{
					uint160 id;
					memcpy(&id, &vchData[0], 20);
					return CScriptID(id);
				}
		}
	}

  return CNoDestination();
}

bool CCoinAddr::GetKeyID(CKeyID &keyID) const
{
  if (!IsValid())
    return false;
	if (vchVersion.size() == 1) {
		const unsigned char *raw = vchVersion.data();
		unsigned int nVersion = (unsigned int)raw[0];

		switch (nVersion) {
			case PUBKEY_G_ADDRESS:
			case PUBKEY_C_ADDRESS:
			case PUBKEY_E_ADDRESS:
			case PUBKEY_S_ADDRESS:
			case PUBKEY_L_ADDRESS:
			case PUBKEY_T_ADDRESS:
				{
					uint160 id;
					memcpy(&id, &vchData[0], 20);
					keyID = CKeyID(id);
					return true;
				}
		}
	}

  return (false);
}

bool CCoinAddr::GetScriptID(CScriptID& scriptID) const 
{

  if (!IsValid())
    return false;

#if 0
	CIface *iface = GetCoinByIndex(ifaceIndex);
	if (iface && (nVersion != BASE58_SCRIPT_ADDRESS(iface)))
		return (false);
#endif
#if 0
  if (nVersion != SCRIPT_ADDRESS &&
      nVersion != SCRIPT_ADDRESS_TEST)
    return false;
#endif
	if (vchVersion.size() == 1) {
		const unsigned char *raw = vchVersion.data();
		unsigned int nVersion = (unsigned int)raw[0];
		switch (nVersion) {
			case SCRIPT_ADDRESS:
			case SCRIPT_ADDRESS_2:
			case SCRIPT_ADDRESS_2S:
			case SCRIPT_ADDRESS_2G:
				{
					uint160 id;
					memcpy(&id, &vchData[0], 20);
					scriptID = CScriptID(id);
				}
				break;
			default:
				return (false);
		}
	} else {
		return (false);
	}

	return (true);
}

int CCoinAddr::GetPubKeyVersion() const 
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	return (BASE58_PUBKEY_ADDRESS(iface));
}

int CCoinAddr::GetScriptVersion() const
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	int ver;

	ver = BASE58_SCRIPT_ADDRESS_2(iface);
	if (ver == 0)
		ver = BASE58_SCRIPT_ADDRESS(iface);
	if (ver == 0)
		ver = BASE58_DEFAULT_SCRIPT_ADDRESS;
	return (ver);
}

static bool params_Bech32HRP(int ifaceIndex, string strName)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);

	if (!iface || !iface->enabled)
		return (false);

	if (0 == strcmp(iface->name, strName.c_str()))
		return (true);

	return (false);
}

bool CCoinAddr::SetString(const std::string& str)
{
	std::vector<unsigned char> vchTemp;
	bool ok;

	ok = CBase58Data::SetString(str);
	if (ok) {
		nType = ADDR_BASE58;
		return (ok);
	}

	auto bech = bech32::Decode(str);
	if (bech.second.size() > 0 && params_Bech32HRP(ifaceIndex, bech.first)) {
		/* Bech32 decoding */
		int version = bech.second[0]; // The first 5 bit symbol is the witness version (0-16)
		// The rest of the symbols are converted witness program bytes.
		if (ConvertBits<5, 8, false>(vchData, bech.second.begin() + 1, bech.second.end())) {

#if 0
			if (version == 0) {
				{
					WitnessV0KeyHash keyid;
					if (vchData.size() == keyid.size()) {
						return (true);
						//std::copy(vchData.begin(), vchData.end(), keyid.begin());
						//return keyid;
					}
				}
				{
					WitnessV0ScriptHash scriptid;
					if (vchData.size() == scriptid.size()) {
						//std::copy(vchData.begin(), vchData.end(), scriptid.begin());
						return (true);//scriptid;
					}
				}
				return false;//CNoDestination();
			}
#endif
			if (version > 16 || vchData.size() < 2 || vchData.size() > 40) {
				return false;//CNoDestination();
			}
#if 0
			WitnessUnknown unk;
			unk.version = version;
			std::copy(vchData.begin(), vchData.end(), unk.program);
			unk.length = vchData.size();
			return unk;
#endif

			unsigned char nVersion = (unsigned char)version;
			unsigned char *raw = &nVersion;
			vchVersion = cbuff(raw, raw + 1); 

			nType = ADDR_BECH32;
			return (true);
		}

		return false;//CNoDestination();
	}

	nType = ADDR_UNKNOWN;
	vchData.clear();
	vchVersion.clear();//nVersion = 0;
	return (error(SHERR_INVAL, "CCoinAddr.SetString: failure decoding \"%s\".", str.c_str()));
}

std::string CCoinAddr::ToString() const
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	string strAddr = "";

	if (iface && nType == ADDR_BECH32) {
		std::vector<unsigned char> data = vchVersion;//{nVersion};
		ConvertBits<8, 5, true>(data, vchData.begin(), vchData.end());
		strAddr = bech32::Encode(iface->name, data);
	} else {
		strAddr = CBase58Data::ToString();
	}

	return (strAddr);
}

bool CCoinAddr::IsScript() const 
{

	if (!IsValid())
		return false;

	if (vchVersion.size() == 1) {
		const unsigned char *raw = vchVersion.data();
		unsigned int nVersion = (unsigned int)raw[0];
		switch (nVersion) {
			case SCRIPT_ADDRESS:
			case SCRIPT_ADDRESS_2:
			case SCRIPT_ADDRESS_2S:
			case SCRIPT_ADDRESS_2G:
				{
					return true;
				}
		}
	}

	return (false);
}

CTxDestination CCoinAddr::GetWitness(int output_type) const 
{
	CWallet *wallet = GetWallet(ifaceIndex);

  if (!IsValid())
    return CNoDestination();

	if (output_type == OUTPUT_TYPE_NONE) {
		output_type = (opt_bool(OPT_BECH32) ? OUTPUT_TYPE_BECH32 : OUTPUT_TYPE_P2SH_SEGWIT);
	}

	if (nType == ADDR_BECH32) { /* already witness */
		return (Get());
	}

	CTxDestination result = CNoDestination();
	{
		CKeyID keyID;
		CScriptID scriptID;
		CScript subscript;

		if (GetKeyID(keyID)) {
			CKey *key;

			key = wallet->GetKey(keyID);
			if (!key)
				return (result); /* non-local */

			/* signing with uncompressed keys is disabled in witness scripts. */
			if (!key->IsCompressed()) {
				return (result);
			}

			if (key->IsDilithium())
				output_type = OUTPUT_TYPE_DILITHIUM;

			int ver = 0;
			if (output_type == OUTPUT_TYPE_DILITHIUM)
				ver = 14;

			CScript basescript = GetScriptForDestination(keyID);
			CScript witscript = GetScriptForWitness(basescript, ver);
			wallet->AddCScript(witscript);

			if (output_type == OUTPUT_TYPE_DILITHIUM) {
				WitnessV14KeyHash hash = keyID;
				result = hash;
			} else if (output_type == OUTPUT_TYPE_BECH32) {
				WitnessV0KeyHash hash = keyID;
				result = hash;
			} else {
				result = CScriptID(witscript);
			}
		} else if (GetScriptID(scriptID) &&
				wallet->GetCScript(scriptID, subscript)) {
			int witnessversion;
			std::vector<unsigned char> witprog;
			if (subscript.IsWitnessProgram(witnessversion, witprog)) {
				/* ID is already for a witness program script */
				result = scriptID;
			} else {
				int ver = (output_type == OUTPUT_TYPE_DILITHIUM) ? 14 : 0;
				CScript witscript = GetScriptForWitness(subscript, ver);
				wallet->AddCScript(witscript);

				if (output_type == OUTPUT_TYPE_DILITHIUM) {
					WitnessV14ScriptHash hash;
					SHA256((unsigned char *)&subscript[0], subscript.size(), (unsigned char *)&hash);
					result = hash;
				} else if (output_type == OUTPUT_TYPE_BECH32) {
					WitnessV0ScriptHash hash;
					SHA256((unsigned char *)&subscript[0], subscript.size(), (unsigned char *)&hash);
					result = hash;
				} else {
					result = CScriptID(witscript);
				}
			}
		}
	}

	return (result);
}

/* set coin addr destination from script. */
bool CCoinAddr::SetScript(const CScript& script)
{
	CTxDestination dest;

	if (!ExtractDestination(script, dest))
		return (false);

	return (Set(dest));
}

/* get script for coin destination. */
CScript CCoinAddr::GetScript()
{
	return (GetScriptForDestination(Get()));
}

/* build a P2WSH scriptPubKey */
CScript GetScriptForWitness(const CScript& redeemscript, int nVer)
{
	CScript ret;
	opcodetype opVer;
	
	opVer = CScript::EncodeOP_N(nVer);

	txnouttype typ;
	std::vector<std::vector<unsigned char> > vSolutions;
	if (Solver(redeemscript, typ, vSolutions)) {
		if (typ == TX_PUBKEY) {
			cbuff vch(vSolutions[0].begin(), vSolutions[0].end());
			uint160 h160 = Hash160(vch);
			ret << opVer << h160;
			return ret;
		} else if (typ == TX_PUBKEYHASH) {
			ret << opVer << vSolutions[0];
			return ret;
		}
	}

	uint256 hash;
	SHA256(&redeemscript[0], redeemscript.size(), (unsigned char *)&hash);
	ret << opVer << ToByteVector(hash);

	return (ret);
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
	vector<valtype> vSolutions;
	txnouttype whichType;

	if (!Solver(scriptPubKey, whichType, vSolutions))
		return (false);

	if (whichType == TX_PUBKEY)
	{
		addressRet = CPubKey(vSolutions[0]).GetID();
		return (true);
	}

	if (whichType == TX_PUBKEYHASH)
	{
		addressRet = CKeyID(uint160(vSolutions[0]));
		return (true);
	}

	if (whichType == TX_SCRIPTHASH)
	{
		addressRet = CScriptID(uint160(vSolutions[0]));
		return (true);
	}

	if (whichType == TX_RETURN) {
		addressRet = CKeyID(); /* blank */
		return (true);
	} 

	if (whichType == TX_WITNESS_V0_KEYHASH) {
		WitnessV0KeyHash hash;
		std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
		addressRet = hash;
		return true;
	}

	if (whichType == TX_WITNESS_V0_SCRIPTHASH) {
		WitnessV0ScriptHash hash;
		std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
		addressRet = hash;
		return (true);
	}

	if (whichType == TX_WITNESS_V14_KEYHASH) {
		WitnessV14KeyHash hash;
		std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
		addressRet = hash;
		return true;
	}

	if (whichType == TX_WITNESS_V14_SCRIPTHASH) {
		WitnessV14ScriptHash hash;
		std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
		addressRet = hash;
		return (true);
	}

	if (whichType == TX_WITNESS_UNKNOWN) {
		WitnessUnknown unk;
		unk.version = vSolutions[0][0];
		std::copy(vSolutions[1].begin(), vSolutions[1].end(), unk.program);
		unk.length = vSolutions[1].size();
		addressRet = unk;
		return (true);
	}

	/* multisig output destination have more than one address. */
	return (false);
}

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, vector<CTxDestination>& addressRet, int& nRequiredRet)
{
	addressRet.clear();
	typeRet = TX_NONSTANDARD;
	vector<valtype> vSolutions;

	if (!Solver(scriptPubKey, typeRet, vSolutions)) {
		return false;
	}

	if (typeRet == TX_MULTISIG)
	{
		nRequiredRet = vSolutions.front()[0];
		for (unsigned int i = 1; i < vSolutions.size()-1; i++)
		{
			CTxDestination address = CPubKey(vSolutions[i]).GetID();
			addressRet.push_back(address);
		}
	}
	else
	{
		nRequiredRet = 1;
		CTxDestination address;
		if (!ExtractDestination(scriptPubKey, address)) {
			return false;
		}
		addressRet.push_back(address);
	}

	return true;
}


