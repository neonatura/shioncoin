
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

#ifndef __SERVER__COINADDR_H__
#define __SERVER__COINADDR_H__

#include <string>
#include <vector>
#include "bignum.h"
#include "key.h"
#include "script.h"

#define OUTPUT_TYPE_NONE 0
#define OUTPUT_TYPE_LEGACY 1
#define OUTPUT_TYPE_P2SH_SEGWIT 2
#define OUTPUT_TYPE_BECH32 3

#define ADDR_UNKNOWN 0
#define ADDR_BASE58 1
#define ADDR_BECH32 2

class CCoinAddr;

class CCoinAddrVisitor : public boost::static_visitor<bool>
{
private:
    CCoinAddr *addr;
public:
    CCoinAddrVisitor(CCoinAddr *addrIn) : addr(addrIn) { }
    bool operator()(const CKeyID& id) const;
    bool operator()(const CScriptID& id) const;
    bool operator()(const CNoDestination& no) const;

		/* bech32 segwit addr */
    bool operator()(const WitnessV0KeyHash& id) const;
    bool operator()(const WitnessV0ScriptHash& id) const;
    bool operator()(const WitnessUnknown& id) const;
};


/** base58-encoded coin addresses.
 * Public-key-hash-addresses have various versions per coin.
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 for all coin services.
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 */
class CCoinAddr : public CBase58Data
{
public:
    enum
		{
			PUBKEY_C_ADDRESS = 29,
			PUBKEY_E_ADDRESS = 33,
			PUBKEY_G_ADDRESS = 38,
			PUBKEY_L_ADDRESS = 48,
			PUBKEY_S_ADDRESS = 62,
			PUBKEY_T_ADDRESS = 65,

			SCRIPT_ADDRESS = 5,
			SCRIPT_ADDRESS_2 = 50,
			SCRIPT_ADDRESS_2S = 25,
			SCRIPT_ADDRESS_2G = 55,
		};

		int nType; /* ADDR_BASE58 | ADDR_BECH32 */
    int ifaceIndex;
		int64_t nCreateTime; 
		int64_t nAccessTime; 

		/* for serialization and initialization */
    CCoinAddr()
		{
			ifaceIndex = 0;
			nType = 0;
			nVersion = 0;
			vchData.clear();
			nCreateTime = 0;
			nAccessTime = 0;
		}

    CCoinAddr(int ifaceIndexIn)
    {
			SetNull();
      ifaceIndex = ifaceIndexIn;
    }

    CCoinAddr(int ifaceIndexIn, const CTxDestination &dest)
    {
			SetNull();
      ifaceIndex = ifaceIndexIn;
      Set(dest);
    }

    CCoinAddr(int ifaceIndexIn, const std::string& strAddress)
    {
			SetNull();
      ifaceIndex = ifaceIndexIn;
      SetString(strAddress);
    }

    CCoinAddr(int ifaceIndexIn, const char* pszAddress)
    {
			SetNull();
      ifaceIndex = ifaceIndexIn;
      SetString(pszAddress);
    }

    CCoinAddr(int ifaceIndexIn, const CScript& script)
		{
			SetNull();
      ifaceIndex = ifaceIndexIn;
			SetScript(script);
		}

		void SetNull()
		{
			ifaceIndex = 0;
			nType = 0;
			nVersion = 0;
			vchData.clear();
			nCreateTime = time(NULL);
			nAccessTime = 0;
		}

		bool Set(const CKeyID &id); 

		bool Set(const CScriptID &id); 

		bool Set(const WitnessV0KeyHash& id);

		bool Set(const WitnessV0ScriptHash& id);

		bool Set(const WitnessUnknown& id);

		bool Set(const CTxDestination &dest);

    CTxDestination Get() const;

    bool IsValid() const;

    bool IsScript() const; 

		bool SetScript(const CScript& script);

		CScript GetScript();

    bool SetString(const std::string& str);

		CTxDestination GetWitness(int output_type = 0) const;

    bool GetKeyID(CKeyID &keyID) const;

    bool GetScriptID(CScriptID &scriptID) const;

		int GetPubKeyVersion() const; 

		int GetScriptVersion() const;

    std::string ToString() const;

};

bool inline CCoinAddrVisitor::operator()(const CKeyID &id) const         { return addr->Set(id); }
bool inline CCoinAddrVisitor::operator()(const CScriptID &id) const      { return addr->Set(id); }
bool inline CCoinAddrVisitor::operator()(const CNoDestination &id) const { return false; }
bool inline CCoinAddrVisitor::operator()(const WitnessV0KeyHash &id) const { return addr->Set(id); }
bool inline CCoinAddrVisitor::operator()(const WitnessV0ScriptHash &id) const { return addr->Set(id); }
bool inline CCoinAddrVisitor::operator()(const WitnessUnknown &id) const { return addr->Set(id); }


class EMC2CoinAddr : public CCoinAddr
{
  public:
    EMC2CoinAddr() : CCoinAddr(EMC2_COIN_IFACE)
    {
    }

    EMC2CoinAddr(const CTxDestination &dest) : CCoinAddr(EMC2_COIN_IFACE)
    {
      Set(dest);
    }
    EMC2CoinAddr(const std::string& strAddress) : CCoinAddr(EMC2_COIN_IFACE)
		{
			SetString(strAddress);
		}
};

class SHCCoinAddr : public CCoinAddr
{
  public:
    SHCCoinAddr() : CCoinAddr(SHC_COIN_IFACE)
    {
    }

    SHCCoinAddr(const CTxDestination &dest) : CCoinAddr(SHC_COIN_IFACE)
    {
      Set(dest);
    }

    SHCCoinAddr(const std::string& strAddress) : CCoinAddr(SHC_COIN_IFACE)
		{
			SetString(strAddress);
		}
};

class USDECoinAddr : public CCoinAddr
{
  public:
    USDECoinAddr() : CCoinAddr(USDE_COIN_IFACE)
    {
    }

    USDECoinAddr(const CTxDestination &dest) : CCoinAddr(USDE_COIN_IFACE)
    {
      Set(dest);
    }

    USDECoinAddr(const std::string& strAddress) : CCoinAddr(USDE_COIN_IFACE)
		{
			SetString(strAddress);
		}
};

class COLORCoinAddr : public CCoinAddr
{
  public:
    COLORCoinAddr() : CCoinAddr(COLOR_COIN_IFACE)
    {
    }

    COLORCoinAddr(const CTxDestination &dest) : CCoinAddr(COLOR_COIN_IFACE)
    {
      Set(dest);
    }
    COLORCoinAddr(const std::string& strAddress) : CCoinAddr(COLOR_COIN_IFACE)
		{
			SetString(strAddress);
		}
};


CScript GetScriptForWitness(const CScript& redeemscript);

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet);

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, vector<CTxDestination>& addressRet, int& nRequiredRet);


#endif /* ndef __SERVER__COINADDR_H__ */

