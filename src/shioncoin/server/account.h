
/*
 * @copyright
 *
 *  Copyright 2018 Brian Burrell
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

#ifndef __SERVER__ACCOUNT_H__
#define __SERVER__ACCOUNT_H__

#include "main.h"
#include "key.h"
#include "keystore.h"
#include "script.h"
#include "coin.h"

void GetAddrDestination(int ifaceIndex, const CKeyID& keyid, vector<CTxDestination>& vDest, int nFlag = 0);

const char *GetPubKeyTag(int type);

class CAccountCache
{
	public:
		CAccount account;
		uint256 _reserved0_;
		string strAccount;
		CCoinAddr vAddr[MAX_ACCADDR];

		mutable CWallet *wallet;

		CAccountCache(CWallet *walletIn) { 
			SetNull(); 
			wallet = walletIn;
		}

		CAccountCache(CWallet *walletIn, CPubKey vchPubKeyIn, string strAccountIn = "")
		{ 
			SetNull(); 
			wallet = walletIn;
			account.vchPubKey = vchPubKeyIn;
			strAccount = strAccountIn;
		}

		CAccountCache(CWallet *walletIn, CAccount accountIn, string strAccountIn = "")
		{
			SetNull();
			wallet = walletIn;
			account = accountIn;
			strAccount = strAccountIn;
		}

		IMPLEMENT_SERIALIZE(
				READWRITE(account);
				READWRITE(_reserved0_);
				READWRITE(strAccount);
				)

			void SetNull() 
			{ 
				account.vchPubKey.SetNull();
				_reserved0_ = 0;
				strAccount.clear();
				for (unsigned int i = 0; i < MAX_ACCADDR; i++)
					vAddr[i].SetNull();
			}

		bool IsNull() const { 
			return (!account.vchPubKey.IsValid());
		}

		friend bool operator==(const CAccountCache& a, const CAccountCache& b)
		{
			return (
					a.strAccount == b.strAccount &&
					a.account.vchPubKey == b.account.vchPubKey
					);
		}

		bool IsAddrUsed(const CCoinAddr& vchPubKey);

		bool IsAddrUsed(const CPubKey& vchPubKey);

		CCoinAddr GetDefaultAddr();

		void SetDefaultAddr(const CPubKey& pubkey);

		CCoinAddr GetAddr(int type);

		void SetAddr(int type, CCoinAddr pubkey);

		void ResetAddr(int type);

		void UpdateAccount();

		bool GetPrimaryAddr(int type, CTxDestination& addrRet);

		bool GetPrimaryPubKey(int type, CPubKey& pubkeyRet);

		bool CreateNewAddr(CTxDestination& addrRet, int type, int flags);

		bool CreateNewPubKey(CPubKey& addrRet, int type, int flags);

		bool GetMergedPubKey(CKey *pkey, int nAlg, cbuff tag, CPubKey& pubkey);

		bool GetMergedPubKey(int nMode, int nAlg, cbuff tag, CPubKey& pubkey);

		bool GetMergedPubKey(cbuff tag, CPubKey& pubkey);

		bool GetMergedAddr(cbuff tag, CCoinAddr& addr);

		bool GetMergedPubKey(const char *tag, CPubKey& pubkey)
		{
			cbuff tagbuf(tag, tag + strlen(tag));
			return (GetMergedPubKey(tagbuf, pubkey));
		}

		bool GetMergedAddr(const char *tag, CCoinAddr& addr)
		{
			cbuff tagbuf(tag, tag + strlen(tag));
			return (GetMergedAddr(tagbuf, addr));
		}

		bool SetAliasHash(const uint160& hAlias);

		uint160 GetAliasHash() const;

		CAccountCache *GetExtAccount();

		int GetAddrMode(const CTxDestination& addr);

		uint GetHDIndex(int nMode, int nAlg);

		void IncrementHDIndex(int nMode, int nAlg);

		void ResetHDIndex();

		bool CalculateHDIndex(vector<CTxDestination>& vAddr, int nMode, int nAlg, int nMinCount = 0);

		void CalculateECKeyChain(vector<CTxDestination>& vAddr, int nType, int nMinCount);

		void CalculateDIKeyChain(vector<CTxDestination>& vAddr, int nMode, int nMinCount);

		bool GetCoinbasePubKey(CPubKey& pubkeyRet);

		CCoinAddr GetCoinbaseAddr();

		bool AddKey(ECKey& key);

		bool AddKey(DIKey& key);

		/**
		 * When the ACCADDRF_DILITHIUM flag is passed in then only the bech32 Witness v14 address is returned, and otherwise a pubkey, pubkey-script, witness, and bech32 is returned based on blockchain capability.
		 * @param nFlag ACCADDRF_XX
		 */
		void CalcAddressBook(const CKeyID& keyid, vector<CTxDestination>& vDest, bool fDilithium);

		void CalcAddressBook(CKey *key, vector<CTxDestination>& vDest);

		void SetAddressBook(const CKeyID& keyid, vector<CTxDestination>& vDest, bool fDilithium);

		void SetAddressBook(CKey *key, vector<CTxDestination>& vDest);

		CTxDestination GetDestination(const CKeyID& keyid, int nFlag);

		CTxDestination GetDestination(CKey *key);

    bool GenerateNewECKey(CPubKey& pubkeyRet, bool fCompressed = true, int nFlag = 0);

    bool GenerateNewDIKey(CPubKey& pubkeyRet, int nFlag = 0);


protected:
    bool DerivePrimaryKey(CPubKey& pubkeyRet, int nType = 0);

    bool GeneratePrimaryKey(CPubKey& pubkeyRet, int nType = 0);

		CKey *GetPrimaryKey(int nMode, int nAlg);

};

class CAccountAddress : public CCoinAddr
{

	public:
		CWallet *wallet;
//		CAccountCache *account;
//		CTxDestination destination;
		CKeyID keyid;

//		CScript scriptPubKey;
//		vector<CTxDestination> addresses;
		txnouttype nOutputType;
//		int nRequired;

		bool fWitness;
		int nWitnessVersion;
		int nWitnessSize;

//		bool fScript;
//		CScriptID scriptID;
		CScript script;

		CAccountAddress(int ifaceIndexIn) : CCoinAddr(ifaceIndexIn) {
			SetNull();
			Init();
    }

		CAccountAddress(int ifaceIndexIn, const CTxDestination& destinationIn) : CCoinAddr(ifaceIndexIn) {
			SetNull();
			Set(destinationIn);
			Init();
    }

		CAccountAddress(int ifaceIndexIn, const std::string& strAddressIn) : CCoinAddr(ifaceIndexIn) {
			SetNull();
			SetString(strAddressIn);
			Init();
    }

		void SetNull();

		void Init();

		/*
		void SetCreateTime(time_t nCreateTimeIn) 
		{
			nCreateTime = nCreateTimeIn;
		}

		time_t GetCreateTime()
		{
			return (nCreateTime);
		}
		*/

		bool IsDefault();

		bool IsMine();

		CAccountCache *GetAccountCache();

		CAccount *GetAccount();

		CTxDestination GetDestination();

		CScript GetScriptPubKey();

		bool GetScriptID(CScriptID& scriptID);

		string GetAccountName();

		string GetExtAccountName();

		void SetAccountName(string strAccount);

		CCoinAddr *GetCoinAddr();

		bool HaveKey();

		const CScript& ToScript();

		Object ToValue();

};

class CAccountAddressKey : public CAccountAddress
{

	protected:
		CKey *key;
		CPubKey pubkey; 

	public:
		CAccountAddressKey(int ifaceIndexIn) : CAccountAddress(ifaceIndexIn) {
			SetNull();
			Init();
    }

		CAccountAddressKey(int ifaceIndexIn, const CTxDestination& destinationIn) : CAccountAddress(ifaceIndexIn, destinationIn) {
			SetNull();
			Init();
    }

		CAccountAddressKey(int ifaceIndexIn, const std::string& strAddressIn) : CAccountAddress(ifaceIndexIn, strAddressIn) {
			SetNull();
			Init();
    }

		CAccountAddressKey(int ifaceIndexIn, CKey *keyIn) : CAccountAddress(ifaceIndexIn) {
			SetNull();
			key = keyIn;
			pubkey = key->GetPubKey();
      Set(pubkey.GetID());
			CAccountAddress::Init();
    }

		void SetNull();

		void Init();

		time_t GetCreateTime()
		{
			return (key ? key->nCreateTime : 0);
		}

		const CPubKey& GetPubKey() {
			return (pubkey);
		}

		CKey *GetKey() {
			return (key);
		}

		Object ToValue();

		bool FromValue(Object obj);

};

#endif /* ndef __SERVER__ACCOUNT_H__ */

