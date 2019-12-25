
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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

#ifndef __SERVER__ACCOUNT_H__
#define __SERVER__ACCOUNT_H__

#include "main.h"
#include "key.h"
#include "keystore.h"
#include "script.h"
#include "coin.h"
#include "account.h"

/* use segwit program, if available. */
#define ACCADDRF_WITNESS (1 << 0)
/* derived via hdkey, if available. */
#define ACCADDRF_DERIVE (1 << 1)
/* always the same address returned */
#define ACCADDRF_STATIC (1 << 2)
/* permit dilithium signature */
#define ACCADDRF_DILITHIUM (1 << 3)

void GetAddrDestination(int ifaceIndex, const CKeyID& keyid, vector<CTxDestination>& vDest, int nFlag = 0);

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

		bool CreateNewPubKey(CPubKey& addrRet, int flags);

		/**
		 * When the ACCADDRF_DILITHIUM flag is passed in then only the bech32 Witness v14 address is returned, and otherwise a pubkey, pubkey-script, witness, and bech32 is returned based on blockchain capability.
		 * @param nFlag ACCADDRF_XX
		 */
		void GetAddrDestination(const CKeyID& keyid, vector<CTxDestination>& vDest, int nFlag = 0)
		{
			::GetAddrDestination(wallet->ifaceIndex, keyid, vDest, nFlag);
		}

		void SetAddrDestinations(const CKeyID& keyid);

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

		bool SetCertHash(const uint160& hCert);

		uint160 GetCertHash() const;

};

#endif /* ndef __SERVER__ACCOUNT_H__ */

