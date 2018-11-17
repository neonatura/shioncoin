
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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

#ifndef __SERVER__ACCOUNT_H__
#define __SERVER__ACCOUNT_H__

#include "main.h"
#include "key.h"
#include "keystore.h"
#include "script.h"
#include "ui_interface.h"
#include "coin.h"
#include "account.h"




/* address has been previously used. */
#define ACCADDRF_USED (1 << 0)
/* new address rotates in based on whether it has been used. */
#define ACCADDRF_DYNAMIC (1 << 1)


class CAccountAddr
{
	public:
		cbuff vchPubKey;
		unsigned int nIndex;
		unsigned int nFlag;
		int64_t nCreateTime;
		int64_t nAccessTime;

		CAccountAddr() { SetNull(); }

		CAccountAddr(CPubKey vchPubKeyIn, int nTypeIn)
		{ 
			SetNull(); 
			vchPubKey = vchPubKeyIn.Raw();
		}

		IMPLEMENT_SERIALIZE(
			READWRITE(vchPubKey);
			READWRITE(nIndex);
			READWRITE(nFlag);
			READWRITE(nCreateTime);
		)

		void SetNull() 
		{ 
			vchPubKey.clear();
			nIndex = 0;
			nFlag = 0;
			nCreateTime = 0;
			nAccessTime = 0;
		}

		bool IsNull() const { 
			return (vchPubKey.size() == 0);
		}

		friend bool operator==(const CAccountAddr& a, const CAccountAddr& b)
		{
			return (
					a.vchPubKey == b.vchPubKey
					);
		}

		time_t GetAccessTime()
		{
			if (nAccessTime == 0)
				return (GetCreateTime());
			return ((time_t)nAccessTime);
		}

		time_t GetCreateTime()
		{
			return ((time_t)nCreateTime);
		}

};

class CAccountCache
{
	public:
		CAccount account;
		uint256 hChain;
		string strAccount;
		CAccountAddr vAddr[MAX_ACCADDR];

		mutable CWallet *wallet;

		vector<uint256> vInvalidTx;

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
				READWRITE(hChain);
				READWRITE(strAccount);
				for (unsigned int i = 0; i < MAX_ACCADDR; i++)
					READWRITE(vAddr[i]);
		)

		void SetNull() 
		{ 
			account.vchPubKey.SetNull();
			hChain = 0;
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


		bool GetFlags(int type)
		{
			return (vAddr[type].nFlag);
		}

		void SetFlag(int type, int flag)
		{
			vAddr[type].nFlag |= flag;
		}

		void UnsetFlag(int type, int flag)
		{
			vAddr[type].nFlag &= ~flag;
		}

		bool IsAddrUsed(const CPubKey& vchPubKey);

		CPubKey GetStaticAddr(int type);

		CPubKey GetDynamicAddr(int type);

		CPubKey GetDefaultAddr();

		CPubKey GetAddr(int type);

		void AddAddr(CPubKey pubkey, int type);

		CPubKey CreateNewAddr(int type);

		CPubKey CreateAddr(int type);

};



#endif /* ndef __SERVER__ACCOUNT_H__ */
