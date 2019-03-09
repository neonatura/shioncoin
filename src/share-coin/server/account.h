
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


/* use segwit program, if available. */
#define ACCADDRF_WITNESS (1 << 0)
/* derived via hdkey, if available. */
#define ACCADDRF_DERIVE (1 << 1)
/* always the same address returned */
#define ACCADDRF_STATIC (1 << 2)
/* use extended account */
#define ACCADDRF_STATIC (1 << 2)


class CAccountCache
{
	public:
		CAccount account;
		uint256 hChain;
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
				READWRITE(hChain);
				READWRITE(strAccount);
#if 0
				for (unsigned int i = 0; i < MAX_ACCADDR; i++)
					READWRITE(vAddr[i]);
#endif
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


#if 0
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
#endif


		bool IsAddrUsed(const CCoinAddr& vchPubKey);

		bool IsAddrUsed(const CPubKey& vchPubKey);

		CCoinAddr GetStaticAddr(int type);

		CCoinAddr GetDynamicAddr(int type);

		CCoinAddr GetDefaultAddr();

		CCoinAddr GetAddr(int type);

		void AddAddr(CCoinAddr pubkey, int type);

		CCoinAddr CreateNewAddr(int type);

		CCoinAddr CreateAddr(int type);

};



#endif /* ndef __SERVER__ACCOUNT_H__ */
