
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

#ifndef __ALIAS_H__
#define __ALIAS_H__


#define DEFAULT_ALIAS_LIFESPAN 378432000 /* 12 yr */ 

class CAlias : public CEntity
{

	private:
		static const int MINIMUM_ALIAS_LIFESPAN = 378432000; /* 12y */

	public:
		static const int ALIAS_NONE = 0;
		static const int ALIAS_COINADDR = TXREF_PUBADDR;

		CAlias()
		{
			SetNull();
		}

		CAlias(const CAlias& alias)
		{
			SetNull();
			Init(alias);
		}

		CAlias(const CEntity& ident)
		{
			SetNull();
			CEntity::Init(ident);
		}

		CAlias(std::string labelIn, const uint160& hashIn)
		{
			SetNull();

			/* assign title */
			SetLabel(labelIn);

			/* fill content layer */
			char hstr[256];
			memset(hstr, 0, sizeof(hstr));
			strncpy(hstr, hashIn.GetHex().c_str(), sizeof(hstr)-1);
			vAddr = cbuff(hstr, hstr + strlen(hstr));

			/* set attributes */
			SetType(ALIAS_COINADDR);
		}

		IMPLEMENT_SERIALIZE (
			READWRITE(*(CEntity *)this);
		)

		bool GetCoinAddr(int ifaceIndex, CCoinAddr& addrRet);

		void SetCoinAddr(CCoinAddr& addr);

		friend bool operator==(const CAlias &a, const CAlias &b)
		{
			return (
					((CEntity&) a) == ((CEntity&) b)
					);
		}
		void Init(const CAlias& alias)
		{
			CEntity::Init(alias);
		}

		CAlias operator=(const CAlias &b)
		{
			SetNull();
			Init(b);
			return *this;
		}

		void SetNull()
		{
			CEntity::SetNull();
		}

#if 0
		void NotifySharenet(int ifaceIndex);
		void FillReference(SHAlias *ref);
#endif

		int64 CalculateFee(CIface *iface, int nHeight);

		time_t GetMinimumLifespan()
		{
			return (MINIMUM_ALIAS_LIFESPAN); 
		}

		int VerifyTransaction();

		std::string ToString(int ifaceIndex);

		Object ToValue(int ifaceIndex);

		const uint160 GetHash()
		{
			uint256 hashOut = SerializeHash(*this);
			unsigned char *raw = (unsigned char *)&hashOut;
			cbuff rawbuf(raw, raw + sizeof(hashOut));
			return Hash160(rawbuf);
		}

};

class CWalletTx;


alias_list *GetAliasTable(int ifaceIndex);

alias_list *GetAliasPendingTable(int ifaceIndex);



bool IsAliasTx(const CTransaction& tx);

bool IsLocalAlias(CIface *iface, const CTransaction& tx);

int64 GetAliasOpFee(CIface *iface, int nHeight); 

bool GetTxOfAlias(CIface *iface, const std::string strTitle, CTransaction& tx);

CAlias *GetAliasByName(CIface *iface, string label, CTransaction& tx);

bool CommitAliasTx(CIface *iface, CTransaction& tx, int nHeight);

bool ConnectAliasTx(CIface *iface, CTransaction& tx);

bool DisconnectAliasTx(CIface *iface, CTransaction& tx);

bool IsValidAliasName(CIface *iface, string label);

bool DecodeAliasHash(const CScript& script, int& mode, uint160& hash);

int IndexOfAliasOutput(const CTransaction& tx);

int init_alias_addr_tx(CIface *iface, const char *title, CCoinAddr& addr, CWalletTx& wtx, bool fTest = false);

int update_alias_addr_tx(CIface *iface, const char *title, CCoinAddr& addr, CWalletTx& wtx, bool fTest = false);

int remove_alias_addr_tx(CIface *iface, string strAccount, string strTitle, CWalletTx& wtx);


#endif /* ndef __ALIAS_H__ */

