
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

#ifndef __EXT__IDENT_H__
#define __EXT__IDENT_H__

class CIdent : public CEntity
{

	public:

		static const int CURRENT_IDENT_VERSION = 4;

		uint160 __uint160_reserved0__;
		CSign __csign_reserved0__;
		cbuff __cbuff_reserved0__;
		int64 __int64_reserved0__;
		int __int_reserved0__;

		CIdent()
		{
			SetNull();
		}

		CIdent(const CIdent& ent)
		{
			SetNull();
			Init(ent);
		}

		CIdent(const CCert& ent)
		{
			SetNull();
			Init(ent);
		}

		CIdent(string labelIn)
		{
			SetNull();
			SetLabel(labelIn);
		}

		IMPLEMENT_SERIALIZE (
			READWRITE(*(CEntity *)this);
			if (this->nVersion < 4) {
				READWRITE(__uint160_reserved0__);
				READWRITE(__csign_reserved0__);
				READWRITE(__cbuff_reserved0__);
				READWRITE(__int64_reserved0__);
				READWRITE(__int_reserved0__);
			}
		)

		friend bool operator==(const CIdent &a, const CIdent &b)
		{
			return (
					((CEntity&) a) == ((CEntity&) b)
					);
		}

		CIdent operator=(const CIdent &b)
		{
			SetNull();
			Init(b);
			return *this;
		}

		void SetNull();

		void Init(const CIdent& b)
		{
			CEntity::Init(b);
			__uint160_reserved0__ = b.__uint160_reserved0__;
			__csign_reserved0__ = b.__csign_reserved0__;
			__cbuff_reserved0__ = b.__cbuff_reserved0__;
			__int64_reserved0__ = b.__int64_reserved0__;
			__int_reserved0__ = b.__int_reserved0__;
		}

		void Init(const CCert& b)
		{
			CEntity::Init((CEntity&)b);
		}

		uint160 GetHash();

		time_t GetMinimumLifespan()
		{
			return (0);
		}

		int VerifyTransaction(int ifaceIndex);

		std::string ToString();

		Object ToValue();

};


class CWalletTx;

int init_ident_stamp_tx(CIface *iface, string strAccount, string strComment, CWalletTx& wtx);

extern int init_ident_donate_tx(CIface *iface, string strAccount, uint64_t nValue, uint160 hashCert, CWalletTx& wtx);

extern int init_ident_certcoin_tx(CIface *iface, string strAccount, uint64_t nValue, uint160 hashCert, CCoinAddr addrDest, CWalletTx& wtx);

extern bool VerifyIdent(CTransaction& tx, int& mode);

cert_list *GetIdentTable(int ifaceIndex);

bool GetTxOfIdent(CIface *iface, const uint160& hash, CTransaction& tx);

bool InsertIdentTable(CIface *iface, CTransaction& tx);

bool IsIdentTx(const CTransaction& tx);

int IndexOfIdentOutput(const CTransaction& tx);

bool DecodeIdentHash(const CScript& script, int& mode, uint160& hash);

int GetIdentTxMode(CTransaction& tx);


#endif /* ndef __EXT__IDENT_H__ */

