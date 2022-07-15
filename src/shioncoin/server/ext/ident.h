
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

	uint160 hash;
	CSign signature;
	cbuff vContext;
	int64 nValue;
	int nFlag;

	public:

	CIdent()
	{
		SetNull();
	}

	CIdent(const CIdent& ent)
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
			READWRITE(this->hash);
			READWRITE(this->signature);
			READWRITE(this->vContext);
			READWRITE(this->nValue);
			READWRITE(this->nFlag);
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

	void SetNull()
	{
		CEntity::SetNull();
		nVersion = 3;
		nValue = 0;
		hash = 0;

		nFlag = SHCERT_ENT_ORGANIZATION | SHCERT_CERT_DIGITAL | SHCERT_CERT_SIGN;
		// should be:
		//nFlag = SHCERT_ENT_ORGANIZATION;
	}

	void Init(const CIdent& b)
	{
		CEntity::Init(b);
	}

	uint160 GetHash();

	time_t GetMinimumLifespan()
	{
		return (0);
	}

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


#endif /* ndef __EXT__IDENT_H__ */

