
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

#ifndef __CONTEXT_H__
#define __CONTEXT_H__



#define DEFAULT_CONTEXT_LIFESPAN 63072000 /* two years */

class CContext : public CCert
{
	public:

		/**
		 * The maximum size permitted of the context context payload.
		 */
		static const unsigned int MAX_VALUE_SIZE = 4096;

		/** The maximum size permitted of the context context payload. */
		static const unsigned int MAX_CONTEXT_CONTENT_LENGTH = 4096;

		CContext()
		{
			SetNull();
		}

		CContext(const CCert& certIn)
		{
			SetNull();
			CCert::Init(certIn);
		}

		CContext(const CContext& ctxIn)
		{
			SetNull();
			Init(ctxIn);
		}

		IMPLEMENT_SERIALIZE (
				READWRITE(*(CCert *)this);
				)

			void SetNull()
			{
				CCert::SetNull();
			}

		void Init(const CContext& ctxIn)
		{
			CCert::Init(ctxIn);
		}

		friend bool operator==(const CContext &a, const CContext &b)
		{
			return (
					((CCert&) a) == ((CCert&) b)
					);
		}

		CContext operator=(const CContext &b)
		{
			SetNull();
			Init(b);
			return (*this);
		}

		bool Sign(int ifaceIndex);

		bool VerifySignature();

		/**
		 * The 'context hash' is identical to the 'hashed context name'.
		 */
		const uint160 GetHash()
		{
			return (hashIssuer);
		}

		void SetName(uint160 hName)
		{
			hashIssuer = hName;
		}

		uint160 GetName()
		{
			return (hashIssuer);
		}

		bool SetValue(string name, cbuff value);

		void NotifySharenet(int ifaceIndex);

		int GetMaximumContentSize() /* CExtCore */
		{
			return (MAX_CONTEXT_CONTENT_LENGTH);
		}

		std::string ToString();

		Object ToValue();

};


ctx_list *GetContextTable(int ifaceIndex);

bool VerifyContextTx(CIface *iface, CTransaction& tx, int& mode);

bool IsContextTx(const CTransaction& tx);

int CommitContextTx(CIface *iface, CTransaction& tx, unsigned int nHeight);

bool DisconnectContextTx(CIface *iface, CTransaction& tx);

int64 GetContextOpFee(CIface *iface, int nHeight, int nSize = 4096);

CContext *GetContextByHash(CIface *iface, uint160 hashName, CTransaction& ctx_tx);

CContext *GetContextByName(CIface *iface, string strName, CTransaction& ctx_tx);


int init_ctx_tx(CIface *iface, CWalletTx& wtx, string strAccount, string strName, cbuff vchValue, shgeo_t *loc = NULL, bool fTest = false);

int update_ctx_tx(CIface *iface, CWalletTx& wtx, string strAccount, string strName, cbuff vchValue, shgeo_t *loc = NULL, bool fTest = false);

/**
 * Verify that the context payload has a valid value.
 */
int ctx_context_verify(cbuff vchValue);

/**
 * Generate a ShionID.
 * @param mapParam A list of ID parameters including the required "id" option specifying an email address. A "password" will automatically be encypted using sha256.
 */
int create_shionid_tx(CIface *iface, CWalletTx& wtx, string strAccount, map<string,string> mapParam, bool fTest = false);

string create_shionid_id(string strEmail);


#endif /* ndef __CONTEXT_H__ */


