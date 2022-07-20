
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

class CContext : public CEntity
{

	public:

		/**
		 * The maximum size permitted of the context context payload.
		 */
		static const unsigned int MAX_VALUE_SIZE = 4096;

		/** The maximum size permitted of the context context payload. */
		static const unsigned int MAX_CONTEXT_CONTENT_LENGTH = 4096;

		static const time_t MIN_CONTEXT_LIFESPAN = 63072000; /* 2y */

		static const time_t MAX_CONTEXT_LIFESPAN = 378432000; /* 12y */ 

		uint160 hashIssuer;
		CSign signature;
		cbuff vContext;
		int64 __reserved_0__;
		int __reserved_1__;

		CContext()
		{
			SetNull();
		}

		CContext(const CEntity& certIn)
		{
			SetNull();
			CEntity::Init(certIn);
		}

		CContext(const CContext& ctxIn)
		{
			SetNull();
			Init(ctxIn);
		}

		IMPLEMENT_SERIALIZE (
			READWRITE(*(CEntity *)this);
			READWRITE(this->hashIssuer);
			READWRITE(this->signature);
			READWRITE(this->vContext);
			READWRITE(this->__reserved_0__);
			READWRITE(this->__reserved_1__);
		)

		void SetNull()
		{
			CEntity::SetNull();

      signature.SetNull();
      vContext.clear();

      nVersion = 3;
      hashIssuer = 0;

			__reserved_0__ = 0;
			__reserved_1__ = 0;
		}

		void Init(const CContext& ctxIn)
		{
			CEntity::Init(ctxIn);
			hashIssuer = ctxIn.hashIssuer;
			signature = ctxIn.signature;
			vContext = ctxIn.vContext;
			__reserved_0__ = ctxIn.__reserved_0__;
			__reserved_1__ = ctxIn.__reserved_1__;
		}

		friend bool operator==(const CContext &a, const CContext &b)
		{
			return (
					((CEntity&) a) == ((CEntity&) b) &&
					a.hashIssuer == b.hashIssuer &&
					a.signature == b.signature &&
					a.vContext == b.vContext &&
					a.__reserved_0__ == b.__reserved_0__ &&
					a.__reserved_1__ == b.__reserved_1__
					);
		}

		CContext operator=(const CContext &b)
		{
			SetNull();
			Init(b);
			return (*this);
		}

		time_t GetMinimumLifespan()
		{
			return (MIN_CONTEXT_LIFESPAN);
		}

		time_t GetMaximumLifespan()
		{
			return (MAX_CONTEXT_LIFESPAN);
		}

		time_t CalculateLifespan(CIface *iface, int64 nFee);

		void ResetExpireTime(CIface *iface, int64 nFee);

		int64 CalculateFee(CIface *iface, int nHeight, int nContentSize = -1, time_t nLifespan = -1);

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

		//		void NotifySharenet(int ifaceIndex);

		cbuff GetContent()
		{
			return (vContext);
		}

		void SetContent(const cbuff& vContextIn)
		{
			vContext = vContextIn;
		}

		void ResetContent()
    {
      vContext = cbuff();
    }

		int GetContentSize()
    {
      return (vContext.size());
    }

		int GetMaximumContentSize() /* CExtCore */
		{
			return (MAX_CONTEXT_CONTENT_LENGTH);
		}

		int64 CalculateContentChecksum()
		{
			Object obj = CEntity::ToValue();
			return ((int64_t)shcrc(vContext.data(), vContext.size()));
		}

		int VerifyTransaction();

		std::string ToString();

		Object ToValue();

};


ctx_list *GetContextTable(int ifaceIndex);

bool IsContextTx(const CTransaction& tx);

int CommitContextTx(CIface *iface, CTransaction& tx, unsigned int nHeight);

bool DisconnectContextTx(CIface *iface, CTransaction& tx);

int64 GetContextOpFee(CIface *iface, int nHeight, int nSize = 4096);

CContext *GetContextByHash(CIface *iface, uint160 hashName, CTransaction& ctx_tx);

CContext *GetContextByName(CIface *iface, string strName, CTransaction& ctx_tx);

int64 CalculateContextFee(CIface *iface, int nHeight, int nSize = 0, int nLifespan = 0);

bool DecodeContextHash(const CScript& script, int& mode, uint160& hash);

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

int IndexOfContextOutput(const CTransaction& tx);


#endif /* ndef __CONTEXT_H__ */


