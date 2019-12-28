
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

#ifndef __PARAM_H__
#define __PARAM_H__


#define EXTPARAM_BLOCKSIZE "blocksize"

#define EXTPARAM_MINFEE "minfee"


class CParam : public CExtCore
{
  public:
		static const int MAX_MODE_LENGTH = 135;

		int64 nValue;

    CParam()
		{
      SetNull();
		}

    CParam(const CParam& param)
    {
      SetNull();
      Init(param);
    }

    CParam(string strLabelIn, int64_t nValueIn)
    {
      SetNull();
			SetLabel(strLabelIn);
			nValue = nValueIn;
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(*(CExtCore *)this);
			READWRITE(this->nValue);
    )

    friend bool operator==(const CParam &a, const CParam &b)
    {
      return (
          ((CExtCore&) a) == ((CExtCore&) b) &&
					a.nValue == b.nValue
        );
    }

    void Init(const CParam& b)
    {
			CExtCore::Init(b);
			nValue = b.nValue;
    }

    CParam operator=(const CParam &b)
    {
			SetNull();
      Init(b);
      return *this;
    }

    void SetNull()
    {
      CExtCore::SetNull();
			nValue = 0;
    }

		string GetMode()
		{
			return (GetLabel());
		}

		int64 GetValue()
		{
			return (nValue);
		}

    const uint160 GetHash();

    std::string ToString();

    Object ToValue();

};

/* Whether blockchain is capable of processing Param extended transactions. */
bool HasParamConsensus(CIface *iface, CBlockIndex *pindexPrev = NULL);

/**
 * Verify the integrity of an param transaction.
 */
bool VerifyParamTx(CTransaction& tx, int& mode);

/**
 * @returns true if the underlying transaction contained an extended param transaction.
 */
bool IsParamTx(const CTransaction& tx);

bool ConnectParamTx(CIface *iface, CTransaction *tx, CBlockIndex *pindexPrev);

bool DisconnectParamTx(CIface *iface, CTransaction *tx);

bool GetParamTxConsensus(CIface *iface, string strName, int64_t nTime, int& nValue);

bool IsValidParamTxConsensus(string strMode, int64_t nValue, int64_t nCurrent);

bool IsValidParamTxConsensus(CIface *iface, CParam *param, int64_t nCurrent = 0);

void AddParamIfNeccessary(CIface *iface, CWalletTx& wtx);

int64_t GetParamTxValue(CIface *iface, string strName);

/**
 * submit consensus vote on a new block-chain parameter setting. 
 * @param wtx A pre-initialized wallet transaction.
 * @note Updating a parameter on a transaction will not cause the transaction to be commited.
 */
int update_param_tx(CIface *iface, string strParam, int64_t valParam, CWalletTx& wtx);


#endif /* ndef __PARAM_H__ */

