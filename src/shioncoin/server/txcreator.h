
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
 *
 *  This file is part of Shioncoin.
 *  (https://github.com/neonatura/shion-coin)
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

#ifndef __SERVER__TXCREATOR_H__
#define __SERVER__TXCREATOR_H__

#include "main.h"
#include "wallet.h"
#include "script.h"

typedef set<pair<CWalletTx *,unsigned int> > coin_set;

class CTxCreator : public CWalletTx
{
  protected:
    bool fGenerate;
    bool fWitness;
    bool fAccount;
		bool fAutoLock;
		bool fAutoParam;
    string strError; 

    int64 nMinFee;
    int64 nCredit; 
    int64 nDebit;
    unsigned int nDepth;
    coin_set setInput;
		map<unsigned int,unsigned int> setSeq;
		int nFeeDepth;

    CPubKey changePubKey;
    int64 nReserveIndex;

  public:
    CTxCreator(CWallet *wallet)
    {
      Init(wallet);
    }

    CTxCreator(CWallet *wallet, string strAccountIn) : CWalletTx(wallet)
    {
      Init(wallet);
      SetAccount(strAccountIn);
    }

    CTxCreator(CWallet* wallet, const CTransaction& txIn) : CWalletTx(wallet, txIn)
    {
      Init(wallet);

      vector<CTxOut> outs = txIn.vout;
      vector<CTxIn> ins = txIn.vin;

      vout.clear();
      vin.clear();

      BOOST_FOREACH(const CTxOut& txout, outs) {
        AddOutput(txout.scriptPubKey, txout.nValue);
      }

      BOOST_FOREACH(const CTxIn& txin, ins) {
        AddInput(txin.prevout.hash, txin.prevout.n);
      }
      
    }

    void Init(CWallet *wallet)
    {

      CWalletTx::Init(wallet);

      fGenerate = false;
      fWitness = false;
      fAccount = false;
			fAutoLock = true;
			fAutoParam = true;
      nMinFee = 0;
      nCredit = 0;
      nDebit = 0;
      nReserveIndex = -1;
      changePubKey = CPubKey();
      nDepth = 0;
      nFeeDepth = 6;
      strError = "";
      setInput.clear();
    }

    void SetAccount(string strAccountIn);

    bool AddInput(CWalletTx *tx, unsigned int n, unsigned int seq = CTxIn::SEQUENCE_FINAL);

    bool AddInput(uint256 hashTx, unsigned int n, unsigned int seq = CTxIn::SEQUENCE_FINAL);

    bool HaveInput(CWalletTx *tx, unsigned int n);

    bool HaveInput(const CTxDestination& pubKey);

    bool HaveInput(const CPubKey& pubKey);

    bool AddExtTx(CWalletTx *tx, const CScript& scriptPubKey, int64 nTxFee = 0, int64 nValue = 0);

    bool AddOutput(const CPubKey& pubkey, int64 nValue, bool fInsert = false);

    bool AddOutput(const CTxDestination& address, int64 nValue, bool fInsert = false);

    bool AddOutput(CScript scriptPubKey, int64 nValue, bool fInsert = false);

    bool HaveOutput(const CTxDestination& pubKey);

    bool HaveOutput(const CPubKey& pubKey);

    bool SetChangeAddr(const CPubKey& addr);

    CCoinAddr GetChangeAddr();

    void SetMinFee(int64 nMinFeeIn);

    size_t GetSerializedSize();

    int64 CalculateFee();

    bool Generate();

    bool Send();

    bool Verify();

    double GetPriority(int64 nBytes = 0);

		bool SetLockTime(time_t t);

		bool SetLockHeight(uint32_t nHeight);

		bool SetLockTimeSpan(int nIn, time_t t);

		bool SetLockHeightSpan(int nIn, uint32_t nHeight);

		void setAutoLock(bool b)
		{
			fAutoLock = b;
		}

		bool isAutoLock()
		{
			if (nLockTime != 0)
				return (false);
			return (fAutoLock);
		}

		void setAutoParam(bool b)
		{
			fAutoParam = b;
		}

		bool isAutoParam()
		{
			return (fAutoParam);
		}

    string GetError()
    {
      return (strError);
    }

		int getInputCount()
		{
			return (setInput.size());
		}

		void setLowFeeRate()
		{
			nFeeDepth = 0;
		}

		void setHighFeeRate()
		{
			nFeeDepth = 12;
		}

};

class CTxBatchCreator : public CTxCreator
{
  protected:
    vector<CWalletTx> vTxList;

    /* a pool of inputs to use as inputs. */
    set<pair<const CWalletTx*,unsigned int> > setCoins;

    int64 nMaxTxSize;
    int64 nMaxSigOp;
    int64 nMinFee;
    int64 nMaxFee;
    CScript scriptPub;

  public:
    /* inputs already processed into vTxList */
    vector<CTxIn> vBatchIn;

    /* coins processed for each underlying output. */
    int64 nBatchValue;

    /* total coins preferred to be sent from all transactions. */
    int64 nOutValue;

    CTxBatchCreator(CWallet *wallet, string strAccountIn, CScript scriptPubIn, int64 nValue) : CTxCreator(wallet, strAccountIn)
    {
      SetNull();

      SetLimits();

      nOutValue = nValue;
      scriptPub = scriptPubIn;
    }

    void SetNull()
    {
      vTxList.clear();
      nBatchValue = 0;
      nOutValue = 0;
    }

    void SetLimits();

    /** A list of the "batch transaction(s)" generated. */
    vector<CWalletTx>& GetTxList()
    {
      if (!fGenerate)
        Generate();
      return (vTxList); 
    }

		void SetMinFee(int64 nFee)
		{
			nMinFee = nFee;
		}

    /** Generate one or more transactions based on the underlying transaction's inputs and outputs. */
    bool Generate();

    /** Submit one or more transactions onto the network. */
    bool Send();

    bool CreateBatchTx();

};



#endif /* ndef __SERVER__TXCREATOR_H__ */
