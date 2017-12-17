
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#ifndef __SERVER__TXCREATOR_H__
#define __SERVER__TXCREATOR_H__

#include "main.h"
#include "key.h"
#include "keystore.h"
#include "script.h"



typedef set<pair<CWalletTx *,unsigned int> > coin_set;

class CTxCreator : public CWalletTx
{
  protected:
    bool fGenerate;
    bool fWitness;
    bool fAccount;
    string strError; 

    int64 nMinFee;
    int64 nCredit; 
    int64 nDebit;
    unsigned int nDepth;
    coin_set setInput;

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
      CWalletTx::Init(wallet);


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
      nMinFee = 0;
      nCredit = 0;
      nDebit = 0;
      nReserveIndex = -1;
      changePubKey = CPubKey();
      nDepth = 0;
      strError = "";
      setInput.clear();

    }

    void SetAccount(string strAccountIn);

    bool AddInput(CWalletTx *tx, unsigned int n);

    bool AddInput(uint256 hashTx, unsigned int n);

    bool HaveInput(CWalletTx *tx, unsigned int n);

    bool AddExtTx(CWalletTx *tx, const CScript& scriptPubKey, int64 nTxFee = 0);

    bool AddOutput(const CPubKey& pubkey, int64 nValue, bool fInsert = false);

    bool AddOutput(const CTxDestination& address, int64 nValue, bool fInsert = false);

    bool AddOutput(CScript scriptPubKey, int64 nValue, bool fInsert = false);

    bool SetChange(const CPubKey& addr);

    void SetMinFee(int64 nMinFeeIn);

    size_t GetSerializedSize();

    int64 CalculateFee();

    void CreateChangeAddr();

    bool Generate();

    bool Send();

    bool Verify();

    double GetPriority(int64 nBytes = 0);


    string GetError()
    {
      return (strError);
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

    /** Generate one or more transactions based on the underlying transaction's inputs and outputs. */
    bool Generate();

    /** Submit one or more transactions onto the network. */
    bool Send();

    bool CreateBatchTx();

};



#endif /* ndef __SERVER__TXCREATOR_H__ */
