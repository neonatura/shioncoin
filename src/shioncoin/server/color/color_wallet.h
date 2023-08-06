
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

#ifndef __COLOR_WALLET_H__
#define __COLOR_WALLET_H__

/**
 * @ingroup sharecoin_color
 * @{
 */


extern CScript COLOR_COINBASE_FLAGS;

class COLORWallet : public CWallet
{
  public:
    COLORWallet() : CWallet(COLOR_COIN_IFACE, "color_wallet.dat") { };  

    void RelayWalletTransaction(CWalletTx& wtx);
    void ResendWalletTransactions();
    void ReacceptWalletTransactions();
//    int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false);
    int64 GetTxFee(CTransaction tx);
    bool CommitTransaction(CWalletTx& wtxNew);

    void AddSupportingTransactions(CWalletTx& wtx);

    bool CreateAccountTransaction(string strFromAccount, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, string& strError, int64& nFeeRet);
    bool CreateAccountTransaction(string strFromAccount, CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, string& strError, int64& nFeeRet);


    bool UnacceptWalletTransaction(const CTransaction& tx);

    int64 GetBlockValue(int nHeight, int64 nFees, uint160 hColor = 0);

    unsigned int GetTransactionWeight(const CTransaction& tx);

    double AllowFreeThreshold();

    int64 GetFeeRate(uint160 hColor);

		int GetCoinbaseMaturity(uint160 hColor = 0);

		bool IsAlgoSupported(int alg, CBlockIndex *pindexPrev = NULL, uint160 hColor = 0);

};


extern COLORWallet *colorWallet;


bool color_LoadWallet(void);

CAccountCache *GetColorAccount(string strAccount, uint160 hColor);

CCoinAddr GetColorCoinAddress(string strAccount, uint160 hColor, int nType);


/**
 * @}
 */


#endif /* ndef __COLOR_WALLET_H__ */
