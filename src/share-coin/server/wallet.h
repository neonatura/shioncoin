
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

  #ifndef __SERVER__WALLET_H__
  #define __SERVER__WALLET_H__


  #include "main.h"
  #include "key.h"
  #include "keystore.h"
  #include "script.h"
  #include "ui_interface.h"

  class CWalletTx;
  class CReserveKey;
  class CWalletDB;
  class COutput;
  class HDPubKey;

  /** (client) version numbers for particular wallet features */
  enum WalletFeature
  {
      FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

      FEATURE_WALLETCRYPT = 40000, // wallet encryption
      FEATURE_COMPRPUBKEY = 60000, // compressed public keys

      FEATURE_LATEST = 60000
  };


  /** A key pool entry */
  class CKeyPool
  {
  public:
      int64 nTime;
      CPubKey vchPubKey;

      CKeyPool()
      {
          nTime = GetTime();
      }

      CKeyPool(const CPubKey& vchPubKeyIn)
      {
          nTime = GetTime();
          vchPubKey = vchPubKeyIn;
      }

      IMPLEMENT_SERIALIZE
      (
          if (!(nType & SER_GETHASH))
              READWRITE(nVersion);
          READWRITE(nTime);
          READWRITE(vchPubKey);
      )
  };

  /** A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
   * and provides the ability to create new transactions.
   */
  class CWallet : public CCryptoKeyStore
  {
  private:

      CWalletDB *pwalletdbEncryption;

      // the current wallet version: clients below this version are not able to load the wallet
      int nWalletVersion;

      // the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
      int nWalletMaxVersion;

  protected:

  public:
      mutable CCriticalSection cs_wallet;
      mutable int ifaceIndex;
      mutable unsigned int nScanHeight;
      mutable unsigned int nValidateHeight;

      mutable std::map<std::string, uint256> mapAlias;
      mutable std::map<uint256, std::string> mapAliasArch;

      mutable std::map<uint160, uint256> mapLicense;
      mutable std::map<uint160, uint256> mapOffer;
      mutable std::map<uint160, uint256> mapOfferAccept;
      mutable std::map<uint160, uint256> mapAsset;
      mutable std::map<uint160, uint256> mapAssetArch;
      mutable std::map<uint160, CTransaction> mapExec;
      mutable std::vector<CTxOut> mapExecCommit;

      mutable std::map<uint160, uint256> mapContext;
      mutable std::map<uint256, uint160> mapContextArch;

      /** A vector of open coin-transfer channels. */
      mutable std::map<uint160, CTransaction> mapChannel;
      /** A vector of commit transactions for each channel. */
      mutable std::map<uint160, CTransaction> mapChannelSpent;
      /** A vector of remedy transactions for each channel. */
      mutable std::map<uint160, CTransaction> mapChannelRedeem;

      /** Incoming TX_NEW : TX_IDENT transactions for the Spring matrix.  */
      mutable std::map<uint160, uint256> mapIdent;

      /** The latest TX_NEW/TX_ACTIVATE : TX_CERT certificate transactions. */
      mutable std::map<uint160, uint256> mapCert;

      /** A table of certificate names. */
      mutable std::map<std::string, uint160> mapCertLabel;

      /** The over-written TX_NEW/TX_ACTIVATE : TX_CERT certificate transactions. */
      mutable std::map<uint256, uint160> mapCertArch;

      bool fFileBacked;
      std::string strWalletFile;

      std::set<int64> setKeyPool;


      typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
      MasterKeyMap mapMasterKeys;
      unsigned int nMasterKeyMaxID;

      CWallet(int index)
      {
          nWalletVersion = FEATURE_BASE;
          nWalletMaxVersion = FEATURE_BASE;
          fFileBacked = false;
          nMasterKeyMaxID = 0;
          pwalletdbEncryption = NULL;
          ifaceIndex = index;
  nScanHeight = 0;
      }
      CWallet(int index, std::string strWalletFileIn)
      {
          nWalletVersion = FEATURE_BASE;
          nWalletMaxVersion = FEATURE_BASE;
          strWalletFile = strWalletFileIn;
          fFileBacked = true;
          nMasterKeyMaxID = 0;
          pwalletdbEncryption = NULL;
          ifaceIndex = index;
  nScanHeight = 0;
      }

      std::map<uint256, CWalletTx> mapWallet;
      std::map<uint256, int> mapRequestCount;

      std::map<CTxDestination, std::string> mapAddressBook;

      CPubKey vchDefaultKey;

      bool SelectCoins(int64 nTargetValue, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const;

      // check whether we are allowed to upgrade (or already support) to the named feature
      bool CanSupportFeature(enum WalletFeature wf) { return nWalletMaxVersion >= wf; }

      void AvailableCoins(std::vector<COutput>& vCoins, bool fOnlyConfirmed =true)  const;
      void AvailableAccountCoins(string strAccount, std::vector<COutput>& vCoins, bool fOnlyConfirmed =true)  const;

      void AvailableAddrCoins(vector<COutput>& vCoins, const CCoinAddr& filterAddr, int64& nTotalValue, bool fOnlyConfirmed) const;

      bool SelectCoinsMinConf(int64 nTargetValue, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const;

      bool SelectAccountCoins(string strAccount, int64 nTargetValue, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const;

      // keystore implementation
      // Generate a new key
      CPubKey GenerateNewKey(bool fCompressed = true);
      HDPubKey GenerateNewHDKey(bool fCompressed = true);
      // Adds a key to the store, and saves it to disk.
      bool AddKey(const HDPrivKey& key);
      bool AddKey(const CKey& key);
      // Adds a key to the store, without saving it to disk (used by LoadWallet)
      bool LoadKey(const CKey& key) { return CCryptoKeyStore::AddKey(key); }

      bool LoadMinVersion(int nVersion) { nWalletVersion = nVersion; nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion); return true; }

      // Adds an encrypted key to the store, and saves it to disk.
      bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
      // Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
      bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret) { SetMinVersion(FEATURE_WALLETCRYPT); return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret); }
      bool AddCScript(const CScript& redeemScript);
      bool LoadCScript(const CScript& redeemScript) { return CCryptoKeyStore::AddCScript(redeemScript); }

      bool Unlock(const SecureString& strWalletPassphrase);
      bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
      bool EncryptWallet(const SecureString& strWalletPassphrase);

      void MarkDirty();
      bool AddToWallet(const CWalletTx& wtxIn);
      bool AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate = false, bool fFindBlock = false);
    bool EraseFromWallet(uint256 hash);
    void WalletUpdateSpent(const CTransaction& prevout);
  //  int ScanForWalletTransaction(const uint256& hashTx);
    int ScanForWalletTransaction(const uint256& hashTx);
    int64 GetBalance() const;
    int64 GetUnconfirmedBalance() const;
    int64 GetImmatureBalance() const;
    std::string SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, bool fAskFee=false);
    std::string SendMoneyToDestination(const CTxDestination &address, int64 nValue, CWalletTx& wtxNew, bool fAskFee=false);

    string SendMoney(string strFromAccount, CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, bool fAskFee = false);
    string SendMoney(string stringFromAccount, const CTxDestination &address, int64 nValue, CWalletTx& wtxNew, bool fAskFee=false);


    bool NewKeyPool();
    bool TopUpKeyPool();
    int64 AddReserveKey(const CKeyPool& keypool);
    void ReserveKeyFromKeyPool(int64& nIndex, CKeyPool& keypool);
    void KeepKey(int64 nIndex);
    void ReturnKey(int64 nIndex);
    bool GetKeyFromPool(CPubKey &key, bool fAllowReuse=true);
    int64 GetOldestKeyPoolTime();
    void GetAllReserveKeys(std::set<CKeyID>& setAddress);

    bool IsMine(const CTxIn& txin) const;
    int64 GetDebit(const CTxIn& txin) const;
    bool IsMine(const CTxOut& txout) const
    {
        return ::IsMine(*this, txout.scriptPubKey);
    }
    int64 GetCredit(const CTxOut& txout) const
    {
        if (!MoneyRange(ifaceIndex, txout.nValue))
            throw std::runtime_error("CWallet::GetCredit() : value out of range");
        return (IsMine(txout) ? txout.nValue : 0);
    }
    bool IsChange(const CTxOut& txout) const;
    int64 GetChange(const CTxOut& txout) const
    {
#if 0
        if (!MoneyRange(txout.nValue))
            throw std::runtime_error("CWallet::GetChange() : value out of range");
#endif
        return (IsChange(txout) ? txout.nValue : 0);
    }
    bool IsMine(const CTransaction& tx) const
    {
      CIface *iface = GetCoinByIndex(ifaceIndex);
      int64 nMinimumInputValue = MIN_INPUT_VALUE(iface);
      BOOST_FOREACH(const CTxOut& txout, tx.vout) {
        // If output is less than minimum value, then don't include transaction.
        // This is to help deal with dust spam bloating the wallet.
        if (IsMine(txout) && txout.nValue >= nMinimumInputValue)
          return true;
      }
      return false;
    }
    bool IsFromMe(const CTransaction& tx) const
    {
        return (GetDebit(tx) > 0);
    }
    int64 GetDebit(const CTransaction& tx) const
    {
        int64 nDebit = 0;
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            nDebit += GetDebit(txin);
            if (!MoneyRange(ifaceIndex, nDebit))
                throw std::runtime_error("CWallet::GetDebit() : value out of range");
        }
        return nDebit;
    }
    int64 GetCredit(const CTransaction& tx) const
    {
        int64 nCredit = 0;
        BOOST_FOREACH(const CTxOut& txout, tx.vout)
        {
            nCredit += GetCredit(txout);
            if (!MoneyRange(ifaceIndex, nCredit))
                throw std::runtime_error("CWallet::GetCredit() : value out of range");
        }
        return nCredit;
    }
    int64 GetChange(const CTransaction& tx) const
    {
        int64 nChange = 0;
        BOOST_FOREACH(const CTxOut& txout, tx.vout)
        {
            nChange += GetChange(txout);
            if (!MoneyRange(ifaceIndex, nChange))
                throw std::runtime_error("CWallet::GetChange() : value out of range");
        }
        return nChange;
    }
    void SetBestChain(const CBlockLocator& loc);

    int LoadWallet(bool& fFirstRunRet);

    bool SetAddressBookName(const CTxDestination& address, const std::string& strName);

    bool DelAddressBookName(const CTxDestination& address);

    void UpdatedTransaction(const uint256 &hashTx);

    void PrintWallet(const CBlock& block);

    void Inventory(const uint256 &hash)
    {
        {
            LOCK(cs_wallet);
            std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
            if (mi != mapRequestCount.end())
                (*mi).second++;
        }
    }

    int GetKeyPoolSize()
    {
        return setKeyPool.size();
    }

    bool AllowFree(double dPriority)
    {
      return (dPriority > AllowFreeThreshold());
    }

    bool GetTransaction(const uint256 &hashTx, CWalletTx& wtx);

    bool SetDefaultKey(const CPubKey &vchPubKey);

    // signify that a particular wallet feature is now used. this may change nWalletVersion and nWalletMaxVersion if those are lower
    bool SetMinVersion(enum WalletFeature, CWalletDB* pwalletdbIn = NULL, bool fExplicit = false);

    // change which version we're allowed to upgrade to (note that this does not immediately imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    // get the current wallet format (the oldest client version guaranteed to understand this wallet)
    int GetVersion() { return nWalletVersion; }

    bool GetMergedAddress(string strAccount, const char *tag, CCoinAddr& addrRet);
    bool GetMergedPubKey(string strAccount, const char *tag, CPubKey& pubkey);


    bool GetWitnessAddress(CCoinAddr& addr, CCoinAddr& witAddr);

    int64 CalculateFee(CTransaction& tx, int64 nMinFee = 0);

    bool FillInputs(const CTransaction& tx, tx_cache& inputs, bool fAllowSpent = true);

    double GetPriority(const CTransaction& tx, MapPrevTx& mapInputs);

    double GetPriority(const CTransaction& tx, tx_cache& inputs);


    virtual void RelayWalletTransaction(CWalletTx& wtx) = 0;
    virtual int64 GetTxFee(CTransaction tx) = 0;
    virtual int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false) = 0;
    virtual void ReacceptWalletTransactions() = 0;
    virtual bool CreateTransaction(const std::vector<std::pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet) = 0;
    virtual bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet) = 0;

    virtual bool CreateAccountTransaction(string strFromAccount, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, string& strError, int64& nFeeRet) = 0;
    virtual bool CreateAccountTransaction(string strFromAccount, CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, string& strError, int64& nFeeRet) = 0;

    virtual bool CommitTransaction(CWalletTx& wtxNew) = 0;
    virtual void AddSupportingTransactions(CWalletTx& wtx) = 0;
    virtual void ResendWalletTransactions() = 0;
    virtual bool UnacceptWalletTransaction(const CTransaction& tx) = 0;
    virtual int64 GetBlockValue(int nHeight, int64 nFees) = 0;

    /* the serialized size of the transaction. */
    virtual unsigned int GetTransactionWeight(const CTransaction& tx) = 0;  

    virtual unsigned int GetVirtualTransactionSize(int64 nWeight, int64 nSigOpCost = 0) = 0;

    virtual unsigned int GetVirtualTransactionSize(const CTransaction& tx) = 0;

    virtual double AllowFreeThreshold() = 0;


    /* 1k data cost */
    virtual int64 GetFeeRate() = 0;

#if 0
    /** Address book entry changed.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const CTxDestination &address, const std::string &label, bool isMine, ChangeType status)> NotifyAddressBookChanged;
    /** Wallet transaction added, removed or updated.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const uint256 &hashTx, ChangeType status)> NotifyTransactionChanged;
#endif
};

/** A key allocated from the key pool. */
class CReserveKey
{
protected:
    CWallet* pwallet;
    int64 nIndex;
    CPubKey vchPubKey;
public:
    CReserveKey(CWallet* pwalletIn)
    {
        nIndex = -1;
        pwallet = pwalletIn;
    }

    ~CReserveKey()
    {
        if (!fShutdown)
            ReturnKey();
    }

    void ReturnKey();
    CPubKey GetReservedKey();
    void KeepKey();
};


/** A transaction with a bunch of additional info that only the owner cares about. 
 * It includes any unrecorded transactions needed to link it back to the block chain.
 */
class CWalletTx : public CMerkleTx
{
protected:
    CWallet *pwallet;

public:
    std::vector<CMerkleTx> vtxPrev;
    std::map<std::string, std::string> mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived;  // time received by this node
    char fFromMe;
    std::string strFromAccount;
    std::vector<char> vfSpent; // which outputs are already spent

    // memory only
    mutable bool fDebitCached;
    mutable bool fCreditCached;
    mutable bool fAvailableCreditCached;
    mutable bool fChangeCached;
    mutable int64 nDebitCached;
    mutable int64 nCreditCached;
    mutable int64 nAvailableCreditCached;
    mutable int64 nChangeCached;

    CWalletTx()
    {
        Init(NULL);
    }

    CWalletTx(CWallet* pwalletIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(CWallet* pwalletIn, const CMerkleTx& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(CWallet *pwalletIn, const CTransaction& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    void Init(CWallet *pwalletIn)
    {
        pwallet = pwalletIn;
        vtxPrev.clear();
        mapValue.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        fFromMe = false;
        strFromAccount.clear();
        vfSpent.clear();
        fDebitCached = false;
        fCreditCached = false;
        fAvailableCreditCached = false;
        fChangeCached = false;
        nDebitCached = 0;
        nCreditCached = 0;
        nAvailableCreditCached = 0;
        nChangeCached = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        CWalletTx* pthis = const_cast<CWalletTx*>(this);
        if (fRead)
            pthis->Init(NULL);
        char fSpent = false;

        if (!fRead)
        {
            pthis->mapValue["fromaccount"] = pthis->strFromAccount;

            std::string str;
            BOOST_FOREACH(char f, vfSpent)
            {
                str += (f ? '1' : '0');
                if (f)
                    fSpent = true;
            }
            pthis->mapValue["spent"] = str;
        }

        nSerSize += SerReadWrite(s, *(CMerkleTx*)this, nType, nVersion,ser_action);
        READWRITE(vtxPrev);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);

        if (fRead)
        {
            pthis->strFromAccount = pthis->mapValue["fromaccount"];

            if (mapValue.count("spent"))
                BOOST_FOREACH(char c, pthis->mapValue["spent"])
                    pthis->vfSpent.push_back(c != '0');
            else
                pthis->vfSpent.assign(vout.size(), fSpent);
        }

        pthis->mapValue.erase("fromaccount");
        pthis->mapValue.erase("version");
        pthis->mapValue.erase("spent");
    )

    // marks certain txout's as spent
    // returns true if any update took place
    bool UpdateSpent(const std::vector<char>& vfNewSpent)
    {
        bool fReturn = false;
        for (unsigned int i = 0; i < vfNewSpent.size(); i++)
        {
            if (i == vfSpent.size())
                break;

            if (vfNewSpent[i] && !vfSpent[i])
            {
                vfSpent[i] = true;
                fReturn = true;
                fAvailableCreditCached = false;
            }
        }
        return fReturn;
    }

    // make sure balances are recalculated
    void MarkDirty()
    {
        fCreditCached = false;
        fAvailableCreditCached = false;
        fDebitCached = false;
        fChangeCached = false;
    }

    void BindWallet(CWallet *pwalletIn)
    {
        pwallet = pwalletIn;
        MarkDirty();
    }

    void MarkSpent(unsigned int nOut)
    {
        if (nOut >= vout.size())
            throw std::runtime_error("CWalletTx::MarkSpent() : nOut out of range");
        vfSpent.resize(vout.size());
        if (!vfSpent[nOut])
        {
            vfSpent[nOut] = true;
            fAvailableCreditCached = false;
        }
    }

/* DEBUG: todo:   retrieve from coin-db instead? */
    bool IsSpent(unsigned int nOut) const
    {
        if (nOut >= vout.size())
            throw std::runtime_error("CWalletTx::IsSpent() : nOut out of range");
        if (nOut >= vfSpent.size())
            return false;
        return (!!vfSpent[nOut]);
    }

    int64 GetDebit() const
    {
        if (vin.empty())
            return 0;
        if (fDebitCached)
            return nDebitCached;
        nDebitCached = pwallet->GetDebit(*this);
        fDebitCached = true;
        return nDebitCached;
    }

    int64 GetCredit(bool fUseCache=true) const
    {
        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity(pwallet->ifaceIndex) > 0)
            return 0;

        // GetBalance can assume transactions in mapWallet won't change
        if (fUseCache && fCreditCached)
            return nCreditCached;
        nCreditCached = pwallet->GetCredit(*this);
        fCreditCached = true;
        return nCreditCached;
    }

    int64 GetAvailableCredit(bool fUseCache=true) const
    {
        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity(pwallet->ifaceIndex) > 0) {
            return 0;
}

        if (fUseCache && fAvailableCreditCached) {
            return nAvailableCreditCached;
        }

        int64 nCredit = 0;
        for (unsigned int i = 0; i < vout.size(); i++)
        {
            if (!IsSpent(i))
            {
                const CTxOut &txout = vout[i];
                nCredit += pwallet->GetCredit(txout);
                if (!MoneyRange(pwallet->ifaceIndex, nCredit))
                    throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
            }
        }

        nAvailableCreditCached = nCredit;
        fAvailableCreditCached = true;
        return nCredit;
    }


    int64 GetChange() const
    {
        if (fChangeCached)
            return nChangeCached;
        nChangeCached = pwallet->GetChange(*this);
        fChangeCached = true;
        return nChangeCached;
    }

    void GetAmounts(int ifaceIndex, int64& nGeneratedImmature, int64& nGeneratedMature) const;

    void GetAmounts(list<pair<CTxDestination, int64> >& listReceived, list<pair<CTxDestination, int64> >& listSent, int64& nFee, string& strSentAccount) const;

    void GetAccountAmounts(const std::string& strAccount, int64& nReceived, int64& nSent, int64& nFee) const;


    bool IsFromMe() const
    {
        return (GetDebit() > 0);
    }

    bool IsConfirmed() const
    {
        // Quick answer in most cases
        if (!IsFinal(pwallet->ifaceIndex))
            return false;
        if (GetDepthInMainChain(pwallet->ifaceIndex) >= 1)
            return true;
        if (!IsFromMe()) // using wtx's cached debit
            return false;

        // If no confirmations but it's from us, we can still
        // consider it confirmed if all dependencies are confirmed
        std::map<uint256, const CMerkleTx*> mapPrev;
        std::vector<const CMerkleTx*> vWorkQueue;
        vWorkQueue.reserve(vtxPrev.size()+1);
        vWorkQueue.push_back(this);
        for (unsigned int i = 0; i < vWorkQueue.size(); i++)
        {
            const CMerkleTx* ptx = vWorkQueue[i];

            if (!ptx->IsFinal(pwallet->ifaceIndex))
                return false;
            if (ptx->GetDepthInMainChain(pwallet->ifaceIndex) >= 1)
                continue;
            if (!pwallet->IsFromMe(*ptx))
                return false;

            if (mapPrev.empty())
            {
                BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
                    mapPrev[tx.GetHash()] = &tx;
            }

            BOOST_FOREACH(const CTxIn& txin, ptx->vin)
            {
                if (!mapPrev.count(txin.prevout.hash))
                    return false;
                vWorkQueue.push_back(mapPrev[txin.prevout.hash]);
            }
        }
        return true;
    }

    bool WriteToDisk();

    int64 GetTxTime() const;
    int GetRequestCount() const;

    void AddSupportingTransactions();

#ifdef USE_LEVELDB_COINDB
    bool AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs=true);
//    void RelayWalletTransaction(CTxDB& txdb);
#else
    bool AcceptWalletTransaction();
#endif

};




class COutput
{
public:
    const CWalletTx *tx;
    int i;
    int nDepth;

    COutput(const CWalletTx *txIn, int iIn, int nDepthIn)
    {
        tx = txIn; i = iIn; nDepth = nDepthIn;
    }

    std::string ToString() const
    {
        return strprintf("COutput(%s, %d, %d) [%s]", tx->GetHash().ToString().substr(0,10).c_str(), i, nDepth, FormatMoney(tx->vout[i].nValue).c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




/** Private key that includes an expiration date in case it never gets used. */
class CWalletKey
{
public:
    CPrivKey vchPrivKey;
    int64 nTimeCreated;
    int64 nTimeExpires;
    std::string strComment;
    //// todo: add something to note what created it (user, getnewaddress, change)
    ////   maybe should have a map<string, string> property map

    CWalletKey(int64 nExpires=0)
    {
        nTimeCreated = (nExpires ? GetTime() : 0);
        nTimeExpires = nExpires;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPrivKey);
        READWRITE(nTimeCreated);
        READWRITE(nTimeExpires);
        READWRITE(strComment);
    )
};






/** Account information.
 * Stored in wallet with key "acc"+string account name.
 */
class CAccount
{
public:
    CPubKey vchPubKey;

    CAccount()
    {
        SetNull();
    }

    void SetNull()
    {
        vchPubKey = CPubKey();
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPubKey);
    )
};



/** Internal transfers.
 * Database key is acentry<account><counter>.
 */
class CAccountingEntry
{
public:
    std::string strAccount;
    int64 nCreditDebit;
    int64 nTime;
    std::string strOtherAccount;
    std::string strComment;

    CAccountingEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        nCreditDebit = 0;
        nTime = 0;
        strAccount.clear();
        strOtherAccount.clear();
        strComment.clear();
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        // Note: strAccount is serialized as part of the key, not here.
        READWRITE(nCreditDebit);
        READWRITE(nTime);
        READWRITE(strOtherAccount);
        READWRITE(strComment);
    )
};





bool GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);

CWallet *GetWallet(int iface_idx);

CWallet *GetWallet(CIface *iface);

void SetWallet(int iface_idx, CWallet *wallet);

void SetWallet(CIface *iface, CWallet *wallet);

bool LoadBlockIndex(CIface *iface);

/**
 * The output index that contains an extended transaction operation.
 */
int IndexOfExtOutput(const CTransaction& tx);


CPubKey GetAccountPubKey(CWallet *wallet, string strAccount, bool bForceNew=false);

CCoinAddr GetAccountAddress(CWallet *wallet, string strAccount, bool bForceNew=false);

/** 
 * Send coins with the inclusion of a specific input transaction.
 */
bool SendMoneyWithExtTx(CIface *iface, CWalletTx& wtxIn, CWalletTx& wtxNew, const CScript& scriptPubKey, vector<pair<CScript, int64> > vecSend, int64 txFee = 0);

bool GetCoinAddr(CWallet *wallet, CCoinAddr& addrAccount, string& strAccount);

bool GetCoinAddr(CWallet *wallet, string strAddress, CCoinAddr& addrAccount);

bool CreateTransactionWithInputTx(CIface *iface, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxIn, int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64 nTxFee = 0);

bool VerifyMatrixTx(CTransaction& tx, int& mode);

void RelayTransaction(int ifaceIndex, const CTransaction& tx, const uint256& hash);

 

#ifdef __cplusplus

extern const string NULL_ACCOUNT;

int64 GetTxFee(int ifaceIndex, CTransaction tx);

int64 GetAccountBalance(int ifaceIndex, CWalletDB& walletdb, const std::string& strAccount, int nMinDepth);

int64 GetAccountBalance(int ifaceIndex, const std::string& strAccount, int nMinDepth);

bool SyncWithWallets(CIface *iface, CTransaction& tx, CBlock *pblock = NULL);

bool SendRemitMoneyTx(CIface *iface, const CCoinAddr& addrFrom, CWalletTx *wtxIn, CWalletTx& wtxNew, vector<pair<CScript, int64> >& vecSend, CScript scriptPubKey);

bool CreateMoneyTx(CIface *iface, CWalletTx& wtxNew, vector<COutput>& vecRecv, vector<CTxOut>& vecSend, CScript scriptPubKey);

bool core_UnacceptWalletTransaction(CIface *iface, const CTransaction& tx);

bool core_CreateWalletAccountTransaction(CWallet *wallet, string strFromAccount, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, string& strError, int64& nFeeRet);

CScript GetScriptForWitness(const CScript& redeemscript);

int64 core_GetFeeRate(int ifaceIndex);

bool SelectCoins_Avg(int64 nTargetValue, vector<COutput>& vCoins, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet);

#endif



#endif /* ndef __SERVER__WALLET_H__ */
