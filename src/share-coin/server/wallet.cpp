
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

#include "shcoind.h"
#include "wallet.h"
#include "walletdb.h"
#include "crypter.h"
#include "ui_interface.h"
#include "base58.h"
#include "chain.h"
#include "txsignature.h"
#include "txmempool.h"
#include "txfeerate.h"

using namespace std;

CWallet* pwalletMaster[MAX_COIN_IFACE];

const string NULL_ACCOUNT = "*";


CWallet *GetWallet(int iface_idx)
{
#ifndef TEST_SHCOIND
  if (iface_idx == 0)
    return (NULL);
#endif

  if (iface_idx < 0 || iface_idx >= MAX_COIN_IFACE)
    return (NULL);

  return (pwalletMaster[iface_idx]); 
}

CWallet *GetWallet(CIface *iface)
{
  return (GetWallet(GetCoinIndex(iface)));
}

void SetWallet(int iface_idx, CWallet *wallet)
{
#ifndef TEST_SHCOIND
  if (iface_idx == 0)
    return;
#endif

  if (iface_idx < 0 || iface_idx >= MAX_COIN_IFACE)
    return;

  pwalletMaster[iface_idx] = wallet;
}

void SetWallet(CIface *iface, CWallet *wallet)
{
  return (SetWallet(GetCoinIndex(iface), wallet));
}





struct CompareValueOnly
{
    bool operator()(const pair<int64, pair<const CWalletTx*, unsigned int> >& t1,
                    const pair<int64, pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

CPubKey CWallet::GenerateNewKey(bool fCompressed)
{
//    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

//    RandAddSeedPerfmon();
    CKey key;
    key.MakeNewKey(fCompressed);

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    if (!AddKey(key))
        throw std::runtime_error("CWallet::GenerateNewKey() : AddKey failed");

    return key.GetPubKey();
}

bool CWallet::AddKey(const CKey& key)
{

  if (!CCryptoKeyStore::AddKey(key))
    return (error(SHERR_INVAL, "CWallet.AddKey: error adding key to crypto key-store."));
  if (!fFileBacked)
    return true;
  if (!IsCrypted()) {
    bool ret = CWalletDB(strWalletFile).WriteKey(key.GetPubKey(), key.GetPrivKey());
    if (!ret)
      return (error(SHERR_INVAL, "CWallet.AddKey: error writing key to wallet."));
  }

  return true;
}

HDPubKey CWallet::GenerateNewHDKey(bool fCompressed)
{
//  bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

  RandAddSeedPerfmon();
  HDMasterPrivKey key;
  key.MakeNewKey(fCompressed);

  // Compressed public keys were introduced in version 0.6.0
  if (fCompressed)
    SetMinVersion(FEATURE_COMPRPUBKEY);

  if (!AddKey(key))
    throw std::runtime_error("CWallet::GenerateNewKey() : AddKey failed");
  return key.GetMasterPubKey();
}

bool CWallet::AddKey(const HDPrivKey& key)
{
  if (!CCryptoKeyStore::AddKey(key))
    return false;
  if (!fFileBacked)
    return true;
  if (!IsCrypted())
    return CWalletDB(strWalletFile).WriteKey(key.GetPubKey(), key.GetPrivKey());
  return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret);
    }
    return false;
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    if (!IsLocked())
        return false;

    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
            {
                int64 nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                Debug("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

// This class implements an addrIncoming entry that causes pre-0.4
// clients to crash on startup if reading a private-key-encrypted wallet.
class CCorruptAddress
{
public:
    IMPLEMENT_SERIALIZE
    (
        if (nType & SER_DISK)
            READWRITE(nVersion);
    )
};

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion >= 40000)
        {
            // Versions prior to 0.4.0 did not support the "minversion" record.
            // Use a CCorruptAddress to make them crash instead.
            CCorruptAddress corruptAddress;
            pwalletdb->WriteSetting("addrIncoming", corruptAddress);
        }
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    RandAddSeedPerfmon();
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    RAND_bytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64 nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    Debug("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin())
                return false;
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked)
                pwalletdbEncryption->TxnAbort();
            exit(1); //We now probably have half of our keys encrypted in memory, and half not...die and let the user reload their unencrypted wallet.
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit())
                exit(1); //We now have keys encrypted in memory, but no on disk...die to avoid confusion and let the user reload their unencrypted wallet.

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);
        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);

    }
    //NotifyStatusChanged(this);

    return true;
}

/**
 * Anytime a signature is successfully verified, it's proof the outpoint is spent.
 * Update the wallet spent flag if it doesn't know due to wallet.dat being
 * restored from backup or the user making copies of wallet.dat.
 */
void CWallet::WalletUpdateSpent(const CTransaction &tx)
{
  {
    LOCK(cs_wallet);
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
      map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
      if (mi != mapWallet.end())
      {
        CWalletTx& wtx = (*mi).second;
        if (txin.prevout.n >= wtx.vout.size()) {
          /* mis-match */
          error(SHERR_INVAL, "WalletUpdateSpent: tx '%s' has prevout-n >= vout-size.", wtx.GetHash().GetHex().c_str());
          continue;
        }

        if (!wtx.IsSpent(txin.prevout.n) && IsMine(wtx.vout[txin.prevout.n]))
        {
//          Debug("WalletUpdateSpent found spent coin %sbc %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
          wtx.MarkSpent(txin.prevout.n);
          wtx.WriteToDisk();
          //NotifyTransactionChanged(this, txin.prevout.hash, CT_UPDATED);
        }
      }
    }
  }
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
            wtx.nTimeReceived = GetAdjustedTime();

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            fUpdated |= wtx.UpdateSpent(wtxIn.vfSpent);
        }

        Debug("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString().substr(0,10).c_str(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated) {
            if (!wtx.WriteToDisk())
                return false;
        }
#ifndef QT_GUI
        // If default receiving address gets used, replace it with a new one
        CScript scriptDefaultKey;
        scriptDefaultKey.SetDestination(vchDefaultKey.GetID());
        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            if (txout.scriptPubKey == scriptDefaultKey)
            {
                CPubKey newDefaultKey;
                if (GetKeyFromPool(newDefaultKey, false))
                {
                    SetDefaultKey(newDefaultKey);
                    SetAddressBookName(vchDefaultKey.GetID(), "");
                }
            }
        }
#endif
        // since AddToWallet is called directly for self-originating transactions, check for consumption of own coins
        WalletUpdateSpent(wtx);

        // Notify UI of new or updated transaction
        //NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);
    }
    return true;
}

// Add a transaction to the wallet, or update it.
// pblock is optional, but should be provided if the transaction is known to be in a block.
// If fUpdate is true, existing transactions will be updated.
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fFindBlock)
{
  uint256 hash = tx.GetHash();
  {
    LOCK(cs_wallet);
    bool fExisted = mapWallet.count(hash);
    if (fExisted && !fUpdate) return false;
    if (fExisted || IsFromMe(tx) || IsMine(tx)) {
      CWalletTx wtx(this,tx);
      // Get merkle branch if transaction was found in a block
      if (pblock) {
        wtx.SetMerkleBranch(pblock);
      }
      return AddToWallet(wtx);
    }
    else {
      WalletUpdateSpent(tx);
    }
  }
  return false;
}

bool CWallet::EraseFromWallet(uint256 hash)
{
    if (!fFileBacked)
        return false;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return true;
}


bool CWallet::IsMine(const CTxIn &txin) const
{
  {
    LOCK(cs_wallet);
    map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
    if (mi != mapWallet.end())
    {
      const CWalletTx& prev = (*mi).second;
      if (txin.prevout.n < prev.vout.size())
        if (IsMine(prev.vout[txin.prevout.n]))
          return true;
    }
  }
  return false;
}

int64 CWallet::GetDebit(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return prev.vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    CTxDestination address;

    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a TX_PUBKEYHASH that is mine but isn't in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (ExtractDestination(txout.scriptPubKey, address) && ::IsMine(*this, address))
    {
        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

int64 CWalletTx::GetTxTime() const
{
    return nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
  // Returns -1 if it wasn't being tracked
  int nRequests = -1;
  {
    LOCK(pwallet->cs_wallet);
    if (IsCoinBase())
    {
      // Generated block
      if (hashBlock != 0)
      {
        map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
        if (mi != pwallet->mapRequestCount.end())
          nRequests = (*mi).second;
      }
    }
    else
    {
      // Did anyone request this transaction?
      map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
      if (mi != pwallet->mapRequestCount.end())
      {
        nRequests = (*mi).second;

        // How about the block it's in?
        if (nRequests == 0 && hashBlock != 0)
        {
          map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
          if (mi != pwallet->mapRequestCount.end())
            nRequests = (*mi).second;
          else
            nRequests = 1; // If it's in someone else's block it must have got out
        }
      }
    }
  }
  return nRequests;
}

void CWalletTx::GetAmounts(list<pair<CTxDestination, int64> >& listReceived, list<pair<CTxDestination, int64> >& listSent, int64& nFee, string& strSentAccount) const
{
  int ifaceIndex = pwallet->ifaceIndex;
  CIface *iface = GetCoinByIndex(ifaceIndex);
//  int64 minValue = (int64)MIN_INPUT_VALUE(iface);

  nFee = 0;
  listReceived.clear();
  listSent.clear();
  strSentAccount = strFromAccount;

  int64 nDebit = 0;
  if (!IsCoinBase()) {
    nDebit = GetDebit();

    // Compute fee:
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
      int64 nValueOut = 0;
      BOOST_FOREACH(const CTxOut& txout, vout) {
        nValueOut += txout.nValue;
      }

      nFee = MAX(0.0, nDebit - nValueOut);
    }
  }

  // Sent/received.
  int idx = -1;
  BOOST_FOREACH(const CTxOut& txout, vout)
  {
    int64 nValue = txout.nValue;

    idx++;
    if (nValue < 0) {
      Debug("GetAmounts: invalid transaction '%s' coin value for output (#%d) [coin value (%f)].", GetHash().GetHex().c_str(), idx, ((double)nValue / (double)COIN));
      continue;
    }

#if 0
if (nValue == 0.00000000) {
CTransaction *t_tx = (CTransaction *)this;
fprintf(stderr, "DEBUG: GetAmounts: warning: %s\n", t_tx->ToString(ifaceIndex).c_str());
}
#endif

    CTxDestination address;
    if (!ExtractDestination(txout.scriptPubKey, address)) {
      error(SHERR_INVAL,
          "CWalletTx::GetAmounts: Unknown transaction type found, txid %s: %s\n",
          this->GetHash().ToString().c_str(), txout.scriptPubKey.ToString().c_str());
    }

    if (nDebit > 0 && pwallet->IsChange(txout)) /* skip change */
      continue;

    if (nDebit > 0)
      listSent.push_back(make_pair(address, nValue));

    if (pwallet->IsMine(txout))
      listReceived.push_back(make_pair(address, nValue));
  }

}

#if 0
void CWalletTx::GetAmounts(int64& nGeneratedImmature, int64& nGeneratedMature, list<pair<CTxDestination, int64> >& listReceived, list<pair<CTxDestination, int64> >& listSent, int64& nFee, string& strSentAccount) const
{
  int ifaceIndex = pwallet->ifaceIndex;

  nGeneratedImmature = nGeneratedMature = nFee = 0;
  listReceived.clear();
  listSent.clear();
  strSentAccount = strFromAccount;

  if (IsCoinBase())
  {
    if (GetBlocksToMaturity(ifaceIndex) > 0) {
      nGeneratedImmature = pwallet->GetCredit(*this);
    } else {
      int64 nFee = 0;
      if (vout.size() > 1) { /* non-standard */
        for (int idx = 1; idx < vout.size(); idx++) {
          const CTxOut& txout = vout[idx];
          if (pwallet->IsMine(txout)) {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address)) {
              nFee += txout.nValue;
              listReceived.push_back(make_pair(address, txout.nValue));
            }
          }
        }
      }
      nGeneratedMature = GetCredit() - nFee;
    }
    return;
  }

  // Compute fee:
  int64 nDebit = GetDebit();
  if (nDebit > 0) // debit>0 means we signed/sent this transaction
  {
    int64 nValueOut = GetValueOut();
    nFee = nDebit - nValueOut;
  }

  // Sent/received.
  BOOST_FOREACH(const CTxOut& txout, vout)
  {
    CTxDestination address;
    vector<unsigned char> vchPubKey;
    if (!ExtractDestination(txout.scriptPubKey, address))
    {
      error(SHERR_INVAL,
          "CWalletTx::GetAmounts: Unknown transaction type found, txid %s: %s\n",
          this->GetHash().ToString().c_str(), txout.scriptPubKey.ToString().c_str());
    }

    // Don't report 'change' txouts
    if (nDebit > 0 && pwallet->IsChange(txout))
      continue;

    if (nDebit > 0)
      listSent.push_back(make_pair(address, txout.nValue));

    if (pwallet->IsMine(txout))
      listReceived.push_back(make_pair(address, txout.nValue));
  }

}
#endif
void CWalletTx::GetAmounts(int ifaceIndex, int64& nGeneratedImmature, int64& nGeneratedMature) const
{

  nGeneratedImmature = nGeneratedMature = 0;

  if (!IsCoinBase())
    return;

  if (GetBlocksToMaturity(ifaceIndex) > 0) {
    nGeneratedImmature = pwallet->GetCredit(*this);
  } else {
    /* base reward */
    nGeneratedMature = GetCredit();

    if (ifaceIndex == TEST_COIN_IFACE ||
        ifaceIndex == SHC_COIN_IFACE) {
      if (vout.size() > 1) {
        int64 nFee = 0;
        /* do not count >0 coinbase outputs as part of miner 'reward' */
        for (int idx = 1; idx < vout.size(); idx++) {
          const CTxOut& txout = vout[idx];
          if (pwallet->IsMine(txout)) {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address)) {
              nFee += txout.nValue;
              //listReceived.push_back(make_pair(address, txout.nValue));
            }
          }
        }
        nGeneratedMature -= nFee;
      }
    } else if (ifaceIndex == EMC2_COIN_IFACE) {
      if (vout.size() > 0) {
        /* subtract donation output */
        nGeneratedMature -= vout[0].nValue;
      }
    }
  }

}

void CWalletTx::GetAccountAmounts(const string& strAccount, int64& nReceived, int64& nSent, int64& nFee) const
{
  //nGenerated = nReceived = nSent = nFee = 0;
  nReceived = nSent = nFee = 0;

  int64 allFee;
  allFee = 0;
  string strSentAccount;
  list<pair<CTxDestination, int64> > listReceived;
  list<pair<CTxDestination, int64> > listSent;
  GetAmounts(listReceived, listSent, allFee, strSentAccount);

#if 0
  if (strAccount == "")
    nGenerated = allGeneratedMature;
#endif

  if (strAccount == strSentAccount)
  {
    BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& s, listSent)
      nSent += s.second;
    nFee = allFee;
  }
  {
    LOCK(pwallet->cs_wallet);
    BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listReceived)
    {
      if (pwallet->mapAddressBook.count(r.first))
      {
        map<CTxDestination, string>::const_iterator mi = pwallet->mapAddressBook.find(r.first);
        if (mi != pwallet->mapAddressBook.end() && (*mi).second == strAccount)
          nReceived += r.second;
      }
      else if (strAccount.empty())
      {
        nReceived += r.second;
      }
    }
  }
}

bool CWalletTx::WriteToDisk()
{
    return CWalletDB(pwallet->strWalletFile).WriteTx(GetHash(), *this);
}

#if 0
// Scan the block chain (starting in pindexStart) for transactions
// from or to us. If fUpdate is true, found transactions that already
// exist in the wallet will be updated.
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    int ret = 0;

    CBlockIndex* pindex = pindexStart;
    {
        LOCK(cs_wallet);
        while (pindex)
        {
            USDEBlock block;
            block.ReadFromDisk(pindex, true);
            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    ret++;
            }
            pindex = pindex->pnext;
        }
    }
    return ret;
}
#endif

int CWallet::ScanForWalletTransaction(const uint256& hashTx)
{
    CTransaction tx;

    if (!tx.ReadTx(ifaceIndex, hashTx)) {
      error(SHERR_INVAL, "ScanForWalletTransaction: unknown tx '%s'\n", hashTx.GetHex().c_str());
      return (0);
    }

//    tx.ReadFromDisk(COutPoint(hashTx, 0));
    if (AddToWalletIfInvolvingMe(tx, NULL, true, true))
        return 1;
    return 0;
}


#if 0
void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
  BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
  {
    if (!tx.IsCoinBase())
    {
      uint256 hash = tx.GetHash();
      if (!txdb.ContainsTx(hash))
        RelayMessage(CInv(txdb.ifaceIndex, MSG_TX, hash), (CTransaction)tx);
    }
  }
  if (!IsCoinBase())
  {
    uint256 hash = GetHash();
    if (!txdb.ContainsTx(hash))
    {
      //printf("Relaying wtx %s\n", hash.ToString().substr(0,10).c_str());
      RelayMessage(CInv(txdb.ifaceIndex, MSG_TX, hash), (CTransaction)*this);
    }
  }
}
#endif






//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


int64 CWallet::GetBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal(ifaceIndex)) {
              continue;
            }
            if (!pcoin->IsConfirmed()) {
              continue;
            }
            nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}

int64 CWallet::GetUnconfirmedBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal(ifaceIndex) || !pcoin->IsConfirmed())
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

int64 CWallet::GetImmatureBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& pcoin = (*it).second;
            if (pcoin.IsCoinBase() && pcoin.GetBlocksToMaturity(ifaceIndex) > 0 && pcoin.GetDepthInMainChain(ifaceIndex) >= 2)
                nTotal += GetCredit(pcoin);
        }
    }
    return nTotal;
}

// populate vCoins with vector of spendable COutputs
void CWallet::AvailableCoins(vector<COutput>& vCoins, bool fOnlyConfirmed) const
{
    vCoins.clear();

    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            if (!pcoin->IsFinal(ifaceIndex))
                continue;

            if (fOnlyConfirmed && !pcoin->IsConfirmed())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity(ifaceIndex) > 0)
                continue;

            // If output is less than minimum value, then don't include transaction.
            // This is to help deal with dust spam clogging up create transactions.
            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
              opcodetype opcode;
              const CScript& script = pcoin->vout[i].scriptPubKey;
              CScript::const_iterator pc = script.begin();
              if (script.GetOp(pc, opcode) &&
                  opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
                continue; /* not avail */
              }

              CIface *iface = GetCoinByIndex(ifaceIndex);
              int64 nMinimumInputValue = MIN_INPUT_VALUE(iface);
              if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) && pcoin->vout[i].nValue >= nMinimumInputValue)
                vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(ifaceIndex)));
            }
        }
    }
}

void CWallet::AvailableAccountCoins(string strAccount, vector<COutput>& vCoins, bool fOnlyConfirmed) const
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTxMemPool *pool = GetTxMemPool(iface);
  int64 nMinValue = MIN_INPUT_VALUE(iface);

  vCoins.clear();

  vector<CTxDestination> vDest;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, mapAddressBook) {
    const string& account = item.second;
    if (account != strAccount)
      continue;
//    const CCoinAddr& address = CCoinAddr(wallet->ifaceIndex, item.first);
    vDest.push_back(item.first);
  }

#if 0
  {
    std::set<CKeyID> keys;
    GetKeys(keys);
    BOOST_FOREACH(const CKeyID& key, keys) {
      if (mapAddressBook.count(key) == 0) { /* loner */
        vDest.push_back(key);
      }
    }
  }
#endif

  {
    LOCK(cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
      const CWalletTx* pcoin = &(*it).second;

      if (!pcoin->IsFinal(ifaceIndex))
        continue;

      if (fOnlyConfirmed && !pcoin->IsConfirmed())
        continue;

      if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity(ifaceIndex) > 0)
        continue;

      // If output is less than minimum value, then don't include transaction.
      // This is to help deal with dust spam clogging up create transactions.
      uint256 pcoinHash = pcoin->GetHash();
      for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
        opcodetype opcode;
        const CScript& script = pcoin->vout[i].scriptPubKey;
        CScript::const_iterator pc = script.begin();
        if (script.GetOp(pc, opcode) &&
            opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
          continue; /* not avail */
        }

        if (pcoin->vout[i].nValue < nMinValue)
          continue;

        /* check whether this output has already been used */
        if (pcoin->IsSpent(i))
          continue;

        /* check mempool for conflict */ 
        if (pool->IsInputTx(pcoinHash, i))
          continue;

        /* filter via account */
        CTxDestination dest;
        if (!ExtractDestination(pcoin->vout[i].scriptPubKey, dest))
          continue;

        if ( std::find(vDest.begin(), vDest.end(), dest) != vDest.end() ) {
          vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(ifaceIndex)));
        } else if (pcoin->strFromAccount == strAccount && 
            0 == mapAddressBook.count(dest)) {
          if (::IsMine(*this, dest)) {
//fprintf(stderr, "DEBUG: AvailableAccountCoins: found change for '%s'\n", pcoin->strFromAccount.c_str());
            vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(ifaceIndex)));
          }
        }

      }
    }
  }
}

static void ApproximateBestSubset(vector<pair<int64, pair<const CWalletTx*,unsigned int> > >vValue, int64 nTotalLower, int64 nTargetValue,
                                  vector<char>& vfBest, int64& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64 nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                if (nPass == 0 ? rand() % 2 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

bool CWallet::SelectCoinsMinConf(int64 nTargetValue, int nConfMine, int nConfTheirs, vector<COutput> vCoins, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const
{
  setCoinsRet.clear();
  nValueRet = 0;

  // List of values less than target
  pair<int64, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
  coinLowestLarger.first = std::numeric_limits<int64>::max();
  coinLowestLarger.second.first = NULL;
  vector<pair<int64, pair<const CWalletTx*,unsigned int> > > vValue;
  int64 nTotalLower = 0;

  random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

  BOOST_FOREACH(COutput output, vCoins)
  {
    const CWalletTx *pcoin = output.tx;

    if (output.nDepth < (pcoin->IsFromMe() ? nConfMine : nConfTheirs))
      continue;

    int i = output.i;
    int64 n = pcoin->vout[i].nValue;

    pair<int64,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

    if (n == nTargetValue)
    {
      setCoinsRet.insert(coin.second);
      nValueRet += coin.first;
      return true;
    }
    else if (n < nTargetValue + CENT)
    {
      vValue.push_back(coin);
      nTotalLower += n;
    }
    else if (n < coinLowestLarger.first)
    {
      coinLowestLarger = coin;
    }
  }

  if (nTotalLower == nTargetValue)
  {
    for (unsigned int i = 0; i < vValue.size(); ++i)
    {
      setCoinsRet.insert(vValue[i].second);
      nValueRet += vValue[i].first;
    }
    return true;
  }

  if (nTotalLower < nTargetValue)
  {
    if (coinLowestLarger.second.first == NULL)
      return false;
    setCoinsRet.insert(coinLowestLarger.second);
    nValueRet += coinLowestLarger.first;
    return true;
  }

  // Solve subset sum by stochastic approximation
  sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
  vector<char> vfBest;
  int64 nBest;

  ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
  if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
    ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

  // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
  //                                   or the next bigger coin is closer), return the bigger coin
  if (coinLowestLarger.second.first &&
      ((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger.first <= nBest))
  {
    setCoinsRet.insert(coinLowestLarger.second);
    nValueRet += coinLowestLarger.first;
  }
  else {
    for (unsigned int i = 0; i < vValue.size(); i++)
      if (vfBest[i])
      {
        setCoinsRet.insert(vValue[i].second);
        nValueRet += vValue[i].first;
      }

/*
    for (unsigned int i = 0; i < vValue.size(); i++)
      if (vfBest[i])
        fprintf(stderr, "DEBUG: select coins: %s ", FormatMoney(vValue[i].first).c_str());
    fprintf(stderr, "DEBUG: select coins: total %s\n", FormatMoney(nBest).c_str());
*/
  }

  return true;
}

bool CWallet::SelectCoins(int64 nTargetValue, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const
{
    vector<COutput> vCoins;
    AvailableCoins(vCoins);

    return (SelectCoinsMinConf(nTargetValue, 1, 6, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, 0, 1, vCoins, setCoinsRet, nValueRet));
}

bool SelectCoins_Avg(int64 nTargetValue, vector<COutput>& vCoins, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet)
{
  setCoinsRet.clear();
  nValueRet = 0;

#if 0
  // List of values less than target
  pair<int64, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
  coinLowestLarger.first = std::numeric_limits<int64>::max();
  coinLowestLarger.second.first = NULL;
#endif
  vector<pair<int64, pair<const CWalletTx*,unsigned int> > > vValue;
  int64 nTotalLower = 0;

  random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

  int low_cnt = 0;
  int64 low_tot = 0;
  int64 max_val = 0;
  int64 avg_val = nTargetValue;
  BOOST_FOREACH(COutput output, vCoins) {
    const CWalletTx *pcoin = output.tx;
    int i = output.i;
    int64 n = pcoin->vout[i].nValue;

    if (n == nTargetValue)
    {
      /* found an exact value */
      setCoinsRet.insert(make_pair(pcoin, i));
      nValueRet += n;
      return true;
    }

    if (n > nTargetValue) {
      if (max_val == 0)
        max_val = n;
      else
        max_val = MIN(max_val, n);
    } else {
      low_tot += n;
      low_cnt++;
    }
  }
  if (low_cnt)
    avg_val = (low_tot / low_cnt);
  avg_val = MIN(avg_val, nTargetValue / 4);

  int64 nTotalValue = 0;

  BOOST_FOREACH(COutput output, vCoins) {
    const CWalletTx *pcoin = output.tx;
    int i = output.i;
    int64 n = pcoin->vout[i].nValue;

    if (max_val != 0 && n > max_val) {
      continue; /* beyond what is needed */
    }

    if ((nTotalValue - CENT) > nTargetValue && n < avg_val) {
      continue; /* skip relative lower values */ 
    }

    nTotalValue += n;

    pair<int64,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));
    vValue.push_back(coin);
  }

  sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());

  nValueRet = 0;
  int idx;
  for (idx = 0; idx < vValue.size(); idx++) {
    int64 nCredit = vValue[idx].first;
//    pair<const CWalletTx*,unsigned int>& val = vValue[idx].second;
//    const CWalletTx *wtx = val.first;
//    int nOut = val.second;


    nTotalValue -= nCredit;
    if (nCredit > avg_val && 
        nTotalValue > (nTargetValue - nValueRet)) {
      continue; /* remainder will be sufficient */
    }

    setCoinsRet.insert(vValue[idx].second);
    nValueRet += nCredit;

    if (nValueRet >= nTargetValue)
      break;
  }

  /* insufficient funds */
  if (nValueRet < nTargetValue)
    return (false); 

  return true;
}

bool CWallet::SelectAccountCoins(string strAccount, int64 nTargetValue, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const
{
  vector<COutput> vCoins;
  AvailableAccountCoins(strAccount, vCoins);

  return (SelectCoins_Avg(nTargetValue, vCoins, setCoinsRet, nValueRet));  
#if 0
    return (SelectCoinsMinConf(nTargetValue, 1, 6, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, 0, 1, vCoins, setCoinsRet, nValueRet));
#endif
}



string CWallet::SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
    CReserveKey reservekey(this);
    int64 nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }
    if (!CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired))
    {
        string strError;
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds  "), FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }

    if (fAskFee)
        return "ABORTED";

    if (!CommitTransaction(wtxNew)) {
      return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    }

    return "";
}



string CWallet::SendMoneyToDestination(const CTxDestination& address, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    if (nValue + nTransactionFee > GetBalance())
        return _("Insufficient funds");

    // Parse Bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address);

    return SendMoney(scriptPubKey, nValue, wtxNew, fAskFee);
}


string CWallet::SendMoney(string strFromAccount, CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
    CReserveKey reservekey(this);
    int64 nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }

    string strError;
    int nMinDepth = 1;
    int64 nBalance = GetAccountBalance(ifaceIndex, strFromAccount, nMinDepth);

    if (!CreateAccountTransaction(strFromAccount, scriptPubKey, nValue, wtxNew, strError, nFeeRequired))
    {
        if (strError.length() == 0) {
          if (//nValue + nFeeRequired > GetBalance() ||
              nValue + nFeeRequired > nBalance) {
              strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds  "), FormatMoney(nFeeRequired).c_str());
          } else {
              strError = _("Error: Transaction creation failed  ");
          }
        }
        return strError;
    }

    if ((nValue + nFeeRequired) > nBalance) {
      string strError;
      strError = strprintf(_("Account \"%s\" has insufficient funds to initiate transaction [fee %f, balance %f]."), strFromAccount.c_str(), ((double)nFeeRequired/(double)COIN), ((double)nBalance/(double)COIN));
      return (strError);
    }

    if (fAskFee)
        return "ABORTED";

    if (!CommitTransaction(wtxNew)) {
      return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    }

    return "";
}



string CWallet::SendMoney(string strFromAccount, const CTxDestination& address, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    if (nValue + nTransactionFee > GetBalance())
        return _("Insufficient funds");

    // Parse Bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address);

    return SendMoney(strFromAccount, scriptPubKey, nValue, wtxNew, fAskFee);
}





int CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return false;
    fFirstRunRet = false;
    int nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // the requires a new key.
        }
        nLoadWalletRet = DB_NEED_REWRITE;
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    CreateThread(ThreadFlushWalletDB, &strWalletFile);
    return DB_LOAD_OK;
}


bool CWallet::SetAddressBookName(const CTxDestination& address, const string& strName)
{
    std::map<CTxDestination, std::string>::iterator mi = mapAddressBook.find(address);
    mapAddressBook[address] = strName;
    //NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address), (mi == mapAddressBook.end()) ? CT_NEW : CT_UPDATED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).WriteName(CCoinAddr(ifaceIndex, address).ToString(), strName);
}

bool CWallet::DelAddressBookName(const CTxDestination& address)
{
    mapAddressBook.erase(address);
    //NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address), CT_DELETED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).EraseName(CCoinAddr(ifaceIndex, address).ToString());
}


void CWallet::PrintWallet(const CBlock& block)
{
    {
        LOCK(cs_wallet);
        if (mapWallet.count(block.vtx[0].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
            printf("    mine:  %d  %d  %d", wtx.GetDepthInMainChain(ifaceIndex), wtx.GetBlocksToMaturity(ifaceIndex), wtx.GetCredit());
        }
    }
    printf("\n");
}

bool CWallet::GetTransaction(const uint256 &hashTx, CWalletTx& wtx)
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
        {
            wtx = (*mi).second;
            return true;
        }
    }
    return false;
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

bool GetWalletFile(CWallet* pwallet, string &strWalletFileOut)
{
    if (!pwallet->fFileBacked)
        return false;
    strWalletFileOut = pwallet->strWalletFile;
    return true;
}

//
// Mark old keypool keys as used,
// and generate all new keys
//
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64 nIndex, setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

        int64 nKeys = max(GetArg("-keypool", 100), (int64)0);
        for (int i = 0; i < nKeys; i++)
        {
            int64 nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        printf("CWallet::NewKeyPool wrote %"PRI64d" new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool()
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize = max(GetArg("-keypool", 100), 0LL);
        while (setKeyPool.size() < (nTargetSize + 1))
        {
            int64 nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool() : writing generated key failed");
            setKeyPool.insert(nEnd);
//            Debug("keypool added key %"PRI64d", size=%d\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool() : read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool() : unknown key in key pool");
        if (!keypool.vchPubKey.IsValid()) {
          Debug("ReserveKeyFromKeyPool: vchPubKey is not valid\n");
        }


//        assert(keypool.vchPubKey.IsValid());
//        Debug("keypool reserve %"PRI64d"\n", nIndex);
    }
}

int64 CWallet::AddReserveKey(const CKeyPool& keypool)
{
    {
        LOCK2(cs_main, cs_wallet);
        CWalletDB walletdb(strWalletFile);

        int64 nIndex = 1 + *(--setKeyPool.end());
        if (!walletdb.WritePool(nIndex, keypool))
            throw runtime_error("AddReserveKey() : writing added key failed");
        setKeyPool.insert(nIndex);
        return nIndex;
    }
    return -1;
}

void CWallet::KeepKey(int64 nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    //printf("keypool keep %"PRI64d"\n", nIndex);
}

void CWallet::ReturnKey(int64 nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    //printf("keypool return %"PRI64d"\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result, bool fAllowReuse)
{
    int64 nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (fAllowReuse && vchDefaultKey.IsValid())
            {
                result = vchDefaultKey;
                return true;
            }
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64 CWallet::GetOldestKeyPoolTime()
{
    int64 nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

CPubKey CReserveKey::GetReservedKey()
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else
        {
            Debug("CReserveKey::GetReservedKey(): Warning: using default key instead of a new key, top up your keypool.");
            vchPubKey = pwallet->vchDefaultKey;
        }
    }
    assert(vchPubKey.IsValid());
    return vchPubKey;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set<CKeyID>& setAddress)
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(const int64& id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes() : read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes() : unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CWallet::UpdatedTransaction(const uint256 &hashTx)
{
#if 0
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
    }
#endif
}

int64 GetTxFee(int ifaceIndex, CTransaction tx)
{
  CWallet *wallet;

  wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (0);

  return (wallet->GetTxFee(tx));
}

int64 GetAccountBalance(int ifaceIndex, CWalletDB& walletdb, const string& strAccount, int nMinDepth)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  int64 nBalance = 0;

  vector <COutput> vCoins;
  pwalletMain->AvailableAccountCoins(strAccount, vCoins, nMinDepth == 0 ? false : true);
  BOOST_FOREACH(const COutput& out, vCoins) {
    nBalance += out.tx->vout[out.i].nValue;
  }

  /* internal accounting entries */
  nBalance += walletdb.GetAccountCreditDebit(strAccount);

  return nBalance;
}
#if 0
int64 GetAccountBalance(int ifaceIndex, CWalletDB& walletdb, const string& strAccount, int nMinDepth)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  int64 nBalance = 0;

  /* wallet transactions */
  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
  {
    const CWalletTx& wtx = (*it).second;
    if (!wtx.IsFinal(ifaceIndex))
      continue;

    if (wtx.IsCoinBase() && wtx.GetBlocksToMaturity(ifaceIndex) > 0)
      continue;

    //int64 nGenerated, nReceived, nSent, nFee;
    //wtx.GetAccountAmounts(strAccount, nGenerated, nReceived, nSent, nFee);
    int64 nReceived, nSent, nFee;
    wtx.GetAccountAmounts(strAccount, nReceived, nSent, nFee);

    if (nReceived != 0 && wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
      nBalance += nReceived;
    nBalance -= nSent + nFee;
  }

  /* internal accounting entries */
  nBalance += walletdb.GetAccountCreditDebit(strAccount);

  return nBalance;
}
#endif

int64 GetAccountBalance(int ifaceIndex, const string& strAccount, int nMinDepth)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  CWalletDB walletdb(wallet->strWalletFile);
  return GetAccountBalance(ifaceIndex, walletdb, strAccount, nMinDepth);
}


bool SyncWithWallets(CIface *iface, CTransaction& tx, CBlock *pblock)
{
  CWallet *pwallet;

  pwallet = GetWallet(iface);
  if (!pwallet)
    return (false);

  return (pwallet->AddToWalletIfInvolvingMe(tx, pblock, true));
}

int CMerkleTx::GetBlocksToMaturity(int ifaceIndex) const
{

  if (!IsCoinBase())
    return 0;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return 0;

  int depth = GetDepthInMainChain(ifaceIndex);
  return max(0, ((int)iface->coinbase_maturity + 1) - depth);
}

int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{

  if (!pblock)
    return (0);

  blkidx_t *mapBlockIndex = GetBlockTable(pblock->ifaceIndex);
  if (!mapBlockIndex)
    return 0;

  // Update the tx's hashBlock
  hashBlock = pblock->GetHash();

  // Locate the transaction
  for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
    if (pblock->vtx[nIndex] == *(CTransaction*)this)
      break;
  if (nIndex == (int)pblock->vtx.size())
  {
    vMerkleBranch.clear();
    nIndex = -1;
    printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
    return 0;
  }

  // Fill in merkle branch
  vMerkleBranch = pblock->GetMerkleBranch(nIndex);

  // Is the tx in a block that's in the main chain
  map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex->find(hashBlock);
  if (mi == mapBlockIndex->end())
    return (0);

  CBlockIndex* pindex = (*mi).second;
  if (!pindex || !pindex->IsInMainChain(pblock->ifaceIndex))
    return (0);

  CBlockIndex *pindexBest = GetBestBlockIndex(pblock->ifaceIndex);
  if (!pindexBest)
    return (0);

  return (pindexBest->nHeight - pindex->nHeight + 1);
}

int CMerkleTx::SetMerkleBranch(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (0);

  CBlock *pblock = GetBlockByTx(iface, GetHash()); 
  if (!pblock)
    return (0);

  int ret = SetMerkleBranch(pblock);
  delete pblock;
  return (ret);
}


#if 0
CCoinAddr GetAccountAddress(CWallet *wallet, string strAccount, bool bForceNew)
{
  CWalletDB walletdb(wallet->strWalletFile);
  CAccount account;
  bool bKeyUsed = false;

  walletdb.ReadAccount(strAccount, account);

  // Check if the current key has been used
  if (account.vchPubKey.IsValid())
  {
    CScript scriptPubKey;
    scriptPubKey.SetDestination(account.vchPubKey.GetID());
    for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin();
        it != wallet->mapWallet.end() && account.vchPubKey.IsValid();
        ++it)
    {
      const CWalletTx& wtx = (*it).second;
      BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        if (txout.scriptPubKey == scriptPubKey)
          bKeyUsed = true;
    }
  }

  // Generate a new key
  if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed)
  {
    if (!wallet->GetKeyFromPool(account.vchPubKey, false))
      return CCoinAddr(wallet->ifaceIndex);//throw JSONRPCError(-12, "Error: Keypool ran out, please call keypoolrefill first");

    wallet->SetAddressBookName(account.vchPubKey.GetID(), strAccount);
    walletdb.WriteAccount(strAccount, account);
  }

  return CCoinAddr(wallet->ifaceIndex, account.vchPubKey.GetID());
}
#endif

CPubKey GetAccountPubKey(CWallet *wallet, string strAccount, bool bForceNew)
{
  CWalletDB walletdb(wallet->strWalletFile);
  CAccount account;
  bool bKeyUsed = false;

  walletdb.ReadAccount(strAccount, account);

  // Check if the current key has been used
  if (!bForceNew && account.vchPubKey.IsValid()) {
    CScript scriptPubKey;
    scriptPubKey.SetDestination(account.vchPubKey.GetID());
    for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin();
        it != wallet->mapWallet.end() && account.vchPubKey.IsValid();
        ++it)
    {
      const CWalletTx& wtx = (*it).second;
      BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        if (txout.scriptPubKey == scriptPubKey)
          bKeyUsed = true;
    }
  }

  // Generate a new key
  if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed)
  {

#if 0
    if (!wallet->GetKeyFromPool(account.vchPubKey, false))
      return CPubKey();
#endif

    account.vchPubKey = wallet->GenerateNewKey(true);
    wallet->SetAddressBookName(account.vchPubKey.GetID(), strAccount);
    walletdb.WriteAccount(strAccount, account);
  }

  return (account.vchPubKey);
}

CCoinAddr GetAccountAddress(CWallet *wallet, string strAccount, bool bForceNew)
{
  const CPubKey& pubkey = GetAccountPubKey(wallet, strAccount, bForceNew);
  return CCoinAddr(wallet->ifaceIndex, pubkey.GetID());
}

bool CWallet::GetMergedPubKey(string strAccount, const char *tag, CPubKey& pubkey)
{
  CWalletDB walletdb(strWalletFile);
  CAccount account;
  CKey pkey;
  bool fUpdate = false;

  walletdb.ReadAccount(strAccount, account);

  if (!account.vchPubKey.IsValid()) {
    if (!GetKeyFromPool(account.vchPubKey, false))
      return false;

    SetAddressBookName(account.vchPubKey.GetID(), strAccount);
    fUpdate = true;
  }

  if (!GetKey(account.vchPubKey.GetID(), pkey)) {
    return error(SHERR_INVAL, "CWallet::GetMergedAddress: account '%s' has no primary key.", strAccount.c_str());
  }

  cbuff tagbuff(tag, tag + strlen(tag)); 
  CKey key = pkey.MergeKey(tagbuff);

  pubkey = key.GetPubKey();
  if (!pubkey.IsValid()) {
    return error(SHERR_INVAL, "CWallet.GetMergedAddress: generated pubkey is invalid.");
  }

  if (!HaveKey(pubkey.GetID())) {
    /* add key to address book */
    if (!AddKey(key)) {
      return error(SHERR_INVAL, "CWallet.GetMergedAddress: error adding generated key to wallet.");
    }

    SetAddressBookName(pubkey.GetID(), strAccount);
  }

  if (fUpdate)
    walletdb.WriteAccount(strAccount, account);

  return (true);
}

bool CWallet::GetMergedAddress(string strAccount, const char *tag, CCoinAddr& addrRet)
{
  CPubKey pubkey;
  bool fRet = GetMergedPubKey(strAccount, tag, pubkey);
  if (!fRet)
    return (false);

  addrRet = CCoinAddr(ifaceIndex, pubkey.GetID());
  if (!addrRet.IsValid()) {
    return (error(SHERR_INVAL, "CWallet.GetMergedAddress: error generating coin addr from pubkey"));
  }

  return (true);
}


/** Generate a transaction with includes a specific input tx. */
bool CreateTransactionWithInputTx(CIface *iface, 
    const vector<pair<CScript, int64> >& vecSend,
    CWalletTx& wtxIn, int nTxOut, CWalletTx& wtxNew,
    CReserveKey& reservekey, int64 nTxFee)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *pwalletMain = GetWallet(iface);
  int64 nMinValue = MIN_INPUT_VALUE(iface);
  int64 nValue = 0;
  int64 nFeeRet;

  if (wtxIn.IsSpent(nTxOut)) {
    return error(ifaceIndex, "CreateTransactionWithInputTx: previous ext tx '%s' is already spent.", wtxIn.GetHash().GetHex().c_str());
  }

  BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
    if (s.second < 0) {//nMinValue) {
      return error(SHERR_INVAL, "CreateTransactionWIthInputTx: send-value(%f) < min-value(%f)", ((double)s.second/(double)COIN), ((double)nMinValue/(double)COIN));
    }
    nValue += s.second;
  }
  if (vecSend.empty() || nValue < 0) {
    return error(SHERR_INVAL, "CreateTransactionWIthInputTx: vecSend.empty()\n");
  }

  wtxNew.BindWallet(pwalletMain);

  {
    nFeeRet = nTransactionFee;
    loop {
      wtxNew.vin.clear();
      wtxNew.vout.clear();
      wtxNew.fFromMe = true;

      int64 nTotalValue = nValue + nFeeRet;
      double dPriority = 0;

      // vouts to the payees
      BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
        wtxNew.vout.push_back(CTxOut(s.second, s.first));

      int64 nWtxinCredit = wtxIn.vout[nTxOut].nValue;

      // Choose coins to use
      set<pair<const CWalletTx*, unsigned int> > setCoins;
      int64 nValueIn = 0;
      if (nTotalValue - nWtxinCredit > 0) {
        if (!pwalletMain->SelectCoins(nTotalValue - nWtxinCredit,
              setCoins, nValueIn)) {
          return error(SHERR_INVAL, "CreateTransactionWithInputTx: error selecting coins\n"); 
        }
      }

      vector<pair<const CWalletTx*, unsigned int> > vecCoins(
          setCoins.begin(), setCoins.end());

      BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
        int64 nCredit = coin.first->vout[coin.second].nValue;
        dPriority += (double) nCredit
          * coin.first->GetDepthInMainChain(ifaceIndex);
      }

      // Input tx always at first position
      vecCoins.insert(vecCoins.begin(), make_pair(&wtxIn, nTxOut));

      nValueIn += nWtxinCredit;
      dPriority += (double) nWtxinCredit * wtxIn.GetDepthInMainChain(ifaceIndex);

      // Fill a vout back to self (new addr) with any change
      int64 nChange = MAX(0, nValueIn - nTotalValue - nTxFee);
      if (nChange >= CENT) {
        CCoinAddr returnAddr = GetAccountAddress(pwalletMain, wtxNew.strFromAccount, true);
        CScript scriptChange;

        if (returnAddr.IsValid()) {
          /* return change to sender */
          scriptChange.SetDestination(returnAddr.Get());
        } else {
          /* use supplied addr */
          CPubKey pubkey = reservekey.GetReservedKey();
          scriptChange.SetDestination(pubkey.GetID());
        }

        /* include as first transaction. */
        vector<CTxOut>::iterator position = wtxNew.vout.begin();
        wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
      }

      // Fill vin
      BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
        wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

      unsigned int nIn = 0;
      BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
        CSignature sig(ifaceIndex, &wtxNew, nIn);
        if (!sig.SignSignature(*coin.first)) {
          return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
        }
        nIn++;
      }
#if 0
      // Sign
      int nIn = 0;
      BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
        if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nIn++)) {
          return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
        }
      }
#endif

      /* Ensure transaction does not breach a defined size limitation. */
      unsigned int nWeight = pwalletMain->GetTransactionWeight(wtxNew);
      if (nWeight >= MAX_TRANSACTION_WEIGHT(iface)) {
        return error(SHERR_INVAL, "CreateTransactionWithInputTx: the transaction is too large.");
      }

      unsigned int nBytes = pwalletMain->GetVirtualTransactionSize(wtxNew);
      dPriority /= nBytes;

      // Check that enough fee is included
      int64 nPayFee = nTransactionFee * (1 + (int64) nBytes / 1000);
#if 0
      bool fAllowFree = pwalletMain->AllowFree(dPriority);
      int64 nMinFee = wtxNew.GetMinFee(ifaceIndex, 1, fAllowFree);
#endif
      int64 nMinFee = pwalletMain->CalculateFee(wtxNew);

      if (nFeeRet < max(nPayFee, nMinFee)) {
        nFeeRet = max(nPayFee, nMinFee);
        Debug("TEST: CreateTransactionWithInputTx: re-iterating (nFreeRet = %s)\n", FormatMoney(nFeeRet).c_str());
        continue;
      }

      // Fill vtxPrev by copying from previous transactions vtxPrev
      pwalletMain->AddSupportingTransactions(wtxNew);
      wtxNew.fTimeReceivedIsTxTime = true;
      break;
    }

  }

  return true;
}

int IndexOfExtOutput(const CTransaction& tx)
{
  int idx;

  idx = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {

    const CScript& script = out.scriptPubKey;
    opcodetype opcode;
    CScript::const_iterator pc = script.begin();
    if (script.GetOp(pc, opcode) &&
        opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
#if 0
      if (script.GetOp(pc, opcode) && /* ext type */
          script.GetOp(pc, opcode) && /* content */
          opcode == OP_HASH160)
#endif
        break;
    }

    idx++;
  }
  if (idx == tx.vout.size())
    return (-1); /* uh oh */

  return (idx);
}

/** Commit a transaction with includes a specific input tx. */
bool SendMoneyWithExtTx(CIface *iface,
    CWalletTx& wtxIn, CWalletTx& wtxNew,
    const CScript& scriptPubKey,
    vector<pair<CScript, int64> > vecSend,
    int64 txFee)
{
  CWallet *pwalletMain = GetWallet(iface);
  CReserveKey reservekey(pwalletMain);
  int ifaceIndex = GetCoinIndex(iface);
  int nTxOut;

  nTxOut = IndexOfExtOutput(wtxIn);
  if (nTxOut == -1) {
    return error(ifaceIndex, "SendMoneyWithExtTx: error obtaining previous tx.");
  }

  /* insert as initial position. this is 'primary' operation. */
  int64 tx_val = wtxIn.vout[nTxOut].nValue;
  txFee = MAX(0, MIN(tx_val - iface->min_tx_fee, txFee));
  int64 nValue = tx_val - txFee;
  vecSend.insert(vecSend.begin(), make_pair(scriptPubKey, nValue));

	if (!CreateTransactionWithInputTx(iface,
        vecSend, wtxIn, nTxOut, wtxNew, reservekey, txFee)) {
    return error(ifaceIndex, "SendMoneyWithExtTx: error creating transaction.");
  }

	if (!pwalletMain->CommitTransaction(wtxNew)) {
    return error(ifaceIndex, "error commiting transaction.");
  }

  return (true);
}


bool GetCoinAddr(CWallet *wallet, CCoinAddr& addrAccount, string& strAccount)
{
  bool fIsScript = addrAccount.IsScript();

  if (!addrAccount.IsValid())
    return (false);

  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(wallet->ifaceIndex, item.first);
    const string& account = item.second;

    if (fIsScript && !address.IsScript())
      continue;

    /* DEBUG: does not compare coinaddr version */
    if (address.Get() == addrAccount.Get()) {
      addrAccount = address;
      strAccount = account;
      return (true);
    }
  }

  return (false);
}

bool GetCoinAddrAlias(CWallet *wallet, string strAlias, CCoinAddr& addrAccount)
{
  CIface *iface = GetCoinByIndex(wallet->ifaceIndex); 
  CTransaction tx;
  CAlias *alias;

  alias = GetAliasByName(iface, strAlias, tx); 
  if (!alias)
    return (false);

  return (alias->GetCoinAddr(addrAccount));
}

bool GetCoinAddr(CWallet *wallet, string strAddress, CCoinAddr& addrAccount)
{

  if (strAddress.length() == 0)
    return (false);

  if (strAddress.at(0) == '@') {
    return (GetCoinAddrAlias(wallet, strAddress.substr(1), addrAccount));
  }

  addrAccount = CCoinAddr(strAddress);
  if (!addrAccount.IsValid())
    return (false);

  return (true);
}

bool DecodeMatrixHash(const CScript& script, int& mode, uint160& hash)
{
  CScript::const_iterator pc = script.begin();
  opcodetype opcode;
  int op;

  if (!script.GetOp(pc, opcode)) {
    return false;
  }
  mode = opcode; /* extension mode (new/activate/update) */
  if (mode < 0xf0 || mode > 0xf9)
    return false;

  if (!script.GetOp(pc, opcode)) {
    return false;
  }
  if (opcode < OP_1 || opcode > OP_16) {
    return false;
  }
  op = CScript::DecodeOP_N(opcode); /* extension type */
  if (op != OP_MATRIX) {
    return false;
  }

  vector<unsigned char> vch;
  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  if (opcode != OP_HASH160)
    return (false);

  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  hash = uint160(vch);
  return (true);
}

bool VerifyMatrixTx(CTransaction& tx, int& mode)
{
  uint160 hashMatrix;
  int nOut;

  /* core verification */
  if (!tx.isFlag(CTransaction::TXF_MATRIX))
    return (false); /* tx not flagged as matrix */

  /* verify hash in pub-script matches matrix hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return error(SHERR_INVAL, "no extension output");

  if (!DecodeMatrixHash(tx.vout[nOut].scriptPubKey, mode, hashMatrix))
    return error(SHERR_INVAL, "no matrix hash in output");

  CTxMatrix *matrix = (CTxMatrix *)&tx.matrix;
  if (hashMatrix != matrix->GetHash())
    return error(SHERR_INVAL, "matrix hash mismatch");

  return (true);
}

#if 0
bool CMerkleTx::AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs)
{
  if (fClient)
  {
    if (!IsInMainChain(txdb.ifaceIndex) && !ClientConnectInputs(txdb.ifaceIndex))
      return false;
    return CTransaction::AcceptToMemoryPool(txdb, false);
  }
  else
  {
    return CTransaction::AcceptToMemoryPool(txdb, fCheckInputs);
  }
}
#endif


bool IsAccountValid(CIface *iface, std::string strAccount)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet;
  int total;

  wallet = GetWallet(iface);
  if (!wallet)
    return (false);

  total = 0;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
    const string& strName = item.second;
    if (strName == strAccount)
      total++;
  }

  return (total != 0);
}

void RelayTransaction(int ifaceIndex, const CTransaction& tx, const uint256& hash)
{
  CInv inv(ifaceIndex, MSG_TX, hash);

  LOCK(cs_vNodes);
  NodeList &vNodes = GetNodeList(ifaceIndex);
  BOOST_FOREACH(CNode* pnode, vNodes)
  {
    if(!pnode->fRelayTxes) {
      Debug("RelayTransaction[iface #%d]: tx (%s) [suppress]", ifaceIndex, hash.GetHex().c_str());
      continue;
    }

    LOCK(pnode->cs_filter);
    CBloomFilter *filter = pnode->GetBloomFilter();
    if (filter) {
      if (filter->IsRelevantAndUpdate(tx, hash)) {
        pnode->PushInventory(inv);
        Debug("RelayTransaction[iface #%d]: tx (%s) [bloom]", ifaceIndex, hash.GetHex().c_str());
      } else {
        Debug("RelayTransaction[iface #%d]: tx (%s) [suppress/bloom]", ifaceIndex, hash.GetHex().c_str());
      }
    } else {
      pnode->PushInventory(inv);
      Debug("RelayTransaction[iface #%d]: tx (%s)", ifaceIndex, hash.GetHex().c_str());
    }
  }

}

int CMerkleTx::GetDepthInMainChain(int ifaceIndex, CBlockIndex* &pindexRet) const
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CBlockIndex *pindex;

  if (hashBlock == 0 || nIndex == -1)
    return 0;

  pindex = GetBlockIndexByHash(ifaceIndex, hashBlock);
  if (!pindex || !pindex->IsInMainChain(ifaceIndex))
    return 0;

  // Make sure the merkle branch connects to this block
  if (!fMerkleVerified)
  {
    CBlock *block = GetBlockByHeight(iface, pindex->nHeight);
    if (!block)
      return 0;
    if (block->CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot) {
      delete block;
      return 0;
    }
    fMerkleVerified = true;
    delete block;
  }

  pindexRet = pindex;
  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  if (!pindexBest)
    return (0);
  return pindexBest->nHeight - pindex->nHeight + 1;
}


void CWallet::AvailableAddrCoins(vector<COutput>& vCoins, const CCoinAddr& filterAddr, int64& nTotalValue, bool fOnlyConfirmed) const
{

  vCoins.clear();
  nTotalValue = 0;

  {
    LOCK(cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
      const CWalletTx* pcoin = &(*it).second;

      if (!pcoin->IsFinal(ifaceIndex))
        continue;

      if (fOnlyConfirmed && !pcoin->IsConfirmed())
        continue;

      if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity(ifaceIndex) > 0)
        continue;

      // If output is less than minimum value, then don't include transaction.
      // This is to help deal with dust spam clogging up create transactions.
      for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
        opcodetype opcode;
        const CScript& script = pcoin->vout[i].scriptPubKey;
        CScript::const_iterator pc = script.begin();
        if (script.GetOp(pc, opcode) &&
            opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
          continue; /* not avail */
        }
#if 0
        CIface *iface = GetCoinByIndex(ifaceIndex);
        int64 nMinimumInputValue = MIN_INPUT_VALUE(iface);
        if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) && pcoin->vout[i].nValue >= nMinimumInputValue)
          vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(ifaceIndex)));
#endif

        CIface *iface = GetCoinByIndex(ifaceIndex);
        int64 nMinValue = MIN_INPUT_VALUE(iface);
        if (pcoin->vout[i].nValue < nMinValue)
          continue; /* weird */

        if (pcoin->IsSpent(i))
          continue;

        CTxDestination dest;
        if (!ExtractDestination(pcoin->vout[i].scriptPubKey, dest))
          continue;
        CKeyID k1;
        CKeyID k2;
        if (!CCoinAddr(ifaceIndex, dest).GetKeyID(k1) || 
            !filterAddr.GetKeyID(k2) || 
            k1 != k2)
          continue; /* wrong coin address */

        vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(ifaceIndex)));
        nTotalValue += pcoin->vout[i].nValue;
      }
    }
  }
}

bool CreateMoneyTx(CIface *iface, CWalletTx& wtxNew, vector<COutput>& vecRecv, vector<CTxOut>& vecSend, CScript scriptPubKey)
{
  CWallet *wallet = GetWallet(iface);
  int64 nTotalValue = 0;
  int64 nTxFee = 0;

  wtxNew.BindWallet(wallet);
  {
    wtxNew.vin.clear();
    wtxNew.vout.clear();

    BOOST_FOREACH(const COutput& out, vecRecv) {
      wtxNew.vin.push_back(CTxIn(out.tx->GetHash(), (unsigned int)out.i));
      nTotalValue += out.tx->vout[out.i].nValue; 
    }

    BOOST_FOREACH(const CTxOut& out, vecSend) {
      wtxNew.vout.push_back(out);
    }

    /* calculate fee */
    unsigned int nBytes = ::GetSerializeSize(wtxNew, SER_NETWORK, PROTOCOL_VERSION(iface));
    nBytes += 66 * vecRecv.size(); /* ~ 66b / sig */
    nTxFee = (1 + (int64)nBytes / 1000) * (int64)iface->min_tx_fee;
    /* add final destination addr */
    wtxNew.vout.push_back(CTxOut(nTotalValue - nTxFee, scriptPubKey));

    unsigned int nIn = 0;
    BOOST_FOREACH(const COutput& out, vecRecv) {
      CSignature sig(wallet->ifaceIndex, &wtxNew, nIn);
      if (!sig.SignSignature(*out.tx)) {
        return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
      }

      nIn++;
    }
#if 0
    int nIn = 0;
    BOOST_FOREACH(const COutput& out, vecRecv) {
      if (!SignSignature(*wallet, *out.tx, wtxNew, nIn++)) {
        return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
      }
    }
#endif

    wallet->AddSupportingTransactions(wtxNew);
    wtxNew.fTimeReceivedIsTxTime = true;
  }

  return (true);
}

/**
 * @param wtxIn An extended tx input to remit coins from.
 * @param scriptPubKey The destination coin address.
 */ 
bool SendRemitMoneyTx(CIface *iface, const CCoinAddr& addrFrom, CWalletTx *wtxIn, CWalletTx& wtxNew, vector<pair<CScript, int64> >& vecSend, CScript scriptPubKey)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  vector<COutput> vCoins;
  int64 nTotalValue = 0;
  wallet->AvailableAddrCoins(vCoins, addrFrom, nTotalValue, true);

  if (wtxIn) {
    /* append primary exec tx */
    int nTxOut = IndexOfExtOutput(*wtxIn);
    if (nTxOut == -1) return (false);
    vCoins.push_back(COutput(wtxIn, nTxOut, wtxIn->GetDepthInMainChain(ifaceIndex)));
  }

  vector <CTxOut> vecOut;
  BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
    vecOut.push_back(CTxOut(s.second, s.first));
  }

  if (!CreateMoneyTx(iface, wtxNew, vCoins, vecOut, scriptPubKey)) {
    return (error(SHERR_CANCELED, "SendRemitMoneyExtTx: error sending money tx: %s.", scriptPubKey.ToString().c_str()));
  }

  CReserveKey rkey(wallet);
  if (!wallet->CommitTransaction(wtxNew)) {
    return error(SHERR_CANCELED, "SendRemitMoneyExtTx: error commiting transaction.");
  }

  return (true);
}
 

#if 0
bool CreateExtTransactionFromAddrTx(CIface *iface, 
    const CCoinAddr& sendAddr, const CTransaction& wtxIn,
    CWalletTx& wtxNew, CReserveKey& reservekey)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
  int64 nFee = 0;

#if 0
  BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
    if (nValue < 0) {
      return error(SHERR_INVAL, "CreateTransactionWIthInputTx: nValue < 0\n");
    }
    nValue += s.second;
  }
  if (vecSend.empty() || nValue < 0) {
    return error(SHERR_INVAL, "CreateTransactionWIthInputTx: vecSend.empty()\n");
  }
#endif

  wtxNew.BindWallet(wallet);

  {
    vector<COutput> vCoins;
    int64 nTotalValue = 0;
    int64 nValue;

    wallet->AvailableAddrCoins(vCoins, sendAddr, nTotalValue, true); 

    nFee = iface->min_tx_fee;
    /* rought estimate ~ 200b per input */
    nFee += (vCoins.size() * 20);

    loop {
      wtxNew.vin.clear();
      wtxNew.vout.clear();
      wtxNew.fFromMe = true;

      int64 nValue = nTotalValue - nFee;
      if (nValue < iface->min_input)
        return error(SHERR_INVAL, "transaction too large."); /* remove/limit vCoins? */

//      int64 nTotalValue = nValue + nFee;
//      double dPriority = 0;

      CScript scriptPub;
      scriptPub.SetDestination(sendAddr.Get());
      wtxNew.vout.push_back(CTxOut(nTotalValue - nFee, scriptPub));

#if 0
      // vouts to the payees
      BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
        wtxNew.vout.push_back(CTxOut(s.second, s.first));

      int64 nWtxinCredit = wtxIn.vout[nTxOut].nValue;

      // Choose coins to use
      set<pair<const CWalletTx*, unsigned int> > setCoins;
      int64 nValueIn = 0;
      if (nTotalValue - nWtxinCredit > 0) {
        if (!wallet->SelectCoins(nTotalValue - nWtxinCredit,
              setCoins, nValueIn)) {
          return error(SHERR_INVAL, "CreateTransactionWithInputTx: error selecting coins\n"); 
        }
      }
#endif

#if 0
      vector<pair<const CWalletTx*, unsigned int> > vecCoins(
          setCoins.begin(), setCoins.end());

      BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
        int64 nCredit = coin.first->vout[coin.second].nValue;
        dPriority += (double) nCredit
          * coin.first->GetDepthInMainChain(ifaceIndex);
      }
#endif

#if 0
      // Input tx always at first position
      vecCoins.insert(vecCoins.begin(), make_pair(&wtxIn, nTxOut));
#endif

#if 0
      nValueIn += nWtxinCredit;
      dPriority += (double) nWtxinCredit * wtxIn.GetDepthInMainChain(ifaceIndex);
#endif

#if 0
      // Fill a vout back to self (new addr) with any change
      int64 nChange = MAX(0, nValueIn - nTotalValue - nTxFee);
      if (nChange >= CENT) {
        CCoinAddr returnAddr = GetAccountAddress(wallet, wtxNew.strFromAccount, true);
        CScript scriptChange;

        if (returnAddr.IsValid()) {
          /* return change to sender */
          scriptChange.SetDestination(returnAddr.Get());
        } else {
          /* use supplied addr */
          CPubKey pubkey = reservekey.GetReservedKey();
          scriptChange.SetDestination(pubkey.GetID());
        }

        /* include as first transaction. */
        vector<CTxOut>::iterator position = wtxNew.vout.begin();
        wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
      }
#endif

      BOOST_FOREACH(const COutput& out, vCoins) {
        wtxNew.vin.push_back(CTxIn(out.tx->GetHash(), (unsigned int)out.i));
      }
#if 0
      // Fill vin
      BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
        wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));
#endif

      int nIn = 0;
      BOOST_FOREACH(const COutput& out, vCoins) {
        if (!SignSignature(*wallet, *out.tx, wtxNew, nIn++)) {
          return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
        }
      }
#if 0
      // Sign
      int nIn = 0;
      BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
        if (!SignSignature(*wallet, *coin.first, wtxNew, nIn++)) {
          return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
        }
      }
#endif

      unsigned int nBytes = ::GetSerializeSize(*(CTransaction*) &wtxNew,
          SER_NETWORK, PROTOCOL_VERSION(iface));
      if (nBytes >= MAX_BLOCK_SIZE_GEN(iface)) {
        return error(SHERR_INVAL, "CreateTransactionWithInputTx: tx too big");
      }
#if 0
      dPriority /= nBytes;
      // Check that enough fee is included
      int64 nPayFee = nTransactionFee * (1 + (int64) nBytes / 1000);
#endif

      int64 nMinFee = wtxNew.GetMinFee(ifaceIndex, 1, false);
      if (nFee < nMinFee) {
        nFee = nMinFee;
        Debug("TEST: CreateTransactionWithInputTx: re-iterating (nFreeRet = %s)\n", FormatMoney(nFee).c_str());
        continue;
      }

      // Fill vtxPrev by copying from previous transactions vtxPrev
      wallet->AddSupportingTransactions(wtxNew);
      wtxNew.fTimeReceivedIsTxTime = true;
      break;
    }

  }

  Debug("CreateTransactionFromAddrTx: commit '%s'", wtxNew.ToString().c_str());
  return true;
}
#endif

/**
 * @note: This functionality is designed to rid of rejected transactions. This does not permit the 'canceling' of already relayed transactions.
 */
bool core_UnacceptWalletTransaction(CIface *iface, const CTransaction& tx)
{
  int ifaceIndex = GetCoinIndex(iface);
  const uint256& tx_hash = tx.GetHash();
  CTxMemPool *pool = GetTxMemPool(iface);
  CWallet *wallet = GetWallet(iface);

  /* remove from wallet */
  wallet->EraseFromWallet(tx_hash);

  if (pool->exists(tx_hash)) {
    pool->RemoveTx(tx_hash);
  }

  /* cycle through inputs */
  BOOST_FOREACH(const CTxIn& in, tx.vin) {
    const uint256& prevhash = in.prevout.hash;
    CTransaction prevtx;

#if 0
    if (pool->mapTx.count(prevhash) != 0)
      continue; /* prevout is in pool */
#endif
    if (pool->exists(prevhash))
      continue; /* prevout is in pool */

    if (!::GetTransaction(iface, prevhash, prevtx, NULL))
      continue; /* dito */

    if (wallet->mapWallet.count(prevhash) == 0)
      /* not being tracked by wallet. */
      continue;

    if (!wallet->IsMine(prevtx)) {
fprintf(stderr, "DEBUG: core_UnacceptWalletTransaction: abandoning tx '%s' -- not owner\n", prevhash.GetHex().c_str()); 
      continue; /* no longer owner */
}

    CWalletTx wtx;

    wtx = wallet->mapWallet[prevhash];

    /* mark output as unspent */
    vector<char> vfNewSpent = wtx.vfSpent;
    if (in.prevout.n >= wtx.vout.size()) {
      error(SHERR_INVAL, "core_UnacceptWalletTransaction: in.prevout.n (%d) >= wtx.vout.size(%d)", in.prevout.n, wtx.vout.size());
      continue;    
    }
    vfNewSpent.resize(wtx.vout.size());
    vfNewSpent[in.prevout.n] = false;
    wtx.UpdateSpent(vfNewSpent);
    wtx.MarkDirty();

    if (!wtx.WriteToDisk()) {
      Debug("rpc_tx_purge: error writing tx \"%s\" to tx database.", prevhash.GetHex().c_str());
      continue;
    }

    /* push pool transaction's inputs back into wallet. */
    wallet->mapWallet[prevhash] = wtx;
  }

#ifndef USE_LEVELDB_COINDB
  BOOST_FOREACH(const CTxIn& in, tx.vin) {
    const uint256& prev_hash = in.prevout.hash; 
    int nTxOut = in.prevout.n;
    vector<uint256> vOuts;

    CTransaction prevTx;
    if (wallet->mapWallet.count(prev_hash) != 0) {
      prevTx = (CTransaction)wallet->mapWallet[prev_hash];
    } else if (!GetTransaction(iface, prev_hash, prevTx, NULL)) {
      continue; /* not found */
    }

    if (prevTx.ReadCoins(ifaceIndex, vOuts))
      continue;

    /* sanity */
    if (nTxOut >= vOuts.size())
      continue;

    if (vOuts[nTxOut].IsNull())
      continue;

    /* set output as unspent */
    vOuts[nTxOut].SetNull();
    prevTx.WriteCoins(ifaceIndex, vOuts);
  }
#endif

  return (true);
}


/* not used, intended as generic interface */
bool core_CreateWalletAccountTransaction(CWallet *wallet, string strFromAccount, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, string& strError, int64& nFeeRet)
{
  CIface *iface = GetCoinByIndex(wallet->ifaceIndex);

  wtxNew.strFromAccount = strFromAccount;

  int64 nValue = 0;
  BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
  {
    if (nValue < 0) {
      strError = "invalid output coin value";
      return false;
    }
    nValue += s.second;
  }
  if (vecSend.empty() || nValue < 0) {
    strError = "incomplete output specified";
    return false;
  }

  wtxNew.BindWallet(wallet);

  {
    //LOCK2(cs_main, cs_wallet);
    {
      nFeeRet = 0;

      loop
      {
        wtxNew.vin.clear();
        wtxNew.vout.clear();
        wtxNew.wit.SetNull();
        wtxNew.fFromMe = true;

        int64 nTotalValue = nValue + nFeeRet;
        double dPriority = 0;
        // vouts to the payees
        BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
          wtxNew.vout.push_back(CTxOut(s.second, s.first));

        // Choose coins to use
        set<pair<const CWalletTx*,unsigned int> > setCoins;
        int64 nValueIn = 0;
        if (!wallet->SelectAccountCoins(strFromAccount, nTotalValue, setCoins, nValueIn)) {
          strError = "An error occurred obtaining sufficient coins in order perform the transaction. Check the transaction fee cost.";
          return false;
        }
        BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
        {
          int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
          dPriority += (double)nCredit * pcoin.first->GetDepthInMainChain(wallet->ifaceIndex);
        }

        int64 nChange = nValueIn - nValue - nFeeRet;
        // if sub-cent change is required, the fee must be raised to at least SHC_MIN_TX_FEE
        // or until nChange becomes zero
        // NOTE: this depends on the exact behaviour of GetMinFee
        if (nFeeRet < MIN_TX_FEE(iface) && nChange > 0 && nChange < CENT)
        {
          int64 nMoveToFee = min(nChange, MIN_TX_FEE(iface) - nFeeRet);
          nChange -= nMoveToFee;
          nFeeRet += nMoveToFee;
        }

        if (nChange > 0)
        {

          CPubKey vchPubKey;
          if (nChange > CENT &&
              wtxNew.strFromAccount.length() != 0 &&
              strFromAccount != NULL_ACCOUNT &&
              wallet->GetMergedPubKey(wtxNew.strFromAccount, "change", vchPubKey)) {
            /* DEBUG: TODO: && none of inputs are vchPubKey */
            /* Use a consistent change address based on primary address. */
            //  reservekey.ReturnKey();
          } else {
            /* Revert to using a quasi-standard 'ghost' address. */
            CReserveKey reservekey(wallet);
            vchPubKey = reservekey.GetReservedKey();
            reservekey.KeepKey();
          }

          CScript scriptChange;
          scriptChange.SetDestination(vchPubKey.GetID());

          // Insert change txn at random position:
          vector<CTxOut>::iterator position = wtxNew.vout.begin()+GetRandInt(wtxNew.vout.size());
          wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));

#if 0
        } else {
          reservekey.ReturnKey();
#endif
        }

        // Fill vin
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
          wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

        unsigned int nIn = 0;
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
          CSignature sig(wallet->ifaceIndex, &wtxNew, nIn);
          const CWalletTx *s_wtx = coin.first;
          if (!sig.SignSignature(*s_wtx)) {
            return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
          }

          nIn++;
        }
#if 0
        // Sign
        int nIn = 0;
        BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
          const CWalletTx *s_wtx = coin.first;
          if (!SignSignature(*wallet, *s_wtx, wtxNew, nIn)) {

#if 0
            /* failing signing against prevout. mark as spent to prohibit further attempts to use this output. */
            s_wtx->MarkSpent(nIn);
#endif

            strError = strprintf(_("An error occurred signing the transaction [input tx \"%s\", output #%d]."), s_wtx->GetHash().GetHex().c_str(), nIn);
            return false;
          }
          nIn++;
        }
#endif

        /* Ensure transaction does not breach a defined size limitation. */
        unsigned int nWeight = wallet->GetTransactionWeight(wtxNew);
        if (nWeight >= MAX_TRANSACTION_WEIGHT(iface)) {
          strError = "The transaction is too large.";
          return false;
        }

        unsigned int nBytes = wallet->GetVirtualTransactionSize(wtxNew);
        dPriority /= nBytes;

        // Check that enough fee is included
        int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
#if 0
        bool fAllowFree = wallet->AllowFree(dPriority);
        int64 nMinFee = wtxNew.GetMinFee(wallet->ifaceIndex, 1, fAllowFree, GMF_SEND);
#endif
        int64 nMinFee = wallet->CalculateFee(wtxNew);

        if (nFeeRet < max(nPayFee, nMinFee))
        {
          nFeeRet = max(nPayFee, nMinFee);
          continue;
        }

        /* established acceptable parameters */
        break;
      }
    }
  }

  return true;
}

template <typename T>
std::vector<unsigned char> ToByteVector(const T& in)
{       
    return std::vector<unsigned char>(in.begin(), in.end());
}   

CScript GetScriptForWitness(const CScript& redeemscript)
{
  CScript ret;

  txnouttype typ;
  std::vector<std::vector<unsigned char> > vSolutions;
  if (Solver(redeemscript, typ, vSolutions)) {
    if (typ == TX_PUBKEY) {
/*
      unsigned char h160[20];
      CHash160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(h160);
      ret << OP_0 << std::vector<unsigned char>(&h160[0], &h160[20]);
*
*/
      cbuff vch(vSolutions[0].begin(), vSolutions[0].end());
      uint160 h160 = Hash160(vch);
      ret << OP_0 << h160;

      return ret;
    } else if (typ == TX_PUBKEYHASH) {
      ret << OP_0 << vSolutions[0];
      return ret;
    }
  }

  uint256 hash;
//  CSHA256().Write(&redeemscript[0], redeemscript.size()).Finalize(hash.begin());
  hash = Hash(redeemscript.begin(), redeemscript.end());
  ret << OP_0 << ToByteVector(hash);

  return ret;
}

bool CWallet::GetWitnessAddress(CCoinAddr& addr, CCoinAddr& witAddr)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  string strAccount;

  if (!addr.IsValid())
    return error(SHERR_INVAL, "GetWitnessAddress: invalid address specified.");

  if (!IsWitnessEnabled(iface, GetBestBlockIndex(iface)))
    return error(SHERR_INVAL, "GetWitnessAddress: seg-wit not enabled.");

  if (!GetCoinAddr((CWallet *)this, addr, strAccount))
    return error(SHERR_ACCESS, "GetWitnessAddress: cannot generate witness address from a non-local coin address.");

  CKeyID keyID;
  CScriptID scriptID;
  CScriptID result;
  if (addr.GetKeyID(keyID)) {
    CKey key;
    if (!GetKey(keyID, key))
      return (error(SHERR_ACCESS, "GetWitnessAddress: cannot generate witness address from a non-local coin address."));

    // Signing with uncompressed keys is disabled in witness scripts
    if (!key.IsCompressed()) {
      return (error(SHERR_INVAL, "GetWitnessAddress: generating witness program signature unsupportd for non-compressed key."));
    }


    CScript basescript = GetScriptForDestination(keyID);

#if 0
    if (!::IsMine(*this, basescript, true))
      return error(SHERR_ACCESS, "GetWitnessAddress: cannot create witness address from non-local pub-key address.");
#endif

    CScript witscript = GetScriptForWitness(basescript);
    this->AddCScript(witscript);
    result = CScriptID(witscript);
  } else if (addr.GetScriptID(scriptID)) {
    CScript subscript;
    if (this->GetCScript(scriptID, subscript)) {
      int witnessversion;
      std::vector<unsigned char> witprog;
      if (subscript.IsWitnessProgram(witnessversion, witprog)) {
        /* ID is already for a witness program script */
        result = scriptID;
      } else {
#if 0
        //isminetype typ;
        //typ = IsMine(*pthisMain, subscript, SIGVERSION_WITNESS_V0);
        //if (typ != ISMINE_SPENDABLE && typ != ISMINE_WATCH_SOLVABLE)
        if (!::IsMine(*this, subscript, true))
          return error(SHERR_ACCESS, "GetWitnessAddress: cannot create witness address from non-local script address.");
#endif

        CScript witscript = GetScriptForWitness(subscript);
        this->AddCScript(witscript);
        result = CScriptID(witscript);
      }
    }
  } else {
    return error(SHERR_ACCESS, "GetWitnessAddress: cannot create witness address from non-standard address.");
  }

  /* retain in addressbook in order to identify */
  this->SetAddressBookName(result, strAccount);

  /* fill in return variable */
  witAddr = CCoinAddr(ifaceIndex, result);

  return (true);
}



int64 CWallet::CalculateFee(CTransaction& tx, int64 nMinFee)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  int64 nBytes;
  int64 nFee;

  nBytes = (int64)GetVirtualTransactionSize(tx); 
  //nBytes = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION(iface));

  /* base fee */
  nFee = GetFeeRate() * (1 + (nBytes / 1000));
  /* dust penalty */
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    if (out.nValue < CENT)
      nFee += MIN_TX_FEE(iface);
  }
  nFee = MAX(nFee, nMinFee);

  int64 nEstFee = 0;
  CBlockPolicyEstimator *est = GetFeeEstimator(iface);
  if (est) {
    static const unsigned int confTarget = 2;
    nEstFee = est->estimateSmartFee(confTarget, NULL).GetFee(nBytes);
    if (nEstFee > nFee) {
      nFee = nEstFee;
      Debug("CWallet.CalculateFee: using estimated fee %f.", (double)nFee/COIN);
    }
  }

  /* constraints */
  nFee = MAX(nFee, (int64)MIN_RELAY_TX_FEE(iface));
  nFee = MIN(nFee, (int64)MAX_TRANSACTION_FEE(iface) - 1);

//fprintf(stderr, "DEBUG: CalculateFee: nBytes(%d) nFee(%f) nEstFee(%f) FeeRate(%f): %s\n", (int)nBytes, (double)nFee/COIN, (double)nEstFee/COIN, (double)GetFeeRate()/COIN, tx.ToString(ifaceIndex).c_str()); 

  return (nFee);
}


bool CWallet::FillInputs(const CTransaction& tx, tx_cache& inputs, bool fAllowSpent)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!iface || !iface->enabled)
    return (false);

  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    COutPoint prevout = tx.vin[i].prevout;

    if (inputs.count(prevout.hash))
      continue;

    CTransaction prevTx;
    const uint256& prev_hash = prevout.hash;
    if (!::GetTransaction(iface, prev_hash, prevTx, NULL))
      return (false);

#ifndef USE_LEVELDB_COINDB
    if (!fAllowSpent) {
      vector<uint256> vOuts;
      if (!prevTx.ReadCoins(ifaceIndex, vOuts)) {
        return (error(SHERR_INVAL, "FillInputs: error reading tx from coin database."));
      }
      if (prevout.n >= vOuts.size()) {
        return (error(SHERR_INVAL, "FillInputs: error reading tx from coin database [invalid index]."));
      }
      if (!vOuts[prevout.n].IsNull()) {
        /* already spent */
        return (error(SHERR_ALREADY, "FillInputs: transaction has spent coins."));
      }
    }
#endif

    inputs[prev_hash] = prevTx;
  }

  return (true);
}

double CWallet::GetPriority(const CTransaction& tx, tx_cache& inputs)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  double dPriority = 0;

  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    const CTxIn& input = tx.vin[i];
    tx_cache::const_iterator mi = inputs.find(input.prevout.hash);
    if (mi == inputs.end()) continue;

    const CTransaction& txPrev = (mi->second);
    if (input.prevout.n >= txPrev.vout.size()) continue;

    const CTxOut& out = txPrev.vout[input.prevout.n];
    dPriority += out.nValue * txPrev.GetDepthInMainChain(ifaceIndex);
  }
  int64 nBytes = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION(iface));
  dPriority /= nBytes;

  return (dPriority);
}

#if 0
int64 core_GetFeeRate(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  int64 nVal;
  int nTot;

  nVal = MIN_TX_FEE(iface);
  nTot = 1;

  { /* determine absolute minimum fee */
    LOCK(cs_vNodes);
    NodeList &vNodes = GetNodeList(ifaceIndex);
    BOOST_FOREACH(CNode* pnode, vNodes) {
      if (pnode->nMinFee == 0)
        continue;

      nVal += pnode->nMinFee;
      nTot++;
    }
  }

  /* scan recent blocks for average tx fee */
  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  CWallet *wallet = GetWallet(iface);
  int nr = 0;
  while (pindexBest) {
    nr++;
    if (nr >= 32) break;

    CBlock *block = GetBlockByHeight(iface, pindexBest->nHeight);
    BOOST_FOREACH(const CTransaction& tx, block->vtx) {
      if (tx.IsCoinBase())
        continue; 

      int64 nFee = wallet->GetTxFee(tx);
      if (nFee < MIN_TX_FEE(iface) || nFee >= MAX_TRANSACTION_FEE(iface))
        continue;

      nVal += nFee;
      nTot++;
    }
    
    delete block;
  }

  return (nVal / (int64)nTot);
}
#endif
int64 core_GetFeeRate(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (0);
  return (MIN_TX_FEE(iface));
}

void CWalletTx::AddSupportingTransactions()
{
  int ifaceIndex = pwallet->ifaceIndex;

  vtxPrev.clear();

  const int COPY_DEPTH = 3;
  if (SetMerkleBranch(ifaceIndex) < COPY_DEPTH)
  {
    vector<uint256> vWorkQueue;
    BOOST_FOREACH(const CTxIn& txin, vin) {
      vWorkQueue.push_back(txin.prevout.hash);
    }

    {
      LOCK(pwallet->cs_wallet);
      map<uint256, const CMerkleTx*> mapWalletPrev;
      set<uint256> setAlreadyDone;
      for (unsigned int i = 0; i < vWorkQueue.size(); i++)
      {
        uint256 hash = vWorkQueue[i];
        if (setAlreadyDone.count(hash))
          continue;
        setAlreadyDone.insert(hash);

        CMerkleTx tx;
        map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(hash);
        if (mi != pwallet->mapWallet.end())
        {
          tx = (*mi).second;
          BOOST_FOREACH(const CMerkleTx& txWalletPrev, (*mi).second.vtxPrev)
            mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
        }
        else if (mapWalletPrev.count(hash))
        {
          tx = *mapWalletPrev[hash];
        }
        else if (!fClient && tx.ReadTx(ifaceIndex, hash))
        {
          ;
        }
        else
        {
          error(SHERR_INVAL, "AddSupportingTransactions: unsupported transaction: %s", hash.GetHex().c_str());
          continue;
        }

        if (tx.IsCoinBase())
          continue;

        int nDepth = tx.SetMerkleBranch(ifaceIndex);
        vtxPrev.push_back(tx);

        if (nDepth < COPY_DEPTH)
        {
          BOOST_FOREACH(const CTxIn& txin, tx.vin) {
            vWorkQueue.push_back(txin.prevout.hash);
          }
        }
      }
    }
  }

  reverse(vtxPrev.begin(), vtxPrev.end());
}



#ifdef USE_LEVELDB_COINDB

#if 0
void CWalletTx::AddSupportingTransactions(CTxDB& txdb)
{
  int ifaceIndex = txdb.ifaceIndex;

  vtxPrev.clear();

  const int COPY_DEPTH = 3;
  if (SetMerkleBranch(ifaceIndex) < COPY_DEPTH)
  {
    vector<uint256> vWorkQueue;
    BOOST_FOREACH(const CTxIn& txin, vin) {
      vWorkQueue.push_back(txin.prevout.hash);
}

    // This critsect is OK because txdb is already open
    {
      LOCK(pwallet->cs_wallet);
      map<uint256, const CMerkleTx*> mapWalletPrev;
      set<uint256> setAlreadyDone;
      for (unsigned int i = 0; i < vWorkQueue.size(); i++)
      {
        uint256 hash = vWorkQueue[i];
        if (setAlreadyDone.count(hash))
          continue;
        setAlreadyDone.insert(hash);

        CMerkleTx tx;
        map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(hash);
        if (mi != pwallet->mapWallet.end())
        {
          tx = (*mi).second;
          BOOST_FOREACH(const CMerkleTx& txWalletPrev, (*mi).second.vtxPrev)
            mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
        }
        else if (mapWalletPrev.count(hash))
        {
          tx = *mapWalletPrev[hash];
        }
        else if (!fClient && txdb.ReadDiskTx(hash, tx))
        {
          ;
        }
        else
        {
          error(SHERR_INVAL, "AddSupportingTransactions: unsupported transaction: %s", hash.GetHex().c_str());
          continue;
        }

        if (tx.IsCoinBase())
          continue;

        int nDepth = tx.SetMerkleBranch(ifaceIndex);
        vtxPrev.push_back(tx);

        if (nDepth < COPY_DEPTH)
        {
          BOOST_FOREACH(const CTxIn& txin, tx.vin) {
            vWorkQueue.push_back(txin.prevout.hash);
          }
        }
      }
    }
  }

  reverse(vtxPrev.begin(), vtxPrev.end());
}
#endif

bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs)
{
  CIface *iface = GetCoinByIndex(txdb.ifaceIndex);
  CTxMemPool *pool;

  pool = GetTxMemPool(iface);
  if (!pool) {
    unet_log(txdb.ifaceIndex, "error obtaining tx memory pool");
    return (false);
  }

  // Add previous supporting transactions first
  BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
  {
    if (!tx.IsCoinBase())
    {
      uint256 hash = tx.GetHash();
      if (!pool->exists(hash) && !txdb.ContainsTx(hash))
        pool->AddTx(tx);
    }
  }

  return pool->AddTx(*this);//AcceptToMemoryPool(txdb, fCheckInputs);
}

#else


bool CWalletTx::AcceptWalletTransaction()
{
  CIface *iface = GetCoinByIndex(pwallet->ifaceIndex);
  CTxMemPool *pool;

  pool = GetTxMemPool(iface);
  if (!pool) {
    unet_log(pwallet->ifaceIndex, "error obtaining tx memory pool");
    return (false);
  }

  /* Add previous supporting transactions first */
  BOOST_FOREACH(CMerkleTx& tx, vtxPrev) {
    pool->AddTx(tx);
  }

  return pool->AddTx(*this);
}


#endif

