
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

#ifndef __SERVER__KEYSTORE_H__
#define __SERVER__KEYSTORE_H__

#include "crypter.h"
#include "sync.h"
#include "eckey.h"
#include "dikey.h"

class CScript;

/** A virtual base class for key stores */
class CKeyStore
{
protected:
    mutable CCriticalSection cs_KeyStore;

public:
    virtual ~CKeyStore() {}

    /* Add an ECDSA key to the store. */
    virtual bool AddKey(ECKey& key) =0;

    /* Add an DILITHIUM key to the store. */
    virtual bool AddKey(DIKey& key) =0;

    // Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const =0;
#if 0
    virtual bool GetKey(const CKeyID &address, HDPrivKey& keyOut) const =0;
#endif

    virtual bool GetECKey(const CKeyID &address, ECKey& keyOut) const =0;

    virtual bool GetDIKey(const CKeyID &address, DIKey& keyOut) const =0;

    virtual CKey *GetKey(const CKeyID &address) const = 0;

    virtual void GetKeys(std::set<CKeyID> &setAddress) const =0;
    virtual bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;

    // Support for BIP 0013 : see https://en.bitcoin.it/wiki/BIP_0013
    virtual bool AddCScript(const CScript& redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const =0;

    virtual bool GetSecret(const CKeyID &address, CSecret& vchSecret, bool &fCompressed) const
		{
			const CKey *key;

			if (!(key = GetKey(address)))
				return (false);

			vchSecret = key->GetSecret(fCompressed);
			return (true);
    }

};

typedef std::map<CKeyID, ECKey> ECKeyMap;
typedef std::map<CKeyID, DIKey> DIKeyMap;
typedef std::map<CScriptID, CScript > ScriptMap;


/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore
{
protected:
    ECKeyMap mapECKeys;
    DIKeyMap mapDIKeys;
    ScriptMap mapScripts;

public:
//    bool AddKey(const HDPrivKey& key);

    bool AddKey(ECKey& key);

    bool AddKey(DIKey& key);

    bool HaveKey(const CKeyID &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapECKeys.count(address) > 0);
						if (!result)
							result = (mapDIKeys.count(address) > 0);
        }
        return result;
    }
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            ECKeyMap::const_iterator mi = mapECKeys.begin();
            while (mi != mapECKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
        {
            LOCK(cs_KeyStore);
            DIKeyMap::const_iterator mi = mapDIKeys.begin();
            while (mi != mapDIKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }
#if 0
    bool GetKey(const CKeyID &address, HDPrivKey &keyOut) const
    {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end())
            {
                keyOut = HDPrivKey((*mi).second.first, (*mi).second.second);
#if 0
                keyOut.Reset();
                keyOut.SetSecret((*mi).second.first, (*mi).second.second);
#endif
                return true;
            }
        }
        return false;
    }
#endif

    bool GetECKey(const CKeyID &address, ECKey &keyOut) const;

    bool GetDIKey(const CKeyID &address, DIKey &keyOut) const;

    CKey *GetKey(const CKeyID &address) const;

    CKeyMetadata *GetKeyMetadata(const CKeyID &address) const;

    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID &hash) const;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const;
};

typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;


#endif /* ndef __SERVER__KEYSTORE_H__ */

