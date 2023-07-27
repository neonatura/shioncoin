
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

#include "shcoind.h"
#include "wallet.h"
#include "main.h"
#include "keystore.h"
#include "script.h"

bool CKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
#if 0
  ECKey key;

  if (!GetKey(address, key))
    return false;

  vchPubKeyOut = key.GetPubKey();
#endif
	CKey *key = GetKey(address);
	if (!key)
		return (false);
  vchPubKeyOut = key->GetPubKey();
  return true;
}

#if 0
bool CBasicKeyStore::AddKey(const HDPrivKey& key)
{
    bool fCompressed = false;
    CSecret secret = key.GetSecret(fCompressed);
    {
        LOCK(cs_KeyStore);
        mapKeys[key.GetPubKey().GetID()] = make_pair(secret, fCompressed);
    }
    return true;
}
#endif

bool CBasicKeyStore::AddKey(ECKey& key)
{
	const CPubKey& pubkey = key.GetPubKey();
	const CKeyID& keyid = pubkey.GetID();

	{
		LOCK(cs_KeyStore);
		mapECKeys[keyid] = key;
	}

	return (true);
}

bool CBasicKeyStore::AddKey(DIKey& key)
{

	const CPubKey& pubkey = key.GetPubKey();
	const CKeyID& keyid = pubkey.GetID();

	{
		LOCK(cs_KeyStore);
		mapDIKeys[keyid] = key;
	}

	return (true);
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    {
        LOCK(cs_KeyStore);
        mapScripts[redeemScript.GetID()] = redeemScript;
    }
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    bool result;
    {
        LOCK(cs_KeyStore);
        result = (mapScripts.count(hash) > 0);
    }
    return result;
}


bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    {
        LOCK(cs_KeyStore);
        ScriptMap::const_iterator mi = mapScripts.find(hash);
        if (mi != mapScripts.end())
        {
            redeemScriptOut = (*mi).second;
            return true;
        }
    }
    return false;
}

#if 0
bool CCryptoKeyStore::SetCrypted()
{
#if 0
    {
        LOCK(cs_KeyStore);
        if (fUseCrypto)
            return true;
        if (!mapECKeys.empty())
            return false;
        fUseCrypto = true;
    }
#endif
    return true;
}
#endif

#if 0
bool CCryptoKeyStore::Lock()
{
#if 0
    if (!SetCrypted())
        return false;

    {
        LOCK(cs_KeyStore);
        vMasterKey.clear();
    }
#endif

    //NotifyStatusChanged(this);
    return true;
}
#endif

#if 0
bool CCryptoKeyStore::Unlock(const CKeyingMaterial& vMasterKeyIn)
{
#if 0
    {
        LOCK(cs_KeyStore);
        if (!SetCrypted())
            return false;

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CSecret vchSecret;
            if(!DecryptSecret(vMasterKeyIn, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
                return false;
            if (vchSecret.size() != 32)
                return false;
            CKey key;
            key.SetPubKey(vchPubKey);
            key.SetSecret(vchSecret);
            if (key.GetPubKey() == vchPubKey)
                break;
            return false;
        }
        vMasterKey = vMasterKeyIn;
    }
    //NotifyStatusChanged(this);
#endif
    return true;
}
#endif

#if 0
bool CCryptoKeyStore::AddKey(const ECKey& key)
{
    {
        LOCK(cs_KeyStore);
				return CBasicKeyStore::AddKey(key);
		}
#if 0
    {
        LOCK(cs_KeyStore);
        if (!IsCrypted())
            return CBasicKeyStore::AddKey(key);

        std::vector<unsigned char> vchCryptedSecret;
        CPubKey vchPubKey = key.GetPubKey();
        bool fCompressed;
        if (!EncryptSecret(vMasterKey, key.GetSecret(fCompressed), vchPubKey.GetHash(), vchCryptedSecret))
            return false;

        if (!AddCryptedKey(key.GetPubKey(), vchCryptedSecret))
            return false;
    }
    return true;
#endif
}
#endif

#if 0
bool CCryptoKeyStore::AddKey(const HDPrivKey& key)
{
  {
    LOCK(cs_KeyStore);
		return CBasicKeyStore::AddKey(key);
	}
#if 0
  {
    LOCK(cs_KeyStore);
    if (!IsCrypted())
      return CBasicKeyStore::AddKey(key);

    std::vector<unsigned char> vchCryptedSecret;
    CPubKey vchPubKey = key.GetPubKey();
    bool fCompressed;
    if (!EncryptSecret(vMasterKey, key.GetSecret(fCompressed), vchPubKey.GetHash(), vchCryptedSecret))
      return false;

    if (!AddCryptedKey(key.GetPubKey(), vchCryptedSecret))
      return false;
  }
  return true;
#endif
}
#endif

#if 0
bool CCryptoKeyStore::AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    {
        LOCK(cs_KeyStore);
        if (!SetCrypted())
            return false;

        mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    }
    return true;
}
#endif

#if 0
bool CCryptoKeyStore::GetKey(const CKeyID &address, ECKey& keyOut) const
{
    {
        LOCK(cs_KeyStore);
				return CBasicKeyStore::GetKey(address, keyOut);
		}
#if 0
    {
        LOCK(cs_KeyStore);
        if (!IsCrypted())
            return CBasicKeyStore::GetKey(address, keyOut);

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
        if (mi != mapCryptedKeys.end())
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CSecret vchSecret;
            if (!DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
                return false;
            if (vchSecret.size() != 32)
                return false;
            keyOut.SetPubKey(vchPubKey);
            keyOut.SetSecret(vchSecret);
            return true;
        }
    }
    return false;
#endif
}
#endif

#if 0
bool CCryptoKeyStore::GetKey(const CKeyID &address, HDPrivKey& keyOut) const
{
    {
        LOCK(cs_KeyStore);
				return CBasicKeyStore::GetKey(address, keyOut);
		}
#if 0
    {
        LOCK(cs_KeyStore);
        if (!IsCrypted())
            return CBasicKeyStore::GetKey(address, keyOut);

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
        if (mi != mapCryptedKeys.end())
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CSecret vchSecret;
            if (!DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
                return false;
            if (vchSecret.size() != 32)
                return false;
            keyOut.SetPubKey(vchPubKey);
            keyOut.SetSecret(vchSecret);
            return true;
        }
    }
    return false;
#endif
}
#endif

#if 0
bool CCryptoKeyStore::GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    {
        LOCK(cs_KeyStore);
        if (!IsCrypted())
            return CKeyStore::GetPubKey(address, vchPubKeyOut);

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
        if (mi != mapCryptedKeys.end())
        {
            vchPubKeyOut = (*mi).second.first;
            return true;
        }
    }
    return false;
}
#endif

#if 0
bool CCryptoKeyStore::EncryptKeys(CKeyingMaterial& vMasterKeyIn)
{
#if 0
    {
        LOCK(cs_KeyStore);
        if (!mapCryptedKeys.empty() || IsCrypted())
            return false;

        fUseCrypto = true;
        BOOST_FOREACH(KeyMap::value_type& mKey, mapKeys)
        {
            CKey key;
            if (!key.SetSecret(mKey.second.first, mKey.second.second))
                return false;
            const CPubKey vchPubKey = key.GetPubKey();
            std::vector<unsigned char> vchCryptedSecret;
            bool fCompressed;
            if (!EncryptSecret(vMasterKeyIn, key.GetSecret(fCompressed), vchPubKey.GetHash(), vchCryptedSecret))
                return false;
            if (!AddCryptedKey(vchPubKey, vchCryptedSecret))
                return false;
        }
        mapKeys.clear();
    }
#endif
    return true;
}
#endif

bool CBasicKeyStore::GetECKey(const CKeyID &address, ECKey &keyOut) const
{
	{
		LOCK(cs_KeyStore);
		ECKeyMap::const_iterator mi = mapECKeys.find(address);
		if (mi != mapECKeys.end())
		{
			keyOut = (*mi).second;
			return true;
		}
	}
	return false;
}

bool CBasicKeyStore::GetDIKey(const CKeyID &address, DIKey &keyOut) const
{
	{
		LOCK(cs_KeyStore);
		DIKeyMap::const_iterator mi = mapDIKeys.find(address);
		if (mi != mapDIKeys.end())
		{
			keyOut = (*mi).second;
			return true;
		}
	}
	return false;
}

CKey *CBasicKeyStore::GetKey(const CKeyID &address) const
{

	{
		LOCK(cs_KeyStore);
		ECKeyMap::const_iterator mi = mapECKeys.find(address);
		if (mi != mapECKeys.end()) {
			return (CKey *)(&(*mi).second);
		}
	}

	{
		LOCK(cs_KeyStore);
		DIKeyMap::const_iterator mi = mapDIKeys.find(address);
		if (mi != mapDIKeys.end()) {
			return (CKey *)(&(*mi).second);
		}
	}

	return (NULL);
}

CKeyMetadata *CBasicKeyStore::GetKeyMetadata(const CKeyID &address) const
{

	CKey *key = GetKey(address);
	if (!key)
		return (NULL);

	return ((CKeyMetadata *)key);
}

void CBasicKeyStore::GetECKeys(std::set<CKeyID> &setAddress) const
{
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
}

void CBasicKeyStore::GetDIKeys(std::set<CKeyID> &setAddress) const
{
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
}

void CBasicKeyStore::GetKeys(std::set<CKeyID> &setAddress) const
{
	set<CKeyID> ecKeys;
	set<CKeyID> diKeys;

	setAddress.clear();

	GetECKeys(ecKeys);
	setAddress.insert(ecKeys.begin(), ecKeys.end());

	GetDIKeys(diKeys);
	setAddress.insert(diKeys.begin(), diKeys.end());
}

