
/*
 * @copyright
 *
 *  Copyright 2019 Brian Burrell
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

#include "test_shcoind.h"
#include <string>
#include <vector>
#include "wallet.h"
#include "txcreator.h"
#include "algobits.h"
#include "test/test_pool.h"
#include "test/test_block.h"
#include "test/test_txidx.h"

struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    explicit TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.push_back(TestDerivation());
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

static TestVector test =
  TestVector("000102030405060708090a0b0c0d0e0f")
    (
		 "xpub661MyMwAqRbcEb8K6igAJA4igisrruQkrtLmsmE9gHwVNzn9sZCbUWQC5hfAEMaVLjWoBePSAoYWs1dSwFFL37bgPE1iz3mAHD5iUsgjxJi",
		 "xprv9s21ZrQH143K273qzh99w27z8h3NTSguVfRB5NpY7xQWWCT1L1tLvi5iESfFhFwDijdJHtwLbqbWmStUMUeWut4NgPtunpy7haqQnFhzotM",
     0x80000000)
    (
		 "xpub68raTJVBUsr9T5AiCUR4HRNTfSaGjYiNbhAXAzJEUQSRTsbCiCvH8xCqY2gRx5QDd8gzBZs5zvXS8xChwkWtur9nBMgjpBB34FiEGfN4F2b",
		 "xprv9usE3nxHeWHrEb6F6St3vHRj7QjnL5zXEUEvNbtcv4uSb5G4Afc2b9tMgks416VEwEudJJQwendifgKr8JGzufxC3S7vzHSs8RHLcfy2QX5",
     1)
    (
		 "xpub6ARpD1wNvXwL72CeUGi8V3UtnVL2Pqc15bktM9vPRoSx3jfMEycH9vvQQ5ydv1RuvhFZevjjGVaTVWZ3emBuVNFGgscpz4LNRad75ZjcxLd",
		 "xprv9wSToWQV6AP2tY8BNFB87uYAETVXzNt9iNqHYmWmsTuyAwLChSJ2c8bvYpuK4st4JiDjSE5hrdN32XHDuqGZ1SCUAAcrfsDrJi2oUMYH2Pz",
     0x80000002)
    (
		 "xpub6Bmd9sYLiw4ymRDUjy2nyTTMC9gDnTvzYoqHXbyNFYVWrq27XpBQp94nZthdpjeK8TFW6PwrrpjLMpTyfQpndQHJLvwSmKGDZSQSfxDKqwt",
		 "xprv9xnGkN1StZWgYw91dwVncKWce7qjP1D9BaugjDZkhCxXz2gxzGsAGLkJid8BgD3DTVt6EbFuT4EGyjxyj5eXNajHaPgK2uA4AfjZrSuJ158",
     2)
    (
		 "xpub6DnPVtWCeUARWZtbk1ME7gWCEBK3NYsycbPH9ZH1s4PXzT3TMzY74riG4QcruMPSJyLznzHHkDwTVSczUaa4MLNgg4PSzepDFDQK1FPQiZm",
		 "xprv9zo36NyJp6c8J5p8dypDkYZTg9UYy6A8FNTgMAsQJirZ7eiJpTDrX4PnD8XErKpfg9Y9XZ847idEEHhfCqfW77GuSznwJY1ZGkKtdadC4hD",
     1000000000)
    (
		 "xpub6FnYBigC3AaKr6wpU63CasRbQh8cYNVVGXCCNZtdY8M3hJvHJBnb1TvukFpaCRmBrTxSjbXwm5mseeHWLXrnnU79BTU47n8FcMWdCTKZDuv",
		 "xprvA2oBnD9JCo22dcsMN4WCDjUrrfJ88umduJGbaBV1ynp4pWb8keULTfcRu1g5Dn1nbgAmdLD7KTKqnbMBxddeokDgZikqz5CuxCttAPD2N7y",
     0);

enum Base58Type {
	PUBKEY_ADDRESS,
	SCRIPT_ADDRESS,
	SCRIPT_ADDRESS2,
	SECRET_KEY,
	EXT_PUBLIC_KEY,
	EXT_SECRET_KEY,

	MAX_BASE58_TYPES
};

static std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];


static const std::vector<unsigned char>& Base58Prefix(Base58Type type) 
{ 

#if 0
	base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
	base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
	base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
	base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
	base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
	base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
#endif
	base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,48);
	base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
	base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,50);
	base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,176);
	base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
	base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};


	return base58Prefixes[type]; 
}


template<typename K, int Size, Base58Type Type> class CBitcoinExtKeyBase : public CBase58Data
{
	public:
		void SetKey(const K &key) {
			unsigned char vch[Size];
			key.Encode(vch);
			SetData(Base58Prefix(Type), vch, vch+Size);
		}

		K GetKey() {
			K ret;
			if (vchData.size() == Size) {
				// If base58 encoded data does not hold an ext key, return a !IsValid() key
				ret.Decode(vchData.data());
			}
			return ret;
		}

		CBitcoinExtKeyBase(const K &key) {
			SetKey(key);
		}

		CBitcoinExtKeyBase(const std::string& strBase58c) {
			SetString(strBase58c.c_str(), Base58Prefix(Type).size());
		}

		CBitcoinExtKeyBase() {}
};

typedef CBitcoinExtKeyBase<ECExtKey, BIP32_EXTKEY_SIZE, EXT_SECRET_KEY> CBitcoinExtKey;
typedef CBitcoinExtKeyBase<ECExtPubKey, BIP32_EXTKEY_SIZE, EXT_PUBLIC_KEY> CBitcoinExtPubKey;

#ifdef __cplusplus
extern "C" {
#endif

_TEST(bip32_hdkey)
{
	std::vector<unsigned char> seed = ParseHex(test.strHexMaster);
	ECExtKey key;
	ECExtPubKey pubkey;
	key.SetMaster(seed.data(), seed.size());
	pubkey = key.Neuter();
	for (const TestDerivation &derive : test.vDerive) {
#if 0
		unsigned char data[74];
		key.Encode(data);
		pubkey.Encode(data);
#endif

		// Test private key
		CBitcoinExtKey b58key; b58key.SetKey(key);
//		_TRUE(b58key.ToString() == derive.prv);

		CBitcoinExtKey b58keyDecodeCheck(derive.prv);
		ECExtKey checkKey = b58keyDecodeCheck.GetKey();
		_TRUE(checkKey == key);
		//        assert(checkKey == key); //ensure a base58 decoded key also matches

		// Test public key
		CBitcoinExtPubKey b58pubkey; b58pubkey.SetKey(pubkey);
		_TRUE(b58pubkey.ToString() == derive.pub);

		CBitcoinExtPubKey b58PubkeyDecodeCheck(derive.pub);
		ECExtPubKey checkPubKey = b58PubkeyDecodeCheck.GetKey();
		_TRUE(checkPubKey == pubkey);
		//        assert(checkPubKey == pubkey); //ensure a base58 decoded pubkey also matches

		// Derive new keys
		ECExtKey keyNew;
		_TRUE(key.Derive(keyNew, derive.nChild) == true);
		ECExtPubKey pubkeyNew = keyNew.Neuter();
		if (!(derive.nChild & 0x80000000)) {
			// Compare with public derivation
			ECExtPubKey pubkeyNew2;
			_TRUE(pubkey.Derive(pubkeyNew2, derive.nChild) == true);
			_TRUE(pubkeyNew == pubkeyNew2);
		}
		key = keyNew;
		pubkey = pubkeyNew;

		CDataStream ssPub(SER_DISK, CLIENT_VERSION);
		ssPub << pubkeyNew;
		_TRUE(ssPub.size() == 75);

		CDataStream ssPriv(SER_DISK, CLIENT_VERSION);
		ssPriv << keyNew;
		_TRUE(ssPriv.size() == 75);

		ECExtPubKey pubCheck;
		ECExtKey privCheck;
		ssPub >> pubCheck;
		ssPriv >> privCheck;

		_TRUE(pubCheck == pubkeyNew);
		_TRUE(privCheck == keyNew);
	}
}

#ifdef __cplusplus
}
#endif
