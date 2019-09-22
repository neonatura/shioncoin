
/*
 * @copyright
 *
 *  Copyright 2019 Neo Natura
 *
 *  This file is part of ShionCoin.
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
#include "account.h"
#include "txcreator.h"
#include "bech32.h"
#include "test/test_pool.h"
#include "test/test_block.h"
#include "test/test_txidx.h"
#include "script.h"



#ifdef __cplusplus
extern "C" {
#endif


_TEST(account_cache)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
	CAccountCache *acc = wallet->GetAccount("");
	string strAccount("");

	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

	/* static addr returns primary */
	const CCoinAddr& n_addr = acc->GetAddr(ACCADDR_NOTARY);
	{
		CTxDestination dest;
		/* primary address for type. */
		_TRUE(acc->GetPrimaryAddr(ACCADDR_NOTARY, dest));
		_TRUE(dest == n_addr.Get());
	}

	/* recv address is dynamic. */
	const CCoinAddr& c_addr1 = acc->GetAddr(ACCADDR_RECV);
	{
		const CCoinAddr& c_addr2 = acc->GetAddr(ACCADDR_RECV);
		_TRUE(c_addr1.Get() == c_addr2.Get());

		CTxCreator wtx1(wallet, strAccount);
		wtx1.AddOutput(c_addr1.Get(), COIN);
		_TRUE(wtx1.Send());
		for (int i = 0; i < 2; i++) {
			CBlock *block = test_GenerateBlock();
			_TRUEPTR(block);
			_TRUE(ProcessBlock(NULL, block) == true);
			delete block;
		}
		_TRUE(wtx1.IsInMemoryPool(TEST_COIN_IFACE) == false);

		const CCoinAddr& c_addr3 = acc->GetAddr(ACCADDR_RECV);
		_FALSE(c_addr1.Get() == c_addr3.Get());
	}

	opt_bool_set(OPT_HDKEY, TRUE);
	opt_bool_set(OPT_DILITHIUM, FALSE);

	/* ecdsa derive bech32 */
	opt_bool_set(OPT_BECH32, TRUE);
	CAccount *hdChain = &acc->account;
	CAccount hdChainCopy = *hdChain;
	ECKey eckey;
	_TRUE(wallet->DeriveNewECKey(&hdChainCopy, eckey));
//	_TRUE(wallet->AddKey(eckey));
//	acc->SetAddrDestinations(eckey.GetPubKey().GetID(), 0);
	acc->ResetAddr(ACCADDR_RECV);
	const CCoinAddr& r_bech32_addr = acc->GetAddr(ACCADDR_RECV);
	/* ecdsa compare */
	CCoinAddr ecaddr(wallet->ifaceIndex, eckey.GetPubKey().GetID());
//	CCoinAddr wit_ecaddr(wallet->ifaceIndex);
	//_TRUE(wallet->GetWitnessAddress(ecaddr, wit_ecaddr));
	CTxDestination witDest = ecaddr.GetWitness();
	CCoinAddr wit_ecaddr(TEST_COIN_IFACE, witDest); 
	_TRUE(wit_ecaddr.Get() == r_bech32_addr.Get());

	/* dilithium derive bech32 */
	opt_bool_set(OPT_DILITHIUM, TRUE);
	hdChainCopy = *hdChain;
	DIKey dikey;
	_TRUE(wallet->DeriveNewDIKey(&hdChainCopy, dikey));
//	_TRUE(wallet->AddKey(dikey));
//	acc->SetAddrDestinations(dikey.GetPubKey().GetID(), ACCADDRF_DILITHIUM);
	acc->ResetAddr(ACCADDR_RECV);
	const CCoinAddr& r_di_addr = acc->GetAddr(ACCADDR_RECV);
	/* dilithium compare */
	CCoinAddr diaddr(wallet->ifaceIndex, dikey.GetPubKey().GetID());
	//CCoinAddr wit_diaddr(wallet->ifaceIndex);
	//_TRUE(wallet->GetWitnessAddress(diaddr, wit_diaddr));
	CTxDestination wit_didest = diaddr.GetWitness();
	CCoinAddr wit_diaddr(TEST_COIN_IFACE, wit_didest); 
	_TRUE(wit_diaddr.Get() == r_di_addr.Get());

	{
		CBlock *block = test_GenerateBlock();
		_TRUEPTR(block);
		_TRUE(ProcessBlock(NULL, block) == true);
		delete block;
	}

}


#ifdef __cplusplus
}
#endif
