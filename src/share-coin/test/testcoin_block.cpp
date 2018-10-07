
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

#include "test_shcoind.h"
#include <sexe.h>
#include <string>
#include <vector>
#include "wallet.h"
#include "txcreator.h"
#include "test/test_pool.h"
#include "test/test_block.h"
#include "test/test_txidx.h"

#include "offer.h"
#include "asset.h"
#include "spring.h"
#include "hdkey.h"
#include "context.h"
#include "script.h"
#include "txsignature.h"



#ifdef __cplusplus
extern "C" {
#endif


_TEST(blockchain)
{
  bc_t *bc;
  bc_hash_t hash[10];
  bc_hash_t t_hash;
  char buf[10240];
  unsigned char *t_data;
  size_t t_data_len;
  int idx;
  bcpos_t n_pos;
  bcpos_t pos;
	bcpos_t t_pos;
  int err;

  err = bc_open("rawtest", &bc);
  _TRUE(err == 0);

  srand(time(NULL));

	(void)bc_idx_next(bc, &n_pos);

  for (idx = 0; idx < 10; idx++) {
    buf[0] = (rand() % 254);
    buf[1] = (rand() % 254);
    buf[2] = (rand() % 254);
    memset(buf + 3, (rand() % 254), sizeof(buf) - 3);

    memcpy(hash[idx], buf + 1, sizeof(hash[idx]));

    err = bc_append(bc, hash[idx], buf, sizeof(buf));
    _TRUE(err == 0);

    err = bc_find(bc, hash[idx], &pos);
    _TRUE(err == 0);

		bc_idx_next(bc, &t_pos);
		_TRUE( (pos+1) == (t_pos) );

    err = bc_get(bc, pos, &t_data, &t_data_len);
    _TRUE(err == 0);
    _TRUE(t_data_len == sizeof(buf));

    _TRUE(0 == memcmp(t_data, buf, t_data_len));
    free(t_data);

    memset(t_hash, 255, sizeof(t_hash));
    err = bc_find(bc, t_hash, NULL);
    _TRUE(err == SHERR_NOENT);
  }

  err = bc_purge(bc, n_pos + 1);
  _TRUE(err == 0);

  /* re-write purged records. */
  for (idx = 1; idx < 10; idx++) {
    bcsize_t a_pos;
    _TRUE(!(err = bc_arch_find(bc, hash[idx], NULL, &a_pos)));
    _TRUE(!(err = bc_arch(bc, a_pos, &t_data, &t_data_len)));
    _TRUEPTR(t_data);
    /* verify hash */  
    memcpy(t_hash, t_data + 1, sizeof(t_hash));
    _TRUE(0 == memcmp(hash[idx], t_hash, sizeof(bc_hash_t)));
    /* add back to main chain */
    _TRUE(0 == bc_write(bc, n_pos + idx, hash[idx], t_data, t_data_len));
    free(t_data);
  }
  
	bc_idx_next(bc, &t_pos);
  _TRUE(t_pos == (n_pos + 10));

  bc_close(bc);
}

_TEST(truncate)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CBlock *blocks[30];
  int of;
  int i, j;

  of = GetBestHeight(iface) + 1;

  /* create some blocks */
  for (i = 0; i < 20; i++) { 
    blocks[i] = test_GenerateBlock();
    _TRUEPTR(blocks[i]);
    _TRUE(ProcessBlock(NULL, blocks[i]) == true);
  }

  blocks[9]->Truncate();

  for (i = 20; i < 30; i++) { 
    blocks[i] = test_GenerateBlock();
    _TRUEPTR(blocks[i]);
    _TRUE(ProcessBlock(NULL, blocks[i]) == true);

    for (j = 10; j < 20; j++) {
      _TRUE(blocks[j]->GetHash() != blocks[i]->GetHash());
    }

  }

  for (i = 20; i < 30; i++) {
    CBlock *cmp_block = GetBlockByHeight(iface, i + of - 10);
    _TRUE(cmp_block->GetHash() == blocks[i]->GetHash());
    delete cmp_block;
  }

  for (j = 10; j < 20; j++) {
    CBlock *cmp_block = GetBlockByHeight(iface, j + of);
    _TRUE(cmp_block->GetHash() != blocks[j]->GetHash());
    delete cmp_block;
  }

}

_TEST(reorganize)
{
  blkidx_t *blockIndex = GetBlockTable(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CBlock *parent;
  CBlock *chain1;
  CBlock *chain2;
  CBlock *chain3;
  CBlock *blocks[40];
  uint256 hashParent;
shtime_t ts;
  int i;

  /* battle1 : start */
  parent = test_GenerateBlock();
  _TRUEPTR(parent);
  hashParent = parent->GetHash();
  _TRUE(ProcessBlock(NULL, parent) == true);
  delete parent;
  /* battle1 : finish */

  /* battle2 : start */
  chain1 = test_GenerateBlock();
  _TRUEPTR(chain1);
  chain2 = test_GenerateBlock();
  _TRUEPTR(chain2);
  chain3 = test_GenerateBlock();
  _TRUEPTR(chain3);
  _TRUE(ProcessBlock(NULL, chain1) == true);
  _TRUE(ProcessBlock(NULL, chain2) == true);
  _TRUE(GetBestBlockChain(iface) == chain1->GetHash()); /* verify mem */
  CBlock *t_block = GetBlockByHeight(iface, 2);
  _TRUEPTR(t_block);
  _TRUE(t_block->GetHash() == chain1->GetHash()); /* verify disk */
  delete t_block;
  /* battle2 : finish */

  /* battle3 : start */
  for (i = 0; i < 39; i++) { 
    blocks[i] = test_GenerateBlock();
    _TRUEPTR(blocks[i]);
    _TRUE(ProcessBlock(NULL, blocks[i]) == true);
  }
  blocks[39] = test_GenerateBlock();
  _TRUEPTR(blocks[39]);

  _TRUE(ProcessBlock(NULL, chain3) == true); /* ALT CHAIN */

  _TRUE(ProcessBlock(NULL, blocks[39]) == true);
  /* battle3 : finish */

  t_block = GetBlockByHeight(iface, 0);
  _TRUEPTR(t_block); 
  _TRUE(t_block->GetHash() == test_hashGenesisBlock);
  delete(t_block);

  t_block = GetBlockByHeight(iface, 1);
  _TRUEPTR(t_block); 
  _TRUE(t_block->GetHash() == hashParent); 
  delete(t_block);

  for (i = 0; i < 40; i++) {
    int nHeight = 3 + i;
    t_block = GetBlockByHeight(iface, nHeight);
    _TRUEPTR(t_block); 
    _TRUE(t_block->GetHash() == blocks[i]->GetHash());
    delete t_block;
  }

  CBlockIndex *pindexBest = GetBestBlockIndex(iface);
  _TRUEPTR(pindexBest);
  _TRUE(pindexBest->GetBlockHash() == blocks[39]->GetHash());
  _TRUE(pindexBest->nHeight == 42);

  for (i = 0; i < 40; i++) { 
    delete(blocks[i]);
  }

  delete chain3;
  delete chain2;
  delete chain1;

  /* battle4 : begin */
  {
    /* create parent */
    CBlock *par_block = test_GenerateBlock();
    _TRUEPTR(par_block);
    _TRUE(ProcessBlock(NULL, par_block) == true);
    delete par_block;
    CBlockIndex *pindex = GetBestBlockIndex(iface);

    /* orphan */
    CBlock *o_block = test_GenerateBlock();
    _TRUEPTR(o_block);
    _TRUE(ProcessBlock(NULL, o_block) == true);

    /* over-riding new */
    CBlock *n_block = test_GenerateBlock(pindex);
    _TRUEPTR(n_block);
    _TRUE(ProcessBlock(NULL, n_block) == true);
    uint256 nhash = n_block->GetHash();
    CBlockIndex *nindex = (*blockIndex)[nhash]; 
    _TRUEPTR(nindex);

#if 0
    {
      TESTTxDB txdb;
      _TRUE(n_block->SetBestChain(txdb, nindex)); 
      txdb.Close();
    }
#endif
    {
      /* create child of new */
      CBlock *t_block = test_GenerateBlock(nindex);
      _TRUEPTR(t_block);
      _TRUE(ProcessBlock(NULL, t_block) == true);

      /* verify */
      pindex = GetBestBlockIndex(iface);
      _TRUE(pindex->GetBlockHash() == t_block->GetHash());
      _TRUEPTR(pindex->pprev);
      _TRUE(pindex->pprev->GetBlockHash() == n_block->GetHash());

      delete t_block;
    }

    delete o_block;
    delete n_block;
  }
  /* battle4 : finish */

}

_TEST(serializetx)
{
  CDataStream ser(SER_DISK, DISK_VERSION);
  CDataStream a_ser(SER_DISK, DISK_VERSION);
  CDataStream e_ser(SER_DISK, DISK_VERSION);
  CTransaction tx;
  CTransaction cmp_tx;

	CTxIn txin;
	txin.scriptSig << OP_0;
	tx.vin.insert(tx.vin.end(), txin);
	CTxOut txout;
	txout.scriptPubKey << OP_0;
	tx.vout.insert(tx.vout.end(), txout);
  ser << tx;
  ser >> cmp_tx;
  _TRUE(tx.GetHash() == cmp_tx.GetHash());

  string strAlias("test");
  uint160 addrAlias("0x1");
  CAlias alias = CAlias(strAlias, addrAlias);
  CAlias cmp_alias;
  a_ser << alias;
  a_ser >> cmp_alias;
  _TRUE(alias.GetHash() == cmp_alias.GetHash());
tx.nFlag |= CTransaction::TXF_ALIAS;
tx.alias = alias;

  string strAsset("test");
char hashstr[256];
  strcpy(hashstr, "0x0");
  string strAssetHash(hashstr);
  CAsset asset(strAsset);//, strAssetHash);
  CAsset cmp_asset;
  a_ser << asset;
  a_ser >> cmp_asset;
  _TRUE(asset.GetHash() == cmp_asset.GetHash());

  CIdent ident;
  ident.SetLabel("test");
  CIdent cmp_ident;
  a_ser << ident;
  a_ser >> cmp_ident;
  _TRUE(ident.GetHash() == cmp_ident.GetHash());

  CCert cert = CCert();
  CCert cmp_cert;
  a_ser << cert;
  a_ser >> cmp_cert;
  _TRUE(cert.GetHash() == cmp_cert.GetHash());

  COffer offer = COffer();
  COffer cmp_offer;
  a_ser << offer;
  a_ser >> cmp_offer;
  _TRUE(offer.GetHash() == cmp_offer.GetHash());
//_TRUE(offer.accepts.first().GetHash() == cmp_offer.accepts.first().GetHash());

  CTransaction mtx;
  mtx.nFlag |= CTransaction::TXF_MATRIX;
  mtx.matrix.vData[0][0] = 1;
  mtx.matrix.vData[0][1] = 2;
  mtx.matrix.vData[1][0] = 3;
  mtx.matrix.nHeight = 1;
  CTransaction cmp_mtx;
  a_ser << mtx;
  a_ser >> cmp_mtx;
  _TRUE(mtx.matrix.GetHash() == cmp_mtx.matrix.GetHash());
  _TRUE(mtx.GetHash() == cmp_mtx.GetHash());

  CTxMatrix cmp_matrix;
  cmp_matrix.Init(mtx.matrix);
  _TRUE(mtx.matrix.GetHash() == cmp_matrix.GetHash());


}

_TEST(signtx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  string strAccount("");
  CCoinAddr extAddr = GetAccountAddress(wallet, strAccount, true);
  char *data;
  size_t data_len;
  bool ret;

	data = (char *)calloc(256, sizeof(char));
	strcpy(data, "secret");
  data_len = (size_t)sizeof(strlen("secret"));
  string strSecret(data);

  /* CExtCore.origin */
  CCert cert;
  cbuff vchContext(data, data + data_len);
  _TRUE(cert.signature.Sign(TEST_COIN_IFACE, extAddr, vchContext) == true);
  _TRUE(cert.signature.Verify(extAddr, (unsigned char *)data, data_len) == true);

  cert.SetNull();
  cbuff vchSecret(vchFromString(strSecret));
  _TRUE(cert.Sign(TEST_COIN_IFACE, extAddr, vchSecret) == true);
  _TRUE(cert.VerifySignature(vchSecret) == true);
 
#if 0
  CAsset asset;
  _TRUE(asset.Sign(&cert) == true);
  _TRUE(asset.VerifySignature(TEST_COIN_IFACE) == true);
#endif

  CLicense license;
  _TRUE(license.signature.SignOrigin(TEST_COIN_IFACE, extAddr) == true);
  _TRUE(license.signature.VerifyOrigin(extAddr) == true);

  free(data);
}

_TEST(cointx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  int idx;

  /* create a coin balance */
  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  bool found = false;
  string strAccount;
  CCoinAddr addr(TEST_COIN_IFACE);
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(TEST_COIN_IFACE, item.first);
    const string& account = item.second;
    addr = address;
    strAccount = account;
    found = true;
    break;
  }

  string strExtAccount = "*" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  CWalletTx wtx;
  wtx.SetNull();
	strAccount = "";
  wtx.strFromAccount = strAccount;

  int64 nFee = 18 * COIN;

  /* send to extended tx storage account */
  CScript scriptPubKey;
  scriptPubKey.SetDestination(extAddr.Get());

  for (idx = 0; idx < 3; idx++) {
    string strError = wallet->SendMoney(strAccount, scriptPubKey, nFee, wtx, false);
    _TRUE(strError == "");

    _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  }
}

_TEST(aliastx)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  int idx;
  int err;

  string strLabel("");

  /* create a coin balance */
  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CCoinAddr addr = GetAccountAddress(wallet, strLabel, false);
  _TRUE(addr.IsValid() == true);

  CWalletTx wtx;
  err = init_alias_addr_tx(iface, "test", addr, wtx);
  _TRUE(0 == err);

  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyAlias(wtx) == true);

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  /* update */

  CWalletTx mod_wtx;
  err = update_alias_addr_tx(iface, "test", addr, mod_wtx);
  _TRUE(0 == err);
  _TRUE(mod_wtx.CheckTransaction(TEST_COIN_IFACE) == true); /* .. */
  _TRUE(VerifyAlias(mod_wtx) == true);
  _TRUE(mod_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  /* insert into block-chain */
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  _TRUE(mod_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

  CTransaction t_tx;
  string strTitle("test");
  _TRUE(GetTxOfAlias(iface, strTitle, t_tx) == true);

  /* remove */

  CWalletTx rem_wtx;
  err = remove_alias_addr_tx(iface, strLabel, strTitle, rem_wtx);
  _TRUE(0 == err);
  _TRUE(rem_wtx.CheckTransaction(TEST_COIN_IFACE) == true); /* .. */
  _TRUE(VerifyAlias(rem_wtx) == true);
  _TRUE(rem_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  /* insert into block-chain */
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  _TRUE(rem_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);
  _TRUE(GetTxOfAlias(iface, strTitle, t_tx) == false);

}




_TEST(assettx)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  int idx;
  int err;


  string strLabel("");

  /* create a coin balance */
  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CCoinAddr addr = GetAccountAddress(wallet, strLabel, false);
  _TRUE(addr.IsValid() == true);

  CWalletTx wtx;
  err = init_asset_tx(iface, strLabel, "test", addr.ToString(), wtx);
  _TRUE(0 == err);

  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyAsset(wtx) == true);

  CAsset asset(wtx.certificate);
  uint160 hashAsset = asset.GetHash();

  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  err = update_asset_tx(iface, strLabel, hashAsset, "test", addr.ToString(), wtx);
  _TRUE(0 == err);

  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyAsset(wtx) == true);

// activate
  //_TRUE(asset.VerifySignature(TEST_COIN_IFACE));
}

_TEST(identtx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  CTxMemPool *pool = GetTxMemPool(iface);
  CWalletTx wtx;
  string strAccount("");
  int64 certFee;
  int64 orig_bal;
  int64 bal;
  int mode;
  int idx;
  int err;
  int i;

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }


  CWalletTx cert_wtx;
  string hexSeed;
  uint160 issuer;
  err = init_cert_tx(iface, cert_wtx, strAccount, "test", hexSeed, 1);
  _TRUE(0 == err);
  uint160 hashCert = cert_wtx.certificate.GetHash();

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  orig_bal = GetAccountBalance(TEST_COIN_IFACE, strAccount, 1);
  _TRUE(orig_bal > COIN + (iface->min_tx_fee * 2));

  certFee = GetCertOpFee(iface, GetBestHeight(iface)) + COIN;
  err = init_ident_donate_tx(iface, strAccount, certFee, hashCert, wtx);  
  _TRUE(err == 0);
  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyIdent(wtx, mode) == true);
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  for (i = 0; i < 2; i++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;

    orig_bal += GetBestHeight(iface) * (int64)COIN;
  }

  /* verify insertion into block-chain */
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

  bal = GetAccountBalance(TEST_COIN_IFACE, strAccount, 1);
  _TRUE(bal < orig_bal);

  orig_bal = bal;


  /* send certified coins to self */
  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);
  _TRUE(addr.IsValid() == true);

  CWalletTx csend_tx;
  certFee = GetCertOpFee(iface, GetBestHeight(iface));
  err = init_ident_certcoin_tx(iface, strAccount, certFee, hashCert, addr, csend_tx);
  _TRUE(err == 0);
  _TRUE(csend_tx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyIdent(csend_tx, mode) == true);

  for (idx = 0; idx < 3; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  bal = GetAccountBalance(TEST_COIN_IFACE, strAccount, 1); /* not counting to-be-matured coins */
  _TRUE(bal > orig_bal);

}

_TEST(certtx)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  int idx;
  int err;


  string strLabel("");

  /* create a coin balance */
  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CCoinAddr addr = GetAccountAddress(wallet, strLabel, false);
  _TRUE(addr.IsValid() == true);

  CWalletTx wtx;
  unsigned int nBestHeight = GetBestHeight(iface) + 1;
  {
    string hexSeed;
    err = init_cert_tx(iface, wtx, strLabel, "SHCOIND TEST CA", hexSeed, 1);
    _TRUE(0 == err);
  }
  uint160 hashCert = wtx.certificate.GetHash();

  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyCert(iface, wtx, nBestHeight) == true);
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  /* insert cert into chain */
  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  /* verify insertion */
  CTransaction t_tx;
  _TRUE(GetTxOfCert(iface, hashCert, t_tx) == true);
  _TRUE(t_tx.GetHash() == wtx.GetHash());
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);


  /* chained certificate */
  CWalletTx chain_wtx;
  string strTitle("SHCOIND TEST CHAIN");
  err = derive_cert_tx(iface, chain_wtx, hashCert, strLabel, strTitle);
  _TRUE(err == 0);
  _TRUE(chain_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyCert(iface, chain_wtx, nBestHeight) == true);
  _TRUE(chain_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  { /* insert derived cert into chain */
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  /* verify insertion */
  t_tx.SetNull();
  hashCert = chain_wtx.certificate.GetHash();
  _TRUE(GetTxOfCert(iface, hashCert, t_tx) == true);
  _TRUE(t_tx.GetHash() == chain_wtx.GetHash());
  _TRUE(chain_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

  /* generake test license from certificate */
  CWalletTx lic_wtx;
  err = init_license_tx(iface, strLabel, hashCert, lic_wtx);
  _TRUE(0 == err);

  _TRUE(lic_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyLicense(lic_wtx) == true);
  CLicense lic(lic_wtx.certificate);
  uint160 licHash = lic.GetHash();

  _TRUE(lic_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
  /* insert license */
  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  _TRUE(lic_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

  /* verify insertion */
  CTransaction t2_tx;
  _TRUE(GetTxOfLicense(iface, licHash, t2_tx) == true);

}

_TEST(ctxtx)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  shgeo_t geo;
  int idx;
  int err;

  string strLabel("");

  for (idx = 0; idx < 3; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  int64 bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);

  CWalletTx wtx;
  int nBestHeight = GetBestHeight(iface) + 1;
  {
    const char *payload = "test context value";
    string strName = "test context name";
    cbuff vchValue(payload, payload + strlen(payload));
    err = init_ctx_tx(iface, wtx, strLabel, strName, vchValue);
    _TRUE(0 == err);
  }
  CContext ctx(wtx.certificate);
  uint160 hashContext = ctx.GetHash();

  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */
  _TRUE(VerifyContextTx(iface, wtx, nBestHeight) == true);
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

  /* insert ctx into chain + create a coin balance */
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  /* verify insertion */
  CTransaction t_tx;
  _TRUEPTR(GetContextByHash(iface, hashContext, t_tx));
  _TRUE(t_tx.GetHash() == wtx.GetHash());
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

  /* test geodetic context */
  shgeo_set(&geo, 46.7467, -114.1096, 0);
  string strName = "geo:46.7467,-114.1096";
  const char *payload = "{\"name\":\"mountain\",\"code\":\"AREA\"}";
  cbuff vchValue(payload, payload + strlen(payload));
  err = init_ctx_tx(iface, wtx, strLabel, strName, vchValue, &geo);
  _TRUE(err == 0);

  /* insert ctx into chain + create a coin balance */
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

}

_TEST(offertx)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CTransaction t_tx;
  int64 nValue;
	int mode;
  int idx;
  int err;

  string strLabel("");


  CCoinAddr addr = GetAccountAddress(wallet, strLabel, false);
  _TRUE(addr.IsValid() == true);

	string strAltLabel("offer");
  CCoinAddr alt_addr = GetAccountAddress(wallet, strAltLabel, false);
  _TRUE(alt_addr.IsValid() == true);

  /* create a coin balance */
  {
		CTxCreator s_wtx(wallet, strLabel);
		s_wtx.AddOutput(alt_addr.Get(), (int64)COIN*2);
		_TRUE(s_wtx.Send());

    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;

		int64 bal = GetAccountBalance(TEST_COIN_IFACE, strAltLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: alt account \"offer\" balance %f\n", (double)bal/COIN);
  }

	int64 bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);

  nValue = 1 * COIN;

	CWalletTx wtx;
	err = init_offer_tx(iface, strLabel, TEST_COIN_IFACE, nValue, nValue, 1.0, wtx);
fprintf(stderr, "DEBUG: TEST: OFFER: %d = init_offer_tx()\n", err);
  _TRUE(0 == err);
  uint160 hashOffer = wtx.offer.GetHash();
  uint256 hashTx = wtx.GetHash();
  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer initialized .. bal is now %f\n", ((double)t_bal / COIN));
  }
  _TRUE(wtx.CheckTransaction(TEST_COIN_IFACE));
  _TRUE(VerifyOffer(wtx, mode) == true);
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
  /* insert offer-tx into chain */
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  /* verify insertion */
  _TRUE(wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);
  _TRUE(GetTxOfOffer(iface, hashOffer, t_tx) == true);
  _TRUE(t_tx.GetHash() == hashTx); 

	CWalletTx acc_wtx;
	err = accept_offer_tx(iface, strAltLabel, hashOffer, nValue, acc_wtx); 
fprintf(stderr, "DEBUG: TEST: OFFER: %d = accept_offer_tx()\n", err);
  if (err == -2) {
    CTxMemPool *mempool = GetTxMemPool(iface);
    if (mempool->exists(hashTx)) {
      fprintf(stderr, "DEBUG: tx '%s' still in mempool\n", hashTx.GetHex().c_str());
    }
  }
  _TRUE(0 == err);
  uint160 hashAccept = acc_wtx.offer.GetHash();
  _TRUE(acc_wtx.CheckTransaction(TEST_COIN_IFACE));
  _TRUE(VerifyOffer(acc_wtx, mode) == true);
  _TRUE(acc_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);
fprintf(stderr, "DEBUG: ACCEPT: %s\n", acc_wtx.ToString(TEST_COIN_IFACE).c_str());
  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer accepted .. bal is now %f\n", ((double)t_bal / COIN));
  }
  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strAltLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer accepted .. alt-bal is now %f\n", ((double)t_bal / COIN));
  }
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  /* verify insertion */
  _TRUE(acc_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);

  /* offer generate operation */
  CWalletTx gen_wtx;
  err = generate_offer_tx(iface, hashOffer, gen_wtx);
if (err) fprintf(stderr, "DEBUG: TEST: OFFER: %d = generate_offer_tx\n", err);
  _TRUE(0 == err);
  uint160 hashGen = gen_wtx.offer.GetHash();
  _TRUE(gen_wtx.CheckTransaction(TEST_COIN_IFACE));
  _TRUE(VerifyOffer(gen_wtx, mode) == true);
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer generated .. bal is now %f\n", ((double)t_bal / COIN));
  }
  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strAltLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer generated .. alt-bal is now %f\n", ((double)t_bal / COIN));
  }
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer generated .. bal is now %f\n", ((double)t_bal / COIN));
  }
  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strAltLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer generated .. alt-bal is now %f\n", ((double)t_bal / COIN));
  }
#if 0
  /* pay operation */
  CWalletTx pay_wtx;
  err = pay_offer_tx(iface, hashAccept, pay_wtx);
if (err) fprintf(stderr, "DEBUG: %d = pay_offer_tx\n", err);
  _TRUE(0 == err);

  /* verify pending transaction */
  uint160 hashPay = pay_wtx.offer.GetHash();
  _TRUE(pay_wtx.CheckTransaction(TEST_COIN_IFACE));
  _TRUE(VerifyOffer(pay_wtx) == true);
  _TRUE(hashPay == hashAccept);
  _TRUE(pay_wtx.IsInMemoryPool(TEST_COIN_IFACE) == true);

#if 0
  {
    int64 t_bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
fprintf(stderr, "DEBUG: TEST: OFFER: offer pay'd .. bal is now %f\n", ((double)t_bal / COIN));
  }
#endif

  /* insert offer */
  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  _TRUE(pay_wtx.IsInMemoryPool(TEST_COIN_IFACE) == false);
#endif
#if 0
  /* verify payment has been appended to block-chain */
  _TRUE(GetTxOfOffer(iface, hashPay, t_tx) == false);
  _TRUE(t_tx.GetHash() == pay_wtx.GetHash());
#endif

#if 0
	/* verify payment */
  int64 new_bal = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1);
fprintf(stderr, "DEBUG: TEST OFFER: offertx: bal %llu < new_bal %llu\n", (unsigned long long)bal, (unsigned long long)new_bal);
  _TRUE(new_bal >= bal);
#endif
}



_TEST(matrix)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CTransaction tx;
  CTxMatrix *m;
  double lat, lon;
bool ret;
  int idx;
  int err;

  CBlockIndex *pindex;
  CBlockIndex *t_pindex;
  uint256 hashBlock;


  /* check for false negative */
  pindex = new CBlockIndex();
  pindex->phashBlock = &hashBlock;
  pindex->nHeight = 54;
  m = tx.GenerateValidateMatrix(TEST_COIN_IFACE, pindex);
  _TRUE(m == NULL);

  /* initial block with no seed */
  t_pindex = new CBlockIndex();
  t_pindex->phashBlock = &hashBlock;
  t_pindex->nHeight = 81;
  t_pindex->pprev = pindex;
  pindex = t_pindex;
  m = tx.GenerateValidateMatrix(TEST_COIN_IFACE, pindex);
  _TRUEPTR(m);
  ret = tx.VerifyValidateMatrix(*m, pindex);
  _TRUE(ret == true);

  for (idx = 108; idx < 351; idx += 27) {
    char buf[256];
    sprintf(buf, "0x%x%x%x%x", idx, idx, idx, idx);
    hashBlock = uint256(buf);

    t_pindex = new CBlockIndex();
    t_pindex->phashBlock = &hashBlock;
    t_pindex->nHeight = idx;
    t_pindex->pprev = pindex;
    pindex = t_pindex;

    tx.SetNull();
    m = tx.GenerateValidateMatrix(TEST_COIN_IFACE, pindex);
    _TRUEPTR(m);

    ret = tx.VerifyValidateMatrix(*m, pindex);
    _TRUE(ret == true);
  }
  matrixValidate.SetNull();

}

_TEST(matrixtx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CTransaction tx;
  CTxMatrix *m;
  double lat, lon;
bool ret;
  int idx;
  int err;

  CBlockIndex *pindex;
  CBlockIndex *t_pindex;
  uint256 hashBlock;


  /* claim a known 'root' location in spring matrix */
  lat = 46.6317; lon = 114.0946;
  _TRUE(is_spring_loc(lat, lon));
  spring_loc_claim(lat, lon);
  _TRUE(!is_spring_loc(lat, lon));

  /* claim a location through block-chain */
  CWalletTx wtx;
  string strAccount("");
  string strComment("geo:46.7467,-114.1096");
  err = init_ident_stamp_tx(iface, strAccount, strComment, wtx); 
  _TRUE(err == 0);


/* DEBUG: TODO: free blockindex's for valgrind mem check */

  /* ensure that block processing does not fail past x2 Validate matrix */
  for (idx = 0; idx < 67; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
}

_TEST(channeltx)
{
  CWallet *wallet = GetWallet(TEST_COIN_IFACE);
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CTransaction t_tx;
  int64 srcValue;
  int64 destValue;
  int idx;
  int err;
  int i;

  for (i = 0; i < 18; i++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  string strLabel("");


  CCoinAddr addr = GetAccountAddress(wallet, strLabel, true);
  _TRUE(addr.IsValid() == true);

  CCoinAddr dest_addr = GetAccountAddress(wallet, strLabel, true);
  _TRUE(dest_addr.IsValid() == true);

  int64 nValue = GetAccountBalance(TEST_COIN_IFACE, strLabel, 1) / 10;

  /* ** Regular Channel Scenerio ** */

  /* request channel funding */
  CWalletTx fund_wtx;
  err = init_channel_tx(iface, strLabel, nValue, dest_addr, fund_wtx); 
if (err) fprintf(stderr, "DEBUG: %d = init_channel_tx()\n", err);
  _TRUE(0 == err);
//fprintf(stderr, "DEBUG: CHAN INIT: %s\n", fund_wtx.ToString().c_str());

  /* fund channel as counter-party */
  CWalletTx chan_wtx;
  err = activate_channel_tx(iface, (CTransaction *)&fund_wtx, nValue, chan_wtx);
  _TRUE(0 == err);

  uint160 hChan = chan_wtx.channel.GetHash();

//fprintf(stderr, "DEBUG: CHAN OPEN: %s\n", chan_wtx.ToString().c_str());
//  _TRUE(chan_wtx.channel.GetHash() == hChan);

  /* perform pay operation to counter-party */
  CWalletTx commit_wtx;
  err = pay_channel_tx(iface, strLabel, hChan, dest_addr, nValue / 10, commit_wtx);  
//fprintf(stderr, "DEBUG: CHAN PAY[err %d]: %s\n", err, commit_wtx.ToString().c_str());
  _TRUE(0 == err);

  /* validate pay op */
  CWalletTx val_wtx;
  err = validate_channel_tx(iface, (CTransaction *)&commit_wtx, val_wtx);  
  _TRUE(0 == err);
//fprintf(stderr, "DEBUG: CHAN VALIDATE: %s\n", val_wtx.ToString().c_str());

#if 0
  /* perform pay operation from counter-party */
  CWalletTx commit_wtx;
  uint160 hChan = chan_wtx.channel.GetHash();
  err = pay_channel_tx(iface, strLabel, hChan, nValue / 2, commit_wtx);  
  _TRUE(0 == err);
#endif

  /* close channel and finalize transaction. */
  CWalletTx fin_wtx;
  err = generate_channel_tx(iface, hChan, fin_wtx);
//fprintf(stderr, "DEBUG: CHAN GEN[status %d]: %s\n", err, fin_wtx.ToString().c_str());
  _TRUE(0 == err);

  /* ** Abort Channel Scenerio ** */

  /* request channel funding */

  /* fund channel as counter-party */

  /* perform pay operation to counter-party */

  /* abort channel and redeem funds at current state */

}

/* test in-script verification of HD sig */
_TEST(hdtx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  string strAccount("");
  int i;

  CTransaction prevTx;
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    prevTx = block->vtx[0];
    delete block;
  }

  /* regular key */
  CKey key;
  CKeyID keyid;
  cbuff vchPubKey;
  CPubKey pubkey = wallet->GenerateNewKey();
	_TRUE(pubkey.IsValid() == true);
  wallet->SetAddressBookName(pubkey.GetID(), strAccount);
  _TRUE(wallet->GetKey(pubkey.GetID(), key) == true);
  _TRUE(key.IsValid());

#if 0 
/* DEBUG: TODO: REINTRODUCE; may be creating faulty tx */
  /* hd key */
  HDPrivKey mkey;
  HDPubKey mpubkey = wallet->GenerateNewHDKey();
  wallet->SetAddressBookName(mpubkey.GetID(), strAccount);
//  _TRUE(wallet->HaveKey(mpubkey.GetID() == true));
  _TRUE(wallet->GetKey(mpubkey.GetID(), mkey) == true);

  if(mpubkey != mkey.GetPubKey()) fprintf(stderr, "DEBUG: mpubkey != mkey.GetPubKey: mpubkey is %s\n", HexStr(mpubkey.Raw()).c_str());
  if(mpubkey != mkey.GetPubKey()) fprintf(stderr, "DEBUG: mpubkey != mkey.GetPubKey: mkey.pubkey is %s\n", HexStr(mkey.GetPubKey().Raw()).c_str());
  _TRUE(key.IsValid());
  _TRUE(mpubkey == mkey.GetPubKey());

  for (i = 0; i < 18; i++) { /* mature block */
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }


  {
    CScript scriptCode;
    scriptCode.SetDestination(mpubkey.GetID());
//fprintf(stderr, "DEBUG: TEST: hdtx: sending tx to hd key: scriptCode %s\n", scriptCode.ToString().c_str());
    CWalletTx wtx;
    wtx.vin.push_back(CTxIn(prevTx.GetHash(), 0));
    wtx.vout.push_back(CTxOut(1, scriptCode));

    CSignature sig(TEST_COIN_IFACE, &wtx, /* nIn = */ 0); 
    _TRUE(sig.SignSignature(prevTx) == true);
    _TRUE(VerifySignature(TEST_COIN_IFACE, prevTx, wtx, 0, false, 0) == true);
#if 0
    _TRUE(SignSignature(*wallet, prevTx, wtx, 0) == true);  
    _TRUE(VerifySignature(prevTx, wtx, 0, false, 0) == true);
#endif
_TRUE(wallet->CommitTransaction(wtx) == true);

#if 0
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    block->vtx.push_back(wtx);
    block->BuildMerkleTree();
    _TRUE(ProcessBlock(NULL, block) == true);
#endif

    prevTx = wtx;
  }
#endif


  {

    CScript scriptCode;
    scriptCode << OP_RETURN;
//    scriptCode.SetDestination(pubkey.GetID());
    CWalletTx wtx;
    wtx.SetNull();
    wtx.vin.push_back(CTxIn(prevTx.GetHash(), 0));
    wtx.vout.push_back(CTxOut(1, scriptCode));

    CSignature sig(TEST_COIN_IFACE, &wtx, /* nIn = */ 0, SIGHASH_HDKEY);
    _TRUE(sig.SignSignature(prevTx) == true);  
    _TRUE(VerifySignature(TEST_COIN_IFACE, prevTx, wtx, 0, false, SIGHASH_HDKEY) == true);
#if 0
    _TRUE(SignSignature(*wallet, prevTx, wtx, 0, SIGHASH_HDKEY) == true);  
    _TRUE(VerifySignature(prevTx, wtx, 0, false, SIGHASH_HDKEY) == true);
#endif
  }

}


static int TEST_sexe_compile(char *path_out, char *path_fname, char *path_dir, int *exec_size)
{
	sexe_t *L;
	int argc;
	char *argv[256];

	argc = 2;
	argv[0] = path_out;
	argv[1] = path_fname;

	L = sexe_init();
	if (L==NULL)
		return (SHERR_NOMEM);

	lua_pushcfunction(L, &sexe_compile_pmain);
	lua_pushinteger(L,argc);
	lua_pushlightuserdata(L,argv);
	if (lua_pcall(L,2,0,0)!=LUA_OK)
		return (SHERR_ILSEQ);
	lua_close(L);

	return (0);
}



_TEST(exectx)
{
#ifdef USE_SEXE
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  string strAccount("");
  char src_path[PATH_MAX+1];
  char sx_path[PATH_MAX+1];
  int mode = -1;
  int idx;
  int err;

  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

	strcpy(sx_path, "BaseObject.lua");
	exec_write_base_object(sx_path);

	err = TEST_sexe_compile("BaseObject.sx", "BaseObject.lua", "", NULL);
	if (err) {
		fprintf(stderr, "DEBUG: %d = TEST_sexe_compile()\n", err);
	}
	_TRUE(err == 0);

  CCoinAddr sendAddr = GetAccountAddress(wallet, strAccount, true);

  /* create a coin balance. */
  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }


	/* - Exec Init Tx - */
  CWalletTx wtx;

  string strPath("BaseObject.sx");
  err = init_exec_tx(iface, strAccount, strPath, wtx); 
if (err) fprintf(stderr, "DEBUG: TEST: EXECTX[status %d]: %s\n", err, wtx.ToString(TEST_COIN_IFACE).c_str());
  _TRUE(err == 0);

  CExec *exec = wtx.GetExec();
  _TRUE(err == 0);
  _TRUE(VerifyExec(wtx, mode) == true);
  _TRUE(mode == OP_EXT_NEW);
  _TRUE(exec->VerifySignature(TEST_COIN_IFACE));

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

	uint160 hExec = exec->GetHash();

	/* clear previous user-data */
	ResetExecChain(iface, hExec);

	/* - Exec Call (direct) - */
  CWalletTx wtx_call;
	wtx_call.SetNull();
	CExecCall *call = wtx_call.GenerateExec(*exec);
if (!call) { fprintf(stderr, "DEBUG: TEST: exectx: !call\n"); } 
	_TRUEPTR(call);

	call->hExec = hExec;
	call->SetSendTime();
	call->SetCommitHeight(TEST_COIN_IFACE);
	call->SetMethodName("verify");


	shjson_t *param = shjson_init(NULL);
	shjson_str_add(param, "sender", (char *)sendAddr.ToString().c_str());
	shjson_str_add(param, "owner", (char *)sendAddr.ToString().c_str());
	shjson_str_add(param, "iface", "test");
	shjson_num_add(param, "value", 0);
	shjson_num_add(param, "version", 3);
	shjson_str_add(param, "class", "BaseObject");
	shjson_str_add(param, "method", "verify");
	shjson_num_add(param, "timestamp", call->GetSendTime());
	shjson_num_add(param, "height", GetBestHeight(iface));

	bool ret = exec->CallStack(TEST_COIN_IFACE, sendAddr, &param);
  _TRUE(ret == true);

	shjson_free(&param);

  for (idx = 0; idx < 2; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }


	/* - Exec Call Tx - */
	wtx_call.SetNull();
	string strClass("BaseObject");
	char *args[3]; args[0] = NULL;
	Value ret_val;
	err = generate_exec_tx(iface, strAccount, strClass, COIN, "update", args, ret_val, wtx_call);  
if (err) fprintf(stderr, "DEBUG: %d = generate_exec_tx()\n", err);
	_TRUE(err == 0);
	_TRUE(ret_val.get_bool() == true);
	uint160 hCall = wtx_call.GetExecCall()->GetHash();

	{
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

	CExecCall t_call;
	_TRUE(GetCallByHash(iface, hCall, t_call));

	/* Checkpoint */

	{
		vector<uint160>& vCall = wallet->mapExecCall[hExec];
		_TRUE(vCall.size() == 1);

		vector<uint160>& vPendCall = wallet->mapExecCallPending[hExec];
		_TRUE(vPendCall.size() == 0);
	}

	ResetExecChain(iface, hExec);

	{
		vector<uint160>& vCall = wallet->mapExecCall[hExec];
		_TRUE(vCall.size() == 0);

		vector<uint160>& vPendCall = wallet->mapExecCallPending[hExec];
		_TRUE(vPendCall.size() == 1);
	}

  for (idx = 0; idx < 10; idx++) {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  CWalletTx wtx2_call;
	wtx2_call.SetNull();
	err = generate_exec_tx(iface, strAccount, strClass, COIN, "update", args, ret_val, wtx2_call);  
if (err) fprintf(stderr, "DEBUG: %d = generate_exec_tx()/2\n", err);
	_TRUE(err == 0);

	{
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

	_TRUE(wallet->mapExecCheckpoint.count(hExec) == 1);

	{
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

	_TRUE(ExecRestoreCheckpoint(iface, hExec) == true);


	{
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

#endif /* def USE_SEXE */
}

_TEST(scriptid)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  string strAccount("");
  string strExtAccount("scriptid");

  CCoinAddr ret_addr = GetAccountAddress(wallet, strAccount, true);
  _TRUE(ret_addr.IsValid());
  CCoinAddr addr = GetAccountAddress(wallet, strExtAccount, true);
  _TRUE(addr.IsValid());

  CKeyID keyID;
  _TRUE(addr.GetKeyID(keyID));
  CScript script = GetScriptForDestination(keyID);
 
  _TRUE(wallet->AddCScript(script));
  CScriptID scriptID = CScriptID(script);
  wallet->SetAddressBookName(scriptID, strExtAccount);

  /* send COIN to scriptID */
  CTxCreator wtx(wallet, strAccount);
  wtx.AddOutput(scriptID, COIN);
  _TRUE(wtx.Send());

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
//int64 nValue = GetAccountBalance(TEST_COIN_IFACE, strExtAccount, 1);
//fprintf(stderr, "DEBUG: TEST: SCRIPTID: bal/before nValue %f\n", (double)nValue / COIN);
  _TRUE(COIN == GetAccountBalance(TEST_COIN_IFACE, strExtAccount, 1));

  /* redeem scriptID back to origin */
  CTxCreator wtx2(wallet, strExtAccount);
  wtx2.AddOutput(ret_addr.Get(), COIN - (iface->min_tx_fee*2));
  _TRUE(wtx2.Send());
    
  _TRUE(wtx2.IsInMemoryPool(TEST_COIN_IFACE) == true);
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  _TRUE(wtx2.IsInMemoryPool(TEST_COIN_IFACE) == false);
//nValue = GetAccountBalance(TEST_COIN_IFACE, strExtAccount, 1);
//fprintf(stderr, "DEBUG: TEST: SCRIPTID: bal/after %f\n", (double)nValue/COIN);


  _TRUE(0 == GetAccountBalance(TEST_COIN_IFACE, strExtAccount, 1));
}

_TEST(segwit)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  CBlock *blocks[1024];
  CBlock *pblock;
  string strError;
  bool ok;
  int i;

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  iface->vDeployments[DEPLOYMENT_SEGWIT].bit = 1;
  iface->vDeployments[DEPLOYMENT_SEGWIT].nStartTime = time(NULL);
  iface->vDeployments[DEPLOYMENT_SEGWIT].nTimeout = time(NULL) + 120;

  /* create some blocks */
  for (i = 0; i < 1024; i++) { 
    CBlockIndex *pindexPrev = GetBestBlockIndex(iface);

    blocks[i] = test_GenerateBlock();
    _TRUEPTR(blocks[i]);
    _TRUE(ProcessBlock(NULL, blocks[i]) == true);

    if (IsWitnessEnabled(iface, pindexPrev))
      break;

//    delete block;
  }

  CBlockIndex *pindexPrev = GetBestBlockIndex(iface);
  _TRUE(IsWitnessEnabled(iface, pindexPrev));

  bool found = false;
  string strAccount;
  CCoinAddr addr(TEST_COIN_IFACE);
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(TEST_COIN_IFACE, item.first);
    const string& account = item.second;
    if (account != "") continue;
    addr = address;
    strAccount = account;
    found = true;
    break;
  }
  _TRUE(found);

  int64 nValue = GetAccountBalance(TEST_COIN_IFACE, strAccount, 1);

  /* send to extended tx storage account */
  string strWitAccount = "witness";
  CCoinAddr extAddr = GetAccountAddress(wallet, strWitAccount, true);

  CTxCreator wtx1(wallet, strAccount);
  wtx1.AddOutput(extAddr.Get(), COIN);
  ok = wtx1.Send();
  strError = wtx1.GetError();
  _TRUE(ok);
  _TRUE(strError == "");
  _TRUE(wtx1.CheckTransaction(TEST_COIN_IFACE)); /* .. */


  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }


  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  nValue = GetAccountBalance(TEST_COIN_IFACE, strWitAccount, 1);

	for (i = 0; i < 4; i++) {
		extAddr = GetAccountAddress(wallet, strWitAccount, true);
		CCoinAddr witAddr(TEST_COIN_IFACE);
		_TRUE(wallet->GetWitnessAddress(extAddr, witAddr) == true);
		CTxCreator wit_wtx(wallet, strAccount);
		wit_wtx.AddOutput(witAddr.Get(), COIN / 4);
		ok = wit_wtx.Send();
		strError = wit_wtx.GetError();
		if (strError != "") fprintf(stderr, "DEBUG: strerror = \"%s\"\n", strError.c_str());
		_TRUE(ok == true);
		_TRUE(strError == "");
		_TRUE(wit_wtx.CheckTransaction(TEST_COIN_IFACE)); /* .. */

		{
			CBlock *block = test_GenerateBlock();
			_TRUEPTR(block);
			_TRUE(ProcessBlock(NULL, block) == true);
			delete block;
		}
	}

/*
  {
    const CScript& scriptPubKey = wit_wtx.vout[0].scriptPubKey;
    int witnessversion;
    cbuff witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
      fprintf(stderr, "DEBUG: TEST: wit_wtx.scriptPubKey IsWitnessProgram: TRUE\n");
    } else {
      fprintf(stderr, "DEBUG: TEST: wit_wtx.scriptPubKey IsWitnessProgram: FALSE\n");
    }
  }
*/

/*
  pblock = test_GenerateBlock();
  _TRUEPTR(pblock);
  _TRUE(ProcessBlock(NULL, pblock) == true);
  const CScript& scriptPubKey = pblock->vtx[1].vout[0].scriptPubKey;
  int witnessversion;
  cbuff witnessprogram;
  if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
    fprintf(stderr, "DEBUG: TEST: pblock.scriptPubKey IsWitnessProgram: TRUE\n");
  } else {
    fprintf(stderr, "DEBUG: TEST: pblock.scriptPubKey IsWitnessProgram: FALSE\n");
  }
  delete pblock;
*/


  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  pindexPrev = GetBestBlockIndex(iface);
  _TRUE(IsWitnessEnabled(iface, pindexPrev));

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  nValue = GetAccountBalance(TEST_COIN_IFACE, strWitAccount, 1);
  _TRUE(((int64)COIN * 2) == nValue); 

  /* return coins back to main account. */
  CTxCreator wtx3(wallet, strWitAccount);
  wtx3.AddOutput(addr.Get(), nValue - (MIN_TX_FEE(iface) * 2));
	{
		CTransaction *t = (CTransaction *)&wtx3;
fprintf(stderr, "DEBUG: TEST: SEGWIT: wtx3.ToString: %s\n", t->ToString(TEST_COIN_IFACE).c_str());
	}
  _TRUE(wtx3.Send());
  strError = wtx3.GetError();
if (strError != "") fprintf(stderr, "DEBUG: wtx3.strerror = \"%s\"\n", strError.c_str());
  _TRUE(strError == "");
  _TRUE(wtx3.CheckTransaction(TEST_COIN_IFACE)); /* .. */

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
fprintf(stderr, "DEBUG: TEST: SEGWIT: wtx3 BLOCK: %s\n", block->ToString().c_str());
    _TRUE(ProcessBlock(NULL, block) == true);
#if 0
    int nIndex = 0;
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      fprintf(stderr, "DEBUG: TEST: wtx3: block.tx[%d] = \"%s\"\n", nIndex, tx.ToString(TEST_COIN_IFACE).c_str());
      nIndex++;
    }
#endif
    delete block;
  }

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  nValue = GetAccountBalance(TEST_COIN_IFACE, strWitAccount, 1);
  _TRUE(0 == nValue); 

}

_TEST(segwit_serializetx)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CBlockIndex *pindexPrev = GetBestBlockIndex(iface);
  CTransaction tx;
  CTransaction cmp_tx;

  CBlock *block = test_GenerateBlock();
  _TRUEPTR(block);
  _TRUE(core_CheckBlockWitness(iface, block, pindexPrev)); 

  TESTBlock cmp1_block;
  CDataStream ser1(SER_DISK, PROTOCOL_VERSION(iface));
  ser1 << *block;
  ser1 >> cmp1_block;
  _TRUE(core_CheckBlockWitness(iface, &cmp1_block, pindexPrev)); 

  TESTBlock cmp2_block;
  CDataStream ser2(SER_DISK, CLIENT_VERSION);
  ser2 << *block;
  ser2 >> cmp2_block;
  _TRUE(core_CheckBlockWitness(iface, &cmp2_block, pindexPrev)); 
}



_TEST(txmempool_pending)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  CTxMemPool *pool = GetTxMemPool(iface);
  string strAccount("");

  /* test transaction */
  CTxCreator inv_tx(wallet, strAccount);

  /* generate transaction without commiting to pool. */
  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);
  _TRUE(true == inv_tx.AddOutput(addr.Get(), (int64)COIN));
  _TRUE(true == inv_tx.Generate());

  /* alter input prev-hash */
  inv_tx.vin[0].prevout.hash = 0x1;

  /* verify txmempool fails commit and adds to pending hash list. */
  _TRUE(false == pool->AddTx(inv_tx));
  _TRUE(true == pool->IsPendingTx(inv_tx.GetHash()));
  
}


_TEST(txmempool_inval)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  CTxMemPool *pool = GetTxMemPool(iface);
  string strAccount("");

  /* test transaction */
  CTxCreator inv_tx(wallet, strAccount);

  /* generate transaction without commiting to pool. */
  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);
  _TRUE(true == inv_tx.AddOutput(addr.Get(), (int64)COIN));
  _TRUE(true == inv_tx.Generate());

  /* alter contents to invalid -- one milliiionnn coihns. */
  inv_tx.vout[0].nValue = 1000000 * (int64)COIN;

  /* verify txmempool fails commit and adds to invalid hash list. */
  _TRUE(false == pool->AddTx(inv_tx));
  _TRUE(true == pool->IsInvalidTx(inv_tx.GetHash()));

}

_TEST(respend)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CWallet *wallet = GetWallet(iface);
  uint256 reuseHash;
  string strAccount("");
  int reuseOut;

  /* obtain test coin address */
  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);

  /* create transaction and track primary input */
  CTxCreator tx(wallet, strAccount);
  _TRUE(true == tx.AddOutput(addr.Get(), (int64)COIN));
  _TRUE(true == tx.Generate());

  reuseHash = tx.vin[0].prevout.hash;
  reuseOut = tx.vin[0].prevout.n;
  _TRUE(true == tx.Send());

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  /* attempt send of tx w/ spent input */
  CTxCreator s_tx(wallet, strAccount);
  _TRUE(false == s_tx.AddInput(reuseHash, reuseOut));
#if 0
  _TRUE(true == s_tx.AddOutput(addr.Get(), (int64)COIN));
  _TRUE(false == s_tx.Send());
#endif

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

}

_TEST(txmempool_depend)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CTxMemPool *pool = GetTxMemPool(iface);
  CWallet *wallet = GetWallet(iface);
  uint256 reuseHash;
  string strAccount("");

  /* obtain test coin address */
  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }
  _TRUE(pool->size() == 0);

  /* create transaction and track primary input */
  CTxCreator tx(wallet, strAccount);
  _TRUE(true == tx.AddOutput(addr.Get(), (int64)COIN * 2));
  _TRUE(true == tx.Send());

  reuseHash = tx.GetHash();

  /* attempt send of tx w/ spent input */
  CTxCreator s_tx(wallet, strAccount);
  _TRUE(true == s_tx.AddInput(reuseHash, 0));
  _TRUE(true == s_tx.AddOutput(addr.Get(), (int64)COIN));
  _TRUE(true == s_tx.Send());

  _TRUE(pool->size() == 2);

  {
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;
  }

  _TRUE(pool->size() == 0);
}

/* simple test to ensure block index "bnChainWork" is larger for each new block committed to the block-chain. */
_TEST(chainwork)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  CBlockIndex *pindex[3];
  int i;

  for (i = 0; i < 3; i++) { 
    CBlock *block = test_GenerateBlock();
    _TRUEPTR(block);
    _TRUE(ProcessBlock(NULL, block) == true);
    delete block;

    pindex[i] = GetBestBlockIndex(iface);
  }

  for (i = 0; i < 2; i++) {
    _TRUE(pindex[i]->bnChainWork != 0);
    _TRUE(pindex[i]->bnChainWork <= pindex[i+1]->bnChainWork);
  }
}

_TEST(orphan_block)
{
  CBlock *block;

  block = test_GenerateBlock();
  _TRUEPTR(block);
  _TRUE(ProcessBlock(NULL, block) == true);
  uint256 phash = block->GetHash();
  delete block;

  block = test_GenerateBlock();
  _TRUEPTR(block);
  uint256 hash = block->GetHash();
  {
    uint256 prevHash;
    test_AddOrphanBlock(block);
    _TRUE(true == test_IsOrphanBlock(hash));
    _TRUE(true == test_GetOrphanPrevHash(hash, prevHash));
    _TRUE(phash == prevHash);

    CBlock *orphan = test_GetOrphanBlock(hash);
    _TRUEPTR(orphan);
    _TRUE(orphan->GetHash() == hash);
    delete orphan;
  }
  _TRUE(ProcessBlock(NULL, block) == true);
  _TRUE(false == test_IsOrphanBlock(hash));
  delete block;

}


#ifdef __cplusplus
}
#endif
