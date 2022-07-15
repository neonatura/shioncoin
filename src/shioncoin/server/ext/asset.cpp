
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
#include "json_spirit_reader_template.h"
#include "json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>
#include "wallet.h"
#include "txcreator.h"
#include "asset.h"

using namespace std;
using namespace json_spirit;

#define MIME_APPLICATION_OCTET_STREAM SHMIME_BINARY
#define MIME_TEXT_PLAIN SHMIME_TEXT_PLAIN
#define MIME_APP_GZIP SHMIME_APP_GZIP
#define MIME_APP_LINUX SHMIME_APP_LINUX
#define MIME_APP_LINUX_32 SHMIME_APP_LINUX_32
#define MIME_APP_TAR SHMIME_APP_TAR
#define MIME_APP_PEM SHMIME_APP_PEM
#define MIME_APP_SQLITE SHMIME_APP_SQLITE
#define MIME_APP_SEXE SHMIME_APP_SEXE
#define MIME_APP_BZ2 SHMIME_APP_BZ2
#define MIME_APP_RAR SHMIME_APP_RAR
#define MIME_APP_ZIP SHMIME_APP_ZIP
#define MIME_APP_XZ SHMIME_APP_XZ
#define MIME_APP_WIN SHMIME_APP_WIN
#define MIME_IMAGE_GIF SHMIME_IMG_GIF
#define MIME_IMAGE_PNG SHMIME_IMG_PNG
#define MIME_IMAGE_JPEG SHMIME_IMG_JPEG
#define MIME_MODEL_OBJ "model/obj"
#define MIME_MODEL_MTL "model/mtl"

asset_list *GetAssetTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapAsset);
}

bool DecodeAssetHash(const CScript& script, int& mode, uint160& hash)
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
  op = CScript::DecodeOP_N(opcode); /* extension type (asset) */
  if (op != OP_ASSET) {
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


string assetFromOp(int op) {
	switch (op) {
	case OP_EXT_NEW:
		return "assetnew";
	case OP_EXT_UPDATE:
		return "assetupdate";
	case OP_EXT_ACTIVATE:
		return "assetactivate";
	case OP_EXT_TRANSFER:
		return "assettransfer";
	case OP_EXT_REMOVE:
		return "assetremove";
	default:
		return "<unknown asset op>";
	}
}

bool DecodeAssetScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) 
{
	opcodetype opcode;
  int mode;

	if (!script.GetOp(pc, opcode))
		return false;
  mode = opcode; /* extension mode (new/activate/update) */

	if (!script.GetOp(pc, opcode))
		return false;
	if (opcode < OP_1 || opcode > OP_16)
		return false;

	op = CScript::DecodeOP_N(opcode); /* extension type (asset) */
  if (op != OP_ASSET)
    return false;

	for (;;) {
		vector<unsigned char> vch;
		if (!script.GetOp(pc, opcode, vch))
			return false;
		if (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP)
			break;
		if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
			return false;
		vvch.push_back(vch);
	}

	// move the pc to after any DROP or NOP
	while (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP) {
		if (!script.GetOp(pc, opcode))
			break;
	}

	pc--;

	if ((mode == OP_EXT_NEW && vvch.size() == 2) ||
      (mode == OP_EXT_ACTIVATE && vvch.size() == 2) ||
      (mode == OP_EXT_UPDATE && vvch.size() == 2) ||
      (mode == OP_EXT_TRANSFER && vvch.size() == 2) ||
      (mode == OP_EXT_REMOVE && vvch.size() == 2))
    return (true);

	return false;
}

bool DecodeAssetScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeAssetScript(script, op, vvch, pc);
}

CScript RemoveAssetScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeAssetScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveAssetScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetAssetOpFee(CIface *iface, int nHeight) 
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5140 / base * COIN;
  double nDif = 4982 /base * COIN;
  int64 nFee = (int64)(nRes - nDif);
  nFee = MAX(MIN_TX_FEE(iface), nFee);
  nFee = MIN(MAX_TX_FEE(iface), nFee);
  return (nFee);
}

bool IsAssetTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_ASSET)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

		/* todo: check mode */
    if (DecodeAssetHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

/**
 * Obtain the tx that defines this asset.
 */
bool GetTxOfAsset(CIface *iface, const uint160& hashAsset, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  asset_list *assetes = GetAssetTable(ifaceIndex);
  bool ret;

  if (assetes->count(hashAsset) == 0) {
    return false; /* nothing by that name, sir */
  }

  uint256 hashBlock;
  uint256 hashTx = (*assetes)[hashAsset];
  CTransaction txIn;
  ret = GetTransaction(iface, hashTx, txIn, NULL);
  if (!ret) {
    return false;
  }

  if (!IsAssetTx(txIn)) 
    return false; /* inval; not an asset tx */

  tx.Init(txIn);
  return true;
}

#if 0
static int IndexOfAssetOutput(const CTransaction& tx)
{
	int idx;

	idx = 0;
	BOOST_FOREACH(const CTxOut& out, tx.vout) {
		const CScript& script = out.scriptPubKey;
		opcodetype opcode;
		CScript::const_iterator pc = script.begin();
		if (script.GetOp(pc, opcode) &&
				opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
			if (script.GetOp(pc, opcode) &&
					CScript::DecodeOP_N(opcode) == OP_ASSET)
				break;
		}

		idx++;
	}
	if (idx == tx.vout.size())
		return (-1); /* uh oh */

	return (idx);
}
#endif
static int IndexOfAssetOutput(const CTransaction& tx)
{
	CScript script;
	int nTxOut;
	int mode;

	if (!GetExtOutput(tx, OP_ASSET, mode, nTxOut, script))
		return (-1);

	return (nTxOut);
}


bool IsLocalAsset(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalAsset(CIface *iface, const CTransaction& tx)
{
  if (!IsAssetTx(tx))
    return (false); /* not a asset */

  int nOut = IndexOfAssetOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalAsset(iface, tx.vout[nOut]));
}

int GetAssetTransactionMode(CTransaction& tx, uint160& hAsset)
{
	int nOut;
  int mode;

	  /* core verification */
  if (!IsAssetTx(tx)) {
    return (-1); /* tx not flagged as asset */
	}

  /* verify hash in pub-script matches asset hash */
  nOut = IndexOfAssetOutput(tx);
  if (nOut == -1) {
    return (-1); /* no extension output */
	}

  if (!DecodeAssetHash(tx.vout[nOut].scriptPubKey, mode, hAsset)) {
    return (-1); /* no asset hash in output */
	}

	return (mode);
}

/**
 * Verify the integrity of an asset transaction.
 */
bool VerifyAsset(CTransaction& tx)
{
  uint160 hashAsset;
  int nOut;

  /* core verification */
  if (!IsAssetTx(tx)) {
    return (false); /* tx not flagged as asset */
}

  /* verify hash in pub-script matches asset hash */
  nOut = IndexOfAssetOutput(tx);
  if (nOut == -1)
    return (false); /* no extension output */

  int mode;
  if (!DecodeAssetHash(tx.vout[nOut].scriptPubKey, mode, hashAsset))
    return (false); /* no asset hash in output */

  if (mode != OP_EXT_NEW && 
      mode != OP_EXT_ACTIVATE &&
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_REMOVE)
    return (false);

  CAsset *asset = (CAsset *)&tx.asset;
  if (hashAsset != asset->GetHash())
    return error(SHERR_INVAL, "asset hash mismatch");

  return (true);
}

bool VerifyAssetAccount(CWallet *wallet, const CTxOut& outAsset, string strAccount)
{
	bool fIsScript;

	strAccount = "@" + strAccount;

	/* extract "extended account" tx-destination. */
	CTxDestination dest;
	if (!ExtractDestination(outAsset.scriptPubKey, dest))
		return (false);
	CCoinAddr addrAsset = CCoinAddr(wallet->ifaceIndex, dest);
	if (!addrAsset.IsValid())
		return (false);
	fIsScript = addrAsset.IsScript();

	/* search for matching output and account name. */
	BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
	{
		const CCoinAddr& address = CCoinAddr(wallet->ifaceIndex, item.first);
		const string& account = item.second;

		if (fIsScript && !address.IsScript())
			continue;

		if (strAccount != account)
			continue;

		if (address.Get() == addrAsset.Get())
			return (true);
	}

	return (false);
}

std::string CAsset::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CAsset::ToValue()
{
  Object obj;

  obj.push_back(Pair("hash", GetHash().GetHex()));
	obj.push_back(Pair("title", GetLabel()));
	if (GetHashIssuer() != 0) {
		obj.push_back(Pair("issuer", GetHashIssuer().GetHex()));
	}
	obj.push_back(Pair("subtype", (int)GetSubType()));
	obj.push_back(Pair("valuecrc", (uint64_t)GetContentChecksum()));
	if (GetContentSize() != 0) {
		obj.push_back(Pair("valuesize", (uint64_t)GetContentSize()));
	}

  return (obj);
}

bool CAsset::SignContent(int ifaceIndex)
{
	cbuff vchContext = GetSignatureContext(ifaceIndex);
	if (vchContext.size() == 0)
		return (false);

  return (signature.SignContext(vchContext));
}

bool CAsset::VerifyContent(int ifaceIndex)
{
	cbuff vchContext = GetSignatureContext(ifaceIndex);
	if (vchContext.size() == 0)
		return (false);

  return (signature.VerifyContext(vchContext.data(), vchContext.size()));
}

cbuff CAsset::GetSignatureContext(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
	cbuff vContext;

  CTransaction cert_tx;
	uint160 hCert(vAddr);
	if (hCert != 0 && GetTxOfCert(iface, hCert, cert_tx)) {
		CDataStream ser(SER_DISK, CLIENT_VERSION);
		CCert *serCert = cert_tx.GetCertificate();

		ser << *serCert;
		size_t buff_len = ser.size();
		uint8_t *buff = (uint8_t *)calloc(buff_len, sizeof(uint8_t));
		ser.read((char *)buff, buff_len);
		vContext.insert(vContext.end(), buff, buff + buff_len);
		free(buff);
	}

  CTransaction asset_tx;
	if (hashIssuer != 0 && GetTxOfAsset(iface, hashIssuer, asset_tx)) {
		CDataStream ser(SER_DISK, CLIENT_VERSION);
		CAsset *serAsset = asset_tx.GetAsset();

		ser << *serAsset;
		size_t buff_len = ser.size();
		uint8_t *buff = (uint8_t *)calloc(buff_len, sizeof(uint8_t));
		ser.read((char *)buff, buff_len);
		vContext.insert(vContext.end(), buff, buff + buff_len);
		free(buff);
	}

	const cbuff& data = GetContent();
	vContext.insert(vContext.end(), data.begin(), data.end());

	return (vContext);
}

string CAsset::GetMimeType()
{

	if (GetType() == AssetType::DATA) {
		switch (GetSubType()) {
			case AssetMimeType::TEXT:
				return (MIME_TEXT_PLAIN);
			case AssetMimeType::IMAGE_GIF:
				return (MIME_IMAGE_GIF);
			case AssetMimeType::IMAGE_PNG:
				return (MIME_IMAGE_PNG);
			case AssetMimeType::IMAGE_JPEG:
				return (MIME_IMAGE_JPEG);
			case AssetMimeType::MODEL_OBJ:
				return (MIME_MODEL_OBJ);
			case AssetMimeType::MODEL_MTL:
				return (MIME_MODEL_MTL);
		}
	}

	return (MIME_APPLICATION_OCTET_STREAM);
}

int CAsset::VerifyTransaction()
{
	const uint160& hCert = GetCertificateHash();
	int err;

	err = CEntity::VerifyTransaction();
	if (err)
		return (err);

	if (vContent.size() == 0 ||
			vContent.size() > MAX_ASSET_CONTENT_LENGTH) {
		return (ERR_INVAL);
	}

	if (hCert == 0) {
		return (ERR_INVAL);
	}

	return (0);
}

/* obtain all previous assets in sequence associated with "tx". */
bool GetAssetChain(CIface *iface, const CTransaction& txIn, vector<CTransaction>& vTx)
{
	CAsset *asset = (CAsset *)&txIn.asset;
	CTransaction tx;
	uint160 l_hashIssuer = 0;
	uint160 hashAsset;
	int nOut;
	int mode;
	int i;

	vTx.clear();

	nOut = IndexOfAssetOutput(txIn);
	if (nOut == -1)
		return (false);
	if (!DecodeAssetHash(txIn.vout[nOut].scriptPubKey, mode, hashAsset))
		return (false);

	if (mode == OP_EXT_NEW)
		return (true); /* all done */

	tx = txIn;
//	mode = OP_EXT_UPDATE;
	l_hashIssuer = tx.GetAsset()->GetHashIssuer();
	while (l_hashIssuer != 0) {//mode == OP_EXT_UPDATE) {
		int txSize = tx.vin.size();
		for (i = 0; i < txSize; i++) {
			const CTxIn& in = tx.vin[i];
			const uint256& hashPrevTx = in.prevout.hash;
			int nPrevOut = in.prevout.n;
			CTransaction p_tx;

			if (!GetTransaction(iface, in.prevout.hash, p_tx, NULL)) {
				continue; /* soft error */
			}

			const CTxOut& out = p_tx.vout[nPrevOut];
			if (!DecodeAssetHash(out.scriptPubKey, mode, hashAsset)) {
				continue; /* onto next tx */
			}

			if (hashAsset != l_hashIssuer) {
				/* wrong chain reference. */
				continue;
			}

			tx = p_tx;
			vTx.insert(vTx.begin(), tx);
			//l_hashIssuer = p_asset->GetHashIssuer();
			l_hashIssuer = tx.GetAsset()->GetHashIssuer();
			break;
		}
		if (i == txSize)
			return (error(ERR_INVAL, "GetAssetChain: invalid chain"));
	}

	return (true);
}

bool GetAssetRootHash(CIface *iface, CTransaction& tx, uint160& hAsset) 
{
	vector<CTransaction> vTx;

	/* load entire asset hierarchy. */
	if (!GetAssetChain(iface, tx, vTx))
		return (false);

	if (vTx.size() == 0) {
		CAsset *asset = tx.GetAsset();
		if (!asset)
			return (false);

		hAsset = asset->GetHash(); 
	} else {
		CAsset *asset = vTx[0].GetAsset();
		if (!asset)
			return (false);

		/* return initial asset hash. */
		hAsset = asset->GetHash();
	}

	return (true);
}

bool VerifyAssetChainOrigin(CIface *iface, CTransaction& tx, uint256& hPrevAssetTx)
{
	uint160 hAsset;

	if (tx.GetAsset() == NULL) {
		return (false);
	}

	if (!GetAssetRootHash(iface, tx, hAsset)) {
		return (error(SHERR_INVAL, "VerifyAssetChainOrigin: unknown asset root hash"));
	}

	CTransaction asset_tx;
	if (!GetTxOfAsset(iface, hAsset, asset_tx)) {
		return (error(SHERR_INVAL, "VerifyAssetChainOrigin: unknown asset hash"));
	}

	CAsset *prevAsset = asset_tx.GetAsset();
	if (!prevAsset)
		return (false);
	if (prevAsset->GetHash() != tx.GetAsset()->GetHashIssuer())
		return (error(ERR_INVAL, "VerifyAssetChainOrigin: invalid hash issuer"));

	/* cycle through inputs and find previous asset. */
	const uint256& hTx = asset_tx.GetHash();
	for (int i = 0; i < tx.vin.size(); i++) {
		const CTxIn& in = tx.vin[i];
		if (in.prevout.hash == hTx) {
			hPrevAssetTx = hTx;
			return (true);
		}
	}

	return (false);
}

static bool InsertAssetTable(CIface *iface, CTransaction& tx)
{
	CWallet *wallet = GetWallet(iface);
	CAsset *asset = tx.GetAsset();
	uint160 hAsset;

	if (asset == NULL) {
		return (error(ERR_INVAL, "InsertAssetTable: invalid asset transaction."));
	}

	if (!GetAssetRootHash(iface, tx, hAsset)) {
		return (error(ERR_INVAL, "InsertAssetTable: invalid asset transaction hierarchy."));
	}

	/* set asset root hash to new transaction id. */
	wallet->mapAsset[hAsset] = tx.GetHash();
	
	/* set asset root hash to new content checksum. */
	wallet->mapAssetChecksum[hAsset] = asset->GetContentChecksum();

	return (true);
}

static bool RemoveAssetTable(CIface *iface, CTransaction& tx)
{
	CWallet *wallet = GetWallet(iface);
	CAsset *asset = tx.GetAsset();
	uint160 hAsset;

	if (asset == NULL) {
		return (error(ERR_INVAL, "InsertAssetTable: invalid asset transaction."));
	}

	if (!GetAssetRootHash(iface, tx, hAsset)) {
		return (error(ERR_INVAL, "InsertAssetTable: invalid asset transaction hierarchy."));
	}

	wallet->mapAsset.erase(hAsset);
	wallet->mapAssetChecksum.erase(hAsset);
	return (true);
}

bool IsExistingAssetChecksum(CWallet *wallet, uint64_t crc)
{
	const map<uint160, uint64_t>& checksumList = wallet->mapAssetChecksum;

	for (map<uint160, uint64_t>::const_iterator mi = checksumList.begin(); mi != checksumList.end(); ++mi) {
		uint64_t cmp_crc = (*mi).second;
		if (cmp_crc == crc) {
			return (true);
		}
	}

	return (false);
}

int64_t GetAssetChecksum(CWallet *wallet, const uint160& hAsset)
{
	map<uint160, uint64_t>& checksumList = wallet->mapAssetChecksum;

	map<uint160, uint64_t>::iterator mi = checksumList.find(hAsset);
	if (mi != checksumList.end()) {
		uint64_t crc = (*mi).second;
		return (crc);
	}

	return (0);
}

static bool ProcessNewAssetTx(CIface *iface, CTransaction& tx)
{
	CWallet *wallet = GetWallet(iface);
	CAsset *asset = tx.GetAsset();
	const uint160& hAsset = asset->GetHash();

	if (wallet->mapAsset.count(hAsset) != 0) {
		return (false); /* dup */
	}

	/* verify content is unique. */
	if (IsExistingAssetChecksum(wallet, asset->GetContentChecksum())) {
		return (false);
	}

	/* verify asset content signature */
	if (!asset->VerifyContent(GetCoinIndex(iface))) {
		return (false);
	}

	InsertAssetTable(iface, tx);
	return (true);
}

static bool ProcessUpdateAssetTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	uint256 hPrevAssetTx;

	CAsset *asset = tx.GetAsset();
	if (!asset)
		return (false);

	if (!VerifyAssetChainOrigin(iface, tx, hPrevAssetTx)) {
		return (error(ERR_INVAL, "ProcessUpdateAssetTx: !VerifyAssetChainOrigin"));
	}

	CTransaction p_tx;
	if (!GetTransaction(iface, hPrevAssetTx, p_tx, NULL)) {
		return (error(ERR_INVAL, "ProcessUpdateAssetTx: !GetTransaction(<previous asset>)"));
	}
	CAsset *prevAsset = p_tx.GetAsset();  
	if (!prevAsset) {
		return (error(ERR_INVAL, "ProcessUpdateAssetTx: !prevAsset"));
	}

	if (prevAsset->GetLabel() != asset->GetLabel()) {
		return (error(ERR_INVAL, "ProcessUpdateAsset invalid asset label."));
	}
	if (prevAsset->GetCertificateHash() != asset->GetCertificateHash()) {
		return (error(ERR_INVAL, "ProcessUpdateAsset invalid asset certificate."));
	}

	InsertAssetTable(iface, tx);

	return (true);
}

static bool ProcessTransferAssetTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	uint256 hPrevAssetTx;

	CAsset *asset = tx.GetAsset();
	if (!asset)
		return (false);

	if (!VerifyAssetChainOrigin(iface, tx, hPrevAssetTx)) {
		return (false);
	}

	CTransaction p_tx;
	if (!GetTransaction(iface, hPrevAssetTx, p_tx, NULL)) {
		return (false);
	}
	CAsset *prevAsset = p_tx.GetAsset();  
	if (!prevAsset) {
		return (false);
	}

	if (prevAsset->GetLabel() != asset->GetLabel()) {
		return (false);
	}
	if (prevAsset->GetCertificateHash() != asset->GetCertificateHash()) {
		return (false);
	}
	if (prevAsset->GetContentChecksum() != asset->GetContentChecksum()) {
		return (false);
	}

	InsertAssetTable(iface, tx);
	return (true);
}

static bool ProcessRemoveAssetTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
	uint256 hPrevAssetTx;
	CCert cert;

	CAsset *asset = tx.GetAsset();
	if (!asset)
		return (false);

	const uint160& hIssuer = asset->GetHashIssuer();

	if (!VerifyAssetChainOrigin(iface, tx, hPrevAssetTx)) {
		return (error(ERR_INVAL, "ProcessRemoveAsset invalid chain"));
	}

	CTransaction p_tx;
	if (!GetTransaction(iface, hPrevAssetTx, p_tx, NULL)) {
		return (error(ERR_INVAL, "ProcessRemoveAsset asset transaction unavailable"));
	}
	CAsset *prevAsset = p_tx.GetAsset();  
	if (!prevAsset) {
		return (error(ERR_INVAL, "ProcessRemoveAsset asset unavailable"));
	}

	if (prevAsset->GetLabel() != asset->GetLabel()) {
		return (error(ERR_INVAL, "ProcessRemoveAsset invalid asset label."));
	}
	if (prevAsset->GetCertificateHash() != asset->GetCertificateHash()) {
		return (error(ERR_INVAL, "ProcessRemoveAsset invalid asset certificate."));
	}
	if (prevAsset->GetContentChecksum() != asset->GetContentChecksum()) {
		return (error(ERR_INVAL, "ProcessRemoveAsset invalid asset content checksum."));
	}

	RemoveAssetTable(iface, tx);
	return (true);
}

bool ProcessAssetTx(CIface *iface, CTransaction& tx, int nHeight)
{
  CWallet *wallet = GetWallet(iface);

	if (!VerifyAsset(tx)) {
		return (error(SHERR_INVAL, "ProcessAssetTx: !VerifyAsset"));
	}

	int nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (false);

	int mode;
	uint160 hashAsset;
	if (!DecodeAssetHash(tx.vout[nOut].scriptPubKey, mode, hashAsset))
		return (false); /* no alias hash in output */

	switch (mode) {
		case OP_EXT_NEW:
			if (!ProcessNewAssetTx(iface, tx))
				return (false);
			break;
		case OP_EXT_UPDATE:
			if (!ProcessUpdateAssetTx(iface, tx))
				return (false);
			break;
		case OP_EXT_TRANSFER:
			if (!ProcessTransferAssetTx(iface, tx))
				return (false);
			break;
		case OP_EXT_REMOVE:
			if (!ProcessRemoveAssetTx(iface, tx))
				return (false);
			break;
	}

	return (true);
}

bool DisconnectAssetTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
	CAsset *asset;
	
	asset = tx.GetAsset();
	if (!asset)
		return (error(ERR_INVAL, "DisconnectAssetTx: !Asset"));

	int nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (error(ERR_INVAL, "DisconnectAssetTx: !ExtOutput"));

	int mode;
	uint160 hAsset;
	if (!DecodeAssetHash(tx.vout[nOut].scriptPubKey, mode, hAsset))
		return (error(SHERR_INVAL, "DisconnectAssetTx: no alias hash in output"));

	if (mode == OP_EXT_NEW) {
		/* scrub clean */
		wallet->mapAsset.erase(hAsset);
		wallet->mapAssetChecksum.erase(hAsset);
		return (true);
	}

	/* load entire asset hierarchy. */
	vector<CTransaction> vTx;
	if (!GetAssetChain(iface, tx, vTx))
		return (error(ERR_INVAL, "DisconnectAssetTx: !GetAssetChain"));

	/* set previous asset as primary */
	hAsset = vTx[0].GetAsset()->GetHash();
	uint256 hTx = vTx.back().GetHash();
	wallet->mapAsset[hAsset] = hTx;
	wallet->mapAssetChecksum[hAsset] = vTx.back().GetAsset()->GetContentChecksum();
	return (true);
}

bool GetAssetContent(CIface *iface, CTransaction& tx, cbuff& vContentOut)
{
	vector<CTransaction> vTx;
	uint160 hAsset;
	int mode;

	mode = GetAssetTransactionMode(tx, hAsset);
	if (mode == -1)
		return (false);

	if (mode == OP_EXT_NEW || mode == OP_EXT_UPDATE) {
		CAsset *asset = tx.GetAsset();
		if (!asset)
			return (false);

		vContentOut = asset->GetContent();
		return (true);
	}

	if (mode != OP_EXT_NEW && mode != OP_EXT_UPDATE) {
		if (!GetAssetChain(iface, tx, vTx)) {
			return (error(ERR_INVAL, "GetAssetContent: GetAssetChain failure."));
		}

		/* search through hiearchy for a content record. */
		for (int i = 0; i < vTx.size(); i++) {
			mode = GetAssetTransactionMode(vTx[i], hAsset);
			if (mode == -1)
				return (false);

			if (mode == OP_EXT_NEW || mode == OP_EXT_UPDATE) {
				CAsset *asset = vTx[i].GetAsset();
				if (!asset)
					return (false);

				vContentOut = asset->GetContent();
				return (true);
			}
		}
	}

	return (-1);
}

int init_asset_tx(CIface *iface, string strAccount, uint160 hCert, int nType, const cbuff& vContent, int64 nMinFee, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

	/* calculate fee for asset creation operation. */
  int64 nFee = MAX(nMinFee, GetAssetOpFee(iface, GetBestHeight(iface)));
	if (!MoneyRange(iface, nFee)) {
		return (ERR_INVAL);
	}

	/* verify balanace of account is sufficient. */
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (ERR_FEE);
  }

	/* establish associated certificate. */
  CTransaction cert_tx;
	if (!GetTxOfCert(iface, hCert, cert_tx)) {
		return (ERR_NOENT);
	}
	CCert *certIssuer = cert_tx.GetCertificate();
	if (!certIssuer) {
		return (ERR_NOENT);
	}

	/* inherited attributes from certificate. */
	CCoinAddr extAddr = wallet->GetExtAddr(strAccount);

	/* initialize an asset transaction. */
  CTxCreator s_wtx(wallet, strAccount);
  CAsset *asset = s_wtx.CreateAsset(certIssuer, nType, vContent);

	/* sign cert */
	/* note: all sub-sequent updates, removals, or transfers will retain the same certificate reference. */
  asset->vAddr = cbuff(hCert.begin(), hCert.end());
  if (!asset->SignContent(ifaceIndex))
		return (ERR_ACCESS);

  uint160 assetHash = asset->GetHash();

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());

  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  if (!s_wtx.AddOutput(scriptPubKey, nFee))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (SHERR_CANCELED);

  wtx = (CWalletTx)s_wtx; 
  Debug("(%s) SENT:ASSETNEW : title=%s, cert=%s, assethash=%s, tx=%s\n",
      iface->name, asset->GetLabel().c_str(), hCert.GetHex().c_str(),
      assetHash.ToString().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}

int update_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, const cbuff& vContent, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
	int nOut;

  /* verify original asset */
  CTransaction tx;
  if (!GetTxOfAsset(iface, hashAsset, tx)) {
    return (SHERR_NOENT);
  }
	nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (false);
#if 0
  if(!IsLocalAsset(iface, tx)) {
    return (SHERR_REMOTE);
  }
#endif
	if (!VerifyAssetAccount(wallet, tx.vout[nOut], strAccount)) {
		return (SHERR_ACCESS); /* invalid account specified. */
	}

  /* establish original tx */
  uint256 hTxIn = tx.GetHash();

  /* generate new coin address */
	CCoinAddr extAddr = wallet->GetExtAddr(strAccount);
  if (!extAddr.IsValid()) {
    return (SHERR_INVAL);
  }

	/* establish fee for asset update. */
	int64 nTxFee = (MIN_TX_FEE(iface) * 2);
	int64 nCredit = wallet->GetCredit(tx.vout[nOut]);
  int64 nNetFee = MAX(nTxFee, nCredit - nTxFee);

	/* verify account has balance for tx fee. */
	if (nNetFee > nCredit) {
		int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
		if (bal < (nNetFee - nCredit)) {
			return (ERR_FEE);
		}
	}

	/* create asset */
  CTxCreator s_wtx(wallet, strAccount);
  CAsset *asset = s_wtx.UpdateAsset(&tx.asset, vContent);

  uint160 assetHash = asset->GetHash();

	if (nCredit > nNetFee) {
		s_wtx.SetMinFee(nCredit - nNetFee);
	}

	if (!s_wtx.AddInput(hTxIn, nOut))
		return (false);

  /* generate output script */
	CScript scriptPubKey;
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
  if (!s_wtx.AddOutput(scriptPubKey, nNetFee))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (error(SHERR_CANCELED, "update_asset_tx: %s", s_wtx.GetError().c_str()));

  wtx = (CWalletTx)s_wtx;
  Debug("(%s) SENT:ASSETUPDATE : assethash=%s, tx=%s", 
			iface->name, asset->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

int transfer_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, const CCoinAddr& extAddr, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
	int nOut;

  /* verify original asset */
  CTransaction tx;
  if (!GetTxOfAsset(iface, hashAsset, tx)) {
    return (ERR_NOENT);
  }
	nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (ERR_INVAL);
#if 0
  if (!IsLocalAsset(iface, tx)) {
    return (SHERR_REMOTE);
  }
#endif
	if (!VerifyAssetAccount(wallet, tx.vout[nOut], strAccount)) {
		return (ERR_ACCESS); /* invalid account specified. */
	}

  /* establish original tx */
  uint256 hTxIn = tx.GetHash();

#if 0
  /* generate new coin address */
	CCoinAddr extAddr = wallet->GetExtAddr(strAccount);
  if (!extAddr.IsValid()) {
    return (ERR_INVAL);
  }
#endif

	/* establish fee for asset update. */
	int64 nTxFee = (MIN_TX_FEE(iface) * 2);
	int64 nCredit = wallet->GetCredit(tx.vout[nOut]);
  int64 nNetFee = MAX(nTxFee, nCredit - nTxFee);

	/* verify account has balance for tx fee. */
	if (nNetFee > nCredit) {
		int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
		if (bal < (nNetFee - nCredit)) {
			return (ERR_FEE);
		}
	}

	/* create asset */
  CTxCreator s_wtx(wallet, strAccount);
  CAsset *asset = s_wtx.TransferAsset(tx.GetAsset());
  uint160 assetHash = asset->GetHash();

	if (nCredit > nNetFee) {
		s_wtx.SetMinFee(nCredit - nNetFee);
	}

	if (!s_wtx.AddInput(hTxIn, nOut))
		return (false);

  /* generate output script */
	CScript scriptPubKey;
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_TRANSFER << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
  if (!s_wtx.AddOutput(scriptPubKey, nNetFee))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (error(SHERR_CANCELED, "update_asset_tx: %s", s_wtx.GetError().c_str()));

  wtx = (CWalletTx)s_wtx;
  Debug("SENT:ASSETUPDATE : assethash=%s, tx=%s", asset->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

/**
 * Removes a pre-existing asset on the block-chain. 
 * @param hashAsset The asset hash from it's last tx op.
 * @param strAccount The account that has ownership over the asset.
 * @param wtx The new transaction to be filled in.
 * @note The previous asset tx fee is returned to the current account. The removal tx fee is burned.
 */
int remove_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  /* verify original asset */
  CTransaction tx;
  if (!GetTxOfAsset(iface, hashAsset, tx)) {
    return (SHERR_NOENT);
  }
	int nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (false);
#if 0
  if(!IsLocalAsset(iface, tx)) {
    return (SHERR_REMOTE);
  }
#endif
	if (!VerifyAssetAccount(wallet, tx.vout[nOut], strAccount)) {
		return (SHERR_ACCESS); /* invalid account specified. */
	}

  /* establish original tx */
  uint256 hTxIn = tx.GetHash();

	/* establish fee for asset update. */
	int64 nCredit = wallet->GetCredit(tx.vout[nOut]);
  int64 nNetFee = MIN_TX_FEE(iface);
	int64 nTxFee = nCredit - nNetFee;
	int64 nDebit = nNetFee + nTxFee;

	/* establish fee for asset removal. */
	if (nDebit > nCredit) {
		int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
		if (bal < (nDebit - nCredit)) {
			return (ERR_FEE);
		}
	}

  /* generate tx */
  CAsset *asset;
	CScript scriptPubKey;

  CTxCreator s_wtx(wallet, strAccount);
  asset = s_wtx.RemoveAsset(tx.GetAsset());

  uint160 assetHash = asset->GetHash();

	s_wtx.SetMinFee(nTxFee);

  /* link previous asset as input */
	if (!s_wtx.AddInput(hTxIn, nOut))
		return (false);

  /* generate output script */
	scriptPubKey << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP << OP_RETURN << OP_0;
  if (!s_wtx.AddOutput(scriptPubKey, nNetFee))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (SHERR_CANCELED);
  
  wtx = (CWalletTx)s_wtx;
  Debug("(%s) SENT:ASSETREMOVE : assethash=%s, tx=%s", iface->name, asset->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

