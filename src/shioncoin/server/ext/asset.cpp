
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

#define MAX_ASSET_TYPES 14
#define MAX_ASSET_MIME_TYPES 10 

static char *AssetTypeLabels[MAX_ASSET_TYPES] =
{
	"None",
	"Person",
	"Organization",
	"System",
	"Database",
	"Network",
	"Service",
	"Data",
	"Device",
	"Circuit",
	"Daemon",
	"Barcode",
	"SerialNumber",
	"Custom"
};

static char *AssetMimeTypeLabels[MAX_ASSET_MIME_TYPES] =
{
	"text/plain",
	"application/octet-stream",
	"application/x-sexe",
	"application/x-sqlite3",
	"application/x-pem-file",
	"image/gif",
	"image/png",
	"image/jpeg",
	"model/obj",
	"model/mtl"
};

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

#if 0
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
#endif

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

int64 CalculateAssetFee(CIface *iface, int nHeight, int nContentSize, time_t nLifespan)
{
	/* base fee */
  double base = ((nHeight+1) / 1024) + 1;
  double nRes = 10280 / base * COIN;
  double nDif = 9964 / base * COIN;
  int64 nFee = (int64)(nRes - nDif);

	/* content fee */
	int nSize = nContentSize / 16;
  double nFact = 8192 / (double)MIN(8192, MAX(64, nSize));
  nFee = (int64)((double)nFee / nFact);

	/* lifespan */
	if (nLifespan != 0) {
		nLifespan = MAX(nLifespan, CAsset::MIN_ASSET_LIFESPAN);
		nLifespan = MIN(nLifespan, CAsset::MAX_ASSET_LIFESPAN);
		nFee = (int64)((double)nFee / (double)CAsset::MIN_ASSET_LIFESPAN * (double)nLifespan);
	}

	/* limits */
  nFee = MAX(MIN_TX_FEE(iface), nFee);
  nFee = MIN(MAX_TX_FEE(iface), nFee);

fprintf(stderr, "DEBUG: CalculateAssetFee(): nContentSize(%u) nLifespan(%d) nFee(%-8.8f)\n", nContentSize, nLifespan, ((double)nFee/COIN));  

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

    if (DecodeAssetHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return (false);
  }

  return (true);
}

/**
 * Obtain the tx that defines this asset.
 */
CAsset *GetAssetByHash(CIface *iface, const uint160& hashAsset, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  asset_list *assetes = GetAssetTable(ifaceIndex);
  bool ret;

  if (assetes->count(hashAsset) == 0) {
    return (NULL); /* nothing by that name, sir */
  }

  uint256 hashBlock;
  uint256 hashTx = (*assetes)[hashAsset];
  ret = GetTransaction(iface, hashTx, tx, NULL);
  if (!ret) {
    return (NULL);
  }

  if (!IsAssetTx(tx)) {
    return (NULL); /* inval; not an asset tx */
	}

	CAsset *asset = tx.GetAsset();
	if (!asset) {
		return (NULL);
	}

	if (asset->IsExpired()) {
		return (NULL); /* no longer valid. */
	}

	return (asset);
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
int IndexOfAssetOutput(const CTransaction& tx)
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

#if 0
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
#endif

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

	const string& strLabel = GetAssetTypeLabel(GetType());
	if (strLabel != "") {
		obj.push_back(Pair("category", strLabel)); 
	}
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
	obj.push_back(Pair("mimetype", GetMimeType()));

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
	if (hashIssuer != 0 && GetAssetByHash(iface, hashIssuer, asset_tx)) {
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

	if (GetType() == AssetType::SOFTWARE ||
			GetType() == AssetType::DATABASE ||
			GetType() == AssetType::DATA) {
		return (GetAssetMimeTypeLabel(GetSubType()));
	}

	return (string("application/octet-stream"));
}

int CAsset::VerifyTransaction()
{
	const uint160& hCert = GetCertificateHash();
	int err;

	err = CEntity::VerifyTransaction();
	if (err)
		return (err);

	if (vContent.size() > MAX_ASSET_CONTENT_LENGTH) {
		return (ERR_2BIG);
	}

	if (hCert == 0) {
		return (ERR_INVAL);
	}

	return (0);
}

int64 CAsset::CalculateFee(CIface *iface, int nHeight, int nContentSize, time_t nLifespan)
{
	if (nContentSize == -1) {
		nContentSize = GetContentSize();
	}
	if (nLifespan == -1) {
		nLifespan = GetLifespan();	
	}

	return (CalculateAssetFee(iface, nHeight, nContentSize, nLifespan));
}

time_t CAsset::CalculateLifespan(CIface *iface, int64 nFee)
{
	nFee = MAX(nFee, MIN_TX_FEE(iface));
	nFee = MIN(nFee, MAX_TX_FEE(iface));

  int nHeight = GetBestHeight(iface);
	int64 nBaseFee = CalculateFee(iface, nHeight, GetContentSize(), 0);
	double fact = 1 / (double)nBaseFee * (double)nFee;

	time_t lifespan = (time_t)(GetMinimumLifespan() * fact);
	lifespan = MAX(lifespan, GetMinimumLifespan());
	lifespan = MIN(lifespan, GetMaximumLifespan());

#if 0
	double feeFactMax = 1 / GetMinimumFee(iface) * GetMaximumFee(iface);
	double feeFact = MIN(feeFactMax, 1 / GetMinimumFee(iface) * nFee);
	double lifespan = MAX((double)GetMinimumLifespan(),
			(double)GetMaximumLifespan() / feeFactMax * feeFact);
	return ((time_t)lifespan);
#endif

	return (lifespan);
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
	if (!GetAssetByHash(iface, hAsset, asset_tx)) {
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

fprintf(stderr, "DEBG: REMOVE ME: ProcessNewAssetTx()/start\n");

	if (wallet->mapAsset.count(hAsset) != 0) {
		return (error(ERR_NOTUNIQ, "ProcessNewAssetTx: non-unique hash asset."));
	}

	/* verify content checksum. */
	if (!asset->VerifyContentChecksum()) {
		return (error(ERR_INVAL, "ProcessNewAssetTx: invalid content checksum."));
	}

	/* verify content is unique. */
	if (IsExistingAssetChecksum(wallet, asset->GetContentChecksum())) {
		return (error(ERR_INVAL, "ProcessNewAssetTx: IsExistingAssetChecksum()"));
	}

	/* verify asset content signature */
	if (!asset->VerifyContent(GetCoinIndex(iface))) {
		return (error(ERR_INVAL, "ProcessNewAssetTx: invalid content signature"));
	}


	InsertAssetTable(iface, tx);
fprintf(stderr, "DEBG: REMOVE ME: ProcessNewAssetTx()/finish\n");
	return (true);
}

static bool ProcessUpdateAssetTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	uint256 hPrevAssetTx;

fprintf(stderr, "DEBG: REMOVE ME: ProcessUpdateAssetTx()/start\n");

	CAsset *asset = tx.GetAsset();
	if (!asset)
		return (false);

	/* verify content is unique. */
	if (IsExistingAssetChecksum(wallet, asset->GetContentChecksum())) {
		return (error(ERR_INVAL, "ProcessUpdateAssetTx: content references already existing content."));
	}

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
	if (prevAsset->GetExpireTime() != asset->GetExpireTime()) {
		return (error(ERR_INVAL, "ProcessRemoveAsset invalid asset expiration."));
	}

	InsertAssetTable(iface, tx);
fprintf(stderr, "DEBG: REMOVE ME: ProcessUpdateAssetTx()/finish\n");

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
	if (prevAsset->GetExpireTime() != asset->GetExpireTime()) {
		return (error(ERR_INVAL, "ProcessRemoveAsset invalid asset expiration."));
	}

	InsertAssetTable(iface, tx);
	return (true);
}

static bool ProcessActivateAssetTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
	uint256 hPrevAssetTx;

fprintf(stderr, "DEBG: REMOVE ME: ProcessActivateAssetTx()/start\n");

	CAsset *asset = tx.GetAsset();
	if (!asset)
		return (false);

	if (!VerifyAssetChainOrigin(iface, tx, hPrevAssetTx)) {
		return (error(ERR_INVAL, "ProcessActivateAssetTx: !VerifyAssetChainOrigin"));
	}

	/* verify content checksum. */
	if (!asset->VerifyContentChecksum()) {
		return (error(ERR_INVAL, "ProcessNewAssetTx: invalid content checksum."));
	}

	CTransaction p_tx;
	if (!GetTransaction(iface, hPrevAssetTx, p_tx, NULL)) {
		return (error(ERR_INVAL, "ProcessActivateAssetTx: !GetTransaction(<previous asset>)"));
	}
	CAsset *prevAsset = p_tx.GetAsset();  
	if (!prevAsset) {
		return (error(ERR_INVAL, "ProcessActivateAssetTx: !prevAsset"));
	}

	if (prevAsset->GetLabel() != asset->GetLabel()) {
		return (error(ERR_INVAL, "ProcessActivateAsset invalid asset label."));
	}
	if (prevAsset->GetCertificateHash() != asset->GetCertificateHash()) {
		return (error(ERR_INVAL, "ProcessActivateAsset invalid asset certificate."));
	}
	if (prevAsset->GetContentChecksum() != asset->GetContentChecksum()) {
fprintf(stderr, "DEBUG: TEST: prevAsset->GetContentChecksum %llu\n", prevAsset->GetContentChecksum());
fprintf(stderr, "DEBUG: TEST: asset->GetContentChecksum %llu\n", asset->GetContentChecksum());
		return (error(ERR_INVAL, "ProcessActivateAsst: invalid asset checksum."));
	}

	InsertAssetTable(iface, tx);
fprintf(stderr, "DEBG: REMOVE ME: ProcessActivateAssetTx()/finish\n");

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
	if (prevAsset->GetExpireTime() != asset->GetExpireTime()) {
		return (error(ERR_INVAL, "ProcessRemoveAsset invalid asset expiration."));
	}

	RemoveAssetTable(iface, tx);
	return (true);
}

bool ProcessAssetTx(CIface *iface, CTransaction& tx, int nHeight)
{
  CWallet *wallet = GetWallet(iface);

	if (!tx.VerifyAsset(GetCoinIndex(iface))) {
		return (error(SHERR_INVAL, "ProcessAssetTx: !VerifyAsset"));
	}

	int nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (error(SHERR_INVAL, "no asset output script"));

	int mode;
	uint160 hashAsset;
	if (!DecodeAssetHash(tx.vout[nOut].scriptPubKey, mode, hashAsset))
		return (error(SHERR_INVAL, "no asset hash in output"));

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
		case OP_EXT_ACTIVATE:
			if (!ProcessActivateAssetTx(iface, tx))
				return (error(ERR_INVAL, "ProcessAssetTx: ProcessActivateAssetTx failure"));
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

	if (mode == OP_EXT_NEW || mode == OP_EXT_UPDATE || mode == OP_EXT_ACTIVATE) {
		CAsset *asset = tx.GetAsset();
		if (!asset)
			return (false);

		vContentOut = asset->GetContent();
		return (true);
	}

	if (!GetAssetChain(iface, tx, vTx)) {
		return (error(ERR_INVAL, "GetAssetContent: GetAssetChain failure."));
	}

	/* search through hiearchy for a content record. */
	for (int i = (vTx.size() - 1); i >= 0; i--) {
		mode = GetAssetTransactionMode(vTx[i], hAsset);
		if (mode == -1)
			return (false);

		if (mode == OP_EXT_NEW || mode == OP_EXT_UPDATE || mode == OP_EXT_ACTIVATE) {
			CAsset *asset = vTx[i].GetAsset();
			if (!asset)
				return (false);

			vContentOut = asset->GetContent();
			return (true);
		}
	}

	return (-1);
}

/* establish fee for generating an asset transaction. */
static bool EstablishAssetFee(CIface *iface, const string& strAccount, CTxCreator& wtx, 
		const CTxOut *vout, int64& nNetFee, int64 nMinFee = 0)
{
  CWallet *wallet = GetWallet(iface);
	CAsset *asset = wtx.GetAsset();
  int nHeight = GetBestHeight(iface);
  int ifaceIndex = GetCoinIndex(iface);
	int64 nCredit = 0;

	if (!asset)
		return (false);

	if (vout) {
		nCredit = vout->nValue;
	}

  nNetFee = MAX(nMinFee, asset->CalculateFee(iface, nHeight)); // asset fee
  int64 nTxFee = MAX(MIN_TX_FEE(iface), nCredit - nNetFee); // remainder as tx fee

  int64 nDebit = nNetFee + nTxFee; // the total debit amount
	if (nDebit > nCredit) {
		/* verify account has balance for tx fee. */
		int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
		if (bal < (nDebit - nCredit)) {
			return (false);
		}
	}

	wtx.SetMinFee(nTxFee);
	return (true);
}

const string GetAssetTypeLabel(int type)
{

	if (type < 0 || type >= MAX_ASSET_TYPES)
		return (string());

	return (string(AssetTypeLabels[type]));
}

int GetAssetType(string strType)
{
	int idx;

	for (idx = 0; idx < MAX_ASSET_TYPES; idx++) {
		if (0 == strcasecmp(strType.c_str(), AssetTypeLabels[idx])) {
			return (idx);
		}
	}

	return (-1);
}

void GetAssetTypeLabels(vector<string>& vLabel)
{
	int idx;

	vLabel.clear();
	for (idx = 0; idx < MAX_ASSET_TYPES; idx++) {
		vLabel.push_back(string(AssetTypeLabels[idx]));
	}
}

int GetMaxAssetSubTypes(int type)
{

	switch (type) {
		case AssetType::SOFTWARE:
		case AssetType::DATABASE:
		case AssetType::DATA:
			return (MAX_ASSET_MIME_TYPES);
	}
	return (0);
}

const string GetAssetSubTypeLabel(int type, int subType)
{

	switch (type) {
		case AssetType::SOFTWARE:
		case AssetType::DATABASE:
		case AssetType::DATA:
			return (GetAssetMimeTypeLabel(subType));
	}

	return (string());
}

int GetAssetSubType(int type, string strSubType)
{

	switch (type) {
		case AssetType::DATA:
			return (GetAssetMimeType(strSubType));
	}

	return (-1);
}

void GetAssetSubTypeLabels(int type, vector<string>& vLabel)
{
	int nMax = GetMaxAssetSubTypes(type);
	int idx;

	vLabel.clear();
	switch (type) {
		case AssetType::DATA:
			for (idx = 0; idx < nMax; idx++) {
				string strLabel = GetAssetSubTypeLabel(type, idx);
				vLabel.push_back(strLabel);
			}
			break;
	}
}

const string GetAssetMimeTypeLabel(int mimeType)
{

	if (mimeType < 0 || mimeType >= MAX_ASSET_MIME_TYPES)
		return (string());

	return (string(AssetMimeTypeLabels[mimeType]));
}

int GetAssetMimeType(string strMimeType)
{
	int idx;

	for (idx = 0; idx < MAX_ASSET_MIME_TYPES; idx++) {
		if (0 == strcasecmp(strMimeType.c_str(), AssetMimeTypeLabels[idx])) {
			return (idx);
		}
	}

	return (-1);
}

int init_asset_tx(CIface *iface, string strAccount, uint160 hCert, int nType, int nSubType, const cbuff& vContent, int64 nMinFee, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

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
  CAsset *asset = s_wtx.CreateAsset(certIssuer, nType, nSubType, vContent);

	/* ensure content is unique per asset type. */
	if (IsExistingAssetChecksum(wallet, asset->GetContentChecksum())) {
		return (ERR_NOTUNIQ);
	}

	/* calculate fee for asset creation operation. */
  int nHeight = GetBestHeight(iface);
  int64 nFee = MAX(nMinFee, asset->CalculateFee(iface, nHeight));
	if (!MoneyRange(iface, nFee)) {
		return (ERR_INVAL);
	}
	/* verify balanace of account is sufficient. */
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (ERR_FEE);
  }

	/* establish expiration timestamp. */
	asset->ResetExpireTime(iface, nFee);

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
  if (!GetAssetByHash(iface, hashAsset, tx)) {
    return (SHERR_NOENT);
  }
	nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (ERR_INVAL);
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

	/* create asset */
  CTxCreator s_wtx(wallet, strAccount);
  CAsset *asset = s_wtx.UpdateAsset(&tx.asset, vContent);

	/* ensure content is unique per asset type. */
	if (IsExistingAssetChecksum(wallet, asset->GetContentChecksum())) {
		return (ERR_NOTUNIQ);
	}

	/* establish fee for asset update. */
	int nHeight = GetBestHeight(iface);
	int64 nCredit = wallet->GetCredit(tx.vout[nOut]); // past credit
	int64 nNetFee = asset->CalculateFee(iface, nHeight); // asset fee
	int64 nTxFee = MAX(MIN_TX_FEE(iface), nCredit - nNetFee); // remainder as tx fee
	int64 nDebit = nNetFee + nTxFee; // the total debit amount
	if (nDebit > nCredit) {
		/* verify account has balance for tx fee. */
		int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
		if (bal < (nDebit - nCredit)) {
			return (ERR_FEE);
		}
	}
	s_wtx.SetMinFee(nTxFee);

  /* link previous asset as input */
	if (!s_wtx.AddInput(hTxIn, nOut))
		return (ERR_INVAL);

  /* generate output script */
	CScript scriptPubKey;
	CScript scriptPubKeyOrig;
  uint160 assetHash = asset->GetHash();
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
  if (!s_wtx.AddOutput(scriptPubKey, nNetFee))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (SHERR_CANCELED);//, "update_asset_tx: %s", s_wtx.GetError().c_str()));

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
  if (!GetAssetByHash(iface, hashAsset, tx)) {
    return (ERR_NOENT);
  }
	nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (ERR_INVAL);
	if (!VerifyAssetAccount(wallet, tx.vout[nOut], strAccount)) {
		return (ERR_ACCESS); /* invalid account specified. */
	}

  /* establish original tx */
  uint256 hTxIn = tx.GetHash();

	/* create asset */
  CTxCreator s_wtx(wallet, strAccount);
  CAsset *asset = s_wtx.TransferAsset(tx.GetAsset());

  /* establish fee for asset transfer. */
  int nHeight = GetBestHeight(iface);
  int64 nCredit = wallet->GetCredit(tx.vout[nOut]); // past credit
  int64 nNetFee = asset->CalculateFee(iface, nHeight); // asset fee
  int64 nTxFee = MAX(MIN_TX_FEE(iface), nCredit - nNetFee); // remainder as tx fee
  int64 nDebit = nNetFee + nTxFee; // the total debit amount
	if (nDebit > nCredit) {
		/* verify account has balance for tx fee. */
		int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
		if (bal < (nDebit - nCredit)) {
			return (ERR_FEE);
		}
	}
	s_wtx.SetMinFee(nTxFee);

	/* add previous asset as transaction input. */
	if (!s_wtx.AddInput(hTxIn, nOut))
		return (ERR_INVAL);

  /* generate output script */
  uint160 assetHash = asset->GetHash();
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

int activate_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, int64 nMinFee, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
	int nOut;

  /* verify original asset */
  CTransaction tx;
  if (!GetAssetByHash(iface, hashAsset, tx)) {
    return (ERR_NOENT);
  }
	nOut = IndexOfAssetOutput(tx);
	if (nOut == -1) {
fprintf(stderr, "DEBUG: TEST: !IndexOfAssetOutput(tx)\n");
		return (ERR_INVAL);
	}
	if (!VerifyAssetAccount(wallet, tx.vout[nOut], strAccount)) {
		return (ERR_ACCESS); /* invalid account specified. */
	}

  /* establish original tx */
  uint256 hTxIn = tx.GetHash();

  /* generate new coin address */
	CCoinAddr extAddr = wallet->GetExtAddr(strAccount);
  if (!extAddr.IsValid()) {
fprintf(stderr, "DEBUG: TEST: !extAddr\n");
    return (SHERR_INVAL);
  }
	/* create asset tx */
  CTxCreator s_wtx(wallet, strAccount);
  CAsset *asset = s_wtx.ActivateAsset(tx.GetAsset());

	/* add previous asset as transaction input. */
	if (!s_wtx.AddInput(hTxIn, nOut)) {
fprintf(stderr, "DEBUG: TEST: !s_wtx.AddInput()\n");
		return (ERR_INVAL);
	}

	/* redefine content. */
	cbuff vContent;
	if (!GetAssetContent(iface, tx, vContent)) {
fprintf(stderr, "DEBUG: TEST: !GetAssetContent\n");
		return (ERR_INVAL);
	}
	asset->SetContent(vContent);
fprintf(stderr, "DEBUG: activate_asset_tx: vContent size %u\n", asset->GetContentSize()); 

  /* establish fee for asset transfer. */
  int nHeight = GetBestHeight(iface);
  int64 nCredit = wallet->GetCredit(tx.vout[nOut]); // past credit
  int64 nNetFee = MAX(nMinFee, asset->CalculateFee(iface, nHeight)); // asset fee
  int64 nTxFee = MAX(MIN_TX_FEE(iface), nCredit - nNetFee); // remainder as tx fee
  int64 nDebit = nNetFee + nTxFee; // the total debit amount
	if (nDebit > nCredit) {
		/* verify account has balance for tx fee. */
		int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
		if (bal < (nDebit - nCredit)) {
			return (ERR_FEE);
		}
	}
	s_wtx.SetMinFee(nTxFee);

	/* reset expiration. */
	asset->ResetExpireTime(iface, nNetFee);

  /* generate output script */
  uint160 assetHash = asset->GetHash();
	CScript scriptPubKey;
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_ACTIVATE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
  if (!s_wtx.AddOutput(scriptPubKey, nNetFee)) {
fprintf(stderr, "DEBUG: TEST: !s_wtx.AddOutput(%s, %-8.8f)\n", scriptPubKey.ToString().c_str(), ((double)nNetFee/COIN));
    return (SHERR_INVAL);
	}


  if (!s_wtx.Send())
    return (error(SHERR_CANCELED, "activate_asset_tx: %s", s_wtx.GetError().c_str()));

  wtx = (CWalletTx)s_wtx;
  Debug("SENT:ASSETACTIVATE : assethash=%s, tx=%s", asset->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

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
  if (!GetAssetByHash(iface, hashAsset, tx)) {
    return (SHERR_NOENT);
  }
	int nOut = IndexOfAssetOutput(tx);
	if (nOut == -1)
		return (SHERR_INVAL);
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

  /* generate tx */
  CTxCreator s_wtx(wallet, strAccount);
  CAsset *asset = s_wtx.RemoveAsset(tx.GetAsset());

	/* establish fee for asset removal. */
	int nHeight = GetBestHeight(iface);
	int64 nCredit = wallet->GetCredit(tx.vout[nOut]); // past credit
  int64 nNetFee = asset->CalculateFee(iface, nHeight); // asset fee
	int64 nTxFee = MAX(MIN_TX_FEE(iface), nCredit - nNetFee); // remainder as tx fee
	int64 nDebit = nNetFee + nTxFee; // the total debit amount
	if (nDebit > nCredit) {
		/* verify account has balance for tx fee. */
		int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
		if (bal < (nDebit - nCredit)) {
			return (ERR_FEE);
		}
	}
	s_wtx.SetMinFee(nTxFee);

  /* link previous asset as input */
	if (!s_wtx.AddInput(hTxIn, nOut))
		return (SHERR_INVAL);

  /* generate output script */
	CScript scriptPubKey;
  uint160 assetHash = asset->GetHash();
	scriptPubKey << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_ASSET) << OP_HASH160 << assetHash << OP_2DROP << OP_RETURN << OP_0;
  if (!s_wtx.AddOutput(scriptPubKey, nNetFee))
    return (SHERR_INVAL);

  if (!s_wtx.Send())
    return (SHERR_CANCELED);
  
  wtx = (CWalletTx)s_wtx;
  Debug("(%s) SENT:ASSETREMOVE : assethash=%s, tx=%s", iface->name, asset->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

