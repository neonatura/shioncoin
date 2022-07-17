
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

#ifndef __ASSET_H__
#define __ASSET_H__

enum AssetType {
	NONE = 0,
	/* Any person considered as an asset by the management domain. */
	PERSON = 1,
	/* An entity of any size, complexity, or positioning within an organizational structure. */
	ORGANIZATION = 2,
	/* A discrete set of information resources organized for the collection, processing, maintenance, use, sharing, dissemination, or disposition of information. */
	SYSTEM = 3,
	/* Computer programs and associated data that may be dynamically written or modified during execution. */
	SOFTWARE = 4,
	/* A repository of information or data, which may or may not be a traditional relational database system. */
	DATABASE = 5,
	/* An information system(s) implemented with a collection of interconnected components. Such components may include routers, hubs, cabling, telecommunications controllers, key distribution centers, and technical control devices. */
	NETWORK = 6,
	/* A set of related IT components provided in support of one or more business processes. */
	SERVICE = 7,
	/* Any piece of information suitable for use in a computer. */
	DATA = 8,
	/* A machine (real or virtual) for performing calculations automatically (including, but not limited to, computer, servers, routers, switches, etc. */
	DEVICE = 9,
	/* A dedicated single connection between two endpoints on a network. */
	CIRCUIT = 10,
	/* A network service provider such as a web hosting daemon. */
	DAEMON = 11,
	/* A barcode referencing a consumer product. */
	PRODUCT_BARCODE = 12,
	/* A serial number of a consumer product. */
	PRODUCT_SERIAL = 13,
	/* n/a */
	CUSTOM = 14
};

enum AssetMimeType {
	BINARY = 0,
	TEXT = 1,
	SEXE = 2,
	SQLITE = 3,
	PEM = 4,
	IMAGE_GIF = 5,
	IMAGE_PNG = 6,
	IMAGE_JPEG = 7,
	MODEL_OBJ = 8,
	MODEL_MTL = 9
};


typedef shgeo_t CAssetRegion;

/**
 * An asset is treated as virtual property. All asset transaction associated with the same certificate are considered different attributes of the same asset, and therefore each asset is afforded it's own certificate.
 * Note: Content committed to block-chain must be unique per asset type and content.
 */
class CAsset : public CEntity
{

	protected:
		uint160 hashIssuer; // parent asset
		CSign signature; // signature of content
		cbuff vContent; // asset content data 
		int64 nContentChecksum;
		int nSubType; // type-specific attribute

		cbuff GetSignatureContext(int ifaceIndex);

	public:
		static const int MIN_ASSET_VERSION = 5;

		static const int DEFAULT_ASSET_VERSION = 5;

		static const int MIN_ASSET_LIFESPAN = 378432000; /* 12y */

		static const int MAX_ASSET_LIFESPAN = MAX_EXT_LIFESPAN; /* 48y */

		static const int MAX_ASSET_LABEL_LENGTH = 135;

		static const int MAX_ASSET_CONTENT_LENGTH = 128000;

		CAsset()
		{
			SetNull();
		}

		CAsset(const CAsset& assetIn)
		{
			SetNull();
			Init(assetIn);
		}

		CAsset(CCert& certIn)
		{
			SetNull();
			hashIssuer = certIn.GetHash();
			SetLabel(certIn.GetLabel());
		}

		CAsset(string labelIn)
		{
			SetNull();
			SetLabel(labelIn);
		}

		IMPLEMENT_SERIALIZE (
				READWRITE(*(CEntity *)this);
				READWRITE(this->hashIssuer);
				READWRITE(this->signature);
				READWRITE(this->vContent);
				READWRITE(this->nContentChecksum);
				READWRITE(this->nSubType);
				)

		void SetNull()
		{
			CEntity::SetNull();
			nVersion = DEFAULT_ASSET_VERSION;
		}

		void Init(const CAsset& assetIn)
		{
			CEntity::Init(assetIn);
			hashIssuer = assetIn.hashIssuer;
			signature = assetIn.signature;
			vContent = assetIn.vContent;
			nContentChecksum = assetIn.nContentChecksum;
			nSubType = assetIn.nSubType;
		}

		friend bool operator==(const CAsset &a, const CAsset &b)
		{
			return (
					((CEntity&) a) == ((CEntity&) b) &&
					a.hashIssuer == b.hashIssuer &&
					a.signature == b.signature &&
					a.vContent == b.vContent &&
					a.nContentChecksum == b.nContentChecksum &&
					a.nSubType == b.nSubType
					);
		}

		CAsset operator=(const CAsset &b)
		{
			SetNull();
			Init(b);
			return (*this);
		}

		bool SignContent(int ifaceIndex);

		bool VerifyContent(int ifaceIndex);

		uint160 GetHashIssuer()
		{
			return (hashIssuer);
		}

		void SetHashIssuer(uint160 hash)
		{
			hashIssuer = hash;
		}

		CSign GetSignature()
		{
			return (signature);
		}

		void SetSignature(const CSign& signatureIn)
		{
			signature = signatureIn;
		}

		cbuff GetContent()
		{
			return (vContent);
		}

		void SetContent(const cbuff& vContentIn)
		{
			vContent = vContentIn;
			SetContentChecksum();
		}

		int64 GetContentChecksum()
		{
			return (nContentChecksum);
		}

		int GetContentSize()
		{
			return (vContent.size());
		}

		int64 CalculateContentChecksum()
		{
			return (GetType() + bcrc(vContent.data(), vContent.size())); // libshare
		}

		void SetContentChecksum(int64 nChecksum)
		{
			nContentChecksum = nChecksum;
		}

		void SetContentChecksum()
		{
			SetContentChecksum(CalculateContentChecksum());
		}

		void ResetContent()
		{
			// retains checksum
			vContent = cbuff();
		}

		int GetMaximumContentSize() /* CEntity */
		{
			return (MAX_ASSET_CONTENT_LENGTH);
		}

		bool VerifyContentChecksum()
		{
			return (GetContentChecksum() == CalculateContentChecksum());
		}

		int GetSubType()
		{
			return (nSubType);
		}

		void SetSubType(int nSubTypeIn)
		{
			nSubType = nSubTypeIn;
		}

		CAssetRegion *GetRegion()
		{
			return (&geo);
		}

		void SetRegion(const CAssetRegion& region)
		{
			memcpy(&geo, &region, sizeof(CAssetRegion));
		}

		uint160 GetCertificateHash()
		{
			uint160 hCert(vAddr);
			return (hCert);
		}

		void SetCertificateHash(uint160 hCert)
		{
			vAddr = cbuff(hCert.begin(), hCert.end());
		}

		string GetMimeType();

		int GetMinimumVersion()
		{
			return (MIN_ASSET_VERSION);
		}

		int64 CalculateFee(CIface *iface, int nHeight, int nContentSize = -1, time_t nLifespan = -1);

		time_t GetMinimumLifespan()
		{
			return (MIN_ASSET_LIFESPAN);
		}

		time_t CalculateLifespan(CIface *iface, int64 nFee);

		void ResetExpireTime(CIface *iface, int64 nFee)
		{
			SetExpireSpan(CalculateLifespan(iface, nFee));
		}

		int VerifyTransaction();

		const uint160 GetHash()
		{
			uint256 hashOut = SerializeHash(*this);
			unsigned char *raw = (unsigned char *)&hashOut;
			cbuff rawbuf(raw, raw + sizeof(hashOut));
			return Hash160(rawbuf);
		}

		string ToString();

		Object ToValue();

		static string GetExtLabel()
		{
			return ("ASSET");
		}

};


CAsset *GetAssetByHash(CIface *iface, const uint160& hashAsset, CTransaction& tx); 

int64 GetAssetOpFee(CIface *iface, int nHeight); 

bool GetAssetContent(CIface *iface, CTransaction& tx, cbuff& vContentOut);

asset_list *GetAssetTable(int ifaceIndex);

bool IsAssetTx(const CTransaction& tx);

bool VerifyAsset(CTransaction& tx);

bool ProcessAssetTx(CIface *iface, CTransaction& tx, int nHeight);

bool DisconnectAssetTx(CIface *iface, CTransaction& tx);

int IndexOfAssetOutput(const CTransaction& tx);

bool DecodeAssetHash(const CScript& script, int& mode, uint160& hash);

int init_asset_tx(CIface *iface, string strAccount, uint160 hCert, int nType, int nSubType, const cbuff& vContent, int64 nMinFee, CWalletTx& wtx);

int update_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, const cbuff& vContent, CWalletTx& wtx);

int transfer_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, const CCoinAddr& dest, CWalletTx& wtx);

int activate_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, int64 nMinFee, CWalletTx& wtx);

int remove_asset_tx(CIface *iface, string strAccount, const uint160& hashAsset, CWalletTx& wtx);

int64 CalculateAssetFee(CIface *iface, int nHeight, int nContentSize = 0, time_t nLifespan = 0);

const string GetAssetTypeLabel(int type);

int GetAssetType(string strType);

void GetAssetTypeLabels(vector<string>& vLabel);

const string GetAssetSubTypeLabel(int type, int subType);

int GetAssetSubType(int type, string strSubType);

void GetAssetSubTypeLabels(int type, vector<string>& vLabel);

const string GetAssetMimeTypeLabel(int mimeType);

int GetAssetMimeType(string strMimeType);


#endif /* ndef __ASSET_H__ */


