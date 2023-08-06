
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

#ifndef __ALTCHAIN_H__
#define __ALTCHAIN_H__

class CTxIn;
class CTxOut;

typedef map<int, int> color_opt;

class CAltBlock
{

	public:

		/* block header */
		unsigned int nFlag;
		uint256 hashPrevBlock;
		uint256 hashMerkleRoot;
		unsigned int nTime;
		unsigned int nBits;
		unsigned int nNonce;

		CAltBlock()
		{
			SetNull();
			nFlag = 1;
		}

		IMPLEMENT_SERIALIZE
			(
			 READWRITE(nFlag);
			 READWRITE(hashPrevBlock);
			 READWRITE(hashMerkleRoot);
			 READWRITE(nTime);
			 READWRITE(nBits);
			 READWRITE(nNonce);
			)

			void SetNull()
			{
				hashPrevBlock = 0;
				hashMerkleRoot = 0;
				nTime = 0;
				nBits = 0;
				nNonce = 0;
			}

		bool IsNull() const
		{
			return (nBits == 0);
		}

		uint256 GetHash() const
		{
			return Hash(BEGIN(nFlag), END(nNonce));
		}

		int64 GetBlockTime() const
		{
			return (int64)nTime;
		}

		friend bool operator==(const CAltBlock& a, const CAltBlock& b)
		{
			return (
					a.nFlag == b.nFlag &&
					a.hashPrevBlock == b.hashPrevBlock &&
					a.hashMerkleRoot == b.hashMerkleRoot &&
					a.nTime == b.nTime &&
					a.nBits == b.nBits &&
					a.nNonce == b.nNonce
					);
		}

		Object ToValue();

		std::string ToString();

};

class CAltTx
{
	public:
		/* traditional core transaction. */
		unsigned int nFlag;
		std::vector<CTxIn> vin;
		std::vector<CTxOut> vout;
		unsigned int nLockTime;

		/* custom color extension. */
		cbuff vchAux;

		CAltTx()
		{
			SetNull();
		}

		IMPLEMENT_SERIALIZE
			(
			 READWRITE(this->nFlag);
			 READWRITE(vin);
			 READWRITE(vout);
			 READWRITE(nLockTime);
			 if (this->nFlag > 1)
			 READWRITE(vchAux);
			)

			void SetNull()
			{
				nFlag = 1;
				vin.clear();
				vout.clear();
				nLockTime = 0;
				vchAux.clear();
			}

		bool IsNull() const
		{
			return (vin.empty() && vout.empty());
		}

		friend bool operator==(const CAltTx& a, const CAltTx& b)
		{
			return (a.nFlag  == b.nFlag &&
					a.vin       == b.vin &&
					a.vout      == b.vout &&
					a.nLockTime == b.nLockTime &&
					a.vchAux == b.vchAux);
		}

		const uint256 GetHash();

		bool IsCoinBase() const;

		std::string ToString();

		Object ToValue();

};

class CAltChain : public CExtCore
{

	public:
		/** The maximum supported version of an entity type transaction. */
		static const int MAX_ALTBLOCK_VERSION = COLOR_VERSION_MAJOR;

		static const int MAX_ALTCHAIN_LABEL_LENGTH = 135;

		static const int MAX_ALTCHAIN_PAYLOAD_LENGTH = 4096;

		uint32_t nFlag;
		uint160 hColor;
		CAltBlock block;
		std::vector<CAltTx> vtx;

		static const int ALT_MANAGED = (1 << 0);

		CAltChain()
		{
			SetNull();
		}

		CAltChain(uint160 hColor)
		{
			SetNull();
		}

		CAltChain(const CAltChain& altchain)
		{
			SetNull();
			Init(altchain);
		}

		IMPLEMENT_SERIALIZE (
				READWRITE(*(CExtCore *)this);
				READWRITE(this->hColor);
				READWRITE(this->block);
				READWRITE(this->vtx);
				)

		friend bool operator==(const CAltChain &a, const CAltChain &b)
		{
			if (a.vtx.size() != b.vtx.size())
				return (false);
#if 0
			for (int i = 0; i < a.vtx.size(); i++) {
				if (a.vtx[i] == b.vtx[i])
					continue;
				return (false);
			}
#endif
			return (
					((CExtCore&) a) == ((CExtCore&) b) &&
					a.hColor == b.hColor &&
					a.block == b.block
					);
		}

		void Init(const CAltChain& altchain)
		{
			CExtCore::Init(altchain);
			hColor = altchain.hColor;
			block = altchain.block;

			vtx.clear();
			for (int i = 0; i < altchain.vtx.size(); i++) {
				vtx.insert(vtx.end(), altchain.vtx[i]);
			}
		}

		CAltChain operator=(const CAltChain &b)
		{
			SetNull();
			Init(b);
			return *this;
		}

		void SetNull()
		{
			CExtCore::SetNull();

			hColor = 0;
			block.SetNull();
			vtx.clear();
		}

		/* return the altchain contents as a regular block. */
		CBlock *GetBlock();

		const uint160 GetHash();

		const uint160 GetColorHash()
		{
			return (hColor);
		}

		int GetMaximumVersion()
		{
			return (MAX_ALTBLOCK_VERSION);
		}

		int64 CalculateFee(CIface *iface, int nHeight, int nContentSize = -1, time_t nLifespan = -1)
		{
			return (GetMinimumFee(iface, nHeight));
		}

		int64 GetMinimumFee(CIface *iface, int nHeight = -1)
		{
			return ((int64)MIN_TX_FEE(iface) * 10);
		}

		int64 GetMaximumFee(CIface *iface, int nHeight = -1)
		{
			return (GetMinimumFee(iface, nHeight));
		}

		time_t GetMaximumLifespan()
		{
			/* does not expire */
			return (SHTIME_UNDEFINED);
		}

		int VerifyTransaction();

		std::string ToString();

		Object ToValue();

};

/**
 * Generate a CAltChain extended transaction that can be commited to the block-chain.
 */
bool GenerateAltChainBlock(CIface *iface, string strAccount, CAltChain *altchain, uint160 hColor, vector<CTransaction> vTx, const CPubKey& pubkey, CBlock **pBlockRet);

/**
 * Obtain a uint160 hash representing a 128-bit color. 
 * @param strTitle The proper name used to generate the color.
 * @param strColorRet A phrase describing the color.
 * @returns The color encoded as a 20-byte hash sequence.
 * @note The first four bytes of the hash contains the "symbol" of the color.
 */
uint160 GetAltColorHash(CIface *iface, string strTitle, string& strColorRet);

string GetAltColorHashAbrev(uint160 hash);

void GetAltColorCode(uint160 hash, uint32_t *r_p, uint32_t *g_p, uint32_t *b_p, uint32_t *a_p);

bool CommitAltChainTx(CIface *iface, CTransaction& tx, CNode *pfrom, bool fUpdate = false);

/** submit a new active pool altchain-tx containing a alt-chain block. */
bool CommitAltChainPoolTx(CIface *iface, CTransaction& tx, bool fPool = false);

/** submit a altchain-tx containing an orphaned (out of index) block. */
bool CommitAltChainOrphanTx(CIface *iface, const CTransaction& tx);

/**
 * @returns true if the underlying transaction contained an extended altchain transaction.
 */
bool IsAltChainTx(const CTransaction& tx);

int GetAltChainTxMode(CTransaction& tx);

bool DecodeAltChainHash(const CScript& script, int& mode, uint160& hash);

int IndexOfAltChainOutput(const CTransaction& tx);

CCoinAddr GetAltChainAddress(string strAccount, uint160 hColor);

bool GetAltChainPubKey(string strAccount, uint160 hColor, CPubKey& pubkeyRet);

int init_altchain_tx(CIface *iface, string strAccount, uint160 hColor, color_opt& opt, CWalletTx& wtx);

int update_altchain_tx(CIface *iface, string strAccount, uint160 hColor, vector<CTransaction> vAltTx, CWalletTx& wtx);

int update_altchain_tx(CIface *iface, string strAccount, uint160 hColor, const CScript& addrTo, int64 nValueTo, CWalletTx& wtx);

int update_altchain_tx(CIface *iface, string strAccount, uint160 color, const CPubKey& addrTo, int64 nValueTo, CWalletTx& wtx);

int update_altchain_tx(CIface *iface, string strAccount, uint160 hColor, const CCoinAddr& addrTo, int64 nValueTo, CWalletTx& wtx);




#endif /* ndef __ALTCHAIN_H__ */

