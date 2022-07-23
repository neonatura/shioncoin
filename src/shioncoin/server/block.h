
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

#ifndef __SERVER__BLOCK_H__
#define __SERVER__BLOCK_H__

#include <boost/foreach.hpp>
#include <vector>

#include "uint256.h"
#include "serialize.h"
#include "util.h"
#include "scrypt.h"
#include "protocol.h"
#include "net.h"
#include "json_spirit_reader_template.h"
#include "json_spirit_writer_template.h"
using namespace std;
using namespace json_spirit;
#include "script.h"
#include "coin_proto.h"
#include "txext.h"
#include "matrix.h"
#include "ext_param.h"

typedef std::map<uint256, CTransaction> tx_cache;


typedef std::vector<uint256> HashList;

typedef map< uint256, vector<uint256> > tx_map;





#if defined(USE_LEVELDB_COINDB) || defined(USE_LEVELDB_TXDB)
class CTxDB;
#endif





bool GetTransaction(CIface *iface, const uint256 &hash, CTransaction &tx, uint256 *hashBlock);



/* block_iface.cpp */
int GetBlockDepthInMainChain(CIface *iface, uint256 blockHash);
int GetTxDepthInMainChain(CIface *iface, uint256 txHash);




extern FILE* AppendBlockFile(unsigned int& nFileRet);
extern bool IsInitialBlockDownload();
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode);



enum GetMinFee_mode
{
    GMF_BLOCK,
    GMF_RELAY,
    GMF_SEND,
};

/* Tue Nov  5 00:53:20 1985 UTC */
static const unsigned int LOCKTIME_THRESHOLD = 500000000; 

inline bool MoneyRange(CIface *iface, int64 nValue) 
{ 
  if (!iface) return (false);
  return (nValue >= 0 && nValue <= iface->max_money);
}
inline bool MoneyRange(int ifaceIndex, int64 nValue) 
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface) return (false);
  return (nValue >= 0 && nValue <= iface->max_money);
}


/** Reference to a specific block transaction. */
class CDiskTxPos
{
public:
    unsigned int nFile;
    unsigned int nBlockPos;
    unsigned int nTxPos;
    mutable uint256 hashBlock;
    mutable uint256 hashTx;

    CDiskTxPos()
    {
        SetNull();
    }

    CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn)
    {
      SetNull();
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nTxPos = nTxPosIn;
    }

    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { nFile = (unsigned int) -1; nBlockPos = 0; nTxPos = 0; }
    bool IsNull() const { return (nFile == (unsigned int) -1); }

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.nFile     == b.nFile &&
                a.nBlockPos == b.nBlockPos &&
                a.nTxPos    == b.nTxPos);
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        if (IsNull())
            return "null";
        else
            return strprintf("(nTxHeight=%d, nBlockHeight=%d, nTxPos=%d)", nFile, nBlockPos, nTxPos);
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }

};


/**  A txdb record that contains the disk location of a transaction and the
 * locations of transactions that spend its outputs.  vSpent is really only
 * used as a flag, but having the location is very helpful for debugging.
 */
class CTxIndex
{
public:
    CDiskTxPos pos;
    std::vector<CDiskTxPos> vSpent;

    CTxIndex()
    {
        SetNull();
    }

    CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs)
    {
        pos = posIn;
        vSpent.resize(nOutputs);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(pos);
        READWRITE(vSpent);
    )

    void SetNull()
    {
        pos.SetNull();
        vSpent.clear();
    }

    bool IsNull()
    {
        return pos.IsNull();
    }

    friend bool operator==(const CTxIndex& a, const CTxIndex& b)
    {
        return (a.pos    == b.pos &&
                a.vSpent == b.vSpent);
    }

    friend bool operator!=(const CTxIndex& a, const CTxIndex& b)
    {
        return !(a == b);
    }
 
};
typedef std::map<uint256, std::pair<CTxIndex, CTransaction> > MapPrevTx;



/** An inpoint - a combination of a transaction and an index n into its vin */
class CInPoint
{
public:
    CTransaction* ptx;
    unsigned int n;

    CInPoint() { SetNull(); }
    CInPoint(CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = (unsigned int) -1; }
    bool IsNull() const { return (ptx == NULL && n == (unsigned int) -1); }
};



/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    unsigned int n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { hash = 0; n = (unsigned int) -1; }
    bool IsNull() const { return (hash == 0 && n == (unsigned int) -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        return strprintf("COutPoint(%s, %d)", hash.ToString().substr(0,10).c_str(), n);
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};



/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
	public:
    COutPoint prevout;
    CScript scriptSig;
    unsigned int nSequence;

		static const uint32_t SEQUENCE_FINAL = 0xffffffff;

		/* Below flags apply in the context of BIP 68*/
		/* If this flag set, CTxIn::nSequence is NOT interpreted as a
		 * relative lock-time. */
		static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

		/* If CTxIn::nSequence encodes a relative lock-time and this flag
		 * is set, the relative lock-time has units of 512 seconds,
		 * otherwise it specifies blocks with a granularity of 1. */
		static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

		/* If CTxIn::nSequence encodes a relative lock-time, this mask is
		 * applied to extract that lock-time from the sequence field. */
		static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

		/* In order to use the same number of bits to encode roughly the
		 * same wall-clock duration, and because blocks are naturally
		 * limited to occur every 600s on average, the minimum granularity
		 * for time-based relative lock-time is fixed at 512 seconds.
		 * Converting from CTxIn::nSequence to seconds is performed by
		 * multiplying by 512 = 2^9, or equivalently shifting up by
		 * 9 bits. */
		static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=SEQUENCE_FINAL)
    {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=SEQUENCE_FINAL)
    {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    )

    bool IsFinal() const
    {
        return (nSequence == SEQUENCE_FINAL);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        std::string str;
        str += "CTxIn(";
        str += prevout.ToString();
        if (prevout.IsNull())
            str += strprintf(", coinbase %s", HexStr(scriptSig).c_str());
        else
            str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24).c_str());
        if (nSequence != std::numeric_limits<unsigned int>::max())
            str += strprintf(", nSequence=%u", nSequence);
        str += ")";
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
	public:
		int64 nValue;
		CScript scriptPubKey;

		CTxOut()
		{
			SetNull();
		}

		CTxOut(int64 nValueIn, CScript scriptPubKeyIn)
		{
			nValue = nValueIn;
			scriptPubKey = scriptPubKeyIn;
		}

		IMPLEMENT_SERIALIZE
			(
			 READWRITE(nValue);
			 READWRITE(scriptPubKey);
			)

			void SetNull()
			{
				nValue = -1;
				scriptPubKey.clear();
			}

		bool IsNull()
		{
			return (nValue == -1);
		}

		uint256 GetHash() const
		{
			return SerializeHash(*this);
		}

		friend bool operator==(const CTxOut& a, const CTxOut& b)
		{
			return (a.nValue       == b.nValue &&
					a.scriptPubKey == b.scriptPubKey);
		}

		friend bool operator!=(const CTxOut& a, const CTxOut& b)
		{
			return !(a == b);
		}

		std::string ToString(int ifaceIndex);

		Object ToValue(int ifaceIndex);

};



class CBlock;
class CBlockIndex;
typedef std::map<uint256, CBlockIndex*> blkidx_t;

#define TX_VERSION TXF_VERSION
#define TX_VERSION_2 TXF_VERSION_2

#define SERIALIZE_TRANSACTION_NO_WITNESS 0x40000000


struct CScriptWitness
{
    /* Note that this encodes the data elements being pushed, rather than encoding them as a CScript that pushes them. */
    cstack_t stack;
    
    /* some compilers complain without a default constructor. */
    CScriptWitness() { }

    bool IsNull() const { return stack.empty(); }

    std::string ToString() const; 
};

class CTxInWitness
{

  public:
    CScriptWitness scriptWitness;


    IMPLEMENT_SERIALIZE
    (
        READWRITE(scriptWitness.stack);
    )

    bool IsNull() const { return scriptWitness.IsNull(); }

    CTxInWitness() { }
};

class CTxWitness
{

  public:
    /** In case vtxinwit is missing, all entries are treated as if they were empty CTxInWitnesses */
    std::vector<CTxInWitness> vtxinwit;

    bool IsEmpty() const { return vtxinwit.empty(); }

    bool IsNull() const
    {
        for (size_t n = 0; n < vtxinwit.size(); n++) {
            if (!vtxinwit[n].IsNull()) {
                return false;
            }
        }
        return true;
    }

    void SetNull()
    {
        vtxinwit.clear();
    }


    IMPLEMENT_SERIALIZE
    (
      for (size_t n = 0; n < vtxinwit.size(); n++) {
        READWRITE(vtxinwit[n]);
      }
    )


};

class CTransactionCore
{
  public:

    static const int TXF_VERSION = (1 << 0);
    static const int TXF_VERSION_2 = (1 << 1);
    static const int TXF_RESERVED_0 = (1 << 2);
    static const int TXF_RESERVED_1 = (1 << 3);
    static const int TXF_CERTIFICATE = (1 << 4);
    static const int TXF_LICENSE = (1 << 5);
    static const int TXF_ALIAS = (1 << 6);
    static const int TXF_OFFER = (1 << 7);
    static const int TXF_PARAM = (1 << 8);
    static const int TXF_ASSET = (1 << 9);
    static const int TXF_IDENT = (1 << 10);
    static const int TXF_MATRIX = (1 << 11);
    static const int TXF_EXEC = (1 << 13);
    static const int TXF_CONTEXT = (1 << 14);
    static const int TXF_ALTCHAIN = (1 << 15);

		static const int VERSION_MASK = 15;

    int nFlag;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    CTxWitness wit;
    unsigned int nLockTime;

    CTransactionCore()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (

        READWRITE(this->nFlag);

        if (fRead) {
          unsigned char flag = 0;

          READWRITE(vin);

          if (vin.size() == 0 && !(nVersion & SERIALIZE_TRANSACTION_NO_WITNESS)) {
            READWRITE(flag);
            if (flag != 0) {
              READWRITE(vin);
              READWRITE(vout);
            }
          } else {
            READWRITE(vout);
          }
          if ((flag & 1) && !(nVersion & SERIALIZE_TRANSACTION_NO_WITNESS)) {
            flag ^= 1;
            const_cast<CTxWitness*>(&wit)->vtxinwit.resize(vin.size());
            READWRITE(wit);
          }

        } else {
          unsigned char flag = 0;

          if (!(nVersion & SERIALIZE_TRANSACTION_NO_WITNESS)) {
            if (!wit.IsNull()) {
              flag |= 1;
            }
          }
          if (flag) {
            std::vector<CTxIn> vinDummy;
            READWRITE(vinDummy);
            READWRITE(flag);
          }
          READWRITE(vin);
          READWRITE(vout);
          if (flag & 1) {
            const_cast<CTxWitness*>(&wit)->vtxinwit.resize(vin.size());
            READWRITE(wit);
          }
        }
        READWRITE(nLockTime);
    )

    void SetNull()
    {
        nFlag = CTransactionCore::TXF_VERSION;
        vin.clear();
        vout.clear();
        wit.SetNull();
        nLockTime = 0;
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

		int GetVersion() const
		{
			uint32_t ver = nFlag;
			return ((int)(ver & VERSION_MASK));
		}

		unsigned int GetFlags() const
		{
			uint32_t fla = nFlag;
			uint32_t v = (uint32_t)GetVersion();
			return (fla - v);
		}

    bool isFlag(unsigned int flag) const
    {
			unsigned int tx_flags = GetFlags();

      if ( (tx_flags & flag) ) {
        return (true);
      } 

      return (false);
    }

		void SetVersion(int ver)
		{
			ver = MAX(0, MIN(VERSION_MASK, ver));
			nFlag = GetFlags() + ver;
		}

		void SetFlag(unsigned int flag)
		{
			if (flag <= VERSION_MASK)
				return;
			nFlag |= flag;
		}

    friend bool operator==(const CTransactionCore& a, const CTransactionCore& b)
		{
			return (a.nFlag  == b.nFlag &&
					a.vin       == b.vin &&
					a.vout      == b.vout &&
					a.nLockTime == b.nLockTime);
		}

    std::string ToString(int ifaceIndex);

    Object ToValue(int ifaceIndex);

};


/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction : public CTransactionCore
{

  public:
    CCert certificate;
    CLicense license;
    CContext context;
    CIdent ident;
		CAsset asset;
    CAlias alias;
    COffer offer;
    CTxMatrix matrix;
		CExecCore exec;
		CAltChain altchain;
		CParam param; 

    CTransaction()
    {
      SetNull();
    }
    CTransaction(const CTransaction& tx)
    {
      SetNull();
      Init(tx);
    }

		CTransaction(const CAltTx& tx)
		{
      SetNull();
			nFlag = tx.nFlag;
			vin.clear();
			for (int i = 0; i < tx.vin.size(); i++)
				vin.insert(vin.end(), tx.vin[i]);
			vout.clear();
			for (int i = 0; i < tx.vout.size(); i++)
				vout.insert(vout.end(), tx.vout[i]);
			nLockTime = tx.nLockTime;
		}

    IMPLEMENT_SERIALIZE
    (
      READWRITE(*(CTransactionCore*)this);
      if (this->nFlag & TXF_CERTIFICATE) {
        READWRITE(certificate);
			}
			if (this->nFlag & TXF_LICENSE) {
        READWRITE(license);
			}
			if (this->nFlag & TXF_CONTEXT) {
        READWRITE(context);
			}
			if (this->nFlag & TXF_IDENT) 
        READWRITE(ident);
			if (this->nFlag & TXF_ASSET) {
        READWRITE(asset);
			}
			if (this->nFlag & TXF_EXEC)
        READWRITE(exec);
      if (this->nFlag & TXF_ALIAS)
        READWRITE(alias);
      if (this->nFlag & TXF_OFFER)
        READWRITE(offer);
      if (this->nFlag & TXF_MATRIX)
        READWRITE(matrix);

      if (this->nFlag & TXF_ALTCHAIN)
        READWRITE(altchain);

      if (this->nFlag & TXF_PARAM)
        READWRITE(param);
    )

    void Init(const CTransaction& tx);

    void SetNull()
    {

      CTransactionCore::SetNull();
      certificate.SetNull();
      license.SetNull();
      context.SetNull();
			ident.SetNull();
			asset.SetNull();
			alias.SetNull();
      offer.SetNull();
      matrix.SetNull();
			exec.SetNull();
			altchain.SetNull();
			param.SetNull();
    }

    uint256 GetHash() const
    {
      return SerializeHash(*this, SERIALIZE_TRANSACTION_NO_WITNESS);
    }

    uint256 GetWitnessHash() const
    {
      return SerializeHash(*this);
    }

    bool IsFinal(int ifaceIndex, int nBlockHeight=0, int64 nBlockTime=0) const;

    bool IsNewerThan(const CTransaction& old) const
    {
        if (vin.size() != old.vin.size())
            return false;
        for (unsigned int i = 0; i < vin.size(); i++)
            if (vin[i].prevout != old.vin[i].prevout)
                return false;

        bool fNewer = false;
        unsigned int nLowest = std::numeric_limits<unsigned int>::max();
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            if (vin[i].nSequence != old.vin[i].nSequence)
            {
                if (vin[i].nSequence <= nLowest)
                {
                    fNewer = false;
                    nLowest = vin[i].nSequence;
                }
                if (old.vin[i].nSequence < nLowest)
                {
                    fNewer = true;
                    nLowest = old.vin[i].nSequence;
                }
            }
        }
        return fNewer;
    }

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    /** Check for standard transaction types
        @return True if all outputs (scriptPubKeys) use only standard transaction forms
    */
    bool IsStandard() const;

    /** Check for standard transaction types
        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return True if all inputs (scriptSigs) use only standard transaction forms
        @see CTransaction::FetchInputs
    */
    bool AreInputsStandard(int ifaceIndex, const MapPrevTx& mapInputs) const;

    /** Count ECDSA signature operations the old-fashioned (pre-0.6) way
        @return number of sigops this transaction's outputs will produce when spent
        @see CTransaction::FetchInputs
    */
    unsigned int GetLegacySigOpCount() const;

    /** Count ECDSA signature operations in pay-to-script-hash inputs.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return maximum number of sigops required to validate this transaction's inputs
        @see CTransaction::FetchInputs
     */
    unsigned int GetP2SHSigOpCount(const MapPrevTx& mapInputs) const;

    int64_t GetSigOpCost(MapPrevTx& mapInputs, int flags = 0);

    int64_t GetSigOpCost(tx_cache& mapInputs, int flags = 0);

    /** Amount of bitcoins spent by this transaction.
        @return sum of all outputs (note: does not include fees)
     */
    int64 GetValueOut() const
    {
        int64 nValueOut = 0;
        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            nValueOut += txout.nValue;
        }
        return nValueOut;
    }

    /** Amount of bitcoins coming in to this transaction
        Note that lightweight clients may not know anything besides the hash of previous transactions,
        so may not be able to calculate this.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return	Sum of value of all inputs (scriptSigs)
        @see CTransaction::FetchInputs
     */
    int64 GetValueIn(const MapPrevTx& mapInputs);

    int64 GetValueIn(tx_cache& mapInputs);

    bool ReadTx(int ifaceIndex, uint256 txHash);

    bool ReadTx(int ifaceIndex, uint256 txHash, uint256 *hashBlock);

    bool WriteTx(int ifaceIndex, uint64_t blockHeight);

    bool ReadFromDisk(int ifaceIndex, COutPoint prevout);


    bool FillTx(int ifaceIndex, CDiskTxPos &pos);

    bool EraseTx(int ifaceIndex);

		CParam *UpdateParam(std::string strName, int64_t nValue);

    CAlias *CreateAlias(std::string name, int type = CAlias::ALIAS_COINADDR);
    CAlias *UpdateAlias(std::string name, const uint160& hash);
    CAlias *RemoveAlias(std::string name);

    CCert *CreateCert(int ifaceIndex, string strTitle, CCoinAddr& addr, string hexSeed, int64 nLicenseFee);

    CCert *DeriveCert(int ifaceIndex, string strTitle, CCoinAddr& addr, CCert *chain, string hexSeed, int64 nLicenseFee);

    CLicense *CreateLicense(CCert *cert);

    COffer *CreateOffer();
    COffer *AcceptOffer(COffer *offerIn);
    COffer *GenerateOffer(COffer *offerIn);
    COffer *PayOffer(COffer *accept);
    COffer *RemoveOffer(uint160 hashOffer);

		/* TXF_ASSET : CAsset */
		CAsset *CreateAsset(CCert *cert, int nType, int nSubType, const cbuff& vContent);
		CAsset *UpdateAsset(CAsset *assetIn, const cbuff& vContent);
    CAsset *TransferAsset(CAsset *assetIn);
    CAsset *ActivateAsset(CAsset *assetIn);
    CAsset *RemoveAsset(CAsset *assetIn);
		/** Verify the integrity of an asset transaction. */
		bool VerifyAsset(int ifaceIndex);

    CExec *CreateExec();
    CExecCheckpoint *UpdateExec(const CExec& execIn);
    CExecCall *GenerateExec(const CExec& execIn);
    CExec *TransferExec(const CExec& execIn);

    CIdent *CreateIdent(const CIdent& ident);
    CIdent *CreateIdent(const CCert& ident);
    CIdent *CreateIdent(int ifaceIndex, CCoinAddr& addr);
		bool VerifyIdent(int ifaceIndex);

    CContext *CreateContext();
		/** Verify the integrity of an context transaction. */
		bool VerifyContext(int ifaceIndex); 

		CAltChain *CreateAltChain();
		/* Verify the integrity of an altchain transaction. */
		bool VerifyAltChain(int ifaceIndex);

    CAlias *GetAlias()
    {

      if (!(this->nFlag & TXF_ALIAS))
				return (NULL);

      return (&alias);
    }

    CIdent *GetIdent()
    {
      if (!(this->nFlag & TXF_IDENT)) {
				return (NULL);
			}
      return (&ident);
    }

    CCert *GetCertificate()
    {
      if (!(this->nFlag & TXF_CERTIFICATE)) {
				return (NULL);
			}
      return ((CCert *)&certificate);
    }

    CLicense *GetLicense()
    {
      if (!(this->nFlag & TXF_LICENSE)) {
				return (NULL);
			}
      return ((CLicense *)&license);
    }

    CContext *GetContext()
    {
      if (!(this->nFlag & TXF_CONTEXT)) {
				return (NULL);
			}
      return ((CContext *)&context);
    }

		CExec *GetExec() const
		{
			if (!(this->nFlag & TXF_EXEC))
				return (NULL);
			return ((CExec *)&exec);
		}

		CExecCall *GetExecCall() const
		{
			if (!(this->nFlag & TXF_EXEC))
				return (NULL);
			return ((CExecCall *)&exec);
		}

		CExecCheckpoint *GetExecCheckpoint() const
		{
			if (!(this->nFlag & TXF_EXEC))
				return (NULL);
			return ((CExecCheckpoint *)&exec);
		}

    COffer *GetOffer() const
    {
      if (!(this->nFlag & TXF_OFFER)) {
				return (NULL);
			}
      return ((COffer *)&offer);
    }

		CAltChain *GetAltChain() const
		{
			if (!(this->nFlag & TXF_ALTCHAIN))
				return (NULL);
			return ((CAltChain *)&altchain);
		}

		CParam *GetParam() const
		{
			if (!(this->nFlag & TXF_PARAM))
				return (NULL);
			return ((CParam *)&param);
		}

		CAsset *GetAsset()
		{
			if (!(this->nFlag & TXF_ASSET))
				return (NULL);
			return ((CAsset *)&asset);
		}

		CAsset *GetNewAsset()
		{
			if (nFlag & CTransaction::TXF_ASSET) {
				return (NULL);
			}

			nFlag |= CTransaction::TXF_ASSET;
			asset = CAsset();
			return ((CAsset *)&asset);
		}

		CAsset *GetDerivedAsset(CAsset *assetIn)
		{
			if (nFlag & CTransaction::TXF_ASSET) {
				return (NULL);
			}

			nFlag |= CTransaction::TXF_ASSET;
			asset = CAsset(*assetIn);
			return ((CAsset *)&asset);
		}

    CTxMatrix *GetMatrix()
    {
      if (!isFlag(TXF_MATRIX))
        return (NULL);
      return (&matrix);
    }

    CTxMatrix *GenerateValidateMatrix(int ifaceIndex, CBlockIndex *pindex = NULL);

		CTxMatrix *GenerateSpringMatrix(int ifaceIndex, CIdent& ident);

    bool VerifyValidateMatrix(int ifaceIndex, const CTxMatrix& matrix, CBlockIndex *pindex);

    bool VerifySpringMatrix(int ifaceIndex, const CTxMatrix& matrix, shnum_t *lat_p, shnum_t *lon_p);

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nFlag  == b.nFlag &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }

    void print(int ifaceIndex)
    {
      shcoind_log(ToString(ifaceIndex).c_str());
    }

    bool ClientConnectInputs(int ifaceIndex);

    bool CheckTransaction(int ifaceIndex); 

    bool CheckTransactionInputs(int ifaceIndex);

    bool IsInMemoryPool(int ifaceIndex);

    Object ToValue(int ifaceIndex);

    Object ToValue(CBlock *pblock);

    std::string ToString(int ifaceIndex);

    int GetDepthInMainChain(int ifaceIndex, CBlockIndex* &pindexRet) const;

    int GetDepthInMainChain(int ifaceIndex) const { CBlockIndex *pindexRet; return GetDepthInMainChain(ifaceIndex, pindexRet); }


    bool WriteCoins(int ifaceIndex, const vector<uint256>& vOuts);

    bool WriteCoins(int ifaceIndex, int nOut, const uint256& hashTxOut);

    bool ReadCoins(int ifaceIndex, vector<uint256>& vOuts);

    bool EraseCoins(int ifaceIndex);

    /* fmap */
    bool ConnectInputs(int ifaceIndex, const CBlockIndex* pindexBlock, tx_map& mapOutput, map<uint256, CTransaction> mapTx, int& nSigOps, int64& nFees, bool fVerifySig = true, bool fVerifyInputs = false, bool fRequireInputs = false);


    bool GetOutputFor(const CTxIn& input, tx_cache& inputs, CTxOut& retOut);

#ifdef USE_LEVELDB_COINDB
    /**
     * Verifies whether a vSpent has been spent.
     * @param hashTx The hash of the transaction attempting to spend the input.
     */
    bool IsSpentTx(const CDiskTxPos& pos);

    bool ReadFromDisk(CDiskTxPos pos);


    /** 
     * Fetch from memory and/or disk. inputsRet keys are transaction hashes.
     *
     * @param[in] txdb  Transaction database
     * @param[in] mapTestPool List of pending changes to the transaction index database
     * @param[in] fBlock  True if being called to add a new best-block to the chain
     * @param[in] fMiner  True if being called by CreateNewBlock
     * @param[out] inputsRet  Pointers to this transaction's inputs
     * @param[out] fInvalid returns true if transaction is invalid
     * @return  Returns true if all inputs are in txdb or mapTestPool
     */
    bool FetchInputs(CTxDB& txdb, const std::map<uint256, CTxIndex>& mapTestPool, CBlock *pblockNew, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid);

    /* leveldb */
    bool DisconnectInputs(CTxDB& txdb);

    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet);
#else
    /* fmap */
    bool DisconnectInputs(int ifaceIndex);
#endif

		void reject(CValidateState *state, int err_code, string err_text);

protected:
    /* leveldb */
    const CTxOut& GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const;



};

class CBlockHeader
{
public:
    /* block header */
    int nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    mutable int ifaceIndex;

    CBlockHeader()
    {
      nVersion = 1;
      SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
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
        return Hash(BEGIN(nVersion), END(nNonce));
    }

    int64 GetBlockTime() const
    {
        return (int64)nTime;
    }

    /**
     * Obtain the block hash used to identify it's "difficulty".
     * @see CBlockHeader.nBits
     */
    uint256 GetPoWHash() const;

		void reject(CValidateState *state, int err_code, string err_text);

    friend bool operator==(const CBlockHeader& a, const CBlockHeader& b)
    {
        return (
						a.nVersion == b.nVersion &&
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


/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlock : public CBlockHeader
{
  public:
    std::vector<CTransaction> vtx;
    mutable CNode *originPeer;
		uint160 hColor;

    CBlock()
    {
      SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
      SetNull();
      *((CBlockHeader*)this) = header;
    }

    CBlock(const CBlock& in_block)
    {
      SetNull();
      *((CBlockHeader*)this) = (CBlockHeader)in_block;
      vtx = in_block.vtx;
    }

    IMPLEMENT_SERIALIZE
      (
       READWRITE(*(CBlockHeader*)this);
       READWRITE(vtx);
      )

    void SetNull()
    {
      CBlockHeader::SetNull();
      vtx.clear();
      originPeer = NULL;
    }

    bool IsNull() const
    {
      return (nBits == 0);
    }

    /**
     * Generate the merkle root hash from all the block's transaction hashes.
     * @see CBlockHeader.nMerkleRoot
     */
    uint256 BuildMerkleTree() const;

    void UpdateTime(const CBlockIndex* pindexPrev);

    /**
     * Permanently store a block's contents to disk.
     * @param The height to associate with the stored block content.
     */
    bool WriteBlock(uint64_t nHeight);

    bool WriteArchBlock();

    bool ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions=true);

    /**
     * Obtain a transaction in the block.
     * @param The transaction hash to obtain.
     */
    const CTransaction *GetTx(uint256 hash);

    /**
     * Track praised and dubious behaviour of a remote coin service.
     */
    bool trust(int deg, const char *msg, ...);

    /**
     * Verify the neccessary transactions exist that are required in order to perform the underlying transaction.
     */
    bool CheckTransactionInputs(int ifaceIndex);

    /**
     * Obtain the header portion of the block content.
     */ 
    CBlockHeader GetBlockHeader() const
    {
      CBlockHeader block;
      block.nVersion       = nVersion;
      block.hashPrevBlock  = hashPrevBlock;
      block.hashMerkleRoot = hashMerkleRoot;
      block.nTime          = nTime;
      block.nBits          = nBits;
      block.nNonce         = nNonce;
      return block;
    }

		CAltBlock GetAltBlockHeader() const
		{
			CAltBlock header;

			header.SetNull();
			header.nFlag = this->nVersion;
			header.hashPrevBlock = hashPrevBlock;
			header.hashMerkleRoot = hashMerkleRoot;
			header.nTime = nTime;
			header.nBits = nBits;
			header.nNonce = nNonce;

			return (header);
		}



    /**
     * Obtain a JSON representation of the block's content.
     */
    Object ToValue(bool fVerbose = false);

    /**
     * Obtain a textual JSON representation of the block's content.
     */
    std::string ToString(bool fVerbose = false);

    /**
     * Log a textual JSON representation of the block's content.
     */
    void print()
    {
      shcoind_log(ToString().c_str());
    }

    virtual bool Truncate() = 0;
    virtual bool ReadBlock(uint64_t nHeight) = 0;
    virtual bool ReadArchBlock(uint256 hash) = 0;
    virtual bool CheckBlock() = 0;




    virtual bool IsBestChain() = 0;
    virtual unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast) = 0;
    virtual CScript GetCoinbaseFlags() = 0;
    virtual bool AcceptBlock() = 0;
    virtual bool IsOrphan() = 0;
    virtual bool AddToBlockIndex() = 0;
    virtual void InvalidChainFound(CBlockIndex* pindexNew) = 0;
    virtual bool VerifyCheckpoint(int nHeight) = 0;
    virtual uint64_t GetTotalBlocksEstimate() = 0;

    /* a weight based on the block size */
    virtual int64_t GetBlockWeight() = 0;

		/* add a new dynamic checkpoint to the block-chain. */
		virtual bool CreateCheckpoint() = 0;

		/* mining algorythm (DEPLOYMENT_ALGO). */
		virtual int GetAlgo() const = 0;

#ifdef USE_LEVELDB_COINDB
    /* leveldb */
    virtual bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex) = 0;
    virtual bool SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew) = 0;
    virtual bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex) = 0;
#else
    /* fmap */
    virtual bool DisconnectBlock(CBlockIndex* pindex) = 0;
    virtual bool SetBestChain(CBlockIndex* pindexNew) = 0;
    virtual bool ConnectBlock(CBlockIndex* pindex) = 0;
#endif

};


/**
 * Obtain a blank block template for a coin interface.
 */
CBlock *GetBlankBlock(CIface *iface);


enum BlockStatus {
    //! Unused.
    BLOCK_VALID_UNKNOWN      =    0,

    //! Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
    BLOCK_VALID_HEADER       =    1,

    //! All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    //! are also at least TREE.
    BLOCK_VALID_TREE         =    2,

    /**
     * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
     * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
     * parent blocks also have TRANSACTIONS, CBlockIndex::nChainTx will be set.
     */
    BLOCK_VALID_TRANSACTIONS =    3,

    //! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30.
    //! Implies all parents are also at least CHAIN.
    BLOCK_VALID_CHAIN        =    4,

    //! Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
    BLOCK_VALID_SCRIPTS      =    5,

    //! All validity bits.
    BLOCK_VALID_MASK         =   BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS |
                                 BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA          =    8, //!< full block available in blk*.dat
    BLOCK_HAVE_UNDO          =   16, //!< undo data available in rev*.dat
    BLOCK_HAVE_MASK          =   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,

    BLOCK_FAILED_VALID       =   32, //!< stage after last reached validness failed
    BLOCK_FAILED_CHILD       =   64, //!< descends from failed block
    BLOCK_FAILED_MASK        =   BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,

    BLOCK_OPT_WITNESS       =   128, //!< block data in blk*.data was received with a witness-enforcing client
};


/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block.  pprev and pnext link a path through the
 * main/longest chain.  A blockindex may have multiple pprev pointing back
 * to it, but pnext will only point forward to the longest branch, or will
 * be null if the block is not part of the longest chain.
 */
class CBlockIndex
{
  public:
    const uint256* phashBlock;
    CBlockIndex* pprev;
    CBlockIndex* pnext;

    /* block index of a predecessor of this block. */
    CBlockIndex *pskip;

    int nHeight;

		/* verification status of this block. see "enum BlockStatus". */
    int nStatus;

		/* this value will be non-zero only if and only if transactions for this block and all its parents are available. */
		unsigned int nChainTx;

    CBigNum bnChainWork;

		/* block header */
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    CBlockIndex()
    {
      phashBlock = NULL;
      pprev = NULL;
      pnext = NULL;
      pskip = NULL;
      nHeight = 0;
      nStatus = 0;
      bnChainWork = 0;

      nVersion       = 0;
      hashMerkleRoot = 0;
      nTime          = 0;
      nBits          = 0;
      nNonce         = 0;
    }

    CBlockIndex(CBlockHeader& block)
    {
      phashBlock = NULL;
      pprev = NULL;
      pnext = NULL;
      nHeight = 0;
      nStatus = 0;
      bnChainWork = 0;

      nVersion       = block.nVersion;
      hashMerkleRoot = block.hashMerkleRoot;
      nTime          = block.nTime;
      nBits          = block.nBits;
      nNonce         = block.nNonce;
    }

    CBlockHeader GetBlockHeader() const
    {
      CBlockHeader block;
      block.nVersion       = nVersion;
      if (pprev)
        block.hashPrevBlock = pprev->GetBlockHash();
      block.hashMerkleRoot = hashMerkleRoot;
      block.nTime          = nTime;
      block.nBits          = nBits;
      block.nNonce         = nNonce;
      return block;
    }

    uint256 GetBlockHash() const
    {
      return *phashBlock;
    }

    int64 GetBlockTime() const
    {
      return (int64)nTime;
    }

    CBigNum GetBlockWork(bool fUseAlgo = true) const;

    bool IsInMainChain(int ifaceIndex) const;

    bool CheckIndex() const
    {
      return (true);
    }

    enum { nMedianTimeSpan=11 };

    int64 GetMedianTimePast() const
    {
      int64 pmedian[nMedianTimeSpan];
      int64* pbegin = &pmedian[nMedianTimeSpan];
      int64* pend = &pmedian[nMedianTimeSpan];

      const CBlockIndex* pindex = this;
      for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
        *(--pbegin) = pindex->GetBlockTime();

      std::sort(pbegin, pend);
      return pbegin[(pend - pbegin)/2];
    }

    int64 GetMedianTime() const
    {
      const CBlockIndex* pindex = this;
      for (int i = 0; i < nMedianTimeSpan/2; i++)
      {
        if (!pindex->pnext)
          return GetBlockTime();
        pindex = pindex->pnext;
      }
      return pindex->GetMedianTimePast();
    }

    CBlockIndex *GetAncestor(int height);

    const CBlockIndex* GetAncestor(int height) const;

    void BuildSkip();

    bool IsValid(int nUpTo = BLOCK_VALID_TRANSACTIONS) const
    {
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        return ((nStatus & BLOCK_VALID_MASK) >= nUpTo);
    }
    
    //! Raise the validity level of this block index entry.
    //! Returns true if the validity was changed.
    bool RaiseValidity(int nUpTo)
    {
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        if ((nStatus & BLOCK_VALID_MASK) < nUpTo) {
            nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
            return true;
        }
        return false;
    }

    std::string ToString() const
    {
      return strprintf("CBlockIndex(nprev=%08x, pnext=%08x, nHeight=%d, merkle=%s, hashBlock=%s)",
          pprev, pnext, nHeight,
          hashMerkleRoot.ToString().c_str(),
          GetBlockHash().ToString().c_str());
    }

    void print() const
    {
      printf("%s\n", ToString().c_str());
    }
};

blkidx_t *GetBlockTable(int ifaceIndex);

CBlockIndex *GetBlockIndexByHash(int ifaceIndex, const uint256 hash);

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
class CBlockLocator
{

	public:
		std::vector<uint256> vHave;

		CBlockLocator() { }

		explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    IMPLEMENT_SERIALIZE
		(
			if (!(nType & SER_GETHASH))
			 READWRITE(nVersion);
			READWRITE(vHave);
		)

		void SetNull()
		{
			vHave.clear();
		}

    bool IsNull()
    {
      return vHave.empty();
    }

};

/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;
    uint256 hashNext;

    CDiskBlockIndex()
    {
        hashPrev = 0;
        hashNext = 0;
    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex)
    {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
        hashNext = (pnext ? pnext->GetBlockHash() : 0);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);
        READWRITE(nHeight);

        /* block header */
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    )

    uint256 GetBlockHash() const
    {
        CBlockHeader block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;
        return block.GetHash();
    }


    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
            GetBlockHash().ToString().c_str(),
            hashPrev.ToString().substr(0,20).c_str(),
            hashNext.ToString().substr(0,20).c_str());
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};


#include "bloom.h"


struct CBlockIndexWorkComparator
{               
    bool operator()(CBlockIndex *pa, CBlockIndex *pb) {
        if (pa->bnChainWork > pb->bnChainWork) return false;
        if (pa->bnChainWork < pb->bnChainWork) return true;
        
        if (pa->GetBlockHash() < pb->GetBlockHash()) return false;
        if (pa->GetBlockHash() > pb->GetBlockHash()) return true;

				/* identical */
        return false;
    }   
};      

typedef set<CBlockIndex*, CBlockIndexWorkComparator> ValidIndexSet;


CBlock *GetBlockByHeight(CIface *iface, int nHeight);

CBlock *GetBlockByHash(CIface *iface, const uint256 hash);

CBlock *GetBlockByTx(CIface *iface, const uint256 hash);

CBlock *CreateBlockTemplate(CIface *iface);

bool ProcessBlock(CNode* pfrom, CBlock* pblock);

int GetBestHeight(CIface *iface);

int GetBestHeight(int ifaceIndex);

bool IsInitialBlockDownload(int ifaceIndex);

uint256 GetBestBlockChain(CIface *iface);

CBlockIndex *GetGenesisBlockIndex(CIface *iface);


void SetBestBlockIndex(CIface *iface, CBlockIndex *pindex);

void SetBestBlockIndex(int ifaceIndex, CBlockIndex *pindex);

CBlockIndex *GetBestBlockIndex(CIface *iface);

CBlockIndex *GetBestBlockIndex(int ifaceIndex);

bool VerifyTxHash(CIface *iface, uint256 hashTx);

CBlock *GetArchBlockByHash(CIface *iface, const uint256 hash);

uint256 GetGenesisBlockHash(int ifaceIndex);

bool core_AcceptBlock(CBlock *pblock, CBlockIndex *pindexPrev);

CBlockIndex *GetBlockIndexByHeight(int ifaceIndex, unsigned int nHeight);


void CloseBlockChain(CIface *iface);

void CloseBlockChains(void);

#ifdef USE_LEVELDB_COINDB
bool core_CommitBlock(CTxDB& txdb, CBlock *pblock, CBlockIndex *pindexNew);
bool core_DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex, CBlock *pblock);
#else
bool core_CommitBlock(CBlock *pblock, CBlockIndex *pindexNew);
bool core_DisconnectBlock(CBlockIndex* pindex, CBlock *pblock);
#endif


int BackupBlockChain(CIface *iface, unsigned int maxHeight);

bool core_ConnectBestBlock(int ifaceIndex, CBlock *block, CBlockIndex *pindexNew);

ValidIndexSet *GetValidIndexSet(int ifaceIndex);

bool IsWitnessEnabled(CIface *iface, const CBlockIndex* pindexPrev);

bool core_CheckBlockWitness(CIface *iface, CBlock *pblock, CBlockIndex *pindexPrev);

int GetWitnessCommitmentIndex(const CBlock& block);

int core_ComputeBlockVersion(CIface *params, CBlockIndex *pindexPrev);

CBlockIndex *GetBlockIndexByTx(CIface *iface, const uint256 hash);

void core_UpdateUncommittedBlockStructures(CIface *iface, CBlock *block, const CBlockIndex* pindexPrev);

bool core_GenerateCoinbaseCommitment(CIface *iface, CBlock *block, CBlockIndex *pindexPrev);

/** obtain the coinbase flags for a coin interface. */
CScript GetCoinbaseFlags(int ifaceIndex);

/** assign a default coinbae signature for current node. */
void core_IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev); 

/** set a 4-byte (8 character) hex string from stratum miner on the block's coinbase signature. */
void core_SetExtraNonce(CBlock* pblock, const char *xn_hex);

/** determines whether a block exists in the disk block-chain with given hash. */
bool HasBlockHash(CIface *iface, uint256 hash);

/** obtain the verification flags neccessary for the block height. */
unsigned int GetBlockScriptFlags(CIface *iface, const CBlockIndex* pindex);

bool CheckFinalTx(CIface *iface, const CTransaction& tx, CBlockIndex *pindexPrev, int flags = 0);

bool CheckSequenceLocks(CIface *iface, const CTransaction &tx, int flags);

CBlockIndex* LastCommonAncestor(CBlockIndex* pa, CBlockIndex* pb); 

const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, int algo);


#endif /* ndef __SERVER_BLOCK_H__ */




