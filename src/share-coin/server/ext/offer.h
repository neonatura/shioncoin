

#ifndef __OFFER_H__
#define __OFFER_H__



class CCoinAddr;

class COffer : public CExtCore 
{
  public:
		/* reserved */
    unsigned int nType;
		/** the output of the sink-tx holding alt-coins. */
		unsigned int hSinkOut;
		/** the actual SHC currency being exchanged. */
		int64 nValue;
		/** the minimum SHC currency to send for exchange. */
		int64 nMinValue;
		/** the maximum SHC currency to send for exchange. */
		int64 nMaxValue;
		/** the exchange rate (<shc-currency> * ((double)nRate*COIN)). */
		int64 nRate;
		/** the original offer's hash. */
    uint160 hashOffer;
		/** optional alt-currency color hash (COLOR_COIN_IFACE). */
		uint160 hashColor;
		/** the final destination SHC currency transaction hash. */
		uint256 hPayTx;
		/** the final destination alt-coin currency transaction hash. */
		uint256 hXferTx;
		/** the intermediate tx where the initiator's is storing alt currency. */
		uint256 hSinkTx;
		/** reserved */
    uint256 hChain;
		/** the offer initiator's alt-currency receiving [pubkey] address. */
    cbuff vchPayAddr;
		/** the offer acceptor's SHC receiving [pubkey] address. */
    cbuff vchXferAddr;
		/** the pubkey address receiving SHC coins. */
		cbuff vchPayCoin;
		/** the pubkey address receiving alt-currency coins. */
		cbuff vchXferCoin;

    COffer() { 
      SetNull();
    }

    COffer(const COffer& offerIn)
    {
      SetNull();
      Init(offerIn);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(*(CExtCore *)this);
			READWRITE(nType);
			READWRITE(nValue);
			READWRITE(nMinValue);
			READWRITE(nMaxValue);
			READWRITE(nRate);
			READWRITE(hashOffer);
			READWRITE(hashColor);
			READWRITE(hPayTx);
			READWRITE(hXferTx);
			READWRITE(hSinkTx);
			READWRITE(hSinkOut);
			READWRITE(hChain);
			READWRITE(vchPayAddr);
			READWRITE(vchXferAddr);
			READWRITE(vchPayCoin);
			READWRITE(vchXferCoin);
    )

    friend bool operator==(const COffer &a, const COffer &b) {
      return (
          ((CExtCore&) a) == ((CExtCore&) b) &&
					a.nType == b.nType &&
					a.nValue == b.nValue &&
					a.nMinValue == b.nMinValue &&
					a.nMaxValue == b.nMaxValue &&
					a.nRate == b.nRate &&
					a.hashOffer == b.hashOffer &&
					a.hashColor == b.hashColor &&
					a.hPayTx == b.hPayTx &&
					a.hXferTx == b.hXferTx &&
					a.hSinkTx == b.hSinkTx &&
					a.hSinkOut == b.hSinkOut &&
					a.hChain == b.hChain &&
					a.vchPayAddr == b.vchPayAddr &&
					a.vchXferAddr == b.vchXferAddr &&
					a.vchPayCoin == b.vchPayCoin &&
					a.vchXferCoin == b.vchXferCoin
          );
    }

    void Init(const COffer& b)
    {
      CExtCore::Init(b);

			nType = b.nType;
			nValue = b.nValue;
			nMinValue = b.nMinValue;
			nMaxValue = b.nMaxValue;
			nRate = b.nRate;
			hashOffer = b.hashOffer;
			hashColor = b.hashColor;
			hPayTx = b.hPayTx;
			hXferTx = b.hXferTx;
			hSinkTx = b.hSinkTx;
			hSinkOut = b.hSinkOut;
			hChain = b.hChain;
			vchPayAddr = b.vchPayAddr;
			vchXferAddr = b.vchXferAddr;
			vchPayCoin = b.vchPayCoin;
			vchXferCoin = b.vchXferCoin;
    }

    COffer operator=(const COffer &b)
    {
			SetNull();
      Init(b);
      return *this;
    }

    friend bool operator!=(const COffer &a, const COffer &b) {
        return !(a == b);
    }
    
    void SetNull()
    {
      CExtCore::SetNull();

			nType = 16; /* reserved */
			nValue == 0;
			nMinValue = 0;
			nMaxValue = 0;
			nRate = 0;
			hashOffer = 0;
			hashColor = 0;
			hPayTx = 0;
			hXferTx = 0;
			hSinkTx = 0;
			hSinkOut = 0;
			hChain = 0;
			vchPayAddr.clear(); 
			vchXferAddr.clear();
			vchPayCoin.clear(); 
			vchXferCoin.clear();
    }

    bool IsNull() const 
    {
      return (nMinValue == 0 || nMaxValue == 0);
    }

    CIface *GetPayIface()
    {
      return (GetCoin(stringFromVch(vchPayCoin).c_str()));
    }

    CIface *GetXferIface()
    {
      return (GetCoin(stringFromVch(vchXferCoin).c_str()));
    }

    const uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    bool GetPayAddr(int ifaceIndex, CCoinAddr& addr);

    bool GetPayAccount(int ifaceIndex, CCoinAddr& addr, std::string& account);

    bool GetXferAddr(int ifaceIndex, CCoinAddr& addr);

    bool GetXferAccount(int ifaceIndex, CCoinAddr& addr, std::string& account);

		void SetPayAddr(const CPubKey& payAddr);

		void SetXferAddr(const CPubKey& xferAddr);

    Object ToValue();

    std::string ToString();
};



/** Verify the integrity of a "Offer Extended Transaction". */
bool VerifyOffer(const CTransaction& tx, int& mode);

/**
 * The coin cost to initiate a offer or offer-accept transaction.
 * @note This is effectively minimized to the smallest possible expense.
 */
int64 GetOfferOpFee(CIface *iface);

/**
 * @param iface The primary coin interface
 * @param strAccount The account name to conduct transactions for.
 * @param srcValue A positive (offering) or negative (requesting) coin value.
 * @param destIndex The counter-coin interface index.
 * @param destValue The counter-coin value being offered (+) or requested (-).
 * @param wtx Filled with the offer transaction being performed.
 * @note One of the coin values must be negative and the other positive.
 */
int init_offer_tx(CIface *iface, std::string strAccount, int altIndex, int64 nMinValue, int64 nMaxValue, double dRate, CWalletTx& wtx, uint160 hColor = 0);

int accept_offer_tx(CIface *iface, std::string strAccount, uint160 hashOffer, int64 nValue, CWalletTx& wtx, uint160 hColor = 0);

extern bool GetTxOfOffer(CIface *iface, const uint160& hash, CTransaction& tx);

int generate_offer_tx(CIface *iface, uint160 hashOffer, CWalletTx& wtx);

bool IsOfferTx(const CTransaction& tx);

int CommitOfferTx(CIface *iface, CTransaction& tx, unsigned int nHeight);



#endif /* ndef __OFFER_H__ */
