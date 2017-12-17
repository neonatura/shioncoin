
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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

#ifndef __CHANNEL_H__
#define __CHANNEL_H__


class CWallet;

class CChannelKey
{
  public:
    uint160 addr;
    cbuff pubkey;
    cbuff mpubkey;
    cbuff mchain;
    cbuff hdpubkey;
    int64 nValue;

    IMPLEMENT_SERIALIZE (
      READWRITE(addr);
      READWRITE(pubkey);
      READWRITE(mpubkey);
      READWRITE(mchain);
      READWRITE(hdpubkey);
      READWRITE(nValue);
    )

    void SetNull()
    {
      addr = 0;
      pubkey.clear();
      mpubkey.clear();
      mchain.clear();
      hdpubkey.clear();
      nValue = 0;
    }

    friend bool operator==(const CChannelKey &a, const CChannelKey &b)
    {
      return (
        a.addr == b.addr &&
        a.pubkey == b.pubkey &&
        a.mpubkey == b.mpubkey &&
        a.mchain == b.mchain &&
        a.hdpubkey == b.hdpubkey &&
        a.nValue == b.nValue
      );
    }

    CChannelKey operator=(const CChannelKey &b)
    {
      Init(b);
      return (*this);
    }

    void Init(const CChannelKey& b)
    {
      addr = b.addr;
      pubkey = b.pubkey;
      mpubkey = b.mpubkey;
      mchain = b.mchain;
      hdpubkey = b.hdpubkey;
      nValue = b.nValue;
    }

    bool GenerateMasterKey(CWallet *wallet, string strAccount);

    bool GetMasterKey(CWallet *wallet, HDPrivKey& privkey);

    bool VerifyChannelMasterKey(CWallet *wallet);

    bool GetPubKey(cbuff& ret_buff, int idx);

    int64 GetValue()
    {
      return (nValue);
    }

    void SetValue(int64 val)
    {
      nValue = val;
    }

    std::string ToString();

    Object ToValue();
};

class CChannel
{
  public:
    CChannelKey origin;
    CChannelKey peer;
    uint160 hRedeem;
    unsigned int nSeq;

    CChannel()
    {
      SetNull();
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(origin);
      READWRITE(peer);
      READWRITE(hRedeem);
      READWRITE(nSeq);
    )

    void SetNull()
    {
      origin.SetNull();
      peer.SetNull();
      hRedeem = 0;
      nSeq = 1;
    }

    void Init(const CChannel& channelIn)
    {
      origin = channelIn.origin;
      peer = channelIn.peer;
      hRedeem = channelIn.hRedeem;
      nSeq = channelIn.nSeq;
    }

    friend bool operator==(const CChannel &a, const CChannel &b)
    {
      return (
        a.origin == b.origin &&
        a.peer == b.peer &&
        a.hRedeem == b.hRedeem &&
        a.nSeq == b.nSeq
      );
    }

    CChannel operator=(const CChannel &b)
    {
      Init(b);
      return (*this);
    }

    const uint160 GetHash()
    {
      return (hRedeem);
    }

    cbuff GetOriginPubKey()
    {
      cbuff ret_buff;

      if (!origin.GetPubKey(ret_buff, nSeq))
        return (cbuff());

      return (ret_buff);
    }

    cbuff GetPeerPubKey()
    {
      cbuff ret_buff;

      if (!peer.GetPubKey(ret_buff, nSeq))
        return (cbuff());

      return (ret_buff);
    }

    CChannelKey *GetOrigin()
    {
      return (&origin);
    }

    CChannelKey *GetPeer()
    {
      return (&peer);
    }

    int64 GetOriginValue()
    {
      return (GetOrigin()->GetValue());
    }
    int64 GetPeerValue()
    {
      return (GetPeer()->GetValue());
    }
    void SetOriginValue(int64 val)
    {
      GetOrigin()->SetValue(val);
    }
    void SetPeerValue(int64 val)
    {
      GetPeer()->SetValue(val);
    }


    bool SetHash();

    bool GetRedeemScript(CScript& script);
 
    bool GetChannelTx(int ifaceIndex, CTransaction& tx);

    const CCoinAddr GetOriginAddr(int ifaceIndex);

    const CCoinAddr GetPeerAddr(int ifaceIndex);

    bool GeneratePubKey();

    bool VerifyPubKey();

    std::string ToString();

    Object ToValue();

};


channel_list *GetChannelTable(int ifaceIndex);

channel_list *GetChannelSpentTable(int ifaceIndex);

int64 GetChannelReturnFee(const CTransaction& tx);


bool IsChannelTx(const CTransaction& tx);


bool GetTxOfChannel(CIface *iface, const uint160& hashChannel, CTransaction& tx); 


/** 
 * Initiate a Channel Funding Transaction for a counter-party.
 * @param strAccount the originating account initiating the channel.
 * @param addr counter-party coin address
 * @param nValue amount to allocate to the channel.
 */
int init_channel_tx(CIface *iface, string strAccount, int64 nValue, CCoinAddr& addr, CWalletTx& wtx);

/** 
 * Activate a Channel Funding Transaction from a counter-party.
 */
int activate_channel_tx(CIface *iface, CTransaction *txIn, int64 nValue, CWalletTx& wtx);

/**
 * Perform a pay operation "outside the blockchain".
 */
int pay_channel_tx(CIface *iface, string strAccount, uint160 hChan, CCoinAddr pay_dest, int64 nValue, CWalletTx& wtx);

/**
 * Commit to a channel payment amendment.
 */
int validate_channel_tx(CIface *iface, CTransaction *txCommit, CWalletTx& wtx);


/**
 * Commit the current balances of the channel onto the block-chain.
 */
int generate_channel_tx(CIface *iface, uint160 hChan, CWalletTx& wtx);

/**
 * Forcibly reset the channel to the last established balance.
 */
int remove_channel_tx(CIface *iface, const uint160& hashChannel, CWalletTx& wtx);





#endif /* ndef __CHANNEL_H__ */


