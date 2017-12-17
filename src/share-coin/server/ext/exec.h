
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

#ifndef __EXEC_H__
#define __EXEC_H__



#define DEFAULT_EXEC_LIFESPAN MAX_SHARE_SESSION_TIME

class CExec : public CCert
{
  public:

    CExec()
    {
      SetNull();
    }

    CExec(const CCert& certIn)
    {
      SetNull();
      CCert::Init(certIn);
    }

    CExec(const CExec& execIn)
    {
      SetNull();
      Init(execIn);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(*(CCert *)this);
    )

    void SetNull()
    {
      CCert::SetNull();
    }

    void Init(const CExec& execIn)
    {
      CCert::Init(execIn);
    }

    friend bool operator==(const CExec &a, const CExec &b)
    {
      return (
        ((CCert&) a) == ((CCert&) b)
      );
    }

    CExec operator=(const CExec &b)
    {
      Init(b);
      return (*this);
    }


    bool Sign(int ifaceIndex, CCoinAddr& addr);

    bool VerifySignature();

    bool LoadData(string path, cbuff& data);

    bool LoadPersistentData(cbuff& data);

    bool SavePersistentData(const cbuff& data);

    bool RemovePersistentData();

    bool VerifyData(const cbuff& data);


    const uint160 GetHash()
    {
      uint256 hashOut = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hashOut;
      cbuff rawbuf(raw, raw + sizeof(hashOut));
      return Hash160(rawbuf);
    }

    bool SetStack(const cbuff& data, const CCoinAddr& sendAddr);

    bool SetStack(cbuff stack)
    {
      vContext = stack;
      return (true);
    }

    cbuff GetStack()
    { 
      return (vContext);
    }

    bool VerifyStack();
 
    bool SetAccount(int ifaceIndex, string& strAccount);

    uint160 GetIdentHash()
    {
      return (CIdent::GetHash());
    }

    CCoinAddr GetExecAddr()
    {
      return (CCoinAddr(stringFromVch(vAddr)));
    }

    std::string ToString();

    Object ToValue();

};

class CExecCall : public CExec
{
  public:
    CExecCall()
    {
      SetNull();
    }

    CExecCall(const CCert& certIn)
    {
      SetNull();
      CExec::Init(certIn);
    }

    CExecCall(const CExecCall& execIn)
    {
      SetNull();
      Init(execIn);
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(*(CExec *)this);
    )

    void SetNull()
    {
      CExec::SetNull();
    }

    void Init(const CExecCall& execIn)
    {
      CExec::Init(execIn);
    }

    void Init(const CExec& execIn)
    {
      CExec::Init(execIn);
    }

    friend bool operator==(const CExecCall &a, const CExecCall &b)
    {
      return (
          ((CExec&) a) == ((CExec&) b)
          );
    }

    CExecCall operator=(const CExecCall &b)
    {
      Init(b);
      return (*this);
    }

    int64 GetSendValue()
    {
      return (nFee);
    }

    void SetSendValue(int64 nFeeIn)
    {
      nFee = nFeeIn;
    }

    CCoinAddr GetSendAddr(int ifaceIndex)
    {
      CCoinAddr addr(ifaceIndex);
      addr.Set(CKeyID(hashIssuer));
      return (addr);
    }

    bool SetSendAddr(const CCoinAddr& addrIn)
    {
      CKeyID k;
      if (!addrIn.GetKeyID(k))
        return (false);

      hashIssuer = k;
      return (true);
    }

    bool Sign(int ifaceIndex, CCoinAddr& addr);

    bool VerifySignature(int ifaceIndex);

    const uint160 GetHash()
    {
      uint256 hashOut = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hashOut;
      cbuff rawbuf(raw, raw + sizeof(hashOut));
      return Hash160(rawbuf);
    }

    std::string ToString();

    Object ToValue();
};

bool VerifyExec(CTransaction& tx, int& mode);


int init_exec_tx(CIface *iface, string strAccount, string strPath, int64 nExecFee, CWalletTx& wtx);

int update_exec_tx(CIface *iface, const uint160& hashExec, string strPath, CWalletTx& wtx);

int generate_exec_tx(CIface *iface, string strAccount, uint160 hExec, string strFunc, CWalletTx& wtx);

int activate_exec_tx(CIface *iface, uint160 hExec, uint160 hCert, CWalletTx& wtx);

int transfer_exec_tx(CIface *iface, uint160 hExec, string strAccount, CWalletTx& wtx);

int remove_exec_tx(CIface *iface, const uint160& hashExec, CWalletTx& wtx);




#endif /* ndef __EXEC_H__ */


