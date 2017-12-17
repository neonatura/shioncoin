
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

#ifndef __SERVER__TXSIGNATURE_H__
#define __SERVER__TXSIGNATURE_H__

#include <string>
#include <vector>

#include <boost/foreach.hpp>
#include <boost/variant.hpp>

class CTransaction;


/** Signature hash types/flags */
enum 
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_HDKEY = 0x40,
    SIGHASH_ANYONECANPAY = 0x80
};

enum 
{
  SIGVERSION_BASE = 0,
  SIGVERSION_WITNESS_V0 = 1
};


class CSignature
{
  protected:
    int ifaceIndex;

  public:
    int nHashType; 
    tx_cache mapInputs;
    CTransaction *tx;
    int nTxIn;

    CSignature(int ifaceIndexIn, CTransaction *txIn, unsigned int nIn, int nHashTypeIn=SIGHASH_ALL)
    {
      ifaceIndex = ifaceIndexIn;
      tx = txIn;
      nTxIn = nIn;
      nHashType = nHashTypeIn;
    }

    bool SignatureHash(CScript scriptCode, int sigver, uint256& hashRet);

    bool CheckSig(cbuff vchSig, cbuff vchPubKey, CScript scriptCode, int sigver);

    bool SignSignature(const CScript& fromPubKey);

    bool SignSignature(const CTransaction& txFrom);

    bool CreateSignature(cbuff& vchSig, const CKeyID& address, const CScript& scriptCode, int sigversion);

    /* in older "common scrypt coin source common" this is known as Solver(). In newer common code, this is known as "SignStep()" */
    bool SignAddress(const CScript& scriptPubKey, cstack_t& ret, txnouttype& whichTypeRet, int sigversion);

};



#endif /* ndef __SERVER__TXSIGNATURE_H__ */


