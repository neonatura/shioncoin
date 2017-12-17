
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

#include "shcoind.h"
#include "main.h"
#include "hdkey.h"

using namespace std;
using namespace boost;

#include "script.h"
#include "txsignature.h"
#include "keystore.h"
#include "bignum.h"
#include "key.h"
#include "derkey.h"
#include "main.h"
#include "sync.h"
#include "util.h"


CScriptID::CScriptID(const CScript& in) : uint160(Hash160(cbuff(in.begin(), in.end()))) {}


typedef vector<unsigned char> valtype;
static const valtype vchFalse(0);
static const valtype vchZero(0);
static const valtype vchTrue(1, 1);
static const CBigNum bnZero(0);
static const CBigNum bnOne(1);
static const CBigNum bnFalse(0);
static const CBigNum bnTrue(1);
static const size_t nMaxNumSize = 4;

// Maximum number of bytes pushable to the stack
static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520;



CBigNum CastToBigNum(const valtype& vch)
{
    if (vch.size() > nMaxNumSize)
        throw runtime_error("CastToBigNum() : overflow");
    // Get rid of extra leading zeros
    return CBigNum(CBigNum(vch).getvch());
}

bool CastToBool(const valtype& vch)
{
    for (unsigned int i = 0; i < vch.size(); i++)
    {
        if (vch[i] != 0)
        {
            // Can be negative zero
            if (i == vch.size()-1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

void MakeSameSize(valtype& vch1, valtype& vch2)
{
    // Lengthen the shorter one
    if (vch1.size() < vch2.size())
        vch1.resize(vch2.size(), 0);
    if (vch2.size() < vch1.size())
        vch2.resize(vch1.size(), 0);
}



//
// Script is a stack machine (like Forth) that evaluates a predicate
// returning a bool indicating valid or not.  There are no loops.
//
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))
static inline void popstack(vector<valtype>& stack)
{
    if (stack.empty())
        throw runtime_error("popstack() : stack empty");
    stack.pop_back();
}


const char* GetTxnOutputType(txnouttype t)
{
  switch (t)
  {
    case TX_NONSTANDARD: return "nonstandard";
    case TX_PUBKEY: return "pubkey";
    case TX_PUBKEYHASH: return "pubkeyhash";
    case TX_SCRIPTHASH: return "scripthash";
    case TX_MULTISIG: return "multisig";
    case TX_RETURN: return "return";
    case TX_WITNESS_V0_KEYHASH: return "witness_v0_keyhash";
    case TX_WITNESS_V0_SCRIPTHASH: return "witness_v0_scripthash";
    }
    return NULL;
}


const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

    // expanson
    case OP_NOP1                   : return "OP_NOP1";
    case OP_NOP2                   : return "OP_NOP2";
    case OP_NOP3                   : return "OP_NOP3";
    case OP_NOP4                   : return "OP_NOP4";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";

    case OP_CONTEXT                : return "OP_CONTEXT";
    case OP_EXEC                   : return "OP_EXEC";
    case OP_ALIAS                  : return "OP_ALIAS";
    case OP_OFFER                  : return "OP_OFFER";
    case OP_IDENT                  : return "OP_IDENT";
    case OP_CERT                   : return "OP_CERT";
    case OP_LICENSE                : return "OP_LICENSE";
    case OP_ASSET                  : return "OP_ASSET";
    case OP_MATRIX                 : return "OP_MATRIX";
    case OP_VAULT                  : return "OP_VAULT";
    case OP_CHANNEL                : return "OP_CHANNEL";

    /* extension operatives */
    case OP_EXT_NEW                : return "OP_EXT_NEW";
    case OP_EXT_ACTIVATE           : return "OP_EXT_ACTIVATE";
    case OP_EXT_UPDATE             : return "OP_EXT_UPDATE";
    case OP_EXT_REMOVE             : return "OP_EXT_REMOVE";
    case OP_EXT_GENERATE           : return "OP_EXT_GENERATE";
    case OP_EXT_TRANSFER           : return "OP_EXT_TRANSFER";
    case OP_EXT_PAY                : return "OP_EXT_PAY";
    case OP_EXT_VALIDATE                : return "OP_EXT_VALIDATE";

    // template matching params
    case OP_PUBKEYHASH             : return "OP_PUBKEYHASH";
    case OP_PUBKEY                 : return "OP_PUBKEY";
    case OP_EXT_HASH               : return "OP_EXT_HASH";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";
    default:
        return "OP_UNKNOWN";
    }
}

bool static _CheckLowS(const std::vector<unsigned char>& vchSig)
{
  secp256k1_context *secp256k1_context_verify = SECP256K1_VERIFY_CONTEXT();
  secp256k1_ecdsa_signature sig;
  bool ok;

  if (vchSig.size() == 0)
    return (true);

  memset(&sig, 0, sizeof(sig));
  if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig, &vchSig[0], vchSig.size())) {
    return error(SHERR_INVAL, "CheckLowS: warning: error parsing DER: vchSig(\"%s)\".", HexStr(vchSig).c_str());
  }

  if (secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, NULL, &sig)) {
    return error(SHERR_INVAL, "CheckLowS: warning: DER signature \"%s\" would require normalizing.", HexStr(vchSig).c_str());
  }

  return (true);
}


//bool EvalScript(vector<vector<unsigned char> >& stack, const CScript& script, const CTransaction& txTo, unsigned int nIn, int nHashType, int sigver, int flags)
bool EvalScript(CSignature& sig, cstack_t& stack, const CScript& script, unsigned int sigver, int flags)
{
  const CTransaction& txTo = *sig.tx;
  int nHashType = sig.nHashType;
  CAutoBN_CTX pctx;
  CScript::const_iterator pc = script.begin();
  CScript::const_iterator pend = script.end();
  CScript::const_iterator pbegincodehash = script.begin();
  opcodetype opcode;
  valtype vchPushValue;
  vector<bool> vfExec;
  vector<valtype> altstack;
  if (script.size() > 10000) {
    return false;
}
  int nOpCount = 0;

  try
  {
    while (pc < pend)
    {
      bool fExec = !count(vfExec.begin(), vfExec.end(), false);

      //
      // Read instruction
      //
      if (!script.GetOp(pc, opcode, vchPushValue))
        return false;
      if (vchPushValue.size() > 520)
        return false;
      if (opcode > OP_16 && ++nOpCount > 201)
        return false;

      if (opcode == OP_CAT ||
          opcode == OP_SUBSTR ||
          opcode == OP_LEFT ||
          opcode == OP_RIGHT ||
          opcode == OP_INVERT ||
          opcode == OP_AND ||
          opcode == OP_OR ||
          opcode == OP_XOR ||
          opcode == OP_2MUL ||
          opcode == OP_2DIV ||
          opcode == OP_MUL ||
          opcode == OP_DIV ||
          opcode == OP_MOD ||
          opcode == OP_LSHIFT ||
          opcode == OP_RSHIFT)
        return false;

      if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4)
        stack.push_back(vchPushValue);
      else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
        switch (opcode)
        {
          //
          // Push value
          //
          case OP_1NEGATE:
          case OP_1:
          case OP_2:
          case OP_3:
          case OP_4:
          case OP_5:
          case OP_6:
          case OP_7:
          case OP_8:
          case OP_9:
          case OP_10:
          case OP_11:
          case OP_12:
          case OP_13:
          case OP_14:
          case OP_15:
          case OP_16:
            {
              // ( -- value)
              CBigNum bn((int)opcode - (int)(OP_1 - 1));
              stack.push_back(bn.getvch());
            }
            break;


            //
            // Control
            //
          case OP_NOP:
          case OP_NOP1: case OP_NOP2: case OP_NOP3: case OP_NOP4: case OP_NOP5:
          case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
            break;

          case OP_IF:
          case OP_NOTIF:
            {
              // <expression> if [statements] [else [statements]] endif
              bool fValue = false;
              if (fExec)
              {
                if (stack.size() < 1)
                  return false;
                valtype& vch = stacktop(-1);
                if (sigver == SIGVERSION_WITNESS_V0 && 
                    (flags & SCRIPT_VERIFY_MINIMALIF)) {
                  if (vch.size() > 1)
                    return false;
                  if (vch.size() == 1 && vch[0] != 1)
                    return false;
                }
                fValue = CastToBool(vch);
                if (opcode == OP_NOTIF)
                  fValue = !fValue;
                popstack(stack);
              }
              vfExec.push_back(fValue);
            }
            break;

          case OP_ELSE:
            {
              if (vfExec.empty())
                return false;
              vfExec.back() = !vfExec.back();
            }
            break;

          case OP_ENDIF:
            {
              if (vfExec.empty())
                return false;
              vfExec.pop_back();
            }
            break;

          case OP_VERIFY:
            {
              // (true -- ) or
              // (false -- false) and return
              if (stack.size() < 1)
                return false;
              bool fValue = CastToBool(stacktop(-1));
              if (fValue)
                popstack(stack);
              else
                return false;
            }
            break;

          case OP_RETURN:
            {
              return false;
            }
            break;


            //
            // Stack ops
            //
          case OP_TOALTSTACK:
            {
              if (stack.size() < 1)
                return false;
              altstack.push_back(stacktop(-1));
              popstack(stack);
            }
            break;

          case OP_FROMALTSTACK:
            {
              if (altstack.size() < 1)
                return false;
              stack.push_back(altstacktop(-1));
              popstack(altstack);
            }
            break;

          case OP_2DROP:
            {
              // (x1 x2 -- )
              if (stack.size() < 2) {
                return false;
              }
              popstack(stack);
              popstack(stack);
            }
            break;

          case OP_2DUP:
            {
              // (x1 x2 -- x1 x2 x1 x2)
              if (stack.size() < 2)
                return false;
              valtype vch1 = stacktop(-2);
              valtype vch2 = stacktop(-1);
              stack.push_back(vch1);
              stack.push_back(vch2);
            }
            break;

          case OP_3DUP:
            {
              // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
              if (stack.size() < 3)
                return false;
              valtype vch1 = stacktop(-3);
              valtype vch2 = stacktop(-2);
              valtype vch3 = stacktop(-1);
              stack.push_back(vch1);
              stack.push_back(vch2);
              stack.push_back(vch3);
            }
            break;

          case OP_2OVER:
            {
              // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
              if (stack.size() < 4)
                return false;
              valtype vch1 = stacktop(-4);
              valtype vch2 = stacktop(-3);
              stack.push_back(vch1);
              stack.push_back(vch2);
            }
            break;

          case OP_2ROT:
            {
              // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
              if (stack.size() < 6)
                return false;
              valtype vch1 = stacktop(-6);
              valtype vch2 = stacktop(-5);
              stack.erase(stack.end()-6, stack.end()-4);
              stack.push_back(vch1);
              stack.push_back(vch2);
            }
            break;

          case OP_2SWAP:
            {
              // (x1 x2 x3 x4 -- x3 x4 x1 x2)
              if (stack.size() < 4)
                return false;
              swap(stacktop(-4), stacktop(-2));
              swap(stacktop(-3), stacktop(-1));
            }
            break;

          case OP_IFDUP:
            {
              // (x - 0 | x x)
              if (stack.size() < 1)
                return false;
              valtype vch = stacktop(-1);
              if (CastToBool(vch))
                stack.push_back(vch);
            }
            break;

          case OP_DEPTH:
            {
              // -- stacksize
              CBigNum bn(stack.size());
              stack.push_back(bn.getvch());
            }
            break;

          case OP_DROP:
            {
              // (x -- )
              if (stack.size() < 1) {
                return false;
              }
              popstack(stack);
            }
            break;

          case OP_DUP:
            {
              // (x -- x x)
              if (stack.size() < 1)
                return false;
              valtype vch = stacktop(-1);
              stack.push_back(vch);
            }
            break;

          case OP_NIP:
            {
              // (x1 x2 -- x2)
              if (stack.size() < 2)
                return false;
              stack.erase(stack.end() - 2);
            }
            break;

          case OP_OVER:
            {
              // (x1 x2 -- x1 x2 x1)
              if (stack.size() < 2)
                return false;
              valtype vch = stacktop(-2);
              stack.push_back(vch);
            }
            break;

          case OP_PICK:
          case OP_ROLL:
            {
              // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
              // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
              if (stack.size() < 2)
                return false;
              int n = CastToBigNum(stacktop(-1)).getint();
              popstack(stack);
              if (n < 0 || n >= (int)stack.size())
                return false;
              valtype vch = stacktop(-n-1);
              if (opcode == OP_ROLL)
                stack.erase(stack.end()-n-1);
              stack.push_back(vch);
            }
            break;

          case OP_ROT:
            {
              // (x1 x2 x3 -- x2 x3 x1)
              //  x2 x1 x3  after first swap
              //  x2 x3 x1  after second swap
              if (stack.size() < 3)
                return false;
              swap(stacktop(-3), stacktop(-2));
              swap(stacktop(-2), stacktop(-1));
            }
            break;

          case OP_SWAP:
            {
              // (x1 x2 -- x2 x1)
              if (stack.size() < 2)
                return false;
              swap(stacktop(-2), stacktop(-1));
            }
            break;

          case OP_TUCK:
            {
              // (x1 x2 -- x2 x1 x2)
              if (stack.size() < 2)
                return false;
              valtype vch = stacktop(-1);
              stack.insert(stack.end()-2, vch);
            }
            break;


            //
            // Splice ops
            //
          case OP_CAT:
            {
              // (x1 x2 -- out)
              if (stack.size() < 2)
                return false;
              valtype& vch1 = stacktop(-2);
              valtype& vch2 = stacktop(-1);
              vch1.insert(vch1.end(), vch2.begin(), vch2.end());
              popstack(stack);
              if (stacktop(-1).size() > 520)
                return false;
            }
            break;

          case OP_SUBSTR:
            {
              // (in begin size -- out)
              if (stack.size() < 3)
                return false;
              valtype& vch = stacktop(-3);
              int nBegin = CastToBigNum(stacktop(-2)).getint();
              int nEnd = nBegin + CastToBigNum(stacktop(-1)).getint();
              if (nBegin < 0 || nEnd < nBegin)
                return false;
              if (nBegin > (int)vch.size())
                nBegin = vch.size();
              if (nEnd > (int)vch.size())
                nEnd = vch.size();
              vch.erase(vch.begin() + nEnd, vch.end());
              vch.erase(vch.begin(), vch.begin() + nBegin);
              popstack(stack);
              popstack(stack);
            }
            break;

          case OP_LEFT:
          case OP_RIGHT:
            {
              // (in size -- out)
              if (stack.size() < 2)
                return false;
              valtype& vch = stacktop(-2);
              int nSize = CastToBigNum(stacktop(-1)).getint();
              if (nSize < 0)
                return false;
              if (nSize > (int)vch.size())
                nSize = vch.size();
              if (opcode == OP_LEFT)
                vch.erase(vch.begin() + nSize, vch.end());
              else
                vch.erase(vch.begin(), vch.end() - nSize);
              popstack(stack);
            }
            break;

          case OP_SIZE:
            {
              // (in -- in size)
              if (stack.size() < 1)
                return false;
              CBigNum bn(stacktop(-1).size());
              stack.push_back(bn.getvch());
            }
            break;


            //
            // Bitwise logic
            //
          case OP_INVERT:
            {
              // (in - out)
              if (stack.size() < 1)
                return false;
              valtype& vch = stacktop(-1);
              for (unsigned int i = 0; i < vch.size(); i++)
                vch[i] = ~vch[i];
            }
            break;

          case OP_AND:
          case OP_OR:
          case OP_XOR:
            {
              // (x1 x2 - out)
              if (stack.size() < 2)
                return false;
              valtype& vch1 = stacktop(-2);
              valtype& vch2 = stacktop(-1);
              MakeSameSize(vch1, vch2);
              if (opcode == OP_AND)
              {
                for (unsigned int i = 0; i < vch1.size(); i++)
                  vch1[i] &= vch2[i];
              }
              else if (opcode == OP_OR)
              {
                for (unsigned int i = 0; i < vch1.size(); i++)
                  vch1[i] |= vch2[i];
              }
              else if (opcode == OP_XOR)
              {
                for (unsigned int i = 0; i < vch1.size(); i++)
                  vch1[i] ^= vch2[i];
              }
              popstack(stack);
            }
            break;

          case OP_EQUAL:
          case OP_EQUALVERIFY:
            //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
            {
              // (x1 x2 - bool)
              if (stack.size() < 2)
                return false;
              valtype& vch1 = stacktop(-2);
              valtype& vch2 = stacktop(-1);
              bool fEqual = (vch1 == vch2);
if (!fEqual) {
fprintf(stderr, "DEBUG: EvalScript: OP_EQUALVERIFY: \"%s\" != \"%s\" [tx %s] [script %s]\n", HexStr(vch1).c_str(), HexStr(vch2).c_str(), sig.tx->GetHash().GetHex().c_str(), script.ToString().c_str());
}
              // OP_NOTEQUAL is disabled because it would be too easy to say
              // something like n != 1 and have some wiseguy pass in 1 with extra
              // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
              //if (opcode == OP_NOTEQUAL)
              //    fEqual = !fEqual;
              popstack(stack);
              popstack(stack);
              stack.push_back(fEqual ? vchTrue : vchFalse);
              if (opcode == OP_EQUALVERIFY)
              {
                if (fEqual)
                  popstack(stack);
                else
                  return false;
              }
            }
            break;


            //
            // Numeric
            //
          case OP_1ADD:
          case OP_1SUB:
          case OP_2MUL:
          case OP_2DIV:
          case OP_NEGATE:
          case OP_ABS:
          case OP_NOT:
          case OP_0NOTEQUAL:
            {
              // (in -- out)
              if (stack.size() < 1)
                return false;
              CBigNum bn = CastToBigNum(stacktop(-1));
              switch (opcode)
              {
                case OP_1ADD:       bn += bnOne; break;
                case OP_1SUB:       bn -= bnOne; break;
                case OP_2MUL:       bn <<= 1; break;
                case OP_2DIV:       bn >>= 1; break;
                case OP_NEGATE:     bn = -bn; break;
                case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                case OP_NOT:        bn = (bn == bnZero); break;
                case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                default:            assert(!"invalid opcode"); break;
              }
              popstack(stack);
              stack.push_back(bn.getvch());
            }
            break;

          case OP_ADD:
          case OP_SUB:
          case OP_MUL:
          case OP_DIV:
          case OP_MOD:
          case OP_LSHIFT:
          case OP_RSHIFT:
          case OP_BOOLAND:
          case OP_BOOLOR:
          case OP_NUMEQUAL:
          case OP_NUMEQUALVERIFY:
          case OP_NUMNOTEQUAL:
          case OP_LESSTHAN:
          case OP_GREATERTHAN:
          case OP_LESSTHANOREQUAL:
          case OP_GREATERTHANOREQUAL:
          case OP_MIN:
          case OP_MAX:
            {
              // (x1 x2 -- out)
              if (stack.size() < 2)
                return false;
              CBigNum bn1 = CastToBigNum(stacktop(-2));
              CBigNum bn2 = CastToBigNum(stacktop(-1));
              CBigNum bn;
              switch (opcode)
              {
                case OP_ADD:
                  bn = bn1 + bn2;
                  break;

                case OP_SUB:
                  bn = bn1 - bn2;
                  break;

                case OP_MUL:
                  if (!BN_mul(&bn, &bn1, &bn2, pctx))
                    return false;
                  break;

                case OP_DIV:
                  if (!BN_div(&bn, NULL, &bn1, &bn2, pctx))
                    return false;
                  break;

                case OP_MOD:
                  if (!BN_mod(&bn, &bn1, &bn2, pctx))
                    return false;
                  break;

                case OP_LSHIFT:
                  if (bn2 < bnZero || bn2 > CBigNum(2048))
                    return false;
                  bn = bn1 << bn2.getulong();
                  break;

                case OP_RSHIFT:
                  if (bn2 < bnZero || bn2 > CBigNum(2048))
                    return false;
                  bn = bn1 >> bn2.getulong();
                  break;

                case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                default:                     assert(!"invalid opcode"); break;
              }
              popstack(stack);
              popstack(stack);
              stack.push_back(bn.getvch());

              if (opcode == OP_NUMEQUALVERIFY)
              {
                if (CastToBool(stacktop(-1)))
                  popstack(stack);
                else
                  return false;
              }
            }
            break;

          case OP_WITHIN:
            {
              // (x min max -- out)
              if (stack.size() < 3)
                return false;
              CBigNum bn1 = CastToBigNum(stacktop(-3));
              CBigNum bn2 = CastToBigNum(stacktop(-2));
              CBigNum bn3 = CastToBigNum(stacktop(-1));
              bool fValue = (bn2 <= bn1 && bn1 < bn3);
              popstack(stack);
              popstack(stack);
              popstack(stack);
              stack.push_back(fValue ? vchTrue : vchFalse);
            }
            break;


            //
            // Crypto
            //
          case OP_RIPEMD160:
          case OP_SHA1:
          case OP_SHA256:
          case OP_HASH160:
          case OP_HASH256:
            {
              // (in -- hash)
              if (stack.size() < 1)
                return false;
              valtype& vch = stacktop(-1);
              valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
              if (opcode == OP_RIPEMD160)
                RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
              else if (opcode == OP_SHA1)
                SHA1(&vch[0], vch.size(), &vchHash[0]);
              else if (opcode == OP_SHA256)
                SHA256(&vch[0], vch.size(), &vchHash[0]);
              else if (opcode == OP_HASH160)
              {
                uint160 hash160 = Hash160(vch);
                memcpy(&vchHash[0], &hash160, sizeof(hash160));
              }
              else if (opcode == OP_HASH256)
              {
                uint256 hash = Hash(vch.begin(), vch.end());
                memcpy(&vchHash[0], &hash, sizeof(hash));
              }
              popstack(stack);
              stack.push_back(vchHash);
            }
            break;

          case OP_CODESEPARATOR:
            {
              // Hash starts after the code separator
              pbegincodehash = pc;
            }
            break;

          case OP_CHECKSIG:
          case OP_CHECKSIGVERIFY:
            {
              // (sig pubkey -- bool)
              if (stack.size() < 2) {
                return (error(SHERR_INVAL, "EvalScript: OP_CHECKSIG stack requires both signature and pub-key [stack-size %d]: \"%s\"\n", stack.size(), script.ToString().c_str()));
              }

              valtype& vchSig    = stacktop(-2);
              valtype& vchPubKey = stacktop(-1);

              ////// debug print
              //PrintHex(vchSig.begin(), vchSig.end(), "evalscript sig: %s\n");
              //PrintHex(vchPubKey.begin(), vchPubKey.end(), "evalscript pubkey: %s\n");

              // Subset of script starting at the most recent codeseparator
              CScript scriptCode(pbegincodehash, pend);

              if (sigver == SIGVERSION_BASE) {
                // Drop the signature, since there's no way for a signature to sign itself
                scriptCode.FindAndDelete(CScript(vchSig));
              }

              if (flags & SCRIPT_VERIFY_LOW_S) {
                std::vector<unsigned char> vchSigCopy(vchSig.begin(), vchSig.begin() + vchSig.size() - 1);
                if (!_CheckLowS(vchSigCopy))
                  return (false); 
              }

              bool fSuccess = sig.CheckSig(vchSig, vchPubKey, scriptCode, sigver);
//fprintf(stderr, "DEBUG: EvalScript: sig.checkSig(%s): vchPubKey(%s) vchSig(%s)\n", (fSuccess ? "success" : "failure"), HexStr(vchPubKey).c_str(), HexStr(vchSig).c_str()); 
if (!fSuccess) { fprintf(stderr, "DEBUG: EvalScript: CheckSig !fSuccess: vchSig-size(%d): \"%s\"\n",  vchSig.size(), CScript(vchSig).ToString().c_str()); }

              popstack(stack);
              popstack(stack);
              stack.push_back(fSuccess ? vchTrue : vchFalse);
              if (opcode == OP_CHECKSIGVERIFY)
              {
                if (fSuccess)
                  popstack(stack);
                else
                  return false;
              }
            }
            break;

          case OP_CHECKMULTISIG:
          case OP_CHECKMULTISIGVERIFY:
            {
              // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

              int i = 1;
              if ((int)stack.size() < i)
                return false;

              int nKeysCount = CastToBigNum(stacktop(-i)).getint();
              if (nKeysCount < 0 || nKeysCount > 20)
                return false;
              nOpCount += nKeysCount;
              if (nOpCount > 201)
                return false;
              int ikey = ++i;
              i += nKeysCount;
              if ((int)stack.size() < i)
                return false;

              int nSigsCount = CastToBigNum(stacktop(-i)).getint();
              if (nSigsCount < 0 || nSigsCount > nKeysCount)
                return false;
              int isig = ++i;
              i += nSigsCount;
              if ((int)stack.size() < i)
                return false;

              // Subset of script starting at the most recent codeseparator
              CScript scriptCode(pbegincodehash, pend);

              // Drop the signatures, since there's no way for a signature to sign itself
              for (int k = 0; k < nSigsCount; k++)
              {
                valtype& vchSig = stacktop(-isig-k);
                if (sigver == SIGVERSION_BASE) {
                  scriptCode.FindAndDelete(CScript(vchSig));
                }
              }

              bool fSuccess = true;
              while (fSuccess && nSigsCount > 0)
              {
                valtype& vchSig    = stacktop(-isig);
                valtype& vchPubKey = stacktop(-ikey);

                // Check signature
                if (sig.CheckSig(vchSig, vchPubKey, scriptCode, sigver))
                {
                  isig++;
                  nSigsCount--;
                }
                ikey++;
                nKeysCount--;

                // If there are more signatures left than keys left,
                // then too many signatures have failed
                if (nSigsCount > nKeysCount)
                  fSuccess = false;
              }

              while (i-- > 0)
                popstack(stack);
              stack.push_back(fSuccess ? vchTrue : vchFalse);

              if (opcode == OP_CHECKMULTISIGVERIFY)
              {
                if (fSuccess)
                  popstack(stack);
                else
                  return false;
              }
            }
            break;

          default:
            if (opcode >= 0xf0 && opcode <= 0xf9) { /* ext */
              break;
            }

fprintf(stderr, "DEBUG: EvalScript: unknown op-code %x\n", (int)opcode);
            return false;
        }

      // Size limits
      if (stack.size() + altstack.size() > 1000)
        return false;
    }
  }
  catch (...)
  {
fprintf(stderr, "DEBUG: EvalScript: caught exception\n");
    return false;
  }


  if (!vfExec.empty()) {
fprintf(stderr, "DEBUG: EvalScript: !vfExec.empty()\n");
    return false;
  }

  return true;
}




uint256 GetPrevoutHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vin.size(); n++) {
        ss << txTo.vin[n].prevout;
    }
    return ss.GetHash();
}

uint256 GetSequenceHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vin.size(); n++) {
        ss << txTo.vin[n].nSequence;
    }
    return ss.GetHash();
}

uint256 GetOutputsHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vout.size(); n++) {
        ss << txTo.vout[n];
    }
    return ss.GetHash();
}




#if 0
uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType, int sigver)
{

  if (nIn >= txTo.vin.size())
  {
    printf("ERROR: SignatureHash() : nIn=%d out of range\n", nIn);
    return 1;
  }
  CTransaction txTmp(txTo);

  // In case concatenating two scripts ends up with two codeseparators,
  // or an extra one at the end, this prevents all those possible incompatibilities.
  scriptCode.FindAndDelete(CScript(OP_CODESEPARATOR));

  // Blank out other inputs' signatures
  for (unsigned int i = 0; i < txTmp.vin.size(); i++)
    txTmp.vin[i].scriptSig = CScript();
  txTmp.vin[nIn].scriptSig = scriptCode;

  // Blank out some of the outputs
  if ((nHashType & 0x1f) == SIGHASH_NONE)
  {
    // Wildcard payee
    txTmp.vout.clear();

    // Let the others update at will
    for (unsigned int i = 0; i < txTmp.vin.size(); i++)
      if (i != nIn)
        txTmp.vin[i].nSequence = 0;
  }
  else if ((nHashType & 0x1f) == SIGHASH_SINGLE)
  {
    // Only lockin the txout payee at same index as txin
    unsigned int nOut = nIn;
    if (nOut >= txTmp.vout.size())
    {
      printf("ERROR: SignatureHash() : nOut=%d out of range\n", nOut);
      return 1;
    }
    txTmp.vout.resize(nOut+1);
    for (unsigned int i = 0; i < nOut; i++)
      txTmp.vout[i].SetNull();

    // Let the others update at will
    for (unsigned int i = 0; i < txTmp.vin.size(); i++)
      if (i != nIn)
        txTmp.vin[i].nSequence = 0;
  }

  // Blank out other inputs completely, not recommended for open transactions
  if (nHashType & SIGHASH_ANYONECANPAY)
  {
    txTmp.vin[0] = txTmp.vin[nIn];
    txTmp.vin.resize(1);
  }

  // Serialize and hash
  CDataStream ss(SER_GETHASH, 0);
  ss.reserve(10000);
  ss << txTmp << nHashType;
  return Hash(ss.begin(), ss.end());
}



// Valid signature cache, to avoid doing expensive ECDSA signature checking
// twice for every transaction (once when accepted into memory pool, and
// again when accepted into the block chain)


bool CheckSig(vector<unsigned char> vchSig, vector<unsigned char> vchPubKey, CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType, int sigver)
{

  // Hash type is one byte tacked on to the end of the signature
  if (vchSig.empty()) {
    return false;
  }
  if (nHashType == 0)
    nHashType = vchSig.back();
  else if (nHashType != vchSig.back()) {
    return false;
  }
  vchSig.pop_back();

  uint256 sighash = SignatureHash(scriptCode, txTo, nIn, nHashType, sigver);

  if (nHashType & SIGHASH_HDKEY) {
    HDPubKey pubkey(vchPubKey);
    if (!pubkey.Verify(sighash, vchSig)) {
      return false;
    }
  } else {
    CKey key;
    if (!key.SetPubKey(vchPubKey))
      return false;

    if (!key.Verify(sighash, vchSig))
      return false;
  }

  return true;
}

#endif





static bool core_CScript_IsPushOnly(const CScript& script, int of = 0)
{       
    CScript::const_iterator pc = script.begin() + of;


  while (pc < script.end())
  {
    opcodetype opcode;
    if (!script.GetOp(pc, opcode))
      return false;
    // Note that IsPushOnly() *does* consider OP_RESERVED to be a
    // push-type opcode, however execution of OP_RESERVED fails, so
    // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
    // the P2SH special validation code being executed.
    if (opcode > OP_16) 
      return false;
  }

  return true;
}       





//
// Return public keys or hashes from scriptPubKey, for 'standard' transaction types.
//
bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, vector<vector<unsigned char> >& vSolutionsRet)
{

  // Templates
  static map<txnouttype, CScript> mTemplates;
  if (mTemplates.empty())
  {
    // Standard tx, sender provides pubkey, receiver adds signature
    mTemplates.insert(make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));

    // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
    mTemplates.insert(make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

    // Sender provides N pubkeys, receivers provides M signatures
    mTemplates.insert(make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));

    /* Extended transactions follow the format of 
     * "OP_EXT_XXX << OP_XXX << OP_HASH160 << <hash> << OP_2DROP << OP_RETURN".
     * The first two directives and last two directives each count as
     * a single sig-op comprising of a total of 2 sig-ops. The 2DROP
     * drops both of them from the stack leaving behind a single 
     * OP_RETURN sig-op with null destination. Note that the 
     * OP_RETURN itself has a nValue (>= min_tx) and is 
     * not counted towards the block transaction fee.
     */ 

    /* sent to null address (burnt coins) */
    mTemplates.insert(make_pair(TX_RETURN, CScript() << OP_RETURN));
  }

  // Shortcut for pay-to-script-hash, which are more constrained than the other types:
  // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
  if (scriptPubKey.IsPayToScriptHash()) {
    typeRet = TX_SCRIPTHASH;
    vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
    vSolutionsRet.push_back(hashBytes);
    return true;
  }

  int witnessversion;
  std::vector<unsigned char> witnessprogram;
  if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
    if (witnessversion == 0 && witnessprogram.size() == 20) {
      typeRet = TX_WITNESS_V0_KEYHASH;
      vSolutionsRet.push_back(witnessprogram);
      return true;
    }
    if (witnessversion == 0 && witnessprogram.size() == 32) {
      typeRet = TX_WITNESS_V0_SCRIPTHASH;
      vSolutionsRet.push_back(witnessprogram);
      return true;
    }
    return false;
  }



  // Scan templates
  const CScript& script1 = scriptPubKey;

  BOOST_FOREACH(const PAIRTYPE(txnouttype, CScript)& tplate, mTemplates)
  {
    const CScript& script2 = tplate.second;
    vSolutionsRet.clear();

    opcodetype opcode1, opcode2;
    vector<unsigned char> vch1, vch2;

    // Compare
    CScript::const_iterator pc1 = script1.begin();
    CScript::const_iterator pc2 = script2.begin();
    loop
    {
      if (pc1 == script1.end() && pc2 == script2.end())
      {
        // Found a match
        typeRet = tplate.first;
        if (typeRet == TX_MULTISIG)
        {
          // Additional checks for TX_MULTISIG:
          unsigned char m = vSolutionsRet.front()[0];
          unsigned char n = vSolutionsRet.back()[0];
          if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
            return false;
        }
        return true;
      }
      if (!script1.GetOp(pc1, opcode1, vch1)) {
        break;
      }
      if (opcode1 >= 0xf0 && opcode1 < 0xfa) { /* ext */
        while (opcode1 != OP_2DROP && opcode1 != OP_DROP) {
          if (!script1.GetOp(pc1, opcode1, vch1))
            break;
        }
        while (opcode1 == OP_2DROP || opcode1 == OP_DROP) {
          if (!script1.GetOp(pc1, opcode1, vch1))
            break;
        }
      }
      if (!script2.GetOp(pc2, opcode2, vch2)) {
        break;
      }


      // Template matching opcodes:
      if (opcode2 == OP_PUBKEYS)
      {
        while (vch1.size() >= 33 && vch1.size() <= 120)
        {
          vSolutionsRet.push_back(vch1);
          if (!script1.GetOp(pc1, opcode1, vch1))
            break;
        }
        if (!script2.GetOp(pc2, opcode2, vch2))
          break;
        // Normal situation is to fall through
        // to other if/else statments
      }

      if (opcode2 == OP_PUBKEY)
      {
        if (vch1.size() < 33 || vch1.size() > 120)
          break;
        vSolutionsRet.push_back(vch1);
      }
      else if (opcode2 == OP_PUBKEYHASH)
      {
        if (vch1.size() != sizeof(uint160))
          break;
        vSolutionsRet.push_back(vch1);
      }
      else if (opcode2 == OP_EXT_HASH)
      {
        if (vch1.size() != sizeof(uint160))
          break;
        //                vSolutionsRet.push_back(vch1);
      }
      else if (opcode2 == OP_SMALLINTEGER)
      {   // Single-byte small integer pushed onto vSolutions
        if (opcode1 == OP_0 ||
            (opcode1 >= OP_1 && opcode1 <= OP_16))
        {
          char n = (char)CScript::DecodeOP_N(opcode1);
          vSolutionsRet.push_back(valtype(1, n));
        }
        else
          break;
      }
      else if (opcode1 != opcode2 || vch1 != vch2)
      {
        // Others must match exactly
        break;
      }
    }
  }
  /* The template above handles extended transaction which resolve into a single OP_RETURN and the remainder pushed off the stacked before-hand. */

  /* The case below handles auxiliary no-op information where OP_RETURN is followed by 1 or more bytes of information containing "push-only" info.
   * It is currently used via BIP 9 to relay consensis commitment for proposed features. The nValue is nominally 0 in this case.
   */
  if (scriptPubKey.size() > 1 && 
      scriptPubKey[0] == OP_RETURN && 
      core_CScript_IsPushOnly(scriptPubKey, 1)) {
    // Provably prunable, data-carrying output..
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    typeRet = TX_RETURN;
    return true;
  }

fprintf(stderr, "DEBUG: Solver: no script template found matching \"%s\"\n", scriptPubKey.ToString().c_str()); 
  vSolutionsRet.clear();
  typeRet = TX_NONSTANDARD;
  return false;
}


bool Sign1(const CKeyID& address, const CKeyStore& keystore, uint256 hash, int nHashType, CScript& scriptSigRet)
{

  if (!(nHashType & SIGHASH_HDKEY)) {
    CKey key;
    if (!keystore.GetKey(address, key))
      return false;

    vector<unsigned char> vchSig;
    if (!key.Sign(hash, vchSig))
      return false;
    vchSig.push_back((unsigned char)nHashType);
    scriptSigRet << vchSig;

  } else {
    HDPrivKey key;
    if (!keystore.GetKey(address, key))
      return false;

    vector<unsigned char> vchSig;
    if (!key.Sign(hash, vchSig))
      return false;

    vchSig.push_back((unsigned char)nHashType);
    scriptSigRet << vchSig;
  }

  return true;
}

bool SignN(const vector<valtype>& multisigdata, const CKeyStore& keystore, uint256 hash, int nHashType, CScript& scriptSigRet)
{
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];

    if (!(nHashType & SIGHASH_HDKEY)) {
      for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++)
      {
          const valtype& pubkey = multisigdata[i];
          CKeyID keyID = CPubKey(pubkey).GetID();
          if (Sign1(keyID, keystore, hash, nHashType, scriptSigRet))
              ++nSigned;
      }
    } else {
      for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++)
      {
          const valtype& pubkey = multisigdata[i];
          CKeyID keyID = HDPubKey(pubkey).GetID();
          if (Sign1(keyID, keystore, hash, nHashType, scriptSigRet))
              ++nSigned;
      }
    }
    return nSigned==nRequired;
}

#if 0
//
// Sign scriptPubKey with private keys stored in keystore, given transaction hash and hash type.
// Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
// unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
// Returns false if scriptPubKey could not be completely satisified.
//
bool Solver(const CKeyStore& keystore, const CScript& scriptPubKey, uint256 hash, int nHashType, CScript& scriptSigRet, txnouttype& whichTypeRet)
{
  scriptSigRet.clear();


  vector<valtype> vSolutions;
  if (!Solver(scriptPubKey, whichTypeRet, vSolutions)) {
fprintf(stderr, "DEBUG: Solver: failed to solve \"%s\"\n", scriptPubKey.ToString().c_str());
    return false;
  }

  CKeyID keyID;
  switch (whichTypeRet) {
    case TX_NONSTANDARD:
      return false;
    case TX_PUBKEY:
      {
        if (!(nHashType & SIGHASH_HDKEY)) {
          keyID = CPubKey(vSolutions[0]).GetID();
          return Sign1(keyID, keystore, hash, nHashType, scriptSigRet);
        }
        keyID = HDPubKey(vSolutions[0]).GetID();
        return Sign1(keyID, keystore, hash, nHashType, scriptSigRet);
      }
    case TX_PUBKEYHASH:
      if (!(nHashType & SIGHASH_HDKEY)) {
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!Sign1(keyID, keystore, hash, nHashType, scriptSigRet))
          return false;
        CPubKey vch;
        keystore.GetPubKey(keyID, vch);
        scriptSigRet << vch;
      } else {
fprintf(stderr, "DEBUG: Solver: TX_PUBKEYHASH: vSolutions.size() = %d\n", vSolutions.size());
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!Sign1(keyID, keystore, hash, nHashType, scriptSigRet))
          return false;
        HDPrivKey key;
        if (!keystore.GetKey(keyID, key))
          return false;
        scriptSigRet << key.GetPubKey().Raw();
      }
      return true;
    case TX_SCRIPTHASH:
      return keystore.GetCScript(uint160(vSolutions[0]), scriptSigRet);

    case TX_MULTISIG:
      scriptSigRet << OP_0; // workaround CHECKMULTISIG bug
      return (SignN(vSolutions, keystore, hash, nHashType, scriptSigRet));

    case TX_WITNESS_V0_KEYHASH:
      {
fprintf(stderr, "DEBUG: Solver: TX_WITNESS_V0_KEYHASH: vSolutions.size() = %d\n", vSolutions.size());
        //scriptSigRet << vSolutions[0];
        cbuff vchSig(vSolutions[0].begin(), vSolutions[0].end());
        scriptSigRet = CScript(vchSig.begin(), vchSig.end());
fprintf(stderr, "DEBUG: Solver: TX_WITNESS_V0_KEYHASH: scriptSigRet: \"%s\"\n", scriptSigRet.ToString().c_str());
fprintf(stderr, "DEBUG: Solver: TX_WITNESS_V0_KEYHASH: vSolutions[0] = \"%s\"\n", HexStr(vSolutions[0].begin(), vSolutions[0].end()).c_str());
        return (true);
      }

    case TX_WITNESS_V0_SCRIPTHASH:
      {
        const cbuff vch(vSolutions[0].begin(), vSolutions[0].end());
        cbuff vchHash;
        uint160 hash160;

        RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
        memcpy(&hash160, &vchHash[0], sizeof(hash160));

        return keystore.GetCScript(hash160, scriptSigRet);
      }
  }

  return false;
}
#endif

#if 0
bool Solver(const CKeyStore& keystore, CSignature& sig, txnouttype& whichTypeRet)
{
  bool ok;
  if (sig.nHashType == TX_WITNESS_V0_KEYHASH) {
    vector<valtype> vSolutions;
    if (!Solver(sig.scriptAddr, whichTypeRet, vSolutions))
      return false;

    sig.stack.push_back(vSolutions[0]);
  } else if (sig.nHashType == TX_WITNESS_V0_SCRIPTHASH) {
    vector<valtype> vSolutions;
    if (!Solver(sig.scriptAddr, whichTypeRet, vSolutions))
      return false;

    if (!keystore.GetCScript(uint160(vSolutions[0]), sig.scriptSig))
      return (false);

    sig.stack.push_back(cbuff(sig.scriptSig.begin(), sig.scriptSig.end()));
  } else {
    ok = Solver(keystore, sig.scriptAddr, sig.hash, sig.nHashType, sig.scriptSig, whichTypeRet);
    if (!ok)
      return (false);

    sig.stack.push_back(cbuff(sig.scriptSig.begin(), sig.scriptSig.end()));
  }

  return (true);
}
#endif

int ScriptSigArgsExpected(txnouttype t, const std::vector<std::vector<unsigned char> >& vSolutions)
{
  switch (t)
  {
    case TX_NONSTANDARD:
      return -1;

    case TX_PUBKEY:
      return 1;

    case TX_PUBKEYHASH:
        return 2;

    case TX_MULTISIG:
        if (vSolutions.size() < 1 || vSolutions[0].size() < 1)
          return -1;
        return vSolutions[0][0] + 1;

    case TX_SCRIPTHASH:
        return 1; // doesn't include args needed by the script

    case TX_WITNESS_V0_SCRIPTHASH:
    case TX_WITNESS_V0_KEYHASH:
      return 0;
  }
  return -1;
}

bool IsStandard(const CScript& scriptPubKey)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_MULTISIG)
    {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3)
            return false;
        if (m < 1 || m > n)
            return false;
    }

    return whichType != TX_NONSTANDARD;
}


unsigned int HaveKeys(const vector<valtype>& pubkeys, const CKeyStore& keystore)
{
    unsigned int nResult = 0;
    BOOST_FOREACH(const valtype& pubkey, pubkeys)
    {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (keystore.HaveKey(keyID))
            ++nResult;
    }
    return nResult;
}


class CKeyStoreIsMineVisitor : public boost::static_visitor<bool>
{
private:
    const CKeyStore *keystore;
public:
    CKeyStoreIsMineVisitor(const CKeyStore *keystoreIn) : keystore(keystoreIn) { }
    bool operator()(const CNoDestination &dest) const { return false; }
    bool operator()(const CKeyID &keyID) const { return keystore->HaveKey(keyID); }
    bool operator()(const CScriptID &scriptID) const { return keystore->HaveCScript(scriptID); }
};

bool IsMine(const CKeyStore &keystore, const CTxDestination &dest)
{
    return boost::apply_visitor(CKeyStoreIsMineVisitor(&keystore), dest);
}



bool IsMine(const CKeyStore &keystore, const CScript& scriptPubKey, bool fWitnessFlag)
{
  vector<valtype> vSolutions;
  txnouttype whichType;
  if (!Solver(scriptPubKey, whichType, vSolutions))
    return false;

  CKeyID keyID;
  switch (whichType)
  {
    case TX_NONSTANDARD:
      return false;

    case TX_PUBKEY:
      if (fWitnessFlag && vSolutions[0].size() != 33) {
        /* segwit restricted to compressed pubkey */
        return (false);
      }
      keyID = CPubKey(vSolutions[0]).GetID();
      return keystore.HaveKey(keyID);

    case TX_PUBKEYHASH:
      keyID = CKeyID(uint160(vSolutions[0]));
      if (fWitnessFlag) {
        CPubKey pubkey;
        if (keystore.GetPubKey(keyID, pubkey) && !pubkey.IsCompressed()) {
          /* segwit restricted to compressed pubkey */
          return (false);
        }
      }
      return keystore.HaveKey(keyID);

    case TX_SCRIPTHASH:
      {
        CScript subscript;
        if (!keystore.GetCScript(CScriptID(uint160(vSolutions[0])), subscript))
          return false;
        return IsMine(keystore, subscript);
      }

    case TX_MULTISIG:
      {
        // Only consider transactions "mine" if we own ALL the
        // keys involved. multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        return HaveKeys(keys, keystore) == keys.size();
      }

    case TX_WITNESS_V0_KEYHASH:
      {
        if (!keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
          /* do not support bare witness outputs unless the P2SH version of it would be acceptable as well. */
          break;
        }

        CScript subscript = GetScriptForDestination(CKeyID(uint160(vSolutions[0])));
        return (::IsMine(keystore, subscript, true));
      }

    case TX_WITNESS_V0_SCRIPTHASH:
      {
        if (!keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0])))
          break;

        uint160 hash2;
        const cbuff vch(vSolutions[0].begin(), vSolutions[0].end());
        cbuff vchHash;
        uint160 hash160;
        RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
        memcpy(&hash160, &vchHash[0], sizeof(hash160));

        CScriptID scriptID = CScriptID(hash160);    
        CScript subscript;
        if (!keystore.GetCScript(scriptID, subscript))
          return (false);
        if (!IsMine(keystore, subscript, true))
          return (false);

        return (true);
      }
  }

  return false;
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_PUBKEY)
    {
        addressRet = CPubKey(vSolutions[0]).GetID();
        return true;
    }
    else if (whichType == TX_PUBKEYHASH)
    {
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    }
    else if (whichType == TX_SCRIPTHASH)
    {
        addressRet = CScriptID(uint160(vSolutions[0]));
        return true;
    } else if (whichType == TX_RETURN) {
        addressRet = CKeyID(); /* blank */
        return true;
    }
    // Multisig txns have more than one address...
    return false;
}

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, vector<CTxDestination>& addressRet, int& nRequiredRet)
{
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, typeRet, vSolutions))
        return false;

    if (typeRet == TX_MULTISIG)
    {
        nRequiredRet = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1; i++)
        {
            CTxDestination address = CPubKey(vSolutions[i]).GetID();
            addressRet.push_back(address);
        }
    }
    else
    {
        nRequiredRet = 1;
        CTxDestination address;
        if (!ExtractDestination(scriptPubKey, address))
           return false;
        addressRet.push_back(address);
    }

    return true;
}

template <typename T>
std::vector<unsigned char> ToByteVector(const T& in)
{       
    return std::vector<unsigned char>(in.begin(), in.end());
}   

static bool VerifyWitnessProgram(CSignature& sig, cstack_t& witness, int witversion, const std::vector<unsigned char>& program, int flags)
{
  unsigned int nIn = sig.nTxIn;
  const CTransaction& txTo = *sig.tx;
  vector<vector<unsigned char> > stack;
  CScript scriptPubKey;

  if (witversion == 0) {
    if (program.size() == 32) {
      // Version 0 segregated witness program: SHA256(CScript) inside the program, CScript + inputs in witness
      if (witness.size() == 0) {
        return false;//set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
      }
      scriptPubKey = CScript(witness.back().begin(), witness.back().end());
      stack = std::vector<std::vector<unsigned char> >(witness.begin(), witness.end() - 1);
      uint256 hashScriptPubKey;

      //CSHA256().Write(&scriptPubKey[0], scriptPubKey.size()).Finalize(hashScriptPubKey.begin());
      hashScriptPubKey = Hash(scriptPubKey.begin(), scriptPubKey.end());

      if (0 != memcmp(hashScriptPubKey.begin(), &program[0], 32)) {
        return false;//set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
      }
    } else if (program.size() == 20) {
      // Special case for pay-to-pubkeyhash; signature + pubkey in witness
      if (witness.size() != 2) {
fprintf(stderr, "DEBUG: ERR_WITNESS_PROGRAM_MISMATCH\n");
        return false;//set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH); // 2 items in witness
      }
      scriptPubKey << OP_DUP << OP_HASH160 << program << OP_EQUALVERIFY << OP_CHECKSIG;
      stack = witness;
    } else {
fprintf(stderr, "DEBUG:VerifWitnessProgram: invalid size program for ver0\n");
      return false;//set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
    }
  } else if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
    return false;//set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
  } else {
    // Higher version witness scripts return true for future softfork compatibility
    return (0);//set_success(serror);
  }

  // Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
  for (unsigned int i = 0; i < stack.size(); i++) {
    if (stack.at(i).size() > MAX_SCRIPT_ELEMENT_SIZE)
      return false;//set_error(serror, SCRIPT_ERR_PUSH_SIZE);
  }

  if (!EvalScript(sig, stack, scriptPubKey, SIGVERSION_WITNESS_V0, SCRIPT_VERIFY_MINIMALIF | flags)) {
    return (error(SHERR_INVAL, "VerifyWitnessProgram: error evaluating witness program."));
  }

  // Scripts inside witness implicitly require cleanstack behaviour
  if (stack.size() != 1)
    return false;//set_error(serror, SCRIPT_ERR_EVAL_FALSE);
  if (!CastToBool(stack.back()))
    return false;//set_error(serror, SCRIPT_ERR_EVAL_FALSE);

  return true;
}


bool VerifyScript(CSignature& sig, const CScript& scriptSig, cstack_t& witness, const CScript& scriptPubKey, bool fValidatePayToScriptHash, int flags)
{
  unsigned int nIn = sig.nTxIn;
  const CTransaction& txTo = *sig.tx;
  //int nHashType = sig.nHashType;
  bool hadWitness = false;

  if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.IsPushOnly()) {
    return (false);
  }

  vector<vector<unsigned char> > stack, stackCopy;

  if (!EvalScript(sig, stack, scriptSig, SIGVERSION_BASE, 0)) {
    return error(SHERR_INVAL, "VerifyScript: error evaluating signature script.");
  }
  if (fValidatePayToScriptHash)
    stackCopy = stack;
  if (!EvalScript(sig, stack, scriptPubKey, SIGVERSION_BASE, 0)) {
    return error(SHERR_INVAL, "VerifyScript: error evaluating script [stack %d]: \"%s\"\n", stack.size(), scriptPubKey.ToString().c_str());
  }
  if (stack.empty()) {
    return error(SHERR_INVAL, "VerifyScript: empty stack for script.");
  }

  if (CastToBool(stack.back()) == false) {
    return error(SHERR_INVAL, "VerifyScript: script does not evaluate to true: \"%s\".", scriptPubKey.ToString().c_str());
  }

  // Bare witness programs
  int witnessversion;
  std::vector<unsigned char> witnessprogram;
  if (flags & SCRIPT_VERIFY_WITNESS) {
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
      hadWitness = true;
      if (scriptSig.size() != 0) {
        // The scriptSig must be _exactly_ CScript(), otherwise we reintroduce malleability.
        return error(SHERR_INVAL, "VerifyScript: witness malleability constraint failure.");
      }
      if (!VerifyWitnessProgram(sig, witness, witnessversion, witnessprogram, flags)) {
        return error(SHERR_INVAL, "VerifyScript: error verifying witness program.");
      }
      // Bypass the cleanstack check at the end. The actual stack is obviously not clean
      // for witness programs.
      stack.resize(1);
    }
  }

  // Additional validation for spend-to-script-hash transactions:
  if (fValidatePayToScriptHash && scriptPubKey.IsPayToScriptHash())
  {
    if (!scriptSig.IsPushOnly()) // scriptSig must be literals-only
      return false;            // or validation fails

    const valtype& pubKeySerialized = stackCopy.back();
    CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
    popstack(stackCopy);

    if (!EvalScript(sig, stackCopy, pubKey2, SIGVERSION_BASE, 0)) {
fprintf(stderr, "DEBUG: VerifyScript: !EvalScript (IsPayToScriptHash)\n");
      return false;
    }
    if (stackCopy.empty())
      return false;
    if (!CastToBool(stackCopy.back()))
      return false;

    // P2SH witness program
    if (flags & SCRIPT_VERIFY_WITNESS) {
      if (pubKey2.IsWitnessProgram(witnessversion, witnessprogram)) {
        hadWitness = true;
        if (scriptSig != CScript() << std::vector<unsigned char>(pubKey2.begin(), pubKey2.end())) {
          // The scriptSig must be _exactly_ a single push of the redeemScript. Otherwise we
          // reintroduce malleability.
          return false;//set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
        }
        if (!VerifyWitnessProgram(sig, witness, witnessversion, witnessprogram,  flags)) {
          return false;
        }
        // Bypass the cleanstack check at the end. The actual stack is obviously not clean
        // for witness programs.
        stack.resize(1);
      }
    }

  }

  if (flags & SCRIPT_VERIFY_WITNESS) {
    if (!hadWitness && !witness.empty()) {
      return (false);
    }
  }

  return true;
}


#if 0
bool SignSignature(const CKeyStore &keystore, const CScript& fromPubKey, CTransaction& txTo, unsigned int nIn, int nHashType)
{
  CSignature sig(fromPubKey, &txTo, nIn, nHashType);
  vector<cbuff> stack;

  stack.clear();

  txnouttype whichType;
  if (!Solver(keystore, sig, whichType)) {
    return (error(SHERR_INVAL, "SignSignature: error solving coin address."));
  }

  bool P2SH = false;
  CScript subscript;
  if (whichType == TX_SCRIPTHASH)
  {
    // Solver returns the subscript that need to be evaluated;
    // the final scriptSig is the signatures from that
    // and then the serialized subscript:
    subscript = sig.scriptSig;
    CSignature sig2(subscript, &txTo, nIn, nHashType);

    txnouttype subType;
    bool fSolved = Solver(keystore, sig2, subType) && subType != TX_SCRIPTHASH;
    sig.stack = sig2.stack;
#if 0
    // Append serialized subscript whether or not it is completely signed:
    txin.scriptSig << static_cast<valtype>(subscript);
#endif
    if (!fSolved) {
      return false;
    }

    P2SH = true;
    subscript = sig2.scriptAddr; 
  }

  /* segwit */
  if (whichType == TX_WITNESS_V0_KEYHASH) {
    CScript witnessscript;
    witnessscript << OP_DUP << OP_HASH160 << ToByteVector(sig.scriptSig) << OP_EQUALVERIFY << OP_CHECKSIG;

    txnouttype subType;
    CSignature sig2(witnessscript, &txTo, nIn, nHashType);
    if (!Solver(keystore, sig2, subType)) {
      return false;
    }

    stack.push_back(cbuff(sig.scriptSig.begin(), sig.scriptSig.end()));
    stack.push_back(sig2.stack[0]);
  } else if (whichType == TX_WITNESS_V0_SCRIPTHASH) {
    CScript witnessscript = sig.scriptSig;
    CSignature sig2(witnessscript, &txTo, nIn, nHashType);

    txnouttype subType;
    if (!Solver(keystore, sig2, subType)) {
      return false;
    } 
//    solved = solved && SignStep(creator, witnessscript, result, subType, SIGVERSION_WITNESS_V0) && subType != TX_SCRIPTHASH && subType != TX_WITNESS_V0_SCRIPTHASH && subType != TX_WITNESS_V0_KEYHASH;

    stack.push_back(cbuff(sig.scriptSig.begin(), sig.scriptSig.end()));
    stack.push_back(sig2.stack[0]);
  }

  /* sig */
  CTxIn& txin = txTo.vin[nIn];
  txin.scriptSig = sig.CombineStack();

  /* segwit */
  if (stack.size() != 0 || txTo.wit.vtxinwit.size() > nIn) {
    txTo.wit.vtxinwit.resize(txTo.vin.size());
    txTo.wit.vtxinwit[nIn].scriptWitness.stack = stack;
  }

  if (P2SH) {
    txin.scriptSig << static_cast<valtype>(subscript);
  }

  // Test solution
  bool ret;
  if (0 == (nHashType & SIGHASH_HDKEY)) {
    ret= VerifyScript(txin.scriptSig, stack, fromPubKey, txTo, nIn, true, 0);
  } else {
    ret= VerifyScript(txin.scriptSig, stack, fromPubKey, txTo, nIn, true, nHashType);
  }
  if (!ret) {
    return (error(SHERR_INVAL, "SignSignature: error verifying integrity."));
  }

  return (true);
}


bool SignSignature(const CKeyStore &keystore, const CScript& fromPubKey, CTransaction& txTo, unsigned int nIn, int nHashType)
{
  CScript script = fromPubKey;
  CTxIn& txin = txTo.vin[nIn];
  vector<cbuff> stack;
  bool P2SH = false;
  bool fSolved = true;

  stack.clear();

  // Leave out the signature from the hash, since a signature can't sign itself.
  // The checksig op will also drop the signatures from its hash.
  uint256 hash = SignatureHash(script, txTo, nIn, nHashType, SIGVERSION_BASE);

  txnouttype whichType;
  if (!Solver(keystore, script, hash, nHashType, txin.scriptSig, whichType)) {
    return (error(SHERR_INVAL, "SignSignature: error solving coin address."));
  }

  CScript subscript;
  if (whichType == TX_SCRIPTHASH) {
    // Solver returns the subscript that need to be evaluated;
    // the final scriptSig is the signatures from that
    // and then the serialized subscript:
    script = subscript = txin.scriptSig;

    // Recompute txn hash using subscript in place of scriptPubKey:
    hash = SignatureHash(script, txTo, nIn, nHashType, SIGVERSION_BASE);
    fSolved = Solver(keystore, script, hash, nHashType, txin.scriptSig, whichType) && whichType != TX_SCRIPTHASH;
    P2SH = true;
#if 0
    // Append serialized subscript whether or not it is completely signed:
    txin.scriptSig << static_cast<valtype>(subscript);
    if (!fSolved) {
      return false;
    }
#endif
  }

  if (fSolved && whichType == TX_WITNESS_V0_KEYHASH) {
    CScript witnessscript;
    witnessscript << OP_DUP << OP_HASH160 << ToByteVector(txin.scriptSig) << OP_EQUALVERIFY << OP_CHECKSIG;

    CScript sig;
    txnouttype subType;
    uint256 hash2 = SignatureHash(witnessscript, txTo, nIn, nHashType, SIGVERSION_WITNESS_V0);
    fSolved = Solver(keystore, witnessscript, hash2, nHashType, sig, subType);

    cbuff st1(txin.scriptSig.begin(), txin.scriptSig.end());
    cbuff st2(sig.begin(), sig.end());
    stack.push_back(cbuff(txin.scriptSig.begin(), txin.scriptSig.end()));
    stack.push_back(cbuff(sig.begin(), sig.end()));
    txin.scriptSig = CScript();
  } else if (fSolved && whichType == TX_WITNESS_V0_SCRIPTHASH) {
    CScript witnessscript(txin.scriptSig.begin(), txin.scriptSig.end());

    CScript sig;
    txnouttype subType;
    uint256 hash2 = SignatureHash(witnessscript, txTo, nIn, nHashType, SIGVERSION_WITNESS_V0);
    fSolved = Solver(keystore, witnessscript, hash2, nHashType, sig, subType) && subType != TX_SCRIPTHASH && subType != TX_WITNESS_V0_SCRIPTHASH && subType != TX_WITNESS_V0_KEYHASH;

    stack.push_back(cbuff(txin.scriptSig.begin(), txin.scriptSig.end()));
    stack.push_back(cbuff(sig.begin(), sig.end()));
    txin.scriptSig = CScript();
  }

  if (P2SH) {
    txin.scriptSig << static_cast<valtype>(subscript);
    //result.push_back(std::vector<unsigned char>(subscript.begin(), subscript.end()));
  }

  if (stack.size() != 0 || txTo.wit.vtxinwit.size() > nIn) {
    txTo.wit.vtxinwit.resize(txTo.vin.size());
    txTo.wit.vtxinwit[nIn].scriptWitness.stack = stack;
  }

  // Test solution
  bool ret;
  if (0 == (nHashType & SIGHASH_HDKEY)) {
    ret = VerifyScript(txin.scriptSig, fromPubKey, txTo, nIn, true, 0);
  } else if (stack.size() == 0) {
    ret = VerifyScript(txin.scriptSig, fromPubKey, txTo, nIn, true, nHashType);
  } else {
    ret = VerifyScript(txin.scriptSig, stack, fromPubKey, txTo, nIn, true, nHashType, SCRIPT_VERIFY_WITNESS);
  }
  if (!ret) {
    return (error(SHERR_INVAL, "SignSignature: error verifying integrity."));
  }

  return (true);
}

bool SignSignature(const CKeyStore &keystore, const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    return SignSignature(keystore, txout.scriptPubKey, txTo, nIn, nHashType);

}

#endif




bool VerifySignature(int ifaceIndex, const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, bool fValidatePayToScriptHash, int nHashType)
{
  assert(nIn < txTo.vin.size());
  const CTxIn& txin = txTo.vin[nIn];
  if (txin.prevout.n >= txFrom.vout.size())
    return false;
  const CTxOut& txout = txFrom.vout[txin.prevout.n];

  if (txin.prevout.hash != txFrom.GetHash())
    return false;

  CTransaction *txSig = (CTransaction *)&txTo;
  CSignature sig(ifaceIndex, txSig, nIn);
  cstack_t witness;
  if (!VerifyScript(sig, txin.scriptSig, witness, txout.scriptPubKey, fValidatePayToScriptHash, 0)){
    txSig->print(ifaceIndex);
    return (false);
  }
  return (true);
}

static CScript PushAll(const vector<valtype>& values)
{
    CScript result;
    BOOST_FOREACH(const valtype& v, values)
        result << v;
    return result;
}

static CScript CombineMultisig(int ifaceIndex, CScript scriptPubKey, const CTransaction& txTo, unsigned int nIn, const vector<valtype>& vSolutions, vector<valtype>& sigs1, vector<valtype>& sigs2)
{
  // Combine all the signatures we've got:
  set<valtype> allsigs;
  BOOST_FOREACH(const valtype& v, sigs1)
  {
    if (!v.empty())
      allsigs.insert(v);
  }
  BOOST_FOREACH(const valtype& v, sigs2)
  {
    if (!v.empty())
      allsigs.insert(v);
  }

  // Build a map of pubkey -> signature by matching sigs to pubkeys:
  assert(vSolutions.size() > 1);
  unsigned int nSigsRequired = vSolutions.front()[0];
  unsigned int nPubKeys = vSolutions.size()-2;
  map<valtype, valtype> sigs;
  CTransaction *txSig = (CTransaction *)&txTo;
  CSignature sig(ifaceIndex, txSig, nIn);
  BOOST_FOREACH(const valtype& sigval, allsigs)
  {
    for (unsigned int i = 0; i < nPubKeys; i++)
    {
      const valtype& pubkey = vSolutions[i+1];
      if (sigs.count(pubkey))
        continue; // Already got a sig for this pubkey

      if (sig.CheckSig(sigval, pubkey, scriptPubKey, SIGVERSION_BASE)) {
        sigs[pubkey] = sigval;
        break;
      }
    }
  }
  // Now build a merged CScript:
  unsigned int nSigsHave = 0;
  CScript result; result << OP_0; // pop-one-too-many workaround
  for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; i++)
  {
    if (sigs.count(vSolutions[i+1]))
    {
      result << sigs[vSolutions[i+1]];
      ++nSigsHave;
    }
  }
  // Fill any missing with OP_0:
  for (unsigned int i = nSigsHave; i < nSigsRequired; i++)
    result << OP_0;

  return result;
}

#if 0
static CScript CombineSignatures(int ifaceIndex, CScript scriptPubKey, const CTransaction& txTo, unsigned int nIn, const txnouttype txType, const vector<valtype>& vSolutions, vector<valtype>& sigs1, vector<valtype>& sigs2)
{
    switch (txType)
    {
    case TX_NONSTANDARD:
        // Don't know anything about this, assume bigger one is correct:
        if (sigs1.size() >= sigs2.size())
            return PushAll(sigs1);
        return PushAll(sigs2);
    case TX_PUBKEY:
    case TX_PUBKEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.empty() || sigs1[0].empty())
            return PushAll(sigs2);
        return PushAll(sigs1);
    case TX_SCRIPTHASH:
        if (sigs1.empty() || sigs1.back().empty())
            return PushAll(sigs2);
        else if (sigs2.empty() || sigs2.back().empty())
            return PushAll(sigs1);
        else
        {
            // Recurse to combine:
            valtype spk = sigs1.back();
            CScript pubKey2(spk.begin(), spk.end());

            txnouttype txType2;
            vector<vector<unsigned char> > vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.pop_back();
            sigs2.pop_back();
            CScript result = CombineSignatures(ifaceIndex, pubKey2, txTo, nIn, txType2, vSolutions2, sigs1, sigs2);
            result << spk;
            return result;
        }
    case TX_MULTISIG:
        return CombineMultisig(ifaceIndex, scriptPubKey, txTo, nIn, vSolutions, sigs1, sigs2);
    }

    return CScript();
}

CScript CombineSignatures(CSignature& sig, CScript scriptPubKey, unsigned int nIn, const CScript& scriptSig1, const CScript& scriptSig2)
{
  const CTransaction& txTo = *sig.tx;

  txnouttype txType;
  vector<vector<unsigned char> > vSolutions;
  Solver(scriptPubKey, txType, vSolutions);

  vector<valtype> stack1;
  EvalScript(sig, stack1, scriptSig1, 0, SIGVERSION_BASE, 0);
//EvalScript(stack1, scriptSig1, CTransaction(), 0, 0, 0, 0);
  vector<valtype> stack2;
  EvalScript(sig, stack2, scriptSig2, 0, SIGVERSION_BASE, 0);
//EvalScript(stack2, scriptSig2, CTransaction(), 0, 0, 0, 0);

  return CombineSignatures(sig.ifaceIndex scriptPubKey, txTo, nIn, txType, vSolutions, stack1, stack2);
}
#endif

unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += 20;
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
{
    if (!IsPayToScriptHash())
        return GetSigOpCount(true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();
    vector<unsigned char> data;
    while (pc < scriptSig.end())
    {
        opcodetype opcode;
        if (!scriptSig.GetOp(pc, opcode, data))
            return 0;
        if (opcode > OP_16)
            return 0;
    }

    /// ... and return it's opcount:
    CScript subscript(data.begin(), data.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsPayToScriptHash() const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    return (this->size() == 23 &&
            this->at(0) == OP_HASH160 &&
            this->at(1) == 0x14 &&
            this->at(22) == OP_EQUAL);
}

bool CScript::IsWitnessProgram(int& version, std::vector<unsigned char>& program) const 
{
    if (this->size() < 4 || this->size() > 42) {
        return false;
    }
    if ((*this)[0] != OP_0 && ((*this)[0] < OP_1 || (*this)[0] > OP_16)) {
        return false;
    }
    if ((size_t)((*this)[1] + 2) == this->size()) {
        version = DecodeOP_N((opcodetype)(*this)[0]);
        program = std::vector<unsigned char>(this->begin() + 2, this->end());
        return true;
    }
    return false;
}

class CScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
public:
    CScriptVisitor(CScript *scriptin) { script = scriptin; }

    bool operator()(const CNoDestination &dest) const {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const {
        script->clear();
        *script << OP_DUP << OP_HASH160 << keyID << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CScriptID &scriptID) const {
        script->clear();
        *script << OP_HASH160 << scriptID << OP_EQUAL;
        return true;
    }
};

void CScript::SetDestination(const CTxDestination& dest)
{
    boost::apply_visitor(CScriptVisitor(this), dest);
}

void CScript::SetMultisig(int nRequired, const std::vector<CKey>& keys)
{
    this->clear();

    *this << EncodeOP_N(nRequired);
    BOOST_FOREACH(const CKey& key, keys)
        *this << key.GetPubKey();
    *this << EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
}
void CScript::SetMultisig(const std::vector<HDPrivKey>& keys)
{
  SetMultisig(keys.size(), keys);
}
void CScript::SetMultisig(int nRequired, const std::vector<HDPrivKey>& keys)
{
    this->clear();

    *this << EncodeOP_N(nRequired);
    BOOST_FOREACH(const HDPrivKey& key, keys)
        *this << key.GetPubKey();
    *this << EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
}

bool isExtOp(opcodetype opcode)
{

  if (opcode >= 0xf0 && opcode <= 0xf9)
    return (true);

  return (false);
}

CScript GetScriptForDestination(const CTxDestination& dest)
{       
    CScript script; 
            
    boost::apply_visitor(CScriptVisitor(&script), dest);
    return script;
} 
