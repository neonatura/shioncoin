
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
#include "block.h"
#include "script.h"
#include "txsignature.h"
#include "wallet.h"


typedef vector<unsigned char> valtype;

template <typename T>
std::vector<unsigned char> ToByteVector(const T& in)
{       
    return std::vector<unsigned char>(in.begin(), in.end());
}   

static uint256 GetPrevoutHash(const CTransaction& txTo) {
  CHashWriter ss(SER_GETHASH, 0);
  for (unsigned int n = 0; n < txTo.vin.size(); n++) {
    ss << txTo.vin[n].prevout;
  }
  return ss.GetHash();
}

static uint256 GetSequenceHash(const CTransaction& txTo) {
  CHashWriter ss(SER_GETHASH, 0);
  for (unsigned int n = 0; n < txTo.vin.size(); n++) {
    ss << txTo.vin[n].nSequence;
  }
  return ss.GetHash();
}

static uint256 GetOutputsHash(const CTransaction& txTo) {
  CHashWriter ss(SER_GETHASH, 0);
  for (unsigned int n = 0; n < txTo.vout.size(); n++) {
    ss << txTo.vout[n];
  }
  return ss.GetHash();
}



static uint256 witness_v0_SignatureHash(CScript scriptCode, CTransaction& txTo, unsigned int nIn, int nHashType, int64 nAmount)
{
  uint256 hashPrevouts;
  uint256 hashSequence;
  uint256 hashOutputs;

  if (!(nHashType & SIGHASH_ANYONECANPAY)) {
    hashPrevouts = GetPrevoutHash(txTo);
  }

  if (!(nHashType & SIGHASH_ANYONECANPAY) && (nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
    hashSequence = GetSequenceHash(txTo);
  }

  if ((nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
    hashOutputs = GetOutputsHash(txTo);
  } else if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn < txTo.vout.size()) {
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTo.vout[nIn];
    hashOutputs = ss.GetHash();
  }

  CHashWriter ss(SER_GETHASH, 0);
  // Version
  ss << txTo.nFlag;
  // Input prevouts/nSequence (none/all, depending on flags)
  ss << hashPrevouts;
  ss << hashSequence;
  // The input being signed (replacing the scriptSig with scriptCode + amount)
  // The prevout may already be contained in hashPrevout, and the nSequence
  // may already be contain in hashSequence.
  ss << txTo.vin[nIn].prevout;
  ss << static_cast<cbuff&>(scriptCode);
  ss << nAmount;
  ss << txTo.vin[nIn].nSequence;
  // Outputs (none/one/all, depending on flags)
  ss << hashOutputs;
  // Locktime
  ss << txTo.nLockTime;
  // Sighash type
  ss << nHashType;

  return ss.GetHash();
}

static uint256 base_SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
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
  CDataStream ss(SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
  ss.reserve(4096);
  ss << txTmp << nHashType;
  return Hash(ss.begin(), ss.end());
}

bool CSignature::SignatureHash(CScript scriptCode, int sigver, uint256& hashRet)
{
  unsigned int nIn = nTxIn;

  if (sigver == SIGVERSION_WITNESS_V0) {
    CWallet *wallet = GetWallet(ifaceIndex); 
    CTxOut out;

    if (!wallet->FillInputs(*tx, mapInputs)) {
fprintf(stderr, "DEBUG: CSignature.SignatureHash: error filling inputs\n");
      return (false);
    }

    const CTxIn& in = tx->vin[nIn];
    if (!tx->GetOutputFor(in, mapInputs, out)) {
fprintf(stderr, "DEBUG: CSignature.SignatureHash: error obtaining coin output\n");
      return (false);
}

    hashRet = witness_v0_SignatureHash(scriptCode, *tx, nIn, nHashType, out.nValue);
    return (true);
  }

  if (nIn >= tx->vin.size()) {
    return (error(SHERR_INVAL, "SignatureHash: nIn out of range"));
  }

  hashRet = base_SignatureHash(scriptCode, *tx, nIn, nHashType);
  return (true);
}


bool CSignature::CheckSig(cbuff vchSig, cbuff vchPubKey, CScript scriptCode, int sigver)
{
  unsigned int nIn = nTxIn;

  // Hash type is one byte tacked on to the end of the signature
  if (vchSig.empty()) {
    return (error(SHERR_INVAL, "CSignature.CheckSig: transaction signature is empty."));
  }
#if 0
  if (nHashType == 0)
    nHashType = vchSig.back();
  else if (nHashType != vchSig.back()) {
    return false;
  }
#endif
  cbuff vch(vchSig);
  nHashType = vch.back();
  vch.pop_back();

  uint256 sighash;
  if (!SignatureHash(scriptCode, sigver, sighash)) {
    return (error(SHERR_ACCESS, "CSignature.CheckSig: failure generating signature hash: \"%s\".", scriptCode.ToString().c_str()));
  }

  if (nHashType & SIGHASH_HDKEY) {
    HDPubKey pubkey(vchPubKey);
    if (!pubkey.Verify(sighash, vch)) {
      return false;
    }
  } else {
    CKey key;
    if (!key.SetPubKey(vchPubKey))
      return false;

    if (!key.Verify(sighash, vch)) {
fprintf(stderr, "DEBUG: CheckSig: !key.Verify: scriptCode(\"%s\") sighash(\"%s\") vchSig(\"%s\") nHashType(%d) sigver(%d)\n", scriptCode.ToString().c_str(), sighash.GetHex().c_str(), HexStr(vchSig.begin(), vchSig.end()).c_str(), nHashType, sigver);
      return (error(SHERR_ACCESS, "CSignature.CheckSig: signature verification failure: \"%s\".", HexStr(vchSig.begin(), vchSig.end()).c_str()));
    }
  }

  return true;
}

static CScript PushAll(const vector<valtype>& values)
{
  CScript result;

  BOOST_FOREACH(const valtype& v, values) {
    if (v.size() == 0) {
      result << OP_0;
    } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
      result << CScript::EncodeOP_N(v[0]);
    } else {
      result << v;
    }
  }

  return result;
}

bool CSignature::SignSignature(const CScript& fromPubKey)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  CScript script = fromPubKey;
  unsigned int nIn = nTxIn;
  CTxIn& txin = tx->vin[nIn];
  cstack_t stack;
  cstack_t result;
  bool P2SH = false;
  bool fSolved = true;


  stack.clear();

#if 0
  // Leave out the signature from the hash, since a signature can't sign itself.
  // The checksig op will also drop the signatures from its hash.
  uint256 hash;
  if (!SignatureHash(script, SIGVERSION_BASE, hash)) {
fprintf(stderr, "DEBUG: SignSignature: SignatureHash error: fromPubKey(\"%s\")\n", fromPubKey.ToString().c_str());
    return false;
  }
//fprintf(stderr, "DEBUG: CSignature.SignSignature: sighash \"%s\"\n", hash.GetHex().c_str());

  txnouttype whichType;
  if (!Solver(*wallet, script, hash, nHashType, txin.scriptSig, whichType)) {
fprintf(stderr, "DEBUG: SignSignature: Solver error: fromPubKey(\"%s\")\n", fromPubKey.ToString().c_str());
    return (error(SHERR_INVAL, "SignSignature: error solving coin address."));
  }
fprintf(stderr, "DEBUG: SignSignature: success: fromPubKey(\"%s\") whichType(%d) scriptSig(\"%s\")\n", fromPubKey.ToString().c_str(), whichType, txin.scriptSig.ToString().c_str()); 
CScript scriptSigCopy(txin.scriptSig);
#endif

  /* primary signature */
  txnouttype whichType;
  fSolved = SignAddress(script, result, whichType, SIGVERSION_BASE);

  CScript subscript;
  if (whichType == TX_SCRIPTHASH) {
    // Solver returns the subscript that need to be evaluated;
    // the final scriptSig is the signatures from that
    // and then the serialized subscript:
    //script = subscript = txin.scriptSig;
    script = subscript = CScript(result[0].begin(), result[0].end());

#if 0
    // Recompute txn hash using subscript in place of scriptPubKey:
    if (!SignatureHash(script, SIGVERSION_BASE, hash))
      return false;

cbuff vchHash(hash.begin(), hash.end());
fprintf(stderr, "DEBUG: SIGN: TX_SCRIPTHASH: hash \"%s\" [u160 %s]\n", hash.GetHex().c_str(), Hash160(vchHash).GetHex().c_str());

    fSolved = Solver(*wallet, script, hash, nHashType, txin.scriptSig, whichType) && whichType != TX_SCRIPTHASH;
#endif

    fSolved = fSolved && SignAddress(script, result, whichType, SIGVERSION_BASE) && whichType != TX_SCRIPTHASH;

    P2SH = true;

  }

  if (whichType == TX_WITNESS_V0_KEYHASH) {
    cbuff vchSig = ToByteVector(result[0]);
    CScript witnessscript;
    witnessscript << OP_DUP << OP_HASH160 << ToByteVector(result[0]) << OP_EQUALVERIFY << OP_CHECKSIG;

    txnouttype subType;
    fSolved = fSolved && SignAddress(witnessscript, result, subType, SIGVERSION_WITNESS_V0);

    cbuff st2(result[0].begin(), result[0].end());

    stack = result; /* signature */

#if 0
    if (stack.size() < 2) { 
      CWallet *wallet = GetWallet(ifaceIndex); 
      CPubKey tKeyPub;
      CKeyID id;
      memcpy(&id, &vchSig[0], 20);
      wallet->GetPubKey(id, tKeyPub);
      cbuff tKey = tKeyPub.Raw();
      stack.push_back(tKey);
fprintf(stderr, "DEBUG: SIgnSignature: appended witness pub-key \"%s\"\n", HexStr(tKey).c_str());
    }
#endif

    txin.scriptSig = CScript();
    result.clear();
  } else if (whichType == TX_WITNESS_V0_SCRIPTHASH) {
    CScript witnessscript(result[0].begin(), result[0].end());

    txnouttype subType;
    fSolved = fSolved && SignAddress(witnessscript, result, subType, SIGVERSION_WITNESS_V0) && subType != TX_SCRIPTHASH && subType != TX_WITNESS_V0_SCRIPTHASH && subType != TX_WITNESS_V0_KEYHASH; 
    result.push_back(std::vector<unsigned char>(witnessscript.begin(), witnessscript.end()));
    stack = result;

    txin.scriptSig = CScript();
    result.clear();
  }

  if (P2SH) {
    result.push_back(std::vector<unsigned char>(subscript.begin(), subscript.end()));
  }

  /* fill in "scriptSig" portion of transaction input. */
  txin.scriptSig = PushAll(result); 

  /* fill in "witness" portion of transaction input. */
  if (stack.size() != 0 || tx->wit.vtxinwit.size() > nIn) {
    tx->wit.vtxinwit.resize(tx->vin.size());
    tx->wit.vtxinwit[nIn].scriptWitness.stack = stack;
//fprintf(stderr, "DEBUG: SignSignature: [nIn %d] stack-size %d: %s\n", nIn, stack.size(), tx->ToString(ifaceIndex).c_str()); 
  }
  if (!fSolved) {
    return (error(SHERR_INVAL, "SignSignature: error generating signature."));
  }

  bool ret = false;
  {
    CSignature t_sig(ifaceIndex, tx, nIn, /* nHashType = */ 0);
    ret = VerifyScript(t_sig, txin.scriptSig, stack, fromPubKey,
        true, (stack.size() == 0) ? 0 : SCRIPT_VERIFY_WITNESS);
  }
  if (!ret) {
    return (error(SHERR_INVAL, "SignSignature: error verifying integrity."));
  }

  return (true);
}

bool CSignature::SignSignature(const CTransaction& txFrom)
{
  unsigned int nIn = nTxIn;

  if (nIn >= tx->vin.size()) {
    return (error(SHERR_INVAL, "CSignature.SignSignature: nIn(%d) < tx->vin.size(%d)", nIn, tx->vin.size()));
  }

  CTxIn& txin = tx->vin[nIn];
  if (txin.prevout.n >= txFrom.vout.size()) {
    return (error(SHERR_INVAL, "SignSignature: tx->prevout.n < txfrom.vout.size"));
    return false;
  }

  /* retain for later */
  const uint256& hash = txFrom.GetHash();
  mapInputs[hash] = txFrom;  

  const CTxOut& txout = txFrom.vout[txin.prevout.n];
  if (!SignSignature(txout.scriptPubKey)) {
    return (error(SHERR_INVAL, "CSignature.SignSignature: error signing script address: \"%s\".", txout.scriptPubKey.ToString().c_str()));
  }

  return (true);
}

bool CSignature::CreateSignature(cbuff& vchSig, const CKeyID& address, const CScript& scriptCode, int sigversion)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  const CKeyStore& keystore = *wallet;

  uint256 hash;
  if (!SignatureHash(scriptCode, sigversion, hash)) {
    return (error(SHERR_INVAL, "CreateSignature: error generating signature hash for script \"%s\" [sigver %d].", scriptCode.ToString().c_str(), sigversion));
  }

  if (!(nHashType & SIGHASH_HDKEY)) {
    CKey key;
    if (!keystore.GetKey(address, key))
      return (error(SHERR_ACCESS, "CreateSignature: error obtaining private key."));
    // Signing with uncompressed keys is disabled in witness scripts
    if (sigversion == SIGVERSION_WITNESS_V0 && !key.IsCompressed()) {
      return (error(SHERR_INVAL, "CreateSignature: generating witness program signature unsupportd for non-compressed key: script \"%s\" [sigver %d].", scriptCode.ToString().c_str(), sigversion));
      return false;
    }

    if (!key.Sign(hash, vchSig))
      return (error(SHERR_ACCESS, "CreateSignature: error signing signature."));
  } else /* HDKEY */ {
    HDPrivKey key;
    if (!keystore.GetKey(address, key))
      return false;
    // Signing with uncompressed keys is disabled in witness scripts
    if (sigversion == SIGVERSION_WITNESS_V0 && !key.IsCompressed())
      return false;

    if (!key.Sign(hash, vchSig))
      return false;
  }

  vchSig.push_back((unsigned char)nHashType);

  return true;
}

static bool Sign1(CSignature *sig, const CKeyID& address, const CScript& scriptCode, cstack_t& ret, int sigversion)
{
  vector<unsigned char> vchSig;

  if (!sig->CreateSignature(vchSig, address, scriptCode, sigversion)) {
    return (error(SHERR_INVAL, "Sign1: error creating signature"));
  }

  ret.push_back(vchSig);
  return true;
}

static bool SignN(CSignature *sig, const vector<valtype>& multisigdata, const CScript& scriptCode, std::vector<valtype>& ret, int sigversion)
{
  int nSigned = 0;
  int nRequired = multisigdata.front()[0];
  for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++)
  {
    const valtype& pubkey = multisigdata[i];
    CKeyID keyID = CPubKey(pubkey).GetID();
    if (Sign1(sig, keyID, scriptCode, ret, sigversion))
      ++nSigned;
  }
  return nSigned==nRequired;
}


bool CSignature::SignAddress(const CScript& scriptPubKey, cstack_t& ret, txnouttype& whichTypeRet, int sigversion)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  const CKeyStore& keystore = *wallet;

  ret.clear();

  vector<valtype> vSolutions;
  if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
    return (error(SHERR_INVAL, "SignAddress: failure signing \"%s\"\n", scriptPubKey.ToString().c_str()));

  CKeyID keyID;
  switch (whichTypeRet) {
    case TX_PUBKEY:
      if (!(nHashType & SIGHASH_HDKEY)) {
        keyID = CPubKey(vSolutions[0]).GetID();
      } else {
        keyID = HDPubKey(vSolutions[0]).GetID();
      }
      return Sign1(this, keyID, scriptPubKey, ret, sigversion);

    case TX_PUBKEYHASH:
      keyID = CKeyID(uint160(vSolutions[0]));
      if (!Sign1(this, keyID, scriptPubKey, ret, sigversion))
        return false;

      if (!(nHashType & SIGHASH_HDKEY)) {
        CPubKey key;
        if (!keystore.GetPubKey(keyID, key)) {
          return (error(SHERR_INVAL, "SignAddress: unknown key-id \"%s\" coin address\n", HexStr(keyID.begin(), keyID.end()).c_str()));
        }

        ret.push_back(key.Raw());
      } else /* HDKEY */ {
        HDPrivKey key;
        if (!keystore.GetKey(keyID, key))
          return false;
        ret.push_back(key.GetPubKey().Raw());
      }
      return true;

    case TX_SCRIPTHASH:
      {
        CScript scriptSigRet;
        if (!keystore.GetCScript(uint160(vSolutions[0]), scriptSigRet))
          return (false);
        ret.push_back(cbuff(scriptSigRet.begin(), scriptSigRet.end()));
        return (true);
      }
      break;

    case TX_MULTISIG:
      {
//        scriptSigRet << OP_0; // workaround CHECKMULTISIG bug
        ret.push_back(valtype());
        return (SignN(this, vSolutions, scriptPubKey, ret, sigversion));
      }
      break;

    case TX_WITNESS_V0_KEYHASH:
      ret.push_back(vSolutions[0]);
      return (true);

    case TX_WITNESS_V0_SCRIPTHASH:
      CScript scriptSigRet;
      const cbuff vch(vSolutions[0].begin(), vSolutions[0].end());
      cbuff vchHash;
      uint160 hash160;

      RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
      memcpy(&hash160, &vchHash[0], sizeof(hash160));

      if (!keystore.GetCScript(hash160, scriptSigRet))
        return (error(SHERR_NOENT, "SignAddress: unknown script \"%s\".", hash160.GetHex().c_str()));

      ret.push_back(cbuff(scriptSigRet.begin(), scriptSigRet.end()));
      return (true);
  }

  return (false);
}



