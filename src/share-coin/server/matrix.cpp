
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
#include "wallet.h"
#include "spring.h"
#include "fractal.h"


#if 0
void CTxMatrix::ClearCells()
{
  int row, col;

  for (row = 0; row < nSize; row++) {
    for (col = 0; col < nSize; col++) {
      SetCell(row, col, 0);
    }
  }
}
#endif

CTxMatrix matrixValidate;


void CTxMatrix::Append(int heightIn, uint256 hash)
{
  nHeight = heightIn;

  int idx = (nHeight / 27) % 9;
  int row = (idx / 3) % 3;
  int col = idx % 3;
  unsigned int crc = (unsigned int)shcrc(hash.GetRaw(), 32);
  AddCell(row, col, crc);
}

void CTxMatrix::Retract(int heightIn, uint256 hash)
{

  if (heightIn > nHeight)
    return;

  nHeight = heightIn - 27;

  int idx = (heightIn / 27) % 9;
  int row = (idx / 3) % 3;
  int col = idx % 3;
  SubCell(row, col, (unsigned int)shcrc(hash.GetRaw(), 32));
}



/* 'zero transactions' penalty. */
bool BlockGenerateValidateMatrix(CIface *iface, CTransaction& tx, int64& nReward)
{
  int ifaceIndex = GetCoinIndex(iface);

  int64 nFee = MAX(0, MIN(COIN, nReward - (int64)iface->min_tx_fee));
  if (nFee < iface->min_tx_fee)
    return (false); /* reward too small */

  CTxMatrix *m = tx.GenerateValidateMatrix(ifaceIndex);
  if (!m)
    return (false); /* not applicable */

  /* define tx op attributes */
  uint160 hashMatrix = m->GetHash();
  CScript scriptMatrix;
  scriptMatrix << OP_EXT_VALIDATE << CScript::EncodeOP_N(OP_MATRIX) << OP_HASH160 << hashMatrix << OP_2DROP << OP_RETURN;
  tx.vout.push_back(CTxOut(nFee, scriptMatrix));

  /* deduct from reward. */
  nReward -= nFee;

  Debug("BlockGenerateValidateMatrix: (matrix hash %s) proposed: %s\n", hashMatrix.GetHex().c_str(), m->ToString().c_str());

  return (true);
}

bool BlockAcceptValidateMatrix(CIface *iface, CTransaction& tx, bool& fCheck)
{
  int ifaceIndex = GetCoinIndex(iface);
  CTxMatrix matrix;
  bool fMatrix = false;
  int mode;

  if (VerifyMatrixTx(tx, mode) && mode == OP_EXT_VALIDATE) {
    CBlockIndex *pindex = GetBestBlockIndex(ifaceIndex);
    CTxMatrix& matrix = *tx.GetMatrix();
    if (matrix.GetType() == CTxMatrix::M_VALIDATE &&
        matrix.GetHeight() > matrixValidate.GetHeight()) {
      if (!tx.VerifyValidateMatrix(matrix, pindex)) {
        fCheck = false;
        error(SHERR_INVAL, "BlockAcceptValidateMatrix: invalid matrix received: %s", matrix.ToString().c_str());
      } else {
        fCheck = true;
        /* apply new hash to matrix */
        matrixValidate = matrix;
        Debug("BlockAcceptValidateMatrix: Validate verify success: %s\n", matrixValidate.ToString().c_str());
      }
      return (true); /* matrix was found */
    }
  }

  return (false); /* no matrix was present */
}


#if 0
void LargeMatrix::compress(CTxMatrix& matrixIn)
{
  int row, col;
  int n_row, n_col;
  double deg;

  matrixIn.ClearCells();

  deg = nSize / matrixIn.nSize; 
  for (row = 0; row < nSize; row++) {
    for (col = 0; col < nSize; col++) {
      n_row = (row / deg); 
      n_col = (col / deg); 
      matrixIn.AddCell(n_row, n_col, GetCell(row, col)); 
    }
  }

}
#endif

/* NOT IMPLEMENTED */
shgeo_t *GetMatrixOrigin(CTransaction& tx)
{
  static shgeo_t geo;
memset(&geo, 0, sizeof(geo));
return (&geo);
}

bool BlockGenerateSpringMatrix(CIface *iface, CTransaction& tx, int64& nReward)
{
  int ifaceIndex = GetCoinIndex(iface);

  int64 nFee = MAX(0, MIN(COIN, nReward - iface->min_tx_fee));
  if (nFee < iface->min_tx_fee)
    return (false); /* reward too small */


  CIdent ident;
  CTxMatrix *m = tx.GenerateSpringMatrix(ifaceIndex, ident);
  if (!m)
    return (false); /* not applicable */

  uint160 hashMatrix = m->GetHash();
  int64 min_tx = (int64)iface->min_tx_fee;

  CScript scriptPubKeyOrig;
  CCoinAddr addr(stringFromVch(ident.vAddr));
  scriptPubKeyOrig.SetDestination(addr.Get());

  CScript scriptMatrix;
  scriptMatrix << OP_EXT_PAY << CScript::EncodeOP_N(OP_MATRIX) << OP_HASH160 << hashMatrix << OP_2DROP;
  scriptMatrix += scriptPubKeyOrig;

  tx.vout.push_back(CTxOut(nFee, scriptMatrix));

  /* deduct from reward. */
  nReward -= nFee;

  Debug("BlockGenerateSpringMatrix: (matrix hash %s) proposed: %s\n", hashMatrix.GetHex().c_str(), m->ToString().c_str());

  return (true);
}

bool BlockAcceptSpringMatrix(CIface *iface, CTransaction& tx, bool& fCheck)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  bool fMatrix = false;
  shnum_t lat, lon;
  int mode = -1;;

  lat = lon = 0;
  if (VerifyMatrixTx(tx, mode) && mode == OP_EXT_PAY) {
    CBlockIndex *pindex = GetBestBlockIndex(ifaceIndex);
    CTxMatrix& matrix = *tx.GetMatrix();
    if (matrix.GetType() == CTxMatrix::M_SPRING) {
      if (!tx.VerifySpringMatrix(ifaceIndex, matrix, &lat, &lon)) {
        fCheck = false;
        Debug("BlockAcceptSpringMatrix: Spring verify failure: (new %s) lat(%f) lon(%f)\n", matrix.ToString().c_str(), lat, lon);
      } else {
        fCheck = true;
        /* remove claim location from spring matrix */
        spring_loc_claim(lat, lon);
        /* erase pending ident tx */
        wallet->mapIdent.erase(matrix.hRef);
        Debug("BlockAcceptSpringMatrix: Spring verify success: (new %s) lat(%f) lon(%f)\n", matrix.ToString().c_str(), lat, lon);
      }
      return (true); /* matrix was found */
    }
  }

  return (false); /* no matrix was present */
}

CTxMatrix *CTransaction::GenerateSpringMatrix(int ifaceIndex, CIdent& ident)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  shnum_t lat, lon;
  int height;

  if (!iface || !iface->enabled)
    return (NULL);

  if (nFlag & CTransaction::TXF_MATRIX)
    return (NULL);

  CWallet *wallet = GetWallet(iface);
  if (!wallet)
    return (NULL);

  if (wallet->mapIdent.size() == 0)
    return (NULL);

  const uint160& hashIdent = wallet->mapIdent.begin()->first;

  CTransaction tx;
  bool hasIdent = GetTxOfIdent(iface, hashIdent, tx);
  if (!hasIdent) {
    wallet->mapIdent.erase(hashIdent); /* invalido */
    return (NULL);
  }
  ident = (CIdent&)tx.certificate;

  shgeo_loc(&ident.geo, &lat, &lon, NULL);
  if (!is_spring_loc(lat, lon)) {
    wallet->mapIdent.erase(hashIdent); /* invalido */
    return (NULL);
  }

  nFlag |= CTransaction::TXF_MATRIX;

  matrix = CTxMatrix();
  spring_matrix_compress(matrix.vData);
  matrix.nType = CTxMatrix::M_SPRING;
  matrix.nHeight = GetBestHeight(iface) + 1; 
  matrix.hRef = hashIdent;
 
  return (&matrix);
}

bool CTransaction::VerifySpringMatrix(int ifaceIndex, const CTxMatrix& matrix, shnum_t *lat_p, shnum_t *lon_p)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  
  CTransaction tx;
  if (!GetTxOfIdent(iface, matrix.hRef, tx))
    return error(SHERR_INVAL, "VerifySpringMatrix: invalid ident tx.");
  CIdent& ident = (CIdent&)tx.certificate;

  shgeo_loc(&ident.geo, lat_p, lon_p, NULL);
  if (!is_spring_loc(*lat_p, *lon_p))
    return error(SHERR_INVAL, "VerifySpringMatrix: invalid spring location.");

  CTxMatrix cmp_matrix;
  spring_matrix_compress(cmp_matrix.vData);
  cmp_matrix.nType = matrix.nType;
  cmp_matrix.nHeight = matrix.nHeight; 
  cmp_matrix.hRef = matrix.hRef;

  bool ret = (cmp_matrix == matrix);
  if (!ret)
    return error(SHERR_INVAL, "VerifySpringMatrix: matrix integrity failure.");

  return (true);
}


void BlockRetractSpringMatrix(CIface *iface, CTransaction& tx, CBlockIndex *pindex)
{
//  int ifaceIndex = GetCoinIndex(iface);
  const CTxMatrix& matrix = tx.matrix;

  if (pindex->nHeight != matrix.nHeight)
    return;

#if 0
  matrixIn->Retract(matrix.nHeight, tx.GetHash());
#endif

  CTransaction id_tx;
  if (!GetTxOfIdent(iface, matrix.hRef, id_tx))
    return;

#if 0
  if (id_tx.IsInMempool(ifaceIndex))
    return;
#endif

  /* re-establish location bits in spring matrix. */
  CIdent& ident = (CIdent&)id_tx.certificate;
  shnum_t lat, lon;
  shgeo_loc(&ident.geo, &lat, &lon, NULL);
  spring_loc_set(lat, lon);
}


Object CTxMatrix::ToValue()
{
  Object obj;
  char buf[2048];
  int row;
  int col;

  obj.push_back(Pair("hash", GetHash().GetHex()));
  obj.push_back(Pair("type", (int)nType));
  obj.push_back(Pair("ref", hRef.GetHex()));
  if (nHeight != 0)
    obj.push_back(Pair("height", (int)nHeight));

  memset(buf, 0, sizeof(buf));
  for (row = 0; row < 3; row++) {
    if (row != 0) strcat(buf, " ");
    strcat(buf, "(");
    for (col = 0; col < 3; col++) {
      if (col != 0) strcat(buf, " "); 
      sprintf(buf+strlen(buf), "%-8.8x", GetCell(row, col));
    }
    strcat(buf, ")");
  }
  string strMatrix(buf);
  obj.push_back(Pair("data", strMatrix));

  return obj;
}

std::string CTxMatrix::ToString()
{
  return (write_string(Value(ToValue()), false));
}



#ifdef __cplusplus
extern "C" {
#endif
int validate_render_fractal(char *img_path, double zoom, double span, double x_of, double y_of)
{
  CTxMatrix *matrix;
  uint32_t m_seed;
  double seed;
  int y, x;

  m_seed = 0;
  for (y = 0; y < 3; y++) {
    for (x = 0; x < 3; x++) {
      m_seed += matrixValidate.vData[y][x];
    }
  }
  seed = (double)m_seed;

  return (fractal_render(img_path, seed, zoom, span, x_of, y_of));
}
#ifdef __cplusplus
}
#endif



