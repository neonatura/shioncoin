
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


#ifndef __MATRIX_H__
#define __MATRIX_H__


class CTxMatrix
{
  public:
    static const int M_VALIDATE = 1;
    static const int M_SPRING = 2;

    unsigned int nType;
    unsigned int nHeight; 
    uint160 hRef;
    uint32_t vData[3][3];

    CTxMatrix()
    {
      SetNull();
    }

    CTxMatrix(const CTxMatrix& matrix)
    {
      SetNull();
      Init(matrix);
    }

    IMPLEMENT_SERIALIZE
      (
       READWRITE(this->nHeight);
       READWRITE(this->nType);
       READWRITE(this->hRef);
       READWRITE(FLATDATA(this->vData));
      )

    friend bool operator==(const CTxMatrix& a, const CTxMatrix& b)
    {
      return (
          a.nHeight == b.nHeight &&
          a.nType == b.nType &&
          a.hRef == b.hRef &&
          a.CompareCells(b)
      );
    }

    friend bool operator!=(const CTxMatrix& a, const CTxMatrix& b)
    {
      return !(a == b);
    }

    CTxMatrix operator=(const CTxMatrix &b)
    {
      Init(b);
      return (*this);
    }

    void SetNull()
    {
      nHeight = 0;
      nType = 0;
      hRef = 0;
      SetCellsNull();
    }

    void Init(const CTxMatrix& b)
    {
      nHeight = b.nHeight;
      nType = b.nType;
      hRef = b.hRef;
      InitCells(b);
    }

    unsigned int GetHeight()
    {
      return (nHeight);
    }

    unsigned int GetSize()
    {
      return (3);
    }

    unsigned int GetType()
    {
      return (nType);
    }

    void SetType(int nTypeIn)
    {
      nType = nTypeIn;
    }

    uint160 GetReferenceHash()
    {
      return (hRef);
    }

    void SetCellsNull()
    {
      int row, col;
      for (row = 0; row < 3; row++) {
        for (col = 0; col < 3; col++) {
          vData[row][col] = 0;
        }
      }
    }

    void InitCells(const CTxMatrix& b)
    {
      int row, col;
      for (row = 0; row < 3; row++) {
        for (col = 0; col < 3; col++) {
          vData[row][col] = b.vData[row][col];
        }
      }
    }

    bool CompareCells(const CTxMatrix& b) const
    {
      int row, col;
      for (row = 0; row < 3; row++) {
        for (col = 0; col < 3; col++) {
          if (vData[row][col] != b.vData[row][col])
            return (false);
        }
      }
      return (true);
    }

    unsigned int GetCell(int row, int col)
    {
      if (row < 0 || row >= 3 ||
          col < 0 || col >= 3)
        return (0);
      return (vData[row][col]);
    }

    void SetCell(int row, int col, unsigned int val)
    {
      if (row < 0 || row >= 3 ||
          col < 0 || col >= 3)
        return;
      vData[row][col] = val;
    }

    void AddCell(int row, int col, unsigned int val)
    {
      if (row < 0 || row >= 3 ||
          col < 0 || col >= 3)
        return;
      vData[row][col] += val;
    }

    void SubCell(int row, int col, unsigned int val)
    {
      if (row < 0 || row >= 3 ||
          col < 0 || col >= 3)
        return;
      vData[row][col] -= val;
    }

   std::string ToString();

    Object ToValue();

    const uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    /** Add in a block height and hash to the matrix. */
    void Append(int heightIn, uint256 hash);

    /** Retract a block hash & height from matrix. */
    void Retract(int heightIn, uint256 hash);
};


extern CTxMatrix matrixValidate;

class CBlock;

bool BlockGenerateValidateMatrix(CIface *iface, CTransaction& tx, int64& nReward);

bool BlockGenerateSpringMatrix(CIface *iface, CTransaction& tx, int64& nReward);

bool BlockAcceptValidateMatrix(CIface *iface, CTransaction& tx, bool& fCheck);

bool BlockAcceptSpringMatrix(CIface *iface, CTransaction& tx, bool& fCheck);

void BlockRetractSpringMatrix(CIface *iface, CTransaction& tx, CBlockIndex *pindex);

#ifdef __cplusplus
extern "C" {
#endif
int validate_render_fractal(char *img_path, double zoom, double span, double x_of, double y_of);
#ifdef __cplusplus
}
#endif



#endif /* ndef __MATRIX_H__ */


