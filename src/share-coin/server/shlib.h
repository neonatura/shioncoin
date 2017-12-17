


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

#ifndef __SHLIB_H__
#define __SHLIB_H__

#include "share.h"
#include "serialize.h"


typedef shesig_t SHCert;
typedef shlic_t SHLicense;
typedef shref_t SHAlias;
typedef shasset_t SHAsset;

class SHPeer
{
  public:
    shpeer_t peer;

    mutable shkey_t pkey;

    SHPeer()
    {
      SetNull();
      memcpy(&peer, ashpeer(), sizeof(peer));
    }
    SHPeer(shpeer_t *peerIn)
    {
      memcpy(&peer, peerIn, sizeof(peer));
    }
    IMPLEMENT_SERIALIZE (
      READWRITE(FLATDATA(peer));
    )
    void SetNull()
    {
      memset(&peer, 0, sizeof(peer));
    }
    shpeer_t *Get()
    {
      return (&peer);
    }
    shkey_t *GetKey()
    {
      memcpy(&pkey, shpeer_kpriv(&peer), sizeof(pkey));
      return (&pkey);
    }
    friend bool operator==(const SHPeer &a, const SHPeer &b)
    {
      return (
          0 == memcmp(&a.peer, &b.peer, sizeof(shpeer_t))
        );
    }
};

class SHSig
{
  public:
    shsig_t sig;

    SHSig()
    {
      SetNull();
    }
    SHSig(shsig_t *sigIn)
    {
      memcpy(&sig, sigIn, sizeof(sig));
    }
    IMPLEMENT_SERIALIZE (
      READWRITE(FLATDATA(sig));
    )
    void SetNull()
    {
      memset(&sig, 0, sizeof(sig));
    }
    friend bool operator==(const SHSig &a, const SHSig &b)
    {
      return (
          0 == memcmp(&a.sig, &b.sig, sizeof(shsig_t))
        );
    }
};

inline std::vector<unsigned char> vchFromString(const std::string &str) {
  unsigned char *strbeg = (unsigned char*) str.c_str();
  return std::vector<unsigned char>(strbeg, strbeg + str.size());
}   

/**
 * Notify the "shared" daemon of a realized transaction.
 */
inline int shnet_inform(CIface *iface, int tx_op, void *data, size_t data_len)
{
  shbuf_t *buff;
  shpeer_t *peer;
  uint32_t mode;
  int qid;
  int err;

  mode = (uint32_t)tx_op;
//  peer = shpeer_init(iface->name, NULL);
  buff = shbuf_init();
  shbuf_cat(buff, &mode, sizeof(uint32_t));
//  shbuf_cat(buff, peer, sizeof(shpeer_t));
  shbuf_cat(buff, data, data_len);
  qid = shmsgget(NULL);
  err = shmsg_write(qid, buff, NULL);
  shbuf_free(&buff);
//  shpeer_free(&peer);
  if (err)
    return (err);

  return (0);
}

#endif /* ndef __SHLIB_H__ */
