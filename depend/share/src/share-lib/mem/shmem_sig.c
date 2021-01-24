
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura 
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

#include "share.h"


int shsig_shr_gen(shsig_t *pub_sig, unsigned char data, size_t data_len)
{
  shkey_t *key;

  if (!data || !data_len) {
    /* generate random public key */
    key = shkey_uniq();
  } else {
    /* generate key from user-supplied content */
    key = shkey_bin(data, data_len);
  }
  if (!key)
    return (SHERR_NOMEM);

  memcpy(&pub_sig->sig_key, key, sizeof(shkey_t));
//  pub_sig->sig_key.alg = SHKEY_ALG_SHR;
  shkey_free(&key);

  /* set birth and expiration time-stamps */
  pub_sig->sig_stamp = shtime_adj(shtime(), -1);
  pub_sig->sig_expire =
    shtime_adj(shtime(), SHARE_DEFAULT_EXPIRE_TIME);

  return (0);
}

int shsig_shr_sign(shsig_t *priv_sig, shsig_t *pub_sig, unsigned char *data, size_t data_len)
{
  shkey_t *key;
  unsigned char *enc_data;
  size_t enc_len;
  int err;

  err = shencode(data, data_len, &enc_data, &enc_len, &pub_sig->sig_key);
  if (err)
    return (err);

  key = shkey_bin(enc_data, enc_len);
  free(enc_data);
  if (!key)
    return (SHERR_NOMEM);

  memcpy(&priv_sig->sig_key, key, sizeof(shkey_t));
  shkey_free(&key);

//  priv_sig->sig_key.alg = SHKEY_ALG_SHR;
  priv_sig->sig_stamp = shtime();
  priv_sig->sig_expire = pub_sig->sig_expire;

  return (0);
}


int shsig_shr_verify(shsig_t *priv_sig, shsig_t *pub_sig, unsigned char *data, size_t data_len)
{
  shkey_t *key;
  unsigned char *enc_data;
  size_t enc_len;
  int err;

  err = shencode((char *)data, data_len, &enc_data, &enc_len, &pub_sig->sig_key);
  if (err)
    return (err);

  key = shkey_bin(enc_data, enc_len);
  free(enc_data);
  if (!key)
    return (SHERR_NOMEM);

//  key->alg = SHKEY_ALG_SHR;
  if (!shkey_cmp(key, &priv_sig->sig_key)) {
    /* encrypted key is not validated. */
    shkey_free(&key);
    return (SHERR_KEYREJECTED);
  }
  shkey_free(&key);

  return (0);
}

_TEST(shsig_shr)
{
  shkey_t *msg_key;
  shsig_t pub_sig;
  shsig_t priv_sig;
  msg_key = shkey_uniq();

  memset(&pub_sig, 0, sizeof(pub_sig));
  memset(&priv_sig, 0, sizeof(priv_sig));

  _TRUE(0 == shsig_shr_gen(&pub_sig, NULL, 0));
  _TRUE(0 == shsig_shr_sign(&priv_sig, &pub_sig, (unsigned char *)msg_key, sizeof(shkey_t)));
  _TRUE(0 == shsig_shr_verify(&priv_sig, &pub_sig, (unsigned char *)msg_key, sizeof(shkey_t)));

  shkey_free(&msg_key);
}


