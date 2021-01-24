

/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura 
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

#define __MEM__SHSYS_PAM_C__

#include "share.h"

#ifdef HAVE_GETPWNAM
#include <pwd.h>
#endif
#ifdef HAVE_GETSPNAM
#include <shadow.h>
#endif



static char itoa64[64] =    /* 0 ... 63 => ascii - 64 */
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static int _auth_alg_default = SHALG_SHKEY;

int shpam_auth_alg_default(int scope)
{
  int alg;
  
  alg = _auth_alg_default;
  switch (scope) {
    case SHAUTH_SCOPE_LOCAL: 
      return (SHALG_SHCR224);
    case SHAUTH_SCOPE_REMOTE: 
      return (SHALG_ECDSA384R);
    case SHAUTH_SCOPE_2FA:
      return (SHALG_SHA1);
  }

  return (alg);
}

void shpam_auth_alg_set(int alg)
{
  _auth_alg_default = alg;
}





int shpam_auth_pass_set(shauth_t *auth, uint64_t uid, shalg_t priv_key, unsigned char *pass_data, size_t pass_len)
{
  shbuf_t *buff;
  int err;

  /* create payload containing pass data */
  buff = shbuf_init();
  shbuf_cat(buff, &auth->auth_stamp, sizeof(auth->auth_stamp));
  shbuf_cat(buff, &uid, sizeof(uid));
  if (pass_data && pass_len)
    shbuf_cat(buff, pass_data, pass_len);

  /* create signature for payload */
  err = shalg_sign(auth->auth_alg, priv_key, auth->auth_sig,
      shbuf_data(buff), shbuf_size(buff)); 
  shbuf_free(&buff);
  if (err)
    return (err);

  /* retain the public key for verification */
  err = shalg_pub(auth->auth_alg, priv_key, auth->auth_pub);
  if (err)
    return (err);

  /* creation time-stamp of authorization method */
  if (auth->auth_stamp == SHTIME_UNDEFINED)
    auth->auth_stamp = shtime();

  /* primary validation method */
  auth->auth_flag |= SHAUTH_PRIMARY;
  /* derived from local "secret data" */
  auth->auth_flag |= SHAUTH_SECRET;

  return (0);
}

int shpam_auth_set(shseed_t *seed, char *username, unsigned char *pass_data, size_t pass_len)
{
  static const size_t raw_len = 256;
  unsigned char raw[256];
  shauth_t *auth;
  shbuf_t *buff;
  shalg_t priv_key;
  int alg;
  int err;
  int idx;

#if 0
  if (seed->seed_uid != shpam_uid(username))
    return (SHERR_INVAL);
#endif
  seed->seed_uid = shpam_uid(username);

  for (idx = 0; idx < SHAUTH_MAX; idx++) {
    if (idx != SHAUTH_SCOPE_LOCAL &&
        idx != SHAUTH_SCOPE_REMOTE)
      continue;

    alg = shpam_auth_alg_default(idx);
    memset(priv_key, 0, sizeof(priv_key));

    auth = &seed->auth[idx];
    if (auth->auth_salt == 0)
      auth->auth_salt = shpam_salt();
    if (auth->auth_stamp == SHTIME_UNDEFINED)
      auth->auth_stamp = shtime();

    /* derive a secret using salt */
    memset(raw, 0, sizeof(raw));
    err = shhkdf_expand(SHALG_SHA512, 
        (unsigned char *)seed->seed_secret, SHSEED_SECRET_SIZE, 
        (unsigned char *)&auth->auth_salt, sizeof(auth->auth_salt),
        raw, raw_len);
    if (err)
      return (err);

    /* generate private key */
    memset(raw, 0, sizeof(raw));
    err = shalg_priv(alg, priv_key, raw, raw_len);
    if (err)
      return (err);

    /* generate signature */
    auth->auth_alg = alg;
    err = shpam_auth_pass_set(auth, seed->seed_uid, 
        priv_key, pass_data, pass_len); 
    if (err)
      return (err);
  }

  return (0);
}

int shpam_auth_remote_set(shseed_t *seed, uint64_t uid, shauth_t *rem_auth)
{
  shauth_t *auth;

  if (!rem_auth)
    return (SHERR_INVAL);
  if (rem_auth->auth_stamp == SHTIME_UNDEFINED)
    return (SHERR_INVAL);
  if (rem_auth->auth_salt == 0)
    return (SHERR_INVAL);
  
  auth = &seed->auth[SHAUTH_SCOPE_REMOTE];
  if (auth->auth_salt != 0 &&
      auth->auth_salt != rem_auth->auth_salt)
    return (SHERR_REMOTE);
  if (auth->auth_stamp != 0 &&
      auth->auth_stamp != rem_auth->auth_stamp)
    return (SHERR_REMOTE);
  if (shalg_size(auth->auth_pub) != 0) {
    if (shalg_size(auth->auth_pub) != shalg_size(rem_auth->auth_pub) ||
        0 != memcmp(auth->auth_pub, rem_auth->auth_pub, shalg_size(auth->auth_pub)))
      return (SHERR_REMOTE);
  }

  memcpy(auth, rem_auth, sizeof(shauth_t));

  auth->auth_flag |= SHAUTH_PRIMARY;
  auth->auth_flag |= SHAUTH_EXTERNAL;
  /* not derived from local secret */
  auth->auth_flag &= ~SHAUTH_SECRET;

  return (0);
}

int shpam_auth_crypt_verify(char *username, unsigned char *pass_data, size_t pass_len)
{
#ifdef HAVE_GETSPNAM
  char cr_salt[256];
  char uname[MAX_SHARE_NAME_LENGTH];
  struct passwd *pw;
  struct spwd *sp;
  char *text;
  char *str;
  char *hex;
  uint64_t cmp_salt;
  size_t ret_len;
  int idx;
  int err;

  memset(cr_salt, 0, sizeof(cr_salt));

  memset(uname, 0, sizeof(uname));
  if (!username || !*username) {
#ifdef HAVE_GETPWNAM
    pw = getpwuid(geteuid());
    if (!pw)
      return (SHERR_NOENT);
    strncpy(uname, pw->pw_name, sizeof(uname)-1);
#endif
  } else {
    strncpy(uname, username, sizeof(uname)-1);
  }
  strtok(uname, "@");

  sp = getspnam(uname);
  if (!sp)
    return (SHERR_ACCESS);

  str = sp->sp_pwdp; /* use shadow passwd */
  if (!str && 0 != strncmp(str, "$6$", 3))
    return (SHERR_INVAL);

  str += 3;
  idx = stridx(str, '$');
  if (idx == -1)
    return (SHERR_INVAL);

  cmp_salt = 0;
  strncpy(cr_salt, str, MIN(idx, sizeof(cr_salt) - 1));
  shcrypt_b64_decode(cr_salt, (unsigned char *)&cmp_salt, &ret_len);
#if 0
  if (salt != cmp_salt)
    return (SHERR_ACCESS);
#endif

  hex = shalg_encode(SHFMT_HEX, pass_data, pass_len);
  text = shcrypt_sha512(hex, cr_salt);
  if (!text)
    return (SHERR_ACCESS);

  if (0 != strcmp(text, sp->sp_pwdp))
    return (SHERR_ACCESS); 

  /* matched system shadow database */
  return (0);

#else
  return (SHERR_OPNOTSUPP);
#endif
}

int shpam_auth_sys_verify(char *username, unsigned char *pass_data, size_t pass_len)
{
  int err;

  err = shpam_auth_crypt_verify(username, pass_data, pass_len);
  if (err)
    return (err);

  return (0); 
}

int shpam_auth_pass_verify(shauth_t *auth, char *username, unsigned char *pass_data, size_t pass_len)
{
  shbuf_t *buff;
  uint64_t uid;
  uint32_t pin;
  int err;

  if (auth->auth_expire != SHTIME_UNDEFINED &&
      shtime_after(shtime(), auth->auth_expire))
    return (SHERR_KEYEXPIRED);

  uid = shpam_uid(username);

  if (auth->auth_flag & SHAUTH_TIME) {
    uint32_t code_2fa;

    if (pass_len != sizeof(uint32_t))
      return (SHERR_INVAL);

    /* time based payload */
    pin = shsha_2fa_bin(auth->auth_alg, 
        auth->auth_pub, shalg_size(auth->auth_pub), 30);

    code_2fa = *((uint32_t *)pass_data);
    if (pin != code_2fa)
      return (SHERR_ACCESS);
  } else {
    /* secret based payload */
    buff = shbuf_init();
    shbuf_cat(buff, &auth->auth_stamp, sizeof(auth->auth_stamp));
    shbuf_cat(buff, &uid, sizeof(uid));
    if (pass_data && pass_len)
      shbuf_cat(buff, pass_data, pass_len);

    err = shalg_ver(auth->auth_alg, auth->auth_pub,
        auth->auth_sig, shbuf_data(buff), shbuf_size(buff));
    shbuf_free(&buff);
    if (err)
      return (err);
  }

  return (0);
}

int shpam_auth_verify(shseed_t *seed, char *username, unsigned char *pass_data, size_t pass_len)
{
  int tot;
  int err;
  int i;

  tot = 0;
  for (i = 0; i < SHAUTH_MAX; i++) {
    if (!(seed->auth[i].auth_flag & SHAUTH_PRIMARY))
      continue;

    tot++;
  }
  if (tot == 0) {
    /* no primary authorization method(s) equate to a public login */
    return (0);
  }

  for (i = 0; i < SHAUTH_MAX; i++) {
    if (!(seed->auth[i].auth_flag & SHAUTH_PRIMARY))
      continue;

    err = shpam_auth_pass_verify(&seed->auth[i],
        username, pass_data, pass_len);
    if (err == 0)
      return (0);
  }

  /* attempt against system (OS) */
  err = shpam_auth_sys_verify(username, pass_data, pass_len);
  if (err == 0) {
    return (0);
}

  return (SHERR_ACCESS);
}

int shpam_auth_2fa_verify(shseed_t *seed, char *username, uint32_t code_2fa)
{
  int tot;
  int err;
  int i;

  tot = 0;
  for (i = 0; i < SHAUTH_MAX; i++) {
    if (!(seed->auth[i].auth_flag & SHAUTH_SECONDARY))
      continue;

    tot++;
  }
  if (tot == 0) {
    /* no secondary authorization method(s) equate to disabled 2fa */
    return (0);
  }

  for (i = 0; i < SHAUTH_MAX; i++) {
    if (!(seed->auth[i].auth_flag & SHAUTH_SECONDARY))
      continue;

    err = shpam_auth_pass_verify(&seed->auth[i],
        username, (unsigned char *)&code_2fa, sizeof(code_2fa));
    if (err == 0)
      return (0);
  }

  return (SHERR_ACCESS);
}

uint64_t shpam_salt_crypt(void)
{
  uint64_t ret_val = 0;
#ifdef HAVE_GETSPNAM
  char cr_salt[256];
  struct passwd *pw;
  struct spwd *sp;
  size_t ret_len;
  char *str;
  int idx;

  pw = getpwuid(geteuid());
  if (!pw)
    return (ret_val);

  sp = getspnam(pw->pw_name);
  if (!sp)
    return (ret_val);

  str = sp->sp_pwdp; /* use shadow passwd */
  if (!str && 0 != strncmp(str, "$6$", 3))
    return (ret_val);

  str += 3;
  idx = stridx(str, '$');
  if (idx == -1)
    return (SHERR_INVAL);

  ret_val = 0;
  strncpy(cr_salt, str, MIN(idx, sizeof(cr_salt) - 1));
  shcrypt_b64_decode(cr_salt, &ret_val, &ret_len);

#endif
  return (ret_val);
}



uint64_t shpam_master_seed(shseed_t *seed)
{
  return (shcrc((unsigned char *)seed->seed_secret, SHSEED_SECRET_SIZE));
}

/* derive a 10-byte key for 2fa */
void shpam_auth_2fa_init(shseed_t *seed, int scope)
{
  shauth_t *auth;

  if (scope < 0 || scope >= SHAUTH_MAX)
    return;

  auth = &seed->auth[scope];

  if (auth->auth_stamp == SHTIME_UNDEFINED)
    auth->auth_stamp = shtime();

  auth->auth_alg = shpam_auth_alg_default(SHAUTH_SCOPE_2FA);
  auth->auth_flag |= SHAUTH_TIME;

  memcpy(auth->auth_pub, &seed->seed_secret[1], 5);
  memcpy((unsigned char *)auth->auth_pub + 5, &seed->seed_secret[3], 5);
  shalg_size(auth->auth_pub) = 10;

}

int shpam_auth_init(uint64_t uid, shseed_t *seed)
{
  shauth_t *auth;
  int err;
  int i;

  if (!seed)
    return (SHERR_INVAL);

  memset(seed, '\000', sizeof(shseed_t));

  seed->seed_uid = uid;
  seed->seed_stamp = shtime();
  seed->seed_expire = SHTIME_UNDEFINED;

  for (i = 0; i < 8; i++) {
    seed->seed_secret[i] = shrand();
  }

  shpam_auth_2fa_init(seed, SHAUTH_SCOPE_2FA);
  
  return (0);
}



_TEST(shpam_auth_verify)
{
  shseed_t seed;
  int err;

  memset(&seed, '\000', sizeof(seed));

  err = shpam_auth_set(&seed, "test", "testpass", 8);
  _TRUE(0 == err);

  err = shpam_auth_verify(&seed, "test", "testpass", 8);
  _TRUE(0 == err);
}





#undef __MEM__SHSYS_PAM_C__
