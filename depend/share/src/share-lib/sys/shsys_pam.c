
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


uint64_t shpam_uid(char *username)
{

  if (!username)
    return (SHMEM_MAGIC); /* arbitrary 64bit number */

  return (shcrc(username, strlen(username)));
}

uint64_t shpam_euid(void)
{
  char *uname = shpam_username_sys();
  return (shpam_uid(uname));
}

shkey_t *shpam_ident_gen(uint64_t uid, shpeer_t *peer)
{
  shbuf_t *buff;
  shkey_t *key;
  char hex_buf[MAX_SHARE_NAME_LENGTH];

  if (!peer)
    return (NULL);

  buff = shbuf_init();
  /* user account identifier */
  shbuf_cat(buff, &uid, sizeof(uid));
  /* application identifier */
  shbuf_cat(buff, shpeer_kpub(peer), sizeof(shkey_t));
  key = shkey_bin(shbuf_data(buff), shbuf_size(buff));
  shbuf_free(&buff);

  return (key);
}

shkey_t *shpam_ident_root(shpeer_t *peer)
{
  return (shpam_ident_gen(shpam_uid(NULL), peer));
}

int shpam_ident_verify(shkey_t *id_key, uint64_t uid, shpeer_t *peer)
{
  shkey_t *ver_key;
  int ok;

  ver_key = shpam_ident_gen(uid, peer);
  ok = shkey_cmp(ver_key, id_key);
  shkey_free(&ver_key);
  if (!ok)
    return (SHERR_ACCESS);

  return (0);
}

shkey_t *shpam_sess_gen(shkey_t *pass_key, shtime_t stamp, shkey_t *id_key)
{
  shtime_t max_stamp;
  shtime_t now;
  shkey_t *key;
  uint64_t crc;
  int err;

  if (!pass_key)
    return (NULL);

  now = shtime();
  if (shtime_after(shtime(), stamp) ||
      shtime_after(stamp, shtime_adj(now, MAX_SHARE_SESSION_TIME))) {
    /* expiration time-stamp is too early or too late */
    return (NULL);
  }

  crc = shcrc(id_key, sizeof(shkey_t));
  key = shkey_cert(pass_key, crc, stamp);
  return (key);
}

int shpam_sess_verify(shkey_t *sess_key, shkey_t *pass_key, shtime_t stamp, shkey_t *id_key)
{
  shkey_t *ver_sess_key;
  int valid;

  ver_sess_key = shpam_sess_gen(pass_key, stamp, id_key);
  valid = shkey_cmp(ver_sess_key, sess_key);
  shkey_free(&ver_sess_key);
  if (!valid)
    return (SHERR_ACCESS);

  return (0);
}


#if 0
/**
 * Generate a random 'salt' number used perturb the account's password key.
 */
uint64_t shpam_salt(void)
{
  shkey_t *key;
  uint64_t crc;

  key = shkey_uniq();
  crc = shcrc(key, sizeof(shkey_t));
  shkey_free(&key);

  return (crc);
}

/**
 * Generate a 'salt' number to perturb the password from a data segment.
 */
uint64_t shpam_salt_gen(unsigned char *data, size_t data_len)
{
  shkey_t *key;
  uint64_t crc;

  key = shkey_bin(data, data_len);
  crc = shcrc(key, sizeof(shkey_t));
  shkey_free(&key);

  return (crc);
}
#endif

const char *shpam_realname_sys(void)
{
  static char ret_buf[256];
  char buf[256];
  char *str;
  int i;

  memset(buf, 0, sizeof(buf));
#ifdef HAVE_GETPWUID
  {
    struct passwd *pw = getpwuid(geteuid());
    if (pw && *pw->pw_gecos)
      strncpy(buf, pw->pw_gecos, sizeof(buf)-1);
  }
#endif
  if (!*buf)
    return (NULL);
  
  /* uppercase */
  for (i = 0; i < strlen(buf); i++)
    buf[i] = toupper(buf[i]);

  str = strchr(buf,  ' ');
  if (!str) {
    strcpy(ret_buf, buf);
  } else {
    *str++ = '\0';
    strncpy(ret_buf, str, sizeof(ret_buf) - 1); /* last */
    strncat(ret_buf, "/", sizeof(ret_buf) - strlen(ret_buf) - 1);
    strncat(ret_buf, buf, sizeof(ret_buf) - strlen(ret_buf) - 1); /* first */
  }

  return ((const char *)ret_buf);
}
const char *shpam_username_sys(void)
{
  static char username[MAX_SHARE_NAME_LENGTH];
  char uname[MAX_SHARE_NAME_LENGTH];
  char user_buf[1024];
  char host_buf[MAXHOSTNAMELEN+1];
  char *rname;
  const char *str;

  memset(uname, 0, sizeof(uname));

  memset(username, 0, sizeof(username));
  str = shpref_get(SHPREF_ACC_NAME, "");
  if (!*str) {
    memset(user_buf, 0, sizeof(user_buf));
    memset(host_buf, 0, sizeof(host_buf));
    
#ifdef HAVE_GETPWUID
    {
      struct passwd *pw = getpwuid(geteuid());
      if (pw) {
        strncpy(uname, pw->pw_name, sizeof(uname)-1);
      }
    }
#endif

    strncpy(user_buf, uname, sizeof(user_buf) - 2);
    gethostname(host_buf, sizeof(host_buf)-1);
    if (*host_buf) {
      /* "@" */
      strcat(user_buf, "@");
      /* "<host>" */
      strncat(user_buf, host_buf, MAX_SHARE_NAME_LENGTH - strlen(user_buf) - 1);
    }

    rname = shpam_realname_sys();
    if (rname && 0 != strcasecmp(rname, uname)) {
      strncat(user_buf, " ", MAX_SHARE_NAME_LENGTH - strlen(user_buf) - 1);
      strncat(user_buf, rname, MAX_SHARE_NAME_LENGTH - strlen(user_buf) - 1);
    }

    str = user_buf;
  }
  strncpy(username, str, MAX_SHARE_NAME_LENGTH-1);

  return (username);
}

#if 0
shseed_t *shpam_pass_gen(char *username, char *passphrase, uint64_t salt)
{
  static shseed_t ret_seed;
  shkey_t *key;
  char pass_buf[MAX_SHARE_PASS_LENGTH];
  size_t len;

  if (!username)
    username = "";
  if (!passphrase)
    passphrase = "";

  memset(pass_buf, 0, sizeof(pass_buf));

  memset(&ret_seed, 0, sizeof(ret_seed));
  ret_seed.seed_uid = shcrc(username, strlen(username));
  ret_seed.seed_stamp = shtime();

  /* password salt */
  ret_seed.seed_salt = salt;

  /* crypt password */
//  ret_seed.seed_type = SHSEED_PLAIN;
  strncpy(pass_buf, passphrase, MAX_SHARE_PASS_LENGTH - 32);
#ifdef HAVE_CRYPT
  {
    char salt_buf[17];
    char *enc_str;

    memset(salt_buf, 0, sizeof(salt_buf));
    sprintf(salt_buf, "$6$%s", shcrcstr(salt));
    enc_str = crypt(passphrase, salt_buf);
    if (enc_str) {
      memset(pass_buf, 0, sizeof(pass_buf));
      strncpy(pass_buf, enc_str, MAX_SHARE_PASS_LENGTH - 32);
      //ret_seed.seed_type = SHSEED_SHA512;
      ret_seed.seed_alg |= SHALG_SHA512;
      ret_seed.seed_flag |= SHSEED_CRYPT; 
    } else {
#if 0
      sprintf(salt_buf, "$1$%s", shcrcstr(salt));
      enc_str = crypt(passphrase, salt_buf);
      if (enc_str) {
        memset(pass_buf, 0, sizeof(pass_buf));
        strncpy(pass_buf, enc_str, MAX_SHARE_PASS_LENGTH - 32);
        ret_seed.seed_type = SHSEED_MD5;
      }
#endif
    }
  }
#endif

  /* encode password */
  key = shkey_num64(salt);
  len = MAX_SHARE_NAME_LENGTH - 32;
  ashencode(pass_buf, &len, key);
  shkey_free(&key);

  /* password key */
  key = shkey_bin(pass_buf, len);
  memcpy(&ret_seed.seed_key, key, sizeof(shkey_t));
  shkey_free(&key);

  /* password signature */
  key = shkey_cert(&ret_seed.seed_key, ret_seed.seed_salt, ret_seed.seed_stamp);
  memcpy(&ret_seed.seed_sig, key, sizeof(shkey_t));
  shkey_free(&key); 

  return (&ret_seed);
}
#endif

#if 0
shseed_t *shpam_pass_sys(char *username)
{
  static shseed_t ret_seed;
  shkey_t *key;
  char cr_salt[256];
  char cr_pass[256];
  char tok[256];
  char *str;
  size_t len;

  if (!username)
    username = "";

  memset(cr_salt, 0, sizeof(cr_salt));
  memset(cr_pass, 0, sizeof(cr_pass));

  memset(&ret_seed, 0, sizeof(ret_seed));
  ret_seed.seed_uid = shpam_uid(username);
  ret_seed.seed_stamp = shtime();

  str = shpref_get(SHPREF_ACC_SALT, "");
  strncpy(cr_salt, str, sizeof(cr_salt)-1); 

  str = shpref_get(SHPREF_ACC_PASS, "");
  strncpy(cr_pass, str, sizeof(cr_pass)-1); 

  if (!*cr_salt && !*cr_pass) {
#ifdef HAVE_GETSPNAM
    struct spwd *sp = getspnam(username);
    if (sp) {
      char *str = sp->sp_pwdp; /* use shadow passwd */
      if (str && 0 == strncmp(str, "$6$", 3)) {
        str += 3;
        int idx = stridx(str, '$');
        if (idx != -1) {
          strncpy(cr_salt, str, MIN(idx, sizeof(cr_salt) - 1));
          strncpy(cr_pass, str + idx + 1, sizeof(cr_pass) - 1);
        }
        //ret_seed.seed_type = SHSEED_SHA512;
        ret_seed.seed_alg |= SHALG_SHA512;
        ret_seed.seed_flag |= SHSEED_CRYPT; 
#if 0
      } else if (str && 0 == strncmp(str, "$1$", 3)) {
        str += 3;
        int idx = stridx(str, '$');
        if (idx != -1) {
          strncpy(cr_salt, str, MIN(idx, sizeof(cr_salt) - 1));
          strncpy(cr_pass, str + idx + 1, sizeof(cr_pass) - 1);
        }
        ret_seed.seed_type = SHSEED_MD5;
#endif
      }
    }
#endif
    ret_seed.seed_salt = shcrcgen(cr_salt);

    /* encode password */
    key = shkey_num64(ret_seed.seed_salt);
    len = MAX_SHARE_NAME_LENGTH - 32;
    ashencode(cr_pass, &len, key);
    shkey_free(&key);

    /* password key */
    key = shkey_bin(cr_pass, len);
  } else {
    ret_seed.seed_salt = shcrcgen(cr_salt);
    key = shkey_gen(cr_pass);
  }
  memcpy(&ret_seed.seed_key, key, sizeof(shkey_t));
  shkey_free(&key);

  /* password signature */
  key = shkey_cert(&ret_seed.seed_key, ret_seed.seed_salt, ret_seed.seed_stamp);
  memcpy(&ret_seed.seed_sig, key, sizeof(shkey_t));
  shkey_free(&key); 

  return (&ret_seed);
}
#endif

#if 0
int shpam_pass_verify(shseed_t *seed, char *username, char *passphrase)
{
  uint64_t salt;
  shseed_t *v_seed;
  int err;

  if (!seed)
    return (SHERR_INVAL);

  salt = seed->seed_salt;
  v_seed = shpam_pass_gen(username, passphrase, salt);

  if (seed->seed_uid != v_seed->seed_uid) {
    return (SHERR_INVAL);
  }

#if 0
  if (seed->seed_type != v_seed->seed_type) {
    return (SHERR_INVAL);
  }
#endif
  if (seed->seed_alg != v_seed->seed_alg) {
    return (SHERR_INVAL);
  }

  if (seed->seed_salt != v_seed->seed_salt) {
    return (SHERR_INVAL);
  }

  if (!shkey_cmp(&seed->seed_key, &v_seed->seed_key)) {
    return (SHERR_INVAL);
  }

  err = shkey_verify(&seed->seed_sig, 
      seed->seed_salt, &seed->seed_key, seed->seed_stamp); 
  if (err)
    return (err);

  return (0);
}
#endif




uint64_t shpam_salt(void)
{
  uint64_t ret_val = 0;

  /* generate random salt */
  ret_val = shrand();  

  return (ret_val);
}


#undef __MEM__SHSYS_PAM_C__
