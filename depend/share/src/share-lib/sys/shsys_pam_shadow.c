
/*
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
*/  

#include "share.h"

#define TIME_24_MIN 1440



static void _shpam_shadow_master_key(shseed_t *seed, shkey_t *ret_key)
{
  char *key;

  if (!seed || !ret_key)
    return;

  key = ashkey_bin((char *)seed->seed_secret, SHSEED_SECRET_SIZE);
  memcpy(ret_key, key, sizeof(shkey_t));
}


#if 0
void shpam_shadow_file(char *acc_name, shfs_t **fs_p, shfs_ino_t **ino_p)
{
  shfs_ino_t *sys_dir;
  shfs_ino_t *file;
  shpeer_t *peer;
	shkey_t *cur_ident;
	shkey_t *key;
	shkey_t ident;
  shfs_t *fs;

	if (!acc_name)
		acc_name = (char *)get_libshare_account_name();

	/* fs peer */
	peer = shpeer_init(PACKAGE, NULL);
	key = shpam_ident_gen(shpam_uid(acc_name), peer);
	memcpy(&ident, key, sizeof(ident));
	shpeer_free(&peer);
	/* open fs */
	fs = shfs_home_fs(key);

#if 0
  if (!fs) {
    fs = shfs_sys_init(SHFS_DIR_PAM, "shadow", &file);
  } else {
    file = shfs_file_find(fs, shfs_sys_dir(SHFS_DIR_PAM, "shadow"));
  }
#endif
	file = shfs_file_find(fs, shfs_sys_dir(SHFS_DIR_PAM, "shadow"));

#if 0
	/* authorization */
	cur_ident = shfs_access_owner_get(file);
	if (!cur_ident) {
		shfs_access_owner_set(file, key);
	} else if (!shkey_cmp(cur_ident, key)) {
		shkey_free(&cur_ident);
		return (SHERR_ACCESS);
	}
#endif
	shkey_free(&key);

  *fs_p = fs;
	*ino_p = file;
}
#endif



#if 0
int shpam_shadow_create(shfs_ino_t *file, uint64_t uid, shadow_t *ret_shadow)
{
  shadow_t shadow;
  shadow_t *sh_list;
  shbuf_t *buff;
  shkey_t *id_key;
  shkey_t *key;
  int sh_list_max;
  int idx;
  int err;

  if (!file->tree)
    return (SHERR_INVAL);

/* In order to prevent this from allowing already created shadow entries from existing prior the SHERR_NOTUNIQ error code is returned when "err == 0". Currently, this is not considered an error in order to allow pre-established IDs from the sharenet (shared) to be created. */
  err = shpam_shadow_load(file, uid, NULL);
  if (err != 0 && err != SHERR_NOENT)
    return (err);

  memset(&shadow, 0, sizeof(shadow_t));
//  memcpy(&shadow.sh_sess, ashkey_blank(), sizeof(shkey_t));
  shadow.sh_uid = uid; 

  id_key = shpam_ident_gen(uid, &file->tree->peer);
  memcpy(&shadow.sh_id, id_key, sizeof(shadow.sh_id));
  shkey_free(&id_key);

  key = shkey_bin((char *)&uid, sizeof(uid));
  err = shfs_cred_store(file, key, (unsigned char *)&shadow, sizeof(shadow_t));
  shkey_free(&key);
  if (err)
    return (err);

  if (ret_shadow)
    memcpy(ret_shadow, &shadow, sizeof(shadow_t));

  return (0);
}

int shpam_shadow_load(shfs_ino_t *file, uint64_t uid, shadow_t *ret_shadow)
{
  shadow_t shadow;
  shkey_t *key;
  int err;

  memset(&shadow, 0, sizeof(shadow_t));

  key = shkey_bin((char *)&uid, sizeof(uid));
  err = shfs_cred_load(file, key, (unsigned char *)&shadow, sizeof(shadow));
  shkey_free(&key);
  if (err)
    return (err);

  if (ret_shadow)
    memcpy(ret_shadow, &shadow, sizeof(shadow_t));

  return (0);
}

int shpam_shadow_store(shfs_ino_t *file, shadow_t *shadow)
{
  shadow_t save;
  shkey_t *key;
  int err;

  if (!shadow)
    return (SHERR_INVAL);

#if 0
  /* ensure record already exists. */
  err = shpam_shadow_load(file, shadow->sh_uid, NULL);
  if (err)
    return (err);
#endif

  memcpy(&save, shadow, sizeof(shadow_t));
  key = shkey_bin((char *)&save.sh_uid, sizeof(save.sh_uid));
  err = shfs_cred_store(file, key, (unsigned char *)&save, sizeof(shadow_t));
  shkey_free(&key);
  if (err)
    return (err);

  return (0);
}

int shpam_shadow_remove(shfs_ino_t *file, uint64_t uid, shkey_t *sess_key)
{
  shadow_t *ent;
  shadow_t save;
  shkey_t *key;
  int err;

  if (!sess_key)
    return (SHERR_NOKEY);

  err = shpam_shadow_load(file, uid, &save);
  if (err) {
    return (err);
}

  if (shtime_after(shtime(), save.sh_expire))
    return (SHERR_KEYEXPIRED);

  if (!shkey_cmp(&save.sh_sess, sess_key))
    return (SHERR_KEYREJECTED);

  key = shkey_bin((char *)&uid, sizeof(uid));
  err = shfs_cred_remove(file, key);
  shkey_free(&key);
  if (err) {
    return (err);
}

  return (0);
}

int shpam_pshadow_create(shfs_ino_t *file, shseed_t *seed)
{
  int err;

  if (!seed)
    return (SHERR_INVAL);

  if (seed->seed_uid != shpam_euid()) {
    err = shpam_pshadow_perm(file, SHPERM_CREATE);
    if (err)
      return (err);
  }

  err = shpam_pshadow_load(file, seed->seed_uid, NULL); 
  if (err == 0)
    return (SHERR_NOTUNIQ);
  if (err != SHERR_NOENT)
    return (err);

  err = shpam_pshadow_store(file, seed);
  if (err) {
    return (err);
}

  return (0);
}


/* local user account creation */
int shpam_pshadow_new(shfs_ino_t *file, char *username, char *passphrase)
{
  shseed_t seed;
  uint64_t uid;
  int err;
  int i;

  memset(&seed, 0, sizeof(seed));

  uid = shpam_uid(username);
  err = shpam_pshadow_init(file, uid, &seed);
  if (err)
    return (err);

  err = shpam_auth_set(&seed, username, passphrase, strlen(passphrase));
  if (err)
    return (err);

  seed.seed_perm |= SHPERM_READ;
  seed.seed_perm |= SHPERM_WRITE;
  seed.seed_perm |= SHPERM_CREATE;
  seed.seed_perm |= SHPERM_VERIFY;

  err = shpam_pshadow_store(file, &seed);
  if (err)
    return (err);

  return (0);
}

int shpam_pshadow_load(shfs_ino_t *file, uint64_t uid, shseed_t *ret_seed)
{
  shbuf_t *buff;
  shseed_t *seeds;
  int total;
  int idx;
  int err;

  if (ret_seed)
    memset(ret_seed, 0, sizeof(shseed_t));

  if (uid != shpam_euid()) {
    err = shpam_pshadow_perm(file, SHPERM_READ);
    if (err)
      return (err);
  }

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err) {
    shbuf_free(&buff);
    //return (err);
    return (SHERR_NOENT); /* done */
  }

  seeds = (shseed_t *)shbuf_data(buff);
  total = shbuf_size(buff) / sizeof(shseed_t);
  if (!total) {
    shbuf_free(&buff);
    return (SHERR_NOENT); /* done */
  }

  for (idx = 0; idx < total; idx++) {
    if (seeds[idx].seed_uid == uid)
      break;
  }

  if (idx == total) {
    shbuf_free(&buff);
    return (SHERR_NOENT);
  }

  if (ret_seed) {
    shseed_t *seed = &seeds[idx];
    memcpy(ret_seed, seed, sizeof(shseed_t));
  }

  shbuf_free(&buff);
  return (0);
}

/**
 * @note Does not require any user permissions.
 */
int shpam_pshadow_auth_load(shfs_ino_t *file, uint64_t uid, int scope, shauth_t *ret_auth)
{
  shbuf_t *buff;
  shseed_t *seeds;
  int total;
  int idx;
  int err;

  if (ret_auth)
    memset(ret_auth, 0, sizeof(shauth_t));

  if (scope < 0 || scope >= SHAUTH_MAX)
    return (SHERR_INVAL); 

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }

  seeds = (shseed_t *)shbuf_data(buff);
  total = shbuf_size(buff) / sizeof(shseed_t);
  if (!total) {
    shbuf_free(&buff);
    return (SHERR_NOENT); /* done */
  }

  for (idx = 0; idx < total; idx++) {
    if (seeds[idx].seed_uid == uid)
      break;
  }

  if (idx == total) {
    shbuf_free(&buff);
    return (SHERR_NOENT);
  }

  if (ret_auth) {
    shauth_t *auth = &seeds[idx].auth[scope];
    memcpy(ret_auth, auth, sizeof(shauth_t));
  }

  shbuf_free(&buff);
  return (0);
}

int shpam_pshadow_store(shfs_ino_t *file, shseed_t *seed)
{
  shbuf_t *buff;
  shseed_t *seeds;
  int total;
  int idx;
  int err;

  if (!seed)
    return (SHERR_INVAL);

#if 0
  /* ensure record exists. */
  err = shpam_pshadow_load(file, seed->seed_uid, NULL);
  if (err)
    return (err);
#endif

  if (seed->seed_uid != shpam_euid()) {
    err = shpam_pshadow_perm(file, SHPERM_WRITE);
    if (err)
      return (err);
  }

  buff = shbuf_init();
  (void)shfs_read(file, buff);

  seeds = (shseed_t *)shbuf_data(buff);
  total = shbuf_size(buff) / sizeof(shseed_t);
  for (idx = 0; idx < total; idx++) {
    if (seeds[idx].seed_uid == seed->seed_uid) {
      memcpy(&seeds[idx], seed, sizeof(shseed_t));
      break;
    }
  }
  if (idx == total) {
    shbuf_cat(buff, seed, sizeof(shseed_t));
  }

  err = shfs_write(file, buff);
  shbuf_free(&buff);
  if (err)
    return (err);

  return (0);
}

int shpam_pshadow_set(shfs_ino_t *file, shseed_t *seed, shpriv_t *priv)
{
  shadow_t save;
  int err;

  err = shpam_shadow_load(file, seed->seed_uid, &save);
  if (err)
    return (err);

  err = shpam_shadow_priv_verify(priv);
  if (err)
    return (err);

  err = shpam_pshadow_store(file, seed);
  if (err)
    return (err);

  return (0);
}

int shpam_pshadow_remove(shfs_ino_t *file, uint64_t rem_uid)
{
  shbuf_t *rbuff;
  shbuf_t *buff;
  shseed_t *seeds;
  int total;
  int idx;
  int err;

  /* ensure record exists. */
  err = shpam_pshadow_load(file, rem_uid, NULL);
  if (err)
    return (err);

  rbuff = shbuf_init();
  shfs_read(file, rbuff);

  buff = shbuf_init();
  seeds = (shseed_t *)shbuf_data(rbuff);
  total = shbuf_size(rbuff) / sizeof(shseed_t);
  for (idx = 0; idx < total; idx++) {
    if (seeds[idx].seed_uid == rem_uid) {
      continue;
}

    shbuf_cat(buff, &seeds[idx], sizeof(shseed_t));
  }
  shbuf_free(&rbuff);

  err = shfs_write(file, buff);
  shbuf_free(&buff);
  if (err)
    return (err);
  
  return (0);
}


#if 0
static shfs_t *_shadow_fs;
static shfs_ino_t *_shadow_file;
int shpam_shadow_open(uint64_t uid, shadow_t **shadow_p, shseed_t **seed_p)
{
  shadow_t ret_shadow;

  if (!_shadow_fs) {
    _shadow_fs = shfs_init(NULL);
    _shadow_file = shpam_shadow_file(_shadow_fs);
  }

  if (shadow_p) {
    shadow_t *sh;

    memset(&ret_shadow, 0, sizeof(ret_shadow));
    err = shfs_cred_load(file, seed_key, (unsigned char *)&ret_shadow, sizeof(ret_shadow));
    if (err)
      return (err);

    sh = (shadow_t *)calloc(1, sizeof(shadow_t));
    memcpy(sh, &ret_shadow, sizeof(ret_shadow));
    *shadow_p = sh;
  }

  if (seed_p) {
    shseed_t ret_seed;
    shseed_t *seed;

    err = shpam_pshadow_load(_shadow_file, uid, &ret_seed); 
    if (err)
      return (err);

    seed = (shseed_t *)calloc(1, sizeof(shseed_t));
    memcpy(seed, &ret_seed, sizeof(ret_seed));
    *seed_p = seed;
  }

  return (0);
}

int shpam_shadow_close(uint64_t uid, shadow_t **shadow_p, shseed_t **seed_p)
{
  if (sh_p) {
    shadow_t *shadow = *shadow_p;
    *shadow_p = NULL;
    if (shadow) free(shadow);
  }
  if (seed_p) {
    shseed_t *seed = *seed_p;
    *seed_p = NULL;
    if (seed) free(seed);
  }
  shfs_free(&_shadow_fs);
}
#endif

#if 0
shadow_t *shpam_shadow(shfs_ino_t *file, shkey_t *seed_key)
{
  static shadow_t ret_shadow;
  int err;

  memset(&ret_shadow, 0, sizeof(ret_shadow));
  err = shfs_cred_load(file, seed_key, (unsigned char *)&ret_shadow, sizeof(ret_shadow));
  if (err)
   return (NULL);
  if (!shkey_cmp(seed_key, &ret_shadow.sh_seed))
    return (NULL);

  return (&ret_shadow);
}
#endif

#if 0
const shseed_t *shpam_shadow_pass(shfs_ino_t *file, uint64_t uid)
{
  static shseed_t ret_seed;
  shbuf_t *buff;
  shseed_t *seeds;
  int total;
  int idx;
  int err;

  memset(&ret_seed, 0, sizeof(ret_seed));

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err) {
    shbuf_free(&buff);
    return (NULL);
  }

  seeds = (shseed_t *)shbuf_data(buff);
  total = shbuf_size(buff) / sizeof(shseed_t);
  for (idx = 0; idx < total; idx++) {
    if (seeds[idx].seed_uid == uid) {
      memcpy(&ret_seed, &seeds[idx], sizeof(shseed_t));
      break;
    }
  }
  shbuf_free(&buff);

  if (idx != total) {
    return (&ret_seed);
  }

  return (NULL);
}
#endif

#if 0
int shpam_shadow_append(shfs_ino_t *file, shadow_t *shadow)
{
  shadow_t save;
  shadow_t *ent;
  int err;

  if (!shadow)
    return (SHERR_INVAL);

  ent = shpam_shadow(file, &shadow->sh_seed);
  if (!ent)
    return (SHERR_NOKEY);

  if (ent->sh_flag & SHPAM_LOCK)
    return (SHERR_ACCESS);

  memcpy(&save, shadow, sizeof(shadow_t));
  memcpy(&save.sh_id, &ent->sh_id, sizeof(shkey_t));
  err = shfs_cred_store(file, &save.sh_seed,
      (unsigned char *)&save, sizeof(shadow_t));
  if (err)
    return (err);

  return (0);
}
#endif

#if 0
int shpam_shadow_pass_append(shfs_ino_t *file, shseed_t *seed)
{
  shbuf_t *buff;
  shseed_t *seeds;
  int total;
  int idx;
  int err;

  buff = shbuf_init();
  shfs_read(file, buff);

  seeds = (shseed_t *)shbuf_data(buff);
  total = shbuf_size(buff) / sizeof(shseed_t);
  for (idx = 0; idx < total; idx++) {
    if (seeds[idx].seed_uid == seed->seed_uid) {
      memcpy(&seeds[idx], seed, sizeof(shseed_t));
      break;
    }
  }
  if (idx == total) {
    shbuf_cat(buff, seed, sizeof(shseed_t));
  }

  err = shfs_write(file, buff);
  shbuf_free(&buff);
  if (err)
    return (err);
  
  return (0);
}
#endif

#if 0
int shpam_shadow_pass_remove(shfs_ino_t *file, uint64_t rem_uid)
{
  shbuf_t *rbuff;
  shbuf_t *buff;
  shseed_t *seeds;
  int total;
  int idx;
  int err;

  rbuff = shbuf_init();
  shfs_read(file, rbuff);

  buff = shbuf_init();
  seeds = (shseed_t *)shbuf_data(rbuff);
  total = shbuf_size(rbuff) / sizeof(shseed_t);
  for (idx = 0; idx < total; idx++) {
    if (seeds[idx].seed_uid == rem_uid)
      continue;

    shbuf_cat(buff, &seeds[idx], sizeof(shseed_t));
  }
  shbuf_free(&rbuff);

  err = shfs_write(file, buff);
  shbuf_free(&buff);
  if (err)
    return (err);
  
  return (0);
}
#endif

#if 0
int shpam_shadow_verify(shfs_ino_t *file, shkey_t *seed_key)
{
  shadow_t shadow;
  int err;

  memset(&shadow, 0, sizeof(shadow));
  err = shfs_cred_load(file, seed_key, (unsigned char *)&shadow, sizeof(shadow));
  if (err)
    return (SHERR_NOKEY);

  if (!shkey_cmp(seed_key, &shadow.sh_seed))
    return (SHERR_ACCESS);

  return (0);
}
#endif

#if 0
int shpam_shadow_delete(shfs_ino_t *file, char *acc_name, shkey_t *sess_key)
{
  shadow_t *ent;
  shadow_t save;
  shkey_t *seed_key;
  int ret_err;
  int err;

  if (!sess_key)
    return (SHERR_INVAL);

  seed_key = shpam_seed(acc_name);
  ent = shpam_shadow(file, seed_key);
  shkey_free(&seed_key);
  if (!ent)
    return (SHERR_NOKEY);

  memcpy(&save, ent, sizeof(shadow_t));

  if (shtime64() >= save.sh_expire)
    return (SHERR_KEYEXPIRED);

  if (!shkey_cmp(&save.sh_sess, sess_key))
    return (SHERR_KEYREJECTED);

  if (save.sh_flag & SHPAM_LOCK)
    return (SHERR_ACCESS);

  ret_err = 0;

  err = shfs_cred_remove(file, &save.sh_seed);
  if (err)
    ret_err = err;

  err = shpam_shadow_pass_remove(file, shpam_uid(acc_name));
  if (err)
    ret_err = err;

  return (ret_err);
}
#endif

#if 0
int shpam_shadow_create(shfs_ino_t *file, shkey_t *seed_key, char *id_label, shadow_t **shadow_p)
{
  static shadow_t shadow;
  shadow_t *sh_list;
  shbuf_t *buff;
  shkey_t *id_key;
  int sh_list_max;
  int idx;
  int err;

  if (!file->tree)
    return (SHERR_INVAL);

  if (shpam_shadow(file, seed_key))
    return (SHERR_NOTUNIQ);

  memset(&shadow, 0, sizeof(shadow));
  memcpy(&shadow.sh_seed, seed_key, sizeof(shkey_t));
  if (id_label)
    strncpy(shadow.sh_label, id_label, sizeof(shadow.sh_label));

  id_key = shpam_ident_gen(&file->tree->peer, seed_key, id_label);
  memcpy(&shadow.sh_id, id_key, sizeof(shkey_t));
  shkey_free(&id_key);

  err = shfs_cred_store(file, seed_key, 
      (unsigned char *)&shadow, sizeof(shadow));
  if (err)
    return (err);

  if (shadow_p)
    *shadow_p = &shadow;

  return (0);
}
#endif

#if 0
int shpam_shadow_pass_gen(shfs_ino_t *file, shseed_t *seed)
{
  shseed_t acc_seed;
  int err;

  if (!seed)
    return (SHERR_INVAL);

  if (shpam_shadow_pass(file, seed->seed_uid)) {
    return (SHERR_NOTUNIQ);
  }

  memcpy(&acc_seed, seed, sizeof(shseed_t));
  err = shpam_shadow_pass_append(file, &acc_seed);
  if (err)
    return (err);

  return (0);
}
#endif

#if 0
int shpam_shadow_pass_new(shfs_ino_t *file, char *username, char *passphrase)
{
  shseed_t acc_seed;
  shseed_t *seed;
  uint64_t salt;
  int err;

  salt = shpam_salt();
  seed = shpam_pass_gen((char *)username, passphrase, salt);
  memcpy(&acc_seed, seed, sizeof(shseed_t));
  err = shpam_shadow_pass_gen(file, &acc_seed);
  if (err)
    return (err);

  return (0);
}
#endif

#if 0
int shpam_shadow_setpass(shfs_ino_t *file, shseed_t *seed, shkey_t *sess_key)
{
  shadow_t *ent;
  shadow_t save;
  shkey_t *seed_key;
  int err;

  seed_key = shkey_bin((char *)&seed->seed_uid, sizeof(seed->seed_uid));
  ent = shpam_shadow(file, seed_key);
  shkey_free(&seed_key);
  if (!ent)
    return (SHERR_NOENT);

  memcpy(&save, ent, sizeof(shadow_t));
  if (shtime64() >= save.sh_expire)
    return (SHERR_KEYEXPIRED);
  if (!shkey_cmp(&save.sh_sess, sess_key))
    return (SHERR_KEYREJECTED);

  seed_key = shkey_bin((char *)&seed->seed_uid, sizeof(seed->seed_uid));
  err = shpam_shadow_session_expire(file, seed_key, sess_key);
  shkey_free(&seed_key);
  if (err)
    return (err);

  err = shpam_shadow_pass_append(file, seed);
  if (err)
    return (err);

  return (0);
}
#endif




int shpam_shadow_session_new(shfs_ino_t *file, char *acc_name, char *passphrase)
{
  uint64_t uid;
  int err;

  uid = shpam_uid(acc_name);
  err = shpam_shadow_create(file, uid, NULL);
  if (err)
    return (err);

  err = shpam_pshadow_new(file, acc_name, passphrase);
  if (err)
    return (err); 

#if 0
{
shadow_t shadow;
memset(&shadow, 0, sizeof(shadow));
err = shpam_shadow_load(file, uid, &shadow);
}
#endif

  return (0);
}

static shkey_t *_shpam_shadow_session_gen(shseed_t *seed, shkey_t *id_key, shtime_t stamp)
{
  shkey_t *sess_key;
  shkey_t seed_key; 
  
  /* generate new session */
  _shpam_shadow_master_key(seed, &seed_key);
  sess_key = shpam_sess_gen(&seed_key, stamp, id_key);
  if (!sess_key)
    return (NULL);

  return (sess_key);
}

int shpam_shadow_session(shfs_ino_t *file, shseed_t *seed, shkey_t **sess_p, shtime_t *expire_p)
{
  shadow_t *ent;
  shadow_t save;
  shkey_t *sess_key;
  shkey_t *ret_key;
  shkey_t *seed_key;
  shtime_t stamp;
  shtime_t now;
  uint64_t crc;
  int err;

  if (!file->tree)
    return (SHERR_INVAL);

  err = shpam_shadow_load(file, seed->seed_uid, &save);
  if (err) {
    return (err);
}

  now = shtime();
  if (shtime_after(now, save.sh_expire)) {
    /* generate new session key with default expiration */
    stamp = shtime_adj(now, MAX_SHARE_SESSION_TIME);
    sess_key = _shpam_shadow_session_gen(seed, &save.sh_id, stamp); 
    if (!sess_key)
      return (SHERR_KEYREVOKED);

    save.sh_expire = stamp;
    memcpy(&save.sh_sess, sess_key, sizeof(save.sh_sess));
    err = shpam_shadow_store(file, &save);
    shkey_free(&sess_key);
    if (err) {
      return (err);
}
  }

  if (expire_p)
    *expire_p = save.sh_expire;

  if (sess_p) {
    ret_key = (shkey_t *)calloc(1, sizeof(shkey_t));
    memcpy(ret_key, &save.sh_sess, sizeof(shkey_t));
    *sess_p = ret_key;
  }

  return (0);
}

int shpam_shadow_session_verify(shfs_ino_t *file, uint64_t uid, shkey_t *sess_key)
{
  shseed_t seed;
  shadow_t shadow;
  shkey_t sess_id;
  shkey_t pass_key;
  shtime_t sess_expire;
  int err;

  memset(&shadow, 0, sizeof(shadow));
  err = shpam_shadow_load(file, uid, &shadow);
  if (err)
    return (err);

  sess_expire = shadow.sh_expire;
  memcpy(&sess_id, &shadow.sh_id, sizeof(sess_id));

  memset(&seed, 0, sizeof(seed));
  err = shpam_pshadow_load(file, uid, &seed);
  if (err)
    return (err);

  _shpam_shadow_master_key(&seed, &pass_key);
  err = shpam_sess_verify(sess_key, &pass_key, sess_expire, &sess_id);
  if (err)
    return (err);

  return (0);
}

int shpam_shadow_session_set(shfs_ino_t *file, uint64_t uid, shkey_t *id_key, uint64_t sess_stamp, shkey_t *sess_key)
{
  shadow_t shadow;
  shseed_t save;
  shkey_t seed_key;
  int err;

  memset(&save, 0, sizeof(save));
  err = shpam_pshadow_load(file, uid, &save);
  if (err)
    return (err);

  _shpam_shadow_master_key(&save, &seed_key);
  err = shpam_sess_verify(sess_key, &seed_key, sess_stamp, id_key);
  if (err)
    return (err);

  err = shpam_shadow_load(file, uid, &shadow);
  if (err)
    return (err);

  if (!shkey_cmp(id_key, &shadow.sh_id))
    return (SHERR_INVAL);

  shadow.sh_expire = sess_stamp;
  memcpy(&shadow.sh_sess, sess_key, sizeof(shadow.sh_sess));
  err = shpam_shadow_store(file, &shadow);
  if (err)
    return (err);

  return (0);
}

int shpam_shadow_session_expire(shfs_ino_t *file, uint64_t uid, shkey_t *sess_key)
{
  shadow_t *ent;
  shadow_t save;
  int err;

  err = shpam_shadow_load(file, uid, &save);
  if (err)
    return (err);

  if (shtime_after(shtime(), save.sh_expire))
    return (SHERR_KEYEXPIRED);
  if (!shkey_cmp(&save.sh_sess, sess_key))
    return (SHERR_KEYREJECTED);

  save.sh_expire = 0;
  err = shpam_shadow_store(file, &save);
  if (err)
    return (err);

  return (0);
}

int shpam_shadow_login(shfs_ino_t *file, char *acc_name, char *acc_pass, shkey_t **sess_key_p)
{
  shadow_t v_shadow;
  shseed_t v_seed;
  uint64_t uid;
  int err;

  if (!file->tree)
    return (SHERR_INVAL);

  uid = shpam_uid(acc_name);

  if (uid != shpam_euid()) {
    err = shpam_pshadow_perm(file, SHPERM_VERIFY);
    if (err)
      return (err);
  }

  err = shpam_shadow_load(file, uid, &v_shadow);
  if (err)
    return (err);

  err = shpam_ident_verify(&v_shadow.sh_id, uid, &file->tree->peer); 
  if (err)
    return (err);

  memset(&v_seed, 0, sizeof(v_seed));
  err = shpam_pshadow_load(file, uid, &v_seed);
  if (err)
    return (err);

  err = shpam_auth_verify(&v_seed, acc_name, acc_pass, strlen(acc_pass));
  if (err) { 
    return (err);
  }

  err = shpam_shadow_session(file, &v_seed, sess_key_p, NULL);
  if (err) {
    return (err);
  }

  return (0);
}





int shpam_pshadow_2fa(shfs_ino_t *file, uint64_t uid, uint32_t *pin_p)
{
  shauth_t auth;
  char str[64];
  uint32_t pin;
  int err;

  memset(&auth, 0, sizeof(auth));
  err = shpam_pshadow_auth_load(file, uid, SHAUTH_SCOPE_2FA, &auth);
  if (err)
    return (err);

  memset(str, 0, sizeof(str));
  (void)shbase32_encode((unsigned char *)auth.auth_pub, 10, str, 16);

  pin = shsha_2fa(str);
  if (pin_p) 
    *pin_p = pin;
 
  return (0);
}

int shpam_pshadow_2fa_verify(shfs_ino_t *file, uint64_t uid, uint32_t pin)
{
  shauth_t auth;
  char str[64];
  int err;

  memset(&auth, 0, sizeof(auth));
  err = shpam_pshadow_auth_load(file, uid, SHAUTH_SCOPE_2FA, &auth);
  if (err)
    return (err);

  memset(str, 0, sizeof(str));
  (void)shbase32_encode((unsigned char *)auth.auth_pub, 10, str, 16);
  return (shsha_2fa_verify(str, pin));
}

#endif









static int _shpam_shadow_perm(shfs_ino_t *file, shpriv_t *priv, int perm);



static int _shpam_shadow_account_load(shfs_ino_t *file, uint64_t uid, shadow_t *ret_acc)
{
  shbuf_t *buff;
  shadow_t *accs;
  int total;
  int idx;
  int err;

  if (ret_acc)
    memset(ret_acc, 0, sizeof(shadow_t));

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err) {
    shbuf_free(&buff);
    //return (err);
    return (SHERR_NOENT); /* done */
  }

  accs = (shadow_t *)shbuf_data(buff);
  total = shbuf_size(buff) / sizeof(shadow_t);
  if (!total) {
    shbuf_free(&buff);
    return (SHERR_NOENT); /* done */
  }

  for (idx = 0; idx < total; idx++) {
    if (accs[idx].sh_uid == uid)
      break;
  }

  if (idx == total) {
    shbuf_free(&buff);
    return (SHERR_NOENT);
  }

  if (ret_acc) {
    shadow_t *acc = &accs[idx];
    memcpy(ret_acc, acc, sizeof(shadow_t));
  }

  shbuf_free(&buff);
  return (0);
}

static int _shpam_pshadow_load(shfs_ino_t *file, uint64_t uid, shseed_t *seed)
{
  shseed_t ret_seed;
  shkey_t *key;
  int err;

#if 0
  err = _shpam_shadow_perm(file, uid, SHPERM_READ);
  if (err)
    return (err);
#endif

  memset(&ret_seed, 0, sizeof(ret_seed));
  key = shkey_bin((char *)&uid, sizeof(uid));
  err = shfs_cred_load(file, key, (unsigned char *)&ret_seed, sizeof(ret_seed));
  shkey_free(&key);
  if (err)
    return (err);

  if (ret_seed.seed_expire != SHTIME_UNDEFINED &&
      shtime_after(shtime(), ret_seed.seed_expire)) {
    return (SHERR_KEYEXPIRED);
  }

  if (seed) {
    memcpy(seed, &ret_seed, sizeof(shseed_t));
  }

  memset(&ret_seed, 0, sizeof(ret_seed));
  return (0);
}


static int _shpam_pshadow_store(shfs_ino_t *file, uint64_t uid, shseed_t *seed)
{
  shkey_t *key;
  int err;

  if (!seed)
    return (SHERR_INVAL);

#if 0
  err = _shpam_shadow_perm(file, uid, SHPERM_WRITE);
  if (err)
    return (err);
#endif

  key = shkey_bin((char *)&uid, sizeof(uid));
  err = shfs_cred_store(file, key, (unsigned char *)seed, sizeof(shseed_t));
  shkey_free(&key);
  if (err)
    return (err);

  return (0);
}

static int _shpam_shadow_account_store(shfs_ino_t *file, uint64_t uid, shadow_t *acc)
{
  shbuf_t *buff;
  shadow_t *accs;
  int total;
  int idx;
  int err;

  if (!acc)
    return (SHERR_INVAL);

  buff = shbuf_init();
  (void)shfs_read(file, buff);

  accs = (shadow_t *)shbuf_data(buff);
  total = shbuf_size(buff) / sizeof(shadow_t);
  for (idx = 0; idx < total; idx++) {
    if (accs[idx].sh_uid == acc->sh_uid) {
      memcpy(&accs[idx], acc, sizeof(shadow_t));
      break;
    }
  }
  if (idx == total) {
    shbuf_cat(buff, acc, sizeof(shadow_t));
  }

  err = shfs_write(file, buff);
  shbuf_free(&buff);
  if (err)
    return (err);

  return (0);
}

static int _shpam_pshadow_remove(shfs_ino_t *file, uint64_t uid)
{
#if 0
  shkey_t *key;
  int err;

  key = shkey_bin((char *)&uid, sizeof(uid));
  err = shfs_cred_remove(file, key);
  shkey_free(&key);
  if (err)
    return (err);
#endif

  return (0);
}

static int _shpam_shadow_account_remove(shfs_ino_t *file, uint64_t rem_uid)
{
  shbuf_t *rbuff;
  shbuf_t *buff;
  shadow_t *accs;
  int total;
  int idx;
  int err;

  rbuff = shbuf_init();
  shfs_read(file, rbuff);

  buff = shbuf_init();
  accs = (shadow_t *)shbuf_data(rbuff);
  total = shbuf_size(rbuff) / sizeof(shadow_t);
  for (idx = 0; idx < total; idx++) {
    if (accs[idx].sh_uid == rem_uid)
      continue;

    shbuf_cat(buff, &accs[idx], sizeof(shadow_t));
  }
  shbuf_free(&rbuff);

  err = shfs_write(file, buff);
  shbuf_free(&buff);
  if (err)
    return (err);
  
  return (0);
}


static int _shpam_shadow_session(shfs_ino_t *file, uint64_t uid, shpriv_t *ret_priv)
{
  shseed_t seed;
  shkey_t seed_key;
  shkey_t *key;
  shkey_t *m_key;
  uint64_t val;
  uint32_t pin;
  int err;

  memset(&seed, 0, sizeof(seed));
  memset(&seed_key, 0, sizeof(seed_key));

  err = _shpam_pshadow_load(file, uid, &seed);
  if (err)
    return (err);

  if (ret_priv) {
    _shpam_shadow_master_key(&seed, &seed_key);
    pin = shsha_2fa_bin(SHALG_SHA256, &seed_key, sizeof(shkey_t), TIME_24_MIN);

    memset(ret_priv, 0, sizeof(shpriv_t));
    ret_priv->priv_uid = uid; 
    memcpy(&ret_priv->priv_sess, ashkey_num(pin), sizeof(shkey_t));
  }

  return (0);
}

static int _shpam_pshadow_create(shfs_ino_t *file, uint64_t uid)
{
  shseed_t seed;
  int err;

  memset(&seed, 0, sizeof(seed));

  err = shpam_auth_init(uid, &seed);
  if (err)
    return (err);


  if (uid == shpam_uid(NULL)) {
    /* administrative account default permissions */
    seed.seed_perm = SHPERM_ADMIN;
  } else {
    /* "regular user" default account permissions */
    seed.seed_perm |= SHPERM_READ;
    seed.seed_perm |= SHPERM_VERIFY;
  }

  return (_shpam_pshadow_store(file, uid, &seed));
}

static int _shpam_shadow_account_create(shfs_ino_t *file, char *acc_name)
{
  shadow_t shadow;
  uint64_t uid;

  memset(&shadow, 0, sizeof(shadow));
  shadow.sh_uid = shpam_uid(acc_name);
  if (acc_name)
    strncpy(shadow.sh_name, acc_name, sizeof(shadow.sh_name)-1); 

  return (_shpam_shadow_account_store(file, uid, &shadow));
}

static int _shpam_shadow_perm(shfs_ino_t *file, shpriv_t *priv, int perm)
{
  uint64_t priv_uid;
  shbuf_t *buff;
  shseed_t seed;
  int total;
  int idx;
  int err;


  if (!priv) {
    priv_uid = shpam_euid();
  } else {
    err = shpam_shadow_priv_verify(file, priv);
    if (err)
      return (err);

    priv_uid = priv->priv_uid;
  }

  if (shpam_euid() == priv_uid) {
    /* read and write of own account is guaranteed. */
    if ((perm & SHPERM_READ) || (perm & SHPERM_WRITE))
      return (0);
  }

  err = _shpam_pshadow_load(file, priv_uid, &seed);
  if (err == SHERR_NOENT) {
    /* no permissions granted when account does not exist. */
    return (SHERR_ACCESS);
  }
  if (err) {
    /* system error */
    return (err);
  }

  if (!(seed.seed_perm & perm)) {
    /* account contains no associatd permission. */
    return (SHERR_ACCESS);
  }

  return (0);
}



int shpam_shadow_create(shfs_ino_t *file, char *acc_name, shpriv_t *priv, shpriv_t **priv_p)
{
  shkey_t *key;
  uint64_t uid;
  int err;

  uid = shpam_uid(acc_name);

  if (uid != shpam_uid(NULL)) {
    if (!priv) {
      if (shpam_euid() != uid)
        return (SHERR_ACCESS);
    } else {
      err = _shpam_shadow_perm(file, priv, SHPERM_CREATE);
      if (err)
        return (err);
    }
  }


  err = shpam_shadow_uid_verify(file, uid);
  if (err == 0)
    return (SHERR_NOTUNIQ); /* This UID already exists. */
  if (err != SHERR_NOENT) {
    return (err);
}

  err = _shpam_pshadow_create(file, uid);
  if (err)
    return (err);

  err = _shpam_shadow_account_create(file, acc_name);
  if (err)
    return (err);

  if (priv_p) {
    shpriv_t *priv;

    priv = (shpriv_t *)calloc(1, sizeof(shpriv_t));
    if (!priv)
      return (SHERR_NOMEM);

    _shpam_shadow_session(file, uid, priv);

    *priv_p = priv;
  }
 
  return (0);
}


int shpam_shadow_login(shfs_ino_t *file, char *acc_name, uint32_t code_2fa, unsigned char *pass_data, size_t pass_len, shpriv_t **priv_p)
{
  shpriv_t ret_priv;
  shseed_t v_seed;
  uint64_t uid;
  int err;

  if (priv_p)
    *priv_p = NULL;

  if (!file->tree)
    return (SHERR_INVAL);

  uid = shpam_uid(acc_name);

  memset(&v_seed, 0, sizeof(v_seed));
  err = _shpam_pshadow_load(file, uid, &v_seed);
  if (err)
    return (err);

  err = shpam_auth_verify(&v_seed, acc_name, pass_data, pass_len);
  if (err)
    return (err);

  err = shpam_auth_2fa_verify(&v_seed, acc_name, code_2fa);
  if (err)
    return (err);

  _shpam_shadow_session(file, uid, &ret_priv);

  if (shpam_euid() != uid) {
    err = _shpam_shadow_perm(file, &ret_priv, SHPERM_VERIFY);
    if (err)
      return (err);
  }

  if (priv_p) {
    shpriv_t *priv;

    priv = (shpriv_t *)calloc(1, sizeof(shpriv_t));
    if (!priv)
      return (SHERR_NOMEM);

    memcpy(priv, &ret_priv, sizeof(shpriv_t));
    *priv_p = priv;
  }

  return (0);
}



int shpam_shadow_pass_set(shfs_ino_t *file, char *acc_name, shpriv_t *priv, unsigned char *pass_data, size_t pass_len)
{
  shseed_t seed;
  uint64_t uid;
  int err;

  uid = shpam_uid(acc_name);

  err = shpam_shadow_priv_verify(file, priv);
  if (err)
    return (err);

  memset(&seed, 0, sizeof(seed));
  err = _shpam_pshadow_load(file, uid, &seed);
  if (err)
    return (err);

  err = shpam_auth_set(&seed, acc_name, pass_data, pass_len); 
  if (err)
    return (err);

  err = _shpam_pshadow_store(file, uid, &seed);
  if (err)
    return (err);

  memset(&seed, 0, sizeof(seed));
  return (0);
}


int shpam_shadow_remove(shfs_ino_t *file, uint64_t uid, shpriv_t *priv)
{
  shseed_t seed;
  int err;

  err = _shpam_shadow_perm(file, priv, SHPERM_DELETE);
  if (err)
    return (err);

  memset(&seed, 0, sizeof(seed));
  err = _shpam_pshadow_load(file, uid, &seed);
  if (err)
    return (err);

#if 0
  err = shpam_auth_verify(&seed, acc_name, pass_data, pass_len);
  if (err)
    return (err);
#endif

  err = _shpam_pshadow_remove(file, uid);
  if (err)
    return (err);

  err = _shpam_shadow_account_remove(file, uid);
  if (err)
    return (err);

  return (0);
}

int shpam_shadow_set(shfs_ino_t *file, uint64_t uid, shpriv_t *priv, int cmd, unsigned char *raw, size_t raw_len)
{
  shadow_t shadow;
  int err;

  if (!priv) {
    if (shpam_euid() != uid)
      return (SHERR_ACCESS);
  } else {
    err = _shpam_shadow_perm(file, priv, SHPERM_WRITE);
    if (err)
      return (err);
  }

  memset(&shadow, 0, sizeof(shadow));
  err = _shpam_shadow_account_load(file, uid, &shadow); 
  if (err)
    return (err);

  switch (cmd) {
    case SHUSER_REALNAME:
      if (raw && raw_len) {
        memset(shadow.sh_name, 0, sizeof(shadow.sh_name));
        strncpy(shadow.sh_name, raw, sizeof(shadow.sh_name)-1);
      }
      break;
    case SHUSER_COINADDR:
      if (raw && raw_len) {
        memset(shadow.sh_sharecoin, 0, sizeof(shadow.sh_sharecoin));
        strncpy(shadow.sh_sharecoin, raw, sizeof(shadow.sh_sharecoin)-1);
      }
      break;
    case SHUSER_GEO:
      if (raw_len != sizeof(shgeo_t))
        return (SHERR_INVAL);
      if (raw && raw_len) {
        memcpy(&shadow.sh_geo, raw, sizeof(shgeo_t));
      }
      break;

    case SHUSER_CTIME:
      return (SHERR_OPNOTSUPP);

    default:
      return (SHERR_INVAL);
  }

  err = _shpam_shadow_account_store(file, uid, &shadow);
  if (err)
    return (err);

  return (0);
}

shtime_t shpam_shadow_ctime(shfs_ino_t *file, uint64_t uid)
{
  shseed_t seed;
  shtime_t stamp;
  shauth_t *auth;
  int err;
  int i;

  memset(&seed, 0, sizeof(seed));
  err = _shpam_pshadow_load(file, uid, &seed);
  if (err)
    return (SHTIME_UNDEFINED);

  stamp = seed.seed_stamp;
  for (i = 0; i < SHAUTH_MAX; i++) {
    auth = &seed.auth[i];
    if (auth->auth_stamp == SHTIME_UNDEFINED)
      continue; 

    if (shtime_before(auth->auth_stamp, stamp))
      stamp = auth->auth_stamp;
  }
  memset(&seed, 0, sizeof(seed));

  return (stamp);
}

int shpam_shadow_get(shfs_ino_t *file, uint64_t uid, int cmd, unsigned char *raw, size_t *raw_len_p)
{
  shadow_t shadow;
  shseed_t seed;
  shkey_t seed_key;
  shtime_t stamp;
  size_t len;
  int err;

#if 0
  err = _shpam_shadow_perm(file, uid, SHPERM_READ);
  if (err)
    return (err);
#endif

  len = *raw_len_p;
  memset(&shadow, 0, sizeof(shadow));
  err = _shpam_shadow_account_load(file, uid, &shadow); 
  if (err)
    return (err);

  switch (cmd) {
    case SHUSER_REALNAME:
      strncpy(raw, shadow.sh_name, len); 
      *raw_len_p = strlen(shadow.sh_name)+1;
      break;
    case SHUSER_COINADDR:
      strncpy(raw, shadow.sh_sharecoin, len); 
      *raw_len_p = strlen(shadow.sh_sharecoin)+1;
      break;
    case SHUSER_GEO:
      if (len < sizeof(shgeo_t))
        return (SHERR_INVAL);
      memcpy(raw, &shadow.sh_geo, sizeof(shgeo_t));
      *raw_len_p = sizeof(shgeo_t);
      break;
    case SHUSER_CTIME:
      stamp = shpam_shadow_ctime(file, uid);
      if (stamp == SHTIME_UNDEFINED)
        return (SHERR_ACCESS);
      memcpy(raw, &stamp, sizeof(stamp));
      *raw_len_p = sizeof(stamp);
      break;
    default:
      return (SHERR_INVAL);
  }

  return (0);

}

shjson_t *shpam_shadow_json(shfs_ino_t *file, uint64_t uid)
{
  shadow_t shadow;
  shjson_t *j;
  char uid_str[1024];
  char buf[256];
  shnum_t lat, lon;
  int err;

  err = _shpam_shadow_account_load(file, uid, &shadow);
  if (err)
    return (NULL);

  memset(uid_str, 0, sizeof(uid_str));
  snprintf(uid_str, sizeof(uid_str)-1, "id:%s", shadow.sh_name);

  j = shjson_init(NULL);
  shjson_str_add(j, "id", shadow.sh_name);
  shjson_num_add(j, "uid", shadow.sh_uid);
  if (shadow.sh_realname[0])
    shjson_str_add(j, "name", shadow.sh_realname);
  if (shadow.sh_sharecoin[0])
    shjson_str_add(j, "sharecoin", shadow.sh_sharecoin);

  shgeo_loc(&shadow.sh_geo, &lat, &lon, NULL);
  sprintf(buf, "%-5.5Lf,%-5.5Lf", lat, lon);
  if (0 != strcmp(buf, "00000,00000"))
    shjson_str_add(j, "geo", buf);

  return (j);
}


int shpam_shadow_uid_verify(shfs_ino_t *file, uint64_t uid)
{
  int err;

  err = _shpam_shadow_account_load(file, uid, NULL);
  if (err)
    return (err);
  
  err = _shpam_pshadow_load(file, uid, NULL);
  if (err)
    return (err);

  return (0);
}

int shpam_shadow_priv_verify(shfs_ino_t *file, shpriv_t *priv)
{
  shseed_t seed;
  shkey_t seed_key;
  shkey_t cmp_key;
  uint64_t uid;
  uint32_t pin;
  int err;

  if (!priv)
    return (SHERR_INVAL);

  uid = priv->priv_uid;

  memset(&seed, 0, sizeof(seed));
  err = _shpam_pshadow_load(file, uid, &seed);
  if (err)
    return (err);

#if 0
  if (seed.seed_expire != SHTIME_UNDEFINED) {
    if (shtime_after(shtime(), seed.seed_expire))
      return (SHERR_KEYEXPIRED);
  }
#endif

  _shpam_shadow_master_key(&seed, &seed_key);
  pin = shsha_2fa_bin(SHALG_SHA256, &seed_key, sizeof(shkey_t), TIME_24_MIN);
  memcpy(&cmp_key, ashkey_num(pin), sizeof(cmp_key));

  if (!shkey_cmp(&cmp_key, &priv->priv_sess))
    return (SHERR_KEYREJECTED);

  return (0);
}

int shpam_shadow_remote_set(shfs_ino_t *file, uint64_t uid, shauth_t *auth)
{
  shseed_t seed;
  int err;

  memset(&seed, 0, sizeof(seed));
  err = _shpam_pshadow_load(file, uid, &seed);
  if (err)
    return (err);

  err = shpam_auth_remote_set(&seed, uid, auth);
  if (err)
    return (err);

  err = _shpam_pshadow_store(file, uid, &seed);
  if (err)
    return (err);

  memset(&seed, 0, sizeof(seed));
  return (0);
}
 
int shpam_shadow_auth_load(shfs_ino_t *file, uint64_t uid, int scope, shauth_t *ret_auth)
{
  shseed_t seed;
  int err;

  if (scope < 0 || scope >= SHAUTH_MAX)
    return (SHERR_INVAL); 

  memset(&seed, 0, sizeof(seed));
  err = _shpam_pshadow_load(file, uid, &seed);
  if (err)
    return (err);

  if (ret_auth) {
    memcpy(ret_auth, &seed.auth[scope], sizeof(shauth_t));
  }

  memset(&seed, 0, sizeof(seed));
  return (0);
}


int shpam_shadow_admin_login(shfs_ino_t *file, unsigned char *pass_data, size_t pass_len, shpriv_t **priv_p)
{
  int err;

  err = shpam_shadow_login(file, NULL, 0, pass_data, pass_len, priv_p);
  if (err)
    return (err);

  return (0);
}

static int _shpam_shadow_admin_init(shfs_ino_t *file, shpriv_t **priv_p)
{
  shpriv_t *priv;
  size_t secret_len;
  uint64_t secret;
  int err;

  err = shpam_shadow_create(file, NULL, NULL, &priv);
  if (err)
    return (err);

  secret = SHMEM_MAGIC;
  secret_len = sizeof(secret);

  err = shpam_shadow_pass_set(file, NULL, priv, (unsigned char *)&secret, secret_len); 
  if (err)
    return (err);

  if (priv_p)
    *priv_p = priv;
  else
    free(priv);

  return (0);
}

shpriv_t *shpam_shadow_admin_default(shfs_ino_t *file)
{
  size_t secret_len;
  uint64_t secret;
  shpriv_t *priv;
  int err;

  secret = SHMEM_MAGIC;
  secret_len = sizeof(secret);

  priv = NULL;
  err = shpam_shadow_admin_login(file, 
      (unsigned char *)&secret, secret_len, &priv); /* "default" passcode */
  if (err == SHERR_NOENT) {
    err = _shpam_shadow_admin_init(file, &priv); /* create */
  }
  if (err)
    return (NULL);

  return (priv);
}





shpam_t *shpam_open(uint64_t uid)
{
  shpeer_t *peer;
	shkey_t *cur_ident;
	shkey_t *key;
	shpam_t *pam;

	pam = (shpam_t *)calloc(1, sizeof(shpam_t));
	if (!pam)
		return (NULL);

	pam->uid = uid;
	
	/* fs peer */
	peer = shpeer_init(PACKAGE, NULL);
	key = shpam_ident_gen(pam->uid, peer);
	memcpy(&pam->ident, key, sizeof(pam->ident));
	shpeer_free(&peer);
	shkey_free(&key);

	/* open fs */
	pam->fs = shfs_home_fs(&pam->ident);

	/* open file */
	pam->file = shfs_file_find(pam->fs, shfs_sys_dir(SHFS_DIR_PAM, "shadow"));

	/* authorization */
	cur_ident = shfs_access_owner_get(pam->file);
	if (!cur_ident) {
		shfs_access_owner_set(pam->file, &pam->ident);
	}

	return (pam);
}

shpam_t *shpam_open_name(char *acc_name)
{
	if (!acc_name)
		acc_name = (char *)get_libshare_account_name();
	return (shpam_open(shpam_uid(acc_name)));
}

void shpam_close(shpam_t **pam_p)
{
	shpam_t *pam;

	if (!pam_p)
		return;

	pam = *pam_p;
	*pam_p = NULL;

	shfs_free(&pam->fs);
	free(pam);
}

