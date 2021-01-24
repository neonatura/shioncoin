
/*
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
*/  

#include "share.h"
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

/**
 * @param flags Bitvector flags such as SHAPP_LOCAL.
 */
shpeer_t *shapp_init(char *exec_path, char *host, int flags)
{
  shpeer_t *peer;
  char *app_name;
  char hostbuf[MAXHOSTNAMELEN+1];
  char ebuf[4096];

  app_name = shfs_app_name(exec_path);
  peer = shpeer_init(app_name, NULL);
  if (!peer)
    return (NULL);
  shpeer_set_default(peer);

  if (!(flags & SHAPP_LOCAL)) {
    if (!host) {
      memset(hostbuf, 0, sizeof(hostbuf));
      gethostname(hostbuf, sizeof(hostbuf) - 1);
      if (gethostbyname(hostbuf) != NULL)
        host = hostbuf;
    }

    shpeer_t *priv_peer = shpeer_init(app_name, host);
    shapp_register(priv_peer);
    shpeer_free(&priv_peer);
  }

  if (0 != strcasecmp(app_name, PACKAGE)) {
#ifdef linux
    FILE *fl;
    char path[PATH_MAX+1];

    sprintf(path, "/var/run/%s.pid", app_name); 
    fl = fopen(path, "wb");
    if (fl) {
      fprintf(fl, "%u\n", (unsigned)getpid());
      fclose(fl);
    }
    chmod(path, 0777); /* allow other users to register same prog name */
/* DEBUG: TODO: remove file on exit in utils/daemons, provide easy wrapper func maybes */
#endif
  }

  if (!(flags & SHAPP_RLIMIT)) {
    shproc_rlim_set();
  }

#if 0
  sprintf(ebuf, "initialized '%s' as peer %s [max-fd %d]", exec_path, shpeer_print(peer), shproc_rlim(RLIMIT_NOFILE));
  shinfo(ebuf);
#endif

  return (peer);
}

int shapp_register(shpeer_t *peer)
{
  shbuf_t *buff;
  char data[256];
  size_t data_len;
  uint32_t mode;
  int qid;
  int err;

  if (!peer)
    peer = ashpeer();

  /* open message queue to share daemon */
  qid = shmsgget(NULL);
  if (qid < 0)
    return (qid);

  /* send a 'peer transaction' operation request. */
  mode = TX_APP;
  buff = shbuf_init();
  shbuf_cat(buff, &mode, sizeof(mode));
  shbuf_cat(buff, peer, sizeof(shpeer_t));
  err = shmsg_write(qid, buff, NULL);
  shbuf_free(&buff);
  if (err)
    return (err);

  /* close message queue */
  shmsgctl(qid, SHMSGF_RMID, TRUE);

  return (0);
}

int shapp_listen(int tx, shpeer_t *peer)
{
  shbuf_t *buff;
  uint32_t mode;
  uint32_t listen_tx;
  int qid;

  mode = TX_SUBSCRIBE;
  listen_tx = (uint32_t)tx;

  buff = shbuf_init();
  shbuf_cat(buff, &mode, sizeof(mode));
  shbuf_cat(buff, &listen_tx, sizeof(uint32_t));
  if (peer)
    shbuf_cat(buff, peer, sizeof(shpeer_t));

  /* open message queue to share daemon. */
  qid = shmsgget(NULL);
  shmsg_write(qid, buff, NULL);
  shbuf_free(&buff);
}


int shapp_ident(uint64_t uid, shkey_t **id_key_p)
{
  tx_id_msg_t m_id;
  shpeer_t *peer;
  shkey_t *id_key;
  shbuf_t *buff;
  uint32_t mode;
  int q_id;
  int err;

  if (id_key_p)
    *id_key_p = NULL;

  /* generate identity */
  peer = shpeer();
  id_key = shpam_ident_gen(uid, peer);
  if (!id_key) {
    shpeer_free(&peer);
    return (SHERR_INVAL);
  }

  memset(&m_id, 0, sizeof(m_id));
  m_id.id_uid = uid;
  memcpy(&m_id.id_key, id_key, sizeof(shkey_t)); /* for validation */
  memcpy(&m_id.id_peer, peer, sizeof(shpeer_t)); /* for validation */
  shpeer_free(&peer);

  /* notify server of identity. */
  mode = TX_IDENT;
  buff = shbuf_init();
  shbuf_cat(buff, &mode, sizeof(mode));
  shbuf_cat(buff, &m_id, sizeof(m_id));
  q_id = shmsgget(NULL);
  err = shmsg_write(q_id, buff, NULL);
  shbuf_free(&buff);
  if (err)
    return (err);

  if (id_key_p) {
    *id_key_p = id_key;
  } else {
    shkey_free(&id_key);
  }

  return (0);
}




shkey_t *shapp_kpriv(shpeer_t *peer)
{
  static shkey_t ret_key;
  unsigned char *raw;
  shec_t *ec;
  shkey_t *key;
  int err;

  ec = shec_init(SHALG_ECDSA160K);
  if (!ec)
    return (NULL);

  raw = (unsigned char *)shpeer_kpriv(peer) + sizeof(uint32_t);
  (void)shec_priv_gen(ec, raw, SHKEY_WORDS * sizeof(uint32_t));

  key = shec_priv_key(ec);
  shec_free(&ec);

  memcpy(&ret_key, key, sizeof(ret_key));
  shkey_free(&key);
  
  return (&ret_key);
}

shkey_t *shapp_kpub(shpeer_t *peer)
{
  static shkey_t ret_key;
  unsigned char *raw;
  shec_t *ec;
  shkey_t *key;
  int err;

  ec = shec_init(SHALG_ECDSA160K);
  if (!ec)
    return (NULL);

  raw = (unsigned char *)shpeer_kpriv(peer) + sizeof(uint32_t);
  (void)shec_priv_gen(ec, raw, SHKEY_WORDS * sizeof(uint32_t));

  shec_pub_gen(ec);
  key = shec_pub_key(ec);
  shec_free(&ec);

  memcpy(&ret_key, key, sizeof(ret_key));
  shkey_free(&key);
  
  return (&ret_key);
}












#if 0

int shapp_account_inform(int flag, shseed_t *seed)
{
  shbuf_t *buff;
  uint32_t mode;
  uint64_t uid;
  int qid;
  int err;

  if (!seed)
    return (SHERR_INVAL);

  uid = seed->seed_uid;

  /* notify server */
  mode = TX_ACCOUNT;
  buff = shbuf_init();
  shbuf_cat(buff, &mode, sizeof(uint32_t));
  shbuf_cat(buff, &uid, sizeof(uid));
  qid = shmsgget(NULL);
  err = shmsg_write(qid, buff, NULL);
  shbuf_free(&buff);
  if (err)
    return (err);

  return (0);
}

int shapp_account_create(char *acc_name, char *acc_pass, shkey_t **id_key_p)
{
  shfs_t *fs;
  shfs_ino_t *shadow_file;
  shbuf_t *buff;
  shkey_t *user_key;
  shseed_t acc_seed;
  shseed_t *seed;
  uint32_t mode;
  uint64_t salt;
  uint64_t uid;
  int qid;
  int err;

  uid = shpam_uid((char *)acc_name);

  fs = NULL;
  shadow_file = shpam_shadow_file(&fs);

  err = shpam_pshadow_load(shadow_file, uid, NULL);
  if (err != SHERR_NOENT) {
    shfs_free(&fs);
    return (SHERR_NOTUNIQ);
  }

  err = shpam_shadow_session_new(shadow_file, acc_name, acc_pass);
  if (err) {
    shfs_free(&fs);
    return (err);
  }
#if 0
  salt = shpam_salt();
  seed = shpam_pass_gen((char *)acc_name, acc_pass, salt);
  memcpy(&acc_seed, seed, sizeof(shseed_t));
  shpam_pshadow_store(shadow_file, &acc_seed); /* soft error */
#endif

  memset(&acc_seed, 0, sizeof(acc_seed));
  err = shpam_pshadow_load(shadow_file, uid, &acc_seed);
  shfs_free(&fs);
  if (err)
    return (err);

  err = shapp_account_inform(SHPAM_CREATE, &acc_seed);
  if (err)
    return (err);

  err = shapp_ident(uid, id_key_p);
  if (err)
    return (err);

#if 0
  /* cache pass as 'system' user preference. */
  shpref_set(SHPREF_ACC_SALT, shcrcstr(acc_seed.seed_salt));
  shpref_set(SHPREF_ACC_PASS, shkey_print(&acc_seed.seed_key));
#endif

  return (0);
}

int shapp_account_verify(char *acc_name, char *acc_pass)
{
  shfs_t *fs;
  shfs_ino_t *shadow_file;
  shbuf_t *buff;
  shkey_t *user_key;
  shseed_t acc_seed;
  shseed_t *seed;
  uint32_t mode;
  uint64_t salt;
  uint64_t uid;
  int qid;
  int err;

  uid = shpam_uid((char *)acc_name);

  fs = NULL;
  shadow_file = shpam_shadow_file(&fs);
  err = shpam_pshadow_load(shadow_file, uid, &acc_seed);
  shfs_free(&fs);
  if (err)
    return (err);

  err = shpam_auth_verify(&acc_seed, 
      (char *)acc_name, acc_pass, strlen(acc_pass));
  if (err)
    return (err);

  return (0);
}

#if 0
int shapp_account(const char *username, char *passphrase)
{
  shfs_t *fs;
  shfs_ino_t *shadow_file;
  shbuf_t *buff;
  shkey_t *user_key;
  tx_account_msg_t m_acc;
  shseed_t acc_seed;
  shseed_t *seed;
  uint32_t mode;
  uint64_t salt;
  uint64_t uid;
  int qid;
  int err;

  uid = shpam_uid((char *)username);
  fs = shfs_init(NULL);
  shadow_file = shpam_shadow_file(fs);
  seed = shpam_shadow_pass(shadow_file, uid);

  memset(&acc_seed, 0, sizeof(acc_seed));
  if (seed) {
    memcpy(&acc_seed, seed, sizeof(shseed_t));
    err = shpam_pass_verify(&acc_seed, (char *)username, passphrase);
    if (err) {
      shfs_free(&fs);
      return (err);
    }
  } else /* !seed */ {
    salt = shpam_salt();
    seed = shpam_pass_gen((char *)username, passphrase, salt);
    memcpy(&acc_seed, seed, sizeof(shseed_t));
    err = shpam_shadow_pass_gen(shadow_file, &acc_seed);
    if (err && err != SHERR_ACCESS) { /* server will have permission */
      shfs_free(&fs);
      return (err);
    }
  }
  shfs_free(&fs);

  memset(&m_acc, 0, sizeof(m_acc));
  memcpy(&m_acc.pam_seed, &acc_seed, sizeof(shseed_t)); 

  mode = TX_ACCOUNT;
  buff = shbuf_init();
  shbuf_cat(buff, &mode, sizeof(uint32_t));
  shbuf_cat(buff, &m_acc, sizeof(tx_account_msg_t));
  qid = shmsgget(NULL);
  err = shmsg_write(qid, buff, NULL);
  shbuf_free(&buff);
  if (err)
    return (err);

  if (seed_p) {
    shseed_t *ret_seed = (shseed_t *)calloc(1, sizeof(shseed_t));
    memcpy(ret_seed, seed, sizeof(shseed_t));
    *seed_p = ret_seed;
  }

  return (0);
}
#endif


int shapp_account_login(char *acc_name, char *acc_pass, shkey_t **sess_key_p)
{
  shfs_t *fs;
  shfs_ino_t *shadow_file;
  const shseed_t *seed_ptr;
  shseed_t seed;
  uint64_t uid;
  int err;

  if (sess_key_p)
    *sess_key_p = NULL;

  uid = shpam_uid(acc_name);

  fs = NULL;
  shadow_file = shpam_shadow_file(&fs);

  err = shpam_pshadow_load(shadow_file, uid, &seed);
  shfs_free(&fs);
  if (err)
    return (err);

  if (acc_pass) {
    err = shpam_auth_verify(&seed, (char *)acc_name, acc_pass, strlen(acc_pass)); 
    if (err)
      return (err);
  }

  err = shapp_session(&seed, sess_key_p);
  if (err)
    return (err);

  return (0);
}

int shapp_account_setpass(char *acc_name, char *opass, char *pass)
{
  char uname[MAX_SHARE_NAME_LENGTH];
  shfs_t *fs;
  shfs_ino_t *shadow_file;
  shkey_t *sess_key;
  shseed_t *raw_seed;
  shseed_t seed;
  uint64_t salt;
  uint64_t uid;
  int err;

  memset(uname, '\000', sizeof(uname));
  if (acc_name)
    strncpy(uname, acc_name, sizeof(uname)-1);
  uid = shpam_uid(uname);

  fs = NULL;
  shadow_file = shpam_shadow_file(&fs);
  err = shpam_shadow_login(shadow_file, uname, opass, &sess_key);
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  memset(&seed, 0, sizeof(seed));
  err = shpam_pshadow_load(shadow_file, uid, &seed);
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  err = shpam_auth_set(&seed, uname, pass, strlen(pass));
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  err = shpam_pshadow_set(shadow_file, &seed, sess_key);
  shkey_free(&sess_key);
  shfs_free(&fs);
  if (err)
    return (err);

#if 0
  /* cache pass as 'system' user preference. */
  shpref_set(SHPREF_ACC_SALT, shcrcstr(seed.seed_salt));
  shpref_set(SHPREF_ACC_PASS, shkey_print(&seed.seed_key));
#endif

  return (0);
}

int shapp_account_remove(char *acc_name, char *acc_pass)
{
  shfs_ino_t *shadow_file;
  shfs_t *fs;
  shkey_t *sess_key;
  uint64_t uid;
  int err;

  fs = NULL;
  shadow_file = shpam_shadow_file(&fs);
  err = shpam_shadow_login(shadow_file, acc_name, acc_pass, &sess_key);
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  uid = shpam_uid(acc_name);
  err = shpam_shadow_remove(shadow_file, uid, sess_key);
  shkey_free(&sess_key);
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  err = shpam_pshadow_remove(shadow_file, uid);
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  shfs_free(&fs);
  return (0);
}

int shapp_account_info(uint64_t uid, shadow_t *shadow, shseed_t *seed)
{
  static shadow_t ret_shadow;
  shfs_ino_t *shadow_file;
  shfs_t *fs;
  int err;
  
  fs = NULL;
  shadow_file = shpam_shadow_file(&fs);
  memset(&ret_shadow, 0, sizeof(ret_shadow));
  err = shpam_shadow_load(shadow_file, uid, &ret_shadow);
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  if (shadow) {
    memcpy(shadow, &ret_shadow, sizeof(shadow_t));
  }

  if (seed) {
    memset(seed, 0, sizeof(shseed_t));
    err = shpam_pshadow_load(shadow_file, uid, seed);
    if (err) {
      shfs_free(&fs);
      return (err);
    }
  }

  shfs_free(&fs);
  return (0);
}

shjson_t *shapp_account_json(shadow_t *shadow)
{
  shjson_t *j;
  char uid_str[1024];
  char buf[256];
  shnum_t lat, lon;
  uint64_t uid;

  if (!shadow)
    return (NULL);

  memset(uid_str, 0, sizeof(uid_str));
  sprintf(uid_str, sizeof(uid_str)-1, "id:%s", shadow->sh_name);

  j = shjson_init(NULL);
  shjson_str_add(j, "id", shadow->sh_name);
  shjson_num_add(j, "uid", shadow->sh_uid);
  if (shadow->sh_realname[0])
    shjson_str_add(j, "name", shadow->sh_realname); 
  if (shadow->sh_email[0])
    shjson_str_add(j, "email", shadow->sh_email);
  if (shadow->sh_sharecoin[0])
    shjson_str_add(j, "sharecoin", shadow->sh_sharecoin);

  shgeo_loc(&shadow->sh_geo, &lat, &lon, NULL);
  sprintf(buf, "%-5.5Lf,%-5.5Lf", lat, lon);
  if (0 != strcmp(buf, "00000,00000"))
    shjson_str_add(j, "geo", buf);

  return (j);
}

int shapp_account_set(char *acc_name, shkey_t *sess_key, shgeo_t *geo, char *rname, char *email, char *shc_addr)
{
  shfs_t *fs;
  shfs_ino_t *shadow_file;
  shadow_t shadow;
  uint64_t uid;
  int err;

  fs = NULL;
  shadow_file = shpam_shadow_file(&fs);

  uid = shpam_uid(acc_name);
  err = shpam_shadow_load(shadow_file, uid, &shadow);
  if (err)
    return (err);

  if (!shkey_cmp(&shadow.sh_sess, sess_key))
    return (SHERR_ACCESS);

  if (geo)
    memcpy(&shadow.sh_geo, geo, sizeof(shadow.sh_geo));
  if (rname)
    strncpy(shadow.sh_realname, rname, sizeof(shadow.sh_realname)-1);
  if (email)
    strncpy(shadow.sh_email, email, sizeof(shadow.sh_email)-1);
  if (shc_addr)
    strncpy(shadow.sh_sharecoin, shc_addr, sizeof(shadow.sh_sharecoin)-1);

  err = shpam_shadow_store(shadow_file, &shadow);
  shfs_free(&fs);
  if (err)
    return (err);

  return (0);
}
int shapp_session(shseed_t *seed, shkey_t **sess_key_p)
{
  shfs_t *fs;
  shfs_ino_t *shadow_file;
  tx_session_msg_t m_sess; 
  shadow_t shadow;
  shbuf_t *buff;
  shkey_t *seed_key;
  uint64_t stamp;
  uint32_t mode;
  int qid;
  int err;

  fs = NULL;
  shadow_file = shpam_shadow_file(&fs);

  memset(&shadow, 0, sizeof(shadow));
  err = shpam_shadow_load(shadow_file, seed->seed_uid, &shadow);
  if (err) {
    shfs_free(&fs);
    return (err);
  }

  /* apply session */
  err = shpam_shadow_session(shadow_file, seed, sess_key_p, &stamp); 
  shfs_free(&fs);
  if (err)
    return (err);

  /* inform shared */
  memset(&m_sess, 0, sizeof(m_sess));
  m_sess.sess_uid = seed->seed_uid;
  memcpy(&m_sess.sess_id, &shadow.sh_id, sizeof(shkey_t)); 
  m_sess.sess_stamp = stamp;

  mode = TX_SESSION;
  buff = shbuf_init();
  shbuf_cat(buff, &mode, sizeof(mode));
  shbuf_cat(buff, &m_sess, sizeof(m_sess));
  qid = shmsgget(NULL);
  err = shmsg_write(qid, buff, NULL);
  if (err)
    return (err);
  
  return (0);
}
shauth_t *shapp_root(void)
{
  static shauth_t ret_auth;
  const int scope = SHAUTH_SCOPE_LOCAL;
  shauth_t *auth;
  shfs_t *fs;
  shfs_ino_t *file; 
  shseed_t seed;
  uint64_t uid;
  int err;
  
  memset(&ret_auth, 0, sizeof(ret_auth));

  if (scope < 0 || scope >= SHAUTH_MAX)
    return (NULL); /* SHERR_INVAL */

  fs = NULL;
  file = shpam_shadow_file(&fs);
  if (!file)
    return (NULL);

  uid = shpam_uid("root");
  err = shpam_pshadow_load(file, uid, &seed);
  if (err) {
    err = shpam_pshadow_new(file, "root", "root");
    if (err) {
      shfs_free(&fs);
      return (NULL);
    }
  }

  auth = &seed.auth[scope];
  memcpy(&ret_auth, auth, sizeof(ret_auth));
  shfs_free(&fs);

  return (&ret_auth);
}

#endif
