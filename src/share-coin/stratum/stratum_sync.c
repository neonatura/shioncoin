
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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
#include "stratum/stratum.h"

#define THIRTY_SECONDS 30

static unsigned int _sync_req_idx;
static char errbuf[1024];

extern shjson_t *shjson_array_get(shjson_t *json, int index);


user_t *stratum_find_netid(shkey_t *netid, char *worker)
{
  user_t *user;

  if (!netid)
    return (FALSE);

  for (user = client_list; user; user = user->next) {
    if (worker && 0 != strcasecmp(user->worker, worker))
      continue;

    if (shkey_cmp(netid, &user->netid))
      return (user);

  }

  return (NULL);
}

/** Loads "stratum.dat" upon proess startup. */
void stratum_sync_init(void)
{
  struct sockaddr_in addr;
  user_t *sys_user;
  shbuf_t *buff;
  shkey_t *s_key;
  char path[PATH_MAX+1];
  char *key;
  char *raw;
  char *tok;
  int err;


  sprintf(path, "%s/blockchain/rpc.dat", get_libshare_path());
  chmod(path, 00400);

  buff = shbuf_init();
  err = shfs_mem_read(path, buff);
  if (!err) {
    raw = shbuf_data(buff);
    tok = strtok(raw, "\r\n");
    while (tok) {
      if (*tok == '#')
        goto next;

      key = strchr(tok, ' ');
      if (!key)
        goto next;

      *key = '\000';
      key++;

      if (unet_local_verify(tok)) {
        goto next;
      }

      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons((uint16_t)STRATUM_DAEMON_PORT);
      if (!inet_pton(AF_INET, tok, &addr.sin_addr)) {
        goto next;
      }

      sys_user = stratum_user_init(-1);
      strncpy(sys_user->worker, tok, sizeof(sys_user->worker) - 1);
//      strncpy(sys_user->pass, key, sizeof(sys_user->pass) - 1);
      sys_user->flags = USER_SYNC; /* overwrite client flags */
      sys_user->sync_flags |= SYNC_IDENT;

      /* unique network ident */
      s_key = shkey_bin((char *)&addr, sizeof(addr));
      memcpy(&sys_user->netid, s_key, sizeof(sys_user->netid));
      shkey_free(&s_key);

      sys_user->next = client_list;
      client_list = sys_user;

next:
      tok = strtok(NULL, "\r\n"); /* next */
    }
  }

  shbuf_free(&buff);
}

int stratum_sync_connect(user_t *user)
{
  struct sockaddr_in addr;
  int err;
  int fd;

  if (!user)
    return (SHERR_INVAL);

  if (user->fd > 0)
    return (0); /* done */

  /* connect to stratum service. */
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)STRATUM_DAEMON_PORT);
  err = inet_pton(AF_INET, user->worker, &addr.sin_addr);
  if (err == 0)
    return (SHERR_PROTO);
  if (err < 0)
    return (-errno); 
  
  err = unet_connect(UNET_STRATUM, (struct sockaddr *)&addr, &fd); 
  if (err < 0)
    return (err);

  if (err == 0) {
    user_t *cli_user;
    if ((cli_user = stratum_user_get(fd))) {
      cli_user->fd = -1;
    }

    user->fd = fd;
  }

  return (0);
}

static int stratum_sync_userlist_req(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  int err;

  if (!(user->flags & USER_SYNC))
    return (SHERR_INVAL);
  if (user->sync_flags & SYNC_RESP_ALL)
    return (SHERR_AGAIN);

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", user->sync_user);
  shjson_str_add(reply, "method", "mining.shares");
  data = shjson_array_add(reply, "params");
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err) {
    user->sync_flags |= SYNC_RESP_USER_LIST;
    sprintf(errbuf, "stratum_sync_cycle: info: requested mining userlist from '%s'.", user->worker);
  } else {
    sprintf(errbuf, "stratum_sync_cycle: error: mining userlist from '%s': %s.", user->worker, sherrstr(err));
  }
  shcoind_log(errbuf);

  return (err);
}

static int stratum_sync_elevate_req(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  shkey_t *skey;
  char lcl_auth[256];
  uint32_t lcl_pin;
  int err;

  if (!(user->flags & USER_SYNC)) {
    //error(SHERR_INVAL, "stratum_sync_elevate_req: user '%s' is not in SYNC mode.", user->worker);
    return (SHERR_INVAL);
  }

  if (user->sync_flags & SYNC_RESP_ALL)
    return (SHERR_AGAIN);

  skey = get_rpc_dat_password(NULL);
  if (!skey)
    return (SHERR_OPNOTSUPP);

  /* generate hash & pin */
  memset(lcl_auth, 0, sizeof(lcl_auth));
  shsha_hex(SHALG_SHA256, (unsigned char *)lcl_auth,
      (unsigned char *)skey, sizeof(shkey_t));
  lcl_pin = shsha_2fa_bin(SHALG_SHA256,
      (unsigned char *)skey, sizeof(shkey_t), RPC_AUTH_FREQ);

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", user->sync_addr);
  shjson_str_add(reply, "method", "stratum.elevate");
  data = shjson_array_add(reply, "params");
  shjson_str_add(data, NULL, lcl_auth);
  shjson_num_add(data, NULL, lcl_pin);
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err) {
    user->sync_flags |= SYNC_RESP_ELEVATE;
    sprintf(errbuf, "stratum_sync_cycle: info: requested RPC permission for account '%s'.", user->worker); 
  } else {
    sprintf(errbuf, "stratum_sync_cycle: error: RPC permission for account '%s': %s.", user->worker, sherrstr(err)); 
  }
  shcoind_log(errbuf);

  return (err);
}

static int stratum_sync_wallet_listaddr_req(user_t *user)
{
  CIface *iface;
  shjson_t *reply;
  shjson_t *data;
  char uname[512];
  uint32_t auth_pin;
  int err;

  iface = GetCoinByIndex(user->ifaceIndex);
  if (!iface || !iface->enabled)
    return (SHERR_OPNOTSUPP);

  if (!(user->flags & USER_SYNC))
    return (SHERR_INVAL);

  if (user->sync_flags & SYNC_RESP_ALL)
    return (SHERR_AGAIN);

  memset(uname, 0, sizeof(uname));
  strncpy(uname, user->sync_acc, sizeof(uname)-1);
  strtok(uname, ".");
  if (!uname[0])
    return (0); /* done */

  /* obtain current RPC authorization token */
  shkey_t *skey = get_rpc_dat_password(user->worker);
  if (!skey)
    return (SHERR_ACCESS);
  unsigned char auth_hash[512];
  shsha_hex(SHALG_SHA256, auth_hash,
      (unsigned char *)skey, sizeof(shkey_t));
  auth_pin = shsha_2fa_bin(SHALG_SHA256,
      (unsigned char *)skey, sizeof(shkey_t), RPC_AUTH_FREQ);
  shkey_free(&skey);

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", user->sync_addr);
  shjson_str_add(reply, "iface", iface->name);
  shjson_str_add(reply, "auth_hash", auth_hash);
  shjson_num_add(reply, "auth_pin", auth_pin);
  shjson_str_add(reply, "method", "wallet.listaddr");
  data = shjson_array_add(reply, "params");
  shjson_str_add(data, NULL, uname);
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err) {
    user->sync_flags |= SYNC_RESP_WALLET_ADDR;
    sprintf(errbuf, "stratum_sync_cycle: info: requested wallet list for account '%s'.", uname);
  } else {
    sprintf(errbuf, "stratum_sync_cycle: error: wallet list for account '%s': %s.", uname, sherrstr(err));
  }
  shcoind_log(errbuf);

  return (err);
}

static int stratum_sync_ping_req(user_t *user)
{
  shjson_t *reply;
  int req_id;
  int err;

  if (!(user->flags & USER_SYNC))
    return (SHERR_INVAL);
  if (user->flags & SYNC_RESP_ALL)
    return (SHERR_AGAIN);

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", (int)shrand());
  shjson_str_add(reply, "method", "mining.ping");
  shjson_array_add(reply, "params");
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err)
    user->sync_flags |= SYNC_RESP_PING;

  return (err);
}

static int stratum_sync_wallet_setkey_req(user_t *user)
{
  CIface *iface;
  shjson_t *reply;
  shjson_t *param;
  char privkey[256];
  uint32_t auth_pin;
  int err;

  iface = GetCoinByIndex(user->ifaceIndex);
  if (!iface || !iface->enabled)
    return (SHERR_OPNOTSUPP);

  if (!user)
    return (SHERR_INVAL);

  if (!(user->flags & USER_SYNC))
    return (SHERR_INVAL);

  if (!user->sync_acc[0] || !user->sync_pubkey[0])
    return (0); /* done */

  memset(privkey, 0, sizeof(privkey));
  err = stratum_getaddrkey(user->ifaceIndex,
      user->sync_acc, user->sync_pubkey, privkey);
  if (err)
    return (err);

  /* obtain current RPC authorization token */
  shkey_t *skey = get_rpc_dat_password(user->worker);
  if (!skey)
    return (SHERR_OPNOTSUPP);
  unsigned char auth_hash[512];
  shsha_hex(SHALG_SHA256, auth_hash,
      (unsigned char *)skey, sizeof(shkey_t));
  auth_pin = shsha_2fa_bin(SHALG_SHA256,
      (unsigned char *)skey, sizeof(shkey_t), RPC_AUTH_FREQ);
  shkey_free(&skey);

  /* send 'wallet.setkey' message. */
  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", user->sync_addr);
  shjson_str_add(reply, "iface", iface->name);
  shjson_str_add(reply, "auth_hash", auth_hash);
  shjson_num_add(reply, "auth_pin", auth_pin);
  shjson_str_add(reply, "method", "wallet.setkey");
  param = shjson_array_add(reply, "params");
  shjson_str_add(param, NULL, privkey);
  shjson_str_add(param, NULL, user->sync_acc);
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err) {
    user->sync_flags |= SYNC_RESP_WALLET_SET;
    sprintf(errbuf, "stratum_sync_wallet_setkey_req [iface #%d]: info: sent new key (<%d bytes>) for account '%s'.", user->ifaceIndex, strlen(privkey), user->sync_acc);
  } else {
    sprintf(errbuf, "stratum_sync_wallet_setkey_req [iface #%d]: error: send new key (<%d bytes>) for account '%s': %s", err, user->ifaceIndex, strlen(privkey), user->sync_acc, sherrstr(err));
  }
  shcoind_log(errbuf);

  return (err);
}

static int stratum_sync_ident_req(user_t *user)
{
  CIface *iface;
  shjson_t *reply;
  shjson_t *param;
  int err;

  if (!user)
    return (SHERR_INVAL);

  if (!(user->flags & USER_SYNC)) {
    //error(SHERR_INVAL, "stratum_sync_ident_req: user '%s' is not in SYNC mode.", user->worker);
    return (SHERR_INVAL);
  }

  /* send 'wallet.setkey' message. */
  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", MAX(1, user->work_stamp));
  shjson_str_add(reply, "iface", iface->name);
  shjson_str_add(reply, "method", "stratum.authorize");
  param = shjson_array_add(reply, "params");
  shjson_str_add(param, NULL, (char *)unet_local_host());
  shjson_str_add(param, NULL, "");
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err)
    user->sync_flags |= SYNC_RESP_IDENT;

  return (err);
}



void stratum_sync_cycle(CIface *iface, user_t *user)
{
  user_t *r_user;
  time_t now;
  int err;

  if (!(user->flags & USER_SYNC))
    return; /* invalid */

#if 0
  if (!(user->sync_flags & SYNC_AUTH)) {
    /* send 'stratum.elevate' stratum command to remote system. */
    return;
  }
#endif
  
  if (user->sync_flags & SYNC_RESP_ALL) {
    return; /* busy waiting for response */
  }

  if (user->sync_flags & SYNC_IDENT) {
    stratum_sync_ident_req(user); 
    user->sync_flags &= ~SYNC_IDENT;
    return;
  }

  now = time(NULL);

  if (user->sync_flags & SYNC_AUTH) {
    if (user->sync_flags & SYNC_WALLET_SET) {
      /* notify */
      stratum_sync_wallet_setkey_req(user);
      /* reset */
      memset(user->sync_acc, 0, sizeof(user->sync_acc));
      memset(user->sync_pubkey, 0, sizeof(user->sync_pubkey));
      /* set next stage */
      user->sync_flags &= ~SYNC_WALLET_SET;
    } else if (user->sync_flags & SYNC_WALLET_ADDR) {
      /* user has been elevated -- perform 'wallet.listaddr' rpc command */
      stratum_sync_wallet_listaddr_req(user);
      /* set next stage. */
      user->sync_flags &= ~SYNC_WALLET_ADDR;
    } else { 
      /* clear perms incase no command was sent. */
      (void)stratum_sync_ping_req(user);
    }

    /* rpc permission has been revoked. */
    user->sync_flags &= ~SYNC_AUTH;
    return;
  }

  if ( /* !SYNC_AUTH */ user->sync_addr < (now - THIRTY_SECONDS)) {
    user->sync_addr = time(NULL); /* must be set first */

    if (user->sync_flags & SYNC_WALLET_ADDR) {
      /* wallet sync */
      stratum_sync_elevate_req(user);
      return;
    }
    if (user->sync_flags & SYNC_WALLET_SET) {
      /* wallet sync */
      stratum_sync_elevate_req(user);
      return;
    }
  }


  if (user->sync_user < (now - THIRTY_SECONDS)) {
    /* request current mining statistics */
    user->sync_user = time(NULL);
    stratum_sync_userlist_req(user);
    return;
  }

}

void stratum_sync(void)
{
  static int _index;
  struct sockaddr_in addr;
  shjson_t *data;
  user_t *user;
  char acc_name[256];
  char acc_key[256];
  int ifaceIndex;
  int err;
  int idx;
  int fd;
time_t expire;
user_t *u_next;

  expire = (time(NULL) - THIRTY_SECONDS);

  _sync_req_idx++;
  ifaceIndex = (_sync_req_idx % MAX_COIN_IFACE);
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled)
    return;

  for (user = client_list; user; user = user->next) {
    if (!(user->flags & USER_SYNC))
      continue;
    if (expire < user->work_stamp)
      continue;

    if (user->fd <= 0)
      stratum_sync_connect(user);
    if (user->fd <= 0)
      continue;

    stratum_sync_cycle(iface, user);
    user->work_stamp = time(NULL);
  }

}

int stratum_sync_userlist_resp(user_t *user, shjson_t *tree)
{
  shjson_t *result;
  shjson_t *node;
  shjson_t *udata;
  shkey_t net_id;
  shkey_t *key;
  user_t *r_user;
  double btot;
  char worker[640];
  char cli_ver[64];
  char id_hex[64];
  char *text;
  unsigned int n_a, n_b, n_c, n_d;
  uint32_t rem_crc;
  uint32_t crc;
  int ar_max;
  int i, j;

  result = shjson_obj_get(tree, "result");
  if (!result)
    return (SHERR_PROTO);

  ar_max = shjson_array_count(result, NULL);
  if (ar_max < 1)
    return (SHERR_PROTO);

  for (i = 0; i < ar_max; i++) {
    node = shjson_array_get(result, i);
    if (!node)
      break; /* ?? */

    /* user->worker */
    memset(worker, 0, sizeof(worker));
    text = shjson_array_astr(node, NULL, 0);
    if (text) strncpy(worker, text, sizeof(worker)-1);
    if (!*worker) {
      /* not registered miner */ 
      continue; 
    }

    if (4 == sscanf(worker, "%u.%u.%u.%u", &n_a, &n_b, &n_c, &n_d)) {
      /* skip users with IP address as name (todo: ipv6 format). */
      continue;
    }

#if 0
/* dont need to be a miner, or mining, to perform tx ops */
    btot = shjson_array_num(node, NULL, 4);
    if (btot < 0.0001) {
      continue; /* no mining contribution */
    }
#endif

    /* user->netid */
    memset(id_hex, 0, sizeof(id_hex));
    text = shjson_array_astr(node, NULL, 11);
    if (text) strncpy(id_hex, text, sizeof(id_hex)-1);
    key = shkey_gen(id_hex); 
    if (!key)
      continue; /* invalid rpc.dat format */
    memcpy(&net_id, key, sizeof(net_id));
    shkey_free(&key);

    r_user = stratum_find_netid(&net_id, worker);
    if (r_user) {
      if ((r_user->flags & USER_SYSTEM))
        continue;
      if ((r_user->flags & USER_SYNC))
        continue;
      if (r_user && !(r_user->flags & USER_REMOTE)) {
fprintf(stderr, "DEBUG: stratum_sync_userlist_resp: skipping \"%s\" due to netid not being USER_REMOTE [found username \"%s\"]\n", worker, r_user->worker);
        continue; /* already registered */
      }
    }

    if (!r_user) {
      r_user = stratum_user_init(-1);
      if (!r_user) {
        sprintf(errbuf, "stratum_sync_userlist_resp: error generating new stratum [remote] user.");
        shcoind_log(errbuf);
        return (SHERR_NOMEM);
      }
fprintf(stderr, "DEBUG: stratum_sync_userlist_resp: creating new remote stratum user '%s'\n", worker); 

      memcpy(&r_user->netid, &net_id, sizeof(user->netid));
      r_user->flags = USER_REMOTE; /* sync'd reward stats */
      r_user->next = client_list;
      client_list = r_user;
    }

    /* user->cli_ver */
    memset(cli_ver, 0, sizeof(cli_ver));
    text = shjson_array_astr(node, NULL, 8);
    if (text) strncpy(cli_ver, text, sizeof(cli_ver)-1);

    /* over-ride in case miner authorizes new worker name */
    strncpy(r_user->worker, worker, sizeof(r_user->worker) - 1);

    /* client version (i.e. bfgminer x.x) */
    strncpy(r_user->cli_ver, cli_ver, sizeof(r_user->cli_ver)-1);

    r_user->block_cnt = 1;
    r_user->block_tot = btot; /* remote avg */
//    r_user->round_stamp = (time_t)shjson_array_num(node, NULL, 1);
//    r_user->block_cnt = (size_t)shjson_array_num(node, NULL, 2);
    r_user->work_diff = (int)shjson_array_num(node, NULL, 5);

    /* normal addr crc */
    udata = shjson_array_get(node, 12);
    if (udata) {
      for (j = 1; j < MAX_COIN_IFACE; j++) {
        CIface *iface = GetCoinByIndex(j);
        if (!iface || !iface->enabled) continue;

        rem_crc = (int)shjson_array_num(udata, NULL, j - 1);
        crc = stratum_addr_crc(j, worker);
        if (crc && crc != rem_crc) {
          /* set user account & iface to synchronize */
          user->ifaceIndex = j;
          memset(user->sync_acc, 0, sizeof(user->sync_acc));
          strncpy(user->sync_acc, r_user->worker, sizeof(user->sync_acc)-1);
          strtok(user->sync_acc, ".");
          user->sync_flags |= SYNC_WALLET_ADDR;

          sprintf(errbuf, "stratum_sync_walletlist_resp[iface #%d]: wallet synchronization required for account \"%s\" [rem-acc: %s].", user->ifaceIndex, user->worker, (rem_crc != 0) ? "true" : "false");
          shcoind_log(errbuf);
          break;
        }
      }
    }

    /* ext addr crc */
    udata = shjson_array_get(node, 13);
    if (udata) {
      for (j = 1; j < MAX_COIN_IFACE; j++) {
        CIface *iface = GetCoinByIndex(j);
        if (!iface || !iface->enabled) continue;

        rem_crc = (int)shjson_array_num(udata, NULL, j - 1);
        crc = stratum_ext_addr_crc(j, worker);
        if (crc && crc != rem_crc) {
#if 0 /* DEBUG: TODO: */
          user->ifaceIndex = j;
          memset(user->sync_acc, 0, sizeof(user->sync_acc));
          strncpy(user->sync_acc, r_user->worker, sizeof(user->sync_acc)-1);
          strtok(user->sync_acc, ".");
          user->sync_flags |= SYNC_WALLET_EXTADDR;
#endif
          break;
        }
      }
    }

  }

  return (0);
}

/* do not free return array */
static char **_pub_addr_list(int ifaceIndex, char *acc_name_in)
{
  static char **ret_list;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  shjson_t *tree;
  shjson_t *node;
  const char *text;
  char acc_name[512];
  char *str;
  int ar_max;
  int i, j;

  if (!iface || !iface->enabled)
    return (NULL);

  if (ret_list) {
    for (i = 0; ret_list[i]; i++) {
      free(ret_list[i]);
    }
    free(ret_list);
  }

  memset(acc_name, 0, sizeof(acc_name));
  strncpy(acc_name, acc_name_in, sizeof(acc_name)-1);
  strtok(acc_name, ".");

  text = stratum_getaccountinfo(ifaceIndex, acc_name, NULL);
  if (!text) return (NULL);
  tree = shjson_init((char *)text);
  if (!tree) return (NULL);

  node = shjson_obj_get(tree, "result");
  node = shjson_obj_get(node, "addresses");
  if (!node) {
    shjson_free(&tree);
    return (NULL);
  }

  ar_max = shjson_array_count(node, NULL);
  if (ar_max <= 0) {
    shjson_free(&tree);
    return (NULL);
  }
  
  ret_list = (char **)calloc(ar_max+1, sizeof(char *));
  if (!ret_list) {
    shjson_free(&tree);
    return (NULL);
  }

  j = -1;
  for (i = 0; i < ar_max; i++) {
    shjson_t *t_node = shjson_array_get(node, i);
    str = shjson_astr(t_node, "coin", "");
    if (!str || 0 != strcasecmp(str, iface->name))
      continue; /* wrong coin interface */
    str = shjson_astr(t_node, "address", "");
    if (!str || !*str)
      continue;

    ret_list[++j] = strdup(str);
  }

  shjson_free(&tree);
  return (ret_list);
}

int stratum_sync_walletlist_resp(user_t *user, shjson_t *tree)
{
  shjson_t *result;
  shkey_t *key;
  char **pub_addrs;
  char *text;
  int err_code;
  int ar_max;
  int err;
  int i, j;

  err_code = shjson_array_num(tree, "error", 0);

  if (err_code && err_code != SHERR_NOENT) {
    sprintf(errbuf, "stratum_sync_walletlist_resp: remote RPC operation \"wallet.listaddr\" for account \"%s\": %s [sherr %d].", user->sync_acc, sherrstr(err_code), err);
    shcoind_log(errbuf);
    return (err_code);
  }

  ar_max = 0;
  if (!err_code) {
    result = shjson_obj_get(tree, "result");
    if (!result)
      return (SHERR_PROTO);

    ar_max = shjson_array_count(result, NULL);
  }

  pub_addrs = _pub_addr_list(user->ifaceIndex, user->sync_acc);
  if (!pub_addrs)
    return (0); /* done */

  for (i = 0; pub_addrs[i]; i++) {
    for (j = 0; j < ar_max; j++) {
      text = shjson_array_astr(result, NULL, j);
      if (text && 0 == strcmp(text, pub_addrs[i]))
        break;
    }
    if (j == ar_max) {
      /* remote host is not aware of local pub addr */
      memset(user->sync_pubkey, 0, sizeof(user->sync_pubkey));
      strncpy(user->sync_pubkey, pub_addrs[i], sizeof(user->sync_pubkey)-1);
      user->sync_flags |= SYNC_WALLET_SET;
      break;
    }
  }

  return (0);
}

/* interpretates a stratum/rpc response from past request */
int stratum_sync_resp(user_t *user, shjson_t *tree)
{
  char *method;
  char errbuf[512];
  int err;

  if (user->sync_flags & SYNC_RESP_IDENT) {
    user->sync_flags &= ~SYNC_RESP_IDENT;
    return (0);
  }

  if (user->sync_flags & SYNC_RESP_ELEVATE) {
    if (shjson_array_num(tree, "error", 0) != 0) {
      {
        char *text = shjson_print(tree); 
        fprintf(stderr, "DEBUG: stratum_sync_resp: SYNC_RESP_ELEVATE: %s\n", text); 
        free(text);
      }
fprintf(stderr, "DEBUG: stratum_sync_resp: SYNC_RESP_ELEVATE: detected error -- canceling wallet modes.\n");
      /* remove wallet modes */
      user->sync_flags &= ~SYNC_WALLET_ADDR;
      user->sync_flags &= ~SYNC_WALLET_SET; 
    } else {
      /* user is now authorized to perform a RPC command */
      user->sync_flags |= SYNC_AUTH;
    }

    user->sync_flags &= ~SYNC_RESP_ELEVATE;
    return (0);
  }

  if (user->sync_flags & SYNC_RESP_USER_LIST) {
    /* remove request flag */
    user->sync_flags &= ~SYNC_RESP_USER_LIST;

    /* this is a response to a stratum 'mining.shares' request */
    err = stratum_sync_userlist_resp(user, tree);
    if (err) {
      sprintf(errbuf, "stratum_sync_resp: SYNC_RESP_WALLET_ADDR: error processing stratum response: %s.", sherrstr(err));
      shcoind_log(errbuf);
    }
    return (err);
  }

  if (user->sync_flags & SYNC_RESP_WALLET_ADDR) {
    /* remove request flag */
    user->sync_flags &= ~SYNC_RESP_WALLET_ADDR;

    /* this is a response to a rpc 'wallet.list' request. */
    err = stratum_sync_walletlist_resp(user, tree);
    if (err) {
      sprintf(errbuf, "stratum_sync_resp: SYNC_RESP_WALLET_ADDR: error processing stratum response: %s.", sherrstr(err));
      shcoind_log(errbuf);
    }
    return (err);
  }

  if (user->sync_flags & SYNC_RESP_WALLET_SET) {
    err = shjson_array_num(tree, "error", 0);
    if (err) {
      { /* DEBUG: TEST: remove me*/
        char *text = shjson_print(tree); 
fprintf(stderr, "DEBUG: stratum_sync_resp: SYNC_RESP_WALLET_SET: %s\n", text); 
        free(text);
      }

      sprintf(errbuf, "stratum_sync_resp: SYNC_RESP_WALLET_SET: error setting private key: %s [sherr %d].", sherrstr(err), err); 
      shcoind_log(errbuf);
    }

    /* remove request flag */
    user->sync_flags &= ~SYNC_RESP_WALLET_SET;
    return (0);
  }

  /* must be last */
  if (user->sync_flags & SYNC_RESP_PING) {
    /* confirmed remote server is responsive. */
    user->sync_flags &= ~SYNC_RESP_PING;
    return (0);
  }

  method = shjson_astr(tree, "method", NULL);
  if (method && *method && 0 != strcmp(method, "null")) {
    if (0 == strcmp(method, "client.get_version")) {
      /* send back version.. */
    } else {
      sprintf(errbuf, "stratum_sync_resp: SYNC_RESP: unknown method \"%s\".", method);
      shcoind_log(errbuf);
    }
    return (0);
  }


  { /* DEBUG: */
    char *text = shjson_print(tree); 
fprintf(stderr, "DEBUG: stratum_sync_resp: SYNC_RESP[unknown response]: %s\n", text); 
    free(text);
  }

  return (0); /* ignore everything else */
}

/**
 * Receive a JSON request/response on a SYNC socket
 */
int stratum_sync_recv(user_t *peer, char *json_text)
{
  shjson_t *j;
  shjson_t *param;
  int err;

  j = stratum_json(json_text);
  if (!j)
    return (SHERR_PROTO);

  param = shjson_obj_get(j, "params");
  if (param != NULL) {
    /* this is an incoming request. */
    shjson_free(&j);
    return (stratum_register_client_task(peer, json_text));
  }

  err = stratum_sync_resp(peer, j);
  shjson_free(&j);

  return (err);
}









