
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
 *
 *  This file is part of ShionCoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcoind.h"
#include "unet/unet.h"
#include "stratum/stratum.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CRED_SECRET_LEN 28

#define MAX_RPC_MESSAGE_SIZE 16000000 /* 16m */

user_t *rpc_client_list;

extern user_t *stratum_user_init(int fd);
extern int stratum_register_client_task(user_t *user, char *json_text);

static const char *rpc_dat_path(void)
{
	static char ret_path[PATH_MAX+1];
	const char *path;

	memset(ret_path, 0, sizeof(ret_path));

	path = (const char *)opt_str(OPT_RPC_MAP);
	if (!path || !*path) {
		path = get_shioncoin_path();
		snprintf(ret_path, sizeof(ret_path)-1, "%sblockchain/rpc.dat", path);
	} else {
		strncpy(ret_path, path, sizeof(ret_path)-1);
	}

	return ((const char *)ret_path);
}

void get_rpc_cred(char *username, char *password)
{
  char *in_name = (char *)get_rpc_username();
  char *in_pass = (char *)get_rpc_password(NULL); 
  int err;

  if (!in_pass) {
    /* generate new key for local use */
    shkey_t *key = shkey_uniq();
    err = set_rpc_dat_password(NULL, key);
    shkey_free(&key);
    if (err) {
      char buf[256];
      sprintf(buf, "warning: get_rpc_cred: !set_rpc_dat_password (%d)\n", err);
      shcoind_log(buf);
    }

    in_pass = shkey_print(key);
  }

  strcpy(username, in_name);
  strcpy(password, in_pass);

}

const char *get_rpc_username(void)
{
  static char uname[MAX_SHARE_NAME_LENGTH];
  shpeer_t *peer;

  peer = shpeer_init("shcoind", NULL);

  /* the EC224-PUBKEY of the priveleged peer key */
  strcpy(uname, shkey_print(shapp_kpriv(peer)));

  shpeer_free(&peer);

  return (uname);
}

const char *get_rpc_password(char *host)
{
  static char ret_str[256];
  shkey_t *key;

  key = get_rpc_dat_password(host);
  if (!key)
    return (NULL);

  memset(ret_str, 0, sizeof(ret_str));
  strncpy(ret_str, shkey_print(key), sizeof(ret_str)-1);
  shkey_free(&key);

  return (ret_str);
}

shkey_t *get_rpc_dat_password(char *host)
{
  shkey_t *key;
  shbuf_t *buff;
  char *tok_ctx;
  char *raw;
  char *key_str;
  char *tok;
  int err;

  if (!host)
    host = "127.0.0.1";

  buff = shbuf_init();
  err = shfs_mem_read(rpc_dat_path(), buff);
  if (!err) {
    raw = shbuf_data(buff);
    tok = strtok_r(raw, "\r\n", &tok_ctx);
    while (tok) {
      key_str = strchr(tok, ' ');
      if (key_str) {
        *key_str = '\000';
        key_str++;

        if (0 == strcmp(host, "127.0.0.1") &&
            unet_local_verify(tok)) {
          key = shkey_gen(key_str);         
          shbuf_free(&buff);
          return (key);
        }

        if (0 == strcasecmp(host, tok)) {
          key = shkey_gen(key_str);         
          shbuf_free(&buff);
          return (key);
        }
      }

      tok = strtok_r(NULL, "\r\n", &tok_ctx);
    }
  }

  shbuf_free(&buff);
  return (NULL);
}

int set_rpc_dat_password(char *host, shkey_t *in_key)
{
  shkey_t *key;
  shbuf_t *buff;
  shbuf_t *w_buff;
	const char *path;
  char *raw;
  char *key_str;
  char *tok;
	int first;
  int err;

  if (!host)
    host = "127.0.0.1";


  w_buff = shbuf_init();
  shbuf_catstr(w_buff, "## Automatically Generated (do not modify) ##\n\n");

	first = FALSE;
  buff = shbuf_init();
	path = rpc_dat_path(); 
  err = shfs_mem_read(path, buff);
  if (!err) {
    raw = shbuf_data(buff);
    tok = strtok(raw, "\r\n");
    while (tok) {
      if (!*tok || *tok == '#')
        continue;

      key_str = strchr(tok, ' ');
      if (!key_str)
        goto next;

      *key_str = '\000';
      key_str++;

      if (0 == strcmp(host, "127.0.0.1") &&
          unet_local_verify(tok))
        goto next;

      if (0 == strcasecmp(host, tok))
        goto next;

      shbuf_catstr(w_buff, tok);
      shbuf_catstr(w_buff, " ");
      shbuf_catstr(w_buff, key_str);
      shbuf_catstr(w_buff, "\n");

  next:
      tok = strtok(NULL, "\r\n");
    }
    shbuf_free(&buff);
  } else {
		first = TRUE;
	}

  /* add updated record */
  shbuf_catstr(w_buff, host);
  shbuf_catstr(w_buff, " ");
  shbuf_catstr(w_buff, shkey_print(in_key));
  shbuf_catstr(w_buff, "\n");

  err = shfs_mem_write(path, w_buff);
  if (err)
    return (err);

	if (first) {
		/* owner-only / read-only */ 
		(void)chmod(path, 00400);
	}
  
  shbuf_free(&w_buff);

  return (0);
}

#define FIVE_MINUTES 300
uint32_t get_rpc_pin(char *host)
{
  unsigned char *raw;
  shkey_t *key;
  uint32_t ret_pin;

  key = get_rpc_dat_password(host);
  if (!key)
    return (0);

  raw = ((unsigned char *)key) + sizeof(uint32_t);
  ret_pin = shsha_2fa_bin(SHALG_SHA224, raw, CRED_SECRET_LEN, FIVE_MINUTES);
  shkey_free(&key);
  if (ret_pin == 0)
    return (0);

  return (ret_pin);
}

int verify_rpc_pin(char *host, uint32_t pin)
{
  unsigned char *raw;
  shkey_t *key;
  int err;

  key = get_rpc_dat_password(host);
  if (!key)
    return (SHERR_NOENT); 

  raw = ((unsigned char *)key) + sizeof(uint32_t);
  err = shsha_2fa_bin_verify(SHALG_SHA224, 
      raw, CRED_SECRET_LEN, FIVE_MINUTES, pin);
  shkey_free(&key);

  return (err);
}

int get_rpc_service_port(void)
{
  return ((int)opt_num(OPT_RPC_PORT));
}

const char *get_rpc_service_host(void)
{
	char *val;

	val = opt_str(OPT_RPC_HOST);
	if (val && *val == '*')
		val = NULL;

	return (val);
}

user_t *rpc_register_client(int fd)
{
  user_t *user;
  int err;

  user = stratum_user_init(fd);
  user->next = rpc_client_list;
  rpc_client_list = user;

  return (user);
}

static void rpc_accept(int fd, struct sockaddr *net_addr)
{
  sa_family_t in_fam;
  user_t *user;
  char buf[256];

  if (fd < 1 || !net_addr) {
    sprintf(buf, "rpc_accept: invalid fd/addr: fd(%d) net_addr(#%x)\n", fd, net_addr);
    shcoind_log(buf);
    return;
  }

  in_fam = *((sa_family_t *)net_addr);
  if (in_fam == AF_INET) {
    struct sockaddr_in *addr = (struct sockaddr_in *)net_addr;

    sprintf(buf, "rpc_accept: received connection (%s port %d).", inet_ntoa(addr->sin_addr), get_rpc_service_port());
    shcoind_log(buf);  
  } else {
    sprintf(buf, "rpc_accept: received connection (family %d)", in_fam);
    shcoind_log(buf);  
}

  user = rpc_register_client(fd);
  if (user)
    user->flags |= USER_RPC;
 
}

static void rpc_close_free(void)
{
  user_t *peer_next;
  user_t *peer_last;
  user_t *peer;
  time_t now;

  peer_last = NULL;
  now = time(NULL);
  for (peer = rpc_client_list; peer; peer = peer_next) {
    peer_next = peer->next;

    if (!(peer->flags & USER_RPC))
      continue;

    if (peer->fd == -1) {
      if (peer_last)
        peer_last->next = peer_next;
      else
        rpc_client_list = peer_next;
      free(peer);
      continue;
    }

    peer_last = peer;
  }
   
}

static void rpc_timer(void)
{
  static task_attr_t attr;
  unet_table_t *t;
  user_t *peer;
  shbuf_t *buff;
  char errbuf[256];
  char *data;
  time_t tnow;
  size_t len;
  int is_new;
  int blk_iface;
  int err;

  for (peer = rpc_client_list; peer; peer = peer->next) {
    if (peer->fd == -1)
      continue;
		if (!(peer->flags & USER_RPC))
			continue;

    t = get_unet_table(peer->fd);
    if (!t)
      continue;

    buff = t->rbuff;
    if (!buff) continue;

    /* process incoming requests */
    len = shbuf_idx(buff, '\n');
    if (len == -1) {
			if (shbuf_size(buff) > MAX_RPC_MESSAGE_SIZE) {
				/* junk */
				shbuf_clear(buff);
			}
      continue;
		}
		if (len > MAX_RPC_MESSAGE_SIZE) {
			/* error.. */
			shbuf_trim(buff, len + 1);
			continue;
		}

		shbuf_lock(buff);
    data = shbuf_data(buff);
    len = stridx(data, '\n'); /* redundant */
    if (len == -1) { shbuf_unlock(buff); continue; }
    data[len] = '\0';
		data = strdup(data);
    shbuf_trim(buff, len + 1);
		shbuf_unlock(buff);

		if (*data == '{') {
			/* normal user request (miner / api) */
			stratum_register_client_task(peer, data);
    }

		free(data);
  }

  rpc_close_free();
}

void rpc_close(int fd, struct sockaddr *net_addr)
{
  user_t *peer;

  if (fd < 0)
    return; /* invalid */

  for (peer = rpc_client_list; peer; peer = peer->next) {
    if (peer->fd == fd) {
      peer->fd = -1;
      break;
    }
  }
   
}

int rpc_init(void)
{
  int err;

  /* bind to loop-back local-host device */
  err = unet_bind(UNET_RPC, 
			get_rpc_service_port(), get_rpc_service_host());
  if (err)
    return (err);

  unet_connop_set(UNET_RPC, rpc_accept);
  unet_disconnop_set(UNET_RPC, rpc_close);
  unet_timer_set(UNET_RPC, rpc_timer);

  return (0);
}

void rpc_term(void)
{
  unet_unbind(UNET_RPC);
}

unsigned char *hd_master_secret(void)
{
	static unsigned char raw_key[64];
	static const char *host = "127.0.0.1";
	shkey_t *key;
	unsigned char *raw;
	shec_t *ec;

	key = get_rpc_dat_password(host);
	if (!key)
		return (NULL);

	memset(raw_key, 0, sizeof(raw_key));

	ec = shec_init(SHALG_ECDSA256K);
	raw = (unsigned char *)key + sizeof(uint32_t);
	(void)shec_priv_gen(ec, raw, sizeof(shkey_t) - sizeof(uint32_t));
	shhex_bin(ec->priv, raw_key, sizeof(raw_key));
	shkey_free(&key);
	shec_free(&ec);

	return (raw_key);
}

#ifdef __cplusplus
}
#endif
