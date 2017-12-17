
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
#include "unet/unet.h"
#include "stratum/stratum.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CRED_SECRET_LEN 28

extern void stratum_close(int fd, struct sockaddr *net_addr);
extern user_t *stratum_register_client(int fd);



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
      fprintf(stderr, "DEBUG: get_rpc_cred: !set_rpc_dat_password (%d)\n", err);
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

  return (ret_str);
}

shkey_t *get_rpc_dat_password(char *host)
{
  shkey_t *key;
  shbuf_t *buff;
  char *tok_ctx;
  char path[PATH_MAX+1];
  char *raw;
  char *key_str;
  char *tok;
  int err;

  if (!host)
    host = "127.0.0.1";

  sprintf(path, "%s/blockchain/rpc.dat", get_libshare_path());
  chmod(path, 00400);

  buff = shbuf_init();
  err = shfs_mem_read(path, buff);
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
  char path[PATH_MAX+1];
  char *raw;
  char *key_str;
  char *tok;
  int err;

  if (!host)
    host = "127.0.0.1";

  sprintf(path, "%s/blockchain/rpc.dat", get_libshare_path());
  chmod(path, 00400);

  w_buff = shbuf_init();
  shbuf_catstr(w_buff, "## Automatically Generated (do not modify) ##\n\n");

  buff = shbuf_init();
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
  }

  /* add updated record */
  shbuf_catstr(w_buff, host);
  shbuf_catstr(w_buff, " ");
  shbuf_catstr(w_buff, shkey_print(in_key));
  shbuf_catstr(w_buff, "\n");

  err = shfs_mem_write(path, w_buff);
  if (err)
    return (err);
  
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
fprintf(stderr, "DEBUG: get_rpc_pin: '%s'\n", shkey_print(key));

  raw = ((unsigned char *)key) + sizeof(uint32_t);
  ret_pin = shsha_2fa_bin(SHALG_SHA224, raw, CRED_SECRET_LEN, FIVE_MINUTES);
  shkey_free(&key);
  if (ret_pin == 0)
    return (0);

fprintf(stderr, "DEBUG: get_rpc_pin: PIN %u\n", ret_pin);
  return (ret_pin);
}

int verify_rpc_pin(char *host, uint32_t pin)
{
  unsigned char *raw;
  shkey_t *key;
  int err;

  key = get_rpc_dat_password(host);
  if (!key) {
fprintf(stderr, "DEBUG: verify_rpc_pin: ERR_NOENT\n");
    return (SHERR_NOENT); 
}
fprintf(stderr, "DEBUG: verify_rpc_pin: '%s' [pin %u]\n", shkey_print(key), pin);

  raw = ((unsigned char *)key) + sizeof(uint32_t);
  err = shsha_2fa_bin_verify(SHALG_SHA224, 
      raw, CRED_SECRET_LEN, FIVE_MINUTES, pin);
  shkey_free(&key);
fprintf(stderr, "DEBUG: verify_rpc_pin: 2fa_bin_verify err %d\n", err);

  return (err);
}

int get_rpc_service_port(void)
{
  return ((int)opt_num(OPT_RPC_PORT));
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

  user = stratum_register_client(fd);
  if (user)
    user->flags |= USER_RPC;
 
}


int rpc_init(void)
{
  int err;

  /* bind to loop-back local-host device */
  err = unet_bind(UNET_RPC, get_rpc_service_port(), UNET_BIND_LOCAL);
  if (err)
    return (err);

  unet_connop_set(UNET_RPC, rpc_accept);
  unet_disconnop_set(UNET_RPC, stratum_close);
#if 0
  unet_timer_set(UNET_RPC, rpc_timer);
#endif

  return (0);
}

void rpc_term(void)
{
  unet_unbind(UNET_RPC);
}

#ifdef __cplusplus
}
#endif
