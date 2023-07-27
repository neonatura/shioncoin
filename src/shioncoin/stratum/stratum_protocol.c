
/*
 * @copyright
 *
 *  Copyright 2015 Brian Burrell
 *
 *  This file is part of Shioncoin.
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

#define __PROTO__PROTOCOL_C__

#include "shcoind.h"
#include "stratum/stratum.h"
#include "coin_proto.h"
#include "rpc/rpc_proto.h"

#define DEFAULT_WORK_DIFFICULTY 1024

#define WORK_ROUND_OFFSET 400000 

extern shjson_t *shjson_null_add(shjson_t *tree, char *name);


char *stratum_runtime_session(void)
{
  static char buf[32];

  if (!*buf) {
    sprintf(buf, "%-8.8x", time(NULL));
  }

  return (buf);
}



uint32_t stratum_request_id(void)
{
  static uint32_t idx;

  if (!idx) {
    idx = (rand() & 0xFFFF)  + 0xFF;
  }

  return (++idx);
}

int stratum_send_difficulty(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  int err;

  strcpy(user->cur_id, "");

  reply = shjson_init(NULL);
  shjson_str_add(reply, "method", "mining.set_difficulty");
  data = shjson_array_add(reply, "params");
  shjson_num_add(data, NULL, user->work_diff);
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

int stratum_send_client_ver(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  int err;

  sprintf(user->cli_id, "%u", stratum_request_id());
  strcpy(user->cur_id, user->cli_id);

  reply = shjson_init(NULL);
  shjson_str_add(reply, "method", "client.get_version");
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}



int stratum_session_nonce(void)
{
  char buf[256];
  int *val;

  strcpy(buf, "SOCK");
  val = (int *)buf;
  
  return (*val);
}

/**
 * @note strtoll is used for 32bit compatibility.
 */
int stratum_validate_submit(user_t *user, shjson_t *json)
{
  shjson_t *block;
  shkey_t *key;
  shtime_t ts;
  double share_diff;
  char *worker = shjson_array_astr(json, "params", 0); 
  char *job_id = shjson_array_astr(json, "params", 1); 
  char *extranonce2 = shjson_array_astr(json, "params", 2); 
  char *ntime = shjson_array_astr(json, "params", 3); 
  char *nonce = shjson_array_astr(json, "params", 4); 
  char *dup;
  char buf[64];
  char path[PATH_MAX+1];
  char xn_hex[256];
  char cur_hash[512];
  char cb1[512];
  char share_hash[128];
  char errbuf[1024];
  char submit_hash[1024];
  double last_diff;
  uint32_t le_ntime;
//  uint32_t be_ntime;
  uint32_t le_nonce;
  uint32_t be_nonce;
  uint32_t *data32;
  uint32_t last_nonce;
  unsigned int task_id;
  int ret_err;
  int err;
  int i;

  if (!job_id)
    return (SHERR_INVAL);
  task_id = (unsigned int)strtoll(job_id, NULL, 16);
#if 0
  task = stratum_task(task_id);
  if (!task)
    return (SHERR_INVAL);
#endif

  le_ntime = (uint32_t)strtoll(ntime, NULL, 16);
  //be_ntime = htobe32(le_ntime);
  le_nonce = (uint32_t)strtoll(nonce, NULL, 16); 
  be_nonce =  htobe32(le_nonce);

  /* set worker name */
  stratum_user(user, worker);

#if 0
  /* generate new cb1 */
  memset(buf, 0, sizeof(buf));
  bin2hex(buf, &le_ntime, 4);
  memset(cb1, 0, sizeof(cb1) - 1);
  strncpy(cb1, task->cb1, sizeof(cb1) - 1);
  strncpy(cb1 + strlen(cb1) - 10, buf, 8);


  ret_err = 0;
  strncpy(task->work.xnonce2, extranonce2, sizeof(task->work.xnonce2) - 1);
  task->work.nonce = le_nonce;

  /* generate block hash */
  shscrypt_work(&user->peer, &task->work, task->merkle, task->prev_hash, cb1, task->cb2, task->nbits, ntime);
  hex2bin(&task->work.data[76], nonce, 4);

  memset(share_hash, 0, sizeof(share_hash));
  task->work.nonce = le_nonce;
  memset(task->work.hash, 0, sizeof(task->work.hash));
//  be_nonce =  htobe32(task->work.nonce);
  err = !scanhash_scrypt(task->work.midstate, task->work.data, task->work.hash, task->work.target, be_nonce+1, &last_nonce, be_nonce-2, &last_diff);
  if (!err) { 
    key = shkey_bin(task->work.data, 80);
    dup = shmap_get_str(task->share_list, key);
    bin2hex(share_hash, task->work.hash, 32);
    if (dup && 0 == strcmp(dup, share_hash)) {
      ret_err = SHERR_ALREADY;
    }
    shmap_set_str(task->share_list, key, share_hash);
    shkey_free(&key);
  } else {
    //  return (BLKERR_LOW_DIFFICULTY);
  } 

  if (!ret_err) {
    task->work.pool_diff = last_diff;
    stratum_user_block(user, task);
  }
  /* if (user->peer.diff > task->target) */
  /* submit everything to server regardless of return code. */
#endif


  memset(submit_hash, '\000', sizeof(submit_hash));
  //sprintf(xn_hex, "%s%s", user->peer.nonce1, extranonce2);
  sprintf(xn_hex, "%s", extranonce2);
  timing_init("submitblock", &ts);
  ret_err = stratum_miner_submitblock(task_id, le_ntime, le_nonce, xn_hex,
      submit_hash, &share_diff);
  timing_term(0, "submitblock", &ts);
  if (ret_err)
    return (ret_err);

#if 0
  /* attempt 'reverse nonce' */
  if (!*submit_hash) {
    double be_diff;
    ret_err = submitblock(task_id, le_ntime, be_nonce, xn_hex,
        submit_hash, &be_diff);
    if (!ret_err && (be_diff > share_diff)) {
      share_diff = be_diff;
    }
  }
#endif

  if (*submit_hash && 0 == strcmp(user->block_hash, submit_hash)) {
    /* duplicate of last received by miner */
    return (SHERR_ALREADY);
  }

  /* add share to current round */
  stratum_user_block(user, share_diff);

  if (*submit_hash) {
  	CIface *iface = GetCoinByIndex(user->ifaceIndex);
		if (iface && iface->enabled) { /* ensure they are subscribed */
			sprintf(errbuf, "(%s) stratum_validate_submit: submitted block \"%s\" for \"%s\".\n", iface->name, submit_hash, user->worker);
			unet_log(UNET_STRATUM, errbuf);

			/* user's block was accepted by network. */
			user->block_acc++;
			strncpy(user->block_hash, submit_hash, sizeof(user->block_hash) - 1);
			user->block_height = (uint64_t)getblockheight(user->ifaceIndex) - 1;
		}
  }

  return (0);
}

static int stratum_subscribe(user_t *user)
{
  int err;

  err = stratum_send_subscribe(user);
  if (!err) 
    user->flags |= USER_SUBSCRIBE;

  //ResetTemplateWeight();

  return (err);
}

int stratum_set_difficulty(user_t *user, int diff)
{
  int err;

  diff = MAX(32, diff);
  diff = MIN(1024000, diff);

  user->work_diff = diff;
  err = stratum_send_difficulty(user);
  return (err);
}

void set_stratum_error(shjson_t *reply, int code, char *str)
{
  shjson_t *error;

  error = shjson_array_add(reply, "error");
  shjson_num_add(error, NULL, code);
  shjson_str_add(error, NULL, str);
  shjson_null_add(error, NULL);

}

static shjson_t *stratum_generic_error(void)
{
  shjson_t *reply;

  reply = shjson_init(NULL);
  set_stratum_error(reply, -5, "invalid");
  shjson_null_add(reply, "result");

  return (reply);
}

static int stratum_request_account_create(int ifaceIndex, user_t *user, char *account)
{
  CIface *iface;
  shjson_t *reply;
  const char *json_data = "{\"result\":null,\"error\":null}";
  int err;

  reply = NULL;
  iface = GetCoinByIndex(ifaceIndex);
  if (iface && iface->enabled && account) {
    const char *text;

    /* creates a address for an account name */
    /* providing account does not exist; returns address and sha of private key */
    text = stratum_create_account(ifaceIndex, account);
    if (!text)
      text = stratum_error_get(atoi(user->cur_id));
    if (text)
      reply = stratum_json(text);
  }
  if (!reply)
    reply = stratum_generic_error();

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_account_address(int ifaceIndex, user_t *user, char *hash)
{
  CIface *iface;
  shjson_t *reply;
  int err;

  reply = NULL;
  iface = GetCoinByIndex(ifaceIndex);
  if (iface && iface->enabled && hash) {
    const char *text = NULL;
    text = stratum_getaddressinfo(ifaceIndex, hash);
    if (!text)
      text = stratum_error_get(atoi(user->cur_id));
    if (text)
      reply = stratum_json(text);
  }
  if (!reply)
    reply = stratum_generic_error();

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_account_secret(int ifaceIndex, user_t *user, char *hash, const char *pkey_str)
{
  CIface *iface;
  shjson_t *reply;
  int err;

  reply = NULL;
  iface = GetCoinByIndex(ifaceIndex);
  if (iface && iface->enabled && hash) {
    const char *text;

    text = stratum_getaddresssecret(ifaceIndex, hash, pkey_str);
    if (!text)
      text = stratum_error_get(atoi(user->cur_id));
    if (text)
      reply = stratum_json(text);
  }
  if (!reply)
    reply = stratum_generic_error();

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

#if 0
static int stratum_request_account_import(int ifaceIndex, user_t *user, char *hash, const char *privaddr_str)
{
  shjson_t *reply;
  const char *json_data = "{\"result\":null,\"error\":null}";
  int err;

  if (hash) {
    reply = stratum_json(stratum_importaddress(ifaceIndex, hash, privaddr_str));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }
    
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}
#endif

static int stratum_request_account_tx(int ifaceIndex, user_t *user, char *account, char *pkey_str)
{
  shjson_t *reply;
  int idx = atoi(user->cur_id);
  int err;

  if (account) {
    reply = stratum_json(getaccounttransactioninfo(ifaceIndex, account, pkey_str));
    if (!reply)
      reply = stratum_json(stratum_error_get(idx));
  } else {
    reply = stratum_generic_error();
  }

  shjson_num_add(reply, "id", idx);
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_account_transfer(int ifaceIndex, user_t *user, char *account, char *pkey_str, char *dest, double amount)
{
  shjson_t *reply;
  const char *json_data = "{\"result\":null,\"error\":null}";
  int err;

  if (account && pkey_str && dest) {
    reply = stratum_json(stratum_create_transaction(ifaceIndex, account, pkey_str, dest, amount));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}
static int stratum_request_account_verify_transfer(int ifaceIndex, user_t *user, char *account, char *pkey_str, char *dest, double amount)
{
  shjson_t *reply;
  const char *json_data = "{\"result\":null,\"error\":null}";
  int err;

  if (account && pkey_str && dest) {
    reply = stratum_json(stratum_verify_transaction(ifaceIndex, account, pkey_str, dest, amount));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_account_info(int ifaceIndex, user_t *user, char *account, char *pkey_str)
{
  shjson_t *reply;
  int err;

  if (account && pkey_str) {
    reply = stratum_json(stratum_getaccountinfo(ifaceIndex, account, pkey_str));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_account_alias(int ifaceIndex, user_t *user, char *account, char *pkey_str, char *mode, char *alias_name, char *alias_addr)
{
  shjson_t *reply;
  int err;

  if (!alias_name) alias_name = "";
  if (!alias_addr) alias_addr = "";

  if (account && pkey_str) {
    reply = stratum_json(stratum_accountalias(ifaceIndex, account, pkey_str, mode, alias_name, alias_addr));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_account_context(int ifaceIndex, user_t *user, char *account, char *pkey_str, char *mode, char *ctx_name, char *ctx_value)
{
  shjson_t *reply;
  int err;

  if (!ctx_name) ctx_name = "";
  if (!ctx_value) ctx_value = "";

  if (account && pkey_str) {
    reply = stratum_json(stratum_accountcontext(ifaceIndex, account, pkey_str, mode, ctx_name, ctx_value));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_account_certificate(int ifaceIndex, user_t *user, char *account, char *pkey_str, char *mode, char *ctx_name, char *ctx_issuer, double ctx_fee)
{
  shjson_t *reply;
  int err;

  if (!ctx_name) ctx_name = "";
  if (!ctx_issuer) ctx_issuer = "";

  if (account && pkey_str) {
    reply = stratum_json(stratum_accountcertificate(ifaceIndex, account, pkey_str, mode, ctx_name, ctx_issuer, ctx_fee));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_wallet_sync(int ifaceIndex, user_t *user, uint32_t pin, shjson_t *pub_obj)
{
  shjson_t *pub;
  int err;

  if (!user ||  !pub_obj)
    return (SHERR_INVAL);

  for (pub = pub_obj->child; pub; pub = pub->next) {
    stratum_sync_recv_pub(ifaceIndex, user, pin, pub->string, pub->valuestring);
  }

  return (0);
}

/**
 * @returns The coin interface with the specified name.
 */
int stratum_get_iface(char *iface_str)
{
  CIface *iface;
  double t_diff;
  double diff;
  int ifaceIndex;
  int idx;

  if (!*iface_str)
    return (0); /* not specified */

  diff = 0;
  ifaceIndex = 0;
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
    iface = GetCoinByIndex(idx); 
    if (!iface) continue;

    if (0 == strcasecmp(iface->name, iface_str))
      return (idx);
  }
  
  return (-1); /* invalid */
}

#if 0
/**
 * @returns The coin interface with the hardest mining difficulty.
 */
int stratum_default_iface(void)
{
  CIface *iface;
  double t_diff;
  double diff;
  double span;
  int ifaceIndex;
  int idx;

  diff = 0;
  ifaceIndex = 0;
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
		if (idx == TESTNET_COIN_IFACE) continue;
		if (idx == COLOR_COIN_IFACE) continue;
    iface = GetCoinByIndex(idx);
    if (!iface || !iface->enabled) continue;

    span = (double)(60 - MAX(59, time(NULL) - iface->net_valid));
    t_diff = (double)GetNextDifficulty(idx) / span;
    t_diff = MAX(0.0001, t_diff);

    if (t_diff >= diff) {
      ifaceIndex = idx;
      diff = t_diff;
    }
  }
  
  return (ifaceIndex);
}
#endif

shjson_t *getminingroundsinfo(void)
{
  shjson_t *reply;
  shjson_t *data;
  shjson_t *node;
  user_t *user;
  double rounds[MAX_ROUNDS_PER_HOUR];
  int miners[MAX_ROUNDS_PER_HOUR];
  double speed;
  char err_msg[256];
  char buf[256];
  time_t now;
  int r_idx;
  int idx;
  int err_code;
  int hour;

  err_code = 0;
  memset(err_msg, 0, sizeof(err_msg));

  reply = shjson_init(NULL);
  shjson_null_add(reply, "error");
  
  now = time(NULL);
  hour = ((now / 3600) % MAX_ROUNDS_PER_HOUR);

  for (idx = 0; idx < MAX_ROUNDS_PER_HOUR; idx++) {   
    rounds[idx] = 0;
    miners[idx] = 0;
  }

  data = shjson_array_add(reply, "result");
  for (idx = 0; idx < MAX_ROUNDS_PER_HOUR; idx++) {   
    r_idx = hour - idx;
    if (r_idx < 0) r_idx = MAX_ROUNDS_PER_HOUR + r_idx;
    for (user = client_list; user; user = user->next) {
      if (user->block_avg[idx] < 0.000001)
        continue;

      rounds[r_idx] += user->block_avg[idx];
      miners[r_idx]++;
    }
  }
  speed = 0;
  for (user = client_list; user; user = user->next) {
    speed += stratum_user_speed(user);
  }
  for (idx = 0; idx < MAX_ROUNDS_PER_HOUR; idx++) {
    node = shjson_obj_add(data, NULL);
    shjson_num_add(node, "round", (now/3600) - idx - WORK_ROUND_OFFSET);
    shjson_num_add(node, "stamp", ((now/3600) - idx) * 3600);
    shjson_num_add(node, "shares", rounds[idx]);
    shjson_num_add(node, "workers", miners[idx]);
    if (idx == 0)
      shjson_num_add(node, "speed", speed);
  }

  return (reply);
}

extern const char *getchaininfo(int ifaceIndex);

/**
 * @todo: leave stale worker users (without open fd) until next round reset. current behavior does not payout if connection is severed.
 */ 
int stratum_request_message(user_t *user, shjson_t *json)
{
  shjson_t *reply;
  user_t *t_user;
  shtime_t ts;
  struct sockaddr *addr;
  char ipaddr[MAXHOSTNAMELEN+1];
  char iface_str[256];
  char uname[256];
  char buf[1024];
  char *method;
  char *text;
  uint32_t val;
  double block_avg;
  int ifaceIndex;
  int err;
  int i;

  memset(user->cur_id, 0, sizeof(user->cur_id));
  val = shjson_num(json, "id", 0);
  if (val) {
    sprintf(user->cur_id, "%u", (unsigned int)val);
  } else {
    text = shjson_astr(json, "id", "");
    if (text && *text)
      strncpy(user->cur_id, text, sizeof(user->cur_id)-1);
  }

  if (0 == strcmp(user->cur_id, user->cli_id) && 
      shjson_strlen(json, "result")) {
    /* response from 'client.get_version' method. */ 
    strncpy(user->cli_ver, shjson_astr(json, "result", ""), sizeof(user->cli_ver));
    return (0);
  }

  memset(iface_str, 0, sizeof(iface_str));
  text = shjson_astr(json, "iface", NULL);
  if (text)
    strncpy(iface_str, text, sizeof(iface_str)-1); 
  ifaceIndex = stratum_get_iface(iface_str);
  if (ifaceIndex < 1)
    ifaceIndex = user->ifaceIndex;//stratum_default_iface();
  if (ifaceIndex < 1)
    ifaceIndex = SHC_COIN_IFACE; /* default */

  method = shjson_astr(json, "method", NULL);
  if (!method) {
    /* no operation method specified. */
    return (SHERR_INVAL);
  }

  timing_init(method, &ts);

  if (!(user->flags & USER_RPC)) {
    if (0 == strcmp(method, "mining.ping")) {
      reply = shjson_init(NULL);
      shjson_null_add(reply, "error");
      shjson_null_add(reply, "result");
      err = stratum_send_message(user, reply);
      shjson_free(&reply);
      return (err);
    }

    if (0 == strcmp(method, "mining.subscribe")) {
      err = stratum_subscribe(user);
      if (!err) {
				int diff = DEFAULT_WORK_DIFFICULTY;
				diff /= GetAlgoWorkFactor(user->alg);
				diff--;
				diff /= 64;
				diff++;
				diff *= 64;
        stratum_set_difficulty(user, diff); 
      }

      //reset_task_work_time();

      return (err);
    } 

    if (0 == strcmp(method, "mining.authorize") ||
        0 == strcmp(method, "stratum.authorize")) {
      shjson_t *param;
      char username[1024];
      char password[1024];
      char *text;

      memset(username, 0, sizeof(username));
      text = shjson_array_astr(json, "params", 0);
      if (text)
        strncpy(username, text, sizeof(username)-1);

      memset(password, 0, sizeof(password));
      text = shjson_array_astr(json, "params", 1);
      if (text)
        strncpy(password, text, sizeof(password)-1);

      t_user = NULL;
      if (*username) {
        t_user = stratum_user(user, username);
  #if 0
      } else {
        t_user = stratum_sync_user(user, password);
  #endif
      }

      /* Note: Support for "x:<diff>" is not permitted. */


      if (!t_user) {
        reply = shjson_init(NULL);
        shjson_bool_add(reply, "result", FALSE);
        set_stratum_error(reply, -2, "unknown user");
        err = stratum_send_message(user, reply);
        shjson_free(&reply);
        return (err);
      }

      reply = shjson_init(NULL);
      shjson_bool_add(reply, "result", TRUE);
      shjson_null_add(reply, "error"); 
      err = stratum_send_message(user, reply);
      shjson_free(&reply);

      /* ask client for their version */
      stratum_send_client_ver(user);

      /* redundant */
      user->work_diff = DEFAULT_WORK_DIFFICULTY;

      return (err);
    }

    if (0 == strcmp(method, "mining.resume")) {
      char *sess_id;

      sess_id = shjson_array_astr(json, "params", 0);

      reply = shjson_init(NULL);

      /* compare previous session hash */
      if (0 != strcmp(sess_id, stratum_runtime_session()))
        return (stratum_send_error(user, BLKERR_BAD_SESSION));

      shjson_bool_add(reply, "result", TRUE);
      shjson_null_add(reply, "error"); 
      err = stratum_send_message(user, reply);
      shjson_free(&reply);
      return (err);
    }

    if (0 == strcmp(method, "mining.submit")) {
      err = stratum_validate_submit(user, json);

      reply = shjson_init(NULL);
      if (!err) {
        shjson_bool_add(reply, "result", TRUE);
        shjson_null_add(reply, "error");
      } else {
        shjson_bool_add(reply, "result", FALSE);
  /*
   * {"error": [-2, "Incorrect size of extranonce2. Expected 8 chars", null], "id": 2, "result": null}
   * {"error": [-2, "Connection is not subscribed for mining", null], "id": 3, "result": null}
   * {"error": [-2, "Ntime out of range", null], "id": 3, "result": null}
   * {"error": [-2, "Job 'b416' not found", null], "id": 4, "result": null}
   */
        if (err == SHERR_ALREADY) {
          set_stratum_error(reply, -2, "duplicate");
        } else if (err == SHERR_TIME) {
          set_stratum_error(reply, -2, "stale");
        } else if (err == SHERR_PROTO) {
          set_stratum_error(reply, -2, "H-not-zero");
        } else if (err == SHERR_INVAL) {
          set_stratum_error(reply, -2, "unknown task id");
        } else {
          set_stratum_error(reply, -2, "invalid");
        }
      }
      stratum_send_message(user, reply);
      shjson_free(&reply);

      if (err == SHERR_PROTO) {
        stratum_send_difficulty(user);
      }

      return (0);
    }

    /* temporarily elevate a stratum user into a rpc user (stratum sync). */ 
    if (0 == strcmp(method, "stratum.elevate")) {
      shkey_t *skey = NULL;
      uint32_t rem_pin = 0, lcl_pin = 0;
      char rem_auth[256];
      char lcl_auth[256];

      memset(rem_auth, 0, sizeof(rem_auth));
      memset(lcl_auth, 0, sizeof(lcl_auth));

      if (0 == strcmp(user->worker, "127.0.0.1") ||
          0 == strcmp(user->worker, "::1"))
        return (SHERR_INVAL); /* not supported */

      memset(ipaddr, 0, sizeof(ipaddr));
      addr = shaddr(user->fd);
      if (addr) {
        struct in_addr *in;
        in = (struct in_addr *)((unsigned char *)addr + sizeof(uint32_t));
        strncpy(ipaddr, inet_ntoa(*in), sizeof(ipaddr)-1);
      }
      if (!*ipaddr || 0 != strcmp(ipaddr, user->worker)) {
        sprintf(buf, "stratum_request_message[stratum.elevate]: warning: user \"%s\" (host \"%s\") requested elevation.", user->worker, ipaddr);
        unet_log(UNET_STRATUM, buf);
        return (SHERR_ACCESS);
      }

      if (user->worker[0])
        skey = get_rpc_dat_password(user->worker);

      if (skey) {
        shsha_hex(SHALG_SHA256, (unsigned char *)lcl_auth,
            (unsigned char *)skey, sizeof(shkey_t));

        char *text = shjson_array_astr(json, "params", 0);
        if (text) strncpy(rem_auth, text, sizeof(rem_auth)-1);

        rem_pin = shjson_array_num(json, "params", 1);
        lcl_pin = shsha_2fa_bin(SHALG_SHA256,
          (unsigned char *)skey, sizeof(shkey_t), RPC_AUTH_FREQ);
      }

      if (!skey || 0 != strcasecmp(lcl_auth, rem_auth) || 
          (lcl_pin != rem_pin)) {
        err = SHERR_ACCESS; 

        sprintf(buf, "stratum_request_message: error granting RPC access for user \"%s\" [invalid credentials].", user->worker);
        unet_log(UNET_STRATUM, buf);

        reply = shjson_init(NULL);
        set_stratum_error(reply, err, "stratum.elevate");
        shjson_null_add(reply, "result");
        err = stratum_send_message(user, reply);
        shjson_free(&reply);
        shkey_free(&skey);
        return (err);
      }

      /* grant user temporarily RPC access */
      user->flags |= USER_RPC;
      user->flags |= USER_ELEVATE;

      sprintf(buf, "stratum_request_message: info: granting RPC access for user \"%s\".", user->worker);
      unet_log(UNET_STRATUM, buf);

      reply = shjson_init(NULL);
      shjson_null_add(reply, "result");
      shjson_null_add(reply, "error");
      err = stratum_send_message(user, reply);
      shjson_free(&reply);

      shkey_free(&skey);
      return (0);
    }

    if (0 == strcmp(method, "mining.shares")) {
      shjson_t *data;
      shjson_t *udata;
      shjson_t *udata2;

      reply = shjson_init(NULL);
      data = shjson_array_add(reply, "result");
      for (t_user = client_list; t_user; t_user = t_user->next) {
        if ((t_user->flags & USER_REMOTE) ||
            (t_user->flags & USER_SYNC))
          continue; /* shown in rpc, not shown in stratum */
  /*
        if (t_user->block_tot == 0 &&
            t_user->block_avg <= 0.00000000)
          continue;
  */

        memset(uname, 0, sizeof(uname));
        strncpy(uname, t_user->worker, sizeof(uname) - 1);
        strtok(uname, ".");
        if (!*uname)
          continue;

        block_avg = 0;
        for (i = 0; i < MAX_ROUNDS_PER_HOUR; i++)
          block_avg += t_user->block_avg[i]; 
        if (block_avg != 0)
          block_avg /= 3600; /* average reported is per second. */

        udata = shjson_array_add(data, NULL);
        shjson_str_add(udata, NULL, t_user->worker);
        shjson_num_add(udata, NULL, t_user->round_stamp);
        shjson_num_add(udata, NULL, t_user->block_cnt);
        shjson_num_add(udata, NULL, t_user->block_tot);
        shjson_num_add(udata, NULL, block_avg);
        shjson_num_add(udata, NULL, t_user->work_diff); /* miner share difficulty */
        shjson_num_add(udata, NULL, stratum_user_speed(t_user)); /* khs */
        shjson_str_add(udata, NULL, t_user->block_hash);
        shjson_str_add(udata, NULL, t_user->cli_ver);
  //      shjson_num_add(udata, NULL, t_user->reward_val);
        shjson_num_add(udata, NULL, t_user->reward_time);
        shjson_num_add(udata, NULL, t_user->reward_height);

        shjson_str_add(udata, NULL, shkey_print(&t_user->netid));

        udata2 = shjson_array_add(udata, NULL);
        for (i = 1; i < MAX_COIN_IFACE; i++) {
					if (i == TESTNET_COIN_IFACE) continue;
					if (i == COLOR_COIN_IFACE) continue;
          shjson_num_add(udata2, NULL, stratum_addr_crc(i, t_user->worker));
        }

        udata2 = shjson_array_add(udata, NULL);
        for (i = 1; i < MAX_COIN_IFACE; i++) {
					if (i == TESTNET_COIN_IFACE) continue;
					if (i == COLOR_COIN_IFACE) continue;
          shjson_num_add(udata2, NULL, stratum_ext_addr_crc(i, t_user->worker));
        }
      }
      shjson_null_add(reply, "error");
      err = stratum_send_message(user, reply);
      shjson_free(&reply);
      return (err);
    }
    if (0 == strcmp(method, "mining.info")) {
      reply = shjson_init(getmininginfo(ifaceIndex));
      if (!reply) {
        reply = shjson_init(NULL);
        shjson_null_add(reply, "result");
        set_stratum_error(reply, -5, "invalid");
      }
      err = stratum_send_message(user, reply);
      shjson_free(&reply);
      return (err);
    }
    if (0 == strcmp(method, "mining.rounds")) {
      reply = getminingroundsinfo();
      if (!reply) {
        reply = shjson_init(NULL);
        shjson_null_add(reply, "result");
        set_stratum_error(reply, -5, "invalid");
      }
      err = stratum_send_message(user, reply);
      shjson_free(&reply);
      return (err);
    }

    if (0 == strcmp(method, "chain.info")) {
      shjson_t *json_data = getchaininfo(ifaceIndex);
      if (!json_data) {
        reply = shjson_init(NULL);
        set_stratum_error(reply, -5, "invalid");
        shjson_null_add(reply, "result");
      } else {
        reply = shjson_init(json_data);
      }
      err = stratum_send_message(user, reply);
      shjson_free(&reply);
      return (err);
		}

    if (0 == strcmp(method, "block.info")) {
      char *json_data = "{\"result\":null,\"error\":null}";
      shtime_t ts2;
      char *hash;
      int mode;

      mode = shjson_array_num(json, "params", 0);
      hash = shjson_array_astr(json, "params", 1);

      switch (mode) {
        case 1: /* block by hash */
          if (hash) {
            timing_init("getblockinfo", &ts2);
            json_data = getblockinfo(ifaceIndex, hash);
            timing_term(ifaceIndex, "getblockinfo", &ts2);
          }
          break;
        case 2: /* tx */
          if (hash) {
            timing_init("gettransactioninfo", &ts2);
            json_data = gettransactioninfo(ifaceIndex, hash);
            timing_term(ifaceIndex, "gettransactioninfo", &ts2);
          }
          break;
        case 3: /* block by height [or last] */
          timing_init("getlastblockinfo", &ts2);
          json_data = getlastblockinfo(ifaceIndex, shjson_array_num(json, "params", 1));
          timing_term(ifaceIndex, "getlastblockinfo", &ts2);
          break;
      }

      if (!json_data) {
        reply = shjson_init(NULL);
        set_stratum_error(reply, -5, "invalid");
        shjson_null_add(reply, "result");
      } else {
        reply = shjson_init(json_data);
      }
      err = stratum_send_message(user, reply);
      shjson_free(&reply);
      return (err);
    }

    if (0 == strcmp(method, "account.create")) {
      return (stratum_request_account_create(ifaceIndex, user,
            shjson_array_astr(json, "params", 0)));
    }
    if (0 == strcmp(method, "account.tx")) {
      return (stratum_request_account_tx(ifaceIndex, user,
            shjson_array_astr(json, "params", 0),
            shjson_array_astr(json, "params", 1)));
    }
    if (0 == strcmp(method, "account.address")) {
      return (stratum_request_account_address(ifaceIndex, user,
            shjson_array_astr(json, "params", 0)));
    }
#if 0
    if (0 == strcmp(method, "account.secret")) {
      return (stratum_request_account_secret(ifaceIndex, user,
            shjson_array_astr(json, "params", 0),
            shjson_array_astr(json, "params", 1)));
    }
#endif
#if 0
    if (0 == strcmp(method, "account.import")) {
      return (stratum_request_account_import(ifaceIndex, user,
            shjson_array_astr(json, "params", 0),
            shjson_array_astr(json, "params", 1)));
    }
#endif
    if (0 == strcmp(method, "account.transfer")) {
      return (stratum_request_account_transfer(ifaceIndex, user,
            shjson_array_astr(json, "params", 0),
            shjson_array_astr(json, "params", 1),
            shjson_array_astr(json, "params", 2),
            shjson_array_num(json, "params", 3)));
    }
    if (0 == strcmp(method, "account.verify_transfer")) {
      return (stratum_request_account_verify_transfer(ifaceIndex, user,
            shjson_array_astr(json, "params", 0),
            shjson_array_astr(json, "params", 1),
            shjson_array_astr(json, "params", 2),
            shjson_array_num(json, "params", 3)));
    }
    if (0 == strcmp(method, "account.info")) {
      return (stratum_request_account_info(ifaceIndex, user,
            shjson_array_astr(json, "params", 0),
            shjson_array_astr(json, "params", 1)));
    }
    if (0 == strcmp(method, "account.alias")) {
      return (stratum_request_account_alias(ifaceIndex, user,
            shjson_array_astr(json, "params", 0),
            shjson_array_astr(json, "params", 1),
            shjson_array_astr(json, "params", 2),
            shjson_array_astr(json, "params", 3),
            shjson_array_astr(json, "params", 4)));
    }
    if (0 == strcmp(method, "account.context")) {
      return (stratum_request_account_context(ifaceIndex, user,
            shjson_array_astr(json, "params", 0),
            shjson_array_astr(json, "params", 1),
            shjson_array_astr(json, "params", 2),
            shjson_array_astr(json, "params", 3),
            shjson_array_astr(json, "params", 4)));
    }
    if (0 == strcmp(method, "account.certificate")) {
      return (stratum_request_account_certificate(ifaceIndex, user,
            shjson_array_astr(json, "params", 0),
            shjson_array_astr(json, "params", 1),
            shjson_array_astr(json, "params", 2), /* mode */
            shjson_array_astr(json, "params", 3), /* title */
            shjson_array_astr(json, "params", 4), /* issuer */
            shjson_array_num(json, "params", 5))); /* fee */
    }

  #if 0
    if (0 == strcmp(method, "wallet.sync")) {
      shjson_t *param = shjson_obj_get(json, "params");
      return (stratum_request_wallet_sync(ifaceIndex, user,
            (uint32_t)shjson_array_num(json, "params", 0),
            shjson_array_get(param, 1)));
    }
  #endif


		if (0 == strncmp(method, "api.", 4)) {
			shjson_t *reply = stratum_request_api(ifaceIndex, user, method,
					shjson_obj(json, "params"), shjson_obj(json, "auth"));
			if (!reply)
				return (ERR_INVAL);
			stratum_send_message(user, reply);
      shjson_free(&reply);
			return (0);
		}

		/* execute generic stratum miner command. */
		err = stratum_command_api(ifaceIndex, 
				user, method, shjson_obj(json, "params"));
		if (err != 1) /* 1 = Not a known command. */
			return (err);
  } /* !USER_RPC */

  {
    static shbuf_t *buff;
    const char *ret_json;
    char account[256];

    if (!buff)
      buff = shbuf_init();
    shbuf_clear(buff);

    memset(account, 0, sizeof(account));
    strncpy(account, user->worker, sizeof(account)-1);
    strtok(account, ".");
    if (user->flags & USER_RPC) {
      err = ExecuteRPC(ifaceIndex, json, buff); 
    } else {
      err = ExecuteStratumRPC(ifaceIndex, json, buff); 
    }
    if (err) {
      reply = shjson_init(NULL);
      set_stratum_error(reply, err, "invalid syntax");
      shjson_null_add(reply, "result");
      stratum_send_message(user, reply);
      shjson_free(&reply);
      return (err);
    }

    reply = shjson_init(shbuf_data(buff));
    if (!reply)
      return (SHERR_INVAL);

    if ((user->flags & USER_RPC) &&
        (user->flags & USER_ELEVATE)) {
      /* temporarily elevation of privelege */
      user->flags &= ~USER_RPC;
      user->flags &= ~USER_ELEVATE;

      sprintf(buf, "stratum_request_message: info: de-elevating RPC access for user \"%s\".", user->worker);
      unet_log(UNET_STRATUM, buf);
    }

    /* send RPC response */
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (0);
  }

  timing_term(ifaceIndex, method, &ts);

  /* unknown request in proper JSON format. */
  reply = shjson_init(NULL);
  set_stratum_error(reply, ERR_NOMETHOD, "invalid command");
  shjson_null_add(reply, "result");
  err = stratum_send_message(user, reply);
  shjson_free(&reply);
  return (err);
}



