
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

#include "shcoind.h"
#include "stratum/stratum.h"

/**
 * Sends textual JSON reply message to a stratum client.
 */
int stratum_send_message(user_t *user, shjson_t *msg)
{
  uint32_t val;
  char *text;
  int err;

  if (!user) {
    shcoind_log("stratum_send_message: stratum_send_message: null user");
    return (0);
  }

  if (user->flags & USER_SYSTEM)
    return (0); /* dummy user */

  if (user->fd == -1) {
    /* no network connection */
    return (0);
  }

  if (!*user->cur_id) {
    shjson_null_add(msg, "id");
  } else if ((val = (uint32_t)atoi(user->cur_id)) != 0) {
    shjson_num_add(msg, "id", val);
  } else {
    shjson_str_add(msg, "id", user->cur_id);
  }

  text = shjson_print(msg);
  if (text) {
    unet_write(user->fd, text, strlen(text));
    unet_write(user->fd, "\n", 1);
//fprintf(stderr, "DEBUG: stratum_send_message: %s\n", text); 
    free(text);
  }

  return (0);
}

int stratum_send_error(user_t *user, int err_code)
{
  shjson_t *reply;
  shjson_t *error;
  char *err_msg;
  int err;

  if (err_code == 21)
    err_msg = "Job not found";
  else if (err_code == 22)
    err_msg = "Duplicate share";
  else if (err_code == 23)
    err_msg = "Low difficulty";
  else if (err_code == 24)
    err_msg = "Unauthorized worker";
  else if (err_code == 25)
    err_msg = "Not subscribed";
  else if (err_code == 61)
    err_msg = "Bad session id";
  else if (err_code == 62)
    err_msg = "Job not found";
  else /* if (err_code == 20) */
    err_msg = "Other/Unknown";

  reply = shjson_init(NULL);
  set_stratum_error(reply, err_code, err_msg);
/*
  error = shjson_array_add(reply, "error");
  shjson_num_add(error, NULL, err_code);
  shjson_str_add(error, "error", err_msg);
  shjson_null_add(error, NULL);
*/
  shjson_bool_add(reply, "result", FALSE);
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

int stratum_send_subscribe(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  shjson_t *data2;
  char nonce_str[64];
  char key_str[64];
  int err;

  reply = shjson_init(NULL);
  shjson_null_add(reply, "error");
  data = shjson_array_add(reply, "result");
  data2 = shjson_array_add(data, NULL);
  shjson_str_add(data2, NULL, "mining.notify");
  shjson_str_add(data2, NULL, 
      (char *)shkey_print(ashkey_str(user->peer.nonce1)));
  shjson_str_add(data, NULL, user->peer.nonce1);
  shjson_num_add(data, NULL, 4);
//  shjson_str_add(data, NULL, stratum_runtime_session());
  err = stratum_send_message(user, reply);
  shjson_free(&reply);
 
  return (err);
}

static void shscrypt_swab256(void *dest_p, const void *src_p)
{
  uint32_t *dest = dest_p;
  const uint32_t *src = src_p;

  dest[0] = swab32(src[7]);
  dest[1] = swab32(src[6]);
  dest[2] = swab32(src[5]);
  dest[3] = swab32(src[4]);
  dest[4] = swab32(src[3]);
  dest[5] = swab32(src[2]);
  dest[6] = swab32(src[1]);
  dest[7] = swab32(src[0]);
}


int stratum_send_task(user_t *user, task_t *task, int clean)
{
  shjson_t *reply;
  shjson_t *param;
  shjson_t *merk_ar;
  char proto_str[32];
  char hash_swap[32];
  char prev_bin[32];
  char prev_hash[128];
  char merk_bin[32];
  char merk_hash[128];
  char time_str[32];
  char task_id[32];
  uint64_t cb1;

  int err;
  int i;

  if (!(user->flags & USER_SUBSCRIBE))
    return (0);

#if 0
  if (task->height < user->height)
    return (SHERR_INVAL);
#endif

  sprintf(proto_str, "%-8.8x", task->version);
  sprintf(time_str, "%-8.8x", task->curtime);
  sprintf(task_id, "%-8.8x", task->task_id);

  hex2bin(hash_swap, task->prev_hash, 32);
  shscrypt_swap256(prev_bin, hash_swap);
  memset(prev_hash, 0, sizeof(prev_hash));
  bin2hex(prev_hash, prev_bin, 32);

  strcpy(user->cur_id, "");

  reply = shjson_init(NULL);
  shjson_str_add(reply, "method", "mining.notify");
  param = shjson_array_add(reply, "params");
  shjson_str_add(param, NULL, task_id);
  shjson_str_add(param, NULL, prev_hash);
  shjson_str_add(param, NULL, task->cb1);
  shjson_str_add(param, NULL, task->cb2);
  merk_ar = shjson_array_add(param, NULL);
  for (i = 0; i < task->merkle_len; i++) {
    hex2bin(hash_swap, task->merkle[i], 32);
    shscrypt_swab256(prev_bin, hash_swap);
    memset(merk_hash, 0, sizeof(merk_hash));
    bin2hex(merk_hash, prev_bin, 32);

    shjson_str_add(merk_ar, NULL, merk_hash);
  }
  shjson_str_add(param, NULL, proto_str);
  shjson_str_add(param, NULL, task->nbits);
  shjson_str_add(param, NULL, time_str); /* ntime */
  shjson_bool_add(param, NULL, task->work_reset);

  err = stratum_send_message(user, reply);
  shjson_free(&reply);


  return (err);
}
