
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
#include "shapi/shapi.h"

extern shjson_t *shjson_null_add(shjson_t *tree, char *name);

char *shapi_runtime_session(void)
{
  static char buf[32];

  if (!*buf) {
    sprintf(buf, "%-8.8x", time(NULL));
  }

  return (buf);
}

uint32_t shapi_request_id(void)
{
  static uint32_t idx;

  if (!idx) {
    idx = (rand() & 0xFFFF)  + 0xFF;
  }

  return (++idx);
}

/**
 * @returns The coin interface with the specified name.
 */
int shapi_get_iface(char *iface_str)
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

int shapi_request_message(shapi_t *user, shjson_t *json)
{
  shjson_t *reply;
  shapi_t *t_user;
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

  memset(iface_str, 0, sizeof(iface_str));
  text = shjson_astr(json, "iface", NULL);
  if (text)
    strncpy(iface_str, text, sizeof(iface_str)-1); 
  ifaceIndex = shapi_get_iface(iface_str);
#if 0
  if (ifaceIndex < 1)
    ifaceIndex = user->ifaceIndex;//shapi_default_iface();
#endif
  if (ifaceIndex < 1)
    ifaceIndex = SHC_COIN_IFACE; /* default */

  method = shjson_astr(json, "method", NULL);
  if (!method) {
    /* no operation method specified. */
    return (SHERR_INVAL);
  }

  timing_init(method, &ts);
	if (0 == strncmp(method, "api.", 4)) {
		shjson_t *reply = shapi_request_api(ifaceIndex, user, method,
				shjson_obj(json, "params"), shjson_obj(json, "auth"));
		if (!reply)
			return (ERR_INVAL);
		shapi_send_message(user, reply);
		shjson_free(&reply);
		return (0);
	}
  timing_term(ifaceIndex, method, &ts);

  /* unknown request in proper JSON format. */
  reply = shjson_init(NULL);
  set_shapi_error(reply, ERR_NOMETHOD, "invalid command");
  shjson_null_add(reply, "result");
  err = shapi_send_message(user, reply);
  shjson_free(&reply);
  return (err);
}

void set_shapi_error(shjson_t *reply, int code, char *str)
{
  shjson_t *error;

  error = shjson_array_add(reply, "error");
  shjson_num_add(error, NULL, code);
  shjson_str_add(error, NULL, str);
  shjson_null_add(error, NULL);

}

int shapi_send_message(shapi_t *user, shjson_t *msg)
{
  uint32_t val;
  char *text;
  int err;

  if (!user) {
    shcoind_log("shapi_send_message: shapi_send_message: null user");
    return (0);
  }

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
    free(text);
  }

  return (0);
}

