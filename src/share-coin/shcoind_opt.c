
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



static shmap_t *_proc_option_table;
#define OPT_LIST _proc_option_table

void opt_print(void)
{
  char buf[512];

  sprintf(buf, "info: option '%s' set to 'true'.", OPT_DEBUG);
  shcoind_info("config", buf); 

  sprintf(buf, "info: option '%s' set to '%d'.", 
      OPT_MAX_CONN, opt_num(OPT_MAX_CONN));
  shcoind_info("config", buf); 

  sprintf(buf, "info: option '%s' set to '%s'.", 
      OPT_PEER_SEED, opt_bool(OPT_PEER_SEED) ? "true" : "false");
  shcoind_info("config", buf); 

  sprintf(buf, "info: option '%s' set to '%d'.", 
      OPT_BAN_SPAN, opt_num(OPT_BAN_SPAN));
  shcoind_info("config", buf); 

  sprintf(buf, "info: option '%s' set to '%d'.", 
      OPT_BAN_THRESHOLD, opt_num(OPT_BAN_THRESHOLD));
  shcoind_info("config", buf); 

  sprintf(buf, "info: option '%s' set to '%s'.", 
      OPT_ADMIN, opt_bool(OPT_ADMIN) ? "true" : "false");
  shcoind_info("config", buf); 

#ifdef STRATUM_SERVICE
  sprintf(buf, "info: option '%s' set to '%s'.", 
      OPT_SERV_STRATUM, opt_bool(OPT_SERV_STRATUM) ? "true" : "false");
  shcoind_info("config", buf); 

  sprintf(buf, "info: option '%s' set to '%d'.", 
      OPT_STRATUM_PORT, opt_num(OPT_STRATUM_PORT));
  shcoind_info("config", buf); 
#endif

#ifdef RPC_SERVICE
  sprintf(buf, "info: option '%s' set to '%s'.", 
      OPT_SERV_RPC, opt_bool(OPT_SERV_RPC) ? "true" : "false");
  shcoind_info("config", buf); 

  sprintf(buf, "info: option '%s' set to '%d'.", 
      OPT_RPC_PORT, opt_num(OPT_RPC_PORT));
  shcoind_info("config", buf); 
#endif

}

static void opt_set_defaults(void)
{
  char buf[256];

  memset(buf, 0, sizeof(buf));

  /** 
   * Whether to log verbose debugging information.
   */
  strncpy(buf, shpref_get("shcoind.debug", ""), sizeof(buf)-1);
  if (tolower(*buf) == 't')
    opt_bool_set(OPT_DEBUG, TRUE); 

  /**
   * The maximum number of inbound connections to allow for each coin service.
   */
  strncpy(buf, shpref_get("shcoind.net.max", ""), sizeof(buf)-1);
  if (isdigit(*buf))
    opt_num_set(OPT_MAX_CONN, MAX(0, atoi(buf)));
  if (opt_num(OPT_MAX_CONN) == 0)
    opt_num_set(OPT_MAX_CONN, 300); /* default */

  strncpy(buf, shpref_get("shcoind.net.seed", ""), sizeof(buf)-1);
  if (tolower(*buf) == 'f')
    opt_bool_set(OPT_PEER_SEED, FALSE);
  else
    opt_bool_set(OPT_PEER_SEED, TRUE); /* default */

  /**
   * The time-span (in seconds) before a ban is lifted.
   */
  strncpy(buf, shpref_get("shcoind.ban.span", ""), sizeof(buf)-1);
  if (isdigit(*buf))
    opt_num_set(OPT_BAN_SPAN, MAX(0, atoi(buf)));
  if (opt_num(OPT_BAN_SPAN) == 0)
    opt_num_set(OPT_BAN_SPAN, 21600); /* 6-hour default */

  /**
   * The minimum 'misbehaviour rate' of a coin service connection before it is banned.
   */
  strncpy(buf, shpref_get("shcoind.ban.threshold", ""), sizeof(buf)-1);
  if (isdigit(*buf))
    opt_num_set(OPT_BAN_THRESHOLD, MAX(0, atoi(buf)));
  if (opt_num(OPT_BAN_THRESHOLD) == 0)
    opt_num_set(OPT_BAN_THRESHOLD, 1000); /* default */

  strncpy(buf, shpref_get("shcoind.admin", ""), sizeof(buf)-1);
  if (tolower(*buf) == 'f')
    opt_bool_set(OPT_ADMIN, FALSE);
  else
    opt_bool_set(OPT_ADMIN, TRUE); /* default */

#ifndef USDE_SERVICE
  opt_bool_set(OPT_SERV_USDE, FALSE);
#else
  strncpy(buf, shpref_get(OPT_SERV_USDE, ""), sizeof(buf)-1);
  if (tolower(*buf) == 'f')
    opt_bool_set(OPT_SERV_USDE, FALSE);
  else
    opt_bool_set(OPT_SERV_USDE, TRUE); /* default */
#endif

#ifndef EMC2_SERVICE
  opt_bool_set(OPT_SERV_EMC2, FALSE);
#else
  strncpy(buf, shpref_get(OPT_SERV_EMC2, ""), sizeof(buf)-1);
  if (tolower(*buf) == 'f')
    opt_bool_set(OPT_SERV_EMC2, FALSE);
  else
    opt_bool_set(OPT_SERV_EMC2, TRUE); /* default */
#endif

#ifndef STRATUM_SERVICE
  opt_bool_set(OPT_SERV_STRATUM, FALSE);
  opt_num_set(OPT_STRATUM_PORT, 0);
#else
  strncpy(buf, shpref_get(OPT_SERV_STRATUM, ""), sizeof(buf)-1);
  if (tolower(*buf) == 'f')
    opt_bool_set(OPT_SERV_STRATUM, FALSE);
  else
    opt_bool_set(OPT_SERV_STRATUM, TRUE); /* default */

  strncpy(buf, shpref_get(OPT_STRATUM_PORT, ""), sizeof(buf)-1);
  if (isdigit(*buf))
    opt_num_set(OPT_STRATUM_PORT, MAX(0, atoi(buf)));
  if (opt_num(OPT_STRATUM_PORT) == 0)
    opt_num_set(OPT_STRATUM_PORT, STRATUM_DAEMON_PORT); /* default */
#endif

#ifndef RPC_SERVICE
  opt_bool_set(OPT_SERV_RPC, FALSE);
  opt_num_set(OPT_RPC_PORT, 0);
#else
  strncpy(buf, shpref_get(OPT_SERV_RPC, ""), sizeof(buf)-1);
  if (tolower(*buf) == 'f')
    opt_bool_set(OPT_SERV_RPC, FALSE);
  else
    opt_bool_set(OPT_SERV_RPC, TRUE); /* default */

  strncpy(buf, shpref_get("shcoind.rpc.port", ""), sizeof(buf)-1);
  if (isdigit(*buf))
    opt_num_set(OPT_RPC_PORT, MAX(0, atoi(buf)));
  if (opt_num(OPT_RPC_PORT) == 0)
    opt_num_set(OPT_RPC_PORT, 9447); /* default */
#endif

}

void opt_init(void)
{
  OPT_LIST = shmap_init();

  opt_set_defaults();
}

void opt_term(void)
{

  if (!OPT_LIST)
    return;

  shmap_free(&OPT_LIST);
  OPT_LIST = NULL;
}

int opt_num(char *tag)
{
  void *v = shmap_get(OPT_LIST, ashkey_str(tag));
  return ((int)(uint64_t)v);
}

void opt_num_set(char *tag, int num)
{
  void *v = (void *)(uint64_t)num;
  shmap_set(OPT_LIST, ashkey_str(tag), v);
}

const char *opt_str(char *tag)
{
  char *str = shmap_get_str(OPT_LIST, ashkey_str(tag));
  return ((const char *)str);
}

void opt_str_set(char *tag, char *str)
{
  shmap_set_astr(OPT_LIST, ashkey_str(tag), str);
}

int opt_bool(char *tag)
{
  int b = opt_num(tag) ? TRUE : FALSE;
  return (b);
}

void opt_bool_set(char *tag, int b)
{
  opt_num_set(tag, b ? TRUE : FALSE);
}


