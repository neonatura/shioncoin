
/*
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
 */

#define __SERVER__SHLOGD_TASK_C__
#include <share.h>
#include "sharelog_server.h"

shfs_t *daemon_task_fs;
shmap_t *daemon_buff_map;

int daemon_task_init(void)
{

  if (!daemon_buff_map)
    daemon_buff_map = shmap_init();
  
  if (!daemon_task_fs)
    daemon_task_fs = shfs_init(NULL);

  return (0);
}

/**
 * Sends textual JSON reply message to a log client.
 */
int shlogd_sock_write(sock_t *user, shjson_t *msg)
{
  char *text;
  int err;

  if (!user) {
    return (0);
  }
  if (user->fd == -1) {
    return (0);
  }

  text = shjson_print(msg);
  err = shnet_write(user->fd, text, strlen(text));
  if (err == -1)
    return (-errno);
  err = shnet_write(user->fd, "\n", 1);
  if (err == -1)
    return (-errno);
  free(text);

  return (0);
}

SHFL *daemon_log_file(shkey_t *log_src)
{
  SHFL *fl;
  char path[256];
  char *tstr;

  tstr = shstrtime(shtime(), "%Y.%m");
  sprintf(path, "/log/%s/%s", tstr, shkey_hex(log_src));
  fl = shfs_file_find(daemon_task_fs, path); 

  return (fl);
}

/**
 * @todo set inode format to compressed
 */
void daemon_task_flush(shkey_t *log_src)
{
  SHFL *fl;
  shbuf_t *buff;
  char tbuf[256];
  char path[256];
  time_t now;


  buff = shmap_get_ptr(daemon_buff_map, log_src);
  if (!buff || shbuf_size(buff) == 0)
    return;

  fl = daemon_log_file(log_src);
  shfs_write(fl, buff);
  shbuf_clear(buff);

}


void daemon_task_list(shbuf_t *buff, shkey_t *log_src, shtime_t stime, shtime_t etime)
{
  SHFL *fl;

  /* flush to disk */
  daemon_task_flush(log_src);

  fl = daemon_log_file(log_src);
  shfs_read(fl, buff);
}

int daemon_request_task(sock_t *user, shjson_t *json)
{
  shjson_t *reply;
  shkey_t *key;
  shbuf_t *buff;
  char method[256];
  char *str;
  int idx;
  int err;

  if (!user || !json)
    return (SHERR_INVAL);

  idx = (int)shjson_num(json, "id", -1);

  memset(method, 0, sizeof(method));
  str = shjson_astr(json, "method", NULL);
    strncpy(method, str, sizeof(method));

  str = shjson_astr(json, "key", NULL);
  if (str && *str) {
    key = shkey_gen(str);
  }
    
  if (0 == strcmp(method, "log.list")) {
    buff = shbuf_init();
    daemon_task_list(buff, key, 0, 0);

    reply = shjson_init(NULL);
    shjson_num_add(reply, "id", idx);
    shjson_null_add(reply, "error");
    shjson_str_add(reply, "key", shkey_print(key));
    if (shbuf_size(buff) == 0)
      shjson_null_add(reply, "result");
    else
      shjson_str_add(reply, "result", shbuf_data(buff));
    shbuf_free(&buff);
    err = shlogd_sock_write(user, reply);
    shjson_free(&reply);
  } else if (0 == strcmp(method, "log.subscribe")) {
    user->flags |= SKUSERF_BROADCAST;
    user->bc_idx = idx;
  } else if (0 == strcmp(method, "status.version")) {
    reply = shjson_init(NULL);
    shjson_num_add(reply, "id", idx);
    shjson_null_add(reply, "error");
    shjson_str_add(reply, "result", (char *)get_libshare_version());
    err = shlogd_sock_write(user, reply);
    shjson_free(&reply);
  } else {
    reply = shjson_init(NULL);
    shjson_num_add(reply, "id", idx);
    shjson_null_add(reply, "error");
    shjson_null_add(reply, "result");
    err = shlogd_sock_write(user, reply);
    shjson_free(&reply);
  }

  return (err);
}

shbuf_t *daemon_log_load(shkey_t *log_src)
{
  shbuf_t *buff;
  SHFL *fl;

  buff = shbuf_init();

  fl = daemon_log_file(log_src);
  shfs_read(fl, buff);

  return (buff);
}

void daemon_task_prune_file(void)
{
  char path[SHFS_PATH_MAX+1];
  char *tstr;
  shtime_t expire_t;
  shtime_t start_t;
  int expire_dur;

  expire_dur = MAX(2592000,
      atoi(shpref_get("shlogd.expire", "31536000"))); /* default : year */
  expire_t = shtime_adj(shtime(), -1 * expire_dur);

  start_t = shtime_adj(expire_t, -31536000);
  while (start_t < expire_t) {
    tstr = shstrtime(start_t, "%Y.%m");
    sprintf(path, "/log/%s/", tstr);
    shfs_unlink(daemon_task_fs, path);

    start_t = shtime_adj(start_t, 2592000); /* +1 month */
  }

}

void daemon_task_append_file(char *log_text, shkey_t *log_src)
{
  shbuf_t *buff;
  char tbuf[256];
  time_t now;

  buff = shmap_get_ptr(daemon_buff_map, log_src);
  if (!buff) {
    buff = daemon_log_load(log_src);
    shmap_set_ptr(daemon_buff_map, log_src, buff);
  }

  now = time(NULL);
  strftime(tbuf, sizeof(tbuf) - 1, "[%D %T] ", localtime(&now));
  shbuf_catstr(buff, tbuf);
  shbuf_catstr(buff, log_text);
}

void daemon_task_append_user(char *log_text, shkey_t *log_src)
{
  sock_t *user;
  shjson_t *reply;
  int err;

  if (!log_text || !log_src)
    return;

  for (user = client_list; user; user = user->next) {
    if (user->fd == -1)
      continue;

    if (user->flags & SKUSERF_BROADCAST) {
      reply = shjson_init(NULL);
      shjson_num_add(reply, "id", user->bc_idx);
      shjson_null_add(reply, "error");
      shjson_str_add(reply, "key", shkey_print(log_src));
      shjson_str_add(reply, "result", log_text);
      err = shlogd_sock_write(user, reply);
      shjson_free(&reply);
    }
  }
}

void daemon_task_append(char *log_text, shkey_t *log_src)
{
  static int prune_idx;

  prune_idx++;
  if (0 == (prune_idx % 4096))
    daemon_task_prune_file();

  daemon_task_append_file(log_text, log_src);
  daemon_task_append_user(log_text, log_src);
}

void daemon_task_flush_pending(int force)
{
  shmap_index_t *hi;
  shkey_t *key;
  char *val;
  ssize_t len;

  for (hi = shmap_first(daemon_buff_map); hi; hi = shmap_next(hi)) {
    shmap_this(hi, (void *)&key, &len, (void*) &val);
    daemon_task_flush(key);
  }

}

void daemon_task_term(void)
{
  /* free the stored mem buffs */
  daemon_task_flush_pending(TRUE);

  shfs_free(&daemon_task_fs);
  shmap_free(&daemon_buff_map);
}


