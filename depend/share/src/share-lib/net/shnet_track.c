
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

/**
 * @returns TRUE or FALSE whether record is active based on creation time and trust value.
 */
static int shnet_track_fresh(time_t ctime, int cond)
{
  double diff;
  double deg;
  time_t now;

  if (cond >= 0)
    return (TRUE);

  now = time(NULL);
  if (ctime > (now - 172800)) {
    /* records are not considered stale until at least two days. */
    return (TRUE);
  }

  if (cond >= 0) {
    /* record is not in an un-healthy condition. */
    return (TRUE);
  }

  /* older records are considered healthier */
  diff = ctime - now;
  deg = 43200 / diff * fabs(cond);
  if (deg >= -1.0)
    return (TRUE);

  return (FALSE);
}

static int shdb_peer_list_cb(void *p, int arg_nr, char **args, char **cols)
{
  shpeer_t **peer_list = (shpeer_t **)p;
  int idx;

  for (idx = 0; peer_list[idx]; idx++);

  if (arg_nr >= 2) {
    if (args[0] && args[1])
      peer_list[idx] = shpeer_init(args[0], args[1]);
  }

  return (0);
}

static int shdb_peer_count_cb(void *p, int arg_nr, char **args, char **cols)
{
  unsigned int *tot_p = (unsigned int *)p;

  *tot_p = *tot_p + 1;
  return (0);
}

static void shnet_track_col_init(shdb_t *db)
{
  shdb_col_new(db, TRACK_TABLE_NAME, "host");
  shdb_col_new(db, TRACK_TABLE_NAME, "label");
  shdb_col_new(db, TRACK_TABLE_NAME, "trust");
  shdb_col_new(db, TRACK_TABLE_NAME, "ctime"); /* creation */
  shdb_col_new(db, TRACK_TABLE_NAME, "mtime"); /* last attempt */
}

shdb_t *shnet_track_open(char *name)
{
  shdb_t *db;
  int err;

  if (!name)
    name = NET_DB_NAME;

  db = shdb_open(name);
  if (!db)
    return (NULL);

  err = shdb_table_new(db, TRACK_TABLE_NAME);
  if (!err) {
    if (!name)
      shinfo("initializing default network tracking database.");
    shnet_track_col_init(db);

/*
    shdb_col_new(db, TRACK_TABLE_NAME, "ltime"); // last connect
    shdb_col_new(db, TRACK_TABLE_NAME, "key");
    shdb_col_new(db, TRACK_TABLE_NAME, "cert");
*/
  }

  return (db);
}

void shnet_track_close(shdb_t *db)
{
  if (db)
    shdb_close(db);
}

int shnet_track_add(shdb_t *db, shpeer_t *peer)
{
  char hostname[MAXHOSTNAMELEN+1];
  char id_str[512];
  char buf[512];
  shdb_idx_t rowid;
  int port;
  int err;

  shpeer_host(peer, hostname, &port);
  sprintf(id_str, "%s %d", hostname, port);
  err = shdb_row_find(db, TRACK_TABLE_NAME, &rowid, "host", id_str, 0);
  if (!err) {
    /* record already exists -- all done */
    return (0);
  }

  err = shdb_row_new(db, TRACK_TABLE_NAME, &rowid);
  if (err)
    goto done;

  err = shdb_row_set(db, TRACK_TABLE_NAME, rowid, "host", id_str);
  if (err)
    goto done;

  err = shdb_row_set_time(db, TRACK_TABLE_NAME, rowid, "ctime");
  if (err)
    goto done;

  err = shdb_row_set(db, TRACK_TABLE_NAME, rowid,
      "label", shpeer_get_app(peer));
  if (err)
    goto done;

#if 0
  strcpy(buf, shkey_print(shpeer_kpriv(peer)));
  err = shdb_row_set(db, TRACK_TABLE_NAME, rowid, "key", buf);
  if (err)
    goto done;
#endif

done:
  return (err);
}

int shnet_track_remove(shdb_t *db, shpeer_t *peer)
{
  char hostname[MAXHOSTNAMELEN+1];
  char id_str[512];
  char buf[512];
  shdb_idx_t rowid;
  int port;
  int err;

  if (!peer)
    return (0); /* all done */

  shpeer_host(peer, hostname, &port);
  sprintf(id_str, "%s %d", hostname, port);
  err = shdb_row_find(db, TRACK_TABLE_NAME, &rowid, "host", id_str, 0);
  if (err)
    return (err);

  err = shdb_row_delete(db, TRACK_TABLE_NAME, rowid);
  if (err)
    return (err);

  return (0);
}


/**
 * Marks a network adderss in a positive or negative manner.
 * @param cond a negative or positive number indicating connection failure or success.
 */
int shnet_track_mark(shdb_t *db, shpeer_t *peer, int cond)
{
  char hostname[MAXHOSTNAMELEN+1];
  char id_str[512];
  char buf[128];
  char *str;
  uint64_t rowid;
  long trust;
  int port;
  int err;

  shpeer_host(peer, hostname, &port);
  sprintf(id_str, "%s %d", hostname, port);
  err = shdb_row_find(db, TRACK_TABLE_NAME, &rowid, "host", id_str, 0);
  if (err)
    return (err);

  str = shdb_row_value(db, TRACK_TABLE_NAME, rowid, "trust");
  if (!str)
    str = strdup("");

  trust = (long)atoll(str);
  free(str);

  if (cond < 0) {
    if (cond < -256) cond = -256;
  } else if (cond > 0) {
    if (cond > 256) cond = 256;
  }

  /* 2 billion total range */
  trust = MAX(-1000000000, MIN(1000000000, trust + cond));

  if (trust < 0) {
    time_t ctime = shdb_row_time(db, TRACK_TABLE_NAME, rowid, "ctime");
    if (!shnet_track_fresh(ctime, trust)) {
      err = shdb_row_delete(db, TRACK_TABLE_NAME, rowid);
      goto done;
    }
  }

  sprintf(buf, "%ld", trust);
  err = shdb_row_set(db, TRACK_TABLE_NAME, rowid, "trust", buf);
  if (err)
    goto done;

  err = shdb_row_set_time(db, TRACK_TABLE_NAME, rowid, "mtime");
  if (err)
    goto done;

#if 0
  if (cond > 0) {
    err = shdb_row_set_time(db, TRACK_TABLE_NAME, rowid, "ltime");
    if (err)
      goto done;
  }
#endif

  err = 0;

done:
  return (err);
}

shpeer_t **shnet_track_scan(shdb_t *db, shpeer_t *peer, int list_max)
{
  shpeer_t **peer_list;
  char sql_str[1024];
  char app_name[MAX_SHARE_NAME_LENGTH];
  time_t min_time;
  int err;

  if (!peer)
    return (NULL);

  memset(app_name, 0, sizeof(app_name));
  strncpy(app_name, shpeer_get_app(peer), sizeof(app_name)-1);

  peer_list = (shpeer_t **)calloc(list_max + 1, sizeof(shpeer_t *));
  if (!peer_list)
    return (NULL);

  list_max = MAX(1, MIN(1000, list_max));
  //min_time = time(NULL) - 3600; /* one hour ago */
  sprintf(sql_str, "select label,host from %s where label = '%s' order by mtime limit %u", TRACK_TABLE_NAME, app_name, (unsigned int)list_max);
  err = shdb_exec_cb(db, sql_str, shdb_peer_list_cb, peer_list);
  if (err) {
    PRINT_ERROR(err, "shnet_track_scan");
    shnet_track_col_init(db); /* DEBUG: */
  }

  return (peer_list);
}

shpeer_t **shnet_track_list(shdb_t *db, shpeer_t *peer, int list_max)
{
  shpeer_t **peer_list;
  char sql_str[512];
  char app_name[MAX_SHARE_NAME_LENGTH];
  char *ret_val;
  int err;

  if (!peer)
    return (NULL);

  memset(app_name, 0, sizeof(app_name));
  strncpy(app_name, shpeer_get_app(peer), sizeof(app_name)-1);

  peer_list = (shpeer_t **)calloc(list_max + 1, sizeof(shpeer_t *));
  if (!peer_list)
    return (NULL);

  /* retrieve most X trusted hosts for service name. */
  list_max = MAX(1, MIN(1000, list_max));
  sprintf(sql_str, "select label,host from %s where label = '%s' order by trust desc limit %d", TRACK_TABLE_NAME, app_name, list_max);
  err = shdb_exec_cb(db, sql_str, shdb_peer_list_cb, peer_list);
  if (err) {
    PRINT_ERROR(err, "shnet_track_list");
    shnet_track_col_init(db); /* DEBUG: */
  }

  return (peer_list);
}

int shnet_track_verify(shpeer_t *peer, int *sk_p)
{
  static char buf[32];
  struct timeval to;
  fd_set w_set;
  socklen_t ret_size;
  int ret;
  int err;
  int sk;

  if (!sk_p)
    return (SHERR_INVAL);
  
  sk = *sk_p;
  if (sk == 0) {
    /* initiate async connection to remote host for verification */
    sk = shconnect_peer(peer, SHNET_CONNECT | SHNET_ASYNC);
    if (sk < 0) {
      /* immediate error state */
      return (0);
    }

    /* async connection has begun. */
    *sk_p = sk;
  }

  FD_ZERO(&w_set);
  FD_SET(sk, &w_set);
  memset(&to, 0, sizeof(to));
  err = shnet_select(sk + 1, NULL, &w_set, NULL, &to);
#if 0
  if (err < 0) {
    *sk_p = 0;
    shnet_close(sk);
    return (errno2sherr());
  }
#endif
  if (err == 0)
    return (SHERR_INPROGRESS);

  ret = 0;
  ret_size = sizeof(ret);
  err = getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &ret_size);
  if (err) {
    ret = errno2sherr();
  } else {
    ret = -ret;
  }

  *sk_p = 0;
  shnet_close(sk);

  return (ret);
}

_TEST(shnet_track)
{
  shdb_t *db;
  shpeer_t **scan_peers;
  shpeer_t *peer;
  int err;
  int sk;

  /* open net track db */
  db = shnet_track_open(NULL);
  _TRUEPTR(db);

  /* create a new peer */
  peer = shpeer_init("", "127.0.0.1:111");
  err = shnet_track_add(db, peer);
  if (err) {
    /* last run failed */
    shdb_table_delete(db, TRACK_TABLE_NAME);
  }
  _TRUE(err == 0);


  /* scan db for fresh peer */
  scan_peers = shnet_track_scan(db, peer, 1);
  _TRUEPTR(scan_peers);
  _TRUEPTR(scan_peers[0]);
  _TRUE(shkey_cmp(shpeer_kpriv(peer), shpeer_kpriv(scan_peers[0])));
  free(scan_peers);

  /* verify peer */
  sk = 0;
  while ((err = shnet_track_verify(peer, &sk)) == SHERR_INPROGRESS) {
    usleep(10000); /* 10ms */
  }
  _TRUE(err == 0);

  /* increment status */
  err = shnet_track_incr(db, peer);
  _TRUE(err == 0);

  /* decrement status to stale state */
  {
    char hostname[256];
    char id_str[256];
    int port;
    uint64_t rowid;

    shpeer_host(peer, hostname, &port);
    sprintf(id_str, "%s %d", hostname, port);
    _TRUE(0 == shdb_row_find(db, TRACK_TABLE_NAME, &rowid, "host", id_str, 0));
    _TRUE(0 == shdb_row_set_time_adj(db, 
          TRACK_TABLE_NAME, rowid, "ctime", -604800)); /* one week ago */
  }
  _TRUE(0 == shnet_track_mark(db, peer, -256));

  /* verify peer has been removed. */
  err = shnet_track_remove(db, peer);
  _TRUE(SHERR_NOENT == err);

  shpeer_free(&peer);
  shdb_close(db);
}

int shnet_track_find(shdb_t *db, shpeer_t *peer)
{
  char hostname[MAXHOSTNAMELEN+1];
  char id_str[512];
  char buf[512];
  shdb_idx_t rowid;
  int port;
  int err;

  shpeer_host(peer, hostname, &port);
  sprintf(id_str, "%s %d", hostname, port);
  err = shdb_row_find(db, TRACK_TABLE_NAME, &rowid, "host", id_str, 0);
  if (err)
    return (err);

  return (0);
}

int shnet_track_count(shdb_t *db, char *app_name)
{
  char sql_str[512];
  int ret_count;
  int err;

  ret_count = 0;
  sprintf(sql_str, "select label from %s where label = '%s'", TRACK_TABLE_NAME, app_name);
  err = shdb_exec_cb(db, sql_str, shdb_peer_count_cb, &ret_count);
  if (err) {
    PRINT_ERROR(err, "shnet_track_count");
  }

  return (ret_count);
}

int shnet_track_incr(shdb_t *db, shpeer_t *peer)
{
  int err;

  err = shnet_track_mark(db, peer, 1);
  if (err) {
    err = shnet_track_add(db, peer);
  }

  return (err);
}

int shnet_track_decr(shdb_t *db, shpeer_t *peer)
{
  return (shnet_track_mark(db, peer, -1));
}


int shnet_track_prune(char *name)
{
  shdb_t *db;
  char sql_str[512];
  int err;

  db = shnet_track_open(name);
  if (!db)
    return (SHERR_INVAL);

  sprintf(sql_str, "delete from %s where trust < 0", TRACK_TABLE_NAME);
  err = shdb_exec(db, sql_str);
  shnet_track_close(db);

  return (err);
}
