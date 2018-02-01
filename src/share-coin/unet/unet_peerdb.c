
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
#include "unet_seed.h"

#define INIT_UNET_PEER_SCAN_SIZE 8
#define MAX_UNET_PEER_SCAN_SIZE 64

#define MAX_PEERDB_TRACK_LIST_SIZE 1000
#define MAX_PEERDB_TRACK_PRUNE_SIZE 100

typedef struct peerdb_t
{
  shpeer_t peer;
  uint32_t birth;
  int64_t trust;
} peerdb_t;

static void peerdb_list_free(peerdb_t **p_list)
{
  int i;

  for (i = 0; p_list[i]; i++) {
    if (p_list[i])
      free(p_list[i]);
  }

  free(p_list);
}

static void peerdb_key_hash(shkey_t *key, bc_hash_t *hash_p)
{
  memset(hash_p, 0, sizeof(bc_hash_t));
  memcpy(hash_p, key, MIN(sizeof(shkey_t), sizeof(bc_hash_t)));
}

char *peerdb_mode_label(int mode)
{
  static char ret_str[256];
  sprintf(ret_str, "%s_peer", unet_mode_label(mode));
  return ((char *)ret_str);
}

static bc_t *peerdb_open(int mode)
{
  unet_bind_t *bind;
  bc_t *bc;
  int err;

  bind = unet_bind_table(mode);
  if (!bind)
    return (NULL);

  if (bind->peer_db == NULL) {
    (void)bc_open(peerdb_mode_label(mode), &bind->peer_db);
  }

  return (bind->peer_db);
}

static peerdb_t *peerdb_new(int mode, shpeer_t *peer)
{
  peerdb_t *ret_peer;

  ret_peer = (peerdb_t *)calloc(1, sizeof(peerdb_t));

  memset(ret_peer, 0, sizeof(ret_peer));
  ret_peer->birth = (uint32_t)time(NULL);
  memcpy(&ret_peer->peer, peer, sizeof(shpeer_t));

  return (ret_peer);
}

static peerdb_t *peerdb_new_host(int mode, char *hostname, unsigned int port)
{
  peerdb_t *p;
  shpeer_t *peer;

  p = (peerdb_t *)calloc(1, sizeof(peerdb_t));
  if (!p)
    return (NULL);
 
  sprintf(hostname, "%s %u", hostname, port);
  peer = shpeer_init((char *)unet_mode_label(mode), hostname);
  p = peerdb_new(mode, peer);
  shpeer_free(&peer);

  return (p);
}

static int peerdb_read_index(bc_t *db, int pos, peerdb_t **peer_p)
{
  unsigned char *data;
  size_t data_len;
  int err;

  /* does index exist? (redundant) */
  err = bc_idx_get(db, pos, NULL);
  if (err)
    return (err);

  err = bc_get(db, pos, (unsigned char **)&data, &data_len);
  if (err)
    return (err);

  if (peer_p)
    *peer_p = (peerdb_t *)data;
  else
    free(data);

  return (0);
}

static int peerdb_read(bc_t *db, shkey_t *key, peerdb_t **peer_p)
{
  unsigned char *data;
  size_t data_len;
  bc_hash_t hash;
  int pos;
  int err;  

  pos = -1;
  peerdb_key_hash(key, &hash);
  err = bc_idx_find(db, hash, NULL, &pos); 
  if (err)
    return (err);

  return (peerdb_read_index(db, pos, peer_p));
}

static int peerdb_sort_cmp(void *a_p, void *b_p)
{
  peerdb_t *a = *((peerdb_t **)a_p);
  peerdb_t *b = *((peerdb_t **)b_p);

  return (b->trust - a->trust);
}
static int peerdb_sort_revcmp(void *a_p, void *b_p)
{
  peerdb_t *a = *((peerdb_t **)a_p);
  peerdb_t *b = *((peerdb_t **)b_p);

  return (a->trust - b->trust);
}



static void peerdb_sort(peerdb_t **ret_list, size_t ret_size, int fact)
{
  if (fact > 0)
    qsort(ret_list, ret_size, sizeof(peerdb_t *), peerdb_sort_cmp); 
  else
    qsort(ret_list, ret_size, sizeof(peerdb_t *), peerdb_sort_revcmp); 
}

static peerdb_t **peerdb_track_scan(bc_t *db, int max)
{
  static uint32_t _scan_index;
  peerdb_t **ret_list;
  peerdb_t *p;
  int ret_cnt;
  int db_max;
  int err;
  int i;

  db_max = bc_idx_next(db); 
  max = MIN(max, db_max);
  max = MIN(max, MAX_PEERDB_TRACK_LIST_SIZE);
  if (max == 0) {
    ret_list = (peerdb_t **)calloc(1, sizeof(peerdb_t));
    return (ret_list);
  } 

  ret_list = (peerdb_t **)calloc(max+1, sizeof(peerdb_t));
  if (!ret_list)
    return (NULL);

  ret_cnt = 0;
  for (i = 0; i < max; i++) {
    err = peerdb_read_index(db, (_scan_index % db_max), &p);
    _scan_index++;
    if (err)
      break;

    ret_list[ret_cnt] = p;
    ret_cnt++;
  }

  return (ret_list);
}

#if 0
static void peerdb_prune(bc_t *db)
{
  peerdb_t **p_list;
  shkey_t *key;
  bc_hash_t hash;
  int del_max;
  int db_max;
  int pos;
  int idx;

  db_max = bc_idx_next(db); 
  if (db_max < MAX_PEERDB_TRACK_LIST_SIZE)
    return;

  p_list = peerdb_track_scan(db, MAX_PEERDB_TRACK_LIST_SIZE);
  if (!p_list)
    return;

  /* reverse sort by trust */
  for (db_max = 0; p_list[db_max]; db_max++);
  peerdb_sort(p_list, db_max, -1);

  del_max = MAX(1, db_max - MAX_PEERDB_TRACK_LIST_SIZE);
  del_max = MIN(del_max, db_max);
  del_max = MIN(del_max, MAX_PEERDB_TRACK_PRUNE_SIZE);
  for (idx = 0; idx < del_max; idx++) {
    if (!p_list[idx] || p_list[idx]->trust > 0)
      break;

    /* delete stale entry */
    pos = -1;
    key = shpeer_kpriv(&p_list[idx]->peer);
    peerdb_key_hash(key, &hash);
    if (bc_idx_find(db, hash, NULL, &pos) == 0)
      bc_clear(db, pos); 
  }

  peerdb_list_free(p_list);
}
#endif

static int peerdb_write(bc_t *db, peerdb_t *p)
{
  bc_hash_t hash;
  shkey_t *key;
  unsigned char *data;
  size_t data_len;
  int pos;
  int err;

//  peerdb_prune(db);

  data = (unsigned char *)p;
  data_len = sizeof(peerdb_t);

  pos = -1;
  key = shpeer_kpriv(&p->peer); 
  peerdb_key_hash(key, &hash);
  err = bc_idx_find(db, hash, NULL, &pos); 

  if (err) { /* new */
    err = bc_append(db, hash, data, data_len);
  } else { /* update */
    err = bc_write(db, pos, hash, data, data_len);
  }


  return (0);
}

const char *unet_netaddr_str(struct sockaddr *addr)
{
  static char ret_buf[256];
  sa_family_t in_fam;
  unsigned char *raw = (unsigned char *)addr;

  in_fam = *((sa_family_t *)addr);
  memset(ret_buf, 0, sizeof(ret_buf));
  inet_ntop(in_fam, raw + 4, ret_buf, sizeof(ret_buf)-1);
 
  return (ret_buf);
}

int unet_peer_find(int mode, struct sockaddr *addr)
{
  struct sockaddr cmp_addr;
  unet_table_t *t;
  char peer_ip[512];
  socklen_t addr_len;
  int sk;

  strcpy(peer_ip, unet_netaddr_str(addr)); 

  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    t = get_unet_table(sk);
    if (!t)
      continue; /* non-active */

    if (t->mode != mode)
      continue;

    if (!(t->flag & DF_SERVICE))
      continue; /* not a coin service connection. */

    addr_len = sizeof(cmp_addr);
    memset(&cmp_addr, 0, sizeof(cmp_addr));
    getpeername(sk, &cmp_addr, &addr_len);
    if (0 == strcmp(peer_ip, unet_netaddr_str(&cmp_addr)))
      return (sk);
  }

  return (0);
}

int unet_peer_wait(unet_bind_t *bind)
{
  double dur;

  dur = MAX(4, MIN(540, 540 * bind->scan_freq));
  if (shtime_after(shtime(), shtime_adj(bind->scan_stamp, dur)))
    return (FALSE);

  return (TRUE);
}

static peerdb_t **peerdb_track_list(int mode, int ret_max)
{
  peerdb_t **ret_list;
  bc_t *db;
  int db_max;
  int idx;

  db = peerdb_open(mode);
  if (!db)
    return (NULL);

  db_max = bc_idx_next(db); 
  db_max = MIN(db_max, ret_max);

  ret_list = peerdb_track_scan(db, db_max);
  if (!ret_list)
    return (NULL);

  /* sort by trust */
  for (db_max = 0; ret_list[db_max]; db_max++);
  peerdb_sort(ret_list, db_max, 1);

  return (ret_list);
}

static void peerdb_del(int mode, shkey_t *key)
{
  bc_t *db;
  bc_hash_t hash;
  int pos;
  int err;

  db = peerdb_open(mode);
  if (!db)
    return;

  pos = -1;
  peerdb_key_hash(key, &hash);
  err = bc_idx_find(db, hash, NULL, &pos);
  if (!err)
    bc_clear(db, pos); 

}


void unet_peer_scan(void)
{
  unet_bind_t *bind;
  peerdb_t **peers;
  shtime_t ts;
  shpeer_t *peer;
  bc_t *db;
  double dur;
  char errbuf[1024];
  char buf[256];
  int mode;
  int err;
  int i;

  for (mode = 0; mode < MAX_UNET_MODES; mode++) {
    bind = unet_bind_table(mode);
    if (!bind)
      continue;
    if (!(bind->flag & UNETF_PEER_SCAN))
      continue;

    if (unet_peer_wait(bind))
      continue;

    db = peerdb_open(mode);
    if (!db) continue;
    peers = peerdb_track_scan(db, MAX_UNET_PEER_SCAN_SIZE);
    if (!peers) continue; 

    for (i = 0; i < MAX_UNET_PEER_SCAN_SIZE; i++) {
      if (!peers[i])
        break;

      /* The event will de-allocate the peer. */
      peer = (shpeer_t *)calloc(1, sizeof(shpeer_t));
      memcpy(peer, &peers[i]->peer, sizeof(shpeer_t));
      create_uevent_verify_peer(mode, peer);

      sprintf(buf, "unet_peer_scan: verifying peer \"%s\".", shpeer_print(peer));
      unet_log(mode, buf);
    }

    peerdb_list_free(peers);
  }

}

void unet_peer_fill_seed(int mode)
{
  unet_bind_t *bind;
  shpeer_t *peer;
  char hostname[MAXHOSTNAMELEN+1];
  char buf[1024];
  int i;

  bind = unet_bind_table(mode);
  if (!bind)
    return;

  memset(hostname, 0, sizeof(hostname));
  if (mode == UNET_SHC) {
    for (i = 0; i < SHC_SEED_LIST_SIZE; i++) {
      sprintf(hostname, "%s %d", shc_seed_list[i], bind->port);
      peer = shpeer_init((char *)unet_mode_label(mode), hostname); 
      create_uevent_verify_peer(mode, peer);

      sprintf(buf, "unet_peer_fill_seed: seeding SHC peer '%s'.", shpeer_print(peer));
      unet_log(mode, buf);
    }
  } else if (mode == UNET_USDE) {
    for (i = 0; i < USDE_SEED_LIST_SIZE; i++) {
      sprintf(hostname, "%s %d", usde_seed_list[i], bind->port);
      peer = shpeer_init((char *)unet_mode_label(mode), hostname); 
      create_uevent_verify_peer(mode, peer);

      sprintf(buf, "unet_peer_fill_seed: seeding USDE peer '%s'.", shpeer_print(peer));
      unet_log(mode, buf);
    }
  } else if (mode == UNET_EMC2) {
    for (i = 0; i < EMC2_SEED_LIST_SIZE; i++) {
      sprintf(hostname, "%s %d", emc2_seed_list[i], bind->port);
      peer = shpeer_init((char *)unet_mode_label(mode), hostname); 
      create_uevent_verify_peer(mode, peer);

      sprintf(buf, "unet_peer_fill_seed: seeding EMC2 peer '%s'.", shpeer_print(peer));
      unet_log(mode, buf);
    }
  }
}

void unet_peer_fill(int mode)
{
  peerdb_t **peer_list;
  unet_bind_t *bind;
  shpeer_t *peer;
  char buf[256];
  int i;

  bind = unet_bind_table(mode);
  if (!bind)
    return;

  i = 0;
  peer_list = peerdb_track_list(mode, MAX_PEERDB_TRACK_LIST_SIZE);
  if (peer_list) {
    for (; peer_list[i] && i < INIT_UNET_PEER_SCAN_SIZE; i++) {
      /* The event will de-allocate the peer. */
      peer = (shpeer_t *)calloc(1, sizeof(shpeer_t)); 
      memcpy(peer, &peer_list[i]->peer, sizeof(shpeer_t));
      create_uevent_connect_peer(mode, peer);

      sprintf(buf, "unet_peer_fill: adding peer \"%s\" [trust %d].", shpeer_print(peer), peer_list[i]->trust);
      unet_log(mode, buf);
    }
    peerdb_list_free(peer_list);
  }
  if (i == 0) {
    char buf[256];

    sprintf(buf, "unet_peer_fill: fresh peer database [%s].", shpeer_print(&bind->peer)); 
    unet_log(mode, buf);

    if (opt_bool(OPT_PEER_SEED))
      unet_peer_fill_seed(mode);
  }

}

unsigned int unet_peer_total(int mode)
{
  bc_t *db;
  unsigned int ret_tot;

  db = peerdb_open(mode);
  if (!db)
    return (0);

  ret_tot = bc_idx_next(db);
  return (ret_tot);
}

void unet_peer_decr(int mode, shpeer_t *peer)
{
  unet_bind_t *bind;
  peerdb_t *p;
  bc_t *db;
  char ibuf[256];
  int err;

  if (mode < 0 || mode >= MAX_UNET_MODES)
    return;

  bind = unet_bind_table(mode);
  if (!bind)
    return;

  if (!(bind->flag & UNETF_PEER_SCAN))
    return;

  db = peerdb_open(mode);
  err = peerdb_read(db, shpeer_kpriv(peer), &p);
  if (err)
    return; /* must exist before it can be 'untrusted'. */

  p->trust -= 1;
  peerdb_write(db, p);

  sprintf(ibuf, "peer: trust %d (-1), peer \"%s\".",
      p->trust, shpeer_print(&p->peer));
  unet_log(mode, ibuf);

  free(p);
}

void unet_peer_incr(int mode, shpeer_t *peer)
{
  unet_bind_t *bind;
  peerdb_t *p;
  bc_t *db;
  char ibuf[256];
  int err;

  if (mode < 0 || mode >= MAX_UNET_MODES)
    return;

  bind = unet_bind_table(mode);
  if (!bind)
    return;

  if (!(bind->flag & UNETF_PEER_SCAN)) {
    return;
  }

  db = peerdb_open(mode);
  if (!db)
    return;
  err = peerdb_read(db, shpeer_kpriv(peer), &p);
  if (err) {
    if (err != SHERR_NOENT)
      return;

    p = peerdb_new(mode, peer);
  }
  p->trust += 1;
  peerdb_write(db, p);

  sprintf(ibuf, "peer: trust %d (+1), peer \"%s\".",
      p->trust, shpeer_print(&p->peer));
  unet_log(mode, ibuf);

  free(p);
}

shpeer_t **unet_peer_track_list(int mode, int max_peer)
{
  shpeer_t **peer_list;
  peerdb_t **peers;
  char sql_str[512];
  char app_name[MAX_SHARE_NAME_LENGTH];
  char *ret_val;
  int max;
  int err;
  int i;

  peers = peerdb_track_list(mode, max_peer);
  if (!peers)
    return (NULL);

  for (max = 0; peers[max]; max++);
  max = MIN(max, max_peer);

  peer_list = (shpeer_t **)calloc(max + 1, sizeof(shpeer_t *));
  if (!peer_list) {
    peerdb_list_free(peers);
    return (NULL);
  }
 
  for (i = 0; i < max; i++) {
    peer_list[i] = (shpeer_t *)calloc(1, sizeof(shpeer_t));
    memcpy(peer_list[i], &peers[i]->peer, sizeof(shpeer_t));
  }
  peerdb_list_free(peers);

  return (peer_list);
}

int unet_peer_export_path(int ifaceIndex, char *path)
{
  const char *iface = unet_mode_label(ifaceIndex); 
  FILE *fl;
  bc_t *db;
  peerdb_t *p;
  shjson_t *root;
  shjson_t *node;
  shjson_t *j;
  char hostname[MAXHOSTNAMELEN+1];
  char idx_str[256];
  char *text;
  int db_max;
  int port;
  int idx;
  int err;

  db = peerdb_open(ifaceIndex);
  if (!db)
    return (SHERR_INVAL);

  root = shjson_init(NULL);
  j = shjson_obj_add(root, "track");

  db_max = bc_idx_next(db);
  for (idx = 0; idx < db_max; idx++) {
    err = peerdb_read_index(db, idx, &p);
    if (err)
      continue;

    port = 0;
    memset(hostname, 0, sizeof(hostname));
    shpeer_host(&p->peer, hostname, &port);
    sprintf(hostname + strlen(hostname), " %d", port);

    sprintf(idx_str, "%d", (idx+1));
    node = shjson_obj_add(j, idx_str);

    shjson_str_add(node, "host", hostname);
    shjson_str_add(node, "label", (char *)iface);
  }

  text = shjson_print(root);
  shjson_free(&root);
  if (!text)
    return (SHERR_NOMEM);

  fl = fopen(path, "wb");
  if (!fl)
    return (-errno);

  fprintf(fl, "%s\n", text);
  (void)fclose(fl);
  free(text);

  return (0);
}

void unet_peer_track_add(int ifaceIndex, shpeer_t *peer)
{
  unet_peer_incr(ifaceIndex, peer);
}

void unet_peer_track_remove(int ifaceIndex, shpeer_t *peer)
{
  peerdb_del(ifaceIndex, shpeer_kpriv(peer)); 
}

void unet_peer_prune(int mode)
{
  peerdb_t **peer_list;
  unet_bind_t *bind;
  bc_t *db;
  char buf[256];
  double diff;
  double deg;
  time_t now;
  int db_max;
  int i;

  bind = unet_bind_table(mode);
  if (!bind)
    return;

  db = peerdb_open(mode);
  if (!db)
    return;

  peer_list = peerdb_track_scan(db, MAX_PEERDB_TRACK_LIST_SIZE);
  if (!peer_list)
    return;

  /* reverse sort by trust */
  for (db_max = 0; peer_list[db_max]; db_max++);
  peerdb_sort(peer_list, db_max, -1);

  now = time(NULL);
  for (i = 0; peer_list[i] && i < MAX_PEERDB_TRACK_PRUNE_SIZE; i++) {
    if (peer_list[i]->trust >= 0) {
      break; /* not in un-healthy condition. */
    }

    if (peer_list[i]->birth > (now - 172800)) {
      /* record is fresh (less than two days), keep trying. */
      continue;
    }

    /* older records weight as healthier */
    diff = (double)(peer_list[i]->birth - now);
    deg = 10800 / diff * (double)peer_list[i]->trust;
    if (deg < 1.0)
      continue; /* may live another day */

    /* debug */
    sprintf(buf, "unet_peer_prune: purging peer \"%s\" [trust %d].", shpeer_print(&peer_list[i]->peer), peer_list[i]->trust);
    unet_log(mode, buf);

    /* remove peer from database */
    unet_peer_track_remove(mode, &peer_list[i]->peer);
  }

  peerdb_list_free(peer_list);

}

