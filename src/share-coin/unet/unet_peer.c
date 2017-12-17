
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

#if 0
int unet_peer_find(int mode, struct sockaddr *addr)
{
  sa_family_t in_fam;
  sa_family_t cmp_fam;
  unet_table_t *t;
  char hostname[MAXHOSTNAMELEN+1];
  char buf[256];
char ipaddr[256];
char cmp_ipaddr[256];
  int sk;

  in_fam = *((sa_family_t *)addr);

memset(ipaddr, 0, sizeof(ipaddr));
inet_ntop(in_fam, addr, ipaddr, sizeof(ipaddr));

  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    t = get_unet_table(sk);
    if (!t)
      continue; /* non-active */

    if (t->mode != mode)
      continue;

    if (!(t->flag & DF_SERVICE))
      continue; /* not a coin service connection. */

    cmp_fam = *((sa_family_t *)&t->net_addr);
    if (cmp_fam != in_fam) {
      continue; /* different network family */
    }

if (in_fam == AF_INET) {
  struct sockaddr_in in;
  socklen_t len = sizeof(in);
  getpeername(sk, (struct sockaddr *)&in, &len);
  memset(cmp_ipaddr, 0, sizeof(cmp_ipaddr));
  inet_ntop(in_fam, &in, cmp_ipaddr, sizeof(cmp_ipaddr));
}

    if (in_fam == AF_INET) {
      struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
      struct sockaddr_in *addr4_cmp = (struct sockaddr_in *)&t->net_addr;
      if (0 == memcmp(&addr4->sin_addr, &addr4_cmp->sin_addr, sizeof(addr4->sin_addr))) {
        return (sk);
      }
    } else if (in_fam == AF_INET6) {
      struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
      struct sockaddr_in6 *addr6_cmp = (struct sockaddr_in6 *)&t->net_addr;
      if (0 == memcmp(&addr6->sin6_addr, &addr6_cmp->sin6_addr, sizeof(addr6->sin6_addr))) {
        return (sk);
      }
   }
  }
  
  return (0);
}
#endif

#if 0
void unet_peer_verify(int mode)
{
  unet_bind_t *bind;
  char buf[256];
  int err;

  bind = unet_bind_table(mode);
  if (!bind)
    return;

  err = shnet_track_verify(&bind->scan_peer, &bind->scan_fd);
  if (err != SHERR_INPROGRESS) {
    if (!err) {
      /* success */
      shnet_track_mark(&bind->scan_peer, 1);
      bind->scan_freq = MAX(0.001, bind->scan_freq * 1.1);

      sprintf(buf, "unet_peer_verify: connect '%s' (success).", shpeer_print(&bind->scan_peer));
      unet_log(mode, buf);

      /* initiate service connection. */
      if (!unet_peer_find(shpeer_addr(&bind->scan_peer)))
        unet_connect(mode, shpeer_addr(&bind->scan_peer), NULL);
    } else {
      /* error */
      shnet_track_mark(&bind->scan_peer, -1);
      bind->scan_freq = MAX(0.001, bind->scan_freq * 0.9);

      sprintf(buf, "unet_peer_verify: error: connect '%s' (%s) [sherr %d].", shpeer_print(&bind->scan_peer), sherrstr(err), err);
      unet_log(mode, buf);
    }
  } else {
    shtime_t now = shtime();
    shtime_t expire_t = shtime_adj(bind->scan_stamp, 5);
    if (shtime_before(expire_t, now)) {
      err = SHERR_TIMEDOUT;
      sprintf(buf, "unet_peer_verify: error: connect '%s' (%s) [wait %-1.1fs] [sherr %d].", shpeer_print(&bind->scan_peer), sherrstr(err), shtime_diff(bind->scan_stamp, now), err);
      unet_log(mode, buf);

      /* error */
      shnet_track_mark(&bind->scan_peer, -1);
      bind->scan_freq = MAX(0.001, bind->scan_freq * 0.9);

      shnet_close(bind->scan_fd);
      bind->scan_fd = 0;
    }
  }


  
}
#endif

int unet_peer_wait(unet_bind_t *bind)
{
  double dur;

  dur = MAX(4, MIN(600, 600 * bind->scan_freq));
  if (shtime_after(shtime(), shtime_adj(bind->scan_stamp, dur)))
    return (FALSE);

  return (TRUE);
}

void unet_peer_scan(void)
{
  unet_bind_t *bind;
  shpeer_t **peers;
  shtime_t ts;
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

    timing_init("shnet_track_scan", &ts);
    peers = shnet_track_scan(bind->peer_db, &bind->peer, MAX_UNET_PEER_SCAN_SIZE);
    timing_term(mode, "shnet_track_scan", &ts);
    if (peers) {
      for (i = 0; i < MAX_UNET_PEER_SCAN_SIZE; i++) {
        if (!peers[i])
          break;

        /* The event will de-allocate the peer. */
        create_uevent_verify_peer(mode, peers[i]);
      }
      free(peers);
    }
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
  shpeer_t **peer_list;
  unet_bind_t *bind;
  int i;

  bind = unet_bind_table(mode);
  if (!bind)
    return;

  peer_list = shnet_track_list(bind->peer_db, &bind->peer, INIT_UNET_PEER_SCAN_SIZE);

  i = 0;
  if (peer_list) {
    for (; peer_list[i] && i < INIT_UNET_PEER_SCAN_SIZE; i++) {
      /* The event will de-allocate the peer. */
      create_uevent_connect_peer(mode, peer_list[i]);
    }
  }
  free(peer_list);
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
  unet_bind_t *bind;

  bind = unet_bind_table(mode);
  if (!bind)
    return (0);

  return (shnet_track_count(bind->peer_db, bind->peer.label));
}

void unet_peer_incr(int mode, shpeer_t *peer)
{
  int err;
  unet_bind_t *bind;

  if (mode < 0 || mode >= MAX_UNET_MODES)
    return;

  bind = unet_bind_table(mode);
  if (!bind)
    return;

  if (!(bind->flag & UNETF_PEER_SCAN))
    return;

  err = shnet_track_mark(bind->peer_db, peer, 1);
  if (err)
    shnet_track_add(bind->peer_db, peer);
}

void unet_peer_decr(int mode, shpeer_t *peer)
{
  unet_bind_t *bind;

  if (mode < 0 || mode >= MAX_UNET_MODES)
    return;

  bind = unet_bind_table(mode);
  if (!bind)
    return;

  if (!(bind->flag & UNETF_PEER_SCAN))
    return;

  shnet_track_mark(bind->peer_db, peer, -1);
} 


