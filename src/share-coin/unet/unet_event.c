
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

static uevent_t event_table[UNET_MAX_EVENTS];

uevent_t *uevent_new(int umode, int type, void *data)
{
  static unsigned int event_idx;
  uevent_t *e;
  unsigned int idx;
  unsigned int of;

  if (!type)
    return (NULL);

  e = NULL;
  for (of = 1; of <= UNET_MAX_EVENTS; of++) {
    idx = (event_idx + of) % UNET_MAX_EVENTS;
    e = &event_table[idx];
    if (e->type == 0)
      break;
  }
  if (of > UNET_MAX_EVENTS) {
    shcoind_log("uevent_new: warning: out of event slots");
    return (NULL);
  }
  event_idx = (event_idx + of) % UNET_MAX_EVENTS;
  
  e->type = type;
  e->data = data;  
  e->mode = umode;

  return (e);
}

uevent_t *create_uevent_verify_peer(int umode, shpeer_t *peer)
{
  return (uevent_new(umode, UEVENT_PEER_VERIFY, peer));
}

uevent_t *create_uevent_connect_peer(int umode, shpeer_t *peer)
{
  return (uevent_new(umode, UEVENT_PEER_CONN, peer));
}

void uevent_clear_pos(int idx)
{
  if (idx < 0 || idx > UNET_MAX_EVENTS)
    return;
  memset(&event_table[idx], '\000', sizeof(uevent_t));
}
void uevent_clear(uevent_t *e)
{
  int of;

  for (of = 0; of < UNET_MAX_EVENTS; of++) {
    if (e == &event_table[of]) {
      memset(&event_table[of], '\000', sizeof(uevent_t));
      break;
    }
  }
  
}

int uevent_peer_verify(uevent_t *e)
{
  unet_bind_t *bind;
  shpeer_t *peer;
  shtime_t now;
  shtime_t expire_t;
  char buf[1024];
  int err;

now = shtime();

  peer = (shpeer_t *)e->data;
  if (!peer) {
    return (0); /* all done */
  }

  bind = unet_bind_table(e->mode);
  if (!bind)
    return (0); /* all done */

  err = shnet_track_verify(peer, &e->fd);
  if (!err) {
    /* success */
    unet_peer_incr(e->mode, peer);
    bind->scan_freq = MAX(0.001, bind->scan_freq * 1.1);

    sprintf(buf, "unet_peer_verify: peer '%s' verified.", shpeer_print(peer));
    unet_log(e->mode, buf);

#if 0
    /* initiate service connection. */
    if (!unet_peer_find(e->mode, shpeer_addr(peer))) /* x2check */
      unet_connect(e->mode, shpeer_addr(peer), NULL);
#endif
    /* transfer peer to new connection event */
    create_uevent_connect_peer(e->mode, peer);
    e->data = NULL; /* prevent event data from being free'd */

    e->fd = 0;
    return (0); /* dispose of event */
  }

  if (err != SHERR_INPROGRESS) {
    /* connection error */
    unet_peer_decr(e->mode, peer);
    bind->scan_freq = MAX(0.001, bind->scan_freq * 0.9);

    if (err != -ECONNREFUSED) { /* SHERR_CONNREFUSED */
      sprintf(buf, "unet_peer_verify: error: peer '%s' (%s) [sherr %d].", shpeer_print(peer), sherrstr(err), err);
      unet_log(e->mode, buf);
    }

    e->fd = 0;
    return (0); /* dispose of event */
  }

  /* SHERR_INPROGRESS */
  if (shtime_after(shtime(), shtime_adj(bind->scan_stamp, 3))) {
    /* async connection socket timeout */
    err = SHERR_TIMEDOUT;

#if 0
    sprintf(buf, "unet_peer_verify: error: peer '%s' (%s) [wait %-1.1fs] [sherr %d] [fd %d].", shpeer_print(peer), sherrstr(err), shtime_diff(bind->scan_stamp, now), err, e->fd);
    unet_log(e->mode, buf);
#endif

    /* error */
    unet_peer_decr(e->mode, peer);
    bind->scan_freq = MAX(0.001, bind->scan_freq * 0.9);

    if (e->fd) {
      shnet_close(e->fd);
      e->fd = 0;
    }

    return (0); /* dispose of event */
  }

  /* keep trying */
  return (SHERR_AGAIN);
}

int uevent_cycle_peer_verify(uevent_t *e)
{
  unet_bind_t *bind;
  shpeer_t *peer;
  char addr_str[256];
  int err;


  if (!e->data)
    return (0); /* all done */

  peer = (shpeer_t *)e->data;

  if (e->fd) {
    err = uevent_peer_verify(e);
    if (err)
      return (err);

    goto fin;
  }

  bind = unet_bind_table(e->mode);
  if (!bind || !(bind->flag & UNETF_PEER_SCAN)) {
    /* try again later */ 
    goto fin;
  }

  if (unet_peer_wait(bind)) {
    return (SHERR_AGAIN); /* wait inbetween connections */
  }

  bind->scan_stamp = shtime();

  unet_peer_incr(e->mode, peer);

  if (unet_peer_find(e->mode, shpeer_addr(peer))) {
    goto fin; /* already connected */
  }

  err = uevent_peer_verify(e);
  if (err)
    return (err);
  
fin:
  peer = (shpeer_t *)e->data;
  if (peer)
    shpeer_free(&peer);

  return (0); /* event completed */
}

int uevent_cycle_peer_conn(uevent_t *e)
{
  shpeer_t *peer;
  int err;

  if (!e->data)
    return (0); /* all done */

  peer = (shpeer_t *)e->data;

  if (!unet_peer_find(e->mode, shpeer_addr(peer))) {
    unet_connect(e->mode, shpeer_addr(peer), NULL);
  }

  shpeer_free(&peer);
  return (0); /* event completed */
}

void uevent_cycle(void)
{
  static unsigned int event_idx;
  uevent_t *e;
  shtime_t start;
  shtime_t ts;
  unsigned int e_max;
  int err;

  start = shtime();
  e_max = (event_idx - 1) % UNET_MAX_EVENTS;
  while (event_idx != e_max) {
    e = &event_table[event_idx];

    if (e->type) {
      err = 0;
      switch (e->type) {
        case UEVENT_PEER_VERIFY:
          err = uevent_cycle_peer_verify(e);
          break;
        case UEVENT_PEER_CONN:
          err = uevent_cycle_peer_conn(e);
          break;
      }

      /* clear event once performed */
      if (err == 0)
        uevent_clear_pos(event_idx);

      if (shtime_after(shtime(), shtime_adj(start, 0.2)))
        break; /* break out after 20ms */
    }

    event_idx = (event_idx + 1) % UNET_MAX_EVENTS;
  }

}

unsigned int uevent_type_count(int type)
{
  int total;
  int of;

  total = 0;
  for (of = 0; of < UNET_MAX_EVENTS; of++) {
    if (event_table[of].type == type)
      total++;
  }

  return (total);

}
