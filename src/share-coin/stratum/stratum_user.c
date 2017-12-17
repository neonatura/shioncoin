
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

#define __STRATUM__USER_C__

#include "shcoind.h"
#include <math.h>
#include "stratum/stratum.h"

#define MAX_STRATUM_USERS 32
#define MIN_SHARE_DIFFICULTY 0.03125 /* diff 1 */


#define MAX_USER_FLAGS 8
static const char *user_flag_label[MAX_USER_FLAGS] = {
  "system",
  "auth",
  "subscribe",
  "sync",
  "client",
  "remote",
  "rpc",
  "elevate"
};

const char *get_user_flag_label(int flag)
{
  int i;

  for (i = 0; i < MAX_USER_FLAGS; i++) {
    if ( flag & (1 << i) )
      return (user_flag_label[i]);
  }

  return ("");
}

user_t *stratum_user_find(char *username)
{
  user_t *user;

  for (user = client_list; user; user = user->next) {
    if (0 == strcasecmp(username, user->worker))
      break;
  }

  return (user);
}

user_t *stratum_user_get(int fd)
{
  user_t *user;

  if (fd < 0)
    return (NULL);

  for (user = client_list; user; user = user->next) {
    if (user->fd == fd)
      break;
  }

  return (user);
}

/**
 * @returns The number of local stratum clients.
 */
int stratum_user_count(user_t *user)
{
  struct sockaddr_in *addr;
  struct sockaddr_in *t_addr;
  user_t *t_user;
  int cnt;

  cnt = 0;
  addr = (struct sockaddr_in *)shaddr(user->fd);
  for (t_user = client_list; t_user; t_user = t_user->next) {
    if (t_user->fd == -1)
      continue;
    if (!(t_user->flags & USER_CLIENT))
      continue;
    t_addr = (struct sockaddr_in *)shaddr(t_user->fd);
    if (!t_addr)
      continue;
    if (0 == memcmp(&addr->sin_addr, 
          &t_addr->sin_addr, sizeof(struct in_addr)))
      cnt++;
  }

  return (cnt);
}

void merge_idle_worker(user_t *user)
{
  user_t *t_user;
  int i;

  for (t_user = client_list; t_user; t_user = t_user->next) {
    if (t_user == user)
      continue; /* does not apply to self */
    if (!(t_user->flags & USER_CLIENT))
      continue; /* skip system users */
    if (t_user->fd != -1)
      continue; /* skip active users */
    if (0 != strcmp(user->worker, t_user->worker))
      continue; /* wrong worker */ 

    /* transfer share rates */
    for (i = 0; i < MAX_ROUNDS_PER_HOUR; i++) {
      user->block_avg[i] += t_user->block_avg[i];
      t_user->block_avg[i] = 0;
    }
    user->block_tot += t_user->block_tot;
    user->block_cnt += t_user->block_cnt;
    t_user->block_tot = 0;
    t_user->block_cnt = 0;

    /* transfer pending reward */
    for (i = 1; i < MAX_COIN_IFACE; i++) {
      user->balance[i] += t_user->balance[i];
      t_user->balance[i] = 0;
    }

    /* mark idle worker for immediate deletion */
    t_user->work_stamp = 0;
  }

}

user_t *stratum_user(user_t *user, char *username)
{
  char name[256]; 
  char *ptr;
  int cli_cnt;

  /* invalid chars */
  if (strchr(username, '@'))
    return (NULL);

  memset(name, 0, sizeof(name));
  strncpy(name, username, sizeof(name) - 1);
  ptr = strchr(name, '_');
  if (ptr)
    *ptr = '\0';

  cli_cnt = stratum_user_count(user);
  if (cli_cnt >= MAX_STRATUM_USERS) {
    char buf[256];

    sprintf(buf, "stratum_user: too many stratum connections (%d/%d).", cli_cnt, MAX_STRATUM_USERS); 
    /* too many connections. */
    return (NULL);
  }


  strncpy(user->worker, username, sizeof(user->worker) - 1);
  merge_idle_worker(user);

  return (user);
}



user_t *stratum_user_init(int fd)
{
  struct sockaddr_in *addr;
  user_t *user;
  char nonce1[32];
  uint32_t seed;

  user = (user_t *)calloc(1, sizeof(user_t));
  user->fd = fd;
  user->round_stamp = time(NULL);

  seed = htonl(shrand() & 0xFFFF);
  sprintf(nonce1, "%-8.8x", (unsigned int)seed);

  shscrypt_peer(&user->peer, nonce1, MIN_SHARE_DIFFICULTY);
  //shscrypt_peer_gen(&user->peer, MIN_SHARE_DIFFICULTY);

  user->block_freq = 2.0;

  if (user->fd > 0) {
    shkey_t *key;
    struct sockaddr *addr;

    user->flags |= USER_CLIENT;

    addr = shaddr(user->fd);
    key = shkey_bin(addr, sizeof(struct sockaddr));
    memcpy(&user->netid, key, sizeof(user->netid));
    shkey_free(&key);
  }

  return (user);
}

/**
 * returns the worker's average speed.
 */
double stratum_user_speed(user_t *user)
{
  double speed;
  int speed_cnt;
  int i;

  speed = 0;
  speed_cnt = 0;
  for (i = 0; i < MAX_SPEED_STEP; i++) {
    if (user->speed[i] > 0.000) {
      speed += user->speed[i];
      speed_cnt++;
    }
  }
  if (!speed_cnt)
    return (0.0);

  return (speed / (double)speed_cnt);
}

void stratum_user_block(user_t *user, double share_diff)
{
  double diff;
  double cur_t;
  double speed;
  double span;
  int step;
  
  if (share_diff != INFINITY) {
    user->block_tot += share_diff;
    user->block_cnt++;
  }

  cur_t = shtimef(shtime());
  if (user->block_tm) {
    span = cur_t - user->block_tm;

    step = ((int)cur_t % MAX_SPEED_STEP);
    speed = (double)user->work_diff / span * pow(2, 32) / 0xffff;
    if (span > 1.0) {
      speed /= 1000; /* khs */
      user->speed[step] = (user->speed[step] + speed) / 2;
    }

//  fprintf(stderr, "stratum_user_block: worker '%s' submitted diff %6.6f block with speed %fkh/s (avg %fkh/s) [%lu/x%d]\n", user->worker, diff, speed, stratum_user_speed(user), (unsigned long)user->block_tot, user->block_cnt);

    user->block_freq = (span + user->block_freq) / 2;
    if (user->block_freq < 1) { 
      if (user->work_diff < 16384)
        stratum_set_difficulty(user, user->work_diff + 16);
    } else if (user->block_freq > 128) { 
      if (user->work_diff > 128)
        stratum_set_difficulty(user, user->work_diff - 8);
    }
  }
  user->block_tm = cur_t;

}


int stratum_user_broadcast_task(task_t *task, task_attr_t *attr)
{
  user_t *user;
  int clear;
  int err;

  if (!task)
    return (0);
  for (user = client_list; user; user = user->next) {
    if (user->fd == -1) {
      continue;
    }

#if 0
    if (user->ifaceIndex == 0) {
      if (task->ifaceIndex != attr->ifaceIndex)
        continue;
    } else {
      if (user->ifaceIndex != task->ifaceIndex)
        continue;
    }
#endif

    if (user->flags & USER_SUBSCRIBE) {
      clear = (user->height != task->height);
      err = stratum_send_task(user, task, clear);
      if (!err) {
        user->height = task->height;
        user->work_stamp = time(NULL);
        user->ifaceIndex = attr->ifaceIndex;
      }
    }

  }

  return (0);
}

void stratum_user_free(user_t *f_user)
{
  user_t *p_user;
  user_t *user;

  p_user = NULL;
  for (user = client_list; user; user = user->next) {
    if (user == f_user) {
      if (user == client_list) {
        client_list = user->next;
      } else {
        p_user->next = user->next;
      }
      free(f_user);
      break;
    }
    p_user = user;
  }

}


