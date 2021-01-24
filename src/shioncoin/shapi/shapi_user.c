
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

#include "shcoind.h"
#include "shapi/shapi.h"
#include <math.h>

/* maximum shapi connections per origin IP address. */
#define MAX_SHAPI_USERS 32

/* minimum difficulty for a single share to be considered valid. */
#define MIN_SHARE_DIFFICULTY 0.03125 /* diff 1 */

/* minimum miner work difficulty permitted. */
#define MIN_USER_WORK_DIFFICULTY 32

/* maximum miner work difficulty permitted. */
#define MAX_USER_WORK_DIFFICULTY 1024000

shapi_t *shapi_client_list;

#if 0
shapi_t *shapi_user_find(char *username)
{
  shapi_t *user;

  for (user = shapi_client_list; user; user = user->next) {
    if (0 == strcasecmp(username, user->worker))
      break;
  }

  return (user);
}
#endif

shapi_t *shapi_user_get(int fd)
{
  shapi_t *user;

  if (fd < 0)
    return (NULL);

  for (user = shapi_client_list; user; user = user->next) {
    if (user->fd == fd)
      break;
  }

  return (user);
}

/**
 * @returns The number of local shapi clients.
 */
int shapi_user_count(shapi_t *user)
{
  struct sockaddr_in *addr;
  struct sockaddr_in *t_addr;
  shapi_t *t_user;
  int cnt;

  cnt = 0;
  addr = (struct sockaddr_in *)shaddr(user->fd);
  for (t_user = shapi_client_list; t_user; t_user = t_user->next) {
    if (t_user->fd == -1)
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

#if 0
void merge_idle_worker(shapi_t *user)
{
  shapi_t *t_user;
  int i;

  for (t_user = shapi_client_list; t_user; t_user = t_user->next) {
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
shapi_t *shapi_user(shapi_t *user, char *username)
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

  cli_cnt = shapi_user_count(user);
  if (cli_cnt >= MAX_SHAPI_USERS) {
    char buf[256];

    sprintf(buf, "shapi_user: too many shapi connections (%d/%d).", cli_cnt, MAX_SHAPI_USERS); 
    /* too many connections. */
    return (NULL);
  }


  strncpy(user->worker, username, sizeof(user->worker) - 1);
  merge_idle_worker(user);

  return (user);
}
#endif

shapi_t *shapi_user_init(int fd)
{
  shapi_t *user;

  user = (shapi_t *)calloc(1, sizeof(shapi_t));
	if (!user)
		return (NULL);

  user->fd = fd;
  return (user);
}

#if 0
/**
 * returns the worker's average speed.
 */
double shapi_user_speed(shapi_t *user)
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
#endif

void shapi_user_free(shapi_t *f_user)
{
  shapi_t *p_user;
  shapi_t *user;

  p_user = NULL;
  for (user = shapi_client_list; user; user = user->next) {
    if (user == f_user) {
      if (user == shapi_client_list) {
        shapi_client_list = user->next;
      } else {
        p_user->next = user->next;
      }
      free(f_user);
      break;
    }
    p_user = user;
  }

}

