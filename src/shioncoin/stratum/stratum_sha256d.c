
/*
 * @copyright
 *
 *  Copyright 2019 Brian Burrell
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
#include "stratum.h"
#include "algobits.h"
#include "stratum_sha256d.h"
#include <math.h>


#define SHA256D_WORK_CYCLE_TIME 720 

static volatile time_t stratum_work_cycle;

/**
 * Called when a new socket is accepted on the shcoind stratum port (default 9448).
 */
static void stratum_sha256d_close(int fd, struct sockaddr *net_addr)
{
	stratum_close(fd, net_addr);
}

static uint64_t pend_block_height[MAX_COIN_IFACE];
static int is_stratum_sha256d_task_pending(int *ret_iface)
{
  static uint32_t usec;
  struct timeval now;
  uint64_t block_height;
  char errbuf[256];
  int ifaceIndex;
	int usec_trigger = 0;

	usec++;
	if (0 == (usec % SHA256D_WORK_CYCLE_TIME)) {
		usec_trigger = 1;
	}

  for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
		if (!is_stratum_miner_algo(ifaceIndex, ALGO_SHA256D))
			continue;

//		if (ifaceIndex == TESTNET_COIN_IFACE) continue;
//		if (ifaceIndex == COLOR_COIN_IFACE) continue;
    CIface *iface = GetCoinByIndex(ifaceIndex);
    if (!iface || !iface->enabled) 
      continue; /* iface not enabled */

		if (stratum_isinitialdownload(ifaceIndex))
			continue;
    block_height = (uint64_t)getblockheight(ifaceIndex);
#if 0
    if (iface->blockscan_max &&
        block_height < (iface->blockscan_max - 1))
      continue; /* downloading blocks.. */
#endif

		if (!usec_trigger && block_height == pend_block_height[ifaceIndex])
			continue; /* no new block. */

    pend_block_height[ifaceIndex] = block_height;
    if (ret_iface)
      *ret_iface = ifaceIndex;

		usec = 1;
    return (TRUE);
  }

  return (FALSE);
}

#if 0
static void stratum_sha256d_task_gen(task_attr_t *attr)
{
  task_t *task;
  scrypt_peer peer;
  unsigned int last_nonce;
	char ebuf[256];
  int time;
  int err;

  task = task_init(attr);
  if (!task) {
    return;
	}

  /* notify subscribed clients of new task. */
  stratum_user_broadcast_task(task, attr);

  task_free(&task);
}
#endif

static void stratum_sha256d_timer(void)
{
  static task_attr_t attr;
  static int _sync_init;
  unet_table_t *t;
  user_t *peer;
  shbuf_t *buff;
  char errbuf[256];
  char *data;
  time_t tnow;
  size_t len;
  int is_new;
  int blk_iface;
  int err;

	attr.alg = ALGO_SHA256D;

	/* OPT_STRATUM_WORK_CYCLE: Maximum time-span between work creation (default: 15 seconds, max: 1 hour). */
  tnow = time(NULL) / stratum_work_cycle;

  blk_iface = 0;
  is_new = is_stratum_sha256d_task_pending(&blk_iface);
  if (is_new || (attr.tnow != tnow)) {
    attr.tnow = tnow;
    if (attr.ifaceIndex == 0) {
      /* init */
      attr.flags |= TASKF_RESET;
    } else if (blk_iface && is_new) {
      /* new block on a coin chain */
      attr.blk_stamp[blk_iface] = time(NULL);
      if (blk_iface == attr.ifaceIndex) /* currently mining */
        attr.flags |= TASKF_RESET;
    }

    /* generate new work, as needed */
    stratum_task_gen(&attr);

    attr.flags &= ~TASKF_RESET;
  }

}

static void stratum_sha256d_term(void)
{

  unet_unbind(UNET_STRATUM_SHA256D); /* close listening socket. */

}

static void stratum_sha256d_accept(int fd, struct sockaddr *net_addr)
{
  sa_family_t in_fam;
	user_t *user;
  char buf[256];

  if (fd < 1 || !net_addr) {
    sprintf(buf, "stratum_accept: invalid fd/addr: fd(%d) net_addr(#%x)\n", fd, net_addr);
    shcoind_log(buf);
    return;
  }

  in_fam = *((sa_family_t *)net_addr);
  if (in_fam == AF_INET) {
    struct sockaddr_in *addr = (struct sockaddr_in *)net_addr;

    sprintf(buf, "stratum_accept: received connection (%s port %d).", inet_ntoa(addr->sin_addr), get_stratum_port(ALGO_SHA256D));
    shcoind_log(buf);  
  } else {
    sprintf(buf, "stratum_accept: received connection (family %d)", in_fam);
    shcoind_log(buf);  
	}

  user = stratum_register_client(fd);
	if (user) {
		user->alg = ALGO_SHA256D;
	}
 
}

int stratum_sha256d_init(void)
{
	int err;

	/* OPT_STRATUM_WORK_CYCLE: Maximum time-span between work creation (default: 15 seconds, max: 1 hour). */
	stratum_work_cycle = (time_t)fabs(opt_num(OPT_STRATUM_WORK_CYCLE));
	if (stratum_work_cycle < 2) stratum_work_cycle = 2;

	err = unet_bind(UNET_STRATUM_SHA256D, get_stratum_port(ALGO_SHA256D), NULL);
	if (err)
		return (err);

	unet_timer_set(UNET_STRATUM_SHA256D, stratum_sha256d_timer); /* x1/s */
	unet_connop_set(UNET_STRATUM_SHA256D, stratum_sha256d_accept);
	unet_disconnop_set(UNET_STRATUM_SHA256D, stratum_sha256d_close);

	return (0);
}

