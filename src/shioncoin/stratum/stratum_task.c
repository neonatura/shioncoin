
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
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

#define __STRATUM__TASK_C__

#include <math.h>

#include "shcoind.h"
#include "stratum/stratum.h"
#include "coin_proto.h"
#include "algobits.h"

#define BLOCK_VERSION 1
#define MAX_SERVER_NONCE 8
#define MAX_ROUND_TIME 600
#define MAX_REWARD_WAIT_TIME 3600

#define POST_BLOCK_TIME 15

#define CPUMINER_WORKER "system.anonymous"

static user_t *sys_user;
static int work_reset[MAX_COIN_IFACE];
static uint64_t last_block_height[MAX_COIN_IFACE];
static char last_payout_hash[MAX_COIN_IFACE][256];

extern int stratum_isinitialdownload(int ifaceIndex);


/**
 * Monitors when a new accepted block becomes confirmed.
 */
static void check_payout(int ifaceIndex)
{
	shjson_t *tree;
	shjson_t *block;
	user_t *user;
	char block_hash[512];
	char category[64];
	char uname[256];
	char buf[256];
	char *templ_json;
	double tot_shares;
	double weight;
	double reward;
	int i;

#if 0
	tree = stratum_miner_getblocktemplate(ifaceIndex, ALGO_SCRYPT);
	if (!tree) {
		shcoind_log("task_init: cannot parse json");
		return;
	}

	block = shjson_obj(tree, "result");
	if (!block) {
		shcoind_log("task_init: cannot parse json result");
		shjson_free(&tree);
		return;
	}
#endif

	tree = block = stratum_miner_lastminerblock(ifaceIndex);
	if (!tree) {
//		shcoind_log("task_init: cannot parse json result");
		return;
	}

	memset(block_hash, 0, sizeof(block_hash));
	strncpy(block_hash, shjson_astr(block, "blockhash", ""), sizeof(block_hash) - 1);
	if (0 == strcmp(block_hash, "")) {
		/* No block has been confirmed since process startup. */
		shjson_free(&tree);
		return;
	}

	if (!*last_payout_hash[ifaceIndex]) {
		strcpy(last_payout_hash[ifaceIndex], block_hash);
	} 

#if 0
	memset(category, 0, sizeof(category));
	strncpy(category, shjson_astr(block, "category", "none"), sizeof(category) - 1);
	if (0 != strcmp(category, "generate")) {
		shjson_free(&tree);
		return;
	}
#endif


	if (0 == strcmp(last_payout_hash[ifaceIndex], block_hash)) {
		shjson_free(&tree);
		return;
	}
	strcpy(last_payout_hash[ifaceIndex], block_hash);

	/* winner winner chicken dinner */
	add_stratum_miner_block(ifaceIndex, block_hash);

	if (!client_list)
		return;

	{
		double amount = shjson_num(block, "amount", 0);
		double fee;

		if (amount < 1) {
			shjson_free(&tree);
			return;
		}

		fee = amount * 0.001; /* 0.1% */
		amount -= fee;

		tot_shares = 0;
		for (user = client_list; user; user = user->next) {
			for (i = 0; i < MAX_ROUNDS_PER_HOUR; i++)
				tot_shares += user->block_avg[i];
		}
		tot_shares = MAX(1.0, tot_shares);

		/* divvy up profit */
		weight = amount / tot_shares;
		for (user = client_list; user; user = user->next) {
			if (user->flags & USER_SYNC)
				continue; /* stratum server */
			if (user->flags & USER_RPC)
				continue; /* rpc user */
			if (!*user->worker)
				continue; /* unknown */
			if (0 == strncmp(user->worker, "system.", strlen("system.")))
				continue; /* public */

			reward = 0;
			for (i = 0; i < MAX_ROUNDS_PER_HOUR; i++)
				reward += (weight * user->block_avg[i]);
			if (reward >= 0.0000001) {
				user->balance[ifaceIndex] += reward;
				/* regulate tx # */
				user->balance_avg[ifaceIndex] =
					(user->balance_avg[ifaceIndex] + reward) / 2;

				CIface *iface = GetCoinByIndex(ifaceIndex);
				sprintf(buf, "check_payout: worker '%s' has pending balance of %-8.8f %s coins (+%-8.8f, avg %-4.4f).", user->worker, user->balance[ifaceIndex], iface->name, reward, user->balance_avg[ifaceIndex]);
				shcoind_log(buf);
			}
		}

	}


	shjson_free(&tree);

}

/**
 * @param block_height the min block height the mining reward will be available.
 */
static void commit_payout(int ifaceIndex, int block_height)
{
  CIface *iface;
  user_t *user;
  double min_input;
  double coin_val;
  double bal;
  time_t now;
  char uname[256];
  char buf[256];

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled)
    return;

  now = time(NULL);
  for (user = client_list; user; user = user->next) {
    if (0 == strncmp(user->worker, "system.", strlen("system.")))
      continue; /* public */

    if (user->balance[ifaceIndex] < 0.01)
      continue;

    memset(uname, 0, sizeof(uname));
    strncpy(uname, user->worker, sizeof(uname) - 1);
    strtok(uname, ".");
    if (!*uname)
      continue;

    if (user->reward_time < (now - MAX_REWARD_WAIT_TIME))
      break; /* waited more than hour for reward. */ 

    coin_val = floor(user->balance[ifaceIndex] * 1000) / 1000;
    if (coin_val > (user->balance_avg[ifaceIndex] * 10)) {
      break;
    }
  }
  if (!user)
    return;

  bal = getaccountbalance(ifaceIndex, "");
  min_input = (double)iface->min_tx_fee / (double)COIN;
  for (user = client_list; user; user = user->next) {
    if (0 == strncmp(user->worker, "system.", strlen("system.")))
      continue; /* public */

    memset(uname, 0, sizeof(uname));
    strncpy(uname, user->worker, sizeof(uname) - 1);
    strtok(uname, ".");
    if (!*uname)
      continue;

    coin_val = floor(user->balance[ifaceIndex] * 1000) / 1000;
    if (coin_val <= min_input)
      continue;

    if (coin_val >= bal)
      continue;

    if (0 == addblockreward(ifaceIndex, uname, coin_val)) {
      user->reward_time = time(NULL);
      user->reward_height = block_height;
      user->balance[ifaceIndex] = MAX(0.0, user->balance[ifaceIndex] - coin_val);
      bal -= coin_val;
    }
  }

  sendblockreward(ifaceIndex);
}

static int task_verify(int ifaceIndex, int *work_reset_p)
{
  uint64_t block_height;

  *work_reset_p = FALSE;

  block_height = getblockheight(ifaceIndex);
  if (block_height == last_block_height[ifaceIndex]) {
    return (SHERR_AGAIN);
  }

	if (stratum_isinitialdownload(ifaceIndex))
		return (ERR_AGAIN);
#if 0
  if (last_block_height[ifaceIndex] != 0) {
    CIface *iface = GetCoinByIndex(ifaceIndex);
    if (iface && iface->blockscan_max &&
        block_height < (iface->blockscan_max - 1)) {
      return (SHERR_AGAIN);
    }
  }
#endif

  check_payout(ifaceIndex);
  commit_payout(ifaceIndex, block_height-1);

  //reset_task_work_time();
  //work_idx = -1;
  *work_reset_p = TRUE;

//  free_tasks();
  last_block_height[ifaceIndex] = block_height;

  return (0);
}


typedef struct task_stat_t
{
  time_t birth;
  time_t stamp;
  uint32_t total;
} task_stat_t;

task_stat_t _task_stat[MAX_COIN_IFACE];

#if 0
typedef struct task_work_t
{
  int timer;
  int f_reset;
  double diff;
} task_work_t;

task_work_t _task_work[MAX_COIN_IFACE];

int task_work_calc(int ifaceIndex)
{
  task_work_t *work = &_task_work[ifaceIndex];
  int err;

  /* count down timer */
  work->timer--;
  
  err = task_verify(ifaceIndex, &work->f_reset);
  if (err)
    return (err);

  work->diff += GetNextDifficulty(idx);
  return (0);
}
#endif



task_t *task_init(task_attr_t *attr)
{
  static time_t last_reset_t;
  CIface *iface;
  shjson_t *block;
//  unsigned char hash_swap[32];
  shjson_t *tree;
  task_t *task;
  const char *templ_json;
  char coinbase[1024];
  char sig[256];
  char *ptr;
  char target[32];
  char errbuf[1024];
//  unsigned long cb1;
//  unsigned long cb2;
  int reset_idx;
  int ifaceIndex;
  int err;
  int i;
  double max_weight = 0.00;
  int max_iface = 0;

  reset_idx = 0;
  if (attr->flags & TASKF_RESET) {
    /* determine weightiest iface */
    stratum_task_weight(attr);
    for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
			if (!is_stratum_miner_algo(ifaceIndex, attr->alg))
				continue;

//			if (ifaceIndex == TESTNET_COIN_IFACE) continue;
//			if (ifaceIndex == COLOR_COIN_IFACE) continue;
      iface = GetCoinByIndex(ifaceIndex);
      if (!iface || !iface->enabled) continue;
      if (max_weight == 0.00 || attr->weight[ifaceIndex] > max_weight) {
        max_weight = attr->weight[ifaceIndex];
        max_iface = ifaceIndex;
      }
    }
    if (max_iface) {
      iface = GetCoinByIndex(max_iface);
      if (iface && iface->enabled) {
        /* debug */
       if (max_iface != attr->ifaceIndex) {
          sprintf(errbuf, "task_init: mining %s coins [weight %f].",
              iface->name, max_weight);
          shcoind_log(errbuf);
        }

        /* assign */
        attr->ifaceIndex = max_iface;
        attr->mine_stamp[max_iface] = time(NULL);
      }
    }

    reset_idx = 0;
    for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
			if (!is_stratum_miner_algo(ifaceIndex, attr->alg))
				continue;

//			if (ifaceIndex == TESTNET_COIN_IFACE) continue;
//			if (ifaceIndex == COLOR_COIN_IFACE) continue;
//     if (!iface || !iface->enabled) continue;

      if (attr->commit_stamp[ifaceIndex] != attr->blk_stamp[ifaceIndex]) {
				if (attr->alg == ALGO_SCRYPT) { 
					/* reward miners */
					check_payout(ifaceIndex);
					commit_payout(ifaceIndex,
							getblockheight(ifaceIndex) - 1);
				}

        /* assign */
        attr->commit_stamp[ifaceIndex] = attr->blk_stamp[ifaceIndex];
        reset_idx = ifaceIndex;
      }
    }
  }

  /* current assigned mining coin interface. */
  ifaceIndex = attr->ifaceIndex;

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (NULL);

  if (!iface->enabled)
    return (NULL);

  tree = stratum_miner_getblocktemplate(ifaceIndex, attr->alg);
  if (!tree) {
#if 0
	  sprintf(errbuf, "(%s) task_init: error decoding JSON.", iface->name);
	  shcoind_log(errbuf);
#endif
	  return (NULL);
  }

  block = shjson_obj(tree, "result");
  if (!block) {
    shjson_free(&tree);
    return (NULL);
  }

  task = (task_t *)calloc(1, sizeof(task_t));
  if (!task) { 
    shjson_free(&tree);
    return (NULL);
  }

  task->ifaceIndex = ifaceIndex;
#if 0
  task->work_reset = work_reset[ifaceIndex];
#endif
  if (reset_idx != ifaceIndex ||
      attr->blk_stamp[ifaceIndex] != last_reset_t) {
    task->work_reset = (reset_idx ? TRUE : FALSE);
    last_reset_t = attr->blk_stamp[ifaceIndex];

#if 0
		/* spammy */
		sprintf(errbuf, "(%s) task_init: created new mining task. (alg: %d) (height: %d) (prev-hash: %s) (reset: %s)\n", iface->name, attr->alg, (int)task->height, task->prev_hash, (task->work_reset ? "true" : "false"));
		shcoind_log(errbuf);
#endif
  } else {
    task->work_reset = FALSE;
  }

  memset(target, 0, sizeof(target));
  strncpy(target, shjson_astr(block, "target", "ffff"), 12);
  task->target = (double)0xffff / (double)(strtoll(target, NULL, 16) & 0x00ffffff);

  memset(coinbase, 0, sizeof(coinbase));
  strncpy(coinbase, shjson_astr(block, "coinbase", ""), sizeof(coinbase) - 1);
  //strncpy(coinbase, shjson_astr(block, "coinbase", "01000000c5c58853010000000000000000000000000000000000000000000000000000000000000000ffffffff1003a55a0704b4b0b000062f503253482fffffffff014b4c0000000000002321026a51c89c384db03cd9381c08f7a9a48eabd0971cf7d86c8ce1446546be38534fac00000000"), sizeof(coinbase) - 1);

  memset(sig, 0, sizeof(sig));
  strncpy(sig, shjson_astr(block, "coinbaseflags", ""), sizeof(sig) - 1);
  //strncpy(sig, shjson_astr(block, "sigScript", "03a55a0704b4b0b000062f503253482f"), sizeof(sig) - 1);

  memset(task->cb2, 0, sizeof(task->cb2));

  ptr = strstr(coinbase, sig);
  if (!ptr) {
    sprintf(errbuf, "task_init: coinbase does not contain sigScript (coinbase:%s, sig:%s)\n", coinbase, sig);
    shcoind_log(errbuf);

    shjson_free(&tree);
    task_free(&task);
    return (NULL);
  }

  strncpy(task->cb1, coinbase, strlen(coinbase) - strlen(ptr) - 16 /* xnonce */);

  if (strlen(ptr) >= sizeof(task->cb2)) {
    shcoind_log("task_init: error: coinbase is too large for stratum\n");
    return (NULL);
  }

  strncpy(task->cb2, ptr, sizeof(task->cb2)-1);
//static int xn_len = 8;
  //xn_len = user->peer.n1_len + user->peer.n2_len;
//  sprintf(task->cb1 + strlen(task->cb1), "%-2.2x", xn_len);

//  sprintf(task->xnonce2, "%-8.8x", shjson_astr(block, "extraNonce", 0));
//  strncpy(task->xnonce2, ptr + 2, 8); /* template xnonce */


  task->merkle_len = shjson_array_count(block, "transactions");
  task->merkle = (char **)calloc(task->merkle_len + 1, sizeof(char *));
  for (i = 0; i < task->merkle_len; i++) {
    task->merkle[i] = shjson_array_str(block, "transactions", i); /* alloc'd */
  }



  /* store server generate block. */
//  strncpy(task->tmpl_merkle, shjson_astr(block, "merkleroot", "9f9731f960b976a07de138599ad8c8f1737aecb0f5365c583c4ffdb3a73808d4"), sizeof(task->tmpl_merkle));
 // strncpy(task->xnonce2, ptr + 2 + 8, 8);
  sprintf(task->xnonce2, "%-8.8x", 0);

  task->version = (int)shjson_num(block, "version", BLOCK_VERSION);

  /* previous block hash */
  strncpy(task->prev_hash, shjson_astr(block, "previousblockhash", "0000000000000000000000000000000000000000000000000000000000000000"), sizeof(task->prev_hash) - 1);
/*
  hex2bin(hash_swap, task->prev_hash, 32);
  swap256(task->work.prev_hash, hash_swap);
*/


  strncpy(task->nbits, shjson_astr(block, "bits", "00000000"), sizeof(task->nbits) - 1);
  task->curtime = (time_t)shjson_num(block, "curtime", time(NULL));
  task->height = getblockheight(ifaceIndex);

  /* generate unique job id from user and coinbase */
  task->task_id = (unsigned int)shjson_num(block, "task", shcrc(task, sizeof(task_t)));

  shjson_free(&tree);

  /* keep list of shares to check for dups */
//  task->share_list = shmap_init(); /* mem */

#if 0
  task->next = task_list;
  task_list = task;
#endif

  return (task);
}

void task_free(task_t **task_p)
{
  task_t *task;
  int i;

  if (!task_p)
    return;

  task = *task_p;
  *task_p = NULL;

//  shmap_free(&task->share_list);

  if (task->merkle) {
    for (i = 0; task->merkle[i]; i++) {
      free(task->merkle[i]);
    }
    free(task->merkle);
  }

  free(task);
}

#if 0
task_t *stratum_task(unsigned int task_id)
{
  task_t *task;

int cnt;

cnt = 0;
  for (task = task_list; task; task = task->next) {
    if (task_id = task->task_id)
      break; 
cnt++;
  }

  return (task);
}
#endif


void stratum_round_reset(time_t stamp)
{
  user_t *user;
  int hour;

  hour = ((stamp / 3600) % MAX_ROUNDS_PER_HOUR);
  for (user = client_list; user; user = user->next) {
    if (user->flags & USER_RPC)
      continue; /* rpc user */
    if (user->flags & USER_SYNC)
      continue; /* stratum server */
    if (!*user->worker)
      continue; /* unknwown user */

    user->block_avg[hour] = 
      (user->block_avg[hour] + ((double)user->block_tot * 2)) / 3;
    user->round_stamp = stamp;
    user->block_tot = 0;
    user->block_cnt = 0;
    user->block_acc = 0;
  }

}

/**
 * Generate MAX_SERVER_NONCE scrypt hashes against a work task.
 * @note Submits a block 
 */
void stratum_task_work(task_t *task, task_attr_t *attr)
{
  static int luck = 2;
  static int idx;
  static time_t round_stamp;
  time_t now;
  unsigned int last_nonce;
  char ntime[16];
  int err;

	if (attr->alg != ALGO_SCRYPT)
		return;

  idx++;
  if (0 != (idx % luck)) {
    return;
  }

  if (!sys_user) {
    /* track server's mining stats. */
    sys_user = stratum_user_init(-1);
    strncpy(sys_user->worker, CPUMINER_WORKER, sizeof(sys_user->worker) - 1);
    sys_user->flags |= USER_SYSTEM;
    sys_user->next = client_list;
    client_list = sys_user;
  }

  now = time(NULL);
  if (round_stamp < (now - MAX_ROUND_TIME)) {
    stratum_round_reset(now);
    round_stamp = now;
  }

	/* sync up with current task iface */
	sys_user->ifaceIndex = attr->ifaceIndex;
  
  /* generate block hash */
/*
  memset(&sys_user->peer, 0, sizeof(sys_user->peer));
  sprintf(sys_user->peer.nonce1, "%-8.8x", 0x00000000);
  sys_user->peer.n1_len = 4;
  sys_user->peer.n2_len = 4;
*/
  sys_user->peer.diff = 0.125;
  sprintf(task->work.xnonce2, "%-8.8x", 0x00000000);
sprintf(ntime, "%-8.8x", (unsigned int)task->curtime);
  shscrypt_work(&sys_user->peer,
 &task->work, task->merkle, task->prev_hash, task->cb1, task->cb2, task->nbits, ntime);

  err = shscrypt(&task->work, MAX_SERVER_NONCE);
  if (!err && task->work.nonce != MAX_SERVER_NONCE) {
    luck = MAX(2, (luck / 2));

    err = shscrypt_verify(&task->work);

    if (!err) {
      /* update server's mining stats. */
      stratum_user_block(sys_user, task->work.pool_diff);

      if (task->work.pool_diff >= task->target) {
        char xn_hex[256];
        uint32_t be_nonce =  htobe32(task->work.nonce);

        //sprintf(xn_hex, "%s%s", sys_user->peer.nonce1, task->work.xnonce2);
        sprintf(xn_hex, "%s", task->work.xnonce2);
        stratum_miner_submitblock(task->task_id, task->curtime, task->work.nonce, xn_hex, NULL, NULL);
      }
    }
  } else {
    luck = (luck % 100) + 2;
  }

}

static uint64_t pend_block_height[MAX_COIN_IFACE];
int is_stratum_task_pending(int *ret_iface)
{
	static uint32_t usec;
	struct timeval now;
	uint64_t block_height;
	char errbuf[256];
	int ifaceIndex;
	int usec_trigger = 0;

	usec++;
	if (0 == (usec % 720)) { /* twelve minutes */
		usec_trigger = 1;
	}

	for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
		if (!is_stratum_miner_algo(ifaceIndex, ALGO_SCRYPT))
			continue;
		//if (ifaceIndex == TESTNET_COIN_IFACE) continue;
		//if (ifaceIndex == COLOR_COIN_IFACE) continue;
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

void stratum_task_gen(task_attr_t *attr)
{
  task_t *task;
  scrypt_peer peer;
  unsigned int last_nonce;
	char ebuf[256];
  int time;
  int err;

  task = task_init(attr);
  if (!task)
    return;

  /* notify subscribed clients of new task. */
  stratum_user_broadcast_task(task, attr);

	if (attr->alg == ALGO_SCRYPT) {
		/* cpuminer (8 cycles) */
		stratum_task_work(task, attr);
	}

  task_free(&task);
}




static uint64_t stratum_user_max_height(void)
{
  user_t *user;
  uint64_t ret_height = 0;

  for (user = client_list; user; user = user->next) {
    if (user->block_height > ret_height)
      ret_height = user->block_height;
  }

  return (ret_height);
}

void stratum_task_weight(task_attr_t *attr)
{
  CIface *iface;
  double weight;
  double dDiff;
  double nHeight;
  time_t now;
  char errbuf[256];
  int idx;

  now = time(NULL);
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
		if (!is_stratum_miner_algo(idx, attr->alg))
			continue;
//		if (idx == TESTNET_COIN_IFACE) continue;
//		if (idx == COLOR_COIN_IFACE) continue;
    iface = GetCoinByIndex(idx);
    if (!iface || !iface->enabled) continue;

    weight = 0;
    dDiff = GetNextDifficulty(idx);
    nHeight = getblockheight(idx); 

    if (attr->ifaceIndex != idx) {
      /* primary - "how long ago pool was mined" */
      weight += MAX(0.01, MIN(900, (double)(now - attr->mine_stamp[idx])));
    }

    /* secondary - "how long ago was block accepted" */
    weight += MAX(0.01, MIN(600, (double)(now - iface->net_valid)));

    /* trinary - "how difficult is next block" (lower=better) */
    attr->avg_diff[idx] = (dDiff + (attr->avg_diff[idx] * 3)) / 4;
    weight -= MAX(0.01, MIN(300, sqrt(attr->avg_diff[idx])));

#if 0
    /* bonus - current mined coin post-submit period. */ 
    if (attr->ifaceIndex == idx) {
      if ((now - iface->net_valid) < POST_BLOCK_TIME) {
        /* more weight based on blocks since last aquired block. */
        weight += MAX(0.01, MIN(100, (double)(nHeight - stratum_user_max_height())));
      }
    }
#endif

    /* calculate running average */
    weight = MAX(0.001, weight);
    attr->weight[idx] = (attr->weight[idx] + weight) / 2;

    /* debug */
    sprintf(errbuf, "stratum_task_weight: %s-coin has weight %-3.3f", iface->name, attr->weight[idx]);
    shcoind_log(errbuf);
  }
  
}
