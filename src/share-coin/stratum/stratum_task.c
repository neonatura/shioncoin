
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

#define __STRATUM__TASK_C__

#include "shcoind.h"
#include "stratum/stratum.h"
#include <math.h>
#include "coin_proto.h"

#define BLOCK_VERSION 1
//#define MAX_SERVER_NONCE 128
#define MAX_SERVER_NONCE 4
#define MAX_ROUND_TIME 600

//static task_t *task_list;
static user_t *sys_user;
static int work_reset[MAX_COIN_IFACE];
static uint64_t last_block_height[MAX_COIN_IFACE];
static double nBankFee[MAX_COIN_IFACE];


#if 0
void free_tasks(void)
{
  task_t *task;
  task_t *task_next;

  for (task = task_list; task; task = task_next) {
    task_next = task->next;
    task_free(&task);
  }
  task_list = NULL;

}
#endif

#if 0
void free_task(task_t **task_p)
{
  task_t *task;
  int i;

  if (!task_p)
    return;
  task = *task_p;
  *task_p = NULL;

  if (task->merkle) {
    for (i = 0; task->merkle[i]; i++) {
      free(task->merkle[i]);
    }
    free(task->merkle);
  }

  free(task);

}
#endif


#if 0
int task_work_t = 2;

void reset_task_work_time(void)
{
  task_work_t = 2;
}

void incr_task_work_time(void)
{

  if (task_work_t < 4)
    task_work_t++;
    
}
#endif

static int work_idx = 0;
#if 0
int DefaultWorkIndex = 0;
#endif
static char last_payout_hash[MAX_COIN_IFACE][256];

/**
 * Monitors when a new accepted block becomes confirmed.
 * @note format: ["height"=<block height>, "category"=<'generate'>, "amount"=<block reward>, "time":<block time>, "confirmations":<block confirmations>]
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

  templ_json = (char *)getblocktransactions(ifaceIndex);
  if (!templ_json) {
    return;
  }

  tree = shjson_init(templ_json);
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

  memset(category, 0, sizeof(category));
  strncpy(category, shjson_astr(block, "category", "none"), sizeof(category) - 1);
  if (0 != strcmp(category, "generate")) {
    shjson_free(&tree);
    return;
  }

  if (0 == strcmp(last_payout_hash[ifaceIndex], block_hash)) {
    shjson_free(&tree);
    return;
  }
  strcpy(last_payout_hash[ifaceIndex], block_hash);



  {
    double amount = shjson_num(block, "amount", 0);
    double fee;

    if (amount < 1) {
      shjson_free(&tree);
      return;
    }
    if (!client_list)
      return;

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
      if (0 == strncmp(user->worker, "anonymous.", strlen("anonymous.")))
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
        sprintf(buf, "check_payout: worker '%s' has pending balance of %-8.8f %s coins (+%-8.8f, avg %-4.4f).", user->worker, user->balance[ifaceIndex], iface->name, reward, user->balance_avg);
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
  char uname[256];
  char buf[256];
  double min_input;
  double coin_val;
  double bal;

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled)
    return;

  for (user = client_list; user; user = user->next) {
    if (0 == strncmp(user->worker, "anonymous.", strlen("anonymous.")))
      continue; /* public */

    if (user->balance[ifaceIndex] < 5.0)
      continue;

    memset(uname, 0, sizeof(uname));
    strncpy(uname, user->worker, sizeof(uname) - 1);
    strtok(uname, ".");
    if (!*uname)
      continue;

    coin_val = floor(user->balance[ifaceIndex] * 1000) / 1000;
    if (coin_val > (user->balance_avg[ifaceIndex] * 8)) {
      break;
    }
  }
  if (!user)
    return;

  bal = getaccountbalance(ifaceIndex, "");
  min_input = (double)iface->min_tx_fee / (double)COIN;
  for (user = client_list; user; user = user->next) {
    if (0 == strncmp(user->worker, "anonymous.", strlen("anonymous.")))
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
      nBankFee[ifaceIndex] += (coin_val * 0.001); /* 0.1% */
    }
  }

  if (nBankFee[ifaceIndex] > 100.0) {
    if (bal > nBankFee[ifaceIndex]) {
      if (0 == addblockreward(ifaceIndex, "bank", nBankFee[ifaceIndex])) {
        sprintf(buf, "(%s) commit_payout: 'bank' account tax'd %f coins.\n", iface->name, nBankFee[ifaceIndex]); 
        shcoind_log(buf);
      }
    }
    nBankFee[ifaceIndex] = 0;
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

  if (last_block_height[ifaceIndex] != 0) {
    CIface *iface = GetCoinByIndex(ifaceIndex);
    if (iface && iface->blockscan_max &&
        block_height < (iface->blockscan_max - 1)) {
      return (SHERR_AGAIN);
    }
  }

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
  char coinbase[512];
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
      if (!iface || !iface->enabled) continue;

      if (attr->commit_stamp[ifaceIndex] != attr->blk_stamp[ifaceIndex]) {
        /* reward miners */
        check_payout(ifaceIndex);
        commit_payout(ifaceIndex,
            getblockheight(ifaceIndex) - 1);

        /* assign */
        attr->commit_stamp[ifaceIndex] = attr->blk_stamp[ifaceIndex];
        reset_idx = ifaceIndex;
      }
    }
  }

#if 0
  reset_idx = 0;
  if (DefaultWorkIndex == 0)
    DefaultWorkIndex = stratum_default_iface(); 
  for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
    iface = GetCoinByIndex(ifaceIndex);
    if (!iface || !iface->enabled)
      continue;

    err = task_verify(ifaceIndex, &work_reset[ifaceIndex]);
    if (!err)
      reset_idx = ifaceIndex;
  }

  int orig_idx = DefaultWorkIndex;
  if (reset_idx) {
    int diff_idx = stratum_default_iface();
    if (diff_idx &&
        diff_idx != DefaultWorkIndex &&
        diff_idx != reset_idx) {
      DefaultWorkIndex = diff_idx;
    } else {
      int idx = (shrand() % (MAX_COIN_IFACE-1)) + 1;
      iface = GetCoinByIndex(idx);
      if (iface && iface->enabled)
        DefaultWorkIndex = idx;
    }

    if (orig_idx && (orig_idx != DefaultWorkIndex)) {
      sprintf(errbuf, "task_init: switching mining pool from coin interface #%d to #%d\n", orig_idx, DefaultWorkIndex); 
      shcoind_log(errbuf);
    }
  }

  if (DefaultWorkIndex == 0)
    return (NULL);

  /* concentrate on single coin at a time */
  if (reset_idx != orig_idx) {
    /* if no block confirmed then delay new work */
    work_idx++;
    if (0 != (work_idx % 6))
      return (NULL);
  }

  ifaceIndex = DefaultWorkIndex;
#endif

  /* current assigned mining coin interface. */
  ifaceIndex = attr->ifaceIndex;

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (NULL);

  if (!iface->enabled)
    return (NULL);

  {
    const char *json_text = getblocktemplate(ifaceIndex);

    if (!json_text) {
        return (NULL);
}

    tree = stratum_json(json_text);
    if (!tree) {
      sprintf(errbuf, "(%s) task_init: error decoding JSON: %s\n", iface->name, json_text); 
      shcoind_log(errbuf);
      return (NULL);
    }
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

  ptr = strstr(coinbase, sig);
  if (!ptr) {
    sprintf(errbuf, "task_init: coinbase does not contain sigScript (coinbase:%s, sig:%s)\n", coinbase, sig);
    shcoind_log(errbuf);

    shjson_free(&tree);
    task_free(&task);
    return (NULL);
  }

  strncpy(task->cb1, coinbase, strlen(coinbase) - strlen(ptr) - 16 /* xnonce */);
//static int xn_len = 8;
  //xn_len = user->peer.n1_len + user->peer.n2_len;
//  sprintf(task->cb1 + strlen(task->cb1), "%-2.2x", xn_len);

//  sprintf(task->xnonce2, "%-8.8x", shjson_astr(block, "extraNonce", 0));
//  strncpy(task->xnonce2, ptr + 2, 8); /* template xnonce */


  if (strlen(ptr) >= sizeof(task->cb2)) {
    shcoind_log("task_init: error: coinbase is too large for stratum\n");
    return (NULL);
  }
  memset(task->cb2, 0, sizeof(task->cb2));
  strncpy(task->cb2, ptr, sizeof(task->cb2)-1);
  //strcpy(task->cb2, ptr);

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

  sprintf(errbuf, "(%s) task_init: created new mining task. (height: %d) (prev-hash: %s)\n", iface->name, (int)task->height, task->prev_hash);
  shcoind_log(errbuf);

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

  if (task->merkle && task->merkle_len) {
    for (i = 0; i < task->merkle_len; i++) {
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
      (user->block_avg[hour] + (double)user->block_tot) / 2;
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
void stratum_task_work(task_t *task)
{
  static int luck = 2;
  static int idx;
  static time_t round_stamp;
  time_t now;
  unsigned int last_nonce;
  char ntime[16];
  int err;

  idx++;
  if (0 != (idx % luck)) {
    return;
  }

  if (!sys_user) {
    /* track server's mining stats. */
    sys_user = stratum_user_init(-1);
    strncpy(sys_user->worker, "anonymous.system", sizeof(sys_user->worker) - 1);
    sys_user->flags |= USER_SYSTEM;
    sys_user->next = client_list;
    client_list = sys_user;
  }

  now = time(NULL);
  if (round_stamp < (now - MAX_ROUND_TIME)) {
    stratum_round_reset(now);
    round_stamp = now;
  }
  
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

        sprintf(xn_hex, "%s%s", sys_user->peer.nonce1, task->work.xnonce2);
        submitblock(task->task_id, task->curtime, task->work.nonce, xn_hex, NULL, NULL);
      }
    }
  } else {
    luck++;
  }

}

static uint64_t pend_block_height[MAX_COIN_IFACE];
int is_stratum_task_pending(int *ret_iface)
{
  static uint32_t usec;
  struct timeval now;
  uint64_t block_height;
  int ifaceIndex;
  char errbuf[256];

  for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
    CIface *iface = GetCoinByIndex(ifaceIndex);
    if (!iface || !iface->enabled) 
      continue; /* iface not enabled */

    block_height = (uint64_t)getblockheight(ifaceIndex);
    if (iface->blockscan_max &&
        block_height < (iface->blockscan_max - 1))
      continue; /* downloading blocks.. */

    if (block_height == pend_block_height[ifaceIndex])
      continue; /* no new block. */

    pend_block_height[ifaceIndex] = block_height;
    if (ret_iface)
      *ret_iface = ifaceIndex;

#if 0
    sprintf(errbuf, "(%s) is_stratum_task_pending: new block detected at height %d", iface->name, (int)block_height);
    shcoind_log(errbuf);
#endif

    return (TRUE);
  }

  return (FALSE);
}

/**
 * @note This function is spaced 1 second apart being called intentionally as to avoid producing orphans.
 */
void stratum_task_gen(task_attr_t *attr)
{
  task_t *task;
  scrypt_peer peer;
  unsigned int last_nonce;
  int time;
  int err;

  task = task_init(attr);
  if (!task)
    return;

  /* notify subscribed clients of new task. */
  stratum_user_broadcast_task(task, attr);

  stratum_task_work(task);

  task_free(&task);
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
    iface = GetCoinByIndex(idx);
    if (!iface || !iface->enabled) continue;

    weight = 0;
    dDiff = GetNextDifficulty(idx);
    nHeight = getblockheight(idx); 

    if (attr->ifaceIndex != idx) {
      /* primary - "how long we ago pool was mined" */
      weight += MAX(0.01, MIN(900, (double)(now - attr->mine_stamp[idx])));
    }

    /* secondary - "how long was block accepted" */
    weight += MAX(0.01, MIN(600, (double)(now - iface->net_valid)));

    /* trinary - "how difficult is next block" */
    weight += MAX(0.01, MIN(300, dDiff / 10));

    /* calculate running average */
    weight = MAX(0.001, weight);
    attr->weight[idx] = (attr->weight[idx] + weight) / 2;

    /* debug */
    sprintf(errbuf, "stratum_task_weight: %s-coin has weight %-3.3f", iface->name, attr->weight[idx]);
    shcoind_log(errbuf);
  }
  
}
