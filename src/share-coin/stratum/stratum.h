
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

#ifndef __STRATUM__STRATUM_H__
#define __STRATUM__STRATUM_H__

/**
 * A stratum protocol implementation which provides basic mining with traditional scrypt commands in additional to extended abilities for managing accounts and reviewing worker status.
 * @ingroup sharecoin
 * @defgroup sharecoin_stratum The share-coin daemon stratum server.
 * @{
 */


#define MAX_SPEED_STEP 60
#define MAX_ROUNDS_PER_HOUR 6

#ifndef RPC_AUTH_FREQ
#define RPC_AUTH_FREQ 300
#endif


#define TASKF_RESET (1 << 0)

/* user flags */
#define USER_SYSTEM (1 << 0)
#define USER_AUTH (1 << 1)
#define USER_SUBSCRIBE (1 << 2)
#define USER_SYNC (1 << 3)
#define USER_CLIENT (1 << 4)
#define USER_REMOTE (1 << 5)
#define USER_RPC (1 << 6)
#define USER_ELEVATE (1 << 7)

/* sync flags */
#define SYNC_AUTH (1 << 1)
#define SYNC_IDENT (1 << 4)
#define SYNC_WALLET_SET (1 << 12)
#define SYNC_WALLET_ADDR (1 << 13)
#define SYNC_WALLET_EXTADDR (1 << 14)
#define SYNC_RESP_PING (1 << 20)
#define SYNC_RESP_USER_LIST (1 << 21)
#define SYNC_RESP_WALLET_ADDR (1 << 22)
#define SYNC_RESP_WALLET_SET (1 << 23)
#define SYNC_RESP_ELEVATE (1 << 24)
#define SYNC_RESP_IDENT (1 << 25)

#define SYNC_RESP_ALL \
  (SYNC_RESP_PING | SYNC_RESP_USER_LIST | SYNC_RESP_WALLET_ADDR | SYNC_RESP_WALLET_SET | SYNC_RESP_ELEVATE | SYNC_RESP_IDENT)
  


typedef struct user_t
{
  scrypt_peer peer;

  /** last aquired usde block */
  char block_hash[256];

  char worker[128];
  char pass[256];
  char cli_ver[128];
  char cli_id[256];
  char cur_id[256];

  char sync_pubkey[256];
  char sync_acc[256];

  int work_diff;

  int fd;
  int flags;
  int sync_flags;

  /** last height notified to user */
  int height;

  /** last submitted block timestamp. */
  double block_tm;

  /** total shares from blocks */ 
  double block_tot;

  /** cntal accepted blocks submitted. */ 
  size_t block_cnt;

  /** average round share value over last hour */
  double block_avg[MAX_ROUNDS_PER_HOUR];

  /** how many blocks submitted per second (avg) */
  double block_freq;

  /** number of blocks accepted for submission */
  int block_acc;

double speed[MAX_SPEED_STEP];

  double balance[MAX_COIN_IFACE];

  double balance_avg[MAX_COIN_IFACE];

  /** the timestamp when the current round started. */
  time_t round_stamp;

  /* the timestamp of when the client last recieved work */
  time_t work_stamp;

  time_t sync_user;
  time_t sync_addr;

  time_t reward_time;
  uint64_t reward_height;
  int ifaceIndex;

  /* a unique reference to the originating IP/port */
  shkey_t netid;

  struct user_t *next;
} user_t;

typedef struct task_t
{

  /** unique reference number for task */
  unsigned int task_id;

  int version;
  char cb1[1024];
  char cb2[1024];
  char prev_hash[256];
  char xnonce2[16];
  char nbits[32];
  time_t curtime;
  long height;
  /** whether new cycle of work tasks has occurred. */
  int work_reset;
  int ifaceIndex;

  /** transactions */
  char **merkle;
  size_t merkle_len;

  /** block template parameters */
  char tmpl_merkle[256];
  char tmpl_xnonce1[16];

  double target;

//  shmap_t *share_list;
 // shfs_ino_t *share_file; 

  scrypt_work work;

  struct task_t *next;
} task_t;

typedef struct task_attr_t
{
  double weight[MAX_COIN_IFACE];
  time_t blk_stamp[MAX_COIN_IFACE];
  time_t commit_stamp[MAX_COIN_IFACE];
  time_t mine_stamp[MAX_COIN_IFACE];
  time_t tnow;
  int ifaceIndex;
  int flags;
} task_attr_t;

#include "stratum_user.h"
#include "stratum_protocol.h"
#include "stratum_message.h"
#include "stratum_task.h"



int stratum_register_client_task(user_t *user, char *json_text);

int get_stratum_daemon_port(void);

shjson_t *stratum_json(const char *json_text);


#ifdef __cplusplus
extern "C" {
#endif

extern user_t *client_list;

user_t *stratum_register_client(int fd);

void stratum_close(int fd, struct sockaddr *net_addr);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ndef __STRATUM__STRATUM_H__ */

