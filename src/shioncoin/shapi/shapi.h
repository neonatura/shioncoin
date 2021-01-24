
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

#ifndef __SHAPI__SHAPI_H__
#define __SHAPI__SHAPI_H__

/**
 * A shapi protocol implementation which provides an API
 * for managing accounts and reviewing worker status.
 * @ingroup sharecoin
 * @defgroup sharecoin_shapi The shioncoin daemon shapi server.
 * @{
 */

#define MAX_SPEED_STEP 60
#define MAX_ROUNDS_PER_HOUR 6

#ifndef RPC_AUTH_FREQ
#define RPC_AUTH_FREQ 300
#endif

#define MAX_SHAPI_MESSAGE_SIZE 16000000 /* 16m */


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
#define USER_EXTRANONCE (1 << 8)

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
  
typedef struct shapi_t
{
	int fd;
	char cur_id[256];
	struct shapi_t *next;
} shapi_t;

int stridx(const char *str, char ch); /* share.c */

#include "shapi_user.h"
#include "shapi_api.h"
#include "shapi_protocol.h"
#include "shapi_api.h"


int shapi_register_client_task(shapi_t *user, char *json_text);

int get_shapi_port(void);

shjson_t *shapi_json(const char *json_text);

int shapi_init(void);

#ifdef __cplusplus
extern "C" {
#endif

extern shapi_t *shapi_client_list;

shapi_t *shapi_register_client(int fd);

void shapi_close(int fd, struct sockaddr *net_addr);

void shapi_accept(int fd, struct sockaddr *net_addr);

#ifdef __cplusplus
}
#endif


/**
 * @}
 */

#endif /* ndef __SHAPI__SHAPI_H__ */

