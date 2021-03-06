
/*
 * @copyright
 *
 *  Copyright 2016 Brian Burrell
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

#ifndef __BLOCKCHAIN__BC_H__
#define __BLOCKCHAIN__BC_H__


#ifdef USE_LIBPTHREAD
#include <pthread.h>
typedef pthread_mutex_t bclock_t;
#else
typedef int bclock_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif


#ifndef linux
#define getpagesize() sysconf(_SC_PAGESIZE)
#endif

#define BC_BLOCKS_PER_JOURNAL 65536

#define BC_MAX_NAME_LENGTH MAX_SHARE_NAME_LENGTH

#define BCMAP_LOCK "bcmap_lock"

typedef uint32_t bcsize_t;

typedef uint32_t bcpos_t;

typedef uint32_t bc_hash_t[8];

typedef struct bc_idx_t
{
  uint32_t jrnl;
  bcsize_t of;
  bcsize_t size;
  uint32_t crc;
  uint64_t __reserved_0__;
  uint64_t __reserved_1__;
  bc_hash_t hash;
} bc_idx_t; /* 16b */

typedef struct bc_hdr_t
{
  /** The last time the map was accessed */
  shtime_t stamp;
  /** An arbritrary number verifying this is a file-map. */
  uint32_t magic;
  /** The offset of data written by the user. */
  bcsize_t of; 
} bc_hdr_t; /* 16b */

typedef struct bc_map_t
{
  volatile int fd;
  volatile size_t size;
  time_t stamp; 
  char ext[64];
  bc_hdr_t *hdr;
  uint8_t *raw;
} bc_map_t;

typedef struct bc_t
{
  char name[BC_MAX_NAME_LENGTH];
  shkey_t data_key;
  bc_map_t idx_map;
  bc_map_t tab_map;
  bc_map_t arch_map;
  bc_map_t *data_map;
  size_t data_map_len;
	bclock_t lk;
} bc_t;

typedef struct bc_t CBlockChain;



#include "bc_mutex.h"
#include "bc_fmap.h"
#include "bc_index.h"
#include "bc_table.h"
#include "bc_arch.h"
#include "bc_block.h"



#ifdef __cplusplus
}
#endif

#endif /* ndef __BLOCKCHAIN__BC_H__ */


