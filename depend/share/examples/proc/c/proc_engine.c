
/*
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
*/  

#include "share.h"

#if 0

_TEST(shproc_schedule)
{
  shproc_pool_t *pool;
  shproc_t *proc_list[256];
  shproc_t *proc;
  int val;
  int t_val;
  int err;
  int i;

  for (i = 0; i < 2; i++) {
    _test_shproc_value[i] = -1;
  }

  pool = shproc_init(_test_shproc_req, _test_shproc_resp);
//  shproc_conf(pool, SHPROC_MAX, 2);

  for (i = 0; i < 2; i++) {
    proc = shproc_start(pool);
    _TRUEPTR(proc);
    proc_list[i] = proc;

    val = i;
    err = shproc_schedule(proc, (unsigned char *)&val, sizeof(val));
    _TRUE(0 == err);
  }
sleep(1);

  /* handle ACK response */
  for (i = 0; i < 2; i++) {
    err = shproc_parent_poll(proc_list[i]);
    _TRUE(0 == err);
  }

#if 0
  for (i = 0; i < 2; i++) {
    /* wait for work to be finished. */
    err = shproc_wait(proc_list[i], 0);
  }
#endif

  for (i = 0; i < 2; i++) {
    _TRUE(0 == shproc_stop(proc_list[i]));
  }

  for (i = 0; i < 2; i++) {
    /* verify response */
    _TRUE(_test_shproc_value[i]-1 == i);
  }

  shproc_free(&pool);
}

_TEST(shproc_push)
{
  shproc_pool_t *pool;
  shproc_t *proc_list[256];
  shproc_t *proc;
FILE *fl;
char path[PATH_MAX+1];
  int val;
  int t_val;
  int err;
  int i;

  for (i = 0; i < 2; i++) {
    _test_shproc_value[i] = -1;
  }

  pool = shproc_init(_test_shproc_req, _test_shproc_resp);
//  shproc_conf(pool, SHPROC_MAX, 2);

  for (i = 0; i < 2; i++) {
    sprintf(path, ".temp%d", i);
    fl = fopen(path, "wb+");
    _TRUEPTR(fl);
    fwrite(&i, sizeof(int), 1, fl);

    val = i;
    err = shproc_push(pool, fileno(fl), NULL, 0);
    fclose(fl);
    _TRUE(0 == err);
  }
sleep(1);

  /* handle ACK response */
  shproc_poll(pool);
  shproc_shutdown(pool);

  for (i = 0; i < 2; i++) {
    /* verify response */
    _TRUE(_test_shproc_value[i]-1 == i);
  }

  for (i = 0; i < 2; i++) {
    sprintf(path, ".temp%d", i);
    unlink(path);
  }

  shproc_free(&pool);
}

#endif
