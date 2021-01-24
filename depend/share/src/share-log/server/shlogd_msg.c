
/*
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
 */

#define __SERVER__SHLOGD_TASK_C__
#include <share.h>
#include "sharelog_server.h"

int daemon_msg_qid;
shbuf_t *daemon_msg_buff;

void daemon_msg_init(void)
{
  shpeer_t *log_peer;

  /* retrieve message queue id for daemon. */
  log_peer = shpeer_init(PROCESS_NAME, NULL);
  daemon_msg_qid = shmsgget(log_peer);
  shpeer_free(&log_peer);

  /* initialize incoming message buffer. */
  daemon_msg_buff = shbuf_init();

}

void daemon_msg_proc(shbuf_t *buff, shkey_t *src_key)
{
  unsigned char *data = shbuf_data(buff);
  size_t data_len = shbuf_size(buff);

  if (!data || data_len == 0)
    return;

  daemon_task_append(data, src_key);
  shbuf_clear(buff);

}

void daemon_msg_poll(void)
{
  shkey_t src_key;
  int err;

  if (daemon_msg_qid <= 0)
    daemon_msg_init();
  if (daemon_msg_qid <= 0)
    return;

retry:
  memset(&src_key, 0, sizeof(src_key));
  err = shmsg_read(daemon_msg_qid, &src_key, daemon_msg_buff);
  if (err) {
    if (err != SHERR_NOMSG && err != SHERR_AGAIN) {
      fprintf(stderr, "shmsg_read: %s\n", sherrstr(err));
    }
    return;
  }

  daemon_msg_proc(daemon_msg_buff, &src_key);
goto retry;

}


