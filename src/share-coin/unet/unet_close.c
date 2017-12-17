
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

#include "shcoind.h"

#define MAX_SOCKET_BUFFER_SIZE 40960000 /* 40meg */

int unet_close(unsigned int sk, char *tag)
{
  unet_table_t *table;
  unet_bind_t *bind;
  char buf[256];
  int err;

  table = get_unet_table(sk);
  if (!table) {
    sprintf(buf, "unet_close: warning: sk %d requested closure but not mapped.\n", sk);
    shcoind_log(buf);
    return (SHERR_INVAL);
  }

  /* inform user-level of socket closure. */
  bind = unet_bind_table(table->mode);
  if (bind && bind->op_close) {
    (*bind->op_close)(sk, &table->net_addr);
  }

  sprintf(buf, "closed connection '%s' (%-2.2fh) [%s] [fd %d].",
      shaddr_print(&table->net_addr), 
      shtime_diff(shtime(), table->cstamp) / 3600,
      tag ? tag : "n/a", (int)sk);
  unet_log(table->mode, buf);

  descriptor_release(sk);

  return (err);
}

int unet_close_all(int mode)
{
  unet_table_t *t;
  int sk;

  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    t = get_unet_table(sk);
    if (!t)
      continue; /* not active */
    if (t->mode != mode)
      continue; /* wrong mode bra */
    if (!(t->flag & DF_SERVICE))
      continue;

    unet_close(sk, "terminate");
  }

  return (0);
}


/**
 * Applies to all sockets regardless of service.
 */
void unet_close_idle(void)
{
  unet_table_t *t;
  shtime_t conn_idle_t;
  shtime_t idle_t;
  shtime_t now;
  char buf[256];
  unsigned int sk;

  now = shtime();
  conn_idle_t = shtime_adj(now, -60);
  idle_t = shtime_adj(now, -3600);

  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    t = get_unet_table(sk);
    if (!t)
      continue; /* non-active */
    if (!(t->flag & DF_SOCK))
      continue; /* sockets */
    if ((t->flag & DF_LISTEN))
      continue; /* !bind */

    if (t->stamp == UNDEFINED_TIME &&
        shtime_before(shtime_adj(t->cstamp, MAX_CONNECT_IDLE_TIME), now)) {
      sprintf(buf, "unet_close_idle: closing peer '%s' for no activity for %ds after connect [mode %d] [fd %d] [flag %d].", shaddr_print(&t->net_addr), MAX_CONNECT_IDLE_TIME, t->mode, sk, t->flag);
      unet_log(t->mode, buf);
      unet_close(sk, "connect-idle");
      continue;
    }

    if (t->mode == UNET_STRATUM ||
        t->mode == UNET_STRATUM_ESL) {
      if (t->stamp != UNDEFINED_TIME &&
          shtime_before(shtime_adj(t->stamp, MAX_IDLE_TIME), now)) {
        unet_close(sk, "idle");
        continue;
      }
    }

    if (shbuf_size(t->wbuff) > MAX_SOCKET_BUFFER_SIZE ||
        shbuf_size(t->rbuff) > MAX_SOCKET_BUFFER_SIZE) {
      unet_close(sk, "overflow");
      continue;
    }
  }

}

#if 0
/**
 * Closes and de-allocates resourcs for all socket connections (regardless of service).
 */
void unet_close_free(void)
{
  unet_table_t *t;
  int sk;

  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    t = get_unet_table(sk);
    if (!t)
      continue; /* active */
    if (t->mode == UNET_NONE)
      continue; /* already cleared */ 
    if (!(t->flag & DF_SOCK))
      continue;

    descriptor_release(sk);
  }

}
#endif

