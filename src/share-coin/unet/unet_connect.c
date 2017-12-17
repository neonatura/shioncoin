
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

#define UNET_CONNECT_TIMEOUT 3

/* ipv4 */
int unet_connect(int mode, struct sockaddr *net_addr, unsigned int *sk_p)
{
  unet_bind_t *bind;
  shtime_t ts;
  char buf[256];
  unsigned int cli_fd;
  int err;

  cli_fd = shnet_sk();
  if (cli_fd < 0) 
    return (cli_fd);

  if (cli_fd >= MAX_UNET_SOCKETS) {
    char buf[256];

    sprintf(buf, "unet_connect: socket descriptor (%u) exceeds supported maximum.", (unsigned int)cli_fd);
    unet_log(mode, buf); 

    /* exceeds supported limit (hard-coded) */
    shnet_close(cli_fd);
    return (SHERR_AGAIN);
  }

  shnet_fcntl(cli_fd, F_SETFL, O_NONBLOCK);
  timing_init("shconnect", &ts);
  err = shconnect(cli_fd, net_addr, sizeof(struct sockaddr));
  timing_term(mode, "shconnect", &ts);
  if (err == SHERR_INPROGRESS) {
    /* async connect -- waits up to UNET_CONNECT_TIMEOUT seconds */
    struct timeval to = { UNET_CONNECT_TIMEOUT, 0 };
    fd_set w_set;

    FD_ZERO(&w_set);
    FD_SET(cli_fd, &w_set);
    err = shselect(cli_fd+1, NULL, &w_set, NULL, &to);
    if (err > 0) {
      err = 0;
    } else if (err == 0) {
      err = SHERR_TIMEDOUT;
    } else {
      err = -errno;
    }
  }
  if (err) {
    shnet_close(cli_fd);
    return (err);
  }

  /* claim descriptor for coin service. */
  unet_add(mode, cli_fd);

  sprintf(buf, "created new '%s' connection (%s) [fd %d].\n", 
      unet_mode_label(mode), shaddr_print(net_addr), (int)cli_fd);
  unet_log(mode, buf);

  bind = unet_bind_table(mode);
  if (bind && bind->op_accept) {
    (*bind->op_accept)(cli_fd, net_addr);
  }

  if (sk_p)
    *sk_p = cli_fd;

  if (bind->flag & UNETF_PEER_SCAN) {
    /* record successfull connection */
    shpeer_t *peer = shpeer_init(
        (char *)unet_mode_label(mode), (char *)shaddr_print(net_addr));
    unet_peer_incr(mode, peer);
    shpeer_free(&peer);
  }

  return (0);
}

