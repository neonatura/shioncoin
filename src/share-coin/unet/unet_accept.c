
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

#if 0
static unet_table_t _unet_table[MAX_UNET_SOCKETS];

unet_table_t *get_unet_table(unsigned int sk)
{

  if (sk <= 0 || sk >= MAX_UNET_SOCKETS)
    return (NULL);

  return (_unet_table + sk);
}
#endif

unet_table_t *get_unet_table(unsigned int sk)
{
  return (descriptor_get(sk));
}

static const char *unet_hostname(struct sockaddr *addr)
{
  static char ipaddr[256];
  sa_family_t in_fam;

  in_fam = *((sa_family_t *)addr);
  memset(ipaddr, 0, sizeof(ipaddr));
  if (in_fam == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    inet_ntop(AF_INET, &sin->sin_addr, ipaddr, sizeof(ipaddr)-1); 
  } else if (in_fam == AF_INET6) {
    struct sockaddr_in6 *sin = (struct sockaddr_in6 *)addr;
    inet_ntop(AF_INET6, &sin->sin6_addr, ipaddr, sizeof(ipaddr)-1); 
  }

  return ((const char *)ipaddr);
}

int unet_local_verify_fd(int fd)
{
  struct sockaddr addr;
  socklen_t len;

  len = sizeof(addr);
  memset(&addr, 0, sizeof(addr));
  getpeername(fd, &addr, &len);

  return (unet_local_verify((char *)unet_hostname(&addr)));
}

int unet_accept(int mode, unsigned int *sk_p)
{
  unet_bind_t *bind;
  struct sockaddr_in *addr;
  char buf[256];
  int cli_fd;

  bind = unet_bind_table(mode);
  if (!bind) {
    return (SHERR_INVAL);
  }

  if (bind->fd == UNDEFINED_SOCKET)
    return (SHERR_BADF);

  cli_fd = shnet_accept_nb(bind->fd);
  if (cli_fd == 0)
    return (SHERR_AGAIN);
  if (cli_fd < 0) {
    sprintf(buf, "unet_accept: warning: error %d (errno %d) (bind->fd %d).", cli_fd, errno, bind->fd);
    unet_log(mode, buf); 
    return ((int)cli_fd);
  }

  if (cli_fd >= MAX_UNET_SOCKETS) {
    char buf[256];

    sprintf(buf, "unet_accept: socket descriptor (%u) exceeds supported maximum.", (unsigned int)cli_fd);
    shcoind_info(unet_mode_label(mode), buf);

    /* exceeds supported limit (hard-coded) */
    shnet_close(cli_fd);
    return (SHERR_AGAIN);
  }

  if (mode < MAX_UNET_COIN_MODES) {
    /* only one connection allowed per origin IP address for coin services */
    if (unet_peer_find(mode, shaddr(cli_fd))) {
      sprintf(buf, "unet_accept: disconnecting non-unique IP origin: %s", shaddr_print(shaddr(cli_fd))); 
      shcoind_info(unet_mode_label(mode), buf);

      /* only one IP origin address per coin service allowed */
      shnet_close(cli_fd);
      return (SHERR_NOTUNIQ);
    }

    /* loop-back connections are not permitted */
    if (unet_local_verify_fd(cli_fd)) {
      sprintf(buf, "unet_accept: disconnecting loopback IP origin: %s", shaddr_print(shaddr(cli_fd))); 
      shcoind_info(unet_mode_label(mode), buf);

      /* only non-local IP address permitted. */
      shnet_close(cli_fd);
      return (SHERR_NOTUNIQ);
    }
  }

  unet_add(mode, cli_fd);

  {
    unet_table_t *t = get_unet_table(cli_fd);
    if (t) {
      t->flag |= UNETF_INBOUND; 
    }
  }

  if (bind->op_accept) {
    (*bind->op_accept)(cli_fd, shaddr(cli_fd));
  }

  if (sk_p)
    *sk_p = cli_fd;

  return (0);
}

