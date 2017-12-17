
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

#include "shcon.h"


int net_write_lim(int sk, shbuf_t *buff, double wait)
{
  struct timeval tv;
  fd_set write_set;
  fd_set exc_set;
  int err;

#ifndef WIN32
  FD_ZERO(&write_set);
  FD_SET(sk, &write_set);
  FD_SET(sk, &exc_set);

  memset(&tv, 0, sizeof(tv));
  tv.tv_sec = (time_t)wait;
  tv.tv_usec = (wait - (double)tv.tv_sec) * 1000000;
  err = shselect(sk + 1, NULL, &write_set, &exc_set, &tv);
  if (err < 0)
    return (-errno);
  if (err == 0)
    return (SHERR_AGAIN);
  if (FD_ISSET(sk, &exc_set))
    return (SHERR_CONNRESET);
#endif

  err = shwrite(sk, shbuf_data(buff), shbuf_size(buff));
  if (err < 0)
    return (-errno);

  shbuf_trim(buff, err);
  return (0);
}

int net_write(int sk, shbuf_t *buff)
{
  static double span = (double)DEFAULT_COMMAND_WAIT;
  return (net_write_lim(sk, buff, span));
}


