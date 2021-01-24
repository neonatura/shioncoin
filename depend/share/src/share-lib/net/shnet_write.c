
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura
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
 *
 */

#include "share.h"

ssize_t shnet_write(int fd, const void *buf, size_t count)
{
  ssize_t w_len;

  w_len = write(fd, buf, count);
  if (w_len < 0) {
    return (errno2sherr());
  }
  
  return (w_len);
}
#if 0
  unsigned int usk = (unsigned int)fd;
  ssize_t w_len;
  size_t len;

  if (usk >= USHORT_MAX)
    return (0);

  if (!_sk_table[usk].send_buff && count < 4096)
    return (write(fd, buf, count));

  if (!_sk_table[usk].send_buff)
    _sk_table[usk].send_buff = shbuf_init();

  if (buf && count)
    shbuf_cat(_sk_table[usk].send_buff, (char *)buf, count);

  if (_sk_table[usk].send_buff->data_of == 0)
    return (0);

  w_len = write(fd, _sk_table[usk].send_buff->data, _sk_table[usk].send_buff->data_of);
  if (w_len >= 1) {
    shbuf_trim(_sk_table[usk].send_buff, w_len);
  }

  /* return bytes read into buffer. */
  return (count);
#endif

/**
 * @returns 0 upon success
 */
int shnet_write_buf(int fd, unsigned char *data, size_t data_len)
{
  unsigned int usk = (unsigned int)fd;
  fd_set w_set;
  struct timeval to;
  shbuf_t *buff;
  ssize_t b_len;
  int err;

  if (!_sk_table[usk].send_buff)
    _sk_table[usk].send_buff = shbuf_init();

  buff = _sk_table[usk].send_buff;
  if (!buff)
    return (SHERR_IO);

  /* append new data */
  if (data && data_len) {
    shbuf_cat(buff, data, data_len);
  }

  /* determine whether data may be written */
  FD_ZERO(&w_set);
  FD_SET(fd, &w_set);
  memset(&to, 0, sizeof(to));
  err = shselect(fd+1, NULL, &w_set, NULL, &to);
  if (err < 1)
    return (err);

  b_len = shnet_write(fd, shbuf_data(buff), shbuf_size(buff)); 
  if (b_len <= 0) {
    return (b_len);
  }

  shbuf_trim(buff, b_len);
  return (0);
}

int shnet_write_flush(int fd)
{
  unsigned int usk = (unsigned int)fd;
  fd_set w_set;
  struct timeval to;
  shbuf_t *buff;
  ssize_t b_len;
  int err;

  buff = _sk_table[usk].send_buff;
  if (!buff)
    return (0);

  while (shbuf_size(buff) != 0) {
    /* 3min timeout */
    FD_ZERO(&w_set);
    FD_SET(fd, &w_set);
    memset(&to, 0, sizeof(to));
    to.tv_sec = 180;
    err = shselect(fd+1, NULL, &w_set, NULL, &to);
    if (err < 1)
      return (err);

    b_len = shnet_write(fd, shbuf_data(buff), shbuf_size(buff)); 
    if (b_len <= 0)
      return (b_len);

    shbuf_trim(buff, b_len);
  }

  return (0);
}



