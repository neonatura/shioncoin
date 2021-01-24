/*
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
*/  

#include "share.h"

/**
 * A typical size supported by most operating systems.
 */
#define MIN_READ_BUFFER_SIZE 65536
#define MAX_READ_BUFFER_SIZE 262144

static unsigned char _read_buff[MAX_READ_BUFFER_SIZE];

ssize_t shnet_read(int fd, const void *buf, size_t count)
{
  unsigned int usk = (unsigned int)fd;
  struct timeval to;
  size_t max_r_len;
  ssize_t r_len;
  size_t len;
  fd_set read_set;
  fd_set exc_set;
  char tbuf[8];
  int err;

  if (_sk_table[usk].fd == 0)
    return (SHERR_BADF);

  if (count == 0) {
    buf = NULL;
    count = 65536;
  }
  count = MIN(MAX_READ_BUFFER_SIZE, count);

  if (!_sk_table[usk].recv_buff)
    _sk_table[usk].recv_buff = shbuf_init();

  if (!(_sk_table[usk].flags & SHNET_ASYNC)) {
    FD_ZERO(&read_set);
    FD_SET(fd, &read_set);
    FD_ZERO(&exc_set);
    FD_SET(fd, &exc_set);

    /* block for data */
    err = select(fd+1, &read_set, NULL, &exc_set, NULL);
    if (err == -1) 
      return (errno2sherr());
  } 

  /* data available for read. */
  memset(_read_buff, 0, sizeof(_read_buff));
  r_len = read(fd, _read_buff, count);
  if (r_len == 0) {
#if 0
    if (shbuf_size(_sk_table[usk].recv_buff) == 0)
#endif
      return (SHERR_CONNRESET);
  } else if (r_len < 1) {
    return (errno2sherr());
  } else {
    /* append to internal buffer */
    shbuf_cat(_sk_table[usk].recv_buff, _read_buff, r_len);
  }

  if (buf) {
    /* extract head */
    r_len = MIN(count, shbuf_size(_sk_table[usk].recv_buff));
    if (r_len != 0) {
      memcpy((char *)buf, (char *)shbuf_data(_sk_table[usk].recv_buff), r_len);
      shbuf_trim(_sk_table[usk].recv_buff, r_len);
    }
  }

  return (r_len);
}

shbuf_t *shnet_read_buf(int fd)
{
  unsigned int usk = (unsigned int)fd;
  int err;

  if (!(_sk_table[usk].flags & SHNET_ASYNC)) {
    /* read() would hang due to no user-supplied size specification */
    return (NULL); /* SHERR_OPNOTSUPP */
  }

  err = shnet_read(fd, NULL, MIN_READ_BUFFER_SIZE);
  if (err < 0 && err != SHERR_AGAIN) {
    if (err != SHERR_CONNRESET)
      PRINT_ERROR(err, "shnet_read_buf");
    if ((shbuf_size(_sk_table[usk].recv_buff) == 0) &&
        (shbuf_size(_sk_table[usk].proc_buff) == 0)) {
      /* no pending data to process */
      return (NULL);
    }
  }

  return (_sk_table[usk].recv_buff);
}

