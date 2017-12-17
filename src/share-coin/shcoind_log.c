
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

#include "shcoind.h"


void f_shcoind_log(int err_code, const char *tag, const char *text, const char *src_fname, long src_line)
{
  static shbuf_t *buff;
  char fname[PATH_MAX+1];
  char origin[256];
  char *date_str;
  char buf[256];
  size_t len;

  if (!err_code && !opt_num(OPT_DEBUG)) {
    return;
  }

  if (!buff)
    buff = shbuf_init();

  if (tag) {
    shbuf_catstr(buff, (char *)tag);
    shbuf_catstr(buff, ": ");
  }
  if (text) {
    len = strlen(text);
    if (*text && text[strlen(text)-1] == '\n')
      len--;
    shbuf_cat(buff, text, len);
  }
  if (src_fname && src_line) {
    char *ptr = strrchr(src_fname, '/');
    if (!ptr)
      strncpy(fname, src_fname, sizeof(fname)-1);
    else
      strncpy(fname, ptr+1, sizeof(fname)-1);

    sprintf(origin, " (%s:%ld)", fname, src_line);
    shbuf_catstr(buff, origin);
  }

  if (err_code && err_code != SHERR_INFO) {
    shlog(SHLOG_ERROR, err_code, shbuf_data(buff));
  } else {
    shlog(SHLOG_INFO, 0, shbuf_data(buff));
  }

  shbuf_clear(buff);
}


void timing_init(char *tag, shtime_t *stamp_p)
{
  
  *stamp_p = shtime();

}

void timing_term(int ifaceIndex, char *tag, shtime_t *stamp_p)
{
  shtime_t stamp = *stamp_p;
  double diff = shtime_diff(stamp, shtime());
  char buf[1024];

  if (diff > 0.2) { /* 200ms */
    sprintf(buf, "TIMING[%s]: total %-2.2f seconds.", tag, diff);
    if (!ifaceIndex)
      shcoind_log(buf);
    else
      unet_log(ifaceIndex, buf);
  }

}


