
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

static FILE *_shcon_log_fout;

const char *shcon_log_timestamp(void)
{
  static char ret_buf[256];
  time_t now;

  now = time(NULL);
  memset(ret_buf, 0, sizeof(ret_buf));
  (void)strftime(ret_buf, sizeof(ret_buf)-1, "[%x %T] ", localtime(&now));

  return (ret_buf);
}

int shcon_log_init(void)
{
  char *str;

  if (opt_bool(OPT_QUIET)) {
    _shcon_log_fout = NULL;
    return (0);
  }

  str = opt_str(OPT_OUTPUT);
  if (str && *str) {
    _shcon_log_fout = fopen(str, "wb");
    if (!_shcon_log_fout)
      return (-errno);
    return (0);
  }
  
  /* default is to standard console output */
  _shcon_log_fout = stdout;
  return (0);
}

int shcon_log(int err_code, const char *format, ...)
{
  va_list ap;
  char *text;
  int err;

  if (!_shcon_log_fout)
    return (0); /* done */

  text = NULL;
  va_start(ap, format);
  (void)vasprintf(&text, format, ap);
  va_end(ap);
  if (!text)
    return (SHERR_INVAL);

  fprintf(_shcon_log_fout, shcon_log_timestamp());
  fprintf(_shcon_log_fout, "%s", text);
  if (err_code)
    fprintf(_shcon_log_fout, ": %s (err %d)", sherrstr(err_code), err_code);
  fprintf(_shcon_log_fout, "\n");
  fflush(_shcon_log_fout);

  free(text);
  return (0);
}

int shcon_info(const char *format, ...)
{
  va_list ap;
  char *text;
  int err;

  text = NULL;
  va_start(ap, format);
  (void)vasprintf(&text, format, ap);
  va_end(ap);
  if (!text)
    return (SHERR_INVAL);

  fprintf(_shcon_log_fout, shcon_log_timestamp());
  fprintf(_shcon_log_fout, "info: %s\n", text);

  free(text);
  return (0);
}



