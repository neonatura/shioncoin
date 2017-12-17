
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

static shmap_t *_shcon_option_table;
#define OPT_LIST _shcon_option_table

int shcon_opt_init(void)
{

  OPT_LIST = shmap_init();
  if (!OPT_LIST)
    return (SHERR_NOMEM);

  return (0);
}

void shcon_opt_term(void)
{

  if (!OPT_LIST)
    return;

  shmap_free(&OPT_LIST);
  OPT_LIST = NULL;
}

const char *opt_str(char *opt_name)
{
  static char blank_str[16];
  const char *ret_str;

  ret_str = (const char *)shmap_get_str(OPT_LIST, ashkey_str(opt_name)); 
  if (!ret_str)
    return (blank_str);

  return (ret_str);
}

int opt_num(char *opt_name)
{
  return (atoi(opt_str(opt_name)));
}


double opt_fnum(char *opt_name)
{
  return (atof(opt_str(opt_name)));
}

int opt_bool(char *opt_name)
{
  return (opt_num(opt_name) ? TRUE : FALSE);
}

void opt_str_set(char *opt_name, char *opt_value)
{
  shmap_set_astr(OPT_LIST, ashkey_str(opt_name), opt_value);
}

void opt_num_set(char *opt_name, int num)
{
  char buf[64];

  memset(buf, 0, sizeof(buf));
  sprintf(buf, "%d", num);
  opt_str_set(opt_name, buf);
}

void opt_fnum_set(char *opt_name, double num)
{
  char buf[64];

  memset(buf, 0, sizeof(buf));
  sprintf(buf, "%f", num);
  opt_str_set(opt_name, buf);
}

void opt_bool_set(char *opt_name, int b)
{
  opt_num_set(opt_name, b ? TRUE : FALSE);
}

const char *opt_iface(void)
{
  return (opt_str(OPT_IFACE));
}

