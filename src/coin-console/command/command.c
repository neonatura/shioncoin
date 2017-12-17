
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

static int is_numeric_string(char *str)
{
  size_t len = strlen(str);
  size_t i;
  int c_dash;
  int c_dot;

  if (len > 20)
    return (FALSE);

  c_dash = c_dot = 0;
  for (i = 0; i < len; i++) {
    if (!isdigit(str[i]) && str[i] != '-' && str[i] != '.')
      return (FALSE);
    if (str[i] == '-') c_dash++;
    if (str[i] == '.') c_dot++;
  }
  if (c_dash > 1 || c_dot > 1)
    return (FALSE); /* not a number format */

  return (TRUE);
}

int shcon_command_send(char **args, int arg_nr)
{
  shjson_t *param;
  shjson_t *j;
  char *mode;
  int err;
  int i;

  if (arg_nr < 1)
    return (SHERR_INVAL);

  mode = args[0];

  j = shjson_init(NULL);
  if (!j)
    return (SHERR_NOMEM);

  /* attributes */
  shjson_str_add(j, "iface", opt_iface()); 
  shjson_num_add(j, "stamp", time(NULL));
  key_auth_append(j);

  /* command */
  shjson_str_add(j, "method", mode); 

  param = shjson_array_add(j, "params");
  for (i = 1; i < arg_nr; i++) {
    if (is_numeric_string(args[i])) {
      shjson_num_add(param, NULL, atof(args[i]));
    } else {
      shjson_str_add(param, NULL, args[i]);
    }
  }

  err = net_json_send(j);
  if (err)
    return (err);

  shjson_free(&j);
  return (0);
}

int shcon_command_recv(shjson_t **resp_p)
{
  return (net_json_recv(resp_p));
}

int shcon_command(char **args, int arg_nr, shjson_t **resp_p)
{
  int err;

  err = shcon_command_send(args, arg_nr);
  if (err)
    return (err);

  err = shcon_command_recv(resp_p);
  if (err)
    return (err);

  return (0);
} 


