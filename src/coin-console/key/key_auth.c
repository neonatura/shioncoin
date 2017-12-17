
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

const char *key_auth_hex(shkey_t *auth_key)
{
  static char ret_str[256];

  memset(ret_str, 0, sizeof(ret_str));
  shsha_hex(SHALG_SHA256, ret_str,
      (unsigned char *)auth_key, sizeof(shkey_t)); 

  return ((const char *)ret_str);
}

unsigned int key_auth_pin(shkey_t *auth_key)
{
  return (shsha_2fa_bin(SHALG_SHA256, (unsigned char *)auth_key, sizeof(shkey_t), RPC_AUTH_FREQ));
}

int key_auth_append(shjson_t *j)
{
  shkey_t *key;

  key = key_dat_pass(NULL);
  if (!key)
    return (SHERR_NOENT);

  shjson_str_add(j, "auth_hash", (char *)key_auth_hex(key));
  shjson_num_add(j, "auth_pin", key_auth_pin(key));

  return (0);
}


