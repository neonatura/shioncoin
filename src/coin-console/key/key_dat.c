
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

shkey_t *key_dat_pass(char *host)
{
  shkey_t *key;
  shbuf_t *buff;
  char *tok_ctx;
  char path[PATH_MAX+1];
  char *raw;
  char *key_str;
  char *tok;
  int err;

  if (!host)
    host = "127.0.0.1";

  sprintf(path, "%s/blockchain/rpc.dat", get_libshare_path());
  chmod(path, 00400);

  buff = shbuf_init();
  err = shfs_mem_read(path, buff);
  if (!err) {
    raw = shbuf_data(buff);
    tok = strtok_r(raw, "\r\n", &tok_ctx);
    while (tok) {
      key_str = strchr(tok, ' ');
      if (key_str) {
        *key_str = '\000';
        key_str++;

#if 0
        if (0 == strcmp(host, "127.0.0.1") &&
            unet_local_verify(tok)) {
          key = shkey_gen(key_str);
          shbuf_free(&buff);
          return (key);
        }
#endif

        if (0 == strcasecmp(host, tok)) {
          key = shkey_gen(key_str);
          shbuf_free(&buff);
          return (key);
        }
      }

      tok = strtok_r(NULL, "\r\n", &tok_ctx);
    }
  }

  shbuf_free(&buff);
  return (NULL);
}


