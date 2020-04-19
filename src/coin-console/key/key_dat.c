
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
 *
 *  This file is part of ShionCoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcon.h"

const char *get_shioncoin_path(void)
{
	static char ret_path[PATH_MAX+1];

	if (!*ret_path) {
#ifdef WINDOWS
		char *str;

		str = getenv("ProgramData");
		if (!str)
			str = "C:\\ProgramData";

		sprintf(ret_path, "%s\\shioncoin\\", str);
		mkdir(ret_path, 0777);
#else
		strcpy(ret_path, "/var/lib/shioncoin/");
		mkdir(ret_path, 0777);
#endif
	}

	return (ret_path);
}

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

	/* may be over-written by command-line argument. */
	key_str = opt_str(OPT_PASS);
	if (key_str && *key_str) {
		key = shkey_hexgen(key_str);
		if (key)
			return (key);
	}

  if (!host) {
		host = opt_str(OPT_HOSTNAME);
		if (!host || !*host || 0 == strcmp(host, "*"))
			host = "127.0.0.1";
	}

  sprintf(path, "%sblockchain/rpc.dat", get_shioncoin_path());
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

