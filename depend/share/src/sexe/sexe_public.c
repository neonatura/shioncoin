
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

#include "sexe.h"
#include <string.h>





int install_sexe_public_data(sexe_t *S, char *tag)
{
  SHFL *fl;
  shjson_t *udata;
  shfs_t *fs;
  shbuf_t *buff;
  shkey_t *k;
  char path[PATH_MAX+1];
	char buf[256];
  int is_new;

	memset(buf, 0, sizeof(buf));
	strncpy(buf, basename(tag), sizeof(buf)-1); 

#if 0
	if (0 != strcasecmp(buf + strlen(buf) - 3, ".sx")) {
		/* only record userdata for compiled programs. */
		return (0);
	}
#endif

  k = shkey_str(buf);
  sprintf(path, "/sys/data/sexe/%s", shkey_hex(k)); 
  memcpy(&S->pname, k, sizeof(S->pname));
  shkey_free(&k);

  buff = shbuf_init();
  fs = shfs_init(NULL);
  fl = shfs_file_find(fs, path);
  is_new = shfs_read(fl, buff);

  udata = shjson_init(shbuf_size(buff) ? (char *)shbuf_data(buff) : NULL);
  shbuf_free(&buff);

  if (is_new)
    shjson_num_add(udata, "birth", shtimef(shtime()));

  sexe_table_set(S, udata);
  lua_setglobal(S, PUBLIC_ENV);
  shjson_free(&udata);

  shfs_free(&fs);

  return (0);
}

/* copy env vars into public table */
void sexe_public_update(sexe_t *L)
{
	char f_name[1024];

  lua_getglobal(L, PUBLIC_ENV);

  lua_pushnil(L);
  while (lua_next(L, -2)) {
		//lua_pop(L, 1);
		memset(f_name, 0, sizeof(f_name));
    strncpy(f_name, lua_tostring(L, -2), sizeof(f_name)-1);
		lua_pop(L, 1);

		/* find public var in environment */
		lua_getglobal(L, f_name);
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			continue; /* var is not set */
		}

		lua_settable(L, -3);
		lua_pushstring(L, f_name);
	}

}

shjson_t *sexe_public_json(sexe_t *S)
{

  lua_getglobal(S, PUBLIC_ENV);
  return (sexe_table_get(S));
}

int update_sexe_public_data(sexe_t *S)
{
  SHFL *fl;
  shjson_t *udata;
  shfs_t *fs;
  shbuf_t *buff;
  shkey_t *k;
  char path[PATH_MAX+1];
  char *str;
  int err;


  k = &S->pname;
  if (shkey_cmp(k, ashkey_blank())) {
    return (0); /* blank */
  }

	/* fill '_PUBLIC' table with '_ENV' counter-parts. */
	sexe_public_update(S);

  udata = sexe_public_json(S);
  if (!udata) {
    return (SHERR_INVAL);
  }

  str = shjson_print(udata);
  if (!str) {
    return (SHERR_INVAL);
}
  shjson_free(&udata);

  buff = shbuf_init();
  shbuf_catstr(buff, str);
  free(str);

  fs = shfs_init(NULL);
  sprintf(path, "/sys/data/sexe/%s", shkey_hex(k)); 
  fl = shfs_file_find(fs, path);
  err = shfs_write(fl, buff);
  shbuf_free(&buff);
  shfs_free(&fs);

  return (err);
}

