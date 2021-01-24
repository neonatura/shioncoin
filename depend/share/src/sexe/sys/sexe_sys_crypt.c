
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



static int _lfunc_sexe_crypt_key(sexe_t *L) 
{
  shkey_t *key;
  char *seed;
  int seed_num;

  seed = luaL_checkstring(L, 1);
  if (!seed)
    seed_num = luaL_checknumber(L, 1);

  if (seed)
    key = shkey_str(seed);
  else
    key = shkey_num(seed_num);

  lua_pushstring(L, shkey_print(key));

  shkey_free(&key);
  return (1); /* (1) string key */
}


static int _lfunc_sexe_crypt_encrypt(sexe_t *L)
{
  const char *raw_str = luaL_checkstring(L, 1);
  const char *key_str = luaL_checkstring(L, 2);
  unsigned char *data;
  size_t data_len;
  shkey_t *key;
  int err;

  if (!raw_str)
    raw_str = "";

  key = shkey_gen(key_str);  
  err = shencode(raw_str, strlen(raw_str), &data, &data_len, key);
  shkey_free(&key);
  if (err) {
    lua_pushnil(L);
    return (1); /* (1) nil */
  }

  lua_pushlstring(L, data, data_len);
  free(data);
  return (1); /* (1) encoded string */ 
}

static int _lfunc_sexe_crypt_decrypt(sexe_t *L)
{
  const char *enc_str;
  const char *key_str;
  shkey_t *key;
  size_t data_len;
	size_t enc_len;
  char *data;
  int err;

	enc_len = 0;
  enc_str = luaL_checklstring(L, 1, &enc_len);
  key_str = luaL_checkstring(L, 2);

  if (enc_len == 0)
    enc_str = "";

  key = shkey_gen(key_str);  
  err = shdecode(enc_str, enc_len, &data, &data_len, key);
  shkey_free(&key);
  if (err) {
    lua_pushnil(L);
    return (1); /* (1) nil */
  }

  lua_pushstring(L, data);
  free(data);
  return (1); /* (1) encoded string */ 
}

static int _lfunc_sexe_crypt_crc32(sexe_t *L)
{
  const char *data = luaL_checkstring(L, 1);
  uint32_t seed = 0;
  uint32_t val;

  val = shcsum_crc32(seed, data, strlen(data));
  lua_pushnumber(L, val);

  return 1; /* 'crc32' */
}

static int _lfunc_sexe_crypt_sha2(sexe_t *L)
{
	char ret_buf[256];
  const char *data;
	size_t data_len;
  uint32_t seed = 0;
  uint32_t val;

	memset(ret_buf, 0, sizeof(ret_buf));
	if (lua_istable(L, 1)) {
		shjson_t *json = sexe_table_get(L); 
		char *text = shjson_print(json);
		if (text)
			(void)shsha_hex(SHALG_SHA256, ret_buf, text, strlen(text));
		free(text);
		shjson_free(&json);
	} else {
		/* obtain parameter */
		data = luaL_checklstring(L, 1, &data_len);

		/* digest string */
		(void)shsha_hex(SHALG_SHA256, ret_buf, data, data_len);
	}

	/* push back return hex */
  lua_pushstring(L, ret_buf);

  return 1; /* 'sha2' */
}

static const luaL_Reg sexe_crypt_lib[] = {
	{"key", _lfunc_sexe_crypt_key },
  {"encrypt", _lfunc_sexe_crypt_encrypt },
  {"decrypt", _lfunc_sexe_crypt_decrypt },
  {"crc", _lfunc_sexe_crypt_crc32 },
  {"sha2", _lfunc_sexe_crypt_sha2 },
	{ NULL, NULL }
};

LUAMOD_API int luaopen_crypt(sexe_t *L) 
{
  luaL_newlib(L, sexe_crypt_lib);
	return 1;
}

