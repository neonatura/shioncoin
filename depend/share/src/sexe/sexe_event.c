
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

shkey_t *sexe_event_key(char *e_name)
{
	/* key does not need to be free'd */
	return (ashkey_str(e_name));
}

unsigned int sexe_event_next_id(void)
{
	static int ef_nr;
	return (++ef_nr);
}

void sexe_event_register(lua_State *L, char *e_name, lua_CFunction f)
{
	unsigned int ef_nr = sexe_event_next_id();
	shkey_t *key = sexe_event_key(e_name);
	char *ptr = shkey_hex(key);

	/* _EVENT table */
	lua_getglobal(L, EVENT_ENV);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		/* _EVENT */
		lua_createtable(L, 0, 1);
	}

	/* _EVENT[<id>] */
	lua_pushstring(L, ptr);
	lua_getfield(L, -2, ptr);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		lua_newtable(L);
	}

	/* event callback function */
	lua_pushnumber(L, ef_nr);
	lua_pushcfunction(L, f);
	lua_settable(L, -3);

	/* set _ENV['_EVENT'][<id>] */
	lua_settable(L, -3);

	/* set _ENV['_EVENT'] */
	lua_setglobal(L, EVENT_ENV);

}

int sexe_event_handle(lua_State *L, char *e_name, shjson_t *json)
{
	shkey_t *key = sexe_event_key(e_name);
	char *e_hex = shkey_hex(key);
  int t_reg = 0;
	int err;
	int ret;

	lua_getglobal(L, EVENT_ENV);
	if (lua_isnil(L, -1))
		return (0); /* error */
	lua_getfield(L, -1, e_hex);
	if (lua_isnil(L, -1))
		return (0); /* error */

	/* iterate through registered functions for event */
	err = SHERR_NOENT;
	lua_pushnil(L);
	while (lua_next(L, -2)) {
		int t = lua_type(L, -1);
		if (t == LUA_TFUNCTION) {
			/* copy function call onto stack  lua_pushvalue(L, 1); */
			/* 1. user args */
			if (json)
				sexe_table_set(L, json);
			else
				lua_pushnil(L);
			/* 2. event name */
			lua_pushstring(L, e_name);
			/* exec */
			if ((ret=lua_pcall(L, 2, 1, 0)) == LUA_OK) {
				int result = lua_toboolean(L, -1);  /* get result */
				if (result)
					err = 0;
				else if (err != 0)
					err = SHERR_INVAL;
				lua_pop(L, 1); /* value */
			} else {
				int status = ret;

				err = SHERR_ILSEQ;
//fprintf(stderr, "DEBUG: lua_pcall !ok: lua_pcall() ret %d\n", ret);

//				luaL_error(L, "error sexe_event_handle method (%s)", "<event>");

				break;
			}
		} else {
			lua_pop(L, 1); /* value */
		}
	}

	return (err);
}


