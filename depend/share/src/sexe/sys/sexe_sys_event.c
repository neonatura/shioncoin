
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


//extern shjson_t *sexe_table_get(lua_State *L);


/**
 * The "os.register(<string>,<function>)" function will register a callback function for the event name specified.
 */
int _lfunc_register_event(sexe_t *L)
{
	const char *e_name;
	int ef_nr;
	shkey_t *key;
	char *ptr;

	e_name = luaL_checkstring(L, 1);
	ef_nr = sexe_event_next_id();
	key = sexe_event_key(e_name);
	ptr = shkey_hex(key);

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
	lua_pushvalue(L, 2);
	lua_settable(L, -3);

	/* set _ENV['_EVENT'][<id>] */
	lua_settable(L, -3);

	/* set _ENV['_EVENT'] */
	lua_setglobal(L, EVENT_ENV);

	return (0);
}

/**
 * The "os.trigger(<string>[,<table>])" function will trigger all callbacks for the specifid event name to be called with an optional object argument.
 */
int lfunc_trigger_event(sexe_t *L)
{
	const char *e_name;
	shjson_t *json;
	int t_reg = 0;
	int ret_bool;
	int err;

	/* first argument: event name */
	e_name = luaL_checkstring(L, 1);

	/* second optional arg; table of data. */
	json = NULL;
	if (lua_istable(L, 2)) {
		lua_pushvalue(L, 2);
		json = sexe_table_get(L);
	}

	ret_bool = 1; 
	err = sexe_event_handle(L, e_name, json);
	if (err)
		ret_bool = 0;

#if 0

	/* iterate through registered functions for event */
	{
		shkey_t *key = sexe_event_key(e_name);
		char *e_hex = shkey_hex(key);
		lua_getglobal(L, EVENT_ENV);
		if (lua_isnil(L, -1)) {
			return (0); /* error */
		}
		lua_getfield(L, -1, e_hex);
		if (lua_isnil(L, -1)) {
			return (0); /* error */
		}

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
				lua_pcall(L, 2, 0, 0); 
			} else {
				lua_pop(L, 1); /* value */
			}

			//lua_pop(L, 1); /* key */
		}
	}
#endif

	if (json)
		shjson_free(&json);

	/* return single boolean */
	lua_pushboolean(L, ret_bool);
	return (1);
}

/**
 * The "os.unregister(<string>,<function>)" function will unregister a callback function for the event name specified.
 */
int _lfunc_unregister_event(sexe_t *L)
{
  const char *e_name;
  int err;

	e_name = luaL_checkstring(L, 1);

#if 0
/* todo: only remove event func, and whole event if last func */
  err = sexe_event_remove(L, e_name);
  if (err)
    return (err);
#endif

  return (0);
}



static const luaL_Reg sexe_event_lib[] = {
	{ "register", _lfunc_register_event },

	{ "trigger", lfunc_trigger_event },

	{ "unregister", _lfunc_unregister_event },

	{ NULL, NULL }
};


/**
 * The "os" library provides runtime level functionality such as event handling and timers.
 */
LUAMOD_API int luaopen_event(sexe_t *L) 
{
  luaL_newlib(L, sexe_event_lib);

	return 1;
}





