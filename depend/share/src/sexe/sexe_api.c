
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

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include "sexe.h"

static lua_State *globalL;

#if !defined(LUA_INIT)
#define LUA_INIT		"LUA_INIT"
#endif
#define LUA_INITVERSION  \
	LUA_INIT "_" LUA_VERSION_MAJOR "_" LUA_VERSION_MINOR

static void _api_l_message (const char *pname, const char *msg) 
{
  if (pname) luai_writestringerror("%s: ", pname);
  luai_writestringerror("%s\n", msg);
}
static int _api_report (lua_State *L, int status) 
{
  if (status != LUA_OK && !lua_isnil(L, -1)) {
    const char *msg = lua_tostring(L, -1);
    if (msg == NULL) msg = "(error object is not a string)";
    _api_l_message("SEXE", msg);
    lua_pop(L, 1);
    /* force a complete garbage collection in case of errors */
    lua_gc(L, LUA_GCCOLLECT, 0);
  }
  return status;
}
static int _api_traceback (lua_State *L) 
{
  const char *msg = lua_tostring(L, 1);
  if (msg)
    luaL_traceback(L, L, msg, 1);
  else if (!lua_isnoneornil(L, 1)) {  /* is there an error object? */
    if (!luaL_callmeta(L, 1, "__tostring"))  /* try its 'tostring' metamethod */
      lua_pushliteral(L, "(no error message)");
  }
  return 1;
}
#if 0
static void _api_lstop (lua_State *L, lua_Debug *ar) {
  (void)ar;  /* unused arg. */
  lua_sethook(L, NULL, 0, 0);
  luaL_error(L, "interrupted!");
}
static void _api_laction (int i) {
  signal(i, SIG_DFL); /* if another SIGINT happens before lstop,
                              terminate process (default action) */
  lua_sethook(globalL, _api_lstop, LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT, 1);
}
#endif
static int _api_docall (lua_State *L, int narg, int nres) {
  int status;
  int base = lua_gettop(L) - narg;  /* function index */
  lua_pushcfunction(L, _api_traceback);  /* push traceback function */
  lua_insert(L, base);  /* put it under chunk and args */
  globalL = L;  /* to be available to 'laction' */
//  signal(SIGINT, _api_laction);
  status = lua_pcall(L, narg, nres, base);
//  signal(SIGINT, SIG_DFL);
  lua_remove(L, base);  /* remove traceback function */
  return status;
}
static int _api_dostring (lua_State *L, const char *s, const char *name) {
  int status = luaL_loadbuffer(L, s, strlen(s), name);
  if (status == LUA_OK) status = _api_docall(L, 0, 0);
  return _api_report(L, status);
}
static int _api_dofile (lua_State *L, const char *name) {
  int status = luaL_loadfile(L, name);
  if (status == LUA_OK) status = _api_docall(L, 0, 0);
  return _api_report(L, status);
}
static int _api_handle_luainit (lua_State *L) 
{
  const char *name = "=" LUA_INITVERSION;
  const char *init = getenv(name + 1);
  if (init == NULL) {
    name = "=" LUA_INIT;
    init = getenv(name + 1);  /* try alternative name */
  }
  if (init == NULL) return LUA_OK;
  else if (init[0] == '@')
    return _api_dofile(L, init+1);
  else
    return _api_dostring(L, init, name);
}

static int _api_getargs(lua_State *L, char **argv, int n) {
  int narg;
  int i;
  int argc = 0;
  while (argv[argc]) argc++;  /* count total number of arguments */
  narg = argc - (n + 1);  /* number of arguments to the script */
  luaL_checkstack(L, narg + 3, "too many arguments to script");
  for (i=n+1; i < argc; i++)
    lua_pushstring(L, argv[i]);
  lua_createtable(L, narg, n + 1);
  for (i=0; i < argc; i++) {
    lua_pushstring(L, argv[i]);
    lua_rawseti(L, -2, i - n);
  }
  return narg;
}
static int _api_push_args(lua_State *L, char **argv, int n)
{
  int narg = _api_getargs(L, argv, n); 
  lua_setglobal(L, "arg");
  return (narg);
}
#if 0
static void _api_push_json(lua_State *L, shjson_t *arg)
{
  sexe_table_set(L, arg);
  lua_setglobal(L, "arg");
}
#endif

#if 0
int sexe_execv(char *path, char **argv)
{
  lua_State *L = luaL_newstate();
  int status;
  int argc;
  int narg;
  int err;

  argc = 0;
  while (argv[argc]) argc++;

  /* open standard libraries */
  luaL_checkversion(L);
  lua_gc(L, LUA_GCSTOP, 0);  /* stop collector during initialization */
  luaL_openlibs(L);  /* open libraries */
  lua_gc(L, LUA_GCRESTART, 0);

  //if (!args[has_E] && handle_luainit(L) != LUA_OK)
  err = _api_handle_luainit(L);
  if (err) {
    lua_close(L);
    return (err);
  }

#if 0
  install_sexe_public_data(L, argv[0]);
#endif

  narg = _api_push_args(L, argv, 0);

  status = sexe_loadfile(L, path, NULL);
  lua_insert(L, -(narg+1));
  if (status == LUA_OK) {
    status = _api_docall(L, narg, LUA_MULTRET);
#if 0
		update_sexe_public_data(L);
#endif

		/* call "InitEvent" event */
		lua_pushcfunction(L, lfunc_trigger_event);
		lua_pushstring(L, "InitEvent");
		lua_pushnil(L);
		lua_pcall(L, 2, 1, 0);
		lua_pop(L, 1);

		/* call "RunEvent" event */
		lua_pushcfunction(L, lfunc_trigger_event);
		lua_pushstring(L, "RunEvent");
		lua_pushnil(L);
		lua_pcall(L, 2, 1, 0);
		lua_pop(L, 1);

  } else {
    lua_pop(L, narg);
  }

  status = _api_report(L, status);
  lua_close(L);

  return (status);
}
int sexe_execve(char *path, char **argv, char *const envp[])
{
  return (sexe_execv(path, argv));
}
#endif

int sexe_pset(sexe_t *S, char *name, shjson_t *arg)
{
  sexe_table_set(S, arg);
  lua_setglobal(S, name);
	return (0);
}

int sexe_pget(sexe_t *S, char *name, shjson_t **arg_p)
{
  shjson_t *json;

  lua_getglobal(S, name);
  json = sexe_table_get(S); 
  if (!json)
    return (SHERR_INVAL);

  *arg_p = json;
  return (0);
}

int sexe_pgetdef(sexe_t *S, char *name, shjson_t **arg_p)
{
  shjson_t *json;

  lua_getglobal(S, name);
  json = sexe_table_getdef(S); 
  if (!json)
    return (SHERR_INVAL);

  *arg_p = json;
  return (0);
}

#if 0
int sexe_exec_popen(shbuf_t *buff, shjson_t *arg, sexe_t **mod_p)
{
  lua_State *L = luaL_newstate();
  sexe_mod_t *mod;
  int narg = 1;
  int status;
  int err;

  if (!mod_p)
    return (SHERR_INVAL);

  *mod_p = NULL;

  if (shbuf_size(buff) < sizeof(sexe_mod_t))
    return (SHERR_INVAL);

  mod = (sexe_mod_t *)shbuf_data(buff);
  if (0 != memcmp(mod->sig, SEXE_SIGNATURE, sizeof(mod->sig)))
    return (SHERR_ILSEQ);

  /* open standard libraries */
  luaL_checkversion(L);
  lua_gc(L, LUA_GCSTOP, 0);  /* stop collector during initialization */
  luaL_openlibs(L);  /* open libraries */
  lua_gc(L, LUA_GCRESTART, 0);

  //if (!args[has_E] && handle_luainit(L) != LUA_OK)
  err = _api_handle_luainit(L);
  if (err) {
    lua_close(L);
    return (err);
  }

#if 0
  install_sexe_public_data(L, mod->name); /* sexe api lib */
#endif

  if (!arg)
    arg = shjson_init(NULL);

  lua_pushstring(L, "arg");
  sexe_exec_pset(L, "arg", arg);

  status = sexe_loadmem(L, mod->name, buff);
  lua_insert(L, -(narg+1));

  if (status != LUA_OK) {
    lua_pop(L, narg);
    status = _api_report(L, status);
    lua_close(L);

    return (status);
  }

	/* call "InitEvent" event */
	lua_pushcfunction(L, lfunc_trigger_event);
	lua_pushstring(L, "InitEvent");
	lua_pushnil(L);
	lua_pcall(L, 2, 1, 0);
	lua_pop(L, 1);

	/* call "RunEvent" event */
	lua_pushcfunction(L, lfunc_trigger_event);
	lua_pushstring(L, "RunEvent");
	lua_pushnil(L);
	lua_pcall(L, 2, 1, 0);
	lua_pop(L, 1);

  *mod_p = L;

  return (LUA_OK);
}
#endif

#if 0
int sexe_exec_pcall(sexe_t *S, char *func, shjson_t *json)
{
  int err;

  if (!S)
    return (SHERR_INVAL);

 lua_getglobal(S, func); /* push global func ref to stack */
  if (!json) {
    err = lua_pcall(S, 0, 0, 0);
  } else {
    sexe_table_set(S, json);
    err = lua_pcall(S, 1, 0, 0);
  }
  if (err)
    return (err);

  return (0);
}
#endif

#if 0
int sexe_exec_pevent(sexe_t *S, char *e_name, shjson_t *arg)
{
  shjson_t *json;
  int err;

	err = sexe_event_handle(S, e_name, arg);
  if (err)
    return (err);

  return (0);
}
#endif

#if 0
int sexe_exec_prun(sexe_t *S)
{
  int status;
  int narg = 1;

  if (!S)
    return (SHERR_INVAL);

  status = _api_docall(S, narg, LUA_MULTRET);
  status = _api_report(S, status);
  return (status);
}
#endif


#if 0
int sexe_execm(shbuf_t *buff, shjson_t *arg)
{
  lua_State *L = luaL_newstate();
  sexe_mod_t *mod;
  int status;
  int narg;
  int err;

  if (shbuf_size(buff) < sizeof(sexe_mod_t))
    return (SHERR_INVAL);

  mod = (sexe_mod_t *)shbuf_data(buff);
  if (0 != memcmp(mod->sig, SEXE_SIGNATURE, sizeof(mod->sig)))
    return (SHERR_ILSEQ);

  /* open standard libraries */
  luaL_checkversion(L);
  lua_gc(L, LUA_GCSTOP, 0);  /* stop collector during initialization */
  luaL_openlibs(L);  /* open libraries */
  lua_gc(L, LUA_GCRESTART, 0);

  //if (!args[has_E] && handle_luainit(L) != LUA_OK)
  err = _api_handle_luainit(L);
  if (err) {
    lua_close(L);
    return (err);
  }

#if 0
  install_sexe_public_data(L, mod->name);
#endif

  if (!arg)
    arg = shjson_init(NULL);

  //  narg = _api_push_args(L, argv, 0);
  narg = 1;
  lua_pushstring(L, "arg");

  _api_push_json(L, arg);
//  shjson_free(&arg);

  status = sexe_loadmem(L, mod->name, buff);
  lua_insert(L, -(narg+1));
  if (status == LUA_OK) {
    status = _api_docall(L, narg, LUA_MULTRET);
#if 0
    update_sexe_public_data(L);
#endif

		/* call "InitEvent" event */
		lua_pushcfunction(L, lfunc_trigger_event);
		lua_pushstring(L, "InitEvent");
		lua_pushnil(L);
		lua_pcall(L, 2, 1, 0);
		lua_pop(L, 1);

		/* call "RunEvent" event */
		lua_pushcfunction(L, lfunc_trigger_event);
		lua_pushstring(L, "RunEvent");
		lua_pushnil(L);
		lua_pcall(L, 2, 1, 0);
		lua_pop(L, 1);
  } else {
    lua_pop(L, narg);
  }

  status = _api_report(L, status);
  lua_close(L);

  return (status);
}
#endif



#if 0
SEXELIB_API int sexe_loadbuffer(lua_State *S, unsigned char *data, size_t data_len)
{
  int err;

  err = luaL_loadbuffer(S, data, data_len, NULL);

  return (err);
}

SEXELIB_API lua_State *sexe_init(void)
{
  lua_State *S;

  S = (lua_State *)luaL_newstate();
  luaL_openlibs((lua_State *)S);
  install_sexe_functions(S);

  return (S);
}


SEXELIB_API int sexe_load_inode(lua_State *S, SHFL *fl)
{
  unsigned char *data;
  size_t data_len;
  int err;

  err = shfs_file_read(fl, &data, &data_len);
  if (err)
    return (err);

  err = sexe_loadbuffer(S, data, data_len);
  if (data) free(data);
  if (err)
    return (err);

  return (err);
}

SEXELIB_API int sexe_load_stack(lua_State *S, sexe_stack_t *chain, size_t stack_len)
{
  int err;

  err = sexe_loadbuffer(S, chain, stack_len);

  return (err);
}

SEXELIB_API int sexe_call(lua_State *S, int nargs, int nresults, int errfunc)
{
  return (lua_pcall(S, nargs, nresults, errfunc));
} 


SEXELIB_API void sexe_free(lua_State *S)
{
  lua_close(S); 
}


#endif



int sexe_compile_pmain(sexe_t *L)
{
	int argc=(int)lua_tointeger(L,1);
	char** argv=(char**)lua_touserdata(L,2);
	char *out_path = argv[0];
	const Proto* f;

	f = sexe_compile(L, argc, argv);
	if (!f)
		return (LUA_ERRRUN);

	FILE* D = fopen(out_path, "wb");
	if (D==NULL)
		return (LUA_ERRERR);
	lua_lock(L);
	sexe_bin_write(L,f,sexe_compile_writer,D, (run_flags & RUNF_STRIP));
	lua_unlock(L);
	fclose(D);

	return (0);
}



void fatal(const char* message)
{
}





/** Create a process handle from SEXE bytecode file. */
int sexe_popen_file(char *path, sexe_t **mod_p)
{
	shbuf_t *buff;
	int err;

	buff = shbuf_init();
	err = shfs_mem_read(path, buff);
	if (err) {
		shbuf_free(&buff);
		return (err);
	}

	err = sexe_popen(buff, mod_p);
	if (err) {
		shbuf_free(&buff);
		return (err);
	}

	shbuf_free(&buff);
	return (0);
}

/** Create a process handle from SEXE bytecode. */
int sexe_popen(shbuf_t *buff, sexe_t **mod_p)
{
  lua_State *L;
  sexe_mod_t *mod;
  int status;
  int narg;
  int err;

  if (shbuf_size(buff) < sizeof(sexe_mod_t))
    return (SHERR_INVAL);

  mod = (sexe_mod_t *)shbuf_data(buff);
  if (0 != memcmp(mod->sig, SEXE_SIGNATURE, sizeof(mod->sig)))
    return (SHERR_ILSEQ);

	L = luaL_newstate();

  /* open standard libraries */
  luaL_checkversion(L);
  lua_gc(L, LUA_GCSTOP, 0);  /* stop collector during initialization */
  luaL_openlibs(L);  /* open libraries */
  lua_gc(L, LUA_GCRESTART, 0);

  //if (!args[has_E] && handle_luainit(L) != LUA_OK)
  err = _api_handle_luainit(L);
  if (err) {
    lua_close(L);
    return (err);
  }

  err = sexe_loadmem(L, mod->name, buff);
	if (err)
		return (err);

	*mod_p = L;
	return (0);
}

int sexe_prun(sexe_t *L, int argc, char **argv)
{
	int status;
	int i;

	/* "arg" array */
  lua_createtable(L, argc, 0);
	for (i = 0; i < argc; i++)
		lua_pushstring(L, argv[i]);
  lua_setglobal(L, "arg");

 // _api_push_json(L, arg);
//  shjson_free(&arg);
//  lua_insert(L, -(argc+1));

	status = _api_docall(L, argc, LUA_MULTRET);
  status = _api_report(L, status);

  if (status == LUA_OK) {
#if 0
		/* call "InitEvent" event */
		lua_pushcfunction(L, lfunc_trigger_event);
		lua_pushstring(L, "InitEvent");
		lua_pushnil(L);
		lua_pcall(L, 2, 1, 0);
		lua_pop(L, 1);
#endif
  } else {
    lua_pop(L, argc);
  }

  return (status);
}

int sexe_pcall_json(sexe_t *S, char *func, shjson_t *call)
{
	shjson_t *args;
	char *text;
	int ret_cnt;
	int narg;
	int tot;
  int err;
	int i;

  if (!S)
    return (SHERR_INVAL);

	narg = shjson_array_count(call, "argument");
	ret_cnt = (shjson_bool(call, "void", FALSE) ? 0 : 1);

	if (!strchr(func, '.')) {
		lua_getglobal(S, func); /* push global func ref to stack */
	} else {
		char class[256];
		char method[256];

		memset(method, 0, sizeof(method));
		strncpy(method, strchr(func, '.') + 1, sizeof(method)-1);

		memset(class, 0, sizeof(class));
		strncpy(class, func, MIN(sizeof(class)-1, strlen(func)-strlen(method)-1));

		lua_getglobal(S, class); /* push global class ref to stack */
		if (lua_isnil(S, -1)) {
			return (SHERR_NOENT);
		}
		lua_getfield(S, -1, method);  /* get <class>.<method> */
		if (lua_isnil(S, -1)) {
			return (SHERR_NOENT);
		}
	}

	tot = 0;
	if (narg != 0) {
		args = shjson_obj_get(call, "argument");
		for (i = 0; i < narg; i++) {
			shjson_t *arg = shjson_array_get(args, i);
			switch (arg->type) {
				case shjson_Object:
					sexe_table_set(S, arg);
					break;
				case shjson_Number:
					lua_pushnumber(S, (lua_Number)shjson_array_num(call, "argument", i));
					break;
				case shjson_String:
					text = shjson_array_str(call, "argument", i);
					lua_pushlstring(S, text, strlen(text));
					break;
				case shjson_True:
					lua_pushboolean(S, TRUE);
					break;
				case shjson_False:
					lua_pushboolean(S, FALSE);
					break;
				default:
					lua_pushnil(S);
					break;
			} 
			tot++;
		}
	}

	err = lua_pcall(S, tot, ret_cnt, 0);
  if (err)
    return (err);

	if (call) {
		if (!ret_cnt || lua_isnil(S, -1)) {
			shjson_null_add(call, "return");
		} else if (lua_isstring(S, -1)) {
			shjson_str_add(call, "return", lua_tostring(S, -1)); 
		} else if (lua_isnumber(S, -1)) {
			shjson_num_add(call, "return", (double)lua_tonumber(S, -1)); 
		} else if (lua_isboolean(S, -1)) {
			shjson_bool_add(call, "return", lua_toboolean(S, -1) ? TRUE : FALSE);
		} else if (lua_istable(S, -1)) {
			shjson_t *obj = sexe_table_get(S);
			shjson_obj_append(obj, shjson_obj_add(call, "return"));
			shjson_free(&obj);
		}
	}

	return (0);
}

int sexe_execm(shbuf_t *buff, char **argv)
{
	sexe_t *S;
	int argc;
	int err;

	err = sexe_popen(buff, &S);
	if (err) {
		return (err);
	}

	for (argc = 0; argv[argc]; argc++);
	err = sexe_prun(S, argc, argv);
	if (err) {
		sexe_pclose(S);
		return (err);
	}

	sexe_pclose(S);
	return (0);
}

int sexe_exec(char *path, char **argv)
{
	sexe_t *S;
	int argc;
	int err;

	err = sexe_popen_file(path, &S);
	if (err) {
		return (err);
	}

	for (argc = 0; argv[argc]; argc++);
	err = sexe_prun(S, argc, argv);
	if (err) {
		sexe_pclose(S);
		return (err);
	}

	sexe_pclose(S);
	return (0);
}

int sexe_execve(char *path, char **argv, char *const envp[])
{
	return (sexe_exec(path, argv));
}

void sexe_pclose(sexe_t *S)
{
	lua_close(S);
}

int sexe_pevent(sexe_t *S, char *event_name, shjson_t *data)
{
	int err;
	int ret;

	lua_pushcfunction(S, lfunc_trigger_event);
	lua_pushstring(S, event_name);
	if (!data)
		lua_pushnil(S);
	else
		sexe_table_set(S, data);

	err = lua_pcall(S, 2, 1, 0);
//if (err) fprintf(stderr, "DEBUG: sexe_pevent: %d = lua_pcall()\n", err);
	if (err != LUA_OK) {
		/* .. */
		return (FALSE);
	}

	ret = lua_toboolean(S, -1);
//if (err) fprintf(stderr, "DEBUG: sexe_pevent: InitEvent ret'd %s\n", ret?"true":"false");
	return (ret);
}

SEXE_API void sexe_pushboolean(sexe_t *S, int b)
{
	return (lua_pushboolean((lua_State *)S, b));
}


