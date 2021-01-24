
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

#define LUA_LIB
#include "sexe.h"
#include <libgen.h>

#if !defined(_FILE_OFFSET_BITS)
#define _FILE_OFFSET_BITS 64
#endif

#define IO_PREFIX	"_IO_"
#define IO_INPUT	(IO_PREFIX "input")
#define IO_OUTPUT	(IO_PREFIX "output")

#define MAX_SIZE_T	(~(size_t)0)


#define l_ftell(f) \
	shftell((int)f)

#define l_seeknum		off_t

#define l_fclose(fd) \
	(shclose(fd))

#define l_fread(p, s, rlen, f) \
	(shread((int)f, p, (s*rlen)))

#define l_fflush(fd) \
	(shflush(fd))

#define l_fwrite(p, s, rlen, f) \
	(shwrite((int)f, p, (s*rlen))) 

#define l_fsize(p) \
	(shfsize((int)p))

#define l_fgetc(f) \
	(shfgetc((int)f))

#define l_fopen(fname, mode) \
	(shopen(fname, mode, NULL))

#define l_tmpfile() \
	(shtmpfile())

#define l_fseek(fd, off, whence) \
	(shfseek(fd, off, whence))

#define tolstream(L)	((LStream *)luaL_checkudata(L, 1, LUA_FILEHANDLE))

#define isclosed(p)	((p)->closef == NULL)

typedef luaL_Stream LStream;



static int tofileno(lua_State *L) 
{
  LStream *p = tolstream(L);
  if (isclosed(p))
    luaL_error(L, "attempt to use a closed file");
  return (p->fileno);
}

#if 0
static int l_fprintf(int fd, char *fmt, ...)
{
	char buff[10240]; /* fix me */
	va_list ap;

	va_start(&ap, fmt);
	vsnprintf(buff, sizeof(buff)-1, fmt, ap);
	va_end(&ap);

	return (l_fwrite(buff, sizeof(char), strlen(buff), fd));
}
#endif

int l_fscanf(int fd, char *fmt, void *value)
{
	char buf[1024];

	memset(buf, 0, sizeof(buf));

	if (0 == strcmp(fmt, "%f")) {
		size_t max = sizeof(buf);
		size_t of;
		char ch;

		while (of < max) {
			ch = l_fgetc(fd);
			if ((of == 0 && ch == '-') ||
					ch == '.' || isdigit(ch)) {
				buf[of] = ch;
				continue;
			}

			break;
		}

		memcpy(value, buf, sizeof(lua_Number));
	}

	return (SHERR_INVAL);
}

static char *l_fgets(char *p, size_t max_len, int fd)
{
	int ch;

	ch = -1;
	while ( max_len > 0 && (ch = l_fgetc(fd)) != -1 ) {
		if (ch == '\r')
			continue;

		*p = (char)ch;
		p++;
		max_len--;

		if (ch == '\n')
			break;
	}
	if (ch == -1)
		return (NULL);

	return (p);
}


static int aux_close (lua_State *L) 
{
  LStream *p = tolstream(L);
  lua_CFunction cf = p->closef;
  p->closef = NULL;  /* mark stream as closed */
  return (*cf)(L);  /* close it */
}

static int f_gc (lua_State *L) {
  LStream *p = tolstream(L);
  if (!isclosed(p))
    aux_close(L);  /* ignore closed and incompletely open files */
  return 0;
}

static int f_tostring (lua_State *L) {
  LStream *p = tolstream(L);
  if (isclosed(p))
    lua_pushliteral(L, "file (closed)");
  else
    lua_pushfstring(L, "file (#%d)", p->fileno);
  return 1;
}

static int getiofileno(lua_State *L, const char *findex) 
{
  LStream *p;
  lua_getfield(L, LUA_REGISTRYINDEX, findex);
  p = (LStream *)lua_touserdata(L, -1);
  if (isclosed(p))
    luaL_error(L, "standard %s file is closed", findex + strlen(IO_PREFIX));
  return p->fileno;
}

static int sexe_io_fileresult(lua_State *L, int err_code)
{
	lua_pushinteger(L, -1); /* ill descriptor */
	lua_pushstring(L, sherrstr(err_code));
	lua_pushinteger(L, err_code);
	return (3); /* 3 results */
}

/*
** function to close regular files
*/
static int io_fclose (lua_State *L) {
  LStream *p = tolstream(L);
	if (p->fileno != -1) {
		l_fclose(p->fileno);
	}
	p->fileno = -1;
	lua_pushboolean(L, 1);
	return (1);
}

/*
** When creating file handles, always creates a `closed' file handle
** before opening the actual file; so, if there is a memory error, the
** file is not left opened.
*/
static LStream *newprefile (lua_State *L) {
  LStream *p = (LStream *)lua_newuserdata(L, sizeof(LStream));
  p->closef = NULL;  /* mark file handle as 'closed' */
  luaL_setmetatable(L, LUA_FILEHANDLE);
  return p;
}

static LStream *newfile (lua_State *L) 
{
  LStream *p = newprefile(L);
	p->fileno = -1;
  p->closef = &io_fclose;
  return p;
}



/* functions for 'io' library */
static int _lfunc_sexe_io_close (lua_State *L) {
  if (lua_isnone(L, 1))  /* no argument? */
    lua_getfield(L, LUA_REGISTRYINDEX, IO_OUTPUT);  /* use standard output */
  tofileno(L);  /* make sure argument is an open stream */
  return aux_close(L);
}

static int _lfunc_sexe_io_open (lua_State *L) 
{
  const char *filename = luaL_checkstring(L, 1);
  const char *mode = luaL_optstring(L, 2, "r");
	int fd;
  int i = 0;

  /* check whether 'mode' matches '[rwa]%+?b?' */
  if (!(mode[i] != '\0' && strchr("rwa", mode[i++]) != NULL &&
       (mode[i] != '+' || ++i) &&  /* skip if char is '+' */
       (mode[i] != 'b' || ++i) &&  /* skip if char is 'b' */
       (mode[i] == '\0')))
    return luaL_error(L, "invalid mode " LUA_QS
                         " (should match " LUA_QL("[rwa]%%+?b?") ")", mode);

	fd = l_fopen(filename, mode);
	if (fd < 0) {
		return (sexe_io_fileresult(L, fd));
	}

  LStream *p = newfile(L);
	p->fileno = fd; 

  return 1;
}

static int _lfunc_sexe_io_tmpfile (lua_State *L) 
{
	LStream *p;
	int fd;
	
	fd = l_tmpfile();
	if (fd < 0) {
		return (sexe_io_fileresult(L, fd));
	}

	p = newfile(L);
	p->fileno = fd;
	return (1);
}

static void opencheck (lua_State *L, const char *fname, const char *mode) 
{
  LStream *p = newfile(L);
	int fd;
	
	fd = l_fopen(fname, mode);
	if (fd < 0) {
    luaL_error(L, "cannot open file " LUA_QS " (%s)", fname, sherrstr(fd));
	} else {
		p->fileno = fd;
	}
}

static int g_iofile(lua_State *L, const char *f, const char *mode) 
{
	if (!lua_isnoneornil(L, 1)) {
		const char *filename = lua_tostring(L, 1);
		if (filename)
			opencheck(L, filename, mode);
		else {
			tofileno(L);  /* check that it's a valid file handle */
			lua_pushvalue(L, 1);
		}
		lua_setfield(L, LUA_REGISTRYINDEX, f);
	}
	/* return current value */
	lua_getfield(L, LUA_REGISTRYINDEX, f);
	return 1;
}

static int _lfunc_sexe_io_input(lua_State *L) 
{
  return g_iofile(L, IO_INPUT, "r");
}



static int _lfunc_sexe_io_type(lua_State *L) 
{
  LStream *p;
  luaL_checkany(L, 1);
  p = (LStream *)luaL_testudata(L, 1, LUA_FILEHANDLE);
  if (p == NULL)
    lua_pushnil(L);  /* not a file */
  else if (isclosed(p))
    lua_pushliteral(L, "closed file");
  else
    lua_pushliteral(L, "file");
  return 1;
}

































/* }====================================================== */


static int g_write(lua_State *L, int fd, int arg) 
{
	char buf[1024];
  int nargs = lua_gettop(L) - arg;
  int status = 1;
	size_t l;
	int err;

  for (; nargs--; arg++) {
    if (lua_type(L, arg) == LUA_TNUMBER) {
			sprintf(buf, LUA_NUMBER_FMT, lua_tonumber(L, arg));
			l = strlen(buf);
      status = status && ((err = l_fwrite(buf, sizeof(char), l, fd)) == l);
    } else {
      const char *s = luaL_checklstring(L, arg, &l);
      status = status && ((err = l_fwrite(s, sizeof(char), l, fd)) == l);
    }
  }
  if (status) return 1;  /* file handle already on stack top */

	return sexe_io_fileresult(L, err);
}


/* local fl = io.output("path") */
static int _lfunc_sexe_io_output(lua_State *L) 
{
  return g_iofile(L, IO_OUTPUT, "w");
}

static int read_chars(lua_State *L, int fd, size_t n) 
{
	size_t nr;  /* number of chars actually read */
	char *p;
	luaL_Buffer b;
	luaL_buffinit(L, &b);
	p = luaL_prepbuffsize(&b, n);  /* prepare buffer to read whole block */
	nr = l_fread(p, sizeof(char), n, fd); /* read 'n' chars */
	luaL_addsize(&b, nr);
	luaL_pushresult(&b);  /* close buffer */
	return (nr > 0);  /* true iff read something */
}

static int read_line (lua_State *L, FILE *f, int chop) 
{
  luaL_Buffer b;
  luaL_buffinit(L, &b);
  for (;;) {
    size_t l;
    char *p = luaL_prepbuffer(&b);
    if (l_fgets(p, LUAL_BUFFERSIZE, f) == NULL) {  /* eof? */
      luaL_pushresult(&b);  /* close buffer */
      return (lua_rawlen(L, -1) > 0);  /* check whether read something */
    }
    l = strlen(p);
    if (l == 0 || p[l-1] != '\n')
      luaL_addsize(&b, l);
    else {
      luaL_addsize(&b, l - chop);  /* chop 'eol' if needed */
      luaL_pushresult(&b);  /* close buffer */
      return 1;  /* read at least an `eol' */
    }
  }
}

static void read_all (lua_State *L, FILE *f) 
{
  size_t rlen = LUAL_BUFFERSIZE;  /* how much to read in each cycle */
  luaL_Buffer b;
  luaL_buffinit(L, &b);
  for (;;) {
    char *p = luaL_prepbuffsize(&b, rlen);
    size_t nr = l_fread(p, sizeof(char), rlen, f);
    luaL_addsize(&b, nr);
    if (nr < rlen) break;  /* eof? */
    else if (rlen <= (MAX_SIZE_T / 4))  /* avoid buffers too large */
      rlen *= 2;  /* double buffer size at each iteration */
  }
  luaL_pushresult(&b);  /* close buffer */
}

static int read_number (lua_State *L, FILE *f) 
{
  lua_Number d;
  if (l_fscanf(f, LUA_NUMBER_SCAN, &d) == 1) {
    lua_pushnumber(L, d);
    return 1;
  }
  else {
   lua_pushnil(L);  /* "result" to be removed */
   return 0;  /* read fails */
  }
}

static int test_eof (lua_State *L, FILE *f) 
{
	return (l_ftell(f) != l_fsize(f));
}

static int g_read(lua_State *L, int fd, int first) 
{
	int nargs = lua_gettop(L) - 1;
	int success;
	int n;

	if (fd == -1) {
		lua_pushnil(L);  /* push nil instead */
		return (1);
	}

	//clearerr(fd);
	if (nargs == 0) {  /* no arguments? */
		success = read_line(L, fd, 1);
		n = first+1;  /* to return 1 result */
	}
	else {  /* ensure stack space for all results and for auxlib's buffer */
		luaL_checkstack(L, nargs+LUA_MINSTACK, "too many arguments");
		success = 1;
		for (n = first; nargs-- && success; n++) {
			if (lua_type(L, n) == LUA_TNUMBER) {
				size_t l = (size_t)lua_tointeger(L, n);
				success = (l == 0) ? test_eof(L, fd) : read_chars(L, fd, l);
			}
			else {
				const char *p = lua_tostring(L, n);
				luaL_argcheck(L, p && p[0] == '*', n, "invalid option");
				switch (p[1]) {
					case 'n':  /* number */
						success = read_number(L, fd);
						break;
					case 'l':  /* line */
						success = read_line(L, fd, 1);
						break;
					case 'L':  /* line with end-of-line */
						success = read_line(L, fd, 0);
						break;
					case 'a':  /* file */
						read_all(L, fd);  /* read entire file */
						success = 1; /* always success */
						break;
					default:
						return luaL_argerror(L, n, "invalid format");
				}
			}
		}
	}
#if 0
	if (ferror(fd))
		return luaL_fileresult(L, 0, NULL);
#endif
	if (!success) {
		lua_pop(L, 1);  /* remove last result */
		lua_pushnil(L);  /* push nil instead */
	}
	return n - first;
}

static int _lfunc_sexe_io_readline (lua_State *L) 
{
	LStream *p = (LStream *)lua_touserdata(L, lua_upvalueindex(1));
	int i;
	int n = (int)lua_tointeger(L, lua_upvalueindex(2));
	if (isclosed(p))  /* file is already closed? */
		return luaL_error(L, "file is already closed");
	lua_settop(L , 1);
	for (i = 1; i <= n; i++)  /* push arguments to 'g_read' */
		lua_pushvalue(L, lua_upvalueindex(3 + i));
	n = g_read(L, p->fileno, 2);  /* 'n' is number of results */
	lua_assert(n > 0);  /* should return at least a nil */
	if (!lua_isnil(L, -n))  /* read at least one value? */
		return n;  /* return them */
	else {  /* first result is nil: EOF or error */
		if (n > 1) {  /* is there error information? */
			/* 2nd result is error message */
			return luaL_error(L, "%s", lua_tostring(L, -n + 1));
		}
		if (lua_toboolean(L, lua_upvalueindex(3))) {  /* generator created file? */
			lua_settop(L, 0);
			lua_pushvalue(L, lua_upvalueindex(1));
			aux_close(L);  /* close it */
		}
		return 0;
	}
}

static void aux_lines (lua_State *L, int toclose) 
{
  int i;
  int n = lua_gettop(L) - 1;  /* number of arguments to read */
  /* ensure that arguments will fit here and into 'io_readline' stack */
  luaL_argcheck(L, n <= LUA_MINSTACK - 3, LUA_MINSTACK - 3, "too many options");
  lua_pushvalue(L, 1);  /* file handle */
  lua_pushinteger(L, n);  /* number of arguments to read */
  lua_pushboolean(L, toclose);  /* close/not close file when finished */
  for (i = 1; i <= n; i++) lua_pushvalue(L, i + 1);  /* copy arguments */
  lua_pushcclosure(L, _lfunc_sexe_io_readline, 3 + n);
}

static int f_lines (lua_State *L) {
  tofileno(L);  /* check that it's a valid file handle */
  aux_lines(L, 0);
  return 1;
}

static int _lfunc_sexe_io_lines (lua_State *L) 
{
  int toclose;
  if (lua_isnone(L, 1)) lua_pushnil(L);  /* at least one argument */
  if (lua_isnil(L, 1)) {  /* no file name? */
    lua_getfield(L, LUA_REGISTRYINDEX, IO_INPUT);  /* get default input */
    lua_replace(L, 1);  /* put it at index 1 */
    tofileno(L);  /* check that it's a valid file handle */
    toclose = 0;  /* do not close it after iteration */
  }
  else {  /* open a new file */
    const char *filename = luaL_checkstring(L, 1);
    opencheck(L, filename, "r");
    lua_replace(L, 1);  /* put file at index 1 */
    toclose = 1;  /* close it after iteration */
  }
  aux_lines(L, toclose);
  return 1;
}








static int _lfunc_sexe_io_read (lua_State *L) 
{
	return g_read(L, getiofileno(L, IO_INPUT), 1);
}

static int f_read (lua_State *L) 
{
	return g_read(L, tofileno(L), 2);
}


static int _lfunc_sexe_io_write (lua_State *L) {
  return g_write(L, getiofileno(L, IO_OUTPUT), 1);
}

static int f_write (lua_State *L) {
  int fd = tofileno(L);
  lua_pushvalue(L, 1);  /* push file at the stack top (to be returned) */
  return g_write(L, fd, 2);
}

static int f_seek (lua_State *L) 
{
  static const int mode[] = {SEEK_SET, SEEK_CUR, SEEK_END};
  static const char *const modenames[] = {"set", "cur", "end", NULL};
  int fd = tofileno(L);
  int op = luaL_checkoption(L, 2, "cur", modenames);

  lua_Number p3 = luaL_optnumber(L, 3, 0);
  l_seeknum offset = (l_seeknum)p3;
  luaL_argcheck(L, (lua_Number)offset == p3, 3,
                  "not an integer in proper range");

  l_fseek(fd, offset, mode[op]);
	lua_pushnumber(L, (lua_Number)l_ftell(fd));
	return 1;
}

/* methods for file handles */
static int f_flush(lua_State *L) {
	l_fflush(tofileno(L));
	lua_pushboolean(L, 1);
	return 1;
}

static int _lfunc_sexe_io_flush(lua_State *L) 
{
	l_fflush(getiofileno(L, IO_OUTPUT));
	lua_pushboolean(L, 1);
	return 1;
}

/* write a table to a json file */
static int _lfunc_sexe_io_serialize(lua_State *L)
{
	shjson_t *j;
	shkey_t *key;
	char path[PATH_MAX+1];
	char *ptr;
	char *tag;
	int err;
	int fd;

	if (lua_isstring(L, 1)) {
		tag = luaL_checkstring(L, 1);
	} else {
		tag = NULL;
	}

	if (!lua_istable(L, 2)) {
		lua_pushboolean(L, FALSE);
		return 1;
	}

	lua_pushvalue(L, 2);
	j = sexe_table_get(L);
	if (!j) {
		lua_pushboolean(L, FALSE);
		return (1);
	}

	err = sexe_io_serialize(L, tag, j); 
	shjson_free(&j);
	if (err) {
		lua_pushboolean(L, FALSE);
		return (1);
	}

	lua_pushboolean(L, 1);
	return (1);
}

/* parse json from a file into a table */
static int _lfunc_sexe_io_unserialize(lua_State *L)
{
	shjson_t *j;
	char *tag;
	int err;

	if (lua_isstring(L, 1)) {
		tag = luaL_checkstring(L, 1);
	} else {
		tag = NULL;
	}

	j = NULL;
	err = sexe_io_unserialize(L, tag, &j);
	if (err) {
		lua_pushnil(L); /* no data avail */
		return (1);
	}

	/* push table on stack. */
	sexe_table_set(L, j);
	shjson_free(&j);
	return (1);
}

static int _lfunc_sexe_io_dirname(lua_State *L)
{
	char path[PATH_MAX+1];
	char *ret_str;

	memset(path, 0, sizeof(path));
	strncpy(path, luaL_checkstring(L, 1), sizeof(path)-1);

	lua_pushstring(L, dirname(path));
	return (1);
}

static int _lfunc_sexe_io_basename(lua_State *L)
{
	char path[PATH_MAX+1];
	char *ret_str;

	memset(path, 0, sizeof(path));
	strncpy(path, luaL_checkstring(L, 1), sizeof(path)-1);

	lua_pushstring(L, basename(path));
	return (1);
}




/* function to (not) close the standard files stdin, stdout, and stderr */
static int io_noclose (lua_State *L) {
	LStream *p = tolstream(L);
	p->closef = &io_noclose;  /* keep file opened */
	lua_pushnil(L);
	lua_pushliteral(L, "cannot close standard file");
	return 2;
}

static void createstdfile(lua_State *L, FILE *f, const char *k, const char *fname) 
{
	LStream *p = newprefile(L);
	p->fileno = fileno(f);
	p->closef = &io_noclose;
	if (k != NULL) {
		lua_pushvalue(L, -1);
		lua_setfield(L, LUA_REGISTRYINDEX, k);  /* add file to registry */
	}
	lua_setfield(L, -2, fname);  /* add file to module */
}


static const luaL_Reg flib[] = {
  {"close", _lfunc_sexe_io_close}, 
  {"flush", f_flush},
  {"lines", f_lines},
  {"read", f_read},
  {"seek", f_seek},
//  {"setvbuf", f_setvbuf},
  {"write", f_write},
  {"__gc", f_gc},
  {"__tostring", f_tostring},
  {NULL, NULL}
};


static void createmeta (lua_State *L) {
  luaL_newmetatable(L, LUA_FILEHANDLE);  /* create metatable for file handles */
  lua_pushvalue(L, -1);  /* push metatable */
  lua_setfield(L, -2, "__index");  /* metatable.__index = metatable */
  luaL_setfuncs(L, flib, 0);  /* add file methods to new metatable */
  lua_pop(L, 1);  /* pop new metatable */
}


static const luaL_Reg sexe_io_lib[] = {
  {"close", _lfunc_sexe_io_close},
  {"flush", _lfunc_sexe_io_flush},
  {"input", _lfunc_sexe_io_input},
  {"lines", _lfunc_sexe_io_lines},
  {"open", _lfunc_sexe_io_open},
  {"output", _lfunc_sexe_io_output},
  {"read", _lfunc_sexe_io_read},
  {"tmpfile", _lfunc_sexe_io_tmpfile},
  {"type", _lfunc_sexe_io_type},
  {"write", _lfunc_sexe_io_write},
  {"serialize", _lfunc_sexe_io_serialize},
  {"unserialize", _lfunc_sexe_io_unserialize},
	{"basename", _lfunc_sexe_io_basename},
	{"dirname", _lfunc_sexe_io_dirname},
  {NULL, NULL}
};


LUAMOD_API int luaopen_io (lua_State *L) 
{
  luaL_newlib(L, sexe_io_lib);  /* new module */
  createmeta(L);
  /* create (and set) default files */
	createstdfile(L, get_sexe_stdin(), IO_INPUT, "stdin");
	createstdfile(L, get_sexe_stdout(), IO_OUTPUT, "stdout");
  createstdfile(L, get_sexe_stderr(), NULL, "stderr");
  return 1;
}

