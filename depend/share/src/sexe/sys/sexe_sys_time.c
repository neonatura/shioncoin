
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


/*
** By default, Lua uses gmtime/localtime, except when POSIX is available,
** where it uses gmtime_r/localtime_r
*/
#if defined(LUA_USE_GMTIME_R)

#define l_gmtime(t,r)		gmtime_r(t,r)
#define l_localtime(t,r)	localtime_r(t,r)

#elif !defined(l_gmtime)

#define l_gmtime(t,r)		((void)r, gmtime(t))
#define l_localtime(t,r)  	((void)r, localtime(t))

#endif

/*
** list of valid conversion specifiers for the 'strftime' function
*/
#if !defined(LUA_STRFTIMEOPTIONS)

#if !defined(LUA_USE_POSIX)
#define LUA_STRFTIMEOPTIONS     { "aAbBcdHIjmMpSUwWxXyYz%", "" }
#else
#define LUA_STRFTIMEOPTIONS     { "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ%", "", \
                                "E", "cCxXyY",  \
                                "O", "deHImMSuUVwWy" }
#endif

#endif


static void setfield (sexe_t *L, const char *key, int value) {
  lua_pushinteger(L, value);
  lua_setfield(L, -2, key);
}

static void setboolfield (sexe_t *L, const char *key, int value) {
  if (value < 0)  /* undefined? */
    return;  /* does not set field */
  lua_pushboolean(L, value);
  lua_setfield(L, -2, key);
}

static int getboolfield (sexe_t *L, const char *key) {
  int res;
  lua_getfield(L, -1, key);
  res = lua_isnil(L, -1) ? -1 : lua_toboolean(L, -1);
  lua_pop(L, 1);
  return res;
}


static int getfield (sexe_t *L, const char *key, int d) {
  int res, isnum;
  lua_getfield(L, -1, key);
  res = (int)lua_tointegerx(L, -1, &isnum);
  if (!isnum) {
    if (d < 0)
      return luaL_error(L, "field " LUA_QS " missing in date table", key);
    res = d;
  }
  lua_pop(L, 1);
  return res;
}

static const char *checkoption (sexe_t *L, const char *conv, char *buff) {
  static const char *const options[] = LUA_STRFTIMEOPTIONS;
  unsigned int i;
  for (i = 0; i < sizeof(options)/sizeof(options[0]); i += 2) {
    if (*conv != '\0' && strchr(options[i], *conv) != NULL) {
      buff[1] = *conv;
      if (*options[i + 1] == '\0') {  /* one-char conversion specifier? */
        buff[2] = '\0';  /* end buffer */
        return conv + 1;
      }
      else if (*(conv + 1) != '\0' &&
               strchr(options[i + 1], *(conv + 1)) != NULL) {
        buff[2] = *(conv + 1);  /* valid two-char conversion specifier */
        buff[3] = '\0';  /* end buffer */
        return conv + 2;
      }
    }
  }
  luaL_argerror(L, 1,
    lua_pushfstring(L, "invalid conversion specifier '%%%s'", conv));
  return conv;  /* to avoid warnings */
}




static int _lfunc_sexe_time(sexe_t *L)
{
  lua_pushnumber(L, shtimef(shtime()));
  return 1; /* 'time' */
}

static int _lfunc_sexe_ctime(sexe_t *L)
{
  double f = luaL_checknumber(L, 1);
  shtime_t t = SHTIME_UNDEFINED;

  shnum_set(f, &t);
  lua_pushstring(L, shctime(t));
  return 1; /* 'ctime' */
}

static int _lfunc_sexe_utime(sexe_t *L)
{
  double f = luaL_optnumber(L, 1, -1);
  shtime_t t = SHTIME_UNDEFINED;

	if (f != -1) {
		/* shtime_t -> time_t */
		shnum_set(f, &t);
		lua_pushnumber(L, (lua_Number)shutime(t));
	} else {
		/* current time */
		lua_pushnumber(L, (lua_Number)time(NULL));
	}

  return 1; /* 'utime' */
}

static int _lfunc_sexe_timeu(sexe_t *L)
{
  time_t t = (time_t)luaL_checknumber(L, 1);
  lua_pushnumber(L, shtimef(shtimeu(t)));
  return 1; /* 'timeu' */
}

static int _lfunc_sexe_strftime(sexe_t *L)
{
  double f = luaL_checknumber(L, 1);
  const char *fmt = luaL_checkstring(L, 2);
  shtime_t t = SHTIME_UNDEFINED;

  shnum_set(f, &t);
  lua_pushstring(L, (char *)shstrtime(t, fmt));
  return 1; /* 'strftime' */
}

static int _lfunc_sexe_clock(sexe_t *L) 
{
  lua_pushnumber(L, ((lua_Number)clock())/(lua_Number)CLOCKS_PER_SEC);
	return 1;
}

/**
 * Retrieve the current time as an object.
 * Format is: { year=%Y, month=%m, day=%d, hour=%H, min=%M, sec=%S, wday=%w+1, yday=%j, isdst=? }
 */
static int _lfunc_sexe_date(sexe_t *L)
{
  const char *s = luaL_optstring(L, 1, "%c");
  time_t t = luaL_opt(L, (time_t)luaL_checknumber, 2, time(NULL));
  struct tm tmr, *stm;
  if (*s == '!') {  /* UTC? */
    stm = l_gmtime(&t, &tmr);
    s++;  /* skip `!' */
  }
  else
    stm = l_localtime(&t, &tmr);
  if (stm == NULL)  /* invalid date? */
    lua_pushnil(L);
  else if (strcmp(s, "*t") == 0) {
    lua_createtable(L, 0, 9);  /* 9 = number of fields */
    setfield(L, "sec", stm->tm_sec);
    setfield(L, "min", stm->tm_min);
    setfield(L, "hour", stm->tm_hour);
    setfield(L, "day", stm->tm_mday);
    setfield(L, "month", stm->tm_mon+1);
    setfield(L, "year", stm->tm_year+1900);
    setfield(L, "wday", stm->tm_wday+1);
    setfield(L, "yday", stm->tm_yday+1);
    setboolfield(L, "isdst", stm->tm_isdst);
  }
  else {
    char cc[4];
    luaL_Buffer b;
    cc[0] = '%';
    luaL_buffinit(L, &b);
    while (*s) {
      if (*s != '%')  /* no conversion specifier? */
        luaL_addchar(&b, *s++);
      else {
        size_t reslen;
        char buff[200];  /* should be big enough for any conversion result */
        s = checkoption(L, s + 1, cc);
        reslen = strftime(buff, sizeof(buff), cc, stm);
        luaL_addlstring(&b, buff, reslen);
      }
    }
    luaL_pushresult(&b);
  }
  return 1;
}

static int _lfunc_sexe_difftime(sexe_t * L)
{
  lua_pushnumber (L, difftime ((time_t) (luaL_checknumber (L, 1)),
			       (time_t) (luaL_optnumber (L, 2, 0))));
  return 1;
}


/* timelib */
static const luaL_Reg sexe_time_lib[] = {
	{ "time", _lfunc_sexe_time },
	{ "ctime", _lfunc_sexe_ctime },
	{ "utime", _lfunc_sexe_utime },
	{ "timeu", _lfunc_sexe_timeu },
	{ "strftime", _lfunc_sexe_strftime },
	{ "clock", _lfunc_sexe_clock },
	{ "date", _lfunc_sexe_date },
	{ "difftime", _lfunc_sexe_difftime },
	{ NULL, NULL }
};


LUAMOD_API int luaopen_time(sexe_t *L) 
{
  luaL_newlib(L, sexe_time_lib);
	return 1;
}





