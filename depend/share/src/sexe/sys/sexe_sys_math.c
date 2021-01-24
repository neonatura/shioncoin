
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

#undef PI
#define PI (3.14159265358979323846)
#define RADIANS_PER_DEGREE (PI/180.0)


/* macro 'l_tg' allows the addition of an 'l' or 'f' to all math operations */
#if !defined(l_tg)
#define l_tg(x)		(x)
#endif



static int _lfunc_sexe_math_abs (lua_State *L) {
  lua_pushnumber(L, l_tg(fabs)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_sin (lua_State *L) {
  lua_pushnumber(L, l_tg(sin)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_sinh (lua_State *L) {
  lua_pushnumber(L, l_tg(sinh)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_cos (lua_State *L) {
  lua_pushnumber(L, l_tg(cos)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_cosh (lua_State *L) {
  lua_pushnumber(L, l_tg(cosh)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_tan (lua_State *L) {
  lua_pushnumber(L, l_tg(tan)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_tanh (lua_State *L) {
  lua_pushnumber(L, l_tg(tanh)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_asin (lua_State *L) {
  lua_pushnumber(L, l_tg(asin)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_acos (lua_State *L) {
  lua_pushnumber(L, l_tg(acos)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_atan (lua_State *L) {
  lua_pushnumber(L, l_tg(atan)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_atan2 (lua_State *L) {
  lua_pushnumber(L, l_tg(atan2)(luaL_checknumber(L, 1),
                                luaL_checknumber(L, 2)));
  return 1;
}

static int _lfunc_sexe_math_ceil (lua_State *L) {
  lua_pushnumber(L, l_tg(ceil)(luaL_checknumber(L, 1)));
  return 1;
}

int lfunc_sexe_math_floor(lua_State *L) 
{
	lua_Number ret_valprec;
	lua_Number prec;
	lua_Number val;

	val = luaL_checknumber(L, 1);
	prec = (lua_Number)luaL_optinteger(L, 2, 0); 
	if (prec > 0)
		val = val * pow(prec, 10);

  val = (lua_Number)l_tg(floor)(val); 
	if (prec > 0)
		val = val / pow(prec, 10);

	/* single argument number result */
  lua_pushnumber(L, val);
  return 1;
}

static int _lfunc_sexe_math_fmod (lua_State *L) {
  lua_pushnumber(L, l_tg(fmod)(luaL_checknumber(L, 1),
                               luaL_checknumber(L, 2)));
  return 1;
}

static int _lfunc_sexe_math_modf (lua_State *L) {
  lua_Number ip;
  lua_Number fp = l_tg(modf)(luaL_checknumber(L, 1), &ip);
  lua_pushnumber(L, ip);
  lua_pushnumber(L, fp);
  return 2;
}

static int _lfunc_sexe_math_sqrt (lua_State *L) {
  lua_pushnumber(L, l_tg(sqrt)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_pow (lua_State *L) {
  lua_pushnumber(L, l_tg(pow)(luaL_checknumber(L, 1),
                              luaL_checknumber(L, 2)));
  return 1;
}

static int _lfunc_sexe_math_log (lua_State *L) {
  lua_Number x = luaL_checknumber(L, 1);
  lua_Number res;
  if (lua_isnoneornil(L, 2))
    res = l_tg(log)(x);
  else {
    lua_Number base = luaL_checknumber(L, 2);
    if (base == 10.0) res = l_tg(log10)(x);
    else res = l_tg(log)(x)/l_tg(log)(base);
  }
  lua_pushnumber(L, res);
  return 1;
}

#if defined(LUA_COMPAT_LOG10)
static int _lfunc_sexe_math_log10 (lua_State *L) {
  lua_pushnumber(L, l_tg(log10)(luaL_checknumber(L, 1)));
  return 1;
}
#endif

static int _lfunc_sexe_math_exp (lua_State *L) {
  lua_pushnumber(L, l_tg(exp)(luaL_checknumber(L, 1)));
  return 1;
}

static int _lfunc_sexe_math_deg (lua_State *L) {
  lua_pushnumber(L, luaL_checknumber(L, 1)/RADIANS_PER_DEGREE);
  return 1;
}

static int _lfunc_sexe_math_rad (lua_State *L) {
  lua_pushnumber(L, luaL_checknumber(L, 1)*RADIANS_PER_DEGREE);
  return 1;
}

static int _lfunc_sexe_math_frexp (lua_State *L) {
  int e;
  lua_pushnumber(L, l_tg(frexp)(luaL_checknumber(L, 1), &e));
  lua_pushinteger(L, e);
  return 2;
}

static int _lfunc_sexe_math_ldexp (lua_State *L) {
  lua_pushnumber(L, l_tg(ldexp)(luaL_checknumber(L, 1),
                                luaL_checkint(L, 2)));
  return 1;
}



static int _lfunc_sexe_math_min (lua_State *L) {
  int n = lua_gettop(L);  /* number of arguments */
  lua_Number dmin = luaL_checknumber(L, 1);
  int i;
  for (i=2; i<=n; i++) {
    lua_Number d = luaL_checknumber(L, i);
    if (d < dmin)
      dmin = d;
  }
  lua_pushnumber(L, dmin);
  return 1;
}


static int _lfunc_sexe_math_max (lua_State *L) {
  int n = lua_gettop(L);  /* number of arguments */
  lua_Number dmax = luaL_checknumber(L, 1);
  int i;
  for (i=2; i<=n; i++) {
    lua_Number d = luaL_checknumber(L, i);
    if (d > dmax)
      dmax = d;
  }
  lua_pushnumber(L, dmax);
  return 1;
}


static int _lfunc_sexe_math_random (lua_State *L) 
{
  /* the `%' avoids the (rare) case of r==1, and is needed also because on
     some systems (SunOS!) `rand()' may return a value larger than RAND_MAX */
  lua_Number r = (lua_Number)(shrand() & 0xFFFFFFFF);
  switch (lua_gettop(L)) {  /* check number of arguments */
    case 0: {  /* no arguments */
      lua_pushnumber(L, r);  /* Number between 0 and 1 */
      break;
    }
    case 1: {  /* only upper limit */
      lua_Number u = luaL_checknumber(L, 1);
      luaL_argcheck(L, 1.0 <= u, 1, "interval is empty");
      lua_pushnumber(L, l_tg(floor)(r*u) + 1.0);  /* int in [1, u] */
      break;
    }
    case 2: {  /* lower and upper limits */
      lua_Number l = luaL_checknumber(L, 1);
      lua_Number u = luaL_checknumber(L, 2);
      luaL_argcheck(L, l <= u, 2, "interval is empty");
      lua_pushnumber(L, l_tg(floor)(r*(u-l+1)) + l);  /* int in [l, u] */
      break;
    }
    default: return luaL_error(L, "wrong number of arguments");
  }
  return 1;
}


static int _lfunc_sexe_math_randomseed (lua_State *L) {
  srand(luaL_checkunsigned(L, 1));
  (void)rand(); /* discard first value to avoid undesirable correlations */
  return 0;
}





static int _lfunc_sexe_math_clamp(sexe_t *L)
{
  double d = lua_tonumber(L, 1);
  double min = lua_tonumber(L, 2);
  double max = lua_tonumber(L, 3);
  if (d > max) d = max;
  if (d < min) d = min;
  lua_pushnumber(L, d);
  return 1; /* math 'clamp' of arg */
}


static int _lfunc_sexe_math_mod(sexe_t *L)
{
  double d = lua_tonumber(L, 1);
  double m = lua_tonumber(L, 2);
  if (m == 0) {
    lua_pushnumber(L, 0);
  } else {
    lua_pushnumber(L, (double)((int)d % (int)m));
  }
  return 1; /* math 'mod' of arg */
}



static int _lfunc_sexe_math_sign(sexe_t *L)
{
  double d = lua_tonumber(L, 1);
  double ret_num;

  if (d == 0) {
    lua_pushnumber(L, d);
  } else {
    lua_pushnumber(L, d > 0 ? 1 : -1);
  }
  return (1); /* (1) math 'sign' of number arg */
}

static const luaL_Reg sexe_math_lib[] = {
  {"abs",   _lfunc_sexe_math_abs},
  {"acos",  _lfunc_sexe_math_acos},
  {"asin",  _lfunc_sexe_math_asin},
  {"atan2", _lfunc_sexe_math_atan2},
  {"atan",  _lfunc_sexe_math_atan},
  {"ceil",  _lfunc_sexe_math_ceil},
  {"clamp", _lfunc_sexe_math_clamp},
  {"cosh",   _lfunc_sexe_math_cosh},
  {"cos",   _lfunc_sexe_math_cos},
  {"deg",   _lfunc_sexe_math_deg},
  {"exp",   _lfunc_sexe_math_exp},
  {"floor", lfunc_sexe_math_floor},
  {"fmod",   _lfunc_sexe_math_fmod},
  {"frexp", _lfunc_sexe_math_frexp},
  {"ldexp", _lfunc_sexe_math_ldexp},
#if defined(LUA_COMPAT_LOG10)
  {"log10", _lfunc_sexe_math_log10},
#endif
  {"log",   _lfunc_sexe_math_log},
  {"max",   _lfunc_sexe_math_max},
  {"min",   _lfunc_sexe_math_min},
  {"mod", _lfunc_sexe_math_mod},
  {"modf",   _lfunc_sexe_math_modf},
  {"pow",   _lfunc_sexe_math_pow},
  {"rad",   _lfunc_sexe_math_rad},
  {"random",     _lfunc_sexe_math_random},
  {"randomseed", _lfunc_sexe_math_randomseed},
  {"sign", _lfunc_sexe_math_sign},
  {"sinh",   _lfunc_sexe_math_sinh},
  {"sin",   _lfunc_sexe_math_sin},
  {"sqrt",  _lfunc_sexe_math_sqrt},
  {"tanh",   _lfunc_sexe_math_tanh},
  {"tan",   _lfunc_sexe_math_tan},
  {NULL, NULL}
};

LUAMOD_API int luaopen_math (lua_State *L) 
{
  luaL_newlib(L, sexe_math_lib);
  lua_pushnumber(L, PI);
  lua_setfield(L, -2, "pi");
  lua_pushnumber(L, HUGE_VAL);
  lua_setfield(L, -2, "huge");
  return 1;
}

