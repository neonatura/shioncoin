

#ifdef CUTEST
#define api_check(L,_e) \
  _TEST(_e)
#define api_checknelems(L,n) \
  api_check((n) < (L->top - L->ci->func))
#define api_checkvalidindex(L, i) \
  api_check((i) != luaO_nilobject)
#else
#define api_check(L,_e)
#define api_checknelems(L,n)
#define api_checkvalidindex(L, i)
#endif

