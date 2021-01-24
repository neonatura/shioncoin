

#ifndef __SEXE__SEXE_BIN_H__
#define __SEXE__SEXE_BIN_H__

#include <stdio.h>
#include "lobject.h"
#include "lzio.h"
#include "lparser.h"


/* official release format version. */
#define SEXE_FORMAT 0	
/* data to catch conversion errors */
#define SEXE_TAIL "\x19\x93\r\n\x1a\n"
/* size in bytes of header of binary files */
#define SEXE_HEADERSIZE sizeof(sexe_mod_t)


#define VOID(p)		((const void*)(p))

#define SS(x)	((x==1)?"":"s")
#define S(x)	(int)(x),SS(x)

#define api_incr_top(L) \
  L->top++

typedef struct DumpState {
 lua_State* L;
 lua_Writer writer;
 void* data;
 int strip;
 int status;
} DumpState;

struct SParser {  /* data to `f_parser' */
  ZIO *z;
  Mbuffer buff;  /* dynamic structure used by the scanner */
  Dyndata dyd;  /* dynamic structures used by the parser */
  const char *mode;
  const char *name;
};

typedef struct LoadS {
  const char *s;
  size_t size;
} LoadS;

typedef struct LoadF {
  int n;  /* number of pre-read characters */
  FILE *f;  /* file being read */
  char buff[LUAL_BUFFERSIZE];  /* area for reading file */
} LoadF;

typedef struct {
 lua_State* L;
 ZIO* Z;
 Mbuffer* b;
 const char* name;
} LoadState;

/** Execute a protected parser.  */
static inline void checkmode (lua_State *L, const char *mode, const char *x) {
  if (mode && strchr(mode, x[0]) == NULL) {
    luaO_pushfstring(L, 
        "attempt to load a %s chunk (mode is " LUA_QS ")", x, mode);
    luaD_throw(L, LUA_ERRSYNTAX);
  }
}

Proto *sexe_undump(lua_State* L, ZIO* Z, Mbuffer* buff, const char* name);


void DumpBlock(const void* b, size_t size, DumpState* D);
void DumpString(const TString* s, DumpState* D);

int sexe_load(lua_State *L, lua_Reader reader, void *data, const char *chunkname, const char *mode);

int sexe_loadmem(lua_State *L, char *name, shbuf_t *buff);

void SexeLoadHeader(LoadState* S);

int sexe_dump (lua_State *L, lua_Writer writer, void *data); 



#endif /* ndef __SEXE__SEXE_BIN_H__ */
