/*
** $Id: luac.c,v 1.69 2011/11/29 17:46:33 lhf Exp $
** Lua compiler (saves bytecodes to files; also list bytecodes)
** See Copyright Notice in lua.h
*/

#include <share.h>

#include "sexe.h"
#include "lauxlib.h"
#include "lobject.h"
#include "lstate.h"
#include "lundump.h"
#include "lopcodes.h"


static char *process_path;
char process_name[PATH_MAX+1];
static char app_name[PATH_MAX+1];

#define getfuncline(f,pc)	(((f)->lineinfo) ? (f)->lineinfo[pc] : 0)
#define UPVALNAME(x) ((f->upvalues[x].name) ? getstr(f->upvalues[x].name) : "-")
#define IS(s)	(strcmp(argv[i],s)==0)
#define FUNCTION "(function()end)();"


static void fatal(const char* message)
{
 fprintf(stderr,"%s: %s\n", process_name, message);
 exit(EXIT_FAILURE);
}

static void cannot(const char* what)
{
 fprintf(stderr,"%s: cannot %s %s: %s\n", process_name,
     what, process_path, strerror(errno));
 exit(EXIT_FAILURE);
}

void print_process_usage(void)
{

  printf (
      "Usage: %s [OPTION] [<files>]\n"
      "List symbols from SEXE bytecode files."
      "\n"
      "Options:\n"
      "\t-h | --help\t\tShows program usage instructions.\n"
      "\t-v | --version\t\tShows program version.\n"
      "\t-V | --verbose\t\tShow verbose information.\n"
//      "\t-f | --fs <name>\tUse application \"<name>\"'s sharefs partition.\n"
      "\n"
      "Files:\n"
      "\tOne or more files which contain Lua source code or pre-compiled SEXE bytecode.\n"
      "\n"
      "Visit 'http://sharelib.net/libshare/' for libshare API documentation.\n",
      process_name);
}

int print_process_version(void)
{

  printf (
      "%s version %-2.2f\n"
      "\n"
      "Copyright 2014 Neo Natura\n"
      "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n",
      process_name, SEXE_VERSION);

  return (0);
}




static const char* reader(lua_State *L, void *ud, size_t *size)
{
 UNUSED(L);
 if ((*(int*)ud)--)
 {
  *size=sizeof(FUNCTION)-1;
  return FUNCTION;
 }
 else
 {
  *size=0;
  return NULL;
 }
}

#define toproto(L,i) getproto(L->top+(i))

static const Proto* combine(lua_State* L, int n)
{
  Proto* f;
  char buf[4096];
  int i=n;

  if (n==1)
    return toproto(L,-1);

  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf)-1, "=(%s)", process_name);
  if (sexe_load(L, reader, &i, buf, NULL)!=LUA_OK) 
    fatal(lua_tostring(L,-1));

  f=toproto(L,-1);
  for (i=0; i<n; i++)
  {
    f->p[i]=toproto(L,i-n-1);
    if (f->p[i]->sizeupvalues>0) f->p[i]->upvalues[0].instack=0;
  }
  f->sizelineinfo=0;
  return f;
}

static int writer(lua_State* L, const void* p, size_t size, void* u)
{
 UNUSED(L);
 return (fwrite(p,size,1,(FILE*)u)!=1) && (size!=0);
}

void SexePrintHeader(const Proto* f)
{
 const char* s=f->source ? getstr(f->source) : "=?";

 if (*s=='@' || *s=='=' || *s == '#')
  s++;
 else if (*s==SEXE_SIGNATURE[0])
  s="(bstring)";
 else
  s="(string)";

 printf("\n%s <%s:%d,%d> (%d instruction%s at %p)\n",
 	(f->linedefined==0)?"main":"function",s,
	f->linedefined,f->lastlinedefined,
	S(f->sizecode),VOID(f));
 printf("%d%s param%s, %d slot%s, %d upvalue%s, ",
	(int)(f->numparams),f->is_vararg?"+":"",SS(f->numparams),
	S(f->maxstacksize),S(f->sizeupvalues));
 printf("%d local%s, %d constant%s, %d function%s\n",
	S(f->sizelocvars),S(f->sizek),S(f->sizep));
}

static void PrintString(const TString* ts)
{
 const char* s=getstr(ts);
 size_t i,n=ts->tsv.len;
 printf("%c",'"');
 for (i=0; i<n; i++)
 {
  int c=(int)(unsigned char)s[i];
  switch (c)
  {
   case '"':  printf("\\\""); break;
   case '\\': printf("\\\\"); break;
   case '\a': printf("\\a"); break;
   case '\b': printf("\\b"); break;
   case '\f': printf("\\f"); break;
   case '\n': printf("\\n"); break;
   case '\r': printf("\\r"); break;
   case '\t': printf("\\t"); break;
   case '\v': printf("\\v"); break;
   default:	if (isprint(c))
   			printf("%c",c);
		else
			printf("\\%03d",c);
  }
 }
 printf("%c",'"');
}

static void PrintConstant(const Proto* f, int i)
{
 const TValue* o=&f->k[i];
 switch (ttype(o))
 {
  case LUA_TNIL:
	printf("nil");
	break;
  case LUA_TBOOLEAN:
	printf(bvalue(o) ? "true" : "false");
	break;
  case LUA_TNUMBER:
	printf(LUA_NUMBER_FMT,nvalue(o));
	break;
  case LUA_TSTRING:
	PrintString(rawtsvalue(o));
	break;
  default:				/* cannot happen */
	printf("? type=%d",ttype(o));
	break;
 }
}

static void PrintDebug(const Proto* f)
{
  int i,n;

  n=f->sizek;
  if (n) {
    printf("constants (%d) for %p:\n",n,VOID(f));
    for (i=0; i<n; i++)
    {
      printf("\t%d\t",i+1);
      PrintConstant(f,i);
      printf("\n");
    }
  }

  n=f->sizelocvars;
  if (n) {
    printf("locals (%d) for %p:\n",n,VOID(f));
    for (i=0; i<n; i++)
    {
      printf("\t%d\t%s\t%d\t%d\n",
          i,getstr(f->locvars[i].varname),f->locvars[i].startpc+1,f->locvars[i].endpc+1);
    }
  }

  n=f->sizeupvalues;
  if (n) {
    printf("upvalues (%d) for %p:\n",n,VOID(f));
    for (i=0; i<n; i++)
    {
      printf("\t%d\t%s\t%d\t%d\n",
          i,UPVALNAME(i),f->upvalues[i].instack,f->upvalues[i].idx);
    }
  }
}

void SexePrintFunction(const Proto* f, int full)
{
 int i,n=f->sizep;
 SexePrintHeader(f);
 SexePrintCode(f);
 PrintDebug(f);
 //if (full) PrintDebug(f);
 for (i=0; i<n; i++) SexePrintFunction(f->p[i],full);
}

static int pmain(lua_State* L)
{
  int argc=(int)lua_tointeger(L,1);
  char** argv=(char**)lua_touserdata(L,2);
  const Proto* f;
  int tot;
  int i;

  if (!lua_checkstack(L,argc)) fatal("too many input files");

  tot = 0;
  for (i=1; i<argc; i++)
  {
    if (argv[i][0] == '-') continue;
    if (sexe_loadfile(L,argv[i], NULL)!=LUA_OK) fatal(lua_tostring(L,-1));
    tot++;
  }
  f=combine(L, tot);

  SexePrintFunction(f, (run_flags & RUNF_VERBOSE));

  return (0);
}

int main(int argc, char* argv[])
{
 lua_State* L;
 int i;

  process_path = argv[0];
  strncpy(process_name, shfs_app_name(process_path), sizeof(process_name) - 1);

  run_flags |= RUNF_LOCAL;
  for (i = 1; i < argc; i++) {
    if (IS("-v") || IS("--version")) {
      print_process_version();
      return (EXIT_SUCCESS);
    }
    if (IS("-h") || IS("--help")) {
      print_process_usage();
      return (EXIT_SUCCESS);
    }
    if (IS("-V") || IS("--verbose")) {
      run_flags |= RUNF_VERBOSE;
      continue;
    }
    if (IS("-f") || IS("--fs")) {
      run_flags &= ~RUNF_LOCAL;
      if (i + 1 < argc && argv[i+1][0] != '-') {
        i++;
        strncpy(app_name, argv[i], sizeof(app_name) - 1);
      }
      continue;
    }

    if (argv[i][0] == '-') {
      printf("Warning: Invalid command-line option \"%s\".\n", argv[i]);
      continue;
    }

    /* source file specification. */
    run_flags |= RUNF_INPUT;
  }

  if (!(run_flags & RUNF_INPUT)) {
    printf("Error: no input file(s) specified.\n");
    exit(1);
  }

 L=luaL_newstate();
 if (L==NULL) fatal("cannot create state: not enough memory");
 lua_pushcfunction(L,&pmain);
 lua_pushinteger(L,argc);
 lua_pushlightuserdata(L,argv);
 if (lua_pcall(L,2,0,0)!=LUA_OK) fatal(lua_tostring(L,-1));
 lua_close(L);

 return EXIT_SUCCESS;
}


#define UPVALNAME(x) ((f->upvalues[x].name) ? getstr(f->upvalues[x].name) : "-")
#define MYK(x)		(-1-(x))

static void PrintCode(const Proto* f)
{
 const Instruction* code=f->code;
 int pc,n=f->sizecode;
 for (pc=0; pc<n; pc++)
 {
  Instruction i=code[pc];
  OpCode o=GET_OPCODE(i);
  int a=GETARG_A(i);
  int b=GETARG_B(i);
  int c=GETARG_C(i);
  int ax=GETARG_Ax(i);
  int bx=GETARG_Bx(i);
  int sbx=GETARG_sBx(i);
  int line=getfuncline(f,pc);
  printf("\t%d\t",pc+1);
  if (line>0) printf("[%d]\t",line); else printf("[-]\t");
  printf("%-9s\t",luaP_opnames[o]);
  switch (getOpMode(o))
  {
   case iABC:
    printf("%d",a);
    if (getBMode(o)!=OpArgN) printf(" %d",ISK(b) ? (MYK(INDEXK(b))) : b);
    if (getCMode(o)!=OpArgN) printf(" %d",ISK(c) ? (MYK(INDEXK(c))) : c);
    break;
   case iABx:
    printf("%d",a);
    if (getBMode(o)==OpArgK) printf(" %d",MYK(bx));
    if (getBMode(o)==OpArgU) printf(" %d",bx);
    break;
   case iAsBx:
    printf("%d %d",a,sbx);
    break;
   case iAx:
    printf("%d",MYK(ax));
    break;
  }
  switch (o)
  {
   case OP_LOADK:
    printf("\t; "); PrintConstant(f,bx);
    break;
   case OP_GETUPVAL:
   case OP_SETUPVAL:
    printf("\t; %s",UPVALNAME(b));
    break;
   case OP_GETTABUP:
    printf("\t; %s",UPVALNAME(b));
    if (ISK(c)) { printf(" "); PrintConstant(f,INDEXK(c)); }
    break;
   case OP_SETTABUP:
    printf("\t; %s",UPVALNAME(a));
    if (ISK(b)) { printf(" "); PrintConstant(f,INDEXK(b)); }
    if (ISK(c)) { printf(" "); PrintConstant(f,INDEXK(c)); }
    break;
   case OP_GETTABLE:
   case OP_SELF:
    if (ISK(c)) { printf("\t; "); PrintConstant(f,INDEXK(c)); }
    break;
   case OP_SETTABLE:
   case OP_ADD:
   case OP_SUB:
   case OP_MUL:
   case OP_DIV:
   case OP_POW:
   case OP_EQ:
   case OP_LT:
   case OP_LE:
    if (ISK(b) || ISK(c))
    {
     printf("\t; ");
     if (ISK(b)) PrintConstant(f,INDEXK(b)); else printf("-");
     printf(" ");
     if (ISK(c)) PrintConstant(f,INDEXK(c)); else printf("-");
    }
    break;
   case OP_JMP:
   case OP_FORLOOP:
   case OP_FORPREP:
   case OP_TFORLOOP:
    printf("\t; to %d",sbx+pc+2);
    break;
   case OP_CLOSURE:
    printf("\t; %p",VOID(f->p[bx]));
    break;
   case OP_SETLIST:
    if (c==0) printf("\t; %d",(int)code[++pc]); else printf("\t; %d",c);
    break;
   case OP_EXTRAARG:
    printf("\t; "); PrintConstant(f,ax);
    break;
   default:
    break;
  }
  printf("\n");
 }
}


static void PrintHeader(const Proto* f)
{
 const char* s=f->source ? getstr(f->source) : "=?";
 if (*s=='@' || *s=='=')
  s++;
 else if (*s==LUA_SIGNATURE[0])
  s="(bstring)";
 else
  s="(string)";
 printf("\n%s <%s:%d,%d> (%d instruction%s at %p)\n",
 	(f->linedefined==0)?"main":"function",s,
	f->linedefined,f->lastlinedefined,
	S(f->sizecode),VOID(f));
 printf("%d%s param%s, %d slot%s, %d upvalue%s, ",
	(int)(f->numparams),f->is_vararg?"+":"",SS(f->numparams),
	S(f->maxstacksize),S(f->sizeupvalues));
 printf("%d local%s, %d constant%s, %d function%s\n",
	S(f->sizelocvars),S(f->sizek),S(f->sizep));
}

void SexePrintCode(const Proto* f)
{
 const Instruction* code=f->code;
 int pc,n=f->sizecode;
 for (pc=0; pc<n; pc++)
 {
  Instruction i=code[pc];
  OpCode o=GET_OPCODE(i);
  int a=GETARG_A(i);
  int b=GETARG_B(i);
  int c=GETARG_C(i);
  int ax=GETARG_Ax(i);
  int bx=GETARG_Bx(i);
  int sbx=GETARG_sBx(i);
  int line=getfuncline(f,pc);
  printf("\t%d\t",pc+1);
  if (line>0) printf("[%d]\t",line); else printf("[-]\t");
  printf("%-9s\t",luaP_opnames[o]);
  switch (getOpMode(o))
  {
   case iABC:
    printf("%d",a);
    if (getBMode(o)!=OpArgN) printf(" %d",ISK(b) ? (MYK(INDEXK(b))) : b);
    if (getCMode(o)!=OpArgN) printf(" %d",ISK(c) ? (MYK(INDEXK(c))) : c);
    break;
   case iABx:
    printf("%d",a);
    if (getBMode(o)==OpArgK) printf(" %d",MYK(bx));
    if (getBMode(o)==OpArgU) printf(" %d",bx);
    break;
   case iAsBx:
    printf("%d %d",a,sbx);
    break;
   case iAx:
    printf("%d",MYK(ax));
    break;
  }
  switch (o)
  {
   case OP_LOADK:
    printf("\t; "); PrintConstant(f,bx);
    break;
   case OP_GETUPVAL:
   case OP_SETUPVAL:
    printf("\t; %s",UPVALNAME(b));
    break;
   case OP_GETTABUP:
    printf("\t; %s",UPVALNAME(b));
    if (ISK(c)) { printf(" "); PrintConstant(f,INDEXK(c)); }
    break;
   case OP_SETTABUP:
    printf("\t; %s",UPVALNAME(a));
    if (ISK(b)) { printf(" "); PrintConstant(f,INDEXK(b)); }
    if (ISK(c)) { printf(" "); PrintConstant(f,INDEXK(c)); }
    break;
   case OP_GETTABLE:
   case OP_SELF:
    if (ISK(c)) { printf("\t; "); PrintConstant(f,INDEXK(c)); }
    break;
   case OP_SETTABLE:
   case OP_ADD:
   case OP_SUB:
   case OP_MUL:
   case OP_DIV:
   case OP_POW:
   case OP_EQ:
   case OP_LT:
   case OP_LE:
    if (ISK(b) || ISK(c))
    {
     printf("\t; ");
     if (ISK(b)) PrintConstant(f,INDEXK(b)); else printf("-");
     printf(" ");
     if (ISK(c)) PrintConstant(f,INDEXK(c)); else printf("-");
    }
    break;
   case OP_JMP:
   case OP_FORLOOP:
   case OP_FORPREP:
   case OP_TFORLOOP:
    printf("\t; to %d",sbx+pc+2);
    break;
   case OP_CLOSURE:
    printf("\t; %p",VOID(f->p[bx]));
    break;
   case OP_SETLIST:
    if (c==0) printf("\t; %d",(int)code[++pc]); else printf("\t; %d",c);
    break;
   case OP_EXTRAARG:
    printf("\t; "); PrintConstant(f,ax);
    break;
   default:
    break;
  }
  printf("\n");
 }
}
