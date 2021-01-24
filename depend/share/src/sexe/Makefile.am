AUTOMAKE_OPTIONS = foreign

ld_flags = -lm -ldl -version-info @version_info@

common_includes = \
	lapi.h \
	lauxlib.h \
	lcode.h \
	lctype.h \
	ldebug.h \
	ldo.h \
	lfunc.h \
	lgc.h \
	llex.h \
	llimits.h \
	lmem.h \
	lobject.h \
	lopcodes.h \
	lparser.h \
	lstate.h \
	lstring.h \
	ltable.h \
	ltm.h \
	luaconf.h \
	lualib.h \
	lvm.h \
	lzio.h \
	sexe_bin.h \
	sexe_var.h \
	sexe_event.h \
	sexe_io.h \
	sys/sexe_sys.h

common_sources = \
	lapi.c \
	lauxlib.c \
	lbaselib.c \
	lbitlib.c \
	lcode.c \
	lcorolib.c \
	lctype.c \
	ldblib.c \
	ldebug.c \
	ldo.c \
	lfunc.c \
	lgc.c \
	linit.c \
	llex.c \
	lmem.c \
	loadlib.c \
	lobject.c \
	lopcodes.c \
	lparser.c \
	lstate.c \
	lstring.c \
	ltable.c \
	ltablib.c \
	ltm.c \
	lvm.c \
	lzio.c \
	sexe_bin.c \
	sexe_var.c \
	sexe_table.c \
	sexe_event.c \
	sexe_io.c \
	sys/sexe_sys_string.c \
	sys/sexe_sys_math.c \
	sys/sexe_sys_time.c \
	sys/sexe_sys_crypt.c \
	sys/sexe_sys_event.c \
	sys/sexe_sys_io.c \
	$(builddir)/sexe.c

lib_LIBRARIES = libshare_sexe.a
bin_PROGRAMS = sx sxc readsexe static_sx static_sxc
include_HEADERS = sexe.h sexe_lua.h sexe_conf.h
lib_LTLIBRARIES = libshare_sexe.la
#TESTS = test_sexe.sh

sx_SOURCES = $(common_includes) $(common_sources) sexe_interp.c
sx_LDADD = $(top_builddir)/src/share-lib/libshare.la
sx_CFLAGS= -Wall -DSEXELIB \
	-I$(top_srcdir)/src/share-lib
sx_LDFLAGS = $(ld_flags)

static_sx_SOURCES = $(common_includes) $(common_sources) sexe_interp.c
static_sx_LDADD = $(top_builddir)/src/share-lib/libshare.a
static_sx_CFLAGS= -Wall -DSEXELIB \
	-I$(top_srcdir)/src/share-lib
static_sx_LDFLAGS = $(ld_flags)

sxc_SOURCES = $(common_includes) $(common_sources) sexe_compile.c
sxc_LDADD = $(top_builddir)/src/share-lib/libshare.la
sxc_CFLAGS= -Wall -DSEXELIB \
	-I$(top_srcdir)/src/share-lib
sxc_LDFLAGS = $(ld_flags)

static_sxc_SOURCES = $(common_includes) $(common_sources) sexe_compile.c
static_sxc_LDADD = $(top_builddir)/src/share-lib/libshare.a
static_sxc_CFLAGS= -Wall -DSEXELIB \
	-I$(top_srcdir)/src/share-lib
static_sxc_LDFLAGS = $(ld_flags)

readsexe_SOURCES = $(common_includes) $(common_sources) sexe_symbol.c
readsexe_LDADD = $(top_builddir)/src/share-lib/libshare.la
readsexe_CFLAGS = -Wall -DSEXELIB \
	-I$(top_srcdir)/src/share-lib
readsexe_LDFLAGS = $(ld_flags)

libshare_sexe_a_SOURCES = $(common_includes) $(common_sources) sexe_api.c
libshare_sexe_a_LIBADD = $(top_builddir)/src/share-lib/libshare.a
libshare_sexe_a_CFLAGS = -Wall -DSEXELIB -I$(top_srcdir)/src/share-lib
libshare_sexe_a_LDFLAGS = $(ld_flags)

libshare_sexe_la_SOURCES = $(common_includes) $(common_sources) sexe_api.c
libshare_sexe_la_LIBADD = $(top_builddir)/src/share-lib/libshare.la
libshare_sexe_la_CFLAGS = -Wall -DSEXELIB \
	-I$(top_srcdir)/src/share-lib
libshare_sexe_la_LDFLAGS = $(ld_flags)

if FREEBSD
sx_CFLAGS += -DLUA_USE_POSIX -DLUA_USE_DLOPEN -Wl,-E
sxc_CFLAGS += -DLUA_USE_POSIX -DLUA_USE_DLOPEN -Wl,-E
endif

if LINUX
sx_CFLAGS += -DLUA_USE_LINUX -Wl,-E
sxc_CFLAGS += -DLUA_USE_LINUX -Wl,-E 
readsexe_CFLAGS += -DLUA_USE_LINUX
libshare_sexe_a_CFLAGS += -DLUA_USE_LINUX
libshare_sexe_la_CFLAGS += -DLUA_USE_LINUX
endif

if DEBUG
sx_CFLAGS += -g
sxc_CFLAGS += -g
endif

if !X86_64
sx_CFLAGS += -D__i386__
sxc_CFLAGS += -D__i386__
readsexe_CFLAGS += -D__i386__
libshare_sexe_la_CFLAGS += -D__i386__ 
else
sx_CFLAGS += -D__x86_64
sxc_CFLAGS += -D__x86_64
readsexe_CFLAGS += -D__x86_64
libshare_sexe_a_CFLAGS += -D__x86_64
libshare_sexe_la_CFLAGS += -D__x86_64
endif

test_sexe.sh: test_sexe.sx

$(builddir)/libshare.so.5:
	ln -sf $(top_builddir)/src/share-lib/.libs/libshare.so.5 $(builddir)/libshare.so.5

test_sexe.sx: sx $(builddir)/libshare.so.5
	./sxc -g -o test_sexe.sx test_sexe.lua

lapi.o: lapi.c luaconf.h lapi.h llimits.h lstate.h lobject.h ltm.h \
 lzio.h lmem.h ldebug.h ldo.h lfunc.h lgc.h lstring.h ltable.h \
 lvm.h
lauxlib.o: lauxlib.c luaconf.h lauxlib.h
lbaselib.o: lbaselib.c luaconf.h lauxlib.h lualib.h
lbitlib.o: lbitlib.c luaconf.h lauxlib.h lualib.h
lcode.o: lcode.c luaconf.h lcode.h llex.h lobject.h llimits.h \
 lzio.h lmem.h lopcodes.h lparser.h ldebug.h lstate.h ltm.h ldo.h lgc.h \
 lstring.h ltable.h lvm.h
lcorolib.o: lcorolib.c luaconf.h lauxlib.h lualib.h
lctype.o: lctype.c lctype.h luaconf.h llimits.h
ldblib.o: ldblib.c luaconf.h lauxlib.h lualib.h
ldebug.o: ldebug.c luaconf.h lapi.h llimits.h lstate.h lobject.h \
 ltm.h lzio.h lmem.h lcode.h llex.h lopcodes.h lparser.h ldebug.h ldo.h \
 lfunc.h lstring.h lgc.h ltable.h lvm.h
ldo.o: ldo.c luaconf.h lapi.h llimits.h lstate.h lobject.h ltm.h \
 lzio.h lmem.h ldebug.h ldo.h lfunc.h lgc.h lopcodes.h lparser.h \
 lstring.h ltable.h lvm.h
lfunc.o: lfunc.c luaconf.h lfunc.h lobject.h llimits.h lgc.h \
 lstate.h ltm.h lzio.h lmem.h
lgc.o: lgc.c luaconf.h ldebug.h lstate.h lobject.h llimits.h ltm.h \
 lzio.h lmem.h ldo.h lfunc.h lgc.h lstring.h ltable.h
linit.o: linit.c luaconf.h lualib.h lauxlib.h
llex.o: llex.c luaconf.h lctype.h llimits.h ldo.h lobject.h \
 lstate.h ltm.h lzio.h lmem.h llex.h lparser.h lstring.h lgc.h ltable.h
lmem.o: lmem.c luaconf.h ldebug.h lstate.h lobject.h llimits.h \
 ltm.h lzio.h lmem.h ldo.h lgc.h
loadlib.o: loadlib.c luaconf.h lauxlib.h lualib.h
lobject.o: lobject.c luaconf.h lctype.h llimits.h ldebug.h lstate.h \
 lobject.h ltm.h lzio.h lmem.h ldo.h lstring.h lgc.h lvm.h
lopcodes.o: lopcodes.c lopcodes.h llimits.h luaconf.h
lparser.o: lparser.c luaconf.h lcode.h llex.h lobject.h llimits.h \
 lzio.h lmem.h lopcodes.h lparser.h ldebug.h lstate.h ltm.h ldo.h lfunc.h \
 lstring.h lgc.h ltable.h
lstate.o: lstate.c luaconf.h lapi.h llimits.h lstate.h lobject.h \
 ltm.h lzio.h lmem.h ldebug.h ldo.h lfunc.h lgc.h llex.h lstring.h \
 ltable.h
lstring.o: lstring.c luaconf.h lmem.h llimits.h lobject.h lstate.h \
 ltm.h lzio.h lstring.h lgc.h
ltable.o: ltable.c luaconf.h ldebug.h lstate.h lobject.h llimits.h \
 ltm.h lzio.h lmem.h ldo.h lgc.h lstring.h ltable.h lvm.h
ltablib.o: ltablib.c luaconf.h lauxlib.h lualib.h
ltm.o: ltm.c luaconf.h lobject.h llimits.h lstate.h ltm.h lzio.h \
 lmem.h lstring.h lgc.h ltable.h
lvm.o: lvm.c luaconf.h ldebug.h lstate.h lobject.h llimits.h ltm.h \
 lzio.h lmem.h ldo.h lfunc.h lgc.h lopcodes.h lstring.h ltable.h lvm.h
lzio.o: lzio.c luaconf.h llimits.h lmem.h lstate.h lobject.h ltm.h \
 lzio.h
