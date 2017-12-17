
bin_PROGRAMS = shc

tool_flags =
if STATIC_LIBSHARE
tool_flags += -I$(LIBSHARE)/include
endif
if DEBUG
tool_flags += -g
else
tool_flags += -O
endif

if STATIC_LIBSHARE
ld_flags = $(LIBSHARE)/src/share-lib/libshare.a
else
ld_flags = -lshare
endif

# main source code for share-coin console client utility program.
console_sources = \
	shcon.c \
	shcon.h \
	shcon_init.c \
	shcon_init.h \
	shcon_term.c \
	shcon_term.h \
	shcon_opt.c \
	shcon_opt.h \
	shcon_log.c \
	shcon_log.h \
	net/net.c \
	net/net.h \
	net/net_conn.c \
	net/net_read.c \
	net/net_write.c \
	key/key.c \
	key/key.h \
	key/key_dat.c \
	key/key_auth.c \
	command/command.c \
	command/command.h \
	command/command_print.c


shc_SOURCES = $(console_sources)
shc_CFLAGS = $(tool_flags) -DSHC_COIN_CLIENT
shc_LDADD = $(ld_flags)

if USDE_SERVICE
bin_PROGRAMS += usde
usde_SOURCES = $(console_sources)
usde_CFLAGS = $(tool_flags) -DUSDE_COIN_CLIENT
usde_LDADD = $(ld_flags)
endif

if EMC2_SERVICE
bin_PROGRAMS += emc2
emc2_SOURCES = $(console_sources)
emc2_CFLAGS = $(tool_flags) -DEMC2_COIN_CLIENT
emc2_LDADD = $(ld_flags)
endif


