
noinst_LIBRARIES = libcoin.a

common_includes = \
	$(srcdir)/addrman.h \
	$(srcdir)/allocators.h \
	$(srcdir)/bech32.h \
	$(srcdir)/bignum.h \
	$(srcdir)/common.h \
	$(srcdir)/compat.h \
	$(srcdir)/netbase.h \
	$(srcdir)/protocol.h \
	$(srcdir)/strlcpy.h \
	$(srcdir)/sync.h \
	$(srcdir)/uint256.h \
	$(srcdir)/serialize.h

common_sources = \
	$(srcdir)/addrman.cpp \
	$(srcdir)/bech32.cpp \
	$(srcdir)/netbase.cpp \
	$(srcdir)/sync.cpp

libcoin_a_SOURCES = \
	$(common_sources) \
	$(common_includes)

libcoin_a_CPPFLAGS = \
	-std=c++11

