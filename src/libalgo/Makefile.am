
noinst_LIBRARIES = libalgo.a

common_includes = \
	$(srcdir)/blake2.h \
	$(srcdir)/blake2s.h \
	$(srcdir)/groestl.h \
	$(srcdir)/hmac_sha512.h \
	$(srcdir)/keccak.h \
	$(srcdir)/qubit.h \
	$(srcdir)/scrypt.h \
	$(srcdir)/sha512.h \
	$(srcdir)/skein.h \
	$(srcdir)/sph_blake.h \
	$(srcdir)/sph_bmw.h \
	$(srcdir)/sph_cubehash.h \
	$(srcdir)/sph_echo.h \
	$(srcdir)/sph_groestl.h \
	$(srcdir)/sph_jh.h \
	$(srcdir)/sph_keccak.h \
	$(srcdir)/sph_luffa.h \
	$(srcdir)/sph_shavite.h \
	$(srcdir)/sph_simd.h \
	$(srcdir)/sph_skein.h \
	$(srcdir)/sph_types.h \
	$(srcdir)/x11.h

common_sources = \
	$(srcdir)/aes_helper.c \
	$(srcdir)/blake2.c \
	$(srcdir)/blake2s.c \
	$(srcdir)/groestl.c \
	$(srcdir)/hmac_sha512.cpp \
	$(srcdir)/keccak.c \
	$(srcdir)/qubit.c \
	$(srcdir)/scrypt.c \
	$(srcdir)/sha512.cpp \
	$(srcdir)/skein.c \
	$(srcdir)/sph_blake.c \
	$(srcdir)/sph_bmw.c \
	$(srcdir)/sph_cubehash.c \
	$(srcdir)/sph_echo.c \
	$(srcdir)/sph_groestl.c \
	$(srcdir)/sph_jh.c \
	$(srcdir)/sph_keccak.c \
	$(srcdir)/sph_luffa.c \
	$(srcdir)/sph_shavite.c \
	$(srcdir)/sph_simd.c \
	$(srcdir)/sph_skein.c \
	$(srcdir)/x11.c

libalgo_a_SOURCES = \
	$(common_sources) \
	$(common_includes)

libalgo_a_CPPFLAGS = \
	-std=c++11

