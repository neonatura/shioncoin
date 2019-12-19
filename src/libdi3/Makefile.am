
noinst_LIBRARIES = libdi3.a
TESTS = test_di3
check_PROGRAMS = test_di3

common_includes = \
	$(srcdir)/di3.h

pqclean_dilithium_includes = \
	$(srcdir)/pqclean_dilithium3_clean/api.h \
	$(srcdir)/pqclean_dilithium3_clean/ntt.h \
	$(srcdir)/pqclean_dilithium3_clean/packing.h \
	$(srcdir)/pqclean_dilithium3_clean/params.h \
	$(srcdir)/pqclean_dilithium3_clean/poly.h \
	$(srcdir)/pqclean_dilithium3_clean/polyvec.h \
	$(srcdir)/pqclean_dilithium3_clean/reduce.h \
	$(srcdir)/pqclean_dilithium3_clean/rounding.h \
	$(srcdir)/pqclean_dilithium3_clean/sign.h \
	$(srcdir)/pqclean_dilithium3_clean/symmetric.h \
	$(srcdir)/pqclean_dilithium3_clean/sha3.h \
	$(srcdir)/pqclean_dilithium3_clean/fips202.h

common_sources = \
	$(srcdir)/di3_derive.c \
	$(srcdir)/di3_keypair.c \
	$(srcdir)/di3_sign.c \
	$(srcdir)/di3_verify.c

pqclean_dilithium_sources = \
	$(srcdir)/pqclean_dilithium3_clean/ntt.c \
	$(srcdir)/pqclean_dilithium3_clean/packing.c \
	$(srcdir)/pqclean_dilithium3_clean/poly.c \
	$(srcdir)/pqclean_dilithium3_clean/polyvec.c \
	$(srcdir)/pqclean_dilithium3_clean/reduce.c \
	$(srcdir)/pqclean_dilithium3_clean/rounding.c \
	$(srcdir)/pqclean_dilithium3_clean/sign.c \
	$(srcdir)/pqclean_dilithium3_clean/symmetric.c \
	$(srcdir)/pqclean_dilithium3_clean/sha3_c.c

libdi3_a_SOURCES = \
	$(common_sources) \
	$(pqclean_dilithium_sources) \
	$(common_includes) \
	$(pqclean_dilithium_includes)

libdi3_a_CFLAGS = \
	-I$(srcdir)/pqclean_dilithium3_clean \
	-DDI3_LIBRARY \
	-std=gnu11

test_di3_SOURCES = \
	test_di3.c \
	$(common_sources) \
	$(pqclean_dilithium_sources) \
	$(common_includes) \
	$(pqclean_dilithium_includes)

test_di3_CFLAGS = \
	-I$(srcdir)/pqclean_dilithium3_clean \
	-DDI3_LIBRARY \
	-std=gnu11

