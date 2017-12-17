
noinst_LIBRARIES = libsecp256k1.a

noinst_PROGRAMS = test_secp256k1

TESTS = test_secp256k1

libsecp256k1_a_CFLAGS = \
	-I$(srcdir)/include \
	-DUSE_NUM_GMP -DUSE_FIELD_INV_NUM -DUSE_SCALAR_INV_NUM \
	-DUSE_FIELD_10X26 \
	-DUSE_SCALAR_8X32 \
	-DENABLE_MODULE_RECOVERY

libsecp256k1_a_CPPFLAGS = \
	-DSECP256K1_BUILD

libsecp256k1_a_SOURCES = \
	$(srcdir)/secp256k1.c \
	$(srcdir)/secp256k1_aux.c

test_secp256k1_SOURCES = \
	test/test_secp256k1.c

test_secp256k1_CFLAGS = \
	-I$(srcdir)/include -DVERIFY \
	-DUSE_NUM_GMP -DUSE_FIELD_INV_NUM -DUSE_SCALAR_INV_NUM \
	-DUSE_FIELD_10X26 \
	-DUSE_SCALAR_8X32 \
	-DENABLE_MODULE_RECOVERY

test_secp256k1_CPPFLAGS = \
	-DSECP256K1_BUILD


