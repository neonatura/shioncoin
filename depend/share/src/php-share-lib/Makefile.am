if LIBSHARE_PHP

# use alternate lib dir
EXTENSION_DIR = @PHPLIBDIR@

BUILT_SOURCES = libshare_php_wrap.c php_share_php.h share_php.php
lib_LTLIBRARIES = libshare_php.la
libshare_php_la_LIBADD = $(top_builddir)/src/share-lib/libshare.la
libshare_php_la_SOURCES = $(swig_sources)
libshare_php_la_LDFLAGS = -no-undefined -version-info @version_info@ \
	-shared -shrext .so
libshare_php_la_CFLAGS = -I$(top_srcdir)/src/share-lib/ \
	-I$(top_srcdir)/src/share-lib/mem \
	-I$(top_srcdir)/src/share-lib/net \
	-I$(top_srcdir)/src/share-lib/fs
#TESTS = test_libshare_php.sh test_libshare_fs.sh
TESTS = test_libshare_php.sh

SWIG_CONF = libshare_php.i
SWIG_PHP_OPT = -php 

common_includes = \
	$(top_srcdir)/src/share-lib/share.h \
	$(top_srcdir)/src/share-lib/sherr.h \
	$(top_srcdir)/src/share-lib/share_base.h \
	$(top_srcdir)/src/share-lib/shpeer.h \
	$(top_srcdir)/src/share-lib/shtime.h \
	$(top_srcdir)/src/share-lib/shcrc.h \
	$(top_srcdir)/src/share-lib/mem/shmem.h \
	$(top_srcdir)/src/share-lib/fs/shfs.h \
	$(top_srcdir)/src/share-lib/shpref.h \
  $(top_srcdir)/src/share-lib/net/shnet.h

swig_sources = \
	$(common_includes) \
	php_share_php.h \
	libshare_php_wrap.c

libshare_php_wrap.c: .stamp
share_php.php: .stamp
php_share_php.h: .stamp

.stamp: libshare_php.i
	$(CP) $(top_srcdir)/src/php-share-lib/prebuild/* .
	$(SWIG_PROG) $(SWIG_PHP_OPT) $(SWIG_CONF)
	echo > .stamp

clean-all:
	rm .stamp libshare_php_wrap.c share_php.php php_share_php.h

install-exec-hook:
	$(LN_S) -f $(libdir)/libshare_php.so $(EXTENSION_DIR)/share_php.so

endif
