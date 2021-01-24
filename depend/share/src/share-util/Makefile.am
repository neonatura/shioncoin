AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = \
	-I$(top_srcdir)/src/gnu -I$(top_builddir)/src/gnu \
	-I$(top_srcdir)/src/share-lib \
	-I$(top_srcdir)/src/sexe \
	-I$(srcdir)/cert/x509 \
	-I$(top_srcdir)/src/share-daemon/bits \
	-DHAVE_CONFIG_H -DSHARELIB \
	"-DDOC_DIR=\"$(dist_docdir)\"" \
	"-DPOLARSSL_CONFIG_FILE=\"sharetool.h\""
if DEBUG
AM_CFLAGS += -g3 -Wno-discarded-qualifiers 
if WINDOWS
AM_CFLAGS += -ggdb3
endif
endif

common_INCLUDES = \
	$(top_builddir)/config.h \
	$(top_srcdir)/src/share-lib/share.h \
	$(top_srcdir)/src/share-lib/mem/shmem.h \
	$(top_srcdir)/src/share-lib/sherr.h \
	$(top_srcdir)/src/share-lib/share_base.h \
	$(top_srcdir)/src/share-lib/shpeer.h \
	$(top_srcdir)/src/share-lib/shtime.h \
	$(top_srcdir)/src/share-lib/shpref.h \
	$(top_srcdir)/src/share-lib/shcrc.h \
	$(top_srcdir)/src/share-lib/shfile.h \
	$(top_srcdir)/src/share-lib/fs/shfs.h \
	$(top_srcdir)/src/share-lib/delta/xdelta3.h \
	$(top_srcdir)/src/share-lib/net/shnet.h \
	sharetool.h \
	sharetool_pref.h \
	sharetool_file.h \
	sharetool_rev.h \
	sharetool_fs.h \
	sharetool_info.h \
	sharetool_appinfo.h \
	sharetool_pwd.h \
	sharetool_pkg.h \
	sharetool_cert.h \
	sharetool_db.h \
	sharetool_arch.h \
	sharetool_geo.h \
	sharetool_alg.h \
	file/file_cat.h \
	file/file_import.h \
	file/file_list.h \
	file/file_copy.h \
	file/file_link.h \
	file/file_unlink.h \
	file/file_attr.h \
	file/file_delta.h \
	file/file_diff.h \
	file/file_rev.h \
	file/file_info.h \
	info/info_table.h \
	cert/x509_read.h \
	cert/x509_write.h \
	cert/x509_print.h

common_SOURCES = \
	sharetool.c \
	sharetool_pref.c \
	sharetool_rev.c \
	sharetool_fs.c \
	sharetool_info.c \
	sharetool_appinfo.c \
	sharetool_pwd.c \
	sharetool_pkg.c \
	sharetool_cert.c \
	sharetool_db.c \
	sharetool_arch.c \
	sharetool_geo.c \
	sharetool_alg.c \
	file/file_cat.c \
	file/file_list.c \
	file/file_copy.c \
	file/file_link.c \
	file/file_unlink.c \
	file/file_attr.c \
	file/file_delta.c \
	file/file_diff.c \
	file/file_rev.c \
	file/file_info.c \
	info/info_table.c \
	cert/x509_read.c \
	cert/x509_write.c \
	cert/x509_print.c

x509_SOURCES = \
	$(srcdir)/cert/x509/aes.c \
	$(srcdir)/cert/x509/aes.h \
	$(srcdir)/cert/x509/aesni.c \
	$(srcdir)/cert/x509/aesni.h \
	$(srcdir)/cert/x509/arc4.c \
	$(srcdir)/cert/x509/arc4.h \
	$(srcdir)/cert/x509/asn1.h \
	$(srcdir)/cert/x509/asn1parse.c \
	$(srcdir)/cert/x509/asn1write.c \
	$(srcdir)/cert/x509/asn1write.h \
	$(srcdir)/cert/x509/base64.c \
	$(srcdir)/cert/x509/base64.h \
	$(srcdir)/cert/x509/blowfish.c \
	$(srcdir)/cert/x509/blowfish.h \
	$(srcdir)/cert/x509/camellia.c \
	$(srcdir)/cert/x509/camellia.h \
	$(srcdir)/cert/x509/ccm.c \
	$(srcdir)/cert/x509/ccm.h \
	$(srcdir)/cert/x509/certs.c \
	$(srcdir)/cert/x509/certs.h \
	$(srcdir)/cert/x509/check_config.h \
	$(srcdir)/cert/x509/cipher.c \
	$(srcdir)/cert/x509/cipher.h \
	$(srcdir)/cert/x509/cipher_wrap.c \
	$(srcdir)/cert/x509/cipher_wrap.h \
	$(srcdir)/cert/x509/compat-1.2.h \
	$(srcdir)/cert/x509/config.h \
	$(srcdir)/cert/x509/ctr_drbg.c \
	$(srcdir)/cert/x509/ctr_drbg.h \
	$(srcdir)/cert/x509/debug.c \
	$(srcdir)/cert/x509/debug.h \
	$(srcdir)/cert/x509/des.c \
	$(srcdir)/cert/x509/des.h \
	$(srcdir)/cert/x509/dhm.c \
	$(srcdir)/cert/x509/dhm.h \
	$(srcdir)/cert/x509/ecdh.c \
	$(srcdir)/cert/x509/ecdh.h \
	$(srcdir)/cert/x509/ecdsa.c \
	$(srcdir)/cert/x509/ecdsa.h \
	$(srcdir)/cert/x509/ecp.c \
	$(srcdir)/cert/x509/ecp_curves.c \
	$(srcdir)/cert/x509/ecp.h \
	$(srcdir)/cert/x509/entropy.c \
	$(srcdir)/cert/x509/entropy.h \
	$(srcdir)/cert/x509/entropy_poll.c \
	$(srcdir)/cert/x509/entropy_poll.h \
	$(srcdir)/cert/x509/error.c \
	$(srcdir)/cert/x509/error.h \
	$(srcdir)/cert/x509/gcm.c \
	$(srcdir)/cert/x509/gcm.h \
	$(srcdir)/cert/x509/havege.c \
	$(srcdir)/cert/x509/havege.h \
	$(srcdir)/cert/x509/hmac_drbg.c \
	$(srcdir)/cert/x509/hmac_drbg.h \
	$(srcdir)/cert/x509/md2.c \
	$(srcdir)/cert/x509/md2.h \
	$(srcdir)/cert/x509/md4.c \
	$(srcdir)/cert/x509/md4.h \
	$(srcdir)/cert/x509/md5.c \
	$(srcdir)/cert/x509/md5.h \
	$(srcdir)/cert/x509/md.c \
	$(srcdir)/cert/x509/md.h \
	$(srcdir)/cert/x509/md_wrap.c \
	$(srcdir)/cert/x509/md_wrap.h \
	$(srcdir)/cert/x509/memory_buffer_alloc.c \
	$(srcdir)/cert/x509/memory_buffer_alloc.h \
	$(srcdir)/cert/x509/memory.h \
	$(srcdir)/cert/x509/net.c \
	$(srcdir)/cert/x509/net.h \
	$(srcdir)/cert/x509/oid.c \
	$(srcdir)/cert/x509/oid.h \
	$(srcdir)/cert/x509/openssl.h \
	$(srcdir)/cert/x509/padlock.c \
	$(srcdir)/cert/x509/padlock.h \
	$(srcdir)/cert/x509/pbkdf2.c \
	$(srcdir)/cert/x509/pbkdf2.h \
	$(srcdir)/cert/x509/pem.c \
	$(srcdir)/cert/x509/pem.h \
	$(srcdir)/cert/x509/pk.c \
	$(srcdir)/cert/x509/pkcs11.c \
	$(srcdir)/cert/x509/pkcs11.h \
	$(srcdir)/cert/x509/pkcs12.c \
	$(srcdir)/cert/x509/pkcs12.h \
	$(srcdir)/cert/x509/pkcs5.c \
	$(srcdir)/cert/x509/pkcs5.h \
	$(srcdir)/cert/x509/pk.h \
	$(srcdir)/cert/x509/pkparse.c \
	$(srcdir)/cert/x509/pk_wrap.c \
	$(srcdir)/cert/x509/pk_wrap.h \
	$(srcdir)/cert/x509/pkwrite.c \
	$(srcdir)/cert/x509/platform.c \
	$(srcdir)/cert/x509/platform.h \
	$(srcdir)/cert/x509/ripemd160.c \
	$(srcdir)/cert/x509/ripemd160.h \
	$(srcdir)/cert/x509/sha1.c \
	$(srcdir)/cert/x509/sha1.h \
	$(srcdir)/cert/x509/sha256.c \
	$(srcdir)/cert/x509/sha256.h \
	$(srcdir)/cert/x509/sha512.c \
	$(srcdir)/cert/x509/sha512.h \
	$(srcdir)/cert/x509/ssl_cache.c \
	$(srcdir)/cert/x509/ssl_cache.h \
	$(srcdir)/cert/x509/ssl_ciphersuites.c \
	$(srcdir)/cert/x509/ssl_ciphersuites.h \
	$(srcdir)/cert/x509/ssl_cli.c \
	$(srcdir)/cert/x509/ssl.h \
	$(srcdir)/cert/x509/ssl_srv.c \
	$(srcdir)/cert/x509/ssl_tls.c \
	$(srcdir)/cert/x509/threading.c \
	$(srcdir)/cert/x509/threading.h \
	$(srcdir)/cert/x509/timing.c \
	$(srcdir)/cert/x509/timing.h \
	$(srcdir)/cert/x509/version.c \
	$(srcdir)/cert/x509/version_features.c \
	$(srcdir)/cert/x509/version.h \
	$(srcdir)/cert/x509/x509.c \
	$(srcdir)/cert/x509/x509_create.c \
	$(srcdir)/cert/x509/x509_crl.c \
	$(srcdir)/cert/x509/x509_crl.h \
	$(srcdir)/cert/x509/x509_crt.c \
	$(srcdir)/cert/x509/x509_crt.h \
	$(srcdir)/cert/x509/x509_csr.c \
	$(srcdir)/cert/x509/x509_csr.h \
	$(srcdir)/cert/x509/x509.h \
	$(srcdir)/cert/x509/x509write_crt.c \
	$(srcdir)/cert/x509/x509write_csr.c \
	$(srcdir)/cert/x509/xtea.c \
	$(srcdir)/cert/x509/xtea.h


bin_PROGRAMS = \
	shattr \
	shcat \
	shcert \
	shcp \
	shdb \
	shdelta \
	shdiff \
	shfsck \
	shinfo \
	shapp \
	shln \
	shls \
	shpatch \
	shstat \
	shpref \
	shpasswd \
	shpkg \
	shrev \
	shz \
	shrm \
	shgeo \
	shalg


noinst_PROGRAMS = shutil_static \
	static/shpref \
	static/shfsck \
	static/shapp \
	static/shinfo \
	static/shpasswd \
	static/shpkg \
	static/shcert \
	static/shdb \
	static/shstat \
	static/shls \
	static/shdiff \
	static/shdelta \
	static/shpatch \
	static/shattr \
	static/shcat \
	static/shcp \
	static/shrm \
	static/shgeo \
	static/shalg \
	static/shln \
	static/shrev \
	static/shz



shutil_static_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shutil_static_LDFLAGS = -static
shutil_static_LDADD = \
	$(top_builddir)/src/share-lib/libshare.a

shpref_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shpref_LDADD = $(top_builddir)/src/share-lib/libshare.la

shdiff_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shdiff_LDADD = $(top_builddir)/src/share-lib/libshare.la

shdelta_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shdelta_LDADD = $(top_builddir)/src/share-lib/libshare.la

shpatch_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shpatch_LDADD = $(top_builddir)/src/share-lib/libshare.la

shstat_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shstat_LDADD = $(top_builddir)/src/share-lib/libshare.la

shdb_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shdb_LDADD = $(top_builddir)/src/share-lib/libshare.la

shinfo_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shinfo_LDADD = $(top_builddir)/src/share-lib/libshare.la

shapp_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shapp_LDADD = $(top_builddir)/src/share-lib/libshare.la

shfsck_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shfsck_LDADD = $(top_builddir)/src/share-lib/libshare.la

shpasswd_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shpasswd_LDADD = $(top_builddir)/src/share-lib/libshare.la

shpkg_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shpkg_LDADD = $(top_builddir)/src/share-lib/libshare.la

shcert_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shcert_LDADD = $(top_builddir)/src/share-lib/libshare.la

shls_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shls_LDADD = $(top_builddir)/src/share-lib/libshare.la

shrm_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shrm_LDADD = $(top_builddir)/src/share-lib/libshare.la

shgeo_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shgeo_LDADD = $(top_builddir)/src/share-lib/libshare.la

shalg_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shalg_LDADD = $(top_builddir)/src/share-lib/libshare.la

shln_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shln_LDADD = $(top_builddir)/src/share-lib/libshare.la

shrev_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shrev_LDADD = $(top_builddir)/src/share-lib/libshare.la

shz_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shz_LDADD = $(top_builddir)/src/share-lib/libshare.la

shcat_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shcat_LDADD = $(top_builddir)/src/share-lib/libshare.la

shcp_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shcp_LDADD = $(top_builddir)/src/share-lib/libshare.la

shattr_SOURCES = $(common_INCLUDES) $(common_SOURCES) $(x509_SOURCES)
shattr_LDADD = $(top_builddir)/src/share-lib/libshare.la

dist_docdir = $(datadir)/doc/@PACKAGE@


static/shpref$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shpref

static/shdiff$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shdiff

static/shdelta$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shdelta

static/shpatch$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shpatch

static/shstat$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shstat

static/shfsck$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shfsck

static/shinfo$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shinfo

static/shapp$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shapp

static/shpasswd$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shpasswd

static/shpkg$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shpkg

static/shcert$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shcert

static/shdb$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shdb

static/shls$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shls

static/shattr$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shattr

static/shcat$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shcat

static/shcp$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shcp

static/shln$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shln

static/shrm$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shrm

static/shgeo$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shgeo

static/shalg$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shalg

static/shrev$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shrev

static/shz$(EXEEXT): shutil_static
	$(MKDIR_P) static
	$(CP) shutil_static static/shz


