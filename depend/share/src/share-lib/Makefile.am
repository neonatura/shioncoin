AUTOMAKE_OPTIONS = foreign

ld_flags = $(LIBSOCKET) $(LIB_SELECT) -version-info @version_info@

noinst_PROGRAMS = test_libshare test_libshare_static test_xd3

#test_libshare
test_libshare_SOURCES = $(common_INCLUDES) test_libshare.c
test_libshare_LDADD = libshare.la
test_libshare_LDFLAGS = $(ld_flags)

# test_libshare_static
test_libshare_static_SOURCES = $(common_INCLUDES) test_libshare.c
test_libshare_static_LDFLAGS = -static
test_libshare_static_LDADD = libshare.a
test_libshare_LDFLAGS = $(ld_flags)

test_xd3_SOURCES = $(srcdir)/mem/delta/shxd_test.c $(xd3_headers)
test_xd3_CFLAGS = -DREGRESSION_TEST -DSHELL_TESTS=0
test_xd3_LDFLAGS = $(ld_flags)

TESTS = test_libshare_static

if LINUX
install-exec-hook:
	mkdir -p /var/lib/share
	chmod 0777 /var/lib/share
endif

noinst_INCLUDES = \
	share.h sherr.h shtime.h shcrc.h shpeer.h shpref.h \
	shnet.h shfs.h shmem.h shsys.h

zlib_sources = \
	mem/zlib/deflate.c \
	mem/zlib/infback.c \
	mem/zlib/inffast.c \
	mem/zlib/inflate.c \
	mem/zlib/inftrees.c \
	mem/zlib/trees.c \
	mem/zlib/zutil.c \
	mem/zlib/compress.c \
	mem/zlib/uncompr.c

mpz_sources = \
	mem/mpz/2fac_ui.c \
	mem/mpz/abs.c \
	mem/mpz/add.c \
	mem/mpz/add_ui.c \
	mem/mpz/and.c \
	mem/mpz/aorsmul.c \
	mem/mpz/aorsmul_i.c \
	mem/mpz/array_init.c \
	mem/mpz/bin_ui.c \
	mem/mpz/bin_uiui.c \
	mem/mpz/cdiv_q.c \
	mem/mpz/cdiv_qr.c \
	mem/mpz/cdiv_qr_ui.c \
	mem/mpz/cdiv_q_ui.c \
	mem/mpz/cdiv_r.c \
	mem/mpz/cdiv_r_ui.c \
	mem/mpz/cdiv_ui.c \
	mem/mpz/cfdiv_q_2exp.c \
	mem/mpz/cfdiv_r_2exp.c \
	mem/mpz/clear.c \
	mem/mpz/clears.c \
	mem/mpz/clrbit.c \
	mem/mpz/cmpabs.c \
	mem/mpz/cmpabs_d.c \
	mem/mpz/cmpabs_ui.c \
	mem/mpz/cmp.c \
	mem/mpz/cmp_d.c \
	mem/mpz/cmp_si.c \
	mem/mpz/cmp_ui.c \
	mem/mpz/combit.c \
	mem/mpz/com.c \
	mem/mpz/cong_2exp.c \
	mem/mpz/cong.c \
	mem/mpz/cong_ui.c \
	mem/mpz/divegcd.c \
	mem/mpz/dive_ui.c \
	mem/mpz/divexact.c \
	mem/mpz/divis_2exp.c \
	mem/mpz/divis.c \
	mem/mpz/divis_ui.c \
	mem/mpz/dump.c \
	mem/mpz/export.c \
	mem/mpz/fac_ui.c \
	mem/mpz/fdiv_q.c \
	mem/mpz/fdiv_qr.c \
	mem/mpz/fdiv_qr_ui.c \
	mem/mpz/fdiv_q_ui.c \
	mem/mpz/fdiv_r.c \
	mem/mpz/fdiv_r_ui.c \
	mem/mpz/fdiv_ui.c \
	mem/mpz/fib2_ui.c \
	mem/mpz/fib_ui.c \
	mem/mpz/fits_sint.c \
	mem/mpz/fits_slong.c \
	mem/mpz/fits_sshort.c \
	mem/mpz/fits_uint.c \
	mem/mpz/fits_ulong.c \
	mem/mpz/fits_ushort.c \
	mem/mpz/gcd.c \
	mem/mpz/gcdext.c \
	mem/mpz/gcd_ui.c \
	mem/mpz/get_d_2exp.c \
	mem/mpz/get_d.c \
	mem/mpz/getlimbn.c \
	mem/mpz/get_si.c \
	mem/mpz/get_str.c \
	mem/mpz/get_ui.c \
	mem/mpz/hamdist.c \
	mem/mpz/import.c \
	mem/mpz/init2.c \
	mem/mpz/init.c \
	mem/mpz/inits.c \
	mem/mpz/inp_raw.c \
	mem/mpz/inp_str.c \
	mem/mpz/invert.c \
	mem/mpz/ior.c \
	mem/mpz/iset.c \
	mem/mpz/iset_d.c \
	mem/mpz/iset_si.c \
	mem/mpz/iset_str.c \
	mem/mpz/iset_ui.c \
	mem/mpz/jacobi.c \
	mem/mpz/kronsz.c \
	mem/mpz/kronuz.c \
	mem/mpz/kronzs.c \
	mem/mpz/kronzu.c \
	mem/mpz/lcm.c \
	mem/mpz/lcm_ui.c \
	mem/mpz/limbs_finish.c \
	mem/mpz/limbs_modify.c \
	mem/mpz/limbs_read.c \
	mem/mpz/limbs_write.c \
	mem/mpz/lucnum2_ui.c \
	mem/mpz/lucnum_ui.c \
	mem/mpz/mfac_uiui.c \
	mem/mpz/millerrabin.c \
	mem/mpz/mod.c \
	mem/mpz/mul_2exp.c \
	mem/mpz/mul.c \
	mem/mpz/mul_si.c \
	mem/mpz/mul_ui.c \
	mem/mpz/neg.c \
	mem/mpz/nextprime.c \
	mem/mpz/n_pow_ui.c \
	mem/mpz/oddfac_1.c \
	mem/mpz/out_raw.c \
	mem/mpz/out_str.c \
	mem/mpz/perfpow.c \
	mem/mpz/perfsqr.c \
	mem/mpz/popcount.c \
	mem/mpz/powm.c \
	mem/mpz/powm_sec.c \
	mem/mpz/powm_ui.c \
	mem/mpz/pow_ui.c \
	mem/mpz/pprime_p.c \
	mem/mpz/primorial_ui.c \
	mem/mpz/prodlimbs.c \
	mem/mpz/realloc2.c \
	mem/mpz/realloc.c \
	mem/mpz/remove.c \
	mem/mpz/roinit_n.c \
	mem/mpz/root.c \
	mem/mpz/rootrem.c \
	mem/mpz/scan0.c \
	mem/mpz/scan1.c \
	mem/mpz/setbit.c \
	mem/mpz/set.c \
	mem/mpz/set_d.c \
	mem/mpz/set_f.c \
	mem/mpz/set_q.c \
	mem/mpz/set_si.c \
	mem/mpz/set_str.c \
	mem/mpz/set_ui.c \
	mem/mpz/size.c \
	mem/mpz/sizeinbase.c \
	mem/mpz/sqrt.c \
	mem/mpz/sqrtrem.c \
	mem/mpz/sub.c \
	mem/mpz/sub_ui.c \
	mem/mpz/swap.c \
	mem/mpz/tdiv_q_2exp.c \
	mem/mpz/tdiv_q.c \
	mem/mpz/tdiv_qr.c \
	mem/mpz/tdiv_qr_ui.c \
	mem/mpz/tdiv_q_ui.c \
	mem/mpz/tdiv_r_2exp.c \
	mem/mpz/tdiv_r.c \
	mem/mpz/tdiv_r_ui.c \
	mem/mpz/tdiv_ui.c \
	mem/mpz/tstbit.c \
	mem/mpz/ui_pow_ui.c \
	mem/mpz/ui_sub.c \
	mem/mpz/urandomb.c \
	mem/mpz/urandomm.c \
	mem/mpz/xor.c

ecdsa_sources = \
	mem/ecdsa/ecdsa_gmp.c \
	mem/ecdsa/ecdsa_gmp.h \
	mem/ecdsa/ecdsa_curves.c \
	mem/ecdsa/ecdsa_curves.h \
	mem/ecdsa/ecdsa_numbertheory.c \
	mem/ecdsa/ecdsa_numbertheory.h \
	mem/ecdsa/ecdsa_param.c \
	mem/ecdsa/ecdsa_param.h \
	mem/ecdsa/ecdsa_point.c \
	mem/ecdsa/ecdsa_point.h \
	mem/ecdsa/ecdsa_signature.c \
	mem/ecdsa/ecdsa_signature.h


gnu_sources = \
	$(top_srcdir)/src/gnu/alloca.c \
	$(top_srcdir)/src/gnu/allocator.c \
	$(top_srcdir)/src/gnu/areadlink.c \
	$(top_srcdir)/src/gnu/areadlinkat.c \
	$(top_srcdir)/src/gnu/argmatch.c \
	$(top_srcdir)/src/gnu/argp-ba.c \
	$(top_srcdir)/src/gnu/argp-eexst.c \
	$(top_srcdir)/src/gnu/argp-fmtstream.c \
	$(top_srcdir)/src/gnu/argp-fs-xinl.c \
	$(top_srcdir)/src/gnu/argp-help.c \
	$(top_srcdir)/src/gnu/argp-parse.c \
	$(top_srcdir)/src/gnu/argp-pin.c \
	$(top_srcdir)/src/gnu/argp-pv.c \
	$(top_srcdir)/src/gnu/argp-pvh.c \
	$(top_srcdir)/src/gnu/argp-xinl.c \
	$(top_srcdir)/src/gnu/asnprintf.c \
	$(top_srcdir)/src/gnu/basename.c \
	$(top_srcdir)/src/gnu/basename-lgpl.c \
	$(top_srcdir)/src/gnu/bitrotate.c \
	$(top_srcdir)/src/gnu/btowc.c \
	$(top_srcdir)/src/gnu/careadlinkat.c \
	$(top_srcdir)/src/gnu/c-ctype.c \
	$(top_srcdir)/src/gnu/chdir-long.c \
	$(top_srcdir)/src/gnu/cloexec.c \
	$(top_srcdir)/src/gnu/close.c \
	$(top_srcdir)/src/gnu/closeout.c \
	$(top_srcdir)/src/gnu/close-stream.c \
	$(top_srcdir)/src/gnu/c-strcasecmp.c \
	$(top_srcdir)/src/gnu/c-strncasecmp.c \
	$(top_srcdir)/src/gnu/dirfd.c \
	$(top_srcdir)/src/gnu/dirname.c \
	$(top_srcdir)/src/gnu/dirname-lgpl.c \
	$(top_srcdir)/src/gnu/dup.c \
	$(top_srcdir)/src/gnu/dup2.c \
	$(top_srcdir)/src/gnu/dup-safer.c \
	$(top_srcdir)/src/gnu/error.c \
	$(top_srcdir)/src/gnu/exclude.c \
	$(top_srcdir)/src/gnu/exitfail.c \
	$(top_srcdir)/src/gnu/fchdir.c \
	$(top_srcdir)/src/gnu/fcntl.c \
	$(top_srcdir)/src/gnu/fd-hook.c \
	$(top_srcdir)/src/gnu/fdopendir.c \
	$(top_srcdir)/src/gnu/fd-safer.c \
	$(top_srcdir)/src/gnu/fdutimensat.c \
	$(top_srcdir)/src/gnu/filenamecat-lgpl.c \
	$(top_srcdir)/src/gnu/float.c \
	$(top_srcdir)/src/gnu/fstat.c \
	$(top_srcdir)/src/gnu/fstatat.c \
	$(top_srcdir)/src/gnu/full-write.c \
	$(top_srcdir)/src/gnu/futimens.c \
	$(top_srcdir)/src/gnu/getcwd-lgpl.c \
	$(top_srcdir)/src/gnu/getdtablesize.c \
	$(top_srcdir)/src/gnu/getopt.c \
	$(top_srcdir)/src/gnu/getopt1.c \
	$(top_srcdir)/src/gnu/getprogname.c \
	$(top_srcdir)/src/gnu/gettime.c \
	$(top_srcdir)/src/gnu/glthread/lock.c \
	$(top_srcdir)/src/gnu/glthread/threadlib.c \
	$(top_srcdir)/src/gnu/hard-locale.c \
	$(top_srcdir)/src/gnu/hash.c \
	$(top_srcdir)/src/gnu/human.c \
	$(top_srcdir)/src/gnu/imaxtostr.c \
	$(top_srcdir)/src/gnu/inttostr.c \
	$(top_srcdir)/src/gnu/iswblank.c \
	$(top_srcdir)/src/gnu/itold.c \
	$(top_srcdir)/src/gnu/link.c \
	$(top_srcdir)/src/gnu/linkat.c \
	$(top_srcdir)/src/gnu/localcharset.c \
	$(top_srcdir)/src/gnu/lstat.c \
	$(top_srcdir)/src/gnu/malloc.c \
	$(top_srcdir)/src/gnu/malloca.c \
	$(top_srcdir)/src/gnu/mbchar.c \
	$(top_srcdir)/src/gnu/mbrtowc.c \
	$(top_srcdir)/src/gnu/mbscasecmp.c \
	$(top_srcdir)/src/gnu/mbsinit.c \
	$(top_srcdir)/src/gnu/mbsrtowcs.c \
	$(top_srcdir)/src/gnu/mbsrtowcs-state.c \
	$(top_srcdir)/src/gnu/mbtowc.c \
	$(top_srcdir)/src/gnu/mbuiter.c \
	$(top_srcdir)/src/gnu/memchr.c \
	$(top_srcdir)/src/gnu/mempcpy.c \
	$(top_srcdir)/src/gnu/memrchr.c \
	$(top_srcdir)/src/gnu/mkdir.c \
	$(top_srcdir)/src/gnu/mktime.c \
	$(top_srcdir)/src/gnu/msvc-inval.c \
	$(top_srcdir)/src/gnu/msvc-nothrow.c \
	$(top_srcdir)/src/gnu/obstack.c \
	$(top_srcdir)/src/gnu/offtostr.c \
	$(top_srcdir)/src/gnu/pipe-safer.c \
	$(top_srcdir)/src/gnu/printf-args.c \
	$(top_srcdir)/src/gnu/printf-parse.c \
	$(top_srcdir)/src/gnu/priv-set.c \
	$(top_srcdir)/src/gnu/progname.c \
	$(top_srcdir)/src/gnu/quotearg.c \
	$(top_srcdir)/src/gnu/raise.c \
	$(top_srcdir)/src/gnu/rawmemchr.c \
	$(top_srcdir)/src/gnu/read.c \
	$(top_srcdir)/src/gnu/readlink.c \
	$(top_srcdir)/src/gnu/readlinkat.c \
	$(top_srcdir)/src/gnu/realloc.c \
	$(top_srcdir)/src/gnu/safe-read.c \
	$(top_srcdir)/src/gnu/safe-write.c \
	$(top_srcdir)/src/gnu/save-cwd.c \
	$(top_srcdir)/src/gnu/savedir.c \
	$(top_srcdir)/src/gnu/setenv.c \
	$(top_srcdir)/src/gnu/sleep.c \
	$(top_srcdir)/src/gnu/stat.c \
	$(top_srcdir)/src/gnu/stat-time.c \
	$(top_srcdir)/src/gnu/stpcpy.c \
	$(top_srcdir)/src/gnu/strcasecmp.c \
	$(top_srcdir)/src/gnu/strchrnul.c \
	$(top_srcdir)/src/gnu/strdup.c \
	$(top_srcdir)/src/gnu/strftime.c \
	$(top_srcdir)/src/gnu/stripslash.c \
	$(top_srcdir)/src/gnu/strncasecmp.c \
	$(top_srcdir)/src/gnu/strnlen.c \
	$(top_srcdir)/src/gnu/strnlen1.c \
	$(top_srcdir)/src/gnu/strtol.c \
	$(top_srcdir)/src/gnu/strtoll.c \
	$(top_srcdir)/src/gnu/strtoul.c \
	$(top_srcdir)/src/gnu/strtoull.c \
	$(top_srcdir)/src/gnu/symlink.c \
	$(top_srcdir)/src/gnu/time_r.c \
	$(top_srcdir)/src/gnu/time_rz.c \
	$(top_srcdir)/src/gnu/timegm.c \
	$(top_srcdir)/src/gnu/timespec.c \
	$(top_srcdir)/src/gnu/uinttostr.c \
	$(top_srcdir)/src/gnu/umaxtostr.c \
	$(top_srcdir)/src/gnu/unistd.c \
	$(top_srcdir)/src/gnu/uniwidth/width.c \
	$(top_srcdir)/src/gnu/unsetenv.c \
	$(top_srcdir)/src/gnu/utimens.c \
	$(top_srcdir)/src/gnu/utimensat.c \
	$(top_srcdir)/src/gnu/vasnprintf.c \
	$(top_srcdir)/src/gnu/vsnprintf.c \
	$(top_srcdir)/src/gnu/wcrtomb.c \
	$(top_srcdir)/src/gnu/wctype-h.c \
	$(top_srcdir)/src/gnu/wcwidth.c \
	$(top_srcdir)/src/gnu/write.c \
	$(top_srcdir)/src/gnu/xalloc-die.c \
	$(top_srcdir)/src/gnu/xmalloc.c \
	$(top_srcdir)/src/gnu/xsize.c \
	$(top_srcdir)/src/gnu/xstrtol.c \
	$(top_srcdir)/src/gnu/xstrndup.c \
	$(top_srcdir)/src/gnu/xstrtol-error.c \
	$(top_srcdir)/src/gnu/xstrtoul.c \
	$(top_srcdir)/src/gnu/xstrtoumax.c \
	$(top_srcdir)/src/gnu/regex.c \
	$(top_srcdir)/src/gnu/openat.c \
	$(top_srcdir)/src/gnu/openat-die.c \
	$(top_srcdir)/src/gnu/openat-proc.c \
	$(top_srcdir)/src/gnu/opendir-safer.c

if WINDOWS
#gnu_sources += $(top_srcdir)/src/gnu/open.c
else
gnu_sources += $(top_srcdir)/src/gnu/fnmatch.c
endif

#	$(top_srcdir)/src/gnu/strerror.c
#	$(top_srcdir)/src/gnu/opendir.c
#	$(top_srcdir)/src/gnu/closedir.c \
#	$(top_srcdir)/src/gnu/acl_entries.c
#	$(top_srcdir)/src/gnu/acl-errno-valid.c \
#	$(top_srcdir)/src/gnu/acl-internal.c \
#	$(top_srcdir)/src/gnu/qcopy-acl.c \
#	$(top_srcdir)/src/gnu/qset-acl.c \
#	$(top_srcdir)/src/gnu/set-permissions.c \
#	$(top_srcdir)/src/gnu/get-permissions.c \
#	$(top_srcdir)/src/gnu/regcomp.c
#	$(top_srcdir)/src/gnu/anytostr.c
#	$(top_srcdir)/src/gnu/at-func.c
#	$(top_srcdir)/src/gnu/at-func2.c
#	$(top_srcdir)/src/gnu/fnmatch_loop.c
#	$(top_srcdir)/src/gnu/fpending.c
#	$(top_srcdir)/src/gnu/localeconv.c
#	$(top_srcdir)/src/gnu/nl_langinfo.c
#	$(top_srcdir)/src/gnu/readdir.c
#	$(top_srcdir)/src/gnu/regcomp.c
#	$(top_srcdir)/src/gnu/regex_internal.c
#	$(top_srcdir)/src/gnu/regexec.c
#	$(top_srcdir)/src/gnu/strerror-override.c
#	$(top_srcdir)/src/gnu/strtoimax.c 
#	$(top_srcdir)/src/gnu/strtoumax.c
#	$(top_srcdir)/src/gnu/gettimeofday.c


common_INCLUDES = \
	$(noinst_INCLUDES) \
	$(top_builddir)/config.h \
	$(top_srcdir)/src/share-lib/shcrc.h \
	$(top_srcdir)/src/share-lib/shpref.h \
	$(top_srcdir)/src/share-lib/fs/shfs_int.h \
	$(top_srcdir)/src/share-lib/test/CuTest.h \
	$(top_srcdir)/src/share-lib/test/shtest.h

common_sources = \
	$(top_srcdir)/src/share-lib/share.c \
	$(top_srcdir)/src/share-lib/share_posix.c \
	$(top_srcdir)/src/share-lib/mem/shmem.c \
	$(top_srcdir)/src/share-lib/mem/shmem_buf.c \
	$(top_srcdir)/src/share-lib/mem/shmem_pool.c \
	$(top_srcdir)/src/share-lib/mem/shmem_map.c \
	$(top_srcdir)/src/share-lib/mem/shmem_crypto.c \
	$(top_srcdir)/src/share-lib/mem/shmem_csum.c \
	$(top_srcdir)/src/share-lib/mem/shmem_key.c \
	$(top_srcdir)/src/share-lib/mem/shmem_lock.c \
	$(top_srcdir)/src/share-lib/mem/shmem_scrypt.c \
	$(top_srcdir)/src/share-lib/mem/shmem_scrypt_gen.c \
	$(top_srcdir)/src/share-lib/mem/shmem_json.c \
	$(top_srcdir)/src/share-lib/mem/shmem_digest.c \
	$(top_srcdir)/src/share-lib/mem/shmem_shz.c \
	$(top_srcdir)/src/share-lib/mem/shmem_tree.c \
	$(top_srcdir)/src/share-lib/mem/shmem_delta.c \
	$(top_srcdir)/src/share-lib/mem/shmem_diff.c \
	$(top_srcdir)/src/share-lib/mem/shmem_base32.c \
	$(top_srcdir)/src/share-lib/mem/shmem_base58.c \
	$(top_srcdir)/src/share-lib/mem/shmem_base64.c \
	$(top_srcdir)/src/share-lib/mem/shmem_mpi.c \
	$(top_srcdir)/src/share-lib/mem/shmem_mpi.h \
	$(top_srcdir)/src/share-lib/mem/shmem_alg.c \
	$(top_srcdir)/src/share-lib/mem/shmem_alg_sha.c \
	$(top_srcdir)/src/share-lib/mem/shmem_alg_sha.h \
	$(top_srcdir)/src/share-lib/mem/shmem_alg_shacrypt.c \
	$(top_srcdir)/src/share-lib/mem/shmem_alg_shr.c \
	$(top_srcdir)/src/share-lib/mem/shmem_alg_ecdsa.c \
	$(top_srcdir)/src/share-lib/mem/shmem_alg_ripemd160.c \
	$(top_srcdir)/src/share-lib/mem/shmem_alg_rsa.c \
	$(top_srcdir)/src/share-lib/mem/shmem_sig.c \
	$(top_srcdir)/src/share-lib/fs/shfs_mem.c \
	$(top_srcdir)/src/share-lib/fs/shfs_meta.c \
	$(top_srcdir)/src/share-lib/fs/shfs_journal.c \
	$(top_srcdir)/src/share-lib/fs/shfs_proc.c \
	$(top_srcdir)/src/share-lib/fs/shfs_rev.c \
	$(top_srcdir)/src/share-lib/fs/shfs_partition.c \
	$(top_srcdir)/src/share-lib/fs/shfs_inode.c \
	$(top_srcdir)/src/share-lib/fs/shfs_link.c \
	$(top_srcdir)/src/share-lib/fs/shfs_list.c \
	$(top_srcdir)/src/share-lib/fs/shfs_lock.c \
	$(top_srcdir)/src/share-lib/fs/shfs_dir.c \
	$(top_srcdir)/src/share-lib/fs/shfs_file.c \
	$(top_srcdir)/src/share-lib/fs/shfs_bin.c \
	$(top_srcdir)/src/share-lib/fs/shfs_zlib.c \
	$(top_srcdir)/src/share-lib/fs/shfs_ext.c \
	$(top_srcdir)/src/share-lib/fs/shfs_cache.c \
	$(top_srcdir)/src/share-lib/fs/shfs_aux.c \
	$(top_srcdir)/src/share-lib/fs/shfs_attr.c \
	$(top_srcdir)/src/share-lib/fs/shfs_ref.c \
	$(top_srcdir)/src/share-lib/fs/shfs_obj.c \
	$(top_srcdir)/src/share-lib/fs/shfs_home.c \
	$(top_srcdir)/src/share-lib/fs/shfs_access.c \
	$(top_srcdir)/src/share-lib/fs/shfs_arch.c \
	$(top_srcdir)/src/share-lib/fs/shfs_db.c \
	$(top_srcdir)/src/share-lib/fs/shfs_db_sqlite.c \
	$(top_srcdir)/src/share-lib/fs/shfs_stream.c \
	$(top_srcdir)/src/share-lib/fs/meta/shfs_mime.c \
	$(top_srcdir)/src/share-lib/fs/meta/shfs_cert.c \
	$(top_srcdir)/src/share-lib/fs/meta/shfs_lic.c \
	$(top_srcdir)/src/share-lib/fs/meta/shfs_sig.c \
	$(top_srcdir)/src/share-lib/net/shnet_read.c \
	$(top_srcdir)/src/share-lib/net/shnet_bind.c \
	$(top_srcdir)/src/share-lib/net/shnet_connect.c \
	$(top_srcdir)/src/share-lib/net/shnet_fcntl.c \
	$(top_srcdir)/src/share-lib/net/shnet_gethost.c \
	$(top_srcdir)/src/share-lib/net/shnet_close.c \
	$(top_srcdir)/src/share-lib/net/shnet_socket.c \
	$(top_srcdir)/src/share-lib/net/shnet_accept.c \
	$(top_srcdir)/src/share-lib/net/shnet_select.c \
	$(top_srcdir)/src/share-lib/net/shnet_write.c \
	$(top_srcdir)/src/share-lib/net/shnet_track.c \
	$(top_srcdir)/src/share-lib/net/shnet_esl.c \
	$(top_srcdir)/src/share-lib/sys/shsys_msg.c \
	$(top_srcdir)/src/share-lib/sys/shsys_app.c \
	$(top_srcdir)/src/share-lib/sys/shsys_proc.c \
	$(top_srcdir)/src/share-lib/sys/shsys_lic.c \
	$(top_srcdir)/src/share-lib/sys/shsys_pam.c \
	$(top_srcdir)/src/share-lib/sys/shsys_pam_auth.c \
	$(top_srcdir)/src/share-lib/sys/shsys_pam_user.c \
	$(top_srcdir)/src/share-lib/sys/shsys_pam_shadow.c \
	$(top_srcdir)/src/share-lib/sys/shsys_log.c \
	$(top_srcdir)/src/share-lib/sys/shsys_geo.c \
	$(top_srcdir)/src/share-lib/sys/shsys_cache.c \
	$(top_srcdir)/src/share-lib/sys/shsys_ctx.c \
	$(top_srcdir)/src/share-lib/sys/shsys_esig.c \
	$(top_srcdir)/src/share-lib/sys/pkg/shpkg_io.c \
	$(top_srcdir)/src/share-lib/sys/pkg/shpkg_op.c \
	$(top_srcdir)/src/share-lib/sys/pkg/shpkg_cert.c \
	$(top_srcdir)/src/share-lib/sys/pkg/shpkg.c \
	$(top_srcdir)/src/share-lib/test/CuTest.c

xd3_headers = \
	$(srcdir)/mem/delta/xdelta3-blkcache.h \
	$(srcdir)/mem/delta/xdelta3-cfgs.h \
	$(srcdir)/mem/delta/xdelta3-decode.h \
	$(srcdir)/mem/delta/xdelta3-djw.h \
	$(srcdir)/mem/delta/xdelta3-fgk.h \
	$(srcdir)/mem/delta/xdelta3.h \
	$(srcdir)/mem/delta/xdelta3-hash.h \
	$(srcdir)/mem/delta/xdelta3-internal.h \
	$(srcdir)/mem/delta/xdelta3-list.h \
	$(srcdir)/mem/delta/xdelta3-lzma.h \
	$(srcdir)/mem/delta/xdelta3-main.h \
	$(srcdir)/mem/delta/xdelta3-merge.h \
	$(srcdir)/mem/delta/xdelta3-second.h \
	$(srcdir)/mem/delta/xdelta3-test.h


lib_LIBRARIES = libshare.a
libshare_a_SOURCES = $(common_INCLUDES) $(common_sources) $(zlib_sources) \
	$(ecdsa_sources) $(gnu_sources) \
	shtest.c
libshare_a_CFLAGS = $(AM_CFLAGS) \
	-DHAVE_CONFIG_H -DSHARELIB=1 \
	-I$(srcdir)/test \
	-I$(srcdir)/net -I$(srcdir)/fs -I$(srcdir)/mem \
	-I$(srcdir)/mem/zlib \
	-I$(top_srcdir)/src/gnu -I$(top_builddir)/src/gnu
libshare_a_LDFLAGS = $(ld_flags)

lib_LTLIBRARIES = libshare.la
libshare_la_SOURCES = $(common_INCLUDES) $(common_sources) \
	$(zlib_sources) $(ecdsa_sources) $(gnu_sources) \
	shtest.c
if LIBSHARE_JAVA
libshare_la_SOURCES += \
	$(srcdir)/java/libshare_java_wrap.c 
endif
libshare_la_CFLAGS = $(AM_CFLAGS) \
	-DHAVE_CONFIG_H -DSHARELIB=1 \
	-I$(srcdir)/test \
	-I$(srcdir)/net -I$(srcdir)/fs -I$(srcdir)/mem \
	-I$(srcdir)/mem/zlib \
	-I$(top_srcdir)/src/gnu -I$(top_builddir)/src/gnu
libshare_la_LDFLAGS = $(ld_flags)

if DEBUG
AM_CFLAGS = -g3 -O0 -DDEBUG -Wno-discarded-qualifiers
AM_CXXFLAGS = -g3 -O0 -DDEBUG
if WINDOWS
AM_CFLAGS += -ggdb3
endif
else
AM_CFLAGS = \
  -fomit-frame-pointer -fstrength-reduce -fthread-jumps -funroll-loops
AM_CXXFLAGS = \
  -fomit-frame-pointer -fstrength-reduce -fthread-jumps -funroll-loops
endif

CLEANFILES = shtest.c

shtest.c: $(common_sources) 
	@mkdir -p $(top_srcdir)/src/share-lib/test/
	@echo "Generating 'shtest.c' for test suite."
	$(top_srcdir)/scripts/make-tests.sh $(top_srcdir)/src/share-lib/*.c $(top_srcdir)/src/share-lib/sys/*.c $(top_srcdir)/src/share-lib/mem/*.c $(top_srcdir)/src/share-lib/fs/*.c $(top_srcdir)/src/share-lib/fs/meta/*.c $(top_srcdir)/src/share-lib/net/*.c $(top_srcdir)/src/share-lib/sys/*.c $(top_srcdir)/src/share-lib/sys/pkg/*.c > shtest.c

clean-local:
	rm -f shtest.c
