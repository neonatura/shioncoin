#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(share-coin, 3.2)
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([src/secp256k1/libsecp256k1-config.h])

AC_SUBST([with_kernel], [`uname -r`])
AC_SUBST([with_kerneldir], [/lib/modules/$with_kernel])
AC_PATH_KERNEL_SOURCE
AC_SUBST([KERNEL_SRC], [$with_kerneldir/build])
AC_SUBST([KERNEL_MOD], [$with_kerneldir/extra])
AM_CONDITIONAL([KERNEL_2_6_32], [test `uname -r|cut -d- -f1` = "2.6.32"])
AM_CONDITIONAL([KMOD_DIR], [test -f /lib/modules/`uname -r`/build])

LT_INIT

version_patch=2
AC_SUBST(version_patch)
version_info=3:2:0
AC_SUBST(version_info)

AC_CONFIG_FILES([doc/NEWS])

# Architecture
AC_MSG_CHECKING([for supported operating system])
case "$host_os" in
  *linux*)
  opsys=linux
AC_DEFINE([LINUX], 1, [Define for the Linux operating system.])
  ;;
  msys*)
  opsys=windows
AC_DEFINE([WINDOWS], 1, [Define for the Windows operating system.])
  ;;
  sunos4*)
  opsys=sunos4
AC_DEFINE([SUNOS4], 1, [Define for the SunOS 4.x operating system.])
  ;;
  solaris2* | sysv[[45]]* | irix[[56]]*)
  opsys=svr4
  AC_DEFINE([SVR4], 1, [Define for the System V release 4 operating
      system or a derivative like Solaris 2.x or Irix 5.x.])
  case "$host_os" in
  sysv4.2uw*)
AC_DEFINE(UNIXWARE, 2, [Define for UnixWare systems.])
  ;;
  sysv5*)
AC_DEFINE(UNIXWARE, 7, [Define for UnixWare systems.])
  ;;
  esac
  ;;
  freebsd*)
  opsys=freebsd
AC_DEFINE([FREEBSD], 1, [Define for the FreeBSD operating system.])
  ;;
  *)
  AC_MSG_RESULT([NO!])
AC_MSG_ERROR([operating system $host_os is not supported by strace])
  ;;
  esac
  AC_MSG_RESULT($opsys)
AC_MSG_CHECKING([for supported architecture])
  case "$host_cpu" in
  bfin)
  arch=bfin
AC_DEFINE([BFIN], 1, [Define for the Blackfin architecture.])
  ;;
  i[[3456]]86|pentium)
  arch=i386
AC_DEFINE([I386], 1, [Define for the i386 architecture.])
  ;;
  ia64)
  arch=ia64
AC_DEFINE([IA64], 1, [Define for the IA64 architecture.])
  ;;
  m68k)
  arch=m68k
AC_DEFINE([M68K], 1, [Define for the m68k architecture.])
  ;;
  sparc64*)
  arch=sparc64
AC_DEFINE([SPARC64], 1, [Define for the SPARC64 architecture.])
  ;;
  sparc*)
  arch=sparc
AC_DEFINE([SPARC], 1, [Define for the SPARC architecture.])
  ;;
  mips*)
  arch=mips
AC_DEFINE([MIPS], 1, [Define for the MIPS architecture.])
  ;;
  alpha*)
  arch=alpha
AC_DEFINE([ALPHA], 1, [Define for the Alpha architecture.])
  ;;
  powerpc*)
  arch=powerpc
AC_DEFINE([POWERPC], 1, [Define for the PowerPC architecture.])
  ;;
  arm*)
  arch=arm
AC_DEFINE([ARM], 1, [Define for the ARM architecture.])
  ;;
  avr32*)
  arch=avr32
AC_DEFINE([AVR32], 1, [Define for the AVR32 architecture.])
  ;;
  s390)
  arch=s390
AC_DEFINE([S390], 1, [Define for the S390 architecture.])
  ;;
  s390x)
  arch=s390x
AC_DEFINE([S390X], 1, [Define for the S390x architecture.])
  ;;
  hppa*|parisc*)
  arch=hppa
AC_DEFINE([HPPA], 1, [Define for the HPPA architecture.])
  ;;
  sh64*)
  arch=sh64
AC_DEFINE([SH64], 1, [Define for the SH64 architecture.])
  ;;
  sh*)
  arch=sh
AC_DEFINE([SH], 1, [Define for the SH architecture.])
  ;;
  x86?64*)
  arch=x86_64
AC_DEFINE([X86_64], 1, [Define for the AMD x86-64 architecture.])
  ;;
  cris|crisv10)
  arch=crisv10
AC_DEFINE([CRISV10], 1, [Define for the CRISv10 architecture.])
  ;;
  crisv32)
  arch=crisv32
AC_DEFINE([CRISV32], 1, [Define for the CRISv32 architecture.])
  ;;
  tile*)
  arch=tile
AC_DEFINE([TILE], 1, [Define for the Tile architecture])
  ;;
  *)
  AC_MSG_RESULT([NO!])
AC_MSG_ERROR([architecture $host_cpu is not supported by strace])
  ;;
  esac
AC_MSG_RESULT($arch)
AC_SUBST(opsys)
AC_SUBST(arch)
AM_CONDITIONAL([LINUX], [test x$opsys = xlinux])
AM_CONDITIONAL([I386], [test x$arch = xi386])
AM_CONDITIONAL([X86_64], [test x$arch = xx86_64])
AM_CONDITIONAL([SUNOS4], [test x$opsys = xsunos4])
AM_CONDITIONAL([SVR4], [test x$opsys = xsvr4])
AM_CONDITIONAL([FREEBSD], [test x$opsys = xfreebsd])
AM_CONDITIONAL([WINDOWS], [test x$opsys = xwindows])


AS_IF([test "x$opsys" = "xwindows"],
  AC_DEFINE_UNQUOTED([_WIN32_WINNT], [0x0601], [Define to the windows os version.])
  AC_DEFINE_UNQUOTED([WINVER], [0x0601], [Define to the windows os version.])
  AC_DEFINE_UNQUOTED([__USE_W32_SOCKETS], 1, [Define for windows sockets compatibility])
  AC_DEFINE_UNQUOTED([WIN32], 1, [Define for windows build compatibility.])
  AC_DEFINE_UNQUOTED([WIN32_LEAN_AND_MEAN], 1, [Define to minimize native windows system calls.])
)
AC_DEFINE_UNQUOTED([NOMINMAX], [1], [Define to use internal MIN and MAX functions.])

# Checks for programs.
AC_PROG_CC
#gl_EARLY

AC_PROG_CXX
AM_PROG_AS
AC_EXEEXT
AC_PROG_YACC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_LIBTOOL
AC_PROG_YACC
AM_PROG_CC_C_O
AM_PROG_GCJ

AC_SYS_LARGEFILE
AC_ISC_POSIX
AC_C_INLINE

# Checks for header files.
AC_CHECK_HEADERS(fcntl.h linux/fd.h memory.h net/errno.h \
  sgtty.h string.h iconv.h fnmatch.h \
  sys/param.h sys/device.h sys/gentape.h \
  sys/inet.h sys/io/trioctl.h sys/ioctl.h \
  sys/mtio.h sys/time.h sys/tprintf.h sys/tape.h \
  unistd.h locale.h arpa/inet.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdio.h stdlib.h sys/socket.h sys/resource.h unistd.h, wctype.h wchar.h utime.h signal.h wchar.h sys/select.h pwd.h \
  paths.h \
  math.h \
)

USER_CPPFLAGS="$CPPFLAGS"
AC_LANG_PUSH([C++])
CPPFLAGS="-std=c++0x"
AC_CHECK_HEADERS([cstdatomic], [have_cstdatomic=1])
CPPFLAGS="-std=c++11"
AC_CHECK_HEADERS([atomic], [have_atomic=1])
AC_LANG_POP([C++])
CPPFLAGS="$USER_CPPFLAGS"
AM_CONDITIONAL(HAVE_CSTDATOMIC, test $have_cstdatomic)
AM_CONDITIONAL(HAVE_ATOMIC, test $have_atomic)
 
AC_HEADER_SYS_WAIT
AC_HEADER_DIRENT
AC_HEADER_MAJOR
AC_HEADER_STAT
AC_HEADER_STDC

AC_CHECK_LIB([m], [fabs], ,
  AC_MSG_ERROR("libm (math library) is required")
)

AC_CHECK_LIB([gmp], [__gmp_version], ,
  AC_MSG_ERROR("libgmp (math library) is required")
)
AC_CHECK_FUNCS([mpn_copyi])

AC_CHECK_LIB([crypto], [BN_new])

AC_CHECK_PROGS([SYSTEMCTL], [systemctl])
AM_CONDITIONAL([HAVE_SYSTEMCTL], [test -n "$SYSTEMCTL"])

AC_CHECK_PROGS([GIT], [git])
AM_CONDITIONAL(HAVE_GIT, [test x"$GIT" = x"git"])

#AC_CHECK_LIB([ssl], [SSL_version], ,
#  AC_MSG_ERROR("libssl (crypt library) is required")
#)

#AC_CHECK_LIB([boost_filesystem], [boost], ,
#  AC_MSG_ERROR("libboost (runtime library) is required")
#)
AC_ARG_WITH([libshare],
  [AS_HELP_STRING([--with-libshare],
  [specify a path to the libshare build directory])],
  [],
  [with_libshare=yes])

LIBSHARE=
AS_IF([test "x$with_libshare" = "xyes"],
  AC_CHECK_LIB([share_sexe], [sexe_prun],
    AC_DEFINE_UNQUOTED([HAVE_LIBSHARE], [1], [Define if you have the libshare library installed]),
    [with_libshare=../../depend/share/build]
  )
)
AC_SUBST([LIBSHARE], $with_libshare)
AM_CONDITIONAL([STATIC_LIBSHARE], test x"$with_libshare" != x"yes") 
AM_CONDITIONAL([GIT_LIBSHARE], test x"$with_libshare" = x"../../depend/share/build") 

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t stdout fpos_t])

gt_TYPE_SSIZE_T
#gl_INIT

AC_CHECK_DECLS([getgrgid],,, [#include <grp.h>])
AC_CHECK_DECLS([getpwuid],,, [#include <pwd.h>])
AC_CHECK_DECLS([time],,, [#include <time.h>])
AC_CHECK_DECLS([isblank],,,[#include <ctype.h>])

AC_REPLACE_FUNCS(waitpid)


# mmap() support
AC_FUNC_MMAP
if test x$ac_cv_func_mmap_fixed_mapped = xyes; then
  AC_CHECK_FUNCS(munmap msync)
fi

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_MEMCMP
AC_FUNC_STRFTIME
AC_FUNC_ALLOCA
AC_CHECK_FUNCS([getcwd gethostname gethostbyname gettimeofday memmove memset mkdir _mkdir socket strchr strdup strerror strrchr atoi strtol strtoll inet_addr ftell stat fstat getrusage fopen fclose fread fwrite fchmod fchown fsync lstat mkfifo readlink symlink kill ftruncate memchr regcomp select setenv setlocale strtoumax open close read write socket ioctl fcntl connect bind accept listen calloc gettid strtod killpg sysconf bsearch isalpha getservbyname getpwnam getpwuid getlogin_r getspnam])

AC_CHECK_MEMBERS([struct stat.st_rdev])

# initd scripts #
AC_CONFIG_FILES([scripts/initd/shcoind], [chmod +x scripts/initd/shcoind])

AC_CHECK_DECL([_PATH_BSHELL],,AC_DEFINE_UNQUOTED([_PATH_BSHELL], "/bin/sh", [Define to system shell path]),[
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
])
AC_CHECK_DECL([_PATH_TTY],,AC_DEFINE_UNQUOTED([_PATH_TTY], "/dev/tty", [Define to tty device node path]),[
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
])
AC_CHECK_DECL([_PATH_DEVNULL],,AC_DEFINE_UNQUOTED([_PATH_DEVNULL], "/dev/null", [Define to devnull device node path]),[
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
])


#AC_SUBST(OPENSSL_DIR, "openssl-1.0.1g")
AC_CHECK_PROGS([CP], [cp])

#AC_CHECK_PROGS([PERL], [perl])


AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
   then AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])
fi
AM_CONDITIONAL([LIBUNISTRING_COMPILE_UNIWIDTH_WIDTH], [false])
AM_CONDITIONAL([HAVE_DOXYGEN],
[test -n "$DOXYGEN"])AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([doc/doxygen.conf])])

# help2man
AC_PATH_PROG(HELP2MAN, help2man, @echo WARNING: skipped: help2man )
AM_CONDITIONAL(HAVE_HELP2MAN, [test x"$HELP2MAN" = x"help2man"])

AC_ARG_ENABLE(pthread,
AS_HELP_STRING([--enable-pthread],
               [enable pthread library, default: no]),
[case "${enableval}" in
             yes) pthread=true ;;
             no)  pthread=false ;;
             *)   AC_MSG_ERROR([bad value ${enableval} for --enable-pthread]) ;;
esac], [pthread=false])
AM_CONDITIONAL(PTHREAD, test x"$pthread" = x"true")
if test "x$enable_pthread" = "xyes" ; then
  AC_CHECK_HEADERS([pthread.h])
  AC_CHECK_LIB([pthread], [pthread_self])
  AC_CHECK_FUNCS([pthread_mutex_lock pthread_mutex_unlock pthread_self pthread_mutex_init pthread_mutex_destroy])
fi

AC_CHECK_FUNCS([BN_bn2mpi])


AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug],
               [enable debugging, default: no]),
[case "${enableval}" in
             yes) debug=true ;;
             no)  debug=false ;;
             *)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac], [debug=false])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

# SEXE Execution Transactions (enabled by default)
AC_ARG_ENABLE([sexe],
  AS_HELP_STRING([--disable-sexe], [Disable execution of SEXE programs.]))
AM_CONDITIONAL(USE_SEXE, [test "x$enable_sexe" != "xno"])
if test "x$enable_sexe" != "xno" ; then
  AC_DEFINE_UNQUOTED([USE_SEXE], 1, [Define to enable execution of SEXE programs.])
fi

AC_ARG_ENABLE([usde],
  AS_HELP_STRING([--enable-usde], [Enable USDE coin service.]))
AM_CONDITIONAL(USDE_SERVICE, [test "x$enable_usde" = "xyes"])
if test "x$enable_usde" = "xyes" ; then
  AC_DEFINE_UNQUOTED([USDE_SERVICE], 1, [Define to enable the USDE coin service.])
fi

AC_ARG_ENABLE([emc2],
  AS_HELP_STRING([--enable-emc2], [Enable EMC2 coin service.]))
AM_CONDITIONAL(EMC2_SERVICE, [test "x$enable_emc2" = "xyes"])
if test "x$enable_emc2" = "xyes" ; then
  AC_DEFINE_UNQUOTED([EMC2_SERVICE], 1, [Define to enable the EMC2 coin service.])
fi

AC_ARG_ENABLE([testnet],
  AS_HELP_STRING([--disable-testnet], [Disable testnet service.]))
AM_CONDITIONAL(TESTNET_SERVICE, [test "x$enable_testnet" != "xno"])
if test "x$enable_testnet" != "xno" ; then
  AC_DEFINE_UNQUOTED([TESTNET_SERVICE], 1, [Define to enable ShareCoin (SHC) Test Network.])
fi

AC_ARG_ENABLE([stratum],
  AS_HELP_STRING([--disable-stratum], [Disable stratum service.]))
AM_CONDITIONAL(STRATUM_SERVICE, [test "x$enable_stratum" != "xno"])
if test "x$enable_stratum" != "xno" ; then
  AC_DEFINE_UNQUOTED([STRATUM_SERVICE], 1, [Define to enable stratum service.])
fi

AC_ARG_ENABLE([rpc],
  AS_HELP_STRING([--disable-rpc], [Disable RPC service.]))
AM_CONDITIONAL(RPC_SERVICE, [test "x$enable_rpc" != "xno"])
if test "x$enable_rpc" != "xno" ; then
  AC_DEFINE_UNQUOTED([RPC_SERVICE], 1, [Define to enable RPC service.])
fi

#enable_wallet="yes"
#AM_CONDITIONAL(ENABLE_WALLET, [test "x$enable_wallet" != "xno"])
#AM_CONDITIONAL([ENABLE_WALLET], 1, [Define to share-wallet functionality.])

AC_OUTPUT(Makefile depend/Makefile src/secp256k1/Makefile src/coin-console/Makefile src/share-coin/Makefile doc/Makefile bin/Makefile)

