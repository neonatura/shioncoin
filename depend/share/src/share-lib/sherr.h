
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura 
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  


#ifndef __SHERR_H__
#define __SHERR_H__

#include <errno.h>

#ifndef EACCESS
#define EACCESS EACCES
#endif

/**
 * The libshare error codes.
 * @ingroup libshare
 * @defgroup libshare_error Generic libshare error status codes.
 * @{
 */


#define SHERR_NONE 0
#define SHERR_UNKNOWN -1
#define SHERR_NOENT -2 /* ENOENT */
#define SHERR_SRCH -3 /* ESRCH */
#define SHERR_IO -5 /* EIO */
#define SHERR_2BIG -7 /* E2BIG */
#define SHERR_NOEXEC -8 /* NOEXEC */
#define SHERR_BADF -9 /* EBADF */
#define SHERR_AGAIN -11 /* EAGAIN */
#define SHERR_NOMEM -12 /* ENOMEM */
#define SHERR_ACCESS -13 /* EACCES */
#define SHERR_EXIST -17 /* EEXIST */
#define SHERR_NOTDIR -20 /* ENOTDIR */
#define SHERR_ISDIR -21 /* EISDIR */
#define SHERR_INVAL -22 /* EINVAL */
#define SHERR_NFILE -23  /* ENFILE (File table overflow) */
#define SHERR_FBIG -27 /* EFBIG */
#define SHERR_NOSPC -28 /* ENOSPC (No space left on device) */
#define SHERR_NAMETOOLONG -36 /* ENAMETOOLONG (File name too long) */
#define SHERR_NOLCK -37 /* No record locks available */
#define SHERR_NOMSG -42 /* ENOMSG */
#define SHERR_XFULL -54 /* EXFULL (Exchange full) */
#define SHERR_OVERFLOW -75 /* Value too large for defined value type */
#define SHERR_NOTUNIQ -76 /* Name not unique on network */
#define SHERR_ILSEQ -84 /* Illegal [byte] sequence. */
#define SHERR_CONNRESET -104 /* Connection reset by peer. */
#define SHERR_NOBUFS -105 /* No buffer space available. */
#define SHERR_ISCONN -106 /* Transport endpoint is already connected */
#define SHERR_NOTCONN -107 /* Transport endpoint is not connected */
#define SHERR_TIMEDOUT -110 /* Conenction timed out */
#define SHERR_CONNREFUSED -111 /* Conenction refused */
#define SHERR_ALREADY -114 /* Operation already in progress */ 
#define SHERR_REMOTEIO -121 /* EREMOTEIO */
#define SHERR_TIME -62 /* Timer expired */
#define SHERR_NONET -64  /* Machine is not on the network */
#define SHERR_NOPKG -65  /* Package not installed */
#define SHERR_REMOTE -66  /* Object is remote */
#define SHERR_NOLINK -67  /* Link has been severed */
#define SHERR_PROTO -71 /* Protocol error */
#define SHERR_NOTSOCK -88  /* Socket operation on non-socket */
#define SHERR_OPNOTSUPP -95 /* Operation not supported */
#define SHERR_ADDRINUSE -98  /* Address already in use */
#define SHERR_ADDRNOTAVAIL -99  /* Cannot assign requested address */
#define SHERR_NETDOWN -100 /* Network is down */
#define SHERR_NETUNREACH -101 /* Network is unreachable */
#define SHERR_SHUTDOWN -108 /* Cannot send after transport endpoint shutdown */
#define SHERR_TOOMANYREFS -109 /* Too many references: cannot splice */
#define SHERR_INPROGRESS -115 /* Operation now in progress */
#define SHERR_NOMEDIUM -123 /* No medium found */

/** Operation canceled */
#define SHERR_CANCELED -125

/** Required key not available */
#define SHERR_NOKEY -126

/** Key has expired */
#define SHERR_KEYEXPIRED -127

/** Key has been revoked */
#define SHERR_KEYREVOKED -128

/** Key was rejected by service */
#define SHERR_KEYREJECTED -129

/** Owner died */
#define SHERR_OWNERDEAD -130



int stderr2sherr(int std_err);
int errno2sherr(void);
int sherr2stderr(int sh_err);

/**
 * Converts a libshare error code to a libshare error message.
 * @param _errcode A libshare error code.
 * @returns A string message associated with the libshare error code.
 */
const char *sherrstr(int sh_err);

/* mimic "strerror()" */ 
#define shstrerror(_code) \
	(sherrstr(_code))


/**
 * @}
 */

#ifdef __SHARE_C__
typedef struct _errcode_t {
	int code; /* sys code */
	int err; /* share code */
} _errcode_t;
static _errcode_t _share_stderr_table[] = {
	{ ENOENT, SHERR_NOENT },
	{ ESRCH, SHERR_SRCH },
	{ EIO, SHERR_IO },
	{ E2BIG, SHERR_2BIG },
	{ EBADF, SHERR_BADF },
	{ EAGAIN, SHERR_AGAIN },
	{ ENOMEM, SHERR_NOMEM },
	{ EACCESS, SHERR_ACCESS },
	{ EEXIST, SHERR_EXIST },
	{ ENOTDIR, SHERR_NOTDIR },
	{ EISDIR, SHERR_ISDIR },
	{ EINVAL, SHERR_INVAL },
	{ ENFILE, SHERR_NFILE },
	{ EFBIG, SHERR_FBIG },
	{ ENOSPC, SHERR_NOSPC },
	{ ENAMETOOLONG, SHERR_NAMETOOLONG },
	{ ENOLCK, SHERR_NOLCK },
	{ ENOMSG, SHERR_NOMSG },
	{ EXFULL, SHERR_XFULL },
	{ EOVERFLOW, SHERR_OVERFLOW },
	{ ENOTUNIQ, SHERR_NOTUNIQ },
	{ EILSEQ, SHERR_ILSEQ },
	{ ECONNRESET, SHERR_CONNRESET },
	{ ENOBUFS, SHERR_NOBUFS },
	{ EISCONN, SHERR_ISCONN },
	{ ENOTCONN, SHERR_NOTCONN },
	{ ETIMEDOUT, SHERR_TIMEDOUT },
	{ ECONNREFUSED, SHERR_CONNREFUSED },
	{ EALREADY, SHERR_ALREADY },
#ifdef EREMOTEIO
	{ EREMOTEIO, SHERR_REMOTEIO },
#endif
#ifdef ETIME
	{ ETIME, SHERR_TIME },
#endif
	{ ENONET, SHERR_NONET },
	{ ENOPKG, SHERR_NOPKG },
	{ EREMOTE, SHERR_REMOTE },
	{ ENOLINK, SHERR_NOLINK },
	{ EPROTO, SHERR_PROTO },
	{ ENOTSOCK, SHERR_NOTSOCK },
	{ EOPNOTSUPP, SHERR_OPNOTSUPP },
	{ EADDRINUSE, SHERR_ADDRINUSE },
	{ EADDRNOTAVAIL, SHERR_ADDRNOTAVAIL },
	{ ENETDOWN, SHERR_NETDOWN },
	{ ENETUNREACH, SHERR_NETUNREACH },
	{ ESHUTDOWN, SHERR_SHUTDOWN },
	{ ETOOMANYREFS, SHERR_TOOMANYREFS },
	{ EINPROGRESS, SHERR_INPROGRESS },
	{ ENOMEDIUM, SHERR_NOMEDIUM },
	{ ECANCELED, SHERR_CANCELED },
#ifdef ENOKEY
	{ ENOKEY, SHERR_NOKEY },
#endif
#ifdef EKEYEXPIRED
	{ EKEYEXPIRED, SHERR_KEYEXPIRED },
#endif
#ifdef EKEYREVOKED 
	{ EKEYREVOKED, SHERR_KEYREVOKED },
#endif
#ifdef EKEYREJECTED
	{ EKEYREJECTED, SHERR_KEYREJECTED },
#endif
#ifdef EOWNERDEAD
	{ EOWNERDEAD, SHERR_OWNERDEAD },
#endif

	/* terminator */
	{ 0, 0 }
};
#endif


/* for conveinence */
#define ERR_NONE SHERR_NONE
#define ERR_NOENT SHERR_NOENT
#define ERR_SRCH SHERR_SRCH
#define ERR_IO SHERR_IO
#define ERR_2BIG SHERR_2BIG
#define ERR_NOEXEC SHERR_NOEXEC
#define ERR_BADF SHERR_BADF
#define ERR_AGAIN SHERR_AGAIN
#define ERR_NOMEM SHERR_NOMEM
#define ERR_ACCESS SHERR_ACCESS
#define ERR_EXIST SHERR_EXIST
#define ERR_NOTDIR SHERR_NOTDIR
#define ERR_ISDIR SHERR_ISDIR
#define ERR_INVAL SHERR_INVAL
#define ERR_NFILE SHERR_NFILE
#define ERR_FBIG SHERR_FBIG
#define ERR_NOSPC SHERR_NOSPC
#define ERR_NAMETOOLONG SHERR_NAMETOOLONG
#define ERR_NOLCK SHERR_NOLCK
#define ERR_NOMSG SHERR_NOMSG
#define ERR_XFULL SHERR_XFULL
#define ERR_OVERFLOW SHERR_OVERFLOW
#define ERR_NOTUNIQ SHERR_NOTUNIQ
#define ERR_ILSEQ SHERR_ILSEQ
#define ERR_CONNRESET SHERR_CONNRESET
#define ERR_NOBUFS SHERR_NOBUFS
#define ERR_TIMEDOUT SHERR_TIMEDOUT
#define ERR_CONNREFUSED SHERR_CONNREFUSED
#define ERR_ALREADY SHERR_ALREADY
#define ERR_REMOTEIO SHERR_REMOTEIO
#define ERR_TIME SHERR_TIME
#define ERR_NONET SHERR_NONET
#define ERR_NOPKG SHERR_NOPKG
#define ERR_REMOTE SHERR_REMOTE
#define ERR_NOLINK SHERR_NOLINK
#define ERR_PROTO SHERR_PROTO
#define ERR_NOTSOCK SHERR_NOTSOCK
#define ERR_OPNOTSUPP SHERR_OPNOTSUPP
#define ERR_ADDRINUSE SHERR_ADDRINUSE
#define ERR_ADDRNOTAVAIL SHERR_ADDRNOTAVAIL
#define ERR_NETDOWN SHERR_NETDOWN
#define ERR_NETUNREACH SHERR_NETUNREACH
#define ERR_SHUTDOWN SHERR_SHUTDOWN
#define ERR_TOOMANYREFS SHERR_TOOMANYREFS
#define ERR_INPROGRESS SHERR_INPROGRESS
#define ERR_NOMEDIUM SHERR_NOMEDIUM
#define ERR_CANCELED SHERR_CANCELED
#define ERR_NOKEY SHERR_NOKEY
#define ERR_KEYEXPIRED SHERR_KEYEXPIRED
#define ERR_KEYREVOKED SHERR_KEYREVOKED
#define ERR_KEYREJECTED SHERR_KEYREJECTED
#define ERR_OWNERDEAD SHERR_OWNERDEAD
#define ERR_ISCONN SHERR_ISCONN
#define ERR_NOTCONN SHERR_NOTCONN


#endif /* ndef __SHERR_H__ */

