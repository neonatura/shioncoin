
/*
 * @copyright
 *
 *  Copyright 2018 Brian Burrell
 *
 *  This file is part of Shioncoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcoind.h"

#ifndef ERR_NOEXEC
#define ERR_NOEXEC -8
#endif

static err_code_t _error_code_table[] = {
	/* reserved */
	{ ERR_UNKNOWN, "Unknown error" },

	/* posix */
	{ ERR_NONE, "NONE" },
	{ ERR_NOENT, "entity not found" },
	{ ERR_SRCH, "SRCH" },
	{ ERR_IO, "IO" },
	{ ERR_2BIG, "2BIG" },
	{ ERR_NOEXEC, "executable format error" },
	{ ERR_BADF, "BADF" },
	{ ERR_AGAIN, "resource temporarily unavailable" },
	{ ERR_NOMEM, "unable to allocate memory" },
	{ ERR_ACCESS, "permission denied" },
	{ ERR_EXIST, "entity already exists" },
	{ ERR_NOTDIR, "NOTDIR" },
	{ ERR_ISDIR, "ISDIR" },
	{ ERR_INVAL, "invalid parameter" },
	{ ERR_NFILE, "NFILE" },
	{ ERR_FBIG, "FBIG" },
	{ ERR_NOSPC, "NOSPC" },
	{ ERR_NAMETOOLONG, "NAMETOOLONG" },
	{ ERR_NOLCK, "NOLCK" },
	{ ERR_NOMSG, "NOMSG" },
	{ ERR_XFULL, "XFULL" },
	{ ERR_OVERFLOW, "OVERFLOW" },
	{ ERR_NOTUNIQ, "NOTUNIQ" },
	{ ERR_ILSEQ, "illegal byte sequence" },
	{ ERR_CONNRESET, "CONNRESET" },
	{ ERR_NOBUFS, "NOBUFS" },
	{ ERR_TIMEDOUT, "timeout" },
	{ ERR_CONNREFUSED, "connection refused" },
	{ ERR_ALREADY, "ALREADY" },
	{ ERR_REMOTEIO, "REMOTEIO" },
	{ ERR_TIME, "TIME" },
	{ ERR_NONET, "NONET" },
	{ ERR_NOPKG, "NOPKG" },
	{ ERR_REMOTE, "remote resource" },
	{ ERR_NOLINK, "NOLINK" },
	{ ERR_PROTO, "protocol error" },
	{ ERR_NOTSOCK, "NOTSOCK" },
	{ ERR_OPNOTSUPP, "operation not supported" },
	{ ERR_ADDRINUSE, "ADDRINUSE" },
	{ ERR_ADDRNOTAVAIL, "ADDRNOTAVAIL" },
	{ ERR_NETDOWN, "NETDOWN" },
	{ ERR_NETUNREACH, "NETUNREACH" },
	{ ERR_SHUTDOWN, "SHUTDOWN" },
	{ ERR_TOOMANYREFS, "TOOMANYREFS" },
	{ ERR_INPROGRESS, "INPROGRESS" },
	{ ERR_NOMEDIUM, "NOMEDIUM" },
	{ ERR_CANCELED, "CANCELED" },
	{ ERR_NOKEY, "key not available" },
	{ ERR_KEYEXPIRED, "expired key" },
	{ ERR_KEYREVOKED, "revoked key" },
	{ ERR_KEYREJECTED, "rejected key" },
	{ ERR_OWNERDEAD, "OWNERDEAD" },

	/* custom */
	{ ERR_EXPIRE, "Task has expired" },
	{ ERR_ENCODE, "Serialization failure" },
	{ ERR_FEE, "Insufficient funds" },
	{ ERR_COMMIT, "Record not commited" },
	{ ERR_NOCLASS, "class not found" },
	{ ERR_NOMETHOD, "method not found" },

	/* terminator */
	{ 0, NULL },
};

const char *error_str(int code)
{
	static const char *unknown_error_str = "Unknown error";
	int i;

	if (code > 0)
		code *= -1;

	for (i = 0; _error_code_table[i].label; i++) {
		if (_error_code_table[i].code == code)
			return (_error_code_table[i].label);
	}

	return (unknown_error_str);
}

int error_code(int sys_code)
{
	return (stderr2sherr(sys_code));
}
