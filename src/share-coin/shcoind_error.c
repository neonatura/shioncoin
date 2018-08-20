
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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

#include "shcoind.h"

static err_code_t _error_code_table[] = {
	/* reserved */
	{ ERR_UNKNOWN, "Unknown error" },

	/* posix */
	{ ERR_NONE, "NONE" },
	{ ERR_NOENT, "Invalid entity specified" },
	{ ERR_SRCH, "SRCH" },
	{ ERR_IO, "IO" },
	{ ERR_2BIG, "2BIG" },
	{ ERR_BADF, "BADF" },
	{ ERR_AGAIN, "AGAIN" },
	{ ERR_NOMEM, "Unable to allocate memory" },
	{ ERR_ACCESS, "Permission denied" },
	{ ERR_EXIST, "EXIST" },
	{ ERR_NOTDIR, "NOTDIR" },
	{ ERR_ISDIR, "ISDIR" },
	{ ERR_INVAL, "Invalid parameter specified" },
	{ ERR_NFILE, "NFILE" },
	{ ERR_FBIG, "FBIG" },
	{ ERR_NOSPC, "NOSPC" },
	{ ERR_NAMETOOLONG, "NAMETOOLONG" },
	{ ERR_NOLCK, "NOLCK" },
	{ ERR_NOMSG, "NOMSG" },
	{ ERR_XFULL, "XFULL" },
	{ ERR_OVERFLOW, "OVERFLOW" },
	{ ERR_NOTUNIQ, "NOTUNIQ" },
	{ ERR_ILSEQ, "Illegal byte sequence" },
	{ ERR_CONNRESET, "CONNRESET" },
	{ ERR_NOBUFS, "NOBUFS" },
	{ ERR_TIMEDOUT, "TIMEDOUT" },
	{ ERR_CONNREFUSED, "CONNREFUSED" },
	{ ERR_ALREADY, "ALREADY" },
	{ ERR_REMOTEIO, "REMOTEIO" },
	{ ERR_TIME, "TIME" },
	{ ERR_NONET, "NONET" },
	{ ERR_NOPKG, "NOPKG" },
	{ ERR_REMOTE, "REMOTE" },
	{ ERR_NOLINK, "NOLINK" },
	{ ERR_PROTO, "PROTO" },
	{ ERR_NOTSOCK, "NOTSOCK" },
	{ ERR_OPNOTSUPP, "Operation not support" },
	{ ERR_ADDRINUSE, "ADDRINUSE" },
	{ ERR_ADDRNOTAVAIL, "ADDRNOTAVAIL" },
	{ ERR_NETDOWN, "NETDOWN" },
	{ ERR_NETUNREACH, "NETUNREACH" },
	{ ERR_SHUTDOWN, "SHUTDOWN" },
	{ ERR_TOOMANYREFS, "TOOMANYREFS" },
	{ ERR_INPROGRESS, "INPROGRESS" },
	{ ERR_NOMEDIUM, "NOMEDIUM" },
	{ ERR_CANCELED, "CANCELED" },
	{ ERR_NOKEY, "NOKEY" },
	{ ERR_KEYEXPIRED, "KEYEXPIRED" },
	{ ERR_KEYREVOKED, "KEYREVOKED" },
	{ ERR_KEYREJECTED, "KEYREJECTED" },
	{ ERR_OWNERDEAD, "OWNERDEAD" },

	/* custom */
	{ ERR_EXPIRE, "Task has expired" },
	{ ERR_ENCODE, "Serialization failure" },
	{ ERR_FEE, "Insufficient funds" },
	{ ERR_COMMIT, "Record not commited" },

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
