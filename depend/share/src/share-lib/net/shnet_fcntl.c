
/*
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
*/  

#include "share.h"

int shnet_fcntl(int fd, int cmd, long arg)
{
	int err;
	unsigned short usk;

	usk = (unsigned short)fd;
	if (!(_sk_table[usk].flags & SHNET_ALIVE))
		return (-EBADF);

	err = 0;
	switch (arg) {
		case O_NONBLOCK:
			if (cmd == F_SETFL) {
				_sk_table[usk].flags |= SHNET_ASYNC;
        err = fcntl(fd, cmd, arg);
			} else if (cmd == F_GETFL) {
				err = (_sk_table[usk].flags & SHNET_ASYNC);
			}
			break;

		default:
#ifdef HAVE_FCNTL
			err = fcntl(fd, cmd, arg);
#endif
			break;
	}

	return (err);
}

