/*
 *  Copyright 2013 Brian Burrell 
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
 *
 *
 *  Todo:
 *    handle EBADF (no accept for 3 min)
 */

#ifndef __NET__SHNET_SELECT_H__
#define __NET__SHNET_SELECT_H__

/**
 * @addtogroup libshare_net
 * @{
 */

/**
 * Waits on the specified read/write socket streams and marks which are available for an IO operation.
 * @see shnet_select()
 */
int shnet_verify(fd_set *readfds, fd_set *writefds, long *millis);

/**
 * Performs a POSIX select() against a set of @ref shnet_t socket streams.
 */
int shnet_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);


/**
 * @}
 */

#endif /* ndef __NET__SHNET_SELECT_H__ */


