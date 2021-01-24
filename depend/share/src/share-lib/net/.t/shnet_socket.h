
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
 */

#ifndef __SOCKET__SOCKET_H__
#define __SOCKET__SOCKET_H__

/**
 * @addtogroup libshare_net
 * @{
 */

extern shnet_t _sk_table[USHORT_MAX];

int shnet_sk(void);
int shnet_socket(int domain, int type, int protocol);
struct sockaddr *shnet_host(int sockfd);


/**
 * @}
 */

#endif /* ndef __SOCKET__SOCKET_H__ */


