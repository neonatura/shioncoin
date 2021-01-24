
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


int shnet_accept(int sockfd)
{
  struct sockaddr peer_addr;
  socklen_t val_len;
  socklen_t peer_len;
  socklen_t src_len;
  ssize_t sk;
  unsigned int usk;
  int val;
  int err;

  peer_len = (socklen_t)sizeof(peer_addr);
  memset(&peer_addr, 0, sizeof(peer_addr));
  sk = accept(sockfd, &peer_addr, &peer_len);
  if (sk == -1) {
    return (errno2sherr());
	}

  usk = (unsigned int)sk;
  src_len = sizeof(_sk_table[usk].addr_src);
  getsockname(sk, &_sk_table[usk].addr_src, &src_len);
  memcpy(&_sk_table[usk].addr_dst,
      &peer_addr, MIN(sizeof(_sk_table[usk].addr_dst), peer_len));

  _sk_table[usk].fd = sk;
  _sk_table[usk].flags |= SHNET_ALIVE;

	val_len = sizeof(int);
	err = getsockopt(sk, SOL_SOCKET, SO_RCVBUF, &val, &val_len);
	if (!err)
		_sk_table[usk].rcvbuf_len = val;

	val_len = sizeof(int);
	err = getsockopt(sk, SOL_SOCKET, SO_SNDBUF, &val, &val_len);
	if (!err)
		_sk_table[usk].sndbuf_len = val;


  memcpy(&_sk_table[usk].key, ashkey_blank(), sizeof(shkey_t));

  return (sk);
}

int shnet_accept_nb(int sockfd)
{
  int err;
  fd_set read_set;
  long ms; 

  ms = 0;
  FD_ZERO(&read_set);
  FD_SET(sockfd, &read_set);
  err = shnet_verify(&read_set, NULL, &ms);
  if (err == 1)
    return (shnet_accept(sockfd));

  return (err);
}

