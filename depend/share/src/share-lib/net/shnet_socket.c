
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

shnet_t _sk_table[USHORT_MAX];

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif


int shnet_sk(void)
{
  int sk;

	sk = shnet_socket(AF_INET, SOCK_STREAM, 0);

  if (sk >= 0) {
    unsigned int usk = (unsigned int)sk;
    if (usk < USHORT_MAX) {
      memset(&_sk_table[usk].key, '\000', sizeof(shkey_t));
    }
  }

	return (sk);
}

int shnet_socket(int domain, int type, int protocol)
{
	int err;
	int sk;
	int val;
	int flags;
	int val_len;
	unsigned short usk;

	if (domain != PF_INET)
		return -EAFNOSUPPORT;
 
	if (type != SOCK_STREAM)
		return -EPROTONOSUPPORT;

	flags = 0;

  sk = -1;
  switch (protocol) {
    case 0:
	  case IPPROTO_TCP:
      sk = socket(domain, SOCK_STREAM, 0);
      break;
#ifdef IPPROTO_SHNET
    case IPPROTO_SHNET:
      sk = socket(domain, type, IPPROTO_SHNET); 
      if (sk == -1) {
        if (domain == AF_INET) 
          sk = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        else if (domain == AF_INET6) 
          sk = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
        flags |= SHNET_EMULATE;
      }
      break;
#endif
    default:
      return -EPROTONOSUPPORT;
  }


	if (sk == -1)
		return (-1);

	flags |= SHNET_ALIVE;

#if 0
	err = fcntl(sk, F_SETFL, O_NONBLOCK);
	if (err) {
		close(sk);
		return (-1);
	}

#ifdef SO_HDRINCL
	val = 0;
	err = setsockopt(sk, SOL_SOCKET, SO_HDRINCL, &val, sizeof(val));
	if (!err)
		flags |= SHNET_IPHDR;
#endif
#endif

  /* maximum for most typical OSs */
//	val = 50630;
	val = 65536;
	setsockopt(sk, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
//	val = 87356;
	val = 65536;
	setsockopt(sk, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));

/*
setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout)
setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout)
*/ 

	usk = (unsigned short)sk;
	_sk_table[usk].fd = sk;
	_sk_table[usk].flags = flags;
  _sk_table[usk].protocol = protocol;

#ifdef LINUX
	/* safe compatible minimum */
	_sk_table[usk].rcvbuf_len = 16360;
	_sk_table[usk].sndbuf_len = 16360;
#endif

	val_len = sizeof(int);
	err = getsockopt(sk, SOL_SOCKET, SO_RCVBUF, &val, &val_len);
	if (!err)
		_sk_table[usk].rcvbuf_len = val;

	val_len = sizeof(int);
	err = getsockopt(sk, SOL_SOCKET, SO_SNDBUF, &val, &val_len);
	if (!err)
		_sk_table[usk].sndbuf_len = val;

#if 0
  _sk_table[usk].src_addr.addr.sin_family = domain;
  _sk_table[usk].dst_addr.addr.sin_family = domain;
#endif

  memcpy(&_sk_table[usk].key, ashkey_blank(), sizeof(shkey_t));

	return (sk);
} 

int shnet_flags(int fd)
{
  unsigned int usk = (unsigned int)fd;

  if (usk >= USHORT_MAX)
    return (0);

  return (_sk_table[usk].flags);
}





/**
 * A socket option for specifying the maximum duration before a connect attempt is considered expired.
 */
#define SO_CONTIMEO

