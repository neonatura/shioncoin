
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


typedef struct shhost_t
{
  char name[MAXHOSTNAMELEN+1];
  uint32_t addr_fam;
  uint32_t addr_list_size;
  struct sockaddr *addr_list;
} shhost_t;

static shmap_t *_host_table;

struct hostent *shresolve_cache_get(char *hostname)
{
  static struct hostent ret_ent;
  static char *ret_alias[2];
  static struct sockaddr ret_addr[64];
  shhost_t *host;
  shkey_t *key;
  int i;

  if (!_host_table)
    return (NULL);

  key = shkey_str(hostname);
  host = (shhost_t *)shmap_get_void(_host_table, key);
  shkey_free(&key);
  if (!host)
    return (NULL);

  memset(&ret_ent, 0, sizeof(ret_ent));
  ret_ent.h_aliases = (char **)ret_alias;
  ret_ent.h_addr_list = (char **)ret_addr;

  ret_ent.h_name = host->name;
  ret_ent.h_addrtype = host->addr_fam;
  ret_ent.h_length = host->addr_list_size * sizeof(struct sockaddr); 
  for (i = 0; i < ret_ent.h_length; i++) {
    ret_ent.h_addr_list[i] = (char *)(host->addr_list + i);
  }

}
void shresolve_cache_set(char *hostname, struct hostent *ent)
{
/* .. */
}

struct hostent *shresolve(char *hostname)
{
	struct hostent *host;

  if (!hostname || !*hostname)
    return (NULL);

  host = shresolve_cache_get(hostname);
  if (host)
    return (host);

	host = gethostbyname(hostname);
  shresolve_cache_set(hostname, host);
	if (!host)
		return (NULL);

#if 0
  /* close sys dns socket */
  endhostent();
#endif

	return (host);
}

struct sockaddr *shaddr(int sockfd)
{
  static struct sockaddr ret_addr;
  unsigned int usk = (unsigned int)sockfd;

  if (usk >= USHORT_MAX)
    return (NULL);

  memcpy(&ret_addr, &_sk_table[usk].addr_dst, sizeof(ret_addr));

  return (&ret_addr);
}

const char *shaddr_print(struct sockaddr *addr)
{
  static char ret_text[1024];
  struct sockaddr_in6 *in6;
  struct sockaddr_in *in;
  sa_family_t in_fam;
  char *ptr;

  if (!addr)
    return (NULL); /* error */

  in_fam = *((sa_family_t *)addr);
  memset(ret_text, 0, sizeof(ret_text));
  switch (in_fam) {
    case AF_INET:
      in = (struct sockaddr_in *)addr;
      sprintf(ret_text, "%s:%d", inet_ntoa(in->sin_addr), ntohs(in->sin_port));
      break;
    case AF_INET6:
      in6 = (struct sockaddr_in6 *)addr;
      ptr = (char *)&in6->sin6_addr;
      sprintf(ret_text,
          "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x %d",
          (int)ptr[0], (int)ptr[1], (int)ptr[2], (int)ptr[3],
          (int)ptr[4], (int)ptr[5], (int)ptr[6], (int)ptr[7],
          (int)ptr[8], (int)ptr[9], (int)ptr[10], (int)ptr[11],
          (int)ptr[12], (int)ptr[13], (int)ptr[14], (int)ptr[15],
          (int)ntohs(in6->sin6_port));
  }

  return (ret_text);
}



