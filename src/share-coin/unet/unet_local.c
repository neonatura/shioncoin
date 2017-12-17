
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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
#include <sys/types.h>
#include <ifaddrs.h>


#define MAX_IPADDR_TABLE_SIZE 512
static char *ipaddr_table[MAX_IPADDR_TABLE_SIZE];
static char primary_ipaddr[MAXHOSTNAMELEN+1];
static int ipaddr_index;

#define CHKIP_HTML_TEMPLATE \
  "GET / HTTP/1.1\r\n" \
  "Host: checkip.dyndns.org\r\n" \
  "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n" \
  "Connection: close\r\n" \
  "\r\n"
static const char *CHKIP_IP_TAG = "Current IP Address: ";

static int external_local_discover_html(char *serv_hostname, struct in_addr *net_addr)
{
  shbuf_t *buff;
  fd_set r_set;
  long to;
  char *text;
  int err;
  int sk;

  /* checkip.dyndns.org */
  sk = shconnect_host(serv_hostname, 80, SHNET_ASYNC);
  if (sk < 0) {
    return (sk);
  }

  err = shnet_write(sk, CHKIP_HTML_TEMPLATE, strlen(CHKIP_HTML_TEMPLATE));
  if (err < 0) {
    shnet_close(sk);
    return (err);
  }

  to = 3000; /* 3s */
  FD_ZERO(&r_set);
  FD_SET(sk, &r_set);
  shnet_verify(&r_set, NULL, &to);

  buff = shnet_read_buf(sk);
  if (!buff) {
    shnet_close(sk);
    return (SHERR_INVAL);
  }

  text = (char *)shbuf_data(buff);
  if (!text) {
    shnet_close(sk);
    return (SHERR_AGAIN);
  }

  text = strstr(text, CHKIP_IP_TAG);
  if (!text) {
    shnet_close(sk);
    return (SHERR_INVAL);
  }

  text += strlen(CHKIP_IP_TAG);
  strtok(text, "<");
  inet_aton(text, net_addr);

  shbuf_clear(buff);
  shnet_close(sk);

  return (0);
}

static int external_local_discover_raw(char *serv_hostname, struct in_addr *net_addr)
{
  shbuf_t *buff;
  fd_set r_set;
  long to;
  char *text;
  int err;
  int sk;

  sk = shconnect_host(serv_hostname, 411, SHNET_ASYNC);
  if (sk < 0) {
    return (sk);
  }

  to = 3000; /* 3s */
  FD_ZERO(&r_set);
  FD_SET(sk, &r_set);
  shnet_verify(&r_set, NULL, &to);

  buff = shnet_read_buf(sk);
  if (!buff) {
    shnet_close(sk);
    return (SHERR_INVAL);
  }

  text = (char *)shbuf_data(buff);
  if (!text) {
    shnet_close(sk);
    return (SHERR_AGAIN);
  }

  strtok(text, "\n");
  if (inet_aton(text, net_addr) == 0)
    return (SHERR_INVAL);

  shbuf_clear(buff);
  shnet_close(sk);

  return (0);
}

void unet_local_set(const char *ipaddr)
{

  if (!ipaddr || !*ipaddr)
    return;

  memset(primary_ipaddr, 0, sizeof(primary_ipaddr));
  strncpy(primary_ipaddr, ipaddr, sizeof(primary_ipaddr)-1);

  unet_local_add(ipaddr);
}

/* todo: retain lat/lon returned in response */
int unet_local_discover1(double *lat_p, double *lon_p) /* ipv4 */
{
  struct in_addr addr;
  struct sockaddr_in sin;
  char selfip_addr[256];
  char buf[512];
  time_t now;
  int err;

  memset(&addr, 0, sizeof(addr));
  strcpy(selfip_addr, "45.79.211.217"); /* s.neo-natura.com */
  err = external_local_discover_raw(selfip_addr, &addr);
  if (err)
    return (err);

  memset(buf, 0, sizeof(buf));
  strncpy(buf, inet_ntoa(addr), sizeof(buf));
  if (!*buf)
    return (SHERR_PROTO);

  /* cache address persistently */
  shpref_set("shcoind.net.addr", buf);

  /* add to collection */
  unet_local_set(buf);

  /* retain a cache time-stamp */
  now = time(NULL);
  sprintf(buf, "%lu", (unsigned long)now);
  shpref_set("shcoind.net.addr.stamp", buf);

  return (0);
}

void unet_local_discover2(void) /* ipv4 */
{
  struct in_addr addr;
  struct sockaddr_in sin;
  char selfip_addr[256];
  char buf[512];
  time_t now;
  int err;

  memset(&addr, 0, sizeof(addr));
  strcpy(selfip_addr, "91.198.22.70");
  err = external_local_discover_html(selfip_addr, &addr);
  if (err)
    return;

  memset(buf, 0, sizeof(buf));
  strncpy(buf, inet_ntoa(addr), sizeof(buf));
  if (!*buf)
    return;

  /* cache address persistently */
  shpref_set("shcoind.net.addr", buf);

  /* add to collection */
  unet_local_set(buf);

  /* retain a cache time-stamp */
  now = time(NULL);
  sprintf(buf, "%lu", (unsigned long)now);
  shpref_set("shcoind.net.addr.stamp", buf);

}

void unet_local_init(void)
{
  struct ifaddrs *addrs, *ifa;
  struct in_addr sin;
  struct in6_addr sin6;
  char buf[256];
  time_t scan_time;
  shnum_t lat, lon;
  shgeo_t geo;

  unet_local_add("127.0.0.1"); /* ipv4 standard loopback */
  unet_local_add("::1"); /* ipv6 standard loopback */

  if (0 == getifaddrs(&addrs)) {
    for (ifa = addrs; ifa; ifa = ifa->ifa_next) {
      if (!ifa->ifa_addr)
        continue;

      memset(buf, 0, sizeof(buf));
      if (ifa->ifa_addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)-1);
      } else if (ifa->ifa_addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin = (struct sockaddr_in6 *)ifa->ifa_addr;
        inet_ntop(AF_INET6, &sin->sin6_addr, buf, sizeof(buf)-1);
      }

      if (*buf && !unet_local_verify(buf))
        unet_local_add(buf);
    }

    freeifaddrs(addrs);
  }

  memset(&geo, 0, sizeof(geo));
  lat = atof(shpref_get("shcoind.geo.latitude", "0"));
  lon = atof(shpref_get("shcoind.geo.longitude", "0"));

  scan_time = (time_t)atol(shpref_get("shcoind.net.addr.stamp", "0"));
  if (scan_time < (time(NULL) - 86400)) { /* > 1 day */
    if (0 != unet_local_discover1(&lat, &lon))
      unet_local_discover2();

    memset(buf, 0, sizeof(buf));
    strncpy(buf, shpref_get("shcoind.net.addr", ""), sizeof(buf)-1);
  } else {
    /* check for cached or pre-defined IP address. */
    memset(buf, 0, sizeof(buf));
    strncpy(buf, shpref_get("shcoind.net.addr", ""), sizeof(buf)-1);
    unet_local_set(buf);
  }

  /* set the local geodetic location based on the listening address. */
  if (lat != 0.0 && lon != 0.0) {
    shgeo_set(&geo, lat, lon, 0);
  } else {
    /* lookup in local libshare db */
    (void)shgeodb_host(buf, &geo);
  }

  shgeo_loc(&geo, &lat, &lon, NULL);
  if (lat != 0.0 && lon != 0.0) {
    /* register location as local with libshare. */
    shgeo_local_set(&geo);

    /* persist */
    sprintf(buf, "%Lf", lat);
    shpref_set("shcoind.geo.latitude", buf);
    sprintf(buf, "%Lf", lon);
    shpref_set("shcoind.geo.longitude", buf);

    /* debug */
    sprintf(buf, "info: latitude %Lf, longitude %Lf.", lat, lon);
    shcoind_log(buf);
  }

}

int unet_local_verify(char *ipaddr)
{
  int idx;

  for (idx = 0; idx < ipaddr_index; idx++) {
    if (0 == strcmp(ipaddr, ipaddr_table[idx]))
      return (TRUE);
  }

  return (FALSE);
}

void unet_local_add(char *ipaddr_in)
{
  char buf[512];
  char ipaddr[256];
  int fam;

  if (!ipaddr_in || !*ipaddr_in)
    return;

  memset(ipaddr, 0, sizeof(ipaddr));

  if (strchr(ipaddr_in, ':'))
    fam = AF_INET6;
  else
    fam = AF_INET;

  if (fam == AF_INET) {
    struct in_addr sin;
    memset(&sin, 0, sizeof(sin));
    inet_pton(AF_INET, ipaddr_in, &sin);
    inet_ntop(AF_INET, &sin, ipaddr, sizeof(ipaddr)-1);
  } else if (fam == AF_INET6) {
    struct in6_addr sin;
    memset(&sin, 0, sizeof(sin));
    inet_pton(AF_INET6, ipaddr_in, &sin); 
    inet_ntop(AF_INET6, &sin, ipaddr, sizeof(ipaddr)-1);
  }
  if (!*ipaddr) {
//fprintf(stderr, "DEBUG: skipping invalid addr '%s'\n", ipaddr_in);
  return;
  }
  
  if ((ipaddr_index + 1) < MAX_IPADDR_TABLE_SIZE) {
    ipaddr_table[ipaddr_index] = strdup(ipaddr);
    ipaddr_index++;
  }

  sprintf(buf, "info: mapped local IP addr '%s'.", ipaddr);
  shcoind_log( buf);

  if (!strchr(ipaddr, ':')) {
    static char ip6_addr[256];

    /* add ipv6 equivelant */
    struct in6_addr sin6;
    struct in_addr sin;
    unsigned char *raw;

    sprintf(buf, "::FFFF:%s", ipaddr);
    memset(&sin6, 0, sizeof(sin6));
    inet_pton(AF_INET6, buf, &sin6);

#if 0
    memset(&sin6, 0, sizeof(sin6));
    raw = (unsigned char *)&sin6;
    memcpy(raw + 12, &sin.s_addr, 4);
    raw[8] = 0xf;
    raw[9] = 0xf;
#endif

    memset(ip6_addr, 0, sizeof(ip6_addr));
    inet_ntop(AF_INET6, &sin6, ip6_addr, sizeof(ip6_addr)-1);

    if (*ip6_addr && strchr(ip6_addr, ':')) {
      unet_local_add(ip6_addr);
    }
  }

}

const char *unet_local_host(void)
{
  static char ret_buf[256];

  strncpy(ret_buf, primary_ipaddr, sizeof(ret_buf)-1);

  return ((const char *)ret_buf);
}


