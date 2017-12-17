
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


const char *_descriptor_flag_label[MAX_DESCRIPTOR_FLAGS] = {
  "file",
  "sock",
  "service",
  "shutdown",
  "peer-scan",
  "inbound",
  "listen",
  "map",
  "sync",
  "esl"
}; 


static desc_t *_descriptor_table;
static uint64_t _total_descriptor_claim;
static uint64_t _total_descriptor_mark;
static uint64_t _total_descriptor_release;

extern shtime_t server_start_t;


const char *descriptor_iface_name(int ifaceIndex)
{
  if (ifaceIndex == 0) {
#ifdef TEST_SHCOIND
    return ("test");
#else
    return ("<n/a>");
#endif
  }
  return (unet_mode_label(ifaceIndex));
}

const char *descriptor_flag_str(int flag)
{
  static char ret_buf[4096];
  int i;
  
  memset(ret_buf, 0, sizeof(ret_buf));
  for (i = 0; i < 32; i ++) {
    if ( flag & (1 << i) ) {
      if (*ret_buf)
        strcat(ret_buf, " ");
      strcat(ret_buf, _descriptor_flag_label[i]);
    }
  }

  return (ret_buf);
}

const char *descriptor_print(int fd)
{
  static char ret_buf[4096];
  desc_t *d;
  char tbuf1[256];
  char tbuf2[256];


  if (fd >= MAX_DESCRIPTORS)
    return (NULL); 

  d = (_descriptor_table + fd);
  memset(ret_buf, 0, sizeof(ret_buf));

  if (d->flag) {
    if (shtime_after(shtime_adj(shtime(), -86400), d->cstamp)) {
      /* more than a day old */ 
      strcpy(tbuf1, shstrtime(d->cstamp, "%D %T"));
    } else {
      strcpy(tbuf1, shstrtime(d->cstamp, "%T"));
    }

    *tbuf2 = '\000';
    if (d->stamp != SHTIME_UNDEFINED) {
      double diff = (shtimef(shtime()) - shtimef(d->stamp));
      if (diff >= 1.0) {
        sprintf(tbuf2, " (%-2.2fs idle)", diff);
      }
    }

    sprintf(ret_buf, "[#%-4.4d] %s iface (%s) %s%s",
        fd, descriptor_iface_name(d->mode), 
        descriptor_flag_str(d->flag), tbuf1, tbuf2);
  }

  return (ret_buf);
}

desc_t *descriptor_claim(int fd, int mode, int flag)
{
  struct sockaddr *addr;
  struct stat st;
  desc_t *d;
  char errbuf[256];
  int err;

  if (fd >= MAX_DESCRIPTORS)
    return (NULL); 

  if (!_descriptor_table) /* init */
    _descriptor_table = (desc_t *)calloc(MAX_DESCRIPTORS, sizeof(desc_t));

  d = (_descriptor_table + fd);

  if (d->flag != 0) {
    sprintf(errbuf, "descriptor_claim: warning: in-use descriptor %d claimed (%s).", fd, descriptor_print(fd));
    shcoind_log(errbuf);

    /* reset for 'new' use */
    shbuf_free(&d->wbuff);
    shbuf_free(&d->rbuff);
  }

  err = fstat(fd, &st);
  if (err) {
    sprintf(errbuf, "descriptor_claim: warning: claimed descriptor #%d not active.", fd);
    shcoind_log(errbuf);
  } else {
    if (S_ISSOCK(st.st_mode)) {
      flag |= DF_SOCK;
    } else if (S_ISREG(st.st_mode)) {
      flag |= DF_FILE;
    } 
  }

  memset(d, 0, sizeof(d));
  d->mode = mode;
  d->flag = flag;
  d->cstamp = shtime();
  d->stamp = SHTIME_UNDEFINED;

  if (d->flag & DF_SOCK) {
    /* retain remote network addr (ipv4) */
    memset(&d->net_addr, 0, sizeof(d->net_addr));
    addr = shaddr(fd);
    if (addr)
      memcpy(&d->net_addr, addr, sizeof(struct sockaddr));
  }

  _total_descriptor_claim++;

  return (d);
}

desc_t *descriptor_mark(int fd)
{
  desc_t *d;
  char errbuf[256];

  if (fd >= MAX_DESCRIPTORS)
    return (NULL); 

  if (!_descriptor_table) /* init */
    _descriptor_table = (desc_t *)calloc(MAX_DESCRIPTORS, sizeof(desc_t));

  d = (_descriptor_table + fd);

  if (!d->flag) {
    sprintf(errbuf, "descriptor_claim: warning: "
        "un-used descriptor %d accessed.", fd);
    shcoind_log(errbuf);
    return (NULL);
  }

  d->total++;
  d->stamp = shtime();

  _total_descriptor_mark++;

  return (d);
}

void descriptor_release(int fd)
{
  struct stat st;
  desc_t *d;

  if (fd >= MAX_UNET_SOCKETS)
    return; 

  if (!_descriptor_table) /* init */
    _descriptor_table = (desc_t *)calloc(MAX_DESCRIPTORS + 1, sizeof(desc_t));

  d = (_descriptor_table + fd);

  if (0 == fstat(fd, &st)) {
    if (S_ISSOCK(st.st_mode)) {
      shnet_close(fd);
    } else {
      close(fd);
    }
  }

  shbuf_free(&d->wbuff);
  shbuf_free(&d->rbuff);

  memset(d, 0, sizeof(desc_t));

  _total_descriptor_release++;
}



void descriptor_list_print(void)
{
  desc_t *d;
  struct stat st;
  char buf[256];
  int err;
  int fd;

  for (fd = 3; fd < MAX_DESCRIPTORS; fd++) {
    d = (desc_t *)(_descriptor_table + fd);

    if (!d->flag) {
      if (0 == fstat(fd, &st)) {
        sprintf(buf, "[#%-4.4d] unknown <%s>",
            fd, S_ISSOCK(st.st_mode) ? "socket" : "file");
        shcoind_info("descriptor_list_print", buf);
      }
      continue;
    }

    strcpy(buf, descriptor_print(fd));
    err = fstat(fd, &st);
    if (err) {
      sprintf(buf+strlen(buf), " <%s>", strerror(errno));
    } else if (S_ISSOCK(st.st_mode)) {
      sprintf(buf+strlen(buf), " <valid socket %s>", shaddr_print(&d->net_addr));
    } else if (S_ISREG(st.st_mode)) {
      sprintf(buf+strlen(buf), " <valid file>");
    }
    shcoind_info("descriptor_list_print", buf);
  }

  /* totals */
  sprintf(buf, "[total : open(%llu) access(%llu) close(%llu)]",
      _total_descriptor_claim, _total_descriptor_mark,
      _total_descriptor_release);
  shcoind_info("descriptor_list_print", buf);

  /* averages */
  double openf = (double)_total_descriptor_claim / 
    (shtimef(shtime()) - shtimef(server_start_t));
  double accessf = (double)_total_descriptor_mark / 
    (shtimef(shtime()) - shtimef(server_start_t));
  sprintf(buf, 
      "[average : open(%-4.4f/s) access(%-4.4f/s) open/access(%-1.1f%%)]", 
      openf, accessf, (accessf / 100.0 * openf));
  shcoind_info("descript_list_print", buf);

}

desc_t *descriptor_get(int fd)
{
  desc_t *d;

  if (fd >= MAX_UNET_SOCKETS)
    return (NULL); 

  d = (_descriptor_table + fd);
  if (!d->flag)
    return (NULL);

  return (d);
}

void descriptor_rbuff_add(int fd, unsigned char *data, size_t data_len)
{
  desc_t *d;
  char errbuf[256];

  if (fd >= MAX_UNET_SOCKETS)
    return; 

  d = (_descriptor_table + fd);
  if (!d->flag) {
    sprintf(errbuf, "invalid fd %d data append <%d bytes>.\n", fd, data_len);
    shcoind_info("descriptor_append", errbuf);
    return;
  }
 
  if (!d->rbuff)
    d->rbuff = shbuf_init();
  shbuf_cat(d->rbuff, data, data_len);
}

void descriptor_wbuff_add(int fd, unsigned char *data, size_t data_len)
{
  desc_t *d;
  char errbuf[256];

  if (fd >= MAX_DESCRIPTORS)
    return; 

  d = (_descriptor_table + fd);
  if (!d->flag) {
    sprintf(errbuf, "descriptor_append: invalid fd %d data append <%d bytes>.\n", fd, data_len);
    shcoind_log(errbuf);
    return;
  }

#if 0
  if (d->flag & DF_ESL) {
    esl_write_data(fd, data, data_len);
    return;
  }
#endif
 
  if (!d->wbuff)
    d->wbuff = shbuf_init();
  shbuf_cat(d->wbuff, data, data_len);
}

shbuf_t *descriptor_rbuff(int fd)
{
  desc_t *d;
  char errbuf[256];

  if (fd >= MAX_UNET_SOCKETS)
    return (NULL); 

  d = (_descriptor_table + fd);
  if (!d->flag) {
    sprintf(errbuf, "descriptor_rbuff: invalid fd %d.", fd);
    shcoind_log(errbuf);
    return (NULL);
  }

  if (!d->rbuff)
    d->rbuff = shbuf_init();

  return (d->rbuff);
}

shbuf_t *descriptor_wbuff(int fd)
{
  desc_t *d;
  char errbuf[256];

  if (fd >= MAX_UNET_SOCKETS)
    return (NULL); 

  d = (_descriptor_table + fd);
  if (!d->flag) {
    sprintf(errbuf, "descriptor_wbuff: invalid fd %d.", fd);
    shcoind_log(errbuf);
    return (NULL);
  }

  if (!d->wbuff)
    d->wbuff = shbuf_init();

  return (d->wbuff);
}
