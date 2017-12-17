
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#ifndef __SHCOIND_DESCRIPTOR_H__
#define __SHCOIND_DESCRIPTOR_H__


#ifdef __cplusplus
extern "C" {
#endif



#define MAX_DESCRIPTORS 4096

#define DF_FILE (1 << 0)
#define DF_SOCK (1 << 1)
#define DF_SERVICE (1 << 2)
#define DF_SHUTDOWN (1 << 3)
#define DF_PEER_SCAN (1 << 4)
#define DF_INBOUND (1 << 5)
#define DF_LISTEN (1 << 6)
#define DF_MAP (1 << 7)
#define DF_SYNC (1 << 8)
#define DF_ESL (1 << 9)
#define MAX_DESCRIPTOR_FLAGS 10


#define CLAIM_FD(_fd, _mode, _flag) \
  (descriptor_claim(_fd, _mode, _flag))

#define MARK_FD(_fd) \
  (descriptor_mark(_fd))

#define RELEASE_FD(_fd) \
  (descriptor_release(fd))

struct desc_t {
  int mode;
  int flag;
  int total;
  shtime_t cstamp;
  shtime_t stamp;
  shbuf_t *rbuff;
  shbuf_t *wbuff;
  struct sockaddr net_addr;
};

typedef struct desc_t desc_t;




desc_t *descriptor_claim(int fd, int mode, int flag);

desc_t *descriptor_mark(int fd);

void descriptor_release(int fd);

desc_t *descriptor_get(int fd);

const char *descriptor_print(int fd);

void descriptor_list_print(void);

void descriptor_rbuff_add(int fd, unsigned char *data, size_t data_len);

void descriptor_wbuff_add(int fd, unsigned char *data, size_t data_len);

shbuf_t *descriptor_rbuff(int fd);

shbuf_t *descriptor_wbuff(int fd);



#ifdef __cplusplus
}
#endif


#endif /* ndef __SHCOIND_DESCRIPTOR_H__ */


