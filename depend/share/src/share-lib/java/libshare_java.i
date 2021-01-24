
/*
 * Copyright 2013 Neo Natura 
 * 
 * This file is part of the Share Library.
 * (https://github.com/neonatura/share)
 *       
 * The Share Library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version. 
 * 
 * The Share Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 */

%module share_java
%include <stdint.i>
%include "arrays_java.i"
%{
/* header files andfunc decls */
#include "share.h"
%}
typedef unsigned long time_t;
typedef uint64_t shtime_t;
%typemap(jtype) (const signed char *arr, size_t sz) "byte[]"
%typemap(jstype) (const signed char *arr, size_t sz) "byte[]"
%typemap(jni) (const signed char *arr, size_t sz) "jbyteArray"
%typemap(javain) (const signed char *arr, size_t sz) "$javainput"
%typemap(in,numinputs=1) (const signed char* arr, size_t sz) {
  $1 = JCALL2(GetByteArrayElements, jenv, $input, NULL);
  const size_t sz = JCALL1(GetArrayLength, jenv, $input);
  $2 = sz;
}
%typemap(freearg) (const signed char *arr, size_t sz) {
  // Or use  0 instead of ABORT to keep changes if it was a copy
  JCALL3(ReleaseByteArrayElements, jenv, $input, $1, JNI_ABORT);
}
%apply (const signed char* arr, size_t sz) { ( void *data, size_t data_len ) }
%pragma(java) jniclasscode=%{
  static {
    try {
      System.loadLibrary("share");
    } catch (UnsatisfiedLinkError e) {
      System.err.println("Native code library failed to load. \n" + e);
      System.exit(1);
    }
  }
%}
int test_main(void);
char *get_libshare_version(void);
char *get_libshare_title(void);
const char *get_libshare_path(void);
shpeer_t *shpeer(void);
shpeer_t *ashpeer(void);
void shpeer_free(shpeer_t **peer_p);
void shpref_free(void);
const char *shpref_get(char *pref, char *default_value);
int shpref_set(char *pref, char *value);

/* libshare time measurement */
double shtimef(shtime_t stamp);
shtime_t shtime(void);
shtime_t shtimeu(time_t unix_t);
int shtimems(shtime_t t);
char *shctime(shtime_t t);
time_t shutime(shtime_t t);
char *shstrtime(shtime_t t, char *fmt);
shtime_t shtime_adj(shtime_t stamp, double secs);
shtime_t shgettime(struct timeval *tv);
int shtime_after(shtime_t stamp, shtime_t cmp_stamp);
int shtime_before(shtime_t stamp, shtime_t cmp_stamp);
double shtime_diff(shtime_t stamp, shtime_t cmp_stamp);

/* libshare memory buffer */
void shbuf_append(shbuf_t *from_buff, shbuf_t *to_buff);
shbuf_t *shbuf_clone(shbuf_t *buff);
void shbuf_memcpy(shbuf_t *buf, void *data, size_t data_len);
shbuf_t *shbuf_init(void);
void shbuf_catstr(shbuf_t *buf, char *data);
void shbuf_cat(shbuf_t *buf, void *data, size_t data_len);
size_t shbuf_size(shbuf_t *buf);
unsigned char *shbuf_data(shbuf_t *buf);
void shbuf_clear(shbuf_t *buf);
void shbuf_trim(shbuf_t *buf, size_t len);
void shbuf_dealloc(shbuf_t *buf);
void shbuf_truncate(shbuf_t *buf, size_t len);

/* libshare checksum module */
uint64_t shcrc(void *data, size_t data_len);
char *shcrcstr(uint64_t crc);
uint64_t shcrcgen(char *str);


int shmsgget(shpeer_t *peer);
int shmsgsnd(int msqid, const void *msgp, size_t msgsz);
int shmsgrcv(int msqid, void *msgp, size_t msgsz);
int shmsgctl(int msg_qid, int cmd, int value);
char *shfs_app_name(char *app_name);
uint64_t shfs_crc(shfs_ino_t *file);
shsize_t shfs_size(shfs_ino_t *file);
shfs_t *shfs_init(shpeer_t *peer);
void shfs_free(shfs_t **tree_p);
shfs_ino_t *shfs_dir_base(shfs_t *tree);
shfs_ino_t *shfs_dir_parent(shfs_ino_t *inode);
shfs_ino_t *shfs_dir_entry(shfs_ino_t *inode, char *fname);
shfs_ino_t *shfs_dir_find(shfs_t *tree, char *path);
const char *shfs_meta_get(shfs_ino_t *file, char *def);
int shfs_meta_perm(shfs_ino_t *file, char *def, shkey_t *user);
int shfs_meta_set(shfs_ino_t *file, char *def, char *value);
int shfs_read_mem(char *path, char **data_p, size_t *data_len_p);
int shfs_write_mem(char *path, void *data, size_t data_len);
shfs_ino_t *shfs_file_find(shfs_t *tree, char *path);
int shfs_file_pipe(shfs_ino_t *file, int fd);
void sherr(int err_code, char *log_str);
void shwarn(char *log_str);
void shinfo(char *log_str);
int shnet_accept(int sockfd);
int shnet_bindsk(int sockfd, char *hostname, unsigned int port);
int shnet_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int shclose(int sk);
int shnet_fcntl(int fd, int cmd, long arg);
int shconnect_host(char *host, unsigned short port, int flags);
struct hostent *shresolve(char *hostname);
struct sockaddr *shaddr(int sockfd);
const char *shaddr_print(struct sockaddr *addr);
ssize_t shnet_read(int fd, const void *buf, size_t count);
int shnet_sk(void);
int shnet_socket(int domain, int type, int protocol);
ssize_t shnet_write(int fd, const void *buf, size_t count);
int shnet_verify(fd_set *readfds, fd_set *writefds, long *millis);
/*int shnet_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);*/
shkey_t *shkey_bin(char *data, size_t data_len);
shkey_t *shkey_str(char *kvalue);
shkey_t *shkey_num(long kvalue);
shkey_t *shkey_uniq(void);
void shkey_free(shkey_t **key_p);
const char *shkey_print(shkey_t *key);
shkey_t *ashkey_str(char *name);
shkey_t *ashkey_num(long num);
int shkey_cmp(shkey_t *key_1, shkey_t *key_2);
shkey_t *shkey_clone(shkey_t *key);
shkey_t *shkey_cert(shkey_t *key, uint64_t crc, shtime_t stamp);
int shkey_verify(shkey_t *sig, uint64_t crc, shkey_t *key, shtime_t stamp);
shkey_t *shkey_gen(char *hex_str);
shpool_t *shpool_init(void);
size_t shpool_size(shpool_t *pool);
void shpool_grow(shpool_t *pool);
shbuf_t *shpool_get(shpool_t *pool, unsigned int *idx_p);
shbuf_t *shpool_get_index(shpool_t *pool, int index);
void shpool_put(shpool_t *pool, shbuf_t *buff);
void shpool_free(shpool_t **pool_p);
int ashencode(char *data, size_t *data_len_p, shkey_t *key);
int shencode(char *data, size_t data_len, unsigned char **data_p, size_t *data_len_p, shkey_t *key);
shkey_t *shencode_str(char *data);
int ashdecode(uint8_t *data, size_t *data_len_p, shkey_t *key);
int shdecode(uint8_t *data, uint32_t data_len, char **data_p, size_t *data_len_p, shkey_t *key);
int shdecode_str(char *data, shkey_t *key);
shlock_t *shlock_open(shkey_t *key, int flags);
int shlock_tryopen(shkey_t *key, int flags, shlock_t **lock_p);
int shlock_close(shkey_t *key);
void sh_sha256(const unsigned char *message, unsigned int len, unsigned char *digest);
char *shdigest(void *data, int32_t len);
char *shjson_print(shjson_t *json);
char *shjson_str(shjson_t *json, char *name, char *def_str);
char *shjson_astr(shjson_t *json, char *name, char *def_str);
shjson_t *shjson_str_add(shjson_t *tree, char *name, char *val);
void shjson_free(shjson_t **tree_p);
double shjson_num(shjson_t *json, char *name, double def_d);
shjson_t *shjson_num_add(shjson_t *tree, char *name, double num);
shjson_t *shjson_init(char *json_str);
shjson_t *shjson_array_add(shjson_t *tree, char *name);
char *shjson_array_str(shjson_t *json, char *name, int idx);
char *shjson_array_astr(shjson_t *json, char *name, int idx);
double shjson_array_num(shjson_t *json, char *name, int idx);
shjson_t *shjson_obj(shjson_t *json, char *name);
size_t shjson_strlen(shjson_t *json, char *name);
shfs_ino_t *shfs_inode(shfs_ino_t *parent, char *name, int mode);
char *shfs_filename(shfs_ino_t *inode);
int shfs_type(shfs_ino_t *inode);
shfs_ino_t *shfs_inode_parent(shfs_ino_t *inode);
shfs_ino_t *shfs_inode_load(shfs_ino_t *parent, shkey_t *key);
