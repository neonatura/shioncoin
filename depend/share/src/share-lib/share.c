
/*
 * @copyright
 *
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
 *
 *  @endcopyright
 */

#define __SHARE_C__
#include "share.h"
#include <math.h>
#ifdef HAVE_GETPWUID
#include <pwd.h>
#endif

static const char *_crc_str_map = "-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+";

static shpeer_t _default_peer;


char *get_libshare_version(void)
{
  return (PACKAGE_VERSION);
}

char *get_libshare_title(void)
{
  return (PACKAGE_NAME);
}

const char *get_libshare_default_path(void)
{
  static char ret_path[PATH_MAX+1];
  struct stat st;
  char pathbuf[PATH_MAX+1];
  const char *path;
  int err;

  if (!*ret_path) {
    /* check app-home dir */
    memset(pathbuf, 0, sizeof(pathbuf));
    path = getenv("SHLIB_PATH");
    if (path && *path) {
      strncpy(ret_path, path, sizeof(ret_path) - 1);
    }
  }

#ifdef linux
  if (!*ret_path) {
    mkdir("/var/lib/share/", 0777);
    err = stat("/var/lib/share/", &st);
    if (!err && S_ISDIR(st.st_mode)) {
      strcpy(ret_path, "/var/lib/share/");
    }
  }
#endif

  if (!*ret_path) {
    path = NULL;
#ifdef WINDOWS
    path = getenv("ProgramData");
    if (!path)
      path = getenv("APPDATA");
#endif
    if (!path)
      path = getenv("HOME");
    if (path && *path) {
#if MAC_OSX
      sprintf(pathbuf, "%s/Library/Application Support", path);
      mkdir(pathbuf, 0777);
#else
      strncpy(pathbuf, path, sizeof(pathbuf) - 1);
#endif
    } else {
      getcwd(pathbuf, sizeof(pathbuf) - 1);
    }
#ifdef WINDOWS
    sprintf(ret_path, "%s\\share\\", pathbuf);
#else
    sprintf(ret_path, "%s/share/", pathbuf);
#endif
    mkdir(ret_path, 0777);
  }

  return ((const char *)ret_path);
}

/**
 * Unix: ~/.shlib
 * Windows: C:\Users\Username\AppData\Roaming\shlib
 * Mac: ~/Library/Application Support/shlib
 * @returns The directory where share library persistent data is stored.
 * @note This value can be overwritten with the 
 * @note This value can be overwritten with the shared preference "base-dir".
 */
const char *get_libshare_path(void)
{
  static char ret_path[PATH_MAX+1];
  struct stat st;
  char pathbuf[PATH_MAX+1];
  const char *path;
  int err;

#if 0
  if (!*ret_path) {
    /* check global setting */
    path = shpref_get(SHPREF_BASE_DIR, NULL);
    if (path && *path) {
      mkdir(path, 0777);
      if (0 == stat(path, &st) && S_ISDIR(st.st_mode)) {
        strncpy(ret_path, path, sizeof(ret_path) - 1);
        return ((const char *)ret_path);      
      }
    }
  }

  return (get_libshare_default_path());
#endif
  if (!*ret_path) {
    strncpy(ret_path, get_libshare_default_path(), sizeof(ret_path)-1);
  }
  return (ret_path);
}

const char *get_libshare_account_name(void)
{
  return (shpam_username_sys());
}


/** return the default identity label for the current account. */
uint64_t get_libshare_account_id(void)
{
  char uname[MAX_SHARE_NAME_LENGTH];

  memset(uname, 0, sizeof(uname));
  strncpy(uname, shpam_username_sys(), MAX_SHARE_NAME_LENGTH-1);

  return (shpam_uid(uname));
}

/**
 * The libshare memory buffer pool allocation utilities.
 */
#ifdef __INLINE__SHBUF__

shbuf_t *shbuf_init(void)
{
  shbuf_t *buf;

  buf = (shbuf_t *)calloc(1, sizeof(shbuf_t));
  return (buf);
}

_TEST(shbuf_init)
{
  shbuf_t *buff = shbuf_init();
  CuAssertPtrNotNull(ct, buff); 
  shbuf_free(&buff);
}

void shbuf_grow(shbuf_t *buf, size_t data_len)
{
  if (!buf->data) {
    buf->data_max = MAX(4096, data_len * 2);
    buf->data = (char *)calloc(buf->data_max, sizeof(char));
  } else if (buf->data_of + data_len >= buf->data_max) {
    buf->data_max = (buf->data_max + data_len) * 2;
    buf->data = (char *)realloc(buf->data, buf->data_max);
  } 
}

_TEST(shbuf_grow)
{
  shbuf_t *buff = shbuf_init();

  shbuf_grow(buff, 10240);
  CuAssertPtrNotNull(ct, buff->data); 
  CuAssertTrue(ct, buff->data_max >= 10240);

  shbuf_free(&buff);
}

void shbuf_catstr(shbuf_t *buf, char *data)
{
  shbuf_cat(buf, (unsigned char *)data, strlen(data));
}

_TEST(shbuf_catstr)
{
  shbuf_t *buff = shbuf_init();
  char *str;
  int i;

  CuAssertPtrNotNull(ct, buff); 
  if (!buff)
    return;

  str = (char *)calloc(10240, sizeof(char));

  for (i = 0; i < 10240; i++) {
    memset(str, 'a', sizeof(str) - 1);
    shbuf_catstr(buff, str);
  }

  CuAssertPtrNotNull(ct, buff->data); 
  if (buff->data)
    CuAssertTrue(ct, strlen(buff->data) == (10240 * (sizeof(str) - 1)));
  CuAssertTrue(ct, buff->data_of == (10240 * (sizeof(str) - 1)));
  CuAssertTrue(ct, buff->data_max <= (2 * 10240 * (sizeof(str) - 1)));

  free(str);
  shbuf_free(&buff);
}

void shbuf_cat(shbuf_t *buf, void *data, size_t data_len)
{

  if (!buf)
    return;

  shbuf_grow(buf, data_len);
  memcpy(buf->data + buf->data_of, data, data_len);
  buf->data_of += data_len;

}

_TEST(shbuf_cat)
{
  shbuf_t *buff = shbuf_init();
  char *str;
  int i;

  CuAssertPtrNotNull(ct, buff); 
  if (!buff)
    return;

  str = (char *)calloc(10240, sizeof(char));

  for (i = 0; i < 10240; i++) {
    memset(str, (char)rand(), sizeof(str) - 1);
    shbuf_cat(buff, str, sizeof(str));
  }

  CuAssertPtrNotNull(ct, buff->data); 
  CuAssertTrue(ct, buff->data_of == (10240 * sizeof(str)));
  CuAssertTrue(ct, buff->data_max <= (2 * 10240 * sizeof(str)));

  free(str);
  shbuf_free(&buff);
}

size_t shbuf_size(shbuf_t *buf)
{

  if (!buf)
    return (0);

  return (buf->data_of);
}

_TEST(shbuf_size)
{
  shbuf_t *buf;

  _TRUEPTR(buf = shbuf_init());
  if (!buf)
    return;
  
  shbuf_catstr(buf, "shbuf_size");
  _TRUE(shbuf_size(buf) == strlen("shbuf_size"));
  shbuf_free(&buf);
}

/**
 * May consider a hook here to trim contents of maximum buffer size or swap in/out of a cache pool.
 */
void shbuf_clear(shbuf_t *buf)
{

  if (!buf)
    return;

  shbuf_trim(buf, buf->data_of);
}

_TEST(shbuf_clear)
{
  shbuf_t *buf = shbuf_init();

  _TRUEPTR(buf);
  if (!buf)
    return;
  shbuf_catstr(buf, "shbuf_clear");
  shbuf_clear(buf);
  _TRUE(shbuf_size(buf) == 0);
  shbuf_free(&buf);
}

void shbuf_trim(shbuf_t *buf, size_t len)
{
  if (!buf || !buf->data)
    return;

  len = MIN(len, buf->data_of);
  if (len == 0)
    return;

  if (buf->data_of == len) {
    buf->data_of = 0;
    return;
  }

  memmove(buf->data, buf->data + len, buf->data_of - len);
  buf->data_of -= len;
}

_TEST(shbuf_trim)
{
  shbuf_t *buff = shbuf_init();
  char *str;

  CuAssertPtrNotNull(ct, buff); 
  if (!buff)
    return;

  str = (char *)calloc(10240, sizeof(char));
  memset(str, (char)rand(), 10240);
  shbuf_cat(buff, str, 10240);
  CuAssertTrue(ct, buff->data_of == 10240);
  shbuf_trim(buff, 5120);
  CuAssertTrue(ct, buff->data_of == 5120);

  free(str);
  shbuf_free(&buff);
}

void shbuf_free(shbuf_t **buf_p)
{
  shbuf_t *buf = *buf_p;
  if (!buf)
    return;
  free(buf->data);
  free(buf);
  *buf_p = NULL;
}
#endif /* def __INLINE__SHBUF__ */



#define __SHCRC__
const int MOD_SHCRC = 65521;
uint64_t shcrc(void *data, size_t data_len)
{
  unsigned char *raw_data = (unsigned char *)data;
  uint64_t b = 0;
  uint64_t d = 0;
  uint32_t a = 1, c = 1;
  uint64_t ret_val;
  char num_buf[8];
  int *num_p;
  int idx;
  if (raw_data) {
    num_p = (int *)num_buf;
    for (idx = 0; idx < data_len; idx += 4) {
      memset(num_buf, 0, 8);
      memcpy(num_buf, raw_data + idx, MIN(4, data_len - idx));
      a = (a + *num_p);
      b = (b + a);
      c = (c + raw_data[idx]) % MOD_SHCRC;
      d = (d + c) % MOD_SHCRC;
    }
  }
  ret_val = ((d << 16) | c);
  ret_val += ((b << 32) | a);
  ret_val = htonll(ret_val);
  return (ret_val);
}
uint16_t shcrc_htons(void *data, size_t data_len)
{
  unsigned char *raw_data = (unsigned char *)data;
  uint64_t b = 0;
  uint64_t d = 0;
  uint32_t a = 1, c = 1;
  uint64_t ret_val;
  char num_buf[8];
  int *num_p;
  int idx;
  if (raw_data) {
    num_p = (int *)num_buf;
    for (idx = 0; idx < data_len; idx += 4) {
      memset(num_buf, 0, 8);
      memcpy(num_buf, raw_data + idx, MIN(4, data_len - idx));
      a = (a + *num_p);
      b = (b + a);
      c = (c + raw_data[idx]) % MOD_SHCRC;
      d = (d + c) % MOD_SHCRC;
    }
  }
  ret_val = ((d << 16) | c);
  ret_val += ((b << 32) | a);
  ret_val = htons(ret_val & 0xFFFF);
  return (ret_val);
}
char *shcrc_hex(void *data, size_t data_len)
{
	static char ret_str[64];
	uint64_t crc = shcrc(data, data_len);
	uint32_t *i_val = &crc;
	sprintf(ret_str, "%-8.8x%-8.8x", i_val[0], i_val[1]);
	return (ret_str);
}
_TEST(shcrc)
{
  char buf[256];
  uint64_t val1;
  uint64_t val2;
  memset(buf, 'a', sizeof(buf));
  val1 = shcrc(buf, sizeof(buf));
  _TRUE(9399264675955488567ULL == val1);
  buf[128] = 'b';
  val2 = shcrc(buf, sizeof(buf));
  _TRUE(9543133578258560823ULL == val2);
}
_TEST(shcrc32)
{
  char buf[256];
  uint32_t val1;
  uint32_t val2;
  memset(buf, 'a', sizeof(buf));
  val1 = shcrc32(buf, sizeof(buf));
  _TRUE(1614034743 == val1);
  buf[128] = 'b';
  val2 = shcrc32(buf, sizeof(buf));
  _TRUE(2150905655 == val2);
}
#if 0 /* faster variant (not compatible) */
uint64_t shcrc(void *data, size_t data_len)
{
  unsigned char *raw_data = (unsigned char *)data;
  uint64_t b = 0;
  uint32_t a = 1;
  uint32_t num_data;
  int idx;

  if (raw_data) {
    for (idx = 0; idx < data_len; idx += 4) {
      num_data = 0;
      memcpy(&num_data, raw_data + idx, MIN(4, data_len - idx));

      a = (a + num_data);
      b = (b + a);
    }
  }

  return (htonll( (uint64_t)a + (b << 32) ));
}
_TEST(shcrc)
{
  char buf[256];
  uint64_t val1;
  uint64_t val2;

  memset(buf, 'a', sizeof(buf));
  val1 = shcrc(buf, sizeof(buf));
  _TRUE(4708610547010254647ULL == val1);

  buf[128] = 'b';
  val2 = shcrc(buf, sizeof(buf));
  _TRUE(4780668141585053495ULL == val2);
  

  _TRUE(val1 != val2);
}
#endif
char *shcrcstr(uint64_t crc)
{
  static char ret_str[256];
  uint64_t tcrc;
  uint8_t *cptr;
  int idx;
  char ch;
int i;

  idx = -1;
  tcrc = crc;
  memset(ret_str, 0, sizeof(ret_str));
  while (tcrc && idx < 64) {
    ch = (tcrc % 64);
    ret_str[++idx] = _crc_str_map[ch];
    tcrc = tcrc >> 6;
  }

  return (ret_str);
}
_TEST(shcrcstr)
{
  char *str;
  char buf[4096];
  uint64_t crc;
  int i, j;

  for (j = 0; j < 256; j++) {
    memset(buf, j, sizeof(buf));
    crc = shcrc(buf, sizeof(buf));
    str = shcrcstr(crc);
    _TRUEPTR(str);

    _TRUE(strlen(str));
    for (i = 0; i < strlen(str); i++) {
      _TRUEPTR( strchr(_crc_str_map, str[i]) );
    }
  }

}
int stridx(const char *str, char ch)
{
  int i, len;
  if (!str)
    return (-1);
  len =strlen(str);
  for (i = 0; i < len; i++)
    if (str[i] == ch)
      return (i);
  return (-1);
}
uint64_t shcrcgen(char *str)
{
  uint64_t crc;
  int idx;
  int i;

  crc = 0;
  for (i = (strlen(str)-1); i >= 0; i--) {
    idx = stridx(_crc_str_map, str[i]);
    if (idx == -1)
      return (0);

    crc += idx;

    if (i != 0)
      crc = crc << 6;
  }

  return (crc);
}
_TEST(shcrcgen)
{
  char *str;
  char buf[4096];
  uint64_t crc;
  uint64_t ncrc;
  int j;

  for (j = 0; j < 256; j++) {
    memset(buf, j, sizeof(buf));
    crc = shcrc(buf, sizeof(buf));
    str = shcrcstr(crc);
    ncrc = shcrcgen(str);
    _TRUE(ncrc == crc);
  }

}
#undef __SHCRC__








#define __SHTIME__
double shtimef(shtime_t stamp)
{
  double ret_val;

  if (stamp == SHTIME_UNDEFINED)
    return (0.0);

  ret_val = (double)shnum_get(stamp);
  return (ret_val);
}
_TEST(shtimef)
{
  _TRUE(shtimef(shtime()) > 31622400); /* > 1 year */
}
shtime_t shtime(void)
{
  struct timeval tv;
  shtime_t ret_stamp;
  shnum_t secs;
  shnum_t ms;

  memset(&tv, 0, sizeof(tv));
  gettimeofday(&tv, NULL);
  secs = (shnum_t)(tv.tv_sec - SHTIME_EPOCH);
  ms = (shnum_t)tv.tv_usec / 1000000;
  shnum_set(secs + ms, &ret_stamp);

  return (ret_stamp);
}
time_t shutime(shtime_t t)
{
  time_t ret_time;

  if (t == SHTIME_UNDEFINED)
    return (0);

  ret_time = (time_t)shnum_get(t) + SHTIME_EPOCH;

  return (ret_time);
}
_TEST(shutime)
{
  time_t now;
  time_t t;

  now = time(NULL);
  t = shutime(shtime());
  _TRUE(now/2 == t/2);
}
shtime_t shtimeu(time_t unix_t)
{
  shtime_t ret_stamp;
  shnum_t secs;

  if (unix_t < SHTIME_EPOCH)
    return (SHTIME_UNDEFINED);

  secs = (shnum_t)(unix_t - SHTIME_EPOCH);
  shnum_set(secs, &ret_stamp);

  return (ret_stamp);
}
_TEST(shtimeu)
{
  shtime_t t;
  shtime_t cmp_t;

  t = shtime();
  cmp_t = shtimeu(time(NULL));
  _TRUE((uint64_t)shtimef(t) == (uint64_t)shtimef(cmp_t));
}
int shtimems(shtime_t t)
{
  int ret_ms;
  int prec;
  
  if (t == SHTIME_UNDEFINED)
    return ((double)SHTIME_UNDEFINED);

  ret_ms = (int)(shtimef(t) * 1000) % 1000;

  return (ret_ms);
}
_TEST(shtimems)
{
  shtime_t t;
  int ms;

  t = shtime();
  ms = shtimems(t);
  _TRUE(ms == (int)(shtimef(t) * 1000) % 1000);
}
char *shctime(shtime_t t)
{
  static char ret_str[256];

  memset(ret_str, 0, sizeof(ret_str));

  if (t != 0) {
    time_t conv_t = shutime(t);
    ctime_r(&conv_t, ret_str); 
  }
  
  return (ret_str);
}
char *shstrtime(shtime_t t, char *fmt)
{
  static char ret_str[256];
  time_t utime;

  if (!fmt)
    fmt = "%x %X"; /* locale-specific format */

  utime = shutime(t);
  memset(ret_str, 0, sizeof(ret_str));
  strftime(ret_str, sizeof(ret_str) - 1, fmt, localtime(&utime)); 

  return (ret_str);
}
_TEST(shctime)
{
  shtime_t s_time;
  time_t u_time;
  char s_buf[64];
  char u_buf[64];

  s_time = shtime();
  u_time = time(NULL);

  strncpy(s_buf, shctime(s_time), sizeof(s_buf) - 1);
  strncpy(u_buf, ctime(&u_time), sizeof(u_buf) - 1);

  _TRUE(0 == strcmp(s_buf, u_buf));
}
shtime_t shtime_adj(shtime_t stamp, double adj_secs)
{
  shtime_t ret_stamp;
  shnum_t secs;

  secs = 0;
  if (stamp != SHTIME_UNDEFINED)
    secs = shtimef(stamp);
  secs = secs + (shnum_t)adj_secs; 
  shnum_set(secs, &ret_stamp);

  return (ret_stamp);
}
_TEST(shtime_adj)
{
  shtime_t t;
  shtime_t cmp_t;

  t = shtime();
  cmp_t = shtime_adj(t, 0.1);
  _TRUE(shnum_prec_dim(shtimef(t), 1) == shnum_prec_dim(shtimef(cmp_t) - 0.1, 1));
}
shtime_t shmktime(struct tm *tm)
{
  shtime_t ret_stamp;
  shnum_t secs;

  secs = (shnum_t)mktime(tm) - SHTIME_EPOCH; 
  shnum_set(secs, &ret_stamp);

  return (ret_stamp);
}
_TEST(shmktime)
{
  shtime_t cmp_t;
  shtime_t t;
  time_t now;

  t = shtime();
  now = time(NULL);
  cmp_t = shmktime(localtime(&now));
  _TRUE((uint64_t)shtimef(t) == (uint64_t)shtimef(cmp_t));
}
shtime_t shgettime(struct timeval *tv)
{
  shtime_t ret_stamp;
  shnum_t secs, ms;

  if (tv->tv_sec < SHTIME_EPOCH)
    return (SHTIME_UNDEFINED);

  secs = (shnum_t)(tv->tv_sec - SHTIME_EPOCH);
  ms = (shnum_t)tv->tv_usec / 1000000;
  shnum_set(secs + ms, &ret_stamp);

  return (ret_stamp);
}
_TEST(shgettime)
{
  struct timeval tv;
  shtime_t t;
  time_t now;

  now = time(NULL);
  gettimeofday(&tv, NULL);
  t = shgettime(&tv);
  _TRUE(shutime(t)/2 == now/2);
}
int shtime_after(shtime_t stamp, shtime_t cmp_stamp)
{
  return (shtimef(stamp) > shtimef(cmp_stamp));
}
int shtime_before(shtime_t stamp, shtime_t cmp_stamp)
{
  return (shtimef(stamp) < shtimef(cmp_stamp));
}
double shtime_diff(shtime_t stamp, shtime_t cmp_stamp)
{
  return (fabs(shtimef(stamp) - shtimef(cmp_stamp)));
}
/** a general 'process/thread sleep' function to belay execution */
void shsleep(double dur)
{
  struct timeval tv;

  tv.tv_sec = (long)abs(dur);
  tv.tv_usec = (long)(dur * 1000000) % 1000000;
  select(0, NULL, NULL, NULL, &tv); /* magic */
}
#undef __SHTIME__




#define __SHPREF__
/**
 * Specifies the list of available preferences to set.
 */
static char *shpref_list[SHPREF_MAX] =
{
  SHPREF_BASE_DIR,
  SHPREF_OVERLAY,
  SHPREF_TRACK,
  SHPREF_ACC_NAME,
  SHPREF_ACC_SALT,
  SHPREF_ACC_PASS
};

/**
 * Private instances of runtime configuration options.
 */
static shmap_t *_local_preferences; 

char *shpref_path(int uid)
{
  static char ret_path[PATH_MAX+1];
  struct stat st;

  memset(ret_path, 0, sizeof(ret_path));
  sprintf(ret_path, "%s/pref", get_libshare_default_path());
  if (0 != stat(ret_path, &st)) {
    mkdir(ret_path, 0777);
    chown(ret_path, 0, 0);
  }

  sprintf(ret_path+strlen(ret_path), "/_%lu", (unsigned long)uid);
  return ((char *)ret_path);
}

int shpref_init(void)
{
  shmap_t *h;
  struct stat st;
  char *path;
  char *data;
  size_t data_len;
  size_t len;
  int err;
  int b_of;
  int uid = getuid();

  if (_local_preferences)
    return (0);

  h = shmap_init();
  if (!h)
    return (SHERR_NOMEM);

  path = shpref_path(uid);
  err = shfs_read_mem(path, &data, &data_len);
  if (!err) { /* file may not have existed. */
    shbuf_t *buff = shbuf_map(data, data_len);
    shmap_load(h, buff);
    free(buff);
    free(data);
  }

  _local_preferences = h;

  return (0);
}

_TEST(shpref_init)
{
  _TRUE(!shpref_init());
}

void shpref_free(void)
{

  if (!_local_preferences)
    return;

  shmap_free(&_local_preferences);

}

int shpref_save(void)
{
  static shbuf_t *buff;
  char *path;
  int err;

  if (!_local_preferences)
    return (0); /* done */

	if (!buff)
		buff = shbuf_init();

	{
		shbuf_lock(buff);

		shbuf_clear(buff);
		shmap_print(_local_preferences, buff);
		path = shpref_path(getuid());
		err = shfs_write_mem(path, buff->data, buff->data_of);

		shbuf_unlock(buff);
	}
  if (err == -1)
    return (err);

  (void)chmod(path, 0700);

  return (0);
}

_TEST(shpref_save)
{
  _TRUE(!shpref_save());
}

const char *shpref_get(char *pref, char *default_value)
{
  static char ret_val[SHPREF_VALUE_MAX+1];
  char tok[SHPREF_NAME_MAX + 16];
  shkey_t *key;
  char *str;
  int err;

  err = shpref_init();
  if (err) {
    return (default_value);
  }

  memset(tok, 0, sizeof(tok));
  strncpy(tok, pref, SHPREF_NAME_MAX);
  key = shkey_str(tok);
  str = shmap_get_str(_local_preferences, key);
  shkey_free(&key);

  memset(ret_val, 0, sizeof(ret_val));
  if (!str) {
    if (default_value)
      strncpy(ret_val, default_value, sizeof(ret_val) - 1);
  } else {
    strncpy(ret_val, str, sizeof(ret_val) - 1); 
  }

  return (ret_val);
}


_TEST(shpref_get)
{
  int i;

  for (i = 0; i < SHPREF_MAX; i++) {
    _TRUEPTR((char *)shpref_get(shpref_list[i], "shpref_get"));
  }
}

int shpref_set(char *pref, char *value)
{
  char tok[SHPREF_NAME_MAX+16];
  shkey_t *key;
  int err;

  err = shpref_init();
  if (err)
    return (err);

  memset(tok, 0, sizeof(tok));
  strncpy(tok, pref, SHPREF_NAME_MAX);
  key = shkey_str(tok);
  if (value) {
    /* set permanent configuration setting. */
    shmap_set_astr(_local_preferences, key, value);
  } else {
    shmap_unset(_local_preferences, key);
  }
  shkey_free(&key);

  err = shpref_save();
  if (err)
    return (err);

  return (0);
}

_TEST(shpref_set)
{
  char *pref_val[SHPREF_MAX];
  char *ptr;
  int i;

  for (i = 0; i < SHPREF_MAX; i++) {
    ptr = (char *)shpref_get(shpref_list[i], "");
    pref_val[i] = strdup(ptr);
  }
  for (i = 0; i < SHPREF_MAX; i++) {
    if (pref_val[i] && *pref_val[i]) {
      _TRUE(0 == shpref_set(shpref_list[i], pref_val[i]));
    } else { 
      _TRUE(0 == shpref_set(shpref_list[i], NULL)); 
    }
    free(pref_val[i]);
  } 
}
#undef __SHPREF__


#define __SHPEER__
static void shpeer_set_app(shpeer_t *peer, char *app_name)
{
  shkey_t *key;
  struct hostent *ent;
  char pref[512];
  char *ptr;
  int idx;

  if (!app_name || !*app_name) {
#ifdef PACKAGE
    app_name = PACKAGE;
#else
    app_name = "libshare";
#endif
  }

  idx = stridx(app_name, ':');
  if (idx == -1) {
    strncpy(peer->label, app_name, sizeof(peer->label) - 1);
  } else {
    strncpy(peer->label, app_name, MIN(sizeof(peer->label) - 1, idx));
  }
}
static void shpeer_set_hwaddr(shpeer_t *peer)
{
	static uint8_t *hwaddr;

#ifdef SIOCGIFHWADDR
  if (!hwaddr) {
		struct ifreq buffer;
		int i;
	  int s;

		memset(&buffer, 0, sizeof(buffer));
		strcpy(buffer.ifr_name, "eth0");

		s = socket(PF_INET, SOCK_DGRAM, 0);

		/* bug: check error code. loop for ethXX. */
		ioctl(s, SIOCGIFHWADDR, &buffer);
		close(s);

		hwaddr = (uint8_t *)calloc(6, sizeof(uint8_t));
		if (hwaddr) {
			for (i = 0; i < 6; i++) {
				hwaddr[i] = (uint8_t)buffer.ifr_hwaddr.sa_data[i];
			}
		}
	}
#endif

	if (hwaddr)
		memcpy(peer->addr.hwaddr, hwaddr, 6);
}
static void shpeer_set_group(shpeer_t *peer, char *name)
{
  char *ptr;

  if (!name)
    return;

  ptr = strchr(name, ':');
  if (ptr)
    strncpy(peer->group, ptr + 1, sizeof(peer->group) - 1);
}
static void shpeer_set_host(shpeer_t *peer, char *hostname)
{
  struct servent *serv;
  struct hostent *ent;
  char peer_host[MAXHOSTNAMELEN+1];
  char *ptr;
  int port;
  int proto;

  port = 0;
  ent = NULL;
  memset(peer_host, 0, sizeof(peer_host));

  if (hostname) {
    strncpy(peer_host, hostname, sizeof(peer_host) - 1);
    ptr = strchr(peer_host, ':');
    if (ptr && strchr(ptr+1, ':')) /* ipv6 */
      ptr = NULL;
    if (!ptr)
      ptr = strchr(peer_host, ' '); /* "<ip> <port>" */
    if (ptr) {
      port = atoi(ptr+1);
      *ptr = '\0';
    }

    ent = shresolve(peer_host);
  }

  /* lookup service port */
  if (!port) {
    if (*peer->label && 0 != strcmp(peer->label, PACKAGE)) {
      serv = getservbyname(peer->label, "tcp");
      if (serv)
        port = ntohs(serv->s_port);
      endservent();
    }
  } else /* (port) */ {
#if 0
    if (!*peer->label || 0 == strcmp(peer->label, PACKAGE)) {
      serv = getservbyport(port, "tcp");
      if (serv)
        strncpy(peer->label, serv->s_name, sizeof(peer->label) - 1);
    }
#endif
  }

  if (!ent) {
    peer->type = SHNET_PEER_LOCAL;
    peer->addr.sin_addr[0] = (uint32_t)htonl(INADDR_LOOPBACK);
    peer->addr.sin_port = htons((uint16_t)port);
    peer->addr.sin_family = AF_INET;
  } else if (ent->h_addrtype == AF_INET6) {
    peer->type = SHNET_PEER_IPV6;
    memcpy((uint32_t *)peer->addr.sin_addr, ent->h_addr, ent->h_length);
    peer->addr.sin_port = htons((uint16_t)port);
    peer->addr.sin_family = AF_INET6;
  } else if (ent->h_addrtype == AF_INET) {
    peer->type = SHNET_PEER_IPV4;
    memcpy(&peer->addr.sin_addr[0], ent->h_addr, ent->h_length);
    peer->addr.sin_port = htons((uint16_t)port);
    peer->addr.sin_family = AF_INET;
  }

}
void shpeer_host(shpeer_t *peer, char *hostname, int *port_p)
{
  struct in_addr ip4_addr;
  char *ptr;

  if (!peer)
    return;

  switch (peer->type) {
    case SHNET_PEER_LOCAL:
    case SHNET_PEER_IPV4:
      if (hostname) {
        memset(&ip4_addr, 0, sizeof(ip4_addr));
        memcpy(&ip4_addr, &peer->addr.sin_addr[0], sizeof(ip4_addr)); 
        strcpy(hostname, inet_ntoa(ip4_addr));
      }
      if (port_p)
        *port_p = (int)ntohs(peer->addr.sin_port);
      break;

    case SHNET_PEER_IPV6: 
      if (hostname) {
        ptr = (char *)peer->addr.sin_addr;
        sprintf(hostname,
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            (int)ptr[0], (int)ptr[1], (int)ptr[2], (int)ptr[3],
            (int)ptr[4], (int)ptr[5], (int)ptr[6], (int)ptr[7],
            (int)ptr[8], (int)ptr[9], (int)ptr[10], (int)ptr[11],
            (int)ptr[12], (int)ptr[13], (int)ptr[14], (int)ptr[15]);
      }
      if (port_p)
        *port_p = (int)ntohs(peer->addr.sin_port);
      break;
  }

}

struct sockaddr *shpeer_addr(shpeer_t *peer)
{
  static struct sockaddr_in ret_in;
  static struct sockaddr_in6 ret_in6;
  struct sockaddr *in;
  struct in_addr ip4_addr;
  struct in6_addr ip6_addr;
  char *ptr;

  if (!peer)
    return (NULL);

  in = NULL;
  switch (peer->type) {
    case SHNET_PEER_LOCAL:
    case SHNET_PEER_IPV4:
      memset(&ret_in, 0, sizeof(ret_in));
      ret_in.sin_port = peer->addr.sin_port;
      ret_in.sin_family = AF_INET;
      memcpy(&ret_in.sin_addr, &peer->addr.sin_addr[0], sizeof(ip4_addr)); 
      in = (struct sockaddr *)&ret_in;
      break;

    case SHNET_PEER_IPV6: 
      memset(&ret_in6, 0, sizeof(ret_in6));
      ret_in6.sin6_family = AF_INET6;
      ret_in6.sin6_port = peer->addr.sin_port;
      memcpy(&ret_in6.sin6_addr, &peer->addr.sin_addr[0], sizeof(ip6_addr)); 
      in = (struct sockaddr *)&ret_in6;
      break;
  }

  return (in);
}

static void shpeer_set_arch(shpeer_t *peer)
{
#if defined(LINUX)
  peer->arch |= SHARCH_LINUX;
#elif defined(FREEBSD)
  peer->arch |= SHARCH_BSD;
#else
  peer->arch |= SHARCH_WIN;
#endif
#ifdef I386
  peer->arch |= SHARCH_32BIT;
#endif
}
static void shpeer_set_key(shpeer_t *peer, shkey_t *out_key)
{
  shkey_t *key;

  key = shkey_bin((char *)peer, sizeof(shpeer_t));
  memcpy(out_key, key, sizeof(shkey_t));
  shkey_free(&key);
}
static void shpeer_set_priv(shpeer_t *peer)
{
  struct passwd *pwd = NULL;

#ifdef HAVE_GETPWUID
  pwd = getpwuid(getuid());
#endif

  if (pwd) {
    peer->uid = shcrc(pwd->pw_name, strlen(pwd->pw_name));
  } else {
#ifndef _WIN32
    peer->uid = getuid();
#endif
  }
  shpeer_set_hwaddr(peer);
  shpeer_set_arch(peer);
}
shpeer_t *shpeer_init(char *appname, char *hostname)
{
  shpeer_t *peer;

  peer = (shpeer_t *)calloc(1, sizeof(shpeer_t));
  if (!peer)
    return (NULL);

  /* pub info */
  shpeer_set_app(peer, appname);
  shpeer_set_group(peer, appname);
  shpeer_set_key(peer, &peer->key.pub);

  /* priv info */
  shpeer_set_host(peer, hostname);
  if (!*peer->group)
    shpeer_set_priv(peer);
  shpeer_set_key(peer, &peer->key.priv);

  return (peer);
}
/** establish default peer */
void shpeer_set_default(shpeer_t *peer)
{
  shpeer_t *def_peer;

  def_peer = NULL;
  if (!peer) {
    def_peer = shpeer_init(NULL, NULL);
    peer = def_peer;
  }
  memcpy(&_default_peer, peer, sizeof(shpeer_t));

  if (def_peer)
    shpeer_free(&def_peer);
}
shpeer_t *shpeer(void)
{
  shpeer_t *peer;

  if (shkey_is_blank(shpeer_kpub(&_default_peer))) {
    shpeer_set_default(NULL);
  }

  peer = (shpeer_t *)calloc(1, sizeof(shpeer_t));
  memcpy(peer, &_default_peer, sizeof(_default_peer));

  return peer;
}
shpeer_t *ashpeer(void)
{
  static shpeer_t ret_peer;
  shpeer_t *peer;

  if (shkey_is_blank(shpeer_kpub(&_default_peer))) {
    shpeer_set_default(NULL);
  }
#if 0
    /* initialize default peer */
    peer = shpeer_init(NULL, NULL);
    memcpy(&ret_peer, peer, sizeof(shpeer_t));
    shpeer_free(&peer);
#endif
  memcpy(&ret_peer, &_default_peer, sizeof(shpeer_t));

  return (&ret_peer);
}
void shpeer_free(shpeer_t **peer_p)
{
  shpeer_t *peer;

  if (!peer_p)
    return;

  peer = *peer_p;
  *peer_p = NULL;

  if (peer)
    free(peer);
}
char *shpeer_print(shpeer_t *peer)
{
  static char ret_buf[4096];
  struct in_addr in_addr;
  int i;

  memset(ret_buf, 0, sizeof(ret_buf));

  if (!peer)
    return (ret_buf);

  if (*peer->label)
    sprintf(ret_buf+strlen(ret_buf), "%s", peer->label);
  if (*peer->group)
    sprintf(ret_buf+strlen(ret_buf), ":%s", peer->group);

  switch (peer->type) {
    case SHNET_PEER_LOCAL:
    case SHNET_PEER_IPV4:
      strcat(ret_buf, "@");
      memcpy(&in_addr, &peer->addr.sin_addr, sizeof(struct in_addr));
      strcat(ret_buf, inet_ntoa(in_addr));
      if (peer->addr.sin_port)
        sprintf(ret_buf+strlen(ret_buf), ":%u",
            (unsigned int)ntohs(peer->addr.sin_port)); 
      break;
    case SHNET_PEER_IPV6:
      strcat(ret_buf, "@");
      for (i = 0; i < 4; i++) {
        uint32_t *in6_addr = (uint32_t *)peer->addr.sin_addr;
        if (i != 0)
          strcat(ret_buf, ":");
        sprintf(ret_buf+strlen(ret_buf), "%x", in6_addr + i);
      }
      if (peer->addr.sin_port)
        sprintf(ret_buf+strlen(ret_buf), ":%u", 
            (unsigned int)ntohs(peer->addr.sin_port)); 
      break;
  }

//  sprintf(ret_buf+strlen(ret_buf), " (%s)", shkey_print(shpeer_kpub(peer)));

  return (ret_buf);
}

int shpeer_localhost(shpeer_t *peer)
{

  if (peer->type == SHNET_PEER_LOCAL)
    return (TRUE);

  if (peer->type == SHNET_PEER_IPV4) {
    if (peer->addr.sin_addr[0] == (uint32_t)htonl(INADDR_LOOPBACK))
      return (TRUE);
  }

  return (FALSE);
}
char *shpeer_get_app(shpeer_t *peer)
{
  struct servent *serv;
  int port;

  if (!*peer->label || 0 == strcmp(peer->label, PACKAGE)) {
    port = (unsigned int)ntohs(peer->addr.sin_port); 
    serv = getservbyport(port, "tcp");
    if (serv)
      return (serv->s_name);
  }

  return (peer->label); 
}
#undef __SHPEER__

#define __SHNUM__
#define SHNUM_MAX_PRECISION 8
#define SHNUM_PRECISION_BASE 10
int shnum_prec(shnum_t fval)
{
  shnum_t d;
  uint64_t i;
  int max_prec;
  int prec;

  i = (uint64_t)fval;
  if (fval == (shnum_t)i)
    return (0);

  for (max_prec = 1; max_prec <= SHNUM_MAX_PRECISION; max_prec++) {
    d = fval * powl(SHNUM_PRECISION_BASE, max_prec);
    i = (uint64_t)d & 0xffffffffffffff;
    d = (shnum_t)i / powl(SHNUM_PRECISION_BASE, max_prec);
    if ((uint64_t)d != (uint64_t)fval)
      break;
  }
  max_prec--;

  for (prec = 1; prec < max_prec; prec++) {
    d = fval * powl(SHNUM_PRECISION_BASE, prec);
    i = fval * powl(SHNUM_PRECISION_BASE, prec);
    if (d == (shnum_t)i)
      break;
  }

  return (prec);
}
shnum_t shnum_prec_dim(shnum_t fval, int prec)
{
  uint64_t num;

  prec = MAX(prec, 0);
  prec = MIN(prec, SHNUM_PRECISION_BASE); 
  num = (uint64_t)roundl(fval * (shnum_t)powl((shnum_t)SHNUM_PRECISION_BASE, (shnum_t)prec));
  fval = (shnum_t)num / (shnum_t)powl((shnum_t)SHNUM_PRECISION_BASE, (shnum_t)prec);

  return (fval);
}
void shnum_set(shnum_t val, uint64_t *bin_p)
{
  uint64_t val_bin;
  uint8_t prec_byte;
  int prec;

  if (!bin_p)
    return;

  val = fabsl(val);
  prec = shnum_prec(val);
  if (prec)
    val = val * powl(SHNUM_PRECISION_BASE, prec);

  val_bin = (uint64_t)val;
  val_bin = val_bin & 0xffffffffffffff;
  val_bin = htonll(val_bin);

  prec_byte = (prec & 0xff);
  memcpy(&val_bin, &prec_byte, 1);

  *bin_p = val_bin;
}
shnum_t shnum_get(uint64_t val_bin)
{
  shnum_t ret_val;
  uint8_t prec;

  memcpy(&prec, &val_bin, 1);
  memset(&val_bin, '\000', 1);
  val_bin = ntohll(val_bin);

  ret_val = (shnum_t)val_bin;
  if (prec)
    ret_val = ret_val / powl(SHNUM_PRECISION_BASE, (shnum_t)prec);

  return (ret_val);
}
double shnum_getf(uint64_t val_bin)
{
  return ((double)shnum_get(val_bin));
}
_TEST(shnum_set)
{
  shnum_t fval;
  uint64_t ival;

  fval = (shnum_t)232883476611.839816;
  /* In PHP runtime this returns as 4 instead of 5. */
  _TRUE( (shnum_prec(fval) == 5) || (shnum_prec(fval) == 4) );
  _TRUE(shnum_prec(shnum_prec_dim(fval, 3)) <= 3);

  fval = (shnum_t)555555555555.5;
  shnum_set(fval, &ival);
  _TRUE(shnum_get(ival) == fval);

  fval = 94424949.97312988;
  shnum_set(fval, &ival);
  _TRUE(shnum_prec_dim(fval, 8) == shnum_get(ival));
}
/**
 * Obtain the 'sign' (i.e. negative or positive) of a number
 * @returns -1, 0, or +1
 */
int shnum_sign(shnum_t v)
{
  return ((v > 0) - (v < 0));
}
#undef __SHNUM__


#define __SHERR__
int stderr2sherr(int std_err)
{
	int i;

	/* all "system error codes" are negative */
	if (std_err <= 0)
		return (std_err);

	for (i = 0; _share_stderr_table[i].code != 0; i++) {
		if (_share_stderr_table[i].code == std_err)
			return (_share_stderr_table[i].err);
	}

	return (SHERR_UNKNOWN);
}
int sherr2stderr(int sh_err)
{
	int i;

	/* all "share error codes" are negative */
	if (sh_err >= 0)
		return (sh_err);

	for (i = 0; _share_stderr_table[i].code != 0; i++) {
		if (_share_stderr_table[i].err == sh_err)
			return (_share_stderr_table[i].code);
	}

	/* return what was provided */
	return (sh_err);
}
int errno2sherr(void)
{
	return (stderr2sherr(errno));
}
const char *sherrstr(int sh_err)
{
	int err_code;

	if (sh_err == 0) {
		return ("Success");
	}

	/* shcode -> syscode */
	if (sh_err < 0)
		sh_err = sherr2stderr(sh_err);

  return (strerror(sh_err));
}
#undef __SHERR__

#if 0
typedef uint64_t shbit_t;
void shbit_clear(shbit_t *flags)
{
  *flags = 0;
}
void shbit_set(shbit_t *flags, uint64_t bits)
{
#ifdef X86_64
  *flags |= bits;
#else
  *flags |= bits;
#endif
}
int shbit_get(shbit_t *flags, int bit)
{
  return ( *flags & bit );
}
void shbit_unset(shbit_t *flags, uint64_t bits)
{
  *flags &= ~bits;
}
#endif

