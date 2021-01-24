
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

#define __MEM__SHMEM_BUF_C__

#include "share.h"
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif


#define MAX_SHBUF_SIZE 0xFFFFFFFFFFFF


/* recursive dir generation for relative paths. */
static void shbuf_mkdir(char *path)
{
	struct stat st;
  char dir[PATH_MAX+1];
	char *s_ptr;
	char *e_ptr;

	if (!path || !*path)
		return;

  memset(dir, 0, sizeof(dir));
  if (*path == '/')
    strcat(dir, "/");

	s_ptr = path;
	while (s_ptr) {
		e_ptr = strchr(s_ptr, '/');
		if (!e_ptr)
			break;

		if (e_ptr != s_ptr) {
			if (strlen(dir) + (e_ptr - s_ptr) >= PATH_MAX)
				break;

			strncat(dir, s_ptr, e_ptr - s_ptr); 
			strcat(dir, "/");
			if (0 != stat(dir, &st))
				mkdir(dir, 0777);
		}
		s_ptr = e_ptr + 1;
	}

#if 0
  save_ptr = NULL;
  tok = strtok_r(path, "/", &save_ptr);
  while (tok) {
    n_tok = strtok_r(NULL, "/", &save_ptr);
    if (!n_tok)
      break;

    strcat(dir, tok);
    strcat(dir, "/");

		if (0 != stat(dir, &st)) {
			mkdir(dir, 0777);
		}

    tok = n_tok;
  }
#endif

}

static void shbuf_lock_init(shbuf_t *buff)
{
#ifdef USE_LIBPTHREAD
	pthread_mutexattr_t attr;

	if (!buff)
		return;

	memset(&attr, 0, sizeof(attr));
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&buff->lk, &attr);

  buff->flags |= SHBUF_MUTEX;
#endif
}

shbuf_t *shbuf_map(unsigned char *data, size_t data_len)
{
  shbuf_t *buf;

  buf = (shbuf_t *)calloc(1, sizeof(shbuf_t));
	if (!buf)
		return (NULL);

  buf->data = data;
  buf->data_of = data_len;
  buf->data_max = data_len;
  buf->flags |= SHBUF_PREALLOC;
	shbuf_lock_init(buf);

  return (buf);
}

shbuf_t *ashbuf_map(unsigned char *data, size_t data_len)
{
  static shbuf_t ret_buf;

  memset(&ret_buf, 0, sizeof(ret_buf));
  ret_buf.data = data;
  ret_buf.data_of = data_len;
  ret_buf.data_max = data_len;

  return (&ret_buf);
}

unsigned char *shbuf_unmap(shbuf_t *buf)
{
  unsigned char *data = shbuf_data(buf);
  free(buf);
  return (data);
}

static int __shbuf_growmap(shbuf_t *buf, size_t data_len)
{
  struct stat st;
  size_t block_size;
  size_t of;
  char *data;
  void *map_data;
  void *map_newdata;
  size_t map_len;
  size_t map_newlen;
  ssize_t w_len;
  int err;

  map_data = NULL;
  map_len = 0;
  if (buf->data) {
    map_data = buf->data;
    //map_len = buf->data_of;
    map_len = buf->data_max;
  }

  if (map_len >= data_len)
    return (0); /* bufmap exceeds allocation requested */

  buf->data = NULL;
  buf->data_max = 0;
  if (buf->fd > 0)
    buf->data_of = 0;

  block_size = sysconf(_SC_PAGE_SIZE);

  if (buf->fd > 0) {
		data_len = MAX(data_len, block_size);	
    map_newlen = (data_len / block_size) * block_size;

    memset(&st, 0, sizeof(st));
    fstat(buf->fd, &st);
    if (st.st_size < map_newlen) {
      lseek(buf->fd, st.st_size, SEEK_SET);

      data = (char *)calloc(block_size, sizeof(char));
      of = st.st_size;
      while (of < map_newlen) {
        w_len = write(buf->fd, data, block_size);
        if (w_len == -1) {
          free(data);
          return (errno2sherr()); /* SHERR_NOSPC */
        }

        of += w_len;
      }
      free(data);

      memset(&st, 0, sizeof(st));
      fstat(buf->fd, &st);
    }

    lseek(buf->fd, 0L, SEEK_SET);
    map_newdata = mmap(NULL, map_newlen, PROT_READ | PROT_WRITE, MAP_SHARED, buf->fd, 0); 
  } else {
    map_newlen = ((data_len / block_size) + 1) * block_size;
    map_newdata = mmap(NULL, map_newlen, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0); 
  }
  if (map_newdata == MAP_FAILED) {
    return (SHERR_NOBUFS);
}

  if (map_data) {
    if (buf->fd < 1) {
      /* copy original content. */
      memcpy(map_newdata, map_data, map_len);
    }

    munmap(map_data, map_len); /* ignore EINVAL return */
  }

  buf->data = map_newdata;
  buf->data_max = map_newlen;
  if (buf->fd > 0)
    buf->data_of = map_newlen;
  buf->flags |= SHBUF_FMAP;

  return (0);
}

int shbuf_growmap(shbuf_t *buf, size_t data_len)
{
	int ret_val;

	if (!buf)
		return (SHERR_INVAL);

	shbuf_lock(buf);
	ret_val = __shbuf_growmap(buf, data_len);
	shbuf_unlock(buf);

	return (ret_val);
}

shbuf_t *shbuf_init(void)
{
  shbuf_t *buf;

  buf = (shbuf_t *)calloc(1, sizeof(shbuf_t));
	if (!buf)
		return (NULL);

	shbuf_lock_init(buf);
  return (buf);
}

_TEST(shbuf_init)
{
  shbuf_t *buff = shbuf_init();
  CuAssertPtrNotNull(ct, buff); 
  shbuf_free(&buff);
}

static int __shbuf_grow(shbuf_t *buf, size_t data_len)
{
  size_t orig_len;
  int block_len;

  block_len = ((data_len + 1) / 16384) + 1;
  if ((block_len * 16384) <= buf->data_max)
    return (0); /* already allocated */

  if (buf->flags & SHBUF_FMAP)
    return (SHERR_OPNOTSUPP);

  orig_len = buf->data_max;
  buf->data_max = block_len * 16384;
  if (!buf->data) {
    buf->data = (char *)calloc(buf->data_max, sizeof(char));
  } else {// if (buf->data_of + data_len >= buf->data_max) {
    unsigned char *orig_data = (unsigned char *)buf->data;
    buf->data = (char *)realloc(buf->data, buf->data_max);
    if (!buf->data) { /* realloc not guaranteed */
      char *data = (char *)calloc(buf->data_max, sizeof(char));
      if (data) {
        memcpy(data, orig_data, orig_len);
        free(orig_data);
        buf->data = data;
      }
    }
  } 

  if (!buf->data) {
    buf->data_max = buf->data_of = 0;
    return (SHERR_NOBUFS);
  }

  return (0);
}

int shbuf_grow(shbuf_t *buf, size_t data_len)
{
	int ret_val;

	if (!buf)
		return (SHERR_INVAL);

	shbuf_lock(buf);
	ret_val = __shbuf_grow(buf, data_len);
	shbuf_unlock(buf);

	return (ret_val);
}

_TEST(shbuf_grow)
{
  shbuf_t *buff = shbuf_init();
	char buf[1024];
  int i;

  for (i = 0; i < 102400; i += 1024) {
    _TRUE(0 == shbuf_grow(buff, i));
    _TRUEPTR(buff->data);
    _TRUE(buff->data_max >= i);
		memset(buf, ((i*i)%32), sizeof(buf));
    _TRUE(buff->data_of == i);
		shbuf_cat(buff, buf, sizeof(buf));
  }
  for (i = 0; i < 102400; i += 1024) {
		memset(buf, ((i*i)%32), sizeof(buf));
		_TRUE(0 == memcmp(shbuf_data(buff) + i, buf, sizeof(buf)));
	}

  shbuf_free(&buff);
}

void shbuf_catstr(shbuf_t *buf, char *data)
{

	if (!data)
		return;

  shbuf_cat(buf, (unsigned char *)data, strlen(data));
}

_TEST(shbuf_catstr)
{
  shbuf_t *buff;
	char *str;
  int i;

  buff = shbuf_init();
  _TRUEPTR(buff);
  if (!buff)
    return;

	str = (char *)calloc(10240, sizeof(char));
  memset(str, 0, 10240);
  memset(str, 'a', 10239);
  shbuf_catstr(buff, str);
	free(str);

  _TRUEPTR(buff->data);
  if (buff->data)
    _TRUE((size_t)strlen(buff->data) == 10239);
  _TRUE((size_t)buff->data_of == 10239);
  _TRUE((size_t)buff->data_max >= 10239);

  shbuf_free(&buff);
}

static void __shbuf_cat(shbuf_t *buf, void *data, size_t data_len)
{
  int err;

  err = shbuf_grow(buf, buf->data_of + data_len + 1);
  if (err) {// && err != SHERR_OPNOTSUPP) {
    sherr(err, "shbuf_cat");
    return; 
  }

  memcpy(buf->data + buf->data_of, data, data_len);
  buf->data_of += data_len;
}

void shbuf_cat(shbuf_t *buf, void *data, size_t data_len)
{

	if (!buf)
		return;

	shbuf_lock(buf);
	__shbuf_cat(buf, data, data_len);
	shbuf_unlock(buf);
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

static void __shbuf_memcpy(shbuf_t *buf, void *data, size_t data_len)
{
  unsigned char *buf_data = shbuf_data(buf); 
  size_t buf_len = MIN(data_len, shbuf_size(buf));
  memcpy(data, buf_data, buf_len);
}
void shbuf_memcpy(shbuf_t *buf, void *data, size_t data_len)
{

	if (!buf)
		return;

	shbuf_lock(buf);
	__shbuf_memcpy(buf, data, data_len);
	shbuf_unlock(buf);
}

size_t shbuf_idx(shbuf_t *buf, unsigned char ch)
{
  int i;

	if (!buf)
		return (-1);

  for (i = 0; i < buf->data_of; i++) {
    if (buf->data[i] == ch)
      return (i);   
  }

  return (-1);
}

_TEST(shbuf_idx)
{
  shbuf_t *buf;

  _TRUEPTR(buf = shbuf_init());
  if (!buf)
    return;
  
  shbuf_catstr(buf, "shbuf_size");
  _TRUE(shbuf_idx(buf, 'b') == 2);
  _TRUE(shbuf_idx(buf, 'Z') == -1);
  shbuf_free(&buf);
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

unsigned char *shbuf_data(shbuf_t *buf)
{

  if (!buf)
    return (NULL);

  return (buf->data);
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
  _TRUE(0 == strcmp(shbuf_data(buf), ""));
  shbuf_free(&buf);
}

static void __shbuf_trim(shbuf_t *buf, size_t len)
{
  size_t nlen;

  if (!buf->data)
    return;

	if (len > MAX_SHBUF_SIZE) {
    sherr(SHERR_2BIG, "shbuf_trim");
		return;
	}

	if (len > buf->data_of)
		len = buf->data_of;
  if (len == 0)
    return;

  if (buf->data_of == len) {
    memset(buf->data, 0, len);
    buf->data_of = 0;
  } else {
		nlen = MAX(0, (ssize_t)buf->data_of - (ssize_t)len);
		memmove(buf->data, buf->data + len, nlen);
		buf->data_of = nlen;
		memset(buf->data + nlen, 0, buf->data_max - nlen);
	}

}
void shbuf_trim(shbuf_t *buf, size_t len)
{

	if (!buf)
		return;

	shbuf_lock(buf);
	__shbuf_trim(buf, len);
	shbuf_unlock(buf);
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

void shbuf_truncate(shbuf_t *buf, size_t len)
{
  size_t nlen;

  if (!buf || !buf->data)
    return;

  len = MIN(len, buf->data_of);
  if (len == 0)
    return;

  if (buf->data_of == len) {
    return;
  }

  nlen = buf->data_of - len;
  memset(buf->data + len, 0, nlen);
  buf->data_of = len;

}

void shbuf_dealloc(shbuf_t *buf)
{
  if (buf->flags & SHBUF_FMAP) {
    munmap(buf->data, buf->data_max);
    if (buf->fd > 0) {

#if 0
      if (buf->data_max != buf->data_of) {
        ftruncate(buf->fd, buf->data_of);
      }
#endif

      close(buf->fd);
    }
  } else if (buf->data) {
    free(buf->data);
  }
  free(buf);
}

static void shbuf_lock_free(shbuf_t *buff)
{
#ifdef USE_LIBPTHREAD
	if (!buff)
		return;

  if (!(buff->flags & SHBUF_MUTEX))
		return;

	pthread_mutex_destroy(&buff->lk);
  buff->flags &= ~SHBUF_MUTEX;
#endif
}

void shbuf_free(shbuf_t **buf_p)
{
  shbuf_t *buf = *buf_p;

  if (!buf)
    return;

#ifdef USE_LIBPHREAD
	/* try to wait for other threads to finish (not atomic). */
	pthread_yield();
	shbuf_lock(buf);
	shbuf_unlock(buf);
#endif

	/* de-alloc pthread mutex */
	shbuf_lock_free(buf);

  if (buf->flags & SHBUF_PREALLOC)
    buf->data = NULL; /* prevent free on pre-alloc'd data */
  shbuf_dealloc(buf);
  *buf_p = NULL;
}


shbuf_t *shbuf_file(char *path)
{
  struct stat st;
  shbuf_t *buff;
  size_t block_size;
  size_t len;
  size_t block_len = 2;
  void *data;
  char *blank;
  int err;
  int fd;

  if (!path)
    return (NULL);

  shbuf_mkdir(path);

  fd = open(path, O_RDWR | O_CREAT, S_IRWXU);
  if (fd == -1) {
    char logmsg[4096];

		memset(logmsg, 0, sizeof(logmsg));
    snprintf(logmsg, sizeof(logmsg)-1, "shbuf_file: open '%s'", path);
    PRINT_ERROR(errno2sherr(), logmsg);
    return (NULL);
  }

  err = fstat(fd, &st);
  if (err) {
    close(fd);
    return (NULL);
  }

  block_size = SHARE_PAGE_SIZE;
  block_len = MAX(1, MAX(st.st_size / block_size, block_len));
  len = (block_size * block_len);

#if 0
  if (st.st_size != len) {
    ftell(fd, st.st_size, SEEK_SET);
    blank = (char *)calloc(block_size, sizeof(char));
    for (of = st.st_size; of < len; of += block_size)
      write(fd, blank, block_size);
    free(blank);
  }
#endif

  buff = shbuf_init();
  if (!buff)
    return (NULL);

  buff->fd = fd;
  err = shbuf_growmap(buff, len);
  if (err) {
    PRINT_ERROR(err, "shbuf_file [growmap]");
    shbuf_free(&buff);
    return (NULL);
  }

  return (buff);
}

void shbuf_append(shbuf_t *from_buff, shbuf_t *to_buff)
{
  if (!from_buff || !to_buff)
    return;
  shbuf_cat(to_buff, shbuf_data(from_buff), shbuf_size(from_buff));
}

shbuf_t *shbuf_clone(shbuf_t *buff)
{
  shbuf_t *ret_buf;

  ret_buf = shbuf_init();
  shbuf_append(buff, ret_buf);

  return (ret_buf);
}

int shbuf_sprintf(shbuf_t *buff, char *fmt, ...)
{
  va_list ap;
  char *str = NULL;
  char tfmt[256];
  int ret_len;
  int is_escape;
  int len;
  int i, j;

  shbuf_clear(buff);

  if (!fmt)
    return (0);

	shbuf_lock(buff);

  ret_len = 0;
  is_escape = FALSE;
  va_start(ap, fmt);
  for(i=0;i<strlen(fmt);i++) {
    if (!is_escape) {
      if (fmt[i] == '%') {
        strcpy(tfmt, "%");
        is_escape = TRUE;
        continue;
      }
      shbuf_cat(buff, fmt + i, 1);
      ret_len++;
      continue;
    } 

    sprintf(tfmt+strlen(tfmt), "%c", fmt[i]);
    switch(fmt[i]) {
      case '%':
        shbuf_catstr(buff, "%");
        is_escape = FALSE;
        ret_len++;
        break;

      case 's':
        str = (char *)va_arg(ap, char *);
        len = strlen(str) * 2;
        shbuf_growmap(buff, ret_len + len);
        len = vsnprintf(buff->data + buff->data_of, len, tfmt, ap);
        ret_len += len;
        buff->data_of += len;
        is_escape = FALSE;
        break;

      case 'd':
      case 'u':
      case 'x':
      case 'c':
        shbuf_growmap(buff, ret_len + 64);
        len = vsnprintf(buff->data + buff->data_of, 64, tfmt, ap);
        ret_len += len;
        buff->data_of += len;
        is_escape = FALSE;
        break;
    }
  }
  va_end(ap);

	shbuf_unlock(buff);

  return (ret_len);
}
 
size_t shbuf_pos(shbuf_t *buff)
{
  return (buff->data_pos);
}

static void __shbuf_pos_set(shbuf_t *buff, size_t pos)
{
  buff->data_pos = MIN(buff->data_of, pos);
}

void shbuf_pos_set(shbuf_t *buff, size_t pos)
{
	shbuf_lock(buff);
	__shbuf_pos_set(buff, pos);
	shbuf_unlock(buff);
}

void shbuf_pos_incr(shbuf_t *buff, size_t pos)
{
  shbuf_pos_set(buff, shbuf_pos(buff) + pos);  
}


int shbuf_cmp(shbuf_t *buff, shbuf_t *cmp_buff)
{
  if (shbuf_size(buff) != shbuf_size(cmp_buff))
    return (FALSE);
  if (0 != memcmp(shbuf_data(buff), shbuf_data(cmp_buff), shbuf_size(buff)))
    return (FALSE);
  return (TRUE);
}


/**
 * Increase the data size of a buffer [with zero ('\000') byte data] from it's current size until it reaches <len> bytes.
 */
void shbuf_padd(shbuf_t *buff, size_t len)
{
  static const char null[8];
  size_t of;

  for (of = shbuf_size(buff); of < len; of++) {
    shbuf_cat(buff, null, 1);
  }

}



void shbuf_lock(shbuf_t *buff)
{
#ifdef USE_LIBPTHREAD
	if (!buff)
		return;

	if (!(buff->flags & SHBUF_MUTEX))
		return;

	(void)pthread_mutex_lock(&buff->lk);
#endif
}

void shbuf_unlock(shbuf_t *buff)
{
#ifdef USE_LIBPTHREAD
	if (!buff)
		return;

	if (!(buff->flags & SHBUF_MUTEX))
		return;

	(void)pthread_mutex_unlock(&buff->lk);
#endif
}


#undef __MEM__SHMEM_BUF_C__







