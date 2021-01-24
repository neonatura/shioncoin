
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

#include "share.h"



#define MAX_SHFS_DESCRIPTORS 1024

#define SHFS_DESCRIPTOR_OFFSET (0xFFFF)


static shfstream_t _stream_table[MAX_SHFS_DESCRIPTORS];


static int shfstream_alloc_expand(shfstream_t *stream, size_t size)
{
  static size_t psize;
  size_t alloc_len;
  int err;

  if (!psize) {
    psize = sysconf(_SC_PAGE_SIZE); /* x1 */
    psize = MAX(65536, psize);
  }

  /* allocate enough of file to perform I/O operation. */
  alloc_len = ((size / psize) + 2) * psize;
  alloc_len = MAX(psize * 4, alloc_len); /* minimum */
  alloc_len += (alloc_len/2); /* read-ahead */

  /* allocate enough of file to perform I/O operation. */
  err = shbuf_growmap(stream->buff, alloc_len);
  if (err) {
    sherr(err, "shbuf_growmap");
    return (err);
  }

  return (0);
}



static int shfstream_init_buff(shfstream_t *stream)
{
  shstat st;
  SHFL *fp;
  shbuf_t *buff;
  int err;

  buff = shbuf_init();

  /* initialize stream */
  stream->buff = buff;

  return (0);
}

int shfstream_init(shfstream_t *stream, SHFL *file)
{
  shstat st;
  SHFL *fp;
  shbuf_t *buff;
  int err;

  if ((stream->flags & SHFS_STREAM_OPEN))
    return (SHERR_INVAL);

  memset(&st, 0, sizeof(st));
  err = shfs_fstat(file, &st);
  if (!(stream->flags & SHFS_STREAM_CREATE)) {
    /* file is required to exist */
    if (err)
      return (err);
  }
  if (!err) {
    /* set maximum seek offset */
    stream->buff_max = st.st_size;
  } else {
    /* new file */
    stream->buff_max = 0;
  }

  /* initialize stream */
  stream->file = file;

  err = shfstream_init_buff(stream);
  if (err)
    return (err);

  stream->flags |= SHFS_STREAM_OPEN;

  return (0);
}

int shfstream_open(shfstream_t *stream, const char *path, shfs_t *fs)
{
  SHFL *file;
  int flags;

  flags = 0;
  if (!fs) {
    fs = shfs_init(NULL); 
    stream->fs = fs;
  }

  file = shfs_file_find(fs, (char *)path);
  return (shfstream_init(stream, file));
}


shfstream_t *shfstream_get(int fd)
{

  fd -= SHFS_DESCRIPTOR_OFFSET;
  if (fd < 0 || fd >= MAX_SHFS_DESCRIPTORS)
    return (NULL);

  return (&_stream_table[fd]);
}

int shfstream_getfd(void)
{
  shfstream_t *stream;
  int max;
  int fd;

  max = SHFS_DESCRIPTOR_OFFSET + MAX_SHFS_DESCRIPTORS;
  for (fd = SHFS_DESCRIPTOR_OFFSET; fd < max; fd++) {
    stream = shfstream_get(fd);
    if (!(stream->flags & SHFS_STREAM_OPEN)) {
      return (fd);
    }
  }

  return (-1);
}

int shfstream_setpos(shfstream_t *stream, size_t pos)
{

  if (pos < 0 || pos > stream->buff_max)
    return (SHERR_INVAL);

  stream->buff_pos = pos;
  return (0);
}

/**
 * Obtain the current position of a file stream.
 */
size_t shfstream_getpos(shfstream_t *stream)
{
  return (stream->buff_pos);
}

int shfstream_close(shfstream_t *stream)
{
  int err;

  if (!stream || !(stream->flags & SHFS_STREAM_OPEN))
    return (SHERR_BADF);

  err = shfstream_flush(stream);

	if (stream->file && (stream->buff_max != shfs_size(stream->file))) {
		(void)shfs_truncate(stream->file, stream->buff_max);
	}

  if (stream->fs) {
    /* free partition reference, if allocated */
    shfs_free(&stream->fs);
  }

  if (stream->buff) {
    /* free mmap buffer */
    shbuf_free(&stream->buff);
  }

  /* reset working variables */
  stream->file = NULL;
  stream->buff_pos = 0;
  stream->buff_max = 0;
  stream->flags = 0;

  return (err);
}

int shfstream_stat(shfstream_t *stream, struct stat *buf)
{
  shstat st;
  int err;

  if (!stream || !buf)
    return (SHERR_INVAL);

  if (!(stream->flags & SHFS_STREAM_OPEN))
    return (SHERR_NOENT);

#if 0 /* too slow */
  err = shfstream_flush(stream);
  if (err)
    return (err);
#endif

  memset(&st, 0, sizeof(st));
  shfs_fstat(stream->file, &st);

  memset(buf, 0, sizeof(shstat));

  buf->st_dev = st.st_dev;
  buf->st_ino = st.st_ino;
  buf->st_mode = st.st_mode;

  buf->st_nlink = 0;
  buf->st_uid = (uid_t)st.uid; /* psuedo ref (64bit->32bit) */
  buf->st_gid = buf->st_uid;

  buf->st_rdev = 0;
  buf->st_size = st.st_size;
  buf->st_blksize = st.st_size;
  buf->st_blocks = st.st_blocks;

  buf->st_ctime = shutime(st.ctime);
  buf->st_mtime = shutime(st.mtime);
  buf->st_atime = buf->st_mtime;

  if (stream->flags & SHFS_STREAM_DIRTY) {
    buf->st_size = stream->buff_max;
  }

  return (0);
}

static int shfstream_size_set(shfstream_t *stream, size_t len)
{
  int err;

  err = shfstream_alloc_expand(stream, len); 
  if (err)
    return (err);

  stream->buff_max = len;

  stream->flags |= SHFS_STREAM_SYNC; /* force full file sync */
  stream->flags |= SHFS_STREAM_DIRTY; /* stream is in flux */

  return (0);
} 

/**
 * Extend or reduce the 'total file size' for a stream. 
 * @see shfs_truncate()
 */
int shfstream_truncate(shfstream_t *stream, size_t len)
{
size_t orig_len = stream->buff_max;
  int err;

  /* grow [as needed] */
  if (shbuf_size(stream->buff) < len) {
    shfstream_alloc(stream, len);
#if 0
    shbuf_growmap(stream->buff, len);
#endif
    shbuf_padd(stream->buff, len);
  }

  /* reduce [as needed] */
  if (shbuf_size(stream->buff) > len)
    shbuf_truncate(stream->buff, len);

  /* sanity */
  stream->buff_pos = MIN(stream->buff_pos, len);

  /* set stream's 'total file size' */
  err = shfstream_size_set(stream, len);
  if (err) {
    sherr(err, "shfstream_size_set");
    return (err);
  }

  return (0);
}

int shfstream_alloc(shfstream_t *stream, size_t size)
{
  struct stat st;
  unsigned char *data;
  size_t tot_len;
  ssize_t len;
  size_t of;
  size_t file_len;
  int err;

  if (size < shbuf_size(stream->buff))
    return (0); /* already alloc'd */

  err = shfstream_alloc_expand(stream, size); 
  if (err)
    return (err);

  of = shbuf_size(stream->buff);
  len = MIN(size, stream->buff->data_max) - of;

  if (len > 0) {
    /* read supplemental content to fullfill total length requested */
    err = shfs_read_of(stream->file, stream->buff, of, len);
    if (err < 0 && err != SHERR_NOENT) {
      sherr(err, "shfs_read_of");
      return (err);
    }
  }

  return (0);
}

int shfstream_flush(shfstream_t *stream)
{
  shbuf_t *buff;
  ssize_t len;
  size_t c_len;
  int err;

  if (!(stream->flags & SHFS_STREAM_OPEN))
    return (SHERR_BADF); /* cannot flush closed file */

  if (!(stream->flags & SHFS_STREAM_DIRTY))
    return (0);

  if (!stream->file) {
    sherr(SHERR_IO, "_shfs_stream_flush: null file");
    return (SHERR_IO);
  }

  err = 0;

	/* read in content that hasn't been streamed (until write_of exists) */
	len = MAX(0, (ssize_t)stream->buff_max - (ssize_t)shbuf_size(stream->buff));
	if (len) {
		err = shfstream_alloc(stream, stream->buff_max);
	}
	if (stream->buff_max < shbuf_size(stream->buff)) {
		shbuf_truncate(stream->buff, stream->buff_max);
	}
	if (!err) {
		/* do actual write operation */
		err = shfs_write(stream->file, stream->buff);
	}

  stream->flags &= ~SHFS_STREAM_DIRTY;

  return (err);
}

ssize_t shfstream_read(shfstream_t *stream, void *ptr, size_t size)
{
  unsigned char *data;
  int err;

  if (!(stream->flags & SHFS_STREAM_OPEN))
    return (SHERR_BADF);

  size = MIN(size, stream->buff_max - stream->buff_pos);
  if (size != 0) {
    size_t max_seek;

    /* load file contents in mmap as neccessary */
    /* note: 1meg is about 256 inodes loaded per swipe */
    max_seek = MIN((stream->buff_pos + MAX(size, 16777216)), stream->buff_max);
    err = shfstream_alloc(stream, max_seek);
    if (err)
      return (err);

//    if (shbuf_data(stream->buff)) {
      /* copy file segment into user-buffer */
      data = shbuf_data(stream->buff) + stream->buff_pos;
      memcpy(ptr, data, size);
 //   }

    /* reposition stream offset after data read */
    shfstream_setpos(stream, stream->buff_pos + size);
  }
 
  return (size);
}

ssize_t shfstream_write(shfstream_t *stream, const void *ptr, size_t size)
{
  unsigned char *data;
  size_t buff_of;
  size_t w_len;
  int err;

  if (!(stream->flags & SHFS_STREAM_OPEN))
    return (SHERR_BADF);

  if (size != 0) {
    size_t max_size;

    max_size = MAX(stream->buff_pos + size, stream->buff_max);
    err = shfstream_alloc(stream, max_size);
    if (err)
      return (err);

    buff_of = stream->buff_pos + size;

//    if (shbuf_data(stream->buff)) {
      data = shbuf_data(stream->buff) + stream->buff_pos;
      memcpy(data, ptr, size);

      /* update buffer 'total size' consumed */
      stream->buff->data_of = MAX(stream->buff->data_of, buff_of);

      /* update 'total file size' */
      shfstream_size_set(stream, MAX(stream->buff_max, buff_of));
 //   }

    shfstream_setpos(stream, buff_of);

  //  stream->flags |= SHFS_STREAM_DIRTY;
  }
 
  return (size);
}

int shfstream_sync(shfstream_t *stream)
{
  static shtime_t stamp;
  int err;

  if (!(stream->flags & SHFS_STREAM_DIRTY))
    return (0);

  /* wait min flush time */
  if (shtime_before(shtime(), stamp))
    return (0);

  /* flush stream */
  err = shfstream_flush(stream);

  /* assign new time after flush operation */
  stamp = shtime_adj(shtime(), 3.7);

  return (err);
}



#define CHUNK_SIZE 640

_TEST(shfstream)
{
  static unsigned char CHUNK[CHUNK_SIZE];
  shpeer_t *peer;
  shfs_t *fs;
  unsigned char data[CHUNK_SIZE];
  int idx;
  int err;
  int fd;

  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);

  fd = shopen("/test/shfstream", "w", fs);
  _TRUE(fd > 0);

  err = shftruncate(fd, 0);
  _TRUE(err == 0);

  for (idx = 0; idx < 128; idx++) {
    memset(CHUNK, idx, CHUNK_SIZE);

    err = shwrite(fd, CHUNK, CHUNK_SIZE);
    _TRUE(err == CHUNK_SIZE);

    shfsetpos(fd, (CHUNK_SIZE * idx));
    err = shread(fd, data, CHUNK_SIZE);
    _TRUE(err == CHUNK_SIZE);

    _TRUE(0 == memcmp(CHUNK, data, CHUNK_SIZE));
  }

  shclose(fd);
  shfs_free(&fs);
}


_TEST(shfwrite)
{
  static unsigned char CHUNK[CHUNK_SIZE];
  struct stat st;
  shpeer_t *peer;
  shfs_t *fs;
  int err;
  int fd;
  int idx;
  int cycle;
  unsigned char ch;

  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);



  fd = shopen("shfwrite", "w", fs);
  _TRUE(fd > 0);

  err = shftruncate(fd, 0);
  _TRUE(err == 0);

  for (cycle = 0; cycle < 64; cycle++) {
    for (idx = 0; idx < 64; idx++) {
      ch = (unsigned char)((cycle * idx) % 256);
      memset(CHUNK, ch, CHUNK_SIZE);
      err = shwrite(fd, CHUNK, CHUNK_SIZE);
      _TRUE(err == CHUNK_SIZE);
    }
  }

  shclose(fd);



  fd = shopen("shfwrite", "r", fs);
  _TRUE(fd > 0);

  memset(&st, 0, sizeof(st));
  err = shfstat(fd, &st);
  _TRUE(err == 0);

  shrewind(fd);
  for (cycle = 0; cycle < 64; cycle++) {
    for (idx = 0; idx < 64; idx++) {
      memset(CHUNK, 0, CHUNK_SIZE);
      err = shread(fd, CHUNK, CHUNK_SIZE);
      _TRUE(err == CHUNK_SIZE);

      ch = (unsigned char)((cycle * idx) % 256);
      _TRUE(CHUNK[0] == ch);
    }
  }

  shclose(fd);



  shfs_free(&fs);
}

_TEST(shftruncate)
{
  static unsigned char CHUNK[CHUNK_SIZE];
  struct stat st;
  shpeer_t *peer;
  shfs_t *fs;
  int err;
  int fd;
  int idx;
  int cycle;

  memset(CHUNK, '\001', CHUNK_SIZE);


  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);



  fd = shopen("shftrunc", "w", fs);
  _TRUE(fd > 0);

  err = shftruncate(fd, 0);
  _TRUE(err == 0);

  err = shwrite(fd, CHUNK, CHUNK_SIZE);
  _TRUE(err == CHUNK_SIZE);

  shclose(fd);



  for (cycle = 1; cycle < 128; cycle++) {
    memset(CHUNK, (unsigned char)(cycle + 1), CHUNK_SIZE);

    fd = shopen("shftrunc", "a", fs);
    _TRUE(fd > 0);

    for (idx = 0; idx < 4; idx++) {
      err = shwrite(fd, CHUNK, CHUNK_SIZE);
      _TRUE(err == CHUNK_SIZE);
    }

    err = shftruncate(fd, CHUNK_SIZE * (cycle + 1));
    _TRUE(err == 0);

    shclose(fd);
  }





  fd = shopen("shftrunc", "r", fs);
  _TRUE(fd > 0);

  memset(&st, 0, sizeof(st));
  err = shfstat(fd, &st);
  _TRUE(err == 0);
  _TRUE(st.st_size == 81920);

  for (idx = 0; idx < 128; idx++) {
    memset(CHUNK, 0, CHUNK_SIZE);
    err = shread(fd, CHUNK, CHUNK_SIZE);
    _TRUE(err == CHUNK_SIZE);
    _TRUE( CHUNK[0] == CHUNK[CHUNK_SIZE-1] );
    _TRUE( (unsigned char)(idx + 1) == CHUNK[0] );
  }

  shclose(fd);


  shfs_free(&fs);
}


