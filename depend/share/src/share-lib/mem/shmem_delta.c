
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
 *
 */  

#include "share.h"

#define vsnprintf_func vsnprintf
static void xprintf (const char *fmt, ...)
{
  char buf[1000];
  va_list a;
  int size;
  va_start (a, fmt);
  size = vsnprintf_func (buf, 1000, fmt, a);
  va_end (a);
  if (size < 0)
  {
    size = sizeof(buf) - 1;
    buf[size] = 0;
  }
  size_t ignore = fwrite(buf, 1, size, stderr);
}


#include "delta/xdelta3.c"

#define PRINTHDR_SPECIAL -4378291

typedef enum
{
  CMD_NONE = 0,
  CMD_PRINTHDR,
  CMD_PRINTHDRS,
  CMD_PRINTDELTA,
  CMD_RECODE,
  CMD_MERGE_ARG,
  CMD_MERGE,
#if XD3_ENCODER
  CMD_ENCODE,
#endif
  CMD_DECODE,
  CMD_TEST,
  CMD_CONFIG,
} xd3_cmd;

typedef enum
{
  RD_FIRST       = (1 << 0),
  RD_NONEXTERNAL = (1 << 1),
  RD_DECOMPSET   = (1 << 2),
  RD_MAININPUT   = (1 << 3),
} xd3_read_flags;

static int         option_no_output          = 0; /* do not write output */
static int         option_quiet              = 1; /* for daemon use */
static usize_t     option_winsize            = XD3_DEFAULT_WINSIZE;
static usize_t         main_bsize = 0;
static uint8_t*        main_bdata = NULL;
static int         option_level              = XD3_DEFAULT_LEVEL;
static int         option_no_compress        = 0;
static int         option_use_checksum       = 0;
static usize_t     option_sprevsz            = XD3_DEFAULT_SPREVSZ;
static usize_t     option_iopt_size          = XD3_DEFAULT_IOPT_SIZE;
static xoff_t      option_srcwinsz           = XD3_DEFAULT_SRCWINSZ;

typedef struct _xd3_file
{
  shbuf_t *buff;
  char *filename;
  const char *realname;
  int flags;
  int mode;
  size_t source_position;
  size_t nwrite;
  size_t nread;
  size_t size_known;
} _xd3_file;


#include "delta/xdelta3-internal.h"

typedef struct _main_blklru      main_blklru;
typedef struct _main_blklru_list main_blklru_list;

struct _main_blklru_list
{
  main_blklru_list  *next;
  main_blklru_list  *prev;
};

struct _main_blklru
{
  uint8_t          *blk;
  xoff_t            blkno;
  usize_t           size;
  main_blklru_list  link;
};

#define MAX_LRU_SIZE 32U
#define XD3_MINSRCWINSZ (XD3_ALLOCSIZE * MAX_LRU_SIZE)
#define XD3_MAXSRCWINSZ (1ULL << 31)

XD3_MAKELIST(main_blklru_list,main_blklru,link);

static usize_t           lru_size = 0;
static main_blklru      *lru = NULL;  /* array of lru_size elts */
static main_blklru_list  lru_list;
static int               do_src_fifo = 0;  /* set to avoid lru */

static int lru_hits   = 0;
static int lru_misses = 0;
static int lru_filled = 0;




static int _xd3_file_isopen (_xd3_file *xfile)
{
  return (xfile->buff != NULL);
}

static int _xd3_read_primary_input(_xd3_file *file, uint8_t  *buf, size_t  size, size_t  *nread)
{
  size_t max_len;

  if (!file->buff)
    return (SHERR_IO);

  max_len = MIN(size, shbuf_size(file->buff));
  if (max_len) {
    memcpy(buf, shbuf_data(file->buff), max_len);
    shbuf_trim(file->buff, max_len);
  }

  if (nread)
    *nread = max_len;
  file->nread += max_len;

  return (0);
}

static int _xd3_file_write (_xd3_file *ofile, uint8_t *buf, usize_t size, const char *msg)
{
  size_t max_len;

  if (!ofile->buff)
    return (SHERR_IO);

  shbuf_cat(ofile->buff, buf, size);

  return (0);
}

static void _xd3_get_appheader(xd3_stream *stream, _xd3_file *ifile, _xd3_file *output, _xd3_file *sfile)
{
}

void _xd3_file_init(_xd3_file *xfile)
{
  memset(xfile, 0, sizeof(_xd3_file));
}

static int _xd3_print_func(xd3_stream* stream, _xd3_file *xfile)
{
  int ret;

  if (option_no_output)
  {
    return 0;
  }


  if (stream->dec_winstart == 0)
  {


    if (stream->dec_hdr_ind & VCD_APPHEADER)
    {
      uint8_t *apphead;
      usize_t appheadsz;
      ret = xd3_get_appheader (stream, & apphead, & appheadsz);

      if (ret == 0 && appheadsz > 0)
      {
        int sq = option_quiet;
        _xd3_file i, o, s;
        XD3_ASSERT (apphead != NULL);
        if ((ret = _xd3_file_write (xfile, apphead,
                appheadsz, "print")) != 0)
        { return ret; }

        _xd3_file_init (& i);
        _xd3_file_init (& o);
        _xd3_file_init (& s);
        option_quiet = 1;
        _xd3_get_appheader (stream, &i, & o, & s);
        option_quiet = sq;
        _xd3_file_cleanup (& i);
        _xd3_file_cleanup (& o);
        _xd3_file_cleanup (& s);
      }
    }
  }


  ret = 0;
  if ((stream->flags & XD3_JUST_HDR) != 0)
  {
    /* Print a header -- finished! */
    ret = PRINTHDR_SPECIAL;
  }
  else if ((stream->flags & XD3_SKIP_WINDOW) == 0)
  {
ret = 0;
//    ret = main_print_window (stream, xfile);
  }

  return ret;
}

static int _xd3_file_stat(_xd3_file *xfile, xoff_t *size)
{
  if (!xfile->buff) {
    *size = 0;
    return;
  }
  *size = shbuf_size(xfile->buff);
}
static int _xd3_file_close(_xd3_file *xfile)
{
  //shbuf_free(&xfile->buff);
  xfile->buff = NULL;
  return (0);
}
int _xd3_file_cleanup(_xd3_file *xfile)
{
  return (_xd3_file_close(xfile));
}
static int _xd3_file_open(_xd3_file *xfile, const char* name, int mode)
{
  xfile->mode = mode;
  xfile->realname = name;
  xfile->nread = 0;
  xfile->buff = shbuf_init();
  return (0);
}

static int _xd3_getblk_lru (xd3_source *source, xoff_t blkno, main_blklru** blrup, int *is_new)
{
  main_blklru *blru = NULL;
  usize_t i;

  (*is_new) = 0;

  if (do_src_fifo)
    {
      /* Direct lookup assumes sequential scan w/o skipping blocks. */
      int idx = blkno % lru_size;
      blru = & lru[idx];
      if (blru->blkno == blkno)
	{
	  (*blrup) = blru;
	  return 0;
	}
      /* No going backwards in a sequential scan. */
      if (blru->blkno != (xoff_t) -1 && blru->blkno > blkno)
	{
	  return XD3_TOOFARBACK;
	}
    }
  else
    {
      /* Sequential search through LRU. */
      for (i = 0; i < lru_size; i += 1)
	{
	  blru = & lru[i];
	  if (blru->blkno == blkno)
	    {
	      main_blklru_list_remove (blru);
	      main_blklru_list_push_back (& lru_list, blru);
	      (*blrup) = blru;
	      return 0;
	    }
	}
    }

  if (do_src_fifo)
    {
      int idx = blkno % lru_size;
      blru = & lru[idx];
    }
  else
    {
      XD3_ASSERT (! main_blklru_list_empty (& lru_list));
      blru = main_blklru_list_pop_front (& lru_list);
      main_blklru_list_push_back (& lru_list, blru);
    }

  lru_filled += 1;
  (*is_new) = 1;
  (*blrup) = blru;
  blru->blkno = -1;
  return 0;
}
static int _xd3_getblk_func (xd3_stream *stream,
		  xd3_source *source,
		  xoff_t      blkno)
{
  int ret = 0;
  xoff_t pos = blkno * source->blksize;
  main_file *sfile = (main_file*) source->ioh;
  main_blklru *blru;
  int is_new;
  int did_seek = 0;
  size_t nread = 0;

  if ((ret = _xd3_getblk_lru (source, blkno, & blru, & is_new)))
  {
    return ret;
  }

  if (!is_new)
  {
    source->curblkno = blkno;
    source->onblk    = blru->size;
    source->curblk   = blru->blk;
    lru_hits++;
    return 0;
  }

  lru_misses += 1;

#if 0
  if (pos != sfile->source_position)
  {
    /* Only try to seek when the position is wrong.  This means the
     * decoder will fail when the source buffer is too small, but
     * only when the input is non-seekable. */
    if ((ret = main_read_seek_source (stream, source, blkno)))
    {
      return ret;
    }

    /* Indicates that another call to _xd3_getblk_lru() may be
     * needed */
    did_seek = 1;
  }
#endif


  if (did_seek &&
      (ret = _xd3_getblk_lru (source, blkno, & blru, & is_new)))
  {
    return ret;
  }

  if ((ret = _xd3_read_primary_input (sfile,
          (uint8_t*) blru->blk,
          source->blksize,
          & nread)))
  {
    return ret;
  }

  /* Save the last block read, used to handle non-seekable files. */
  sfile->source_position = pos + nread;

  source->curblk   = blru->blk;
  source->curblkno = blkno;
  source->onblk    = nread;
  blru->size       = nread;
  blru->blkno      = blkno;

  return 0;
}

static void *_xd3_alloc(void *opaque, size_t  items, usize_t  size)
{
  return calloc(items, size);
}

static void _xd3_free1(void *opaque, void *ptr)
{
  free (ptr);
}

static int _xd3_set_source (xd3_stream *stream, xd3_cmd cmd, _xd3_file *sfile, xd3_source *source)
{
  int ret = 0;
  usize_t i;
  xoff_t source_size = 0;
  usize_t blksize;

  XD3_ASSERT (lru == NULL);
  XD3_ASSERT (stream->src == NULL);
  XD3_ASSERT (option_srcwinsz >= XD3_MINSRCWINSZ);

  /* TODO: this code needs refactoring into FIFO, LRU, FAKE.  Yuck!
   * This is simplified from 3.0z which had issues with sizing the
   * source buffer memory allocation and the source blocksize. */

  /* LRU-specific */
  main_blklru_list_init (& lru_list);

  if ((ret = _xd3_file_open (sfile, sfile->filename, XO_READ)))
  {
    return ret;
  }

  /* If the file is regular we know it's size.  If the file turns
   * out to be externally compressed, size_known may change. */
  sfile->size_known = (_xd3_file_stat(sfile, &source_size) == 0);

  /* Note: The API requires a power-of-two blocksize and srcwinsz
   * (-B).  The logic here will use a single block if the entire file
   * is known to fit into srcwinsz. */
  option_srcwinsz = xd3_pow2_roundup (option_srcwinsz);

  /* Though called "lru", it is not LRU-specific.  We always allocate
   * a maximum number of source block buffers.  If the entire file
   * fits into srcwinsz, this buffer will stay as the only
   * (lru_size==1) source block.  Otherwise, we know that at least
   * option_srcwinsz bytes are available.  Split the source window
   * into buffers. */
  if ((lru = (main_blklru*)_xd3_alloc(NULL, MAX_LRU_SIZE,
          sizeof (main_blklru))) == NULL)
  {
    ret = ENOMEM;
    return ret;
  }

  memset (lru, 0, sizeof(lru[0]) * MAX_LRU_SIZE);

  /* Allocate the entire buffer. */
  if ((lru[0].blk = (uint8_t*)_xd3_alloc(NULL, 1, option_srcwinsz))) {
    ret = ENOMEM;
    return ret;
  }

  /* Main calls _xd3_getblk_func() once before xd3_set_source().  This
   * is the point at which external decompression may begin.  Set the
   * system for a single block. */
  lru_size = 1;
  lru[0].blkno = (xoff_t) -1;
  blksize = option_srcwinsz;
  main_blklru_list_push_back (& lru_list, & lru[0]);
  XD3_ASSERT (blksize != 0);

  /* Initialize xd3_source. */
  source->blksize  = blksize;
  source->name     = sfile->filename;
  source->ioh      = sfile;
  source->curblkno = (xoff_t) -1;
  source->curblk   = NULL;
  source->max_winsize = option_srcwinsz;

  if ((ret = _xd3_getblk_func (stream, source, 0)) != 0)
  {
    return ret;
  }

  source->onblk = lru[0].size;  /* xd3 sets onblk */

  /* If the file is smaller than a block, size is known. */
  if (!sfile->size_known && source->onblk < blksize)
  {
    source_size = source->onblk;
    sfile->size_known = 1;
  }

  /* If the size is not known or is greater than the buffer size, we
   * split the buffer across MAX_LRU_SIZE blocks (already allocated in
   * "lru"). */
  if (!sfile->size_known || source_size > option_srcwinsz)
  {
    /* Modify block 0, change blocksize. */
    blksize = option_srcwinsz / MAX_LRU_SIZE;
    source->blksize = blksize;
    source->onblk = blksize;  /* xd3 sets onblk */
    /* Note: source->max_winsize is unchanged. */
    lru[0].size = blksize;
    lru_size = MAX_LRU_SIZE;

    /* Setup rest of blocks. */
    for (i = 1; i < lru_size; i += 1)
    {
      lru[i].blk = lru[0].blk + (blksize * i);
      lru[i].blkno = i;
      lru[i].size = blksize;
      main_blklru_list_push_back (& lru_list, & lru[i]);
    }
  }

  /* Call the appropriate set_source method, handle errors, print
   * verbose message, etc. */
  if (sfile->size_known)
  {
    ret = xd3_set_source_and_size (stream, source, source_size);
  }
  else
  {
    ret = xd3_set_source (stream, source);
  }

  if (ret)
  {
    return ret;
  }

  return 0;
}

static int _xd3_write_output(xd3_stream* stream, _xd3_file *ofile)
{
  int ret;

  if (option_no_output)
    {
      return 0;
    }

  if (stream->avail_out > 0 &&
      (ret = _xd3_file_write (ofile, stream->next_out,
			      stream->avail_out, "write failed")))
    {
      return ret;
    }

  return 0;
}

static usize_t _xd3_get_winsize(_xd3_file *ifile) 
{ 
  static shortbuf iszbuf;
  xoff_t file_size = 0; 
  usize_t size = option_winsize;

  if (_xd3_file_stat (ifile, &file_size) == 0) {
    size = (usize_t) min(file_size, (xoff_t) size);
  }

  size = max(size, XD3_ALLOCSIZE);
  return size;
}

static int _xd3_set_appheader (xd3_stream *stream, _xd3_file *input, _xd3_file *sfile)
{
  return 0;
}

static int _xd3_merge_func (xd3_stream* stream, _xd3_file *no_write)
{
  int ret;


  return 0;
}

static int _xd3_open_output(xd3_stream *stream, main_file *ofile)
{
  int ret;

  if ((ret = _xd3_file_open (ofile, ofile->filename, XO_WRITE)))
  {
    return ret;
  }

  return 0;
}
static long get_millisecs_now(void)
{
#ifndef _WIN32
  struct timeval tv;

  gettimeofday (& tv, NULL);

  return (tv.tv_sec) * 1000L + (tv.tv_usec) / 1000;
#else
  SYSTEMTIME st;
  FILETIME ft;
  __int64 *pi = (__int64*)&ft;
  GetLocalTime(&st);
  SystemTimeToFileTime(&st, &ft);
  return (long)((*pi) / 10000);
#endif
}
static long get_millisecs_since (void)
{
  static long last = 0;
  long now = get_millisecs_now();
  long diff = now - last;
  last = now;
  return diff;
}
static int _xd3_main_input (xd3_cmd     cmd,
	    _xd3_file   *ifile,
	    _xd3_file   *ofile,
	    _xd3_file   *sfile)
{
  int        ret;
  xd3_stream stream;
  size_t     nread = 0;
  usize_t    winsize;
  int        stream_flags = 0;
  xd3_config config;
  xd3_source source;
  xoff_t     last_total_in = 0;
  xoff_t     last_total_out = 0;
  long       start_time;
  int        stdout_only = 0;
  int (*input_func) (xd3_stream*);
  int (*output_func) (xd3_stream*, _xd3_file *);

  memset (& stream, 0, sizeof (stream));
  memset (& source, 0, sizeof (source));
  memset (& config, 0, sizeof (config));

  config.alloc = _xd3_alloc;
  config.freef = _xd3_free1;

  config.iopt_size = option_iopt_size;
  config.sprevsz = option_sprevsz;

  start_time = get_millisecs_now ();

  if (option_use_checksum) { stream_flags |= XD3_ADLER32; }

  /* main_input setup. */
  switch ((int) cmd)
  {
#if VCDIFF_TOOLS
    if (1) { case CMD_PRINTHDR:   stream_flags |= XD3_JUST_HDR; }
    else if (1) { case CMD_PRINTHDRS:  stream_flags |= XD3_SKIP_WINDOW; }
    else        { case CMD_PRINTDELTA: stream_flags |= XD3_SKIP_EMIT; }
    ifile->flags |= RD_NONEXTERNAL;
    input_func    = xd3_decode_input;
    output_func   = main_print_func;
    stream_flags |= XD3_ADLER32_NOVER;
    stdout_only   = 1;
    break;

    case CMD_RECODE:
    case CMD_MERGE:
    case CMD_MERGE_ARG:
    /* No source will be read */
    stream_flags |= XD3_ADLER32_NOVER | XD3_SKIP_EMIT;
    ifile->flags |= RD_NONEXTERNAL;
    input_func = xd3_decode_input;

    if ((ret = main_init_recode_stream ()))
    {
      return (SHERR_INVAL);
    }

    if (cmd == CMD_RECODE) { output_func = main_recode_func; }
    else                   { output_func = _xd3_merge_func; }
    break;
#endif /* VCDIFF_TOOLS */

#if XD3_ENCODER
    case CMD_ENCODE:
    input_func  = xd3_encode_input;
    output_func = _xd3_write_output;

    if (option_no_compress)      { stream_flags |= XD3_NOCOMPRESS; }

    {
      if (option_level == 0)
      {
        stream_flags |= XD3_NOCOMPRESS;
        config.smatch_cfg = XD3_SMATCH_FASTEST;
      }
      else if (option_level == 1)
      { config.smatch_cfg = XD3_SMATCH_FASTEST; }
      else if (option_level == 2)
      { config.smatch_cfg = XD3_SMATCH_FASTER; }
      else if (option_level <= 5)
      { config.smatch_cfg = XD3_SMATCH_FAST; }
      else if (option_level == 6)
      { config.smatch_cfg = XD3_SMATCH_DEFAULT; }
      else
      { config.smatch_cfg = XD3_SMATCH_SLOW; }
    }
    break;
#endif
    case CMD_DECODE:
    if (option_use_checksum == 0) { stream_flags |= XD3_ADLER32_NOVER; }
    ifile->flags |= RD_NONEXTERNAL;
    input_func    = xd3_decode_input;
    output_func   = _xd3_write_output;
    break;
    default:
    XPR(NT "internal error\n");
    return (SHERR_INVAL);
  }

  main_bsize = winsize = _xd3_get_winsize (ifile);

  if (!(main_bdata = (uint8_t*)_xd3_alloc(NULL, 1, winsize))) {
    return (SHERR_NOMEM);
  }

  config.winsize = winsize;
  config.getblk = _xd3_getblk_func;
  config.flags = stream_flags;

  if ((ret = xd3_config_stream (& stream, & config)))
  {
    return (SHERR_INVAL);
  }

#if VCDIFF_TOOLS
  if ((cmd == CMD_MERGE || cmd == CMD_MERGE_ARG) &&
      (ret = xd3_whole_state_init (& stream)))
  {
    XPR(NT XD3_LIB_ERRMSG (& stream, ret));
    return (SHERR_INVAL);
  }
#endif

  if (cmd != CMD_DECODE)
  {
    /* When not decoding, set source now.  The decoder delays this
     * step until XD3_GOTHEADER. */
    if (sfile && sfile->filename != NULL)
    {
      if ((ret = _xd3_set_source (& stream, cmd, sfile, & source)))
      {
        return (SHERR_INVAL);
      }

      XD3_ASSERT(stream.src != NULL);
    }
  }

  /* This times each window. */
  get_millisecs_since ();

  /* Main input loop. */
  do
  {
    xoff_t input_offset;
    xoff_t input_remain;
    usize_t try_read;

    input_offset = ifile->nread;

    input_remain = XOFF_T_MAX - input_offset;

    try_read = (usize_t) min ((xoff_t) config.winsize, input_remain);

    ret = _xd3_read_primary_input(ifile, main_bdata, try_read, &nread);
    if (ret != 0)
      return (SHERR_IO);

    /* If we've reached EOF tell the stream to flush. */
    if (nread < try_read)
    {
      stream.flags |= XD3_FLUSH;
    }

#if XD3_ENCODER
    /* After the first _xd3_read_primary_input completes, we know
     * all the information needed to encode the application
     * header. */
    if (cmd == CMD_ENCODE &&
        (ret = _xd3_set_appheader (& stream, ifile, sfile)))
    {
      return (SHERR_INVAL);
    }
#endif
    xd3_avail_input (& stream, main_bdata, nread);

    /* If we read zero bytes after encoding at least one window... */
    if (nread == 0 && stream.current_window > 0) {
      break;
    }

again:
    ret = input_func (& stream);

    switch (ret)
    {
      case XD3_INPUT:
        continue;

      case XD3_GOTHEADER:
        {
          XD3_ASSERT (stream.current_window == 0);

          /* Need to process the appheader as soon as possible.  It may
           * contain a suggested default filename/decompression routine for
           * the ofile, and it may contain default/decompression routine for
           * the sources. */
          if (cmd == CMD_DECODE)
          {
            /* May need to set the sfile->filename if none was given. */
            _xd3_get_appheader (& stream, ifile, ofile, sfile);

            /* Now open the source file. */
            if ((sfile->filename != NULL) &&
                (ret = _xd3_set_source (& stream, cmd, sfile, & source)))
            {
              return (SHERR_INVAL);
            }
          }
        }
        /* FALLTHROUGH */
      case XD3_WINSTART:
        {
          /* e.g., set or unset XD3_SKIP_WINDOW. */
          goto again;
        }

      case XD3_OUTPUT:
        {
          /* Defer opening the output file until the stream produces its
           * first output for both encoder and decoder, this way we
           * delay long enough for the decoder to receive the
           * application header.  (Or longer if there are skipped
           * windows, but I can't think of any reason not to delay
           * open.) */
          if (ofile != NULL &&
              ! _xd3_file_isopen (ofile) &&
              (ret = _xd3_open_output (& stream, ofile)) != 0)
          {
            return (SHERR_INVAL);
          }

          if ((ret = output_func (& stream, ofile)) &&
              (ret != PRINTHDR_SPECIAL))
          {
            return (SHERR_INVAL);
          }

          if (ret == PRINTHDR_SPECIAL)
          {
            xd3_abort_stream (& stream);
            ret = 0;
            goto done;
          }

          ret = 0;

          xd3_consume_output (& stream);
          goto again;
        }

      case XD3_WINFINISH:
        {
          goto again;
        }

      default:
        /* input_func() error */
        if (! option_quiet && ret == XD3_INVALID_INPUT)
        {
          XPR(NT "normally this indicates that the source file is incorrect\n");
          XPR(NT "please verify the source file with sha1sum or equivalent\n");
        }
        return (SHERR_INVAL);
    }
  }
  while (nread == config.winsize);

done:
  /* Close the inputs. (ifile must be open, sfile may be open) */
  _xd3_file_close (ifile);
  if (sfile != NULL)
  {
    _xd3_file_close (sfile);
  }


  /* If output file is not open yet because of delayed-open, it means
   * we never encountered a window in the delta, but it could have had
   * a VCDIFF header?  TODO: solve this elsewhere.  For now, it prints
   * "nothing to output" below, but the check doesn't happen in case
   * of option_no_output.  */
  if (! option_no_output && ofile != NULL)
  {
    if (!stdout_only && ! _xd3_file_isopen (ofile))
    {
      XPR(NT "nothing to output: %s\n", ifile->filename);
      return (SHERR_INVAL);
    }

    /* Have to close the output before calling
     * main_external_compression_finish, or else it hangs. */
    if (_xd3_file_close (ofile) != 0)
    {
      return (SHERR_INVAL);
    }
  }

#if EXTERNAL_COMPRESSION
  if ((ret = main_external_compression_finish ()))
  {
    XPR(NT "external compression commands failed\n");
    return (SHERR_INVAL);
  }
#endif

  if ((ret = xd3_close_stream (& stream)))
  {
    return (SHERR_INVAL);
  }

  xd3_free_stream (& stream);

  return (0);
}

int shdelta(shbuf_t *src_buff, shbuf_t *in_buff, shbuf_t *out_buff)
{
  xd3_cmd cmd;
  _xd3_file ifile;
  _xd3_file ofile;
  _xd3_file sfile;
  int ret;

  _xd3_file_init (& ifile);
  _xd3_file_init (& ofile);
  _xd3_file_init (& sfile);

  cmd = CMD_ENCODE;

  ifile.flags    = RD_FIRST | RD_MAININPUT;
  ifile.buff = in_buff;

  sfile.flags    = RD_FIRST;
  sfile.buff = src_buff;

  ofile.buff = out_buff;

  ret = _xd3_main_input (cmd, & ifile, & ofile, & sfile);

  return ret;
}

int shpatch(shbuf_t *src_buff, shbuf_t *in_buff, shbuf_t *out_buff)
{
  xd3_cmd cmd;
  _xd3_file ifile;
  _xd3_file ofile;
  _xd3_file sfile;
  int ret;

  _xd3_file_init (& ifile);
  _xd3_file_init (& ofile);
  _xd3_file_init (& sfile);

  cmd = CMD_DECODE;

  ifile.flags    = RD_FIRST | RD_MAININPUT;
  ifile.buff = in_buff;

  sfile.flags    = RD_FIRST;
  sfile.buff = src_buff;

  ofile.buff = out_buff;

  ret = _xd3_main_input (cmd, & ifile, & ofile, & sfile);

  return ret;
}


