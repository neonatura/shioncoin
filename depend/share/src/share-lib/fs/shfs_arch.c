
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura
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




#if 0



#include "shfs_arch.h"



int open_searchdir_flags;
int open_read_flags;
int incremental_level;
int recursion_option;
bool read_full_records_option;
bool numeric_owner_option;
size_t strip_name_components;
bool one_file_system_option;
size_t archive_names;
const char *listed_incremental_option;
int same_owner_option;
nlink_t trivial_link_count;
bool block_number_option;
bool dereference_option;
int savedir_sort_order;
bool absolute_names_option;
bool multi_volume_option;
struct mode_change *mode_option;
uid_t owner_option;
bool seekable_archive = true;
bool starting_file_option;
char const *owner_name_option;
bool same_order_option;
uintmax_t occurrence_option;
struct timespec mtime_option;
char const *group_name_option;
bool check_device_option;
bool utc_option;
int fstatat_flags;
bool set_mtime_option;
int exit_status;
mode_t initial_umask;
bool incremental_option;
struct tar_stat_info current_stat_info;
int after_date_option;
gid_t group_option;
const char *volume_label_option;
bool unquote_option;
bool ignore_zeros_option;
bool one_top_level_option;
char *one_top_level_dir;
struct timespec newer_mtime_option;


static union block *arch_record_buffer_aligned[2];


static bool to_chars_subst(sharch_t *arch, int negative, int gnu_format, uintmax_t value, size_t valsize, uintmax_t (*substitute) (int *), char *where, size_t size, const char *type);

static bool _sharch_to_chars(sharch_t *arch, int negative, uintmax_t value, size_t valsize, uintmax_t (*substitute) (int *), char *where, size_t size, const char *type);



bool valid_timespec (struct timespec t)
{
  return 0 <= t.tv_nsec;
}

int tar_timespec_cmp (struct timespec a, struct timespec b)
{
  return (a.tv_sec < b.tv_sec ? -1
      : a.tv_sec > b.tv_sec ? 1
      : a.tv_nsec < b.tv_nsec ? -1
      : a.tv_nsec > b.tv_nsec ? 1
      : 0);
}

void tar_stat_destroy (struct tar_stat_info *st)
{
  free (st->orig_file_name);
  free (st->file_name);
  free (st->link_name);
  free (st->uname);
  free (st->gname);
  free (st->cntx_name);
  free (st->dumpdir);
  memset (st, 0, sizeof (*st));
}

void tar_stat_init (struct tar_stat_info *st)
{
  memset (st, 0, sizeof (*st));
}

void set_exit_status (int val)
{
  if (val > exit_status)
    exit_status = val;
}

intmax_t represent_uintmax (uintmax_t n)
{
  if (n <= INTMAX_MAX)
    return n;
  /* Avoid signed integer overflow on picky platforms.  */
  intmax_t nd = n - INTMAX_MIN;
  return nd + INTMAX_MIN;

}

int sharch_buffer_read(shbuf_t *buff, void *data, size_t data_len)
{
  size_t len;

  len = MIN(data_len, shbuf_size(buff) - shbuf_pos(buff));  
  memcpy(data, shbuf_data(buff) + shbuf_pos(buff), len);

  return (len);
}

static void pad_archive(sharch_t *arch, off_t size_left)
{
  union block *blk;
  while (size_left > 0)
  {
    blk = sharch_buffer_next(arch);
    memset (blk->buffer, 0, BLOCKSIZE);
    sharch_set_next_block_after(arch, blk);
    size_left -= BLOCKSIZE;
  }
}

static bool uintmax_to_chars(sharch_t *arch, uintmax_t v, char *p, size_t s)
{
  return _sharch_to_chars(arch, 0, v, sizeof v, 0, p, s, "uintmax_t");
}

static void _simple_finish_header(sharch_t *arch, union block *header)
{
  size_t i;
  int sum;
  char *p;

  memcpy (header->header.chksum, CHKBLANKS, sizeof header->header.chksum);

  sum = 0;
  p = header->buffer;
  for (i = sizeof *header; i-- != 0; )
    /* We can't use unsigned char here because of old compilers, e.g. V7.  */
    sum += 0xFF & *p++;

  /* Fill in the checksum field.  It's formatted differently from the
     other fields: it has [6] digits, a null, then a space -- rather than
     digits, then a null.  We use to_chars.
     The final space is already there, from
     checksumming, and to_chars doesn't modify it.

     This is a fast way to do:

     sprintf(header->header.chksum, "%6o", sum);  */

  uintmax_to_chars(arch, (uintmax_t) sum, header->header.chksum, 7);

  sharch_set_next_block_after(arch, header);
}

/** Finish off a filled-in header block and write it out.  We also print the file name and/or full info if verbose is on.  If BLOCK_ORDINAL is not negative, is the block ordinal of the first record for this file, which may be a preceding long name or long link record.  */
void sharch_finish_header(sharch_t *arch, struct tar_stat_info *st, union block *header, off_t block_ordinal)
{
  _simple_finish_header(arch, header);
}

static enum dump_status _dump_regular_file(sharch_t *arch, int fd, struct tar_stat_info *st)
{
  off_t size_left = st->stat.st_size;
  off_t block_ordinal;
  union block *blk;


  block_ordinal = current_block_ordinal(arch);
  blk = sharch_start_header(arch, st);
  if (!blk)
    return dump_status_fail;

  /* Mark contiguous files, if we support them.  */
  if (arch->archive_format != V7_FORMAT && S_ISCTG (st->stat.st_mode))
    blk->header.typeflag = CONTTYPE;

  sharch_finish_header(arch, st, blk, block_ordinal);

  mv_begin_write(arch, st->file_name, st->stat.st_size, st->stat.st_size);
  while (size_left > 0) {
    size_t bufsize, count;

    blk = sharch_buffer_next(arch);

    bufsize = available_space_after(arch, blk);

    if (size_left < bufsize)
    {
      /* Last read -- zero out area beyond.  */
      bufsize = size_left;
      count = bufsize % BLOCKSIZE;
      if (count)
        memset (blk->buffer + size_left, 0, BLOCKSIZE - count);
    }

    count = (fd <= 0) ? bufsize : shread(fd, blk->buffer, bufsize);
    if (count < 0) {
      pad_archive(arch, size_left);
      return dump_status_short;
    }

    size_left -= count;
    sharch_set_next_block_after(arch, blk + (bufsize - 1) / BLOCKSIZE);
    if (count != bufsize)
    {
      //char buf[UINTMAX_STRSIZE_BOUND];
      memset (blk->buffer + count, 0, bufsize - count);
      set_exit_status (2);
      pad_archive(arch, size_left - (bufsize - count));
      return dump_status_short;
    }
  }


  return dump_status_ok;
}

static void _sharch_file_dump(sharch_t *arch, struct tar_stat_info *st, shfs_t *fs, char const *name, char const *p)
{
  union block *header;
  char type;
  off_t original_size;
  struct timespec original_ctime;
  off_t block_ordinal = -1;
  int fd = 0;
  bool is_dir;
  struct tar_stat_info const *parent = st->parent;
  bool top_level = ! parent;
//  int parentfd = top_level ? chdir_fd : parent->fd;
  void (*diag) (char const *) = 0;
  bool ok;
  int err;

  assign_string (&st->orig_file_name, p);
  assign_string (&st->file_name,
      safer_name_suffix (p, false, absolute_names_option));

  transform_name (&st->file_name, XFORM_REGFILE);

  fd = sharch_fs_open(name, SHARCH_ACCESS_READ, fs);
//  fd = shopen(name, "rb", fs);
  if (fd < 0) {
    errno = -fd;
    return;
  }

  err = shfstat(fd, &st->stat);
  if (err) {
    shclose(fd);
    errno = -err;
    return;
  }

  st->fd = fd;

  st->archive_file_size = original_size = st->stat.st_size;
  st->atime = get_stat_atime (&st->stat);
  st->mtime = get_stat_mtime (&st->stat);
  st->ctime = original_ctime = get_stat_ctime (&st->stat);


  is_dir = S_ISDIR (st->stat.st_mode) != 0;
  //if (!is_dir && !S_ISREG (st->stat.st_mode) && !S_ISCTG (st->stat.st_mode))
  if (!S_ISREG (st->stat.st_mode) && !S_ISCTG (st->stat.st_mode))
    return;

#if 0
  if (is_dir)
  {
    //const char *tag_file_name;
    _ensure_slash (&st->orig_file_name);
    _ensure_slash (&st->file_name);

//    ok = dump_dir (st);
    fd = st->fd;
    parentfd = top_level ? chdir_fd : parent->fd;
  }
#endif

  _dump_regular_file(arch, fd, st);

  shclose(fd);

}

static void _sharch_local_file_dump(sharch_t *arch, struct tar_stat_info *st, char const *name, char const *p)
{
  union block *header;
  char type;
  off_t original_size;
  struct timespec original_ctime;
  off_t block_ordinal = -1;
  int fd = 0;
  bool is_dir;
  struct tar_stat_info const *parent = st->parent;
  bool top_level = ! parent;
//  int parentfd = top_level ? chdir_fd : parent->fd;
  void (*diag) (char const *) = 0;
  bool ok;
  int err;

  assign_string (&st->orig_file_name, p);
  assign_string (&st->file_name,
      safer_name_suffix (p, false, absolute_names_option));

  transform_name (&st->file_name, XFORM_REGFILE);

  fd = open(name, O_RDONLY);
  if (fd < 0) {
    return;
  }

  err = fstat(fd, &st->stat);
  if (err) {
    close(fd);
    return;
  }

  st->fd = fd;

  st->archive_file_size = original_size = st->stat.st_size;
  st->atime = get_stat_atime (&st->stat);
  st->mtime = get_stat_mtime (&st->stat);
  st->ctime = original_ctime = get_stat_ctime (&st->stat);


  is_dir = S_ISDIR (st->stat.st_mode) != 0;
  //if (!is_dir && !S_ISREG (st->stat.st_mode) && !S_ISCTG (st->stat.st_mode))
  if (!S_ISREG (st->stat.st_mode) && !S_ISCTG (st->stat.st_mode))
    return;

#if 0
  if (is_dir)
  {
    //const char *tag_file_name;
    _ensure_slash (&st->orig_file_name);
    _ensure_slash (&st->file_name);

//    ok = dump_dir (st);
    fd = st->fd;
    parentfd = top_level ? chdir_fd : parent->fd;
  }
#endif

  _dump_regular_file(arch, fd, st);

  close(fd);

}

/**
 * Dump a file, recursively.
 * @param parent the parent directory.
 * @param name The file's name relative to PARENT.
 * @param fullname The full path name optionally relative to the working directory.  
 * @note The name param may contain slashes at the top level of invocation.
 */
static void sharch_file_dump(sharch_t *arch, shfs_t *fs, char *name, char *fullname)
{
  sharch_ent_t st;

  memset(&st, 0, sizeof(st));
  tar_stat_init (&st);
  _sharch_file_dump(arch, &st, fs, name, fullname);

  tar_stat_destroy (&st);
}

static int sharch_read_recursive(sharch_t *arch, SHFL *dir, char *rel_path)
{
  SHFL *file;
  shfs_dirent_t *ents;
  char path[SHFS_PATH_MAX];
  int ent_nr;
  int err;
  int i;

  ent_nr = shfs_list(dir, NULL, &ents);
  if (ent_nr < 0)
    return (ent_nr);

  for (i = 0; i < ent_nr; i++) {
    if (ents[i].d_type == SHINODE_FILE) {
      sprintf(path, "%s%s", rel_path, ents[i].d_name); 
      file = shfs_inode(dir, ents[i].d_name, SHINODE_FILE);

      sharch_file_dump(arch, shfs_inode_tree(file), 
          shfs_inode_path(file), path);

//      name_add_inode(path, file);
//      name_add_name(path, MAKE_INCL_OPTIONS(path));
    } else if (ents[i].d_type == SHINODE_DIRECTORY) {
      sprintf(path, "%s%s", rel_path, ents[i].d_name); 
      file = shfs_inode(dir, ents[i].d_name, SHINODE_DIRECTORY);
      sharch_read_recursive(arch, file, path);
    }
  }

  shfs_list_free(&ents);
  return (0);
}

/**
 * Pad atleast 2 blocks of 'null' data.
 */
void sharch_write_eot(sharch_t *arch)
{
  union block *pointer;

  pointer = sharch_buffer_next(arch);
  memset(pointer->buffer, 0, BLOCKSIZE);
  sharch_set_next_block_after(arch, pointer);

  pointer = sharch_buffer_next(arch);
  memset(pointer->buffer, 0, available_space_after(arch, pointer));
  sharch_set_next_block_after(arch, pointer);

  /* establish final archive size */
{
size_t len = shbuf_pos(arch->archive);
arch->archive->data_of = len;
}

}

/** 
 * Create TAR formatted data from an archive directory hierarchy.
 */
int sharch_create(sharch_t *arch, shfs_ino_t *file)
{
  shfs_t *fs;
  struct name const *p;
  char rel_path[SHFS_PATH_MAX];

  if (!arch || !file)
    return (SHERR_INVAL);

  trivial_link_count = name_count <= 1 && ! dereference_option;

  sharch_open_archive(arch, ACCESS_WRITE);// open_archive (ACCESS_WRITE);


  memset(rel_path, 0, sizeof(rel_path));
  sharch_read_recursive(arch, file, rel_path);

  sharch_write_eot(arch);
  sharch_close_archive(arch);

  arch->archive = NULL;

  return (0);
}

#if 0
int sharch_path_create(sharch_t *arch, char *rel_path)
{
  struct name const *p;

  if (!arch)
    return (SHERR_INVAL);

  trivial_link_count = name_count <= 1 && ! dereference_option;

  sharch_open_archive(arch, ACCESS_WRITE);// open_archive (ACCESS_WRITE);
  sharch_local_read_recursive(arch, rel_path);
  sharch_write_eot(arch);
  sharch_close_archive(arch);

  return (0);
}
#endif

/** 
 * Convert an archive directory into TAR formatted binary.
 * @param file Directory archive to encapsulate.
 * @param TAR data contents of directory archive.
 */
int shfs_arch_read(SHFL *file, shbuf_t *buff)
{
  sharch_t *arch;
  int err;

  arch = sharch_init(ACCESS_WRITE);
  arch->archive = buff;
  err = sharch_create(arch, file);
  sharch_free(&arch);

  return (err);
}

/** 
 * Extract TAR formatted data into an archive directory.
 */
int shfs_arch_write(SHFL *file, shbuf_t *buff)
{
  sharch_t *arch;
  int err;

  if (shfs_type(file) == SHINODE_FILE) {
    /* raw write */
    return (shfs_write(file, buff));
  }

  arch = sharch_init(ACCESS_READ);
  arch->archive = buff;
  err = sharch_extract(arch, file);
  sharch_free(&arch);

  return (err);
}



/* Ensure exactly one trailing slash.  */
static void _ensure_slash (char **pstr)
{
  size_t len = strlen (*pstr);

  while (len >= 1 && ISSLASH ((*pstr)[len - 1]))
    len--;
  if (!ISSLASH ((*pstr)[len]))
    *pstr = xrealloc (*pstr, len + 2);
  (*pstr)[len++] = '/';
  (*pstr)[len] = '\0';
}

#if 0
static bool _file_dumpable(struct stat *st)
{
  if (S_ISDIR (st->st_mode))
    return true;
  if (! (S_ISREG (st->st_mode) || S_ISCTG (st->st_mode)))
    return false;
  return ! (st->st_size == 0 && (st->st_mode & MODE_R) == MODE_R);
}
#endif

static void to_octal(uintmax_t value, char *where, size_t size)
{
  uintmax_t v = value;
  size_t i = size;

  do
    {
      where[--i] = '0' + (v & ((1 << LG_8) - 1));
      v >>= LG_8;
    }
  while (i);
}
static void to_base256(int negative, uintmax_t value, char *where, size_t size)
{
  uintmax_t v = value;
  uintmax_t propagated_sign_bits =
    ((uintmax_t) - negative << (CHAR_BIT * sizeof v - LG_256));
  size_t i = size;

  do
  {
    where[--i] = v & ((1 << LG_256) - 1);
    v = propagated_sign_bits | (v >> LG_256);
  }
  while (i);
}
static bool _sharch_to_chars(sharch_t *arch, int negative, uintmax_t value, size_t valsize, uintmax_t (*substitute) (int *), char *where, size_t size, const char *type)
{
  int gnu_format = (arch->archive_format == GNU_FORMAT
		    || arch->archive_format == OLDGNU_FORMAT);

  /* Generate the POSIX octal representation if the number fits.  */
  if (! negative && value <= MAX_VAL_WITH_DIGITS (size - 1, LG_8))
    {
      where[size - 1] = '\0';
      to_octal (value, where, size - 1);
      return true;
    }
  else if (gnu_format)
    {
      /* Try to cope with the number by using traditional GNU format
	 methods */

      /* Generate the base-256 representation if the number fits.  */
      if (((negative ? -1 - value : value)
	   <= MAX_VAL_WITH_DIGITS (size - 1, LG_256)))
	{
	  where[0] = negative ? -1 : 1 << (LG_256 - 1);
	  to_base256 (negative, value, where + 1, size - 1);
	  return true;
	}

      /* Otherwise, if the number is negative, and if it would not cause
	 ambiguity on this host by confusing positive with negative
	 values, then generate the POSIX octal representation of the value
	 modulo 2**(field bits).  The resulting tar file is
	 machine-dependent, since it depends on the host word size.  Yuck!
	 But this is the traditional behavior.  */
      else if (negative && valsize * CHAR_BIT <= (size - 1) * LG_8)
	{
	  where[size - 1] = '\0';
	  to_octal (value & MAX_VAL_WITH_DIGITS (valsize * CHAR_BIT, 1),
		    where, size - 1);
	  return true;
	}
      /* Otherwise fall back to substitution, if possible: */
    }
  else
    substitute = NULL; /* No substitution for formats, other than GNU */

  return to_chars_subst(arch, negative, gnu_format, value, valsize, substitute,
			 where, size, type);
}
static bool to_chars_subst(sharch_t *arch, int negative, int gnu_format, uintmax_t value, size_t valsize, uintmax_t (*substitute) (int *), char *where, size_t size, const char *type)
{
  uintmax_t maxval = (gnu_format
		      ? MAX_VAL_WITH_DIGITS (size - 1, LG_256)
		      : MAX_VAL_WITH_DIGITS (size - 1, LG_8));
  char valbuf[UINTMAX_STRSIZE_BOUND + 1];
  //char maxbuf[UINTMAX_STRSIZE_BOUND];
  char minbuf[UINTMAX_STRSIZE_BOUND + 1];
  char const *minval_string;
  //char const *maxval_string = STRINGIFY_BIGINT (maxval, maxbuf);
  char const *value_string;

  if (gnu_format)
    {
      uintmax_t m = maxval + 1 ? maxval + 1 : maxval / 2 + 1;
      char *p = STRINGIFY_BIGINT (m, minbuf + 1);
      *--p = '-';
      minval_string = p;
    }
  else
    minval_string = "0";

  if (negative)
    {
      char *p = STRINGIFY_BIGINT (- value, valbuf + 1);
      *--p = '-';
      value_string = p;
    }
  else
    value_string = STRINGIFY_BIGINT (value, valbuf);

  if (substitute)
    {
      int negsub;
      uintmax_t sub = substitute (&negsub) & maxval;
      /* NOTE: This is one of the few places where GNU_FORMAT differs from
	 OLDGNU_FORMAT.  The actual differences are:

	 1. In OLDGNU_FORMAT all strings in a tar header end in \0
	 2. Incremental archives use oldgnu_header.

	 Apart from this they are completely identical. */
      uintmax_t s = (negsub &= arch->archive_format == GNU_FORMAT) ? - sub : sub;
      char subbuf[UINTMAX_STRSIZE_BOUND + 1];
      char *sub_string = STRINGIFY_BIGINT (s, subbuf + 1);
      if (negsub)
        *--sub_string = '-';
      return _sharch_to_chars(arch, negsub, s, valsize, 0, where, size, type);
    }
  return false;
}
static bool major_to_chars(sharch_t *arch, major_t v, char *p, size_t s)
{
  return _sharch_to_chars(arch, v < 0, (uintmax_t) v, sizeof v, 0, p, s, "major_t");
}
bool sharch_time_to_chars(sharch_t *arch, time_t v, char *p, size_t s)
{
  return _sharch_to_chars(arch, v < 0, (uintmax_t) v, sizeof v, 0, p, s, "time_t");
}
static uintmax_t uid_substitute(int *negative)
{
  uid_t r;
#ifdef UID_NOBODY
  r = UID_NOBODY;
#else
  static uid_t uid_nobody;
  if (!uid_nobody && !uname_to_uid ("nobody", &uid_nobody))
    uid_nobody = -2;
  r = uid_nobody;
#endif
  *negative = r < 0;
  return r;
}
static bool uid_to_chars(sharch_t *arch, uid_t v, char *p, size_t s)
{
  return _sharch_to_chars(arch, v < 0, (uintmax_t) v, sizeof v, uid_substitute, p, s, "uid_t");
}
static void tar_copy_str(char *dst, const char *src, size_t len)
{
  size_t i;
  for (i = 0; i < len; i++)
    if (! (dst[i] = src[i]))
      break;
}
static void string_to_chars(char const *str, char *p, size_t s)
{
  tar_copy_str (p, str, s);
  p[s - 1] = '\0';
}
static bool minor_to_chars(sharch_t *arch, minor_t v, char *p, size_t s)
{
  return _sharch_to_chars(arch, v < 0, (uintmax_t) v, sizeof v, 0, p, s, "minor_t");
}
static bool off_to_chars(sharch_t *arch, off_t v, char *p, size_t s)
{
  return _sharch_to_chars(arch, v < 0, (uintmax_t) v, sizeof v, 0, p, s, "off_t");
}
static void tar_name_copy_str(sharch_t *arch, char *dst, const char *src, size_t len)
{
  tar_copy_str (dst, src, len);
  if (arch->archive_format == OLDGNU_FORMAT)
    dst[len-1] = 0;
}
static union block *write_short_name(sharch_t *arch, struct tar_stat_info *st)
{
  union block *header = sharch_buffer_next(arch);
  memset (header->buffer, 0, sizeof (union block));
  tar_name_copy_str(arch, header->header.name, st->file_name, NAME_FIELD_SIZE);
  return header;
}
static union block *write_long_name(sharch_t *arch, struct tar_stat_info *st)
{
  return write_short_name(arch, st);
}
static bool string_ascii_p(char const *p)
{
  for (; *p; p++)
    if (*p & ~0x7f)
      return false;
  return true;
}
static union block *sharch_write_header_name(sharch_t *arch, struct tar_stat_info *st)
{
  if (NAME_FIELD_SIZE - (arch->archive_format == OLDGNU_FORMAT)
      < strlen (st->file_name))
    return write_long_name(arch, st);
  else
    return write_short_name(arch, st);
}
static uintmax_t gid_substitute(int *negative)
{
  gid_t r;
#ifdef GID_NOBODY
  r = GID_NOBODY;
#else
  static gid_t gid_nobody;
  if (!gid_nobody && !gname_to_gid ("nobody", &gid_nobody))
    gid_nobody = -2;
  r = gid_nobody;
#endif
  *negative = r < 0;
  return r;
}
static bool gid_to_chars(sharch_t *arch, gid_t v, char *p, size_t s)
{
  return _sharch_to_chars(arch, v < 0, (uintmax_t) v, sizeof v, gid_substitute, p, s, "gid_t");
}
static bool mode_to_chars(sharch_t *arch, mode_t v, char *p, size_t s)
{
  /* In the common case where the internal and external mode bits are the same,
     and we are not using POSIX or GNU format,
     propagate all unknown bits to the external mode.
     This matches historical practice.
     Otherwise, just copy the bits we know about.  */
  int negative;
  uintmax_t u;
  if (S_ISUID == TSUID && S_ISGID == TSGID && S_ISVTX == TSVTX
      && S_IRUSR == TUREAD && S_IWUSR == TUWRITE && S_IXUSR == TUEXEC
      && S_IRGRP == TGREAD && S_IWGRP == TGWRITE && S_IXGRP == TGEXEC
      && S_IROTH == TOREAD && S_IWOTH == TOWRITE && S_IXOTH == TOEXEC
      && arch->archive_format != POSIX_FORMAT
      && arch->archive_format != USTAR_FORMAT
      && arch->archive_format != GNU_FORMAT)
    {
      negative = v < 0;
      u = v;
    }
  else
    {
      negative = 0;
      u = ((v & S_ISUID ? TSUID : 0)
	   | (v & S_ISGID ? TSGID : 0)
	   | (v & S_ISVTX ? TSVTX : 0)
	   | (v & S_IRUSR ? TUREAD : 0)
	   | (v & S_IWUSR ? TUWRITE : 0)
	   | (v & S_IXUSR ? TUEXEC : 0)
	   | (v & S_IRGRP ? TGREAD : 0)
	   | (v & S_IWGRP ? TGWRITE : 0)
	   | (v & S_IXGRP ? TGEXEC : 0)
	   | (v & S_IROTH ? TOREAD : 0)
	   | (v & S_IWOTH ? TOWRITE : 0)
	   | (v & S_IXOTH ? TOEXEC : 0));
    }
  return _sharch_to_chars(arch, negative, u, sizeof v, 0, p, s, "mode_t");
}
union block *sharch_start_header(sharch_t *arch, struct tar_stat_info *st)
{
  union block *header;

  header = sharch_write_header_name(arch, st);
  if (!header)
    return NULL;

  /* Override some stat fields, if requested to do so.  */

  if (owner_option != (uid_t) -1)
    st->stat.st_uid = owner_option;
  if (group_option != (gid_t) -1)
    st->stat.st_gid = group_option;
  if (mode_option)
    st->stat.st_mode =
      ((st->stat.st_mode & ~MODE_ALL)
       | mode_adjust (st->stat.st_mode, S_ISDIR (st->stat.st_mode) != 0,
         initial_umask, mode_option, NULL));

  /* Paul Eggert tried the trivial test ($WRITER cf a b; $READER tvf a)
     for a few tars and came up with the following interoperability
matrix:

WRITER
1 2 3 4 5 6 7 8 9   READER
. . . . . . . . .   1 = SunOS 4.2 tar
# . . # # . . # #   2 = NEC SVR4.0.2 tar
. . . # # . . # .   3 = Solaris 2.1 tar
. . . . . . . . .   4 = GNU tar 1.11.1
. . . . . . . . .   5 = HP-UX 8.07 tar
. . . . . . . . .   6 = Ultrix 4.1
. . . . . . . . .   7 = AIX 3.2
. . . . . . . . .   8 = Hitachi HI-UX 1.03
. . . . . . . . .   9 = Omron UNIOS-B 4.3BSD 1.60Beta

. = works
# = "impossible file type"

The following mask for old archive removes the '#'s in column 4
above, thus making GNU tar both a universal donor and a universal
acceptor for Paul's test.  */

  if (arch->archive_format == V7_FORMAT || arch->archive_format == USTAR_FORMAT)
    MODE_TO_CHARS(arch, st->stat.st_mode & MODE_ALL, header->header.mode);
  else
    MODE_TO_CHARS(arch, st->stat.st_mode, header->header.mode);

  {
    uid_t uid = st->stat.st_uid;
    if (arch->archive_format == POSIX_FORMAT
        && MAX_OCTAL_VAL (header->header.uid) < uid)
    {
      uid = 0;
    }
    if (!UID_TO_CHARS(arch, uid, header->header.uid))
      return NULL;
  }

  {
    gid_t gid = st->stat.st_gid;
    if (arch->archive_format == POSIX_FORMAT
        && MAX_OCTAL_VAL (header->header.gid) < gid)
    {
      gid = 0;
    }
    if (!GID_TO_CHARS(arch, gid, header->header.gid))
      return NULL;
  }

  {
    off_t size = st->stat.st_size;
    if (arch->archive_format == POSIX_FORMAT
        && MAX_OCTAL_VAL (header->header.size) < size)
    {
      size = 0;
    }
    if (!OFF_TO_CHARS(arch, size, header->header.size))
      return NULL;
  }

  {
    struct timespec mtime = set_mtime_option ? mtime_option : st->mtime;
    if (arch->archive_format == POSIX_FORMAT)
    {
      if (MAX_OCTAL_VAL (header->header.mtime) < mtime.tv_sec
          || mtime.tv_nsec != 0)
      if (MAX_OCTAL_VAL (header->header.mtime) < mtime.tv_sec)
        mtime.tv_sec = 0;
    }
    if (!TIME_TO_CHARS(arch, mtime.tv_sec, header->header.mtime))
      return NULL;
  }

  /* FIXME */
  if (S_ISCHR (st->stat.st_mode)
      || S_ISBLK (st->stat.st_mode))
  {
    major_t devmajor = major (st->stat.st_rdev);
    minor_t devminor = minor (st->stat.st_rdev);

    if (arch->archive_format == POSIX_FORMAT
        && MAX_OCTAL_VAL (header->header.devmajor) < devmajor)
    {
      devmajor = 0;
    }
    if (!MAJOR_TO_CHARS(arch, devmajor, header->header.devmajor))
      return NULL;

    if (arch->archive_format == POSIX_FORMAT
        && MAX_OCTAL_VAL (header->header.devminor) < devminor)
    {
      devminor = 0;
    }
    if (!MINOR_TO_CHARS(arch, devminor, header->header.devminor))
      return NULL;
  }
  else if (arch->archive_format != GNU_FORMAT && arch->archive_format != OLDGNU_FORMAT)
  {
    if (!(MAJOR_TO_CHARS(arch, 0, header->header.devmajor)
          && MINOR_TO_CHARS(arch, 0, header->header.devminor)))
      return NULL;
  }

  if (arch->archive_format == POSIX_FORMAT)
  {
  }
  else if (incremental_option)
    if (arch->archive_format == OLDGNU_FORMAT || arch->archive_format == GNU_FORMAT)
    {
      TIME_TO_CHARS(arch, st->atime.tv_sec, header->oldgnu_header.atime);
      TIME_TO_CHARS(arch, st->ctime.tv_sec, header->oldgnu_header.ctime);
    }

  header->header.typeflag = arch->archive_format == V7_FORMAT ? AREGTYPE : REGTYPE;

  switch (arch->archive_format)
  {
    case V7_FORMAT:
      break;

    case OLDGNU_FORMAT:
    case GNU_FORMAT:   /*FIXME?*/
      /* Overwrite header->header.magic and header.version in one blow.  */
      strcpy (header->buffer + offsetof (struct posix_header, magic),
          OLDGNU_MAGIC);
      break;

    case POSIX_FORMAT:
    case USTAR_FORMAT:
      strncpy (header->header.magic, TMAGIC, TMAGLEN);
      strncpy (header->header.version, TVERSION, TVERSLEN);
      break;

    default:
      abort ();
  }

  if (arch->archive_format == V7_FORMAT || numeric_owner_option)
  {
    /* header->header.[ug]name are left as the empty string.  */
  }
  else
  {
    if (owner_name_option)
      st->uname = xstrdup (owner_name_option);
    else
      uid_to_uname (st->stat.st_uid, &st->uname);

    if (group_name_option)
      st->gname = xstrdup (group_name_option);
    else
      gid_to_gname (st->stat.st_gid, &st->gname);

    if (arch->archive_format == POSIX_FORMAT
        && (strlen (st->uname) > UNAME_FIELD_SIZE
          || !string_ascii_p (st->uname)))
    UNAME_TO_CHARS(arch, st->uname, header->header.uname);

    if (arch->archive_format == POSIX_FORMAT
        && (strlen (st->gname) > GNAME_FIELD_SIZE
          || !string_ascii_p (st->gname)))

    GNAME_TO_CHARS(arch, st->gname, header->header.gname);
  }

  return header;
}

/**
 * Extract a archive TAR buffer into a archive directory.
 */
int sharch_extract(sharch_t *arch, shfs_ino_t *file)
{
  return (sharch_extract_archive(arch, file));
}


void sharch_init_buffer(sharch_t *arch)
{

  if (! arch_record_buffer_aligned[arch->arch_record_index])
    arch_record_buffer_aligned[arch->arch_record_index] =
      page_aligned_alloc (&arch_record_buffer[arch->arch_record_index],
          arch->record_size);

  arch->record_start = arch_record_buffer_aligned[arch->arch_record_index];
  arch->current_block = arch->record_start;
  arch->record_end = arch->record_start + BLOCKING_FACTOR;

}

sharch_t *sharch_init(int access_mode)
{
  sharch_t *arch;

  arch = (sharch_t *)calloc(1, sizeof(sharch_t));
  if (!arch)
    return (NULL);

  arch->arch_record_index = 0;
  arch->records_written = 0;
  arch->records_read = 0;

  arch->access_mode = access_mode;
  arch->archive_format = GNU_FORMAT;
  gettime (&arch->start_time);
  arch->last_stat_time = arch->start_time;
  arch->record_size = BLOCKING_FACTOR * BLOCKSIZE;
  sharch_init_buffer(arch);

  if (access_mode != ACCESS_READ) {
    trivial_link_count = name_count <= 1 && ! dereference_option;
    sharch_open_archive(arch, access_mode);
  }

  return (arch);
}

sharch_t *sharch_open(shbuf_t *buff, int mode)
{
  sharch_t *arch;

  arch = sharch_init(mode);
  arch->archive = buff;

  return (arch);
}

sharch_t *sharch_open_inode(shfs_ino_t *inode, int mode)
{
  sharch_t *arch;
  shbuf_t *buff;
  int err;

  buff = shbuf_init();
  err = shfs_read(inode, buff);
  if (err) {
    return (NULL);
  }

  arch = sharch_open(buff, mode);
  if (!arch) {
    shbuf_free(&buff);
    return (NULL);
  }

  arch->flags |= SHARCH_DEALLOC;
  return (arch);
}
  

sharch_t *sharch_open_path(char *path, int mode)
{
  sharch_t *arch;
  shbuf_t *buff;

  buff = shbuf_file(path);
  if (!buff)
    return (NULL);

  arch = sharch_open(buff, mode);
  if (!arch) {
    shbuf_free(&buff);
    return (NULL);
  }

  arch->flags |= SHARCH_DEALLOC;
  return (arch);
}

void sharch_free(sharch_t **arch_p)
{
  sharch_t *arch;

  if (!arch_p)
    return;

  arch = *arch_p;
  *arch_p = NULL;

  if (arch->flags & SHARCH_DEALLOC)
    shbuf_free(&arch->archive);

  free(arch);
}

void sharch_close(sharch_t *arch)
{

  if (arch->access_mode == SHARCH_ACCESS_WRITE ||
      arch->access_mode == SHARCH_ACCESS_UPDATE) {
    sharch_write_eot(arch);
  }

  sharch_close_archive(arch);

  sharch_free(&arch);

}

int sharch_append_inode(sharch_t *arch, shfs_ino_t *file)
{
  int err;

  err = sharch_create(arch, file);

  return (err);
}

static int _sharch_append_path(sharch_t *arch, char *rel_path, char *fullname)
{
  struct stat st;
  DIR *dir;
  struct dirent *ent;
  char path[PATH_MAX+1];
  int ent_nr;
  int err;
  int i;

  err = stat(rel_path, &st);
  if (err)
    return (err);

  if (S_ISREG(st.st_mode)) {
    /* regular file */
    sharch_ent_t st;

    memset(&st, 0, sizeof(st));
    tar_stat_init (&st);
    _sharch_local_file_dump(arch, &st, rel_path, fullname);
    tar_stat_destroy (&st);
    return (0);
  }

  if (S_ISDIR(st.st_mode)) {
    dir = opendir(rel_path);
    if (!dir)
      return (SHERR_NOTDIR);

    err = 0;
    while ((ent = readdir(dir))) {
      if (0 == strcmp(ent->d_name, ".") ||
          0 == strcmp(ent->d_name, ".."))
        continue;

      memset(path, 0, sizeof(path));
      strncpy(path, rel_path, sizeof(path)-1);
      strncat(path, "/", sizeof(path)-strlen(path)-1);
      strncat(path, ent->d_name, sizeof(path)-strlen(path)-1);

      strncat(fullname, "/", PATH_MAX - strlen(fullname));
      strncat(fullname, ent->d_name, PATH_MAX - strlen(fullname));

      err = _sharch_append_path(arch, path, fullname);
      if (err)
        break;
    }

    closedir(dir);
    return (err);
  }

  return (0);
}

int sharch_append_path(sharch_t *arch, char *rel_path)
{
  char fullname[PATH_MAX+1];
  char path[PATH_MAX+1];

  memset(fullname, 0, sizeof(fullname));
  strncpy(fullname, basename(rel_path), sizeof(fullname)-1);
  if (*fullname && fullname[strlen(fullname)-1] == '/')
    fullname[strlen(fullname)-1] = '\000';

  memset(path, 0, sizeof(path));
  strncpy(path, rel_path, sizeof(path)-1);
  if (*path && path[strlen(path)-1] == '/')
    path[strlen(path)-1] = '\000';

  return (_sharch_append_path(arch, path, fullname));
}

int sharch_extract_inode(sharch_t *arch, shfs_ino_t *dir)
{
  return (sharch_extract_archive(arch, dir));
}

int sharch_extract_path(sharch_t *arch, char *dir_path)
{
  int err;

  err = sharch_extract_local_archive(arch, dir_path);

  return (err);
}

shbuf_t *sharch_buffer(sharch_t *arch)
{
  if (!arch)
    return (NULL);
  return (arch->archive);
}



int sharch_fs_open(const char *fname, int mode, shfs_t *fs)
{
  char *open_mode;

  if (!fs) {
    mode = (mode == SHARCH_ACCESS_WRITE) ? (O_CREAT | O_RDWR) : (O_RDONLY);
    return (open(fname, mode, 0777));
  }

  open_mode = (mode == SHARCH_ACCESS_WRITE) ? "wb" : "rb";
  return (shopen(fname, open_mode, fs));
}

ssize_t sharch_fs_read(int fd, char *data, size_t data_len)
{
  return (shread(fd, data, data_len));
}

ssize_t sharch_fs_write(int fd, char *data, size_t data_len)
{
  return (shwrite(fd, data, data_len));
}

int sharch_fs_close(int fd)
{
  return (shclose(fd));
}

int sharch_fs_stat(int fd, struct stat *buf)
{
  return (shfstat(fd, buf));
}
#endif












int shfs_arch_write_op(shz_t *z, shz_idx f_idx, char *f_path, shbuf_t *buff, void *p)
{
  shfs_t *fs;
  shfs_ino_t *inode;
  shfs_ino_t *file;
  int err;

  if (!buff)
    return (SHERR_INVAL);

  inode = (shfs_ino_t *)p;
  if (!inode)
    return (SHERR_INVAL);

  fs = shfs_inode_tree(inode);
  file = shfs_file_find(fs, f_path); 
  err = shfs_write(file, buff);
  if (err)
    return (err);

  return (0);
}

int shfs_arch_write(SHFL *file, shbuf_t *buff)
{
  shz_t z;
  int err;

  if (shfs_type(file) == SHINODE_FILE) {
    /* raw write */
    err = shfs_write(file, buff);
    if (err)
      return (err);
    return (0);
  }

  err = shz_arch_init(&z, buff, 0);
  if (err)
    return (err);

  err = shz_list(&z, shfs_inode_path(file), NULL, shfs_arch_write_op, file);
  shz_arch_free(&z);
  if (err)
    return (err);

  return (0);
}


int shfs_arch_read_file(shz_t *z, char *path, SHFL *file)
{
  shbuf_t *buff;
  int err;

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err) {
    shbuf_free(&buff);
    return (0);
  }

  err = shz_file_write(z, path, buff);
  shbuf_free(&buff);
  return (err);
}

int shfs_arch_read_r(shz_t *z, char *rel_path, char *path, SHFL *file)
{
  shfs_dirent_t *ents;
  int ent_nr;
  char d_path[PATH_MAX+1];
  shfs_ino_t *d_file;
  int err;
  int i;

  if (shfs_type(file) == SHINODE_FILE) {
    err = shfs_arch_read_file(z, path + strlen(rel_path), file);
    if (err)
      return (err);
    return (0);
  }

  if (shfs_type(file) == SHINODE_DIRECTORY) {
    ent_nr = shfs_list(file, NULL, &ents);
    if (ent_nr < 0)
      return (ent_nr);
    for (i = 0; i < ent_nr; i++) {
      if (ents[i].d_type == SHINODE_DIRECTORY) {
        sprintf(d_path, "%s%s", path, ents[i].d_name);
        d_file = shfs_inode(file, ents[i].d_name, SHINODE_DIRECTORY);
        err = shfs_arch_read_r(z, rel_path, d_path, d_file); 
      } else if (ents[i].d_type == SHINODE_FILE) {
        sprintf(d_path, "%s%s", path, ents[i].d_name);
        d_file = shfs_inode(file, ents[i].d_name, SHINODE_FILE);
        err = shfs_arch_read_file(z, d_path + strlen(rel_path), d_file); 
      }
      if (err) {
        shfs_list_free(&ents);
        return (err);
      }
    }
    shfs_list_free(&ents);
  }

  return (0);
}

int shfs_arch_read(SHFL *file, shbuf_t *buff)
{
  shz_t z;
  shfs_ino_t *parent;
  char rel_path[PATH_MAX+1];
  int err;

  err = shz_arch_init(&z, buff, 0); 
  if (err)
    return (err);

  memset(rel_path, 0, sizeof(rel_path));
  strncpy(rel_path, shfs_inode_path(file), sizeof(rel_path)-1);
  err = shfs_arch_read_r(&z, rel_path, rel_path, file);
  shz_arch_free(&z);
  if (err)
    return (err);

  return (0);
}



_TEST(sharch)
{
  SHFL *dir;
  SHFL *file;
  SHFL *to_dir;
  SHFL *to_file;
  shpeer_t *peer;
  shbuf_t *to_buff;
  shbuf_t *buff;
  shfs_t *fs;
char *data;
  char text[1024];
  int err;

  memset(text, 0, sizeof(text));
  memset(text, 'a', 512);

  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);
  _TRUEPTR(fs);

  file = shfs_file_find(fs, "/sharch/file.txt");
  _TRUEPTR(file);

  /* create 'archive directory' to store files */
  dir = shfs_dir_find(fs, "/sharch/");
  _TRUEPTR(dir);
  _TRUE(0 == shfs_attr_set(dir, SHATTR_ARCH));

  buff = shbuf_init();
  shbuf_cat(buff, text, sizeof(text));
  err = shfs_write(file, buff);
  _TRUE(0 == err);
  shbuf_free(&buff);

  /* generate SHZ format data from 'share-fs archive directory' contents */
  buff = shbuf_init();
  err = shfs_arch_read(dir, buff);
  _TRUE(0 == err);

#if 0
  /* write TAR format data to a file */
  to_file = shfs_file_find(fs, "/sharch.tar");
  err = shfs_arch_write(to_file, buff);
  _TRUE(0 == err);

to_buff = shbuf_init();
  err = shfs_read(to_file, to_buff);
_TRUE(0 == err);
_TRUE(shbuf_size(to_buff) == shbuf_size(buff));
_TRUE(0 == memcmp(shbuf_data(to_buff), shbuf_data(buff), shbuf_size(buff)));
shbuf_free(&to_buff);
#endif

  /* apply SHZ archive to 'share-fs archive directory'. */
  to_dir = shfs_dir_find(fs, "/sharch_copy/");
  err = shfs_arch_write(to_dir, buff); 
  _TRUE(0 == err);

  /* verify arch is extracted */
  file = shfs_file_find(fs, "/sharch_copy/file.txt");
  _TRUE(0 == shfs_fstat(file, NULL)); 

  /* verify contents of extracted file */
  shbuf_clear(buff);
  err = shfs_read(file, buff);
  _TRUE(0 == err);
  _TRUE(shbuf_size(buff) == sizeof(text));

  data = shbuf_data(buff);
  _TRUE(0 == memcmp(data, text, sizeof(text)));

  shbuf_free(&buff);
  shfs_free(&fs);
}


