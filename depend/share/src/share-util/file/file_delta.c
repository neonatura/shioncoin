
#include "sharetool.h"

#ifdef NATIVE_STDIO
#undef NATIVE_STDIO
#endif


#ifdef NATIVE_STDIO
static int shdelta_file(char *src_path, char *in_path, FILE *out)
{
  char *src_data;
  char *in_data;
  size_t src_datalen;
  size_t in_datalen;
  shbuf_t *src_buff;
  shbuf_t *in_buff;
  shbuf_t *out_buff;
  size_t b_of;
  int b_len;
  int err;

  src_buff = in_buff = out_buff = NULL;

  src_buff = shbuf_init();
  err = shfs_mem_read(src_path, src_buff);
  if (err)
    goto done;

  in_buff = shbuf_init();
  err = shfs_mem_read(in_path, in_buff);
  if (err)
    goto done;

  out_buff = shbuf_init();
  err = shdelta(src_buff, in_buff, out_buff);
  if (err)
    goto done;

  err = 0;
  b_of = 0;
  while (b_of < shbuf_size(out_buff)) {
    b_len = fwrite(shbuf_data(out_buff) + b_of, sizeof(char), shbuf_size(out_buff) - b_of, out);
    if (b_len < 0) {
      err = -errno;
      goto done;
    }

    b_of += b_len;
  }

done:

  shbuf_free(&src_buff);
  shbuf_free(&in_buff);
  shbuf_free(&out_buff);

  return (err);
}
#else
static int shdelta_file(char *src_path, char *in_path, FILE *out)
{
  shfs_t *src_fs;
  shfs_t *in_fs;
  shfs_ino_t *file;
  shbuf_t *src_buff;
  shbuf_t *in_buff;
  shbuf_t *out_buff;
  char *src_data;
  char *in_data;
  size_t src_datalen;
  size_t in_datalen;
  size_t b_of;
  int b_len;
  int err;

  src_buff = in_buff = out_buff = NULL;
  in_fs = src_fs = NULL;

  src_buff = shbuf_init();
  src_fs = shfs_uri_init(src_path, 0, &file);
  if (!src_fs) {
    err = SHERR_NOENT;
    goto done;
  }
  err = shfs_read(file, src_buff);
  if (err)
    goto done;

  in_buff = shbuf_init();
  in_fs = shfs_uri_init(in_path, 0, &file);
  if (!in_fs) {
    err = SHERR_NOENT;
    goto done;
  }
  err = shfs_read(file, in_buff);
  if (err)
    goto done;

  out_buff = shbuf_init();
  err = shdelta(src_buff, in_buff, out_buff);
  if (err)
    goto done;

  err = 0;
  b_of = 0;
  while (b_of < shbuf_size(out_buff)) {
    b_len = fwrite(shbuf_data(out_buff) + b_of, sizeof(char), shbuf_size(out_buff) - b_of, out);
    if (b_len < 0) {
      err = -errno;
      goto done;
    }

    b_of += b_len;
  }

done:

  shbuf_free(&src_buff);
  shbuf_free(&in_buff);
  shbuf_free(&out_buff);
  shfs_free(&in_fs);
  shfs_free(&src_fs);

  return (err);
}
#endif


int share_file_delta(char **args, int arg_cnt, int pflags)
{
  int err;

  err = SHERR_INVAL;
  if (arg_cnt >= 3) {
    err = shdelta_file(args[1], args[2], sharetool_fout);
  }

  return (err);
}

#ifdef NATIVE_STDIO
static int shpatch_file(char *src_path, char *in_path, FILE *out)
{
  char *src_data;
  char *in_data;
  size_t src_datalen;
  size_t in_datalen;
  shbuf_t *src_buff;
  shbuf_t *in_buff;
  shbuf_t *out_buff;
  size_t b_of;
  int b_len;
  int err;

  src_buff = in_buff = out_buff = NULL;

  src_buff = shbuf_init();
  err = shfs_mem_read(src_path, src_buff);
  if (err)
    goto done;

  in_buff = shbuf_init();
  err = shfs_mem_read(in_path, in_buff);
  if (err)
    goto done;

  out_buff = shbuf_init();
  err = shpatch(src_buff, in_buff, out_buff);
  if (err)
    goto done;

  err = 0;
  b_of = 0;
  while (b_of < shbuf_size(out_buff)) {
    b_len = fwrite(shbuf_data(out_buff) + b_of, sizeof(char), shbuf_size(out_buff) - b_of, out);
    if (b_len < 0) {
      err = -errno;
      goto done;
    }

    b_of += b_len;
  }

done:
  shbuf_free(&src_buff);
  shbuf_free(&in_buff);
  shbuf_free(&out_buff);

  return (err);
}
#else
static int shpatch_file(char *src_path, char *in_path, FILE *out)
{
  shfs_t *src_fs;
  shfs_t *in_fs;
  shfs_ino_t *file;
  shbuf_t *src_buff;
  shbuf_t *in_buff;
  shbuf_t *out_buff;
  char *src_data;
  char *in_data;
  size_t src_datalen;
  size_t in_datalen;
  size_t b_of;
  int b_len;
  int err;

  src_buff = in_buff = out_buff = NULL;
  in_fs = src_fs = NULL;

  src_buff = shbuf_init();
  src_fs = shfs_uri_init(src_path, 0, &file);
  if (!src_fs) {
    err = SHERR_NOENT;
    goto done;
  }
  err = shfs_read(file, src_buff);
  if (err)
    goto done;

  in_buff = shbuf_init();
  in_fs = shfs_uri_init(in_path, 0, &file);
  if (!in_fs) {
    err = SHERR_NOENT;
    goto done;
  }
  err = shfs_read(file, in_buff);
  if (err)
    goto done;

  out_buff = shbuf_init();
  err = shpatch(src_buff, in_buff, out_buff);
  if (err)
    goto done;

  err = 0;
  b_of = 0;
  while (b_of < shbuf_size(out_buff)) {
    b_len = fwrite(shbuf_data(out_buff) + b_of, sizeof(char), shbuf_size(out_buff) - b_of, out);
    if (b_len < 0) {
      err = -errno;
      goto done;
    }

    b_of += b_len;
  }

done:
  shbuf_free(&src_buff);
  shbuf_free(&in_buff);
  shbuf_free(&out_buff);
  shfs_free(&src_fs);
  shfs_free(&in_fs);

  return (err);
}
#endif


int share_file_patch(char **args, int arg_cnt, int pflags)
{
  int err;

  err = 0;
  if (arg_cnt >= 3) {
    err = shpatch_file(args[1], args[2], sharetool_fout);
  }

  return (err);
}
