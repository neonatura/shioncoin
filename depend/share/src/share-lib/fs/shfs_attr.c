
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

#include "share.h"


#define MAX_INODE_ATTRIBUTES 16 
static char *_shfs_inode_attr_labels[MAX_INODE_ATTRIBUTES] = 
{
  "Arch",
  "Block",
  "Credential",
  "Database",
  "Encrypt",
  "FLock",
  "Hidden",
  "Link",
  "Meta",
  "Read",
  "Sync",
  "Temp",
  "Version",
  "Write",
  "Execute",
  "Compress"
};

char *shfs_attr_label(int attr_idx)
{

  if (attr_idx < 0 || attr_idx >= MAX_INODE_ATTRIBUTES)
    return ("Unknown");

  if (0 == strcmp(_shfs_inode_attr_labels[attr_idx], ""))
    return ("Unknown");

  return (_shfs_inode_attr_labels[attr_idx]);
}

shfs_attr_t shfs_block_attr(shfs_block_t *blk)
{
  if (!blk)
    return (0);
  return (blk->hdr.attr);
}

shfs_attr_t shfs_attr(shfs_ino_t *inode)
{
  if (!inode)
    return (0);
  return (shfs_block_attr(&inode->blk));
}

char *shfs_attr_str(shfs_attr_t attr)
{
  static char ret_str[256];
  const char *bits = (const char *)SHFS_ATTR_BITS;
  int i;

  memset(ret_str, 0, sizeof(ret_str));
  for (i = 0; i < 16; i++) {
    if (attr & (1 << i)) {
      if (!*ret_str)
        strcat(ret_str, "+");
      sprintf(ret_str + strlen(ret_str), "%c", bits[i]);
    }
  }

  while (strlen(ret_str) < 8)
    strcat(ret_str, "-");

  return (ret_str);
}

int shfs_attr_set(shfs_ino_t *file, int attr)
{
  shfs_attr_t cur_flag;
  shmime_t *mime;
  int err_code;

  if (!file || !attr)
    return (SHERR_INVAL);

  cur_flag = shfs_attr(file);
  if (cur_flag & attr)
    return (0); /* already set */

  err_code = SHERR_OPNOTSUPP;
  switch (attr) {
    case SHATTR_ARCH:
      if (shfs_type(file) == SHINODE_DIRECTORY) { 
        err_code = 0;
      }
      break;
    case SHATTR_COMP:
      if (shfs_type(file) == SHINODE_DIRECTORY) { 
        /* files inherit */
        err_code = 0;
        break;
      }
      err_code = shfs_format_set(file, SHINODE_COMPRESS);
      break;
    case SHATTR_SYNC:
      err_code = 0;
      //err_code = shfs_file_notify(file);
      break;
    case SHATTR_TEMP:
      err_code = 0;
      break;
    case SHATTR_VER:
      err_code = shfs_rev_init(file);
      break;
    case SHATTR_READ:
    case SHATTR_WRITE:
    case SHATTR_EXE:
      err_code = 0;
      break;

    case SHATTR_DB:
      if (shfs_type(file) != SHINODE_FILE ||
          shfs_format(file) != SHINODE_NULL) {
        /* not a file or already contains content */
        err_code = SHERR_INVAL;
        break;
      }


err_code = 0;

#if 0
      err_code = shfs_format_set(file, SHINODE_DATABASE);
#endif




#if 0
      if (shfs_size(file) == 0) {
        /* new database. */
        err_code = 0;
      }

      mime = shmime_file(file);
      if (!mime || 0 == strcmp(mime->mime_name, SHMIME_APP_SQLITE)) {
        err_code = SHERR_INVAL;
        break;
      }
/* DEBUG: move to copy file area */
#endif

      break;
  }

  if (!err_code) {
    file->blk.hdr.attr |= attr;
    err_code = shfs_inode_write_entity(file);
  }

   
  if (!err_code && 
      ((file->blk.hdr.attr & SHATTR_SYNC) ||
       (cur_flag & cur_flag))) {
    /* notify share daemon of altered attribute state for synchronized inode. */
    shfs_file_notify(file);
  }

  return (err_code);
}

int shfs_attr_unset(shfs_ino_t *file, int attr)
{
  shfs_attr_t cur_attr;
  shfs_attr_t new_attr;
  int err_code;
  int format;

  if (!file || !attr)
    return (SHERR_INVAL);

  cur_attr = shfs_attr(file);
  if (!(cur_attr & attr))
    return (0); /* already unset */

  new_attr = cur_attr;
  new_attr &= ~attr;

  err_code = SHERR_OPNOTSUPP;
  switch (attr) {
    case SHATTR_COMP:
      err_code = 0;
      format = SHINODE_DEFAULT_ATTR_FORMAT(new_attr);
      if (format != shfs_format(file))
        err_code = shfs_format_set(file, format); 
      break;
    case SHATTR_SYNC:
      err_code = 0;
      break;
    case SHATTR_TEMP:
      err_code = 0;
      break;
    case SHATTR_VER:
      err_code = shfs_rev_clear(file);
      break;
    case SHATTR_LINK:
      /* unimplemented. */
      err_code = SHERR_OPNOTSUPP;
      /* this is now a local copy */
      file->blk.hdr.attr &= ~SHATTR_SYNC; 
      break;
    case SHATTR_READ:
    case SHATTR_WRITE:
    case SHATTR_EXE:
      err_code = 0;
      break;
    case SHATTR_DB:
/* DEBUG: TODO: write file pertaining to original aux contents. */
      err_code = 0;
      break;
  }

  if (!err_code) {
    file->blk.hdr.attr = new_attr;
    err_code = shfs_inode_write_entity(file);
  }

  if (!err_code && (file->blk.hdr.attr & SHATTR_SYNC))
    shfs_file_notify(file);

  return (err_code);
}


/**
 * Store supplementary credential data in a file.
 */
int shfs_cred_store(shfs_ino_t *file, shkey_t *key, unsigned char *data, size_t data_len)
{
  shfs_ino_t *cred;
  shbuf_t *buff;
  char key_buf[MAX_SHARE_HASH_LENGTH];
  int err;

  memset(key_buf, 0, sizeof(key_buf));
  sprintf(key_buf, "%s", shkey_hex(key));
  cred = shfs_inode(file, key_buf, SHINODE_ACCESS);
  if (!cred)
    return (SHERR_IO);

  cred->blk.hdr.format = SHINODE_ACCESS;
  buff = shbuf_map(data, data_len);
  err = shfs_aux_write(cred, buff);
  free(buff);
  if (err)
    return (err);

  file->blk.hdr.attr |= SHATTR_CRED;
  file->blk.hdr.crc = shcrc(data, data_len);
  file->blk.hdr.size = data_len;
  err = shfs_inode_write_entity(file);
  if (err)
    return (err);

  return (0);
}

/**
 * Load supplementary credential data from a file.
 */
int shfs_cred_load(shfs_ino_t *file, shkey_t *key, unsigned char *data, size_t max_len)
{
  shfs_ino_t *cred;
  shbuf_t *buff;
  char key_buf[MAX_SHARE_HASH_LENGTH];
  int err;

  if (!(file->blk.hdr.attr & SHATTR_CRED))
    return (SHERR_NOENT);

  memset(key_buf, 0, sizeof(key_buf));
  sprintf(key_buf, "%s", shkey_hex(key));
  cred = shfs_inode(file, key_buf, SHINODE_ACCESS);
  if (!cred)
    return (SHERR_IO);

  if (cred->blk.hdr.format != SHINODE_ACCESS)
    return (SHERR_NOENT);

  buff = shbuf_init();
  err = shfs_aux_read(cred, buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }
  if (shbuf_size(buff) == 0) {
    shbuf_free(&buff);
    return (SHERR_IO);
  }

  /* copy buffer */
  memcpy(data, shbuf_data(buff), MIN(shbuf_size(buff), max_len));
  shbuf_free(&buff);

  return (0);
}


int shfs_cred_remove(shfs_ino_t *file, shkey_t *key)
{
  shfs_ino_t *cred;
  char key_buf[MAX_SHARE_HASH_LENGTH];
  int err;

  memset(key_buf, 0, sizeof(key_buf));
  sprintf(key_buf, "%s", shkey_hex(key));
  cred = shfs_inode(file, key_buf, SHINODE_ACCESS);
  if (!cred)
    return (SHERR_IO);

  if (shfs_format(cred) != SHINODE_ACCESS)
    return (0); /* done */

  err = shfs_inode_clear(cred);
  if (err)
    return (err);

  return (0);
}

_TEST(shfs_cred)
{
  shfs_t *fs;
  shfs_ino_t *file;
  shpeer_t *peer;
  shkey_t *key;
  char test_buf[1024];
  char cred_buf[1024];

  peer = shpeer_init("test", NULL);
  _TRUEPTR(peer);
  fs = shfs_init(peer);
  shpeer_free(&peer);
  _TRUEPTR(fs);

  file = shfs_file_find(fs, "/shfs_cred");
  _TRUEPTR(file);
  key = ashkey_uniq();
  _TRUEPTR(key);

  /* store */
  memset(test_buf, 'T', sizeof(test_buf));
  _TRUE(0 == shfs_cred_store(file, key, test_buf, sizeof(test_buf)));

  /* load */
  memset(cred_buf, 0, sizeof(cred_buf));
  _TRUE(0 == shfs_cred_load(file, key, cred_buf, sizeof(cred_buf)));

  /* compare */
  _TRUE(0 == strncmp(test_buf, cred_buf, sizeof(test_buf))); 

  shfs_free(&fs);
}
