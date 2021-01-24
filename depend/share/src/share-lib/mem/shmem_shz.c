
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

#include <stdio.h>
#include "share.h"
#include "zlib.h"

#ifdef HAVE_FNMATCH_H
#include <fnmatch.h>
#endif

/** The maximum chunk size processed at once. */
#define MAX_BUFFER_SIZE 0x4000
/** The maximum possible compression. */
#define windowBits 15
/** The flag indicating a GZIP format. */
#define GZIP_ENCODING 16

#define MAX_SHZ_TYPE_LABELS 11
struct shz_type_label_t
{
  int type;
  char *label;
};
static const struct shz_type_label_t _shz_type_label[MAX_SHZ_TYPE_LABELS] = {
  { SHZ_PAGE_NONE, "none" },
  { SHZ_PAGE_ROOT, "root" },
  { SHZ_PAGE_BRANCH, "branch" },
  { SHZ_PAGE_DATA, "data" },
  { SHZ_PAGE_RAW, "raw" },
  { SHZ_PAGE_INDEX, "index" },
  { SHZ_PAGE_ZLIB, "zlib" },
  { SHZ_PAGE_ZLIB_DATA, "zlib-data" },
  { SHZ_PAGE_DIR, "dir" },
  { SHZ_PAGE_FILE, "file" },
  { SHZ_PAGE_BASE, "base" }
};

const char *shz_type_label(int type)
{
  const char *na_label = "n/a";
  int i;

  if (type >= 0 && type < MAX_SHZ_PAGE_MODES) {
    for (i = 0; i < MAX_SHZ_TYPE_LABELS; i++) {
      if (_shz_type_label[i].type == type)
        return (_shz_type_label[i].label);
    } 
  }

  return (na_label);
}

static inline int _shz_err(int code)
{
  int ret_code;

  ret_code = -1;

  if (code == Z_MEM_ERROR) {
    ret_code = SHERR_NOMEM;
  } else if (code == Z_STREAM_ERROR) {
    ret_code = SHERR_IO;
  } else if (code == Z_ERRNO) {
    ret_code = errno2sherr();
  } else if (code == Z_DATA_ERROR) {
    ret_code = SHERR_INVAL;
  } else if (code == Z_VERSION_ERROR) {
    ret_code = SHERR_INVAL;
  } else if (code == Z_NEED_DICT) {
    ret_code = SHERR_INVAL;
  }

  return (ret_code);
}

int shzenc(shbuf_t *buff, void *data, size_t data_len)
{
  unsigned char out[MAX_BUFFER_SIZE];
  z_stream strm;
  int err;

  memset(&strm, 0, sizeof(z_stream));
  err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
  if (err) {
    return -1;
  }

  strm.next_in = (unsigned char *)data;
  strm.avail_in = data_len;

  do {
    int have;

    strm.avail_out = MAX_BUFFER_SIZE;
    strm.next_out = out;
    err = z_deflate(&strm, Z_FINISH);
    if (err < 0) {
      deflateEnd (& strm);
      return -1;
    }

    have = MAX_BUFFER_SIZE - strm.avail_out;
    shbuf_cat(buff, out, have); 
  }
  while (strm.avail_out == 0);

  z_deflateEnd(&strm);
  return (0);
}

int shzdec(shbuf_t *buff, unsigned char *data, size_t data_len)
{
  z_stream strm;
  unsigned char out[MAX_BUFFER_SIZE];
  unsigned have;
  int ret;

  if (data_len == 0)
    return (0);

  /* allocate inflate state */
  memset(&strm, 0, sizeof(strm));
  ret = inflateInit2(&strm, 47); /* auto-detect */
  if (ret != Z_OK)
    return ret;

  strm.next_in = data;
  strm.avail_in = data_len;

  /* run inflate() on input until output buffer not full */
  do {
    strm.avail_out = MAX_BUFFER_SIZE;
    strm.next_out = out;
    ret = z_inflate(&strm, Z_NO_FLUSH);
    switch (ret) {
      case Z_NEED_DICT:
      case Z_DATA_ERROR:
      case Z_MEM_ERROR:
        (void)inflateEnd(&strm);
        return _shz_err(ret);
    }

    have = MAX_BUFFER_SIZE - strm.avail_out;
    shbuf_cat(buff, out, have);
  } while (strm.avail_out == 0);

  /* clean up and return */
  (void)z_inflateEnd(&strm);
  return ret == Z_STREAM_END ? 0 : SHERR_INVAL;
}

_TEST(shzenc)
{
  char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec sed hendrerit sapien.";
  shbuf_t *raw_buff;
  shbuf_t *buff;
  int err;

  buff = shbuf_init();
  err = shzenc(buff, data, strlen(data) + 1);
  _TRUE(err == 0);
  
  raw_buff = shbuf_init();
  err = shzdec(raw_buff, shbuf_data(buff), shbuf_size(buff));
  _TRUE(err == 0);

  _TRUE(0 == strcmp(data, shbuf_data(raw_buff)));

  shbuf_free(&raw_buff);
  shbuf_free(&buff);
}


static uint16_t shz_crc16(unsigned char *data, size_t data_len, uint16_t seed)
{
  unsigned char *raw_data = (unsigned char *)data;
  uint32_t b = 0;
  uint16_t a = 1 + seed;
  uint16_t num_data;
  int idx;

  if (raw_data) {
    for (idx = 0; idx < data_len; idx += 2) {
      num_data = 0;
      memcpy(&num_data, raw_data + idx, MIN(2, data_len - idx));

      a = (a + num_data);
      b = (b + a);
    }
  }

  return ((uint16_t)htons( (uint16_t)a + (b << 8) ));
}

#if 0
static uint32_t shz_crc32(unsigned char *data, size_t data_len, uint32_t seed)
{
  unsigned char *raw_data = (unsigned char *)data;
  uint64_t b = 0;
  uint32_t a = 1 + seed;
  uint32_t num_data;
  int idx;

  if (raw_data) {
    for (idx = 0; idx < data_len; idx += 2) {
      num_data = 0;
      memcpy(&num_data, raw_data + idx, MIN(2, data_len - idx));

      a = (a + num_data);
      b = (b + a);
    }
  }

  return ((uint32_t)htons( (uint32_t)a + (b << 8) ));
}
#endif

size_t shz_avail(shz_t *z)
{
  if (!z->buff)
    return (0);
  return (MAX(0, z->buff->data_max - (z->bseq * SHZ_PAGE_SIZE)));
}

size_t shz_page_size(shz_hdr_t *hdr)
{
  return ((uint32_t)ntohs((uint16_t)hdr->size));
}

int shz_page_size_set(shz_hdr_t *hdr, size_t len)
{
  if (len < sizeof(shz_hdr_t) || len > SHZ_PAGE_SIZE)
    return (SHERR_INVAL);

  hdr->size = htons((uint16_t)len);
  return (0);
}

void shz_page_type_set(shz_hdr_t *hdr, int type)
{
  hdr->type = htons((uint16_t)type);
}

int shz_page_type(shz_hdr_t *hdr)
{
  return (ntohs(hdr->type));
}

uint16_t shz_salt(shz_t *z)
{
  if (!z || !z->base)
    return (0);
  return (ntohs(z->base->salt));
}


/**
 * Obtain the "SHZ checksum" for a segment of data.
 */
uint16_t shz_crc_get(shz_t *z, shz_hdr_t *hdr)
{
  unsigned char raw[SHZ_PAGE_SIZE];
  shz_hdr_t *r_hdr;
  size_t size;
  uint16_t crc;

  if (!hdr)
    return (0);

  size = shz_page_size(hdr);
  if (size < sizeof(shz_hdr_t) || size >= SHZ_PAGE_SIZE)
    return (0);

  memset(raw, 0, sizeof(raw));
  memcpy(raw, hdr, size);

  r_hdr = (shz_hdr_t *)raw;
  r_hdr->crc = 0;

  return (shz_crc16(raw, size, shz_salt(z)));
}

/**
 * Apply the current checksum to a page.
 */
void shz_crc_set(shz_t *z, shz_hdr_t *hdr)
{

  hdr->crc = 0;
  hdr->crc = shz_crc_get(z, hdr);
}


/**
 * The size of the data content being archived.
 */
ssize_t shz_size(shz_t *z)
{
  if (!z)
    return (SHERR_INVAL);
  if (!z->base)
    return (SHERR_INVAL);
  return ((ssize_t)ntohll(z->base->size));
}

shtime_t shz_ctime(shz_t *z)
{
  if (!z)
    return (SHTIME_UNDEFINED);
  if (!z->base)
    return (SHTIME_UNDEFINED);
  return (z->base->ctime);
}

shtime_t shz_mtime(shz_t *z)
{
  if (!z)
    return (SHTIME_UNDEFINED);
  if (!z->base)
    return (SHTIME_UNDEFINED);
  return (z->base->mtime);
}

time_t shz_uctime(shz_t *z)
{
  return (shutime(shz_ctime(z)));
}

time_t shz_umtime(shz_t *z)
{
  return (shutime(shz_mtime(z)));
}

/**
 * The actual size of the archive.
 */
ssize_t shz_zsize(shz_t *z)
{
  if (!z)
    return (SHERR_INVAL);
  if (!z->base)
    return (SHERR_INVAL);
  return ((ssize_t)ntohll(z->base->zsize));
}

void shz_size_incr(shz_t *z, size_t len)
{
  size_t tot_len;

  tot_len = ntohll(z->base->size);
  tot_len += len;
  z->base->size = htonll(tot_len);
}

void shz_zsize_incr(shz_t *z, size_t len)
{
  size_t tot_len;

  tot_len = ntohll(z->base->zsize);
  tot_len += len;
  z->base->zsize = htonll(tot_len);
}

/**
 * A unique checksum representing the archive.
 */
uint64_t shz_crc(shz_t *z)
{
  if (!z)
    return (SHERR_INVAL);
  if (!z->base)
    return (SHERR_INVAL);
  return (z->base->crc);
}


void shz_scan(shz_t *z, size_t of, size_t max)
{
  size_t s_of;

  of /= SHZ_PAGE_SIZE;
  if (of >= z->bseq)
    return;

  of *= SHZ_PAGE_SIZE;
  for (s_of = of; s_of < max; s_of += SHZ_PAGE_SIZE) {
    shz_hdr_t *hdr = (shz_hdr_t *)(shbuf_data(z->buff) + s_of);
    int type = shz_page_type(hdr);

    if (type == 0)
      break;

    z->bseq++;
    switch(type) {
      case SHZ_PAGE_BASE:
        break;
      case SHZ_PAGE_INDEX:
        break;
      case SHZ_PAGE_ZLIB:
        break;
    }
  }

}

shtree_t *shz_tree_new(shz_idx bnum)
{
  shz_tree_t *info;
  shtree_t *node;

  info = (shz_tree_t *)calloc(1, sizeof(shz_tree_t));
  if (!info)
    return (NULL);

  info->seq = bnum;

  node = shtree_new(NULL, info);
  if (!node) {
    free(info);
    return (NULL);
  }

  return (node);
} 
shtree_t *shz_tree_left_new(shtree_t *parent, shz_idx bnum)
{
  shz_tree_t *info;
  shtree_t *node;

  info = (shz_tree_t *)calloc(1, sizeof(shz_tree_t));
  if (!info)
    return (NULL);

  info->seq = bnum;

  node = shtree_left_new(parent, info);
  if (!node) {
    free(info);
    return (NULL);
  }

  return (node);
}
shtree_t *shz_tree_right_new(shtree_t *parent, shz_idx bnum)
{
  shz_tree_t *info;
  shtree_t *node;

  info = (shz_tree_t *)calloc(1, sizeof(shz_tree_t));
  if (!info)
    return (NULL);

  info->seq = bnum;

  node = shtree_right_new(parent, info);
  if (!node) {
    free(info);
    return (NULL);
  }

  return (node);
}

static void shz_tree_free_r(shtree_t *node)
{
  shz_tree_t *info;

  info = shtree_data_get(node);
  if (!info)
    return;

  shtree_data_set(node, NULL);
  free(info);
}

static void shz_tree_free(shtree_t **tree_p)
{
  shtree_t *tree;

  if (!tree_p)
    return;

  tree = *tree_p;
  *tree_p = NULL;
  if (!tree)
    return;

  shtree_traverse(tree, SHTREE_ORDER_POST, shz_tree_free_r);

  shtree_free(&tree);
}

static void shz_arch_dtable_init(shz_t *z)
{
  shz_hdr_t *blk;
  shz_idx bnum;

  if (!z)
    return;

  shz_tree_free(&z->dtable);

  bnum = 0;
  blk = NULL;
  if (z->base->dtable) {
    bnum = ntohl(z->base->dtable);
    blk = shz_page(z, bnum);
  }
  if (!blk) {
    blk = shz_page_new(z, SHZ_PAGE_ROOT, &bnum);
    if (!blk)
      return;

    z->base->dtable = htonl(bnum);
    shz_page_size_set(blk, sizeof(shz_map_t));
    shz_crc_set(z, blk);
  }

  z->dtable = shz_tree_new(bnum);

}
static void shz_arch_ftable_init(shz_t *z)
{
  shz_hdr_t *blk;
  shz_idx bnum;

  if (!z)
    return;

  shz_tree_free(&z->ftable);

  bnum = 0;
  blk = NULL;
  if (z->base->ftable) {
    bnum = ntohl(z->base->ftable);
    blk = shz_page(z, bnum);
  }
  if (!blk) {
    blk = shz_page_new(z, SHZ_PAGE_ROOT, &bnum);
    if (!blk)
      return;

    z->base->ftable = htonl(bnum);
    shz_page_size_set(blk, sizeof(shz_map_t));
    shz_crc_set(z, blk);
  }

  z->ftable = shz_tree_new(bnum);

}

shz_tree_t *shz_tree_data(shz_t *z, shtree_t *node)
{
  shz_tree_t *info;

  if (!node)
    return (NULL);

  info = shtree_data_get(node);

  if (info && !info->page) {
    info->page = (shz_map_t *)shz_page(z, info->seq); 
  }

  return (info);
}

/* re-iterate through mapping table and re-apply pointer references. */
static void shz_arch_table_reset(shz_t *z, shtree_t *tree, shz_idx tree_idx)
{
  shz_tree_t *info;
  shtree_t *node;
  shz_hdr_t *blk;
  shz_idx bnum;

  if (!tree)
    return; /* error (inval) */

  info = shz_tree_data(z, tree);
  if (!info)
    return; /* error (??) */
  info->page = NULL;//shz_page(z, tree_idx); 

  if ((node = shtree_left(tree))) {
    shz_arch_table_reset(z, node, info->seq); 
  }
  if ((node = shtree_right(tree))) {
    shz_arch_table_reset(z, node, info->seq); 
  }


}

int shz_alloc(shz_t *z, size_t len)
{
  size_t s_len;
  int err;

  len = ((len-1) / SHZ_ALLOC_SIZE) + 1;
  len *= SHZ_ALLOC_SIZE;

  if (len < shz_avail(z))
    return (0);

  if (!z->buff)
    z->buff = shbuf_init();

  s_len = z->buff->data_max;

  if (z->buff->fd > 0) { /* fmap */
    err = shbuf_growmap(z->buff, len);
  } else {
    err = shbuf_grow(z->buff, len);
  }

  z->base = (shz_base_t *)shbuf_data(z->buff);

  if (z->dtable && z->base->dtable) {
    shz_arch_table_reset(z, z->dtable, ntohl(z->base->dtable));
  }

  if (z->ftable && z->base->ftable) {
    shz_arch_table_reset(z, z->ftable, ntohl(z->base->ftable));
  }

  /* update internals */
  shz_scan(z, s_len, z->buff->data_max);

  return (err);
}

void shz_base_set(shz_t *z)
{

  if (!z || !z->buff)
    return;
  if (shbuf_size(z->buff) == 0)
    return;

  z->base = (shz_base_t *)shbuf_data(z->buff);

}

shz_hdr_t *shz_page(shz_t *z, int bnum)
{
  unsigned char *raw;

  if (!z)
    return (NULL);

  if (bnum >= z->bseq) {
    size_t max_seq = (shz_size(z) / SHZ_PAGE_SIZE);
    int err;
 
    if (bnum >= max_seq) {
      return (NULL); /* out of range */
    }

    /* allocate to suffice */
    z->bseq = bnum + 1;
    err = shz_alloc(z,
        (z->bseq * SHZ_PAGE_SIZE) + SHZ_PAGE_SIZE);
    if (err)
      return (NULL);
  }

  raw = (unsigned char *)shbuf_data(z->buff) + (bnum * SHZ_PAGE_SIZE); 
  return ((shz_hdr_t *)raw);
}


shz_hdr_t *shz_page_new(shz_t *z, int type, shz_idx *bnum_p)
{
  shz_hdr_t *blk;
  int bnum;
  int err;


  if (SHZ_PAGE_SIZE >= shz_avail(z)) {
    err = shz_alloc(z,
        (z->bseq * SHZ_PAGE_SIZE) + SHZ_PAGE_SIZE);
    if (err)
      return (NULL);
  }

  /* obtain next page index number */
  bnum = z->bseq++;

  /* increase total size of archive. */
  shz_size_incr(z, SHZ_PAGE_SIZE);

  blk = shz_page(z, bnum);
  if (!blk)
    return (NULL);

  blk->magic = SHMEM16_MAGIC;
  shz_page_type_set(blk, type);

  if (bnum_p)
    *bnum_p = bnum;

  return (blk);
}

/**
 * Obtain the data segment associated with a particular page.
 */
int shz_data_read(shz_t *z, int page_bnum, shbuf_t *ret_buff)
{
  shz_hdr_t *hdr;

  hdr = shz_page(z, page_bnum);
  if (!hdr)
    return (SHERR_INVAL);

  switch (shz_page_type(hdr)) {
    case SHZ_PAGE_ZLIB:
      return (shz_zlib_read(z, page_bnum, ret_buff));
  }

  return (SHERR_OPNOTSUPP);
}

/**
 * @data The memory buffer to fill.
 * @data_len The maximum length of data to fill.
 */
ssize_t shz_read_page(shz_t *z, int bnum, unsigned char *data, size_t data_len)
{
  shz_hdr_t *blk;
  int type;
  int err;

  blk = shz_page(z, bnum);
  if (!blk) {
    return (SHERR_IO);
  }

  type = ntohs(blk->type);

  if (type == 0) {
    return (0); /* nothing to do */
}

  if (type >= MAX_SHZ_PAGE_MODES)
    return (SHERR_INVAL);

  if (blk->magic != SHMEM16_MAGIC) {
    return (SHERR_INVAL);
}

  if (shz_page_size(blk) > SHZ_PAGE_SIZE) {
    return (SHERR_INVAL);
  }

  if (type != SHZ_PAGE_BASE) {
    /* verify checksum */
    if (shz_crc_get(z, blk) != blk->crc) {
      return (SHERR_ILSEQ);
    }
  }

  err = 0;
  switch (type) {
#if 0
    case SHZ_PAGE_INDEX:
      /* an index of hashes to decode into data */
      err = shz_index_read(z, blk, data, data_len);
      break;
#endif
  }

  return (err);
}

int shz_map_set(shz_map_t *map, int hnum, shz_idx ref_bnum)
{
  unsigned char *raw = (unsigned char *)map + sizeof(shz_index_t);
  shz_idx *seg;

  if (hnum <= 0 || hnum >= SHZ_HASH_MASK) {
    return (SHERR_INVAL);
  }

  seg = (shz_idx *)raw;

  if (seg[hnum] != 0) {
    if (ntohl(seg[hnum]) == ref_bnum)
      return (0); /* already was set */

    /* already in use */
    return (SHERR_EXIST);
  }

  seg[hnum] = htonl(ref_bnum);
  return (0);
}

int shz_map_load(shz_t *z, shtree_t *node)
{
  shz_tree_t *info;
  shz_map_t *map;

  info = (shz_tree_t *)shz_tree_data(z, node);
  if (!info) return (SHERR_IO);

  map = (shz_map_t *)info->page;
  if (!map) return (SHERR_IO);

  if (!shtree_left(node) && map->left) {
    if (!shz_tree_left_new(node, ntohl(map->left)))
      return (SHERR_NOMEM);
  }

  if (!shtree_right(node) && map->right) {
    if (!shz_tree_right_new(node, ntohl(map->right)))
      return (SHERR_NOMEM);
  }

  return (0);
}

int shz_map_get(shz_map_t *map, int hnum, shz_idx *ref_bnum_p)
{
  unsigned char *raw = (unsigned char *)map + sizeof(shz_index_t);
  shz_idx *seg;

  if (hnum <= 0 || hnum >= SHZ_HASH_MASK) {
    return (SHERR_INVAL);
  }

  seg = (shz_idx *)raw;

  if (seg[hnum] == 0) {
    return (SHERR_NOENT);
  }

  if (ref_bnum_p) {
    *ref_bnum_p = ntohl(seg[hnum]);
  }
  
  return (0);
}

int shz_tree_add(shz_t *z, shtree_t *tree, shz_idx ref_bnum, shkey_t *ref_id)
{
  shz_tree_t *info;
  shz_map_t *blk;
  shtree_t *node;
  uint64_t crc;
  int l_or_r;
  int hnum;
  int err;

  if (!tree)
    return (SHERR_INVAL);

  crc = shkey_crc(ref_id);
  l_or_r = (crc % 2);
  hnum = ((crc / 2) % SHZ_HASH_MASK);

  node = tree;
  while (node) {
    info = shz_tree_data(z, node);
    if (!info) return (SHERR_IO);

    /* determine if node has same id ref */
    blk = (shz_map_t *)info->page;
    if (!blk) return (SHERR_IO);

    err = shz_map_set(blk, hnum, ref_bnum); 
    if (!err)
      break;

    if (l_or_r == 0) { /* even */
      if (!shtree_left(node)) {
        shz_map_t *r_blk = NULL;
        shz_idx bnum;

        bnum = 0;
        if (!blk->left) {
          r_blk = (shz_map_t *)shz_page_new(z, SHZ_PAGE_BRANCH, &bnum);
          if (!r_blk)
            return (SHERR_IO);

          blk->left = htonl(bnum);
          shz_crc_set(z, (shz_hdr_t *)blk);
        }

        if (!shz_tree_left_new(node, ntohl(blk->left)))
          return (SHERR_NOMEM);
      }

      node = shtree_left(node);
    } else { /* odd */
      if (!shtree_right(node)) {
        shz_map_t *r_blk = NULL;
        shz_idx bnum;

        if (!blk->right) {
          r_blk = (shz_map_t *)shz_page_new(z, SHZ_PAGE_BRANCH, &bnum);
          if (!r_blk)
            return (SHERR_IO);

          blk->right = htonl(bnum);
          shz_crc_set(z, (shz_hdr_t *)blk);
        }

        if (!shz_tree_right_new(node, ntohl(blk->right)))
          return (SHERR_NOMEM);
      }

      node = shtree_right(node);
    }
  }
 
  return (0);
}


int is_shz_mod_type(int type)
{

  switch (type) {
    case SHZ_PAGE_FILE:
    case SHZ_PAGE_DIR:
    case SHZ_PAGE_ZLIB:
      return (TRUE);
  }

  return (FALSE);
}

int shz_mod_id(shz_t *z, int bnum, shkey_t **id_p)
{
  shz_mod_t *blk;
  int type;
  int err;

  blk = (shz_mod_t *)shz_page(z, bnum);
  if (!blk)
    return (SHERR_NOENT);

  type = shz_page_type((shz_hdr_t *)blk);
  if (!is_shz_mod_type(type)) {
    return (SHERR_INVAL);
}

  if (id_p) {
    *id_p = &blk->id;
  }

  return (0);
}


time_t shz_mod_ctime(shz_t *z, shz_idx bnum)
{
  shz_mod_t *mod;
  int type;

  mod = (shz_mod_t *)shz_page(z, bnum);
  if (!mod)
    return (SHERR_INVAL);

  type = shz_page_type((shz_hdr_t *)mod);
  if (!is_shz_mod_type(type))
    return (SHERR_INVAL);

  return (shutime(mod->ctime));
}

time_t shz_mod_mtime(shz_t *z, shz_idx bnum)
{
  shz_mod_t *mod;
  int type;

  mod = (shz_mod_t *)shz_page(z, bnum);
  if (!mod)
    return (SHERR_INVAL);

  type = shz_page_type((shz_hdr_t *)mod);
  if (!is_shz_mod_type(type))
    return (SHERR_INVAL);

  return (shutime(mod->mtime));
}

const char *shz_mod_label(shz_t *z, shz_idx bnum)
{
  shz_mod_t *mod;
  int type;

  mod = (shz_mod_t *)shz_page(z, bnum);
  if (!mod)
    return (NULL);

  type = shz_page_type((shz_hdr_t *)mod);
  if (!is_shz_mod_type(type))
    return (NULL);

  return (shz_type_label(type));
}

/* check for duplicate data entry */
int shz_tree_get(shz_t *z, shtree_t *tree, shkey_t *id, shz_idx *bnum_p)
{
  shz_mod_t *mod;
  shtree_t *node;
  shz_tree_t *info;
  shz_map_t *blk;
  shkey_t *ref_id;
  shkey_t *key;
  uint64_t crc;
  int l_or_r;
  int ref_bnum;
  int bnum;
  int hnum;
  int err;

  if (!tree)
    return (SHERR_INVAL);

  crc = shkey_crc(id);
  l_or_r = (crc % 2);
  hnum = ((crc / 2) % SHZ_HASH_MASK);

  node = tree;
  while (node) {
    info = shz_tree_data(z, node);
    if (!info) return (SHERR_IO);
 
    blk = (shz_map_t *)info->page;
    if (!blk) return (SHERR_IO);

    err = shz_map_get(blk, hnum, &ref_bnum);
    if (err)
      return (err);

    ref_id = NULL;
    err = shz_mod_id(z, ref_bnum, &ref_id);
    if (err)
      return (err);

    if (shkey_cmp(ref_id, id)) {
      if (bnum_p) {
        *bnum_p = ref_bnum;
      }
      break; /* found match */
    }

    if (l_or_r == 0) { /* even */
      if (!shtree_left(node) && blk->left) {
        if (!shz_tree_left_new(node, ntohl(blk->left)))
          return (SHERR_NOMEM);
      }

      node = shtree_left(node);
    } else {
      if (!shtree_right(node) && blk->right) {
        if (!shz_tree_right_new(node, ntohl(blk->right)))
          return (SHERR_NOMEM);
      }

      node = shtree_right(node);
    }
  }

  if (!node)
    return (SHERR_NOENT); /* not map'd */

  return (0);
}
 
int shz_zlib_new(shz_t *z, int raw_bnum, size_t raw_len, shz_idx *z_bnum_p, shkey_t *z_id)
{
  shz_mod_t *blk;
  int err;

  blk = (shz_mod_t *)shz_page_new(z, SHZ_PAGE_ZLIB, z_bnum_p);
  if (!blk)
    return (SHERR_IO);

  blk->size = htonl(raw_len);
  blk->seq = htonl(raw_bnum);
  memcpy(&blk->id, z_id, sizeof(blk->id));

  shz_page_size_set((shz_hdr_t *)blk, sizeof(shz_mod_t));
  shz_crc_set(z, (shz_hdr_t *)blk);

  return (0);
}

int shz_dtable_get(shz_t *z, shkey_t *id, shz_idx *pnum_p)
{
  int err;

  err = shz_tree_get(z, z->dtable, id, pnum_p);
  if (err)
    return (err);

  return (0);
}

int shz_dtable_set(shz_t *z, shkey_t *id, shz_idx pnum)
{
  int err;

  err = shz_tree_add(z, z->dtable, pnum, id);
  if (err)
    return (err);

  return (0);
}

int shz_ftable_get(shz_t *z, const char *filename, shz_idx *pnum_p)
{
  shkey_t *key;
  int err;

  key = shkey_bin((char *)filename, strlen(filename));
  err = shz_tree_get(z, z->ftable, key, pnum_p);
  shkey_free(&key);
  if (err)
    return (err);

  return (0);
}

int shz_ftable_set(shz_t *z, const char *filename, shz_idx pnum)
{
  shkey_t *key;
  int err;

  key = shkey_bin((char *)filename, strlen(filename));
  err = shz_tree_add(z, z->ftable, pnum, key);
  shkey_free(&key);
  if (err)
    return (err);

  return (0);
}






int shz_arch_init(shz_t *z, shbuf_t *buff, int flags)
{
  shz_base_t *base;
  int err;

  if (!z)
    return (SHERR_INVAL);

  memset(z, 0, sizeof(shz_t));

  if (buff) {
    z->buff = buff;
    if (shbuf_size(buff) < SHZ_PAGE_SIZE)
      flags |= SHZ_FRESH;
  } else {
    z->buff = shbuf_init();
    flags |= SHZ_FRESH;
    flags |= SHZ_ALLOC;
  }
  if ((flags & SHZ_TRUNC)) {
    flags |= SHZ_FRESH;
  }

  /* count anything already allocated */
  z->base = (shz_base_t *)shbuf_data(z->buff);
  shz_scan(z, 0, z->buff->data_max);

  err = shz_alloc(z, MAX(z->bseq * SHZ_PAGE_SIZE, SHZ_ALLOC_SIZE));
  if (err)
    return (err);

#if 0
  z->base = (shz_base_t *)shbuf_data(z->buff);
  if (z->base->size == 0)
    flags |= SHZ_FRESH;
#endif

  if (flags & SHZ_FRESH) {
    z->bseq = 0;

    z->base = base = (shz_base_t *)shz_page_new(z, SHZ_PAGE_BASE, NULL);
    base->hdr.magic = SHMEM16_MAGIC;
    /* unique quantifier for checksum */
    base->salt = htons(shrand() % 0xFFFF);

    /* base header */
    base->size = (uint64_t)htonll((uint64_t)SHZ_PAGE_SIZE);
    base->zsize = (uint64_t)htonll(0LL);
    base->ctime = base->mtime = shtime();

    shz_page_size_set(&base->hdr, sizeof(shz_base_t));
  } else {
    z->base = (shz_base_t *)shbuf_data(z->buff);
    if (z->base->hdr.magic != SHMEM16_MAGIC)
      return (SHERR_ILSEQ);
    if (z->base->size == 0)
      return (SHERR_ILSEQ);
  }

  shz_arch_dtable_init(z);
  shz_arch_ftable_init(z);

  z->flags = flags;

  return (0);
}

shz_t *shz_init(shbuf_t *buff, int flags)
{
  shz_t *z;
  int err;

  z = (shz_t *)calloc(1, sizeof(shz_t));
  if (!z)
    return (NULL);

  err = shz_arch_init(z, buff, flags);
  if (err) {
    free(z);
    return (NULL);
  }

  return (z); 
}

int shz_arch_fopen(shz_t *z, const char *path, int flags)
{
  struct stat st;
  shbuf_t *buff;
  int err;

  err = stat(path, &st);
  if (err) {
    if (!(flags & SHZ_CREATE)) {
      return (errno2sherr());
    }

    flags |= SHZ_FRESH;
  }

  buff = shbuf_file((char *)path);
  if (!buff)
    return (SHERR_NOENT);

  err = shz_arch_init(z, buff, flags | SHZ_ALLOC);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }

  return (0);
}

shz_t *shz_fopen(const char *path, int flags)
{
  shz_t *z;
  int err;

  z = (shz_t *)calloc(1, sizeof(shz_t));
  if (!z)
    return (NULL);

  err = shz_arch_fopen(z, path, flags);
  if (err) {
    free(z);
    return (NULL);
  }

  return (z);
}

static void shz_arch_close(shz_t *z)
{
  if (!z || !z->buff || !z->buff->fd)
    return;

  /* truncate to actual size */
  struct stat st;
  int fd = dup(z->buff->fd);
  size_t len = shz_size(z);
  int err;

  if (z->flags & SHZ_ALLOC) {
    shbuf_free(&z->buff);
  }

  err = fstat(fd, &st);
  if (!err && st.st_size != len) {
    ftruncate(fd, len); 
  }

  close(fd);
}

void shz_arch_free(shz_t *z)
{
  size_t len;

  if (!z)
    return;

  len = shz_size(z);

  shz_tree_free(&z->dtable);
  shz_tree_free(&z->ftable);

  shz_arch_close(z);

  z->base = NULL;
//  z->index = NULL;

  if ((z->flags & SHZ_ALLOC)) {
    if (z->buff)
      shbuf_free(&z->buff);
  } else {
    if (z->buff) {
      z->buff->data_of = len;
    }
  }
}

void shz_free(shz_t **z_p)
{
  shz_t *z;

  if (!z_p)
    return;

  z = *z_p;
  if (!z)
    return;

  shz_arch_free(z);
  free(z);
}



ssize_t shz_raw_write(shz_t *z, shz_idx *ret_idx_p, unsigned char *data, size_t data_len)
{
  shz_hdr_t *blk;
  unsigned char *raw;
  ssize_t w_len;
  shz_idx ret_idx;

  blk = shz_page_new(z, SHZ_PAGE_DATA, &ret_idx);
  if (!blk)
    return (0);

  w_len = MIN(SHZ_PAGE_SIZE - sizeof(shz_data_t), data_len);

  raw = ((unsigned char *)blk) + sizeof(shz_data_t);
  memcpy(raw, data, w_len);

  shz_page_size_set(blk, w_len + sizeof(shz_data_t));
  shz_crc_set(z, blk);

  if (ret_idx_p)
    *ret_idx_p = ret_idx;

  return (w_len);
}

int shz_raw_read(shz_t *z, shz_idx bnum, shbuf_t *buff)
{
  shz_hdr_t *blk;
  unsigned char *raw;
  ssize_t r_len;

  blk = shz_page(z, bnum);
  if (!blk)
    return (SHERR_INVAL);

  r_len = shz_page_size(blk) - sizeof(shz_data_t);
  if (r_len < 0)
    return (SHERR_IO);

  raw = ((unsigned char *)blk) + sizeof(shz_data_t);
  shbuf_cat(buff, raw, r_len);

  return (0);
}

int shz_index_append(shz_t *z, shz_index_t *idx, shz_idx bnum)
{
  shz_idx *seg;
  unsigned char *raw;
  int i;

  raw = (unsigned char *)idx;
  seg = (shz_idx *)(raw + sizeof(shz_index_t));
 
  for (i = 0; i < SHZ_MAX_INDEX_SIZE; i++) {
    if (seg[i] != 0)
      continue;

    break;
  }
  if (i == SHZ_MAX_INDEX_SIZE)
    return (SHERR_NOBUFS);

  seg[i] = (shz_idx)htonl(bnum);
  shz_page_size_set((shz_hdr_t *)idx,
      sizeof(shz_index_t) + ((i + 1) * sizeof(shz_idx)));

  return (0);
}

int shz_index_add(shz_t *z, shz_write_f f, shbuf_t *buff, shz_idx *ret_idx_p)
{
  shz_idx ret_idx;
  shz_idx bnum;
  shz_idx seq;
  shz_idx l_seq;
  size_t max_len;
  size_t of;
  ssize_t w_len;
  int err;

  max_len = shbuf_size(buff);

  seq = 0;
  if (*ret_idx_p)
    seq = *ret_idx_p;

  of = 0;
  l_seq = 0;
  ret_idx = 0;
  while (of < max_len) {
    unsigned char *raw = shbuf_data(buff) + of;
    size_t len = shbuf_size(buff) - of;
    shz_index_t *idx;

    w_len = (*f)(z, &bnum, raw, len);
    if (w_len < 0)
      return (w_len);

    if (seq) {
      idx = (shz_index_t *)shz_page(z, seq);
      if (!idx)
        return (SHERR_IO);
    }
    if (!seq) {
      /* create new index page */
      idx = (shz_index_t *)shz_page_new(z, SHZ_PAGE_INDEX, &seq);
      if (!idx)
        return (SHERR_IO);

      if (!ret_idx)
        ret_idx = seq;

      if (l_seq) {
        shz_index_t *blk = (shz_index_t *)shz_page(z, l_seq);
        if (blk) { /* record chain sequence */
          blk->seq = htonl(seq);
          shz_crc_set(z, (shz_hdr_t *)blk);
        }
      }
    }

    /* add reference to data content */
    err = shz_index_append(z, idx, bnum);
    if (err == SHERR_NOBUFS) {
      /* create a new page */
      l_seq = seq;
      shz_crc_set(z, (shz_hdr_t *)idx);
      seq = 0; 
    } else if (err) {
      return (err);
    }

    of += w_len;
  }

  if (ret_idx_p) {
    *ret_idx_p = ret_idx;
  }

  return (0);
}

int shz_index_write(shz_t *z, shz_write_f f, shbuf_t *buff, shz_idx *ret_idx_p)
{
  shz_idx ret_idx;
  int err;

  ret_idx = 0;
  err = shz_index_add(z, f, buff, &ret_idx);
  if (err)
    return (err);

  if (ret_idx_p)
    *ret_idx_p = ret_idx;

  return (0);
}

int shz_index_read(shz_t *z, shz_read_f f, shbuf_t *buff, shz_idx bnum)
{
  shz_idx *seg;
  shz_idx ref_bnum;
  shz_index_t *idx;
  size_t alloc_len;
  unsigned char *raw;
  int err;
  int i;

  while (bnum) {
    for (i = 0; i < SHZ_MAX_INDEX_SIZE; i++) {
      idx = (shz_index_t *)shz_page(z, bnum);
      if (!idx) return (SHERR_INVAL);
      raw = (unsigned char *)idx + sizeof(shz_index_t);
      seg = (shz_idx *)raw;
      ref_bnum = ntohl(seg[i]);
      if (!ref_bnum)
        break;

      alloc_len = (ref_bnum * SHZ_PAGE_SIZE) + SHZ_PAGE_SIZE;
      err = shz_alloc(z, alloc_len);
      if (err)
        return (err);

      err = (*f)(z, ref_bnum, buff);
      if (err)
        return (err);
    }

    /* iterate to next index page in chain */
    idx = (shz_index_t *)shz_page(z, bnum);
    if (!idx) return (SHERR_INVAL);
    bnum = ntohl(idx->seq);
  }

  return (0);
}

ssize_t shz_zlib_write(shz_t *z, shz_idx *z_bnum_p, unsigned char *data, size_t data_len)
{
  shz_mod_t *blk;
  shz_mod_t *l_blk;
  shbuf_t *buff;
  shkey_t z_key;
  shkey_t *key;
  shz_idx f_bnum;
  shz_idx z_bnum;
  shz_idx l_bnum;
  unsigned char *z_data;
  uint64_t z_id;
  ssize_t ret_len;
  size_t z_len;
  size_t len;
  size_t of;
  int tr_bnum;
  int hnum;
  int step;
  int err;

  data_len = MIN(1048576, data_len); /* one meg segs */

  /* check whether data segment is already stored */
  z_bnum = 0;

  buff = shbuf_init();
  err = shzenc(buff, data, data_len);
  if (err)
    return (err);

  f_bnum = 0;

  z_data = (unsigned char *)shbuf_data(buff);
  z_len = shbuf_size(buff);

  ret_len = 0;
  l_bnum = 0;
  step = SHZ_PAGE_SIZE - sizeof(shz_mod_t);

  of = 0;
  while (of < z_len) {
    len = MIN(step, (z_len - of));

    blk = (shz_mod_t *)shz_page_new(z, SHZ_PAGE_ZLIB_DATA, &z_bnum);
    if (!blk) return (SHERR_IO);

    if (!f_bnum)
      f_bnum = z_bnum;

    if (l_bnum) {
      l_blk = (shz_mod_t *)shz_page(z, l_bnum);
      if (l_blk) {
        l_blk->seq = htonl(z_bnum);
        shz_crc_set(z, (shz_hdr_t *)l_blk);
      }
    }

    blk = (shz_mod_t *)shz_page(z, z_bnum);
    if (!blk) return (SHERR_IO);

    err = shz_page_size_set((shz_hdr_t *)blk, sizeof(shz_mod_t) + len);
    if (err) {
      return (err);
}

    memcpy((unsigned char *)blk + sizeof(shz_mod_t), z_data + of, len);

    shz_crc_set(z, (shz_hdr_t *)blk);

    of += len;
    l_bnum = z_bnum;
  }

  shbuf_free(&buff);

  key = shkey_bin(data, data_len);
  err = shz_zlib_new(z, f_bnum, z_len, &z_bnum, key);
  shkey_free(&key);
  if (err)
    return (err);

  /* add to the 'archived data size' reported by archive. */
  shz_zsize_incr(z, data_len);

  if (z_bnum_p)
    *z_bnum_p = z_bnum;

  return (data_len);
}

int shz_zlib_read(shz_t *z, int page_bnum, shbuf_t *dec_buff)
{
  shz_mod_t *blk;
  shz_mod_t *page;
  shbuf_t *buff;
  unsigned char *enc_data;
  ssize_t ret_len;
  size_t max;
  int bnum;
  int err;

  blk = (shz_mod_t *)shz_page(z, page_bnum);
  if (!blk)
    return (SHERR_IO);

  if (shz_page_type((shz_hdr_t *)blk) != SHZ_PAGE_ZLIB)
    return (SHERR_IO);

  max = ntohl(blk->size);
  bnum = ntohl(blk->seq);

  buff = shbuf_init();
  page = (shz_mod_t *)shz_page(z, bnum);
  while (page) {
    size_t page_size = shz_page_size((shz_hdr_t *)page);

    if (page_size < sizeof(shz_mod_t) || 
        page_size > SHZ_PAGE_SIZE)
      return (SHERR_IO);

    shbuf_cat(buff, 
        (unsigned char *)page + sizeof(shz_mod_t), 
        page_size - sizeof(shz_mod_t));

    /* next page */
    bnum = ntohl(page->seq);
    if (!bnum) break;
    page = (shz_mod_t *)shz_page(z, bnum);
  }

  err = shzdec(dec_buff, shbuf_data(buff), shbuf_size(buff));
  shbuf_free(&buff);
  if (err)
    return (err);

  return (0);
}













int shz_filename(shz_t *z, shz_idx mod_bnum, char *filename, size_t max_len)
{
  shz_mod_t *mod;
  shbuf_t *buff;
  int err;

  mod = (shz_mod_t *)shz_page(z, mod_bnum);
  if (!mod)
    return (SHERR_INVAL);

  filename[0] = '\000';

  buff = shbuf_init();
  err = shz_raw_read(z, ntohl(mod->name), buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }

  strncpy(filename, shbuf_data(buff), max_len);
  return (0);
}

int shz_mod_write(shz_t *z, shz_idx mod_bnum, shbuf_t *buff)
{
  shz_mod_t *mod;
  shz_idx bnum;
  int err;
  
  if (z->flags & SHZ_RAW) {
    err = shz_index_write(z, SHZ_WRITE_F(shz_raw_write), buff, &bnum);
  } else {
    err = shz_index_write(z, SHZ_WRITE_F(shz_zlib_write), buff, &bnum);
  }
  if (err)
    return (err);

  mod = (shz_mod_t *)shz_page(z, mod_bnum);
  if (!mod)
    return (SHERR_IO);

  mod->seq = htonl(bnum);
  mod->size = htonl(shbuf_size(buff));
  mod->crc = shcrc32(shbuf_data(buff), shbuf_size(buff));
  mod->ctime = mod->mtime = shtime();

  shz_page_size_set((shz_hdr_t *)mod, sizeof(shz_mod_t));
  shz_crc_set(z, (shz_hdr_t *)mod); 

  return (0);
}

int shz_mod_read(shz_t *z, shz_mod_t *mod, shbuf_t *buff)
{
  size_t alloc_len;
  shz_idx bnum;
  int err;

  bnum = ntohl(mod->seq);

  alloc_len = (bnum * SHZ_PAGE_SIZE) + SHZ_PAGE_SIZE;
  err = shz_alloc(z, alloc_len);
  if (err)
    return (err);

  if (z->flags & SHZ_RAW) {
    err = shz_index_read(z, SHZ_READ_F(shz_raw_read), buff, bnum);
  } else {
    err = shz_index_read(z, SHZ_READ_F(shz_zlib_read), buff, bnum);
  }
  if (err)
    return (err);

/* .. verify size & crc */

  return (0);
}


int shz_entity_get(shz_t *z, shz_idx *fd_p, const char *filename, int page_type)
{
  shz_mod_t *file;
  shkey_t *key;
  shz_idx bidx;
  shz_idx name_bidx;
  int err;

  err = shz_ftable_get(z, filename, fd_p);
  if (!err) {
    if (fd_p)
      *fd_p = bidx;
    return (0);
  }

  file = (shz_mod_t *)shz_page_new(z, page_type, &bidx);
  if (!file) {
    return (SHERR_IO);
  }

  /* save the filename in the archive. */
  err = (int)shz_raw_write(z, &name_bidx, 
    (unsigned char *)filename, (size_t)strlen(filename));
  if (err < 0)
    return (err); /* note: truncates if filename is not written at once. */

  /* record the file in the file table */
  err = shz_ftable_set(z, filename, bidx);
  if (err)
    return (err);

  file = (shz_mod_t *)shz_page(z, bidx);

  /* set filename */
  file->name = htonl(name_bidx);

  /* set ID key */
  key = shkey_bin((char *)filename, strlen(filename));
  memcpy(&file->id, key, sizeof(file->id));
  shkey_free(&key);

  /* finalize checksum */
  shz_crc_set(z, (shz_hdr_t *)file);

  if (fd_p)
    *fd_p = bidx;

  return (0);
}

int shz_file_get(shz_t *z, shz_idx *fd_p, const char *filename)
{
  return (shz_entity_get(z, fd_p, filename, SHZ_PAGE_FILE));
}

int shz_dir_get(shz_t *z, shz_idx *fd_p, const char *dirname)
{
  return (shz_entity_get(z, fd_p, dirname, SHZ_PAGE_DIR));
}

int shz_file_append(shz_t *z, const char *filename, shbuf_t *buff)
{
  return (SHERR_OPNOTSUPP);
}

int shz_file_write(shz_t *z, const char *filename, shbuf_t *buff)
{
  shz_mod_t *file;
  ssize_t size;
  shz_idx bidx;
  shz_idx bnum;
  int err;

  err = shz_file_get(z, &bidx, filename);
  if (err)
    return (err);

  err = shz_mod_write(z, bidx, buff);
  if (err)
    return (err);

  return (0);
}

#if 0
/* note: 'shz' utility makes dirs as needed upon extract */
int shz_dir_add(shz_t *z, const char *dirname)
{
  shz_mod_t *mod;
  ssize_t size;
  shz_idx bidx;
  shz_idx bnum;
  int err;

  err = shz_dir_get(z, &bidx, dirname);
  if (err)
    return (err);

  mod = shz_page(z, bidx);
  if (err)
    return (SHERR_IO);

  mod->ctime = mod->mtime = shtime();
  shz_page_size_set((shz_hdr_t *)mod, sizeof(shz_mod_t));
  shz_crc_set(z, (shz_hdr_t *)mod);

  return (0);
}
#endif


int shz_file_read(shz_t *z, const char *filename, shbuf_t *buff)
{
  shz_mod_t *file;
  shkey_t *key;
  shz_idx d_num;
  shz_idx bidx;
  int err;

  key = shkey_bin((char *)filename, strlen(filename));
  err = shz_tree_get(z, z->ftable, key, &bidx);
  shkey_free(&key);
  if (err)
    return (err);

  file = (shz_mod_t *)shz_page(z, bidx);
  if (!file)
    return (SHERR_IO);

  d_num = ntohl(file->seq);
  err = shz_data_read(z, d_num, buff);
  if (err)
    return (err);

  if (ntohl(file->size) != shbuf_size(buff))
    return (SHERR_INVAL);

  if (shcrc32(shbuf_data(buff), shbuf_size(buff)) != file->crc)
    return (SHERR_ILSEQ); 

  return (0);
}

int shz_file_add(shz_t *z, const char *filename)
{
  shbuf_t *buff;
  int err;

/* parse path recursive.. */
/* add "SHZ_PAGE_DIR" before any sub-dir entries */

  buff = shbuf_init();
  err = shfs_mem_read((char *)filename, buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }

  if (!(z->flags & SHZ_ABSOLUTE)) {
    if (*filename == '/')
      filename++;
  }

  err = shz_file_write(z, filename, buff);
  if (err)
    return (err);

  shbuf_free(&buff);
  return (0);
}



int shz_list_write(shz_t *z, shz_idx f_idx, char *f_path, shbuf_t *buff, void *p)
{
  int err;

  /* write data content to the file */
  err = shfs_mem_write(f_path, buff);
  if (err)
    return (err);

  return (0);
}



static int shz_list_r(shz_t *z, shtree_t *node, char *rel_path, char *fspec, shz_list_f op, void *p)
{
  shz_tree_t *info;
  shbuf_t *buff;
  shz_map_t *map;
  shz_mod_t *mod;
  unsigned char *raw;
  char filename[PATH_MAX+1];
  char path[PATH_MAX+1];
  shz_idx *seg;
  shz_idx bnum;
  int hnum;
  int err;

  err = shz_map_load(z, node);
  if (err)
    return (err);

  if (shtree_left(node)) {
    err = shz_list_r(z, shtree_left(node), rel_path, fspec, op, p);
    if (err)
      return (err);
  }

  if (shtree_right(node)) {
    err = shz_list_r(z, shtree_right(node), rel_path, fspec, op, p);
    if (err)
      return (err);
  }


  for (hnum = 0; hnum < SHZ_HASH_MASK; hnum++) {
    info = shz_tree_data(z, node); 
    if (!info) return (SHERR_IO);

    map = (shz_map_t *)info->page;
    if (!map) return (SHERR_IO);

    raw = (unsigned char *)map + sizeof(shz_map_t);
    seg = (shz_idx *)raw;

    if (seg[hnum] == 0)
      continue;

    bnum = ntohl(seg[hnum]);

    memset(filename, 0, sizeof(filename));
    err = shz_filename(z, bnum, filename, sizeof(filename)-1);
    if (err) {
      return (err);
    }

    mod = (shz_mod_t *)shz_page(z, bnum);
    if (!mod) {
      return (SHERR_IO);
    }

    if (!*filename) {
//fprintf(stderr, "DEBUG: shz_list_r: !filename\n"); 
      continue; /* ?? */
}

    if (fspec) {
      /* compare against file spec filter */
      if (0 != fnmatch(fspec, filename, 
            FNM_NOESCAPE | FNM_PATHNAME
            )) {
        continue; /* not a match */
      }
    }

    /* read data content from archive */
    buff = shbuf_init(); /* handle as MAP_PRIVATE? */
    err = shz_mod_read(z, mod, buff);
    if (err) {
      shbuf_free(&buff);
      return (err);
    }

    mod = (shz_mod_t *)shz_page(z, bnum);
    if (!mod) {
      return (SHERR_IO);
    }

    if (ntohl(mod->size) != shbuf_size(buff)) {
      shbuf_free(&buff);
      return (SHERR_INVAL);
    }

    if (shcrc32(shbuf_data(buff), shbuf_size(buff)) != mod->crc) {
      shbuf_free(&buff);
      return (SHERR_ILSEQ); 
    }

    sprintf(path, "%s/%s", rel_path, filename);
    err = (*op)(z, bnum, path, buff, p); 
    shbuf_free(&buff);
    if (err)
      return (err);
  }

  return (0);
}


int shz_list(shz_t *z, char *rel_path, char *fspec, shz_list_f op, void *p)
{
  char pwd_path[PATH_MAX+1];

  memset(pwd_path, 0, sizeof(pwd_path));
  if (!rel_path) {
    getcwd(pwd_path, sizeof(pwd_path)-1);
  } else {
    strncpy(pwd_path, rel_path, sizeof(pwd_path)-1);
  }

  if (*pwd_path && pwd_path[strlen(pwd_path)-1] == '/')
    pwd_path[strlen(pwd_path)-1] = '\000';

  return (shz_list_r(z, z->ftable, pwd_path, fspec, op, p)); 
}

int shz_file_extract(shz_t *z, char *rel_path, char *fspec)
{
  return (shz_list(z, rel_path, fspec, shz_list_write, NULL));
}

int shz_extract(shz_t *z, char *fspec)
{
  return (shz_file_extract(z, NULL, fspec));
}























static const char *SHZ_TEST_TEXT =
  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris suscipit enim ac ornare malesuada. Proin et ipsum et ipsum malesuada tincidunt. Proin elit magna, aliquam et urna vel, viverra tincidunt mauris. In ullamcorper nisi vitae enim tincidunt fringilla. Proin viverra finibus neque, et ornare dui suscipit a. Morbi purus ipsum, pellentesque a felis quis, porta vestibulum nulla. Etiam feugiat lobortis consequat. In justo ligula, elementum a massa ac, fermentum malesuada nibh. In sed urna id arcu ornare elementum. Nunc ullamcorper tincidunt volutpat. Nullam mi est, aliquam vitae massa sed, gravida egestas est.\n";


_TEST(shz_zlib_write)
{
  shz_t z;
  shbuf_t *z_buff;
  shz_idx ret_idx;
  shbuf_t *cmp_buff;
  shbuf_t *buff;
  int err;

  z_buff = shbuf_init();
  err = shz_arch_init(&z, z_buff, 0);
  _TRUE(err == 0);



  buff = shbuf_init();
  shbuf_cat(buff, SHZ_TEST_TEXT, strlen(SHZ_TEST_TEXT));
  err = shz_index_write(&z, SHZ_WRITE_F(shz_zlib_write), buff, &ret_idx);
  _TRUE(err == 0);

  cmp_buff = shbuf_init();
  err = shz_index_read(&z, SHZ_READ_F(shz_zlib_read), cmp_buff, ret_idx);
  _TRUE(err == 0);

  _TRUE( shbuf_cmp(buff, cmp_buff) );

  shbuf_free(&buff);
  shbuf_free(&cmp_buff);

  shz_arch_free(&z);
  shbuf_free(&z_buff);

}




