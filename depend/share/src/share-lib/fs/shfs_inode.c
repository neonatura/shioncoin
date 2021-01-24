
/*
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
*/  

#include "share.h"
#include <assert.h>

static void _shfs_inode_access_init(shfs_ino_t *parent, shfs_ino_t *ent)
{
  shkey_t *owner;

  /* inherit ownership */
  owner = shfs_access_owner_get(parent);
  if (!owner && parent->tree) {
    shkey_t *id_key;
    uint64_t uid;

    /* obtain default identity for current account. */
    uid = shpam_uid((char *)get_libshare_account_name());
    id_key = shpam_ident_gen(uid, &parent->tree->peer);
    shfs_access_owner_set(ent, id_key);
    shkey_free(&id_key);
  } else {
    shfs_access_owner_set(ent, owner);
  }

  /* apply access permissions */
  if (shfs_type(parent) == SHINODE_DIRECTORY) {
    if (parent) {
      if (shfs_attr(parent) & SHATTR_TEMP)
        shfs_attr_set(ent, SHATTR_TEMP);
      if (shfs_attr(parent) & SHATTR_SYNC)
        shfs_attr_set(ent, SHATTR_SYNC);
    } 

    if (shfs_attr(parent) & SHATTR_READ)
      shfs_attr_set(ent, SHATTR_READ);
    if (shfs_attr(parent) & SHATTR_WRITE)
      shfs_attr_set(ent, SHATTR_WRITE);
    if (shfs_attr(parent) & SHATTR_EXE)
      shfs_attr_set(ent, SHATTR_EXE);
  }
}

shfs_ino_t *shfs_inode(shfs_ino_t *parent, char *name, int mode)
{
  struct shfs_ino_t *ent = NULL;
  shfs_block_t blk;
  shkey_t ino_key;
  shkey_t *tkey;
  char path[SHFS_PATH_MAX];
  uint16_t salt;
  int err;

  memset(path, 0, sizeof(path));
  if (name)
    strncpy(path, name, sizeof(path) - 1);
  if (*path && path[strlen(path) - 1] == '/') {
    path[strlen(path) - 1] = '\0';
    if (!mode)
      mode = SHINODE_DIRECTORY;
  } else {
    if (!mode)
      mode = SHINODE_FILE;
  }

  /* generate inode token key */
	tkey = shfs_token_init(parent, mode, path);
	if (!tkey)
		return (NULL); /* invalid */

  /* check parent's cache */
  ent = shfs_cache_get(parent, tkey);
  if (ent) { 
		shkey_free(&tkey);
    return (ent);
  }

  /* find inode entry. */
  memset(&blk, 0, sizeof(blk));
  err = shfs_link_find(parent, tkey, &blk);
  if (err && err != SHERR_NOENT) {
		shkey_free(&tkey);
    PRINT_ERROR(err, "shfs_inode: shfs_link_find");
    return (NULL);
  }

  ent = (shfs_ino_t *)calloc(1, sizeof(shfs_ino_t));
  if (!ent) {
		shkey_free(&tkey);
    return (NULL);
	}

  if (!err) {
    memcpy(&ent->blk, &blk, sizeof(shfs_block_t));
  } else {
    ent->blk.hdr.type = mode;
    memcpy(&ent->blk.hdr.name, tkey, sizeof(shkey_t));

    if (IS_INODE_CONTAINER(mode))
      strcpy(ent->blk.raw, path);

    if (mode == SHINODE_DIRECTORY)
      ent->blk.hdr.format = mode;

    if (parent) { /* link inode to parent */
      err = shfs_link(parent, ent);
      if (err) {
				shkey_free(&tkey);
        PRINT_ERROR(err, "shfs_inode: shfs_inode_link");
        return (NULL);
      }

      _shfs_inode_access_init(parent, ent);
    }

    ent->blk.hdr.salt = (uint16_t)(shrand() % 65536);
  }
	shkey_free(&tkey);

  if (parent) {
    ent->parent = parent;
    ent->base = parent->base;
    ent->tree = parent->tree;
  } else {
    ent->base = ent;
  }

  ent->meta = NULL;
  ent->cache = shmap_init();

  shfs_cache_set(parent, ent);

  return (ent);
}

_TEST(shfs_inode)
{
  shfs_t *tree;
  shfs_ino_t *root;
  shfs_ino_t *dir;
  shfs_ino_t *file;
  shfs_ino_t *ref;

  _TRUEPTR(tree = shfs_init(NULL));

  /* verify partition's root. */
  _TRUE(tree->base_ino->blk.hdr.type == SHINODE_DIRECTORY);
  _TRUE(tree->base_ino->blk.hdr.pos.jno);
  _TRUE(tree->base_ino->blk.hdr.pos.ino);

  /* verify directory */
  _TRUEPTR(dir = shfs_inode(tree->base_ino, "shfs_inode", SHINODE_DIRECTORY));
  _TRUE(dir->blk.hdr.type == SHINODE_DIRECTORY);
  _TRUE(dir->blk.hdr.pos.jno);
  _TRUE(dir->blk.hdr.pos.ino);

  shfs_free(&tree);
}

shfs_ino_t *shfs_inode_load(shfs_ino_t *parent, shkey_t *key) 
{
  struct shfs_ino_t *ent = NULL;
  shfs_block_t blk;
  shkey_t ino_key;
  int err;

  /* check parent's cache */
  ent = shfs_cache_get(parent, key);
  if (ent) { 
    return (ent);
  }

  /* find inode entry. */
  memset(&blk, 0, sizeof(blk));
  err = shfs_link_find(parent, key, &blk);
  if (err) {
    PRINT_ERROR(err, "shfs_inode: shfs_link_find");
    return (NULL);
  }

  ent = (shfs_ino_t *)calloc(1, sizeof(shfs_ino_t));
  if (!ent)
    return (NULL);
  memcpy(&ent->blk, &blk, sizeof(shfs_block_t));

  /* link parent */
  ent->parent = parent;
  ent->base = parent->base;
  ent->tree = parent->tree;

  ent->meta = NULL;
  ent->cache = shmap_init();

  shfs_cache_set(parent, ent);

  return (ent);
}

shfs_t *shfs_inode_tree(shfs_ino_t *inode)
{
  if (!inode)
    return (NULL);
  return (inode->tree);
}

_TEST(shfs_inode_tree)
{
  shfs_t *tree;

  _TRUEPTR(tree = shfs_init(NULL));
  if (tree)
    _TRUEPTR(shfs_inode_tree(tree->base_ino));
  shfs_free(&tree);
}

shpeer_t *shfs_inode_peer(shfs_ino_t *inode)
{
  shfs_t *fs;

  fs = shfs_inode_tree(inode);
  if (!fs)
    return (NULL);

  return (shfs_peer(fs));
}

shfs_ino_t *shfs_inode_parent(shfs_ino_t *inode)
{
  if (!inode)
    return (NULL);
  return (inode->parent);
}

shfs_ino_t *shfs_inode_root(shfs_ino_t *inode)
{
  if (!inode)
    return (NULL);
  return (inode->base);
}

int shfs_inode_write_entity(shfs_ino_t *ent)
{
  return (shfs_inode_write_block(ent->tree, &ent->blk));
}

int shfs_inode_write_block(shfs_t *tree, shfs_block_t *blk)
{
  shfs_idx_t *pos = &blk->hdr.pos;
  shfs_journal_t *jrnl;
  shfs_block_t *jblk;
  char *seg;
  int err;

  if (!tree)
    return (-1);

  jrnl = shfs_journal_open(tree, (int)pos->jno);
  if (!jrnl) {
    return (SHERR_IO);
  }

  jblk = shfs_journal_block(jrnl, (int)pos->ino);
  if (!jblk) {
    return (SHERR_IO);
  }

/*
  blk->hdr.crc = shcrc(&blk->hdr.name, sizeof(shkey_t));
  blk->hdr.crc += shcrc((char *)blk->raw, SHFS_BLOCK_DATA_SIZE);
*/

  /* fill block */
  blk->hdr.mtime = shtime();
  memcpy(jblk, blk, sizeof(shfs_block_t));

  err = shfs_journal_close(&jrnl);
  if (err) {
    PRINT_RUSAGE("shfs_inode_write_block: error closing journal.");
    return (err);
  }

  return (0);
}

int shfs_inode_clear_block(shfs_t *tree, shfs_idx_t *pos)
{
  shfs_journal_t *jrnl;
  shfs_block_t *jblk;
  char *seg;
  int err;

  if (!tree)
    return (-1);

  jrnl = shfs_journal_open(tree, (int)pos->jno);
  if (!jrnl) {
    char ebuf[256];

    sprintf(ebuf, "shfs_inode_clear_block: error opening journal #%u.", (unsigned int)pos->jno);
    PRINT_RUSAGE(ebuf);
    return (SHERR_IO);
  }

  jblk = shfs_journal_block(jrnl, (int)pos->ino);
  if (!jblk) {
    PRINT_RUSAGE("shfs_inode_clear_block: error referencing block.");
    return (SHERR_IO);
  }

  /* clear block */
  memset(jblk, 0, sizeof(shfs_block_t));

  err = shfs_journal_close(&jrnl);
  if (err) {
    PRINT_RUSAGE("shfs_inode_clear_block: error closing journal.");
    return (err);
  }

  return (0);
}


int shfs_inode_read_block(shfs_t *tree, shfs_idx_t *pos, shfs_block_t *ret_blk)
{
  shfs_journal_t *jrnl;
  shfs_block_t *jblk;
  int err;

  jrnl = shfs_journal_open(tree, (int)pos->jno);
  if (!jrnl) {
    PRINT_ERROR(SHERR_IO, "shfs_inode_read_block [shfs_journal_open]");
    return (SHERR_IO);
  }

  jblk = shfs_journal_block(jrnl, (int)pos->ino);
  if (!jblk) {
    PRINT_ERROR(SHERR_IO, "shfs_inode_read_block [shfs_journal_block]");
    return (SHERR_IO);
  }

  if (ret_blk)
    memcpy(ret_blk, jblk, sizeof(shfs_block_t));

  err = shfs_journal_close(&jrnl);
  if (err) {
    PRINT_ERROR(err, "shfs_inode_read_block [shfs_journal_close]");
    return (err);
  }

  return (0);
}


void shfs_inode_free(shfs_ino_t **inode_p)
{
  shfs_ino_t *c_inode;
  shfs_ino_t *inode;
  void **inode_list;
  int i;
int tot;

  if (!inode_p)
    return;
  
  inode = *inode_p;
  if (!inode)
    return;

#if 0
  if (inode->tree) {
    if (inode->tree->base_ino == inode || inode->tree->cur_ino == inode)
      return; /* required for additional reference. */
  }
#endif

  *inode_p = NULL;

tot = 0;
  inode_list = shmap_get_ptr_list(inode->cache);
  if (inode_list) {
    for (i = 0; inode_list[i]; i++) {
      c_inode = (shfs_ino_t *)inode_list[i]; 
      shfs_inode_free(&c_inode);
tot++;
    }
    free(inode_list);
  }

  if (inode->parent && inode->parent->cache)
    shmap_unset(inode->parent->cache, &inode->blk.hdr.name);

  shfs_inode_cache_free(inode);

  shmap_free(&inode->meta);

  /* de-allocate inode structure */
  free(inode);
}

_TEST(shfs_inode_free)
{
  shfs_t *tree;
  shfs_ino_t *file;

  _TRUEPTR(tree = shfs_init(NULL));
  if (!tree)
     return;

  /* ensure we cannot free root node of partition. */
#if 0
  shfs_inode_free(&tree->base_ino);
  _TRUEPTR(tree->base_ino);
#endif

  /* ensure we can free newly created file. */
  _TRUEPTR(file = shfs_inode(tree->base_ino, "shfs_inode_free", SHINODE_FILE));
  if (file) {
    shfs_inode_free(&file);
    _TRUE(!file);
  }

  shfs_free(&tree);
}

char *shfs_inode_path(shfs_ino_t *inode)
{
  static char path[PATH_MAX+1];
  char buf[PATH_MAX+1];
  shfs_ino_t *node;

  memset(path, 0, sizeof(path));
  for (node = inode; node; node = node->parent) {
    char *fname = node->blk.raw;
    if (!fname)
      continue;
    strcpy(buf, path);

    strcpy(path, fname);
    if (*buf) {
      strncat(path, "/", PATH_MAX - strlen(path));
      strncat(path, buf, PATH_MAX - strlen(path));
    }
  }
  if (shfs_type(inode) == SHINODE_DIRECTORY) {
    strcat(path, "/");
  }

  return (path);
}

void shfs_filename_set(shfs_ino_t *inode, char *name)
{
  static char fname[SHFS_MAX_BLOCK_SIZE];
  shkey_t *key;

  if (!inode)
    return;

  if (!IS_INODE_CONTAINER(inode->blk.hdr.type)) {
    shfs_meta_set(inode, SHMETA_DESC, name);
    return;
  }


  if (!name || !name[0]) {
    return;
  }

  memset(fname, 0, sizeof(fname));
  strncpy(fname, name, SHFS_PATH_MAX);
  if (strlen(name) > SHFS_PATH_MAX) {
    // suffix identifier to track all size names
    strcat(fname, "$");
    strcat(fname, shkey_print(ashkey_str(name)));
  }

  strcpy(inode->blk.raw, fname);

}

char *shfs_filename(shfs_ino_t *inode)
{

  if (!inode)
    return ("");

  if (!IS_INODE_CONTAINER(inode->blk.hdr.type))
    return ((char *)shkey_print(&inode->blk.hdr.name));

  return (inode->blk.raw);
}


/**
 * Evolve a token key to denote particular shfs inode mode and path.
 * @returns An allocated key (use shkey_free).
 */
shkey_t *shfs_token_init(shfs_ino_t *parent, int mode, char *fname)
{
  char buf[5120];
  size_t buf_len;
  shkey_t *key;
	int alg;

  buf_len = 0;
  memset(buf, 0, sizeof(buf));

//	alg = parent ? parent->blk.hdr.name.alg : SHALG_SHR224;
	alg = parent ? parent->blk.hdr.name.alg : 0;

	if (!SHALG(alg, SHALG_SHR224)) {
		/* inode parent token */
		if (parent) {
			memcpy(buf, &parent->blk.hdr.name, sizeof(shkey_t));
			buf_len += sizeof(shkey_t);
		}
	}
 
  /* inode mode */
  memcpy(buf + buf_len, &mode, sizeof(mode));
  buf_len += sizeof(mode);

  if (fname) {
    size_t fname_len = MIN(SHFS_PATH_MAX + 1, strlen(fname) + 1);
    strncpy(buf + buf_len, fname, fname_len);
    buf_len += fname_len;
  }

  if (parent) {
    memcpy(buf + buf_len, &parent->blk.hdr.salt, sizeof(parent->blk.hdr.salt));
    buf_len += sizeof(parent->blk.hdr.salt);
  }

  /* create unique key token. */
	key = shkey(alg, buf, buf_len);
	if (parent && SHALG(alg, SHALG_SHR224)) {
		shkey_t *tkey = shkey_xor(key, &parent->blk.hdr.name);
		shkey_free(&key);
		key = tkey;
	}

  return (key);
}


_TEST(shfs_token_init)
{
  shfs_ino_t fake_parent;
  shkey_t *key[256];
  char buf[4096];
  shkey_t *ukey;
  int i, j;
  shfs_t *tree;
  shkey_t *tok_key;

  /* (1) ensure root partition inode key-name does not equal a blank child. */
  tree = shfs_init(NULL);
  _TRUEPTR(tree);
  tok_key = shfs_token_init(tree->base_ino, 0, NULL);
  _TRUE(0 != memcmp(tok_key, &tree->base_ino->blk.hdr.name, sizeof(shkey_t)));
	shkey_free(&tok_key);
  shfs_free(&tree);

  /* (2) ensure similar filenames of same parent generate unique key-names. */
  memset(&fake_parent, 0, sizeof(fake_parent));
  memcpy(&fake_parent.blk.hdr.name, ashkey_uniq(), sizeof(shkey_t));
  memset(buf, 0, sizeof(buf));
  buf[0] = 'a';
  for (i = 0; i < 256; i++) {
    buf[1] = i;
    key[i] = shfs_token_init(&fake_parent, 0, buf);
  }
  for (i = 0; i < 256; i++) {
    _TRUE(!shkey_cmp(key[i], ashkey_blank()));
    for (j = 0; j < 256; j++) {
      if (i == j) continue;
      _TRUE(!shkey_cmp(key[i], key[j]));
    } 
  }
  for (i = 0; i < 256; i++) {
    shkey_free(&key[i]);
  }

}

char *shfs_inode_id(shfs_ino_t *inode)
{
  return ((char *)shkey_print(&inode->blk.hdr.name));
}

char *shfs_inode_print(shfs_ino_t *inode)
{
  return (shfs_inode_block_print(&inode->blk));
}


/**
 * Removes children inodes.
 * @param The inode to clear.
 * @note Does not remove grandchildren, etc. Only 'clears' inode.  
 */
int shfs_inode_clear(shfs_ino_t *inode)
{
  shfs_block_t blk;
  shfs_block_t nblk;
  shfs_idx_t *idx;
  shkey_t *key;
  size_t b_len;
  size_t b_of;
  int err;
  int jno;

  if (!inode)
    return (0);

  b_of = 0;
  idx = &inode->blk.hdr.fpos;
  memcpy(&blk, &inode->blk, sizeof(blk));
  while (idx->ino) {
    /* wipe current position */
    err = shfs_inode_clear_block(inode->tree, idx);
    if (err)
      return (err);

    /* read in next block. */
    idx = &blk.hdr.npos;
    memset(&nblk, 0, sizeof(nblk));
    if (idx->ino) {
      err = shfs_inode_read_block(inode->tree, idx, &nblk);
      if (err)
        return (err);
    }

    memcpy(&blk, &nblk, sizeof(shfs_block_t));
  }

  /* write the inode to the parent directory */
  inode->blk.hdr.ctime = 0;
  inode->blk.hdr.mtime = 0;
  inode->blk.hdr.size = 0;
  // inode->blk.hdr.type = 0;
  inode->blk.hdr.format = 0;
  // inode->blk.hdr.attr = 0;
  memset(&inode->blk.hdr.fpos, 0, sizeof(shfs_idx_t));
//  memset(&inode->blk.hdr.npos, 0, sizeof(shfs_idx_t));
  inode->blk.hdr.crc = 0;
  err = shfs_inode_write_entity(inode);
  if (err) {
    PRINT_RUSAGE("shfs_inode_write: error writing entity.");
    return (err);
  }

  return (0);
}

int shfs_inode_truncate(shfs_ino_t *inode, shsize_t ino_len)
{
  shfs_block_t blk;
  shfs_block_t nblk;
  shfs_idx_t idx;
  shkey_t *key;
  uint64_t seg_crc;
  size_t blk_len;
  size_t b_len;
  size_t b_of;
  int err;
  int jno;

  if (!inode)
    return (0); /* nothing to do */

  if (shfs_type(inode) != SHINODE_BINARY) /* only inode currently supported */
    return (SHERR_INVAL);

  if (shfs_size(inode) == ino_len)
    return (0); /* all done */

  if (shfs_size(inode) > ino_len) {
    seg_crc = 0;

    b_of = 0;
    memcpy(&idx, &inode->blk.hdr.fpos, sizeof(shfs_idx_t));
    while (idx.ino) {
      memset(&blk, 0, sizeof(blk));
      err = shfs_inode_read_block(inode->tree, &idx, &blk);
      if (err)
        return (err);

      blk_len = blk.hdr.size;
      if (b_of >= ino_len) { 
        /* after specified length - wipe current position */
        err = shfs_inode_clear_block(inode->tree, &idx);
        if (err)
          return (err);
      } else if ((b_of + blk.hdr.size) >= ino_len) {
        /* partially truncate current block. */
        b_len = MIN(SHFS_BLOCK_DATA_SIZE, ino_len - b_of); /* jic */
        blk.hdr.size = b_len;

        if (blk.hdr.size != SHFS_BLOCK_DATA_SIZE)
          memset(blk.raw + blk.hdr.size, '\000',
              SHFS_BLOCK_DATA_SIZE - blk.hdr.size); 

        /* compute new checksum */
        blk.hdr.crc = shfs_crc_init(&blk);

        /* store update */
        err = shfs_inode_write_block(inode->tree, &blk);
        if (err)
          return (err);
      }
      b_of += blk_len;

      seg_crc += blk.hdr.crc;

      /* read in next block. */
      memcpy(&idx, &blk.hdr.npos, sizeof(shfs_idx_t));
    }

    /* set after any potential errors may occur during I/O */
    inode->blk.hdr.crc = seg_crc;
  }

  /* update attributes */
  inode->blk.hdr.mtime = shtime();
  inode->blk.hdr.size = ino_len;

  /* write the inode to the parent directory */
  err = shfs_inode_write_entity(inode);
  if (err) {
    PRINT_RUSAGE("shfs_inode_write: error writing entity.");
    return (err);
  }

  return (0);
}

char *shfs_inode_size_str(shsize_t size)
{
  static char ret_str[256];
  double val;
  char *prefix;

  if (size > 1000000000000) {
    prefix = "T";
    val = (double)size / 1000000000000;
  } else if (size > 1000000000) {
    prefix = "G";
    val = (double)size / 1000000000;
  } else if (size > 1000000) {
    prefix = "M";
    val = (double)size / 1000000;
  } else if (size > 1000) {
    prefix = "K";
    val = (double)size / 1000;
  } else {
    prefix = "";
    val = (double)size;
  }  
 
  if (*prefix)
    sprintf(ret_str, "%-2.2f%s", val, prefix);
  else
    sprintf(ret_str, "%llu", (uint64_t)val);
  return (ret_str);
}

char *shfs_inode_block_print(shfs_block_t *jblk)
{
  static char ret_buf[4096];

  memset(ret_buf, 0, sizeof(ret_buf));

  if (!jblk)
    return (ret_buf);

#if 0
  /* print file inode position. */
  sprintf(ret_buf + strlen(ret_buf), " %-4.4x:%-4.4x", 
      jblk->hdr.pos.jno, jblk->hdr.pos.ino);
#endif
  /* print file checksum. */
  sprintf(ret_buf + strlen(ret_buf), " {%11.11s}", shcrcstr(jblk->hdr.crc));
  sprintf(ret_buf + strlen(ret_buf), " %c%8s",
      shfs_type_char(shfs_block_type(jblk)),
      shfs_attr_str(jblk->hdr.attr));
  sprintf(ret_buf+strlen(ret_buf), " %7s", shfs_inode_size_str(jblk->hdr.size));
  sprintf(ret_buf + strlen(ret_buf), " %14.14s",
      shstrtime(jblk->hdr.mtime, NULL));
  if (IS_INODE_CONTAINER(jblk->hdr.type)) {
    sprintf(ret_buf + strlen(ret_buf), " %s", jblk->raw);
  }

  return (ret_buf);
}

uint64_t shfs_crc_init(shfs_block_t *blk)
{
  uint64_t crc;

  crc = 0;

  if (IS_INODE_CONTAINER(blk->hdr.type)) {
    crc += shcrc(&blk->hdr.name, sizeof(shkey_t));
  } else {
    if (blk->hdr.size) {
      crc += shcrc(&blk->hdr.name, sizeof(shkey_t));
      crc += shcrc((char *)blk->raw,
          MIN(SHFS_BLOCK_DATA_SIZE, blk->hdr.size));
    }
  }

  return (crc);
}

uint64_t shfs_crc(shfs_ino_t *file)
{
  
  if (!file)
    return (0);

  return (file->blk.hdr.crc);
}

_TEST(shfs_crc)
{
  shfs_t *fs;
  SHFL *file;

  fs = shfs_init(NULL);
  file = shfs_file_find(fs, "/test/shfs_crc");
  _TRUE(shfs_crc(file));
  shfs_free(&fs);

}





int shfs_block_type(shfs_block_t *blk)
{

  if (!blk)
    return (SHINODE_NULL);

  return (blk->hdr.type);
}

int shfs_type(shfs_ino_t *inode)
{

  if (!inode)
    return (SHINODE_NULL);

  return (shfs_block_type(&inode->blk));
}

int shfs_block_format(shfs_block_t *blk)
{

  if (!blk)
    return (SHINODE_NULL);

  return (blk->hdr.format);
}

int shfs_format(shfs_ino_t *inode)
{

  if (!inode)
    return (SHINODE_NULL);

  return (shfs_block_format(&inode->blk));
}


char *shfs_type_str(int type)
{
  static char ret_buf[1024];

  memset(ret_buf, 0, sizeof(ret_buf));

  switch (type) {
    case SHINODE_PARTITION:
      strcpy(ret_buf, "FS");
      break;
    case SHINODE_FILE:
      strcpy(ret_buf, "File");
      break;
    case SHINODE_DIRECTORY:
      strcpy(ret_buf, "Dir");
      break;
    case SHINODE_BINARY:
      strcpy(ret_buf, "Bin");
      break;
    case SHINODE_AUX:
      strcpy(ret_buf, "Aux");
      break;
    case SHINODE_COMPRESS:
      strcpy(ret_buf, "ZX"); 
      break;
    case SHINODE_CRYPT:
      strcpy(ret_buf, "Enc");
      break;
    case SHINODE_DATABASE:
      strcpy(ret_buf, "DB"); 
      break;
    case SHINODE_ACCESS:
      strcpy(ret_buf, "Access");
      break;
    case SHINODE_FILE_LOCK:
      strcpy(ret_buf, "Lock");
      break;
    case SHINODE_LICENSE:
      strcpy(ret_buf, "Cert");
      break;
    case SHINODE_EXTERNAL:
      strcpy(ret_buf, "Ext");
      break;
    case SHINODE_REPOSITORY:
      strcpy(ret_buf, "Repo");
      break;
    case SHINODE_REVISION:
      strcpy(ret_buf, "Ver");
      break;
    case SHINODE_DELTA:
      strcpy(ret_buf, "Delta");
      break;
    case SHINODE_OBJECT:
      strcpy(ret_buf, "Obj");
      break;
    case SHINODE_OBJECT_KEY:
      strcpy(ret_buf, "Key");
      break;
    case SHINODE_META:
      strcpy(ret_buf, "Meta");
      break;
    case SHINODE_APP:
      strcpy(ret_buf, "App");
      break;
    case SHINODE_TEST:
      strcpy(ret_buf, "Test");
      break;
    case SHINODE_REFERENCE:
      strcpy(ret_buf, "Ref");
      break;
    case SHINODE_DEVICE:
      strcpy(ret_buf, "Dev");
      break;
    default:
      sprintf(ret_buf, "Unknown(%d)", type); 
      break;
  }

  return (ret_buf);
}

char shfs_type_char(int type)
{
  char *str = shfs_type_str(type);
  return (tolower(str[0]));
}

char *shfs_format_str(int format)
{
  return (shfs_type_str(format));
}

int shfs_format_set(shfs_ino_t *file, int format)
{
  shbuf_t *buff;
  shfs_ino_t *inode;
  int orig_format;
  int err;

  if (!IS_INODE_CONTAINER(format)) {
    return (SHERR_INVAL);
  }
  if (format == SHINODE_DIRECTORY)
    return (SHERR_INVAL);

  orig_format = shfs_format(file);
  if (format == orig_format)
    return (0); /* done */

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err) {
//    if (err != SHERR_NOENT || format != SHINODE_DATABASE) {
      return (err);
//    }
  }

  /* clear previous format */
  inode = shfs_inode(file, NULL, orig_format);
  shfs_inode_clear(inode);

  /* create new format */
  switch (format) {
    case SHINODE_COMPRESS:
      err = shfs_zlib_write(file, buff);
      break;
    default:
      err = shfs_bin_write(file, buff);
      break;
  }
  shbuf_free(&buff);

  return (err);
}

int shfs_block_stat(shfs_block_t *blk, shstat *st)
{

  if (!blk)
    return (0);

  st->st_ino = (uint32_t)blk->hdr.pos.ino;
  st->st_dev = (uint32_t)blk->hdr.pos.jno;

  if (shfs_block_type(blk) == SHINODE_FILE)
    st->st_mode = S_IFREG;
  else if (shfs_block_type(blk) == SHINODE_DIRECTORY)
    st->st_mode = S_IFDIR;
  else
    st->st_mode = 0;

  st->st_size = (off_t)blk->hdr.size;
  st->st_blksize = (blksize_t)SHFS_BLOCK_DATA_SIZE;
  st->st_blocks = (blkcnt_t)(blk->hdr.size / SHFS_BLOCK_DATA_SIZE) + 1;
  st->crc = blk->hdr.crc;

  st->uid = shkey_crc(&blk->hdr.owner);

  st->ctime = blk->hdr.ctime;
  st->mtime = blk->hdr.mtime;

  return (0);
}

int shfs_fstat(shfs_ino_t *file, shstat *st)
{

  if (!file)
    return (SHERR_INVAL);

  if (shfs_format(file) == SHINODE_NULL) {
    return (SHERR_NOENT); /* no data content */
  }

  if (!st) {
    return (0);
  }

  return (shfs_block_stat(&file->blk, st));
}

int shfs_stat(shfs_t *fs, const char *path, shstat *st)
{
  shfs_ino_t *file;

  file = shfs_file_find(fs, (char *)path);
  return (shfs_fstat(file, st));
}

/**
 * Obtain a unique key reference for an inode.
 * @returns a non-allocated key referencing the inode.
 * @note A file key is not modifiable.
 */
shkey_t *shfs_token(shfs_ino_t *inode)
{

  if (!inode)
    return (NULL);
  return (&inode->blk.hdr.name);
}

shsize_t shfs_size(shfs_ino_t *inode)
{
  
  if (!inode)
    return ((shsize_t)0);

  return (inode->blk.hdr.size);
}

int shfs_inode_remove(shfs_ino_t *file)
{
  switch (shfs_format(file)) {
    case SHINODE_DIRECTORY:
      return (shfs_dir_remove(file));
    case SHINODE_FILE:
      return (shfs_file_remove(file));
  }

  return (0);
}

int shfs_unlink(shfs_t *fs, char *path)
{
  shfs_ino_t *file;

  file = shfs_file_find(fs, path);
  if (!file)
    return (SHERR_IO);
  
  return (shfs_inode_remove(file));
}

shtime_t shfs_ctime(shfs_ino_t *ino)
{
  if (!ino)
    return (0);
  return (ino->blk.hdr.ctime);
}
shtime_t shfs_mtime(shfs_ino_t *ino)
{
  if (!ino)
    return (0);
  return (ino->blk.hdr.mtime);
}
