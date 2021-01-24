
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

#define OBJGROUP_TAG "tag"
#define OBJGROUP_BRANCH "head"

shfs_ino_t *shfs_rev_get(shfs_ino_t *repo, shkey_t *rev_key)
{
  shfs_ino_t *rev;

  if (shfs_type(repo) == SHINODE_FILE)
    repo = shfs_inode(repo, NULL, SHINODE_REPOSITORY);
  if (shfs_type(repo) != SHINODE_REPOSITORY)
    return (NULL);

  if (shkey_cmp(rev_key, ashkey_blank()))
    return (NULL);

  return (shfs_inode(repo, (char *)shkey_hex(rev_key), SHINODE_REVISION));
}

_TEST(shfs_rev_get)
{
  shfs_t *fs;
  shfs_ino_t *file;
  shfs_ino_t *repo;
  shfs_ino_t *rev;
  shpeer_t *peer;
  shkey_t *rev_key;
  shkey_t *key[16];
  shbuf_t *buff;
  int i;

  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);

  file = shfs_file_find(fs, "/shfs_rev_get");
  buff = shbuf_init();
  shbuf_cat(buff, "aaaa", 4);
  _TRUE(0 == shfs_write(file, buff));
  shbuf_free(&buff);

  _TRUE(0 == shfs_attr_set(file, SHATTR_VER));
  _TRUEPTR((repo = shfs_inode(file, NULL, SHINODE_REPOSITORY)));

  for (i = 0; i < 16; i++) {
    key[i] = shkey_uniq();
  }
  for (i = 0; i < 16; i++) {
    _TRUEPTR(shfs_inode(repo, (char *)shkey_hex(key[i]), SHINODE_REVISION));
  }
  for (i = 0; i < 16; i++) {
    _TRUEPTR((rev = shfs_rev_get(repo, key[i])));
    rev_key = shkey_hexgen(shfs_filename(rev));
    _TRUE(shkey_cmp(rev_key, key[i]));
    shkey_free(&rev_key);
  }
  for (i = 0; i < 16; i++) {
    shkey_free(&key[i]);
  }

  shfs_free(&fs);
}

/** reference a revision by name */
int shfs_rev_ref(shfs_ino_t *file, char *group, char *name, shfs_ino_t *rev)
{
  shfs_ino_t *branch;
  shfs_ino_t *ref;
  shkey_t *ref_key;
  char buf[SHFS_PATH_MAX];
  int err;

  if (!rev) {
    return (SHERR_INVAL);
  }

  if (shfs_type(rev) != SHINODE_REVISION)
    return (SHERR_INVAL);

  ref_key = shkey_hexgen(shfs_filename(rev));
  if (!ref_key)
    return (SHERR_IO);

  if (shkey_cmp(ref_key, ashkey_blank())) {
    /* not a revision (filename has no hex key) */
    shkey_free(&ref_key);
    return (SHERR_INVAL);
  }

  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf)-1, "%s/%s", group, name);
  err = shfs_obj_set(file, buf, ref_key);
  shkey_free(&ref_key);
  if (err)
    return (err);

  return (0);
}

shfs_ino_t *shfs_rev_ref_resolve(shfs_ino_t *file, char *group, char *name)
{
  shfs_ino_t *branch;
  shfs_ino_t *repo;
  shfs_ino_t *ref;
  shkey_t *key;
  char buf[SHFS_PATH_MAX];
  int obj_type;
  int err;

  if (!file)
    return (NULL);

  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf)-1, "%s/%s", group, name);
  err = shfs_obj_get(file, buf, &key);
  if (err)
    return (NULL);

  repo = shfs_inode(file, NULL, SHINODE_REPOSITORY);
  branch = shfs_rev_get(repo, key);
  shkey_free(&key);

  return (branch);
}

_TEST(shfs_rev_ref_resolve)
{
  shfs_t *fs;
  shfs_ino_t *file;
  shfs_ino_t *repo;
  shfs_ino_t *ref_rev;
  shfs_ino_t *rev;
  shpeer_t *peer;
  shbuf_t *buff;
  shkey_t *key;
  char buf[256];

  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);

  file = shfs_file_find(fs, "/shfs_rev_ref");
  buff = shbuf_init();
  shbuf_cat(buff, "aaaa", 4);
  _TRUE(0 == shfs_write(file, buff));
  shbuf_free(&buff);

  _TRUE(0 == shfs_attr_set(file, SHATTR_VER));
  _TRUEPTR((repo = shfs_inode(file, NULL, SHINODE_REPOSITORY)));

  key = shkey_uniq();
  rev = shfs_inode(repo, (char *)shkey_hex(key), SHINODE_REVISION);
  _TRUEPTR(rev);
  _TRUE(0 == shfs_rev_ref(file, "test", "shfs_rev_ref_resolve", rev));
  ref_rev = shfs_rev_ref_resolve(file, "test", "shfs_rev_ref_resolve");
  _TRUEPTR(ref_rev);
  _TRUE(shkey_cmp(shfs_token(rev), shfs_token(ref_rev)));
  shkey_free(&key);

  shfs_free(&fs);
}


int shfs_rev_branch(shfs_ino_t *file, char *name, shfs_ino_t *rev)
{
  return (shfs_rev_ref(file, "head", name, rev));
}

shfs_ino_t *shfs_rev_branch_resolve(shfs_ino_t *file, char *name)
{
  return (shfs_rev_ref_resolve(file, "head", name));
}

int shfs_rev_tag(shfs_ino_t *file, char *name, shfs_ino_t *rev)
{
  return (shfs_rev_ref(file, "tag", name, rev));
} 

shfs_ino_t *shfs_rev_tag_resolve(shfs_ino_t *file, char *name)
{
  return (shfs_rev_ref_resolve(file, "tag", name));
}

int shfs_rev_ref_write(shfs_ino_t *file, char *group, char *name, shbuf_t *buff)
{
  shfs_ino_t *ref;
  shfs_ino_t *aux;
  char buf[SHFS_PATH_MAX];
  int err;

  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf) - 1, "%s/%s", group, name);
  ref = shfs_inode(file, buf, SHINODE_OBJECT);
  err = shfs_bin_write(ref, buff);
  if (err)
    return (err);
#if 0
  err = shfs_aux_write(aux, buff);
  if (err)
    return (err);
#endif

  err = shfs_inode_write_entity(ref);
  if (err) {
    sherr(err, "shfs_rev_ref_write [shfs_inode_write_entity]");
    return (err);
  }

#if 0
  /* copy aux stats to file inode. */
  file->blk.hdr.mtime = ref->blk.hdr.mtime;
  file->blk.hdr.size = ref->blk.hdr.size;
  file->blk.hdr.crc = ref->blk.hdr.crc;
  file->blk.hdr.format = SHINODE_OBJECT;
#endif

  return (0);
}

int shfs_rev_ref_read(shfs_ino_t *file, char *group, char *name, shbuf_t *buff)
{
  shfs_ino_t *ref;
  shfs_ino_t *aux;
  char buf[SHFS_PATH_MAX];
  int err;

  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf) - 1, "%s/%s", group, name);
  ref = shfs_inode(file, buf, SHINODE_OBJECT);
  err = shfs_bin_read(ref, buff);
  if (err)
    return (err);

#if 0
  aux = shfs_inode(ref, NULL, SHINODE_BINARY);
  err = shfs_aux_read(aux, buff);
  if (err)
    return (err);
#endif

  return (0);
}

_TEST(shfs_rev_ref_read)
{
  shfs_t *fs;
  shfs_ino_t *file;
  shpeer_t *peer;
  shbuf_t *buff;
  int err;

  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);

  file = shfs_file_find(fs, "/shfs_rev_ref_read");

  buff = shbuf_init();
  shbuf_cat(buff, "aaaa", 4);
  _TRUE(0 == shfs_rev_ref_write(file, "test", "shfs_rev_ref_read", buff));
  shbuf_clear(buff);
  _TRUE(0 == shfs_rev_ref_read(file, "test", "shfs_rev_ref_read", buff));
  _TRUEPTR(shbuf_data(buff));
  _TRUE(0 == strcmp(shbuf_data(buff), "aaaa"));
  shbuf_free(&buff);

  shfs_free(&fs);
}

int shfs_rev_init(shfs_ino_t *file)
{
  shfs_attr_t attr;
  shfs_ino_t *repo;
  shfs_ino_t *head;
  shfs_ino_t *rev;
  shfs_ino_t *tag;
  int err;

  if (shfs_type(file) != SHINODE_FILE)
    return (SHERR_OPNOTSUPP);

  attr = shfs_attr(file);
  if (attr & SHATTR_VER) {
    /* inode is already initialized for repository. */
    return (0);
  }

  /* commit current data content */
  err = shfs_rev_commit(file, &rev);
  if (err)
    return (err);

  /* set initial description */
  shfs_rev_desc_set(rev, "initial revision");

  /* create master branch */
  err = shfs_rev_branch(file, "master", rev);
  if (err)
    return (err);

  return (0);
}

int shfs_rev_clear(shfs_ino_t *file)
{
  shfs_ino_t *repo;

  /* obtain repository for inode. */
  repo = shfs_inode(file, NULL, SHINODE_REPOSITORY);

  /* clear contents of repository. */
  return (shfs_inode_clear(repo));
}

shfs_ino_t *shfs_rev_base(shfs_ino_t *file)
{
  return (shfs_rev_tag_resolve(file, "BASE"));
}
int shfs_rev_base_set(shfs_ino_t *file, shfs_ino_t *rev)
{
  if (!file)
    return (SHERR_INVAL);
  return (shfs_rev_tag(file, "BASE", rev)); 
}

const char *shfs_rev_desc_get(shfs_ino_t *rev)
{
  return (shfs_meta_get(rev, SHMETA_DESC));
}

void shfs_rev_desc_set(shfs_ino_t *rev, char *desc)
{
  shfs_meta_set(rev, SHMETA_DESC, desc);
}

int shfs_rev_delta_read(shfs_ino_t *rev, shbuf_t *buff)
{
  shfs_ino_t *aux;
  int err;

  aux = shfs_inode(rev, NULL, SHINODE_DELTA);
  if (!aux)
    return (SHERR_IO);

  err = shfs_aux_read(aux, buff);
  if (err)
    return (err);

  return (0);
}

int shfs_rev_delta_write(shfs_ino_t *rev, shbuf_t *buff)
{
  shfs_ino_t *aux;
  int err;

  aux = shfs_inode(rev, NULL, SHINODE_DELTA);
  if (!aux)
    return (SHERR_IO);

  err = shfs_aux_write(aux, buff);
  if (err)
    return (err);

  return (0);
}

shfs_ino_t *shfs_rev_prev(shfs_ino_t *rev)
{
  return (shfs_rev_tag_resolve(rev, "PREV"));
}

int shfs_rev_delta(shfs_ino_t *file, shbuf_t *diff_buff)
{
  shstat st;
  shbuf_t *work_buff;
  shbuf_t *head_buff;
  shbuf_t *ref_buff;
  shfs_t *fs;
  shkey_t *key;
  int err;

  if (shfs_type(file) != SHINODE_FILE)
    return (SHERR_INVAL);

  err = shfs_fstat(file, &st);
  if (err)
    return (err);

  work_buff = shbuf_init();
  err = shfs_read(file, work_buff);
  if (err) {
    shbuf_free(&work_buff);
    return (err);
  }

  /* obtain BASE branch snapshot */
  head_buff = shbuf_init();
  err = shfs_rev_ref_read(file, "tag", "BASE", head_buff);
  if (err)
    goto done;

  if (shbuf_size(work_buff) == shbuf_size(head_buff) &&
      0 == memcmp(shbuf_data(work_buff), shbuf_data(head_buff), shbuf_size(work_buff))) {
    /* no difference */
    err = SHERR_AGAIN;
    goto done;
  }

  err = shdelta(work_buff, head_buff, diff_buff); 

done:
  shbuf_free(&work_buff);
  shbuf_free(&head_buff);
  shbuf_free(&work_buff);

  return (err);
}

int shfs_rev_commit(shfs_ino_t *file, shfs_ino_t **rev_p)
{
  shstat st;
  shbuf_t *diff_buff;
  shbuf_t *work_buff;
  shbuf_t *head_buff;
  shfs_ino_t *base;
  shfs_ino_t *repo; /* SHINODE_REPOSITORY */
  shfs_ino_t *new_rev; /* SHINODE_REVISION */
  shfs_ino_t *delta; /* SHINODE_DELTA */
  shkey_t *rev_key;
  shfs_t *fs;
  int err;

  if (rev_p)
    *rev_p = NULL;

  head_buff = work_buff = diff_buff = NULL;

  err = shfs_fstat(file, &st);
  if (err)
    return (err);

  work_buff = shbuf_init();
  err = shfs_read(file, work_buff); 
  if (err)
    goto done;

  base = shfs_rev_base(file);
  if (base) {
    /* obtain delta of current file data content against BASE revision's data content. */
    head_buff = shbuf_init();
    err = shfs_rev_ref_read(file, "tag", "BASE", head_buff);
    if (err)
      goto done;

    if (shbuf_size(work_buff) == shbuf_size(head_buff) &&
        0 == memcmp(shbuf_data(work_buff), shbuf_data(head_buff), shbuf_size(work_buff))) {
      /* no difference */
      err = SHERR_AGAIN;
      goto done;
    }

    diff_buff = shbuf_init();
    err = shdelta(work_buff, head_buff, diff_buff); 
    shbuf_free(&head_buff);
    if (err)
      return (err);

    rev_key = shfs_token(base);
  } else {
    /* initial revision */
    rev_key = ashkey_uniq();
  }

  repo = shfs_inode(file, NULL, SHINODE_REPOSITORY);
  if (!repo) {
    err = SHERR_IO;
    goto done;
  }

  /* create a new revision using previous revision's inode name */
  new_rev = shfs_inode(repo, (char *)shkey_hex(rev_key), SHINODE_REVISION); 
  if (!new_rev) {
    err = SHERR_IO;
    goto done;
  }

  /* define revision's meta information. */
  shfs_meta_set(new_rev, 
      SHMETA_USER_NAME, (char *)get_libshare_account_name());

  /* save delta to new revision */
  err = shfs_rev_delta_write(new_rev, diff_buff);
  shbuf_free(&diff_buff);
  if (err)
    goto done;


  /* save new revision as BASE branch head */
  err = shfs_rev_base_set(file, new_rev);
  if (err)
    goto done;

  /* save work-data to BASE tag. */
  err = shfs_rev_ref_write(file, "tag", "BASE", work_buff); 
  shbuf_free(&work_buff);
  if (err)
    goto done;

  if (base) {
    /* tag previous revision's key token onto revision inode. */
    shfs_rev_tag(new_rev, "PREV", base);
  }

  if (rev_p)
    *rev_p = new_rev;

done:
  shbuf_free(&work_buff);
  shbuf_free(&diff_buff);
  shbuf_free(&head_buff);

  return (err);
}

int shfs_rev_cat(shfs_ino_t *file, shkey_t *rev_key, shbuf_t *buff, shfs_ino_t **rev_p)
{
  shfs_ino_t *repo;
  shfs_ino_t *rev;
  int err;

  /* obtain repository for inode. */
  repo = shfs_inode(file, NULL, SHINODE_REPOSITORY);
  if (!repo)
    return (SHERR_IO);

  if (!rev_key) {
    /* obtain current revision */
    rev = shfs_rev_base(file);
  } else {
    rev = shfs_rev_get(repo, rev_key);
  }
  if (!rev)
    return (SHERR_NOENT);

  err = shfs_rev_read(rev, buff);
  if (err)
    return (err);

  if (rev_p)
    *rev_p = rev;

  return (0);
}

/**
 * Generates the working-copy for a particular revision.
 */
int shfs_rev_read(shfs_ino_t *i_rev, shbuf_t *buff)
{
  shfs_ino_t *repo;
  shfs_ino_t *file;
  shfs_ino_t *rev;
  shbuf_t *delta_buff;
  shbuf_t *head_buff;
  shbuf_t *out_buff;
  int err;

  if (shfs_type(i_rev) != SHINODE_REVISION) {
    return (SHERR_INVAL);
  }

  repo = shfs_inode_parent(i_rev);
  if (!repo || shfs_type(repo) != SHINODE_REPOSITORY)
    return (SHERR_IO);

  file = shfs_inode_parent(repo);
  if (!file || shfs_type(file) != SHINODE_FILE)
    return (SHERR_IO);

  head_buff = shbuf_init();
  err = shfs_rev_ref_read(file, "tag", "BASE", head_buff);
  if (err)
    return (err);

  err = SHERR_NOENT; /* ret'd when no matching revision found */
  out_buff = shbuf_init();
  delta_buff = shbuf_init();

  /* search BASE chain for revision -- applying each revision's patch. */
  rev = shfs_rev_tag_resolve(file, "BASE");
  while (rev) {
    if (shkey_cmp(shfs_token(rev), shfs_token(i_rev))) {
      /* found revision in branch chain. */
      shbuf_append(head_buff, buff);
      err = 0;
      break;
    }

    shbuf_clear(delta_buff);
    err = shfs_rev_delta_read(rev, delta_buff);
    if (err)
      break;

/* DEBUG: TODO: merge together deltas to reduce performance over-head */
    shbuf_clear(out_buff);
    err = shpatch(head_buff, delta_buff, out_buff); 
    if (err)
      break;

    shbuf_clear(head_buff);
    shbuf_append(out_buff, head_buff);

    rev = shfs_rev_prev(rev);
  }

  shbuf_free(&head_buff);
  shbuf_free(&out_buff);
  shbuf_free(&delta_buff);
  return (err);
}

/** 
 * The non-supported operation of writing diretly to a SHINODE_REVISION inode.
 * @note use shfs_rev_commit() to write new revisions.
 */
int shfs_rev_write(shfs_ino_t *i_rev, shbuf_t *buff)
{
  return (SHERR_OPNOTSUPP);
}

int shfs_rev_revert(shfs_ino_t *file)
{
  shbuf_t *buff;
  int err;

  buff = shbuf_init();
  err = shfs_rev_ref_read(file, "tag", "BASE", buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }

  err = shfs_write(file, buff);
  shbuf_free(&buff);
  if (err)
    return (err);

  return (0);
}

/**
 * Switch to a pre-existing branch or tag.
 * @param ref_name The reference name or NULL for "master" branch.
 */ 
int shfs_rev_switch(shfs_ino_t *file, char *ref_name, shfs_ino_t **rev_p)
{
  shfs_ino_t *rev;
  int err;

 if (!ref_name)
    ref_name = "master";

  rev = shfs_rev_branch_resolve(file, ref_name);
  if (!rev)
    rev = shfs_rev_tag_resolve(file, ref_name);
  if (!rev)
    return (SHERR_NOENT);

  err = shfs_rev_base_set(file, rev);
  if (err)
    return (err);

  if (rev_p)
    *rev_p = rev;

  return (0);
}

int shfs_rev_checkout(shfs_ino_t *file, shkey_t *key, shfs_ino_t **rev_p)
{
  shfs_ino_t *repo;
  shfs_ino_t *rev;
  int err;

  if (!file || shfs_type(file) != SHINODE_FILE)
    return (SHERR_INVAL);

  repo = shfs_inode(file, NULL, SHINODE_REPOSITORY);
  rev = shfs_rev_get(repo, key);
  if (!rev)
    return (SHERR_NOENT);

  err = shfs_rev_base_set(file, rev);
  if (err)
    return (err);

  if (rev_p)
    *rev_p = rev;

  return (0);
}

_TEST(shfs_rev_checkout)
{
  shfs_t *fs;
  shfs_ino_t *file;
  shfs_ino_t *rev;
  shpeer_t *peer;
  shbuf_t *buff;

  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);

  file = shfs_file_find(fs, "/shfs_rev_checkout");
  buff = shbuf_init();
  shbuf_cat(buff, "aaaa", 4);
  _TRUE(0 == shfs_write(file, buff));
  _TRUE(0 == shfs_attr_set(file, SHATTR_VER));

  rev = shfs_rev_base(file);
  _TRUE(0 == shfs_rev_checkout(file, shfs_token(rev), NULL)); 

  shbuf_free(&buff);
  shfs_free(&fs);
}

int shfs_rev_diff(shfs_ino_t *file, shkey_t *rev_key, shbuf_t *buff)
{
  shbuf_t *work_buff;
  shbuf_t *head_buff;
  shfs_ino_t *new_rev;
  shfs_ino_t *delta;
  shfs_ino_t *rev;
  shfs_t *fs;
  int err;

  if (!file || shfs_type(file) != SHINODE_FILE)
    return (SHERR_INVAL);

  if (!buff)
    return (SHERR_INVAL);

  if (!rev_key) {
    /* obtain current committed revision. */
    rev = shfs_rev_base(file);
  } else {
    rev = shfs_rev_get(file, rev_key);
  }
  if (!rev)
    return (SHERR_NOENT);

 /* obtain work-data for BASE branch revision. */
  head_buff = shbuf_init();
  err = shfs_rev_ref_read(file, "tag", "BASE", head_buff);
  if (err) {
    shbuf_free(&head_buff);
    return (err);
  }

  work_buff = shbuf_init();
  err = shfs_read(file, work_buff);
  if (err) {
    shbuf_free(&head_buff);
    shbuf_free(&work_buff);
    return (err);
  }

  if (shbuf_size(work_buff) == shbuf_size(head_buff) &&
      0 == memcmp(shbuf_data(work_buff), 
        shbuf_data(head_buff), shbuf_size(work_buff))) {
    /* no difference to report */
    err = 0;
  } else {
    /* print textual difference to <buff> */
    err = shdiff(buff, shbuf_data(work_buff), shbuf_data(head_buff));
  }
  shbuf_free(&work_buff);
  shbuf_free(&head_buff);

  return (err);
}

_TEST(shfs_rev_diff)
{
  shfs_t *fs;
  shfs_ino_t *file;
  shfs_ino_t *rev;
  shpeer_t *peer;
  shbuf_t *buff;

  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);

  file = shfs_file_find(fs, "/shfs_rev_diff");
  buff = shbuf_init();
  shbuf_cat(buff, "aaaa", 4);
  _TRUE(0 == shfs_write(file, buff));

  _TRUE(0 == shfs_attr_set(file, SHATTR_VER));

  shbuf_cat(buff, "aaaa", 4);
  _TRUE(0 == shfs_write(file, buff));

  /* revert fresh change */
  _TRUE(0 == shfs_rev_revert(file));
  shbuf_clear(buff);
  _TRUE(0 == shfs_read(file, buff));
  _TRUEPTR(shbuf_data(buff));
  _TRUE(0 == strcmp(shbuf_data(buff), "aaaa")); 

  shbuf_free(&buff);
  shfs_free(&fs);
}

