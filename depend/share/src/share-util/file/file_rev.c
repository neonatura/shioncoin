
/*
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
 */  

#include "sharetool.h"

int share_file_revision_status(revop_t *r, shfs_ino_t *file, int pflags)
{
  shbuf_t *buff;
  int err;

  buff = shbuf_init();
  err = shfs_rev_delta(file, buff); 
  if (err)
    return (err);

  if (shbuf_size(buff) == 0)
    return (0);

  /* print contents of file with header */
  fprintf(sharetool_fout, "\t%s\n", shfs_filename(file));

  return (0);
}

int share_file_revision_revert(revop_t *r, shfs_ino_t *file, int pflags)
{
  shfs_ino_t *rev;
  int err;

  if (shfs_type(file) != SHINODE_FILE)
    return (SHERR_INVAL); 

  if (!(shfs_attr(file) & SHATTR_VER))
    return (SHERR_INVAL); 

  rev = shfs_rev_base(file);
  if (!rev)
    return (SHERR_IO);

  err = shfs_rev_revert(file);
  if (err)
    return (err);

  /* print contents of file with header */
  fprintf(sharetool_fout, "switched %s: ref 'BASE' (%s)\n",
      shfs_filename(file), shfs_filename(rev));

  return (0);
}

/**
 * Checkout a branch by name.
 */
int share_file_revision_switch(revop_t *r, char *ref_name, shfs_ino_t *file, int pflags)
{
  shfs_ino_t *rev;
  int err;

  err = shfs_rev_switch(file, ref_name, &rev);
  if (err)
    return (err);
  
  /* print contents of file with header */
  fprintf(sharetool_fout, "switched %s: ref '%s' (%s)\n",
      shfs_filename(file), ref_name?ref_name:"master", shfs_filename(rev));

  return (0);
}

int share_file_revision_checkout(revop_t *r, shfs_ino_t *file, shkey_t *key, int pflags)
{
  shfs_ino_t *rev;
  shbuf_t *head_buff;
  int err;

  if (!key) {
    err = shfs_rev_switch(file, NULL, &rev);
  } else {
    err = shfs_rev_checkout(file, key, &rev);
  }
  if (err)
    return (err);

  /* print contents of file with header */
  fprintf(sharetool_fout, "switched %s: %s\n",
      shfs_filename(file), shfs_filename(rev));

  return (0);
}

int share_file_revision_cat(revop_t *r, shfs_ino_t *file, shkey_t *key, int pflags)
{
  shfs_ino_t *rev;
  shbuf_t *buff;
  int err;

  buff = shbuf_init();
  err = shfs_rev_cat(file, key, buff, &rev);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }
  
  /* print contents of file with header */
  fprintf(sharetool_fout, "index %s (%s)\n",
      shfs_filename(file), shfs_filename(rev));
  fwrite(shbuf_data(buff), sizeof(char), shbuf_size(buff), sharetool_fout);

  shbuf_free(&buff);
  return (0);
}

int share_file_revision_branch(revop_t *r, char *name, shfs_ino_t *file, int pflags)
{
  shfs_ino_t *repo;
  shfs_ino_t *base;
  shfs_ino_t *branch;
  int err;

  /* obtain current revision */
  repo = shfs_inode(file, NULL, SHINODE_REPOSITORY);
  base = shfs_rev_base(file);
  if (!base)
    return (SHERR_IO);

  err = shfs_rev_branch(file, name, base);
  if (err)
    return (err);

  fprintf(sharetool_fout, "%s: ref '%s' (%s)\n", 
      shfs_filename(file), name, shfs_filename(base));

  return (0);
}

int share_file_revision_tag(revop_t *r, char *name, shfs_ino_t *file, int pflags)
{
  shfs_ino_t *base;
  int err;

  /* obtain current revision */
  base = shfs_rev_base(file);
  if (!base)
    return (SHERR_IO);

  err = shfs_rev_tag(file, name, base);
  if (err)
    return (err);

  fprintf(sharetool_fout, "%s: ref '%s' (%s)\n", 
    shfs_filename(file), name, shfs_filename(base));

  return (0);
}

int share_file_revision_print(revop_t *r, shfs_ino_t *rev)
{
  char rev_name[MAX_SHARE_NAME_LENGTH];
  char rev_email[MAX_SHARE_NAME_LENGTH];
  char *desc;

  /* hash signature of commit revision. */
  fprintf(sharetool_fout, "commit %s\n", shfs_filename(rev));

  /* repository credentials. */
  strncpy(rev_name, shfs_meta_get(rev, "user.name"), sizeof(rev_name) - 1);
  strncpy(rev_email, shfs_meta_get(rev, "user.email"), sizeof(rev_email) - 1);
  if (*rev_name || *rev_email)
    fprintf(sharetool_fout, "Author: %s <%s>\n", rev_name, rev_email);

  /* revision commit time-stamp */
  fprintf(sharetool_fout, "Date: %20.20s\n", shctime(rev->blk.hdr.ctime)+4);

  /* a checksum to verify integrity */
  fprintf(sharetool_fout, "Checksum: %s\n", shcrcstr(rev->blk.hdr.crc));

  desc = shfs_rev_desc_get(rev);
  if (desc && *desc)
    fprintf(sharetool_fout, "\t%s\n", desc);

  fprintf(sharetool_fout, "\n");
}

int share_file_revision_log(revop_t *r, shfs_ino_t *file, shkey_t *key, int pflags)
{
  shfs_ino_t *repo;
  shfs_ino_t *rev;
  int err;

  repo = shfs_inode(file, NULL, SHINODE_REPOSITORY);
  if (!repo)
    return (SHERR_IO);

  if (key) {
    /* specific revision instance */
    rev = shfs_rev_get(repo, key);
    if (!rev)
      return (SHERR_NOENT);

    share_file_revision_print(r, rev);
    return (0);
  }

  /* entire file log */
  rev = shfs_rev_base(file);
  while (rev) {
    share_file_revision_print(r, rev);
    rev = shfs_rev_prev(rev);
  }

  return (0);
}

int share_file_revision_commit(revop_t *r, shfs_ino_t *file, int pflags)
{
  shfs_ino_t *rev;
  int err;

  err = shfs_rev_commit(file, &rev);
  if (err)
    return (err);

  fprintf(sharetool_fout, "\tcommit %s: ref 'BASE' (%s)\n", 
      shfs_filename(file), shfs_filename(rev));

  return (0);
}

int share_file_revision_diff(revop_t *r, shfs_ino_t *file, shkey_t *rev_key, int pflags)
{
  shbuf_t *buff;
  int err;

  buff = shbuf_init();
  err = shfs_rev_diff(file, rev_key, buff);
  if (!err) {
    fwrite(shbuf_data(buff), sizeof(char), 
        shbuf_size(buff), sharetool_fout); 
  }
  shbuf_free(&buff);

  return (err);
}

int share_file_revision_command(revop_t *r, char **args, int arg_cnt, int pflags)
{
#define MAX_FL_CNT 256
  shfs_ino_t **fl_spec;
  shfs_t **fl_fs;
  struct stat st;
  shfs_t *fs;
  shfs_ino_t *dir;
  shkey_t *s_hash;
  shkey_t *e_hash;
  shkey_t *key;
  char *ref_name;
  int fl_cnt;
  int err;
  int i;

  ref_name = NULL;
  if (r->cmd == REV_BRANCH || r->cmd == REV_TAG || r->cmd == REV_CHECKOUT) {
    ref_name = args[0]; 
    args++;
    arg_cnt--;
  }

  fl_spec = (shfs_ino_t **)calloc(arg_cnt+256, sizeof(shfs_ino_t *));
  fl_fs = (shfs_t **)calloc(arg_cnt+256, sizeof(shfs_t *));

  fl_cnt = 0;
  s_hash = NULL;
  e_hash = NULL;
  for (i = 0; i < arg_cnt && fl_cnt < (MAX_FL_CNT-1); i++) {
    if (args[i][0] == '@' && strlen(args[i]) == 49) {
      key = shkey_hexgen(args[i]);
      if (!shkey_cmp(key, ashkey_blank())) {
        if (!s_hash)
          s_hash = key;
        else
          e_hash = key;
        continue;
      }
      shkey_free(&key);
    }

    fl_fs[fl_cnt] = shfs_uri_init(args[i], 0, &fl_spec[fl_cnt]);
    fl_cnt++;
  }

  if (fl_cnt == 0) {
    DIR *dir;
    struct dirent *ent;
    char cwd[PATH_MAX+1];

    /* default to current directory. */
    memset(cwd, 0, sizeof(cwd));
    getcwd(cwd, sizeof(cwd) - 1);
    dir = opendir(cwd);
    if (dir) {
      while (ent = readdir(dir)) {
        if (0 == strcmp(ent->d_name, ".") ||
            0 == strcmp(ent->d_name, ".."))
          continue;

        fl_fs[fl_cnt] = shfs_uri_init(ent->d_name, 0, &fl_spec[fl_cnt]);
        fl_cnt++;

        if (fl_cnt >= 256)
          break;
      }
      closedir(dir);
    }
  }

  for (i = 0; i < fl_cnt; i++) {
    err = shfs_fstat(fl_spec[i], &st);
    if (err) {
      fprintf(stderr, "%s: cannot access %s: %s.\n", process_path, args[i], sherrstr(err)); 
      fl_spec[i] = NULL;
    }
  }

  dir = NULL;
  err = SHERR_OPNOTSUPP;
  switch (r->cmd) {
    case REV_ADD:
      for (i = 0; i < fl_cnt; i++) {
        if (!fl_spec[i])
          continue;

        if (shfs_attr(fl_spec[i]) & SHATTR_VER) {
          err = 0;
          continue; /* already set */
        }

        err = shfs_attr_set(fl_spec[i], SHATTR_VER);
        if (err) {
          fprintf(stderr, "%s: cannot add %s: %s.\n", process_path, args[i], sherrstr(err)); 
          break;
        }

        fprintf(sharetool_fout, "\tadded %s\n", shfs_filename(fl_spec[i]));
      }
      break;

    case REV_BRANCH:
      if (!ref_name) {
        /* list branches.. */
        break;
      }
      for (i = 0; i < fl_cnt; i++) {
        if (!fl_spec[i])
          continue;

        err = share_file_revision_branch(r, ref_name, fl_spec[i], pflags);
        if (err)
          break;
      }
      break;

    case REV_CAT:
      err = 0;
      for (i = 0; i < fl_cnt; i++) {
        if (!fl_spec[i])
          continue;

        err = share_file_revision_cat(r, fl_spec[i], s_hash, pflags);
        if (err)
          break;
      }
      break;

    case REV_CHECKOUT:
      for (i = 0; i < fl_cnt; i++) {
        if (!fl_spec[i])
          continue;

        err = share_file_revision_checkout(r, fl_spec[i], s_hash, pflags);
        if (err)
          break;
      }
      break;

    case REV_COMMIT:
      for (i = 0; i < fl_cnt; i++) {
        if (!fl_spec[i])
          continue;

        err = share_file_revision_commit(r, fl_spec[i], pflags);
        if (err)
          break;
      }
      break;

    case REV_DIFF:
      for (i = 0; i < fl_cnt; i++) {
        if (!fl_spec[i])
          continue;

        err = share_file_revision_diff(r, fl_spec[i], s_hash, pflags);
        if (err)
          break;
      }

      break;
    case REV_LOG:
      for (i = 0; i < fl_cnt; i++) {
        if (!fl_spec[i])
          continue;

        err = share_file_revision_log(r, fl_spec[i], s_hash, pflags);
        if (err)
          break;
      }
      break;

    case REV_REVERT:
      for (i = 0; i < fl_cnt; i++) {
        if (!fl_spec[i])
          continue;

        err = share_file_revision_revert(r, fl_spec[i], pflags);
        if (err)
          break;
      }
      break;

    case REV_STATUS:
      err = 0;
      for (i = 0; i < fl_cnt; i++) {
        if (!fl_spec[i])
          continue;

        err = share_file_revision_status(r, fl_spec[i], pflags);
        if (err)
          break;
      }
      break;

    case REV_SWITCH:
      for (i = 0; i < fl_cnt; i++) {
        if (!fl_spec[i])
          continue;

        err = share_file_revision_switch(r, ref_name, fl_spec[i], pflags);
        if (err)
          break;
      }
      break;

    case REV_TAG:
      if (!ref_name) {
        /* list tages.. */
        break;
      }
      for (i = 0; i < fl_cnt; i++) {
        if (!fl_spec[i])
          continue;

        err = share_file_revision_tag(r, ref_name, fl_spec[i], pflags);
        if (err)
          break;
      }
      break;
  }

  return (err);
}

int share_file_revision(char **args, int arg_cnt, int pflags)
{
  revop_t *r;
  int err_code;

  if (arg_cnt < 2)
    return (SHERR_INVAL);
  
  r = rev_init();
  rev_command_setstr(r, args[1]); 

  if (r->cmd == REV_NONE) {
    fprintf(stderr, "%s: unknown mode '%s'.\n", process_path, args[1]);
    return (SHERR_OPNOTSUPP);
  }

  args += 2;
  arg_cnt -= 2;

  err_code = share_file_revision_command(r, args, arg_cnt, pflags);

done:
  rev_free(&r);
  return (err_code);
}
