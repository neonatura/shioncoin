
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
#include "sharetool.h"


#if 0
int share_file_stat_recursive(SHFL *dest_file, char *fname, int *total_p)
{
  shfs_dirent_t *ents;
  shfs_t *fs;
  SHFL **files;
  SHFL *dir;
  struct stat st;
  char spec_prefix[SHFS_PATH_MAX];
  char spec_dir[SHFS_PATH_MAX];
  char spec_fname[SHFS_PATH_MAX];
  char path[SHFS_PATH_MAX];
  char work_path[SHFS_PATH_MAX];
char *list_fname;
char buf[4096];
  char *ptr;
  int ent_nr;
  int err;
  int i;

  memset(spec_prefix, 0, sizeof(spec_prefix));

  ptr = strstr(fname, ":/");
  if (ptr) {
    ptr += 2;
    strncpy(spec_prefix, fname, MIN(sizeof(spec_prefix)-1, (ptr-fname)));
    fname += strlen(spec_prefix);
  }

  if (!strchr(fname, '/') || 0 == strncmp(fname, "./", 2)) {
    if (0 == strncmp(fname, "./", 2)) 
      fname += 2;

    strcpy(spec_prefix, "file:/");
    getcwd(buf, sizeof(buf)-1);
    strcat(buf, "/");
    strcat(buf, fname);
    ptr = strrchr(buf, '/');
    strncpy(spec_dir, buf + 1, strlen(buf) - strlen(ptr));
    sprintf(spec_fname, "%s%s", spec_dir, ptr+1);

    list_fname = basename(spec_fname);
  } else {
    memset(spec_fname, 0, sizeof(spec_fname));
    strncpy(spec_fname, fname, sizeof(spec_fname)-1);
    list_fname = basename(spec_fname);

    memset(spec_dir, 0, sizeof(spec_dir));
    strncpy(spec_dir, fname, MIN(strlen(fname) - strlen(list_fname), sizeof(spec_dir)-1));
  }



fprintf(stderr, "DEBUG: spec_prefix(%s) spec_dir(%s) spec_fname(%s)\n", spec_prefix, spec_dir, spec_fname);


  sprintf(path, "%s%s", spec_prefix, spec_dir); 
  fs = shfs_uri_init(path, 0, &dir);
fprintf(stderr, "DEBUG: shfs_uri_init(%s)\n", path);

  if (!*list_fname) {
    /* directory reference. */
    ent_nr = 1;
  } else {
    /* search files in directory */
    err = 0;
    ent_nr = shfs_list(dir, list_fname, &ents);
    if (ent_nr <= 0) {
fprintf(stderr, "DEBUG: share_file_stat_recursive: shfs_list('%s'): ent_nr = %d\n", list_fname, ent_nr);
      return (ent_nr);
}

    err = SHERR_NOENT;
    files = (SHFL **)calloc(ent_nr+1, sizeof(SHFL *)); 
    if (!files) return (SHERR_NOMEM);
    for (i = 0; i < ent_nr; i++) {
      ptr = strstr(spec_dir, ":/");
      if (ptr) {
        sprintf(path, "%s%s", ptr+2, ents[i].d_name);
      } else {
        sprintf(path, "%s%s", spec_dir, ents[i].d_name);
      }
      err = shfs_stat(fs, path, &st);
      if (err) { 
fprintf(stderr, "DEBUG: share_file_stat_recursive: %d = shfs_stat('%s')\n", err, path);
        break;
}
    }
    shfs_list_free(&ents);
    if (err) {
      return (err);
    }
  }

  *total_p = ent_nr;

  shfs_free(&fs);

  return (0);
}
#endif
int share_file_stat_recursive(SHFL *dest_file, char *fname, int *total_p)
{
  shfs_dirent_t *ents;
  shfs_t *fs;
  SHFL **files;
  SHFL *dir;
  struct stat st;
  char spec_prefix[SHFS_PATH_MAX];
  char spec_dir[SHFS_PATH_MAX];
  char spec_fname[SHFS_PATH_MAX];
  char path[SHFS_PATH_MAX];
  char work_path[SHFS_PATH_MAX];
char *list_fname;
char buf[4096];
  char *ptr;
  int ent_nr;
  int err;
  int i;

  memset(spec_prefix, 0, sizeof(spec_prefix));

  ptr = strstr(fname, ":/");
  if (ptr) {
    ptr += 2;
    strncpy(spec_prefix, fname, MIN(sizeof(spec_prefix)-1, (ptr-fname)));
    fname += strlen(spec_prefix);
  }

  if (!strchr(fname, '/') || 0 == strncmp(fname, "./", 2)) {
    if (0 == strncmp(fname, "./", 2)) 
      fname += 2;

    strcpy(spec_prefix, "file:/");
    getcwd(buf, sizeof(buf)-1);
    strcat(buf, "/");
    strcat(buf, fname);
    ptr = strrchr(buf, '/');
    strncpy(spec_dir, buf + 1, strlen(buf) - strlen(ptr));
    sprintf(spec_fname, "%s%s", spec_dir, ptr+1);

    list_fname = basename(spec_fname);
  } else {
    memset(spec_fname, 0, sizeof(spec_fname));
    strncpy(spec_fname, fname, sizeof(spec_fname)-1);
    list_fname = basename(spec_fname);

    memset(spec_dir, 0, sizeof(spec_dir));
    strncpy(spec_dir, fname, MIN(strlen(fname) - strlen(list_fname), sizeof(spec_dir)-1));
  }



  sprintf(path, "%s%s", spec_prefix, spec_dir); 
  fs = shfs_uri_init(path, 0, &dir);

  if (!*list_fname) {
    /* directory reference. */
    ent_nr = 1;
  } else {
    ent_nr = shfs_list_cb(dir, list_fname, NULL, NULL); 
  }

  *total_p += ent_nr;

  shfs_free(&fs);

  return (0);
}

#if 0
int share_file_copy_recursive(SHFL *dest_file, char *fname)
{
  shfs_dirent_t *ents;
  shfs_t *fs;
  SHFL **files;
  SHFL *dir;
  struct stat st;
  char spec_prefix[SHFS_PATH_MAX];
  char spec_dir[SHFS_PATH_MAX];
  char spec_fname[SHFS_PATH_MAX];
  char path[SHFS_PATH_MAX];
  char work_path[SHFS_PATH_MAX];
  char buf[4096];
char *list_fname;
  char *ptr;
  int ent_nr;
  int err;
  int i;

  memset(spec_prefix, 0, sizeof(spec_prefix));
  ptr = strstr(fname, ":/");
  if (ptr) {
    ptr += 2;
    strncpy(spec_prefix, fname, MIN(sizeof(spec_prefix)-1, (ptr-fname)));
    fname += strlen(spec_prefix);
  }

  if (!strchr(fname, '/') || 0 == strncmp(fname, "./", 2)) {
    if (0 == strncmp(fname, "./", 2)) 
      fname += 2;

    strcpy(spec_prefix, "file:/");
    getcwd(buf, sizeof(buf)-1);
    strcat(buf, "/");
    strcat(buf, fname);
    ptr = strrchr(buf, '/');
    strncpy(spec_dir, buf + 1, strlen(buf) - strlen(ptr));
    sprintf(spec_fname, "%s%s", spec_dir, ptr+1);

    list_fname = basename(spec_fname);
  } else {
    memset(spec_fname, 0, sizeof(spec_fname));
    strncpy(spec_fname, fname, sizeof(spec_fname)-1);
    list_fname = basename(spec_fname);

    memset(spec_dir, 0, sizeof(spec_dir));
    strncpy(spec_dir, fname, MIN(strlen(fname) - strlen(list_fname), sizeof(spec_dir)-1));
  }

  sprintf(path, "%s%s", spec_prefix, spec_dir); 
fprintf(stderr, "DEBUG: file_recursive: shfs_uri_init(%s)\n", path);
  fs = shfs_uri_init(path, 0, &dir);

  if (!*list_fname) {
    /* directory reference. */
    ent_nr = 1;
    files = (SHFL **)calloc(ent_nr+1, sizeof(SHFL *)); 
    if (!files) return (SHERR_NOMEM);
    files[0] = dir;
  } else {
    /* search files in directory */
    err = 0;
    ent_nr = shfs_list(dir, list_fname, &ents);
    if (ent_nr <= 0)
      return (ent_nr);

    err = SHERR_NOENT;
    files = (SHFL **)calloc(ent_nr+1, sizeof(SHFL *)); 
    if (!files) return (SHERR_NOMEM);
    for (i = 0; i < ent_nr; i++) {
      ptr = strstr(spec_dir, ":/");
      if (ptr) {
        sprintf(path, "%s%s", ptr+2, ents[i].d_name);
      } else {
        sprintf(path, "%s%s", spec_dir, ents[i].d_name);
      }
      err = shfs_stat(fs, path, &st);
      if (err)
        break;

      files[i] = shfs_file_find(fs, path);
    }
    shfs_list_free(&ents);
    if (err) {
      free(files);
      return (err);
    }
  }

#if 0
  /* handle recursive hierarchy */
  if ((run_flags & PFLAG_RECURSIVE)) {
    for (i = 0; i < ent_nr; i++) {
      if (shfs_type(files[i]) != SHINODE_DIRECTORY)
        continue;

      /* .. */
    }
  }
#endif
    
  for (i = 0; i < ent_nr; i++) {
    /* perform file copy */
    err = shfs_file_copy(files[i], dest_file);
    if (err) {
      fprintf(sharetool_fout, "%s: error copying \"%s\" to \"%s\": %s [sherr %d].\n",
          process_path, shfs_filename(files[i]), shfs_filename(dest_file),
          sherrstr(err), err);
      return (err);
    }

    if (!(run_flags & PFLAG_QUIET) && (run_flags & PFLAG_VERBOSE)) {
      fprintf(sharetool_fout, "%s: %s \"%s\" copied to %s \"%s\".\n",
        process_path,
        shfs_type_str(shfs_type(files[i])), shfs_filename(files[i]), 
        shfs_type_str(shfs_type(dest_file)), shfs_filename(dest_file)); 
    }
  }

  free(files);
  shfs_free(&fs);

  return (0);
}
#endif
int share_file_copy_cb(SHFL *src_file, SHFL *dest_file)
{
  shpeer_t *src_peer = shfs_inode_peer(src_file);
  int err;

  if (0 == strcmp(src_peer->label, "file")) {
    char path[PATH_MAX+1];

    /* set link to local-disk path. */
    sprintf(path, "%s", shfs_inode_path(src_file));
    err = shfs_ext_set(src_file, path);
    if (err)
      return (err);
  }

  /* perform file copy */
  err = shfs_file_copy(src_file, dest_file);
  if (err) {
    fprintf(sharetool_fout, "%s: error copying \"%s\" to \"%s\": %s [sherr %d].\n",
        process_path, shfs_filename(src_file), shfs_filename(dest_file),
        sherrstr(err), err);
    return (err);
  }

  if (!(run_flags & PFLAG_QUIET) && (run_flags & PFLAG_VERBOSE)) {
    fprintf(sharetool_fout, "%s: %s \"%s\" copied to %s \"%s\".\n",
        process_path,
        shfs_type_str(shfs_type(src_file)), shfs_filename(src_file),
        shfs_type_str(shfs_type(dest_file)), shfs_filename(dest_file)); 
  }

  return (0);
}
int share_file_copy_recursive(SHFL *dest_file, char *fname)
{
  shfs_dirent_t *ents;
  shfs_t *fs;
  SHFL **files;
  SHFL *dir;
  struct stat st;
  char spec_prefix[SHFS_PATH_MAX];
  char spec_dir[SHFS_PATH_MAX];
  char spec_fname[SHFS_PATH_MAX];
  char path[SHFS_PATH_MAX];
  char work_path[SHFS_PATH_MAX];
  char buf[4096];
char *list_fname;
  char *ptr;
  int ent_nr;
  int err;
  int i;

  memset(spec_prefix, 0, sizeof(spec_prefix));
  ptr = strstr(fname, ":/");
  if (ptr) {
    ptr += 2;
    strncpy(spec_prefix, fname, MIN(sizeof(spec_prefix)-1, (ptr-fname)));
    fname += strlen(spec_prefix);
  }

  if (!strchr(fname, '/') || 0 == strncmp(fname, "./", 2)) {
    if (0 == strncmp(fname, "./", 2)) 
      fname += 2;

    strcpy(spec_prefix, "file:/");
    getcwd(buf, sizeof(buf)-1);
    strcat(buf, "/");
    strcat(buf, fname);
    ptr = strrchr(buf, '/');
    strncpy(spec_dir, buf + 1, strlen(buf) - strlen(ptr));
    sprintf(spec_fname, "%s%s", spec_dir, ptr+1);

    list_fname = basename(spec_fname);
  } else {
    memset(spec_fname, 0, sizeof(spec_fname));
    strncpy(spec_fname, fname, sizeof(spec_fname)-1);
    list_fname = basename(spec_fname);

    memset(spec_dir, 0, sizeof(spec_dir));
    strncpy(spec_dir, fname, MIN(strlen(fname) - strlen(list_fname), sizeof(spec_dir)-1));
  }

  sprintf(path, "%s%s", spec_prefix, spec_dir); 
  fs = shfs_uri_init(path, 0, &dir);

  if (!*list_fname) {
    /* directory reference. */
    share_file_copy_cb(dir, dest_file);
  } else {
    /* search files in directory */
    err = shfs_list_cb(dir, list_fname, share_file_copy_cb, dest_file);
    if (err < 0)
      return (err);
  }

  shfs_free(&fs);

  return (0);
}

int share_file_copy(char **args, int arg_cnt, int pflags)
{
  shfs_t *dest_fs;
  shfs_t *src_fs;
  shfs_ino_t *dest_file;
  shfs_ino_t *src_file;
  shbuf_t *buff;
  char fpath[PATH_MAX+1];
  unsigned char *data;
  size_t data_len;
  size_t of;
  int total;
  int src_cnt;
  int w_len;
  int err;
  int i;

  if (arg_cnt < 2)
    return (SHERR_INVAL);

  arg_cnt--;
  dest_fs = shfs_uri_init(args[arg_cnt], O_CREAT, &dest_file);
  if (!dest_fs)
    return (SHERR_IO);

  total = 0;
  for (i = 1; i < arg_cnt; i++) {
    err = share_file_stat_recursive(dest_file, args[i], &total);
    if (err)
      break;
  }
  if (err) {
    shfs_free(&dest_fs);
    return (err);
  }

  if (total == 0) {
    /* no matches */
    shfs_free(&dest_fs);
    return (SHERR_INVAL);
  }
  if (total > 1 &&
      shfs_type(dest_file) != SHINODE_DIRECTORY) {
    /* cannot copy multiple files to a single file */
    shfs_free(&dest_fs);
    return (SHERR_NOTDIR);
  }

err = 0;
  for (i = 1; i < arg_cnt; i++) {
    err = share_file_copy_recursive(dest_file, args[i]);
    if (err)
      break;
  }
  if (err) {
    shfs_free(&dest_fs);
    return (err);
  }

  shfs_free(&dest_fs);
  return (0);
}

#if 0
int share_file_copy(char **args, int arg_cnt, int pflags)
{
  struct stat st;
  shfs_t *dest_fs;
  shfs_t **src_fs;
  shfs_ino_t *dest_file;
  shfs_ino_t **src_file;
  shbuf_t *buff;
  char fpath[PATH_MAX+1];
  unsigned char *data;
  size_t data_len;
  size_t of;
  int src_cnt;
  int w_len;
  int err;
  int i;

  if (arg_cnt < 1)
    return (SHERR_INVAL);

  src_file = NULL;
  src_fs = NULL;

  arg_cnt--;
  src_cnt = 0;
  if (!arg_cnt) {
    /* create faux substitute. */
/*DEBUG: */return (SHERR_INVAL);
  } else {
    dest_file = sharetool_file(args[arg_cnt], &dest_fs);

    src_file = (shfs_ino_t **)calloc(arg_cnt + 1, sizeof(shfs_ino_t *));
    src_fs = (shfs_t **)calloc(arg_cnt + 1, sizeof(shfs_t *));

    for (i = 1; i < arg_cnt; i++) {
      src_file[src_cnt] = sharetool_file(args[i], &src_fs[src_cnt]);
      err = shfs_fstat(src_file[src_cnt], &st);
      src_cnt++;
      if (err)
        goto done;
    }
  }

  for (i = 0; i < src_cnt; i++) {
    shfs_t *s_fs = src_fs[i];
    err = shfs_file_copy(src_file[i], dest_file);
    shfs_free(&s_fs);
    if (err)
      goto done;
  }

  err = 0;
done:
  if (src_file) free(src_file);
  if (src_fs) free(src_fs);

  return (err);
}
#endif

