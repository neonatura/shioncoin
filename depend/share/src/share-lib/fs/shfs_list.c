
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


#if 0
int shfs_list(shfs_ino_t *parent, shfs_dirent_t **dirent_p)
{
  shfs_block_t blk;
  shfs_hdr_t hdr;
  shfs_idx_t idx;
  shfs_dirent_t ent;
  shbuf_t *buff;
  size_t b_of;
  size_t b_max;
  char tbuf[64];
  int tot;
  int err;

  if (!parent) {
    return (SHERR_NOENT);
  }

  if (!IS_INODE_CONTAINER(parent->blk.hdr.type)) {
    PRINT_RUSAGE("shfs_inode_link_search: warning: non-container parent.");
    return (SHERR_INVAL);
  }

  buff = shbuf_init();
  tot = 0;

  /* find existing link */
  memcpy(&idx, &parent->blk.hdr.fpos, sizeof(shfs_idx_t));
  while (idx.ino) {
    memset(&blk, 0, sizeof(blk));
    err = shfs_inode_read_block(parent->tree, &idx, &blk);
    if (err) {
      shbuf_free(&buff);
      return (err);
    }

    if (blk.hdr.npos.jno == idx.jno && blk.hdr.npos.ino == idx.ino) {
      shbuf_free(&buff);
      return (SHERR_IO);
    }

    if (blk.hdr.type != SHINODE_NULL &&
        blk.hdr.format != SHINODE_NULL) {
      char path[SHFS_PATH_MAX];

      memset(path, 0, sizeof(path));
      strncpy(path, (char *)blk.raw, sizeof(path) - 1);
      if (blk.hdr.type == SHINODE_DIRECTORY)
        strcat(path, "/");

      memset(&ent, 0, sizeof(ent));
      strncpy(ent.d_name, path, sizeof(ent.d_name) - 1); 
      ent.d_crc = blk.hdr.crc;
      ent.d_type = blk.hdr.type;
      ent.d_format = blk.hdr.format;
      ent.d_attr = blk.hdr.attr;
      shfs_block_stat(&blk, &ent.d_stat);
      shbuf_cat(buff, &ent, sizeof(shfs_dirent_t));

      tot++;
    }

    memcpy(&idx, &blk.hdr.npos, sizeof(shfs_idx_t));
  }

  *dirent_p = shbuf_data(buff);
  free(buff);

  return (tot);
}
int shfs_list_fnmatch_native(shfs_ino_t *file, char *fspec, shfs_dirent_t **ent_p)
{
  DIR *dir;
  shfs_ino_t *inode;
  struct shfs_dirent_t *ents;
  struct dirent *ent;
  char dir_path[PATH_MAX+1];
  char path[PATH_MAX+1];
  int total;
  int err;
  int i, j;

  memset(dir_path, 0, sizeof(dir_path));
  strncpy(dir_path, shfs_inode_path(file), sizeof(dir_path)-1);

  dir = opendir(dir_path);
  if (!dir) {
    return (errno2sherr());
}

  while ((ent = readdir(dir))) {
    if (0 == strcmp(ent->d_name, ".") ||
        0 == strcmp(ent->d_name, ".."))
      continue; /* sys dir */

    if (0 == fnmatch(fspec, ent->d_name, 0)) {
      total++;
    }
  }
  closedir(dir);

  if (total == 0)
    return (SHERR_NOENT);

  ents = (shfs_dirent_t *)calloc(total + 1, sizeof(shfs_dirent_t));

  total = 0;
  dir = opendir(dir_path);
  while ((ent = readdir(dir))) {
    if (0 == strcmp(ent->d_name, ".") ||
        0 == strcmp(ent->d_name, ".."))
      continue; /* sys dir */

    if (0 != fnmatch(fspec, ent->d_name, 0))
      continue;


    inode = shfs_inode(file, ent->d_name, SHINODE_FILE);

   /* set link to local-disk path. */
    sprintf(path, "%s%s", dir_path, ent->d_name);
    err = shfs_ext_set(inode, path);
    if (err) {
      free(ents);
      return (err);
    }
    err = shfs_inode_write_entity(inode);
    if (err) {
      free(ents);
      return (err);
    }


    strncpy(ents[total].d_name,
        shfs_filename(inode), sizeof(ents[total].d_name)-1);
    shfs_fstat(inode, &ents[total].d_stat);
    ents[total].d_type = shfs_type(inode);
    ents[total].d_format = shfs_format(inode);
    ents[total].d_attr = shfs_attr(inode);
    total++;
  }
  closedir(dir);

  /* return matches */
  *ent_p = ents;
  return (total);
}
int shfs_list_fnmatch(shfs_ino_t *file, char *fspec, shfs_dirent_t **ent_p)
{
  struct shfs_dirent_t *ents;
  shpeer_t *fs_peer;
  int ent_tot;
  int tot;
  int err;
  int i, j;

  fs_peer = shfs_inode_peer(file);
  if (0 == strcmp(fs_peer->label, "file")) {
    return (shfs_list_fnmatch_native(file, fspec, ent_p));
  }

  ent_tot = shfs_list(file, &ents);
  if (ent_tot < 1)
    return (ent_tot);

  j = 0;
  for (i = 0; i < ent_tot; i++) {
    if (0 == fnmatch(fspec, ents[i].d_name, 0)) {
      memmove(&ents[j], &ents[i], sizeof(shfs_dirent_t));
      j++;
    }
  }

  if (j == 0) {
    free(ents);
    return (SHERR_NOENT); /* no matches found */
  }

  /* return matches */
  *ent_p = ents;
  return (j);
}
#endif





static int shfs_list_native(shfs_ino_t *file, char *fspec, shfs_list_f cb, void *arg)
{
  DIR *dir;
  struct stat st;
  shfs_ino_t *inode;
  struct dirent *ent;
  char dir_path[PATH_MAX+1];
  char fullpath[PATH_MAX+1];
  char path[PATH_MAX+1];
  int total;
  int type;
  int err;

  memset(dir_path, 0, sizeof(dir_path));
  strncpy(dir_path, shfs_inode_path(file), sizeof(dir_path)-1);

  dir = opendir(dir_path);
  if (!dir) {
    return (errno2sherr());
  }

  total = 0;
  while ((ent = readdir(dir))) {
    if (0 == strcmp(ent->d_name, ".") ||
        0 == strcmp(ent->d_name, ".."))
      continue; /* sys dir */

    if (!fspec || 0 == fnmatch(fspec, ent->d_name, 0)) {
      if (cb) {
        memset(path, 0, sizeof(path));
        strncpy(path, ent->d_name, sizeof(path)-1);

        sprintf(fullpath, "%s%s", dir_path, path);
        err = stat(fullpath, &st);
        if (!err) {
          type = SHINODE_FILE;
          if (S_ISDIR(st.st_mode))
            type = SHINODE_DIRECTORY;
          if (type == SHINODE_DIRECTORY)
            strcat(path, "/");

          inode = shfs_inode(file, path, type); 
          err = cb(inode, arg);
          if (err) {
            closedir(dir);
            return (err);
          }
        }
      }
      total++;
    }
  }
  closedir(dir);

  if (total == 0)
    return (SHERR_NOENT);

  return (total);
}

int shfs_list_cb(shfs_ino_t *parent, char *fspec, shfs_list_f cb, void *arg)
{
  shfs_ino_t *inode;
  shfs_block_t blk;
  shpeer_t *fs_peer;
  shfs_hdr_t hdr;
  shfs_idx_t idx;
  int tot;
  int err;

  if (!parent) {
    return (SHERR_NOENT);
  }

  fs_peer = shfs_inode_peer(parent);
  if (0 == strcmp(fs_peer->label, "file")) {
    return (shfs_list_native(parent, fspec, cb, arg));
  }

  if (!IS_INODE_CONTAINER(parent->blk.hdr.type)) {
    PRINT_RUSAGE("shfs_inode_link_search: warning: non-container parent.");
    return (SHERR_INVAL);
  }

  tot = 0;

  memcpy(&idx, &parent->blk.hdr.fpos, sizeof(shfs_idx_t));
  while (idx.ino) {
    memset(&blk, 0, sizeof(blk));
    err = shfs_inode_read_block(parent->tree, &idx, &blk);
    if (err) {
      return (err);
    }

    if (blk.hdr.npos.jno == idx.jno && blk.hdr.npos.ino == idx.ino) {
      return (SHERR_IO);
    }

    if (blk.hdr.type != SHINODE_NULL &&
        blk.hdr.format != SHINODE_NULL) {
      char path[SHFS_PATH_MAX];

      memset(path, 0, sizeof(path));
      strncpy(path, (char *)blk.raw, sizeof(path) - 1);
      if (!fspec || 0 == fnmatch(fspec, path, 0)) {

        if (cb) {
          if (blk.hdr.type == SHINODE_DIRECTORY)
            strcat(path, "/");
          inode = shfs_inode(parent, path, blk.hdr.type); 
          err = cb(inode, arg);
          if (err)
            return (err);
        }

        tot++;
      }
    }

    memcpy(&idx, &blk.hdr.npos, sizeof(shfs_idx_t));
  }

  return (tot);
}

_TEST(shfs_list_cb)
{
  SHFL *file;
  shpeer_t *peer;
  shfs_t *fs;
  shbuf_t *buff;

  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);

  file = shfs_file_find(fs, "/shfs_list_cb");
  buff = shbuf_init();
  shbuf_cat(buff, "aaaa", 4);
  _TRUE(0 == shfs_write(file, buff));
  shbuf_free(&buff);
 
  /* verify more than one record is listed for parent directory */
  _TRUE(shfs_list_cb(shfs_inode_parent(file), NULL, NULL, NULL) > 0);
  _TRUE(shfs_list_cb(shfs_inode_parent(file), "shfs_list_cb", NULL, NULL) > 0);

  shfs_free(&fs);

}

static int shfs_dirent_cb(shfs_ino_t *inode, shfs_dirent_t *ents)
{
  int idx;

  for (idx = 0; ents[idx].d_type; idx++);

  memset(&ents[idx], 0, sizeof(ents[idx]));
  strncpy(ents[idx].d_name, shfs_filename(inode), sizeof(ents[idx].d_name) - 1); 
  ents[idx].d_crc = inode->blk.hdr.crc;
  ents[idx].d_type = inode->blk.hdr.type;
  ents[idx].d_format = inode->blk.hdr.format;
  ents[idx].d_attr = inode->blk.hdr.attr;
  shfs_fstat(inode, &ents[idx].d_stat);

  return (0);
}

int shfs_list(shfs_ino_t *file, char *fspec, shfs_dirent_t **ent_p)
{
  shfs_dirent_t *ents;
  int ent_tot;
  int err;

  ent_tot = shfs_list_cb(file, fspec, NULL, NULL);
  if (ent_tot < 0)
    return (ent_tot);
 
  ents = (shfs_dirent_t *)calloc(ent_tot+1, sizeof(shfs_dirent_t));
  if (!ents)
    return (SHERR_NOMEM);

  ent_tot = shfs_list_cb(file, fspec, SHLIST_F(shfs_dirent_cb), ents);
  if (ent_tot < 0) {
    free(ents);
    return (ent_tot);
  }

  *ent_p = ents;
  return (ent_tot);
}

_TEST(shfs_list)
{
  struct shfs_dirent_t *ents;
  SHFL *file;
  shpeer_t *peer;
  shfs_t *fs;
  shbuf_t *buff;

  peer = shpeer_init("test", NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);

  file = shfs_file_find(fs, "/shfs_list");
  buff = shbuf_init();
  shbuf_cat(buff, "aaaa", 4);
  _TRUE(0 == shfs_write(file, buff));
  shbuf_free(&buff);
 
  /* verify more than one record is listed for parent directory */
  ents = NULL;
  _TRUE(shfs_list(shfs_inode_parent(file), "shfs_list", &ents) > 0);
  _TRUEPTR(ents);
  free(ents);

  shfs_free(&fs);

}


void shfs_list_free(shfs_dirent_t **ent_p)
{
  shfs_dirent_t *ent_list;

  if (!ent_p)
    return;

  ent_list = *ent_p;
  *ent_p = NULL;

  free(ent_list);
}
