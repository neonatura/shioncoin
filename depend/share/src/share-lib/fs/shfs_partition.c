
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
#include "shfs_int.h"

#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif

static int _file_queue_id = -1;
static uint32_t _shfs_partition_ref = 0;

#if 0
struct shfs_root_t
{

  /** A reference to the share-fs partition peer public key */
  shkey_t root_peer;

  /** A reference to the last time when the file-system was checked */
  shtime_t root_stamp;

  /** The share-fs partition version. */
  uint32_t root_ver;

} shfs_root_t;
#endif

static int shfs_scan_partition(shfs_t *fs, shfs_block_t *node)
{
  shfs_block_t p_node;
  shfs_idx_t idx;
  struct stat st;
  size_t size;
  char path[PATH_MAX+1];;
  int err;

  shfs_journal_path(fs, 0, path); 

  memset(&st, 0, sizeof(st));
  stat(path, &st);
  size = MAX(SHFS_MAX_BLOCK_SIZE*2, st.st_size) / SHFS_MAX_BLOCK_SIZE;

  memset(&idx, 0, sizeof(idx));
  for (idx.ino = (size-1); idx.ino > 0; idx.ino--) {
    memset(&p_node, 0, sizeof(p_node));
    err = shfs_inode_read_block(fs, &idx, &p_node);
    if (err) {
      return (err);
    }

    if (shfs_block_type(&p_node) == SHINODE_NULL) {
      return (SHERR_NOENT);
    }

    if (shfs_block_type(&p_node) == SHINODE_PARTITION &&
        shkey_cmp(&p_node.hdr.name, shpeer_kpub(&fs->peer))) {
      memcpy(node, &p_node, sizeof(shfs_block_t));
      return (0);
    }
  }

  return (SHERR_NOENT);
}

shfs_t *shfs_init(shpeer_t *peer)
{
  shfs_t *tree;
  shfs_block_t p_node;
  shfs_block_t base_blk;
  shfs_ino_t blk;
  shfs_ino_t *root;
  shkey_t *key;
  char path[PATH_MAX + 1];
  char ebuf[1024];
  char *ptr;
  int flags;
  int err;

  { /* sanity check */
    char jrnl_path[PATH_MAX+1];
    struct stat st;

    sprintf(jrnl_path, "%s", get_libshare_path());
    if (0 != stat(jrnl_path, &st)) {
      mkdir(jrnl_path, 0777);
      chown(jrnl_path, 0, 0);
    }

    sprintf(jrnl_path, "%s/fs", get_libshare_path());
    if (0 != stat(jrnl_path, &st)) {
      mkdir(jrnl_path, 0777);
      chown(jrnl_path, 0, 0);
    }
  }

  tree = (shfs_t *)calloc(1, sizeof(shfs_t));
  if (!tree)
    return (NULL);

  /* establish peer */
  flags = 0;
  if (!peer) {
    /* default peer's partition. */
    peer = shpeer();
    memcpy(&tree->peer, peer, sizeof(shpeer_t));
    shpeer_free(&peer);
  } else {
    memcpy(&tree->peer, peer, sizeof(shpeer_t));
  }

  /* read partition (supernode) block */
  memset(&p_node, 0, sizeof(p_node));
  err = shfs_scan_partition(tree, &p_node);
  if (err) {
    if (err != SHERR_NOENT) {
      /* something bad happened */
      sherr(err, "shfs_init [shfs_scan_partition]");
    }

    /* obtain a new block on initial journal. */
    memset(&p_node, 0, sizeof(p_node));
    err = shfs_journal_scan(tree, NULL, &p_node.hdr.pos);
    if (err) {
      PRINT_ERROR(err, "shfs_init [shfs_journal_scan]");
      return (NULL);
    }

    /* unitialized partition inode */
    p_node.hdr.type = SHINODE_PARTITION;
    memcpy(&p_node.hdr.name, shpeer_kpub(&tree->peer), sizeof(shkey_t));
    p_node.hdr.crc = shfs_crc_init(&p_node);
    p_node.hdr.ctime = shtime();
    memcpy((unsigned char *)p_node.raw, &tree->peer, sizeof(shpeer_t));

    /* establish directory tree */
    err = shfs_journal_scan(tree, &p_node.hdr.name, &p_node.hdr.fpos);
    if (err) {
      PRINT_ERROR(err, "shfs_init [shfs_journal_scan]");
      return (NULL);
    }

    /* default full public access */
    p_node.hdr.attr |= SHATTR_READ;
    p_node.hdr.attr |= SHATTR_WRITE;
    p_node.hdr.attr |= SHATTR_EXE;

    err = shfs_inode_write_block(tree, &p_node);
    if (err) {
      sprintf(ebuf, "shfs_init: error writing super-node block (%d:%d) for peer '%s'.", p_node.hdr.pos.jno, p_node.hdr.pos.ino, shpeer_print(peer));
      PRINT_ERROR(err, ebuf);
      return (NULL);
    }

#if 0
    sprintf(ebuf, "shfs_init: fresh supernode (%d:%d) %s", p_node.hdr.pos.jno, p_node.hdr.pos.ino, shpeer_print(peer));
    PRINT_RUSAGE(ebuf);
#endif
  }

  err = shfs_inode_read_block(tree, &p_node.hdr.fpos, &base_blk);
  if (err) { 
    PRINT_ERROR(err, "shfs_init [shfs_inode]");
    return (NULL);
  }

  root = shfs_inode(NULL, NULL, SHINODE_DIRECTORY);
  if (!root) {
    PRINT_ERROR(err, "shfs_init [shfs_inode error]");
    return (NULL);
  }

  if (base_blk.hdr.type == SHINODE_DIRECTORY) {
    memcpy(&root->blk, &base_blk, sizeof(shfs_block_t));
  } else {
    memcpy(&root->blk.hdr.pos, &p_node.hdr.fpos, sizeof(shfs_idx_t));

    root->blk.hdr.crc = shfs_crc_init(&root->blk);
    err = shfs_inode_write_block(tree, &root->blk);
    if (err) {
      PRINT_ERROR(err, "shfs_init [shfs_inode error]");
      return (NULL);
    }
  }

  tree->base_ino = root;
  tree->fsbase_ino = root;
  root->tree = tree;
  root->base = root;

  _shfs_partition_ref++;

  return (tree);
}

/**
 * @todo needs to free inode's cache'd in it's hierarchy
 */
void shfs_free(shfs_t **tree_p)
{
  shfs_t *tree;

  if (!tree_p)
    return;
  
  tree = *tree_p;
  *tree_p = NULL;
  if (!tree)
    return;

  if (tree->fsbase_ino)
    shfs_inode_free(&tree->fsbase_ino);

  if (_shfs_partition_ref != 0)
    _shfs_partition_ref--;
  if (_shfs_partition_ref == 0)
    shfs_journal_cache_free(tree);

  free(tree);

  if (_file_queue_id != -1) {
    shmsg_queue_free(_file_queue_id);
    _file_queue_id = -1;
  }
}

_TEST(shfs_init)
{
  shfs_t *tree;
  shfs_idx_t pos;

  _TRUEPTR(tree = shfs_init(NULL));
  memcpy(&pos, &tree->base_ino->blk.hdr.pos, sizeof(shfs_idx_t));
  shfs_free(&tree);

  _TRUEPTR(tree = shfs_init(NULL));
  _TRUE(0 == memcmp(&pos, &tree->base_ino->blk.hdr.pos, sizeof(shfs_idx_t)));
  shfs_free(&tree);
}

shkey_t *shfs_partition_id(shfs_t *tree)
{
  return (shpeer_kpub(&tree->peer));
}



int _shfs_file_qid(void)
{
  int err;

  if (_file_queue_id = -1) {
    /* initialize queue to share daemon */
    err = shmsgget(NULL);
    if (err < 0)
      return (err);

    _file_queue_id = err;
  }

  return (_file_queue_id);
}


char *shfs_sys_dir(char *sys_dir, char *fname)
{
  static char ret_path[SHFS_PATH_MAX];

  memset(ret_path, 0, sizeof(ret_path));
  snprintf(ret_path, sizeof(ret_path)-1, "/sys/%s/%s", sys_dir, fname);

  return (ret_path);
}

shfs_t *shfs_sys_init(char *sys_dir, char *fname, shfs_ino_t **file_p)
{
  shfs_t *fs;
  shpeer_t *peer;

  peer = shpeer_init(PACKAGE, NULL);
  fs = shfs_init(peer);
  shpeer_free(&peer);

  if (file_p) {
    *file_p = shfs_file_find(fs, shfs_sys_dir(sys_dir, fname));
  }

  return (fs);
}

shpeer_t *shfs_peer(shfs_t *fs)
{
  if (!fs)
    return (NULL);
  return (&fs->peer);
}



#define SHURI_CREATE O_CREAT


#define SHFSURI_NONE 0
#define SHFSURI_PREFIX 1
#define SHFSURI_GROUP 2
#define SHFSURI_PASS 3
#define SHFSURI_HOST 4
#define SHFSURI_PORT 5
#define SHFSURI_PATH 6

shfs_t *shfs_uri_init(char *path, int flags, shfs_ino_t **ino_p)
{
  struct stat st;
  shfs_t *fs;
  shfs_ino_t *dir;
  shfs_ino_t *file;
  shpeer_t *peer;
  char p_prefix[PATH_MAX+1];
  char p_group[PATH_MAX+1];
  char p_pass[PATH_MAX+1];
  char p_host[PATH_MAX+1];
  char p_dir[PATH_MAX+1];
  char p_path[PATH_MAX+1];
  char f_path[PATH_MAX+1];
  char *peer_name;
  char *peer_host;
  char *cptr;
  char *ptr;
  int p_port;
  int pmode;
  int idx;
  int err;

  memset(p_prefix, 0, sizeof(p_prefix));
  memset(p_group, 0, sizeof(p_group));
  memset(p_pass, 0, sizeof(p_pass));
  memset(p_host, 0, sizeof(p_host));
  memset(p_dir, 0, sizeof(p_dir));
  memset(p_path, 0, sizeof(p_path));
  p_port = 0;

#ifdef PACKAGE
  strncpy(p_prefix, PACKAGE, sizeof(p_prefix) - 1);
#endif

  if (0 == strncmp(path, "home:", 5)) {
    shkey_t *id_key;

    id_key = shpam_ident_gen(shpam_uid(
          (char *)get_libshare_account_name()), ashpeer());
    fs = shfs_home_fs(id_key);
    shkey_free(&id_key);

    file = shfs_home_file(fs, path + 5);
    if (ino_p)
      *ino_p = file;
    return (fs);
  }
  
  if (!strchr(path, '/') || 0 == strncmp(path, "./", 2)) {
    if (0 == strncmp(path, "./", 2))
      path += 2;
    strcpy(p_prefix, "file");
    getcwd(p_dir, sizeof(p_dir) - 1);
    strncpy(p_path, path, sizeof(p_path) - 1);
  } else {
    pmode = SHFSURI_NONE;
    ptr = path;
    while (*ptr) {
      idx = strcspn(ptr, ":/@");
      cptr = ptr;
      ptr += idx;

      if (pmode == SHFSURI_NONE) {
        if (0 == strncmp(ptr, ":/", 2)) {
          pmode = SHFSURI_GROUP;
          memset(p_prefix, 0, sizeof(p_prefix));
          strncpy(p_prefix, cptr, idx);
          ptr += 2;
        } else {
          pmode = SHFSURI_PATH;
        }
      } else if (pmode == SHFSURI_GROUP) {
        if (*ptr == ':') {
          pmode = SHFSURI_PASS;
          ptr++;
        } else if (*ptr == '@') {
          pmode = SHFSURI_HOST;
          ptr++;
        } else {
          pmode = SHFSURI_PATH;
          ptr = cptr; /* fall back */
        }
        strncpy(p_group, cptr, idx);
      } else if (pmode == SHFSURI_PASS) {
        if (*ptr == '@') {
          pmode = SHFSURI_HOST;
          ptr++;
        } else {
          pmode = SHFSURI_PATH;
        }
        strncpy(p_pass, cptr, idx);
      } else if (pmode == SHFSURI_HOST) {
        if (*ptr == ':') {
          pmode = SHFSURI_PORT;
          ptr++;
        } else {
          pmode = SHFSURI_PATH;
        }
        strncpy(p_host, cptr, idx);
      } else if (pmode == SHFSURI_PORT) {
        pmode = SHFSURI_PATH;
        p_port = atoi(cptr);
      } else if (pmode == SHFSURI_PATH) {
        strncpy(p_dir, cptr, sizeof(p_dir) - 1);

        if (*p_dir && p_dir[strlen(p_dir)-1] != '/') {
          ptr = strrchr(p_dir, '/');
          if (ptr) {
            *ptr++ = '\0';
            strncpy(p_path, ptr, sizeof(p_path) - 1); 
          }
        }
        break;
      }

    }
  }

  sprintf(f_path, "%s/%s", p_dir, p_path);

  peer_name = NULL;
  if (*p_prefix) {
    peer_name = p_prefix;
    if (*p_pass) {
      strcat(peer_name, ":");
      strcat(peer_name, p_pass);
    }
  }
  peer_host = NULL;
  if (*p_host) {
    peer_host = p_host; 
    if (p_port)
      sprintf(peer_host+strlen(peer_host), ":%d", p_port);
  }
  peer = shpeer_init(peer_name, peer_host);
  fs = shfs_init(peer);
  shpeer_free(&peer);

  if (!*p_path) {
    /* no file specified. */
    dir = shfs_dir_find(fs, p_dir);
    if (ino_p)
      *ino_p = dir;
    return (fs);
  }

  /* regular shfs file */
  file = shfs_file_find(fs, f_path);

  if (0 == strcmp(p_prefix, "file")) {
    err = stat(f_path, &st);
    if (err && errno == ENOENT) {
      if ((flags & SHURI_CREATE)) {
        FILE *fl = fopen(f_path, "wb");
        if (fl) 
          err = fclose(fl);
      }
    }
    if (err)
      return (NULL);

    /* set link to local-disk path. */
    err = shfs_ext_set(file, f_path);
    if (err)
      return (NULL);

    err = shfs_inode_write_entity(file);
    if (err)
      return (NULL);
  }

  if (ino_p)
    *ino_p = file;

  return (fs);
}

size_t shfs_avail(void)
{
#ifdef HAVE_SYS_STATVFS_H
  struct statvfs fs;
  int err;

  memset(&fs, 0, sizeof(fs));
  err = statvfs(get_libshare_path(), &fs);
  if (err)
    return (errno2sherr());

  if (fs.f_bsize == 0)
    return (SHERR_OPNOTSUPP);

  return ((fs.f_bsize * fs.f_bavail) / 1000000);
#else
  return (SHERR_OPNOTSUPP);
#endif
}
