
/*
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
 */  

#include "share.h"
#include "sharetool.h"

typedef struct fs_stat_t
{
  int tot_inode;
  shtime_t first_mod;
  shtime_t last_mod;
  uint64_t aux_crc;
  double scan_time;
} fs_stat_t;

static void shfs_inode_verify(shfs_t *fs, shfs_block_t *blk, fs_stat_t *stat, shmap_t *imap, int *level_p);

static char *_print_size_value(size_t val)
{
#if 0
  static char ret_str[256];

  memset(ret_str, 0, sizeof(ret_str));
  if (val > 1000000000) {
    sprintf(ret_str, "%-3.3f gigs", ((double)val / 1000000000));
  } else if (val > 1000000) {
    sprintf(ret_str, "%-2.2f megs", ((double)val / 1000000));
  } else if (val > 1000) {
    sprintf(ret_str, "%-1.1f kb", ((double)val / 1000));
  } else {
    sprintf(ret_str, "%lu bytes", val);
  }

  return (ret_str);
#endif
  return (shfs_inode_size_str(val));
}

#define FSERR_VERBOSE 0
#define FSERR_INFO 1
#define FSERR_WARN 2
#define FSERR_ERROR 3

#define MAX_FS_ERROR_PREFIXES 5
static const char *_fs_error_prefix[MAX_FS_ERROR_PREFIXES] = {
  "verbose",
  "info",
  "warn",
  "error",
  "critical"
};

static void sharetool_fs_error(int level, char *text)
{
  if (level == FSERR_VERBOSE) {
    if (run_flags & PFLAG_VERBOSE) {
      fprintf(sharetool_fout, "%s: %s: %s\n", 
          process_path, _fs_error_prefix[level], text); 
    }
  } else if (level == FSERR_INFO) {
    fprintf(sharetool_fout, "%s: %s: %s\n", 
        process_path, _fs_error_prefix[level], text); 
  } else {
    time_t now = time(NULL);
    fprintf(stderr, "[%-20.20s] %s: %s\n", 
        ctime(&now)+4, _fs_error_prefix[level], text); 
  }
}

#if 0
static long _partition_verify(shfs_t *fs, shfs_block_t *blk, fs_stat_t *stat)
{
  shfs_block_t nblk;
  char text[1024];
  int seq_tot, chain_tot;
  int err;


  chain_tot = 0;
  if (blk->hdr.fpos.jno) {
    /* obtain next 'child' block */
    memset(&nblk, 0, sizeof(nblk));
    err = shfs_inode_read_block(fs, &blk->hdr.fpos, &nblk);
    if (!err) {
      /* recursive scan partition's attached inodes. */
      chain_tot = _partition_verify(fs, &nblk, stat);
    } else {
      sprintf(text, "[inode %d:%d] %s.", blk->hdr.fpos.jno, blk->hdr.fpos.ino, sherrstr(err));
      sharetool_fs_error(FSERR_ERROR, text);
    }
  }



  if (shfs_block_type(blk) == SHINODE_AUX) {
    uint64_t crc = shfs_crc_init(blk);
    /* verify checksum integrity */
    if (shfs_crc_init(blk) != blk->hdr.crc) {
      /* data integrity has been breached capt'n */
      sprintf(text, "[inode %d:%d] Invalid data checksum (%s). [size %s]",
          blk->hdr.pos.jno, blk->hdr.pos.ino, 
          shfs_type_str(shfs_block_type(blk)),
          _print_size_value(blk->hdr.size));
      sharetool_fs_error(FSERR_ERROR, text);
    }
    stat->aux_crc += crc;
  } else if (shfs_block_type(blk) == SHINODE_BINARY) {
    /* contains AUX data */
    if (/* stat->aux_crc && */ blk->hdr.crc != stat->aux_crc) {
      sprintf(text, "[inode %d:%d] Invalid data checksum (%s). [size %s]",
          blk->hdr.pos.jno, blk->hdr.pos.ino, 
          shfs_type_str(shfs_block_type(blk)),
          _print_size_value(blk->hdr.size));
      sharetool_fs_error(FSERR_ERROR, text);
fprintf(stderr, "DEBUG: FILE: crc %x vs. aux_crc %x [format %d]\n", blk->hdr.crc, stat->aux_crc, blk->hdr.format);
    }
  }
  if (IS_INODE_CONTAINER(blk)) {
    stat->aux_crc = 0;
  }
  


  seq_tot = 0;
  if (blk->hdr.npos.jno) {
    /* obtain next 'sequence' block */
    memset(&nblk, 0, sizeof(nblk));
    err = shfs_inode_read_block(fs, &blk->hdr.npos, &nblk);
    if (!err) {
      /* recursive scan partition's attached inodes. */
      seq_tot = _partition_verify(fs, &nblk, stat);
    } else {
      sprintf(text, "[inode %d:%d] %s.", blk->hdr.pos.jno, blk->hdr.pos.ino, sherrstr(err)); 
      sharetool_fs_error(FSERR_ERROR, text);
    }
  }




  stat->tot_inode++;
  if (shtime_after(blk->hdr.mtime, stat->last_mod))
    stat->last_mod = blk->hdr.mtime;
  if (shtime_before(blk->hdr.mtime, stat->first_mod))
    stat->first_mod = blk->hdr.mtime;

  sprintf(text, "inode %d:%d (%s). [seq x%d, chain x%d, size %s]", blk->hdr.pos.jno, blk->hdr.pos.ino, shfs_type_str(shfs_block_type(blk)), seq_tot, chain_tot, _print_size_value(blk->hdr.size));
  sharetool_fs_error(FSERR_VERBOSE, text);
}
#endif

static void shfs_inode_update(shfs_t *fs, shfs_block_t *blk, fs_stat_t *stat)
{
  char text[1024];

  stat->tot_inode++;
  if (shtime_after(blk->hdr.mtime, stat->last_mod))
    stat->last_mod = blk->hdr.mtime;
  if (shtime_before(blk->hdr.mtime, stat->first_mod))
    stat->first_mod = blk->hdr.mtime;


  sprintf(text, "inode %d:%d (%s). [size %s]", blk->hdr.pos.jno, blk->hdr.pos.ino, shfs_type_str(shfs_block_type(blk)), _print_size_value(blk->hdr.size));
  sharetool_fs_error(FSERR_VERBOSE, text);

}

static void shfs_chain_verify(shfs_t *fs, shfs_block_t *blk, fs_stat_t *stat, shmap_t *imap, int *level_p)
{
  shfs_block_t nblk;
  char text[1024];
  int err;

  if (blk->hdr.fpos.jno) {
    /* obtain next 'sequence' block */
    memset(&nblk, 0, sizeof(nblk));
    err = shfs_inode_read_block(fs, &blk->hdr.fpos, &nblk);
    if (!err) {
      /* recursive scan partition's attached inodes. */
      shfs_inode_verify(fs, &nblk, stat, imap, level_p);
    } else {
      sprintf(text, "[inode %d:%d] %s.", blk->hdr.pos.jno, blk->hdr.pos.ino, sherrstr(err)); 
      sharetool_fs_error(FSERR_ERROR, text);
    }
  }

}

static void shfs_sequence_verify(shfs_t *fs, shfs_block_t *blk, fs_stat_t *stat, shmap_t *imap, int *level_p)
{
  shfs_block_t nblk;
  char text[1024];
  int err;


  if (blk->hdr.npos.jno != 0) {
#if 0
    if (0 == memcmp(&nblk.hdr.pos, &blk->hdr.pos, sizeof(shfs_idx_t)))
      return (SHERR_IO); /* endless loop */
#endif

    /* obtain next 'sequence' block */
    memset(&nblk, 0, sizeof(nblk));
    err = shfs_inode_read_block(fs, &blk->hdr.npos, &nblk);
    if (!err) {
      /* recursive scan partition's attached inodes. */
      shfs_inode_verify(fs, &nblk, stat, imap, level_p);
    } else {
      sprintf(text, "[inode %d:%d/%d] %s.", blk->hdr.pos.jno, blk->hdr.pos.ino, sherrstr(err)); 
      sharetool_fs_error(FSERR_ERROR, text);
    }

  }


}

static void shfs_inode_verify(shfs_t *fs, shfs_block_t *blk, fs_stat_t *stat, shmap_t *imap, int *level_p)
{
  shfs_idx_t *idx;
  char text[1024];
  uint64_t crc;

  shfs_inode_update(fs, blk, stat);

  idx = shmap_get(imap, &blk->hdr.name);
  if (idx) {
    sprintf(text, "[inode %d:%d] %s inode duplicate of inode %d:%d.",
        blk->hdr.pos.jno, blk->hdr.pos.ino, 
        shfs_type_str(shfs_block_type(blk)), idx->jno, idx->ino);
    sharetool_fs_error(FSERR_ERROR, text);
  } else {
    idx = (shfs_idx_t *)calloc(1, sizeof(shfs_idx_t));
    memcpy(idx, &blk->hdr.pos, sizeof(shfs_idx_t));
    shmap_set(imap, &blk->hdr.name, idx);
  }

	*level_p = *level_p + 1;
	if (*level_p >= 500) {
		/* DEBUG: */
		sprintf(text, "[inode %d:%d/%d] Too many links.", blk->hdr.pos.jno, blk->hdr.pos.ino, *level_p);
		sharetool_fs_error(FSERR_ERROR, text);
		return;
	}

  /* sequential chain of inodes. */
  shfs_sequence_verify(fs, blk, stat, imap, level_p);

  if (shfs_block_type(blk) == SHINODE_BINARY) {
    stat->aux_crc = 0;
  }

  if (IS_INODE_CONTAINER(shfs_block_type(blk))) {

    /* some sort of inode container */
    shfs_chain_verify(fs, blk, stat, imap, level_p);

  } else {
    if (blk->hdr.fpos.jno || blk->hdr.fpos.ino) {
      /* non-container inodes cannot have children. */
      sprintf(text, "[inode %d:%d] Invalid attachment (%s). [size %s]",
          blk->hdr.pos.jno, blk->hdr.pos.ino, 
          shfs_type_str(shfs_block_type(blk)),
          _print_size_value(blk->hdr.size));
      sharetool_fs_error(FSERR_ERROR, text);
    }
  }

  if (shfs_block_type(blk) == SHINODE_AUX) {
    /* verify checksum integrity */
    crc = shfs_crc_init(blk);
    if (shfs_crc_init(blk) != blk->hdr.crc) {
      /* data integrity has been breached capt'n */
      sprintf(text, "[inode %d:%d] Invalid data checksum (%s). [size %s]",
          blk->hdr.pos.jno, blk->hdr.pos.ino, 
          shfs_type_str(shfs_block_type(blk)),
          _print_size_value(blk->hdr.size));
      sharetool_fs_error(FSERR_ERROR, text);
//fprintf(stderr, "DEBUG: FILE: crc %x vs. gen crc %x [format %d]\n", blk->hdr.crc, crc, blk->hdr.format);
    }
    stat->aux_crc += crc;
  } else if (shfs_block_type(blk) == SHINODE_BINARY) {
    if (stat->aux_crc && 
blk->hdr.size && /* NOTE: comment out line to expose removed inodes w/ crc */
        blk->hdr.crc != stat->aux_crc) {
      sprintf(text, "[inode %d:%d] Invalid data checksum (%s). [size %s]",
          blk->hdr.pos.jno, blk->hdr.pos.ino, 
          shfs_type_str(shfs_block_type(blk)),
          _print_size_value(blk->hdr.size));
      sharetool_fs_error(FSERR_ERROR, text);
//fprintf(stderr, "DEBUG: FILE: crc %x vs. aux_crc %x [format %d]\n", blk->hdr.crc, stat->aux_crc, blk->hdr.format);
    }
  }

}


fs_stat_t *sharetool_fs_partition_verify(shfs_t *fs, shfs_block_t *blk, shmap_t *imap)
{
  static fs_stat_t stat;
  char text[1024];
  shtime_t now;
	int level;
  int err;

  memset(&stat, 0, sizeof(stat));

  now = shtime();
  stat.first_mod = now;

	level = 0;
  shfs_inode_verify(fs, blk, &stat, imap, &level);

  stat.scan_time = shtimef(shtime()) - shtimef(now);

  return (&stat);
}

int sharetool_fscheck(void)
{
  DIR *dir;
  FILE *fl;
  shfs_block_t blk;
  struct stat st;
  struct dirent *ent;
  shbuf_t *msg_buff;
  shmap_t *imap;
  shfs_idx_t *idx;
  char base_path[PATH_MAX+1];
  char path[PATH_MAX+1];
  char p_name[256];
  char text[1024];
  size_t tot_size;
  size_t v_size;
  int v_count;
  int p_cnt;
  int jno;
  int err;

  sprintf(base_path, "%s/fs", get_libshare_path());
  dir = opendir(base_path);
  if (!dir)
    return (-errno);

  msg_buff = shbuf_init();
  while ((ent = readdir(dir))) {
    if (0 != strncmp(ent->d_name, "_", 1))
      continue;

    memset(p_name, 0, sizeof(p_name));
    strncpy(p_name, ent->d_name, sizeof(p_name) - 1);

    v_size = 0;
    v_count = 0;
    sprintf(text, "\nVolume '%s'\n", p_name + 2);
    shbuf_catstr(msg_buff, text);

    for (jno = 0; jno < SHFS_MAX_JOURNAL; jno++) {
      sprintf(path, "%s/%s/_%d", base_path, p_name, jno);
      if (0 != stat(path, &st))
        continue; 

      tot_size += st.st_size;
      v_size += st.st_size;
      v_count++;
    }
    sprintf(text, "\tPhysical Size: %s\n", _print_size_value(v_size));
    shbuf_catstr(msg_buff, text);
    sprintf(text, "\tTotal Journals: %d / %d\n", v_count, SHFS_MAX_JOURNAL);
    shbuf_catstr(msg_buff, text);
    sprintf(text, "\tAverage Journal Size: %s\n", 
        _print_size_value(abs((double)v_size / (double)v_count)));
    shbuf_catstr(msg_buff, text);

    sprintf(path, "%s/%s/_0", base_path, p_name);
    if (0 != stat(path, &st))
      continue; 
    fl = fopen(path, "rb");

    imap = shmap_init();
    
    p_cnt = 0;
    fread(&blk, SHFS_MAX_BLOCK_SIZE, 1, fl);
    while (!feof(fl)) {
      if (p_cnt == 0) {
        /* must be SHINODE_NULL. */
        if (shfs_block_type(&blk) != SHINODE_NULL) {
          sprintf(text, "Volume '%s' has an invalid super-block prefix.", p_name+2);
          sharetool_fs_error(FSERR_WARN, text);
        }
      } else if (shfs_block_type(&blk) != SHINODE_NULL) {
        if (shfs_block_type(&blk) != SHINODE_PARTITION) {
          sprintf(text, "Volume '%s' has an invalid super-block inode: %s.", p_name+2, shfs_type_str(shfs_block_type(&blk)));
          sharetool_fs_error(FSERR_WARN, text);
        } else {
          shfs_root_t *root = (shfs_root_t *)blk.raw;
          shfs_t *fs = shfs_init(&root->peer);
          fs_stat_t *stat = sharetool_fs_partition_verify(fs, &blk, imap);
          shfs_free(&fs);

          sprintf(text, "\tTotal Inodes: %d\n", stat->tot_inode);
          shbuf_catstr(msg_buff, text);
          sprintf(text, "\tMinimum Timestamp: %-20.20s\n", shctime(stat->first_mod)+4);
          shbuf_catstr(msg_buff, text);
          sprintf(text, "\tMaximum Timestamp: %-20.20s\n", shctime(stat->last_mod)+4);
          shbuf_catstr(msg_buff, text);
          sprintf(text, "\tScan Time: %-3.3fms per inode\n",
              (stat->scan_time / (double)stat->tot_inode) * 1000);
          shbuf_catstr(msg_buff, text);
        }
      }

      p_cnt++;
      fread(&blk, SHFS_MAX_BLOCK_SIZE, 1, fl);
    }
    fclose(fl);

    for (jno = 1; jno < SHFS_MAX_JOURNAL; jno++) {
      sprintf(path, "%s/%s/_%d", base_path, p_name, jno);
      fl = fopen(path, "rb");
      if (!fl)
        continue;
      while (!feof(fl)) {
        err = fread(&blk, SHFS_MAX_BLOCK_SIZE, 1, fl);
        if (err != 1)
          break;

        if (!blk.hdr.type)
          continue; /* empty */

        idx = shmap_get(imap, &blk.hdr.name);
        if (!idx) {
          sprintf(text, "Unattached inode %d:%d (%s).",
              blk.hdr.pos.jno, blk.hdr.pos.ino,
              shfs_type_str(shfs_block_type(&blk)));
          sharetool_fs_error(FSERR_WARN, text);
        }
      }
      fclose(fl);
    }

    shmap_free(&imap);
  }
  closedir(dir);

  sprintf(text, "\nTotal Size: %s\n", _print_size_value(tot_size));
  shbuf_catstr(msg_buff, text);


  fwrite(shbuf_data(msg_buff), shbuf_size(msg_buff), sizeof(char), sharetool_fout); 
  shbuf_free(&msg_buff);

  return (0);
}
