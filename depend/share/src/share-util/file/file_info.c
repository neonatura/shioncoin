
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

void share_file_info_print(shfs_ino_t *file)
{
  shmime_t *mime;
  shkey_t *owner;

  if (file->tree) {
    fprintf(sharetool_fout, "Partition: %s\n", 
        shpeer_print(&file->tree->peer));
  }

  if (file->parent && IS_INODE_CONTAINER(file->blk.hdr.type)) {
    /* print parent header */
    fprintf(sharetool_fout,
        "Parent: %s \"%s\"\n",
        shfs_type_str(shfs_type(file->parent)),
        shfs_filename(file->parent));
  }

  fprintf(sharetool_fout, 
      "%s: %s\n"
      "Journal %-5.5d\tInode: %-5.5d\tSize: %llu bytes\n"
      "Attributes: %8s\tChecksum: %s\n"
      "Token: %s\n",
      shfs_type_str(shfs_type(file)), shfs_filename(file),
      (int)file->blk.hdr.pos.jno, (int)file->blk.hdr.pos.ino,
      (unsigned long long)shfs_size(file),
      shfs_attr_str(shfs_attr(file)),
      shcrcstr(shfs_crc(file)),
      shkey_print(shfs_token(file)));

  owner = shfs_access_owner_get(file);
  if (owner) {
    fprintf(sharetool_fout, "Owner: %s\n", shkey_print(owner));
  } else {
    fprintf(sharetool_fout, "Owner: <public>\n");
  }

  fprintf(sharetool_fout, "Created: %s\n",
      shstrtime(file->blk.hdr.ctime, NULL));
  fprintf(sharetool_fout, "Modified: %s\n",
      shstrtime(file->blk.hdr.mtime, NULL));

  if (shfs_type(file) == SHINODE_FILE) {
    mime = shmime_file(file);
    if (mime)
      fprintf(sharetool_fout, "Mime: %s\n", shmime_print(mime));
  }

}

int share_file_info(char **args, int arg_cnt, int pflags)
{
  shfs_t *tree;
  shfs_ino_t *file;
  struct stat st;
  int err;
  int i;

  if (arg_cnt <= 1)
    return (SHERR_INVAL);

  for (i = 1; i < arg_cnt; i++) { 
    tree = shfs_uri_init(args[i], 0, &file);
    if (!tree) {
      fprintf (stderr, "%s: cannot stat %s: %s\n", process_path, args[i], sherrstr(SHERR_NOENT)); 
      continue;
    }

    err = shfs_fstat(file, &st);
    if (err) {
      fprintf (stderr, "%s: cannot stat %s: %s\n", process_path, args[i], sherrstr(err)); 
      shfs_free(&tree);
      continue;
    }

    share_file_info_print(file);
    shfs_free(&tree);
  }

  return (0);
}





