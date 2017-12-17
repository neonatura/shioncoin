
#include "shcoind.h"

shfs_t *block_fs;



/* experimental */
char *block_load(int block_height)
{
  shfs_ino_t *file;
  shbuf_t *buff;
  char path[PATH_MAX+1];
  char *data;
  char errbuf[1024];
  size_t data_len;
  int err;

  /* save entire block using hash as reference */
  sprintf(path, "/block/index/%d", block_height);
  file = shfs_file_find(block_fs, path);
  if (!file) {
    return (NULL);
  }

  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (err) {
    shbuf_free(&buff);
    return (NULL);
  }

  printf ("[READ : stat %d] Block index %d is hash '%s'.\n", err, block_height, data);

  return (shbuf_unmap(buff));
}



void block_init(void)
{
  shpeer_t *peer;
  shfs_ino_t *file;
  int err;

  if (!block_fs) {
    peer = shpeer_init("usde", NULL);
    block_fs = shfs_init(peer);
    shpeer_free(&peer);
  }

}

void block_close(void)
{
  if (block_fs) {
    shfs_free(&block_fs);
  }

}



int block_save(int block_height, const char *json_str)
{
  char path[PATH_MAX+1];
  char errbuf[1024];
  shfs_ino_t *file;
  shbuf_t *buff;
  int err;

  /* save entire block using hash as reference */
  sprintf(path, "/block/%d.json", block_height);
  file = shfs_file_find(block_fs, path);
  if (!file) {
    return (SHERR_INVAL);
  }

  buff = shbuf_init();
  shbuf_cat(buff, (char *)json_str, strlen(json_str));
  err = shfs_write(file, buff);
  shbuf_free(&buff);

  printf ("[WRITE : stat %d] Block index %d (%d bytes): %s\n", err, block_height, strlen(json_str), shfs_inode_print(file));

  return (err);
}



