

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "share.h"
#include "bc.h"

int main(int argc, char **argv)
{
  bc_t *bc;
  bc_hash_t hash;
  char buf[10240];
  unsigned char *t_data;
  size_t t_data_len;
  int idx;
  bcsize_t n_pos;
  bcsize_t pos;
  int err;

  err = bc_open("test", &bc);
  if (err) {
    fprintf(stderr, "bc_test: error opening blockchain 'test': %s.", sherrstr(err));
    return (1);
  }

  srand(time(NULL));

n_pos = bc_idx_next(bc);

  for (idx = 0; idx < 10; idx++) {
    buf[0] = (rand() % 254);
    buf[1] = (rand() % 254);
    buf[2] = (rand() % 254);
    memset(buf + 3, (rand() % 254), sizeof(buf) - 3);

    memcpy(hash, buf + 1, sizeof(hash));

    pos = bc_append(bc, hash, buf, sizeof(buf));
    if (pos < 0) {
      fprintf(stderr, "bc_test: error appending blockchain 'test': %s.", sherrstr(pos));
      return (1);
    }

    err = bc_find(bc, hash, NULL);
    if (err) {
      fprintf(stderr, "bc_test: error searching blockchain 'test': %s.", sherrstr(err));
      return (1);
    }

    if ((pos + 1) != bc_idx_next(bc)) {
      fprintf(stderr, "bc_test: position error in blockchain 'test': %s. [cur-pos %d, next-pos %d]", sherrstr(err), pos, bc_idx_next(bc));
      return (1);
    }

    err = bc_get(bc, pos, &t_data, &t_data_len);
    if (err) {
      fprintf(stderr, "bc_test: error retrieving blockchain 'test': %s.", sherrstr(err));
      return (1);
    }
    if (t_data_len != sizeof(buf)) {
      fprintf(stderr, "bc_test: size error with blockchain 'test': %s.", sherrstr(err));
      return (1);
    }
    if (0 != memcmp(t_data, buf, t_data_len)) {
      int j;
      for (j = 0; j < 10240; j += 4) {
        if (t_data[j] != buf[j]) fprintf(stderr, "bc_test: checksum error with blockchain 'test': #%d '%x' vs '%x' [pos %d]\n", j, *((int *)(t_data + j)), *((int *)(buf + j)), pos);
      }
      return (1);
    }
    free(t_data);

    memset(hash, 255, sizeof(hash));
    err = bc_find(bc, hash, NULL);
    if (err != SHERR_NOENT) {
      fprintf(stderr, "bc_test: error searching blockchain 'test': false positive.\n");
      return (1);
    } 
  }

  err = bc_purge(bc, n_pos + 1);
  if (err) {
    fprintf(stderr, "bc_test: error purging records: %s.\n", sherrstr(err));
  }

fprintf(stderr, "OK (height %d)\n", (bc_idx_next(bc)-1));
  bc_close(bc);


  return (0);
}
