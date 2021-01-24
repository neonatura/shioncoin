
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
*/  

#include "share.h"

#define RUN_NONE 0
#define RUN_LIST 1
#define RUN_GENERATE 4
#define RUN_VERIFY 5

#define PROGRAM_NAME PACKAGE_NAME

typedef struct peerstore_t 
{
  shpeer_t peer;
  shtime_t birth;
  shtime_t stamp;
  shkey_t context;
  uint32_t trust;
} peerstore_t;

static int run_mode;
static char prog_name[PATH_MAX+1];

/**
 * Displays the program's version information to the command console.
 */
void program_version(void)
{
  printf ("%s version %s (%s)\n"
      "\n"
      "Copyright 2014 Neo Natura\n"
      "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n"
      "Visit 'https://github.com/neonatura/share' for more information.\n",
      prog_name, PACKAGE_VERSION, PACKAGE_NAME);
}

/**
 * Displays the program's usage information to the command console.
 */
void program_usage(void)
{
  printf (
    "%s version %s (%s)\n"
    "usage: %s [--gen] [--verify] [--context <context>] [<app-name>]\n"
    "\n"
    "Command-line arguments:\n"
    "  --gen\t\t\tGenerate a new key for the app.\n"
    "  --verify\t\tVerify data context against existing key-store.\n"
    "  --host <host>[:<port>]\t\tA ipv4/ipv6 network address.\n"
    "  --context @<filename>\tUse file as context for key generation.\n"
    "  --context <string>\tUse text string as context for key generation.\n"
    "\n"
    "Example of managing a table of application peers.\n"
    "\n"
    "Visit 'https://github.com/neonatura/share' for more information.\n",
    prog_name, PACKAGE_VERSION, PACKAGE_NAME, prog_name);
}

void print_peer_store(peerstore_t *k_item)
{
  printf ("\n");
  if (k_item->stamp)
    printf ("Connection: None", ctime(&k_item->stamp)); 
  else
    printf ("Connection: %-19.19s", ctime(&k_item->stamp)); 
  printf (" (Created %-19.19s)\n", ctime(&k_item->birth)); 
  printf ("Trust: %u\n", (unsigned int)k_item->trust);
  printf ("Context: %s\n", shkey_print(&k_item->context));
  printf ("Peer: %s\n", shpeer_print(&k_item->peer));
}

void shpeer_msg_proc(shbuf_t *buff)
{
  unsigned char *data;
  shpeer_t peer;
  int mode;

  data = shbuf_data(buff);
  memcpy(&mode, data, sizeof(uint32_t));

  switch (mode) {
#if 0
/* DEBUG: -> TX_APP */
    case TX_PEER:
      memcpy(&peer, data + sizeof(uint32_t), sizeof(shpeer_t));
fprintf(stderr, "DEBUG: shpeer_msg_proc: received from server: %s\n", shpeer_print(&peer));
      break;
#endif
    default:
fprintf(stderr, "DEBUG: shpeer_msg_proc: unknown msg %d received from server.\n", mode);
  }

}

void shpeer_msg_poll(void)
{
  shbuf_t *buff;
  int qid;

  /* open message queue to share daemon. */
  qid = shmsgget(NULL);

  /* retrieve any pending messages. */
  buff = shbuf_init();
  while ((0 == shmsg_read(qid, NULL, buff))) {
    shpeer_msg_proc(buff);
    shbuf_clear(buff);
  }
  shbuf_free(&buff);

//  shmsgctl(qid, SHMSGF_RMID, TRUE);
}

void shpeer_msg_push(shpeer_t *peer)
{
  static int qid;
  shbuf_t *buff;
  uint32_t mode;

#if 0
/* DEBUG: -> TX_APP */
  mode = TX_PEER;
  buff = shbuf_init();
  shbuf_cat(buff, &mode, sizeof(mode));
  shbuf_cat(buff, peer, sizeof(shpeer_t));

  /* open message queue to share daemon. */
if (!qid)
  qid = shmsgget(NULL);
  shmsg_write(qid, buff, NULL);
//  shmsgctl(qid, SHMSGF_RMID, TRUE);


  shbuf_free(&buff);
#endif
}

/**
 * Performs key-store List, Generate, and Verify operations.
 */
int main(int argc, char **argv)
{
  shfs_t *tree;
  shfs_ino_t *file;
  peerstore_t **k_list;
  peerstore_t *sv_list;
  peerstore_t key_data;
  shpeer_t *app_peer;
  shpeer_t *proc_peer;
  shpeer_t *peer;
  shkey_t *app_key;
  shkey_t *ref_key;
  shbuf_t *buff;
  char path[PATH_MAX+1];
  char app[1024];
  char hostname[1024];
  char *ref_data;
  size_t ref_data_len;
  unsigned char *k_data;
  size_t k_len;
  int ret_code;
  int rec_nr;
  int err;
  int i;


  memset(prog_name, 0, sizeof(prog_name));
  strncpy(prog_name, argv[0], sizeof(prog_name) - 1);

  memset(hostname, 0, sizeof(hostname));
  gethostname(hostname, sizeof(hostname) - 1);

  run_mode = RUN_LIST;

  memset(app, 0, sizeof(app));
  strncpy(app, PACKAGE_NAME, sizeof(app) - 1);

  ref_data = NULL;
  ref_data_len = 0;

  for (i = 1; i < argc; i++) {
    if (0 == strcmp(argv[i], "-h") ||
        0 == strcmp(argv[i], "--help")) {
      program_usage();
      return (0);
    }
    if (0 == strcmp(argv[i], "-v") ||
       0 == strcmp(argv[i], "--version")) {
      program_version();
      return (0);
    }
    if (0 == strcmp(argv[i], "--gen")) {
      run_mode = RUN_GENERATE;
      continue;
    }
    if (0 == strcmp(argv[i], "--verify")) {
      run_mode = RUN_VERIFY;
      continue;
    }
    if (0 == strcmp(argv[i], "--host")) {
      if ((i+1) < argc && argv[i+1][0] != '-') {
        memset(hostname, 0, sizeof(hostname));
        strncpy(hostname, argv[i+1], sizeof(hostname) - 1);
        i++;
      }
      continue;
    }
    if (0 == strcmp(argv[i], "--context")) {
      if ((i+1) < argc && argv[i+1][0] != '-') {
        if (argv[i+1][0] == '@') {
          err = shfs_read_mem(argv[i+1] + 1, &ref_data, &ref_data_len);
          if (err) {
            fprintf(stderr, "%s: %s\n", argv[i+1] + 1, sherrstr(err));
            return (1);
          }
        } else {
          ref_data = strdup(argv[i+1]);
          ref_data_len = strlen(argv[i+1]);
        }
        i++;
      }
    }

    if (argv[i][0] != '-') {
      memset(app, 0, sizeof(app));
      strncpy(app, argv[i], sizeof(app) - 1);
      continue;
    }
  }

  proc_peer = shapp_init(prog_name, NULL, 0);

  if (!ref_data)
    ref_data = strdup("");

  app_peer = shpeer_init(app, NULL);
  app_key = shpeer_kpub(app_peer);

  tree = shfs_init(NULL);
  sprintf(path, "/peer/%s", shkey_print(app_key));
  file = shfs_file_find(tree, path);

  rec_nr = 0;
  k_list = NULL;
  buff = shbuf_init();
  err = shfs_read(file, buff);
  if (!err) {
    rec_nr = (shbuf_size(buff) / sizeof(peerstore_t));
    k_list = (peerstore_t **)calloc(rec_nr + 1, sizeof(peerstore_t *));
    for (i = 0; i < rec_nr; i++) {
      k_list[i] = (peerstore_t *)(shbuf_data(buff) + (sizeof(peerstore_t) * i));
    }
  }
  shbuf_free(&buff);

  /* read pending peer messages. .*/
  shpeer_msg_poll();

  printf ("App: %s (\"%s\")\n", shkey_print(app_key), app);
  shpeer_msg_push(app_peer);

  ret_code = 0;
  switch (run_mode) {
    case RUN_LIST:
      if (k_list) {
        for (i = 0; k_list[i]; i++) {
          print_peer_store(k_list[i]);
        }
      }
      break;

    case RUN_GENERATE:
      /* initialize peerstore record */
      memset(&key_data, 0, sizeof(key_data));
      key_data.birth = shtime();

      peer = shpeer_init(app, hostname);
      memcpy(&key_data.peer, peer, sizeof(shpeer_t));
      printf("Generated peer %s\n", shpeer_print(peer));
      shpeer_msg_push(peer);
      shpeer_free(&peer);

      /* generate key referencing context data. */
      ref_key = shkey_bin(ref_data, ref_data_len);
      memcpy(&key_data.context, ref_key, sizeof(shkey_t)); 
      shkey_free(&ref_key);

      /* create new peerstore list */
      rec_nr++;
      sv_list = (peerstore_t *)calloc(rec_nr, sizeof(peerstore_t));
      if (k_list) {
        for (i = 0; k_list[i]; i++)
          memcpy(&sv_list[i], k_list[i], sizeof(peerstore_t));
      }
      memcpy(&sv_list[i], &key_data, sizeof(peerstore_t));

      /* write peerstore list to share file */
      buff = shbuf_init();
      shbuf_cat(buff, sv_list, sizeof(peerstore_t) * rec_nr);
      err = shfs_write(file, buff);
      shbuf_free(&buff);
      if (err) {
        fprintf(stderr, "%s: %s\n", path, sherrstr(err));
        ret_code = 1;
      }

      break;

    case RUN_VERIFY:
      if (k_list) {
        ref_key = shkey_bin(ref_data, ref_data_len);
        for (i = 0; k_list[i]; i++) {
          if (0 == memcmp(ref_key, &k_list[i]->context, sizeof(shkey_t))) {
            print_peer_store(k_list[i]);
            break; /* found matching key */
          }
        }
        shkey_free(&ref_key);
      }

      if (!k_list || !k_list[i]) {
        /* context is not referenced in key-store. */
        printf ("No matching context was found.\n");
        ret_code = 1;
      } else {
        printf ("The context was verified successfully.\n");
      }
      break;
  }

  shfs_free(&tree);
  shpeer_free(&app_peer);
  shpeer_free(&proc_peer);
  free(ref_data);

  return (ret_code);
}
