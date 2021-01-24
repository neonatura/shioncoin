
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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

#include <stdio.h>
#include <string.h>

#include "config.h"
#include "share.h"

#define EXAMPLE_PORT 48981

char prog_name[PATH_MAX+1];
int run_state;
shkey_t *eslkey;

/**
 * Displays the program's version information to the command console.
 */
void program_version(void)
{
  printf ("%s version %s (%s)\n"
      "\n"
      "Copyright 2016 Neo Natura\n"
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
      "usage: esl_server [-k <key>]\n"
      "\n"
      "\t-k <key>\tSpecify a ESL key for server authentification.\n"
      "\n"
      "Example of utilizing the Encrypted Socket Protocol.\n"
      "\n"
      "Visit 'http://www.sharelib.net/' for more information.\n",
      prog_name, PACKAGE_VERSION, PACKAGE_NAME, prog_name);
}

void main_esl_server(int sk)
{
  shbuf_t *r_buff;
  fd_set r_set;
  ssize_t b_len;
  char raw_data[8192];
  uint32_t raw_len;
  int l_sk;
  int err;
  int of;

  l_sk = esl_accept(sk);
  if (l_sk < 0) {
    sleep(1);
    return;
  }

  FD_ZERO(&r_set);
  FD_SET(l_sk, &r_set);
  err = shnet_verify(&r_set, NULL, NULL);

  /* read file size from socket */
  raw_len = 0;
  err = esl_read(l_sk, &raw_len, sizeof(raw_len));
  if (err == 0) {
    FD_ZERO(&r_set);
    FD_SET(l_sk, &r_set);
    shnet_verify(&r_set, NULL, NULL);

    err = esl_read(l_sk, &raw_len, sizeof(raw_len));
  }
  raw_len = ntohl(raw_len);
  if (!raw_len) {
    shnet_close(l_sk);
    run_state = FALSE;
    return;
  }
  printf("info: reading %d bytes from socket.\n", raw_len);

  /* read file from socket */
  of = 0;
  r_buff = shbuf_init();
  while (of < raw_len) {
    b_len = esl_read(l_sk, raw_data, sizeof(raw_data));
    if (b_len < 0) {
      fprintf(stderr, "error: read failure: %s; closing socket.\n", sherrstr(b_len));
      shnet_close(l_sk);
      run_state = FALSE;
      return;
    }
    shbuf_cat(r_buff, raw_data, b_len); 
    of += b_len;   
  }
  printf("info: read %d byte file from socket.\n", raw_len);

  /* write file to socket */
  b_len = esl_write(l_sk, shbuf_data(r_buff), shbuf_size(r_buff));
  if (b_len < 0) {
    fprintf(stderr, "error: socket write failure: %s.\n", sherrstr(b_len));
    shnet_close(l_sk);
    run_state = FALSE;
    return;
  }

  shnet_close(l_sk);

  run_state = FALSE;
}

int main(int argc, char *argv[])
{
  char *app_name;
  shpeer_t *app_peer;
  shpeer_t *serv_peer;
  char opt_key[1024];
  shkey_t *eslkey;
  int opt_port = EXAMPLE_PORT;
  int err;
  int sk;
  int i;

  memset(opt_key, 0, sizeof(opt_key));

  app_name = shfs_app_name(argv[0]);
  strncpy(prog_name, app_name, sizeof(prog_name));
  for (i = 1; i < argc; i++) {
    if (*argv[i] == '-') {
      if (0 == strcmp(argv[i], "-v") ||
          0 == strcmp(argv[i], "--version")) {
        program_version();
        return (0);
      }
      if (0 == strcmp(argv[i], "-h") ||
          0 == strcmp(argv[i], "--help")) {
        program_usage();
        return (0);
      }
      if (0 == strcmp(argv[i], "-k") ||
          0 == strcmp(argv[i], "--key")) {
        i++;
        if (i < argc)
          strncpy(opt_key, argv[i], sizeof(opt_key)-1);
      }
      continue;
    }
  }


  app_peer = shapp_init(app_name, NULL, 0);


  sk = esl_bind(opt_port);
  if (sk < 0) {
fprintf(stderr, "error: unable to bind to port %d.\n", opt_port);
    exit(1);
  }

  if (*opt_key) {
    eslkey = shkey_str(opt_key);
    esl_key_set(sk, eslkey);
printf("info: using ESL key \"%s\".\n", shkey_print(eslkey));
    shkey_free(&eslkey);
  }

  run_state = TRUE;
  while (run_state) {
    main_esl_server(sk);
  }

  shnet_close(sk);
  shpeer_free(&app_peer);
  return (0);
}


