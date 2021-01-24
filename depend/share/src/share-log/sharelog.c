
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
#include "sharelog.h"
#include <sys/signal.h>

char process_path[PATH_MAX + 1];
char process_file_path[PATH_MAX + 1];
char process_outfile_path[PATH_MAX + 1];
char process_socket_host[PATH_MAX + 1];
int proc_mode;

void print_process_version(void)
{
  char *app_name = shfs_app_name(process_path);
  printf (
      "%s version %s\n"
      "\n"
      "Copyright 2014 Neo Natura\n"
      "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n",
      app_name, VERSION); 
}

void print_process_usage(void)
{
  printf (
      "%s: Command-line tool for the Share Library.\n"
      "\n"
      "Usage: %s [OPTION] [<app>]\n"
      "\n"
      "Options:\n"
      "\t--help\t\t\t\tShows program usage instructions.\n"
      "\t--version\t\t\tShows program version.\n"
      "\t-f\t\t\toutput appended data as the log grows\n"
/*
      "\t--nosync\t\t\tDo not write outside of the base directory.\n"
      "\t-b<dir>[=\$HOME/.share]\t\tSpecifies the base directory to use for sharefs.\n"
      "\t-d<host>[=localhost]\t\tSpecifies a network hostname.\n"
      "\t-p<port>\t\t\tSpecifies a ipv4/6 socket port number.\n"
      "\t-f<path>\t\t\tSpecifies a input file path.\n"
      "\t-o<path>\t\t\tSpecifies a output file path.\n"
*/
      "\n"
      "Visit 'https://sharelib.net/libshare/' for more information.\n"
      "See 'man libshare' for additional manuals on the Share Library.\n",
      get_libshare_title(), process_path);
}

int sharelog_list(shpeer_t *peer, time_t stime, time_t etime)
{
  shbuf_t *buff;
  fd_set read_fd;
  shjson_t *json;
  char tbuf[256];
  char *data;
  time_t now;
  char *str;
  int err;
  int fd;

  fd = shconnect_host("127.0.0.1", PROCESS_PORT, SHNET_ASYNC);
  if (fd < 0)
    return (fd);

  json = shjson_init(NULL);
  shjson_num_add(json, "id", 1);
  shjson_str_add(json, "method", "log.list");
  shjson_str_add(json, "key", (char *)shkey_print(shpeer_kpub(peer)));
  shjson_null_add(json, "params");

  str = shjson_print(json);
  shjson_free(&json);

  err = shnet_write(fd, str, strlen(str));
  free(str);
  if (err < 0) {
    shclose(fd);
    return (err);
  }

  err = shnet_write(fd, "\n", 1);
  if (err < 0) {
    shclose(fd);
    return (err);
  }

  while (1) {
    FD_ZERO(&read_fd);
    FD_SET(fd, &read_fd);
    err = shnet_verify(&read_fd, NULL, NULL);
    if (err < 0) {
      continue;
    }

    buff = shnet_read_buf(fd);
    if (!buff)
      break;

    data = shbuf_data(buff);
    if (!strchr(data, '\n'))
      continue;

    json = shjson_init(data);
    if (json) {
      char *text = shjson_astr(json, "result", NULL);
      if (text) {
        printf("%s", text);
      }
      shjson_free(&json);
    }

    break;
  }

  shclose(fd);

  return (0);
}

int sharelog_tail(shpeer_t *peer)
{
  shbuf_t *buff;
  fd_set read_fd;
  shjson_t *json;
  char tbuf[256];
  time_t stime, etime;
  time_t now;
  char *str;
  int err;
  int fd;

  fd = shconnect_host("127.0.0.1", PROCESS_PORT, SHNET_ASYNC);
  if (fd < 0)
    return (fd);

  json = shjson_init(NULL);
  shjson_num_add(json, "id", 1);
  shjson_str_add(json, "method", "log.subscribe");
  shjson_str_add(json, "key", (char *)shkey_print(shpeer_kpub(peer)));
  shjson_null_add(json, "params");

  str = shjson_print(json);
  shjson_free(&json);

  err = shnet_write(fd, str, strlen(str));
  free(str);
  if (err < 0) {
    shclose(fd);
    return (err);
  }

  err = shnet_write(fd, "\n", 1);
  if (err < 0) {
    shclose(fd);
    return (err);
  }

  while (proc_mode == RUN_TAIL) {
    FD_ZERO(&read_fd);
    FD_SET(fd, &read_fd);
    err = shnet_verify(&read_fd, NULL, NULL);
    if (err < 0) {
      continue;
    }

    buff = shnet_read_buf(fd);
    if (!buff || shbuf_size(buff) == 0)
      continue;

    json = shjson_init(shbuf_data(buff));
    if (json) {
      char *text = shjson_astr(json, "result", NULL);
      if (text) {
        now = time(NULL);
        strftime(tbuf, sizeof(tbuf) - 1, "%D %T", localtime(&now));
        printf("[%s] %s", tbuf, text);
      }
    }

    shbuf_clear(buff);
  }

  shclose(fd);

  return (0);
}

int main(int argc, char **argv)
{
  shpeer_t *app_peer;
  time_t stime, etime;
  time_t now;
  char subcmd[256];
  char **args;
  char app_name[256];
  int i;

  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  strncpy(process_path, argv[0], PATH_MAX);

  proc_mode = RUN_NONE;

  /* handle traditional arguments */
  for (i = 1; i < argc; i++) {
    if (0 == strcmp(argv[i], "--version") ||
        0 == strcmp(argv[i], "-v")) {
      print_process_version();
      return (0);
    }
    if (0 == strcmp(argv[i], "--help") ||
        0 == strcmp(argv[i], "-h")) {
      print_process_usage();
      return (0);
    }
  }


  memset(app_name, 0, sizeof(app_name));
  for (i = 1; i < argc; i++) {
    if (0 == strcmp(argv[i], "-f")) {
      proc_mode = RUN_TAIL;
      continue;
    }

    if (argv[i][0] == '-') {
      continue;
    }

    strncpy(app_name, argv[i], sizeof(app_name) - 1);
    if (proc_mode == RUN_NONE)
      proc_mode = RUN_LIST;
  }

  app_peer = shpeer_init(app_name, NULL);

  now = time(NULL);
  stime = etime = now;
  switch (proc_mode) {
    case RUN_NONE:
      print_process_usage();
      break;

    case RUN_LIST:
      sharelog_list(app_peer, stime, etime);
      break;

    case RUN_TAIL:
      sharelog_list(app_peer, now, now);
      sharelog_tail(app_peer);
      break;
  }

  shpeer_free(&app_peer);

	return (0);
}


