
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
#include "sharelog_server.h"

unsigned int process_socket_port;
unsigned int process_socket_fd;
char process_path[PATH_MAX + 1];
shpeer_t *proc_peer;
sock_t *client_list;

#define PROCESS_NAME "shlogd"
#define PROCESS_PORT 32071

void sharelog_server(int parent_pid)
{
  unsigned int port = (unsigned int)process_socket_port;
  char buff[TEST_BUFFER_SIZE];
  ssize_t b_read, b_write;
  int cli_fd;
  int err;
  int fd;

  err = shfs_proc_lock(process_path, "");
  if (err) {
    printf ("Terminating.. '%s' server '%s' is already running.\n", "shlogd", process_path);
    return;
  }

  fd = shnet_sk();
  if (fd == -1) {
    perror("shsk");
    return;
  }
  
  err = shnet_bindsk(fd, NULL, port);
  if (err) {
    perror("shbindport");
    shclose(fd);
    return;
  }

  process_socket_fd = fd;
  daemon_server(parent_pid);

#if 0
  cli_fd = shnet_accept(fd);
  if (cli_fd == -1) {
    perror("shnet_accept");
    shclose(fd);
    return;
  }

  printf ("Received new connection on port %d.\n", port);

  memset(buff, 0, sizeof(buff));
  memset(buff, 'a', sizeof(buff) - 1);
  b_write = shnet_write(cli_fd, buff, sizeof(buff));
  if (b_write <= 0) {
    shclose(cli_fd);
    shnet_close(fd);
    perror("shnet_write");
return;
  }
  printf ("%d of %d bytes written to port %d on fd %d..\n", b_write, sizeof(buff), port, cli_fd); 

  memset(buff, 0, sizeof(buff));
  b_read = shnet_read(cli_fd, buff, sizeof(buff));
  if (b_read <= 0) {
    perror("shread");
    shnet_close(cli_fd);
    shnet_close(fd);
    return;
  }

  printf ("MESSAGE: %-*.*s\n", b_read, b_read, buff);
  printf ("%d of %d bytes read from port %d on fd %d..\n", b_read, sizeof(buff), port, cli_fd); 
  
  err = shnet_close(fd);
  if (err) {
    perror("shnet_close");
    shnet_close(cli_fd);
    shnet_close(fd);
    return;
  }

  shnet_close(cli_fd);
#endif

  shclose(fd);

}

int shlogd_main(int argc, char **argv)
{
  int err;
  int fd;

#ifdef SHLOGD_APPLICATION
  daemon(0, 1);
#endif

  strncpy(process_path, argv[0], PATH_MAX);
  proc_peer = shapp_init(PROCESS_NAME, NULL, SHAPP_LOCAL);

  process_socket_port = PROCESS_PORT; 

  fd = shnet_sk();
  if (fd == -1) {
    perror("shsk");
    return;
  }
  
  err = shnet_bindsk(fd, NULL, process_socket_port);
  if (err) {
    perror("shbindport");
    shclose(fd);
    return (err);
  }

  process_socket_fd = fd;

  daemon_server(0);

  shpeer_free(&proc_peer);
}

#ifdef SHLOGD_PROGRAM
int main(int argc, char **argv)
{
  return (shlogd_main(argc, argv));
}
#endif


