
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

#ifndef __SHARELOG_SERVER_H__
#define __SHARELOG_SERVER_H__

#include "sharelog.h"

#define SKUSERF_BROADCAST (1 << 0)

typedef struct sock_t
{
  int fd;
  int flags;
  int bc_idx;
  struct sock_t *next;
} sock_t;


extern unsigned int process_socket_port;
extern unsigned int process_socket_fd;
extern char process_path[PATH_MAX + 1];
extern shpeer_t *proc_peer;
extern sock_t *client_list;

#define PROCESS_NAME "shlogd"
#define PROCESS_PORT 32071


int shlogd_main(int argc, char **argv);
void sharelog_server(int parent_pid);



#endif /* __SHARELOG_SERVER_H__ */

