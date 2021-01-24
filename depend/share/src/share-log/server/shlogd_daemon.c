
#include <share.h>
#include "sharelog_server.h"
#include <signal.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

void daemon_close_clients(void)
{
  sock_t *user;

  for (user = client_list; user; user = user->next) {
    if (user->fd == -1)
      continue;
    close(user->fd);
    user->fd = -1;
  }

}

void daemon_signal(int sig_num)
{
  signal(sig_num, SIG_DFL);

  daemon_close_clients();
  if (process_socket_fd != -1) {
    shclose(process_socket_fd);
    process_socket_fd = -1;
  }

  daemon_task_term();
}

sock_t *daemon_sock_init(int fd)
{
  sock_t *user;

  user = (sock_t *)calloc(1, sizeof(sock_t));
  user->fd = fd;

  return (user);
}

sock_t *register_client(int fd)
{
  sock_t *user;
  int err;

  err = shnet_fcntl(fd, F_SETFL, O_NONBLOCK);
  if (err) {
    shclose(fd);
    return (NULL);
  }

  user = daemon_sock_init(fd);
  user->next = client_list;
  client_list = user;

  return (user);
}

int register_client_task(sock_t *user, char *json_text)
{
  shjson_t *tree;
  int err;

  if (!*json_text) {
    return (0);
}

  tree = shjson_init(json_text);
  if (tree == NULL) {
    return (SHERR_INVAL);
  }

  err = daemon_request_task(user, tree);
  shjson_free(&tree);

  return (err);
}

#define SHLOGPREF_RETAIN_TIME "retain-time"
#define DEFAULT_SHLOG_RETAIN_TIME 7776000 /* 3 months */
long shlogd_retain_time;

/**
 * Establishes the global application preferences.
 */
void daemon_load_config(void)
{
  char *str;

  str = shpref_get(SHLOGPREF_RETAIN_TIME, NULL);
  if (!str)
    str = DEFAULT_SHLOG_RETAIN_TIME;
  shlogd_retain_time = atol(str);
    
}
void daemon_load_config_signal(int sig_num)
{
  daemon_load_config();
}

void daemon_server(int parent_pid)
{
  sock_t *peer;
  sock_t *peer_last;
  sock_t *peer_next;
  fd_set read_set;
  fd_set write_set;
shbuf_t *buff;
  char *data;
  size_t len;
  double work_t;
  double cur_t;
  int fd_max;
  int cli_fd;
  int fd;
  int err;

  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, daemon_signal);
  signal(SIGQUIT, daemon_signal);
  signal(SIGINT, daemon_signal);

  daemon_load_config();
  signal(SIGHUP, daemon_load_config_signal);

  daemon_task_init();
 
  work_t = shtime();
  while (process_socket_fd != -1) {
    double start_t, diff_t;
    struct timeval to;

    start_t = shtime();

    peer_last = NULL;
    for (peer = client_list; peer; peer = peer_next) {
      peer_next = peer->next;

      if (peer->fd != -1) {
        peer_last = peer;
        continue;
      }

      if (!peer_last) {
        client_list = peer_next;
      } else {
        peer_last->next = peer_next;
      }
      free(peer);
    }


    cli_fd = shnet_accept_nb(process_socket_fd);
    if (cli_fd < 0 && cli_fd != SHERR_AGAIN) {
      perror("shnet_accept");
    } else if (cli_fd > 0) {
      register_client(cli_fd);
    }

    for (peer = client_list; peer; peer = peer->next) {
      if (peer->fd == -1)
        continue;

      buff = shnet_read_buf(peer->fd);
      if (!buff) {
        shclose(peer->fd);
        peer->fd = -1;
        continue;
      }


      len = shbuf_idx(buff, '\n');
      if (len == -1)
        continue;
      data = shbuf_data(buff);
      data[len] = '\0';
      register_client_task(peer, data);
      shbuf_trim(buff, len + 1);
    }

    for (peer = client_list; peer; peer = peer->next) {
      if (peer->fd == -1)
        continue;

      /* flush writes */
      len = shnet_write_flush(peer->fd);
      if (len == -1) {
        perror("shnet_write");
        shclose(peer->fd);
        peer->fd = -1;
        continue;
      }
    }

    /* once per x1 seconds */
    cur_t = shtime();
    if (cur_t - 1.0 > work_t) {
      daemon_msg_poll();
      daemon_task_flush_pending();

      work_t = cur_t;
    }

    diff_t = (shtime() - start_t);
    diff_t = MAX(0, 20 - (diff_t * 1000));
    memset(&to, 0, sizeof(to));
    to.tv_usec = (1000 * diff_t);
    if (to.tv_usec > 1000) {
      select(1, NULL, NULL, NULL, &to);
    }

  }

}


