
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
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <fcntl.h>
#undef fcntl

static shproc_t *child_proc;
static shproc_pool_t *_proc_pool;
static sighandler_t *_shproc_signal_handler;

static shproc_pool_t *shproc_pool_init(void)
{
  shproc_pool_t *pool;
  struct rlimit rlim;
  char buf[256];

  pool = (shproc_pool_t *)calloc(1, sizeof(shproc_pool_t));
  if (!pool)
    return (NULL);

  /* soft -> hard fd max / process */
  memset(&rlim, 0, sizeof(rlim));
  getrlimit(RLIMIT_NOFILE, &rlim);
  rlim.rlim_cur = MAX(rlim.rlim_cur, rlim.rlim_max);
  if (rlim.rlim_cur > 0)
    setrlimit(RLIMIT_NOFILE, &rlim);

  /* allocate enough slots for spawned workers */
  getrlimit(RLIMIT_NOFILE, &rlim);
  rlim.rlim_cur = MAX(rlim.rlim_cur, 1024);
  pool->pool_lim = rlim.rlim_cur;
  pool->proc = (shproc_t *)calloc(pool->pool_lim, sizeof(shproc_pool_t));

  /* maximum number of processes spawned at once. */
  pool->pool_max = SHPROC_POOL_DEFAULT_SIZE; /* default */

  /* set spawned process with same priority by default */
  pool->pool_prio = getpriority(PRIO_PROCESS, 0);

  sprintf(buf, "shproc_pool_init: initialized new pool #%x (max %d, limit %d).\n", pool, pool->pool_max, pool->pool_lim);
  shinfo(buf);

  return (pool);
}

shproc_pool_t *shproc_init(shproc_op_t req_f, shproc_op_t resp_f)
{
  shproc_pool_t *pool;

  pool = shproc_pool_init(); 
  pool->pool_req = req_f;
  pool->pool_resp = resp_f;

  _proc_pool = pool;
  return (pool);
}

int shproc_conf(shproc_pool_t *pool, int type, int val)
{

  if (type == SHPROC_MAX) {
    if (!val) {
      /* get */
      return (pool->pool_max);
    }

    /* set */
    pool->pool_max = MAX(1, MIN(pool->pool_lim, val));
    /* note: realloc is 'allowed' to return NULL albiet not handled here. */
    pool->proc = (shproc_t *)realloc(pool->proc,
        (size_t)(pool->pool_max * sizeof(shproc_t)));
  } else if (type == SHPROC_PRIO) {
    /* process priority level */
    if (!val) {
      /* get */
      return (pool->pool_prio);
    }

    pool->pool_prio = val;
  }

  return (0);
}

shproc_pool_t *shproc_pool(void)
{
  return (_proc_pool);
}

static void shproc_nonblock(int fd)
{
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

void shproc_signal(void *sig_f)
{
  _shproc_signal_handler = (sighandler_t *)&sig_f;
}

static void shproc_worker_signal(int sig_num)
{
  shbuf_free(&child_proc->proc_buff);
  close(child_proc->proc_fd);
  child_proc = NULL;

  /* user-supplied signal handler for spawned worker process */
  if (_shproc_signal_handler)
    (*_shproc_signal_handler)(sig_num);

  exit(0);
}

static void shproc_state_set(shproc_t *proc, int state)
{
  int ostate = proc->proc_state;

  if (state < 0 || state >= MAX_SHPROC_STATES)
    return;

  if (proc->proc_state == state)
    return;

  if (proc->proc_stamp) {
    proc->stat.span_tot[ostate] += (shtimef(shtime()) - shtimef(proc->proc_stamp));
    proc->stat.span_cnt[ostate]++;
  }

  proc->proc_stamp = shtime();
  proc->proc_state = state;
}

static int shproc_worker_main(shproc_t *proc)
{
  
  while (1) {
    shproc_child_poll(proc); 
  }

}

void shproc_rlim_set(void)
{
  struct rlimit rlim;

  /* set hard limit for 'max number of file descriptors' */
  memset(&rlim, 0, sizeof(rlim));
  getrlimit(RLIMIT_NOFILE, &rlim);
  rlim.rlim_cur = rlim.rlim_max;
  if (rlim.rlim_cur > 0)
    setrlimit(RLIMIT_NOFILE, &rlim);

  /* set hard limit for 'max data allocation' */
  memset(&rlim, 0, sizeof(rlim));
  getrlimit(RLIMIT_DATA, &rlim);
  rlim.rlim_cur = rlim.rlim_max;
  if (rlim.rlim_cur > 0)
    setrlimit(RLIMIT_DATA, &rlim);

  /* set hard limit for 'max cpu usage' */
  memset(&rlim, 0, sizeof(rlim));
  getrlimit(RLIMIT_CPU, &rlim);
  rlim.rlim_cur = rlim.rlim_max;
  if (rlim.rlim_cur > 0)
    setrlimit(RLIMIT_CPU, &rlim);

}

uint64_t shproc_rlim(int mode)
{
  struct rlimit rlim;
  int err;

  /* set hard limit for 'max number of file descriptors' */
  memset(&rlim, 0, sizeof(rlim));
  err = getrlimit(mode, &rlim);
  if (err == -1)
    return (errno2sherr());

  return (rlim.rlim_cur);
}

static int shproc_fork(shproc_t *proc)
{
  int dgram_fds[2];
  int fds[2];
  int server_sd;
  int worker_sd;
  int err;

  if (proc->proc_state != SHPROC_NONE)
    return (0);

  socketpair(PF_LOCAL, SOCK_STREAM, 0, fds);

  socketpair(AF_UNIX, SOCK_DGRAM, 0, dgram_fds);
  server_sd = dgram_fds[0];
  worker_sd = dgram_fds[1];
 
  err = fork();
  switch (err) {
    case 0:
      /* spawned worker */
      child_proc = proc;
      close(fds[0]);
      proc->proc_fd = fds[1];

      close(server_sd);
      proc->dgram_fd = worker_sd;

      shproc_nonblock(fds[1]);
      shproc_state_set(proc, SHPROC_IDLE);
      signal(SIGQUIT, shproc_worker_signal);
      setpriority(PRIO_PROCESS, 0, proc->proc_prio);
      shproc_rlim_set();

      /* process worker requests */
      shproc_worker_main(proc);
      exit (0); /* never returns */

    case -1:
      /* fork failure */
      shproc_state_set(proc, SHPROC_NONE);
      return (errno2sherr());

    default:
      /* parent process */
      close(fds[1]);
      proc->proc_fd = fds[0];

      close(worker_sd);
      proc->dgram_fd = server_sd;

      shproc_nonblock(fds[0]);
      proc->proc_pid = err;
      shproc_state_set(proc, SHPROC_IDLE);
      break;
  }

  return (0);
}

shproc_t *shproc_start(shproc_pool_t *pool)
{
  shproc_t *proc;
  int err;

  if (child_proc)
    return (NULL); /* invalid */

  proc = shproc_get(pool, SHPROC_NONE); 
  if (!proc)
    return (NULL); /* nut'n avail */

  /* used by spawn worker */
  proc->proc_req = pool->pool_req;
  proc->proc_resp = pool->pool_resp;
  proc->proc_prio = pool->pool_prio;
  /* used by parent and spawn */
  proc->proc_buff = shbuf_init();

  /* fire new one up */
  err = shproc_fork(proc);
  if (err)
    return (NULL);

  return (proc);
}

int shproc_stop(shproc_t *proc)
{
  int err;

  if (child_proc)
    return (SHERR_INVAL);

  if (proc->proc_pid == 0)
    return (SHERR_INVAL);

  if (proc->proc_state == SHPROC_NONE)
    return (0); /* all done */

  err = kill(proc->proc_pid, SIGQUIT);  
  if (err)
    return (err);

  shproc_state_set(proc, SHPROC_NONE);

  shbuf_free(&proc->proc_buff);

  close(proc->proc_fd);
  close(proc->dgram_fd);

  proc->proc_fd =  proc->proc_pid = 0;
  proc->dgram_fd = 0;

  return (0);
}

double shproc_stat_avg(shproc_t *proc)
{
  int type = proc->proc_state;
  if (proc->stat.span_cnt[type] == 0)
    return (0);
  return (proc->stat.span_tot[type] / (double)proc->stat.span_cnt[type]);
}


shproc_t *shproc_get(shproc_pool_t *pool, int state)
{
  shproc_t *proc;
  int i;

  if (child_proc)
    return (NULL);

  for (i = 0; i < pool->pool_max; i++) {
    if (pool->proc[i].proc_state == state) {
      proc = (pool->proc + i);

      return (proc);
    }
  }

  return (NULL);
}

/**
 * @param wait_t milliseconds to wait for process to send a message.
 */ 
int shproc_read_wait(shproc_t *proc, int wait_t)
{
  struct timeval to;
  fd_set in_set;
  int err;

  if (!proc)
    return (SHERR_INVAL);

  if (wait_t) {
    to.tv_sec = wait_t / 1000; 
    to.tv_usec = (wait_t % 1000) * 1000; 
  }

  /* full-blocking poll */
  FD_ZERO(&in_set);
  FD_SET(proc->proc_fd, &in_set);
  err = select(proc->proc_fd+1, &in_set, NULL, NULL, 
      !wait_t ? NULL /* blocking poll */ : &to /* semi-blocking */);
  if (err < 0)
    return (errno2sherr());

  return (0);
}

int shproc_write_wait(shproc_t *proc, int wait_t)
{
  struct timeval to;
  fd_set out_set;
  int err;

  if (!proc)
    return (SHERR_INVAL);

  to.tv_sec = wait_t / 1000; 
  to.tv_usec = ((wait_t % 1000) * 1000) + 1;

  /* full-blocking poll */
  FD_ZERO(&out_set);
  FD_SET(proc->proc_fd, &out_set);
  err = select(proc->proc_fd+1, NULL, &out_set, NULL, &to); 
  if (err < 0)
    return (errno2sherr());

  return (0);
}

static int shproc_write(shproc_t *proc, shproc_req_t *req)
{
  int w_len;
  int err;
  int of;

  req->data_len = shbuf_size(proc->proc_buff);
  req->crc = shcrc(shbuf_data(proc->proc_buff), shbuf_size(proc->proc_buff));
  err = write(proc->proc_fd, req, sizeof(shproc_req_t));
  if (err == -1) 
    return (errno2sherr());
  if (err == 0)
    return (SHERR_AGAIN);

  of = 0;
  while (of < shbuf_size(proc->proc_buff)) {
    /*
     * On i386 the buffer is 4096 and 65k otherwise. 
     * Parent is granted 100ms to 'poll' when size exceeds buffer limit.
     */
    err = shproc_write_wait(proc, 100);
    if (err)
      return (err);

    w_len = write(proc->proc_fd, 
        shbuf_data(proc->proc_buff) + of, 
        shbuf_size(proc->proc_buff) - of);
    if (w_len == -1)
      return (errno2sherr());
    if (w_len == 0)
      return (SHERR_AGAIN);

    of += w_len;
  }

  return (0);
}

int shproc_write_fd(shproc_t *proc, int fd)
{
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  struct msghdr parent_msg;
  int err;

  memset(&parent_msg, 0, sizeof(parent_msg));
  struct cmsghdr *cmsg;
  parent_msg.msg_control = cmsgbuf;
  parent_msg.msg_controllen = sizeof(cmsgbuf); // necessary for CMSG_FIRSTHDR to return the correct value
  cmsg = CMSG_FIRSTHDR(&parent_msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
  memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
  parent_msg.msg_controllen = cmsg->cmsg_len; // total size of all control blocks

  err = sendmsg(proc->dgram_fd, &parent_msg, 0);
  if (err == -1)
    return (errno2sherr());

  return (0);
}

int shproc_read_fd(shproc_t *proc)
{
  struct msghdr child_msg;
  struct cmsghdr *cmsg;
  int pass_sd;
  int err;


  memset(&child_msg,   0, sizeof(child_msg));
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  child_msg.msg_control = cmsgbuf; // make place for the ancillary message to be received
  child_msg.msg_controllen = sizeof(cmsgbuf);

  err = recvmsg(proc->dgram_fd, &child_msg, 0);
  cmsg = CMSG_FIRSTHDR(&child_msg);
  if (cmsg == NULL || cmsg -> cmsg_type != SCM_RIGHTS) {
    return (-1);
  }

  memcpy(&pass_sd, CMSG_DATA(cmsg), sizeof(pass_sd));
  return (pass_sd);
}

int shproc_schedule(shproc_t *proc, unsigned char *data, size_t data_len)
{
  shproc_req_t req;
  int err;

  if (!proc)
    return (SHERR_INVAL);

  shbuf_clear(proc->proc_buff);
  if (data && data_len)
    shbuf_cat(proc->proc_buff, data, data_len);

  memset(&req, 0, sizeof(req));
  req.state = SHPROC_RUN;
  req.user_fd = proc->user_fd;
  err = shproc_write(proc, &req);
  if (err) {
    return (err);
  }

  if (proc->user_fd)
    shproc_write_fd(proc, proc->user_fd);

  /* set process to pending state */
  shproc_state_set(proc, SHPROC_PEND);
  proc->stat.out_tot++;

  return (0);
}

static int shproc_read(shproc_t *proc)
{
  struct shproc_req_t req;
  struct timeval to;
  fd_set in_set;
  char buf[32768];
  int r_len;
  int err;
  int of;

  err = shproc_read_wait(proc, child_proc ? 1000 : 1);

  memset(&req, 0, sizeof(req));
  r_len = read(proc->proc_fd, &req, sizeof(req));
  if (r_len == -1 && errno != EAGAIN) {
    return (errno2sherr());
  }
  if (r_len != sizeof(req))
    return (1); /* nothing to read */

  if (!child_proc) {
    /* parent process */
    if (req.state == SHPROC_RUN || 
        req.state == SHPROC_IDLE) {
      shproc_state_set(proc, req.state);
    }
    proc->stat.in_tot++;
    if (req.state == SHPROC_IDLE) {
      proc->user_fd = 0;
    }
  } else {
    proc->user_fd = req.user_fd;
  }


  of = 0;
  shbuf_clear(proc->proc_buff);
  for (of = 0; of < req.data_len; of += r_len) {
    r_len = read(proc->proc_fd, buf, MIN(req.data_len-of, sizeof(buf)));
    if (r_len == -1)
      return (errno2sherr());
    if (r_len == 0)
      return (SHERR_AGAIN);

    shbuf_cat(proc->proc_buff, buf, r_len);
  }

  proc->proc_error = req.error;

  return (0);
}

int shproc_parent_poll(shproc_t *proc)
{
  struct timeval to;
  shbuf_t *sp_buf;
  fd_set in_set;
  int r_len;
  int err;

  if (proc->proc_pid == 0 || proc->proc_state == SHPROC_NONE)
    return (SHERR_INVAL);

  if (0 != kill(proc->proc_pid, 0)) {
    err = errno2sherr();
    shproc_stop(proc);
    return (err);
  }

  if (proc->proc_state == SHPROC_IDLE)
    return (0); /* spawn process is idle -- nothing to read */ 

  while ((err = shproc_read(proc)) == 0) {
    if (proc->proc_state != SHPROC_IDLE) {
      continue; /* not a response */
    }
    if (proc->proc_resp) {
      /* return response data to callback */
      (*proc->proc_resp)(proc->proc_error, proc->proc_buff);
    }
    proc->proc_error = 0;
  }
  if (err == 1)
    return (0); /* nothing to do */
  if (err)
    return (err);

  return (0);
}

void shproc_poll(shproc_pool_t *pool)
{
  int i;

  if (child_proc)
    return;

  for (i = 0; i < pool->pool_max; i++) {
    if (pool->proc[i].proc_state == SHPROC_NONE ||
        pool->proc[i].proc_state == SHPROC_IDLE)
      continue;

    shproc_parent_poll(pool->proc + i); 
  }

}

void shproc_shutdown(shproc_pool_t *pool)
{
  int i;

  if (child_proc)
    return;

  for (i = 0; i < pool->pool_max; i++) {
    if (pool->proc[i].proc_state == SHPROC_NONE)
      continue;

    shproc_stop(pool->proc + i); 
  }

}

int shproc_child_poll(shproc_t *proc)
{
  struct shproc_req_t req;
  struct timeval to;
  shbuf_t *sp_buf;
  fd_set in_set;
  int r_len;
  int err;
  int fd;

  err = shproc_read(proc);
  if (err == 1)
    return (0); /* nothing to do */
  if (err)
    return (err);

  memset(&req, 0, sizeof(req));
  /* spawned worker - data receieved as request */
  sp_buf = shbuf_clone(proc->proc_buff);

  memset(&req, 0, sizeof(req));
  req.state = SHPROC_RUN;
  shbuf_clear(proc->proc_buff);
  err = shproc_write(proc, &req);

  fd = 0;
  if (proc->user_fd) {
    fd = shproc_read_fd(proc);
  }

  err = 0;
  if (proc->proc_req) {
    err = (*proc->proc_req)(fd, sp_buf);
    /* user-result data */
    shbuf_append(sp_buf, proc->proc_buff);
  }
  if (fd != 0)
    close(fd);
  shbuf_free(&sp_buf);

  memset(&req, 0, sizeof(req));
  req.state = SHPROC_IDLE;
  req.error = err;
  err = shproc_write(proc, &req);

  proc->proc_idx++;
  shproc_state_set(proc, SHPROC_IDLE);
  shbuf_clear(proc->proc_buff);

  return (0);
}

static int _test_shproc_value[256];
static int _test_shproc_req(int fd, shbuf_t *buff)
{
  int val;

  if (!fd) {
    if (shbuf_size(buff) != sizeof(val)) {
      return (-1);
    }
    val = *((int *)shbuf_data(buff));
  } else {
    if (shbuf_size(buff) != 0) {
      return (-1);
    }
    lseek(fd, 0L, SEEK_SET);
    read(fd, &val, sizeof(int));
    close(fd);
  }

  _test_shproc_value[val] = -1;

  shbuf_clear(buff);
  shbuf_cat(buff, &val, sizeof(int));

  return (0);
}

static int _test_shproc_resp(int err_code, shbuf_t *buff)
{
  if (err_code == 0) {
    int val = *((int *)shbuf_data(buff));
    _test_shproc_value[val] = val+1;
  }
  return (0);
}

shproc_t *shproc_pull(shproc_pool_t *pool)
{
  shproc_t *p;

  p = shproc_get(pool, SHPROC_IDLE);
  if (!p)
    p = shproc_start(pool);

  return (p);
}

int shproc_push(shproc_pool_t *pool, int fd, unsigned char *data, size_t data_len)
{
  shproc_t *p;
  int i;

  if (child_proc)
    return (SHERR_INVAL);

  p = shproc_pull(pool);
  if (!p)
    return (SHERR_AGAIN);

  if (fd)
    shproc_setfd(p, fd);

  return (shproc_schedule(p, data, data_len));
}

void shproc_free(shproc_pool_t **pool_p)
{
  shproc_pool_t *pool;

  if (!pool_p)
    return;

  pool = *pool_p;
  *pool_p = NULL;

  if (!pool)
    return;

  free(pool->proc);
  free(pool);
}

void shproc_setfd(shproc_t *proc, int fd)
{
  proc->user_fd = fd;
}

int shproc_getfd(shproc_t *proc)
{
  return (proc->user_fd);
}


