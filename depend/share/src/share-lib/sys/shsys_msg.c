
/*
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
*/  

#include <sys/msg.h>
#include <sys/mman.h>
#include "share.h"





static shkey_t _message_peer_key;
static shmap_t *_message_peer_map;
static int _message_peer_ref;

static unsigned char *_message_queue[MAX_MESSAGE_QUEUES];
static FILE *_message_queue_fl[MAX_MESSAGE_QUEUES];

static void shmsg_peer_set(int msg_qid, shpeer_t *peer)
{
  /* map peer <-> message queue id */
  if (!_message_peer_map)
    _message_peer_map = shmap_init();
  shmap_set_void(_message_peer_map, ashkey_num(msg_qid), shpeer_kpub(peer), sizeof(shkey_t));
  _message_peer_ref++;
}

static shkey_t *shmsg_peer_get(int msg_qid)
{
  return ((shkey_t *)shmap_get_void(_message_peer_map, ashkey_num(msg_qid)));
}

unsigned char *shmsg_queue_init(int q_idx)
{
  struct stat st;
  unsigned char *ret_data;
  char path[PATH_MAX+1];
  int err;

  sprintf(path, "%s/msg", get_libshare_path());
  mkdir(path, 0777);
  sprintf(path+strlen(path), "/%x", (unsigned int)q_idx);

  err = stat(path, &st);
  if (err) {
    FILE *fl;
    char *ptr;

    ptr = (char *)calloc(1, MESSAGE_QUEUE_SIZE);
    if (!ptr)
      return (NULL);

    fl = fopen(path, "wb");
    if (!fl)
      return (NULL);

    fwrite(ptr, MESSAGE_QUEUE_SIZE, 1, fl);
    fclose(fl);

    chmod(path, 0777);
    free(ptr);
  }

  _message_queue_fl[q_idx] = fopen(path, "rb+");
  if (!_message_queue_fl[q_idx])
    return (NULL);

  ret_data = mmap(NULL, MESSAGE_QUEUE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fileno(_message_queue_fl[q_idx]), 0);
  if (ret_data == MAP_FAILED) { 
    fclose(_message_queue_fl[q_idx]);
    _message_queue_fl[q_idx] = NULL;
    return (NULL);
  }

  return (ret_data);
}

void shmsg_queue_free(int q_idx)
{

  q_idx = (q_idx % MAX_MESSAGE_QUEUES);
  if (q_idx < 0 || q_idx >= MAX_MESSAGE_QUEUES)
    return;

  if (_message_queue[q_idx]) {
    munmap(_message_queue[q_idx], MESSAGE_QUEUE_SIZE);
    _message_queue[q_idx] = NULL;
  }

  if (_message_queue_fl[q_idx]) {
    fclose(_message_queue_fl[q_idx]);
    _message_queue_fl[q_idx] = 0;
  }

  if (_message_peer_map)
    shmap_unset(_message_peer_map, ashkey_num(q_idx));

  _message_peer_ref = MAX(0, _message_peer_ref - 1);
  if (_message_peer_ref == 0)
    shmap_free(&_message_peer_map);

}

static shmsgq_t *shmsg_queue_map(int msg_qid)
{
  int q_idx;

  q_idx = (msg_qid % MAX_MESSAGE_QUEUES);
  if (!_message_queue[q_idx])
    _message_queue[q_idx] = shmsg_queue_init(q_idx);

  return ((shmsgq_t *)_message_queue[q_idx]);
}

int shmsg_lock(shmsgq_t *hdr)
{
  shtime_t t;

  t = shtime();
  if (hdr->lock_t) {
    if (hdr->lock_t > t)
      return (SHERR_AGAIN);
  }

  hdr->lock_t = shtime_adj(t, 1.0); /* one second timeout */
  return (0);
}

void shmsg_unlock(shmsgq_t *hdr)
{
  hdr->lock_t = 0;
}

shmsg_t *shmsg_write_map(shmsgq_t *map)
{
  shmsg_t *msg;
  size_t start_idx;
  size_t end_idx;
  size_t idx;

  start_idx = map->write_idx;
  end_idx = map->read_idx;

  msg = NULL;
  if (map->read_idx <= map->write_idx) {
    for (idx = map->write_idx; idx < MAX_MESSAGES_PER_QUEUE; idx++) {
      msg = &map->msg[idx];
      if (shkey_is_blank(&msg->src_key))
        goto done;
    }
    for (idx = 0; idx < map->read_idx; idx++) {
      msg = &map->msg[idx];
      if (shkey_is_blank(&msg->src_key))
        goto done;
    }
  } else {
    for (idx = map->write_idx; idx <= map->read_idx; idx++) {
      msg = &map->msg[idx];
      if (shkey_is_blank(&msg->src_key))
        goto done;
    }
  }

  if (!(map->flags & SHMSGF_OVERFLOW))
    return (NULL); /* full */

  /* 'overflow' onto next slot */
  idx = map->read_idx;
  msg = &map->msg[idx];
  map->read_idx = (idx + 1) % MAX_MESSAGES_PER_QUEUE;
  map->read_of = msg->msg_of + msg->msg_size;

done:
  map->write_idx = (idx + 1) % MAX_MESSAGES_PER_QUEUE;
  memset(msg, 0, sizeof(shmsg_t));

  return (msg);
}

int shmsg_write_map_data(shmsgq_t *map, shmsg_t *msg, shbuf_t *msg_buff)
{
  size_t start_of;
  size_t end_of;
  size_t max_len;
  size_t msg_size;
  int reset;

  max_len = MESSAGE_QUEUE_SIZE - sizeof(shmsgq_t);
  msg_size = shbuf_size(msg_buff);

  start_of = map->write_of;
  if (map->write_of >= map->read_of) {
    end_of = MESSAGE_QUEUE_SIZE - sizeof(shmsgq_t);
    reset = TRUE;
  } else {
    end_of = map->read_of;
    reset = FALSE;
  }

  if (reset && (end_of - start_of) < msg_size) {
    start_of = 0;
    end_of = map->read_of;
  }

  if ((end_of - start_of) < msg_size) {
    /* message too big */
    return (SHERR_AGAIN);
  }
  
  /* append message content */
  map->write_of = start_of + msg_size; 
  memcpy((char *)map->data + start_of, shbuf_data(msg_buff), msg_size);
  msg->msg_size = msg_size;
  msg->msg_of = start_of;

  return (0);
}

int shmsgsnd(int msqid, const void *msgp, size_t msgsz)
{
  shbuf_t *buff;
  int err;

  if (!msgp)
    return (SHERR_INVAL);

  buff = shbuf_map((unsigned char *)msgp, msgsz);
  err = shmsg_write(msqid, buff, NULL);
  free(buff);

  return (err);
}

int shmsg_write(int msg_qid, shbuf_t *msg_buff, shkey_t *dest_key)
{
  shmsg_t *msg;
  shmsg_t *msg_n;
  shmsgq_t *map;
  shkey_t *src_key;
  size_t msg_size;
  size_t of;
  int err;

  src_key = &_message_peer_key;

  msg_size = shbuf_size(msg_buff);
  if (msg_size >= (MESSAGE_QUEUE_SIZE - sizeof(shmsgq_t)))
    return (SHERR_INVAL); /* can only do so much */

  map = shmsg_queue_map(msg_qid);
  if (!map)
    return (SHERR_INVAL);

  err = shmsg_lock(map);
  if (err)
    return (err);

  /* obtain a message slot. note: updates 'map->write_idx'. */
  msg = shmsg_write_map(map);
  if (!msg) {
    shmsg_unlock(map);
    return (SHERR_AGAIN); /* no space avail */
  }

  /* source peer */
  memcpy(&msg->src_key, src_key, sizeof(shkey_t));

  /* destination peer */
  if (dest_key)
    memcpy(&msg->dest_key, dest_key, sizeof(shkey_t));
  else
    memcpy(&msg->dest_key, shmsg_peer_get(msg_qid), sizeof(shkey_t));

  /* write definition contents of message */
  msg->msg_qid = msg_qid; 

  /* write data contents of message */
  err = shmsg_write_map_data(map, msg, msg_buff);
  if (err) {
    memcpy(&msg->src_key, ashkey_blank(), sizeof(shkey_t));
    shmsg_unlock(map);
    return (err);
  }

  shmsg_unlock(map);
  return (0);
}

_TEST(shmsgsnd)
{
  shpeer_t *peer;
  char cmp_buf[1024];
  char buf[1024];
  int err;
  int id;
  int i;

  peer = shpeer();
  id = shmsgget(peer);

  shmsgctl(id, SHMSGF_ANONYMOUS, 1);
  shmsgctl(id, SHMSGF_OVERFLOW, 0); 
  //shmsgctl(id, SHMSGF_TRUNCATE, 0); 

  for (i = 0; i < MAX_MESSAGES_PER_QUEUE; i++) {
    memset(buf, 'a' + (i % 8), sizeof(buf)); 
    err = shmsgsnd(id, buf, sizeof(buf));
    _TRUE(0 == err);
  }

  err = shmsgsnd(id, buf, sizeof(buf));
  _TRUE(SHERR_AGAIN == err);

  for (i = 0; i < MAX_MESSAGES_PER_QUEUE; i++) {
    memset(buf, 0, sizeof(buf));
    memset(cmp_buf, 'a' + (i % 8), sizeof(cmp_buf)); 
  
    err = shmsgrcv(id, (unsigned char *)buf, sizeof(buf));
    _TRUE(sizeof(buf) == err);
    err = memcmp(cmp_buf, buf, 1024);
    _TRUE(0 == err);
  }

  err = shmsgrcv(id, buf, sizeof(buf));
  _TRUE(SHERR_NOMSG == err);

  shmsgctl(id, SHMSGF_OVERFLOW, 1); 
  for (i = 0; i < MAX_MESSAGES_PER_QUEUE; i++)
    _TRUE(0 == shmsgsnd(id, buf, sizeof(buf)));
  _TRUE(0 == shmsgsnd(id, buf, sizeof(buf)));

  for (i = 0; i < MAX_MESSAGES_PER_QUEUE; i++) {
    err = shmsgrcv(id, buf, 0);
    _TRUE(0 == err);
  }
 
  shmsg_queue_free(id);
  shpeer_free(&peer);
}

int shmsg_read_valid(shmsg_t *msg, int msg_qid, shkey_t *dest_key)
{

  if (shkey_is_blank(&msg->src_key))
    return (FALSE);

  if (msg->msg_size == 0)
    return (FALSE);

  /* verify message is destined for self. */
  if (dest_key && !shkey_cmp(dest_key, &msg->dest_key))
    return (FALSE);

  return (TRUE);
}

/** Scan a range of messages for readable content. */
shmsg_t *shmsg_read_map(shmsgq_t *map, int msg_qid, shkey_t *dest_key)
{
  int start_of;
  int end_of;
  int idx;

  if (!map)
    return (NULL);

  start_of = map->read_idx;
  end_of = map->write_idx;
  if (end_of <= start_of) {
    for (idx = start_of; idx < MAX_MESSAGES_PER_QUEUE; idx++) {
      if (shmsg_read_valid(&map->msg[idx], msg_qid, dest_key)) {
//        map->read_idx = (idx+1) % MAX_MESSAGES_PER_QUEUE;
        return (&map->msg[idx]);
      }
    }
    for (idx = 0; idx < end_of; idx++) {
      if (shmsg_read_valid(&map->msg[idx], msg_qid, dest_key)) {
//        map->read_idx = (idx+1) % MAX_MESSAGES_PER_QUEUE;
        return (&map->msg[idx]);
      }
    }
  } else {
    for (idx = start_of; idx < end_of; idx++) {
      if (shmsg_read_valid(&map->msg[idx], msg_qid, dest_key)) {
//        map->read_idx = (idx+1) % MAX_MESSAGES_PER_QUEUE;
        return (&map->msg[idx]);
      }
    }
  }

  return (NULL);
}

int shmsgrcv(int msqid, void *msgp, size_t msgsz)
{
//  int trunc_flag = (msgflg == MSG_NOERROR);
  unsigned char *msg_data = (unsigned char *)msgp;
  shbuf_t *buff;
  size_t len;
  int err;

  if (!msgp)
    return (SHERR_INVAL);

  buff = shbuf_init();
  err = shmsg_read(msqid, NULL, buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }

  len = MIN(shbuf_size(buff), msgsz);
  memcpy(msg_data, shbuf_data(buff), len);
  shbuf_free(&buff);

  return (len);
}

int shmsg_read(int msg_qid, shkey_t *src_key, shbuf_t *msg_buff)
{
  shmsg_t *msg;
  shmsgq_t *map;
  shkey_t *dest_key;
  size_t msg_size;
  size_t len;
  size_t of;
  size_t max_len;
  int ret_len;
  int idx;
  int err;

  /* obtain message queue */
  map = shmsg_queue_map(msg_qid);
  if (!map)
    return (SHERR_INVAL);

  if (map->flags & SHMSGF_ANONYMOUS) {
    dest_key = NULL;
  } else {
    /* only read messages not marked with our own peer key */
    dest_key = &_message_peer_key;
  }

  err = shmsg_lock(map);
  if (err)
    return (err);

  /* obtain a message */
  msg = shmsg_read_map(map, msg_qid, dest_key);
  if (!msg) {
    shmsg_unlock(map);
    return (SHERR_NOMSG);
  }

  /* iterate index */
  map->read_idx = (map->read_idx + 1) % MAX_MESSAGES_PER_QUEUE;
  if (msg->msg_of == map->read_of) {
    map->read_of += msg->msg_size;
  }

  /* fill content for caller */
  if (msg_buff)
    shbuf_cat(msg_buff, (char *)map->data + msg->msg_of, msg->msg_size);
  if (src_key)
    memcpy(src_key, &msg->src_key, sizeof(shkey_t));

  /* clean up */
  memcpy(&msg->src_key, ashkey_blank(), sizeof(shkey_t));
  shmsg_unlock(map);

  return (0);
}

/**
 * @param peer destination message queue 
 */
int shmsgget(shpeer_t *peer)
{
  shpeer_t *src_peer;
  shmsgq_t *map;
  unsigned char q_key[256];
  int q_id;

  if (peer) {
    q_id = (int)(shcrc(shpeer_kpub(peer), sizeof(shkey_t)) % INT_MAX);
    shmsg_peer_set(q_id, peer);
  } else {
    /* libshare daemon. */
    peer = shpeer_init("shared", NULL);
    q_id = (int)(shcrc(shpeer_kpub(peer), sizeof(shkey_t)) % INT_MAX);
    shmsg_peer_set(q_id, peer);
    shpeer_free(&peer);
  }

  src_peer = shpeer();
  memcpy(&_message_peer_key, shpeer_kpub(src_peer), sizeof(shkey_t));
  shpeer_free(&src_peer);

  return (q_id);
}

int shmsgctl(int msg_qid, int cmd, int value)
{
  shmsgq_t *map;

  switch (cmd) {
    case SHMSGF_RMID:
      shmsg_queue_free(msg_qid);
      break;

    case SHMSGF_OVERFLOW:
      map = shmsg_queue_map(msg_qid);
      if (!map)
        break;
      if (value)
        map->flags |= SHMSGF_OVERFLOW;
      else
        map->flags &= ~SHMSGF_OVERFLOW;
      break;

#if 0
    case SHMSGF_TRUNCATE:
      map = shmsg_queue_map(msg_qid);
      if (!map)
        break;
      if (value)
        map->flags |= SHMSGF_TRUNCATE;
      else
        map->flags &= ~SHMSGF_TRUNCATE;
      break;
#endif
  }

}


