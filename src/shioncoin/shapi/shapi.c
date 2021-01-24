
/*
 * @copyright
 *
 *  Copyright 2015 Brian Burrell
 *
 *  This file is part of Shioncoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcoind.h"
#include "shapi.h"

int get_shapi_port(void)
{
  return (opt_num(OPT_SHAPI_PORT));
}

char *get_shapi_host(void)
{
  return (opt_str(OPT_SHAPI_HOST));
}


/**
 * Called when a new socket is accepted on the shcoind shapi port (default 9448).
 */
void shapi_accept(int fd, struct sockaddr *net_addr)
{
  sa_family_t in_fam;
  char buf[256];

  if (fd < 1 || !net_addr) {
    sprintf(buf, "shapi_accept: invalid fd/addr: fd(%d) net_addr(#%x)\n", fd, net_addr);
    shcoind_log(buf);
    return;
  }

  in_fam = *((sa_family_t *)net_addr);
  if (in_fam == AF_INET) {
    struct sockaddr_in *addr = (struct sockaddr_in *)net_addr;

    sprintf(buf, "shapi_accept: received connection (%s port %d).", inet_ntoa(addr->sin_addr), get_shapi_port());
    shcoind_log(buf);  
  } else {
    sprintf(buf, "shapi_accept: received connection (family %d)", in_fam);
    shcoind_log(buf);  
	}

  shapi_register_client(fd);
 
}

void shapi_close(int fd, struct sockaddr *net_addr)
{
  shapi_t *peer;

  if (fd < 0)
    return; /* invalid */

  for (peer = shapi_client_list; peer; peer = peer->next) {
    if (peer->fd == fd) {
      peer->fd = -1;
      break;
    }
  }
   
}

static void shapi_close_free(void)
{
  shapi_t *peer_next;
  shapi_t *peer_last;
  shapi_t *peer;
  time_t now;

  peer_last = NULL;
  now = time(NULL);
  for (peer = shapi_client_list; peer; peer = peer_next) {
    peer_next = peer->next;

    if (peer->fd == -1) {
      if (peer_last)
        peer_last->next = peer_next;
      else
        shapi_client_list = peer_next;
      free(peer);
      continue;
    }

    peer_last = peer;
  }
   
}

static void shapi_timer(void)
{
  unet_table_t *t;
  shapi_t *peer;
  shbuf_t *buff;
  char *data;
  size_t len;
  int err;

  for (peer = shapi_client_list; peer; peer = peer->next) {
    if (peer->fd == -1)
      continue;

    t = get_unet_table(peer->fd);
    if (!t) {
      continue;
    }

    buff = t->rbuff;
    if (!buff) continue;

    /* process incoming requests */
    len = shbuf_idx(buff, '\n');
    if (len == -1) {
			if (shbuf_size(buff) > MAX_SHAPI_MESSAGE_SIZE) {
				/* junk */
				shbuf_clear(buff);
			}
      continue;
		}
		if (len > MAX_SHAPI_MESSAGE_SIZE) {
			/* error.. */
			shbuf_trim(buff, len + 1);
			continue;
		}

		shbuf_lock(buff);
    data = shbuf_data(buff);
    len = stridx(data, '\n'); /* redundant */
    if (len == -1) { shbuf_unlock(buff); continue; }
    data[len] = '\0';
		data = strdup(data);
    shbuf_trim(buff, len + 1);
		shbuf_unlock(buff);

    if (*data == '{') {
			/* normal api request. */
			shapi_register_client_task(peer, data);
    }

		free(data);
  }

  shapi_close_free();

}

static void shapi_close_all(void)
{
  shapi_t *peer_next;
  shapi_t *peer;

  for (peer = shapi_client_list; peer; peer = peer_next) {
    peer_next = peer->next;

    if (peer->fd == -1)
			continue;

		descriptor_release(peer->fd);
		free(peer);
  }
  shapi_client_list = NULL;

}

void shapi_term(void)
{

	shapi_close_all(); /* close client sockets. */
  unet_unbind(UNET_SHAPI); /* close listening socket. */

}

shapi_t *shapi_register_client(int fd)
{
  shapi_t *user;
  int err;

  user = shapi_user_init(fd);
  user->next = shapi_client_list;
  shapi_client_list = user;

  return (user);
}

int shapi_register_client_task(shapi_t *user, char *json_text)
{
  shjson_t *tree;
  int err;

  if (!*json_text) {
    return (0);
  }

  tree = shjson_init(json_text);
  if (tree == NULL)
    return (SHERR_INVAL);

  err = shapi_request_message(user, tree);
  shjson_free(&tree);

  return (err);
}

int shapi_init(void)
{
  int err;

  err = unet_bind_esl(UNET_SHAPI, get_shapi_port(), get_shapi_host());
  if (err)
    return (err);

  unet_timer_set(UNET_SHAPI, shapi_timer); /* x1/s */
  unet_connop_set(UNET_SHAPI, shapi_accept);
  unet_disconnop_set(UNET_SHAPI, shapi_close);

  return (0);
}

shjson_t *shapi_json(const char *json_text)
{
  shjson_t *tree;
  char *text;

  if (!json_text)
    return (NULL);

  text = strdup(json_text);
  tree = shjson_init(text);
  free(text);
  if (!tree)
    return (NULL);

  return (tree);
}



