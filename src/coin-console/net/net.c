
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

#include "shcon.h"

static int _client_socket;

int net_json_send(shjson_t *j)
{
  shbuf_t *buff;
  char *text;
  int err;

  if (_client_socket == 0) {
    int sk = net_conn();
    if (sk < 0)
      return (sk);

    _client_socket = sk;
  }

  text = shjson_print(j);
  if (!text)
    return (SHERR_INVAL);
  buff = shbuf_init();
  shbuf_catstr(buff, text);
  shbuf_catstr(buff, "\n");
  free(text);

//fprintf(stderr, "DEBUG: NET_JSON_SEND:\n%s\n", text);
  err = net_write(_client_socket, buff);
  shbuf_free(&buff);
  if (err)
    return (err);

  return (0);
}

#ifndef SHERR_PROTO
#define SHERR_PROTO -EPROTO
#endif

int net_json_recv(shjson_t **json_p)
{
  shbuf_t *buff;
  shjson_t *j;
  int err;

  if (json_p)
    *json_p = NULL;

  buff = shbuf_init();
  err = net_readline(_client_socket, buff);
  if (err) {
    shbuf_free(&buff);
    return (err);
  }
//fprintf(stderr, "DEBUG: NET_JSON_RECV:\n%s\n", shbuf_data(buff));

  j = shjson_init((char *)shbuf_data(buff));
  shbuf_free(&buff);
  if (!j) {
    return (SHERR_PROTO);
}

  if (json_p) {
    *json_p = j;
  } else {
    shjson_free(&j);
  }

  return (0);
}

int shcon_net_init(void)
{
  return (0);
}

void shcon_net_term(void)
{

  if (_client_socket == 0)
    return;

  shclose(_client_socket);
  _client_socket = 0;
}
