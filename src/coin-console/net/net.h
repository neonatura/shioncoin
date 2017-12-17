
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

#ifndef __COIN_CONSOLE__NET_H__
#define __COIN_CONSOLE__NET_H__


/** The maximum seconds, by default, to wait for a response after a command is requested. */
#define DEFAULT_COMMAND_WAIT 300


/** Send a JSON message to the server. */
int net_json_send(shjson_t *j);

/** Receive a JSON response from the server. */
int net_json_recv(shjson_t **json_p);


int shcon_net_init(void);

void shcon_net_term(void);

int net_conn(void);

void net_close(int sk);

int net_read(int sk, shbuf_t *buff);

int net_read_lim(int sk, shbuf_t *buff, double wait);

int net_readline(int sk, shbuf_t *buff);

int net_readline_lim(int sk, shbuf_t *buff, double wait);

int net_write(int sk, shbuf_t *buff);

int net_write_lim(int sk, shbuf_t *buff, double wait);



#endif /* ndef __COIN_CONSOLE__NET_H__ */


