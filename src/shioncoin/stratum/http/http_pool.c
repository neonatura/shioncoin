
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura
 *
 *  This file is part of ShionCoin.
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
#include "stratum/stratum.h"
#include <math.h>
#include "coin_proto.h"


void http_pool_blurb(httpreq_t *req)
{
  const int ifaceIndex = SHC_COIN_IFACE;
	shbuf_t *buff = req->buff;
  user_t *user;
	char html[4096];

  shbuf_catstr(buff, 
      "<table cellspacing=2 class=\"list\">\r\n"
      "<tr class=\"listheader\"><td>User</td><td>Speed</td><td>Shares</td><td>Submits</td></tr>");
  for (user = client_list; user; user = user->next) {
    if (!*user->worker)
      continue;

    sprintf(html,
        "<tr><td><div class=\"item\"><div class=\"title\">User</div><div class=\"value\">%s</div></div></td>\r\n"
        "<td><div class=\"item\"><div class=\"title\">Speed</div><div class=\"value\">%-2.2f</div></div></td>\r\n"
        "<td><div class=\"item\"><div class=\"title\">Shares</div><div class=\"value\">%-8.8f</div></div></td>\r\n"
        "<td><div class=\"item\"><div class=\"title\">Submits</div><div class=\"value\">%u</div></div></td></tr>\r\n",
        user->worker, stratum_user_speed(user),
        user->block_tot, (unsigned int)user->block_cnt);
    shbuf_catstr(buff, html);
  }
  shbuf_catstr(buff, "</table>\r\n");


}

void http_pool_content(httpreq_t *req)
{
	shbuf_t *buff = req->buff;
	char html[4096];

	http_pool_blurb(req);

}


