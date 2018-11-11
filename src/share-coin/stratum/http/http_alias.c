
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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

#include "shcoind.h"
#include "stratum/stratum.h"
#include <math.h>
#include "coin_proto.h"

extern const char *getaliaslist(int ifaceIndex);

void http_alias_list(httpreq_t *req)
{
	const char *json;
	shjson_t *list;
	shjson_t *j;

	json = getaliaslist(SHC_COIN_IFACE);
	j = shjson_init(json);
	if (!j)
		return;

	list = shjson_obj(j, "result");
	list = shjson_obj(list, "alias");
	if (!list)
		return;

	shbuf_catstr(req->buff,
			"<table cellspacing=2 class=\"list\">"
			"<tr class=\"listheader\"><td>Label</td><td>Expire</td><td>Addr</td><td>Type</td></tr>");

	for (j = list->child; j; j = j->next) {
		shjson_num_add(j, "version", 0);
		shjson_num_add(j, "type", 0);
		shbuf_catstr(req->buff, "<tr>");
		http_print_values(j, req->buff);
		shbuf_catstr(req->buff, "</tr>");
	}

	shbuf_catstr(req->buff, "</table>");

}

void http_alias_blurb(httpreq_t *req)
{

	http_alias_list(req);

}

void http_alias_content(httpreq_t *req)
{
	
	http_alias_list(req);

}



