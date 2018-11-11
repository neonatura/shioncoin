
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

extern const char *getcontextlist(int ifaceIndex);

void http_context_list(httpreq_t *req)
{
	const char *json;
	shjson_t *list;
	shjson_t *j;

	json = getcontextlist(SHC_COIN_IFACE);
	j = shjson_init(json);
	if (!j)
		return;

	list = shjson_obj(j, "result");
	if (!list) {
		shjson_free(&j);
		return;
	}

	shbuf_catstr(req->buff,
			"<table cellspacing=2 class=\"list\">"
			"<tr class=\"listheader\"><td>Label</td><td>Expire</td><td>Signature</td><td>Hash</td><td>Size</td><td>CRC</td></tr>");

	for (j = list->child; j; j = j->next) {
		shjson_num_add(j, "version", 0);
		shjson_num_add(j, "type", 0);
		shjson_num_add(j, "flags", 0);
		shbuf_catstr(req->buff, "<tr>");
		http_print_values(j, req->buff);
		shbuf_catstr(req->buff, "</tr>");
	}

	shbuf_catstr(req->buff, "</table>");

	shjson_free(&j);
}

void http_context_blurb(httpreq_t *req)
{

	http_context_list(req);

}

void http_context_content(httpreq_t *req)
{
	
	http_context_list(req);

}



