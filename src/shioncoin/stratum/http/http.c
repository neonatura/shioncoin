
/*
 * @copyright
 *
 *  Copyright 2018 Brian Burrell
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
#include "stratum/stratum.h"
#include <math.h>
#include "coin_proto.h"


void http_print_values(shjson_t *obj, shbuf_t *buff)
{
	shjson_t *j;
	char html[4096];
	char buf[64];
	unsigned int ival;

	for (j = obj->child; j; j = j->next) {
		switch (j->type) {
			case SHJSON_STRING:
				if (!j->valuestring || !*j->valuestring)
					break;
				if (strlen(j->valuestring) >= 32) {
					memset(buf, 0, sizeof(buf));
					strncpy(buf, j->valuestring, 32);
					sprintf(html, "<td><div class=\"item\"><div class=\"title\">%s</div><div class=\"value\" title=\"%s\"><small>%s..</small></div></div></td>\r\n", j->string, j->valuestring, buf);
				} else {
					sprintf(html, "<td><div class=\"item\"><div class=\"title\">%s</div><div class=\"value\">%s</div></div></td>\r\n", j->string, j->valuestring);
				}
				shbuf_catstr(buff, html);
				break;
			case SHJSON_NUMBER:
				ival = shjson_num(obj, j->string, 0);
				if ((double)ival != shjson_num(obj, j->string, 0)) {
					/* real */
					sprintf(html, "<td><div class=\"item\"><div class=\"title\">%s</div><div class=\"value\">%f</div></div></td>\r\n", j->string, shjson_num(obj, j->string, 0));
					shbuf_catstr(buff, html);
				} else if (ival != 0) {
					/* intregal */
					sprintf(html, "<td><div class=\"item\"><div class=\"title\">%s</div><div class=\"value\">%u</div></div></td>\r\n", j->string, ival);
					shbuf_catstr(buff, html);
				}
				break;
			case SHJSON_TRUE:
				sprintf(html, "<td><div class=\"item\"><div class=\"title\">%s</div><div class=\"value\">True</div></div></td>\r\n", 
						j->string);
				shbuf_catstr(buff, html);
				break;
			case SHJSON_FALSE:
				sprintf(html, "<td><div class=\"item\"><div class=\"title\">%s</div><div class=\"value\">False</div></div></td>\r\n", 
						j->string);
				shbuf_catstr(buff, html);
				break;
		}
	}

}
