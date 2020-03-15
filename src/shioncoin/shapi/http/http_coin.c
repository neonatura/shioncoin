
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
#include "stratum/stratum.h"
#include <math.h>
#include "coin_proto.h"


void http_coin_iface_blurb(httpreq_t *req, int ifaceIndex)
{
	CIface *iface = GetCoinByIndex(ifaceIndex);
	http_t *http = req->h;
	shbuf_t *buff = req->buff;
	shjson_t *args = req->args;
	char html[1024];
	double speed;
	double diff;
	unsigned long max_coins;
	int height;
	int idx;
	const char *json_str;
	shjson_t *json;
			
	json_str = getmininginfo(ifaceIndex);
	json = shjson_init(json_str);
	if (!json)
		return;

	sprintf(html, "<td><div class=\"item\"><div class=\"title\">Coin</div><div class=\"value\">%s</div></div></td>\r\n", iface->name);
	shbuf_catstr(buff, html);

	height = shjson_array_num(json, "result", 0);
	if (height >= 0) {
		sprintf(html, "<td><div class=\"item\"><div class=\"title\">Block Height</div><div class=\"value\">%d</div></div></td>\r\n", height);
		shbuf_catstr(buff, html);
	}

	diff = shjson_array_num(json, "result", 1);
	if (diff >= 0.0) {
		sprintf(html, "<td><div class=\"item\"><div class=\"title\">Difficulty</div><div class=\"value=\">%-4.4f</div></div></td>\r\n", diff);
		shbuf_catstr(buff, html);
	}

	speed = shjson_array_num(json, "result", 2) / 1000000;
	if (speed > 0.0) {
		sprintf(html, "<td><div class=\"item\"><div class=\"title\">Net Speed</div><div style=\"value\">%-3.3fmh/s</div></div></td>\r\n", speed);
		shbuf_catstr(buff, html);
	}


	max_coins = (iface->max_money / COIN);
	if (max_coins > 0) {
		sprintf(html, "<td><div class=\"item\"><div class=\"title\">Max Coins</div><div class=\"value\">%lu</div></div></td>\r\n", max_coins);
		shbuf_catstr(buff, html);
	}

	shjson_free(&json);

}
void http_coin_blurb(httpreq_t *req)
{
	CIface *iface;
	shbuf_t *buff = req->buff;
	int idx;

	shbuf_catstr(buff,
			"<table cellspacing=2 class=\"list\">"
			"<tr class=\"listheader\"><td>Coin</td><td>Height</td><td>Difficulty</td><td>Net Speed</td><td>Max Coins</td></tr>");

	for (idx = 0; idx < MAX_COIN_IFACE; idx++) {
		if (idx == COLOR_COIN_IFACE) continue; /* handled seperately */
		iface = GetCoinByIndex(idx);
		if (!iface || !iface->enabled) continue;

		shbuf_catstr(buff, "<tr>\r\n");
		http_coin_iface_blurb(req, idx);
		shbuf_catstr(buff, "</tr>\r\n");
	}

	shbuf_catstr(buff, "</table>\r\n");


}

void http_coin_content(httpreq_t *req)
{
	http_t *http = req->h;
	shbuf_t *buff = req->buff;
	shjson_t *args = req->args;
	shjson_t *jblock;
	shjson_t *j;
	char prevhash[256];
	char html[1024];
	char tbuf[256];
	char *block;
	time_t t;
	int idx;

	shbuf_catstr(buff,
			"<table cellspacing=2 class=\"list\">"
			"<tr class=\"listheader\"><td>Coin</td><td>Height</td><td>Difficulty</td><td>Net Speed</td><td>Max Coins</td></tr>");
	http_coin_iface_blurb(req, SHC_COIN_IFACE);
	shbuf_catstr(buff, "</table>");


	shbuf_catstr(buff,
			"<table cellspacing=2 class=\"list\">"
//			"<tr style=\"background-color : rgba(128,128,128,0.5); color : #eee;\"><td>Coin</td><td>Height</td><td>Difficulty</td><td>Net Speed</td><td>Max Coins</td></tr>");
			);

	block = getlastblockinfo(SHC_COIN_IFACE, 0);
	for (idx = 0; idx < 10 && block; idx++) {
		jblock = shjson_init(block); 
		if (!jblock)
			break;

		j = shjson_obj(jblock, "result");

		memset(prevhash, 0, sizeof(prevhash));
		strncpy(prevhash, shjson_str(j, "previousblockhash", ""), sizeof(prevhash));

#if 0

		sprintf(html, "<div class=\"item\">Hash: %s</div>\r\n", 
				shjson_str(j, "hash", ""));
		shbuf_catstr(buff, html);

		sprintf(html, "<div class=\"item\">Height: %u</div>\r\n", 
				(unsigned int)shjson_num(j, "height", 0));
		shbuf_catstr(buff, html);

		sprintf(html, "<div class=\"item\">Amount: %-8.8f</div>\r\n", 
				shjson_num(j, "amount", 0));
		shbuf_catstr(buff, html);

		sprintf(html, "<div class=\"item\">Size: %-3.3fkb</div>\r\n", 
				shjson_num(j, "amount", 0) / 1000);
		shbuf_catstr(buff, html);

		t = (time_t)shjson_num(j, "time", 0);
		memset(tbuf, 0, sizeof(tbuf));
		strftime(tbuf, sizeof(tbuf), "%x %T", gmtime(&t));
		sprintf(html, "<div class=\"item\">Time: %s</div>\r\n", tbuf); 
		shbuf_catstr(buff, html);

		sprintf(html, "<div class=\"item\">Difficulty: %-4.4f</div>\r\n", 
				shjson_num(j, "difficulty", 0));
		shbuf_catstr(buff, html);

		sprintf(html, "<div class=\"item\">Tx's: %u</div>\r\n", 
				(unsigned int)shjson_array_count(j, "tx"));
		shbuf_catstr(buff, html);

#endif

		shbuf_catstr(buff, "<tr>\r\n");
		http_print_values(j, buff);
		shbuf_catstr(buff, "</tr>\r\n");

		shjson_free(&jblock);

		/* iterate to previous block. */
		block = getblockinfo(SHC_COIN_IFACE, prevhash);
	}

	shbuf_catstr(buff, "</table>");

}


