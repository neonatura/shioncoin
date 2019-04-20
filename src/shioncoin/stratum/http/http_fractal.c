
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


void http_fractal_cb(httpreq_t *req)
{
	http_t *h = req->h;
	shbuf_t *buff = req->buff;
	shjson_t *args = req->args;
  FILE *fl;
  struct stat st;
  double x_of, y_of, zoom;
  double span;
  char *bmp_path;
  char tag[256];
  char *data;
  char str[256];
  char *ptr;
  int err;

	zoom = MAX(0.001, shjson_num(args, "zoom", 1.0));
	x_of = shjson_num(args, "x", 0.0);
	y_of = shjson_num(args, "y", 0.0);
	span = MAX(0.2, MIN(2.0, shjson_num(args, "span", 1.0)));

  x_of = floor(x_of / 8) * 8;
  y_of = floor(y_of / 8) * 8;

  sprintf(tag, "%s:%f,%f,%f,%f", h->page, zoom, span, x_of, y_of);
  bmp_path = shcache_path(tag);
  if (!shcache_fresh(tag)) {
		(void)unlink(bmp_path);
		if (0 == strcmp(h->page, "/i/spring.bmp"))
			spring_render_fractal(bmp_path, zoom, span, x_of, y_of);
		else if (0 == strcmp(h->page, "/i/validate.bmp"))
			validate_render_fractal(SHC_COIN_IFACE, bmp_path, zoom, span, x_of, y_of);
	}
  stat(bmp_path, &st);

  (void)shfs_mem_read(bmp_path, buff);
}

void http_fractal_validate_cb(httpreq_t *req)
{
	http_fractal_cb(req);
}

void http_fractal_spring_cb(httpreq_t *req)
{
	http_fractal_cb(req);
}


