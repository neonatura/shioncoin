
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

#ifndef __STRATUM__STRATUM_HTTP_H__
#define __STRATUM__STRATUM_HTTP_H__


#define MIME_HTML "text/html"
#define MIME_BMP "image/bmp"

#define HTTPF_DISABLE (1 << 0)


struct httpreq_t;
typedef void (*http_f)(struct httpreq_t *);

typedef struct http_t {
	char *page;
	char *title;
	char *mime;
	http_f f_content;
	http_f f_blurb;
	int flag;
} http_t;

typedef struct httpreq_t {
	http_t *h;
	shbuf_t *buff;
	shjson_t *args;
	int flag;
} httpreq_t;



#endif /* ndef __STRATUM__STRATUM_HTTP_H__ */
