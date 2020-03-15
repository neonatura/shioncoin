
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
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

#ifndef __HTTP__HTTP_H__
#define __HTTP__HTTP_H__



void http_coin_blurb(httpreq_t *req);

void http_coin_content(httpreq_t *req);

void http_fractal_validate_cb(httpreq_t *req);

void http_matrix_validate_content(httpreq_t *req);

void http_matrix_validate_blurb(httpreq_t *req);

void http_fractal_spring_cb(httpreq_t *req);

void http_matrix_spring_content(httpreq_t *req);

void http_matrix_spring_blurb(httpreq_t *req);

void http_pool_blurb(httpreq_t *req);

void http_pool_content(httpreq_t *req);

void http_print_values(shjson_t *obj, shbuf_t *buff);

void http_alias_blurb(httpreq_t *req);

void http_alias_content(httpreq_t *req);

void http_context_blurb(httpreq_t *req);

void http_context_content(httpreq_t *req);


#endif /* ndef #define __HTTP__HTTP_H__ */

