
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

#ifndef __SHAPI__PROTOCOL_H__
#define __SHAPI__PROTOCOL_H__

#ifdef __cplusplus
extern "C" {
#endif


int shapi_request_message(shapi_t *user, shjson_t *json);

int shapi_send_template(shapi_t *user, int clean);

int shapi_set_difficulty(shapi_t *user, int diff);

void set_shapi_error(shjson_t *reply, int code, char *str);

int shapi_validate_submit(shapi_t *user, shjson_t *json);

int shapi_send_message(shapi_t *user, shjson_t *msg);


#ifdef __cplusplus
}
#endif

#endif /* __SHAPI__PROTOCOL_H__ */

