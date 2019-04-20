
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#ifndef __STRATUM__PROTOCOL_H__
#define __STRATUM__PROTOCOL_H__

#ifdef __cplusplus
extern "C" {
#endif


int stratum_request_message(user_t *user, shjson_t *json);

int stratum_send_template(user_t *user, int clean);

int stratum_set_difficulty(user_t *user, int diff);

void set_stratum_error(shjson_t *reply, int code, char *str);

int stratum_validate_submit(user_t *user, shjson_t *json);


#ifdef __cplusplus
}
#endif

#endif /* __STRATUM__PROTOCOL_H__ */

