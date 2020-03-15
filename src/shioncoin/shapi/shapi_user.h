
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

#ifndef __SHAPI__USER_H__
#define __SHAPI__USER_H__


#ifdef __cplusplus
extern "C" {
#endif

const char *get_user_flag_label(int flag);

extern shapi_t *shapi_client_list;

#ifdef __cplusplus
}
#endif

shapi_t *shapi_user_init(int fd);

shapi_t *shapi_user_get(int fd);

void shapi_user_free(shapi_t *f_user);


#endif /* __SHAPI__USER_H__ */

