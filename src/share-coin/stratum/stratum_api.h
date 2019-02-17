
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura
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

#ifndef __STRATUM__API_H__
#define __STRATUM__API_H__

#ifdef __cplusplus
extern "C" {
#endif

extern void shjson_AddItemToArray(shjson_t *array, shjson_t *item);

shjson_t *stratum_request_api(int ifaceIndex, user_t *user, char *method, shjson_t *params, shjson_t *auth);


#ifdef __cplusplus
}
#endif

#endif /* __STRATUM__API_H__ */

