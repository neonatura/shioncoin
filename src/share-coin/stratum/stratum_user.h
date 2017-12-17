
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



#ifndef __STRATUM__USER_H__
#define __STRATUM__USER_H__


#ifdef __cplusplus
extern "C" {
#endif

const char *get_user_flag_label(int flag);

#ifdef __cplusplus
}
#endif


user_t *stratum_user(user_t *user, char *username);

double stratum_user_speed(user_t *user);

user_t *stratum_user_init(int fd);

void stratum_user_block(user_t *user, double share_diff);

user_t *stratum_user_get(int fd);

void stratum_user_free(user_t *f_user);

int stratum_user_broadcast_task(task_t *task, task_attr_t *attr);


#endif /* __STRATUM__USER_H__ */

