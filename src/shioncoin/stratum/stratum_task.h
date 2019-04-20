
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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

#ifndef __STRATUM__TASK_H__
#define __STRATUM__TASK_H__

/**
 * Maximum time-span before a task assigned to a stratum client expires.
 */
#define MAX_TASK_LIFESPAN 100 


/** */
void task_free(task_t **task_p);

/** */
task_t *stratum_task(unsigned int task_id);

int is_stratum_task_pending(int *ret_iface);

void stratum_task_gen(task_attr_t *attr);

task_t *task_init(task_attr_t *attr);

void stratum_task_weight(task_attr_t *attr);



#endif /* __STRATUM__TASK_H__ */

