
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura 
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
 *
 *  @file schedule.h
 */

#ifndef __BITS__SCHEDULE_H__
#define __BITS__SCHEDULE_H__


/**
 * A rotating log of tasks to perform.
 */
//extern sh_task_t schedule[MAX_SCHEDULE_TASKS];

/**
 * The current rotating log task index.
 */
//extern sh_task_index;


void sched_tx_payload(shkey_t *dest_key, void *data, size_t data_len, void *payload, size_t payload_len);

/**
 * Transmit a transaction to a specific peer.
 */
void sched_tx_sink(shkey_t *priv, void *data, size_t data_len);

/**
 * Broadcast a network transaction.
 */
void sched_tx(void *data, size_t data_len);


#endif /* ndef __BITS__SCHEDULE_H__ */



