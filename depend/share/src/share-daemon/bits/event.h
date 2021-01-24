

/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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

#ifndef __BITS__EVENT_H__
#define __BITS__EVENT_H__

tx_event_t *alloc_event(shgeo_t *geo, shtime_t stamp, shkey_t *ctx_key);

int inittx_event(tx_event_t *event, shgeo_t *geo, shtime_t stamp, shkey_t *ctx_key);

int txop_event_init(shpeer_t *cli_peer, tx_event_t *event);
int txop_event_confirm(shpeer_t *cli_peer, tx_event_t *event);
int txop_event_send(shpeer_t *cli_peer, tx_event_t *event);
int txop_event_recv(shpeer_t *cli_peer, tx_event_t *event);

#if 0
/**
 * A trusted client is requesting a transaction be performed in the future.
 * @param duration The number of ms before the transaction will occur.
 */
int generate_event(tx_event_t *event, shpeer_t *peer, time_t duration);
#endif

#endif /* ndef __BITS__EVENT_H__ */

