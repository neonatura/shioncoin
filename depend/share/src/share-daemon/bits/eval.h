
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
 *
 *  @file ward.h
 */

#ifndef __BITS__EVAL_H__
#define __BITS__EVAL_H__



int inittx_eval(tx_eval_t *eval, tx_event_t *event, tx_context_t *ctx, uint64_t user_id, shnum_t value);

tx_eval_t *alloc_eval(tx_event_t *event, tx_context_t *ctx, uint64_t user_id, shnum_t value);


int txop_eval_init(shpeer_t *cli_peer, tx_eval_t *eval);

int txop_eval_confirm(shpeer_t *peer, tx_eval_t *eval);

int txop_eval_send(shpeer_t *peer, tx_eval_t *eval);

int txop_eval_recv(shpeer_t *peer, tx_eval_t *eval);



#endif /* ndef __BITS__EVAL_H__ */

