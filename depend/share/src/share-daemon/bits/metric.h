

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
 *  @file metric.h
 */

#ifndef __BITS__METRIC_H__
#define __BITS__METRIC_H__

int inittx_metric(tx_metric_t *met, int type, void *data, size_t *data_len);

tx_metric_t *alloc_metric(int type, void *data, size_t *data_len);

int txop_metric_init(shpeer_t *cli_peer, tx_metric_t *met);

int txop_metric_confirm(shpeer_t *cli_peer, tx_metric_t *met);

int txop_metric_send(shpeer_t *cli_peer, tx_metric_t *met);

int txop_metric_recv(shpeer_t *cli_peer, tx_metric_t *met);


#endif /* ndef __BITS__METRIC_H__ */
