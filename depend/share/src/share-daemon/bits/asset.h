
/*
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
 */

#ifndef __BITS__ASSET_H__
#define __BITS__ASSET_H__


const char *asset_type_label(int type);

int txop_asset_init(shpeer_t *cli_peer, tx_asset_t *asset);
int txop_asset_confirm(shpeer_t *cli_peer, tx_asset_t *asset);


#endif /* ndef __BITS__ASSET_H__ */

