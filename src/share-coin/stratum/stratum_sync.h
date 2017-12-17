
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

#ifndef __STRATUM__STRATUM_SYNC_H__
#define __STRATUM__STRATUM_SYNC_H__


void stratum_sync_init(void);

/**
 * 1. periodically review (every hour via 'wallet.list') to determine if tracked accounts have changed, and if so, sends as 'wallet.listaddr' to find out what coin addrs are missing locally. when coin addr(s) are found missing a 'wallet.setkey' is performed to add the missing entry.
 * 2. A duplicate set of workers is periodically (10min via "stratum.list") created locally in order to mirror the remote work.
 *
 * @note The coin server will only reward coins mined by it's own mining address.
 */
void stratum_sync(void);

user_t *stratum_find_netid(shkey_t *netid, char *worker);


#endif /* ndef __STRATUM__STRATUM_SYNC_H__ */


