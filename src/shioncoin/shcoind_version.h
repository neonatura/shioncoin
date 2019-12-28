
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

#ifndef __SHCOIND_VERSION_H__
#define __SHCOIND_VERSION_H__

#include <string.h>

#define DISK_VERSION_MAJOR       SHC_VERSION_MAJOR
#define DISK_VERSION_MINOR       SHC_VERSION_MINOR
#define DISK_VERSION_REVISION    SHC_VERSION_REVISION
#define DISK_VERSION_BUILD       SHC_VERSION_BUILD

#define DISK_VERSION \
    COIN_IFACE_VERSION(SHC_VERSION_MAJOR, SHC_VERSION_MINOR, \
      SHC_VERSION_REVISION, SHC_VERSION_BUILD)

#define CLIENT_VERSION DISK_VERSION

/* client version of network node for particular coin service */
#define IFACE_VERSION(_iface) \
  ((_iface)->client_ver)


//
// network protocol versioning
//

#define PROTOCOL_VERSION(_iface) \
  ((_iface)->proto_ver)

#endif
