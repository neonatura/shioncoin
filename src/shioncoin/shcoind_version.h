// Copyright (c) 2012 The Bitcoin developers
// Copyright (c) 2012 Litecoin Developers
// Copyright (c) 2013 usde Developers
// Copyright (c) 2013 usde Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef __SHCOIND_VERSION_H__
#define __SHCOIND_VERSION_H__

#include <string.h>

//
// client versioning
//

#if 0
// These need to be macro's, as version.cpp's voodoo requires it
#define CLIENT_VERSION_MAJOR       1
#define CLIENT_VERSION_MINOR       0
#define CLIENT_VERSION_REVISION    4
#define CLIENT_VERSION_BUILD       0

static const int CLIENT_VERSION =
                           1000000 * CLIENT_VERSION_MAJOR
                         +   10000 * CLIENT_VERSION_MINOR 
                         +     100 * CLIENT_VERSION_REVISION
                         +       1 * CLIENT_VERSION_BUILD;
#endif




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
//static const int PROTOCOL_VERSION = 1000400;

// earlier versions not supported as of Feb 2012, and are disconnected
static const int MIN_PROTO_VERSION = 209;

// nTime field added to CAddress, starting with this version;
// if possible, avoid requesting addresses nodes older than this
static const int CADDR_TIME_VERSION = 31402;

// only request blocks from nodes outside this range of versions
static const int NOBLKS_VERSION_START = 32000;
static const int NOBLKS_VERSION_END = 32400;

// BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

#endif
