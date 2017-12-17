
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

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2013 usde Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef __USDE_NETMGSG_H__
#define __USDE_NETMGSG_H__



extern "C"
{
#ifdef GNULIB_NAMESPACE
#undef GNULIB_NAMESPACE
#endif
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
}


//extern map<uint256, CDataStream*> mapOrphanTransactions;
//extern map<uint256, CBlock*> mapOrphanBlocks;

bool usde_ProcessMessages(CIface *iface, CNode* pfrom);
bool usde_SendMessages(CIface *iface, CNode* pto, bool fSendTrickle);

bool usde_AddOrphanTx(const CDataStream& vMsg);

unsigned int usde_LimitOrphanTxSize(unsigned int nMaxOrphans);



#endif /* ndef __USDE_NETMGSG_H__ */
