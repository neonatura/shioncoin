
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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

#ifndef __TESTNET_NETMGSG_H__
#define __TESTNET_NETMGSG_H__

/**
 * @ingroup sharecoin_testnet
 * @{
 */


extern "C"
{
#ifdef GNULIB_NAMESPACE
#undef GNULIB_NAMESPACE
#endif
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
}


bool testnet_ProcessMessages(CIface *iface, CNode* pfrom);
bool testnet_SendMessages(CIface *iface, CNode* pto, bool fSendTrickle);
void testnet_SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate);


/**
 * @}
 */


#endif /* ndef __TESTNET_NETMGSG_H__ */
