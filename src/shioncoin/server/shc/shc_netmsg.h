
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
 *
 *  This file is part of ShionCoin.
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

#ifndef __SHC_NETMGSG_H__
#define __SHC_NETMGSG_H__

/**
 * @ingroup sharecoin_shc
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


bool shc_ProcessMessages(CIface *iface, CNode* pfrom);
bool shc_SendMessages(CIface *iface, CNode* pto, bool fSendTrickle);
void shc_SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate);


/**
 * @}
 */


#endif /* ndef __SHC_NETMGSG_H__ */
