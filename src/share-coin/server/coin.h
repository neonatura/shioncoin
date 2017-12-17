
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

#ifndef __SERVER__COIN_H__
#define __SERVER__COIN_H__


bool core_VerifyCoinInputs(int ifaceIndex, CTransaction& tx, unsigned int nIn, CTxOut& prev);

bool core_ConnectBlock(CBlock *block, CBlockIndex* pindex);

bool core_DisconnectInputs(int ifaceIndex, CTransaction *tx);

bool core_AcceptPoolTx(int ifaceIndex, CTransaction& tx, bool fCheckInputs);

bool EraseTxCoins(CIface *iface, uint256 hash);

bool WriteTxCoins(uint256 hash, int ifaceIndex, const vector<uint256>& vOuts);

void WriteHashBestChain(CIface *iface, uint256 hash);

bool ReadHashBestChain(CIface *iface, uint256& ret_hash);

bool core_Truncate(CIface *iface, uint256 hash);

bool HasTxCoins(CIface *iface, uint256 hash);

bool UpdateBlockCoins(CBlock& block);

#endif /* ndef __SERVER_COIN_H__ */




