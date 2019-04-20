
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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

#ifndef __SERVER__CHAIN_H__
#define __SERVER__CHAIN_H__

#ifdef __cplusplus
extern "C" {
#endif

#define BCOP_NONE 0
#define BCOP_IMPORT 1
#define BCOP_EXPORT 2
#define BCOP_DOWNLOAD 3
#define BCOP_VALIDATE 4
#define BCOP_MINER 5

#include <stdio.h>

typedef struct ChainOp
{
  char path[PATH_MAX+1];
  int mode;
  int ifaceIndex;
  int pos;
  unsigned int max;
  unsigned int total;
} ChainOp;

int InitChainImport(int ifaceIndex, const char *path, int offset);

int InitChainExport(int ifaceIndex, const char *path, int min, int max);

void event_cycle_chain(int ifaceIndex);

void ServiceWalletEventUpdate(CWallet *wallet, const CBlock *pblock);

void InitServiceWalletEvent(CWallet *wallet, uint64_t nHeight);

void InitServiceValidateEvent(CWallet *wallet, uint64_t nHeight);

int InitServiceBlockEvent(int ifaceIndex, uint64_t nHeight);

void UpdateServiceBlockEvent(int ifaceIndex);

void ServiceBlockEventUpdate(int ifaceIndex);

void ResetServiceWalletEvent(CWallet *wallet);

void ResetServiceValidateEvent(CWallet *wallet);

int InitServiceMinerEvent(int ifaceIndex, uint64_t nHeight);

bool UpdateServiceMinerEvent(int ifaceIndex);

void ProcessBlockAvailability(int ifaceIndex, CNode *pfrom);

void UpdateBlockAvailability(int ifaceIndex, CNode *pfrom, const uint256& hash);


#ifdef __cplusplus
}
#endif

#endif /* ndef __SERVER__CHAIN_H__ */
