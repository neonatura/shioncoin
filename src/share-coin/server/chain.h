

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


#ifdef __cplusplus
}
#endif

#endif /* ndef __SERVER__CHAIN_H__ */
