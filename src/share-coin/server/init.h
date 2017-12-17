#ifndef SERVER_INIT_H
#define SERVER_INIT_H



#include "wallet.h"

//extern CWallet* pwalletMain;
//std::string HelpMessage();

void StartServerShutdown();
void ServerShutdown(void* parg);
bool AppInit2();


#endif
