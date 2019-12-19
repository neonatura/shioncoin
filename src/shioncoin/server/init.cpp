
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

#include "shcoind.h"
#include "walletdb.h"
#include "net.h"
#include "init.h"
#include "util.h"
#include "ui_interface.h"
#include "block.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/convenience.hpp>
#ifndef WIN32
#include <signal.h>
#endif

using namespace std;
using namespace boost;

//CWallet* pwalletMain;




extern CSemaphore *semOutbound;

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//


void ExitTimeout(void* parg)
{
#ifdef WIN32
    sleep(5);
    ExitProcess(0);
#endif
}

void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}

void HandleSIGHUP(int)
{
    fReopenDebugLog = true;
}

bool static InitError(const std::string &str)
{
    return false;
}

bool static InitWarning(const std::string &str)
{
    return true;
}



#ifdef __cplusplus
extern "C" {
#endif


extern void map_work_term(void);

void server_shutdown(void)
{
  map_work_term();
  CloseBlockChains();
  fShutdown = true;


}

#ifdef __cplusplus
}
#endif


