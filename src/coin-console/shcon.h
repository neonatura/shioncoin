
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

#ifndef __SHCON_H__
#define __SHCON_H__

#include "config.h"
#ifdef __USE_W32_SOCKETS
#undef __USE_W32_SOCKETS
#endif
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/select.h>
#include "share.h"



extern FILE *_shcon_fout;




#include "shcon_init.h"
#include "shcon_term.h"
#include "shcon_log.h"
#include "shcon_opt.h"
#include "shcon_stream.h"
#include "shcon_gui.h"
#include "key/key.h"
#include "net/net.h"
#include "command/command.h"


#endif


