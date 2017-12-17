
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

#ifndef __SERVER__GLOBAL_H__
#define __SERVER__GLOBAL_H__











#endif /* ndef __SERVER__GLOBAL_H__ */


const char *ReadGlobalVar(char *tag, char *var);

void WriteGlobalVar(char *tag, char *var, char *value);

int ReadVersion(CIface *iface);

void WriteVersion(CIface *iface, int nVersion);

uint256 ReadBestChain(CIface *iface);

void WriteBestChain(CIface *iface, uint256 hash);

CBigNum ReadBestInvalid(CIface *iface);

void WriteBestInvalid(CIface *iface, CBigNum bn);


