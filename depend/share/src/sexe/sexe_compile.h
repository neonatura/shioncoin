
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

#ifndef __SEXE__SEXE_COMPILE_H__
#define __SEXE__SEXE_COMPILE_H__



int sexe_bcode_write(lua_State* L, const Proto* f, lua_Writer w, void* data, int strip);

void SexePrintFunction(const Proto* f, int full);

void SexePrintCode(const Proto* f);

void SexeDumpFunction(const Proto* f, DumpState* D);

Proto *sexe_compile(lua_State *L, int argc, char **argv);


#endif /* ndef __SEXE__SEXE_COMPILE_H__ */
