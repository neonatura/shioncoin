
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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


#ifndef __ALTCHAIN_COLOR_H__
#define __ALTCHAIN_COLOR_H__

#ifdef __cplusplus
extern "C" {
#endif


void color_gen(char *name, uint32_t *red_p, uint32_t *green_p, uint32_t *blue_p, uint32_t *alpha_p, char *ret_label, char *ret_abrev);


#ifdef __cplusplus
}
#endif

#endif /* ndef __ALTCHAIN_COLOR_H__ */

