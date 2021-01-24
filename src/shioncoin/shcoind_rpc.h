
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
 *
 *  This file is part of Shioncoin.
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

#ifdef __cplusplus
extern "C" {
#endif


int set_rpc_dat_password(char *host, shkey_t *in_key);

shkey_t *get_rpc_dat_password(char *host);

const char *get_rpc_password(char *host);

const char *get_rpc_username(void);

uint32_t get_rpc_pin(char *host);

int verify_rpc_pin(char *host, uint32_t pin);

int rpc_init(void);

void rpc_term(void);


#ifdef __cplusplus
}
#endif

