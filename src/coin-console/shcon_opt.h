
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

#ifndef __SHCON_OPT_H__
#define __SHCON_OPT_H__



#define OPT_IFACE "shcon.iface"

#define OPT_QUIET "shcon.quiet"

#define OPT_VERBOSE "shcon.verbose"

#define OPT_OUTPUT "shcon.output"

#define OPT_PORT "shcoind.stratum.port"

#define OPT_HOSTNAME "shcon.hostname"


int shcon_opt_init(void);

void shcon_opt_term(void);

const char *opt_str(char *opt_name);

int opt_num(char *opt_name);

double opt_fnum(char *opt_name);

int opt_bool(char *opt_name);

void opt_str_set(char *opt_name, char *opt_value);

void opt_num_set(char *opt_name, int num);

void opt_fnum_set(char *opt_name, double num);

void opt_bool_set(char *opt_name, int b);

/** The current coin interface being utilized. */
const char *opt_iface(void);


#endif /* ndef __SHCON_OPT_H__ */
