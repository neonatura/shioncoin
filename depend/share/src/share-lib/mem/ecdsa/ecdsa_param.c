
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura 
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

#include "share.h"

#ifdef HAVE_LIBGMP

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "ecdsa_gmp.h"
#include "ecdsa_param.h"
#include "ecdsa_point.h"

/*Initialize a curve*/
ecdsa_parameters ecdsa_parameters_init()
{
	ecdsa_parameters curve;
	curve = malloc(sizeof(struct ecdsa_parameters_s));

	//Initialize all members
	mpz_init(curve->p);
	mpz_init(curve->a);
	mpz_init(curve->b);
	curve->G = ecdsa_point_init();
	mpz_init(curve->n);
	mpz_init(curve->h);

	return curve;
}

/*Sets the name of a curve*/
void ecdsa_parameters_set_name(ecdsa_parameters curve, char* name)
{
	int len = strlen(name);
	curve->name = (char*)malloc( sizeof(char) * (len+1) );
	curve->name[len] = '\0';
	strcpy(curve->name, name);
}

/*Set domain parameters from decimal unsigned long ints*/
void ecdsa_parameters_set_ui(ecdsa_parameters curve,
								char* name,
								unsigned long int p,
								unsigned long int a,
								unsigned long int b,
								unsigned long int Gx,
								unsigned long int Gy,
								unsigned long int n,
								unsigned long int h)
{
	ecdsa_parameters_set_name(curve, name);
	mpz_set_ui(curve->p, p);
	mpz_set_ui(curve->a, a);
	mpz_set_ui(curve->b, b);
	ecdsa_point_set_ui(curve->G, Gx, Gy);
	mpz_set_ui(curve->n, n);
	mpz_set_ui(curve->h, h);
}

/*Set domain parameters from hexadecimal string*/
void ecdsa_parameters_set_hex(ecdsa_parameters curve, char* name, char* p, char* a, char* b, char* Gx, char* Gy, char* n, char* h)
{
	ecdsa_parameters_set_name(curve, name);
	mpz_set_str(curve->p, p, 16);
	mpz_set_str(curve->a, a, 16);
	mpz_set_str(curve->b, b, 16);
	ecdsa_point_set_hex(curve->G, Gx, Gy);
	mpz_set_str(curve->n, n, 16);
	mpz_set_str(curve->h, h, 16);
}

/*Release memory*/
void ecdsa_parameters_clear(ecdsa_parameters curve)
{
	mpz_clear(curve->p);
	mpz_clear(curve->a);
	mpz_clear(curve->b);
	ecdsa_point_clear(curve->G);
	mpz_clear(curve->n);
	mpz_clear(curve->h);
	free(curve->name);
	free(curve);
}

#endif /* HAVE_LIBGMP */

