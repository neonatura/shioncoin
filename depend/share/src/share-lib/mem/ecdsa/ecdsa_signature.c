
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
#include <stdio.h>
#include <stdbool.h>

#include "ecdsa_gmp.h"
#include "ecdsa_param.h"
#include "ecdsa_point.h"
#include "ecdsa_signature.h"
#include "ecdsa_numbertheory.h"


/*Initialize a ecdsa_signature*/
ecdsa_signature ecdsa_signature_init(void)
{
	ecdsa_signature sig;
	sig = malloc(sizeof(struct ecdsa_signature_s));
	mpz_init(sig->r);
	mpz_init(sig->s);
	return sig;
}

/*Print ecdsa_signature to standart output stream*/
void ecdsa_signature_print(ecdsa_signature sig)
{
	printf("\nSignature (r,s): \n\t(");
	mpz_out_str(stdout, 10, sig->r);
	printf(",\n\t");
	mpz_out_str(stdout, 10, sig->s);
	printf(")\n");
}

/*Set ecdsa_signature from strings of a base from 2-62*/
void ecdsa_signature_set_str(ecdsa_signature sig, char *r, char *s, int base)
{
	mpz_set_str(sig->r, r, base);
	mpz_set_str(sig->s, s, base);
}

/*Set ecdsa_signature from hexadecimal strings*/
void ecdsa_signature_set_hex(ecdsa_signature sig, char *r, char *s)
{
	ecdsa_signature_set_str(sig,r,s,16);
}

/*Set ecdsa_signature from decimal unsigned long ints*/
void ecdsa_signature_set_ui(ecdsa_signature sig, unsigned long int r, unsigned long int s)
{
	mpz_set_ui(sig->r, r);
	mpz_set_ui(sig->s, s);
}

/*Make R a copy of P*/
void ecdsa_signature_copy(ecdsa_signature R, ecdsa_signature sig)
{
	mpz_set(R->r, sig->r);
	mpz_set(R->s, sig->s);
}


/*Compare two ecdsa_signatures return 1 if not the same, returns 0 if they are the same*/
bool ecdsa_signature_cmp(ecdsa_signature sig1, ecdsa_signature sig2)
{
	return !mpz_cmp(sig1->r,sig2->r) && !mpz_cmp(sig1->s,sig2->s);
}

/*Generates a public key for a private key*/
void ecdsa_signature_generate_key(ecdsa_point public_key, mpz_t private_key, ecdsa_parameters curve)
{
	ecdsa_point_multiplication(public_key, private_key, curve->G, curve);
}

#if 0
typedef enum
{
  GMP_RAND_ALG_DEFAULT = 0,
  GMP_RAND_ALG_LC = GMP_RAND_ALG_DEFAULT /* Linear congruential.  */
} gmp_randalg_t;

/* Random state struct.  */
typedef struct
{
  mpz_t _mp_seed;   /* _mp_d member points to state of the generator. */
  gmp_randalg_t _mp_alg;  /* Currently unused. */
  union {
    void *_mp_lc;         /* Pointer to function pointers structure.  */
  } _mp_algdata;
} __gmp_randstate_struct;
typedef __gmp_randstate_struct gmp_randstate_t[1];

static void ecdsa_random_seeding(gmp_randstate_t r_state)
{
  char buf[8];
  uint32_t rval;
  char i1, i2, i3, i4;

  rval = (uint32_t)shrand();
  memcpy(buf, &rval, sizeof(rval));

  i1 = buf[0];
  i2 = buf[1];
  i3 = buf[2];
  i4 = buf[3];

	//abs() returns long (signed long), therefor there must be two, since DO NOT want to loose any randomness
	__gmp_randseed_ui(r_state, (unsigned long int)abs(i1)* (unsigned long int)abs(i2*i3*i4));

}
#endif

/*Generate ecdsa_signature for a message*/
void ecdsa_signature_sign(ecdsa_signature sig, mpz_t message, mpz_t private_key, ecdsa_parameters curve)
{
	//message must not have a bit length longer than that of n
	//see: Guide to Elliptic Curve Cryptography, section 4.4.1.
	//assert(mpz_sizeinbase(message, 2) <= mpz_sizeinbase(curve->n, 2));
	
	//Initializing variables
	mpz_t k;mpz_init(k);
	mpz_t x;mpz_init(x);
	ecdsa_point Q = ecdsa_point_init();
	mpz_t r;mpz_init(r);
	mpz_t t1;mpz_init(t1);
	mpz_t t2;mpz_init(t2);
	mpz_t t3;mpz_init(t3);
	mpz_t s;mpz_init(s);

//	gmp_randstate_t r_state;

	ecdsa_signature_sign_start:

	//Set k
#if 0
	__gmp_randinit_default(r_state);
	ecdsa_random_seeding(r_state);
	mpz_sub_ui(t1, curve->n, 2);
	__gmpz_urandomm(k , r_state , t1);
	__gmp_randclear(r_state);
#endif

	mpz_sub_ui(t1, curve->n, 2);
  ecdsa_random(k, t1);

	//Calculate x
	ecdsa_point_multiplication(Q, k, curve->G, curve);
	mpz_set(x, Q->x);
	ecdsa_point_clear(Q);

	//Calculate r
	mpz_mod(r, x, curve->n);
	if(!mpz_sgn(r))	//Start over if r=0, note haven't been tested memory might die :)
		goto ecdsa_signature_sign_start;
	mpz_clear(x);

	//Calculate s
	//s = k¯¹(e+d*r) mod n = (k¯¹ mod n) * ((e+d*r) mod n) mod n
	number_theory_inverse(t1, k, curve->n);//t1 = k¯¹ mod n
	mpz_mul(t2, private_key, r);//t2 = d*r
	mpz_add(t3, message, t2);	//t3 = e+t2
	mpz_mod(t2, t3, curve->n);	//t2 = t3 mod n
	mpz_mul(t3, t2, t1);		//t3 = t2 * t1
	mpz_mod(s, t3, curve->n);	//s = t3 mod n
	mpz_clear(t1);
	mpz_clear(t2);
	mpz_clear(t3);

	//Set ecdsa_signature
	mpz_set(sig->r, r);
	mpz_set(sig->s, s);

	//Release k,r and s
	mpz_clear(k);
	mpz_clear(r);
	mpz_clear(s);
}

/*Verify the integrity of a message using it's ecdsa_signature*/
bool ecdsa_signature_verify(mpz_t message, ecdsa_signature sig, ecdsa_point public_key, ecdsa_parameters curve)
{
	//verify r and s are within [1, n-1]
	mpz_t one;mpz_init(one);
	mpz_set_ui(one, 1);
	if(	mpz_cmp(sig->r,one) < 0 &&
		mpz_cmp(curve->n,sig->r) <= 0 &&
		mpz_cmp(sig->s,one) < 0 &&
		mpz_cmp(curve->n,sig->s) <= 0)
	{
		mpz_clear(one);
		return false;
	}

	mpz_clear(one);
	
	//Initialize variables
	mpz_t w;mpz_init(w);
	mpz_t u1;mpz_init(u1);
	mpz_t u2;mpz_init(u2);
	mpz_t t;mpz_init(t);
	mpz_t tt2;mpz_init(tt2);
	ecdsa_point x = ecdsa_point_init();
	ecdsa_point t1 = ecdsa_point_init();
	ecdsa_point t2 = ecdsa_point_init();

	//w = s¯¹ mod n
	number_theory_inverse(w, sig->s, curve->n);
	
	//u1 = message * w mod n
	mpz_mod(tt2, message, curve->n);
	mpz_mul(t, tt2, w);
	mpz_mod(u1, t, curve->n);

	//u2 = r*w mod n
	mpz_mul(t, sig->r, w);
	mpz_mod(u2, t, curve->n);

	//x = u1*G+u2*Q
	ecdsa_point_multiplication(t1, u1, curve->G, curve);
	ecdsa_point_multiplication(t2, u2, public_key, curve);
	ecdsa_point_addition(x, t1, t2, curve);

	//Get the result, by comparing x value with r and verifying that x is NOT at infinity
	bool result = mpz_cmp(sig->r, x->x) == 0 && !x->infinity;

	//release memory
	ecdsa_point_clear(x);
	ecdsa_point_clear(t1);
	ecdsa_point_clear(t2);
	mpz_clear(w);
	mpz_clear(u1);
	mpz_clear(u2);
	mpz_clear(t);
	mpz_clear(tt2);

	//Return result
	return result;
}

/*Release ecdsa_signature*/
void ecdsa_signature_clear(ecdsa_signature sig)
{
	mpz_clear(sig->r);
	mpz_clear(sig->s);
	free(sig);
}


#endif /* HAVE_LIBGMP */

