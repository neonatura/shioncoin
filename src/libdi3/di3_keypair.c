/* Copyright 2019 Brian Burrell */

#include "di3.h"

int di3_keypair(uint8_t *pk, uint8_t *sk, uint8_t *seedbuf)
{
	unsigned int i;
	unsigned char tr[CRHBYTES];
	const unsigned char *rho, *rhoprime, *key;
	uint16_t nonce = 0;
	polyvecl mat[K];
	polyvecl s1, s1hat;
	polyveck s2, t, t1, t0;

	/* Expand 32 bytes of randomness into rho, rhoprime and key */
	rho = seedbuf;
	rhoprime = seedbuf + SEEDBYTES;
	key = seedbuf + 2 * SEEDBYTES;

	/* Expand matrix */
	PQCLEAN_DILITHIUM3_CLEAN_expand_mat(mat, rho);

	/* Sample short vectors s1 and s2 */
	for (i = 0; i < L; ++i) {
		PQCLEAN_DILITHIUM3_CLEAN_poly_uniform_eta(&s1.vec[i], rhoprime, nonce++);
	}
	for (i = 0; i < K; ++i) {
		PQCLEAN_DILITHIUM3_CLEAN_poly_uniform_eta(&s2.vec[i], rhoprime, nonce++);
	}

	/* Matrix-vector multiplication */
	s1hat = s1;
	PQCLEAN_DILITHIUM3_CLEAN_polyvecl_ntt(&s1hat);
	for (i = 0; i < K; ++i) {
		PQCLEAN_DILITHIUM3_CLEAN_polyvecl_pointwise_acc_invmontgomery(&t.vec[i], &mat[i], &s1hat);
		PQCLEAN_DILITHIUM3_CLEAN_poly_reduce(&t.vec[i]);
		PQCLEAN_DILITHIUM3_CLEAN_poly_invntt_montgomery(&t.vec[i]);
	}

	/* Add error vector s2 */
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_add(&t, &t, &s2);

	/* Extract t1 and write public key */
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_freeze(&t);
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_power2round(&t1, &t0, &t);
	PQCLEAN_DILITHIUM3_CLEAN_pack_pk(pk, rho, &t1);

	/* Compute CRH(rho, t1) and write secret key */
	crh(tr, pk, CRYPTO_PUBLICKEYBYTES);
	PQCLEAN_DILITHIUM3_CLEAN_pack_sk(sk, rho, key, tr, &s1, &s2, &t0);

	return 0;
}


