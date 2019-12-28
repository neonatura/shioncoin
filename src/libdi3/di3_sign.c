/* Copyright 2019 Brian Burrell */

#include "di3.h"

int di3_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) 
{
	unsigned long long i;
	unsigned int n;
	unsigned char seedbuf[2 * SEEDBYTES + 3 * CRHBYTES];
	unsigned char *rho, *tr, *key, *mu, *rhoprime;
	uint16_t nonce = 0;
	poly c, chat;
	polyvecl mat[K], s1, y, yhat, z;
	polyveck t0, s2, w, w1, w0;
	polyveck h, cs2, ct0;

	rho = seedbuf;
	tr = rho + SEEDBYTES;
	key = tr + CRHBYTES;
	mu = key + SEEDBYTES;
	rhoprime = mu + CRHBYTES;
	PQCLEAN_DILITHIUM3_CLEAN_unpack_sk(rho, key, tr, &s1, &s2, &t0, sk);


	// use incremental hash API instead of copying around buffers
	/* Compute CRH(tr, msg) */
	shake256incctx state;
	shake256_inc_init(&state);
	shake256_inc_absorb(&state, tr, CRHBYTES);
	shake256_inc_absorb(&state, m, mlen);
	shake256_inc_finalize(&state);
	shake256_inc_squeeze(mu, CRHBYTES, &state);

	crh(rhoprime, key, SEEDBYTES + CRHBYTES);

	/* Expand matrix and transform vectors */
	PQCLEAN_DILITHIUM3_CLEAN_expand_mat(mat, rho);
	PQCLEAN_DILITHIUM3_CLEAN_polyvecl_ntt(&s1);
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_ntt(&s2);
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_ntt(&t0);

rej:
	/* Sample intermediate vector y */
	for (i = 0; i < L; ++i) {
		PQCLEAN_DILITHIUM3_CLEAN_poly_uniform_gamma1m1(&y.vec[i], rhoprime, nonce++);
	}

	/* Matrix-vector multiplication */
	yhat = y;
	PQCLEAN_DILITHIUM3_CLEAN_polyvecl_ntt(&yhat);
	for (i = 0; i < K; ++i) {
		PQCLEAN_DILITHIUM3_CLEAN_polyvecl_pointwise_acc_invmontgomery(&w.vec[i], &mat[i], &yhat);
		PQCLEAN_DILITHIUM3_CLEAN_poly_reduce(&w.vec[i]);
		PQCLEAN_DILITHIUM3_CLEAN_poly_invntt_montgomery(&w.vec[i]);
	}

	/* Decompose w and call the random oracle */
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_csubq(&w);
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_decompose(&w1, &w0, &w);
	PQCLEAN_DILITHIUM3_CLEAN_challenge(&c, mu, &w1);
	chat = c;
	PQCLEAN_DILITHIUM3_CLEAN_poly_ntt(&chat);

	/* Check that subtracting cs2 does not change high bits of w and low bits
	 * do not reveal secret information */
	for (i = 0; i < K; ++i) {
		PQCLEAN_DILITHIUM3_CLEAN_poly_pointwise_invmontgomery(&cs2.vec[i], &chat, &s2.vec[i]);
		PQCLEAN_DILITHIUM3_CLEAN_poly_invntt_montgomery(&cs2.vec[i]);
	}
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_sub(&w0, &w0, &cs2);
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_freeze(&w0);
	if (PQCLEAN_DILITHIUM3_CLEAN_polyveck_chknorm(&w0, GAMMA2 - BETA)) {
		goto rej;
	}

	/* Compute z, reject if it reveals secret */
	for (i = 0; i < L; ++i) {
		PQCLEAN_DILITHIUM3_CLEAN_poly_pointwise_invmontgomery(&z.vec[i], &chat, &s1.vec[i]);
		PQCLEAN_DILITHIUM3_CLEAN_poly_invntt_montgomery(&z.vec[i]);
	}
	PQCLEAN_DILITHIUM3_CLEAN_polyvecl_add(&z, &z, &y);
	PQCLEAN_DILITHIUM3_CLEAN_polyvecl_freeze(&z);
	if (PQCLEAN_DILITHIUM3_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
		goto rej;
	}

	/* Compute hints for w1 */
	for (i = 0; i < K; ++i) {
		PQCLEAN_DILITHIUM3_CLEAN_poly_pointwise_invmontgomery(&ct0.vec[i], &chat, &t0.vec[i]);
		PQCLEAN_DILITHIUM3_CLEAN_poly_invntt_montgomery(&ct0.vec[i]);
	}

	PQCLEAN_DILITHIUM3_CLEAN_polyveck_csubq(&ct0);
	if (PQCLEAN_DILITHIUM3_CLEAN_polyveck_chknorm(&ct0, GAMMA2)) {
		goto rej;
	}

	PQCLEAN_DILITHIUM3_CLEAN_polyveck_add(&w0, &w0, &ct0);
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_csubq(&w0);
	n = PQCLEAN_DILITHIUM3_CLEAN_polyveck_make_hint(&h, &w0, &w1);
	if (n > OMEGA) {
		goto rej;
	}

	/* Write signature */
	PQCLEAN_DILITHIUM3_CLEAN_pack_sig(sig, &z, &h, &c);

	*siglen = CRYPTO_BYTES;
	return 0;
}

