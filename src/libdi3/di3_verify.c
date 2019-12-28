/* Copyright 2019 Brian Burrell */

#include "di3.h"

int di3_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk)
{
	unsigned long long i;
	unsigned char rho[SEEDBYTES];
	unsigned char mu[CRHBYTES];
	poly c, chat, cp;
	polyvecl mat[K], z;
	polyveck t1, w1, h, tmp1, tmp2;

	if (siglen < CRYPTO_BYTES) {
		return -1;
	}

	PQCLEAN_DILITHIUM3_CLEAN_unpack_pk(rho, &t1, pk);
	if (PQCLEAN_DILITHIUM3_CLEAN_unpack_sig(&z, &h, &c, sig)) {
		return -1;
	}
	if (PQCLEAN_DILITHIUM3_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
		return -1;
	}

	/* Compute CRH(CRH(rho, t1), msg) */
	crh(mu, pk, CRYPTO_PUBLICKEYBYTES);

	shake256incctx state;
	shake256_inc_init(&state);
	shake256_inc_absorb(&state, mu, CRHBYTES);
	shake256_inc_absorb(&state, m, mlen);
	shake256_inc_finalize(&state);
	shake256_inc_squeeze(mu, CRHBYTES, &state);

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	PQCLEAN_DILITHIUM3_CLEAN_expand_mat(mat, rho);

	PQCLEAN_DILITHIUM3_CLEAN_polyvecl_ntt(&z);
	for (i = 0; i < K ; ++i) {
		PQCLEAN_DILITHIUM3_CLEAN_polyvecl_pointwise_acc_invmontgomery(&tmp1.vec[i], &mat[i], &z);
	}

	chat = c;
	PQCLEAN_DILITHIUM3_CLEAN_poly_ntt(&chat);
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_shiftl(&t1);
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_ntt(&t1);
	for (i = 0; i < K; ++i) {
		PQCLEAN_DILITHIUM3_CLEAN_poly_pointwise_invmontgomery(&tmp2.vec[i], &chat, &t1.vec[i]);
	}

	PQCLEAN_DILITHIUM3_CLEAN_polyveck_sub(&tmp1, &tmp1, &tmp2);
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_reduce(&tmp1);
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_invntt_montgomery(&tmp1);

	/* Reconstruct w1 */
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_csubq(&tmp1);
	PQCLEAN_DILITHIUM3_CLEAN_polyveck_use_hint(&w1, &tmp1, &h);

	/* Call random oracle and verify challenge */
	PQCLEAN_DILITHIUM3_CLEAN_challenge(&cp, mu, &w1);
	for (i = 0; i < N; ++i) {
		if (c.coeffs[i] != cp.coeffs[i]) {
			return -1;
		}
	}

	// All good
	return 0;
}

