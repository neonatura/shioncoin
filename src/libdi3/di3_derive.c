/* Copyright 2019 Neo Natura */

#include "di3.h"

uint8_t *di3_derive_hash(uint8_t *pubkey, uint8_t *hd_chain, uint32_t hd_index)
{
	static const uint16_t seed = 0; /* not defined */
	static char result[64];
	uint8_t data[128];
	size_t data_len;

	data_len = 68; /* 32 + 32 + 4 */
	memcpy(data, pubkey, 32);
	memcpy(data + 32, hd_chain, 32);
	memcpy(data + 64, &hd_index, sizeof(uint32_t));

	memset(result, 0, sizeof(result));
	OQS_SHA3_cshake256_simple(result, 64, seed, data, data_len); 

	return (result);
}

int di3_derive_keypair(uint8_t *sk_in, uint8_t *hash, uint8_t *pk, uint8_t *sk) 
{
	polyvecl mat[K];
	polyveck s2, t, t1, t0;
	polyvecl s1, s1hat;
	unsigned char rho[64];
	unsigned char key[64];
	unsigned char tr[CRHBYTES];
	unsigned int i;

	memset(rho, 0, sizeof(rho));
	memset(key, 0, sizeof(key));

	/* deserialize private key */
	PQCLEAN_DILITHIUM3_CLEAN_unpack_sk(rho, key, tr, &s1, &s2, &t0, sk_in);

	/* Expand matrix */
	memcpy(rho, hash, 32);
	PQCLEAN_DILITHIUM3_CLEAN_expand_mat(mat, rho); /* 32b */

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

