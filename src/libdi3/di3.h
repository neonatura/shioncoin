/* Copyright 2019 Brian Burrell */

#ifndef __DI3_H__
#define __DI3_H__

/*
 * DILITHIUM_3
 *
 * Secret key length: 3504
 * Public key length: 1472
 * Signature length: 2701
 * Secret (seedbuf) length: 96
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef DI3_LIBRARY
#include "pqclean_dilithium3_clean/params.h"
#include "pqclean_dilithium3_clean/polyvec.h"
#include "pqclean_dilithium3_clean/sign.h"
#include "pqclean_dilithium3_clean/symmetric.h"
#include "pqclean_dilithium3_clean/packing.h"
#endif


int di3_keypair(uint8_t *pk, uint8_t *sk, uint8_t *seedbuf);

int di3_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);

int di3_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

int di3_derive_hash(uint8_t *result, size_t result_len, uint8_t *hash, size_t hash_len, uint8_t *hd_chain, uint32_t hd_index, uint16_t seed);

/**
 * Hash (SHA3) the first 32 bytes of the public key, the 32-byte chain, and a 4-byte integer. The result is a 32-byte segment for peturbation and a 32-byte segment for the next chain.
 * @returns A 64-byte hash result. The first 32-byte segment is passed on to di3_derive() and the second 32-byte segment is used as the next hd-chain.
 */
uint8_t *di3_derive_keypair_hash(uint8_t *pubkey, uint8_t *hd_chain, uint32_t hd_index);

/**
 * Create a new keypair from a previously established private key. The derived key pair are produced by changing the "material" used to multiply against the midstate vector (t). This material can be seen in both the public and private keys as the first 32-byte segment. The (s1, s2, and) key variables generated for the original private key are not altered.
 *
 * @param sk_in A previously generated private key.
 * @param hash A 32-byte hash segment from di3_derive_hash.
 * @param pk The derived public key.
 * @param sk The derived private key.
 */
int di3_derive_keypair(uint8_t *sk_in, uint8_t *hash, uint8_t *pk, uint8_t *sk);

#endif /* ndef __DI3_H__ */

