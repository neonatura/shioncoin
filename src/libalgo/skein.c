
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
#include "sph_skein.h"

void skeinhash(void *state, const void *input)
{
	sph_skein512_context ctx_skein;
	SHA256_CTX sha256;

	uint32_t hash[16];

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, input, 80);
	sph_skein512_close(&ctx_skein, hash);

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, hash, 64);
	SHA256_Final((unsigned char*) hash, &sha256);

	memcpy(state, hash, 32);
}

