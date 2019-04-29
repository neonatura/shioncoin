
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sph_groestl.h"

// static __thread sph_groestl512_context ctx;

void groestlhash(void *output, const void *input)
{
	uint32_t hash[16];
	//uint32_t _ALIGN(32) hash[16];
	sph_groestl512_context ctx;

	// memset(&hash[0], 0, sizeof(hash));

	sph_groestl512_init(&ctx);
	sph_groestl512(&ctx, input, 80);
	sph_groestl512_close(&ctx, hash);

	//sph_groestl512_init(&ctx);
	sph_groestl512(&ctx, hash, 64);
	sph_groestl512_close(&ctx, hash);

	memcpy(output, hash, 32);
}

