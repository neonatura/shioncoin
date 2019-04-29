/**
 * Blake2-S Implementation
 * tpruvot@github 2015-2016
 */

#include <string.h>
#include <stdint.h>

#include "blake2s.h"

static __thread blake2s_state s_midstate;
static __thread blake2s_state s_ctx;
#define MIDLEN 76

void blake2s_hash(void *output, const void *input)
{
	//uint8_t _ALIGN(_A) hash[BLAKE2S_OUTBYTES];
	uint8_t hash[BLAKE2S_OUTBYTES];
	blake2s_state blake2_ctx;

	blake2s_init(&blake2_ctx, BLAKE2S_OUTBYTES);
	blake2s_update(&blake2_ctx, input, 80);
	blake2s_final(&blake2_ctx, hash, BLAKE2S_OUTBYTES);

	memcpy(output, hash, 32);
}

