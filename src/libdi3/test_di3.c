/* Copyright 2019 Brian Burrell */

#include "di3.h"

#if 0
static char *hex_str(uint8_t *data, size_t data_len)
{
	  static char ret_buf[10240];
		  int of;

			  memset(ret_buf, 0, sizeof(ret_buf));
				  for (of = 0; of < data_len; of += 4) {
						    sprintf(ret_buf + (of*2), "%-8.8x", *((unsigned int *)(data+of)));
								  }

					  return (ret_buf);
}
#endif

int di3_derive_test(void)
{
	uint8_t *m_sk = calloc(3504, sizeof(uint8_t));
	uint8_t *m_pk = calloc(1472, sizeof(uint8_t));
	uint8_t *sk = calloc(3504, sizeof(uint8_t));
	uint8_t *pk = calloc(1472, sizeof(uint8_t));
	uint8_t *msg = calloc(1024, sizeof(uint8_t));
	uint8_t sig[4096]; /* 2701b */
	char chain[32];
	uint8_t secret[96];
	uint8_t *hd_hash;
	size_t sig_len = 0;
	size_t msg_len = 1024;
	int err;

	/* generate a public key (pk) and secret key (sk). */
	memset(secret, 127, 96);
	err = di3_keypair(m_pk, m_sk, secret);
	if (err)
		return (err);

	memset(chain, 0, sizeof(chain));
	hd_hash = di3_derive_keypair_hash(m_pk, chain, 0);
	err = di3_derive_keypair(m_sk, hd_hash, pk, sk); 
	if (err)
		return (err);

	/* sign the [empty] message with the secret key. */
	err = di3_sign(sig, &sig_len, msg, msg_len, sk);
	if (err)
		return (err);

	/* verify the message is authenticate with the public key. */
	err = di3_verify(sig, sig_len, msg, msg_len, pk);
	if (err)
		return (err);

	return (0);
}

int main(void)
{
	uint8_t *sk = calloc(3504, sizeof(uint8_t));
	uint8_t *pk = calloc(1472, sizeof(uint8_t));
	uint8_t *msg = calloc(1024, sizeof(uint8_t));
	uint8_t sig[4096]; /* 2701b */
	uint8_t secret[96];
	size_t sig_len = 0;
	size_t msg_len = 1024;
	int err;

	/* generate a public key (pk) and secret key (sk). */
	memset(secret, 127, 96);
	err = di3_keypair(pk, sk, secret);
	if (err) return (err & 255);

	/* sign the [empty] message with the secret key. */
	err = di3_sign(sig, &sig_len, msg, msg_len, sk);
	if (err) return (err & 255);

	/* verify the message is authenticate with the public key. */
	err = di3_verify(sig, sig_len, msg, msg_len, pk);
	if (err) return (err & 255);

	/* verify altered signature is not authenticate. */
	sig[2700] = sig[2700] + 1;
	err = di3_verify(sig, sig_len, msg, msg_len, pk);
	if (err == 0) return (1);
	sig[2700] = sig[2700] - 1;

	/* verify altered message is not authenticate. */
	msg[1020] = msg[1020] + 1;
	err = di3_verify(sig, sig_len, msg, msg_len, pk);
	if (err == 0) return (1);

	err = di3_derive_test();
	if (err)
		return (1);

	return (0);
}

