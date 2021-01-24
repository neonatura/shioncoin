

/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura 
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
#include <sys/cdefs.h>
#include <sys/types.h>
#include <stdbool.h>



static char shcrypt_iota64[] =		/* 0 ... 63 => ascii - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* Define our magic string to mark salt for SHA256 "encryption" replacement. */
static const char sha256_salt_prefix[] = "$5$";

/* Prefix for optional rounds specification. */
static const char sha256_rounds_prefix[] = "rounds=";

/* Define our magic string to mark salt for SHA512 "encryption" replacement. */
static const char sha512_salt_prefix[] = "$6$";

/* Prefix for optional rounds specification. */
static const char sha512_rounds_prefix[] = "rounds=";

/* magic sizes */
#define MD4_SIZE 16
#define MD5_SIZE 16
#define SHA_LBLOCK  16
#define SHA512_CBLOCK  (SHA_LBLOCK*8)  



typedef uint32_t UINT4;     /* 32 bits */

#define SHA_LONG unsigned long

#if defined(_WIN32) || defined(_WIN64)
#define SHA_LONG64 unsigned __int64
#else
#define SHA_LONG64 uint64_t
#endif

typedef struct sh_sha256_t SHA256_CTX;

#define SHA256_Init sh_sha256_init
#define SHA256_Update sh_sha256_update
#define SHA256_Final(_digest,_ctx) \
  sh_sha256_final((_ctx),(_digest))

#define SHA512_Init sh_sha512_init
#define SHA512_Update sh_sha512_update
#define SHA512_Final(_digest,_ctx) \
  sh_sha512_final((_ctx),(_digest))

typedef struct sh_sha512_t SHA512_CTX;


/* Maximum salt string length. */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified. */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds. */
#define ROUNDS_MIN 1000
/* Maximum number of rounds. */
#define ROUNDS_MAX 999999999


void _crypt_to64(char *s, u_long v, int n)
{
	while (--n >= 0) {
		*s++ = shcrypt_iota64[v&0x3f];
		v >>= 6;
	}
}

void b64_from_24bit(uint8_t B2, uint8_t B1, uint8_t b_0, int n, int *buflen, char **cp)
{
	uint32_t w;
	int i;

	w = (B2 << 16) | (B1 << 8) | b_0;
	for (i = 0; i < n; i++) {
		**cp = shcrypt_iota64[w&0x3f];
		(*cp)++;
		if ((*buflen)-- < 0)
			break;
		w >>= 6;
	}
}

static char *shcrypt_sha256_r(const char *key, const char *salt, char *buffer, int buflen)
{
	u_long srounds;
	int n;
	uint8_t alt_result[32], temp_result[32];
	sh_sha_t ctx, alt_ctx;
	size_t salt_len, key_len, cnt, rounds;
	char *cp, *copied_key, *copied_salt, *p_bytes, *s_bytes, *endp;
	const char *num;
	bool rounds_custom;

	copied_key = NULL;
	copied_salt = NULL;

	/* Default number of rounds. */
	rounds = ROUNDS_DEFAULT;
	rounds_custom = false;

	/* Find beginning of salt string. The prefix should normally always
	 * be present. Just in case it is not. */
	if (strncmp(sha256_salt_prefix, salt, sizeof(sha256_salt_prefix) - 1) == 0)
		/* Skip salt prefix. */
		salt += sizeof(sha256_salt_prefix) - 1;

	if (strncmp(salt, sha256_rounds_prefix, sizeof(sha256_rounds_prefix) - 1)
	    == 0) {
		num = salt + sizeof(sha256_rounds_prefix) - 1;
		srounds = strtoul(num, &endp, 10);

		if (*endp == '$') {
			salt = endp + 1;
			rounds = MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
			rounds_custom = true;
		}
	}

	salt_len = MIN(strcspn(salt, "$"), SALT_LEN_MAX);
	key_len = strlen(key);

	/* Prepare for the real work. */
	sh_sha256_init(&ctx);

	/* Add the key string. */
	sh_sha256_write(&ctx, key, key_len);

	/* The last part is the salt string. This must be at most 8
	 * characters and it ends at the first `$' character (for
	 * compatibility with existing implementations). */
	sh_sha256_write(&ctx, salt, salt_len);

	/* Compute alternate SHA256 sum with input KEY, SALT, and KEY. The
	 * final result will be added to the first context. */
	sh_sha256_init(&alt_ctx);

	/* Add key. */
	sh_sha256_write(&alt_ctx, key, key_len);

	/* Add salt. */
	sh_sha256_write(&alt_ctx, salt, salt_len);

	/* Add key again. */
	sh_sha256_write(&alt_ctx, key, key_len);

	/* Now get result of this (32 bytes) and add it to the other context. */
	sh_sha256_result(&alt_ctx, alt_result);

	/* Add for any character in the key one byte of the alternate sum. */
	for (cnt = key_len; cnt > 32; cnt -= 32)
		sh_sha256_write(&ctx, alt_result, 32);
	sh_sha256_write(&ctx, alt_result, cnt);

	/* Take the binary representation of the length of the key and for
	 * every 1 add the alternate sum, for every 0 the key. */
	for (cnt = key_len; cnt > 0; cnt >>= 1)
		if ((cnt & 1) != 0)
			sh_sha256_write(&ctx, alt_result, 32);
		else
			sh_sha256_write(&ctx, key, key_len);

	/* Create intermediate result. */
	sh_sha256_result(&ctx, alt_result);

	/* Start computation of P byte sequence. */
	sh_sha256_init(&alt_ctx);

	/* For every character in the password add the entire password. */
	for (cnt = 0; cnt < key_len; ++cnt)
		sh_sha256_write(&alt_ctx, key, key_len);

	/* Finish the digest. */
	sh_sha256_result(&alt_ctx, temp_result);

	/* Create byte sequence P. */
	cp = p_bytes = alloca(key_len);
	for (cnt = key_len; cnt >= 32; cnt -= 32) {
		memcpy(cp, temp_result, 32);
		cp += 32;
	}
	memcpy(cp, temp_result, cnt);

	/* Start computation of S byte sequence. */
	sh_sha256_init(&alt_ctx);

	/* For every character in the password add the entire password. */
	for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt)
		sh_sha256_write(&alt_ctx, salt, salt_len);

	/* Finish the digest. */
	sh_sha256_result(&alt_ctx, temp_result);

	/* Create byte sequence S. */
	cp = s_bytes = alloca(salt_len);
	for (cnt = salt_len; cnt >= 32; cnt -= 32) {
		memcpy(cp, temp_result, 32);
		cp += 32;
	}
	memcpy(cp, temp_result, cnt);

	/* Repeatedly run the collected hash value through SHA256 to burn CPU
	 * cycles. */
	for (cnt = 0; cnt < rounds; ++cnt) {
		/* New context. */
		sh_sha256_init(&ctx);

		/* Add key or last result. */
		if ((cnt & 1) != 0)
			sh_sha256_write(&ctx, p_bytes, key_len);
		else
			sh_sha256_write(&ctx, alt_result, 32);

		/* Add salt for numbers not divisible by 3. */
		if (cnt % 3 != 0)
			sh_sha256_write(&ctx, s_bytes, salt_len);

		/* Add key for numbers not divisible by 7. */
		if (cnt % 7 != 0)
			sh_sha256_write(&ctx, p_bytes, key_len);

		/* Add key or last result. */
		if ((cnt & 1) != 0)
			sh_sha256_write(&ctx, alt_result, 32);
		else
			sh_sha256_write(&ctx, p_bytes, key_len);

		/* Create intermediate result. */
		sh_sha256_result(&ctx, alt_result);
	}

	/* Now we can construct the result string. It consists of three
	 * parts. */
	cp = stpncpy(buffer, sha256_salt_prefix, MAX(0, buflen));
	buflen -= sizeof(sha256_salt_prefix) - 1;

	if (rounds_custom) {
		n = snprintf(cp, MAX(0, buflen), "%s%zu$",
			 sha256_rounds_prefix, rounds);

		cp += n;
		buflen -= n;
	}

	cp = stpncpy(cp, salt, MIN((size_t)MAX(0, buflen), salt_len));
	buflen -= MIN((size_t)MAX(0, buflen), salt_len);

	if (buflen > 0) {
		*cp++ = '$';
		--buflen;
	}

	b64_from_24bit(alt_result[0], alt_result[10], alt_result[20], 4, &buflen, &cp);
	b64_from_24bit(alt_result[21], alt_result[1], alt_result[11], 4, &buflen, &cp);
	b64_from_24bit(alt_result[12], alt_result[22], alt_result[2], 4, &buflen, &cp);
	b64_from_24bit(alt_result[3], alt_result[13], alt_result[23], 4, &buflen, &cp);
	b64_from_24bit(alt_result[24], alt_result[4], alt_result[14], 4, &buflen, &cp);
	b64_from_24bit(alt_result[15], alt_result[25], alt_result[5], 4, &buflen, &cp);
	b64_from_24bit(alt_result[6], alt_result[16], alt_result[26], 4, &buflen, &cp);
	b64_from_24bit(alt_result[27], alt_result[7], alt_result[17], 4, &buflen, &cp);
	b64_from_24bit(alt_result[18], alt_result[28], alt_result[8], 4, &buflen, &cp);
	b64_from_24bit(alt_result[9], alt_result[19], alt_result[29], 4, &buflen, &cp);
	b64_from_24bit(0, alt_result[31], alt_result[30], 3, &buflen, &cp);
	if (buflen <= 0) {
		errno = ERANGE;
		buffer = NULL;
	}
	else
		*cp = '\0';	/* Terminate the string. */

	/* Clear the buffer for the intermediate result so that people
	 * attaching to processes or reading core dumps cannot get any
	 * information. We do it in this way to clear correct_words[] inside
	 * the SHA256 implementation as well. */
	sh_sha256_init(&ctx);
	sh_sha256_result(&ctx, alt_result);
	memset(temp_result, '\0', sizeof(temp_result));
	memset(p_bytes, '\0', key_len);
	memset(s_bytes, '\0', salt_len);
	memset(&ctx, '\0', sizeof(ctx));
	memset(&alt_ctx, '\0', sizeof(alt_ctx));
	if (copied_key != NULL)
		memset(copied_key, '\0', key_len);
	if (copied_salt != NULL)
		memset(copied_salt, '\0', salt_len);

	return buffer;
}

/* This entry point is equivalent to crypt(3). */
char *shcrypt_sha256(const char *key, const char *salt)
{
	/* We don't want to have an arbitrary limit in the size of the
	 * password. We can compute an upper bound for the size of the
	 * result in advance and so we can prepare the buffer we pass to
	 * `crypt_sha256_r'. */
	static char *buffer;
	static int buflen;
	int needed;
	char *new_buffer;

	needed = (sizeof(sha256_salt_prefix) - 1
	      + sizeof(sha256_rounds_prefix) + 9 + 1
	      + strlen(salt) + 1 + 43 + 1);

	if (buflen < needed) {
		new_buffer = (char *)realloc(buffer, needed);

		if (new_buffer == NULL)
			return NULL;

		buffer = new_buffer;
		buflen = needed;
	}

	return shcrypt_sha256_r(key, salt, buffer, buflen);
}





static char *shcrypt_sha512_r(const char *key, const char *salt, char *buffer, int buflen)
{
	u_long srounds;
	int n;
	uint8_t alt_result[64], temp_result[64];
	sh_sha_t ctx, alt_ctx;
	size_t salt_len, key_len, cnt, rounds;
	char *cp, *copied_key, *copied_salt, *p_bytes, *s_bytes, *endp;
	const char *num;
	bool rounds_custom;

  memset(alt_result, 0, sizeof(alt_result));
  memset(temp_result, 0, sizeof(temp_result));
  memset(buffer, '\000', buflen);

	copied_key = NULL;
	copied_salt = NULL;

	/* Default number of rounds. */
	rounds = ROUNDS_DEFAULT;
	rounds_custom = false;

	/* Find beginning of salt string. The prefix should normally always
	 * be present. Just in case it is not. */
	if (strncmp(sha512_salt_prefix, salt, sizeof(sha512_salt_prefix) - 1) == 0)
		/* Skip salt prefix. */
		salt += sizeof(sha512_salt_prefix) - 1;

	if (strncmp(salt, sha512_rounds_prefix, sizeof(sha512_rounds_prefix) - 1)
	    == 0) {
		num = salt + sizeof(sha512_rounds_prefix) - 1;
		srounds = strtoul(num, &endp, 10);

		if (*endp == '$') {
			salt = endp + 1;
			rounds = MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
			rounds_custom = true;
		}
	}

	salt_len = MIN(strcspn(salt, "$"), SALT_LEN_MAX);
	key_len = strlen(key);

	/* Prepare for the real work. */
	sh_sha512_init(&ctx);

	/* Add the key string. */
	sh_sha512_write(&ctx, key, key_len);

	/* The last part is the salt string. This must be at most 8
	 * characters and it ends at the first `$' character (for
	 * compatibility with existing implementations). */
	sh_sha512_write(&ctx, salt, salt_len);

	/* Compute alternate SHA512 sum with input KEY, SALT, and KEY. The
	 * final result will be added to the first context. */
	sh_sha512_init(&alt_ctx);

	/* Add key. */
	sh_sha512_write(&alt_ctx, key, key_len);

	/* Add salt. */
	sh_sha512_write(&alt_ctx, salt, salt_len);

	/* Add key again. */
	sh_sha512_write(&alt_ctx, key, key_len);

	/* Now get result of this (64 bytes) and add it to the other context. */
	sh_sha512_result(&alt_ctx, alt_result);

	/* Add for any character in the key one byte of the alternate sum. */
	for (cnt = key_len; cnt > 64; cnt -= 64)
		sh_sha512_write(&ctx, alt_result, 64);
	sh_sha512_write(&ctx, alt_result, cnt);

	/* Take the binary representation of the length of the key and for
	 * every 1 add the alternate sum, for every 0 the key. */
	for (cnt = key_len; cnt > 0; cnt >>= 1)
		if ((cnt & 1) != 0)
			sh_sha512_write(&ctx, alt_result, 64);
		else
			sh_sha512_write(&ctx, key, key_len);

	/* Create intermediate result. */
	sh_sha512_result(&ctx, alt_result);

	/* Start computation of P byte sequence. */
	sh_sha512_init(&alt_ctx);

	/* For every character in the password add the entire password. */
	for (cnt = 0; cnt < key_len; ++cnt)
		sh_sha512_write(&alt_ctx, key, key_len);

	/* Finish the digest. */
	sh_sha512_result(&alt_ctx, temp_result);

	/* Create byte sequence P. */
	cp = p_bytes = alloca(key_len);
	for (cnt = key_len; cnt >= 64; cnt -= 64) {
		memcpy(cp, temp_result, 64);
		cp += 64;
	}
	memcpy(cp, temp_result, cnt);

	/* Start computation of S byte sequence. */
	sh_sha512_init(&alt_ctx);

	/* For every character in the password add the entire password. */
	for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt)
		sh_sha512_write(&alt_ctx, salt, salt_len);

	/* Finish the digest. */
	sh_sha512_result(&alt_ctx, temp_result);

	/* Create byte sequence S. */
	cp = s_bytes = alloca(salt_len);
	for (cnt = salt_len; cnt >= 64; cnt -= 64) {
		memcpy(cp, temp_result, 64);
		cp += 64;
	}
	memcpy(cp, temp_result, cnt);

	/* Repeatedly run the collected hash value through SHA512 to burn CPU
	 * cycles. */
	for (cnt = 0; cnt < rounds; ++cnt) {
		/* New context. */
		sh_sha512_init(&ctx);

		/* Add key or last result. */
		if ((cnt & 1) != 0)
			sh_sha512_write(&ctx, p_bytes, key_len);
		else
			sh_sha512_write(&ctx, alt_result, 64);

		/* Add salt for numbers not divisible by 3. */
		if (cnt % 3 != 0)
			sh_sha512_write(&ctx, s_bytes, salt_len);

		/* Add key for numbers not divisible by 7. */
		if (cnt % 7 != 0)
			sh_sha512_write(&ctx, p_bytes, key_len);

		/* Add key or last result. */
		if ((cnt & 1) != 0)
			sh_sha512_write(&ctx, alt_result, 64);
		else
			sh_sha512_write(&ctx, p_bytes, key_len);

		/* Create intermediate result. */
		sh_sha512_result(&ctx, alt_result);
	}

	/* Now we can construct the result string. It consists of three
	 * parts. */
	cp = stpncpy(buffer, sha512_salt_prefix, MAX(0, buflen));
	buflen -= sizeof(sha512_salt_prefix) - 1;

	if (rounds_custom) {
		n = snprintf(cp, MAX(0, buflen), "%s%zu$",
			 sha512_rounds_prefix, rounds);

		cp += n;
		buflen -= n;
	}

	cp = stpncpy(cp, salt, MIN((size_t)MAX(0, buflen), salt_len));
	buflen -= MIN((size_t)MAX(0, buflen), salt_len);

	if (buflen > 0) {
		*cp++ = '$';
		--buflen;
	}

	b64_from_24bit(alt_result[0], alt_result[21], alt_result[42], 4, &buflen, &cp);
	b64_from_24bit(alt_result[22], alt_result[43], alt_result[1], 4, &buflen, &cp);
	b64_from_24bit(alt_result[44], alt_result[2], alt_result[23], 4, &buflen, &cp);
	b64_from_24bit(alt_result[3], alt_result[24], alt_result[45], 4, &buflen, &cp);
	b64_from_24bit(alt_result[25], alt_result[46], alt_result[4], 4, &buflen, &cp);
	b64_from_24bit(alt_result[47], alt_result[5], alt_result[26], 4, &buflen, &cp);
	b64_from_24bit(alt_result[6], alt_result[27], alt_result[48], 4, &buflen, &cp);
	b64_from_24bit(alt_result[28], alt_result[49], alt_result[7], 4, &buflen, &cp);
	b64_from_24bit(alt_result[50], alt_result[8], alt_result[29], 4, &buflen, &cp);
	b64_from_24bit(alt_result[9], alt_result[30], alt_result[51], 4, &buflen, &cp);
	b64_from_24bit(alt_result[31], alt_result[52], alt_result[10], 4, &buflen, &cp);
	b64_from_24bit(alt_result[53], alt_result[11], alt_result[32], 4, &buflen, &cp);
	b64_from_24bit(alt_result[12], alt_result[33], alt_result[54], 4, &buflen, &cp);
	b64_from_24bit(alt_result[34], alt_result[55], alt_result[13], 4, &buflen, &cp);
	b64_from_24bit(alt_result[56], alt_result[14], alt_result[35], 4, &buflen, &cp);
	b64_from_24bit(alt_result[15], alt_result[36], alt_result[57], 4, &buflen, &cp);
	b64_from_24bit(alt_result[37], alt_result[58], alt_result[16], 4, &buflen, &cp);
	b64_from_24bit(alt_result[59], alt_result[17], alt_result[38], 4, &buflen, &cp);
	b64_from_24bit(alt_result[18], alt_result[39], alt_result[60], 4, &buflen, &cp);
	b64_from_24bit(alt_result[40], alt_result[61], alt_result[19], 4, &buflen, &cp);
	b64_from_24bit(alt_result[62], alt_result[20], alt_result[41], 4, &buflen, &cp);
	b64_from_24bit(0, 0, alt_result[63], 2, &buflen, &cp);

	if (buflen <= 0) {
		errno = ERANGE;
		buffer = NULL;
	}
	else
		*cp = '\0';	/* Terminate the string. */

	/* Clear the buffer for the intermediate result so that people
	 * attaching to processes or reading core dumps cannot get any
	 * information. We do it in this way to clear correct_words[] inside
	 * the SHA512 implementation as well. */
	sh_sha512_init(&ctx);
	sh_sha512_result(&ctx, alt_result);
	memset(temp_result, '\0', sizeof(temp_result));
	memset(p_bytes, '\0', key_len);
	memset(s_bytes, '\0', salt_len);
	memset(&ctx, '\0', sizeof(ctx));
	memset(&alt_ctx, '\0', sizeof(alt_ctx));
	if (copied_key != NULL)
		memset(copied_key, '\0', key_len);
	if (copied_salt != NULL)
		memset(copied_salt, '\0', salt_len);

	return buffer;
}

/* This entry point is equivalent to crypt(3). */
char *shcrypt_sha512(const char *key, const char *salt)
{
	/* We don't want to have an arbitrary limit in the size of the
	 * password. We can compute an upper bound for the size of the
	 * result in advance and so we can prepare the buffer we pass to
	 * `crypt_sha512_r'. */
	static char *buffer;
	static int buflen;
	int needed;
	char *new_buffer;

	needed = (sizeof(sha512_salt_prefix) - 1
	      + sizeof(sha512_rounds_prefix) + 9 + 1
	      + strlen(salt) + 1 + 86 + 1);

	if (buflen < needed) {
		new_buffer = (char *)realloc(buffer, needed);

		if (new_buffer == NULL)
			return NULL;

		buffer = new_buffer;
		buflen = needed;
	}

	return shcrypt_sha512_r(key, salt, buffer, buflen);
}





char *shcrypt(const char *passwd, const char *salt)
{
  char *cr_pass;

  if (strlen(salt) < 3)
    return (NULL);

  cr_pass = NULL;
  if (0 == strncmp(salt, "$6$", 3)) {
    cr_pass = shcrypt_sha512(passwd, salt);
  } else if (0 == strncmp(salt, "$5$", 3)) {
    cr_pass = shcrypt_sha256(passwd, salt);
#if 0
  } else if (0 == strncmp(salt, "$1", 3)) {
    cr_pass = crypt_md5(passwd, salt);
#endif
  }
 
  return (cr_pass);
}

/** Encode binary into crypt-b64 format */
void shcrypt_b64_encode(char *ret_str, unsigned char *data, size_t data_len)
{
  size_t ret_len;
  uint32_t crc;
  uint32_t *recs;
  int blks;
  int blk;
  int pad;
  int i;

  blks = data_len / 3;
  pad = (data_len % 3);

  ret_len = 0;
  recs = (uint32_t *)data;
  for (blk = 0; blk < blks; blk++) {
    memcpy(&crc, data + (blk * 3), 3);
    for (i = 0; i < 4; i++) {
      ret_str[ret_len++] = shcrypt_iota64[crc&0x3f];
      crc >>= 6;
    }
  }
  if (pad == 1) {
    memcpy(&crc, data + (blks * 3), 1);
    for (i = 0; i < 2; i++) {
      ret_str[ret_len++] = shcrypt_iota64[crc&0x3f];
      crc >>= 6;
    }
  } else if (pad == 2) {
    memcpy(&crc, data + (blks * 3), 2);
    for (i = 0; i < 3; i++) {
      ret_str[ret_len++] = shcrypt_iota64[crc&0x3f];
      crc >>= 6;
    }
  }
  ret_str[ret_len] = '\000';

}

void shcrypt_b64_decode(char *str, unsigned char *data, size_t *data_len_p)
{
  char buf[8];
  int str_len;
  size_t ret_len;
  uint32_t crc;
  uint32_t idx;
  size_t data_len;
  size_t data_of;
  int str_of;
  int len;
  int i;

  ret_len = 0;
  if (data_len_p)
    *data_len_p = 0;

  str_len = strlen(str);
  for (str_of = 0; str_of < str_len; str_of += 4) {
    len = MIN(4, str_len - str_of);
    memset(buf, 0, sizeof(buf));
    strncpy(buf, str + str_of, len);

    crc = 0;
    for (i = (len-1); i >= 0; i--) {
      idx = stridx(shcrypt_iota64, buf[i]);
      if (idx == -1)
        return;

      crc += idx;
      if (i != 0)
        crc = crc << 6;
    }

    memcpy(data + ret_len, &crc, len-1);
    ret_len += (len - 1);
  }

  if (data_len_p)
    *data_len_p = ret_len;

}


_TEST(shcrypt_b64)
{
  unsigned char cmp_data[64];
  unsigned char data[64];
  char text[256];
  size_t cmp_data_len;

  memset(text, 0, sizeof(text));
  memset(data, 1, sizeof(data));
  shcrypt_b64_encode(text, data, sizeof(data));

  memset(cmp_data, 0, sizeof(cmp_data));
  shcrypt_b64_decode(text, cmp_data, &cmp_data_len);
  _TRUE(cmp_data_len == sizeof(data));
  _TRUE(0 == memcmp(data, cmp_data, 64));
}


_TEST(shcrypt_512)
{
  char buf[512];
  char *passphrase = "test";
  char *cr_salt = "UsVxACzd";
  char *cr_bsalt = "////////////////";
  char *cr_sig = "BN23JTVeZ1ZQB7aCKclm9k7kKhO/YaEQYyazT1DisLsz7lkgox4oSMMTjZkj8/MdwBUyWyGEMrQVb3nHaBVq3/";
  char *cr_bsig = "fcjBPMkZ1OHzX5G7iVrKdkqw/S7WoOGCWn4KLp9.aZ9gIILhpaAEuQc5HxSk6fhKXuUXnPho4/2MXauQSY5Ov/";
  char *sig;

  sig = shcrypt_sha512(passphrase, cr_salt);
  sprintf(buf, "$6$%s$%s", cr_salt, cr_sig);
  _TRUE(0 == strcmp(buf, sig));

  sig = shcrypt_sha512(passphrase, cr_bsalt);
  sprintf(buf, "$6$%s$%s", cr_bsalt, cr_bsig);
  _TRUE(0 == strcmp(buf, sig));

}







/* test routine */

static const struct {
  const char *salt;
  const char *input;
  const char *expected;
} _sha256_test[] =
{
  {
    "$5$saltstring", "Hello world!",
    "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"
  },
  {
    "$5$rounds=10000$saltstringsaltstring", "Hello world!",
    "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2."
      "opqey6IcA"
  },
  {
    "$5$rounds=5000$toolongsaltstring", "This is just a test",
    "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8"
      "mGRcvxa5"
  },
  {
    "$5$rounds=1400$anotherlongsaltstring",
    "a very much longer text to encrypt.  This one even stretches over more"
      "than one line.",
    "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12"
      "oP84Bnq1"
  },
  {
    "$5$rounds=77777$short",
    "we have a short salt string but not a short password",
    "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"
  },
  {
    "$5$rounds=123456$asaltof16chars..", "a short string",
    "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/"
      "cZKmF/wJvD"
  },
  {
    "$5$rounds=10$roundstoolow", "the minimum number is still observed",
    "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL97"
      "2bIC"
  },
};
#define n_sha256_test (sizeof (_sha256_test) / sizeof (_sha256_test[0]))

static const struct {
  const char *salt;
  const char *input;
  const char *expected;
} _sha512_test[] =
{
  {
    "$6$saltstring", "Hello world!",
    "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
    "esI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
  },
  {
    "$6$rounds=10000$saltstringsaltstring", "Hello world!",
    "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb"
    "HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
  },
  {
    "$6$rounds=5000$toolongsaltstring", "This is just a test",
    "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQ"
    "zQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"
  },
  {
    "$6$rounds=1400$anotherlongsaltstring",
    "a very much longer text to encrypt.  This one even stretches over more"
    "than one line.",
    "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wP"
    "vMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"
  },
  {
    "$6$rounds=77777$short",
    "we have a short salt string but not a short password",
    "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0g"
    "ge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"
  },
  {
    "$6$rounds=123456$asaltof16chars..", "a short string",
    "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
    "elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"
  },
  {
    "$6$rounds=10$roundstoolow", "the minimum number is still observed",
    "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1x"
    "hLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."
  },
};
#define n_sha512_test (sizeof (_sha512_test) / sizeof (_sha512_test[0]))


_TEST(shcrypt)
{
  int cnt;

  for (cnt = 0; cnt < n_sha256_test; cnt++) {
    char *cp = shcrypt(_sha256_test[cnt].input, _sha256_test[cnt].salt);
    _TRUEPTR(cp);
    _TRUE(0 == strcmp(cp, _sha256_test[cnt].expected));
  }

  for (cnt = 0; cnt < n_sha512_test; ++cnt) {
    char *cp = shcrypt_sha512(_sha512_test[cnt].input, _sha512_test[cnt].salt);

    _TRUE(0 == strcmp(cp, _sha512_test[cnt].expected));
  }

}













#ifdef SHA512_TEST

static const struct {
	const char *input;
	const char result[64];
} tests[] =
{
	/* Test vectors from FIPS 180-2: appendix C.1. */
	{
		"abc",
		"\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31"
		"\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a"
		"\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd"
		"\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f"
	},
	/* Test vectors from FIPS 180-2: appendix C.2. */
	{
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
		"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		"\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14\x3f"
		"\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88\x90\x18"
		"\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4\xb5\x43\x3a"
		"\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09"
	},
	/* Test vectors from the NESSIE project. */
	{
		"",
		"\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07"
		"\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce"
		"\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f"
		"\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e"
	},
	{
		"a",
		"\x1f\x40\xfc\x92\xda\x24\x16\x94\x75\x09\x79\xee\x6c\xf5\x82\xf2"
		"\xd5\xd7\xd2\x8e\x18\x33\x5d\xe0\x5a\xbc\x54\xd0\x56\x0e\x0f\x53"
		"\x02\x86\x0c\x65\x2b\xf0\x8d\x56\x02\x52\xaa\x5e\x74\x21\x05\x46"
		"\xf3\x69\xfb\xbb\xce\x8c\x12\xcf\xc7\x95\x7b\x26\x52\xfe\x9a\x75"
	},
	{
		"message digest",
		"\x10\x7d\xbf\x38\x9d\x9e\x9f\x71\xa3\xa9\x5f\x6c\x05\x5b\x92\x51"
		"\xbc\x52\x68\xc2\xbe\x16\xd6\xc1\x34\x92\xea\x45\xb0\x19\x9f\x33"
		"\x09\xe1\x64\x55\xab\x1e\x96\x11\x8e\x8a\x90\x5d\x55\x97\xb7\x20"
		"\x38\xdd\xb3\x72\xa8\x98\x26\x04\x6d\xe6\x66\x87\xbb\x42\x0e\x7c"
	},
	{
		"abcdefghijklmnopqrstuvwxyz",
		"\x4d\xbf\xf8\x6c\xc2\xca\x1b\xae\x1e\x16\x46\x8a\x05\xcb\x98\x81"
		"\xc9\x7f\x17\x53\xbc\xe3\x61\x90\x34\x89\x8f\xaa\x1a\xab\xe4\x29"
		"\x95\x5a\x1b\xf8\xec\x48\x3d\x74\x21\xfe\x3c\x16\x46\x61\x3a\x59"
		"\xed\x54\x41\xfb\x0f\x32\x13\x89\xf7\x7f\x48\xa8\x79\xc7\xb1\xf1"
	},
	{
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"\x20\x4a\x8f\xc6\xdd\xa8\x2f\x0a\x0c\xed\x7b\xeb\x8e\x08\xa4\x16"
		"\x57\xc1\x6e\xf4\x68\xb2\x28\xa8\x27\x9b\xe3\x31\xa7\x03\xc3\x35"
		"\x96\xfd\x15\xc1\x3b\x1b\x07\xf9\xaa\x1d\x3b\xea\x57\x78\x9c\xa0"
		"\x31\xad\x85\xc7\xa7\x1d\xd7\x03\x54\xec\x63\x12\x38\xca\x34\x45"
	},
	{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"\x1e\x07\xbe\x23\xc2\x6a\x86\xea\x37\xea\x81\x0c\x8e\xc7\x80\x93"
		"\x52\x51\x5a\x97\x0e\x92\x53\xc2\x6f\x53\x6c\xfc\x7a\x99\x96\xc4"
		"\x5c\x83\x70\x58\x3e\x0a\x78\xfa\x4a\x90\x04\x1d\x71\xa4\xce\xab"
		"\x74\x23\xf1\x9c\x71\xb9\xd5\xa3\xe0\x12\x49\xf0\xbe\xbd\x58\x94"
	},
	{
		"123456789012345678901234567890123456789012345678901234567890"
		"12345678901234567890",
		"\x72\xec\x1e\xf1\x12\x4a\x45\xb0\x47\xe8\xb7\xc7\x5a\x93\x21\x95"
		"\x13\x5b\xb6\x1d\xe2\x4e\xc0\xd1\x91\x40\x42\x24\x6e\x0a\xec\x3a"
		"\x23\x54\xe0\x93\xd7\x6f\x30\x48\xb4\x56\x76\x43\x46\x90\x0c\xb1"
		"\x30\xd2\xa4\xfd\x5d\xd1\x6a\xbb\x5e\x30\xbc\xb8\x50\xde\xe8\x43"
	}
};

#define ntests (sizeof (tests) / sizeof (tests[0]))

static const struct {
	const char *salt;
	const char *input;
	const char *expected;
} tests2[] =
{
	{
		"$6$saltstring", "Hello world!",
		"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
		"esI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
	},
	{
		"$6$rounds=10000$saltstringsaltstring", "Hello world!",
		"$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb"
		"HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
	},
	{
		"$6$rounds=5000$toolongsaltstring", "This is just a test",
		"$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQ"
		"zQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"
	},
	{
		"$6$rounds=1400$anotherlongsaltstring",
		"a very much longer text to encrypt.  This one even stretches over more"
		"than one line.",
		"$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wP"
		"vMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"
	},
	{
		"$6$rounds=77777$short",
		"we have a short salt string but not a short password",
		"$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0g"
		"ge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"
	},
	{
		"$6$rounds=123456$asaltof16chars..", "a short string",
		"$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
		"elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"
	},
	{
		"$6$rounds=10$roundstoolow", "the minimum number is still observed",
		"$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1x"
		"hLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."
	},
};

#define ntests2 (sizeof (tests2) / sizeof (tests2[0]))

int
main(void)
{
	SHA512_CTX ctx;
	uint8_t sum[64];
	int result = 0;
	int i, cnt;

	for (cnt = 0; cnt < (int)ntests; ++cnt) {
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, tests[cnt].input, strlen(tests[cnt].input));
		SHA512_Final(sum, &ctx);
		if (memcmp(tests[cnt].result, sum, 64) != 0) {
			printf("test %d run %d failed\n", cnt, 1);
			result = 1;
		}

		SHA512_Init(&ctx);
		for (i = 0; tests[cnt].input[i] != '\0'; ++i)
			SHA512_Update(&ctx, &tests[cnt].input[i], 1);
		SHA512_Final(sum, &ctx);
		if (memcmp(tests[cnt].result, sum, 64) != 0) {
			printf("test %d run %d failed\n", cnt, 2);
			result = 1;
		}
	}

	/* Test vector from FIPS 180-2: appendix C.3. */
	char buf[1000];

	memset(buf, 'a', sizeof(buf));
	SHA512_Init(&ctx);
	for (i = 0; i < 1000; ++i)
		SHA512_Update(&ctx, buf, sizeof(buf));
	SHA512_Final(sum, &ctx);
	static const char expected[64] =
	"\xe7\x18\x48\x3d\x0c\xe7\x69\x64\x4e\x2e\x42\xc7\xbc\x15\xb4\x63"
	"\x8e\x1f\x98\xb1\x3b\x20\x44\x28\x56\x32\xa8\x03\xaf\xa9\x73\xeb"
	"\xde\x0f\xf2\x44\x87\x7e\xa6\x0a\x4c\xb0\x43\x2c\xe5\x77\xc3\x1b"
	"\xeb\x00\x9c\x5c\x2c\x49\xaa\x2e\x4e\xad\xb2\x17\xad\x8c\xc0\x9b";

	if (memcmp(expected, sum, 64) != 0) {
		printf("test %d failed\n", cnt);
		result = 1;
	}

	for (cnt = 0; cnt < ntests2; ++cnt) {
		char *cp = crypt_sha512(tests2[cnt].input, tests2[cnt].salt);

		if (strcmp(cp, tests2[cnt].expected) != 0) {
			printf("test %d: expected \"%s\", got \"%s\"\n",
			       cnt, tests2[cnt].expected, cp);
			result = 1;
		}
	}

	if (result == 0)
		puts("all tests OK");

	return result;
}

#endif /* TEST */










#ifdef SHA256_TEST

static const struct {
	const char *input;
	const char result[32];
} tests[] =
{
	/* Test vectors from FIPS 180-2: appendix B.1. */
	{
		"abc",
		"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
		"\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad"
	},
	/* Test vectors from FIPS 180-2: appendix B.2. */
	{
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
		"\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1"
	},
	/* Test vectors from the NESSIE project. */
	{
		"",
		"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
		"\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55"
	},
	{
		"a",
		"\xca\x97\x81\x12\xca\x1b\xbd\xca\xfa\xc2\x31\xb3\x9a\x23\xdc\x4d"
		"\xa7\x86\xef\xf8\x14\x7c\x4e\x72\xb9\x80\x77\x85\xaf\xee\x48\xbb"
	},
	{
		"message digest",
		"\xf7\x84\x6f\x55\xcf\x23\xe1\x4e\xeb\xea\xb5\xb4\xe1\x55\x0c\xad"
		"\x5b\x50\x9e\x33\x48\xfb\xc4\xef\xa3\xa1\x41\x3d\x39\x3c\xb6\x50"
	},
	{
		"abcdefghijklmnopqrstuvwxyz",
		"\x71\xc4\x80\xdf\x93\xd6\xae\x2f\x1e\xfa\xd1\x44\x7c\x66\xc9\x52"
		"\x5e\x31\x62\x18\xcf\x51\xfc\x8d\x9e\xd8\x32\xf2\xda\xf1\x8b\x73"
	},
	{
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
		"\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1"
	},
	{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"\xdb\x4b\xfc\xbd\x4d\xa0\xcd\x85\xa6\x0c\x3c\x37\xd3\xfb\xd8\x80"
		"\x5c\x77\xf1\x5f\xc6\xb1\xfd\xfe\x61\x4e\xe0\xa7\xc8\xfd\xb4\xc0"
	},
	{
		"123456789012345678901234567890123456789012345678901234567890"
		"12345678901234567890",
		"\xf3\x71\xbc\x4a\x31\x1f\x2b\x00\x9e\xef\x95\x2d\xd8\x3c\xa8\x0e"
		"\x2b\x60\x02\x6c\x8e\x93\x55\x92\xd0\xf9\xc3\x08\x45\x3c\x81\x3e"
	}
};

#define ntests (sizeof (tests) / sizeof (tests[0]))

static const struct {
	const char *salt;
	const char *input;
	const char *expected;
} tests2[] =
{
	{
		"$5$saltstring", "Hello world!",
		"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"
	},
	{
		"$5$rounds=10000$saltstringsaltstring", "Hello world!",
		"$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2."
		"opqey6IcA"
	},
	{
		"$5$rounds=5000$toolongsaltstring", "This is just a test",
		"$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8"
		"mGRcvxa5"
	},
	{
		"$5$rounds=1400$anotherlongsaltstring",
		"a very much longer text to encrypt.  This one even stretches over more"
		"than one line.",
		"$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12"
		"oP84Bnq1"
	},
	{
		"$5$rounds=77777$short",
		"we have a short salt string but not a short password",
		"$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"
	},
	{
		"$5$rounds=123456$asaltof16chars..", "a short string",
		"$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/"
		"cZKmF/wJvD"
	},
	{
		"$5$rounds=10$roundstoolow", "the minimum number is still observed",
		"$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL97"
		"2bIC"
	},
};

#define ntests2 (sizeof (tests2) / sizeof (tests2[0]))

int
crypt_test_main(void)
{
	SHA256_CTX ctx;
	uint8_t sum[32];
	int result = 0;
	int i, cnt;

	for (cnt = 0; cnt < (int)ntests; ++cnt) {
		sh_sha256_init(&ctx);
		SHA256_Update(&ctx, tests[cnt].input, strlen(tests[cnt].input));
		SHA256_Final(sum, &ctx);
		if (memcmp(tests[cnt].result, sum, 32) != 0) {
			for (i = 0; i < 32; i++)
				printf("%02X", tests[cnt].result[i]);
			printf("\n");
			for (i = 0; i < 32; i++)
				printf("%02X", sum[i]);
			printf("\n");
			printf("test %d run %d failed\n", cnt, 1);
			result = 1;
		}

		sh_sha256_init(&ctx);
		for (i = 0; tests[cnt].input[i] != '\0'; ++i)
			SHA256_Update(&ctx, &tests[cnt].input[i], 1);
		SHA256_Final(sum, &ctx);
		if (memcmp(tests[cnt].result, sum, 32) != 0) {
			for (i = 0; i < 32; i++)
				printf("%02X", tests[cnt].result[i]);
			printf("\n");
			for (i = 0; i < 32; i++)
				printf("%02X", sum[i]);
			printf("\n");
			printf("test %d run %d failed\n", cnt, 2);
			result = 1;
		}
	}

	/* Test vector from FIPS 180-2: appendix B.3. */
	char buf[1000];

	memset(buf, 'a', sizeof(buf));
	sh_sha256_init(&ctx);
	for (i = 0; i < 1000; ++i)
		SHA256_Update(&ctx, buf, sizeof(buf));
	SHA256_Final(sum, &ctx);
	static const char expected[32] =
	"\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67"
	"\xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0";

	if (memcmp(expected, sum, 32) != 0) {
		printf("test %d failed\n", cnt);
		result = 1;
	}

	for (cnt = 0; cnt < ntests2; ++cnt) {
		char *cp = crypt_sha256(tests2[cnt].input, tests2[cnt].salt);

		if (strcmp(cp, tests2[cnt].expected) != 0) {
			printf("test %d: expected \"%s\", got \"%s\"\n",
			       cnt, tests2[cnt].expected, cp);
			result = 1;
		}
	}

	if (result == 0)
		puts("all tests OK");

	return result;
}

#endif /* TEST */


