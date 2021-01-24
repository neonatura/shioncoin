#ifndef SCRYPT_H
#define SCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

const int SCRYPT_SCRATCHPAD_SIZE = 131072 + 63;

void scrypt_1024_1_1_256_sp(const char *input, char *output, char *scratchpad);
void scrypt_1024_1_1_256(const char *input, char *output);

void PBKDF2_SHA256(const unsigned char *passwd, size_t passwdlen, const unsigned char *salt, size_t saltlen, uint64_t c, unsigned char *buf, size_t dkLen);

#ifdef __cplusplus
}
#endif

#endif
