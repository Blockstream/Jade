#ifndef _LIBJADE_SODIUM_CRYPTO_VERIFY_64_H_
#define _LIBJADE_SODIUM_CRYPTO_VERIFY_64_H_ 1

static inline int crypto_verify_64(const unsigned char* x, const unsigned char* y) { return memcmp(x, y, 64); }

#endif // _LIBJADE_SODIUM_CRYPTO_VERIFY_64_H_
