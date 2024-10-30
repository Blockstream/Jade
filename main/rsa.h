#ifndef JADE_RSA_H_
#define JADE_RSA_H_

#include <stdbool.h>
#include <stddef.h>

#define RSA_KEY_SIZE_VALID(bits) (bits == 1024 || bits == 2048 || bits == 3072 || bits == 4096 || bits == 8192)
#define MAX_RSA_GEN_KEY_LEN 4096

// Function to get bip85-generated rsa key pem
bool rsa_get_bip85_pubkey_pem(size_t key_bits, size_t index, char* output, size_t output_len);

#endif /* JADE_RSA_H_ */
