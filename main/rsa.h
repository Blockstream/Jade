#ifndef JADE_RSA_H_
#define JADE_RSA_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RSA_KEY_SIZE_VALID(bits) (bits == 1024 || bits == 2048 || bits == 3072 || bits == 4096 || bits == 8192)
#define MAX_RSA_GEN_KEY_LEN 4096
#define RSA_DIGEST_LEN 32 // sha256

typedef struct {
    uint8_t digest[RSA_DIGEST_LEN];
    size_t digest_len;
} rsa_signing_digest_t;

typedef struct {
    uint8_t signature[MAX_RSA_GEN_KEY_LEN / 8];
    size_t signature_len;
} rsa_signature_t;

// Function to get bip85-generated rsa key pem
bool rsa_get_bip85_pubkey_pem(size_t key_bits, size_t index, char* output, size_t output_len);

// Function to get bip85-generated rsa key pem
bool rsa_bip85_key_sign_digests(size_t key_bits, size_t index, const rsa_signing_digest_t* digests, size_t digests_len,
    rsa_signature_t* signatures, size_t signatures_len);

#endif /* JADE_RSA_H_ */
