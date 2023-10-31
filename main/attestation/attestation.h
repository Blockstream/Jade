#ifndef JADE_ATTESTATION_H_
#define JADE_ATTESTATION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// RSA 4096-bit key
#define JADE_ATTEST_RSA_KEY_LEN 512
#define JADE_ATTEST_RSA_PUBKEY_PEM_MAX_LEN 832 // usually 800
#define JADE_ATTEST_RSA_PRIVKEY_PEM_MAX_LEN 3264 // usually 3243 or 3247

bool attestation_initialised(void);

bool attestation_initialise(const char* privkey_pem, size_t privkey_pem_len, const char* ext_pubkey_pem,
    size_t ext_pubkey_pem_len, const uint8_t* ext_signature, size_t ext_signature_len);

bool attestation_sign_challenge(const uint8_t* challenge, size_t challenge_len, uint8_t* signature,
    size_t signature_len, char* pubkey_pem, size_t pubkey_pem_len, size_t* pem_written, uint8_t* ext_signature,
    size_t ext_signature_len, size_t* ext_sig_written);

bool attestation_verify(const uint8_t* challenge, size_t challenge_len, const char* pubkey_pem, size_t pubkey_pem_len,
    const uint8_t* signature, size_t signature_len, const char* ext_pubkey_pem, size_t ext_pubkey_pem_len,
    const uint8_t* ext_signature, size_t ext_signature_len);

#endif /* JADE_ATTESTATION_H_ */
