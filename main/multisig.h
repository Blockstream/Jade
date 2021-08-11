#ifndef MULTISIG_H_
#define MULTISIG_H_

#include "utils/cbor_rpc.h"
#include "wallet.h"

#include <stdbool.h>

// The length of a multisig wallet name (see also storage key name size limit)
#define MAX_MULTISIG_NAME_SIZE 16

// The maximum number of concurrent multisig registrations supported
#define MAX_MULTISIG_REGISTRATIONS 8

// The size of the byte-string required to store a multisig registration
#define MULTISIG_BYTES_LEN(num_signers) ((3 * sizeof(uint8_t)) + (num_signers * BIP32_SERIALIZED_LEN) + HMAC_SHA256_LEN)

typedef struct {
    script_variant_t variant;
    uint8_t threshold;
    uint8_t xpubs[MAX_MULTISIG_SIGNERS * BIP32_SERIALIZED_LEN];
    size_t xpubs_len;
} multisig_data_t;

bool multisig_validate_signers(const char* network, const signer_t* signers, size_t num_signers,
    const uint8_t* wallet_fingerprint, size_t wallet_fingerprint_len);

bool multisig_data_to_bytes(script_variant_t variant, uint8_t threshold, const signer_t* signers, size_t num_signers,
    uint8_t* output_bytes, size_t output_len);

bool multisig_data_from_bytes(const uint8_t* bytes, size_t bytes_len, multisig_data_t* output);

#endif /* MULTISIG_H_ */
