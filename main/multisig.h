#ifndef MULTISIG_H_
#define MULTISIG_H_

#include "utils/cbor_rpc.h"
#include "wallet.h"

#include <stdbool.h>

// The length of a multisig wallet name (see also storage key name size limit)
#define MAX_MULTISIG_NAME_SIZE 16

// The maximum number of concurrent multisig registrations supported
#define MAX_MULTISIG_REGISTRATIONS 16

// The size of the byte-string required to store a multisig registration
#define MULTISIG_BYTES_LEN(num_signers) ((4 * sizeof(uint8_t)) + (num_signers * BIP32_SERIALIZED_LEN) + HMAC_SHA256_LEN)

typedef struct {
    script_variant_t variant;
    bool sorted;
    uint8_t threshold;
    uint8_t xpubs[MAX_MULTISIG_SIGNERS * BIP32_SERIALIZED_LEN];
    uint8_t xpubs_len;
} multisig_data_t;

bool multisig_validate_signers(const char* network, const signer_t* signers, size_t num_signers,
    const uint8_t* wallet_fingerprint, size_t wallet_fingerprint_len);

bool multisig_data_to_bytes(script_variant_t variant, bool sorted, uint8_t threshold, const signer_t* signers,
    size_t num_signers, uint8_t* output_bytes, size_t output_len);

bool multisig_data_from_bytes(const uint8_t* bytes, size_t bytes_len, multisig_data_t* output);

bool multisig_load_from_storage(const char* multisig_name, multisig_data_t* output, const char** errmsg);

bool multisig_validate_paths(
    const bool is_change, CborValue* all_signer_paths, bool* all_paths_as_expected, bool* final_elements_consistent);

bool multisig_get_pubkeys(const uint8_t* xpubs, size_t num_xpubs, CborValue* all_signer_paths, uint8_t* pubkeys,
    size_t pubkeys_len, size_t* written);

#endif /* MULTISIG_H_ */
