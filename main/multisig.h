#ifndef MULTISIG_H_
#define MULTISIG_H_

#include "utils/cbor_rpc.h"
#include "wallet.h"

#include <stdbool.h>

// The length of a multisig wallet name (see also storage key name size limit)
#define MAX_MULTISIG_NAME_SIZE 16

// The maximum number of concurrent multisig registrations supported
#define MAX_MULTISIG_REGISTRATIONS 16

// The expected size of a liquid master blinding key
#define MULTISIG_MASTER_BLINDING_KEY_SIZE (HMAC_SHA512_LEN / 2)

// Check the master blinding key is either null and zero length, or non-null and the expected length
#define IS_VALID_BLINDING_KEY(master_blinding_key, master_blinding_key_len)                                            \
    ((!master_blinding_key && !master_blinding_key_len)                                                                \
        || (master_blinding_key && master_blinding_key_len == MULTISIG_MASTER_BLINDING_KEY_SIZE))

// The size of the byte-string required to store a multisig registration of the current 'version'
#define MULTISIG_BYTES_LEN(master_blinding_key_len, num_signers, total_num_path_elements)                              \
    ((6 * sizeof(uint8_t)) + master_blinding_key_len + (num_signers * (6 + BIP32_SERIALIZED_LEN))                      \
        + (total_num_path_elements * sizeof(uint32_t)) + HMAC_SHA256_LEN)

// The largest supported multisig record
// NOTE: beware of a later 'version' reducing this size as we may end up with larger records persisted in storage
#define MAX_MULTISIG_BYTES_LEN                                                                                         \
    (MULTISIG_BYTES_LEN(                                                                                               \
        MULTISIG_MASTER_BLINDING_KEY_SIZE, MAX_MULTISIG_SIGNERS, MAX_MULTISIG_SIGNERS * 2 * MAX_PATH_LEN))

// Multisig registration file, field names
#define MSIG_FILE_NAME "Name"
#define MSIG_FILE_FORMAT "Format"
#define MSIG_FILE_SORTED "Sorted"
#define MSIG_FILE_POLICY "Policy"
#define MSIG_FILE_BLINDING_KEY "BlindingKey"
#define MSIG_FILE_DERIVATION "Derivation"

#define MULTISIG_FILE_MAX_LEN(num_signers)                                                                             \
    (32 + 22 + 17 + 19 + 14 + 78 + (num_signers * (13 + MAX_PATH_STR_LEN(MAX_PATH_LEN) + 122)))

// Multisig data as persisted
typedef struct _multisig_data {
    script_variant_t variant;
    bool sorted;
    uint8_t threshold;
    uint8_t num_xpubs;
    uint8_t master_blinding_key_len;
    uint8_t master_blinding_key[MULTISIG_MASTER_BLINDING_KEY_SIZE];
    uint8_t xpubs[MAX_MULTISIG_SIGNERS * BIP32_SERIALIZED_LEN];
} multisig_data_t;

// Signer details passed in during multisig registration
typedef struct {
    uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN];

    // The derivation is the path to get from the root/fingerprint to
    // the xpub provided.  Only actually needs to be present and correct
    // for this wallet's xpub - as will be used to verify the xpub.
    uint32_t derivation[MAX_PATH_LEN];
    size_t derivation_len;

    // Should be sufficient as all xpubs should be <= 112
    char xpub[120];
    size_t xpub_len;

    // This is any fixed path always applied after the given xpub, but
    // before any variable path suffix provided on a per-call basis.
    uint32_t path[MAX_PATH_LEN];
    size_t path_len;
} signer_t;

bool multisig_validate_signers(const signer_t* signers, size_t num_signers, const uint8_t* wallet_fingerprint,
    size_t wallet_fingerprint_len, size_t* total_num_path_elements);

bool multisig_data_to_bytes(script_variant_t variant, bool sorted, uint8_t threshold,
    const uint8_t* master_blinding_key, size_t master_blinding_key_len, const signer_t* signers, size_t num_signers,
    size_t total_num_path_elements, uint8_t* output_bytes, size_t output_len);

bool multisig_data_from_bytes(const uint8_t* bytes, size_t bytes_len, multisig_data_t* output, signer_t* signer_details,
    size_t signer_details_len, size_t* written);

bool multisig_load_from_storage(const char* multisig_name, multisig_data_t* output, signer_t* signer_details,
    size_t signer_details_len, size_t* written, const char** errmsg);

bool multisig_validate_paths(
    const bool is_change, CborValue* all_signer_paths, bool* all_paths_as_expected, bool* final_elements_consistent);

bool multisig_get_pubkeys(const uint8_t* xpubs, size_t num_xpubs, CborValue* all_signer_paths, uint8_t* pubkeys,
    size_t pubkeys_len, size_t* written);

bool multisig_get_master_blinding_key(const multisig_data_t* multisig_data, uint8_t* master_blinding_key,
    size_t master_blinding_key_len, const char** errmsg);

void multisig_get_valid_record_names(
    const size_t* script_type, char names[][MAX_MULTISIG_NAME_SIZE], size_t num_names, size_t* num_written);

bool multisig_create_export_file(const char* multisig_name, const multisig_data_t* multisig_data,
    const signer_t* signer_details, size_t num_signer_details, char* output, size_t output_len, size_t* written);

#endif /* MULTISIG_H_ */
