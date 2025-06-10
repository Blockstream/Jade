#ifndef WALLET_H_
#define WALLET_H_

#include <stdbool.h>

#include "utils/network.h"

#include <wally_bip32.h>
#include <wally_map.h>
#include <wally_transaction.h>

// Blinding factors
typedef enum { BF_ASSET, BF_VALUE, BF_ASSET_VALUE } BlindingFactorType_t;

// Input/Output data for signing a tx input
typedef struct {
    uint8_t signature_hash[SHA256_LEN]; // Input: The signature hash to sign
    uint32_t path[16]; // Input: The path to sign with
    uint8_t sig[EC_SIGNATURE_DER_MAX_LEN + 1]; // Output: The DER or Schnorr signature
    char id[16 + 1]; // For caller use: not used by signing.
    uint8_t sig_type; // Input: Signature hash type required (WALLY_SIGTYPE_)
    uint8_t sighash; // Input: The sighash flags to sign with
    bool use_ae; // Output: Whether the input is using anti-exfil
    size_t path_len; // Input: The length of the path in "path"
    size_t sig_len; // Output: The length of the signature in "sig"
} input_data_t;

// Input/Output data for signing a tx
// segwit v1: All "amounts"/"assets" must be populated, and "scriptpubkeys"
//     must have an entry for each item in "inputs".
// Otherwise: "amounts"/"assets" must contain an amount for the index
//     being signed, and "scriptpubkeys" is unused.
typedef struct {
    input_data_t* inputs;
    size_t num_inputs;
    struct wally_map amounts;
    struct wally_map assets;
    struct wally_map scriptpubkeys;
    struct wally_map cache;
} signing_data_t;

#define MAX_VARIANT_LEN 24
#define GASERVICE_ROOT_PATH_LEN (1 + 32)
#define MAX_GASERVICE_PATH_TAIL_LEN (1 + 1)
#define MAX_GASERVICE_PATH_LEN (GASERVICE_ROOT_PATH_LEN + MAX_GASERVICE_PATH_TAIL_LEN)

// 'm' + ( ('/' + <10 digit number>[+ ']) * n) + '\0'
#define MAX_PATH_STR_LEN(max_path_elems) (1 + ((1 + 10 + 1) * max_path_elems) + 1)

// Supported script variants (singlesig and multisig versions)
// New variants must be added to the end, as this enum is persisted
// e.g. in multisig registrations.
typedef enum { GREEN, P2PKH, P2WPKH, P2WPKH_P2SH, MULTI_P2WSH, MULTI_P2SH, MULTI_P2WSH_P2SH, P2TR } script_variant_t;

void wallet_init(void);

bool wallet_bip32_path_as_str(const uint32_t parts[], size_t num_parts, char* output, size_t output_len);
bool wallet_bip32_path_from_str(const char* pathstr, size_t str_len, uint32_t* path, size_t path_len, size_t* written);

bool wallet_derive_pubkey(const uint8_t* serialised_key, size_t key_len, const uint32_t* path, size_t path_len,
    uint32_t flags, struct ext_key* hdkey);
bool wallet_derive_from_xpub(
    const char* xpub, const uint32_t* path, size_t path_len, uint32_t flags, struct ext_key* hdkey);

size_t script_length_for_variant(script_variant_t variant);
const char* get_script_variant_string(script_variant_t variant);
bool get_script_variant(const char* variant, size_t variant_len, script_variant_t* output);
bool get_singlesig_variant_from_script_type(size_t script_type, script_variant_t* variant);
bool is_greenaddress(script_variant_t variant);
bool is_singlesig(script_variant_t variant);
bool is_multisig(script_variant_t variant);

void wallet_get_bip85_bip39_entropy(size_t nwords, size_t index, uint8_t* entropy, size_t entropy_len, size_t* written);
void wallet_get_bip85_rsa_entropy(size_t key_bits, size_t index, uint8_t* entropy, size_t entropy_len, size_t* written);

void wallet_get_default_xpub_export_path(
    script_variant_t variant, uint16_t account, uint32_t* path, size_t path_len, size_t* written);
bool wallet_is_expected_singlesig_path(
    network_t network_id, script_variant_t script_variant, bool is_change, const uint32_t* path, size_t path_len);
bool wallet_is_expected_multisig_path(size_t cosigner_index, bool is_change, const uint32_t* path, size_t path_len);
void wallet_build_receive_path(
    uint32_t subaccount, uint32_t branch, uint32_t pointer, uint32_t* output_path, size_t output_len, size_t* written);

bool wallet_build_ga_script_ex(network_t network_id, const struct ext_key* user_key,
    const struct ext_key* recovery_hdkey, size_t csv_blocks, const uint32_t* path, size_t path_len, uint8_t* output,
    size_t output_len, size_t* written);
bool wallet_build_ga_script(network_t network_id, const char* xpubrecovery, size_t csv_blocks, const uint32_t* path,
    size_t path_len, uint8_t* output, size_t output_len, size_t* written);
bool wallet_build_singlesig_script(network_t network_id, script_variant_t script_variant, const struct ext_key* hdkey,
    uint8_t* output, size_t output_len, size_t* written);
bool wallet_search_for_singlesig_script(network_t network_id, script_variant_t script_variant,
    const struct ext_key* search_root, size_t* index, size_t search_depth, const uint8_t* script, size_t script_len);
bool wallet_build_multisig_script(script_variant_t script_variant, bool sorted, uint8_t threshold,
    const uint8_t* pubkeys, size_t pubkeys_len, uint8_t* output, size_t output_len, size_t* written);
bool wallet_search_for_multisig_script(script_variant_t script_variant, bool sorted, uint8_t threshold,
    const struct ext_key* search_roots, size_t search_roots_len, size_t* index, size_t search_depth,
    const uint8_t* script, size_t script_len);

typedef struct _descriptor_data descriptor_data_t;
bool wallet_build_descriptor_script(network_t network_id, const char* descriptor_name,
    const descriptor_data_t* descriptor, size_t multi_index, size_t index, uint8_t* output, size_t output_len,
    size_t* written, const char** errmsg);
bool wallet_search_for_descriptor_script(network_t network_id, const char* descriptor_name,
    const descriptor_data_t* descriptor, size_t multi_index, size_t* index, size_t search_depth, const uint8_t* script,
    size_t script_len);

void wallet_get_fingerprint(uint8_t* output, size_t output_len);
bool wallet_get_hdkey(const uint32_t* path, size_t path_len, uint32_t flags, struct ext_key* output);
bool wallet_get_xpub(network_t network_id, const uint32_t* path, size_t path_len, char** output);

bool wallet_calculate_gaservice_path(struct ext_key* root_key, uint32_t* gaservice_path, size_t gaservice_path_len);
bool wallet_serialize_gaservice_path(
    uint8_t* serialized, size_t serialized_len, const uint32_t* gaservice_path, size_t gaservice_path_len);
bool wallet_unserialize_gaservice_path(
    const uint8_t* serialized, size_t serialized_len, uint32_t* gaservice_path, size_t gaservice_path_len);
bool wallet_get_gaservice_fingerprint(network_t network_id, uint8_t* output, size_t output_len);
bool wallet_get_gaservice_path(
    const uint32_t* path, size_t path_len, uint32_t* ga_path, size_t ga_path_len, size_t* written);
bool wallet_get_gaservice_root_key(const struct ext_key* service, bool subaccount_root, struct ext_key* gakey);

bool wallet_get_message_hash(const uint8_t* bytes, size_t bytes_len, uint8_t* output, size_t output_len);
bool wallet_sign_message_hash(const uint8_t* signature_hash, size_t signature_hash_len, const uint32_t* path,
    size_t path_len, const uint8_t* ae_host_entropy, size_t ae_host_entropy_len, uint8_t* output, size_t output_len,
    size_t* written);

signing_data_t* signing_data_allocate(const size_t num_inputs);

void signing_data_free(void* signing_data);

// Get the signature hash for the "index"-th input of "tx".
bool wallet_get_tx_input_hash(struct wally_tx* tx, size_t index, signing_data_t* signing_data, const uint8_t* script,
    size_t script_len, const uint8_t* genesis, const size_t genesis_len);
bool wallet_get_signer_commitment(const uint8_t* signature_hash, size_t signature_hash_len, const uint32_t* path,
    size_t path_len, const uint8_t* commitment, size_t commitment_len, uint8_t* output, size_t output_len);
// Sign the signature hash in input_data.
bool wallet_sign_tx_input_hash(input_data_t* input_data, const uint8_t* ae_host_entropy, size_t ae_host_entropy_len);

bool wallet_hmac_with_master_key(const uint8_t* data, size_t data_len, uint8_t* output, size_t output_len);
bool wallet_get_public_blinding_key(const uint8_t* master_blinding_key, size_t master_blinding_key_len,
    const uint8_t* script, size_t script_len, uint8_t* output, size_t output_len);
bool wallet_get_shared_blinding_nonce(const uint8_t* master_blinding_key, size_t master_blinding_key_len,
    const uint8_t* script, size_t script_len, const uint8_t* their_pubkey, size_t their_pubkey_len,
    uint8_t* output_nonce, size_t output_nonce_len, uint8_t* output_pubkey, size_t output_pubkey_len);
bool wallet_get_blinding_factor(const uint8_t* master_blinding_key, size_t master_blinding_key_len,
    const uint8_t* hash_prevouts, size_t hash_len, size_t output_index, BlindingFactorType_t type, uint8_t* output,
    size_t output_len);

#endif /* WALLET_H_ */
