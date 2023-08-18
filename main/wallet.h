#ifndef WALLET_H_
#define WALLET_H_

#include <stdbool.h>

#include <wally_bip32.h>
#include <wally_transaction.h>

// Blinding factors
typedef enum { BF_ASSET, BF_VALUE, BF_ASSET_VALUE } BlindingFactorType_t;

#define MAX_VARIANT_LEN 24

// 'm' + ( ('/' + <10 digit number>[+ ']) * n) + '\0'
#define MAX_PATH_STR_LEN(max_path_elems) (1 + ((1 + 10 + 1) * max_path_elems) + 1)

// Supported script variants (singlesig and multisig versions)
typedef enum { GREEN, P2PKH, P2WPKH, P2WPKH_P2SH, MULTI_P2WSH, MULTI_P2SH, MULTI_P2WSH_P2SH } script_variant_t;

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

void wallet_get_default_xpub_export_path(
    script_variant_t variant, uint16_t account, uint32_t* path, size_t path_len, size_t* written);
bool wallet_is_expected_singlesig_path(
    const char* network, script_variant_t script_variant, bool is_change, const uint32_t* path, size_t path_len);
bool wallet_is_expected_multisig_path(size_t cosigner_index, bool is_change, const uint32_t* path, size_t path_len);
void wallet_build_receive_path(
    uint32_t subaccount, uint32_t branch, uint32_t pointer, uint32_t* output_path, size_t output_len, size_t* written);

bool wallet_build_ga_script(const char* network, const char* xpubrecovery, size_t csvBlocks, const uint32_t* path,
    size_t path_len, uint8_t* output, size_t output_len, size_t* written);
bool wallet_build_singlesig_script(script_variant_t script_variant, const uint8_t* pubkey, size_t pubkey_len,
    uint8_t* output, size_t output_len, size_t* written);
bool wallet_search_for_singlesig_script(script_variant_t script_variant, const struct ext_key* search_root,
    size_t* index, size_t search_depth, const uint8_t* script, size_t script_len);
bool wallet_build_multisig_script(script_variant_t script_variant, bool sorted, uint8_t threshold,
    const uint8_t* pubkeys, size_t pubkeys_len, uint8_t* output, size_t output_len, size_t* written);
bool wallet_search_for_multisig_script(script_variant_t script_variant, bool sorted, uint8_t threshold,
    const struct ext_key* search_roots, size_t search_roots_len, size_t* index, size_t search_depth,
    const uint8_t* script, size_t script_len);

typedef struct _descriptor_data descriptor_data_t;
bool wallet_build_descriptor_script(const char* network, const char* descriptor_name,
    const descriptor_data_t* descriptor, size_t multi_index, size_t index, uint8_t* output, size_t output_len,
    size_t* written, const char** errmsg);

void wallet_get_fingerprint(uint8_t* output, size_t output_len);
bool wallet_get_hdkey(const uint32_t* path, size_t path_len, uint32_t flags, struct ext_key* output);
bool wallet_get_xpub(const char* network, const uint32_t* path, size_t path_len, char** output);

bool wallet_get_message_hash(const uint8_t* bytes, size_t bytes_len, uint8_t* output, size_t output_len);
bool wallet_sign_message_hash(const uint8_t* signature_hash, size_t signature_hash_len, const uint32_t* path,
    size_t path_len, const uint8_t* ae_host_entropy, size_t ae_host_entropy_len, uint8_t* output, size_t output_len,
    size_t* written);

bool wallet_get_tx_input_hash(struct wally_tx* tx, size_t index, bool is_witness, const uint8_t* script,
    size_t script_len, uint64_t satoshi, uint8_t sighash, uint8_t* output, size_t output_len);
bool wallet_get_signer_commitment(const uint8_t* signature_hash, size_t signature_hash_len, const uint32_t* path,
    size_t path_len, const uint8_t* commitment, size_t commitment_len, uint8_t* output, size_t output_len);
bool wallet_sign_tx_input_hash(const uint8_t* signature_hash, size_t signature_hash_len, const uint32_t* path,
    size_t path_len, uint8_t sighash, const uint8_t* ae_host_entropy, size_t ae_host_entropy_len, uint8_t* output,
    size_t output_len, size_t* written);

bool wallet_hmac_with_master_key(const uint8_t* data, size_t data_len, uint8_t* output, size_t output_len);
bool wallet_get_public_blinding_key(const uint8_t* master_blinding_key, size_t master_blinding_key_len,
    const uint8_t* script, size_t script_len, uint8_t* output, size_t output_len);
bool wallet_get_shared_blinding_nonce(const uint8_t* master_blinding_key, size_t master_blinding_key_len,
    const uint8_t* script, size_t script_len, const uint8_t* their_pubkey, size_t their_pubkey_len,
    uint8_t* output_nonce, size_t output_nonce_len, uint8_t* output_pubkey, size_t output_pubkey_len);
bool wallet_get_blinding_factor(const uint8_t* master_blinding_key, size_t master_blinding_key_len,
    const uint8_t* hash_prevouts, size_t hash_len, size_t output_index, BlindingFactorType_t type, uint8_t* output,
    size_t output_len);
bool wallet_get_elements_tx_input_hash(struct wally_tx* tx, size_t index, bool is_witness, const uint8_t* script,
    size_t script_len, const uint8_t* satoshi, size_t satoshi_len, uint8_t sighash, uint8_t* output, size_t output_len);

#endif /* WALLET_H_ */
