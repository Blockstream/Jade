#ifndef WALLET_H_
#define WALLET_H_

#include <stdbool.h>

#include "wally_anti_exfil.h"
#include "wally_bip32.h"
#include "wally_bip39.h"
#include "wally_core.h"
#include "wally_crypto.h"
#include "wally_script.h"
#include "wally_transaction.h"

// Blinding factor type prefixes
#define ASSET_BLINDING_FACTOR 'A'
#define VALUE_BLINDING_FACTOR 'V'

// The maximum number of multisig signers supported
#define MAX_MULTISIG_SIGNERS 15

#define MAX_VARIANT_LEN 24

// Supported script variants (singlesig and multisig versions)
typedef enum { GREEN, P2PKH, P2WPKH, P2WPKH_P2SH, MULTI_P2WSH, MULTI_P2SH, MULTI_P2WSH_P2SH } script_variant_t;

void wallet_init(void);

bool bip32_path_as_str(const uint32_t parts[], size_t num_parts, char* output, size_t output_len);

bool wallet_derive_pubkey(const uint8_t* serialised_key, size_t key_len, const uint32_t* path, size_t path_len,
    uint32_t flags, struct ext_key* hdkey);
bool wallet_derive_from_xpub(
    const char* xpub, const uint32_t* path, size_t path_len, uint32_t flags, struct ext_key* hdkey);

const char* get_script_variant_string(script_variant_t variant);
bool get_script_variant(const char* variant, size_t variant_len, script_variant_t* output);
bool is_greenaddress(script_variant_t variant);
bool is_singlesig(script_variant_t variant);
bool is_multisig(script_variant_t variant);

bool wallet_is_expected_singlesig_path(
    const char* network, script_variant_t script_variant, bool is_change, const uint32_t* path, size_t path_len);
bool wallet_is_expected_multisig_path(size_t cosigner_index, bool is_change, const uint32_t* path, size_t path_len);
void wallet_build_receive_path(
    uint32_t subaccount, uint32_t branch, uint32_t pointer, uint32_t* output_path, size_t output_len, size_t* written);

bool wallet_build_ga_script(const char* network, const char* xpubrecovery, uint32_t csvBlocks, const uint32_t* path,
    size_t path_len, uint8_t* output, size_t output_len, size_t* written);
bool wallet_build_singlesig_script(const char* network, script_variant_t script_variant, const uint32_t* path,
    size_t path_len, uint8_t* output, size_t output_len, size_t* written);
bool wallet_build_multisig_script(const char* network, script_variant_t script_variant, bool sorted, uint8_t threshold,
    const uint8_t* pubkeys, size_t pubkeys_len, uint8_t* output, size_t output_len, size_t* written);

void wallet_get_fingerprint(uint8_t* output, size_t output_len);
bool wallet_get_xpub(const char* network, const uint32_t* path, uint32_t path_len, char** output);

bool wallet_get_message_hash(const uint8_t* bytes, size_t bytes_len, uint8_t* output, size_t output_len);
bool wallet_sign_message_hash(const uint8_t* signature_hash, size_t signature_hash_len, const uint32_t* path,
    size_t path_len, const uint8_t* ae_host_entropy, size_t ae_host_entropy_len, uint8_t* output, size_t output_len,
    size_t* written);

bool wallet_get_tx_input_hash(struct wally_tx* tx, size_t index, bool is_witness, const uint8_t* script,
    size_t script_len, uint64_t satoshi, uint8_t* output, size_t output_len);
bool wallet_get_signer_commitment(const uint8_t* signature_hash, size_t signature_hash_len, const uint32_t* path,
    size_t path_len, const uint8_t* commitment, size_t commitment_len, uint8_t* output, size_t output_len);
bool wallet_sign_tx_input_hash(const uint8_t* signature_hash, size_t signature_hash_len, const uint32_t* path,
    size_t path_len, const uint8_t* ae_host_entropy, size_t ae_host_entropy_len, uint8_t* output, size_t output_len,
    size_t* written);

bool wallet_hmac_with_master_key(const uint8_t* data, uint32_t data_len, uint8_t* output, uint32_t output_len);
bool wallet_get_public_blinding_key(const uint8_t* script, uint32_t script_len, uint8_t* output, uint32_t output_len);
bool wallet_get_shared_blinding_nonce(const uint8_t* script, const uint32_t script_len, const uint8_t* their_pubkey,
    const size_t their_pubkey_len, uint8_t* output_nonce, const uint32_t output_nonce_len, uint8_t* output_pubkey,
    const uint32_t output_pubkey_len);
bool wallet_get_blinding_factor(const uint8_t* hash_prevouts, size_t hash_len, uint32_t output_index, uint8_t type,
    uint8_t* output, uint32_t output_len);
bool wallet_get_elements_tx_input_hash(struct wally_tx* tx, size_t index, bool is_witness, const uint8_t* script,
    size_t script_len, const uint8_t* satoshi, size_t satoshi_len, uint8_t* output, size_t output_len);

#endif /* WALLET_H_ */
