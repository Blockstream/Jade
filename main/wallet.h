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

// Supported script variants
typedef enum { GREEN, P2PKH, P2WPKH, P2WPKH_P2SH } script_variant_t;

void wallet_init();

bool bip32_path_as_str(uint32_t parts[], size_t num_parts, char* output, size_t output_len);
bool get_script_variant(const char* variant, size_t variant_len, script_variant_t* output);

void wallet_build_receive_path(uint32_t subaccount, uint32_t branch, uint32_t pointer, uint32_t* output_path,
    size_t output_size, size_t* output_len);
bool wallet_build_receive_script(const char* network, script_variant_t variant, const char* xpubrecovery,
    uint32_t csvBlocks, const uint32_t* path, size_t path_size, unsigned char* output, size_t output_len,
    size_t* written);
bool wallet_validate_receive_script(const char* network, script_variant_t variant, const char* xpubrecovery,
    uint32_t csvBlocks, const uint32_t* path, size_t path_size, const unsigned char* script, size_t script_len);

bool wallet_get_xpub(const char* network, const uint32_t* path, uint32_t path_len, char** output);
bool wallet_get_message_hash_hex(const char* message, size_t msg_len, char** output);
bool wallet_sign_message(const uint32_t* path, size_t path_size, const char* message, size_t bytes_len,
    unsigned char* output, size_t output_len, size_t* written);

bool wallet_get_tx_input_hash(struct wally_tx* tx, size_t index, bool is_witness, const uint8_t* script,
    size_t script_len, uint64_t satoshi, unsigned char* output, size_t output_len);
bool wallet_get_signer_commitment(const uint8_t* signature_hash, size_t signature_hash_len, const uint32_t* path,
    size_t path_size, const uint8_t* commitment, size_t commitment_len, uint8_t* output, size_t output_len);
bool wallet_sign_tx_input_hash(const uint8_t* signature_hash, size_t signature_hash_len, const uint32_t* path,
    size_t path_size, const uint8_t* ae_host_entropy, size_t ae_host_entropy_len, uint8_t* output, size_t output_len,
    size_t* written);

bool wallet_hmac_with_master_key(
    const unsigned char* data, uint32_t data_len, unsigned char* output, uint32_t output_len);
bool wallet_get_public_blinding_key(
    const unsigned char* script, uint32_t script_size, unsigned char* output, uint32_t output_len);
bool wallet_get_shared_nonce(const unsigned char* script, uint32_t script_size, const unsigned char* their_pubkey,
    size_t pubkey_len, unsigned char* output, uint32_t output_len);
bool wallet_get_blinding_factor(const unsigned char* hash_prevouts, size_t hash_len, uint32_t output_index,
    uint8_t type, unsigned char* output, uint32_t output_len);
bool wallet_get_elements_tx_input_hash(struct wally_tx* tx, size_t index, bool is_witness, const uint8_t* script,
    size_t script_len, const unsigned char* satoshi, size_t satoshi_len, unsigned char* output, size_t output_len);

#endif /* WALLET_H_ */
