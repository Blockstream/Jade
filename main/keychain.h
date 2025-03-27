#ifndef KEYCHAIN_H_
#define KEYCHAIN_H_

#include <network_type.h>

#include <stdbool.h>
#include <wally_bip32.h>
#include <wally_crypto.h>

#define PASSPHRASE_MAX_LEN 100
#define GASERVICE_PATH_LEN (HMAC_SHA512_LEN / 2)

typedef struct {
    uint32_t gaservice_path[GASERVICE_PATH_LEN];
    uint8_t master_unblinding_key[HMAC_SHA512_LEN];
    uint8_t seed[BIP32_ENTROPY_LEN_512];
    struct ext_key xpriv;
    struct ext_key cached_gaservice_main_root;
    struct ext_key cached_gaservice_subact_root;
    const struct ext_key* cached_service;
    size_t seed_len;
} keychain_t;

typedef enum { PASSPHRASE_NEVER, PASSPHRASE_ONCE, PASSPHRASE_ALWAYS } passphrase_freq_t;
typedef enum { PASSPHRASE_WORDLIST, PASSPHRASE_FREETEXT } passphrase_type_t;

void keychain_init_cache(void);
bool keychain_init_unit_key(void);
void keychain_set(const keychain_t* src, uint8_t userdata, bool temporary);
const struct ext_key* keychain_cached_service(const struct ext_key* service, bool subaccount_root);
void keychain_clear(void);

const keychain_t* keychain_get(void);
bool keychain_requires_passphrase(void);

// key flags
void keychain_set_passphrase_frequency(passphrase_freq_t freq);
passphrase_freq_t keychain_get_passphrase_freq();
void keychain_set_passphrase_type(passphrase_type_t type);
passphrase_type_t keychain_get_passphrase_type();
void keychain_set_confirm_export_blinding_key(const bool confirm_export);
bool keychain_get_confirm_export_blinding_key(void);
void keychain_persist_key_flags(void);

void keychain_set_temporary(void);
bool keychain_has_temporary(void);
uint8_t keychain_get_userdata(void);

// Temporarily cache mnemonic entropy (if using passphrase)
void keychain_cache_mnemonic_entropy(const char* mnemonic);

// Clear/set/get/compare the pinned/restricted network type
void keychain_clear_network_type_restriction(void);
void keychain_set_network_type_restriction(const char* network);
network_type_t keychain_get_network_type_restriction(void);
bool keychain_is_network_type_consistent(const char* network);

// mnemonic returned should be freed by caller with wally_free_string
void keychain_get_new_mnemonic(char** mnemonic, size_t nwords);
bool keychain_get_new_privatekey(uint8_t* privatekey, size_t size);

bool keychain_has_pin(void);
uint8_t keychain_pin_attempts_remaining(void);
void keychain_erase_encrypted(void);

void keychain_derive_from_seed(const uint8_t* seed, size_t seed_len, keychain_t* keydata);
bool keychain_derive_from_mnemonic(const char* mnemonic, const char* passphrase, keychain_t* keydata);
bool keychain_complete_derivation_with_passphrase(const char* passphrase);

bool keychain_store(const uint8_t* aeskey, size_t aeslen);
bool keychain_load(const uint8_t* aeskey, size_t aeslen);
bool keychain_reencrypt(const uint8_t* curr_aeskey, size_t curr_aeslen, const uint8_t* new_aeskey, size_t new_aeslen);

#endif /* KEYCHAIN_H_ */
