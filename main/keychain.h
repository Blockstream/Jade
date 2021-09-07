#ifndef KEYCHAIN_H_
#define KEYCHAIN_H_

#include <stdbool.h>
#include <wally_bip32.h>
#include <wally_crypto.h>

#define PASSPHRASE_MAX_LEN 28

typedef struct {
    struct ext_key xpriv;
    unsigned char service_path[HMAC_SHA512_LEN];
    unsigned char master_unblinding_key[HMAC_SHA512_LEN];
} keychain_t;

bool keychain_init(void);
void keychain_set(const keychain_t* src, uint8_t userdata, bool temporary);
void keychain_free(void);

const keychain_t* keychain_get(void);
bool keychain_has_temporary(void);
uint8_t keychain_get_userdata(void);

// Temporarily cache mnemonic entropy (if using passphrase)
void keychain_cache_mnemonic_entropy(const char* mnemonic);

// Set/clear/compare the pinned/restricted network type
void keychain_set_network_type_restriction(const char* network);
void keychain_clear_network_type_restriction(void);
bool keychain_is_network_type_consistent(const char* network);

// mnemonic returned should be freed by caller with wally_free_string
void keychain_get_new_mnemonic(char** mnemonic, size_t nwords);
bool keychain_get_new_privatekey(unsigned char* privatekey, size_t size);

bool keychain_has_pin(void);
uint8_t keychain_pin_attempts_remaining(void);

bool keychain_derive(const char* mnemonic, const char* passphrase, keychain_t* keydata);
void keychain_derive_from_seed(const unsigned char* seed, size_t seed_len, keychain_t* keydata);

// this expects a 32 byte server key, an n byte pin, that size n, and returns a 32 bytes aes key
bool keychain_get_aes_key(const unsigned char* server_key, size_t key_len, const uint8_t* pin, size_t pin_size,
    unsigned char* aeskey, size_t aes_len);

bool keychain_store_encrypted(const unsigned char* aeskey, size_t aes_len, const keychain_t* keydata);
bool keychain_load_cleartext(const unsigned char* aeskey, size_t aes_len, keychain_t* keydata);

#endif /* KEYCHAIN_H_ */
