#ifndef KEYCHAIN_H_
#define KEYCHAIN_H_

#include <stdbool.h>
#include <wally_bip32.h>
#include <wally_crypto.h>

#define SERIALIZED_SIZE (BIP32_SERIALIZED_LEN + HMAC_SHA512_LEN + HMAC_SHA512_LEN)
#define SERIALIZED_SIZE_AES (((SERIALIZED_SIZE / AES_BLOCK_LEN) + 1) * AES_BLOCK_LEN)
#define ENCRYPTED_SIZE_AES (SERIALIZED_SIZE_AES + AES_BLOCK_LEN + HMAC_SHA256_LEN)

struct keychain_handle {
    struct ext_key xpriv;
    unsigned char service_path[HMAC_SHA512_LEN];
    unsigned char master_unblinding_key[HMAC_SHA512_LEN];
};

extern struct keychain_handle* keychain;

bool keychain_init();
void set_keychain(struct keychain_handle* src);
void free_keychain();

// Compare pinned/restricted network type and the type of the network passed
bool keychain_is_network_type_consistent(const char* network);
void keychain_clear_network_type_restriction();

// mnemonic returned should be freed by caller with wally_free_string
void keychain_get_new_mnemonic(char** mnemonic);
bool keychain_get_new_privatekey(unsigned char* privatekey, size_t size);

bool keychain_has_pin();
uint8_t keychain_pin_attempts_remaining();

bool keychain_derive(const char* mnemonic, struct keychain_handle* handle);

// this expects a 32 byte server key, an n byte pin, that size n, and returns a 32 bytes aes key
bool keychain_get_aes_key(const unsigned char* server_key, size_t key_len, const uint8_t* pin, size_t pin_size,
    unsigned char* aeskey, size_t aes_len);

bool keychain_store_encrypted(const unsigned char* aeskey, size_t aes_len, const struct keychain_handle* handle);
bool keychain_load_cleartext(const unsigned char* aeskey, size_t aes_len, struct keychain_handle* handle);

#endif /* KEYCHAIN_H_ */
