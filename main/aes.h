#ifndef AES_H_
#define AES_H_

#include <stdbool.h>
#include <stddef.h>

#include <wally_crypto.h>

// Round 'len' up to next multiple of AES_BLOCK_LEN
// NOTE: exact multiples are rounded up to the next multiple
#define AES_PADDED_LEN(len) (((len / AES_BLOCK_LEN) + 1) * AES_BLOCK_LEN)

// iv, padded payload (un-padded length provided)
#define AES_ENCRYPTED_LEN(len) (AES_BLOCK_LEN + AES_PADDED_LEN(len))

bool aes_encrypt_bytes(const uint8_t* aeskey, size_t aeskey_len, const uint8_t* bytes, size_t bytes_len,
    uint8_t* output, size_t output_len);

bool aes_decrypt_bytes(const uint8_t* aeskey, size_t aeskey_len, const uint8_t* bytes, size_t bytes_len,
    uint8_t* output, size_t output_len, size_t* written);

#endif /* AES_H_ */