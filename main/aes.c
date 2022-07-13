#include <aes.h>
#include <jade_assert.h>
#include <jade_wally_verify.h>
#include <random.h>

#include <wally_crypto.h>

// Use aes-cbc to encrypt passed bytes.
// Output buffer must be exact correct size to hold the iv followed by the encrypted/padded payload.
bool aes_encrypt_bytes(const uint8_t* aeskey, const size_t aeskey_len, const uint8_t* bytes, const size_t bytes_len,
    uint8_t* output, const size_t output_len)
{
    JADE_ASSERT(aeskey);
    JADE_ASSERT(aeskey_len == AES_KEY_LEN_256);
    JADE_ASSERT(bytes);
    JADE_ASSERT(bytes_len);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len > AES_BLOCK_LEN); // iv

    // 1. Generate random iv at front of buffer
    get_random(output, AES_BLOCK_LEN);

    // 2. Encrypt the passed bytes into the buffer (after the iv)
    const size_t payload_len = AES_PADDED_LEN(bytes_len); // round up to whole number of blocks
    JADE_ASSERT(output_len == AES_BLOCK_LEN + payload_len);

    // Encrypt - written length must be exactly as expected
    size_t written = 0;
    JADE_WALLY_VERIFY(wally_aes_cbc(aeskey, aeskey_len, output, AES_BLOCK_LEN, bytes, bytes_len, AES_FLAG_ENCRYPT,
        output + AES_BLOCK_LEN, payload_len, &written));
    JADE_ASSERT(written == payload_len);

    return true;
}

// Use aes-cbc to decrypt passed bytes.
// Output buffer must be of sufficient size to hold decrypted output or call fails
bool aes_decrypt_bytes(const uint8_t* aeskey, const size_t aeskey_len, const uint8_t* bytes, const size_t bytes_len,
    uint8_t* output, const size_t output_len, size_t* written)
{
    JADE_ASSERT(aeskey);
    JADE_ASSERT(aeskey_len == AES_KEY_LEN_256);
    JADE_ASSERT(bytes);
    JADE_ASSERT(bytes_len > AES_BLOCK_LEN); // iv
    JADE_ASSERT(output);
    JADE_ASSERT(output_len);
    JADE_INIT_OUT_SIZE(written);

    const size_t payload_len = bytes_len - AES_BLOCK_LEN;
    JADE_ASSERT(payload_len % AES_BLOCK_LEN == 0); // whole number of blocks
    JADE_ASSERT(AES_PADDED_LEN(output_len) >= payload_len); // not obviously bad, but not necessarily sufficient

    // Decrypt - output length must be sufficient or call fails
    const int wret = wally_aes_cbc(aeskey, aeskey_len, bytes, AES_BLOCK_LEN, bytes + AES_BLOCK_LEN, payload_len,
        AES_FLAG_DECRYPT, output, output_len, written);
    if (wret != WALLY_OK) {
        JADE_LOGE("Failed to decrypt payload: %d - is output buffer (%u) sufficient for data (%u)?", wret, output_len,
            *written);
        return false;
    }

    return true;
}
