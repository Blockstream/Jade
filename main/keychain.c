#include "keychain.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "random.h"
#include "sensitive.h"
#include "storage.h"
#include "utils/malloc_ext.h"
#include "utils/network.h"

#include <sodium/crypto_verify_32.h>
#include <string.h>
#include <wally_bip39.h>
#include <wally_elements.h>

// GA derived key index, and fixed GA key message
static const uint32_t GA_PATH_ROOT = BIP32_INITIAL_HARDENED_CHILD + 0x4741;
static const unsigned char GA_KEY_MSG[] = "GreenAddress.it HD wallet path";

// Internal variables - the single/global keychain data
static keychain_t* keychain_data = NULL;
static network_type_t network_type_restriction = NONE;
static uint8_t keychain_userdata = 0;

void set_keychain(const keychain_t* src, const uint8_t userdata)
{
    JADE_ASSERT(src);

    // Maybe freeing and re-allocing is unnecessary, but shouldn't happen very
    // often, and ensures it is definitely in dram.  Better safe ...
    free_keychain();
    keychain_data = JADE_MALLOC_DRAM(sizeof(keychain_t));
    memcpy(keychain_data, src, sizeof(keychain_t));

    // Hold the associated userdata
    keychain_userdata = userdata;
}

void free_keychain()
{
    if (keychain_data) {
        wally_bzero(keychain_data, sizeof(keychain_t));
        free(keychain_data);
        keychain_data = NULL;
    }
    keychain_userdata = 0;
}

const keychain_t* keychain_get() { return keychain_data; }

uint8_t keychain_get_userdata() { return keychain_userdata; }

// Clear the network type restriction
void keychain_clear_network_type_restriction()
{
    JADE_LOGI("Clearing network type restriction");
    storage_set_network_type_restriction(NONE);
    network_type_restriction = NONE;
}

// Set the network type restriction (must currently be 'none', or same as passed).
void keychain_set_network_type_restriction(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));

    const network_type_t network_type = isTestNetwork(network) ? TEST : MAIN;
    JADE_ASSERT(network_type_restriction == NONE || network_type_restriction == network_type);

    if (network_type_restriction == NONE) {
        JADE_LOGI("Restricting to network type: %s", network_type == TEST ? "TEST" : "MAIN");
        storage_set_network_type_restriction(network_type);
        network_type_restriction = network_type;
    }
}

// Compare pinned/restricted network type and the type of the network passed
bool keychain_is_network_type_consistent(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));
    const network_type_t network_type = isTestNetwork(network) ? TEST : MAIN;
    return network_type_restriction == NONE || network_type == network_type_restriction;
}

// Helper to create the service/gait path.
// (The below is correct for newly created wallets, verified in regtest).
static bool populate_service_path(keychain_t* keydata)
{
    JADE_ASSERT(keydata);
    uint8_t extkeydata[EC_PRIVATE_KEY_LEN + EC_PUBLIC_KEY_LEN];
    SENSITIVE_PUSH(extkeydata, sizeof(extkeydata));

    // 1. Derive a child of our private key using the fixed GA index
    struct ext_key derived;
    SENSITIVE_PUSH(&derived, sizeof(derived));
    JADE_WALLY_VERIFY(bip32_key_from_parent_path(
        &keydata->xpriv, &GA_PATH_ROOT, 1, BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH, &derived));

    // 2. Get it as an 'extended public key' byte-array
    memcpy(extkeydata, derived.chain_code, EC_PRIVATE_KEY_LEN);
    memcpy(extkeydata + EC_PRIVATE_KEY_LEN, derived.pub_key, EC_PUBLIC_KEY_LEN);
    SENSITIVE_POP(&derived);

    // 3. HMAC the fixed GA key message with 2. to yield the 512-bit 'service path' for this mnemonic/private key
    JADE_WALLY_VERIFY(wally_hmac_sha512(GA_KEY_MSG, sizeof(GA_KEY_MSG), extkeydata, sizeof(extkeydata),
        keydata->service_path, sizeof(keydata->service_path)));
    SENSITIVE_POP(extkeydata);

    // Debug log
    // char *logbuf = NULL;
    // wally_hex_from_bytes(keydata->service_path, sizeof(keydata->service_path), &logbuf);
    // JADE_LOGI("Service path: %s", logbuf);
    // wally_free_string(logbuf);

    return true;
}

void keychain_get_new_mnemonic(char** mnemonic)
{
    JADE_ASSERT(mnemonic);

    unsigned char entropy[BIP39_ENTROPY_LEN_256];
    SENSITIVE_PUSH(entropy, sizeof(entropy));

    get_random(entropy, BIP39_ENTROPY_LEN_256);
    const int wret = bip39_mnemonic_from_bytes(NULL, entropy, BIP39_ENTROPY_LEN_256, mnemonic);
    SENSITIVE_POP(entropy);
    JADE_WALLY_VERIFY(wret);
    JADE_WALLY_VERIFY(bip39_mnemonic_validate(NULL, *mnemonic));
}

bool keychain_get_aes_key(const unsigned char* server_key, const size_t key_len, const uint8_t* pin,
    const size_t pin_size, unsigned char* aeskey, const size_t aes_len)
{

    if (!server_key || key_len != SHA256_LEN || !pin || pin_size == 0 || !aeskey || aes_len != HMAC_SHA256_LEN) {
        return false;
    }

    JADE_WALLY_VERIFY(wally_hmac_sha256(server_key, key_len, pin, pin_size, aeskey, aes_len));
    return true;
}

// Derive keys from mnemonic if passed a valid mnemonic
bool keychain_derive(const char* mnemonic, keychain_t* keydata)
{
    if (!mnemonic || !keydata) {
        return false;
    }

    // Mnemonic must be valid
    if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
        JADE_LOGE("Invalid mnemonic");
        return false;
    }

    unsigned char seed[BIP32_ENTROPY_LEN_512];
    SENSITIVE_PUSH(seed, sizeof(seed));

    size_t written = 0;
    JADE_WALLY_VERIFY(bip39_mnemonic_to_seed(mnemonic, NULL, seed, sizeof(seed), &written));
    JADE_ASSERT_MSG(written == sizeof(seed), "Unexpected seed length: %u", written);

    keychain_derive_from_seed(seed, sizeof(seed), keydata);

    SENSITIVE_POP(seed);
    return true;
}

void keychain_derive_from_seed(const unsigned char* seed, const size_t seed_len, keychain_t* keydata)
{
    JADE_ASSERT(seed);
    JADE_ASSERT(seed_len);
    JADE_ASSERT(keydata);

    // Use mainnet version by default - will be overridden if key serialised for specific network
    // (eg. in get_xpub call).
    JADE_WALLY_VERIFY(bip32_key_from_seed(seed, seed_len, BIP32_VER_MAIN_PRIVATE, 0, &keydata->xpriv));
    JADE_WALLY_VERIFY(
        wally_asset_blinding_key_from_seed(seed, seed_len, keydata->master_unblinding_key, HMAC_SHA512_LEN));

    if (!populate_service_path(keydata)) {
        JADE_ASSERT_MSG(false, "Failed to compute GA service path");
    }
}

static bool serialize(unsigned char* serialized, const keychain_t* keydata)
{
    JADE_ASSERT(serialized);
    JADE_ASSERT(keydata);

    JADE_WALLY_VERIFY(bip32_key_serialize(&keydata->xpriv, BIP32_FLAG_KEY_PRIVATE, serialized, BIP32_SERIALIZED_LEN));
    memcpy(serialized + BIP32_SERIALIZED_LEN, keydata->service_path, HMAC_SHA512_LEN);
    memcpy(serialized + BIP32_SERIALIZED_LEN + HMAC_SHA512_LEN, keydata->master_unblinding_key, HMAC_SHA512_LEN);

    return true;
}

bool keychain_store_encrypted(const unsigned char* aeskey, const size_t aes_len, const keychain_t* keydata)
{
    unsigned char encrypted[ENCRYPTED_SIZE_AES]; // iv, payload, hmac
    unsigned char serialized[SERIALIZED_SIZE];
    unsigned char iv[AES_BLOCK_LEN];

    if (!aeskey || aes_len != AES_KEY_LEN_256 || !keydata) {
        return false;
    }

    SENSITIVE_PUSH(serialized, sizeof(serialized));
    SENSITIVE_PUSH(iv, sizeof(iv));

    // 1. Copy initialisation vector into the buffer
    get_random(iv, AES_BLOCK_LEN);
    memcpy(encrypted, iv, AES_BLOCK_LEN);

    // 2. Write the encrypted payload into the buffer
    size_t written = 0;
    const size_t writable = ENCRYPTED_SIZE_AES - (AES_BLOCK_LEN + HMAC_SHA256_LEN);
    if (!serialize(serialized, keydata)) {
        JADE_LOGE("Failed to serialise key data");
        SENSITIVE_POP(iv);
        SENSITIVE_POP(serialized);
        return false;
    }
    const int wret = wally_aes_cbc(aeskey, aes_len, iv, AES_BLOCK_LEN, serialized, SERIALIZED_SIZE, AES_FLAG_ENCRYPT,
        encrypted + AES_BLOCK_LEN, writable, &written);
    SENSITIVE_POP(iv);
    SENSITIVE_POP(serialized);
    JADE_WALLY_VERIFY(wret);
    JADE_ASSERT(written == writable);

    // 3. Write the hmac into the buffer
    JADE_WALLY_VERIFY(wally_hmac_sha256(aeskey, aes_len, encrypted, ENCRYPTED_SIZE_AES - HMAC_SHA256_LEN,
        encrypted + ENCRYPTED_SIZE_AES - HMAC_SHA256_LEN, HMAC_SHA256_LEN));
    if (!storage_set_encrypted_blob(encrypted, sizeof(encrypted))) {
        JADE_LOGE("Failed to store encrypted key data");
        return false;
    }

    // Clear main/test network restriction
    keychain_clear_network_type_restriction();

    return true;
}

static bool unserialize(const unsigned char* decrypted, keychain_t* keydata)
{
    JADE_ASSERT(decrypted);
    JADE_ASSERT(keydata);

    JADE_WALLY_VERIFY(bip32_key_unserialize(decrypted, BIP32_SERIALIZED_LEN, &keydata->xpriv));

    memcpy(keydata->service_path, decrypted + BIP32_SERIALIZED_LEN, HMAC_SHA512_LEN);
    memcpy(keydata->master_unblinding_key, decrypted + BIP32_SERIALIZED_LEN + HMAC_SHA512_LEN, HMAC_SHA512_LEN);

    return true;
}

static bool verify_hmac(const unsigned char* aeskey, const unsigned char* encrypted)
{
    JADE_ASSERT(aeskey);
    JADE_ASSERT(encrypted);
    unsigned char hmacsha[HMAC_SHA256_LEN];

    JADE_WALLY_VERIFY(wally_hmac_sha256(
        aeskey, AES_KEY_LEN_256, encrypted, ENCRYPTED_SIZE_AES - HMAC_SHA256_LEN, hmacsha, HMAC_SHA256_LEN));
    return crypto_verify_32(hmacsha, encrypted + ENCRYPTED_SIZE_AES - HMAC_SHA256_LEN) == 0;
}

bool keychain_load_cleartext(const unsigned char* aeskey, const size_t aes_len, keychain_t* keydata)
{
    unsigned char encrypted[ENCRYPTED_SIZE_AES];
    unsigned char decrypted[SERIALIZED_SIZE];

    if (!aeskey || aes_len != AES_KEY_LEN_256 || !keydata) {
        return false;
    }

    if (!storage_decrement_counter()) {
        return false;
    }

    if (!storage_get_encrypted_blob(encrypted, sizeof(encrypted))) {
        storage_erase_encrypted_blob();
        return false;
    }

    if (!verify_hmac(aeskey, encrypted)) {
        JADE_LOGW("Failed to decrypt key data (bad pin)");
        if (storage_get_counter() == 0) {
            JADE_LOGW("Multiple failures to decrypt key data - erasing encrypted keys");
            storage_erase_encrypted_blob();
        }
        return false;
    }

    // ignore failure as it can't make things worse
    storage_restore_counter();

    size_t written = 0;
    SENSITIVE_PUSH(decrypted, sizeof(decrypted));
    JADE_WALLY_VERIFY(wally_aes_cbc(aeskey, aes_len, encrypted, AES_BLOCK_LEN, encrypted + AES_BLOCK_LEN,
        SERIALIZED_SIZE_AES, AES_FLAG_DECRYPT, decrypted, SERIALIZED_SIZE, &written));
    JADE_ASSERT(written == SERIALIZED_SIZE);
    const bool ret = unserialize(decrypted, keydata);
    JADE_ASSERT(ret);
    SENSITIVE_POP(decrypted);

    // Cache whether we are restricted to main/test networks
    network_type_restriction = storage_get_network_type_restriction();

    return true;
}

bool keychain_has_pin() { return keychain_pin_attempts_remaining() > 0; }

uint8_t keychain_pin_attempts_remaining() { return storage_get_counter(); }

bool keychain_get_new_privatekey(unsigned char* privatekey, const size_t size)
{
    if (!privatekey || size != EC_PRIVATE_KEY_LEN) {
        return false;
    }

    for (size_t counter = 4; counter > 0; --counter) {
        get_random(privatekey, size);

        if (wally_ec_private_key_verify(privatekey, size) == WALLY_OK) {
            JADE_LOGD("Created new random private key");
            return true;
        }
    }

    // Exhausted attempts
    JADE_LOGE("Exhausted attempts creating new private key");
    return false;
}

bool keychain_init()
{
    unsigned char privatekey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(privatekey, sizeof(privatekey));

    bool res = storage_get_pin_privatekey(privatekey, sizeof(privatekey));
    if (!res) {
        if (!keychain_get_new_privatekey(privatekey, sizeof(privatekey))) {
            JADE_LOGE("Failed to create new hw private key");
            SENSITIVE_POP(privatekey);
            return false;
        }
        res = storage_set_pin_privatekey(privatekey, sizeof(privatekey));
        if (res) {
            JADE_LOGI("Initialised new hw private key");
        } else {
            JADE_LOGE("Failed to set new hw private key");
        }
    }
    SENSITIVE_POP(privatekey);
    return res;
}
