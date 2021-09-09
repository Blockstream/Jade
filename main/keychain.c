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

// Size of keydata_t elements - ext-key, ga-path, master-blinding-key
#define SERIALIZED_KEY_LEN (BIP32_SERIALIZED_LEN + HMAC_SHA512_LEN + HMAC_SHA512_LEN)

// Round 'len' up to next multiple of AES_BLOCK_LEN
// NOTE: exact multiple are rounded up to the next multiple
#define SERIALIZED_AES_LEN(len) (((len / AES_BLOCK_LEN) + 1) * AES_BLOCK_LEN)

// iv, padded payload (un-padded length provided), hmac
#define ENCRYPTED_AES_LEN(len) (SERIALIZED_AES_LEN(len) + AES_BLOCK_LEN + HMAC_SHA256_LEN)

// GA derived key index, and fixed GA key message
static const uint32_t GA_PATH_ROOT = BIP32_INITIAL_HARDENED_CHILD + 0x4741;
static const unsigned char GA_KEY_MSG[] = "GreenAddress.it HD wallet path";

// Internal variables - the single/global keychain data
static keychain_t* keychain_data = NULL;
static network_type_t network_type_restriction = NETWORK_TYPE_NONE;
static bool has_encrypted_blob = false;
static uint8_t keychain_userdata = 0;
static bool keychain_temporary = false;

// If using a passphrase we may need to cache the mnemonic entropy
// while the passphrase is entered and the wallet master key derived.
static uint8_t mnemonic_entropy[BIP39_ENTROPY_LEN_256]; // Maximum supported entropy is 24 words
static size_t mnemonic_entropy_len = 0;

void keychain_set(const keychain_t* src, const uint8_t userdata, const bool temporary)
{
    JADE_ASSERT(src);

    // Copy-from-self is no-op for keys (but we may override 'userdata' below)
    if (src != keychain_data) {
        // Maybe freeing and re-allocing is unnecessary, but shouldn't happen very
        // often, and ensures it is definitely in dram.  Better safe ...
        keychain_free();
        keychain_data = JADE_MALLOC_DRAM(sizeof(keychain_t));
        memcpy(keychain_data, src, sizeof(keychain_t));
    }

    // Clear any mnemonic entropy we may have been holding
    wally_bzero(mnemonic_entropy, sizeof(mnemonic_entropy));
    mnemonic_entropy_len = 0;

    // Hold the associated userdata
    keychain_userdata = userdata;

    // Store whether this is intended to be a temporary keychain
    keychain_temporary = temporary;
}

void keychain_free(void)
{
    if (keychain_data) {
        wally_bzero(keychain_data, sizeof(keychain_t));
        free(keychain_data);
        keychain_data = NULL;
    }

    // Clear any mnemonic entropy we may have been holding
    wally_bzero(mnemonic_entropy, sizeof(mnemonic_entropy));
    mnemonic_entropy_len = 0;

    keychain_userdata = 0;
    keychain_temporary = false;
}

const keychain_t* keychain_get(void) { return keychain_data; }

bool keychain_has_temporary(void)
{
    JADE_ASSERT(!keychain_temporary || keychain_data);
    return keychain_temporary;
}

uint8_t keychain_get_userdata(void) { return keychain_userdata; }

// Cache/clear mnemonic entropy (if using passphrase)
void keychain_cache_mnemonic_entropy(const char* mnemonic)
{
    JADE_ASSERT(mnemonic);
    JADE_ASSERT(!keychain_temporary);
    JADE_ASSERT(!mnemonic_entropy_len);

    JADE_WALLY_VERIFY(
        bip39_mnemonic_to_bytes(NULL, mnemonic, mnemonic_entropy, sizeof(mnemonic_entropy), &mnemonic_entropy_len));

    // Only 12 or 24 word mnemonics are supported
    JADE_ASSERT(mnemonic_entropy_len == BIP39_ENTROPY_LEN_128 || mnemonic_entropy_len == BIP39_ENTROPY_LEN_256);
}

// Clear the network type restriction
void keychain_clear_network_type_restriction(void)
{
    JADE_LOGI("Clearing network type restriction");
    storage_set_network_type_restriction(NETWORK_TYPE_NONE);
    network_type_restriction = NETWORK_TYPE_NONE;
}

// Set the network type restriction (must currently be 'none', or same as passed).
void keychain_set_network_type_restriction(const char* network)
{
    JADE_ASSERT(keychain_is_network_type_consistent(network));

    if (network_type_restriction == NETWORK_TYPE_NONE) {
        const network_type_t network_type = isTestNetwork(network) ? NETWORK_TYPE_TEST : NETWORK_TYPE_MAIN;
        JADE_LOGI("Restricting to network type: %s", network_type == NETWORK_TYPE_TEST ? "TEST" : "MAIN");
        storage_set_network_type_restriction(network_type);
        network_type_restriction = network_type;
    }
}

// Compare pinned/restricted network type and the type of the network passed
bool keychain_is_network_type_consistent(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));
    const network_type_t network_type = isTestNetwork(network) ? NETWORK_TYPE_TEST : NETWORK_TYPE_MAIN;
    return network_type_restriction == NETWORK_TYPE_NONE || network_type == network_type_restriction;
}

// Helper to create the service/gait path.
// (The below is correct for newly created wallets, verified in regtest).
static void populate_service_path(keychain_t* keydata)
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
}

void keychain_get_new_mnemonic(char** mnemonic, const size_t nwords)
{
    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);
    JADE_ASSERT(mnemonic);

    // Large enough for 12 and 24 word mnemonic
    unsigned char entropy[BIP39_ENTROPY_LEN_256];
    SENSITIVE_PUSH(entropy, sizeof(entropy));

    const size_t entropy_len = nwords == 12 ? BIP39_ENTROPY_LEN_128 : BIP39_ENTROPY_LEN_256;
    get_random(entropy, entropy_len);
    const int wret = bip39_mnemonic_from_bytes(NULL, entropy, entropy_len, mnemonic);
    SENSITIVE_POP(entropy);
    JADE_WALLY_VERIFY(wret);
    JADE_WALLY_VERIFY(bip39_mnemonic_validate(NULL, *mnemonic));
}

void keychain_derive_from_seed(const unsigned char* seed, const size_t seed_len, keychain_t* keydata)
{
    JADE_ASSERT(seed);
    JADE_ASSERT(seed_len);
    JADE_ASSERT(keydata);

    // Use mainnet version by default - will be overridden if key serialised for specific network
    // (eg. in get_xpub call).
    JADE_WALLY_VERIFY(bip32_key_from_seed(seed, seed_len, BIP32_VER_MAIN_PRIVATE, 0, &keydata->xpriv));

    // NOTE: 'master_unblinding_key' is stored here as the full output of hmac512, when according to slip-0077
    // the master unblinding key is only the second half of that - ie. 256 bits.
    JADE_WALLY_VERIFY(
        wally_asset_blinding_key_from_seed(seed, seed_len, keydata->master_unblinding_key, HMAC_SHA512_LEN));

    // Compute and cache the path the GA server will use to sign
    populate_service_path(keydata);
}

// Derive keys from mnemonic if passed a valid mnemonic
bool keychain_derive_from_mnemonic(const char* mnemonic, const char* passphrase, keychain_t* keydata)
{
    // NOTE: passphrase is optional, but if passed must fit the size limit
    if (!mnemonic || !keydata) {
        return false;
    }
    if (passphrase) {
        const size_t passphrase_len = strnlen(passphrase, PASSPHRASE_MAX_LEN + 1);
        if (passphrase_len > PASSPHRASE_MAX_LEN) {
            JADE_LOGE("Passphrase too long");
            return false;
        }
    }

    // Mnemonic must be valid
    if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
        JADE_LOGE("Invalid mnemonic");
        return false;
    }

    unsigned char seed[BIP32_ENTROPY_LEN_512];
    SENSITIVE_PUSH(seed, sizeof(seed));

    size_t written = 0;
    JADE_WALLY_VERIFY(bip39_mnemonic_to_seed(mnemonic, passphrase, seed, sizeof(seed), &written));
    JADE_ASSERT_MSG(written == sizeof(seed), "Unexpected seed length: %u", written);

    keychain_derive_from_seed(seed, sizeof(seed), keydata);

    SENSITIVE_POP(seed);
    return true;
}

static void serialize(unsigned char* serialized, const size_t serialized_len, const keychain_t* keydata)
{
    JADE_ASSERT(serialized);
    JADE_ASSERT(serialized_len == SERIALIZED_KEY_LEN);
    JADE_ASSERT(keydata);

    // ext-key, ga-path, master-blinding-key
    JADE_WALLY_VERIFY(bip32_key_serialize(&keydata->xpriv, BIP32_FLAG_KEY_PRIVATE, serialized, BIP32_SERIALIZED_LEN));
    memcpy(serialized + BIP32_SERIALIZED_LEN, keydata->service_path, HMAC_SHA512_LEN);
    memcpy(serialized + BIP32_SERIALIZED_LEN + HMAC_SHA512_LEN, keydata->master_unblinding_key, HMAC_SHA512_LEN);
}

static void unserialize(const unsigned char* decrypted, const size_t decrypted_len, keychain_t* keydata)
{
    JADE_ASSERT(decrypted);
    JADE_ASSERT(decrypted_len == SERIALIZED_KEY_LEN);
    JADE_ASSERT(keydata);

    // ext-key, ga-path, master-blinding-key
    JADE_WALLY_VERIFY(bip32_key_unserialize(decrypted, BIP32_SERIALIZED_LEN, &keydata->xpriv));
    memcpy(keydata->service_path, decrypted + BIP32_SERIALIZED_LEN, HMAC_SHA512_LEN);
    memcpy(keydata->master_unblinding_key, decrypted + BIP32_SERIALIZED_LEN + HMAC_SHA512_LEN, HMAC_SHA512_LEN);
}

static void get_encrypted_blob(const unsigned char* aeskey, const size_t aes_len, const uint8_t* bytes,
    const size_t bytes_len, uint8_t* output, const size_t output_len)
{
    JADE_ASSERT(aeskey);
    JADE_ASSERT(aes_len == AES_KEY_LEN_256);
    JADE_ASSERT(bytes);
    JADE_ASSERT(bytes_len > 0);
    JADE_ASSERT(output);

    const size_t payload_len = SERIALIZED_AES_LEN(bytes_len); // round up to whole number of blocks
    JADE_ASSERT(payload_len % AES_BLOCK_LEN == 0); // whole number of blocks
    JADE_ASSERT(output_len == AES_BLOCK_LEN + payload_len + HMAC_SHA256_LEN); // iv, payload, hmac

    // 1. Generate random iv
    get_random(output, AES_BLOCK_LEN);

    // 2. Encrypt the passed bytes into the buffer (after the iv)
    size_t written = 0;
    const int wret = wally_aes_cbc(aeskey, aes_len, output, AES_BLOCK_LEN, bytes, bytes_len, AES_FLAG_ENCRYPT,
        output + AES_BLOCK_LEN, payload_len, &written);
    JADE_WALLY_VERIFY(wret);
    JADE_ASSERT(written == payload_len);

    // 3. Write the hmac into the buffer
    JADE_WALLY_VERIFY(wally_hmac_sha256(
        aeskey, aes_len, output, output_len - HMAC_SHA256_LEN, output + output_len - HMAC_SHA256_LEN, HMAC_SHA256_LEN));
}

static bool get_decrypted_payload(const unsigned char* aeskey, const size_t aes_len, const uint8_t* bytes,
    const size_t bytes_len, uint8_t* output, const size_t output_len, size_t* written)
{
    JADE_ASSERT(aeskey);
    JADE_ASSERT(aes_len == AES_KEY_LEN_256);
    JADE_ASSERT(bytes);
    JADE_ASSERT(bytes_len > AES_BLOCK_LEN + HMAC_SHA256_LEN); // iv, no-payload, hmac
    JADE_ASSERT(output);

    const size_t payload_len = bytes_len - (AES_BLOCK_LEN + HMAC_SHA256_LEN);
    JADE_ASSERT(payload_len % AES_BLOCK_LEN == 0); // whole number of blocks
    JADE_ASSERT(output_len >= payload_len);

    // 1. Verify HMAC
    unsigned char hmac_calculated[HMAC_SHA256_LEN];
    JADE_WALLY_VERIFY(wally_hmac_sha256(
        aeskey, aes_len, bytes, bytes_len - HMAC_SHA256_LEN, hmac_calculated, sizeof(hmac_calculated)));
    if (crypto_verify_32(hmac_calculated, bytes + bytes_len - HMAC_SHA256_LEN) != 0) {
        JADE_LOGW("hmac mismatch (bad pin)");
        return false;
    }

    // 2. Decrypt
    JADE_WALLY_VERIFY(wally_aes_cbc(aeskey, aes_len, bytes, AES_BLOCK_LEN, bytes + AES_BLOCK_LEN, payload_len,
        AES_FLAG_DECRYPT, output, output_len, written));
    JADE_ASSERT(*written <= output_len);

    return true;
}

bool keychain_store_encrypted(const unsigned char* aeskey, const size_t aes_len)
{
    if (!aeskey || aes_len != AES_KEY_LEN_256) {
        return false;
    }
    if (!keychain_data) {
        // No keychain data to store
        return false;
    }

    unsigned char serialized[SERIALIZED_KEY_LEN];
    unsigned char encrypted[ENCRYPTED_AES_LEN(sizeof(serialized))];
    SENSITIVE_PUSH(encrypted, sizeof(encrypted));

    // 1. Serialise keychain
    SENSITIVE_PUSH(serialized, sizeof(serialized));
    serialize(serialized, sizeof(serialized), keychain_data);

    // 2. Get as encrypted blob
    get_encrypted_blob(aeskey, aes_len, serialized, sizeof(serialized), encrypted, sizeof(encrypted));
    SENSITIVE_POP(serialized);

    // 3. Push into flash storage
    if (!storage_set_encrypted_blob(encrypted, sizeof(encrypted))) {
        JADE_LOGE("Failed to store encrypted key data");
        SENSITIVE_POP(encrypted);
        return false;
    }
    SENSITIVE_POP(encrypted);

    // 4. Clear main/test network restriction and cache that we have encrypted keys
    keychain_clear_network_type_restriction();
    has_encrypted_blob = true;

    return true;
}

bool keychain_load_cleartext(const unsigned char* aeskey, const size_t aes_len)
{
    if (!aeskey || aes_len != AES_KEY_LEN_256) {
        return false;
    }
    if (keychain_data) {
        // We already have loaded keychain data - do not overwrite
        return false;
    }
    if (!keychain_has_pin() || !storage_decrement_counter()) {
        // No valid keychain data in storage to load
        return false;
    }

    unsigned char serialized[SERIALIZED_AES_LEN(SERIALIZED_KEY_LEN)];
    unsigned char encrypted[ENCRYPTED_AES_LEN(SERIALIZED_KEY_LEN)];

    // 1. Load from flash storage
    size_t written = 0;
    if (!storage_get_encrypted_blob(encrypted, sizeof(encrypted), &written) || written != sizeof(encrypted)) {
        JADE_LOGW("Failed to load encrypted blob from storage - ensuring fully erased");
        storage_erase_encrypted_blob();
        has_encrypted_blob = false;
        return false;
    }

    // 2. Get decrypted payload from the encrypted blob
    written = 0;
    SENSITIVE_PUSH(serialized, sizeof(serialized));
    if (!get_decrypted_payload(aeskey, aes_len, encrypted, sizeof(encrypted), serialized, sizeof(serialized), &written)
        || written != SERIALIZED_KEY_LEN) {
        JADE_LOGW("Failed to decrypt key data (bad pin)");
        if (keychain_pin_attempts_remaining() == 0) {
            JADE_LOGW("Multiple failures to decrypt key data - erasing encrypted keys");
            storage_erase_encrypted_blob();
            keychain_clear_network_type_restriction();
            has_encrypted_blob = false;
        }
        SENSITIVE_POP(serialized);
        return false;
    }

    // 3. Decrypt succeed so pin ok - reset counter
    // (Ignore failure as it can't make things worse)
    storage_restore_counter();

    // 4. Deserialise keychain
    keychain_t keydata;
    SENSITIVE_PUSH(&keydata, sizeof(keydata));
    unserialize(serialized, written, &keydata);
    keychain_set(&keydata, 0, false);
    SENSITIVE_POP(&keydata);
    SENSITIVE_POP(serialized);

    return true;
}

bool keychain_has_pin(void) { return has_encrypted_blob; }

uint8_t keychain_pin_attempts_remaining(void) { return storage_get_counter(); }

bool keychain_get_new_privatekey(unsigned char* privatekey, const size_t size)
{
    if (!privatekey || size != EC_PRIVATE_KEY_LEN) {
        return false;
    }

    for (size_t attempts = 0; attempts < 4; ++attempts) {
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

bool keychain_init(void)
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

    // Cache whether we are restricted to main/test networks and whether we have an encrypted blob
    network_type_restriction = storage_get_network_type_restriction();
    has_encrypted_blob = keychain_pin_attempts_remaining() > 0;

    return res;
}
