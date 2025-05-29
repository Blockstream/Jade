#ifndef AMALGAMATED_BUILD
#include "keychain.h"
#include "aes.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "random.h"
#include "sensitive.h"
#include "storage.h"
#include "utils/malloc_ext.h"
#include "utils/network.h"
#include "wallet.h"

#include <sodium/crypto_verify_32.h>
#include <string.h>
#include <wally_bip39.h>
#include <wally_elements.h>

// Size of keydata_t elements - ext-key, ga-path, master-blinding-key
#define SERIALIZED_KEY_LEN (BIP32_SERIALIZED_LEN + HMAC_SHA512_LEN + HMAC_SHA512_LEN)

// Encrypted length plus hmac (input length given)
#define ENCRYPTED_DATA_LEN(len) (AES_ENCRYPTED_LEN(len) + HMAC_SHA256_LEN)

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

// Cached key flags
static uint8_t key_flags = 0;

void keychain_set(const keychain_t* src, const uint8_t userdata, const bool temporary)
{
    JADE_ASSERT(src);

    // We will hold any loaded keychain here - saves malloc'ing a struct which
    // can fragment DRAM (as will be persistent once allocated).
    static keychain_t internal_keychain = { 0 };

    // Copy-from-self is no-op for keys (but we may override 'userdata' below)
    if (src != keychain_data) {
        keychain_clear();
        keychain_data = &internal_keychain;
        memcpy(keychain_data, src, sizeof(keychain_t));
    }

    // Clear any mnemonic entropy we may have been holding
    JADE_WALLY_VERIFY(wally_bzero(mnemonic_entropy, sizeof(mnemonic_entropy)));
    mnemonic_entropy_len = 0;

    // Reload key flags
    key_flags = storage_get_key_flags();

    // Hold the associated userdata
    keychain_userdata = userdata;

    // Store whether this is intended to be a temporary keychain
    keychain_temporary = temporary;
}

void keychain_clear(void)
{
    if (keychain_data) {
        JADE_WALLY_VERIFY(wally_bzero(keychain_data, sizeof(keychain_t)));
        keychain_data = NULL;
    }

    // Clear any mnemonic entropy we may have been holding
    JADE_WALLY_VERIFY(wally_bzero(mnemonic_entropy, sizeof(mnemonic_entropy)));
    mnemonic_entropy_len = 0;

    // Reload key flags
    key_flags = storage_get_key_flags();

    keychain_userdata = 0;
    keychain_temporary = false;
}

const keychain_t* keychain_get(void) { return keychain_data; }

bool keychain_requires_passphrase(void)
{
    // We require a passphrase when we have mnemonic entropy but no key data as yet
    // ie. the final wallet derivation step has yet to occur.
    // (This may be an explicitly user-provided phrase, or may be the default/blank phrase)
    return !keychain_data && mnemonic_entropy_len;
}

void keychain_set_passphrase_frequency(const passphrase_freq_t freq)
{
    switch (freq) {
    case PASSPHRASE_NEVER:
        key_flags |= KEY_FLAGS_AUTO_DEFAULT_PASSPHRASE;
        key_flags &= ~KEY_FLAGS_USER_TO_ENTER_PASSPHRASE;
        break;
    case PASSPHRASE_ALWAYS:
        key_flags &= ~KEY_FLAGS_AUTO_DEFAULT_PASSPHRASE;
        key_flags |= KEY_FLAGS_USER_TO_ENTER_PASSPHRASE;
        break;
    case PASSPHRASE_ONCE:
        // Set both 'auto default' and 'user to set' to imply
        // 'user to enter just this once, but usually auto-default'
        key_flags |= KEY_FLAGS_AUTO_DEFAULT_PASSPHRASE;
        key_flags |= KEY_FLAGS_USER_TO_ENTER_PASSPHRASE;
        break;
    default:
        JADE_LOGE("Unexpected passphrase frequency flag ignored: %u", freq);
    }
}

passphrase_freq_t keychain_get_passphrase_freq(void)
{
    // NOTE: Both flags set implies 'once only'
    return (key_flags & KEY_FLAGS_USER_TO_ENTER_PASSPHRASE)
        ? ((key_flags & KEY_FLAGS_AUTO_DEFAULT_PASSPHRASE) ? PASSPHRASE_ONCE : PASSPHRASE_ALWAYS)
        : PASSPHRASE_NEVER;
}

void keychain_set_passphrase_type(const passphrase_type_t type)
{
    if (type == PASSPHRASE_WORDLIST) {
        key_flags |= KEY_FLAGS_WORDLIST_PASSPHRASE;
    } else {
        key_flags &= ~KEY_FLAGS_WORDLIST_PASSPHRASE;
    }
}

passphrase_type_t keychain_get_passphrase_type(void)
{
    return (key_flags & KEY_FLAGS_WORDLIST_PASSPHRASE) ? PASSPHRASE_WORDLIST : PASSPHRASE_FREETEXT;
}

void keychain_set_confirm_export_blinding_key(const bool confirm_export)
{
    if (confirm_export) {
        key_flags |= KEY_FLAGS_CONFIRM_EXPORT_BLINDING_KEY;
    } else {
        key_flags &= ~KEY_FLAGS_CONFIRM_EXPORT_BLINDING_KEY;
    }
}

bool keychain_get_confirm_export_blinding_key(void) { return (key_flags & KEY_FLAGS_CONFIRM_EXPORT_BLINDING_KEY); }

void keychain_persist_key_flags(void)
{
    // If both the 'auto-default (ie. empty) passphrase' flag and the 'ask user for passphrase'
    // flags are set, then we ask the user for a passphrase *just for the
    // current session/next-login*.
    // ie. We cache the 'user to enter passphrase' flag in memory, but we persist the
    // 'auto-apply empty passphrase' flag into flash nvs.
    // NOTE: the flags use is a bit clumsy because of the way they evolved over time, and we
    // always want to maintain backward-compatibility with the previous meanings of these flags.
    if ((key_flags & KEY_FLAGS_AUTO_DEFAULT_PASSPHRASE) && (key_flags & KEY_FLAGS_USER_TO_ENTER_PASSPHRASE)) {
        storage_set_key_flags(key_flags & ~KEY_FLAGS_USER_TO_ENTER_PASSPHRASE);
    } else {
        storage_set_key_flags(key_flags);
    }
}

// Only for use under specific circumstances during wallet setup, when the initialisation is
// started as standard/pin-protected, but the user then wants to flip to temporary-wallet only.
void keychain_set_temporary(void)
{
    // This combination should only occur when part way through initial setup
    JADE_ASSERT(keychain_data);
    JADE_ASSERT(mnemonic_entropy_len);
    JADE_ASSERT(!keychain_temporary);
    JADE_ASSERT(!keychain_has_pin());
    keychain_temporary = true;
}

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
    // If we are not currently working with temporary keys, clear the keys from storage
    if (!keychain_has_temporary()) {
        storage_set_network_type_restriction(NETWORK_TYPE_NONE);
    }
    network_type_restriction = NETWORK_TYPE_NONE;
}

// Set the network type restriction (must currently be 'none', or same as passed).
void keychain_set_network_type_restriction(const network_type_t network_type)
{
    JADE_ASSERT(keychain_is_network_type_consistent(network_type));

    if (network_type_restriction == NETWORK_TYPE_NONE) {
        JADE_LOGI("Restricting to network type: %s", network_type == NETWORK_TYPE_TEST ? "TEST" : "MAIN");

        // If we have a persisted wallet, and we are not currently working with temporary keys
        // then persist the network type to the storage (as it applies to the stored wallet)
        if (keychain_has_pin() && !keychain_has_temporary()) {
            storage_set_network_type_restriction(network_type);
        }

        // If we have keys loaded in memory, set the in-memory value also
        if (keychain_data) {
            network_type_restriction = network_type;
        }
    }
}

// Get the current network type restriction
network_type_t keychain_get_network_type_restriction(void) { return network_type_restriction; }

// Compare pinned/restricted network type and the type of the network passed
bool keychain_is_network_type_consistent(const network_type_t network_type)
{
    return network_type_restriction == NETWORK_TYPE_NONE || network_type == network_type_restriction;
}

bool keychain_is_network_id_consistent(const network_t network_id)
{
    const network_type_t network_type = network_to_type(network_id);
    return keychain_is_network_type_consistent(network_type);
}

const struct ext_key* keychain_cached_service(const struct ext_key* const service, const bool subaccount_root)
{
    JADE_ASSERT(keychain_data);

    // If no service passed, invalidate cache
    if (!service) {
        keychain_data->cached_service = NULL;
        return NULL;
    }

    // Recompute cached values if service mismatch
    if (service != keychain_data->cached_service) {
        wallet_get_gaservice_root_key(service, false, &keychain_data->cached_gaservice_main_root);
        wallet_get_gaservice_root_key(service, true, &keychain_data->cached_gaservice_subact_root);
        keychain_data->cached_service = service;
    }

    // Return cached value
    return subaccount_root ? &keychain_data->cached_gaservice_subact_root : &keychain_data->cached_gaservice_main_root;
}

void keychain_get_new_mnemonic(char** mnemonic, const size_t nwords)
{
    JADE_INIT_OUT_PPTR(mnemonic);

    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);

    // Large enough for 12 and 24 word mnemonic
    uint8_t entropy[BIP39_ENTROPY_LEN_256];
    SENSITIVE_PUSH(entropy, sizeof(entropy));

    const size_t entropy_len = nwords == 12 ? BIP39_ENTROPY_LEN_128 : BIP39_ENTROPY_LEN_256;
    get_random(entropy, entropy_len);
    const int wret = bip39_mnemonic_from_bytes(NULL, entropy, entropy_len, mnemonic);
    SENSITIVE_POP(entropy);
    JADE_WALLY_VERIFY(wret);
    JADE_WALLY_VERIFY(bip39_mnemonic_validate(NULL, *mnemonic));
}

// Derive master key from given seed
void keychain_derive_from_seed(const uint8_t* seed, const size_t seed_len, keychain_t* keydata)
{
    JADE_ASSERT(seed);
    JADE_ASSERT(seed_len);
    JADE_ASSERT(keydata);
    JADE_ASSERT(seed_len <= sizeof(keydata->seed));

    // Cache the seed
    memcpy(keydata->seed, seed, seed_len);
    keydata->seed_len = seed_len;

    // Use mainnet version by default - will be overridden if key serialised for specific network
    // (eg. in get_xpub call).
    JADE_WALLY_VERIFY(bip32_key_from_seed(seed, seed_len, BIP32_VER_MAIN_PRIVATE, 0, &keydata->xpriv));

    // NOTE: 'master_unblinding_key' is stored here as the full output of hmac512, when according to slip-0077
    // the master unblinding key is only the second half of that - ie. 256 bits.
    JADE_WALLY_VERIFY(
        wally_asset_blinding_key_from_seed(seed, seed_len, keydata->master_unblinding_key, HMAC_SHA512_LEN));

    // Compute and cache the path the GA server will use to sign
    wallet_calculate_gaservice_path(&keydata->xpriv, keydata->gaservice_path, GASERVICE_PATH_LEN);

    // Ensure cached green-multisig service path roots are unset
    keydata->cached_service = NULL;
}

// Derive master key from mnemonic if passed a valid mnemonic
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

    uint8_t seed[BIP32_ENTROPY_LEN_512];
    SENSITIVE_PUSH(seed, sizeof(seed));

    size_t written = 0;
    JADE_WALLY_VERIFY(bip39_mnemonic_to_seed(mnemonic, passphrase, seed, sizeof(seed), &written));
    JADE_ASSERT_MSG(written == sizeof(seed), "Unexpected seed length: %u", written);

    keychain_derive_from_seed(seed, sizeof(seed), keydata);

    SENSITIVE_POP(seed);
    return true;
}

// Derive keys from cached mnemonic and passed passphrase
bool keychain_complete_derivation_with_passphrase(const char* passphrase)
{
    if (!passphrase || !keychain_requires_passphrase()) {
        return false;
    }

    keychain_t keydata = { 0 };
    SENSITIVE_PUSH(&keydata, sizeof(keydata));

    // Convert entropy bytes to mnemonic string
    bool ret = false;
    char* mnemonic = NULL;
    if (bip39_mnemonic_from_bytes(NULL, mnemonic_entropy, mnemonic_entropy_len, &mnemonic) != WALLY_OK) {
        JADE_LOGE("Failed to convert entropy bytes to mnemonic string");
        goto cleanup;
    }
    JADE_ASSERT(mnemonic);

    SENSITIVE_PUSH(mnemonic, strlen(mnemonic));
    ret = keychain_derive_from_mnemonic(mnemonic, passphrase, &keydata);
    SENSITIVE_POP(mnemonic);
    JADE_WALLY_VERIFY(wally_free_string(mnemonic));

    if (ret) {
        keychain_set(&keydata, 0, false);
    }

cleanup:
    SENSITIVE_POP(&keydata);
    return ret;
}

static void serialize(uint8_t* serialized, const size_t serialized_len, const keychain_t* keydata)
{
    JADE_ASSERT(serialized);
    JADE_ASSERT(serialized_len == SERIALIZED_KEY_LEN);
    JADE_ASSERT(keydata);

    // ext-key, ga-path, master-blinding-key
    JADE_WALLY_VERIFY(bip32_key_serialize(&keydata->xpriv, BIP32_FLAG_KEY_PRIVATE, serialized, BIP32_SERIALIZED_LEN));
    const bool ret = wallet_serialize_gaservice_path(
        serialized + BIP32_SERIALIZED_LEN, HMAC_SHA512_LEN, keydata->gaservice_path, GASERVICE_PATH_LEN);
    JADE_ASSERT(ret);
    memcpy(serialized + BIP32_SERIALIZED_LEN + HMAC_SHA512_LEN, keydata->master_unblinding_key, HMAC_SHA512_LEN);
}

static void unserialize(const uint8_t* decrypted, const size_t decrypted_len, keychain_t* keydata)
{
    JADE_ASSERT(decrypted);
    JADE_ASSERT(decrypted_len == SERIALIZED_KEY_LEN);
    JADE_ASSERT(keydata);

    // ext-key, ga-path, master-blinding-key
    JADE_WALLY_VERIFY(bip32_key_unserialize(decrypted, BIP32_SERIALIZED_LEN, &keydata->xpriv));
    const bool ret = wallet_unserialize_gaservice_path(
        decrypted + BIP32_SERIALIZED_LEN, HMAC_SHA512_LEN, keydata->gaservice_path, GASERVICE_PATH_LEN);
    JADE_ASSERT(ret);
    memcpy(keydata->master_unblinding_key, decrypted + BIP32_SERIALIZED_LEN + HMAC_SHA512_LEN, HMAC_SHA512_LEN);
}

// AES encrypt passed bytes with passed key (uses new random iv).  Also appends HMAC of the encrypted bytes.
static bool get_encrypted_blob(const uint8_t* aeskey, const size_t aeslen, const uint8_t* bytes, const size_t bytes_len,
    uint8_t* output, const size_t output_len)
{
    JADE_ASSERT(aeskey);
    JADE_ASSERT(aeslen);
    JADE_ASSERT(bytes);
    JADE_ASSERT(bytes_len);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len == AES_ENCRYPTED_LEN(bytes_len) + HMAC_SHA256_LEN); // hmac appended

    // 1. Encrypt the passed data into the start of the buffer
    if (!aes_encrypt_bytes(aeskey, aeslen, bytes, bytes_len, output, output_len - HMAC_SHA256_LEN)) {
        JADE_LOGW("Failed to encrypt wallet!");
        return false;
    }

    // 2. Write the hmac into the buffer after the encrypted data
    JADE_WALLY_VERIFY(wally_hmac_sha256(
        aeskey, aeslen, output, output_len - HMAC_SHA256_LEN, output + output_len - HMAC_SHA256_LEN, HMAC_SHA256_LEN));

    return true;
}

static bool get_decrypted_payload(const uint8_t* aeskey, const size_t aeslen, const uint8_t* bytes,
    const size_t bytes_len, uint8_t* output, const size_t output_len, size_t* written)
{
    JADE_ASSERT(aeskey);
    JADE_ASSERT(aeslen);
    JADE_ASSERT(bytes);
    JADE_ASSERT(bytes_len > HMAC_SHA256_LEN); // hmac appended
    JADE_ASSERT(output);
    JADE_ASSERT(output_len);
    JADE_INIT_OUT_SIZE(written);

    // 1. Verify HMAC at the tail of the input buffer
    uint8_t hmac_calculated[HMAC_SHA256_LEN];
    JADE_WALLY_VERIFY(wally_hmac_sha256(
        aeskey, aeslen, bytes, bytes_len - HMAC_SHA256_LEN, hmac_calculated, sizeof(hmac_calculated)));
    if (crypto_verify_32(hmac_calculated, bytes + bytes_len - HMAC_SHA256_LEN) != 0) {
        JADE_LOGW("hmac mismatch (bad pin)");
        return false;
    }

    // 2. Decrypt bytes at front of buffer
    if (!aes_decrypt_bytes(aeskey, aeslen, bytes, bytes_len - HMAC_SHA256_LEN, output, output_len, written)) {
        JADE_LOGW("Failed to decrypt wallet!");
        return false;
    }

    return true;
}

static bool keychain_encrypt_and_save_blob(
    const uint8_t* aeskey, const size_t aeslen, const uint8_t* cleartext_blob, const size_t blob_len)
{
    if (!aeskey || aeslen != AES_KEY_LEN_256) {
        return false;
    }
    if (!cleartext_blob || blob_len > SERIALIZED_KEY_LEN) {
        // Invlaid cleartext blob
        return false;
    }

    // This buffer is sized for deserialising the extended key structure
    // If instead we are storing mnemonic entropy, the buffer is of ample size.
    uint8_t encrypted[ENCRYPTED_DATA_LEN(SERIALIZED_KEY_LEN)];

    // 1. Get as encrypted blob
    const size_t encrypted_data_len = ENCRYPTED_DATA_LEN(blob_len);
    if (!get_encrypted_blob(aeskey, aeslen, cleartext_blob, blob_len, encrypted, encrypted_data_len)) {
        JADE_LOGE("Failed to encrypt key data");
        return false;
    }

    // 2. Push into flash storage
    if (!storage_set_encrypted_blob(encrypted, encrypted_data_len)) {
        JADE_LOGE("Failed to store encrypted key data");
        return false;
    }

    return true;
}

static bool keychain_load_and_decrypt_blob(
    const uint8_t* aeskey, const size_t aeslen, uint8_t* cleartext_blob, const size_t blob_len, size_t* written)
{
    if (!aeskey || aeslen != AES_KEY_LEN_256 || !cleartext_blob || blob_len < AES_PADDED_LEN(SERIALIZED_KEY_LEN)
        || !written) {
        return false;
    }
    if (!keychain_has_pin() || !storage_decrement_counter()) {
        // No valid keychain data in storage to load
        return false;
    }

    // This buffer is sized for deserialising the extended key structure
    // If instead we are storing mnemonic entropy, the buffer is of ample size.
    uint8_t encrypted[ENCRYPTED_DATA_LEN(SERIALIZED_KEY_LEN)];

    // 1. Load from flash storage
    size_t encrypted_data_len = 0;
    if (!storage_get_encrypted_blob(encrypted, sizeof(encrypted), &encrypted_data_len)) {
        JADE_LOGE("Failed to load encrypted blob from storage - ensuring fully erased");
        storage_erase_encrypted_blob();
        has_encrypted_blob = false;
        return false;
    }

    // 2. Get decrypted payload from the encrypted blob
    if (!get_decrypted_payload(aeskey, aeslen, encrypted, encrypted_data_len, cleartext_blob, blob_len, written)) {
        JADE_LOGW("Failed to decrypt key data (bad pin)");
        if (keychain_pin_attempts_remaining() == 0) {
            JADE_LOGW("Multiple failures to decrypt key data - erasing encrypted keys");
            keychain_erase_encrypted();
        }
        return false;
    }

    // 3. Decrypt succeed so pin ok - reset counter
    // (Ignore failure as it can't make things worse)
    storage_restore_counter();

    return true;
}

bool keychain_store(const uint8_t* aeskey, const size_t aeslen)
{
    if (!aeskey || aeslen != AES_KEY_LEN_256) {
        return false;
    }
    if (!keychain_data && !mnemonic_entropy_len) {
        // No keychain data to store
        return false;
    }

    // This buffer is sized for deserialising the extended key structure
    // If instead we are storing mnemonic entropy, the buffer is of ample size.
    uint8_t serialized[SERIALIZED_KEY_LEN];
    SENSITIVE_PUSH(serialized, sizeof(serialized));

    // If we have cached mnemonic entropy, we store that (as the wallet is passphrase-protected)
    // Otherwise we store the master keychain data (classic)
    uint8_t* p_serialized_data;
    size_t serialized_data_len;

    // 1. Get serialised data to encrypt/persist
    if (mnemonic_entropy_len) {
        // Use mnemonic entropy
        // Only 12 or 24 word mnemonics are supported
        JADE_ASSERT(mnemonic_entropy_len == BIP39_ENTROPY_LEN_128 || mnemonic_entropy_len == BIP39_ENTROPY_LEN_256);
        JADE_ASSERT(mnemonic_entropy_len <= sizeof(mnemonic_entropy));
        JADE_ASSERT(mnemonic_entropy_len < sizeof(serialized));
        p_serialized_data = mnemonic_entropy;
        serialized_data_len = mnemonic_entropy_len;
    } else {
        // Use serialised keychain
        serialize(serialized, sizeof(serialized), keychain_data);
        p_serialized_data = serialized;
        serialized_data_len = sizeof(serialized);
    }

    // 2. Get as encrypted blob and save into storage
    if (!keychain_encrypt_and_save_blob(aeskey, aeslen, p_serialized_data, serialized_data_len)) {
        JADE_LOGE("Failed to encrypt and save key data");
        SENSITIVE_POP(serialized);
        return false;
    }
    SENSITIVE_POP(serialized);

    // 3. Clear main/test network restriction and cache that we have encrypted keys
    keychain_clear_network_type_restriction();
    has_encrypted_blob = true;

    return true;
}

bool keychain_load(const uint8_t* aeskey, const size_t aeslen)
{
    if (!aeskey || aeslen != AES_KEY_LEN_256) {
        return false;
    }
    if (keychain_data || mnemonic_entropy_len) {
        // We already have loaded keychain data - do not overwrite
        return false;
    }
    if (!keychain_has_pin()) {
        // No valid keychain data in storage to load
        return false;
    }

    // This buffer is sized for deserialising the extended key structure
    // If instead we are storing mnemonic entropy, the buffer is of ample size.
    size_t serialized_data_len = 0;
    uint8_t serialized[AES_PADDED_LEN(SERIALIZED_KEY_LEN)];
    SENSITIVE_PUSH(serialized, sizeof(serialized));

    // 1. Load from flash storage and decrypt
    if (!keychain_load_and_decrypt_blob(aeskey, aeslen, serialized, sizeof(serialized), &serialized_data_len)) {
        JADE_LOGE("Failed to load and decrypt blob from storage");
        SENSITIVE_POP(serialized);
        return false;
    }

    // 2. Cache mnemonic entropy or deserialise keychain
    if (serialized_data_len == BIP39_ENTROPY_LEN_128 || serialized_data_len == BIP39_ENTROPY_LEN_256) {
        // Write mnemonic entropy - only 12 or 24 word mnemonics are supported
        memcpy(mnemonic_entropy, serialized, serialized_data_len);
        mnemonic_entropy_len = serialized_data_len;
    } else if (serialized_data_len == SERIALIZED_KEY_LEN) {
        // Deserialise keychain
        keychain_t keydata = { 0 };
        SENSITIVE_PUSH(&keydata, sizeof(keydata));
        unserialize(serialized, serialized_data_len, &keydata);
        keychain_set(&keydata, 0, false);
        SENSITIVE_POP(&keydata);
    } else {
        JADE_LOGE("Unexpected length of decrypted serialised data: %d", serialized_data_len);
        SENSITIVE_POP(serialized);
        return false;
    }
    SENSITIVE_POP(serialized);

    return true;
}

bool keychain_reencrypt(
    const uint8_t* curr_aeskey, const size_t curr_aeslen, const uint8_t* new_aeskey, const size_t new_aeslen)
{
    if (!curr_aeskey || curr_aeslen != AES_KEY_LEN_256 || !new_aeskey || new_aeslen != AES_KEY_LEN_256) {
        return false;
    }

    if (!keychain_has_pin()) {
        // No valid keychain data in storage to load
        return false;
    }

    // This buffer is sized for deserialising the extended key structure
    // If instead we are storing mnemonic entropy, the buffer is of ample size.
    uint8_t serialized[AES_PADDED_LEN(SERIALIZED_KEY_LEN)];
    SENSITIVE_PUSH(serialized, sizeof(serialized));
    size_t serialized_data_len = 0;

    // 1. Load from flash storage and decrypt
    if (!keychain_load_and_decrypt_blob(
            curr_aeskey, curr_aeslen, serialized, sizeof(serialized), &serialized_data_len)) {
        JADE_LOGE("Failed to load and decrypt blob from storage");
        SENSITIVE_POP(serialized);
        return false;
    }

    // 3. Re-encrypt blob (new key) and save to flash storage
    // 2. Get as (re-)encrypted blob (new key) and save into storage
    if (!keychain_encrypt_and_save_blob(new_aeskey, new_aeslen, serialized, serialized_data_len)) {
        JADE_LOGE("Failed to encrypt and save key data");
        SENSITIVE_POP(serialized);
        return false;
    }
    SENSITIVE_POP(serialized);

    return true;
}

bool keychain_has_pin(void) { return has_encrypted_blob; }

uint8_t keychain_pin_attempts_remaining(void) { return storage_get_counter(); }

void keychain_erase_encrypted(void)
{
    storage_erase_encrypted_blob();
    keychain_clear_network_type_restriction();
    has_encrypted_blob = false;
}

bool keychain_get_new_privatekey(uint8_t* privatekey, const size_t size)
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

void keychain_init_cache(void)
{
    // Cache whether we are restricted to main/test networks and whether we have an encrypted blob
    network_type_restriction = storage_get_network_type_restriction();
    has_encrypted_blob = keychain_pin_attempts_remaining() > 0;

    // Cache the user key/passphrase preferences
    key_flags = storage_get_key_flags();
}

bool keychain_init_unit_key(void)
{
    uint8_t privatekey[EC_PRIVATE_KEY_LEN];
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
#endif // AMALGAMATED_BUILD
