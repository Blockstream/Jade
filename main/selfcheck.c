#ifndef AMALGAMATED_BUILD
#include <sdkconfig.h>
#include <string.h>

#include "bcur.h"
#include "jade_wally_verify.h"
#include "multisig.h"
#include "qrmode.h"
#include "random.h"
#include "rsa.h"
#include "selfcheck.h"
#include "storage.h"
#include "utils/malloc_ext.h"
#include "utils/shake256.h"
#include "utils/util.h"
#include "wallet.h"

#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <sodium/crypto_verify_64.h>
#include <sodium/utils.h>

#include <wally_bip32.h>
#include <wally_bip85.h>

int register_multisig_file(const char* multisig_file, size_t multisig_file_len, const char** errmsg);

static const char SERVICE_PATH_HEX[] = "00c9678fbd9d9f6a96bd43221d56733b5aba8f528487602b894e72d0f56e380f7d145b65639db7e"
                                       "e4f528a3fcfb8277b0cbbea00ef64767a531e9a447cacbfbc";

// See macros in keychain.c for calculating encrypted blob lengths below
// (Payload data is padded to next multiple of 16, and is concatenated between iv and hmac)
// 16 (iv) + 208 (length of data stored (78 (key) + 64 (ga path) + 64 (blinding key)) padded to next 16x) + 32 (hmac)
static const size_t FULL_KEY_BLOBLEN = 256;
// 16 (iv) + 32 (12-word entropy (16) padded to next 16x) + 32 (hmac)
static const size_t MNEMONIC_12_ENTROPY_BLOBLEN = 80;
// 16 (iv) + 48 (24-word entropy (32) padded to next 16x) + 32 (hmac)
static const size_t MNEMONIC_24_ENTROPY_BLOBLEN = 96;

// *All* fields are identical
static bool all_fields_same(const keychain_t* keydata1, const keychain_t* keydata2, const bool strict_seeds)
{
    JADE_ASSERT(keydata1);
    JADE_ASSERT(keydata2);

    if (sodium_memcmp(&keydata1->xpriv, &keydata2->xpriv, sizeof(keydata1->xpriv))) {
        return false;
    }
    if (sodium_memcmp(keydata1->gaservice_path, keydata2->gaservice_path, sizeof(keydata1->gaservice_path))) {
        return false;
    }
    if (crypto_verify_64(keydata1->master_unblinding_key, keydata2->master_unblinding_key)) {
        return false;
    }

    // In some cases allow a seed to be missing/blank, in which case don't compare seed data.
    // If both present, seeds must match.  If 'strict_seeds' passed, then seeds must match.
    const bool seed_missing = keydata1->seed_len == 0 || keydata2->seed_len == 0;
    const bool skip_seed_check = seed_missing && !strict_seeds;
    if (!skip_seed_check) {
        if (keydata1->seed_len != keydata2->seed_len) {
            return false;
        }
        if (sodium_memcmp(&keydata1->seed, &keydata2->seed, keydata1->seed_len)) {
            return false;
        }
    }

    return true;
}

// *Any* fields are identical
static bool any_fields_same(const keychain_t* keydata1, const keychain_t* keydata2)
{
    JADE_ASSERT(keydata1);
    JADE_ASSERT(keydata2);

    if (!sodium_memcmp(&keydata1->xpriv, &keydata2->xpriv, sizeof(keydata1->xpriv))) {
        return true;
    }
    if (!sodium_memcmp(keydata1->gaservice_path, keydata2->gaservice_path, sizeof(keydata1->gaservice_path))) {
        return true;
    }
    if (!crypto_verify_64(keydata1->master_unblinding_key, keydata2->master_unblinding_key)) {
        return true;
    }

    // Skip checking seeds if either is unset/blank
    if (keydata1->seed_len && keydata2->seed_len) {
        if (keydata1->seed_len == keydata2->seed_len
            && !sodium_memcmp(&keydata1->seed, &keydata2->seed, keydata1->seed_len)) {
            return true;
        }
    }

    return false;
}

// Restore test mnemonic and check ga service path
static bool test_simple_restore(void)
{
    size_t written = 0;
    uint8_t expected_gaservice_path[HMAC_SHA512_LEN];
    const int ret
        = wally_hex_to_bytes(SERVICE_PATH_HEX, expected_gaservice_path, sizeof(expected_gaservice_path), &written);
    if (ret != WALLY_OK || written != HMAC_SHA512_LEN) {
        FAIL();
    }

    keychain_t keydata = { 0 };
    if (!keychain_derive_from_mnemonic(TEST_MNEMONIC, NULL, &keydata)) {
        FAIL();
    }

    uint8_t serialized[HMAC_SHA512_LEN];
    if (!wallet_serialize_gaservice_path(serialized, sizeof(serialized), keydata.gaservice_path, GASERVICE_PATH_LEN)) {
        FAIL();
    }
    if (crypto_verify_64(serialized, expected_gaservice_path) != 0) {
        FAIL();
    }

    uint32_t deserialised_expected_path[GASERVICE_PATH_LEN];
    if (!wallet_unserialize_gaservice_path(
            expected_gaservice_path, sizeof(expected_gaservice_path), deserialised_expected_path, GASERVICE_PATH_LEN)) {
        FAIL();
    }
    if (sodium_memcmp(keydata.gaservice_path, deserialised_expected_path, sizeof(keydata.gaservice_path))) {
        FAIL();
    }

    return true;
}

// Generate new mnemonics/wallets
// NOTE: only 12- and 24- words supported
static bool test_new_wallets(const size_t nwords)
{
    char* mnemonic;
    keychain_get_new_mnemonic(&mnemonic, nwords);
    if (!mnemonic) {
        FAIL();
    }

    keychain_t keydata1 = { 0 };
    if (!keychain_derive_from_mnemonic(mnemonic, NULL, &keydata1)) {
        WALLY_FREE_STR(mnemonic);
        FAIL();
    }

    keychain_t keydata2 = { 0 };
    if (!keychain_derive_from_mnemonic(mnemonic, "passphrase123", &keydata2)) {
        WALLY_FREE_STR(mnemonic);
        FAIL();
    }

    keychain_t keydata3 = { 0 };
    if (!keychain_derive_from_mnemonic(mnemonic, "different", &keydata3)) {
        WALLY_FREE_STR(mnemonic);
        FAIL();
    }

    WALLY_FREE_STR(mnemonic);

    // Check passphrases lead to completely different wallets
    if (any_fields_same(&keydata1, &keydata2) || any_fields_same(&keydata2, &keydata3)
        || any_fields_same(&keydata3, &keydata1)) {
        FAIL();
    }
    return true;
}

// Check can write key data to storage, and read it back with correct PIN
// Check 3 incorrect PIN attempts erases stored key data
// NOTE: also tests loading legacy wallets
// (master keys rather than mnemonic entropy)
static bool test_storage_with_pin(jade_process_t* process)
{
    JADE_ASSERT(process);

    // Check encryption/decryption and pin attempts exhausted
    keychain_t keydata = { 0 };
    if (!keychain_derive_from_mnemonic(TEST_MNEMONIC, NULL, &keydata)) {
        FAIL();
    }

    uint8_t aeskey[AES_KEY_LEN_256];
    get_random(aeskey, AES_KEY_LEN_256);

    // Save keychain to nvs
    keychain_set(&keydata, process->ctx.source, false);
    if (!keychain_store(aeskey, sizeof(aeskey))) {
        FAIL();
    }
    if (!keychain_has_pin()) {
        FAIL();
    }
    if (storage_get_counter() != 3) {
        FAIL();
    }
    keychain_clear();

    // At this point we should just have stored the full keychain in the blob
    uint8_t blob[FULL_KEY_BLOBLEN];
    size_t blob_len = 0;
    if (!storage_get_encrypted_blob(blob, sizeof(blob), &blob_len)) {
        FAIL();
    }
    if (blob_len != FULL_KEY_BLOBLEN) {
        FAIL();
    }

    // Reload keychain from nvs
    if (!keychain_load(aeskey, sizeof(aeskey))) {
        FAIL();
    }
    if (!keychain_has_pin()) {
        FAIL();
    }
    if (keychain_pin_attempts_remaining() != 3) {
        FAIL();
    }
    if (!all_fields_same(&keydata, keychain_get(), false)) {
        FAIL();
    }

    char* base58res = NULL;
    char* base58res_copy = NULL;
    int val = bip32_key_to_base58(&keydata.xpriv, BIP32_FLAG_KEY_PRIVATE, &base58res);
    if (val != WALLY_OK) {
        FAIL();
    }
    val = bip32_key_to_base58(&keychain_get()->xpriv, BIP32_FLAG_KEY_PRIVATE, &base58res_copy);
    if (val != WALLY_OK) {
        FAIL();
    }
    if (sodium_memcmp(base58res, base58res_copy, strlen(base58res)) != 0) {
        FAIL();
    }
    keychain_clear();

    WALLY_FREE_STR(base58res);
    WALLY_FREE_STR(base58res_copy);

    // Check re-encrypting with new aeskey
    uint8_t new_aeskey[AES_KEY_LEN_256];
    get_random(new_aeskey, AES_KEY_LEN_256);

    if (!keychain_reencrypt(aeskey, sizeof(aeskey), new_aeskey, sizeof(new_aeskey))) {
        FAIL();
    }

    // Should now only load with new aeskey
    if (keychain_load(aeskey, sizeof(aeskey))) {
        FAIL();
    }
    if (!keychain_load(new_aeskey, sizeof(new_aeskey))) {
        FAIL();
    }
    if (!all_fields_same(&keydata, keychain_get(), false)) {
        FAIL();
    }
    keychain_clear();

    // Reload from nvs again ...
    // BUT! pass the wrong aes-key (ie. wrong PIN) 3 times
    for (size_t i = 3; i > 0; --i) {
        if (keychain_pin_attempts_remaining() != i) {
            FAIL();
        }

        if (!keychain_has_pin()) {
            FAIL();
        }

        if (keychain_load(aeskey, sizeof(aeskey))) {
            FAIL();
        }

        if (keychain_pin_attempts_remaining() + 1 != i) {
            FAIL();
        }
    }

    if (keychain_has_pin()) {
        FAIL();
    }

    // Now even the correct key/PIN should fail
    if (keychain_load(new_aeskey, sizeof(new_aeskey))) {
        FAIL();
    }

    return true;
}

// Test storing mnemonic entropy in storage, and deriving wallet with passphrase when reloading
// NOTE: only 12- and 24- words supported
static bool test_storage_with_passphrase(jade_process_t* process, const size_t nwords)
{
    JADE_ASSERT(process);

    uint8_t aeskey[AES_KEY_LEN_256];
    get_random(aeskey, AES_KEY_LEN_256);

    char* mnemonic;
    keychain_get_new_mnemonic(&mnemonic, nwords);
    if (!mnemonic) {
        FAIL();
    }

    keychain_t keydata = { 0 };
    if (!keychain_derive_from_mnemonic(mnemonic, "test123", &keydata)) {
        WALLY_FREE_STR(mnemonic);
        FAIL();
    }

    keychain_set(&keydata, process->ctx.source, false);
    keychain_cache_mnemonic_entropy(mnemonic);
    WALLY_FREE_STR(mnemonic);

    if (!keychain_store(aeskey, sizeof(aeskey))) {
        FAIL();
    }
    if (!keychain_has_pin()) {
        FAIL();
    }
    keychain_clear();

    // At this point we should just have stored a small entropy blob
    uint8_t blob[MNEMONIC_24_ENTROPY_BLOBLEN];
    size_t blob_len = 0;
    if (!storage_get_encrypted_blob(blob, sizeof(blob), &blob_len)) {
        FAIL();
    }
    const size_t expected_blob_len = nwords == 12 ? MNEMONIC_12_ENTROPY_BLOBLEN : MNEMONIC_24_ENTROPY_BLOBLEN;
    if (blob_len != expected_blob_len) {
        FAIL();
    }

    // Reload should prompt for a passphrase
    if (!keychain_load(aeskey, sizeof(aeskey))) {
        FAIL();
    }
    if (!keychain_requires_passphrase()) {
        FAIL();
    }
    if (!keychain_complete_derivation_with_passphrase("test123")) {
        FAIL();
    }

    // Check is same wallet
    if (!all_fields_same(&keydata, keychain_get(), true)) {
        FAIL();
    }
    keychain_clear();

    // Check different passphrase leads to different wallet
    if (!keychain_load(aeskey, sizeof(aeskey))) {
        FAIL();
    }
    if (!keychain_requires_passphrase()) {
        FAIL();
    }
    if (!keychain_complete_derivation_with_passphrase("test12345")) {
        FAIL();
    }

    // Check is NOT same wallet
    if (any_fields_same(&keydata, keychain_get())) {
        FAIL();
    }
    keychain_clear();

    return true;
}

bool test_multisig_files(jade_process_t* process)
{
    JADE_ASSERT(process);

    // Set standard test wallet
    keychain_t keydata = { 0 };
    if (!keychain_derive_from_mnemonic(TEST_MNEMONIC, NULL, &keydata)) {
        FAIL();
    }
    keychain_set(&keydata, process->ctx.source, true);

    const char* nameA = "roundtripperA";
    const char* filedata = "# Passport Multisig setup file (created by Sparrow)\n"
                           "#\n"
                           "Name: roundtripperA\n"
                           "Policy: 2 of 3\n"
                           "Derivation: m/48'/0'/0'/2'\n"
                           "Format: P2WSH\n"
                           "\n"
                           "E3EBCC79: "
                           "xpub6EWJLhf2M3XbBH22hCW69RL6gvfeUyLFfhLBtAH7W8ci4DgTCmEmoDEqkYVME5qAx6DtUG82h4JeNPHV33AoD93"
                           "uGM7MzvuoJNvBmStqhwc\n"
                           "249192D2: "
                           "xpub6EbXynW6xjYR3crcztum6KzSWqDJoAJQoovwamwVnLaCSHA6syXKPnJo6U3bVeGdeEaXAeHsQTxhkLam9Dw2Yfo"
                           "AabtNm44XUWnnUZfHJRq\n"
                           "67F90FFC: "
                           "xpub6EHuWWrYd8bp5FS1XAZsMPkmCqLSjpULmygWqAqWRCCjSWQwz6ntq5KnuQnL23No2Jo8qdp48PrL8SVyf14uBry"
                           "nurgPxonvnX6R5pbit3w\n";

    const char* errmsg = NULL;
    if (register_multisig_file(filedata, strlen(filedata), &errmsg)) {
        FAIL();
    }

    uint8_t registrationA[MULTISIG_BYTES_LEN(0, 3, 12)];
    size_t reglenA = 0;
    if (!storage_get_multisig_registration(nameA, registrationA, sizeof(registrationA), &reglenA)) {
        FAIL();
    }

    multisig_data_t multisig_data;
    signer_t signer_details[3];
    size_t num_signers = 0;
    if (!multisig_data_from_bytes(registrationA, reglenA, &multisig_data, signer_details, 3, &num_signers)) {
        FAIL();
    }
    if (num_signers != 3) {
        FAIL();
    }
    if (signer_details[0].path_is_string || signer_details[1].path_is_string || signer_details[2].path_is_string) {
        FAIL();
    }

    const char* nameB = "roundtripperB";
    char file_out[MULTISIG_FILE_MAX_LEN(3)];
    size_t file_len = 0;
    if (!multisig_create_export_file(
            nameB, &multisig_data, signer_details, num_signers, file_out, sizeof(file_out), &file_len)) {
        FAIL();
    }

    // Can't compare fileA to fileB as format/whitespace/comments etc could be different.
    // But we can re-register and compare serialised bytes which should be same.
    if (register_multisig_file(file_out, file_len, &errmsg)) {
        FAIL();
    }

    uint8_t registrationB[sizeof(registrationA)];
    size_t reglenB = 0;
    if (!storage_get_multisig_registration(nameB, registrationB, sizeof(registrationB), &reglenB)) {
        FAIL();
    }

    if (reglenA != reglenB || memcmp(registrationA, registrationB, reglenA)) {
        FAIL();
    }

    return true;
}

static bool contains_bytes(const uint8_t* data, const size_t data_len, const uint8_t* needle, const size_t needle_len)
{
    for (size_t i = 0; i + needle_len <= data_len; ++i) {
        if (!memcmp(data + i, needle, needle_len)) {
            return true;
        }
    }
    return false;
}

// Test parsing of user-entered custom xpub export paths, that the 'crypto-account'
// bcur for the longest supported custom path fits in the xpub export buffer, and
// that the custom path is tagged with the selected script type.
static bool test_xpub_custom_path(jade_process_t* process)
{
    JADE_ASSERT(process);

    const uint32_t bip45_purpose = BIP32_INITIAL_HARDENED_CHILD + 45;
    const char* valid[] = { "m/45'", "m/45h", "M/45H", "45'" };
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        uint32_t path[EXPORT_XPUB_PATH_LEN];
        size_t path_len = 0;
        if (!wallet_bip32_path_from_str(valid[i], strlen(valid[i]), path, EXPORT_XPUB_PATH_LEN, &path_len)) {
            FAIL();
        }
        if (path_len != 1 || path[0] != bip45_purpose) {
            FAIL();
        }
    }

    // Leading slash without 'm' is accepted as a non-bare path
    const char* leading_slash = "/45";
    uint32_t leading_slash_path[EXPORT_XPUB_PATH_LEN];
    size_t leading_slash_path_len = 0;
    if (!wallet_bip32_path_from_str(
            leading_slash, strlen(leading_slash), leading_slash_path, EXPORT_XPUB_PATH_LEN, &leading_slash_path_len)) {
        FAIL();
    }
    if (leading_slash_path_len != 1 || leading_slash_path[0] != 45) {
        FAIL();
    }

    // Deepest custom export path allowed
    const char* deepest = "m/1/2/3/4";
    uint32_t deepest_path[EXPORT_XPUB_PATH_LEN];
    size_t deepest_path_len = 0;
    if (!wallet_bip32_path_from_str(deepest, strlen(deepest), deepest_path, EXPORT_XPUB_PATH_LEN, &deepest_path_len)) {
        FAIL();
    }
    if (deepest_path_len != EXPORT_XPUB_PATH_LEN || deepest_path[0] != 1 || deepest_path[3] != 4) {
        FAIL();
    }

    // Largest index allowed
    const char* largest = "m/2147483647'";
    uint32_t largest_path[EXPORT_XPUB_PATH_LEN];
    size_t largest_path_len = 0;
    if (!wallet_bip32_path_from_str(largest, strlen(largest), largest_path, EXPORT_XPUB_PATH_LEN, &largest_path_len)) {
        FAIL();
    }
    if (largest_path_len != 1 || largest_path[0] != UINT32_MAX) {
        FAIL();
    }

    // Index far too large to fit - 'm/' followed by 100 digits
    char huge_index[2 + 100 + 1];
    memcpy(huge_index, "m/", 2);
    memset(huge_index + 2, '1', 100);
    huge_index[sizeof(huge_index) - 1] = '\0';

    // Bad characters, empty elements, trailing slash, negative or out-of-range index,
    // repeated hardened marker, and too deep for a custom export path
    const char* invalid[]
        = { "m/x", "m//45", "m/45'/", "m/-1", "m/2147483648", "m/2147483648'", "m/45'''", huge_index, "m/1/2/3/4/5" };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        uint32_t path[EXPORT_XPUB_PATH_LEN];
        size_t path_len = 0;
        if (wallet_bip32_path_from_str(invalid[i], strlen(invalid[i]), path, EXPORT_XPUB_PATH_LEN, &path_len)) {
            FAIL();
        }
    }

    // Custom path entry rules - prefix-less length limit, normalisation, and length after normalisation
    const struct {
        const char* str;
        xpub_path_err_t expected_err;
        const char* expected_pathstr;
    } entries[] = {
        { "m/48'/10000'/10000'/2'", XPUB_PATH_ERR_OK, "m/48'/10000'/10000'/2'" },
        { "48'/10000'/10000'/2'", XPUB_PATH_ERR_OK, "m/48'/10000'/10000'/2'" },
        { "M/48h/0H/0'/2'", XPUB_PATH_ERR_OK, "m/48'/0'/0'/2'" },
        { "M/48'/10000'/10000'/2'", XPUB_PATH_ERR_OK, "m/48'/10000'/10000'/2'" },
        { "48'/10000'/100000'/2'", XPUB_PATH_ERR_TOO_LONG_UNPREFIXED, NULL },
        { "m/48'/100000'/10000'/2'", XPUB_PATH_ERR_TOO_LONG, "m/48'/100000'/10000'/2'" },
        { "/", XPUB_PATH_ERR_INVALID, NULL },
        { "m/x", XPUB_PATH_ERR_INVALID, NULL },
        { "m/1/2/3/4/5", XPUB_PATH_ERR_INVALID, NULL },
    };
    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); ++i) {
        uint32_t path[EXPORT_XPUB_PATH_LEN];
        size_t path_len = 0;
        char pathstr[MAX_PATH_STR_LEN(EXPORT_XPUB_PATH_LEN)];
        const xpub_path_err_t err = parse_custom_xpub_export_path(
            entries[i].str, strlen(entries[i].str), path, EXPORT_XPUB_PATH_LEN, &path_len, pathstr, sizeof(pathstr));
        if (err != entries[i].expected_err) {
            JADE_LOGE("Custom path '%s' gave error %u, expected %u", entries[i].str, err, entries[i].expected_err);
            FAIL();
        }
        if (entries[i].expected_pathstr && strcmp(pathstr, entries[i].expected_pathstr)) {
            JADE_LOGE(
                "Custom path '%s' gave '%s', expected '%s'", entries[i].str, pathstr, entries[i].expected_pathstr);
            FAIL();
        }
    }

    // Custom path entry from buffers that are not NUL-terminated - only 'str_len' characters are read
    const char unterminated_short[] = { '4' };
    const char unterminated[] = { '4', '5', '\'', '/', '1', 'x' };
    const struct {
        const char* str;
        size_t str_len;
        const char* expected_pathstr;
    } unterminated_entries[] = {
        { unterminated_short, sizeof(unterminated_short), "m/4" },
        { unterminated, sizeof(unterminated) - 1, "m/45'/1" },
    };
    for (size_t i = 0; i < sizeof(unterminated_entries) / sizeof(unterminated_entries[0]); ++i) {
        uint32_t path[EXPORT_XPUB_PATH_LEN];
        size_t path_len = 0;
        char pathstr[MAX_PATH_STR_LEN(EXPORT_XPUB_PATH_LEN)];
        if (parse_custom_xpub_export_path(unterminated_entries[i].str, unterminated_entries[i].str_len, path,
                EXPORT_XPUB_PATH_LEN, &path_len, pathstr, sizeof(pathstr))
                != XPUB_PATH_ERR_OK
            || strcmp(pathstr, unterminated_entries[i].expected_pathstr)) {
            FAIL();
        }
    }

    // Set standard test wallet
    keychain_t keydata = { 0 };
    if (!keychain_derive_from_mnemonic(TEST_MNEMONIC, NULL, &keydata)) {
        FAIL();
    }
    keychain_set(&keydata, process->ctx.source, true);

    // Longest custom path, largest index at every level, script variant with two tags
    uint32_t path[EXPORT_XPUB_PATH_LEN];
    for (size_t i = 0; i < EXPORT_XPUB_PATH_LEN; ++i) {
        path[i] = UINT32_MAX;
    }
    uint8_t cbor[EXPORT_XPUB_CBOR_BUFLEN];
    size_t written = 0;
    bcur_build_cbor_crypto_account(MULTI_P2WSH_P2SH, path, EXPORT_XPUB_PATH_LEN, cbor, sizeof(cbor), &written);

    // A testnet wallet adds a 9-byte 'use-info' map - ensure there is room for it
    if (!written || written + 16 > sizeof(cbor)) {
        JADE_LOGE("Unexpected crypto-account length: %u", written);
        FAIL();
    }

    // Single-element descriptor array, script tags sh(400) and wsh(401), then hdkey tag (303)
    const uint8_t script_tags[] = { 0x81, 0xd9, 0x01, 0x90, 0xd9, 0x01, 0x91, 0xd9, 0x01, 0x2f };
    if (!contains_bytes(cbor, written, script_tags, sizeof(script_tags))) {
        FAIL();
    }

    // Build the testnet variant, unless the device is already restricted to mainnet.
    // The keychain is temporary, so the restriction is not persisted to storage.
    const network_type_t initial_restriction = keychain_get_network_type_restriction();
    if (keychain_is_network_type_consistent(NETWORK_TYPE_TEST)) {
        keychain_set_network_type_restriction(NETWORK_TYPE_TEST);

        uint8_t testnet_cbor[EXPORT_XPUB_CBOR_BUFLEN];
        size_t testnet_written = 0;
        bcur_build_cbor_crypto_account(
            MULTI_P2WSH_P2SH, path, EXPORT_XPUB_PATH_LEN, testnet_cbor, sizeof(testnet_cbor), &testnet_written);

        if (initial_restriction == NETWORK_TYPE_NONE) {
            keychain_clear_network_type_restriction();
        }

        if (!testnet_written || testnet_written > sizeof(testnet_cbor)) {
            JADE_LOGE("Unexpected testnet crypto-account length: %u", testnet_written);
            FAIL();
        }

        // use-info key (5), tag (305), map of type btc (1: 0) and network testnet (2: 1)
        const uint8_t use_info[] = { 0x05, 0xd9, 0x01, 0x31, 0xa2, 0x01, 0x00, 0x02, 0x01 };
        if (!contains_bytes(testnet_cbor, testnet_written, use_info, sizeof(use_info))) {
            FAIL();
        }
    } else {
        JADE_LOGW("Device restricted to mainnet - skipping testnet crypto-account check");
    }

    keychain_clear();
    return true;
}

typedef struct {
    size_t index;
    size_t key_size;
    const char* expected_hash;
} rsa_test_params_t;

static bool test_bip85_rsa_key_gen(jade_process_t* process)
{
    JADE_ASSERT(process);

    // Set the debug wallet
    keychain_t keydata = { 0 };
    if (!keychain_derive_from_mnemonic(TEST_MNEMONIC, NULL, &keydata)) {
        FAIL();
    }
    keychain_set(&keydata, process->ctx.source, true);

    const rsa_test_params_t rsa_tests[] = {
#if defined(CONFIG_FREERTOS_UNICORE) && defined(CONFIG_ETH_USE_OPENETH) && defined(CONFIG_DEBUG_MODE)
        { 0, 1024, "9e11d24ae78faeb37afea49abfd7bbe798a1fe2d24e601e9c53364ec325f8818" },
        { 2, 1024, "4516a6cc9ad3bec438ec39105eaf62942b02f0dc3fd8a8227631374549b8da8b" },
        { 0, 2048, "6597690e045f8aac15365b1a1f54a2de0557f355a3867c2b26c4650a747a646f" },
        { 2, 2048, "9de081011a4d41f5a615a6ef0fde801fe8cbe7ab20bca02c1847623c7af56446" },
        { 0, 3072, "6dec7236f0b93d8a41baae7fd9c3519ffcfa5872f44e73fb113bc79567748f99" },
        { 2, 3072, "9632771cae8fadf9c7e1ef82c774a8dae050410827663dc124c77597ceb0d499" },
        { 0, 4096, "03745cefd37483eea96bdbf695bbf3fae31f13cdeaf1358820f069be89fc6871" },
#endif
        { 1, 1024, "833fe83dd7dac618cdaea48b197aff21feeb874b5437ca20d2ea2967b5a973c2" },
        { 1, 2048, "692a57a0de7ec4c76a823652d95e6d2ff60ac08033f50e4b2edec24f9f193c91" },
        { 1, 3072, "60e223889e71e799a3432f7978e9f4b32198ad2a524fb1fe585e47e1336e6213" }
    };

    const size_t num_tests = sizeof(rsa_tests) / sizeof(rsa_tests[0]);
    for (size_t i = 0; i < num_tests; ++i) {
        // Get bip85 rsa pubkey pem
        char pem[1024];
        if (!rsa_get_bip85_pubkey_pem(rsa_tests[i].key_size, rsa_tests[i].index, pem, sizeof(pem))) {
            FAIL();
        }

        // Compare the hash to expected
        unsigned char public_key_hash[SHA256_LEN];
        char* public_key_hash_hex = NULL;
        JADE_WALLY_VERIFY(wally_sha256((const uint8_t*)pem, strlen(pem), public_key_hash, sizeof(public_key_hash)));
        JADE_WALLY_VERIFY(wally_hex_from_bytes(public_key_hash, sizeof(public_key_hash), &public_key_hash_hex));

        if (memcmp(public_key_hash_hex, rsa_tests[i].expected_hash, strlen(public_key_hash_hex)) != 0) {
            JADE_LOGE("%s\nvs\n%s\n", public_key_hash_hex, rsa_tests[i].expected_hash);
            wally_free_string(public_key_hash_hex);
            FAIL();
        }
        wally_free_string(public_key_hash_hex);
    }

    return true;
}

bool debug_selfcheck(jade_process_t* process)
{
    JADE_ASSERT(process);

    // Test can restore known mnemonic and service path is computed as expected
    if (!test_simple_restore()) {
        FAIL();
    }

    // Check 12- and 24-word mnemonic generation, with and without passphrase
    if (!test_new_wallets(12)) {
        FAIL();
    }
    if (!test_new_wallets(24)) {
        FAIL();
    }

    // Test can write and read-back key data from storage
    // Test that 3 bad PIN attempts erases stored keys
    if (!test_storage_with_pin(process)) {
        FAIL();
    }

    // Test save/load when using passphrase
    if (!test_storage_with_passphrase(process, 12)) {
        FAIL();
    }
    if (!test_storage_with_passphrase(process, 24)) {
        FAIL();
    }

    // Test multisig file import/export
    if (!test_multisig_files(process)) {
        FAIL();
    }

    // Temporary test - will be replaced by python test when external rsa signing interface is completed
    if (!test_bip85_rsa_key_gen(process)) {
        FAIL();
    }

    // Test custom xpub export path parsing, and the export buffer size for the longest path
    if (!test_xpub_custom_path(process)) {
        FAIL();
    }

    // PASS !
    return true;
}
#endif // AMALGAMATED_BUILD
