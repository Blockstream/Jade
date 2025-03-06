#ifndef AMALGAMATED_BUILD
#include <sdkconfig.h>
#include <string.h>
#include <wally_bip32.h>

#include "bcur.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "multisig.h"
#include "process.h"
#include "random.h"
#include "rsa.h"
#include "storage.h"
#include <sodium/crypto_verify_64.h>
#include <sodium/utils.h>
#include <utils/malloc_ext.h>
#include <utils/util.h>

#include "utils/shake256.h"
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <wally_bip85.h>

#include <cdecoder.h>
#include <cencoder.h>
#include <ctype.h>

int register_multisig_file(const char* multisig_file, size_t multisig_file_len, const char** errmsg);

static const char TEST_MNEMONIC[] = "fish inner face ginger orchard permit useful method fence kidney chuckle party "
                                    "favorite sunset draw limb science crane oval letter slot invite sadness banana";
static const char SERVICE_PATH_HEX[] = "00c9678fbd9d9f6a96bd43221d56733b5aba8f528487602b894e72d0f56e380f7d145b65639db7e"
                                       "e4f528a3fcfb8277b0cbbea00ef64767a531e9a447cacbfbc";

// See macros in keychain.c for calculating encrpyted blob lengths below
// (Payload data is padded to next multiple of 16, and is concatenated between iv and hmac)
// 16 (iv) + 208 (length of data stored (78 (key) + 64 (ga path) + 64 (blinding key)) padded to next 16x) + 32 (hmac)
static const size_t FULL_KEY_BLOBLEN = 256;
// 16 (iv) + 32 (12-word entropy (16) padded to next 16x) + 32 (hmac)
static const size_t MNEMONIC_12_ENTROPY_BLOBLEN = 80;
// 16 (iv) + 48 (24-word entropy (32) padded to next 16x) + 32 (hmac)
static const size_t MNEMONIC_24_ENTROPY_BLOBLEN = 96;

#define FAIL()                                                                                                         \
    do {                                                                                                               \
        JADE_LOGE("SELFCHECK FAILURE@%d", __LINE__);                                                                   \
        return false;                                                                                                  \
    } while (false)

#define WALLY_FREE_STR(str)                                                                                            \
    do {                                                                                                               \
        if (wally_free_string(str) != WALLY_OK) {                                                                      \
            FAIL();                                                                                                    \
        }                                                                                                              \
    } while (false)

// *All* fields are identical
static bool all_fields_same(const keychain_t* keydata1, const keychain_t* keydata2, const bool strict_seeds)
{
    JADE_ASSERT(keydata1);
    JADE_ASSERT(keydata2);

    if (sodium_memcmp(&keydata1->xpriv, &keydata2->xpriv, sizeof(keydata1->xpriv))) {
        return false;
    }
    if (crypto_verify_64(keydata1->service_path, keydata2->service_path)) {
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
    if (!crypto_verify_64(keydata1->service_path, keydata2->service_path)) {
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
    uint8_t expected_service_path[HMAC_SHA512_LEN];
    const int ret
        = wally_hex_to_bytes(SERVICE_PATH_HEX, expected_service_path, sizeof(expected_service_path), &written);
    if (ret != WALLY_OK || written != HMAC_SHA512_LEN) {
        FAIL();
    }

    keychain_t keydata = { 0 };
    if (!keychain_derive_from_mnemonic(TEST_MNEMONIC, NULL, &keydata)) {
        FAIL();
    }
    if (crypto_verify_64(keydata.service_path, expected_service_path) != 0) {
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

#define FREE_DECODER_AND_FAIL(d)                                                                                       \
    do {                                                                                                               \
        urfree_placement_decoder(d);                                                                                   \
        FAIL();                                                                                                        \
    } while (false)

#define FREE_ENCODER_AND_FAIL(e)                                                                                       \
    do {                                                                                                               \
        urfree_placement_encoder(e);                                                                                   \
        FAIL();                                                                                                        \
    } while (false)

#define FREE_ENCODED_PARTS(p)                                                                                          \
    do {                                                                                                               \
        for (int i = 0; i < sizeof(p) / sizeof(p[0]); ++i) {                                                           \
            urfree_encoded_encoder(p[i]);                                                                              \
        }                                                                                                              \
    } while (false)

static bool test_bcur_decode_encode(void)
{
    const size_t encoder_max_fragment_len = 142; // relates to the size of the string fragments below
    const char qr_part1of2[]
        = "UR:CRYPTO-PSBT/1-2/"
          "LPADAOCFADCWCYGEFGCHDWHDMNHKADCSJOJKIDJYZMADAEJPAOAEAEAEADECKIPKNBTODLATWTEOPRECNTCLGYDKOTMOGMECVSTELKEHVEHE"
          "KEAYGRPLRHTNLTADAEAEAEAEZMZMZMZMAOTIATAEAEAEAEAEAECHPTBBPMWNSSLUBTBEPRZMFWIMPTCPIOAXECQDWEAMLUKILTPKDRAEAEAE"
          "AEAEAECMAEBBKPLFPKADUYWKGAMNRDIHGYZTMTTTFXRSGSZTGEWTAEAEAEAEAEADADCTBNEOAEAEAEAEAEAECMAEBBMTDESNLBPSCP";
    const char qr_part2of2[]
        = "UR:CRYPTO-PSBT/2-2/"
          "LPAOAOCFADCWCYGEFGCHDWHDMNSBWEJSNDVWKESSMDZCZCOLFPSPPMCEBGYKYTCPAMAXLDMDHSREMNCTEHLFMTBNBNGLLPRYGOTKFPCPFEVT"
          "FRBZVASNJYNDRHHHLRAALRTSCSAEAEAEAEGHAEAELAAEAEAELAAEAEAELAAEAEAEAEBWAEAEAEAEAECPAOAOCMLPLOTYFHEHCYKEJNGDFNJT"
          "IHKPYAEMKPVENLGSDIECNLRYWSIAFDJZNDNTLDAHCSAEAEAEAEGHAEAELAAEAEAELAAEAEAELAADAEAEAEBAAEAEAEAEAEDTSOTETL";
    const char expected_type[] = "crypto-psbt";
    const char hex_expected[]
        = "59011870736274ff0100720200000001357daaa0ce2f07f033b2359d215124a3925235e8d38c31e45f7c084baeb9da870100000000ff"
          "ffffff02d00700000000000017a914adf1c48b0d10b2ff426aa922670335b3ed068b7d87aa2a0000000000001600147582aa01dbf449"
          "8eba6551fc96d143bf4cfc4af0000000000001011f0c330000000000001600149628cbed719be57cc495fdfda641c8ad1c12f5f92206"
          "03899561b58e1f3182960c0c4e85bd55cf412245e03b15e6cd749bb95c840484d7180000000054000080000000800000008000000000"
          "130000000000220202168588d43f311a7c6d503c6e6575f83775e4994c273599bdef63486c9b9d890518000000005400008000000080"
          "00000080010000000e00000000";

    size_t payload_len = 0;
    uint8_t payload[sizeof(hex_expected) / 2];
    const int wret = wally_hex_to_bytes(hex_expected, payload, sizeof(payload), &payload_len);
    JADE_ASSERT(wret == WALLY_OK);
    JADE_ASSERT(payload_len == sizeof(payload));

    // 1. Try decoder
    {
        // Check decoder with a message of 2 'pure' fragments
        uint8_t decoder[URDECODER_SIZE];
        urcreate_placement_decoder(decoder, sizeof(decoder));
        if (uris_success_decoder(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (uris_complete_decoder(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (uris_failure_decoder(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (urreceived_parts_count_decoder(decoder) != 0) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        // NOTE: Can't call urexpected_part_count_decoder() until first part processed

        // send first qr
        if (!urreceive_part_decoder(decoder, qr_part1of2)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (uris_failure_decoder(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (uris_success_decoder(decoder)) {
            // Should NOT be complete yet
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (urreceived_parts_count_decoder(decoder) != 1) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (urexpected_part_count_decoder(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }

        // send first qr again - should be ignored/harmless
        if (!urreceive_part_decoder(decoder, qr_part1of2)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (uris_failure_decoder(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (uris_success_decoder(decoder)) {
            // Should NOT be complete yet
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (urreceived_parts_count_decoder(decoder) != 1) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (urexpected_part_count_decoder(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }

        // send second qr
        if (!urreceive_part_decoder(decoder, qr_part2of2)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (uris_failure_decoder(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (!uris_success_decoder(decoder)) {
            // Should now be complete
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (urreceived_parts_count_decoder(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (urexpected_part_count_decoder(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }

        // read the result
        const char* type = NULL;
        uint8_t* result = NULL;
        size_t result_len = 0;
        urresult_ur_decoder(decoder, &result, &result_len, &type);
        JADE_ASSERT(type);
        JADE_ASSERT(result_len);
        JADE_ASSERT(result);
        if (strncmp(expected_type, type, strlen(expected_type))) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (result_len != payload_len || memcmp(result, payload, result_len)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        urfree_placement_decoder(decoder);
    }

    // 2. Try encoder
    {
        // If we encode the data, the first two parts should match the original payloads
        // ie. the 'pure' fragments (ie. the actual data split into two and encoded)
        uint8_t encoder[URENCODER_SIZE];
        urcreate_placement_encoder(
            encoder, sizeof(encoder), expected_type, payload, payload_len, encoder_max_fragment_len, 0, 10);
        const bool force_uppercase = true;
        char* parts[3] = { NULL, NULL, NULL };
        urnext_part_encoder(encoder, force_uppercase, &parts[0]);
        if (!parts[0] || strncmp(parts[0], qr_part1of2, strlen(qr_part1of2))) {
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }
        if (uris_complete_encoder(encoder)) {
            // Should NOT be complete yet
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }

        urnext_part_encoder(encoder, force_uppercase, &parts[1]);
        if (!parts[1] || strncmp(parts[1], qr_part2of2, strlen(qr_part2of2))) {
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }
        if (!uris_complete_encoder(encoder)) {
            // Should now be complete
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }

        // We can continue to generate additional parts - these are fountain-code fragments
        // which can stand in for any missed fragments.  NOTE: the sequence-numbers appear 'overflowed'.
        urnext_part_encoder(encoder, force_uppercase, &parts[2]);
        if (!parts[2] || strncmp(parts[2], "UR:CRYPTO-PSBT/3-2/", strlen("UR:CRYPTO-PSBT/3-2/"))) {
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }
        urfree_placement_encoder(encoder);

        // Check fountain encoding / redundancy with fresh decoders - incl. getting a 'later' part first
        // Check all 2-of-3 combinations - any 2 distinct parts should be sufficient.
        for (size_t i = 0; i < 3; ++i) {
            // Fountain code parts are blended together or with other 'pure' data parts to generate
            // additional/missing data parts.  If we receive a fountain-code part first it can't generate
            // any data parts on its own - so does not initially bump the 'received parts' count.
            // (It is cached in the decoder, and may generate one or more parts later when further parts
            // are received - so 'received parts' can jump by more than 1 when a subsequent message is received.)
            const size_t initial_expected_received = i == 2 ? 0 : 1;

            for (size_t j = 0; j < 3; ++j) {
                uint8_t decoder[URDECODER_SIZE];
                urcreate_placement_decoder(decoder, sizeof(decoder));

                // Present first part
                if (!urreceive_part_decoder(decoder, parts[i])) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (uris_success_decoder(decoder)) {
                    // Should NOT be complete yet
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (urprocessed_parts_count_decoder(decoder) != 1) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (urexpected_part_count_decoder(decoder) != 2) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (urreceived_parts_count_decoder(decoder) != initial_expected_received) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }

                // Present second part
                if (!urreceive_part_decoder(decoder, parts[j])) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (urprocessed_parts_count_decoder(decoder) != 2) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (urexpected_part_count_decoder(decoder) != 2) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (uris_failure_decoder(decoder)) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }

                // If any two different parts are presented, this should be
                // sufficient to reconstruct the complete message.
                // NOTE: a fountain part followed by a 'pure' part will mean the
                // 'received' count 0 after the fountain part, then jumps to 2 when
                // the 'pure' data part is received (and can be combined with the fountain
                // part to generate the missing data part).
                if (i != j) {
                    if (urreceived_parts_count_decoder(decoder) != 2) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                    if (!uris_success_decoder(decoder)) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }

                    // Check payload is as expected
                    const char* type = NULL;
                    uint8_t* result = NULL;
                    size_t result_len = 0;
                    urresult_ur_decoder(decoder, &result, &result_len, &type);
                    JADE_ASSERT(type);
                    JADE_ASSERT(result_len);
                    JADE_ASSERT(result);
                    if (strncmp(expected_type, type, strlen(expected_type))) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                    if (result_len != payload_len || memcmp(result, payload, result_len)) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                } else {
                    // Same part received twice - does not increment 'received_parts'
                    if (urreceived_parts_count_decoder(decoder) != initial_expected_received) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                    if (uris_success_decoder(decoder)) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                }
                urfree_placement_decoder(decoder);
            }
        }
        FREE_ENCODED_PARTS(parts);
    }
    return true;
}

bool test_bcur_decode_bad_cases(void)
{
    const char* cases[] = { // Simple cases
        "this is not even a ur message at all!", "ur:has prefix but still not a ur message?",
        "ur:crypto-bip39/looks like a bip39 message but bad payload encoding",
        "ur:bytes/1-3/multipart bad payload encoding, it would seem", "ur:bytes/1,2/multipart bad sequence numbers",

        // Singlepart messages can have any payload, so long as it is bytewords encoded

        // Multipart messages - encoded payload should be wrapped in a known cbor envelope with
        // metadata for the fountain encoder  (the actual user-payload inside that can be anything)
        "ur:bytes/1-3/jyisinjkcxinjkcxjtjljycxiaidjljpclstwpfdmk", // encoded payload not cbor
        "ur:bytes/1-3/" // encoded payload is cbor, but not the expected fields
        "oeieiahsjkihksceiaidjljpcxiajljtjyihjtjycxjtjljycxhsjkcxihksjoihiajyihiejlihksjoihiajyihiecxjpihjkkpjzjyioinio"
        "jtjljpihiedklbcfpt",

        // This one was actually produced by one of the 3rd-party sw wallet apps - wrong on so many levels!
        "UR:BYTES/3OF3/V6Z4WY8JQT9JZPXQCQWNV8HRWL2FKYJ9HDPHN6HZSYPC3K284N3S0V96L4/"
        "8LF6C3NEX24337544L49GQQQSQQQQQYQQQQQPQQPQQQQQQQQQQQQQH47708"
    };
    const size_t ncases = sizeof(cases) / sizeof(cases[0]);

    // Various bad cases - test the decoder ignores them
    for (size_t i = 0; i < ncases; ++i) {
        uint8_t decoder[URDECODER_SIZE];
        urcreate_placement_decoder(decoder, sizeof(decoder));

        // Present first part - should be ignored and all counts
        // of 'parts seen' should remain zero, and 'is complete'
        // and 'is success' should be false.
        if (urreceive_part_decoder(decoder, cases[i])) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (urprocessed_parts_count_decoder(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (urreceived_parts_count_decoder(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (uris_complete_decoder(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (uris_success_decoder(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        urfree_placement_decoder(decoder);
    }
    return true;
}

// Test we can render a small sequence of bcur qr-code icons
// Cover all handled versions - use more data for larger versions.
// ('ver * ver * 8' seems to give 6 icons, which seems reasonable)
static bool test_bcur_icons(void)
{
    const uint8_t payload[12 * 12 * 8];
    for (uint8_t ver = 4; ver <= 12; ++ver) {
        const size_t payload_len = ver * ver * 8;
        Icon* icons = NULL;
        size_t num_icons = 0;
        bcur_create_qr_icons(payload, payload_len, "test-type", ver, &icons, &num_icons);
        if (!icons || !num_icons) {
            FAIL();
        }
        for (size_t i = 0; i < num_icons; ++i) {
            JADE_ASSERT(icons[i].data);
            free(icons[i].data);
        }
        free(icons);
    }
    return true;
}

#ifdef CONFIG_SPIRAM
// Test we can render a sequence of up to 1000 bcur fragments
static bool test_bcur_large_payload_many_icons(void)
{
    const int qr_version = 4; // smallest supported
    const int payload_len = 22 * 1024; // 22k, should result ~1000 fragments
    uint8_t* payload = JADE_MALLOC_PREFER_SPIRAM(payload_len);
    Icon* icons = NULL;
    size_t num_icons = 0;
    bcur_create_qr_icons(payload, payload_len, "test-type", qr_version, &icons, &num_icons);
    if (!icons || !num_icons) {
        FAIL();
    }
    for (size_t i = 0; i < num_icons; ++i) {
        JADE_ASSERT(icons[i].data);
        free(icons[i].data);
    }
    free(icons);
    free(payload);
    return true;
}
#endif // CONFIG_SPIRAM

// Temporary test - will be replaced by python test when external interface completed
#include "descriptor.h"

#define INIT_DESC(d, s)                                                                                                \
    do {                                                                                                               \
        d.script_len = strlen(s);                                                                                      \
        JADE_ASSERT(d.script_len < sizeof(d.script));                                                                  \
        strcpy(d.script, s);                                                                                           \
        d.type = DESCRIPTOR_TYPE_UNKNOWN;                                                                              \
        d.num_values = 0;                                                                                              \
    } while (false)

#define ADD_MAP_VAL(d, k, v)                                                                                           \
    do {                                                                                                               \
        string_value_t* const sv = &(d.values[d.num_values]);                                                          \
        sv->key_len = strlen(k);                                                                                       \
        JADE_ASSERT(sv->key_len < sizeof(sv->key));                                                                    \
        strcpy(sv->key, k);                                                                                            \
        sv->value_len = strlen(v);                                                                                     \
        JADE_ASSERT(sv->value_len < sizeof(sv->value));                                                                \
        strcpy(sv->value, v);                                                                                          \
        ++d.num_values;                                                                                                \
    } while (false)

#define FP_XPUB_MATCH(n, fp, xp)                                                                                       \
    (wally_hex_to_bytes(fp, buf, sizeof(buf), &written) == WALLY_OK && written == sizeof(signers[n].fingerprint)       \
        && !memcmp(buf, signers[n].fingerprint, written) && !strcmp(xp, signers[n].xpub))

static bool check_descriptor_serialisation(descriptor_data_t* const desc)
{
    JADE_ASSERT(desc);

    // Should be same if serialised and de-serialised
    uint8_t serialised[768];
    const size_t serialised_len = DESCRIPTOR_BYTES_LEN(desc);
    JADE_ASSERT(serialised_len < sizeof(serialised));
    if (!descriptor_to_bytes(desc, serialised, serialised_len)) {
        FAIL();
    }

    wally_bzero(desc, sizeof(descriptor_data_t));

    if (!descriptor_from_bytes(serialised, serialised_len, desc)) {
        FAIL();
    }

    // Re-serialise - should be same as first serialisation
    if (DESCRIPTOR_BYTES_LEN(desc) != serialised_len) {
        FAIL();
    }

    uint8_t serialised2[sizeof(serialised)];
    if (!descriptor_to_bytes(desc, serialised2, serialised_len)) {
        FAIL();
    }
    if (memcmp(serialised, serialised2, serialised_len)) {
        FAIL();
    }

    return true;
}

static bool test_miniscript_descriptors(void)
{
    const char* errmsg = NULL;
    descriptor_data_t desc = {};
    bool ret;

    uint8_t buf[BIP32_KEY_FINGERPRINT_LEN];
    size_t num_signers = 0;
    signer_t signers[3];
    size_t written;

    // Anchor Watch example
    INIT_DESC(desc, "wsh(or_d(pk(@0/<0;1>/*),and_v(v:multi(2,@1/<0;1>/*,@2/<0;1>/*),older(4320))))");
    ADD_MAP_VAL(desc, "@0",
        "[1bf12fe0/48'/1'/0'/2']"
        "tpubDEHXLZfMAAM5duEnX6SSnZjGYbrxqXvRJmMxw8MFwr3gu4LC4DSxR9KVEfVDVcZxre4XL5tGcwVRrHwQ9euTMnSq6P"
        "6BqREemaqrFsC96Fy");
    ADD_MAP_VAL(desc, "@1",
        "[eda3d606/48'/1'/0'/2']"
        "tpubDEAmqvQkhqP6SbfbSPu3AeRR9kfHLFXYvNDiWashLy7V2zicg1YLg654AqfomsC6kFwTs4MpcnqwxN2AnYAqi5JZeu"
        "VDBn3rfZZLTaAuS8Y");
    ADD_MAP_VAL(desc, "@2",
        "[e1640396/48'/1'/0'/2']"
        "tpubDFgDvZifofePphQiVjLfkov8YTDg3UPuHRvt6LzbySYMZQhN19p6zvR7NTEXi1ZJAMNostHMTnz2sfXXYcJFQqtyCn"
        "NuUfgYqsahxTLGJq2");

    // Check parsing and key iteration
    ret = descriptor_get_signers("A0", &desc, "testnet", NULL, NULL, 0, &num_signers, &errmsg);
    if (!ret) {
        FAIL();
    }
    if (num_signers != 3) {
        FAIL();
    }
    ret = descriptor_get_signers("A0", &desc, "testnet", &desc.type, signers, 3, &num_signers, &errmsg);
    if (!ret) {
        FAIL();
    }
    if (desc.type != DESCRIPTOR_TYPE_MIXED) {
        FAIL();
    }
    if (num_signers != 3) {
        FAIL();
    }
    for (size_t i = 0; i < 3; ++i) {
        if (signers[i].derivation_len != 4 || signers[i].derivation[0] != harden(48)
            || signers[i].derivation[1] != harden(1) || signers[i].derivation[2] != harden(0)
            || signers[i].derivation[3] != harden(2)) {
            FAIL();
        }
        if (!signers[i].path_is_string || strcmp(signers[i].path_str, "<0;1>/*")) {
            FAIL();
        }
    }

    if (!FP_XPUB_MATCH(0, "1bf12fe0",
            "tpubDEHXLZfMAAM5duEnX6SSnZjGYbrxqXvRJmMxw8MFwr3gu4LC4DSxR9KVEfVDVcZxre4XL5tGcwVRrHwQ9euTMnSq6P6BqREemaqrFs"
            "C96Fy")) {
        FAIL();
    }
    if (!FP_XPUB_MATCH(1, "eda3d606",
            "tpubDEAmqvQkhqP6SbfbSPu3AeRR9kfHLFXYvNDiWashLy7V2zicg1YLg654AqfomsC6kFwTs4MpcnqwxN2AnYAqi5JZeuVDBn3rfZZLTa"
            "AuS8Y")) {
        FAIL();
    }
    if (!FP_XPUB_MATCH(2, "e1640396",
            "tpubDFgDvZifofePphQiVjLfkov8YTDg3UPuHRvt6LzbySYMZQhN19p6zvR7NTEXi1ZJAMNostHMTnz2sfXXYcJFQqtyCnNuUfgYqsahxT"
            "LGJq2")) {
        FAIL();
    }

    // Check scripts/addresses
    uint32_t multi_index = 0;
    const char* expectedA[2] = { "tb1qcf6egdkhq96vwkn4ge6fyz446zn09alwhuadcz8ezf6remuw7r7stzu9gj",
        "tb1qep0hehn3gl5nse6w5vyqe0g4q9czvhgr3nlzj76uhmfsxvqcz8pq2zyy4c" };

    for (uint32_t child_num = 0; child_num < 2; ++child_num) {
        char* addr = NULL;
        ret = descriptor_to_address("A1", &desc, "testnet", multi_index, child_num, NULL, &addr, &errmsg);
        if (!ret || strcmp(addr, expectedA[child_num])) {
            wally_free_string(addr);
            FAIL();
        }
        wally_free_string(addr);

        // Pass unknown type - should give same answer
        desc.type = DESCRIPTOR_TYPE_UNKNOWN;
        ret = descriptor_to_address("A2", &desc, "testnet", multi_index, child_num, NULL, &addr, &errmsg);
        if (!ret || strcmp(addr, expectedA[child_num])) {
            wally_free_string(addr);
            FAIL();
        }
        wally_free_string(addr);

        // Wrong network should fail
        ret = descriptor_to_address("A3", &desc, "mainnet", multi_index, child_num, NULL, &addr, &errmsg);
        if (ret) {
            FAIL();
        }

        // Wrong descriptor type should fail
        desc.type = DESCRIPTOR_TYPE_MINISCRIPT_ONLY;
        ret = descriptor_to_address("A4", &desc, "testnet", multi_index, child_num, NULL, &addr, &errmsg);
        if (ret) {
            FAIL();
        }
        desc.type = DESCRIPTOR_TYPE_MIXED;
    }

    // Check serialisation
    if (!check_descriptor_serialisation(&desc)) {
        FAIL();
    }

    // Liana example
    INIT_DESC(desc, "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:pkh(@2/<0;1>/*),older(100))))");
    ADD_MAP_VAL(desc, "@0",
        "[7897b5b3/48'/1'/0'/2']"
        "tpubDE8B47dY4JuGLnXVyDzG76UuhBM5hTjc6sXeJjG6ThbPsryiAnKqQY8CmxWcYjM6eVvkyH7CNTVrmPMxSWP9ZzCfHV"
        "Ho6preHp6Xhgd42JH");
    ADD_MAP_VAL(desc, "@1",
        "[1bf12fe0/48'/1'/0'/2']"
        "tpubDEHXLZfMAAM5duEnX6SSnZjGYbrxqXvRJmMxw8MFwr3gu4LC4DSxR9KVEfVDVcZxre4XL5tGcwVRrHwQ9euTMnSq6P"
        "6BqREemaqrFsC96Fy");
    ADD_MAP_VAL(desc, "@2",
        "[7897b5b3/48'/1'/1'/2']"
        "tpubDFf2ES1oUSZRgiCFT4mvBQ4jC2xTfRzVwfa6KewXZthgtL83UquqirWXzo1EKi4et3bx2wQz9QFKLDeu6vXoKpgQnJ"
        "HyV8DomjCjJRT3d57");

    // Check parsing and key iteration
    ret = descriptor_get_signers("B0", &desc, "testnet", NULL, NULL, 0, &num_signers, &errmsg);
    if (!ret) {
        FAIL();
    }
    if (num_signers != 3) {
        FAIL();
    }
    ret = descriptor_get_signers("B0", &desc, "testnet", &desc.type, signers, 3, &num_signers, &errmsg);
    if (!ret) {
        FAIL();
    }
    if (desc.type != DESCRIPTOR_TYPE_MIXED) {
        FAIL();
    }
    if (num_signers != 3) {
        FAIL();
    }
    for (size_t i = 0; i < 3; ++i) {
        if (signers[i].derivation_len != 4 || signers[i].derivation[0] != harden(48)
            || signers[i].derivation[1] != harden(1) || signers[i].derivation[2] != harden(i == 2 ? 1 : 0)
            || signers[i].derivation[3] != harden(2)) {
            FAIL();
        }
        if (!signers[i].path_is_string || strcmp(signers[i].path_str, "<0;1>/*")) {
            FAIL();
        }
    }

    if (!FP_XPUB_MATCH(0, "7897b5b3",
            "tpubDE8B47dY4JuGLnXVyDzG76UuhBM5hTjc6sXeJjG6ThbPsryiAnKqQY8CmxWcYjM6eVvkyH7CNTVrmPMxSWP9ZzCfHV"
            "Ho6preHp6Xhgd42JH")) {
        FAIL();
    }
    if (!FP_XPUB_MATCH(1, "1bf12fe0",
            "tpubDEHXLZfMAAM5duEnX6SSnZjGYbrxqXvRJmMxw8MFwr3gu4LC4DSxR9KVEfVDVcZxre4XL5tGcwVRrHwQ9euTMnSq6P"
            "6BqREemaqrFsC96Fy")) {
        FAIL();
    }
    if (!FP_XPUB_MATCH(2, "7897b5b3",
            "tpubDFf2ES1oUSZRgiCFT4mvBQ4jC2xTfRzVwfa6KewXZthgtL83UquqirWXzo1EKi4et3bx2wQz9QFKLDeu6vXoKpgQnJ"
            "HyV8DomjCjJRT3d57")) {
        FAIL();
    }

    // Check scripts/addresses
    const char* expectedB[2][2] = { { "tb1q0ddn2fn5y66gt2r69dv6el32lw44lupa2ry9enlm8zduxhpwk6aqen88zh",
                                        "tb1qfj66kfjk98cfcays67c9rvkzals7tnxz2dkxnwrjslwk5tzcd8ysgx9ahf" },
        { "tb1qu6j64q9kezc0dxgfl67fgnm2z9yycc55c0fa09uresf65w6py04s4qwgul",
            "tb1qkmr7qpxagfn7mafmsrt6e3qzzc599w28cl037cktjjegenfnhyysllxj5p" } };

    for (multi_index = 0; multi_index < 2; ++multi_index) {
        for (uint32_t child_num = 0; child_num < 2; ++child_num) {
            // Use unknown type
            char* addr = NULL;
            ret = descriptor_to_address("B1", &desc, "testnet", multi_index, child_num, NULL, &addr, &errmsg);
            if (!ret || strcmp(addr, expectedB[multi_index][child_num])) {
                wally_free_string(addr);
                FAIL();
            }
            wally_free_string(addr);
        }
    }

    // Check serialisation
    if (!check_descriptor_serialisation(&desc)) {
        FAIL();
    }

    // Addresses should be same
    for (multi_index = 0; multi_index < 2; ++multi_index) {
        for (uint32_t child_num = 0; child_num < 2; ++child_num) {
            // Use unknown type
            char* addr = NULL;
            ret = descriptor_to_address("B2", &desc, "testnet", multi_index, child_num, NULL, &addr, &errmsg);
            if (!ret || strcmp(addr, expectedB[multi_index][child_num])) {
                wally_free_string(addr);
                FAIL();
            }
            wally_free_string(addr);
        }
    }

    // Another Liana example - NOTE: resuing placeholder @0
    INIT_DESC(desc, "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:pkh(@0/<2;3>/*),older(65535))))");
    ADD_MAP_VAL(desc, "@0",
        "[fb5d3ada/48'/1'/0'/2']"
        "tpubDFa4d4JXKYKrsyxkaxxk6QQscMo1bmwkczNWGKrwkPZiXSbwHueBEsS8Hq4RNTz2cm37MseAhzDRgyrmuaSDTtT6zi"
        "rPxsi8FTVUBY6FLiQ");
    ADD_MAP_VAL(desc, "@1",
        "[077ace32/48'/1'/0'/2']"
        "tpubDDzogRd3Gt71WEQavJggpR6R38iru9kC2uMkMcftBHLF8RzzPNSeZeTUoqvoa9xfXr2qeihmpysKbzwj6NmLbFQ9v2"
        "VHdMw7p8MnQycgAV8");

    // Check parsing and key iteration
    ret = descriptor_get_signers("b0", &desc, "testnet", NULL, NULL, 0, &num_signers, &errmsg);
    if (!ret) {
        FAIL();
    }
    if (num_signers != 3) {
        FAIL();
    }
    ret = descriptor_get_signers("b0", &desc, "testnet", &desc.type, signers, 3, &num_signers, &errmsg);
    if (!ret) {
        FAIL();
    }
    if (desc.type != DESCRIPTOR_TYPE_MIXED) {
        FAIL();
    }
    if (num_signers != 3) {
        FAIL();
    }
    for (size_t i = 0; i < 2; ++i) {
        if (signers[i].derivation_len != 4 || signers[i].derivation[0] != harden(48)
            || signers[i].derivation[1] != harden(1) || signers[i].derivation[2] != harden(0)
            || signers[i].derivation[3] != harden(2)) {
            FAIL();
        }
        if (!signers[i].path_is_string || strcmp(signers[i].path_str, i == 2 ? "<2;3>/*" : "<0;1>/*")) {
            FAIL();
        }
    }

    if (!FP_XPUB_MATCH(0, "fb5d3ada",
            "tpubDFa4d4JXKYKrsyxkaxxk6QQscMo1bmwkczNWGKrwkPZiXSbwHueBEsS8Hq4RNTz2cm37MseAhzDRgyrmuaSDTtT6zi"
            "rPxsi8FTVUBY6FLiQ")) {
        FAIL();
    }
    if (!FP_XPUB_MATCH(1, "077ace32",
            "tpubDDzogRd3Gt71WEQavJggpR6R38iru9kC2uMkMcftBHLF8RzzPNSeZeTUoqvoa9xfXr2qeihmpysKbzwj6NmLbFQ9v2"
            "VHdMw7p8MnQycgAV8")) {
        FAIL();
    }

    // Check scripts/addresses
    const char* expectedb[2][2] = { { "tb1q8uu3hj86chgu2zgpn4x32crv7cxl8skjdexue2ku2mjgwjvm7t3q4x2yxa",
                                        "tb1qf84tqnrcp36vtghf530406wyct00ns4jma3hw3ztfv5h98cka52qajm5v8" },
        { "tb1qx8zx3x9wf33uaar3ghvzy8y7l5wzh7e8vs5gthwvxr5z3x7ekuvsn8689q",
            "tb1q3a3k2m7qt3v05gar4kynpuu6xspqucet529mavjru4ca90ppayqqj0ad9f" } };

    for (multi_index = 0; multi_index < 2; ++multi_index) {
        for (uint32_t child_num = 0; child_num < 2; ++child_num) {
            // Use unknown type
            char* addr = NULL;
            ret = descriptor_to_address("b1", &desc, "testnet", multi_index, child_num, NULL, &addr, &errmsg);
            if (!ret || strcmp(addr, expectedb[multi_index][child_num])) {
                wally_free_string(addr);
                FAIL();
            }
            wally_free_string(addr);
        }
    }

    // Check serialisation
    if (!check_descriptor_serialisation(&desc)) {
        FAIL();
    }

    // Addresses should be same
    for (multi_index = 0; multi_index < 2; ++multi_index) {
        for (uint32_t child_num = 0; child_num < 2; ++child_num) {
            // Use unknown type
            char* addr = NULL;
            ret = descriptor_to_address("b2", &desc, "testnet", multi_index, child_num, NULL, &addr, &errmsg);
            if (!ret || strcmp(addr, expectedb[multi_index][child_num])) {
                wally_free_string(addr);
                FAIL();
            }
            wally_free_string(addr);
        }
    }

    // Another miniscript example... NOTE: not a 'wallet policy'
    INIT_DESC(desc,
        "sh(wsh(or_d(thresh(1,pk("
        "[7897b5b3/48'/1'/0'/2']"
        "tpubDE8B47dY4JuGLnXVyDzG76UuhBM5hTjc6sXeJjG6ThbPsryiAnKqQY8CmxWcYjM6eVvkyH7CNTVrmPMxSWP9ZzCfHV"
        "Ho6preHp6Xhgd42JH/0/*))"
        ",and_v(v:thresh(1,pk("
        "[1bf12fe0/48'/1'/0'/2']"
        "tpubDEHXLZfMAAM5duEnX6SSnZjGYbrxqXvRJmMxw8MFwr3gu4LC4DSxR9KVEfVDVcZxre4XL5tGcwVRrHwQ9euTMnSq6P"
        "6BqREemaqrFsC96Fy/0/*))"
        ",older(30)))))");

    // Check parsing and key iteration
    ret = descriptor_get_signers("C0", &desc, "testnet", NULL, NULL, 0, &num_signers, &errmsg);
    if (!ret) {
        FAIL();
    }
    if (num_signers != 2) {
        FAIL();
    }
    ret = descriptor_get_signers("C0", &desc, "testnet", &desc.type, signers, 3, &num_signers, &errmsg);
    if (!ret) {
        FAIL();
    }
    if (desc.type != DESCRIPTOR_TYPE_MIXED) {
        FAIL();
    }
    if (num_signers != 2) {
        FAIL();
    }
    for (size_t i = 0; i < 2; ++i) {
        if (signers[i].derivation_len != 4 || signers[i].derivation[0] != harden(48)
            || signers[i].derivation[1] != harden(1) || signers[i].derivation[2] != harden(0)
            || signers[i].derivation[3] != harden(2)) {
            FAIL();
        }
        if (!signers[i].path_is_string || strcmp(signers[i].path_str, "0/*")) {
            FAIL();
        }
    }

    if (!FP_XPUB_MATCH(0, "7897b5b3",
            "tpubDE8B47dY4JuGLnXVyDzG76UuhBM5hTjc6sXeJjG6ThbPsryiAnKqQY8CmxWcYjM6eVvkyH7CNTVrmPMxSWP9ZzCfHV"
            "Ho6preHp6Xhgd42JH")) {
        FAIL();
    }
    if (!FP_XPUB_MATCH(1, "1bf12fe0",
            "tpubDEHXLZfMAAM5duEnX6SSnZjGYbrxqXvRJmMxw8MFwr3gu4LC4DSxR9KVEfVDVcZxre4XL5tGcwVRrHwQ9euTMnSq6P"
            "6BqREemaqrFsC96Fy")) {
        FAIL();
    }

    // Check scripts/addresses
    const char* expectedC[2] = { "2MzcimvUcAwWKDDufQmTwq2FU4qenKL51fL", "2Mw3VJsaTKNCuZ2Drw3UMBvQg7QyHEvt8Nz" };

    multi_index = 0;
    for (uint32_t child_num = 0; child_num < 2; ++child_num) {
        // Use unknown type
        char* addr = NULL;
        ret = descriptor_to_address("C1", &desc, "testnet", multi_index, child_num, NULL, &addr, &errmsg);
        if (!ret || strcmp(addr, expectedC[child_num])) {
            wally_free_string(addr);
            FAIL();
        }
        wally_free_string(addr);
    }

    // Check serialisation
    if (!check_descriptor_serialisation(&desc)) {
        FAIL();
    }

    // Addresses should be same
    multi_index = 0;
    for (uint32_t child_num = 0; child_num < 2; ++child_num) {
        // Use unknown type
        char* addr = NULL;
        const bool ret = descriptor_to_address("C2", &desc, "testnet", multi_index, child_num, NULL, &addr, &errmsg);
        if (!ret || strcmp(addr, expectedC[child_num])) {
            wally_free_string(addr);
            FAIL();
        }
        wally_free_string(addr);
    }

    // Test Ledger issue - NOTE: not a 'wallet policy' and 'miniscript-only'
    INIT_DESC(desc,
        "and_b(pk([7897b5b3/48'/1'/0'/2']"
        "tpubDE8B47dY4JuGLnXVyDzG76UuhBM5hTjc6sXeJjG6ThbPsryiAnKqQY8CmxWcYjM6eVvkyH7CNTVrmPMxSWP9ZzCfHVHo6"
        "preHp6Xhgd42JH/0/*),a:1)");

    // Check parsing and key iteration
    ret = descriptor_get_signers("L0", &desc, "testnet", NULL, NULL, 0, &num_signers, &errmsg);
    if (!ret) {
        FAIL();
    }
    if (num_signers != 1) {
        FAIL();
    }
    ret = descriptor_get_signers("L0", &desc, "testnet", &desc.type, signers, 3, &num_signers, &errmsg);
    if (!ret) {
        FAIL();
    }
    if (desc.type != DESCRIPTOR_TYPE_MIXED) {
        FAIL();
    }
    if (num_signers != 1) {
        FAIL();
    }
    if (signers[0].derivation_len != 4 || signers[0].derivation[0] != harden(48)
        || signers[0].derivation[1] != harden(1) || signers[0].derivation[2] != harden(0)
        || signers[0].derivation[3] != harden(2)) {
        FAIL();
    }
    if (!signers[0].path_is_string || strcmp(signers[0].path_str, "0/*")) {
        FAIL();
    }

    if (!FP_XPUB_MATCH(0, "7897b5b3",
            "tpubDE8B47dY4JuGLnXVyDzG76UuhBM5hTjc6sXeJjG6ThbPsryiAnKqQY8CmxWcYjM6eVvkyH7CNTVrmPMxSWP9ZzCfHV"
            "Ho6preHp6Xhgd42JH")) {
        FAIL();
    }

    // The expected/correct script: <pubkey> OP_CHECKSIG OP_TOALTSTACK 1 OP_FROMALTSTACK OP_BOOLAND
    const char* expectedL[2] = { "2102afd5b7ce022720e0bbef9a34d2ed81196b700e5639229087c817119dd421483cac6b516c9a",
        "210272269b3301a5565a844c8a4d9940a70f0df0adaa1f2d7fd7cb20d8783d225501ac6b516c9a" };

    multi_index = 0;
    for (uint32_t child_num = 0; child_num < 2; ++child_num) {
        // Use unknown type
        uint8_t* script = NULL;
        size_t script_len = 0;
        ret = descriptor_to_script("L1", &desc, "testnet", multi_index, child_num, NULL, &script, &script_len, &errmsg);
        if (!ret) {
            FAIL();
        }

        char* hex = NULL;
        JADE_WALLY_VERIFY(wally_hex_from_bytes(script, script_len, &hex));
        if (!hex || strcmp(hex, expectedL[child_num])) {
            free(hex);
            free(script);
            FAIL();
        }

        free(hex);
        free(script);
    }

    // Check serialisation
    if (!check_descriptor_serialisation(&desc)) {
        FAIL();
    }

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

    // Temporary test - will be replaced by python test when external interface completed
    if (!test_miniscript_descriptors()) {
        FAIL();
    }

    // Temporary test - will be replaced by python test when external rsa signing interface is completed
    if (!test_bip85_rsa_key_gen(process)) {
        FAIL();
    }

    // Test we can decode a sequence of qrcodes into a psbt and back
    if (!test_bcur_decode_encode()) {
        FAIL();
    }

    // Test various bc-ur bad inputs
    if (!test_bcur_decode_bad_cases()) {
        FAIL();
    }

    // Test we can render a small sequence of bcur qr-code icons in all supported qr versions
    if (!test_bcur_icons()) {
        FAIL();
    }

#ifdef CONFIG_SPIRAM
    // Test we can render a large sequence of bcur fragments (smallest supported qr version)
    if (!test_bcur_large_payload_many_icons()) {
        FAIL();
    }
#endif

    // Iterative check of bcur sizing macro.
    // Run under qemu only as takes too long on esp32 hw.
#if defined(CONFIG_FREERTOS_UNICORE) && defined(CONFIG_ETH_USE_OPENETH) && defined(CONFIG_DEBUG_MODE)
    bool bcur_check_fragment_sizes(void);
    if (!bcur_check_fragment_sizes()) {
        FAIL();
    }
#endif

    // PASS !
    return true;
}
#endif // AMALGAMATED_BUILD
