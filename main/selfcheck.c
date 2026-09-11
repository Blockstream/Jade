#ifndef AMALGAMATED_BUILD
#include <sdkconfig.h>
#include <string.h>

#include "bcur.h"
#include "jade_wally_verify.h"
#include "multisig.h"
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

#include <ctype.h>
#include <ur_decoder.h>
#include <ur_encoder.h>

int register_multisig_file(const char* multisig_file, size_t multisig_file_len, const char** errmsg);

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

#define FREE_DECODER_AND_FAIL(d)                                                                                       \
    do {                                                                                                               \
        ur_decoder_free(d);                                                                                            \
        FAIL();                                                                                                        \
    } while (false)

#define FREE_ENCODER_AND_FAIL(e)                                                                                       \
    do {                                                                                                               \
        ur_encoder_free(e);                                                                                            \
        FAIL();                                                                                                        \
    } while (false)

#define FREE_ENCODED_PARTS(p)                                                                                          \
    do {                                                                                                               \
        for (int i = 0; i < sizeof(p) / sizeof(p[0]); ++i) {                                                           \
            free(p[i]);                                                                                                \
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
        ur_decoder_t* const decoder = ur_decoder_new();
        JADE_ASSERT(decoder);
        if (ur_decoder_get_state(decoder) != UR_DECODER_PROCESSING) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_received_parts_count(decoder) != 0) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        // NOTE: Can't call ur_decoder_expected_part_count() until first part processed

        // send first qr - should be processed, but NOT complete yet
        if (ur_decoder_receive_part(decoder, qr_part1of2) != UR_DECODER_PROCESSING) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_received_parts_count(decoder) != 1) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_expected_part_count(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }

        // send first qr again - should be ignored/harmless, still NOT complete
        if (ur_decoder_receive_part(decoder, qr_part1of2) != UR_DECODER_PROCESSING) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_received_parts_count(decoder) != 1) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_expected_part_count(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }

        // send second qr - should now be complete
        if (ur_decoder_receive_part(decoder, qr_part2of2) != UR_DECODER_OK) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_received_parts_count(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_expected_part_count(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }

        // read the result - borrowed from the decoder, freed with it
        const ur_result_t* const result = ur_decoder_get_result(decoder);
        JADE_ASSERT(result);
        JADE_ASSERT(result->type);
        JADE_ASSERT(result->cbor_len);
        JADE_ASSERT(result->cbor_data);
        if (strcmp(expected_type, result->type)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (result->cbor_len != payload_len || memcmp(result->cbor_data, payload, result->cbor_len)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        ur_decoder_free(decoder);
    }

    // 2. Try encoder
    {
        // If we encode the data, the first two parts should match the original payloads
        // ie. the 'pure' fragments (ie. the actual data split into two and encoded)
        ur_encoder_t* const encoder
            = ur_encoder_new(expected_type, payload, payload_len, encoder_max_fragment_len, 0, 10);
        JADE_ASSERT(encoder);
        char* parts[3] = { NULL, NULL, NULL };
        if (!ur_encoder_next_part(encoder, &parts[0]) || !parts[0] || strcmp(parts[0], qr_part1of2)) {
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }
        if (ur_encoder_is_complete(encoder)) {
            // Should NOT be complete yet
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }

        if (!ur_encoder_next_part(encoder, &parts[1]) || !parts[1] || strcmp(parts[1], qr_part2of2)) {
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }
        if (!ur_encoder_is_complete(encoder)) {
            // Should now be complete
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }

        // We can continue to generate additional parts - these are fountain-code fragments
        // which can stand in for any missed fragments.  NOTE: the sequence-numbers appear 'overflowed'.
        // NOTE: deliberately a prefix comparison, unlike the checks above -
        // only the header is fixed, the fountain-fragment body varies. The
        // length check stops a header-only string from passing.
        if (!ur_encoder_next_part(encoder, &parts[2]) || !parts[2] || strlen(parts[2]) <= strlen("UR:CRYPTO-PSBT/3-2/")
            || strncmp(parts[2], "UR:CRYPTO-PSBT/3-2/", strlen("UR:CRYPTO-PSBT/3-2/"))) {
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }
        ur_encoder_free(encoder);

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
                ur_decoder_t* const decoder = ur_decoder_new();
                JADE_ASSERT(decoder);

                // Present first part - should be processed, but NOT complete yet
                if (ur_decoder_receive_part(decoder, parts[i]) != UR_DECODER_PROCESSING) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (ur_decoder_processed_parts_count(decoder) != 1) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (ur_decoder_expected_part_count(decoder) != 2) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (ur_decoder_received_parts_count(decoder) != initial_expected_received) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }

                // Present second part
                const ur_decoder_state_t state = ur_decoder_receive_part(decoder, parts[j]);
                if (ur_decoder_state_is_error(state)) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                // NOTE: a duplicate part is deduped before it is counted, so
                // 'processed' remains 1 if the same part is presented twice
                if (ur_decoder_processed_parts_count(decoder) != (i != j ? 2 : 1)) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (ur_decoder_expected_part_count(decoder) != 2) {
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
                    if (ur_decoder_received_parts_count(decoder) != 2) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                    if (state != UR_DECODER_OK) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }

                    // Check payload is as expected - result borrowed from the decoder
                    const ur_result_t* const result = ur_decoder_get_result(decoder);
                    JADE_ASSERT(result);
                    JADE_ASSERT(result->type);
                    JADE_ASSERT(result->cbor_len);
                    JADE_ASSERT(result->cbor_data);
                    if (strcmp(expected_type, result->type)) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                    if (result->cbor_len != payload_len || memcmp(result->cbor_data, payload, result->cbor_len)) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                } else {
                    // Same part received twice - does not increment 'received_parts'
                    if (ur_decoder_received_parts_count(decoder) != initial_expected_received) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                    if (state != UR_DECODER_PROCESSING) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                }
                ur_decoder_free(decoder);
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
        ur_decoder_t* const decoder = ur_decoder_new();
        JADE_ASSERT(decoder);

        // Present first part - should be rejected with a transient (non-terminal)
        // error, and all counts of 'parts seen' should remain zero.
        const ur_decoder_state_t state = ur_decoder_receive_part(decoder, cases[i]);
        if (!ur_decoder_state_is_error(state)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_state_is_terminal(state)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_processed_parts_count(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_received_parts_count(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        ur_decoder_free(decoder);
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
