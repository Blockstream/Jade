#include "multisig.h"
#include "jade_assert.h"
#include "storage.h"
#include "utils/malloc_ext.h"

#include <sodium/utils.h>

// Walks the multisig signers and validates - this wallet must have at least one xpub and it must be correct
bool multisig_validate_signers(const char* network, const signer_t* signers, const size_t num_signers,
    const uint8_t* wallet_fingerprint, const size_t wallet_fingerprint_len)
{
    if (!signers || num_signers < 2 || num_signers > MAX_MULTISIG_SIGNERS || !wallet_fingerprint
        || wallet_fingerprint_len != BIP32_KEY_FINGERPRINT_LEN) {
        return false;
    }

    bool bFound = false;
    for (size_t i = 0; i < num_signers; ++i) {
        const signer_t* signer = signers + i;

        // Check additional 'path' (after the xpub) contains no hardened elements
        for (size_t j = 0; j < signer->path_len; ++j) {
            if (signer->path[j] & BIP32_INITIAL_HARDENED_CHILD) {
                JADE_LOGE("Found hardened path %d at pos %d in signer %d", signer->path[j], j, i);
                return false;
            }
        }

        // See if signer that matches this wallet (by fingerprint)
        if (sodium_memcmp(wallet_fingerprint, signer->fingerprint, wallet_fingerprint_len) == 0) {
            // This signer has our fingerprint - check xpub provided
            char* wallet_xpub = NULL;
            if (!wallet_get_xpub(network, signer->derivation, signer->derivation_len, &wallet_xpub)) {
                JADE_LOGE("Cannot get xpub for derivation path (signer %d)", i);
                return false;
            }
            if (strcmp(wallet_xpub, signer->xpub) != 0) {
                JADE_LOGE("xpub mismatch (signer %d) - this wallet: %s - param: %s", i, wallet_xpub, signer->xpub);
                wally_free_string(wallet_xpub);
                return false;
            }
            wally_free_string(wallet_xpub);

            // All good - we have found our signer in the multisig
            bFound = true;
        }
    }

    return bFound;
}

bool multisig_data_to_bytes(const script_variant_t variant, const bool sorted, const uint8_t threshold,
    const signer_t* signers, const size_t num_signers, uint8_t* output_bytes, const size_t output_len)
{
    JADE_ASSERT(threshold > 0);
    JADE_ASSERT(signers);
    JADE_ASSERT(num_signers > 1);
    JADE_ASSERT(num_signers <= MAX_MULTISIG_SIGNERS);
    JADE_ASSERT(output_bytes);
    JADE_ASSERT(output_len == MULTISIG_BYTES_LEN(num_signers));

    // Version byte
    // (1 - now that we include the 'sorted' flag)
    const uint8_t version = 1;
    uint8_t* write_ptr = output_bytes;
    memcpy(write_ptr, &version, sizeof(version));
    write_ptr += sizeof(version);

    // Script variant
    const uint8_t variant_byte = (uint8_t)variant;
    memcpy(write_ptr, &variant_byte, sizeof(variant_byte));
    write_ptr += sizeof(variant_byte);

    // 'sorted' flag
    const uint8_t sorted_byte = (uint8_t)sorted;
    memcpy(write_ptr, &sorted_byte, sizeof(sorted_byte));
    write_ptr += sizeof(sorted_byte);

    // Threshold
    memcpy(write_ptr, &threshold, sizeof(threshold));
    write_ptr += sizeof(threshold);

    // All signers immediate parent keys
    for (size_t i = 0; i < num_signers; ++i) {
        struct ext_key hdkey;
        const signer_t* signer = signers + i;
        if (!wallet_derive_from_xpub(signer->xpub, signer->path, signer->path_len, BIP32_FLAG_SKIP_HASH, &hdkey)) {
            JADE_LOGE("Failed to derive signer pubkey");
            return false;
        }

        // Get xpub in bytes-serialised form
        uint8_t xpub[BIP32_SERIALIZED_LEN];
        if (bip32_key_serialize(&hdkey, BIP32_FLAG_KEY_PUBLIC, xpub, sizeof(xpub)) != WALLY_OK) {
            JADE_LOGE("Failed to serialise signer xpub");
            return false;
        }

        // Append serialised xpub to the data bytes
        memcpy(write_ptr, xpub, sizeof(xpub));
        write_ptr += sizeof(xpub);
    }

    // Append hmac
    JADE_ASSERT(write_ptr + HMAC_SHA256_LEN == output_bytes + output_len);
    return wallet_hmac_with_master_key(output_bytes, output_len - HMAC_SHA256_LEN, write_ptr, HMAC_SHA256_LEN);
}

bool multisig_data_from_bytes(const uint8_t* bytes, const size_t bytes_len, multisig_data_t* output)
{
    JADE_ASSERT(bytes);
    JADE_ASSERT(bytes_len > MULTISIG_BYTES_LEN(1));
    JADE_ASSERT(output);

    // Check hmac first
    uint8_t hmac_calculated[HMAC_SHA256_LEN];
    if (!wallet_hmac_with_master_key(bytes, bytes_len - HMAC_SHA256_LEN, hmac_calculated, sizeof(hmac_calculated))
        || sodium_memcmp(bytes + bytes_len - HMAC_SHA256_LEN, hmac_calculated, sizeof(hmac_calculated)) != 0) {
        JADE_LOGW("Multisig data HMAC error/mismatch");
        return false;
    }

    // Version byte
    // (0 - before 'sorted' flag was added; 1 - includes 'sorted' flag)
    const uint8_t* read_ptr = bytes;
    const uint8_t version = *read_ptr;
    if (version > 1) {
        JADE_LOGE("Bad version byte in stored registered multisig data");
        return false;
    }
    read_ptr += sizeof(version);

    // Script variant
    uint8_t variant_byte;
    memcpy(&variant_byte, read_ptr, sizeof(variant_byte));
    output->variant = variant_byte;
    read_ptr += sizeof(variant_byte);

    // Version 1 adds the 'sorted' flag (which otherwise defaults to false)
    output->sorted = false;
    if (version > 0) {
        uint8_t sorted_byte;
        memcpy(&sorted_byte, read_ptr, sizeof(sorted_byte));
        output->sorted = (bool)sorted_byte;
        read_ptr += sizeof(sorted_byte);
    }

    // Threshold
    output->threshold = *read_ptr;
    read_ptr += sizeof(uint8_t);

    // All signers immediate parent keys
    const size_t xpubs_bytes_len = bytes + bytes_len - HMAC_SHA256_LEN - read_ptr;
    const size_t num_xpubs = xpubs_bytes_len / BIP32_SERIALIZED_LEN;
    if (num_xpubs > MAX_MULTISIG_SIGNERS) {
        JADE_LOGE("Unexpected number of multisig signers %d", output->xpubs_len);
        return false;
    }
    if (num_xpubs * BIP32_SERIALIZED_LEN != xpubs_bytes_len) {
        JADE_LOGE("Unexpected multisig data length %d for %d signers", bytes_len, output->xpubs_len);
        return false;
    }
    output->xpubs_len = (uint8_t)num_xpubs; // ok as less than MAX_MULTISIG_SIGNERS

    memcpy(output->xpubs, read_ptr, xpubs_bytes_len);
    read_ptr += xpubs_bytes_len;

    // Check just got the hmac (checked first, above) left in the buffer
    JADE_ASSERT(read_ptr + HMAC_SHA256_LEN == bytes + bytes_len);

    return true;
}

bool multisig_load_from_storage(const char* multisig_name, multisig_data_t* output, const char** errmsg)
{
    JADE_ASSERT(multisig_name);
    JADE_ASSERT(output);
    JADE_ASSERT(errmsg);

    size_t written = 0;
    uint8_t registration[MULTISIG_BYTES_LEN(MAX_MULTISIG_SIGNERS)]; // Sufficient
    if (!storage_get_multisig_registration(multisig_name, registration, sizeof(registration), &written)) {
        *errmsg = "Cannot find named multisig wallet";
        return false;
    }

    if (!multisig_data_from_bytes(registration, written, output)) {
        *errmsg = "Cannot de-serialise multisig wallet data";
        return false;
    }

    // Sanity check data we are have loaded
    if (!is_multisig(output->variant) || output->threshold == 0 || output->threshold > output->xpubs_len
        || output->xpubs_len < 2 || output->xpubs_len > MAX_MULTISIG_SIGNERS) {
        *errmsg = "Multisig wallet data invalid";
    }

    return true;
}

bool multisig_validate_paths(const bool is_change, CborValue* all_signer_paths, bool* all_paths_as_expected)
{
    JADE_ASSERT(all_signer_paths);
    JADE_ASSERT(all_paths_as_expected);

    bool seen_unusual_path = false;

    size_t array_len = 0;
    if (cbor_value_get_array_length(all_signer_paths, &array_len) != CborNoError || array_len == 0) {
        return false;
    }

    uint32_t path[MAX_PATH_LEN];
    const size_t max_path_len = sizeof(path) / sizeof(path[0]);

    CborValue arrayItem;
    CborError cberr = cbor_value_enter_container(all_signer_paths, &arrayItem);
    JADE_ASSERT(cberr == CborNoError);
    for (size_t i = 0; i < array_len; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));

        size_t path_len = 0;
        if (!rpc_get_bip32_path_from_value(&arrayItem, path, max_path_len, &path_len) || path_len == 0) {
            return false;
        }

        if (!wallet_is_expected_multisig_path(i, is_change, path, path_len)) {
            // Path is valid, but does not fit an expected pattern/format
            seen_unusual_path = true;
        }
    }

    *all_paths_as_expected = !seen_unusual_path;
    return true;
}

bool multisig_get_pubkeys(const uint8_t* xpubs, const size_t num_xpubs, CborValue* all_signer_paths, uint8_t* pubkeys,
    const size_t pubkeys_len, size_t* written)
{
    JADE_ASSERT(xpubs);
    JADE_ASSERT(num_xpubs > 1);
    JADE_ASSERT(all_signer_paths);
    JADE_ASSERT(pubkeys);
    JADE_ASSERT(pubkeys_len >= num_xpubs * EC_PUBLIC_KEY_LEN);
    JADE_ASSERT(written);

    // Check the number of signers
    *written = 0;
    if (cbor_value_get_array_length(all_signer_paths, written) != CborNoError || *written != num_xpubs) {
        return false;
    }

    uint32_t path[MAX_PATH_LEN];
    const size_t max_path_len = sizeof(path) / sizeof(path[0]);

    CborValue arrayItem;
    CborError cberr = cbor_value_enter_container(all_signer_paths, &arrayItem);
    JADE_ASSERT(cberr == CborNoError);
    for (size_t i = 0; i < num_xpubs; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));

        *written = 0;
        if (!rpc_get_bip32_path_from_value(&arrayItem, path, max_path_len, written) || *written == 0) {
            return false;
        }
        for (size_t j = 0; j < *written; ++j) {
            if (path[j] & BIP32_INITIAL_HARDENED_CHILD) {
                return false;
            }
        }

        struct ext_key hdkey;
        const uint8_t* xpub = xpubs + (i * BIP32_SERIALIZED_LEN);
        if (!wallet_derive_pubkey(xpub, BIP32_SERIALIZED_LEN, path, *written, BIP32_FLAG_SKIP_HASH, &hdkey)) {
            return false;
        }

        uint8_t* dest = pubkeys + (i * EC_PUBLIC_KEY_LEN);
        memcpy(dest, hdkey.pub_key, EC_PUBLIC_KEY_LEN);
    }
    *written = num_xpubs * EC_PUBLIC_KEY_LEN;

    return true;
}
