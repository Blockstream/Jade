#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../descriptor.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../process.h"
#include "../sensitive.h"
#include "../storage.h"
#include "../ui/sign_tx.h"
#include "../utils/cbor_rpc.h"
#include "../utils/event.h"
#include "../utils/malloc_ext.h"
#include "../utils/psbt.h"
#include "../utils/temporary_stack.h"
#include "../utils/util.h"
#include "../utils/wally_ext.h"
#include "../wallet.h"

#include <sodium/utils.h>

#include <wally_map.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>

#include "sign_utils.h"

// From https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
static const uint8_t PSBT_MAGIC_PREFIX[5] = { 0x70, 0x73, 0x62, 0x74, 0xFF }; // 'psbt' + 0xff
static const uint8_t PSET_MAGIC_PREFIX[5] = { 0x70, 0x73, 0x65, 0x74, 0xFF }; // 'pset' + 0xff

// Cache what type of inputs we are signing
#define PSBT_SIGNING_SINGLESIG 0x1
#define PSBT_SIGNING_MULTISIG 0x2
#define PSBT_SIGNING_GREEN_MULTISIG 0x4

// Also if just one multisig record used for all signing inputs
#define PSBT_SIGNING_SINGLE_MULTISIG_RECORD 0x10
#define PSBT_SIGNING_MULTISIG_CHANGE_ABANDONED 0x20

#define PSBT_OUT_CHUNK_SIZE (MAX_OUTPUT_MSG_SIZE - 64)

static bool is_green_multisig_signers(const network_t network_id, const key_iter* iter, struct ext_key* recovery_hdkey)
{
    JADE_ASSERT(network_id != NETWORK_NONE);
    JADE_ASSERT(iter && iter->is_valid);

    const size_t num_keys = key_iter_get_num_keys(iter);
    if (num_keys != 2 && num_keys != 3) {
        // Green multisig is 2of2 or 2of3 only
        return false;
    }

    uint8_t user_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    wallet_get_fingerprint(user_fingerprint, sizeof(user_fingerprint));
    uint32_t user_path[MAX_PATH_LEN];
    size_t user_path_len = 0;

    uint8_t ga_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    if (!wallet_get_gaservice_fingerprint(network_id, ga_fingerprint, sizeof(ga_fingerprint))) {
        // Can't get ga-signer for network
        return false;
    }
    uint32_t ga_path[MAX_GASERVICE_PATH_LEN];
    size_t ga_path_len = 0;

    uint32_t recovery_path[MAX_PATH_LEN];
    size_t recovery_path_len = 0;

    for (size_t ikey = 0; ikey < num_keys; ++ikey) {
        uint8_t key_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
        key_iter_get_fingerprint_at(iter, ikey, key_fingerprint, sizeof(key_fingerprint));

        if (!memcmp(key_fingerprint, user_fingerprint, sizeof(key_fingerprint))) {
            // Appears to be our signer
            if (user_path_len || !key_iter_get_path_at(iter, ikey, user_path, MAX_PATH_LEN, &user_path_len)) {
                // Seen user signer already or path too long
                return false;
            }
        } else if (!memcmp(key_fingerprint, ga_fingerprint, sizeof(key_fingerprint))) {
            // Appears to be ga-service signer
            if (ga_path_len || !key_iter_get_path_at(iter, ikey, ga_path, MAX_GASERVICE_PATH_LEN, &ga_path_len)) {
                // Seen ga service signer already or path too long
                return false;
            }
        } else {
            // 2of3 recovery key
            if (recovery_path_len
                || !key_iter_get_path_at(iter, ikey, recovery_path, MAX_PATH_LEN, &recovery_path_len)) {
                // Seen 'third-party' signer already or path too long
                return false;
            }

            // Return the recovery pubkey if the caller so desires
            // NOTE: only compressed pubkeys are expected/supported.
            if (recovery_hdkey) {
                if (!key_iter_get_pubkey_at(iter, ikey, recovery_hdkey->pub_key, sizeof(recovery_hdkey->pub_key))) {
                    JADE_LOGE("Error fetching ga-multisig 2of3 recovery key");
                    return false;
                }
            }
        }
    }

    // Check got expected paths
    if (!user_path_len || !ga_path_len || (num_keys == 3 && !recovery_path_len)) {
        return false;
    }

    // Check final path elements identical
    const uint32_t user_ptr = user_path[user_path_len - 1];
    if (ga_path[ga_path_len - 1] != user_ptr || (num_keys == 3 && recovery_path[recovery_path_len - 1] != user_ptr)) {
        return false;
    }

    // Check entire ga-service path
    uint32_t expected_ga_path[MAX_GASERVICE_PATH_LEN];
    size_t expected_ga_path_len = 0;
    if (!wallet_get_gaservice_path(
            user_path, user_path_len, expected_ga_path, MAX_GASERVICE_PATH_LEN, &expected_ga_path_len)) {
        // Can't get ga-service path for given user path
        return false;
    }

    if (ga_path_len != expected_ga_path_len
        || sodium_memcmp(expected_ga_path, ga_path, ga_path_len * sizeof(ga_path[0]))) {
        // Unexpected ga service path
        return false;
    }

    // Looks like GA signers...
    return true;
}

// Generate a green-multisig script, and compare it to the target script provided.
// Returns true if the generated script matches the target script.
static bool verify_ga_script_matches(const network_t network_id, const struct ext_key* user_key,
    const struct ext_key* recovery_key, const uint32_t* path, const size_t path_len, const uint8_t* target_script,
    const size_t target_script_len)
{
    JADE_ASSERT(network_id != NETWORK_NONE);
    JADE_ASSERT(path);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);

    uint32_t csv_blocks = 0;
    // NOTE: 2of3 csv not supported, so we don't check for it if we have a recovery key
    if (recovery_key) {
        // 2of2: fetch the number of csv blocks if this is a csv script
        int ret = wally_scriptpubkey_csv_blocks_from_csv_2of2_then_1(target_script, target_script_len, &csv_blocks);
        if (ret == WALLY_OK && !network_is_known_csv_blocks(network_id, csv_blocks)) {
            return false; // csv script with an invalid csv_blocks
        }
    }

    // Generate and match the script, either csv, or legacy if csv_blocks is 0
    size_t trial_script_len = 0;
    uint8_t trial_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient

    if (!wallet_build_ga_script_ex(network_id, user_key, recovery_key, csv_blocks, path, path_len, trial_script,
            sizeof(trial_script), &trial_script_len)) {
        // Failed to build script
        JADE_LOGE("Receive script cannot be constructed");
        return false;
    }

    // Compare generated script to that expected/in the txn
    if (trial_script_len != target_script_len || sodium_memcmp(target_script, trial_script, trial_script_len) != 0) {
        JADE_LOGW("Receive script failed validation");
        return false;
    }

    // Script matches
    return true;
}

// Helper to generate a singlesig script of the given type with the pubkey given, and
// compare it to the target script provided.
// Returns true if the generated script matches the target script.
static bool verify_singlesig_script_matches(const network_t network_id, const script_variant_t script_variant,
    const struct ext_key* hdkey, const uint8_t* target_script, const size_t target_script_len)
{
    JADE_ASSERT(is_singlesig(script_variant));
    JADE_ASSERT(hdkey);
    JADE_ASSERT(target_script);

    // Check expected script length
    if (script_length_for_variant(script_variant) != target_script_len) {
        JADE_LOGE("Receive script unexpected size");
        return false;
    }

    // Build our script
    size_t trial_script_len = 0;
    uint8_t trial_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient
    if (!wallet_build_singlesig_script(
            network_id, script_variant, hdkey, trial_script, sizeof(trial_script), &trial_script_len)) {
        // Failed to build script
        JADE_LOGE("Receive script cannot be constructed");
        return false;
    }

    // Compare generated script to that expected/in the txn
    if (trial_script_len != target_script_len || sodium_memcmp(target_script, trial_script, trial_script_len) != 0) {
        JADE_LOGW("Receive script failed validation");
        return false;
    }

    // Script matches
    return true;
}

// Use the passed multisig to derive the signers pubkeys, and if they seem good to make the output script
// Return whether that is all good and the generated output script matches the passed target script
static bool verify_multisig_script_matches(const multisig_data_t* multisig_data, const uint32_t* path,
    const size_t path_len, const key_iter* iter, const uint8_t* target_script, const size_t target_script_len)
{
    JADE_ASSERT(multisig_data);
    JADE_ASSERT(path);
    JADE_ASSERT(path_len);
    JADE_ASSERT(iter && iter->is_valid);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);

    // Ensure script length matches
    if (script_length_for_variant(multisig_data->variant) != target_script_len) {
        JADE_LOGD("Mismatch in script size");
        return false;
    }

    // Ensure number of signatories match
    const size_t num_keys = key_iter_get_num_keys(iter);
    if (multisig_data->num_xpubs != num_keys) {
        JADE_LOGD("Mismatch in number of signatories");
        return false;
    }

    // Check pubkeys match those given
    struct ext_key hdkey;
    uint8_t pubkeys[MAX_ALLOWED_SIGNERS * EC_PUBLIC_KEY_LEN]; // Sufficient
    const size_t pubkeys_len = multisig_data->num_xpubs * EC_PUBLIC_KEY_LEN;
    for (size_t i = 0; i < multisig_data->num_xpubs; ++i) {
        // Derive a pubkey for this registered signer based for the common path tail
        const uint8_t* xpub = multisig_data->xpubs + (i * BIP32_SERIALIZED_LEN);
        if (!wallet_derive_pubkey(xpub, BIP32_SERIALIZED_LEN, path, path_len, BIP32_FLAG_SKIP_HASH, &hdkey)) {
            JADE_LOGE("Failed to derive pubkey from xpub and path (len %u)", path_len);
            return false;
        }

        // See if it is present in the iterators keypath map
        if (!key_iter_contains_pubkey(iter, hdkey.pub_key, sizeof(hdkey.pub_key))) {
            // Derived key not in map
            JADE_LOGD("Derived key not present in output keymap");
            return false;
        }

        // Copy pubkey
        uint8_t* const dest = pubkeys + (i * EC_PUBLIC_KEY_LEN);
        memcpy(dest, hdkey.pub_key, EC_PUBLIC_KEY_LEN);
    }

    // Build multisig script
    size_t trial_script_len = 0;
    uint8_t trial_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient;
    if (!wallet_build_multisig_script(multisig_data->variant, multisig_data->sorted, multisig_data->threshold, pubkeys,
            pubkeys_len, trial_script, sizeof(trial_script), &trial_script_len)) {
        JADE_LOGE("Receive script cannot be constructed");
        return false;
    }

    // Compare generated script to that expected/in the txn
    if (trial_script_len != target_script_len || sodium_memcmp(trial_script, target_script, target_script_len) != 0) {
        JADE_LOGW("Receive script failed validation");
        return false;
    }

    // Script matches
    return true;
}

// Use the passed descriptor to derive the output script
// Return whether the generated output script matches the passed target script
static bool verify_descriptor_script_matches_impl(const char* descriptor_name, const descriptor_data_t* descriptor,
    const network_t network_id, const uint32_t multi_index, const uint32_t index, const uint8_t* target_script,
    const size_t target_script_len)
{
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(descriptor);
    JADE_ASSERT(network_id != NETWORK_NONE);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);

    // Build descriptor script
    const char* errmsg = NULL;
    size_t trial_script_len = 0;
    uint8_t trial_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient;
    if (!wallet_build_descriptor_script(network_id, descriptor_name, descriptor, multi_index, index, trial_script,
            sizeof(trial_script), &trial_script_len, &errmsg)) {
        JADE_LOGE("Receive script cannot be constructed");
        return false;
    }

    // Compare generated script to that expected/in the txn
    if (trial_script_len != target_script_len || sodium_memcmp(trial_script, target_script, target_script_len) != 0) {
        JADE_LOGW("Receive script failed validation");
        return false;
    }

    // Script matches
    return true;
}

// Use the passed descriptor to derive the output script
// Return whether the generated output script matches the passed target script
static bool verify_descriptor_script_matches(const char* descriptor_name, const descriptor_data_t* descriptor,
    const network_t network_id, const uint32_t* path, const size_t path_len, const key_iter* iter,
    const uint8_t* target_script, const size_t target_script_len)
{
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(descriptor);
    JADE_ASSERT(network_id != NETWORK_NONE);
    JADE_ASSERT(path);
    JADE_ASSERT(path_len);
    JADE_ASSERT(iter && iter->is_valid);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);

    // Ensure number of pubkeys is not less than the number of xpub signers
    // (xpubs can be reused with different paths, but they cannot be left unused)
    const size_t num_keys = key_iter_get_num_keys(iter);
    if (descriptor->num_values > num_keys) {
        JADE_LOGD("Mismatch in number of signatories");
        return false;
    }

    // Get the final path index
    const uint32_t index = path[path_len - 1];

    // If longer path tail, try descriptor with multi-path 1
    uint32_t multi_index = 1;
    if (path_len > 1
        && verify_descriptor_script_matches_impl(
            descriptor_name, descriptor, network_id, multi_index, index, target_script, target_script_len)) {
        return true;
    }

    multi_index = 0;
    return verify_descriptor_script_matches_impl(
        descriptor_name, descriptor, network_id, multi_index, index, target_script, target_script_len);
}

// Try to find a multisig registration which creates the passed script with the given
// key iterators keys.  Our signer's path tail is passed in, and is assumed to be common across signers.
static bool get_suitable_multisig_record(const key_iter* iter, const uint32_t* path, const size_t path_len,
    const uint8_t* target_script, const size_t target_script_len, char* wallet_name, const size_t wallet_name_len,
    multisig_data_t* const multisig_data)
{
    JADE_ASSERT(iter && iter->is_valid);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);
    JADE_ASSERT(wallet_name);
    JADE_ASSERT(wallet_name_len);
    JADE_ASSERT(multisig_data);

    // Load multisig record names saved in nvs
    char names[MAX_MULTISIG_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t num_names = sizeof(names) / sizeof(names[0]);
    size_t num_multisigs = 0;
    if (!storage_get_all_multisig_registration_names(names, num_names, &num_multisigs)) {
        JADE_LOGE("Error loading multisig record names");
        return false;
    }

    // Iterate over named persisted multisigs to see if one fits
    for (int i = 0; i < num_multisigs; ++i) {
        const char* errmsg = NULL;
        if (!multisig_load_from_storage(names[i], multisig_data, NULL, 0, NULL, &errmsg)) {
            JADE_LOGD("Ignoring multisig %s as not valid for this wallet", names[i]);
            continue;
        }

        JADE_LOGD("Trying loaded multisig: %s", names[i]);
        if (!verify_multisig_script_matches(multisig_data, path, path_len, iter, target_script, target_script_len)) {
            JADE_LOGD("Receive script failed validation with %s", names[i]);
            continue;
        }

        // Found suitable record
        JADE_LOGI("Found suitable multisig record: %s", names[i]);
        JADE_ASSERT(strlen(names[i]) < wallet_name_len);
        strcpy(wallet_name, names[i]);
        return true;
    }

    JADE_LOGW("No suitable multisig record found");
    return false;
}

// Try to find a descriptor registration which creates the passed script with the given
// key iterators keys.  Our signer's path tail is passed in, and is assumed to be common across signers.
static bool get_suitable_descriptor_record(const key_iter* iter, const uint32_t* path, const size_t path_len,
    const uint8_t* target_script, const size_t target_script_len, const network_t network_id, char* wallet_name,
    const size_t wallet_name_len, descriptor_data_t* const descriptor)
{
    JADE_ASSERT(iter && iter->is_valid);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);
    JADE_ASSERT(network_id != NETWORK_NONE);
    JADE_ASSERT(wallet_name);
    JADE_ASSERT(wallet_name_len);
    JADE_ASSERT(descriptor);

    // Load descriptor record names saved in nvs
    char names[MAX_DESCRIPTOR_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t num_names = sizeof(names) / sizeof(names[0]);
    size_t num_descriptors = 0;
    if (!storage_get_all_descriptor_registration_names(names, num_names, &num_descriptors)) {
        JADE_LOGE("Error loading descriptor record names");
        return false;
    }

    // Iterate over named persisted descriptors to see if one fits
    for (int i = 0; i < num_descriptors; ++i) {
        const char* errmsg = NULL;
        if (!descriptor_load_from_storage(names[i], descriptor, &errmsg)) {
            JADE_LOGD("Ignoring descriptor %s as not valid for this wallet", names[i]);
            continue;
        }

        JADE_LOGI("Trying loaded descriptor: %s", names[i]);
        if (!verify_descriptor_script_matches(
                names[i], descriptor, network_id, path, path_len, iter, target_script, target_script_len)) {
            JADE_LOGD("Receive script failed validation with %s", names[i]);
            continue;
        }

        // Found suitable record
        JADE_LOGI("Found suitable descriptor record: %s", names[i]);
        JADE_ASSERT(strlen(names[i]) < wallet_name_len);
        strcpy(wallet_name, names[i]);
        return true;
    }

    JADE_LOGW("No suitable descriptor record found");
    return false;
}

// Examine outputs for change we can automatically validate
static bool validate_outputs(const network_t network_id, struct wally_psbt* psbt, const uint8_t signing_flags,
    const char* wallet_name, const multisig_data_t* multisig_data, const descriptor_data_t* descriptor,
    output_info_t* output_info, const char** errmsg)
{
    JADE_ASSERT(network_id != NETWORK_NONE);
    JADE_ASSERT(psbt);
    // wallet_name, multisig_data and descriptor optional
    JADE_ASSERT(output_info);
    JADE_INIT_OUT_PPTR(errmsg);

    const bool is_liquid = network_is_liquid(network_id);
    JADE_ASSERT(!multisig_data || !descriptor); // cannot have both
    JADE_ASSERT(!is_liquid || !descriptor); // atm do not support liquid descriptors

    key_iter iter; // Holds any public key in use

    // Check each output in turn
    for (size_t index = 0; index < psbt->num_outputs; ++index) {
        size_t written = 0;
        output_info_t* const outinfo = output_info + index;

        // If liquid, look for blinding data and explicit fees (scriptless outputs)
        if (is_liquid) {
            if ((wally_psbt_get_output_asset_commitment_len(psbt, index, &written) == WALLY_OK && written)
                || (wally_psbt_get_output_value_commitment_len(psbt, index, &written) == WALLY_OK && written)) {
                outinfo->flags |= OUTPUT_FLAG_CONFIDENTIAL;
            }

            if (wally_psbt_get_output_blinding_public_key(
                    psbt, index, outinfo->blinding_key, sizeof(outinfo->blinding_key), &written)
                    == WALLY_OK
                && written) {
                JADE_ASSERT(written == sizeof(outinfo->blinding_key));
                outinfo->flags |= OUTPUT_FLAG_HAS_BLINDING_KEY;
            }

            if (wally_psbt_get_output_amount(psbt, index, &outinfo->value) == WALLY_OK
                && wally_psbt_get_output_asset(psbt, index, outinfo->asset_id, sizeof(outinfo->asset_id), &written)
                    == WALLY_OK
                && written) {
                JADE_ASSERT(written == sizeof(outinfo->asset_id));
                reverse_in_place(outinfo->asset_id, sizeof(outinfo->asset_id));
                outinfo->flags |= OUTPUT_FLAG_HAS_UNBLINDED;
            }

            if (wally_psbt_get_output_script_len(psbt, index, &written) != WALLY_OK || !written) {
                // Fee output
                JADE_ASSERT(!(outinfo->flags & OUTPUT_FLAG_CONFIDENTIAL));
                JADE_ASSERT(outinfo->flags & OUTPUT_FLAG_HAS_UNBLINDED);
                // Fee outputs can't be change, so may as well skip now
                JADE_ASSERT(!(outinfo->flags & (OUTPUT_FLAG_VALIDATED | OUTPUT_FLAG_CHANGE)));
                continue;
            }
        }

        JADE_LOGD("Considering output %u for change", index);

        // By default, assume not a validated or change output, and so user must verify
        JADE_ASSERT(!(outinfo->flags & (OUTPUT_FLAG_VALIDATED | OUTPUT_FLAG_CHANGE)));

        // Find the first key belonging to this signer
        if (!key_iter_output_begin_public(psbt, index, &iter)) {
            // No key in this output belongs to this signer
            JADE_LOGD("No key in output %u, ignoring", index);
            continue;
        }

        // Get the key path, and check the penultimate element
        size_t path_len = 0;
        uint32_t path[MAX_PATH_LEN];
        if (!key_iter_get_path(&iter, path, MAX_PATH_LEN, &path_len)) {
            JADE_LOGE("No valid path in output %u, ignoring", index);
            continue;
        }
        const bool is_change = path_len >= 2 && path[path_len - 2] == 1;

        // Get the output scriptpubkey
        uint8_t tx_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient
        size_t tx_script_len = 0;
        if (wally_psbt_get_output_script(psbt, index, tx_script, sizeof(tx_script), &tx_script_len) != WALLY_OK
            || tx_script_len > sizeof(tx_script)) {
            JADE_LOGE("Failed to get output script for output %u", index);
            continue;
        }

        const size_t num_keys = key_iter_get_num_keys(&iter);
        if (num_keys == 1) {
            JADE_ASSERT(iter.key_index == 0); // only key present

            // Skip if we did not sign any singlesig inputs
            if (!(signing_flags & PSBT_SIGNING_SINGLESIG)) {
                JADE_LOGD("Ignoring singlesig output %u as not signing singlesig inputs", index);
                continue;
            }

            // Get our script 'variant'
            size_t script_type;
            script_variant_t script_variant;
            if (wally_scriptpubkey_get_type(tx_script, tx_script_len, &script_type) != WALLY_OK
                || !get_singlesig_variant_from_script_type(script_type, &script_variant)) {
                JADE_LOGE("Failed to get valid script variant type");
                continue;
            }

            // Check that we can generate a script that matches the tx
            if (!verify_singlesig_script_matches(network_id, script_variant, &iter.hdkey, tx_script, tx_script_len)) {
                JADE_LOGW("Receive script failed validation");
                continue;
            }

            // Change path valid and matches tx output script
            JADE_LOGI("Output %u singlesig %s path/script validated", index, is_change ? "change" : "receive");

            // Set appropriate flags
            outinfo->flags |= OUTPUT_FLAG_VALIDATED;
            if (is_change) {
                outinfo->flags |= OUTPUT_FLAG_CHANGE;
            }

            // Check the path is as expected
            if (!wallet_is_expected_singlesig_path(network_id, script_variant, is_change, path, path_len)) {
                // Not our standard change path - add warning
                char path_str[MAX_PATH_STR_LEN(MAX_PATH_LEN)];
                const bool have_path_str = wallet_bip32_path_as_str(path, path_len, path_str, sizeof(path_str));
                const int ret = snprintf(outinfo->message, sizeof(outinfo->message), "Unusual receive path: %s",
                    have_path_str ? path_str : "too long");
                JADE_ASSERT(ret > 0 && ret < sizeof(outinfo->message));
            }
        } else if (signing_flags == (PSBT_SIGNING_GREEN_MULTISIG | PSBT_SIGNING_MULTISIG_CHANGE_ABANDONED)) {
            // Signed only Green multisig inputs, only consider similar outputs
            JADE_ASSERT(iter.key_index < num_keys);

            struct ext_key recovery_hdkey;
            struct ext_key* recovery_p = num_keys == 3 ? &recovery_hdkey : NULL;
            if (!is_green_multisig_signers(network_id, &iter, recovery_p)) {
                JADE_LOGD("Ignoring non-green-multisig output %u as only signing green-multisig inputs", index);
                continue;
            }

            if (!verify_ga_script_matches(
                    network_id, &iter.hdkey, recovery_p, path, path_len, tx_script, tx_script_len)) {
                JADE_LOGD("Receive script failed validation for Green multisig");
                continue;
            }

            // Change path valid and matches expected output script
            JADE_LOGI("Output %u green-multisig path/script validated", index);

            // Set appropriate flags - note Green wallet-output is always assumed to be change
            outinfo->flags |= (OUTPUT_FLAG_VALIDATED | OUTPUT_FLAG_CHANGE);

        } else if (signing_flags == (PSBT_SIGNING_MULTISIG | PSBT_SIGNING_SINGLE_MULTISIG_RECORD)) {
            // Generic multisig or descriptor
            JADE_ASSERT(iter.key_index < num_keys);
            JADE_ASSERT(!multisig_data != !descriptor); // one or the other

            // Get the path tail after the last hardened element
            const size_t path_tail_start = path_get_unhardened_tail_index(path, path_len);
            JADE_ASSERT(path_tail_start <= path_len);
            const size_t path_tail_len = path_len - path_tail_start;

            if (multisig_data
                && !verify_multisig_script_matches(
                    multisig_data, &path[path_tail_start], path_tail_len, &iter, tx_script, tx_script_len)) {
                JADE_LOGD("Receive script failed validation with multisig %s", wallet_name);
                continue;
            }
            if (descriptor
                && !verify_descriptor_script_matches(wallet_name, descriptor, network_id, &path[path_tail_start],
                    path_tail_len, &iter, tx_script, tx_script_len)) {
                JADE_LOGD("Receive script failed validation with descriptor %s", wallet_name);
                continue;
            }

            // Change path valid and matches expected output script
            JADE_LOGI("Output %u multisig %s path/script validated: %s", index, is_change ? "change" : "receive",
                wallet_name);

            // Set appropriate flags
            outinfo->flags |= OUTPUT_FLAG_VALIDATED;
            if (is_change) {
                outinfo->flags |= OUTPUT_FLAG_CHANGE;
            }

            // Check path tail looks as expected
            if (!wallet_is_expected_multisig_path(iter.key_index, is_change, &path[path_tail_start], path_tail_len)) {
                // Not our standard change path - add warning
                char path_str[MAX_PATH_STR_LEN(MAX_PATH_LEN)];
                const bool have_path_str = wallet_bip32_path_as_str(path, path_len, path_str, sizeof(path_str));
                const int ret = snprintf(outinfo->message, sizeof(outinfo->message), "Unusual change path suffix: %s",
                    have_path_str ? path_str : "too long");
                JADE_ASSERT(ret > 0 && ret < sizeof(outinfo->message));
            }
        } else {
            // Skip if we did not sign *only* multisig inputs for a single multisig record
            JADE_LOGI(
                "Ignoring multisig output %u as not signing only multisig inputs for a single registration", index);
        }
    }
    return true;
}

// Sign a psbt/pset - the passed wally psbt struct is updated with any signatures.
// Returns 0 if no errors occurred - does not necessarily indicate that signatures were added.
// Returns an rpc/message error code on error, and the error string should be populated.
int sign_psbt(const network_t network_id, struct wally_psbt* psbt, const char** errmsg)
{
    JADE_ASSERT(psbt);
    JADE_INIT_OUT_PPTR(errmsg);
    JADE_ASSERT(network_id != NETWORK_NONE);
    int retval = 0;

    size_t is_elements = 0;
    JADE_WALLY_VERIFY(wally_psbt_is_elements(psbt, &is_elements));
    if (!is_elements != !network_is_liquid(network_id)) {
        *errmsg = "Network/psbt type mismatch";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    uint64_t explicit_fee = 0;
    struct wally_tx* tx = NULL; // Holds the extracted tx

    // Fetch the tx to sign
    if (psbt->version == WALLY_PSBT_VERSION_0) {
        tx = psbt->tx; // For v0, use the PSBT tx directly
    } else if (wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, &tx) != WALLY_OK) {
        *errmsg = "Failed to extract valid txn from passed psbt";
        return CBOR_RPC_BAD_PARAMETERS;
    }
    JADE_ASSERT(tx && tx->num_inputs == psbt->num_inputs && tx->num_outputs == psbt->num_outputs);

    if (!params_txn_validate(network_id, for_liquid, tx, &explicit_fee, errmsg)) {
        retval = CBOR_RPC_BAD_PARAMETERS;
        goto cleanup;
    }

    key_iter iter; // Holds any public/private key in use
    SENSITIVE_PUSH(&iter, sizeof(iter));

    // We track if the type of the inputs we are signing changes (ie. single-sig vs
    // green/multisig/other) so we can show a warning to the user if so.
    script_flavour_t aggregate_inputs_scripts_flavour = SCRIPT_FLAVOUR_NONE;

    // Output info
    output_info_t* const output_info = JADE_CALLOC(psbt->num_outputs, sizeof(output_info_t));

    // Go through each of the inputs summing amounts
    // Also, if we are signing this input, inspect the script type and any multisig info
    // For inputs we are signing, record the signature type
    uint8_t* const sig_types = JADE_CALLOC(psbt->num_inputs, sizeof(uint8_t));
    uint64_t input_amount = 0;
    uint8_t signing_flags = 0;
    char wallet_name[NVS_KEY_NAME_MAX_SIZE] = { '\0' };
    multisig_data_t* multisig_data = NULL;
    descriptor_data_t* descriptor = NULL;
    for (size_t index = 0; index < psbt->num_inputs; ++index) {
        struct wally_psbt_input* input = &psbt->inputs[index];

        // Get the utxo being spent
        // FIXME: for btc only accept 'non-witness utxo' ?
        const struct wally_tx_output* utxo = NULL;
        if (wally_psbt_get_input_best_utxo(psbt, index, &utxo) != WALLY_OK || !utxo) {
            *errmsg = "Input utxo missing";
            retval = CBOR_RPC_BAD_PARAMETERS;
            goto cleanup;
        }
        if (!is_elements) {
            // Bitcoin: Collect input total for fee calculation
            input_amount += utxo->satoshi;
        }

        if (!key_iter_input_begin_public(psbt, index, &iter)) {
            // Our key not present: we are not signing this input
            continue;
        }

        // Found our key - we are signing this input
        JADE_LOGD("Key %u belongs to this signer, so we will need to sign input %u", iter.key_index, index);
        uint32_t sig_type;
        JADE_WALLY_VERIFY(wally_psbt_get_input_signature_type(psbt, index, &sig_type));
        JADE_ASSERT(sig_type);
        sig_types[index] = (uint8_t)sig_type; // Sufficient

        const size_t num_keys = key_iter_get_num_keys(&iter);
        if (num_keys > 1) {
            const bool is_green = is_green_multisig_signers(network_id, &iter, NULL);
            signing_flags |= is_green ? PSBT_SIGNING_GREEN_MULTISIG : PSBT_SIGNING_MULTISIG;
        } else {
            signing_flags |= PSBT_SIGNING_SINGLESIG;
        }

        // Only support SIGHASH_ALL, or SIGHASH_DEFAULT for taproot atm.
        // SIGHASH_DEFAULT is 0 so passes this check, the 0 is
        // converted to ALL/DEFAULT by wally when signing
        if (input->sighash && input->sighash != WALLY_SIGHASH_ALL) {
            JADE_LOGW("Unsupported sighash for signing input %u", index);
            *errmsg = "Unsupported sighash";
            retval = CBOR_RPC_BAD_PARAMETERS;
            goto cleanup;
        }

        // Track the types of the input prevout scripts
        if (utxo->script && utxo->script_len) {
            bool is_p2tr = false;
            const script_flavour_t script_flavour = get_script_flavour(utxo->script, utxo->script_len, &is_p2tr);
            update_aggregate_scripts_flavour(script_flavour, &aggregate_inputs_scripts_flavour);
        }

        // If multisig, see if all signing inputs match the same persisted wallet record
        // and if so, cache the record details to use later to verify any multisig change outputs
        if (signing_flags & PSBT_SIGNING_MULTISIG_CHANGE_ABANDONED) {
            // Already abandoned multisig change detection - do nothing
        } else if (signing_flags & (PSBT_SIGNING_SINGLESIG | PSBT_SIGNING_GREEN_MULTISIG)) {
            // Green-multisig or singlesig input - mark multisig change detection as abandoned
            JADE_LOGW("Signing singlesig or Green-multisig input %u - multisig change detection abandoned", index);
            signing_flags |= PSBT_SIGNING_MULTISIG_CHANGE_ABANDONED;
        } else {
            size_t path_len = 0;
            uint32_t path[MAX_PATH_LEN];
            if (!key_iter_get_path(&iter, path, MAX_PATH_LEN, &path_len)) {
                JADE_LOGE("No valid path in input %u, ignoring", index);
                continue;
            }

            // Get the path tail after the last hardened element
            const size_t path_tail_start = path_get_unhardened_tail_index(path, path_len);
            JADE_ASSERT(path_tail_start <= path_len);
            const size_t path_tail_len = path_len - path_tail_start;

            if (signing_flags & PSBT_SIGNING_SINGLE_MULTISIG_RECORD) {
                // Test this input against the record previously found
                JADE_ASSERT(!multisig_data != !descriptor); // must be one or the other

                if (multisig_data
                    && !verify_multisig_script_matches(
                        multisig_data, &path[path_tail_start], path_tail_len, &iter, utxo->script, utxo->script_len)) {
                    // Previously found multisig record does not work for this input.  Abandon multisig
                    // change detection.
                    JADE_LOGW("Previously found multisig record '%s' inappropriate for input %u - change "
                              "detection abandoned",
                        wallet_name, index);
                    signing_flags |= PSBT_SIGNING_MULTISIG_CHANGE_ABANDONED;
                }

                if (descriptor
                    && !verify_descriptor_script_matches(wallet_name, descriptor, network_id, &path[path_tail_start],
                        path_tail_len, &iter, utxo->script, utxo->script_len)) {
                    // Previously found descriptor record does not work for this input.  Abandon multisig
                    // change detection.
                    JADE_LOGW("Previously found descriptor record '%s' inappropriate for input %u - change "
                              "detection abandoned",
                        wallet_name, index);
                    signing_flags |= PSBT_SIGNING_MULTISIG_CHANGE_ABANDONED;
                }
            } else {
                // Search all multisig and descriptor records looking for one that fits this input
                multisig_data = JADE_MALLOC(sizeof(multisig_data_t));
                if (get_suitable_multisig_record(&iter, &path[path_tail_start], path_tail_len, utxo->script,
                        utxo->script_len, wallet_name, sizeof(wallet_name), multisig_data)) {
                    JADE_LOGI("Signing multisig input - registered multisig record found: %s", wallet_name);
                    signing_flags |= PSBT_SIGNING_SINGLE_MULTISIG_RECORD;
                } else {
                    free(multisig_data);
                    multisig_data = NULL;
                }

                // NOTE: descriptors not supported for elements atm
                if (!multisig_data && !is_elements) {
                    descriptor = JADE_MALLOC(sizeof(descriptor_data_t));
                    if (get_suitable_descriptor_record(&iter, &path[path_tail_start], path_tail_len, utxo->script,
                            utxo->script_len, network_id, wallet_name, sizeof(wallet_name), descriptor)) {
                        JADE_LOGI("Signing multisig input - registered descriptor record found: %s", wallet_name);
                        signing_flags |= PSBT_SIGNING_SINGLE_MULTISIG_RECORD;
                    } else {
                        free(descriptor);
                        descriptor = NULL;
                    }
                }

                if (!multisig_data && !descriptor) {
                    // No suitable multisig or descriptor record - mark as abandoned
                    JADE_LOGW(
                        "No multisig or descriptor record found for input %u - change detection abandoned", index);
                    signing_flags |= PSBT_SIGNING_MULTISIG_CHANGE_ABANDONED;
                }
            }
        }
    } // iterate keys

    // Examine outputs for liquid unblinded info and fees, and for change we can automatically validate
    if (!validate_outputs(
            network_id, psbt, signing_flags, wallet_name, multisig_data, descriptor, output_info, errmsg)) {
        // errmsg will be populated
        retval = CBOR_RPC_BAD_PARAMETERS;
        goto cleanup;
    }

    // Explicit fee is only valid for Liquid
    JADE_ASSERT(!explicit_fee || is_elements);

    if (is_elements) {
        // FIXME: some assumptions for now
        const TxType_t txtype = TXTYPE_SEND_PAYMENT;
        const bool is_partial = false;
        const asset_info_t* assets = NULL;
        const size_t num_assets = 0;

        if (txtype == TXTYPE_SWAP) {
#if 0
            // FIXME: Support swaps/partial txs
            // Confirm wallet-summary info (ie. net inputs and outputs)
            if (!show_elements_swap_activity(network_id, is_partial, in_sums, num_in_sums,
                    out_sums, num_out_sums, assets, num_assets)) {
                *errmsg = "User declined to sign psbt";
                retval = CBOR_RPC_USER_CANCELLED;
                goto cleanup;
            }
#else
            *errmsg = "Swap psbt signing is not yet supported";
            retval = CBOR_RPC_BAD_PARAMETERS;
            goto cleanup;
#endif
        } else {
            // Confirm all non-change outputs
            if (!show_elements_transaction_outputs_activity(network_id, tx, output_info, assets, num_assets)) {
                *errmsg = "User declined to sign psbt";
                retval = CBOR_RPC_USER_CANCELLED;
                goto cleanup;
            }
        }
        JADE_LOGD("User accepted outputs");

        // User to agree fee amount
        // Check to see whether user accepted or declined
        if (!show_elements_fee_confirmation_activity(
                network_id, tx, output_info, aggregate_inputs_scripts_flavour, explicit_fee, txtype, is_partial)) {
            *errmsg = "User declined to sign psbt";
            retval = CBOR_RPC_USER_CANCELLED;
            goto cleanup;
        }
        JADE_LOGD("User accepted fee");
    } else {
        // Bitcoin: Sanity check amounts
        uint64_t output_amount;
        JADE_WALLY_VERIFY(wally_tx_get_total_output_satoshi(tx, &output_amount));
        if (output_amount > input_amount) {
            *errmsg = "Invalid input/output amounts";
            retval = CBOR_RPC_BAD_PARAMETERS;
            goto cleanup;
        }

        if (!show_btc_transaction_outputs_activity(network_id, tx, output_info)) {
            *errmsg = "User declined to sign psbt";
            retval = CBOR_RPC_USER_CANCELLED;
            goto cleanup;
        }
        JADE_LOGD("User accepted outputs");

        // User to agree fee amount
        // Check to see whether user accepted or declined
        if (!show_btc_fee_confirmation_activity(
                network_id, tx, output_info, aggregate_inputs_scripts_flavour, input_amount, output_amount)) {
            *errmsg = "User declined to sign psbt";
            retval = CBOR_RPC_USER_CANCELLED;
            goto cleanup;
        }
        JADE_LOGD("User accepted fee");
    }

    // Show warning if nothing to sign
    if (!signing_flags) {
        const char* message[] = { "There are no relevant", "inputs to be signed" };
        await_message_activity(message, 2);
    }

    display_processing_message_activity();

    // Sign our inputs
    JADE_WALLY_VERIFY(wally_psbt_signing_cache_enable(psbt, 0));

    for (size_t index = 0; index < psbt->num_inputs; ++index) {
        // See if we flagged this input for signing
        if (!sig_types[index]) {
            JADE_LOGD("Not required to sign input %u", index);
            continue;
        }

        JADE_LOGD("Signing input %u", index);

        // Get the scriptpubkey or redeemscript, then the actual signing script, then the txhash
        uint8_t script[WALLY_SCRIPTSIG_MAX_LEN]; // Sufficient
        uint8_t scriptcode[WALLY_SCRIPTSIG_MAX_LEN]; // Sufficient
        uint8_t txhash[WALLY_TXHASH_LEN];
        size_t script_len = 0;
        size_t scriptcode_len = 0;
        if (wally_psbt_get_input_signing_script(psbt, index, script, sizeof(script), &script_len) != WALLY_OK
            || script_len > sizeof(script)
            || wally_psbt_get_input_scriptcode(
                   psbt, index, script, script_len, scriptcode, sizeof(scriptcode), &scriptcode_len)
                != WALLY_OK
            || scriptcode_len > sizeof(scriptcode)
            || wally_psbt_get_input_signature_hash(
                   psbt, index, tx, scriptcode, scriptcode_len, 0, txhash, sizeof(txhash))
                != WALLY_OK) {
            JADE_LOGE("Failed to generate tx input hash");
            *errmsg = "Failed to generate tx input hash";
            retval = CBOR_RPC_INTERNAL_ERROR;
            goto cleanup;
        }

        key_iter_input_begin(psbt, index, &iter);
        while (iter.is_valid) {
            // Sign the input with this key
            if (wally_psbt_sign_input_bip32(
                    psbt, index, iter.key_index, txhash, sizeof(txhash), &iter.hdkey, EC_FLAG_GRIND_R)
                != WALLY_OK) {
                *errmsg = "Failed to generate signature";
                retval = CBOR_RPC_INTERNAL_ERROR;
                goto cleanup;
            }
            // Loop in case we need sign again - ie. we are multiple signers in a multisig
            // Continue search from next key index position
            key_iter_next(&iter);
        }
    }

    // No errors - may or may not have added signatures
    JADE_ASSERT(!retval);

cleanup:
    SENSITIVE_POP(&iter);
    if (tx && psbt->version != WALLY_PSBT_VERSION_0) {
        JADE_WALLY_VERIFY(wally_tx_free(tx));
    }
    free(descriptor);
    free(multisig_data);
    free(sig_types);
    free(output_info);
    return retval;
}

typedef struct {
    const uint8_t* bytes;
    size_t bytes_len;
    struct wally_psbt* psbt_out;
} psbt_parse_data_t;

static bool parse_psbt_bytes(void* ctx)
{
    JADE_ASSERT(ctx);
    psbt_parse_data_t* data = (psbt_parse_data_t*)ctx;
    data->psbt_out = NULL;
    const uint32_t flags = WALLY_PSBT_PARSE_FLAG_STRICT;
    const int wret = wally_psbt_from_bytes(data->bytes, data->bytes_len, flags, &data->psbt_out);
    return wret == WALLY_OK && data->psbt_out != NULL;
}

// PSBT bytes -> wally struct
// Returns false on error.
// Otherwise caller takes ownership of wally struct, and must call wally_psbt_free()
bool deserialise_psbt(const uint8_t* bytes, const size_t bytes_len, struct wally_psbt** psbt_out)
{
    JADE_ASSERT(bytes);
    JADE_INIT_OUT_PPTR(psbt_out);

    psbt_parse_data_t data = { .bytes = bytes, .bytes_len = bytes_len, NULL };
    bool ret = false;

    if (bytes_len <= sizeof(PSBT_MAGIC_PREFIX)) {
        ret = false; // PSBT/PSET is too short
    } else if (!memcmp(bytes, PSBT_MAGIC_PREFIX, sizeof(PSBT_MAGIC_PREFIX))) {
        // PSBT - can parse immediately
        ret = parse_psbt_bytes(&data);
    } else if (!memcmp(bytes, PSET_MAGIC_PREFIX, sizeof(PSET_MAGIC_PREFIX))) {
        // PSET - can need large stack to unblind and/or verify proofs - parse on dedicated stack
        const size_t stack_size = 54 * 1024; // 54kb seems sufficient
        ret = run_in_temporary_task(stack_size, parse_psbt_bytes, &data);
    }
    if (ret) {
        *psbt_out = data.psbt_out;
    } else {
        JADE_LOGE("Failed to parse PSBT/PSET");
    }
    return ret;
}

// PSBT wally struct -> bytes
// Returns false on error.
// Otherwise caller takes ownership of bytes, and must call free()
bool serialise_psbt(const struct wally_psbt* psbt, uint8_t** output, size_t* output_len)
{
    JADE_ASSERT(psbt);
    JADE_INIT_OUT_PPTR(output);
    JADE_INIT_OUT_SIZE(output_len);

    // Serialise updated psbt
    size_t psbt_len_out = 0;
    if (wally_psbt_get_length(psbt, 0, &psbt_len_out) != WALLY_OK) {
        return false;
    }

    uint8_t* psbt_bytes_out = JADE_MALLOC_PREFER_SPIRAM(psbt_len_out);
    size_t written = 0;
    if (wally_psbt_to_bytes(psbt, 0, psbt_bytes_out, psbt_len_out, &written) != WALLY_OK || written != psbt_len_out) {
        free(psbt_bytes_out);
        return false;
    }

    // Return allocated buffer
    *output = psbt_bytes_out;
    *output_len = psbt_len_out;
    return true;
}

void sign_psbt_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_psbt");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    struct wally_psbt* psbt = NULL;

    {
        // psbt must be sent as bytes
        const uint8_t* bytes = NULL;
        size_t bytes_len = 0;
        rpc_get_bytes_ptr("psbt", &params, &bytes, &bytes_len);
        if (!bytes || !bytes_len) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract psbt bytes from parameters");
            goto cleanup;
        }

        // Parse to wally structure
        if (!deserialise_psbt(bytes, bytes_len, &psbt)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract psbt from passed bytes");
            goto cleanup;
        }
        jade_process_call_on_exit(process, jade_wally_free_psbt_wrapper, psbt);
    }

    // Sign the psbt - parameter updated with any signatures
    const char* errmsg = NULL;
    const int errcode = sign_psbt(network_id, psbt, &errmsg);
    if (errcode) {
        jade_process_reject_message(process, errcode, errmsg);
        goto cleanup;
    }

    // Serialise signed psbt
    uint8_t* bytes = NULL;
    size_t bytes_len = 0;
    if (!serialise_psbt(psbt, &bytes, &bytes_len)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to serialise sign psbt");
        goto cleanup;
    }
    jade_process_free_on_exit(process, bytes);

    // Send as cbor message - maybe split over N messages if the result is large
    char original_id[MAXLEN_ID + 1];
    size_t original_id_len = 0;
    rpc_get_id(&process->ctx.value, original_id, sizeof(original_id), &original_id_len);

    const int nmsgs = (bytes_len / PSBT_OUT_CHUNK_SIZE) + 1;
    uint8_t* const msgbuf = JADE_MALLOC(MAX_OUTPUT_MSG_SIZE);
    uint8_t* chunk = bytes;
    for (size_t imsg = 0; imsg < nmsgs; ++imsg) {
        JADE_ASSERT(chunk < bytes + bytes_len);
        const size_t remaining = bytes + bytes_len - chunk;
        const size_t chunk_len = remaining < PSBT_OUT_CHUNK_SIZE ? remaining : PSBT_OUT_CHUNK_SIZE;
        const size_t seqnum = imsg + 1;
        jade_process_reply_to_message_bytes_sequence(
            process->ctx, seqnum, nmsgs, chunk, chunk_len, msgbuf, MAX_OUTPUT_MSG_SIZE);
        chunk += chunk_len;

        if (seqnum < nmsgs) {
            // Await a 'get_extended_data' message
            jade_process_load_in_message(process, true);
            if (!IS_CURRENT_MESSAGE(process, "get_extended_data")) {
                // Protocol error
                jade_process_reject_message(
                    process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'get_extended_data'");
                free(msgbuf);
                goto cleanup;
            }

            // Sanity check extended-data payload fields
            GET_MSG_PARAMS(process);
            if (!check_extended_data_fields(&params, original_id, "sign_psbt", seqnum + 1, nmsgs)) {
                // Protocol error
                jade_process_reject_message(
                    process, CBOR_RPC_PROTOCOL_ERROR, "Mismatched fields in 'get_extended_data' message");
                free(msgbuf);
                goto cleanup;
            }
        }
    }
    free(msgbuf);

    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
