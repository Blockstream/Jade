#include "../button_events.h"
#include "../descriptor.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../process.h"
#include "../sensitive.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/event.h"
#include "../utils/malloc_ext.h"
#include "../utils/network.h"
#include "../utils/util.h"
#include "../wallet.h"

#include <sodium/utils.h>

#include <wally_map.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>

#include "process_utils.h"

bool show_btc_transaction_outputs_activity(
    const char* network, const struct wally_tx* tx, const output_info_t* output_info);
bool show_btc_fee_confirmation_activity(const struct wally_tx* tx, const output_info_t* outinfo,
    script_flavour_t aggregate_inputs_scripts_flavour, uint64_t input_amount, uint64_t output_amount);

static void wally_free_psbt_wrapper(void* psbt) { JADE_WALLY_VERIFY(wally_psbt_free((struct wally_psbt*)psbt)); }

// From https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
static const uint8_t PSBT_MAGIC_PREFIX[5] = { 0x70, 0x73, 0x62, 0x74, 0xFF }; // 'psbt' + 0xff

// Cache what type of inputs we are signing
#define PSBT_SIGNING_SINGLESIG 0x1
#define PSBT_SIGNING_MULTISIG 0x2
#define PSBT_SIGNING_GREEN_MULTISIG 0x4

// Also if just one multisig record used for all signing inputs
#define PSBT_SIGNING_SINGLE_MULTISIG_RECORD 0x10
#define PSBT_SIGNING_MULTISIG_CHANGE_ABANDONED 0x20

#define PSBT_OUT_CHUNK_SIZE (MAX_OUTPUT_MSG_SIZE - 64)

struct pubkey_data {
    uint8_t key[EC_PUBLIC_KEY_LEN];
    size_t key_len;
};

// Helper to get next key derived from the signer master key in the passed keypath map.
// NOTE: Both start_index and found_index are zero-based.
// The return indicates whether any key was found - and if so hdkey and index will be populated.
static bool get_our_next_key(
    const struct wally_map* keypaths, const size_t start_index, struct ext_key* hdkey, size_t* index)
{
    JADE_ASSERT(keypaths);
    JADE_ASSERT(hdkey);
    JADE_ASSERT(index);
    JADE_ASSERT(keychain_get());

    struct ext_key* nextkey = NULL;
    JADE_WALLY_VERIFY(
        wally_map_keypath_get_bip32_key_from_alloc(keypaths, start_index, &keychain_get()->xpriv, &nextkey));
    if (!nextkey) {
        // No key of ours here
        return false;
    }

    // Copy and free the allocated key
    memcpy(hdkey, nextkey, sizeof(struct ext_key));
    JADE_WALLY_VERIFY(bip32_key_free(nextkey));

    // Find the pubkey in the map and return the (0-based) index
    JADE_WALLY_VERIFY(wally_map_find_bip32_public_key_from(keypaths, start_index, hdkey, index));
    JADE_ASSERT(index); // 1-based - should def be found!
    --*index; // reduce to 0-based

    return true;
}

static bool is_green_multisig_signers(
    const char* network, const struct wally_map* keypaths, struct pubkey_data* recovery_pubkey)
{
    JADE_ASSERT(network);
    JADE_ASSERT(keypaths);

    // recovery_pubkey is optional
    if (recovery_pubkey) {
        recovery_pubkey->key_len = 0;
    }

    size_t num_keys = 0;
    JADE_WALLY_VERIFY(wally_map_get_num_items(keypaths, &num_keys));

    if (num_keys != 2 && num_keys != 3) {
        // Green multisig is 2of2 or 2of3 only
        return false;
    }

    uint8_t user_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    wallet_get_fingerprint(user_fingerprint, sizeof(user_fingerprint));
    uint32_t user_path[MAX_PATH_LEN];
    size_t user_path_len = 0;

    uint8_t ga_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    if (!wallet_get_gaservice_fingerprint(network, ga_fingerprint, sizeof(ga_fingerprint))) {
        // Can't get ga-signer for network
        return false;
    }
    uint32_t ga_path[MAX_GASERVICE_PATH_LEN];
    size_t ga_path_len = 0;

    uint32_t recovery_path[MAX_PATH_LEN];
    size_t recovery_path_len = 0;

    for (size_t ikey = 0; ikey < num_keys; ++ikey) {
        uint8_t key_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
        JADE_WALLY_VERIFY(
            wally_map_keypath_get_item_fingerprint(keypaths, ikey, key_fingerprint, sizeof(key_fingerprint)));

        if (!memcmp(key_fingerprint, user_fingerprint, sizeof(key_fingerprint))) {
            // Appears to be our signer
            if (user_path_len
                || wally_map_keypath_get_item_path(keypaths, ikey, user_path, MAX_PATH_LEN, &user_path_len)
                    != WALLY_OK) {
                // Seen user signer already or path too long
                return false;
            }
        } else if (!memcmp(key_fingerprint, ga_fingerprint, sizeof(key_fingerprint))) {
            // Appears to be ga-service signer
            if (ga_path_len
                || wally_map_keypath_get_item_path(keypaths, ikey, ga_path, MAX_GASERVICE_PATH_LEN, &ga_path_len)
                    != WALLY_OK) {
                // Seen ga service signer already or path too long
                return false;
            }
        } else {
            // 2of3 recovery key
            if (recovery_path_len
                || wally_map_keypath_get_item_path(keypaths, ikey, recovery_path, MAX_PATH_LEN, &recovery_path_len)
                    != WALLY_OK) {
                // Seen 'third-party' signer already or path too long
                return false;
            }

            // Return the recovery pubkey if the caller so desires
            // NOTE: only compressed pubkeys are expected/supported.
            if (recovery_pubkey) {
                size_t written = 0;
                if (wally_map_get_item_key(keypaths, ikey, recovery_pubkey->key, sizeof(recovery_pubkey->key), &written)
                        != WALLY_OK
                    || written > sizeof(recovery_pubkey->key)) {
                    JADE_LOGE("Error fetching ga-multisig 2of3 recovery key");
                    return false;
                }
                recovery_pubkey->key_len = written;
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

// Generate a green-multisig script and test whether it matches the passed target_script
static bool verify_ga_script_matches_impl(const char* network, const uint32_t* path, const size_t path_len,
    const struct pubkey_data* recovery_key, const size_t csv_blocks, const uint8_t* target_script,
    const size_t target_script_len)
{
    JADE_ASSERT(network);
    JADE_ASSERT(path);
    JADE_ASSERT(recovery_key);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);

    size_t trial_script_len = 0;
    uint8_t trial_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient

    if (!wallet_build_ga_script_ex(network, recovery_key->key, recovery_key->key_len, csv_blocks, path, path_len,
            trial_script, sizeof(trial_script), &trial_script_len)) {
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

// Generate green-multisig scripts for multisig and for any possible csv scripts and test whether any match
static bool verify_ga_script_matches(const char* network, const uint32_t* path, const size_t path_len,
    const struct pubkey_data* recovery_key, const uint8_t* target_script, const size_t target_script_len)
{
    JADE_ASSERT(network);
    JADE_ASSERT(path);
    JADE_ASSERT(recovery_key);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);

    // NOTE: 2of3 csv not supported
    if (!recovery_key || !recovery_key->key_len) {
        // Try each of the allowed csv blocks
        const size_t* allowed_csv_blocks = NULL;
        const size_t num_allowed = csvBlocksForNetwork(network, &allowed_csv_blocks);
        JADE_ASSERT(num_allowed);
        JADE_ASSERT(allowed_csv_blocks);

        for (size_t i = 0; i < num_allowed; ++i) {
            if (verify_ga_script_matches_impl(
                    network, path, path_len, recovery_key, allowed_csv_blocks[i], target_script, target_script_len)) {
                // csv script match
                return true;
            }
        }
    }

    // Check 2of2/2of3 legacy multisig
    const size_t csv_blocks = 0;
    if (verify_ga_script_matches_impl(
            network, path, path_len, recovery_key, csv_blocks, target_script, target_script_len)) {
        // Legacy multisig w/o csv
        return true;
    }

    // No csv values match
    return false;
}

// Helper to generate a singlesig script of the given type with the pubkey given, and
// compare it to the target script provided.
// Returns true if then generated script matches the target script.
static bool verify_singlesig_script_matches(const script_variant_t script_variant, const struct ext_key* hdkey,
    const uint8_t* target_script, const size_t target_script_len)
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
    if (!wallet_build_singlesig_script(script_variant, hdkey->pub_key, sizeof(hdkey->pub_key), trial_script,
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

// Find the last hardened path index, and return the next index
// ie. the start of the non-hardened path tail (if it exists)
static size_t get_multisig_path_tail_start_index(const uint32_t* path, const size_t path_len)
{
    JADE_ASSERT(path);

    // Get the path tail after the last hardened element
    size_t path_tail_start = 0;
    for (size_t i = 0; i < path_len; ++i) {
        if (ishardened(path[i])) {
            path_tail_start = i + 1;
        }
    }
    return path_tail_start;
}

// Use the passed multisig to derive the signers pubkeys, and if they seem good to make the output script
// Return whether that is all good and the generated output script matches the passed target script
static bool verify_multisig_script_matches(const multisig_data_t* multisig_data, const uint32_t* path,
    const size_t path_len, const struct wally_map* keypaths, const uint8_t* target_script,
    const size_t target_script_len)
{
    JADE_ASSERT(multisig_data);
    JADE_ASSERT(path);
    JADE_ASSERT(path_len);
    JADE_ASSERT(keypaths);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);

    // Ensure script length matches
    if (script_length_for_variant(multisig_data->variant) != target_script_len) {
        JADE_LOGD("Mismatch in script size");
        return false;
    }

    // Ensure number of signatories match
    size_t num_keys = 0;
    JADE_WALLY_VERIFY(wally_map_get_num_items(keypaths, &num_keys));
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

        // See if it is present in the keypath map
        size_t written = 0;
        if (wally_map_find(keypaths, hdkey.pub_key, sizeof(hdkey.pub_key), &written) != WALLY_OK || !written) {
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
    const char* network, const uint32_t multi_index, const uint32_t index, const uint8_t* target_script,
    const size_t target_script_len)
{
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(descriptor);
    JADE_ASSERT(network);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);

    // Build descriptor script
    const char* errmsg = NULL;
    size_t trial_script_len = 0;
    uint8_t trial_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient;
    if (!wallet_build_descriptor_script(network, descriptor_name, descriptor, multi_index, index, trial_script,
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
    const char* network, const uint32_t* path, const size_t path_len, const struct wally_map* keypaths,
    const uint8_t* target_script, const size_t target_script_len)
{
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(descriptor);
    JADE_ASSERT(network);
    JADE_ASSERT(path);
    JADE_ASSERT(path_len);
    JADE_ASSERT(keypaths);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);

    // Ensure number of pubkeys is not less than the number of xpub signers
    // (xpubs can be reused with different paths, but they cannot be left unused)
    size_t num_keys = 0;
    JADE_WALLY_VERIFY(wally_map_get_num_items(keypaths, &num_keys));
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
            descriptor_name, descriptor, network, multi_index, index, target_script, target_script_len)) {
        return true;
    }

    multi_index = 0;
    return verify_descriptor_script_matches_impl(
        descriptor_name, descriptor, network, multi_index, index, target_script, target_script_len);
}

// Try to find a multisig registration which creates the passed script with the given
// keypaths map.  Our signer's path tail is passed in, and is assumed to be common across signers.
static bool get_suitable_multisig_record(const struct wally_map* keypaths, const uint32_t* path, const size_t path_len,
    const uint8_t* target_script, const size_t target_script_len, char* wallet_name, const size_t wallet_name_len,
    multisig_data_t* const multisig_data)
{
    JADE_ASSERT(keypaths);
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
        if (!verify_multisig_script_matches(
                multisig_data, path, path_len, keypaths, target_script, target_script_len)) {
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
// keypaths map.  Our signer's path tail is passed in, and is assumed to be common across signers.
static bool get_suitable_descriptor_record(const struct wally_map* keypaths, const uint32_t* path,
    const size_t path_len, const uint8_t* target_script, const size_t target_script_len, const char* network,
    char* wallet_name, const size_t wallet_name_len, descriptor_data_t* const descriptor)
{
    JADE_ASSERT(keypaths);
    JADE_ASSERT(target_script);
    JADE_ASSERT(target_script_len);
    JADE_ASSERT(network);
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
                names[i], descriptor, network, path, path_len, keypaths, target_script, target_script_len)) {
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
static void validate_any_change_outputs(const char* network, struct wally_psbt* psbt, const uint8_t signing_flags,
    const char* wallet_name, const multisig_data_t* multisig_data, const descriptor_data_t* descriptor,
    output_info_t* output_info, struct ext_key* hdkey)
{
    JADE_ASSERT(network);
    JADE_ASSERT(psbt);
    JADE_ASSERT(signing_flags);
    // wallet_name, multisig_data and descriptor optional
    JADE_ASSERT(output_info);
    JADE_ASSERT(hdkey);

    JADE_ASSERT(!multisig_data || !descriptor); // cannot have both

    // Check each output in turn
    for (size_t index = 0; index < psbt->num_outputs; ++index) {
        struct wally_psbt_output* const output = &psbt->outputs[index];
        JADE_LOGD("Considering output %u for change", index);

        // By default, assume not a validated or change output, and so user must verify
        JADE_ASSERT(!(output_info[index].flags & (OUTPUT_FLAG_VALIDATED | OUTPUT_FLAG_CHANGE)));

        // Find the first key belonging to this signer
        const size_t start_index_zero = 0;
        size_t our_key_index = 0;
        if (!get_our_next_key(&output->keypaths, start_index_zero, hdkey, &our_key_index)) {
            // No key in this output belongs to this signer
            JADE_LOGD("No key in input %u, ignoring", index);
            continue;
        }

        // Get the key path, and check the penultimate element
        size_t path_len = 0;
        uint32_t path[MAX_PATH_LEN];
        JADE_WALLY_VERIFY(
            wally_map_keypath_get_item_path(&output->keypaths, our_key_index, path, MAX_PATH_LEN, &path_len));
        const bool is_change = path_len >= 2 && path[path_len - 2] == 1;

        // Get the output scriptpubkey
        uint8_t tx_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient
        size_t tx_script_len = 0;
        if (wally_psbt_get_output_script(psbt, index, tx_script, sizeof(tx_script), &tx_script_len) != WALLY_OK
            || tx_script_len > sizeof(tx_script)) {
            JADE_LOGE("Failed to get output script for output %u", index);
            continue;
        }

        size_t num_keys = 0;
        JADE_WALLY_VERIFY(wally_map_get_num_items(&output->keypaths, &num_keys));
        if (num_keys == 1) {
            JADE_ASSERT(our_key_index == 0); // only key present

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
            if (!verify_singlesig_script_matches(script_variant, hdkey, tx_script, tx_script_len)) {
                JADE_LOGW("Receive script failed validation");
                continue;
            }

            // Change path valid and matches tx output script
            JADE_LOGI("Output %u singlesig %s path/script validated", index, is_change ? "change" : "receive");

            // Set appropriate flags
            output_info[index].flags |= OUTPUT_FLAG_VALIDATED;
            if (is_change) {
                output_info[index].flags |= OUTPUT_FLAG_CHANGE;
            }

            // Check the path is as expected
            if (!wallet_is_expected_singlesig_path(network, script_variant, is_change, path, path_len)) {
                // Not our standard change path - add warning
                char path_str[MAX_PATH_STR_LEN(MAX_PATH_LEN)];
                const bool have_path_str = wallet_bip32_path_as_str(path, path_len, path_str, sizeof(path_str));
                const int ret = snprintf(output_info[index].message, sizeof(output_info[index].message),
                    "Unusual receive path: %s", have_path_str ? path_str : "too long");
                JADE_ASSERT(ret > 0 && ret < sizeof(output_info[index].message));
            }
        } else if (signing_flags == (PSBT_SIGNING_GREEN_MULTISIG | PSBT_SIGNING_MULTISIG_CHANGE_ABANDONED)) {
            // Signed only Green multisig inputs, only consider similar outputs
            JADE_ASSERT(our_key_index < num_keys);

            struct pubkey_data recovery_pubkey = { .key_len = 0 };
            if (!is_green_multisig_signers(network, &output->keypaths, &recovery_pubkey)) {
                JADE_LOGD("Ignoring non-green-multisig output %u as only signing green-multisig inputs", index);
                continue;
            }

            if (!verify_ga_script_matches(network, path, path_len, &recovery_pubkey, tx_script, tx_script_len)) {
                JADE_LOGD("Receive script failed validation for Green multisig");
                continue;
            }

            // Change path valid and matches expected output script
            JADE_LOGI("Output %u green-multisig path/script validated", index);

            // Set appropriate flags - note Green wallet-output is always assumed to be change
            output_info[index].flags |= (OUTPUT_FLAG_VALIDATED | OUTPUT_FLAG_CHANGE);

        } else if (signing_flags == (PSBT_SIGNING_MULTISIG | PSBT_SIGNING_SINGLE_MULTISIG_RECORD)) {
            // Generic multisig or descriptor
            JADE_ASSERT(our_key_index < num_keys);
            JADE_ASSERT(!multisig_data != !descriptor); // one or the other

            // Get the path tail after the last hardened element
            const size_t path_tail_start = get_multisig_path_tail_start_index(path, path_len);
            JADE_ASSERT(path_tail_start <= path_len);
            const size_t path_tail_len = path_len - path_tail_start;

            if (multisig_data
                && !verify_multisig_script_matches(multisig_data, &path[path_tail_start], path_tail_len,
                    &output->keypaths, tx_script, tx_script_len)) {
                JADE_LOGD("Receive script failed validation with multisig %s", wallet_name);
                continue;
            }
            if (descriptor
                && !verify_descriptor_script_matches(wallet_name, descriptor, network, &path[path_tail_start],
                    path_tail_len, &output->keypaths, tx_script, tx_script_len)) {
                JADE_LOGD("Receive script failed validation with descriptor %s", wallet_name);
                continue;
            }

            // Change path valid and matches expected output script
            JADE_LOGI("Output %u multisig %s path/script validated: %s", index, is_change ? "change" : "receive",
                wallet_name);

            // Set appropriate flags
            output_info[index].flags |= OUTPUT_FLAG_VALIDATED;
            if (is_change) {
                output_info[index].flags |= OUTPUT_FLAG_CHANGE;
            }

            // Check path tail looks as expected
            if (!wallet_is_expected_multisig_path(our_key_index, is_change, &path[path_tail_start], path_tail_len)) {
                // Not our standard change path - add warning
                char path_str[MAX_PATH_STR_LEN(MAX_PATH_LEN)];
                const bool have_path_str = wallet_bip32_path_as_str(path, path_len, path_str, sizeof(path_str));
                const int ret = snprintf(output_info[index].message, sizeof(output_info[index].message),
                    "Unusual change path suffix: %s", have_path_str ? path_str : "too long");
                JADE_ASSERT(ret > 0 && ret < sizeof(output_info[index].message));
            }
        } else {
            // Skip if we did not sign *only* multisig inputs for a single multisig record
            JADE_LOGI(
                "Ignoring multisig output %u as not signing only multisig inputs for a single registration", index);
        }
    }
}

// Sign a psbt - the passed wally psbt struct is updated with any signatures.
// Returns 0 if no errors occurred - does not necessarily indicate that signatures were added.
// Returns an rpc/message error code on error, and the error string should be populated.
int sign_psbt(const char* network, struct wally_psbt* psbt, const char** errmsg)
{
    JADE_ASSERT(network);
    JADE_ASSERT(psbt);
    JADE_INIT_OUT_PPTR(errmsg);

    // Elements/PSET not supported
    size_t is_elements = 0;
    if (wally_psbt_is_elements(psbt, &is_elements) != WALLY_OK || is_elements) {
        *errmsg = "Liquid/Elements PSET not supported";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // Txn data must be available
    struct wally_tx* tx = NULL;
    if (wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, &tx) != WALLY_OK || !tx) {
        *errmsg = "Failed to extract valid txn from passed psbt";
        return CBOR_RPC_BAD_PARAMETERS;
    }
    JADE_ASSERT(tx->num_inputs == psbt->num_inputs && tx->num_outputs == psbt->num_outputs);

    // Any private key in use
    struct ext_key hdkey;
    SENSITIVE_PUSH(&hdkey, sizeof(hdkey));
    int retval = 0;

    // We track if the type of the inputs we are signing changes (ie. single-sig vs
    // green/multisig/other) so we can show a warning to the user if so.
    script_flavour_t aggregate_inputs_scripts_flavour = SCRIPT_FLAVOUR_NONE;

    // Output info
    output_info_t* const output_info = JADE_CALLOC(psbt->num_outputs, sizeof(output_info_t));

    // Go through each of the inputs summing amounts
    // Also, if we are signing this input, inspect the script type and any multisig info
    // Record which inputs we are interested in signing
    bool* const signing_inputs = JADE_CALLOC(psbt->num_inputs, sizeof(bool));
    uint64_t input_amount = 0;
    uint8_t signing_flags = 0;
    char wallet_name[NVS_KEY_NAME_MAX_SIZE] = { '\0' };
    multisig_data_t* multisig_data = NULL;
    descriptor_data_t* descriptor = NULL;
    for (size_t index = 0; index < psbt->num_inputs; ++index) {
        struct wally_psbt_input* input = &psbt->inputs[index];

        // Get the utxo being spent
        const struct wally_tx_output* utxo = NULL;
        if (wally_psbt_get_input_best_utxo(psbt, index, &utxo) != WALLY_OK || !utxo) {
            *errmsg = "Input utxo missing";
            retval = CBOR_RPC_BAD_PARAMETERS;
            goto cleanup;
        }
        input_amount += utxo->satoshi;

        // If we are signing this input, look at the script type, sighash, multisigs etc.
        const size_t start_index_zero = 0;
        size_t our_key_index = 0;
        if (get_our_next_key(&input->keypaths, start_index_zero, &hdkey, &our_key_index)) {
            // Found our key - we are signing this input
            JADE_LOGD("Key %u belongs to this signer, so we will need to sign input %u", our_key_index, index);
            signing_inputs[index] = true;

            size_t num_keys = 0;
            JADE_WALLY_VERIFY(wally_map_get_num_items(&input->keypaths, &num_keys));
            if (num_keys > 1) {
                signing_flags |= is_green_multisig_signers(network, &input->keypaths, NULL)
                    ? PSBT_SIGNING_GREEN_MULTISIG
                    : PSBT_SIGNING_MULTISIG;
            } else {
                signing_flags |= PSBT_SIGNING_SINGLESIG;
            }

            // Only support SIGHASH_ALL atm.
            if (input->sighash && input->sighash != WALLY_SIGHASH_ALL) {
                JADE_LOGW("Unsupported sighash for signing input %u", index);
                *errmsg = "Unsupported sighash";
                retval = CBOR_RPC_BAD_PARAMETERS;
                goto cleanup;
            }

            // Track the types of the input prevout scripts
            if (utxo->script && utxo->script_len) {
                const script_flavour_t script_flavour = get_script_flavour(utxo->script, utxo->script_len);
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
                JADE_WALLY_VERIFY(
                    wally_map_keypath_get_item_path(&input->keypaths, our_key_index, path, MAX_PATH_LEN, &path_len));

                // Get the path tail after the last hardened element
                const size_t path_tail_start = get_multisig_path_tail_start_index(path, path_len);
                JADE_ASSERT(path_tail_start <= path_len);
                const size_t path_tail_len = path_len - path_tail_start;

                if (signing_flags & PSBT_SIGNING_SINGLE_MULTISIG_RECORD) {
                    // Test this input against the record previously found
                    JADE_ASSERT(!multisig_data != !descriptor); // must be one or the other

                    if (multisig_data
                        && !verify_multisig_script_matches(multisig_data, &path[path_tail_start], path_tail_len,
                            &input->keypaths, utxo->script, utxo->script_len)) {
                        // Previously found multisig record does not work for this input.  Abandon multisig
                        // change detection.
                        JADE_LOGW("Previously found multisig record '%s' inappropriate for input %u - change "
                                  "detection abandoned",
                            wallet_name, index);
                        signing_flags |= PSBT_SIGNING_MULTISIG_CHANGE_ABANDONED;
                    }

                    if (descriptor
                        && !verify_descriptor_script_matches(wallet_name, descriptor, network, &path[path_tail_start],
                            path_tail_len, &input->keypaths, utxo->script, utxo->script_len)) {
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
                    if (get_suitable_multisig_record(&input->keypaths, &path[path_tail_start], path_tail_len,
                            utxo->script, utxo->script_len, wallet_name, sizeof(wallet_name), multisig_data)) {
                        JADE_LOGI("Signing multisig input - registered multisig record found: %s", wallet_name);
                        signing_flags |= PSBT_SIGNING_SINGLE_MULTISIG_RECORD;
                    } else {
                        free(multisig_data);
                        multisig_data = NULL;
                    }

                    if (!multisig_data) {
                        descriptor = JADE_MALLOC(sizeof(descriptor_data_t));
                        if (get_suitable_descriptor_record(&input->keypaths, &path[path_tail_start], path_tail_len,
                                utxo->script, utxo->script_len, network, wallet_name, sizeof(wallet_name),
                                descriptor)) {
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
        } // is our key
    } // iterate keys

    // Sanity check amounts
    uint64_t output_amount;
    JADE_WALLY_VERIFY(wally_tx_get_total_output_satoshi(tx, &output_amount));
    if (output_amount > input_amount) {
        *errmsg = "Invalid input/output amounts";
        retval = CBOR_RPC_BAD_PARAMETERS;
        goto cleanup;
    }

    // Examine outputs for change we can automatically validate
    if (signing_flags) {
        validate_any_change_outputs(
            network, psbt, signing_flags, wallet_name, multisig_data, descriptor, output_info, &hdkey);
    }

    // User to verify outputs and fee amount
    if (!show_btc_transaction_outputs_activity(network, tx, output_info)) {
        *errmsg = "User declined to sign psbt";
        retval = CBOR_RPC_USER_CANCELLED;
        goto cleanup;
    }

    JADE_LOGD("User accepted outputs");

    // User to agree fee amount
    // Check to see whether user accepted or declined
    if (!show_btc_fee_confirmation_activity(
            tx, output_info, aggregate_inputs_scripts_flavour, input_amount, output_amount)) {
        *errmsg = "User declined to sign psbt";
        retval = CBOR_RPC_USER_CANCELLED;
        goto cleanup;
    }

    JADE_LOGD("User accepted fee");

    // Show warning if nothing to sign
    if (!signing_flags) {
        const char* message[] = { "There are no relevant", "inputs to be signed" };
        await_message_activity(message, 2);
    }

    display_processing_message_activity();

    // Sign our inputs
    for (size_t index = 0; index < psbt->num_inputs; ++index) {
        // See if we flagged this input for signing
        if (!signing_inputs[index]) {
            JADE_LOGD("Not required to sign input %u", index);
            continue;
        }

        JADE_LOGD("Signing input %u", index);
        struct wally_psbt_input* input = &psbt->inputs[index];

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

        size_t key_index = 0; // Counter updated as we search for our key(s)
        while (get_our_next_key(&input->keypaths, key_index, &hdkey, &key_index)) {
            // Sign the input with this key
            if (wally_psbt_sign_input_bip32(psbt, index, key_index, txhash, sizeof(txhash), &hdkey, EC_FLAG_GRIND_R)
                != WALLY_OK) {
                *errmsg = "Failed to generate signature";
                retval = CBOR_RPC_INTERNAL_ERROR;
                goto cleanup;
            }

            // Loop in case we need sign again - ie. we are multiple signers in a multisig
            // Continue search from next key index position
            ++key_index;
        }
    }

    // No errors - may or may not have added signatures
    JADE_ASSERT(!retval);

cleanup:
    SENSITIVE_POP(&hdkey);
    JADE_WALLY_VERIFY(wally_tx_free(tx));
    free(descriptor);
    free(multisig_data);
    free(signing_inputs);
    free(output_info);
    return retval;
}

// PSBT bytes -> wally struct
// Returns false on error.
// Otherwise caller takes ownership of wally struct, and must call wally_psbt_free()
bool deserialise_psbt(const uint8_t* psbt_bytes, const size_t psbt_len, struct wally_psbt** psbt_out)
{
    JADE_ASSERT(psbt_bytes);
    JADE_INIT_OUT_PPTR(psbt_out);

    // Sanity check lead bytes before attempting full parse
    // NOTE: libwally supports PSET (elements) which Jade does not as yet.
    if (psbt_len < sizeof(PSBT_MAGIC_PREFIX) || memcmp(psbt_bytes, PSBT_MAGIC_PREFIX, sizeof(PSBT_MAGIC_PREFIX))) {
        JADE_LOGE("Unexpected leading 'magic' bytes for PSBT");
        return false;
    }

    return wally_psbt_from_bytes(psbt_bytes, psbt_len, WALLY_PSBT_PARSE_FLAG_STRICT, psbt_out) == WALLY_OK && *psbt_out;
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
    char network[MAX_NETWORK_NAME_LEN];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_psbt");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    // Check network is valid and consistent with prior usage
    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);
    if (isLiquidNetwork(network)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "sign_tx call not appropriate for liquid network", NULL);
        goto cleanup;
    }

    // psbt must be sent as bytes
    size_t psbt_len_in = 0;
    const uint8_t* psbt_bytes_in = NULL;
    rpc_get_bytes_ptr("psbt", &params, &psbt_bytes_in, &psbt_len_in);
    if (!psbt_bytes_in || !psbt_len_in) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract psbt bytes from parameters", NULL);
        goto cleanup;
    }

    // Parse to wally structure
    struct wally_psbt* psbt = NULL;
    if (!deserialise_psbt(psbt_bytes_in, psbt_len_in, &psbt)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract psbt from passed bytes", NULL);
        goto cleanup;
    }
    jade_process_call_on_exit(process, wally_free_psbt_wrapper, psbt);

    // Sign the psbt - parameter updated with any signatures
    const char* errmsg = NULL;
    const int errcode = sign_psbt(network, psbt, &errmsg);
    if (errcode) {
        jade_process_reject_message(process, errcode, errmsg, NULL);
        goto cleanup;
    }

    // Serialise updated psbt
    size_t psbt_len_out = 0;
    uint8_t* psbt_bytes_out = NULL;
    if (!serialise_psbt(psbt, &psbt_bytes_out, &psbt_len_out)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to serialise sign psbt", NULL);
        goto cleanup;
    }
    jade_process_free_on_exit(process, psbt_bytes_out);

    // Send as cbor message - maybe split over N messages if the result is large
    char original_id[MAXLEN_ID + 1];
    size_t original_id_len = 0;
    rpc_get_id(&process->ctx.value, original_id, sizeof(original_id), &original_id_len);

    const int nmsgs = (psbt_len_out / PSBT_OUT_CHUNK_SIZE) + 1;
    uint8_t* const msgbuf = JADE_MALLOC(MAX_OUTPUT_MSG_SIZE);
    uint8_t* chunk = psbt_bytes_out;
    for (size_t imsg = 0; imsg < nmsgs; ++imsg) {
        JADE_ASSERT(chunk < psbt_bytes_out + psbt_len_out);
        const size_t remaining = psbt_bytes_out + psbt_len_out - chunk;
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
                    process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'get_extended_data'", NULL);
                free(msgbuf);
                goto cleanup;
            }

            // Sanity check extended-data payload fields
            GET_MSG_PARAMS(process);
            if (!check_extended_data_fields(&params, original_id, "sign_psbt", seqnum + 1, nmsgs)) {
                // Protocol error
                jade_process_reject_message(
                    process, CBOR_RPC_PROTOCOL_ERROR, "Mismatched fields in 'get_extended_data' message", NULL);
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
