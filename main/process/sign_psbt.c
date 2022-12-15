#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/event.h"
#include "../utils/malloc_ext.h"
#include "../utils/network.h"
#include "../wallet.h"

#include <sodium/utils.h>

#include <wally_map.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>

#include "process_utils.h"

static void wally_free_psbt_wrapper(void* psbt) { JADE_WALLY_VERIFY(wally_psbt_free((struct wally_psbt*)psbt)); }

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

// Sign a psbt - the passed wally psbt struct is updated with any signatures.
// Returns 0 if no errors occurred - does not necessarily indicate that signatures were added.
// Returns an rpc/message error code on error, and the error string should be populated.
// NOTE: this function needs further refactoring:
// a) to handle multisig change, and
// b) to incorporate upcoming wally PSBT interface changes
int sign_psbt(struct wally_psbt* psbt, const char** errmsg)
{
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
    output_info_t* output_info = JADE_CALLOC(psbt->num_outputs, sizeof(output_info_t));

    // Go through each of the inputs summing amounts
    // Also, if we are signing this input, inspect the script type
    // Record which inputs we are interested in signing
    bool* const signing_inputs = JADE_CALLOC(psbt->num_inputs, sizeof(bool));
    uint64_t input_amount = 0;
    for (size_t index = 0; index < psbt->num_inputs; ++index) {
        struct wally_psbt_input* input = &psbt->inputs[index];

        // Get the utxo being spent
        struct wally_tx_output* utxo = NULL;
        JADE_WALLY_VERIFY(wally_psbt_get_input_best_utxo_alloc(psbt, index, &utxo));
        if (!utxo) {
            *errmsg = "Input utxo missing";
            retval = CBOR_RPC_BAD_PARAMETERS;
            goto cleanup;
        }
        input_amount += utxo->satoshi;

        // If we are signing this input, look at the script type, sighash, etc.
        const size_t start_index_zero = 0;
        size_t our_key_index = 0;
        if (get_our_next_key(&input->keypaths, start_index_zero, &hdkey, &our_key_index)) {
            // Found our key - we are signing this input
            JADE_LOGD("Key %u belongs to this signer, so we will need to sign input %u", our_key_index, index);
            signing_inputs[index] = true;

            // Only support SIGHASH_ALL atm.
            if (input->sighash && input->sighash != WALLY_SIGHASH_ALL) {
                JADE_LOGW("Unsupported sighash for signing input %u", index);
                *errmsg = "Unsupported sighash";
                retval = CBOR_RPC_BAD_PARAMETERS;
                JADE_WALLY_VERIFY(wally_tx_output_free(utxo));
                goto cleanup;
            }

            // Track the types of the input prevout scripts
            if (utxo->script && utxo->script_len) {
                const script_flavour_t script_flavour = get_script_flavour(utxo->script, utxo->script_len);
                update_aggregate_scripts_flavour(script_flavour, &aggregate_inputs_scripts_flavour);
            }
        }
        JADE_WALLY_VERIFY(wally_tx_output_free(utxo));
    }

    // Sanity check amounts
    uint64_t output_amount;
    JADE_WALLY_VERIFY(wally_tx_get_total_output_satoshi(tx, &output_amount));
    if (output_amount > input_amount) {
        *errmsg = "Invalid input/output amounts";
        retval = CBOR_RPC_BAD_PARAMETERS;
        goto cleanup;
    }

    // Examine outputs for change we can automatically validate
    // We only handle singlesig change atm, so skip if signing only multisig inputs
    if (aggregate_inputs_scripts_flavour != SCRIPT_FLAVOUR_MULTISIG) {
        for (size_t index = 0; index < psbt->num_outputs; ++index) {
            struct wally_psbt_output* const output = &psbt->outputs[index];
            JADE_LOGD("Considering output %u for change", index);

            // Ignore multisig outputs for initial release
            size_t num_keys = 0;
            JADE_WALLY_VERIFY(wally_map_get_num_items(&output->keypaths, &num_keys));
            if (num_keys != 1) {
                continue;
            }

            size_t script_type;
            script_variant_t script_variant;
            uint8_t tx_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient
            size_t tx_script_len = 0;
            if (wally_psbt_get_output_script(psbt, index, tx_script, sizeof(tx_script), &tx_script_len) != WALLY_OK
                || tx_script_len > sizeof(tx_script)) {
                JADE_LOGE("Failed to get output script for output %u", index);
                continue;
            }
            if (wally_scriptpubkey_get_type(tx_script, tx_script_len, &script_type) != WALLY_OK
                || !get_singlesig_variant_from_script_type(script_type, &script_variant)) {
                continue;
            }

            // See if this is our key
            const size_t start_index_zero = 0;
            size_t our_key_index = 0;
            if (!get_our_next_key(&output->keypaths, start_index_zero, &hdkey, &our_key_index)) {
                // No key in this output belongs to this signer
                JADE_LOGD("No key in input %u, ignoring", index);
                continue;
            }
            JADE_ASSERT(our_key_index == 0); // should only be one key present

            // Get the key path, and check the penultimate element
            size_t path_len = 0;
            uint32_t path[MAX_PATH_LEN];
            JADE_WALLY_VERIFY(
                wally_map_keypath_get_item_path(&output->keypaths, our_key_index, path, MAX_PATH_LEN, &path_len));

            // Check the path
            const bool is_change = true;
            bool change_path_as_expected = false;
            if (keychain_get_network_type_restriction() != NETWORK_TYPE_TEST) {
                change_path_as_expected
                    |= wallet_is_expected_singlesig_path(TAG_MAINNET, script_variant, is_change, path, path_len);
            }
            if (!change_path_as_expected && keychain_get_network_type_restriction() != NETWORK_TYPE_MAIN) {
                change_path_as_expected
                    |= wallet_is_expected_singlesig_path(TAG_TESTNET, script_variant, is_change, path, path_len);
            }
            if (!change_path_as_expected) {
                // Not our standard change path - add warning
                char path_str[96];
                const bool have_path_str = bip32_path_as_str(path, path_len, path_str, sizeof(path_str));
                const int ret = snprintf(output_info[index].message, sizeof(output_info[index].message),
                    "Unusual change path: %s", have_path_str ? path_str : "too long");
                JADE_ASSERT(ret > 0 && ret < sizeof(output_info[index].message));
                continue;
            }

            // Build our script
            uint8_t trial_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient
            size_t trial_script_len = 0;
            if (!wallet_build_singlesig_script(script_variant, hdkey.pub_key, sizeof(hdkey.pub_key), trial_script,
                    sizeof(trial_script), &trial_script_len)) {
                // Failed to build script
                JADE_LOGE("Receive script cannot be constructed");
                *errmsg = "Change script cannot be constructed";
                retval = CBOR_RPC_BAD_PARAMETERS;
                goto cleanup;
            }

            // Compare generated script to that expected/in the txn
            if (trial_script_len != tx_script_len || sodium_memcmp(tx_script, trial_script, trial_script_len) != 0) {
                JADE_LOGE("Receive script failed validation");
                *errmsg = "Change script cannot be validated";
                retval = CBOR_RPC_BAD_PARAMETERS;
                goto cleanup;
            }

            // Change path valid and matches tx output script
            JADE_LOGI("Output %u change path/script validated", index);
            output_info[index].is_validated_change_address = true;
        }
    }

    // User to verify outputs and fee amount
    gui_activity_t* first_activity = NULL;
    make_display_output_activity(TAG_MAINNET, tx, output_info, &first_activity);
    JADE_ASSERT(first_activity);
    gui_set_current_activity(first_activity);

    // ----------------------------------
    // wait for the last "next" (proceed with the protocol and then final confirmation)
    int32_t ev_id;
    // In a debug unattended ci build, assume buttons pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const esp_err_t outputs_ret = sync_await_single_event(JADE_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    sync_await_single_event(
        JADE_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const esp_err_t outputs_ret = ESP_OK;
    ev_id = SIGN_TX_ACCEPT_OUTPUTS;
#endif

    // Check to see whether user accepted or declined
    if (outputs_ret != ESP_OK || ev_id != SIGN_TX_ACCEPT_OUTPUTS) {
        *errmsg = "User declined to sign psbt";
        retval = CBOR_RPC_USER_CANCELLED;
        goto cleanup;
    }

    JADE_LOGD("User accepted outputs");

    // User to agree fee amount
    gui_activity_t* final_activity = NULL;
    const uint64_t fees = input_amount - output_amount;
    const char* const warning_msg
        = aggregate_inputs_scripts_flavour == SCRIPT_FLAVOUR_MIXED ? WARN_MSG_MIXED_INPUTS : NULL;
    make_display_final_confirmation_activity(fees, warning_msg, &final_activity);
    JADE_ASSERT(final_activity);
    gui_set_current_activity(final_activity);

    // ----------------------------------
    // Wait for the confirmation btn
    // In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const bool fee_ret
        = gui_activity_wait_event(final_activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    gui_activity_wait_event(final_activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
        CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const bool fee_ret = true;
    ev_id = BTN_ACCEPT_SIGNATURE;
#endif

    // Check to see whether user accepted or declined
    if (!fee_ret || ev_id != BTN_ACCEPT_SIGNATURE) {
        *errmsg = "User declined to sign psbt";
        retval = CBOR_RPC_USER_CANCELLED;
        goto cleanup;
    }

    JADE_LOGD("User accepted fee");
    display_message_activity("Processing...");

    // Sign our inputs
    for (size_t index = 0; index < psbt->num_inputs; ++index) {
        // See if we flagged this input for signing
        if (!signing_inputs[index]) {
            JADE_LOGD("Not required to sign input %u", index);
            continue;
        }

        JADE_LOGD("Signing input %u", index);
        struct wally_psbt_input* input = &psbt->inputs[index];
        size_t key_index = 0; // Counter updated as we search for our key(s)
        while (get_our_next_key(&input->keypaths, key_index, &hdkey, &key_index)) {
            // Try to sign the psbt for this key
            // NOTE: this will again search through all the signers on all the inputs looking for where
            // this key is needed, so not ideal by any stretch, but will do for an initial implementation.
            if (wally_psbt_sign(psbt, hdkey.priv_key + 1, sizeof(hdkey.priv_key) - 1, EC_FLAG_GRIND_R) != WALLY_OK) {
                *errmsg = "Failed to sign psbt";
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
    return wally_psbt_from_bytes(psbt_bytes, psbt_len, 0, psbt_out) == WALLY_OK && *psbt_out;
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
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_psbt");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    // psbt must be sent as bytes
    size_t psbt_len_in = 0;
    const uint8_t* psbt_bytes_in = NULL;
    rpc_get_bytes_ptr("psbt", &params, &psbt_bytes_in, &psbt_len_in);
    if (!psbt_bytes_in || !psbt_len_in) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract psbt bytes from parameters", NULL);
        goto cleanup;
    }

    // At the moment there is maximum size we can send as output - if the input psbt is larger
    // than that before we potentially add signatures, we may as well reject it now.
    if (psbt_len_in > MAX_STANDARD_OUTPUT_MSG_SIZE) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Signed psbt will be too large to transmit", NULL);
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
    const int errcode = sign_psbt(psbt, &errmsg);
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

    // At the moment there is maximum size we can send as output
    const size_t buflen = psbt_len_out + 32; // sufficent for cbor overhead
    if (buflen > MAX_STANDARD_OUTPUT_MSG_SIZE) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Signed psbt too large to transmit", NULL);
        goto cleanup;
    }

    // Send as cbor message
    uint8_t* buf = JADE_MALLOC_PREFER_SPIRAM(buflen);
    jade_process_reply_to_message_bytes(process->ctx, psbt_bytes_out, psbt_len_out, buf, buflen);
    free(psbt_bytes_out);
    free(buf);

    JADE_LOGI("Success");

cleanup:
    return;
}
