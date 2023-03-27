#include "../assets.h"
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
#include "../utils/util.h"
#include "../wallet.h"

#include <sodium/utils.h>
#include <wally_anti_exfil.h>
#include <wally_elements.h>

#include "process_utils.h"

// From sign_tx.c
bool validate_wallet_outputs(jade_process_t* process, const char* network, const struct wally_tx* tx,
    CborValue* wallet_outputs, output_info_t* output_info, const char** errmsg);
void send_ae_signature_replies(jade_process_t* process, signing_data_t* all_signing_data, uint32_t num_inputs);
void send_ec_signature_replies(jade_msg_source_t source, signing_data_t* all_signing_data, uint32_t num_inputs);

static void wally_free_tx_wrapper(void* tx) { JADE_WALLY_VERIFY(wally_tx_free((struct wally_tx*)tx)); }

static bool get_commitment_data(CborValue* item, commitment_t* commitment)
{
    JADE_ASSERT(item);
    JADE_ASSERT(commitment);

    commitment->content = BLINDERS_NONE;

    if (!rpc_get_n_bytes("blinding_key", item, sizeof(commitment->blinding_key), commitment->blinding_key)) {
        return false;
    }

    if (!rpc_get_n_bytes("abf", item, sizeof(commitment->abf), commitment->abf)) {
        return false;
    }

    if (!rpc_get_n_bytes("vbf", item, sizeof(commitment->vbf), commitment->vbf)) {
        return false;
    }

    if (!rpc_get_n_bytes("asset_id", item, sizeof(commitment->asset_id), commitment->asset_id)) {
        return false;
    }

    if (!rpc_get_uint64_t("value", item, &commitment->value)) {
        return false;
    }

    // Actual commitments are optional - but must be both commitments or neither.
    // If both are passed these will be copied into the tx and signed.
    // If not passed, the above blinding factors must match what is already present in the transaction output.
    // If just one commitment is passed it will be ignored.
    if (rpc_has_field_data("asset_generator", item) || rpc_has_field_data("value_commitment", item)) {
        if (!rpc_get_n_bytes(
                "asset_generator", item, sizeof(commitment->asset_generator), commitment->asset_generator)) {
            return false;
        }

        if (!rpc_get_n_bytes(
                "value_commitment", item, sizeof(commitment->value_commitment), commitment->value_commitment)) {
            return false;
        }

        // Set flag to show struct is fully populated/initialised, including commitments to sign.
        commitment->content = BLINDERS_AND_COMMITMENTS;
    } else {
        // Set flag to show struct is partially populated/initialised - no commitment overrides.
        // Passed blinders/unblinded values refer to commitments already present in the transaction outputs.
        commitment->content = BLINDERS_ONLY;
    }

    return true;
}

static void get_commitments_allocate(const char* field, const CborValue* value, commitment_t** data, size_t* written)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_INIT_OUT_PPTR(data);
    JADE_INIT_OUT_SIZE(written);

    CborValue result;
    if (!rpc_get_array(field, value, &result)) {
        return;
    }

    size_t num_array_items = 0;
    CborError cberr = cbor_value_get_array_length(&result, &num_array_items);
    if (cberr != CborNoError || !num_array_items) {
        return;
    }

    CborValue arrayItem;
    cberr = cbor_value_enter_container(&result, &arrayItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&arrayItem)) {
        return;
    }

    commitment_t* const commitments = JADE_CALLOC(num_array_items, sizeof(commitment_t));

    for (size_t i = 0; i < num_array_items; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        commitments[i].content = BLINDERS_NONE;

        if (cbor_value_is_null(&arrayItem)) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        if (!cbor_value_is_map(&arrayItem)) {
            free(commitments);
            return;
        }

        size_t num_map_items = 0;
        if (cbor_value_get_map_length(&arrayItem, &num_map_items) == CborNoError && num_map_items == 0) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        // Populate commitments data
        if (!get_commitment_data(&arrayItem, &commitments[i])) {
            free(commitments);
            return;
        }

        CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr != CborNoError) {
        free(commitments);
        return;
    }

    *written = num_array_items;
    *data = commitments;
}

static bool verify_commitment_consistent(const commitment_t* commitments, const char** errmsg)
{
    JADE_ASSERT(commitments);
    JADE_INIT_OUT_PPTR(errmsg);

    if (commitments->content != BLINDERS_AND_COMMITMENTS) {
        *errmsg = "Failed to extract final commitment values from commitments data";
        return false;
    }

    // 1. Check the blinded asset commitment can be reconstructed
    // (ie. from the given reversed asset_id and abf)
    uint8_t reversed_asset_id[sizeof(commitments->asset_id)];
    reverse(reversed_asset_id, commitments->asset_id, sizeof(commitments->asset_id));

    uint8_t generator_tmp[sizeof(commitments->asset_generator)];
    if (wally_asset_generator_from_bytes(reversed_asset_id, sizeof(reversed_asset_id), commitments->abf,
            sizeof(commitments->abf), generator_tmp, sizeof(generator_tmp))
            != WALLY_OK
        || sodium_memcmp(commitments->asset_generator, generator_tmp, sizeof(generator_tmp)) != 0) {
        *errmsg = "Failed to verify blinded asset generator from commitments data";
        return false;
    }

    // 2. Check the blinded value commitment can be reconstructed
    // (ie. from value, vbf, and asset generator)
    uint8_t commitment_tmp[sizeof(commitments->value_commitment)];
    if (wally_asset_value_commitment(commitments->value, commitments->vbf, sizeof(commitments->vbf), generator_tmp,
            sizeof(generator_tmp), commitment_tmp, sizeof(commitment_tmp))
            != WALLY_OK
        || sodium_memcmp(commitments->value_commitment, commitment_tmp, sizeof(commitment_tmp)) != 0) {
        *errmsg = "Failed to verify blinded value commitment from commitments data";
        return false;
    }

    return true;
}

static bool add_output_info(
    commitment_t* commitments, const struct wally_tx_output* txoutput, output_info_t* outinfo, const char** errmsg)
{
    JADE_ASSERT(commitments);
    JADE_ASSERT(txoutput);
    JADE_ASSERT(outinfo);
    JADE_INIT_OUT_PPTR(errmsg);

    if (commitments->content != BLINDERS_ONLY && commitments->content != BLINDERS_AND_COMMITMENTS) {
        // No blinding info, should be unblinded output, remaining unblinded/unconfidential/explicit
        if (txoutput->asset_len != sizeof(outinfo->asset_id) + 1
            || txoutput->asset[0] != WALLY_TX_ASSET_CT_EXPLICIT_PREFIX
            || txoutput->value[0] != WALLY_TX_ASSET_CT_EXPLICIT_PREFIX) {
            *errmsg = "Missing commitments data for blinded output";
            return false;
        }

        // unconfidential, take directly from the tx
        outinfo->flags &= ~OUTPUT_FLAG_CONFIDENTIAL;

        // Copy the asset ID without the leading unconfidential tag byte
        // NOTE: we reverse the asset-id bytes to the 'display' order
        reverse(outinfo->asset_id, txoutput->asset + 1, sizeof(outinfo->asset_id));

        JADE_WALLY_VERIFY(
            wally_tx_confidential_value_to_satoshi(txoutput->value, txoutput->value_len, &outinfo->value));
    } else {
        // Output to be confidential/blinded, use the commitments data
        outinfo->flags |= OUTPUT_FLAG_CONFIDENTIAL;

        // 1. Sanity checks
        if (txoutput->asset_len != sizeof(commitments->asset_generator)) {
            *errmsg = "Invalid asset generator in tx output";
            return false;
        }
        if (txoutput->value_len != sizeof(commitments->value_commitment)) {
            *errmsg = "Invalid value commitment in tx output";
            return false;
        }

        // 2. If passed explicit commitments copy them into the transaction output ready for signing
        // If not, copy the values from the tx into the commitment structure.
        // ie. so in any case commitment struct is complete, and reflects what is in the tx output
        if (commitments->content == BLINDERS_AND_COMMITMENTS) {
            memcpy(txoutput->asset, commitments->asset_generator, sizeof(commitments->asset_generator));
            memcpy(txoutput->value, commitments->value_commitment, sizeof(commitments->value_commitment));
        } else {
            memcpy(commitments->asset_generator, txoutput->asset, sizeof(commitments->asset_generator));
            memcpy(commitments->value_commitment, txoutput->value, sizeof(commitments->value_commitment));
            commitments->content = BLINDERS_AND_COMMITMENTS;
        }

        // 3. Check the asset generator and value commitment can be reconstructed
        if (!verify_commitment_consistent(commitments, errmsg)) {
            // errmsg populated by call if failure
            return false;
        }

        // 4. Fetch the asset_id, value, and blinding_key into the info struct
        JADE_ASSERT(sizeof(outinfo->blinding_key) == sizeof(commitments->blinding_key));
        JADE_ASSERT(sizeof(outinfo->asset_id) == sizeof(commitments->asset_id));
        memcpy(outinfo->blinding_key, commitments->blinding_key, sizeof(commitments->blinding_key));
        memcpy(outinfo->asset_id, commitments->asset_id, sizeof(commitments->asset_id));
        outinfo->value = commitments->value;
    }

    return true;
}

/*
 * The message flow here is complicated because we cater for both a legacy flow
 * for standard deterministic EC signatures (see rfc6979) and a newer message
 * exchange added later to cater for anti-exfil signatures.
 * At the moment we retain the older message flow for backward compatibility,
 * but at some point we should remove it and use the new message flow for all
 * cases, which would simplify the code here and in the client.
 */
void sign_liquid_tx_process(void* process_ptr)
{
    JADE_LOGI("Starting: %lu", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;
    char network[MAX_NETWORK_NAME_LEN];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_liquid_tx");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    const jade_msg_source_t source = process->ctx.source;

    // Check network is valid and consistent with prior usage
    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);
    if (!isLiquidNetwork(network)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "sign_liquid_tx call only appropriate for liquid network", NULL);
        goto cleanup;
    }

    written = 0;
    const uint8_t* txbytes = NULL;
    rpc_get_bytes_ptr("txn", &params, &txbytes, &written);

    if (written == 0) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract txn from parameters", NULL);
        goto cleanup;
    }
    JADE_ASSERT(txbytes);

    struct wally_tx* tx = NULL;
    const int res = wally_tx_from_bytes(txbytes, written, WALLY_TX_FLAG_USE_ELEMENTS, &tx); // elements, without witness
    if (res != WALLY_OK || !tx) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract tx from passed bytes", NULL);
        goto cleanup;
    }
    jade_process_call_on_exit(process, wally_free_tx_wrapper, tx);

    // copy the amount
    size_t num_inputs = 0;
    bool ret = rpc_get_sizet("num_inputs", &params, &num_inputs);
    if (!ret || num_inputs == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid number of inputs from parameters", NULL);
        goto cleanup;
    }

    // Check the number of inputs the client wants to send is what we
    // would expect for the given transaction.  Fail if not.
    if (num_inputs != tx->num_inputs) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Unexpected number of inputs for transaction", NULL);
        goto cleanup;
    }

    // Copy trusted commitment data into a temporary structure (so we can free the message)
    commitment_t* commitments = NULL;
    size_t num_commitments = 0;
    get_commitments_allocate("trusted_commitments", &params, &commitments, &num_commitments);

    if (num_commitments == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract trusted commitments from parameters", NULL);
        goto cleanup;
    }

    JADE_ASSERT(commitments);
    jade_process_free_on_exit(process, commitments);

    // Check the trusted commitments: expect one element in the array for each output.
    // (Can be null/zero's for unblinded outputs.)
    if (num_commitments != tx->num_outputs) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Unexpected number of trusted commitments for transaction", NULL);
        goto cleanup;
    }

    // We always need this extra data to 'unblind' confidential txns
    output_info_t* output_info = JADE_CALLOC(tx->num_outputs, sizeof(output_info_t));
    jade_process_free_on_exit(process, output_info);

    // Whether to use Anti-Exfil signatures and message flow
    // Optional flag, defaults to false
    bool use_ae_signatures = false;
    rpc_get_boolean("use_ae_signatures", &params, &use_ae_signatures);

    // Can optionally be passed info for wallet outputs, which we verify internally
    // NOTE: Element named 'change' for backward-compatibility reasons
    const char* errmsg = NULL;
    CborValue wallet_outputs;
    if (rpc_get_array("change", &params, &wallet_outputs)) {
        if (!validate_wallet_outputs(process, network, tx, &wallet_outputs, output_info, &errmsg)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
            goto cleanup;
        }
    }

    // Can optionally be passed asset info data (registry json)
    // NOTE: these asset-info structs point at fields in the current message
    // IE. THIS DATA IS NOT VALID AFTER THE INITIAL MESSAGE HAS BEEN PROCESSED
    asset_info_t* assets = NULL;
    size_t num_assets = 0;
    if (!assets_get_allocate("asset_info", &params, &assets, &num_assets)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid asset info passed", NULL);
        goto cleanup;
    }
    jade_process_free_on_exit(process, assets);
    JADE_LOGI("Read %d assets from message", num_assets);

    // save fees for the final confirmation screen
    uint64_t fees = 0;

    // Check the trusted commitments: expect one element in the array for each output.
    // Can be null for unblinded outputs as we will skip them.
    // Populate an `output_index` -> (blinding_key, asset, value) map
    uint8_t policy_asset[ASSET_TAG_LEN];
    const char* policy_asset_hex = networkGetPolicyAsset(network);
    JADE_WALLY_VERIFY(wally_hex_to_bytes(policy_asset_hex, policy_asset, sizeof(policy_asset), &written));
    JADE_ASSERT(written == sizeof(policy_asset));

    for (size_t i = 0; i < tx->num_outputs; ++i) {
        if ((tx->outputs[i].asset[0] == WALLY_TX_ASSET_CT_EXPLICIT_PREFIX)
            != (tx->outputs[i].value[0] == WALLY_TX_ASSET_CT_EXPLICIT_PREFIX)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Output asset and value blinding inconsistent", NULL);
            goto cleanup;
        }

        // Gather the (unblinded) output info for user confirmation
        const char* errmsg = NULL;
        if (!add_output_info(&commitments[i], &tx->outputs[i], &output_info[i], &errmsg)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
            goto cleanup;
        }

        // Collect fees (ie. outputs with no script)
        // NOTE: fees must be unconfidential, and must be denominated in the policy asset
        if (!tx->outputs[i].script) {
            if (output_info[i].flags & OUTPUT_FLAG_CONFIDENTIAL) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Fee output (without script) cannot be blinded", NULL);
                goto cleanup;
            }
            if (memcmp(output_info[i].asset_id, policy_asset, sizeof(policy_asset))) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Unexpected fee output (without script) asset-id", NULL);
                goto cleanup;
            }
            fees += output_info[i].value;
        }
    }

    gui_activity_t* first_activity = NULL;
    make_display_elements_output_activity(network, tx, output_info, assets, num_assets, &first_activity);
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
        JADE_LOGW("User declined to sign transaction");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign transaction", NULL);
        goto cleanup;
    }

    JADE_LOGD("User accepted outputs");
    display_message_activity("Processing...");

    // Send ok - client should send inputs
    jade_process_reply_to_message_ok(process);

    // We generate the hashes for each input but defer signing them
    // until after the final user confirmation.  Hold them in an block for
    // ease of cleanup if something goes wrong part-way through.
    signing_data_t* const all_signing_data = JADE_CALLOC(num_inputs, sizeof(signing_data_t));
    jade_process_free_on_exit(process, all_signing_data);

    // We track if the type of the inputs we are signing changes (ie. single-sig vs
    // green/multisig/other) so we can show a warning to the user if so.
    script_flavour_t aggregate_inputs_scripts_flavour = SCRIPT_FLAVOUR_NONE;

    // Run through each input message and generate a signature for each one
    for (size_t index = 0; index < num_inputs; ++index) {
        jade_process_load_in_message(process, true);
        if (!IS_CURRENT_MESSAGE(process, "tx_input")) {
            // Protocol error
            jade_process_reject_message(
                process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'tx_input'", NULL);
            goto cleanup;
        }

        // txn input as expected - get input parameters
        GET_MSG_PARAMS(process);

        size_t script_len = 0;
        const uint8_t* script = NULL;

        // The ae commitments for this input (if using anti-exfil signatures)
        size_t ae_host_commitment_len = 0;
        const uint8_t* ae_host_commitment = NULL;
        uint8_t ae_signer_commitment[WALLY_S2C_OPENING_LEN];

        // Make and store the reply data, and then delete the (potentially
        // large) input message.  Replies will be sent after user confirmation.
        written = 0;
        signing_data_t* const sig_data = all_signing_data + index;
        rpc_get_id(&process->ctx.value, sig_data->id, sizeof(sig_data->id), &written);
        JADE_ASSERT(written != 0);

        bool is_witness = false;
        ret = rpc_get_boolean("is_witness", &params, &is_witness);
        if (!ret) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract is_witness from parameters", NULL);
            goto cleanup;
        }

        // Path node can be omitted if we don't want to sign this input
        // (But if passed must be valid - empty/root path is not allowed for signing)
        const bool has_path = rpc_has_field_data("path", &params);
        if (has_path) {
            const size_t max_path_len = sizeof(sig_data->path) / sizeof(sig_data->path[0]);
            if (!rpc_get_bip32_path("path", &params, sig_data->path, max_path_len, &sig_data->path_len)
                || sig_data->path_len == 0) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid path from parameters", NULL);
                goto cleanup;
            }

            // If required, read anti-exfil host commitment data
            if (use_ae_signatures) {
                rpc_get_bytes_ptr("ae_host_commitment", &params, &ae_host_commitment, &ae_host_commitment_len);
                if (!ae_host_commitment || ae_host_commitment_len != WALLY_HOST_COMMITMENT_LEN) {
                    jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS,
                        "Failed to extract valid host commitment from parameters", NULL);
                    goto cleanup;
                }
            }

            // Get prevout script - required for signing inputs
            rpc_get_bytes_ptr("script", &params, &script, &script_len);
            if (!script || script_len == 0) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract script from parameters", NULL);
                goto cleanup;
            }

            // Track the types of the input prevout scripts
            const script_flavour_t script_flavour = get_script_flavour(script, script_len);
            update_aggregate_scripts_flavour(script_flavour, &aggregate_inputs_scripts_flavour);
        }

        size_t value_len = 0;
        const uint8_t* value_commitment = NULL;
        if (has_path && is_witness) {
            JADE_LOGD("For segwit input using explicitly passed value_commitment");

            rpc_get_bytes_ptr("value_commitment", &params, &value_commitment, &value_len);
            if (value_len != ASSET_COMMITMENT_LEN && value_len != WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract value commitment from parameters", NULL);
                goto cleanup;
            }
        }

        // Make signature if given a path (should have a script in hand)
        if (has_path) {
            JADE_ASSERT(script);
            JADE_ASSERT(script_len > 0);
            JADE_ASSERT(sig_data->path_len > 0);

            // Generate hash of this input which we will sign later
            if (!wallet_get_elements_tx_input_hash(tx, index, is_witness, script, script_len,
                    value_len == 0 ? NULL : value_commitment, value_len, sig_data->signature_hash,
                    sizeof(sig_data->signature_hash))) {
                jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to make tx input hash", NULL);
                goto cleanup;
            }

            // If using anti-exfil signatures, compute signer commitment for returning to caller
            if (use_ae_signatures) {
                JADE_ASSERT(ae_host_commitment);
                JADE_ASSERT(ae_host_commitment_len == WALLY_HOST_COMMITMENT_LEN);
                if (!wallet_get_signer_commitment(sig_data->signature_hash, sizeof(sig_data->signature_hash),
                        sig_data->path, sig_data->path_len, ae_host_commitment, ae_host_commitment_len,
                        ae_signer_commitment, sizeof(ae_signer_commitment))) {
                    jade_process_reject_message(
                        process, CBOR_RPC_INTERNAL_ERROR, "Failed to make ae signer commitment", NULL);
                    goto cleanup;
                }
            }
        } else {
            // Empty byte-string reply (no path given implies no sig needed or expected)
            JADE_ASSERT(!script);
            JADE_ASSERT(script_len == 0);
            JADE_ASSERT(sig_data->path_len == 0);
        }

        // If using ae-signatures, reply with the signer commitment
        // FIXME: change message flow to reply here even when not using ae-signatures
        // as this simplifies the code both here and in the client.
        if (use_ae_signatures) {
            uint8_t buffer[256];
            jade_process_reply_to_message_bytes(process->ctx, ae_signer_commitment,
                has_path ? sizeof(ae_signer_commitment) : 0, buffer, sizeof(buffer));
        }
    }

    gui_activity_t* final_activity = NULL;
    const char* const warning_msg
        = aggregate_inputs_scripts_flavour == SCRIPT_FLAVOUR_MIXED ? WARN_MSG_MIXED_INPUTS : NULL;
    make_display_elements_final_confirmation_activity(network, fees, warning_msg, &final_activity);
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

    // If user cancels we'll send the 'cancelled' error response for the last input message only
    if (!fee_ret || ev_id != BTN_ACCEPT_SIGNATURE) {
        // If using ae-signatures, we need to load the message to send the error back on
        if (use_ae_signatures) {
            jade_process_load_in_message(process, true);
        }
        JADE_LOGW("User declined to sign transaction");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign transaction", NULL);
        goto cleanup;
    }

    JADE_LOGD("User accepted fee");
    display_message_activity("Processing...");

    // Send signature replies.
    // NOTE: currently we have two message flows - the backward compatible version
    // for normal EC signatures, and the new flow required for Anti-Exfil signatures.
    // Once we have migrated the companion applications onto AE signatures we should
    // convert normal EC signatures to use the new/improved message flow.
    if (use_ae_signatures) {
        // Generate and send Anti-Exfil signature replies
        send_ae_signature_replies(process, all_signing_data, num_inputs);
    } else {
        // Generate and send standard EC signature replies
        send_ec_signature_replies(source, all_signing_data, num_inputs);
    }
    JADE_LOGI("Success");

cleanup:
    return;
}
