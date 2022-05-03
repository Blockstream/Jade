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
#include <wally_elements.h>

#include "process_utils.h"

// From sign_tx.c
script_flavour_t get_script_flavour(const uint8_t* script, size_t script_len);
void update_aggregate_scripts_flavour(script_flavour_t new_script_flavour, script_flavour_t* aggregate_scripts_flavour);
bool validate_change_paths(jade_process_t* process, const char* network, const struct wally_tx* tx, CborValue* change,
    output_info_t* output_info, const char** errmsg);
void send_ae_signature_replies(jade_process_t* process, signing_data_t* all_signing_data, uint32_t num_inputs);
void send_ec_signature_replies(jade_msg_source_t source, signing_data_t* all_signing_data, uint32_t num_inputs);

static void wally_free_tx_wrapper(void* tx) { JADE_WALLY_VERIFY(wally_tx_free((struct wally_tx*)tx)); }

static inline void reverse(uint8_t* buf, size_t len)
{
    // flip the order of the bytes in-place
    for (uint8_t *c1 = buf, *c2 = buf + len - 1; c1 < c2; ++c1, --c2) {
        const uint8_t tmp = *c1;
        *c1 = *c2;
        *c2 = tmp;
    }
}

static void get_commitments_allocate(const char* field, const CborValue* value, commitment_t** data, size_t* written)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_ASSERT(data);
    JADE_ASSERT(written);

    *data = NULL;
    *written = 0;

    CborValue result;
    if (!rpc_get_array(field, value, &result)) {
        return;
    }

    size_t array_len = 0;
    CborError cberr = cbor_value_get_array_length(&result, &array_len);
    if (cberr != CborNoError || !array_len) {
        return;
    }

    CborValue arrayItem;
    cberr = cbor_value_enter_container(&result, &arrayItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&arrayItem)) {
        return;
    }

    commitment_t* const commitments = JADE_CALLOC(array_len, sizeof(commitment_t));

    size_t tmp = 0;
    for (size_t i = 0; i < array_len; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        commitment_t* const commitment = commitments + i;

        if (cbor_value_is_null(&arrayItem)) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        if (!cbor_value_is_map(&arrayItem)) {
            free(commitments);
            return;
        }

        tmp = 0;
        if (cbor_value_get_map_length(&arrayItem, &tmp) == CborNoError && tmp == 0) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        tmp = 0;
        rpc_get_bytes(
            "asset_generator", sizeof(commitment->asset_generator), &arrayItem, commitment->asset_generator, &tmp);
        if (tmp != sizeof(commitment->asset_generator)) {
            free(commitments);
            return;
        }

        tmp = 0;
        rpc_get_bytes(
            "value_commitment", sizeof(commitment->value_commitment), &arrayItem, commitment->value_commitment, &tmp);
        if (tmp != sizeof(commitment->value_commitment)) {
            free(commitments);
            return;
        }

        tmp = 0;
        rpc_get_bytes("abf", sizeof(commitment->abf), &arrayItem, commitment->abf, &tmp);
        if (tmp != sizeof(commitment->abf)) {
            free(commitments);
            return;
        }

        tmp = 0;
        rpc_get_bytes("vbf", sizeof(commitment->vbf), &arrayItem, commitment->vbf, &tmp);
        if (tmp != sizeof(commitment->vbf)) {
            free(commitments);
            return;
        }

        tmp = 0;
        rpc_get_bytes("asset_id", sizeof(commitment->asset_id), &arrayItem, commitment->asset_id, &tmp);
        if (tmp != sizeof(commitment->asset_id)) {
            free(commitments);
            return;
        }
        reverse(commitment->asset_id, sizeof(commitment->asset_id));

        tmp = 0;
        rpc_get_bytes("blinding_key", sizeof(commitment->blinding_key), &arrayItem, commitment->blinding_key, &tmp);
        if (tmp != sizeof(commitment->blinding_key)) {
            free(commitments);
            return;
        }

        if (!rpc_get_uint64_t("value", &arrayItem, &commitment->value)) {
            free(commitments);
            return;
        }

        // Set flag to show struct is populated/initialised
        commitment->have_commitments = true;

        CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr != CborNoError) {
        free(commitments);
        return;
    }

    *written = array_len;
    *data = commitments;
}

static bool add_validated_confidential_output_info(const commitment_t* commitments,
    const struct wally_tx_output* txoutput, output_info_t* outinfo, const char** errmsg)
{
    JADE_ASSERT(commitments);
    JADE_ASSERT(txoutput);
    JADE_ASSERT(outinfo);
    JADE_ASSERT(errmsg);
    JADE_ASSERT(txoutput->value[0] != 0x01); // Don't call for unblinded outputs

    uint8_t generator_tmp[ASSET_GENERATOR_LEN];
    uint8_t commitment_tmp[ASSET_COMMITMENT_LEN];

    if (!commitments->have_commitments) {
        *errmsg = "Missing commitments data for blinded output";
        return false;
    }

    // 1. Check the asset_generator can be rebuilt from the given asset_id and abf
    if (wally_asset_generator_from_bytes(commitments->asset_id, sizeof(commitments->asset_id), commitments->abf,
            sizeof(commitments->abf), generator_tmp, sizeof(generator_tmp))
            != WALLY_OK
        || sodium_memcmp(commitments->asset_generator, generator_tmp, sizeof(generator_tmp)) != 0) {
        *errmsg = "Failed to verify asset_generator from commitments data";
        return false;
    }

    // 2. Check the value_commitment can be rebuilt from the given value, vbf, and asset_generator
    if (wally_asset_value_commitment(commitments->value, commitments->vbf, sizeof(commitments->vbf),
            commitments->asset_generator, sizeof(commitments->asset_generator), commitment_tmp, sizeof(commitment_tmp))
            != WALLY_OK
        || sodium_memcmp(commitments->value_commitment, commitment_tmp, sizeof(commitment_tmp)) != 0) {
        *errmsg = "Failed to verify value_commitment from commitments data";
        return false;
    }

    // 3. Copy the 'trusted' commitments into the tx so we sign over them
    if (txoutput->asset_len != sizeof(commitments->asset_generator)) {
        *errmsg = "Failed to update tx asset_generator from commitments data";
        return false;
    }
    memcpy(txoutput->asset, commitments->asset_generator, sizeof(commitments->asset_generator));

    if (txoutput->value_len != sizeof(commitments->value_commitment)) {
        *errmsg = "Failed to update tx value_commitment from commitments data";
        return false;
    }
    memcpy(txoutput->value, commitments->value_commitment, sizeof(commitments->value_commitment));

    // 4. Fetch the asset_id, value, and blinding_key into the info struct
    JADE_ASSERT(sizeof(outinfo->asset_id) == sizeof(commitments->asset_id));
    JADE_ASSERT(sizeof(outinfo->blinding_key) == sizeof(commitments->blinding_key));
    memcpy(outinfo->asset_id, commitments->asset_id, sizeof(commitments->asset_id));
    outinfo->value = commitments->value;
    memcpy(outinfo->blinding_key, commitments->blinding_key, sizeof(commitments->blinding_key));

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
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
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
    int res = wally_tx_from_bytes(txbytes, written, WALLY_TX_FLAG_USE_ELEMENTS, &tx); // elements, without witness
    if (res != WALLY_OK || !tx) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract tx from passed bytes", NULL);
        goto cleanup;
    }
    jade_process_call_on_exit(process, wally_free_tx_wrapper, tx);

    // copy the amount
    uint32_t num_inputs = 0;
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

    // Can optionally be passed paths for change outputs, which we verify internally
    const char* errmsg = NULL;
    CborValue change;
    if (rpc_get_array("change", &params, &change)) {
        if (!validate_change_paths(process, network, tx, &change, output_info, &errmsg)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
            goto cleanup;
        }
    }

    // save fees for the final confirmation screen
    uint64_t fees = 0;

    // Check the trusted commitments: expect one element in the array for each output.
    // Can be null for unblinded outputs as we will skip them.
    // Populate an `output_index` -> (blinding_key, asset, value) map
    for (size_t i = 0; i < tx->num_outputs; ++i) {
        if (tx->outputs[i].value[0] == 0x01) {
            // unconfidential, take directly from the tx
            output_info[i].is_confidential = false;

            memcpy(output_info[i].asset_id, tx->outputs[i].asset + 1, sizeof(output_info[i].asset_id));
            wally_tx_confidential_value_to_satoshi(
                tx->outputs[i].value, tx->outputs[i].value_len, &output_info[i].value);

            // fees can only be unconfidential
            if (!tx->outputs[i].script) {
                fees += output_info[i].value;
            }
        } else {
            // confidential, use the trusted_commitments
            output_info[i].is_confidential = true;

            const char* errmsg = NULL;
            if (!add_validated_confidential_output_info(&commitments[i], &tx->outputs[i], &output_info[i], &errmsg)) {
                jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
                goto cleanup;
            }
        }
    }

    gui_activity_t* first_activity = NULL;
    make_display_elements_output_activity(network, tx, output_info, &first_activity);
    JADE_ASSERT(first_activity);
    gui_set_current_activity(first_activity);

    // ----------------------------------
    // wait for the last "next" (proceed with the protocol and then final confirmation)
    int32_t ev_id;
    // In a debug unattended ci build, assume buttons pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const esp_err_t outputs_ret = sync_await_single_event(JADE_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
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

        uint32_t value_len = 0;
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

    gui_activity_t* final_activity;
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
    vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
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
