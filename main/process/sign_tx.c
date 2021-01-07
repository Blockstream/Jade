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

#include <inttypes.h>
#include <sodium/utils.h>
#include <string.h>

#include "process_utils.h"

static void wally_free_tx_wrapper(void* tx) { JADE_WALLY_VERIFY(wally_tx_free((struct wally_tx*)tx)); }

// Can optionally be passed paths for change outputs, which we verify internally
bool validate_change_paths(jade_process_t* process, const char* network, struct wally_tx* tx, CborValue* change,
    output_info_t* output_info, char** errmsg)
{
    JADE_ASSERT(process);
    JADE_ASSERT(tx);
    JADE_ASSERT(change);
    JADE_ASSERT(output_info);
    JADE_ASSERT(errmsg);

    size_t length = 0;

    if (!cbor_value_is_array(change) || cbor_value_get_array_length(change, &length) != CborNoError
        || length != tx->num_outputs) {
        *errmsg = "Unexpected number of output (change) entries for transaction";
        return false;
    }

    CborValue arrayItem;

    CborError cberr = cbor_value_enter_container(change, &arrayItem);
    JADE_ASSERT(cberr == CborNoError);
    for (size_t i = 0; i < tx->num_outputs; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        if (!cbor_value_is_map(&arrayItem)) {
            // Not a change output, user must verify
            output_info[i].is_validated_change_address = false;
        } else {
            JADE_ASSERT(cbor_value_is_map(&arrayItem));
            JADE_LOGD("Output %u has change-path passed", i);

            uint32_t path_len = 0;
            uint32_t path[MAX_PATH_LEN];
            bool retval = rpc_get_bip32_path("path", &arrayItem, path, MAX_PATH_LEN, &path_len);

            // NOTE: for receiving change the root (empty bip32 path) is not allowed.
            if (!retval || path_len == 0) {
                *errmsg = "Failed to extract valid change path from parameters";
                return false;
            }

            // Optional recovery xpub for 2of3 accounts
            char xpubrecovery[120];
            size_t written = 0;
            rpc_get_string("recovery_xpub", sizeof(xpubrecovery), &arrayItem, xpubrecovery, &written);

            // Optional 'blocks' for csv outputs
            uint32_t csvBlocks = 0;
            rpc_get_sizet("csv_blocks", &arrayItem, &csvBlocks);

            // Try to recreate the change/receive script and compare to the txn value
            if (!wallet_validate_receive_script(network, !written ? NULL : xpubrecovery, csvBlocks, path, path_len,
                    tx->outputs[i].script, tx->outputs[i].script_len)) {
                // Change path provided, but failed to validate - error
                JADE_LOGE("Output %u change path/script failed to validate", i);
                *errmsg = "Change script cannot be validated";
                return false;
            }

            // Change path valid and matches tx output script
            JADE_LOGI("Output %u change path/script validated", i);

            // If the number of csv blocks is unexpected, show a warning message
            // and make the user confirm.  Otherwise all is fine and we don't
            // need to ask the user to manually confirm this change output.
            if (csvBlocks && !csvBlocksExpectedForNetwork(network, csvBlocks)) {
                JADE_LOGW("Unexpected number of csv blocks in change path output: %u", csvBlocks);
                output_info[i].is_validated_change_address = false;

                const int ret = snprintf(output_info[i].message, sizeof(output_info[i].message),
                    "This change output has a non-standard csv value (%u), so it may be difficult to find.  Proceed at "
                    "your own risk.",
                    csvBlocks);
                JADE_ASSERT(ret > 0 && ret < sizeof(output_info[i].message)); // Keep message within size handled by gui
            } else {
                output_info[i].is_validated_change_address = true;
            }
        }
        const CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }
    cberr = cbor_value_leave_container(change, &arrayItem);
    JADE_ASSERT(cberr == CborNoError);

    // All paths checked
    return true;
}

void sign_tx_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;
    char network[strlen(TAG_LOCALTESTLIQUID) + 1];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_tx");
    GET_MSG_PARAMS(process);
    const jade_msg_source_t source = process->ctx.source;

    // Check network is valid and consistent with prior usage
    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);
    if (isLiquid(network)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "sign_tx call not appropriate for liquid network", NULL);
        goto cleanup;
    }

    written = 0;
    const uint8_t* txbytes = NULL;
    rpc_get_bytes_ptr("txn", &params, &txbytes, &written);

    if (written == 0) {
        JADE_ASSERT(txbytes == NULL);
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract tx from parameters", NULL);
        goto cleanup;
    }
    JADE_ASSERT(txbytes);

    struct wally_tx* tx = NULL;
    int res = wally_tx_from_bytes(txbytes, written, 0, &tx); // 0 = no witness, TODO
    if (res != WALLY_OK || !tx) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract tx from passed bytes", NULL);
        goto cleanup;
    }
    jade_process_call_on_exit(process, wally_free_tx_wrapper, tx);

    // copy the amount
    uint32_t num_inputs = 0;
    bool retval = rpc_get_sizet("num_inputs", &params, &num_inputs);
    if (!retval || num_inputs == 0) {
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

    // Can optionally be passed paths for change outputs, which we verify internally
    char* errmsg = NULL;
    output_info_t* output_info = NULL;
    // we have one change
    // for each tx there may be a change field
    // if it's there it's an array of length n_inputs
    // that contains a map or null. The map has  "csv_blocks": 65535,"path":[1,5], "recovery_xpub":null
    CborValue change;
    if (rpc_get_change("change", &params, &change) && cbor_value_is_array(&change)) {
        output_info = JADE_CALLOC(tx->num_outputs, sizeof(output_info_t));
        jade_process_free_on_exit(process, output_info);

        if (!validate_change_paths(process, network, tx, &change, output_info, &errmsg)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
            goto cleanup;
        }
    }

    gui_activity_t* first_activity = NULL;
    gui_activity_t* last_activity = NULL;
    make_display_output_activity(network, tx, output_info, &first_activity, &last_activity);
    JADE_ASSERT(first_activity);
    JADE_ASSERT(last_activity);
    gui_set_current_activity(first_activity);

    // ----------------------------------
    // wait for the last "next" (proceed with the protocol and then final confirmation)
    int32_t ev_id;
    // In a debug unattended ci build, assume buttons pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    // We manually wait for a 'JADE_EVENT' here - we can't use the normal gui wait for a
    // button call, as we do not know which output activity the 'exit' event might come from.
    wait_event_data_t* wait_data = make_wait_event_data();
    esp_event_handler_register(JADE_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, wait_data);
    const esp_err_t outputs_ret = sync_wait_event(JADE_EVENT, ESP_EVENT_ANY_ID, wait_data, NULL, &ev_id, NULL, 0);
    free_wait_event_data(wait_data);
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

    // Run through each input message and generate a signature for each one
    uint64_t input_amount = 0;
    for (size_t index = 0; index < num_inputs; ++index) {
        jade_process_load_in_message(process, true);
        if (!rpc_is_method(&process->ctx.value, "tx_input")) {
            // Protocol error
            jade_process_reject_message(
                process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'tx_input'", NULL);
            goto cleanup;
        }

        // txn input as expected - get input parameters
        GET_MSG_PARAMS(process);

        // Store the signing data so we can free the (potentially large) input message.
        // Signatures will be generated and replies sent after user confirmation.
        // Reply is our signature for the input, or an empty string if we are not
        // signing this input (ie. if no path was passed for this input).
        written = 0;
        signing_data_t* const sig_data = all_signing_data + index;
        rpc_get_id(&process->ctx.value, sig_data->id, sizeof(sig_data->id), &written);
        JADE_ASSERT(written != 0);

        bool is_witness = false;
        retval = rpc_get_boolean("is_witness", &params, &is_witness);
        if (!retval) {
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
        }

        uint64_t input_satoshi = 0;
        size_t script_len = 0;
        uint8_t* script = NULL;

        // Full input tx can be omitted for transactions with only one single witness
        // input, otherwise it must be present to validate the input utxo amounts.
        const unsigned char* txbuf = NULL;
        size_t txsize = 0;
        rpc_get_bytes_ptr("input_tx", &params, &txbuf, &txsize);

        // If we have the full prior transaction, use it.
        if (txbuf) {
            JADE_LOGD("Validating input utxo amount using full prior transaction");

            // Parse buffer into tx struct, and free (potentially large) buffer
            struct wally_tx* input_tx = NULL;
            res = wally_tx_from_bytes(txbuf, txsize, 0, &input_tx); // 0 = no witness

            if (res != WALLY_OK || !input_tx) {
                jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract input_tx", NULL);
                JADE_WALLY_VERIFY(wally_tx_free(input_tx));
                goto cleanup;
            }

            // Check that txhash of passed input_tx == tx->inputs[index].txhash
            // ie. that the 'input-tx' passed is indeed the correct transaction
            uint8_t txhash[WALLY_TXHASH_LEN];
            res = wally_tx_get_txid(input_tx, txhash, sizeof(txhash));

            if (res != WALLY_OK || sodium_memcmp(txhash, tx->inputs[index].txhash, sizeof(txhash)) != 0) {
                jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS,
                    "input_tx cannot be verified against transaction input data", NULL);
                JADE_WALLY_VERIFY(wally_tx_free(input_tx));
                goto cleanup;
            }

            // Check that passed input tx has an output at tx->input[index].index
            if (input_tx->num_outputs <= tx->inputs[index].index) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "input_tx missing corresponding output", NULL);
                JADE_WALLY_VERIFY(wally_tx_free(input_tx));
                goto cleanup;
            }

            // Fetch the amount from the txn
            input_satoshi = input_tx->outputs[tx->inputs[index].index].satoshi;

            // Fetch the scriptPubKey from the txn for a non-segwit input we intend to sign
            if (has_path && !is_witness) {
                JADE_LOGD("Using script from input utxo txn");
                script_len = input_tx->outputs[tx->inputs[index].index].script_len;
                script = JADE_MALLOC(script_len);
                memcpy(script, input_tx->outputs[tx->inputs[index].index].script, script_len);
                jade_process_free_on_exit(process, script);
            }

            // Free the (potentially large) txn immediately
            JADE_WALLY_VERIFY(wally_tx_free(input_tx));
        } else {
            if (!is_witness || num_inputs > 1) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract input_tx from parameters", NULL);
                goto cleanup;
            }

            // For single segwit input we can instead get just the amount directly from message
            JADE_LOGD("Single witness input - using explicitly passed amount");

            // Get the amount
            retval = rpc_get_uint64_t("satoshi", &params, &input_satoshi);
            if (!retval) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract satoshi from parameters", NULL);
                goto cleanup;
            }
        }

        // For segwit input we expect the prevout-script to be passed explicitly, if
        //  we are signing (and we would not have extracted it from the input-tx above).
        if (has_path && is_witness) {
            JADE_ASSERT(!script);
            JADE_ASSERT(script_len == 0);
            JADE_LOGD("For segwit input using explicitly passed prevout script");

            rpc_get_bytes_ptr("script", &params, (const uint8_t**)&script, &script_len);
            if (!script || script_len <= 0) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract script from parameters", NULL);
                goto cleanup;
            }
        }

        // Make signature if given a path (should have a script in hand)
        if (has_path) {
            JADE_ASSERT(script);
            JADE_ASSERT(script_len > 0);
            JADE_ASSERT(sig_data->path_len > 0);

            // Generate hash of this input which we will sign later
            if (!wallet_get_tx_input_hash(tx, index, is_witness, script, script_len, input_satoshi,
                    sig_data->signature_hash, sizeof(sig_data->signature_hash))) {
                jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to make tx input hash", NULL);
                goto cleanup;
            }
        } else {
            // Empty byte-string reply (no path given implies no sig needed or expected)
            JADE_ASSERT(!script);
            JADE_ASSERT(script_len == 0);
            JADE_ASSERT(sig_data->path_len == 0);
        }

        // Keep a running total
        input_amount += input_satoshi;
        if (input_amount > UINT32_MAX) {
            JADE_LOGD("input_amount over UINT32_MAX, truncated low = %" PRIu32 " high %" PRIu32, (uint32_t)input_amount,
                (uint32_t)(input_amount >> 32));
        } else {
            JADE_LOGD("input_amount = %" PRIu32, (uint32_t)input_amount);
        }
    }

    gui_activity_t* final_activity;
    make_display_final_confirmation_activity(tx, input_amount, &final_activity);
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
        JADE_LOGW("User declined to sign transaction");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign transaction", NULL);
        goto cleanup;
    }

    JADE_LOGD("User accepted fee");

    // User confirmed - make all signatures
    uint8_t msgbuf[256];
    SENSITIVE_PUSH(all_signing_data, sizeof(all_signing_data));
    for (size_t i = 0; i < num_inputs; ++i) {
        signing_data_t* const sig_data = all_signing_data + i;
        if (sig_data->path_len > 0) {
            // Generate signature
            if (!wallet_sign_tx_input_hash(sig_data->signature_hash, sizeof(sig_data->signature_hash), sig_data->path,
                    sig_data->path_len, sig_data->sig, sizeof(sig_data->sig), &sig_data->sig_size)) {
                jade_process_reject_message_with_id(sig_data->id, CBOR_RPC_INTERNAL_ERROR, "Failed to sign tx input",
                    NULL, 0, msgbuf, sizeof(msgbuf), source);
                goto cleanup_sigs;
            }
            JADE_ASSERT(sig_data->sig_size > 0);
        }
    }

    // Now send all signatures - one per message - in reply to input messages
    for (size_t i = 0; i < num_inputs; ++i) {
        const signing_data_t* const sig_data = all_signing_data + i;
        const bytes_info_t bytes_info = { .data = sig_data->sig, .size = sig_data->sig_size };
        jade_process_reply_to_message_result_with_id(
            sig_data->id, msgbuf, sizeof(msgbuf), source, &bytes_info, cbor_result_bytes_cb);
    }
    JADE_LOGI("Success");

cleanup_sigs:
    SENSITIVE_POP(all_signing_data);
cleanup:
    return;
}
