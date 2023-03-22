#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../multisig.h"
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

#include <wally_anti_exfil.h>
#include <wally_script.h>

#include "process_utils.h"

static void wally_free_tx_wrapper(void* tx) { JADE_WALLY_VERIFY(wally_tx_free((struct wally_tx*)tx)); }

// Can optionally be passed paths for change outputs, which we verify internally
bool validate_change_paths(jade_process_t* process, const char* network, const struct wally_tx* tx, CborValue* change,
    output_info_t* output_info, const char** errmsg)
{
    JADE_ASSERT(process);
    JADE_ASSERT(network);
    JADE_ASSERT(tx);
    JADE_ASSERT(change);
    JADE_ASSERT(output_info);
    JADE_INIT_OUT_PPTR(errmsg);

    *errmsg = NULL;
    size_t num_array_items = 0;
    if (!cbor_value_is_array(change) || cbor_value_get_array_length(change, &num_array_items) != CborNoError
        || num_array_items != tx->num_outputs) {
        *errmsg = "Unexpected number of output (change) entries for transaction";
        return false;
    }

    CborValue arrayItem;
    CborError cberr = cbor_value_enter_container(change, &arrayItem);
    JADE_ASSERT(cberr == CborNoError);
    for (size_t i = 0; i < tx->num_outputs; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));

        // By default, assume not a validated or change output, and so user must verify
        JADE_ASSERT(!(output_info[i].flags & (OUTPUT_FLAG_VALIDATED | OUTPUT_FLAG_CHANGE)));
        if (cbor_value_is_map(&arrayItem)) {
            // Change info passed, try to verify output
            JADE_LOGD("Output %u has change-path passed", i);

            size_t csvBlocks = 0;
            size_t script_len = 0;
            uint8_t script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient
            size_t written = 0;

            // If multisig change, need to verify against the registered multisig wallets
            if (rpc_has_field_data("multisig_name", &arrayItem)) {
                // Load multisig data record
                multisig_data_t multisig_data;
                char multisig_name[MAX_MULTISIG_NAME_SIZE];
                if (!params_load_multisig(&arrayItem, multisig_name, sizeof(multisig_name), &multisig_data, errmsg)) {
                    // 'errmsg' populated by above call
                    return false;
                }
                JADE_LOGI("Change is to %uof%u multisig: '%s'", multisig_data.threshold, multisig_data.num_xpubs,
                    multisig_name);

                // Get the paths (suffixes) and derive pubkeys
                const bool is_change = true;
                uint8_t pubkeys[MAX_MULTISIG_SIGNERS * EC_PUBLIC_KEY_LEN]; // Sufficient
                if (!params_multisig_pubkeys(is_change, &arrayItem, &multisig_data, pubkeys, sizeof(pubkeys), &written,
                        output_info[i].message, sizeof(output_info[i].message), errmsg)) {
                    // 'errmsg' populated by above call
                    return false;
                }

                // Build a script pubkey for the passed parameters
                if (!wallet_build_multisig_script(multisig_data.variant, multisig_data.sorted, multisig_data.threshold,
                        pubkeys, written, script, sizeof(script), &script_len)) {
                    *errmsg = "Failed to generate valid multisig script";
                    return false;
                }
            } else {
                size_t path_len = 0;
                uint32_t path[MAX_PATH_LEN];
                const size_t max_path_len = sizeof(path) / sizeof(path[0]);

                // NOTE: for receiving change the root (empty bip32 path) is not allowed.
                const bool ret = rpc_get_bip32_path("path", &arrayItem, path, max_path_len, &path_len);
                if (!ret || path_len == 0) {
                    *errmsg = "Failed to extract valid change path from parameters";
                    return false;
                }

                // Optional script variant, default is green-multisig
                written = 0;
                char variant[MAX_VARIANT_LEN];
                script_variant_t script_variant;
                rpc_get_string("variant", sizeof(variant), &arrayItem, variant, &written);
                if (!get_script_variant(variant, written, &script_variant)) {
                    *errmsg = "Invalid script variant parameter";
                    return false;
                }

                if (is_greenaddress(script_variant)) {
                    // Optional recovery xpub for 2of3 accounts
                    written = 0;
                    char xpubrecovery[120]; // Should be sufficient as all xpubs should be <= 112
                    rpc_get_string("recovery_xpub", sizeof(xpubrecovery), &arrayItem, xpubrecovery, &written);

                    // Optional 'blocks' for csv outputs
                    rpc_get_sizet("csv_blocks", &arrayItem, &csvBlocks);

                    // If number of csv blocks unexpected show a warning message and ask the user to confirm
                    if (csvBlocks && !csvBlocksExpectedForNetwork(network, csvBlocks)) {
                        JADE_LOGW("Unexpected number of csv blocks in change path output: %u", csvBlocks);
                        const int ret = snprintf(output_info[i].message, sizeof(output_info[i].message),
                            "This change output has a non-standard csv value (%u), so it may be difficult to find.  "
                            "Proceed at your own risk.",
                            csvBlocks);
                        JADE_ASSERT(
                            ret > 0 && ret < sizeof(output_info[i].message)); // Keep message within size handled by gui
                    }

                    // Build a script pubkey for the passed parameters
                    if (!wallet_build_ga_script(network, written ? xpubrecovery : NULL, csvBlocks, path, path_len,
                            script, sizeof(script), &script_len)) {
                        JADE_LOGE("Output %u change path/script failed to construct", i);
                        *errmsg = "Change script cannot be constructed";
                        return false;
                    }
                } else if (is_singlesig(script_variant)) {
                    // If paths not as expected show a warning message and ask the user to confirm
                    const bool is_change = true;
                    if (!wallet_is_expected_singlesig_path(network, script_variant, is_change, path, path_len)) {
                        char path_str[96];
                        if (!bip32_path_as_str(path, path_len, path_str, sizeof(path_str))) {
                            *errmsg = "Failed to convert path to string format";
                            return false;
                        }
                        const int ret = snprintf(output_info[i].message, sizeof(output_info[i].message),
                            "Unusual change path: %s", path_str);
                        JADE_ASSERT(
                            ret > 0 && ret < sizeof(output_info[i].message)); // Keep message within size handled by gui
                    }

                    // Build a script pubkey for the passed parameters
                    // Derive user pubkey from the path
                    struct ext_key derived;
                    if (!wallet_get_hdkey(path, path_len, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &derived)
                        || !wallet_build_singlesig_script(script_variant, derived.pub_key, sizeof(derived.pub_key),
                            script, sizeof(script), &script_len)) {
                        JADE_LOGE("Output %u change path/script failed to construct", i);
                        *errmsg = "Change script cannot be constructed";
                        return false;
                    }
                } else {
                    // Multisig handled above, so should be nothing left
                    JADE_LOGE("Output %u change path/script unknown variant %d", i, script_variant);
                    *errmsg = "Change script variant not handled";
                    return false;
                }
            }

            // Compare generated script to that expected/in the txn
            if (script_len != tx->outputs[i].script_len
                || sodium_memcmp(tx->outputs[i].script, script, script_len) != 0) {
                JADE_LOGE("Receive script failed validation");
                *errmsg = "Change script cannot be validated";
                return false;
            }

            // Change path valid and matches tx output script
            JADE_LOGI("Output %u change path/script validated", i);

            // Set appropriate flags
            output_info[i].flags |= (OUTPUT_FLAG_VALIDATED | OUTPUT_FLAG_CHANGE);
        }
        const CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }
    cberr = cbor_value_leave_container(change, &arrayItem);
    JADE_ASSERT(cberr == CborNoError);

    // All paths checked
    return true;
}

// Loop to generate and send Anti-Exfil signatures as they are requested.
void send_ae_signature_replies(jade_process_t* process, signing_data_t* all_signing_data, const uint32_t num_inputs)
{
    JADE_ASSERT(process);
    JADE_ASSERT(all_signing_data);
    JADE_ASSERT(num_inputs > 0);

    SENSITIVE_PUSH(all_signing_data, sizeof(all_signing_data));
    for (size_t i = 0; i < num_inputs; ++i) {
        signing_data_t* const sig_data = all_signing_data + i;

        // We always need a 'get-signature' exchange even if we are not providing a signature
        jade_process_load_in_message(process, true);
        if (!IS_CURRENT_MESSAGE(process, "get_signature")) {
            // Protocol error
            jade_process_reject_message(
                process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'get_signature'", NULL);
            goto cleanup;
        }

        if (sig_data->path_len > 0) {
            // We are expecting to generate a signature for this input
            GET_MSG_PARAMS(process);

            size_t ae_host_entropy_len = 0;
            const uint8_t* ae_host_entropy = NULL;
            rpc_get_bytes_ptr("ae_host_entropy", &params, &ae_host_entropy, &ae_host_entropy_len);

            if (!ae_host_entropy || ae_host_entropy_len != WALLY_S2C_DATA_LEN) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract host entropy from parameters", NULL);
                goto cleanup;
            }

            // Generate Anti-Exfil signature
            if (!wallet_sign_tx_input_hash(sig_data->signature_hash, sizeof(sig_data->signature_hash), sig_data->path,
                    sig_data->path_len, ae_host_entropy, ae_host_entropy_len, sig_data->sig, sizeof(sig_data->sig),
                    &sig_data->sig_len)) {
                jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to sign tx input", NULL);
                goto cleanup;
            }
            JADE_ASSERT(sig_data->sig_len > 0);
        }

        // Send signature reply - will be empty for any inputs we are not signing
        const bytes_info_t bytes_info = { .data = sig_data->sig, .size = sig_data->sig_len };
        jade_process_reply_to_message_result(process->ctx, &bytes_info, cbor_result_bytes_cb);
    }

cleanup:
    SENSITIVE_POP(all_signing_data);
}

// The backward compatible 'send all messages in a batch' method for standard EC signatures.
// NOTE: should be converted to the same message flow as above, at some point.
void send_ec_signature_replies(
    const jade_msg_source_t source, signing_data_t* all_signing_data, const uint32_t num_inputs)
{
    JADE_ASSERT(all_signing_data);
    JADE_ASSERT(num_inputs > 0);

    uint8_t msgbuf[256];
    SENSITIVE_PUSH(all_signing_data, sizeof(all_signing_data));
    for (size_t i = 0; i < num_inputs; ++i) {
        signing_data_t* const sig_data = all_signing_data + i;
        if (sig_data->path_len > 0) {
            // Generate EC signature
            if (!wallet_sign_tx_input_hash(sig_data->signature_hash, sizeof(sig_data->signature_hash), sig_data->path,
                    sig_data->path_len, NULL, 0, sig_data->sig, sizeof(sig_data->sig), &sig_data->sig_len)) {
                jade_process_reject_message_with_id(sig_data->id, CBOR_RPC_INTERNAL_ERROR, "Failed to sign tx input",
                    NULL, 0, msgbuf, sizeof(msgbuf), source);
                goto cleanup;
            }
            JADE_ASSERT(sig_data->sig_len > 0);
        }
    }

    // Now send all signatures - one per message - in reply to input messages
    // Will be empty for any inputs we are not signing
    for (size_t i = 0; i < num_inputs; ++i) {
        const signing_data_t* const sig_data = all_signing_data + i;
        const bytes_info_t bytes_info = { .data = sig_data->sig, .size = sig_data->sig_len };
        jade_process_reply_to_message_result_with_id(
            sig_data->id, msgbuf, sizeof(msgbuf), source, &bytes_info, cbor_result_bytes_cb);
    }

cleanup:
    SENSITIVE_POP(all_signing_data);
}

/*
 * The message flow here is complicated because we cater for both a legacy flow
 * for standard deterministic EC signatures (see rfc6979) and a newer message
 * exchange added later to cater for anti-exfil signatures.
 * At the moment we retain the older message flow for backward compatibility,
 * but at some point we should remove it and use the new message flow for all
 * cases, which would simplify the code here and in the client.
 */
void sign_tx_process(void* process_ptr)
{
    JADE_LOGI("Starting: %lu", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;
    char network[MAX_NETWORK_NAME_LEN];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_tx");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    const jade_msg_source_t source = process->ctx.source;

    // Check network is valid and consistent with prior usage
    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);
    if (isLiquidNetwork(network)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "sign_tx call not appropriate for liquid network", NULL);
        goto cleanup;
    }

    written = 0;
    const uint8_t* txbytes = NULL;
    rpc_get_bytes_ptr("txn", &params, &txbytes, &written);

    if (written == 0) {
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

    // Whether to use Anti-Exfil signatures and message flow
    // Optional flag, defaults to false
    bool use_ae_signatures = false;
    rpc_get_boolean("use_ae_signatures", &params, &use_ae_signatures);

    // Can optionally be passed paths for change outputs, which we verify internally
    const char* errmsg = NULL;
    output_info_t* output_info = NULL;
    // we have one change
    // for each tx there may be a change field
    // if it's there it's an array of length n_inputs
    // that contains a map or null. The map has  "csv_blocks": 65535,"path":[1,5], "recovery_xpub":null
    CborValue change;
    if (rpc_get_array("change", &params, &change)) {
        output_info = JADE_CALLOC(tx->num_outputs, sizeof(output_info_t));
        jade_process_free_on_exit(process, output_info);

        if (!validate_change_paths(process, network, tx, &change, output_info, &errmsg)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
            goto cleanup;
        }
    }

    gui_activity_t* first_activity = NULL;
    make_display_output_activity(network, tx, output_info, &first_activity);
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
    uint64_t input_amount = 0;
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
        uint64_t input_satoshi = 0;

        // The ae commitments for this input (if using anti-exfil signatures)
        size_t ae_host_commitment_len = 0;
        const uint8_t* ae_host_commitment = NULL;
        uint8_t ae_signer_commitment[WALLY_S2C_OPENING_LEN];

        // Store the signing data so we can free the (potentially large) input message.
        // Signatures will be generated and replies sent after user confirmation.
        // Reply is our signature for the input, or an empty string if we are not
        // signing this input (ie. if no path was passed for this input).
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

        // Full input tx can be omitted for transactions with only one single witness
        // input, otherwise it must be present to validate the input utxo amounts.
        const uint8_t* txbuf = NULL;
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
            ret = rpc_get_uint64_t("satoshi", &params, &input_satoshi);
            if (!ret) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract satoshi from parameters", NULL);
                goto cleanup;
            }
        }

        // Make signature if given a path (should have a prevout script in hand)
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

        // Keep a running total
        input_amount += input_satoshi;
        if (input_amount > UINT32_MAX) {
            JADE_LOGD("input_amount over UINT32_MAX, truncated low = %" PRIu32 " high %" PRIu32, (uint32_t)input_amount,
                (uint32_t)(input_amount >> 32));
        } else {
            JADE_LOGD("input_amount = %" PRIu32, (uint32_t)input_amount);
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

    // Sanity check amounts
    uint64_t output_amount;
    JADE_WALLY_VERIFY(wally_tx_get_total_output_satoshi(tx, &output_amount));
    if (output_amount > input_amount) {
        // If using ae-signatures, we need to load the message to send the error back on
        if (use_ae_signatures) {
            jade_process_load_in_message(process, true);
        }
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Total input amounts less than total output amounts", NULL);
        goto cleanup;
    }

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
