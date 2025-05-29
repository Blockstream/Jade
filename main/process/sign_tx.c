#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../descriptor.h"
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
#include "../utils/wally_ext.h"
#include "../wallet.h"

#include <inttypes.h>
#include <sodium/utils.h>

#include <wally_address.h>
#include <wally_anti_exfil.h>
#include <wally_map.h>
#include <wally_script.h>

#include "process_utils.h"

bool show_btc_transaction_outputs_activity(
    const uint32_t network_id, const struct wally_tx* tx, const output_info_t* output_info);
bool show_btc_final_confirmation_activity(uint64_t fee, const char* warning_msg);

// Can optionally be passed paths for change outputs, which we verify internally
bool validate_wallet_outputs(jade_process_t* process, const uint32_t network_id, const struct wally_tx* tx,
    CborValue* wallet_outputs, output_info_t* output_info, const char** errmsg)
{
    JADE_ASSERT(process);
    JADE_ASSERT(network_id != WALLY_NETWORK_NONE);
    JADE_ASSERT(tx);
    JADE_ASSERT(wallet_outputs);
    JADE_ASSERT(output_info);
    JADE_INIT_OUT_PPTR(errmsg);

    bool ret = false;
    multisig_data_t* multisig_data = NULL;
    descriptor_data_t* descriptor = NULL;

    size_t num_array_items = 0;
    if (!cbor_value_is_array(wallet_outputs)
        || cbor_value_get_array_length(wallet_outputs, &num_array_items) != CborNoError
        || num_array_items != tx->num_outputs) {
        *errmsg = "Unexpected number of output entries for transaction";
        goto cleanup;
    }

    CborValue arrayItem;
    CborError cberr = cbor_value_enter_container(wallet_outputs, &arrayItem);
    JADE_ASSERT(cberr == CborNoError);
    for (size_t i = 0; i < tx->num_outputs; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));

        // By default, assume not a validated or change output, and so user must verify
        JADE_ASSERT(!(output_info[i].flags & (OUTPUT_FLAG_VALIDATED | OUTPUT_FLAG_CHANGE)));
        if (cbor_value_is_map(&arrayItem)) {
            // Output path info passed, try to verify output
            JADE_LOGD("Output %u has output/change data passed", i);

            // For backward-compatibility reasons we assume all populated items
            // are change unless told otherwise (ie. explcit is_change: false)
            bool is_change = true;
            rpc_get_boolean("is_change", &arrayItem, &is_change);

            size_t csvBlocks = 0;
            size_t script_len = 0;
            uint8_t script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient
            size_t written = 0;

            // If multisig, need to verify against the registered multisig wallets
            if (rpc_has_field_data("multisig_name", &arrayItem)) {
                // Load multisig data record (alloc on first use)
                if (!multisig_data) {
                    multisig_data = JADE_MALLOC(sizeof(multisig_data_t));
                }

                char multisig_name[MAX_MULTISIG_NAME_SIZE];
                if (!params_load_multisig(&arrayItem, multisig_name, sizeof(multisig_name), multisig_data, errmsg)) {
                    // 'errmsg' populated by above call
                    goto cleanup;
                }
                JADE_LOGI("Change is to %uof%u multisig: '%s'", multisig_data->threshold, multisig_data->num_xpubs,
                    multisig_name);

                // Get the paths (suffixes) and derive pubkeys
                uint8_t pubkeys[MAX_ALLOWED_SIGNERS * EC_PUBLIC_KEY_LEN]; // Sufficient
                if (!params_multisig_pubkeys(is_change, &arrayItem, multisig_data, pubkeys, sizeof(pubkeys), &written,
                        output_info[i].message, sizeof(output_info[i].message), errmsg)) {
                    // 'errmsg' populated by above call
                    goto cleanup;
                }

                // Build a script pubkey for the passed parameters
                if (!wallet_build_multisig_script(multisig_data->variant, multisig_data->sorted,
                        multisig_data->threshold, pubkeys, written, script, sizeof(script), &script_len)) {
                    *errmsg = "Failed to generate valid multisig script";
                    goto cleanup;
                }
            } else if (rpc_has_field_data("descriptor_name", &arrayItem)) {
                // Not valid for liquid wallets atm
                if (isLiquidNetworkId(network_id)) {
                    *errmsg = "Descriptor wallets not supported on liquid network";
                    goto cleanup;
                }

                // Load descriptor record (alloc on first use)
                if (!descriptor) {
                    descriptor = JADE_MALLOC(sizeof(descriptor_data_t));
                }

                char descriptor_name[MAX_DESCRIPTOR_NAME_SIZE];
                if (!params_load_descriptor(&arrayItem, descriptor_name, sizeof(descriptor_name), descriptor, errmsg)) {
                    // 'errmsg' populated by above call
                    goto cleanup;
                }

                // The path is given in two parts - optional (change) branch and mandatory index pointer
                size_t branch = 0, pointer = 0;
                rpc_get_sizet("branch", &arrayItem, &branch); // optional
                if (!rpc_get_sizet("pointer", &arrayItem, &pointer)) {
                    *errmsg = "Failed to extract path elements from parameters";
                    goto cleanup;
                }

                // Build a script pubkey for the passed parameters
                if (!wallet_build_descriptor_script(network_id, descriptor_name, descriptor, branch, pointer, script,
                        sizeof(script), &script_len, errmsg)) {
                    *errmsg = "Failed to generate valid descriptor script";
                    goto cleanup;
                }
            } else {
                size_t path_len = 0;
                uint32_t path[MAX_PATH_LEN];
                const size_t max_path_len = sizeof(path) / sizeof(path[0]);

                // NOTE: for receiving [change] the root (empty bip32 path) is not allowed.
                const bool ret = rpc_get_bip32_path("path", &arrayItem, path, max_path_len, &path_len);
                if (!ret || path_len == 0) {
                    *errmsg = "Failed to extract valid receive path from parameters";
                    goto cleanup;
                }

                // Optional script variant, default is green-multisig
                written = 0;
                char variant[MAX_VARIANT_LEN];
                script_variant_t script_variant;
                rpc_get_string("variant", sizeof(variant), &arrayItem, variant, &written);
                if (!get_script_variant(variant, written, &script_variant)) {
                    *errmsg = "Invalid script variant parameter";
                    goto cleanup;
                }

                const char* const network = networkIdToNetwork(network_id); // TODO: use ID
                if (is_greenaddress(script_variant)) {
                    // Optional recovery xpub for 2of3 accounts
                    written = 0;
                    char xpubrecovery[120]; // Should be sufficient as all xpubs should be <= 112
                    rpc_get_string("recovery_xpub", sizeof(xpubrecovery), &arrayItem, xpubrecovery, &written);

                    // Optional 'blocks' for csv outputs
                    rpc_get_sizet("csv_blocks", &arrayItem, &csvBlocks);

                    // If number of csv blocks unexpected show a warning message and ask the user to confirm
                    if (csvBlocks && !csvBlocksExpectedForNetwork(network, csvBlocks)) {
                        JADE_LOGW("Unexpected number of csv blocks in path for output: %u", csvBlocks);
                        const int ret = snprintf(output_info[i].message, sizeof(output_info[i].message),
                            "This wallet output has a non-standard csv value (%u), so it may be difficult to find.  "
                            "Proceed at your own risk.",
                            csvBlocks);
                        JADE_ASSERT(
                            ret > 0 && ret < sizeof(output_info[i].message)); // Keep message within size handled by gui
                    }

                    // Build a script pubkey for the passed parameters
                    if (!wallet_build_ga_script(network, written ? xpubrecovery : NULL, csvBlocks, path, path_len,
                            script, sizeof(script), &script_len)) {
                        JADE_LOGE("Output %u path/script failed to construct", i);
                        *errmsg = "Receive script cannot be constructed";
                        goto cleanup;
                    }
                } else if (is_singlesig(script_variant)) {
                    // If paths not as expected show a warning message and ask the user to confirm
                    if (!wallet_is_expected_singlesig_path(network, script_variant, is_change, path, path_len)) {
                        char path_str[MAX_PATH_STR_LEN(MAX_PATH_LEN)];
                        if (!wallet_bip32_path_as_str(path, path_len, path_str, sizeof(path_str))) {
                            *errmsg = "Failed to convert path to string format";
                            goto cleanup;
                        }
                        const int ret = snprintf(output_info[i].message, sizeof(output_info[i].message),
                            "Unusual %s path: %s", is_change ? "change" : "receive", path_str);
                        JADE_ASSERT(
                            ret > 0 && ret < sizeof(output_info[i].message)); // Keep message within size handled by gui
                    }

                    // Build a script pubkey for the passed parameters
                    // Derive user pubkey from the path
                    struct ext_key derived;
                    if (!wallet_get_hdkey(path, path_len, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &derived)
                        || !wallet_build_singlesig_script(
                            script_variant, &derived, script, sizeof(script), &script_len)) {
                        JADE_LOGE("Output %u path/script failed to construct", i);
                        *errmsg = "Receive script cannot be constructed";
                        goto cleanup;
                    }
                } else {
                    // Multisig handled above, so should be nothing left
                    JADE_LOGE("Output %u unknown script variant %d", i, script_variant);
                    *errmsg = "Receive script variant not handled";
                    goto cleanup;
                }
            }

            // Compare generated script to that expected/in the txn
            if (script_len != tx->outputs[i].script_len
                || sodium_memcmp(tx->outputs[i].script, script, script_len) != 0) {
                JADE_LOGE("Receive script failed validation");
                *errmsg = "Receive script cannot be validated";
                goto cleanup;
            }

            // Change path valid and matches tx output script
            JADE_LOGI("Output %u receive path/script validated", i);

            // Set appropriate flags
            output_info[i].flags |= OUTPUT_FLAG_VALIDATED;
            if (is_change) {
                output_info[i].flags |= OUTPUT_FLAG_CHANGE;
            }
        }
        const CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }
    cberr = cbor_value_leave_container(wallet_outputs, &arrayItem);
    JADE_ASSERT(cberr == CborNoError);

    // All paths checked
    ret = true;

cleanup:
    free(multisig_data);
    free(descriptor);
    return ret;
}

bool show_btc_fee_confirmation_activity(const struct wally_tx* tx, const output_info_t* outinfo,
    const script_flavour_t aggregate_inputs_scripts_flavour, const uint64_t input_amount, const uint64_t output_amount)
{
    JADE_ASSERT(tx);
    // outputinfo is optional
    JADE_ASSERT(input_amount);
    JADE_ASSERT(output_amount);

    JADE_ASSERT(input_amount >= output_amount);

    // User to agree fee amount
    // The fee amount is the shortfall between input and output amounts
    // The 'spend' amount is the total of the outputs not flagged as change
    const uint64_t fees = input_amount - output_amount;
    uint64_t spend_amount = output_amount;
    if (outinfo) {
        for (size_t i = 0; i < tx->num_outputs; ++i) {
            if (outinfo[i].flags & OUTPUT_FLAG_CHANGE) {
                // Deduct change output amount
                JADE_ASSERT(spend_amount >= tx->outputs[i].satoshi);
                spend_amount -= tx->outputs[i].satoshi;
            }
        }
    }

    char warnbuf[128]; // sufficient
    const char* warning_msg = NULL;
    const bool warn_fees = fees && fees >= spend_amount;
    const bool warn_scripts = aggregate_inputs_scripts_flavour == SCRIPT_FLAVOUR_MIXED;
    if (warn_fees && warn_scripts) {
        const int retval = snprintf(warnbuf, sizeof(warnbuf), "%s %s", WARN_MSG_HIGH_FEES, WARN_MSG_MIXED_INPUTS);
        JADE_ASSERT(retval > 0 && retval < sizeof(warnbuf));
        warning_msg = warnbuf;
    } else if (warn_scripts) {
        warning_msg = WARN_MSG_MIXED_INPUTS;
    } else if (warn_fees) {
        warning_msg = WARN_MSG_HIGH_FEES;
    }

    // Return whether the user accepts or declines
    return show_btc_final_confirmation_activity(fees, warning_msg);
}

// Loop to generate and send Anti-Exfil signatures as they are requested.
void send_ae_signature_replies(jade_process_t* process, signing_data_t* signing_data)
{
    JADE_ASSERT(process);
    JADE_ASSERT(signing_data);
    JADE_ASSERT(signing_data->num_inputs > 0);

    for (size_t i = 0; i < signing_data->num_inputs; ++i) {
        input_data_t* const input_data = &signing_data->inputs[i];

        // We always need a 'get-signature' exchange even if we are not providing a signature
        jade_process_load_in_message(process, true);
        if (!IS_CURRENT_MESSAGE(process, "get_signature")) {
            // Protocol error
            jade_process_reject_message(
                process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'get_signature'", NULL);
            goto cleanup;
        }

        if (input_data->path_len > 0) {
            // We are expecting to generate a signature for this input
            GET_MSG_PARAMS(process);

            const uint8_t* ae_host_entropy = NULL;
            size_t ae_host_entropy_len = 0;

            // Fetch any host entropy to include in the signature.
            rpc_get_bytes_ptr("ae_host_entropy", &params, &ae_host_entropy, &ae_host_entropy_len);
            if (ae_host_entropy_len && ae_host_entropy_len != WALLY_S2C_DATA_LEN) {
                jade_process_reject_message(
                    process, CBOR_RPC_PROTOCOL_ERROR, "Failed to extract valid host entropy from parameters", NULL);
                goto cleanup;
            }
            const bool use_ae = ae_host_entropy_len != 0;
            if (input_data->use_ae != use_ae) {
                // We must be given both a commitment and entropy, or neither.
                jade_process_reject_message(process, CBOR_RPC_PROTOCOL_ERROR,
                    "Failed to extract valid host commitment and entropy from parameters", NULL);
                goto cleanup;
            }

            // Generate Anti-Exfil, non-AE ECDSA or non-AE Schnorr signature
            if (!wallet_sign_tx_input_hash(input_data, ae_host_entropy, ae_host_entropy_len)) {
                jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to sign tx input", NULL);
                goto cleanup;
            }
            JADE_ASSERT(input_data->sig_len > 0);
        }

        // Send signature reply - will be empty for any inputs we are not signing
        const bytes_info_t bytes_info = { .data = input_data->sig, .size = input_data->sig_len };
        jade_process_reply_to_message_result(process->ctx, &bytes_info, cbor_result_bytes_cb);
    }
cleanup:
    (void)process; /* No-op for label */
}

// The backward compatible 'send all messages in a batch' method for standard EC signatures.
// NOTE: should be converted to the same message flow as above, at some point.
void send_ec_signature_replies(const jade_msg_source_t source, signing_data_t* signing_data)
{
    JADE_ASSERT(signing_data);
    JADE_ASSERT(signing_data->num_inputs > 0);

    uint8_t msgbuf[256];
    for (size_t i = 0; i < signing_data->num_inputs; ++i) {
        input_data_t* const input_data = &signing_data->inputs[i];

        if (input_data->path_len > 0) {
            // Generate EC signature
            if (!wallet_sign_tx_input_hash(input_data, NULL, 0)) {
                jade_process_reject_message_with_id(input_data->id, CBOR_RPC_INTERNAL_ERROR, "Failed to sign tx input",
                    NULL, 0, msgbuf, sizeof(msgbuf), source);
                return;
            }
            JADE_ASSERT(input_data->sig_len > 0);
        }
    }

    // Now send all signatures - one per message - in reply to input messages
    // Will be empty for any inputs we are not signing
    for (size_t i = 0; i < signing_data->num_inputs; ++i) {
        input_data_t* const input_data = &signing_data->inputs[i];

        const bytes_info_t bytes_info = { .data = input_data->sig, .size = input_data->sig_len };
        jade_process_reply_to_message_result_with_id(
            input_data->id, msgbuf, sizeof(msgbuf), source, &bytes_info, cbor_result_bytes_cb);
    }
}

// Whether or not a sighash type is valid for BTC.
// NOTE: atm we only accept 'SIGHASH_ALL', or SIGHASH_DEFAULT for p2tr
static bool is_valid_btc_sig_type(const input_data_t* const input_data)
{
    if (input_data->sig_type == WALLY_SIGTYPE_SW_V1) {
        return input_data->sighash == WALLY_SIGHASH_DEFAULT || input_data->sighash == WALLY_SIGHASH_ALL;
    }
    return input_data->sighash == WALLY_SIGHASH_ALL;
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
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_tx");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);
    if (isLiquidNetworkId(network_id)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "sign_tx call not appropriate for liquid network", NULL);
        goto cleanup;
    }
    const jade_msg_source_t source = process->ctx.source;

    size_t written = 0;
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
    jade_process_call_on_exit(process, jade_wally_free_tx_wrapper, tx);

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

    // Can optionally be passed info for wallet outputs, which we verify internally
    // NOTE: Element named 'change' for backward-compatibility reasons
    CborValue wallet_outputs;
    if (rpc_get_array("change", &params, &wallet_outputs)) {
        output_info = JADE_CALLOC(tx->num_outputs, sizeof(output_info_t));
        jade_process_free_on_exit(process, output_info);

        if (!validate_wallet_outputs(process, network_id, tx, &wallet_outputs, output_info, &errmsg)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
            goto cleanup;
        }
    }

    // User to confirm
    if (!show_btc_transaction_outputs_activity(network_id, tx, output_info)) {
        JADE_LOGW("User declined to sign transaction");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign transaction", NULL);
        goto cleanup;
    }

    JADE_LOGD("User accepted outputs");
    display_processing_message_activity();

    // Send ok - client should send inputs
    jade_process_reply_to_message_ok(process);

    // We generate the hashes for each input but defer signing them
    // until after the final user confirmation.  Hold them in a struct for
    // ease of cleanup if something goes wrong part-way through.
    signing_data_t* const signing_data = signing_data_allocate(num_inputs);
    jade_process_call_on_exit(process, signing_data_free, signing_data);

    // We track if the type of the inputs we are signing changes (ie. single-sig vs
    // green/multisig/other) so we can show a warning to the user if so.
    script_flavour_t aggregate_inputs_scripts_flavour = SCRIPT_FLAVOUR_NONE;

    // Run through each input message and generate a signature-hash for each one
    uint64_t input_amount = 0;

    uint32_t num_to_sign = 0; // Total number of inputs to sign
    uint32_t num_p2tr_to_sign = 0; // Total number of p2tr inputs to sign

    // Loop to fetch data for and validate all inputs
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

        // Store the signing data so we can free the (potentially large) input message.
        // Signatures will be generated and replies sent after user confirmation.
        // Reply is our signature for the input, or an empty string if we are not
        // signing this input (ie. if no path was passed for this input).
        written = 0;
        input_data_t* const input_data = &signing_data->inputs[index];
        rpc_get_id(&process->ctx.value, input_data->id, sizeof(input_data->id), &written);
        JADE_ASSERT(written != 0);

        // Path node can be omitted if we don't want to sign this input
        // (But if passed must be valid - empty/root path is not allowed for signing)
        const bool has_path = rpc_has_field_data("path", &params);
        if (has_path) {
            num_to_sign += 1;

            // Get all common tx-signing input fields which must be present if a path is given
            if (!params_tx_input_signing_data(use_ae_signatures, &params, input_data, &ae_host_commitment,
                    &ae_host_commitment_len, &script, &script_len, &aggregate_inputs_scripts_flavour, &errmsg)) {
                jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
                goto cleanup;
            }
            if (!is_valid_btc_sig_type(input_data)) {
                jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Unsupported sighash value", NULL);
                goto cleanup;
            }
            if (input_data->sig_type == WALLY_SIGTYPE_SW_V1) {
                num_p2tr_to_sign += 1;
            }
        } else {
            // May still need witness flag
            bool is_witness = false;
            rpc_get_boolean("is_witness", &params, &is_witness);
            input_data->sig_type = is_witness ? WALLY_SIGTYPE_SW_V0 : WALLY_SIGTYPE_PRE_SW;
            input_data->sighash = WALLY_SIGHASH_ALL;
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

            // Fetch the amount and scriptpubkey from the passed input tx
            const struct wally_tx_output* const txout = &input_tx->outputs[tx->inputs[index].index];
            res = wally_map_add_integer(&signing_data->scriptpubkeys, index, txout->script, txout->script_len);
            if (res == WALLY_OK) {
                res = wally_map_add_integer(&signing_data->amounts, index, (uint8_t*)&txout->satoshi, sizeof(uint64_t));
                // Keep a running total
                input_amount += txout->satoshi;
            }
            if (res != WALLY_OK) {
                jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract prevout", NULL);
                JADE_WALLY_VERIFY(wally_tx_free(input_tx));
                goto cleanup;
            }

            // Free the (potentially large) txn immediately
            JADE_WALLY_VERIFY(wally_tx_free(input_tx));
        } else {
            // For single segwit v0 inputs we can instead get just the amount
            // directly from message. This optimization is deprecated and will
            // be removed in a future firmware release.
            if (input_data->sig_type != WALLY_SIGTYPE_SW_V0 || num_inputs > 1) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract input_tx from parameters", NULL);
                goto cleanup;
            }

            JADE_LOGD("Single witness input - using explicitly passed amount");

            // Get the amount
            uint64_t satoshi;
            if (!rpc_get_uint64_t("satoshi", &params, &satoshi)) {
                res = WALLY_EINVAL;
            } else {
                res = wally_map_add_integer(&signing_data->amounts, index, (uint8_t*)&satoshi, sizeof(uint64_t));
                // Keep a running total
                input_amount += satoshi;
            }
            if (res != WALLY_OK) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract satoshi from parameters", NULL);
                goto cleanup;
            }
        }

        bool made_ae_commitment = false;

        if (has_path && input_data->sig_type == WALLY_SIGTYPE_SW_V1) {
            // We have been given a path, so are expected to sign this input.
            // We can't compute a taproot signature hash until we have all
            // values and scriptpubkeys - do nothing here and do taproot
            // processing below after this initial loop instead.
            // Taproot Schnorr signatures do not support Anti-Exfil, so we
            // skip creating a signer commitment here as well.
            if (!use_ae_signatures) {
                jade_process_reject_message(
                    process, CBOR_RPC_INTERNAL_ERROR, "Taproot signing requires Anti-exfil flow", NULL);
                goto cleanup;
            }
        } else if (has_path) {
            // We have been given a path, so are expected to sign this input.
            // Generate the signature hash of this input which we will sign later
            if (!wallet_get_tx_input_hash(tx, index, signing_data, script, script_len)) {
                jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to make tx input hash", NULL);
                goto cleanup;
            }

            // If using anti-exfil signatures for this input,
            // compute signer commitment for returning to caller
            if (input_data->use_ae) {
                JADE_ASSERT(ae_host_commitment);
                if (!wallet_get_signer_commitment(input_data->signature_hash, sizeof(input_data->signature_hash),
                        input_data->path, input_data->path_len, ae_host_commitment, ae_host_commitment_len,
                        ae_signer_commitment, sizeof(ae_signer_commitment))) {
                    jade_process_reject_message(
                        process, CBOR_RPC_INTERNAL_ERROR, "Failed to make ae signer commitment", NULL);
                    goto cleanup;
                }
                made_ae_commitment = true;
            }
        } else {
            // Empty byte-string reply (no path given implies no sig needed or expected)
            JADE_ASSERT(!script);
            JADE_ASSERT(script_len == 0);
            JADE_ASSERT(input_data->path_len == 0);
        }

        // Check/log a running total
        if (input_amount > UINT32_MAX) {
            JADE_LOGD("input_amount over UINT32_MAX, truncated low = %" PRIu32 " high %" PRIu32, (uint32_t)input_amount,
                (uint32_t)(input_amount >> 32));
        } else {
            JADE_LOGD("input_amount = %" PRIu32, (uint32_t)input_amount);
        }

        // If using ae-signatures, reply with the (possibly empty) signer commitment
        // FIXME: change message flow to reply here even when not using ae-signatures
        // as this simplifies the code both here and in the client.
        if (use_ae_signatures) {
            uint8_t buffer[256];
            const size_t commitment_len = made_ae_commitment ? sizeof(ae_signer_commitment) : 0;
            jade_process_reply_to_message_bytes(
                process->ctx, ae_signer_commitment, commitment_len, buffer, sizeof(buffer));
        }
    }

    // Loop to process any taproot inputs now that we have all input
    // amounts and scriptpubkeys
    for (size_t index = 0; num_p2tr_to_sign != 0 && index < num_inputs; ++index) {
        input_data_t* const input_data = &signing_data->inputs[index];
        if (input_data->sig_type != WALLY_SIGTYPE_SW_V1 || !input_data->path_len) {
            // Not signing this input
            continue;
        }
        if (!wallet_get_tx_input_hash(tx, index, signing_data, NULL, 0)) {
            // We are using ae-signatures, so we need to load the message to send the error back on
            jade_process_load_in_message(process, true);
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to make taproot tx input hash", NULL);
            goto cleanup;
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

    // User to agree fee amount
    // If user cancels we'll send the 'cancelled' error response for the last input message only
    if (!show_btc_fee_confirmation_activity(
            tx, output_info, aggregate_inputs_scripts_flavour, input_amount, output_amount)) {
        // If using ae-signatures, we need to load the message to send the error back on
        if (use_ae_signatures) {
            jade_process_load_in_message(process, true);
        }
        JADE_LOGW("User declined to sign transaction");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign transaction", NULL);
        goto cleanup;
    }

    JADE_LOGD("User accepted fee");

    // Show warning if nothing to sign
    if (num_to_sign == 0) {
        const char* message[] = { "There are no relevant", "inputs to be signed" };
        await_message_activity(message, 2);
    }

    display_processing_message_activity();

    // Send signature replies.
    // NOTE: currently we have two message flows - the backward compatible version
    // for normal EC signatures, and the new flow required for Anti-Exfil signatures.
    // Once we have migrated the companion applications onto AE signatures we should
    // convert normal EC signatures to use the new/improved message flow.
    if (use_ae_signatures) {
        // Generate and send Anti-Exfil signature replies
        send_ae_signature_replies(process, signing_data);
    } else {
        // Generate and send standard EC signature replies
        send_ec_signature_replies(source, signing_data);
    }
    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
