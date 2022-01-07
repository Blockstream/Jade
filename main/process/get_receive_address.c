#include "../jade_assert.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../process.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/address.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"
#include "../wallet.h"

#include "../button_events.h"

#include <esp_event.h>

#include "process_utils.h"

void get_receive_address_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char network[MAX_NETWORK_NAME_LEN];
    char multisig_name[MAX_MULTISIG_NAME_SIZE];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_receive_address");
    GET_MSG_PARAMS(process);

    // Check network is valid and consistent with prior usage
    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);

    // Handle single-sig and generic multisig script variants
    // (Green-multisig is the default for backwards compatibility)
    size_t script_len = 0;
    unsigned char script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient for all scripts

    char warning_msg_text[128];
    const char* warning_msg = NULL;

    if (rpc_has_field_data("multisig_name", &params)) {
        if (isLiquidNetwork(network)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Multisig is not supported for liquid networks", NULL);
            goto cleanup;
        }

        written = 0;
        rpc_get_string("multisig_name", sizeof(multisig_name), &params, multisig_name, &written);
        if (written == 0) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Missing or invalid multisig name parameter", NULL);
            goto cleanup;
        }

        multisig_data_t multisig_data = { 0 };
        const char* errmsg = NULL;
        if (!multisig_load_from_storage(multisig_name, &multisig_data, &errmsg)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
            goto cleanup;
        }

        CborValue all_signer_paths;
        const bool is_change = false;
        bool all_paths_as_expected;
        if (!rpc_get_array("paths", &params, &all_signer_paths)
            || !multisig_validate_paths(is_change, &all_signer_paths, &all_paths_as_expected)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract signer paths from parameters", NULL);
            goto cleanup;
        }

        // If paths not as expected show a warning message with the address
        if (!all_paths_as_expected) {
            const int ret = snprintf(
                warning_msg_text, sizeof(warning_msg_text), "Warning: Unusual path suffix for multisig address");
            JADE_ASSERT(ret > 0 && ret < sizeof(warning_msg_text));
            warning_msg = warning_msg_text;
        }

        written = 0;
        uint8_t pubkeys[MAX_MULTISIG_SIGNERS * EC_PUBLIC_KEY_LEN]; // Sufficient
        if (!multisig_get_pubkeys(
                multisig_data.xpubs, multisig_data.xpubs_len, &all_signer_paths, pubkeys, sizeof(pubkeys), &written)
            || written != multisig_data.xpubs_len * EC_PUBLIC_KEY_LEN) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS,
                "Unexpected number of signer paths or invalid path for multisig", NULL);
            goto cleanup;
        }

        // Build a script pubkey for the passed parameters
        if (!wallet_build_multisig_script(network, multisig_data.variant, multisig_data.sorted, multisig_data.threshold,
                pubkeys, written, script, sizeof(script), &script_len)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to generate valid multisig script", NULL);
            goto cleanup;
        }
    } else {
        uint32_t path[MAX_PATH_LEN];
        size_t path_len = 0;
        const size_t max_path_len = sizeof(path) / sizeof(path[0]);

        char variant[MAX_VARIANT_LEN];
        script_variant_t script_variant;

        // Green-multisig is the default (for backwards compatibility) if no variant passed
        written = 0;
        rpc_get_string("variant", sizeof(variant), &params, variant, &written);
        if (!get_script_variant(variant, written, &script_variant)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid script variant parameter", NULL);
            goto cleanup;
        }

        if (is_greenaddress(script_variant)) {
            // For green-multisig the path is constructed from subaccount, branch and pointer
            uint32_t subaccount = 0, branch = 0, pointer = 0;
            if (!rpc_get_sizet("subaccount", &params, &subaccount) || !rpc_get_sizet("branch", &params, &branch)
                || !rpc_get_sizet("pointer", &params, &pointer)) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract path elements from parameters", NULL);
                goto cleanup;
            }
            wallet_build_receive_path(subaccount, branch, pointer, path, max_path_len, &path_len);

            // Optional xpub for 2of3 accounts
            written = 0;
            char xpubrecovery[120];
            rpc_get_string("recovery_xpub", sizeof(xpubrecovery), &params, xpubrecovery, &written);

            // Optional 'blocks' for csv outputs
            uint32_t csvBlocks = 0;
            rpc_get_sizet("csv_blocks", &params, &csvBlocks);

            if (csvBlocks && !csvBlocksExpectedForNetwork(network, csvBlocks)) {
                const int ret = snprintf(warning_msg_text, sizeof(warning_msg_text),
                    "This output has a non-standard csv value (%u), so it may be difficult to find.  Proceed at "
                    "your own risk.",
                    csvBlocks);
                JADE_ASSERT(ret > 0 && ret < sizeof(warning_msg_text));
                warning_msg = warning_msg_text;
            }

            // Build a script pubkey for the passed parameters
            if (!wallet_build_ga_script(network, written ? xpubrecovery : NULL, csvBlocks, path, path_len, script,
                    sizeof(script), &script_len)) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to generate valid green address script", NULL);
                goto cleanup;
            }
        } else if (is_singlesig(script_variant)) {
            // For single-sig the path is explicit in the params
            rpc_get_bip32_path("path", &params, path, max_path_len, &path_len);
            if (path_len == 0) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid path from parameters", NULL);
                goto cleanup;
            }

            // If paths not as expected show a warning message with the address
            const bool is_change = false;
            if (!wallet_is_expected_singlesig_path(network, script_variant, is_change, path, path_len)) {
                char path_str[96];
                if (!bip32_path_as_str(path, path_len, path_str, sizeof(path_str))) {
                    jade_process_reject_message(
                        process, CBOR_RPC_INTERNAL_ERROR, "Failed to convert path to string format", NULL);
                    goto cleanup;
                }
                const int ret
                    = snprintf(warning_msg_text, sizeof(warning_msg_text), "Warning: Unusual path: %s", path_str);
                JADE_ASSERT(ret > 0 && ret < sizeof(warning_msg_text));
                warning_msg = warning_msg_text;
            }

            // Build a script pubkey for the passed parameters
            if (!wallet_build_singlesig_script(
                    network, script_variant, path, path_len, script, sizeof(script), &script_len)) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to generate valid singlesig script", NULL);
                goto cleanup;
            }
        } else {
            // Multisig handled above, so should be nothing left
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Unhandled script variant", NULL);
            goto cleanup;
        }
    }

    // Convert that into an address string
    JADE_ASSERT(script_len > 0);
    char address[MAX_ADDRESS_LEN];
    if (isLiquidNetwork(network)) {
        bool confidential = true; // default to confidential addresses for liquid
        rpc_get_boolean("confidential", &params, &confidential);

        if (confidential) {
            // Blind address
            unsigned char blinding_key[EC_PUBLIC_KEY_LEN];
            if (!wallet_get_public_blinding_key(script, script_len, blinding_key, sizeof(blinding_key))) {
                jade_process_reject_message(
                    process, CBOR_RPC_INTERNAL_ERROR, "Cannot get blinding key for script", NULL);
                goto cleanup;
            }
            elements_script_to_address(
                network, script, script_len, blinding_key, sizeof(blinding_key), address, sizeof(address));
        } else {
            elements_script_to_address(network, script, script_len, NULL, 0, address, sizeof(address));
        }
    } else {
        bool confidential = false;
        rpc_get_boolean("confidential", &params, &confidential);
        if (confidential) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Confidential addresses only apply to liquid network", NULL);
            goto cleanup;
        }
        script_to_address(network, script, script_len, address, sizeof(address));
    }

    // Display to the user to confirm
    gui_activity_t* activity;
    make_confirm_address_activity(&activity, address, warning_msg);
    JADE_ASSERT(activity);
    gui_set_current_activity(activity);

    int32_t ev_id;
    // In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const bool ret = true;
    ev_id = BTN_ACCEPT_ADDRESS;
#endif

    // Check to see whether user accepted or declined
    if (!ret || ev_id != BTN_ACCEPT_ADDRESS) {
        JADE_LOGW("User declined to confirm address");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to confirm address", NULL);
        goto cleanup;
    }
    JADE_LOGD("User pressed accept");

    // Reply with the address
    jade_process_reply_to_message_result(process->ctx, address, cbor_result_string_cb);

    JADE_LOGI("Success");

cleanup:
    return;
}
