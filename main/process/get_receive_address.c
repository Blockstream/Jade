#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
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

    char network[strlen(TAG_LOCALTESTLIQUID) + 1];
    char variant[16];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_receive_address");
    GET_MSG_PARAMS(process);

    // Check network is valid and consistent with prior usage
    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);

    // Handle script variants.
    // (Green-multisig is the default for backwards compatibility)
    written = 0;
    script_variant_t script_variant;
    rpc_get_string("variant", sizeof(variant), &params, variant, &written);
    if (!get_script_variant(variant, written, &script_variant)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid script variant parameter", NULL);
        goto cleanup;
    }

    uint32_t path[MAX_PATH_LEN];
    size_t path_len = 0;
    const size_t max_path_len = sizeof(path) / sizeof(path[0]);

    if (script_variant == GREEN) {
        // For green-multisig the path is constructed from subaccount, branch and pointer
        uint32_t subaccount = 0, branch = 0, pointer = 0;
        if (!rpc_get_sizet("subaccount", &params, &subaccount) || !rpc_get_sizet("branch", &params, &branch)
            || !rpc_get_sizet("pointer", &params, &pointer)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract path elements from parameters", NULL);
            goto cleanup;
        }

        wallet_build_receive_path(subaccount, branch, pointer, path, max_path_len, &path_len);
    } else {
        // Otherwise the path is explicit in the params
        rpc_get_bip32_path("path", &params, path, max_path_len, &path_len);
        if (path_len == 0) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid path from parameters", NULL);
            goto cleanup;
        }
    }

    // Optional xpub for 2of3 accounts
    written = 0;
    char xpubrecovery[120];
    rpc_get_string("recovery_xpub", sizeof(xpubrecovery), &params, xpubrecovery, &written);

    // Optional 'blocks' for csv outputs
    uint32_t csvBlocks = 0;
    rpc_get_sizet("csv_blocks", &params, &csvBlocks);

    // Build a script pubkey for the passed parameters
    size_t script_len = 0;
    unsigned char script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient for all scripts
    if (!wallet_build_receive_script(network, script_variant, written ? xpubrecovery : NULL, csvBlocks, path, path_len,
            script, sizeof(script), &script_len)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to generate valid green address script", NULL);
        goto cleanup;
    }

    // Convert that into an address string
    char address[MAX_ADDRESS_LEN];
    if (isLiquidNetwork(network)) {
        // Blind address
        unsigned char blinding_key[EC_PUBLIC_KEY_LEN];
        if (!wallet_get_public_blinding_key(script, script_len, blinding_key, sizeof(blinding_key))) {
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Cannot get blinding key for script", NULL);
            goto cleanup;
        }
        elements_script_to_address(
            network, script, script_len, blinding_key, sizeof(blinding_key), address, sizeof(address));
    } else {
        script_to_address(network, script, script_len, address, sizeof(address));
    }

    // Display to the user to confirm
    gui_activity_t* activity;
    make_confirm_address_activity(&activity, address);
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
