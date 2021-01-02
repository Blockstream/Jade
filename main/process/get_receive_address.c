#include "../jade_assert.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/address.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"
#include "../wallet.h"

#include "../button_events.h"

#include <esp_event.h>

#include <string.h>

#include "process_utils.h"

void get_receive_address_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char network[strlen(TAG_LOCALTESTLIQUID) + 1];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_receive_address");
    GET_MSG_PARAMS(process);

    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);

    if (written == 0 || !isValidNetwork(network)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid network from parameters", NULL);
        goto cleanup;
    }

    // Subaccount, branch and pointer passed in message
    uint32_t subaccount = 0, branch = 0, pointer = 0;
    if (!rpc_get_sizet("subaccount", &params, &subaccount) || !rpc_get_sizet("branch", &params, &branch)
        || !rpc_get_sizet("pointer", &params, &pointer)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract path elements from parameters", NULL);
        goto cleanup;
    }

    uint32_t path[4]; // Sufficient for all green-address paths
    size_t path_len = 0;
    wallet_build_receive_path(subaccount, branch, pointer, path, sizeof(path), &path_len);

    // Optional xpub for 2of3 accounts
    written = 0;
    char xpubrecovery[120];
    rpc_get_string("recovery_xpub", sizeof(xpubrecovery), &params, xpubrecovery, &written);

    // Optional 'blocks' for csv outputs
    uint32_t csvBlocks = 0;
    rpc_get_sizet("csv_blocks", &params, &csvBlocks);

    // Build a greenaddress script pubkey for the passed parameters
    unsigned char script[WALLY_SCRIPTPUBKEY_P2SH_LEN];
    if (!wallet_build_receive_script(
            network, !written ? NULL : xpubrecovery, csvBlocks, path, path_len, script, sizeof(script))) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to generate valid green address script", NULL);
        goto cleanup;
    }

    // Convert that into an address string
    char address[MAX_ADDRESS_LEN];
    if (isLiquid(network)) {
        // Blind address
        unsigned char blinding_key[EC_PUBLIC_KEY_LEN];
        if (!wallet_get_public_blinding_key(script, sizeof(script), blinding_key, sizeof(blinding_key))) {
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Cannot get blinding key for script", NULL);
            goto cleanup;
        }
        elements_script_to_address(
            network, script, sizeof(script), blinding_key, sizeof(blinding_key), address, sizeof(address));
    } else {
        script_to_address(network, script, sizeof(script), address, sizeof(address));
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
