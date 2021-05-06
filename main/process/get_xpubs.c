#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"
#include "../wallet.h"

#include "process_utils.h"

static void wally_free_string_wrapper(void* str) { wally_free_string((char*)str); }

void get_xpubs_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char network[strlen(TAG_LOCALTESTLIQUID) + 1];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_xpub");
    GET_MSG_PARAMS(process);

    // Check network is valid and consistent with prior usage
    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);

    // NOTE: for get-xpub accessing the root key (empty bip32 path array) *IS* allowed.
    written = 0;
    uint32_t path[MAX_PATH_LEN];
    const bool has_path = rpc_get_bip32_path("path", &params, path, MAX_PATH_LEN, &written);
    if (!has_path) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid path from parameters", NULL);
        goto cleanup;
    }

    char* output = NULL;
    if (!wallet_get_xpub(network, path, written, &output) || !output) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Cannot get xpub for path", NULL);
        goto cleanup;
    }
    jade_process_call_on_exit(process, wally_free_string_wrapper, output);
    jade_process_reply_to_message_result(process->ctx, output, cbor_result_string_cb);

    JADE_LOGI("Success");

cleanup:
    return;
}
