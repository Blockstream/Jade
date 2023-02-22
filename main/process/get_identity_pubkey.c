#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include "../button_events.h"

#include "../identity.h"
#include "process_utils.h"

void get_identity_pubkey_process(void* process_ptr)
{
    JADE_LOGI("Starting: %lu", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_identity_pubkey");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    const char* errmsg = NULL;

    const char* identity = NULL;
    size_t identity_len = 0;
    const char* curve = NULL;
    size_t curve_len = 0;
    size_t index = 0;
    if (!params_identity_curve_index(&params, &identity, &identity_len, &curve, &curve_len, &index, &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
        goto cleanup;
    }

    const char* type = NULL;
    size_t type_len = 0;
    rpc_get_string_ptr("type", &params, &type, &type_len);
    if (!type || !is_key_type_valid(type, type_len)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid key type from parameters", NULL);
        goto cleanup;
    }

    // Check keychain has seed data
    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.  Wallet must be re-initialised from mnemonic.");
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Feature requires resetting Jade", NULL);
        await_error_activity("Feature requires Jade reset");
        goto cleanup;
    }

    // Get identity pubkey - Note we use uncompressed keys in this api
    uint8_t pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    if (!get_identity_pubkey(identity, identity_len, index, curve, curve_len, type, type_len, pubkey, sizeof(pubkey))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to get identity pubkey", NULL);
        goto cleanup;
    }

    // Return pubkey to caller
    uint8_t buffer[256];
    jade_process_reply_to_message_bytes(process->ctx, pubkey, sizeof(pubkey), buffer, sizeof(buffer));

    JADE_LOGI("Success");

cleanup:
    return;
}
