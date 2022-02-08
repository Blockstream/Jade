#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include "../button_events.h"

#include "../identity.h"
#include "process_utils.h"

void get_identity_shared_key_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_identity_shared_key");
    GET_MSG_PARAMS(process);

    const char* identity = NULL;
    size_t identity_len = 0;
    rpc_get_string_ptr("identity", &params, &identity, &identity_len);
    if (!identity || identity_len >= MAX_DISPLAY_MESSAGE_LEN || !is_identity_protocol_valid(identity, identity_len)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid identity from parameters", NULL);
        goto cleanup;
    }

    const char* curve = NULL;
    size_t curve_len = 0;
    rpc_get_string_ptr("curve", &params, &curve, &curve_len);
    if (!curve || !is_identity_curve_valid(curve, curve_len)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid curve name from parameters", NULL);
        goto cleanup;
    }

    const uint8_t* their_pubkey = NULL;
    size_t their_pubkey_len = 0;
    rpc_get_bytes_ptr("their_pubkey", &params, &their_pubkey, &their_pubkey_len);
    if (!their_pubkey || their_pubkey_len != EC_PUBLIC_KEY_UNCOMPRESSED_LEN) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid pubkey from parameters", NULL);
        goto cleanup;
    }

    // Index is optional
    size_t index = 0;
    if (rpc_has_field_data("index", &params)) {
        if (!rpc_get_sizet("index", &params, &index)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid index from parameters", NULL);
            goto cleanup;
        }
    }

    // Check keychain has seed data
    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.  Wallet must be re-initialised from mnemonic.");
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Feature requires resetting Jade", NULL);
        await_error_activity("Feature requires resetting Jade");
        goto cleanup;
    }

    // Get identity pubkey - Note we use uncompressed keys in this api
    uint8_t shared_key[SHA256_LEN];
    if (!get_identity_shared_key(identity, identity_len, index, curve, curve_len, their_pubkey, their_pubkey_len,
            shared_key, sizeof(shared_key))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to get identity pubkey", NULL);
        goto cleanup;
    }

    // Return pubkey to caller
    uint8_t buffer[256];
    jade_process_reply_to_message_bytes(process->ctx, shared_key, sizeof(shared_key), buffer, sizeof(buffer));

    JADE_LOGI("Success");

cleanup:
    return;
}
