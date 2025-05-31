#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include "process_utils.h"

void get_master_blinding_key_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_master_blinding_key");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);

    // Ask the user if necessary
    if (keychain_get_confirm_export_blinding_key()) {
        // Optional field to suppress asking user for permission and instead
        // error in the cases where we would normally need to ask the user.
        bool onlyIfSilent = false;

        CborValue params;
        const CborError cberr = cbor_value_map_find_value(&process->ctx.value, CBOR_RPC_TAG_PARAMS, &params);
        if (cberr == CborNoError || cbor_value_is_valid(&params) || cbor_value_is_map(&params)) {
            rpc_get_boolean("only_if_silent", &params, &onlyIfSilent);
        }

        const char* question[] = { "Export master", "blinding key?" };
        if (onlyIfSilent || !await_yesno_activity("Blinding Key", question, 2, true, "blkstrm.com/blindingkey")) {
            JADE_LOGW("User declined to export master blinding key");
            jade_process_reject_message(
                process, CBOR_RPC_USER_CANCELLED, "User declined to export master blinding key");
            goto cleanup;
        }
        JADE_LOGD("User pressed accept");
    }

    // NOTE: 'master_unblinding_key' is stored here as the full output of hmac512, when according to slip-0077
    // the master unblinding key is only the second half of that - ie. 256 bits
    // So we only return the relevant slice of the data.
    JADE_STATIC_ASSERT(sizeof(keychain_get()->master_unblinding_key) == HMAC_SHA512_LEN);

    uint8_t buffer[256];
    jade_process_reply_to_message_bytes(process->ctx, keychain_get()->master_unblinding_key + HMAC_SHA512_LEN / 2,
        HMAC_SHA512_LEN / 2, buffer, sizeof(buffer));
    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
