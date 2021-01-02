#include "../jade_assert.h"
#include "../process.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"

#include <string.h>

#include "process_utils.h"

void get_blinding_key_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_blinding_key");
    GET_MSG_PARAMS(process);

    size_t script_len = 0;
    const uint8_t* script = NULL;
    rpc_get_bytes_ptr("script", &params, &script, &script_len);
    if (!script || script_len <= 0) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract script from parameters", NULL);
        goto cleanup;
    }

    unsigned char public_blinding_key[EC_PUBLIC_KEY_LEN];
    if (!wallet_get_public_blinding_key(script, script_len, public_blinding_key, sizeof(public_blinding_key))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Cannot get blinding key for script", NULL);
        goto cleanup;
    }

    uint8_t buffer[256];
    jade_process_reply_to_message_bytes(process->ctx, public_blinding_key, EC_PUBLIC_KEY_LEN, buffer, sizeof(buffer));
    JADE_LOGI("Success");

cleanup:
    return;
}
