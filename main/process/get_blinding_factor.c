#include "../jade_assert.h"
#include "../process.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"

#include <wally_elements.h>

#include "process_utils.h"

void get_blinding_factor_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_blinding_factor");
    GET_MSG_PARAMS(process);

    // needed to generate the blinding factors deterministically
    uint32_t hash_prevouts_len = 0;
    const uint8_t* hash_prevouts = NULL;
    rpc_get_bytes_ptr("hash_prevouts", &params, &hash_prevouts, &hash_prevouts_len);
    if (hash_prevouts_len != SHA256_LEN) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract hash_prevouts from parameters", NULL);
        goto cleanup;
    }

    uint32_t output_index = 0;
    bool retval = rpc_get_sizet("output_index", &params, &output_index);
    if (!retval) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract output index from parameters", NULL);
        goto cleanup;
    }

    char type_str[8];
    size_t written = 0;
    rpc_get_string("type", sizeof(type_str), &params, type_str, &written);
    if (written == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Cannot extract blinding factor type from parameters", NULL);
        goto cleanup;
    }

    // Map type
    uint8_t type = 0;
    if (strcmp("ASSET", type_str) == 0) {
        type = ASSET_BLINDING_FACTOR;
    } else if (strcmp("VALUE", type_str) == 0) {
        type = VALUE_BLINDING_FACTOR;
    } else {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Invalid blinding factor type - must be either 'ASSET' or 'VALUE'", NULL);
        goto cleanup;
    }

    unsigned char result_bytes[HMAC_SHA256_LEN];
    if (!wallet_get_blinding_factor(
            hash_prevouts, hash_prevouts_len, output_index, type, result_bytes, sizeof(result_bytes))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Cannot get blinding factor for output", NULL);
        goto cleanup;
    }

    uint8_t buffer[256];
    jade_process_reply_to_message_bytes(process->ctx, result_bytes, sizeof(result_bytes), buffer, sizeof(buffer));
    JADE_LOGI("Success");

cleanup:
    return;
}
