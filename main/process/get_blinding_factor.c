#include "../jade_assert.h"
#include "../keychain.h"
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
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    const char* errmsg = NULL;

    // hash-prevouts and output index are needed to generate deterministic blinding factors
    size_t hash_prevouts_len = 0;
    const uint8_t* hash_prevouts = NULL;
    size_t output_index = 0;
    if (!params_hashprevouts_outputindex(&params, &hash_prevouts, &hash_prevouts_len, &output_index, &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
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

    uint8_t master_blinding_key[HMAC_SHA512_LEN];
    if (!params_get_master_blindingkey(&params, master_blinding_key, sizeof(master_blinding_key), &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
        goto cleanup;
    }

    uint8_t blinding_factor[HMAC_SHA256_LEN];
    if (!wallet_get_blinding_factor(master_blinding_key, sizeof(master_blinding_key), hash_prevouts, hash_prevouts_len,
            output_index, type, blinding_factor, sizeof(blinding_factor))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Cannot get blinding factor for output", NULL);
        goto cleanup;
    }

    uint8_t buffer[256];
    jade_process_reply_to_message_bytes(process->ctx, blinding_factor, sizeof(blinding_factor), buffer, sizeof(buffer));
    JADE_LOGI("Success");

cleanup:
    return;
}
