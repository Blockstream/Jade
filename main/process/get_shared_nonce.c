#include "../jade_assert.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"

#include <string.h>

#include "process_utils.h"

void get_shared_nonce_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_shared_nonce");
    GET_MSG_PARAMS(process);

    size_t script_len = 0;
    const uint8_t* script = NULL;
    rpc_get_bytes_ptr("script", &params, &script, &script_len);
    if (!script || script_len <= 0) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract script from parameters", NULL);
        goto cleanup;
    }

    size_t their_pubkey_len = 0;
    const uint8_t* their_pubkey = NULL;
    rpc_get_bytes_ptr("their_pubkey", &params, &their_pubkey, &their_pubkey_len);
    if (!their_pubkey || their_pubkey_len != EC_PUBLIC_KEY_LEN) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract their_pubkey from parameters", NULL);
        goto cleanup;
    }

    // get nonce and pre-hash so we can use it directly to unblind later
    unsigned char shared_nonce[SHA256_LEN];
    unsigned char shared_nonce_hash[SHA256_LEN];
    if (!wallet_get_shared_nonce(script, script_len, their_pubkey, their_pubkey_len, shared_nonce, sizeof(shared_nonce))
        || wally_sha256(shared_nonce, sizeof(shared_nonce), shared_nonce_hash, sizeof(shared_nonce_hash)) != WALLY_OK) {
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Failed to compute hashed shared nonce value for the parameters", NULL);
        goto cleanup;
    }

    uint8_t buffer[256];
    jade_process_reply_to_message_bytes(
        process->ctx, shared_nonce_hash, sizeof(shared_nonce_hash), buffer, sizeof(buffer));
    JADE_LOGI("Success");

cleanup:
    return;
}
