#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"

#include "process_utils.h"

typedef struct {
    const uint8_t* shared_nonce;
    const size_t shared_nonce_len;
    const uint8_t* pubkey;
    const size_t pubkey_len;
} nonce_pubkey_data_t;

static void reply_nonce_and_pubkey(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);

    const nonce_pubkey_data_t* data = (const nonce_pubkey_data_t*)ctx;
    JADE_ASSERT(data->shared_nonce_len == SHA256_LEN);
    JADE_ASSERT(data->pubkey_len == EC_PUBLIC_KEY_LEN);

    CborEncoder result_encoder;
    CborError cberr = cbor_encoder_create_map(container, &result_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&result_encoder, "shared_nonce", data->shared_nonce, data->shared_nonce_len);
    add_bytes_to_map(&result_encoder, "blinding_key", data->pubkey, data->pubkey_len);

    cberr = cbor_encoder_close_container(container, &result_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void get_shared_nonce_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_shared_nonce");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    size_t script_len = 0;
    const uint8_t* script = NULL;
    rpc_get_bytes_ptr("script", &params, &script, &script_len);
    if (!script || !script_len) {
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

    // Optional field to additionally return the blinding public key - defaults to false
    uint8_t blinding_pubkey[EC_PUBLIC_KEY_LEN];
    uint8_t* p_blinding_pubkey = NULL;
    size_t blinding_pubkey_len = 0;
    if (rpc_has_field_data("include_pubkey", &params)) {
        bool include_pubkey = false;
        if (!rpc_get_boolean("include_pubkey", &params, &include_pubkey)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid pubkey flag from parameters", NULL);
            goto cleanup;
        }

        // If the client also wants the pubkey, setup the parameters
        if (include_pubkey) {
            p_blinding_pubkey = blinding_pubkey;
            blinding_pubkey_len = sizeof(blinding_pubkey);
        }
    }

    const char* errmsg = NULL;
    uint8_t master_blinding_key[HMAC_SHA512_LEN];
    if (!params_get_master_blindingkey(&params, master_blinding_key, sizeof(master_blinding_key), &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
        goto cleanup;
    }

    // Get blinding nonce - sha256(ecdh(our_privkey, their_pubkey))
    uint8_t shared_nonce[SHA256_LEN];
    if (!wallet_get_shared_blinding_nonce(master_blinding_key, sizeof(master_blinding_key), script, script_len,
            their_pubkey, their_pubkey_len, shared_nonce, sizeof(shared_nonce), p_blinding_pubkey,
            blinding_pubkey_len)) {
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Failed to compute hashed shared nonce value for the parameters", NULL);
        goto cleanup;
    }

    if (p_blinding_pubkey) {
        // Return shared blinding nonce *and* the blinding pubkey (as it is explicitly requested)
        const nonce_pubkey_data_t data = { .shared_nonce = shared_nonce,
            .shared_nonce_len = sizeof(shared_nonce),
            .pubkey = p_blinding_pubkey,
            .pubkey_len = blinding_pubkey_len };
        jade_process_reply_to_message_result(process->ctx, &data, reply_nonce_and_pubkey);
    } else {
        // Just shared blinding nonce alone (default/legacy behaviour)
        uint8_t buffer[256];
        jade_process_reply_to_message_bytes(process->ctx, shared_nonce, sizeof(shared_nonce), buffer, sizeof(buffer));
    }
    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
