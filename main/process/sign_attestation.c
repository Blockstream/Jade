#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../process.h"
#include "../ui.h"
#include "process_utils.h"

#ifdef CONFIG_IDF_TARGET_ESP32S3
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "attestation/attestation.h"

typedef struct {
    char pubkey_pem[JADE_ATTEST_RSA_PUBKEY_PEM_MAX_LEN];
    uint8_t signature[JADE_ATTEST_RSA_KEY_LEN];
    uint8_t ext_signature[JADE_ATTEST_RSA_KEY_LEN];
    size_t ext_signature_len;
} attestation_reply_t;

static void reply_attestation(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);
    const attestation_reply_t* data = (const attestation_reply_t*)ctx;

    CborEncoder result_encoder;
    CborError cberr = cbor_encoder_create_map(container, &result_encoder, 3);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&result_encoder, "signature", data->signature, sizeof(data->signature));
    add_string_to_map(&result_encoder, "pubkey_pem", data->pubkey_pem);
    add_bytes_to_map(&result_encoder, "ext_signature", data->ext_signature, data->ext_signature_len);

    cberr = cbor_encoder_close_container(container, &result_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void sign_attestation_and_send_reply(jade_process_t* process, const uint8_t* challenge, const size_t challenge_len)
{
    // Compute the signature and send back to caller
    size_t pem_written = 0;
    attestation_reply_t output;
    if (!attestation_sign_challenge(challenge, challenge_len, output.signature, sizeof(output.signature),
            output.pubkey_pem, sizeof(output.pubkey_pem), &pem_written, output.ext_signature,
            sizeof(output.ext_signature), &output.ext_signature_len)
        || !pem_written || !output.ext_signature_len) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to sign attestation");
    }

    // Reply with pubkey and signatures
    const size_t buflen = 2560;
    uint8_t* const buf = JADE_MALLOC(buflen);
    jade_process_reply_to_message_result(process->ctx, buf, buflen, &output, reply_attestation);
    free(buf);
}
#endif // CONFIG_IDF_TARGET_ESP32S3

void sign_attestation_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_attestation");
    GET_MSG_PARAMS(process);

#ifdef CONFIG_IDF_TARGET_ESP32S3
    if (!attestation_initialised()) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Attestation data not initialised");
        goto cleanup;
    }

    const uint8_t* challenge = NULL;
    size_t challenge_len = 0;
    rpc_get_bytes_ptr("challenge", &params, &challenge, &challenge_len);
    if (challenge_len == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid challenge from parameters");
        goto cleanup;
    }

    // User to confirm signing
    const char* message[] = { "Sign Genuine Check?" };
    if (!await_yesno_activity("Genuine Check", message, 1, true, "blkstrm.com/genuine")) {
        JADE_LOGW("User declined to sign attestation");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign genuine check");
        goto cleanup;
    }
    JADE_LOGD("User pressed accept");

    display_processing_message_activity();
    sign_attestation_and_send_reply(process, challenge, challenge_len); // sends reply

    JADE_LOGI("Success");
#else // CONFIG_IDF_TARGET_ESP32S3
    jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Attestation not supported");
#endif // CONFIG_IDF_TARGET_ESP32S3

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
