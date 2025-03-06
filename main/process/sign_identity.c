#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include "../button_events.h"

#include "../identity.h"
#include "process_utils.h"

bool show_sign_identity_activity(const char* identity, size_t identity_len);

typedef struct {
    // NOTE: signature with leading 0x00 (required or can strip?)
    // Note also that we use uncompressed keys in this api
    uint8_t signature[EC_SIGNATURE_LEN + 1];
    uint8_t pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
} signature_and_pubkey_t;

static void reply_signature_and_pubkey(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);
    const signature_and_pubkey_t* data = (const signature_and_pubkey_t*)ctx;

    CborEncoder result_encoder;
    CborError cberr = cbor_encoder_create_map(container, &result_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&result_encoder, "signature", data->signature, sizeof(data->signature));
    add_bytes_to_map(&result_encoder, "pubkey", data->pubkey, sizeof(data->pubkey));

    cberr = cbor_encoder_close_container(container, &result_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void sign_identity_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_identity");
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

    const uint8_t* challenge = NULL;
    size_t challenge_len = 0;
    rpc_get_bytes_ptr("challenge", &params, &challenge, &challenge_len);
    if (challenge_len == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid challenge from parameters", NULL);
        goto cleanup;
    }

    // Check keychain has seed data - old wallets may not
    // Reinitialising the wallet would address that, as seed is cached after mnemonic entry
    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.  Wallet must be re-initialised from mnemonic.");
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Feature requires resetting Jade", NULL);

        const char* message[] = { "Feature requires Jade reset" };
        await_error_activity(message, 1);
        goto cleanup;
    }

    // User to confirm identity
    if (!show_sign_identity_activity(identity, identity_len)) {
        JADE_LOGW("User declined to sign message");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign identity", NULL);
        goto cleanup;
    }
    JADE_LOGD("User pressed accept");

    display_processing_message_activity();

    // Compute the signature and send back to caller
    signature_and_pubkey_t output;
    if (!sign_identity(identity, identity_len, index, curve, curve_len, challenge, challenge_len, output.pubkey,
            sizeof(output.pubkey), output.signature, sizeof(output.signature))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to sign identity", NULL);
        goto cleanup;
    }

    // Return pubkey and signature
    jade_process_reply_to_message_result(process->ctx, &output, reply_signature_and_pubkey);

    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
