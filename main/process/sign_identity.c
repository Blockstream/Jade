#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include "../button_events.h"

#include "../identity.h"
#include "process_utils.h"

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
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
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
        await_error_activity("Feature requires Jade reset");
        goto cleanup;
    }

    // User to confirm identity
    gui_activity_t* activity = NULL;
    make_sign_identity_activity(&activity, identity, identity_len);
    JADE_ASSERT(activity);
    gui_set_current_activity(activity);

    int32_t ev_id;

    // In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const bool ret = true;
    ev_id = BTN_ACCEPT_SIGNATURE;
#endif

    // Check to see whether user accepted or declined
    if (!ret || ev_id != BTN_ACCEPT_SIGNATURE) {
        JADE_LOGW("User declined to sign message");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign identity", NULL);
        goto cleanup;
    }
    JADE_LOGD("User pressed accept");

    display_message_activity("Processing...");

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
