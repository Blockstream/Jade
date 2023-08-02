#include "../gui.h"
#include "../jade_assert.h"
#include "../otpauth.h"
#include "../process.h"
#include "../sensitive.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include "../button_events.h"

#include "process_utils.h"

bool display_otp_screen(
    otpauth_ctx_t* otp_ctx, uint64_t value, char* token, size_t token_len, bool confirm_only, bool auto_update);

void get_otp_code_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char otp_uri[OTP_MAX_URI_LEN];
    SENSITIVE_PUSH(otp_uri, sizeof(otp_uri));

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_otp_code");
    GET_MSG_PARAMS(process);
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);

    size_t written = 0;
    char otp_name[OTP_MAX_NAME_LEN];
    rpc_get_string("name", sizeof(otp_name), &params, otp_name, &written);
    if (!written) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to fetch valid otp name from parameters", NULL);
        goto cleanup;
    }

    // Check keychain has seed data
    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.  Wallet must be re-initialised from mnemonic.");
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Feature requires resetting Jade", NULL);
        await_error_activity("Feature requires Jade reset");
        goto cleanup;
    }

    // Load OTP record from storage given the name
    written = 0;
    if (!otp_load_uri(otp_name, otp_uri, sizeof(otp_uri), &written) || !written) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Cannot find or load named otp record", NULL);
        goto cleanup;
    }

    // Parse loaded uri
    otpauth_ctx_t otp_ctx = { .name = otp_name };
    if (!otp_uri_to_ctx(otp_uri, written, &otp_ctx)) {
        JADE_LOGE("Failed to parse otp record: %.*s", written, otp_uri);
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to parse otp record", NULL);
        goto cleanup;
    }

    // Update the context with the current calculated counter value (derived from current time for TOTP)
    uint64_t value = 0;
    if (!otp_set_default_value(&otp_ctx, &value)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to set OTP counter", NULL);
        goto cleanup;
    }

    // In debug mode can send explicit counter or timestamp override (ie. for testing)
    // totp token/code updates with time - but we disable that if an explicit epoch value is passed
    bool auto_update = true;
#ifdef CONFIG_DEBUG_MODE
    if (rpc_get_uint64_t("override", &params, &value)) {
        otp_set_explicit_value(&otp_ctx, value);
        auto_update = false; // frozen on passed override value
    }
#endif

    char token[OTP_MAX_TOKEN_LEN];
    if (!otp_get_auth_code(&otp_ctx, token, sizeof(token))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to calculate otp token", NULL);
        goto cleanup;
    }

    // Check to see whether user confirmed code
    const bool confirm_only = true;
    if (!display_otp_screen(&otp_ctx, value, token, sizeof(token), confirm_only, auto_update)) {
        JADE_LOGW("User declined OTP code");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined OTP code", NULL);
        goto cleanup;
    }
    JADE_LOGD("User pressed accept");

    jade_process_reply_to_message_result(process->ctx, token, cbor_result_string_cb);

    JADE_LOGI("Success");

cleanup:
    SENSITIVE_POP(otp_uri);
    return;
}
