#include "../gui.h"
#include "../jade_assert.h"
#include "../otpauth.h"
#include "../process.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include "../button_events.h"

#include "process_utils.h"

void make_confirm_otp_activity(gui_activity_t** activity_ptr, const otpauth_ctx_t* ctx);

static bool validate_otp_name(const char* otp_name, const char** errmsg)
{
    JADE_ASSERT(otp_name);
    JADE_INIT_OUT_PPTR(errmsg);

    // Check name is valid
    if (!storage_key_name_valid(otp_name)) {
        *errmsg = "OTP name invalid";
        return false;
    }

    // If not overwriting an existing record, check storage slot available
    if (!storage_otp_exists(otp_name)) {
        if (storage_get_otp_count() >= OTP_MAX_RECORDS) {
            *errmsg = "Already have maximum number of otp records";
            return false;
        }
    }

    return true;
}

// Internal helper method to validate and persist a new otp record
// NOTE: otp_name must be nul-terminated, uri does not
static int handle_new_otp_uri(const char* otp_name, const char* otp_uri, const size_t uri_len, const char** errmsg)
{
    JADE_ASSERT(otp_name);
    JADE_ASSERT(otp_uri);
    JADE_ASSERT(uri_len);
    JADE_INIT_OUT_PPTR(errmsg);

    // Check name valid and have storage slot available
    if (!validate_otp_name(otp_name, errmsg)) {
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // Parse uri
    otpauth_ctx_t otp_ctx = { .name = otp_name };
    if (!otp_uri_to_ctx(otp_uri, uri_len, &otp_ctx)) {
        *errmsg = "Failed to parse otp record";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // Get a token now, as a test that the data is valid
    // We don't care what actual result is, just that it can be calculated
    char token[OTP_MAX_TOKEN_LEN];
    if (!otp_get_auth_code(&otp_ctx, token, sizeof(token))) {
        *errmsg = "Failed to calculate otp token";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // Get user to confirm saving otp record
    gui_activity_t* act = NULL;
    make_confirm_otp_activity(&act, &otp_ctx);
    JADE_ASSERT(act);
    gui_set_current_activity(act);

    int32_t ev_id;

    // In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const bool ret = true;
    ev_id = BTN_OTP_CONFIRM;
#endif

    // Check to see whether user accepted or declined
    if (!ret || ev_id != BTN_OTP_CONFIRM) {
        JADE_LOGW("User declined OTP record");
        *errmsg = "User declined OTP record";
        return CBOR_RPC_USER_CANCELLED;
    }
    JADE_LOGD("User pressed accept");

    // If no obvious issues, persist the otp uri
    if (!otp_save_uri(otp_name, otp_uri, uri_len)) {
        *errmsg = "Failed to persist otp details";
        return CBOR_RPC_INTERNAL_ERROR;
    }

    // If HOTP, persist initial counter value
    if (otp_ctx.otp_type == OTPTYPE_HOTP) {
        if (!storage_set_otp_hotp_counter(otp_name, otp_ctx.counter)) {
            storage_erase_otp(otp_name);
            *errmsg = "Failed to persist otp counter";
            return CBOR_RPC_INTERNAL_ERROR;
        }
    }

    // All good, return 0 (no error)
    return 0;
}

void register_otp_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "register_otp");
    GET_MSG_PARAMS(process);
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);

    size_t written = 0;
    char otp_name[OTP_MAX_NAME_LEN];
    rpc_get_string("name", sizeof(otp_name), &params, otp_name, &written);
    if (!written || !storage_key_name_valid(otp_name)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to fetch valid otp name from parameters", NULL);
        goto cleanup;
    }

    written = 0;
    const char* otp_uri = NULL;
    rpc_get_string_ptr("uri", &params, &otp_uri, &written);
    if (!otp_uri || !written) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to fetch otp uri from parameters", NULL);
        goto cleanup;
    }

    // Check keychain has seed data
    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.  Wallet must be re-initialised from mnemonic.");
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Feature requires resetting Jade", NULL);
        await_error_activity("Feature requires Jade reset");
        goto cleanup;
    }

    // Validate and persist the new otp uri
    const char* errmsg = NULL;
    const int errcode = handle_new_otp_uri(otp_name, otp_uri, written, &errmsg);
    if (errcode) {
        // Display any internal error that may occur after the user has viewed
        // and confirmed the OTP record (earlier errors are just messaged)
        if (errcode == CBOR_RPC_INTERNAL_ERROR) {
            await_error_activity(errmsg);
        }
        jade_process_reject_message(process, errcode, errmsg, NULL);
        goto cleanup;
    }

    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    return;
}
