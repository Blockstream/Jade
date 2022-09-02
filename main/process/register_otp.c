#include "../jade_assert.h"
#include "../otpauth.h"
#include "../process.h"
#include "../qrscan.h"
#include "../sensitive.h"
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
    gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
        CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
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

// Helper so user can enter OTP Name and URI via the keyboard screeens
static bool get_otp_data_from_kb(
    char* otp_name, const size_t name_len, char* otp_uri, const size_t uri_len, size_t* uri_written)
{
    JADE_ASSERT(otp_name);
    JADE_ASSERT(name_len);
    JADE_ASSERT((otp_uri == NULL) == !uri_len); // uri is optional

    // For otp data we want all keyboards
    keyboard_entry_t kb_entry = { .max_allowed_len = name_len - 1 };
    kb_entry.keyboards[0] = KB_LOWER_CASE_CHARS;
    kb_entry.keyboards[1] = KB_UPPER_CASE_CHARS;
    kb_entry.keyboards[2] = KB_NUMBERS_SYMBOLS;
    kb_entry.keyboards[3] = KB_REMAINING_SYMBOLS;
    kb_entry.num_kbs = 4;

    make_keyboard_entry_activity(&kb_entry, "OTP Name");
    JADE_ASSERT(kb_entry.activity);

    // 1. Get the OTP Name from the keyboard
    bool done = false;
    while (!done) {
        // Run the keyboard entry loop to get a typed passphrase
        run_keyboard_entry_loop(&kb_entry);

        const char* errmsg = NULL;
        if (!kb_entry.len) {
            // If empty, perhaps abort registering the OTP and return false
            if (await_yesno_activity("Discard OTP", "Do you want to discard\nthe OTP record?", false)) {
                return false;
            }
        } else if (!validate_otp_name(kb_entry.strdata, &errmsg)) {
            // Invalid otp name
            await_error_activity(errmsg);
        } else {
            char message[64];
            const int ret = snprintf(
                message, sizeof(message), "Do you confirm the following\nOTP Name:\n\n  %s", kb_entry.strdata);
            JADE_ASSERT(ret > 0 && ret < sizeof(message));
            done = await_yesno_activity("Confirm OTP Name", message, true);
        }
    }

    JADE_ASSERT(kb_entry.len < name_len);
    strcpy(otp_name, kb_entry.strdata);

    // 2. Optionally get the OTP URI also
    if (otp_uri && uri_len) {
        JADE_INIT_OUT_SIZE(uri_written);
        JADE_ASSERT(uri_len >= OTP_MAX_URI_LEN);
        JADE_ASSERT(sizeof(kb_entry.strdata) >= OTP_MAX_URI_LEN);

        // Reset kb data - note URI can be longer than name
        gui_set_activity_title(kb_entry.activity, "OTP URI");
        kb_entry.max_allowed_len = uri_len - 1;

        // Pre-enter correct uri protocol
        strcpy(kb_entry.strdata, "otpauth://");
        kb_entry.len = strlen(kb_entry.strdata);
        done = false;

        // The URI contains the secret, so better guard it as sensitive
        SENSITIVE_PUSH(kb_entry.strdata, sizeof(kb_entry.strdata));

        // For testing uri validity
        while (!done) {
            // Run the keyboard entry loop to get a typed passphrase
            run_keyboard_entry_loop(&kb_entry);

            // If empty, abort action and return false
            if (!kb_entry.len) {
                SENSITIVE_POP(kb_entry.strdata);
                return false;
            }

            otpauth_ctx_t otp_ctx = { .name = otp_name };
            if (!otp_uri_to_ctx(kb_entry.strdata, kb_entry.len, &otp_ctx)) {
                await_error_activity("Invalid OTP URI");
            } else {
                // URI valid, so exit text entry loop here
                done = true;
            }
        }

        JADE_ASSERT(kb_entry.len < uri_len);
        strcpy(otp_uri, kb_entry.strdata);
        *uri_written = kb_entry.len;

        SENSITIVE_POP(kb_entry.strdata);
    }

    return true;
}

// Register a new OTP record by screen kb entry
bool register_otp_kb_entry(void)
{
    JADE_ASSERT(keychain_get());

    // Check keychain has seed data
    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.  Wallet must be re-initialised from mnemonic.");
        await_error_activity("Feature requires Jade reset");
        return false;
    }

    bool ret = false;
    const char* errmsg = NULL;

    // Get OTP Name and URI from kb
    char otp_name[OTP_MAX_NAME_LEN];
    char otp_uri[OTP_MAX_URI_LEN];
    SENSITIVE_PUSH(otp_uri, sizeof(otp_uri));

    size_t uri_written = 0;
    if (!get_otp_data_from_kb(otp_name, sizeof(otp_name), otp_uri, sizeof(otp_uri), &uri_written)) {
        // User abandoned
        JADE_LOGW("User abandoned (entering otp name/uri)");
        goto cleanup;
    }

    // Validate and persist the new otp uri
    const int errcode = handle_new_otp_uri(otp_name, otp_uri, uri_written, &errmsg);
    if (errcode && errcode != CBOR_RPC_USER_CANCELLED) {
        // Display any error (ignoring explicit user cancel)
        await_error_activity(errmsg);
        goto cleanup;
    }

    // All good
    ret = true;

cleanup:
    SENSITIVE_POP(otp_uri);
    return ret;
}

// Register a new OTP record by scanning a qr code
static bool validate_scanned_otp_uri(qr_data_t* qr_data)
{
    JADE_ASSERT(qr_data);
    JADE_ASSERT(qr_data->len <= sizeof(qr_data->strdata));
    JADE_ASSERT(qr_data->strdata[qr_data->len] == '\0');

    if (qr_data->len >= OTP_MAX_URI_LEN) {
        JADE_LOGW("String data from qr unexpectedly long: %u", qr_data->len);
        goto invalid_qr;
    }

    otpauth_ctx_t otp_ctx = { .name = "otp_scanning" };
    if (!otp_uri_to_ctx(qr_data->strdata, qr_data->len, &otp_ctx)) {
        JADE_LOGW("Invalid otp uri string: %s", qr_data->strdata);
        goto invalid_qr;
    }

    // uri appears valid
    return true;

invalid_qr:
    // Show the user that a valid qr was scanned, but the string data
    // did not constitute a valid/parseable OTP URI string.
    await_error_activity("Invalid OTP URI");
    return false;
}

bool register_otp_qr(void)
{
    JADE_ASSERT(keychain_get());

    // Check keychain has seed data
    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.  Wallet must be re-initialised from mnemonic.");
        await_error_activity("Feature requires Jade reset");
        return false;
    }

    bool ret = false;
    const char* errmsg = NULL;

    qr_data_t qr_data = { .len = 0, .is_valid = validate_scanned_otp_uri };
    SENSITIVE_PUSH(&qr_data, sizeof(qr_data));

    // Get URI from qr code scan
    if (!jade_camera_scan_qr(&qr_data) || !qr_data.len) {
        // User exit without scanning
        JADE_LOGW("No qr code scanned");
        goto cleanup;
    }

    // Get OTP Name (only) from kb
    char otp_name[OTP_MAX_NAME_LEN];
    if (!get_otp_data_from_kb(otp_name, sizeof(otp_name), NULL, 0, NULL)) {
        // User abandoned
        JADE_LOGW("User abandoned (entering otp name)");
        goto cleanup;
    }

    // Validate and persist the new otp uri
    const int errcode = handle_new_otp_uri(otp_name, qr_data.strdata, qr_data.len, &errmsg);
    if (errcode && errcode != CBOR_RPC_USER_CANCELLED) {
        // Display any error (ignoring explicit user cancel)
        await_error_activity(errmsg);
        goto cleanup;
    }

    // All good
    ret = true;

cleanup:
    SENSITIVE_POP(&qr_data);
    return ret;
}
