#ifndef AMALGAMATED_BUILD
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

bool show_otp_details_activity(
    const otpauth_ctx_t* ctx, bool initial_confirmation, bool is_valid, bool show_delete_btn);

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

    // Get user to confirm saving otp record for this wallet
    const bool initial_confirmation = true;
    const bool is_valid_for_this_wallet = true;
    const bool show_delete_btn = false;
    if (!show_otp_details_activity(&otp_ctx, initial_confirmation, is_valid_for_this_wallet, show_delete_btn)) {
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
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "register_otp");
    GET_MSG_PARAMS(process);
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);

    char otp_name[OTP_MAX_NAME_LEN];
    size_t otp_name_len = 0;
    rpc_get_string("name", sizeof(otp_name), &params, otp_name, &otp_name_len);
    if (!otp_name_len || !storage_key_name_valid(otp_name)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to fetch valid otp name from parameters", NULL);
        goto cleanup;
    }

    const char* otp_uri = NULL;
    size_t otp_uri_len = 0;
    rpc_get_string_ptr("uri", &params, &otp_uri, &otp_uri_len);
    if (!otp_uri || !otp_uri_len) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to fetch otp uri from parameters", NULL);
        goto cleanup;
    }

    // Check keychain has seed data
    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.  Wallet must be re-initialised from mnemonic.");
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Feature requires resetting Jade", NULL);
        const char* message[] = { "Feature requires Jade reset" };
        await_error_activity(message, 1);
    }

    // Validate and persist the new otp uri
    const char* errmsg = NULL;
    const int errcode = handle_new_otp_uri(otp_name, otp_uri, otp_uri_len, &errmsg);
    if (errcode) {
        // Display any internal error that may occur after the user has viewed
        // and confirmed the OTP record (earlier errors are just messaged)
        if (errcode == CBOR_RPC_INTERNAL_ERROR) {
            const char* message[] = { errmsg };
            await_error_activity(message, 1);
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
            const char* question[] = { "Do you want to discard", "the OTP record?" };
            if (await_yesno_activity("Discard OTP", question, 2, false, NULL)) {
                return false;
            }
        } else if (!validate_otp_name(kb_entry.strdata, &errmsg)) {
            // Invalid otp name
            const char* message[] = { errmsg };
            await_error_activity(message, 1);
        } else {
            const char* question[] = { kb_entry.strdata };
            done = await_yesno_activity("Confirm OTP Name", question, 1, true, "blkstrm.com/otp");
        }
    }

    JADE_ASSERT(kb_entry.len < name_len);
    strcpy(otp_name, kb_entry.strdata);

    // 2. Optionally get the OTP URI also
    if (otp_uri && uri_len) {
        JADE_INIT_OUT_SIZE(uri_written);
        JADE_ASSERT(uri_len >= OTP_MAX_URI_LEN);
        JADE_STATIC_ASSERT(sizeof(kb_entry.strdata) >= OTP_MAX_URI_LEN);

        // Reset kb data - note URI can be longer than name
        gui_set_activity_title(kb_entry.activity, "OTP URI");
        kb_entry.max_allowed_len = uri_len - 1;

        // Pre-enter correct uri protocol
        strcpy(kb_entry.strdata, OTP_SCHEMA_FULL);
        kb_entry.len = strlen(kb_entry.strdata);
        done = false;

        // The URI contains the secret, so better guard it as sensitive
        SENSITIVE_PUSH(kb_entry.strdata, sizeof(kb_entry.strdata));

        // For testing uri validity
        while (!done) {
            // Run the keyboard entry loop to get a typed passphrase
            run_keyboard_entry_loop(&kb_entry);

            // If empty, abandon
            if (!kb_entry.len) {
                // empty, abandon
                break;
            }

            otpauth_ctx_t otp_ctx = { .name = otp_name };
            if (!otp_uri_to_ctx(kb_entry.strdata, kb_entry.len, &otp_ctx)) {
                const char* message[] = { "Invalid OTP URI" };
                if (!await_continueback_activity(NULL, message, 1, true, "blkstrm.com/otp")) {
                    // Invalid and user opts to abandon
                    kb_entry.len = 0; // blank out any invalid value
                    break;
                }
            } else {
                // URI valid, so exit text entry loop here
                done = true;
            }
        }

        if (done) {
            // ie. success
            JADE_ASSERT(kb_entry.len);
            JADE_ASSERT(kb_entry.len < uri_len);
            strcpy(otp_uri, kb_entry.strdata);
            *uri_written = kb_entry.len;
        }
        SENSITIVE_POP(kb_entry.strdata);
    }
    return done;
}

// Register a new OTP record by screen kb entry
bool register_otp_kb_entry(void)
{
    JADE_ASSERT(keychain_get());

    // Check keychain has seed data
    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.  Wallet must be re-initialised from mnemonic.");
        const char* message[] = { "Feature requires Jade reset" };
        await_error_activity(message, 1);
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
        const char* message[] = { errmsg };
        await_error_activity(message, 1);
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
    JADE_ASSERT(qr_data->len <= sizeof(qr_data->data));
    JADE_ASSERT(qr_data->data[qr_data->len] == '\0');

    if (qr_data->len >= OTP_MAX_URI_LEN) {
        JADE_LOGW("String data from qr unexpectedly long: %u", qr_data->len);
        goto invalid_qr;
    }

    otpauth_ctx_t otp_ctx = { .name = "otp_scanning" };
    if (!otp_uri_to_ctx((const char*)qr_data->data, qr_data->len, &otp_ctx)) {
        JADE_LOGW("Invalid otp uri string: %s", (const char*)qr_data->data);
        goto invalid_qr;
    }

    // uri appears valid
    return true;

invalid_qr:
    /* no-op */; // Need an empty statement to allow a label before a declaration

    // Show the user that a valid qr was scanned, but the string data
    // did not constitute a valid/parseable OTP URI string.
    const char* message[] = { "Invalid OTP URI" };
    if (!await_continueback_activity(NULL, message, 1, true, "blkstrm.com/otp")) {
        // return true if we are done (ie abandoning) or false if we are to return to scanning
        qr_data->len = 0; // blank out any invalid value
        return true; // ie. done with scanning
    }
    return false;
}

bool register_otp_qr(void)
{
    JADE_ASSERT(keychain_get());

    // Check keychain has seed data
    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.  Wallet must be re-initialised from mnemonic.");
        const char* message[] = { "Feature requires Jade reset" };
        await_error_activity(message, 1);
        return false;
    }

    bool ret = false;
    const char* errmsg = NULL;

    qr_data_t qr_data = { .len = 0, .is_valid = validate_scanned_otp_uri };
    SENSITIVE_PUSH(&qr_data, sizeof(qr_data));

    // Get URI from qr code scan
    const qr_frame_guides_t qr_frame_guides = QR_GUIDES_SMALL;
    if (!jade_camera_scan_qr(&qr_data, NULL, qr_frame_guides, "blkstrm.com/otp") || !qr_data.len) {
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
    const int errcode = handle_new_otp_uri(otp_name, (const char*)qr_data.data, qr_data.len, &errmsg);
    if (errcode && errcode != CBOR_RPC_USER_CANCELLED) {
        // Display any error (ignoring explicit user cancel)
        const char* message[] = { errmsg };
        await_error_activity(message, 1);
        goto cleanup;
    }

    // All good
    ret = true;

cleanup:
    SENSITIVE_POP(&qr_data);
    return ret;
}

bool register_otp_string(const char* otp_uri, const size_t uri_len, const char** errmsg)
{
    JADE_ASSERT(otp_uri);
    JADE_ASSERT(uri_len);
    JADE_INIT_OUT_PPTR(errmsg);
    JADE_ASSERT(keychain_get());

    // Parse uri
    otpauth_ctx_t otp_ctx = { .name = "otp_string" };
    if (!otp_uri_to_ctx(otp_uri, uri_len, &otp_ctx)) {
        *errmsg = "Failed to parse otp record";
        return false;
    }

    // Check keychain has seed data
    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.  Wallet must be re-initialised from mnemonic.");
        *errmsg = "Failed to parse otp record";
        const char* message[] = { "Feature requires Jade reset" };
        await_error_activity(message, 1);
        return false;
    }

    // Get OTP Name (only) from kb
    char otp_name[OTP_MAX_NAME_LEN];
    if (!get_otp_data_from_kb(otp_name, sizeof(otp_name), NULL, 0, NULL)) {
        // User abandoned
        JADE_LOGW("User abandoned (entering otp name)");
        *errmsg = "User abandoned entering otp name";
        return false;
    }

    // Validate and persist the new otp uri
    return handle_new_otp_uri(otp_name, otp_uri, uri_len, errmsg);
}
#endif // AMALGAMATED_BUILD
