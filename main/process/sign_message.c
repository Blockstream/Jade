#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "../wallet.h"

#include "../button_events.h"

#include "process_utils.h"

#include <ctype.h>
#include <wally_anti_exfil.h>

bool show_sign_message_activity(const char* msg_str, const char* hashhex, const char* path_as_str);

// Maximum message length
#define SIGN_MESSAGE_MAX_LEN 4096u

static const char SIGN_MESSAGE_FILE_PREFIX[] = "signmessage";
static const char SIGN_MESSAGE_FILE_LABEL_ASCII[] = "ascii";

// GDK logon parameters
#define GDK_CHALLENGE_LENGTH 32u
#define GDK_CHALLENGE_PREFIX "greenaddress.it      login "
#define GDK_CHALLENGE_PATH "m/1195487518"

// Return true if the path and message-prefix match a gdk login challenge
static inline bool is_gdk_login_challenge(const char* msg, const size_t msg_len, const char* pathstr)
{
    JADE_ASSERT(msg && msg_len && pathstr);
    return msg_len == GDK_CHALLENGE_LENGTH && !strncmp(msg, GDK_CHALLENGE_PREFIX, strlen(GDK_CHALLENGE_PREFIX))
        && strlen(pathstr) == strlen(GDK_CHALLENGE_PATH) && !strcmp(pathstr, GDK_CHALLENGE_PATH);
}

static char* get_sign_msg_display_text(const char* msg, const size_t msg_len)
{
    char* display_text = JADE_MALLOC(msg_len + 1);
    char* out = display_text;

    for (size_t i = 0; i < msg_len; ++i) {
        const char c = msg[i];
        if (isprint(c) || c == ' ' || c == '\n') {
            *out++ = c;
        } else {
            JADE_ASSERT(c != '\0');
            *out++ = '?'; // Unrepresentable
        }
    }
    *out++ = '\0';
    return display_text;
}

// Ask the user to confirm signing the message
static int confirm_sign_message(const char* msg, const size_t msg_len, const char* pathstr, uint8_t* hash_out,
    const size_t hash_len, bool* skipped_confirm, const char** errmsg)
{
    JADE_ASSERT(msg && pathstr);
    JADE_ASSERT(hash_out && hash_len == SHA256_LEN);
    JADE_ASSERT(skipped_confirm);
    *skipped_confirm = false;

    JADE_INIT_OUT_PPTR(errmsg);

    if (!msg || !msg_len || msg_len > SIGN_MESSAGE_MAX_LEN) {
        *errmsg = "Invalid message";
        return CBOR_RPC_INVALID_REQUEST;
    }

    if (!wallet_get_message_hash((const uint8_t*)msg, msg_len, hash_out, hash_len)) {
        *errmsg = "Failed to get message hash";
        return CBOR_RPC_INTERNAL_ERROR;
    }

    if (is_gdk_login_challenge(msg, msg_len, pathstr)) {
        // gdk login challenge: sign without prompting the user to confirm.
        *skipped_confirm = true;
        JADE_LOGI("Auto-signing GDK login challenge message");
        return 0;
    }

    char* display_text = get_sign_msg_display_text(msg, msg_len);
    const size_t display_len = strlen(display_text);

    // Truncate message if overlong
    char message[MAX_DISPLAY_MESSAGE_LEN];
    if (display_len < MAX_DISPLAY_MESSAGE_LEN) {
        const int ret = snprintf(message, sizeof(message), "%.*s", display_len, display_text);
        JADE_ASSERT(ret == display_len);
    } else {
        const int ret = snprintf(message, sizeof(message), "%.*s...", sizeof(message) - 4, display_text);
        JADE_ASSERT(ret == sizeof(message) - 1);
    }

    // Ask user to confirm
    char* hashhex = NULL;
    JADE_WALLY_VERIFY(wally_hex_from_bytes(hash_out, hash_len, &hashhex));
    const bool confirmed = show_sign_message_activity(message, hashhex, pathstr);
    JADE_WALLY_VERIFY(wally_free_string(hashhex));
    free(display_text);

    if (!confirmed) {
        *errmsg = "User declined to sign message";
        return CBOR_RPC_USER_CANCELLED;
    }
    JADE_LOGD("User pressed accept");
    return 0;
}

int sign_message_file(const char* str, const size_t str_len, uint8_t* sig_output, const size_t sig_len, size_t* written,
    const char** errmsg)
{
    JADE_ASSERT(str);
    JADE_ASSERT(str_len);
    JADE_ASSERT(sig_output);
    JADE_ASSERT(sig_len >= EC_SIGNATURE_LEN * 2); // Should be len * 4/3 plus any padding, so * 2 is plenty.
    JADE_INIT_OUT_SIZE(written);
    JADE_INIT_OUT_PPTR(errmsg);

    const char* ptr = str;
    const char* const str_end = str + str_len;

    // Parse file - 3 fields on one line expected
    // signmessage <bip32 path> ascii:<message text>

    // 'signmessage' prefix
    const char* end = memchr(ptr, ' ', str_len);
    if (!end || end - ptr != sizeof(SIGN_MESSAGE_FILE_PREFIX) - 1
        || strncasecmp(ptr, SIGN_MESSAGE_FILE_PREFIX, end - ptr)) {
        *errmsg = "Invalid prefix";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // bip32 path - parse, then print back as standardised nul-terminated string
    ptr = end + 1;
    end = memchr(ptr, ' ', str_end - ptr);
    if (!end) {
        *errmsg = "Invalid bip32 path";
        return CBOR_RPC_BAD_PARAMETERS;
    }
    uint32_t path[MAX_PATH_LEN];
    size_t path_len = 0;
    if (!wallet_bip32_path_from_str(ptr, end - ptr, path, sizeof(path) / sizeof(path[0]), &path_len) || !path_len) {
        *errmsg = "Invalid bip32 path";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    char pathstr[MAX_PATH_STR_LEN(MAX_PATH_LEN)];
    const bool path_only = false;
    if (!wallet_bip32_path_as_str(path, path_len, pathstr, sizeof(pathstr), path_only)) {
        *errmsg = "Invalid bip32 path";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // 'ascii:' prefix
    ptr = end + 1;
    end = memchr(ptr, ':', str_end - ptr);
    if (!end || end - ptr != sizeof(SIGN_MESSAGE_FILE_LABEL_ASCII) - 1
        || strncasecmp(ptr, SIGN_MESSAGE_FILE_LABEL_ASCII, end - ptr)) {
        *errmsg = "Invalid message prefix";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // Get the message string
    ptr = end + 1;
    if (ptr >= str_end || *ptr == '\0') {
        *errmsg = "Invalid message bytes";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    const size_t msg_len = str_end - ptr;
    uint8_t message_hash[SHA256_LEN];
    // Ask the user to confirm signing the message
    bool skipped_confirm = false;
    const int ret
        = confirm_sign_message(ptr, msg_len, pathstr, message_hash, sizeof(message_hash), &skipped_confirm, errmsg);
    JADE_ASSERT(!skipped_confirm);
    if (ret != 0) {
        JADE_LOGW("%s", *errmsg);
        return ret;
    }

    // Compute the signature and send back to caller
    if (!wallet_sign_message_hash(
            message_hash, sizeof(message_hash), path, path_len, NULL, 0, sig_output, sig_len, written)) {
        *errmsg = "Failed to sign message";
        return CBOR_RPC_INTERNAL_ERROR;
    }
    return 0;
}

/*
 * The message flow here is complicated because we cater for both a legacy flow
 * for standard deterministic EC signatures (see rfc6979) and a newer message
 * exchange added later to cater for anti-exfil signatures.
 * At the moment we retain the older message flow for backward compatibility,
 * but at some point we could remove it and use the new message flow for all
 * cases, which would simplify the code here and in the client.
 */
void sign_message_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_message");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    // We accept a signing file, as produced by Specter wallet app (at least)
    if (rpc_has_field_data("message_file", &params)) {
        const char* message_file = NULL;
        size_t message_file_len = 0;
        rpc_get_string_ptr("message_file", &params, &message_file, &message_file_len);
        if (!message_file || !message_file_len) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid sign message file data");
            goto cleanup;
        }

        uint8_t signature[EC_SIGNATURE_LEN * 2]; // Sufficient
        size_t written = 0;
        const char* errmsg = NULL;
        const int errcode
            = sign_message_file(message_file, message_file_len, signature, sizeof(signature), &written, &errmsg);
        if (errcode) {
            jade_process_reject_message(process, errcode, errmsg);
            goto cleanup;
        }

        JADE_ASSERT(written);
        JADE_ASSERT(written < sizeof(signature));
        JADE_ASSERT(signature[written - 1] == '\0');

        uint8_t buf[256];
        jade_process_reply_to_message_result(
            &process->ctx, buf, sizeof(buf), (const char*)signature, cbor_result_string_cb);
        return;
    }

    const char* message = NULL;
    size_t msg_len = 0;
    rpc_get_string_ptr("message", &params, &message, &msg_len);
    if (msg_len == 0) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract message from parameters");
        goto cleanup;
    }

    // NOTE: for signing the root key (empty bip32 path) is not allowed.
    size_t path_len = 0;
    uint32_t path[MAX_PATH_LEN];
    const size_t max_path_len = sizeof(path) / sizeof(path[0]);
    const bool has_path = rpc_get_bip32_path("path", &params, path, max_path_len, &path_len);
    if (!has_path || path_len == 0) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid path from parameters");
        goto cleanup;
    }

    char pathstr[MAX_PATH_STR_LEN(MAX_PATH_LEN)];
    const bool path_only = false;
    if (!wallet_bip32_path_as_str(path, path_len, pathstr, sizeof(pathstr), path_only)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to convert path to string format");
        goto cleanup;
    }

    // Read any anti-exfil host commitment data (optional)
    // If present implies the use of the anti-exfil protocol and new message flow
    size_t ae_host_commitment_len = 0;
    const uint8_t* ae_host_commitment = NULL;
    const bool use_ae_signatures = rpc_has_field_data("ae_host_commitment", &params);
    if (use_ae_signatures) {
        rpc_get_bytes_ptr("ae_host_commitment", &params, &ae_host_commitment, &ae_host_commitment_len);
        if (!ae_host_commitment || ae_host_commitment_len != WALLY_HOST_COMMITMENT_LEN) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid host commitment from parameters");
            goto cleanup;
        }
    }

    uint8_t message_hash[SHA256_LEN];
    // Ask the user to confirm signing the message
    const char* errmsg = NULL;
    bool skipped_confirm = false;
    const int ret = confirm_sign_message(
        message, msg_len, pathstr, message_hash, sizeof(message_hash), &skipped_confirm, &errmsg);
    if (ret != 0) {
        JADE_LOGW("%s", errmsg);
        jade_process_reject_message(process, ret, errmsg);
        goto cleanup;
    }

    // Send signature replies.
    // NOTE: currently we have two message flows - the backward compatible version
    // for normal EC signatures, and the new flow required for Anti-Exfil signatures.
    // Once we have migrated the companion applications onto AE signatures we could
    // convert normal EC signatures to use the new/improved message flow.
    size_t ae_host_entropy_len = 0;
    const uint8_t* ae_host_entropy = NULL;
    if (use_ae_signatures) {
        JADE_ASSERT(ae_host_commitment);
        JADE_ASSERT(ae_host_commitment_len == WALLY_HOST_COMMITMENT_LEN);

        if (!skipped_confirm) {
            display_processing_message_activity();
        }

        // Compute signer-commitment
        uint8_t ae_signer_commitment[WALLY_S2C_OPENING_LEN];
        if (!wallet_get_signer_commitment(message_hash, sizeof(message_hash), path, path_len, ae_host_commitment,
                ae_host_commitment_len, ae_signer_commitment, sizeof(ae_signer_commitment))) {
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to make ae signer commitment");
            goto cleanup;
        }

        // Return signer commitment to caller
        jade_process_reply_to_message_bytes(&process->ctx, ae_signer_commitment, sizeof(ae_signer_commitment));

        // Await 'get_signature' message containing host entropy
        jade_process_load_in_message(process, true);
        if (!IS_CURRENT_MESSAGE(process, "get_signature")) {
            // Protocol error
            jade_process_reject_message(
                process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'get_signature'");
            goto cleanup;
        }

        GET_MSG_PARAMS(process);
        rpc_get_bytes_ptr("ae_host_entropy", &params, &ae_host_entropy, &ae_host_entropy_len);
        if (!ae_host_entropy || ae_host_entropy_len != WALLY_S2C_DATA_LEN) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract host entropy from parameters");
            goto cleanup;
        }
    }

    // Compute the signature and send back to caller
    size_t written = 0;
    uint8_t sig_output[EC_SIGNATURE_LEN * 2]; // Should be len * 4/3 plus any padding, so * 2 is plenty.
    if (!wallet_sign_message_hash(message_hash, sizeof(message_hash), path, path_len, ae_host_entropy,
            ae_host_entropy_len, sig_output, sizeof(sig_output), &written)
        || !written) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to sign message");
        goto cleanup;
    }
    JADE_ASSERT(written < sizeof(sig_output));
    JADE_ASSERT(sig_output[written - 1] == '\0');

    uint8_t buf[256];
    jade_process_reply_to_message_result(
        &process->ctx, buf, sizeof(buf), (const char*)sig_output, cbor_result_string_cb);

    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
