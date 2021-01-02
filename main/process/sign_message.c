#include "../jade_assert.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"

#include "../button_events.h"

#include <esp_event.h>

#include <string.h>

#include "process_utils.h"

// GDK logon parameters
static const uint32_t GDK_CHALLENGE_LENGTH = 32;
static const char GDK_CHALLENGE_PREFIX[] = "greenaddress.it      login ";
static const uint32_t GDK_CHALLENGE_PATH = 0x4741b11e;

static void wally_free_string_wrapper(void* str) { wally_free_string((char*)str); }

// Return true if the path and message-prefix match a gdk login challenge
static inline bool isGdkLoginChallenge(
    const uint32_t* path, const size_t path_size, const char* message, const size_t msg_len)
{
    JADE_ASSERT(message);
    return path_size == 1 && path[0] == GDK_CHALLENGE_PATH && msg_len == GDK_CHALLENGE_LENGTH
        && !strncmp(message, GDK_CHALLENGE_PREFIX, sizeof(GDK_CHALLENGE_PREFIX) - 1);
}

void sign_message_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_message");
    GET_MSG_PARAMS(process);

    const char* message = NULL;
    size_t msg_len = 0;
    rpc_get_string_ptr("message", &params, &message, &msg_len);
    if (msg_len == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract message from parameters", NULL);
        goto cleanup;
    }

    char* message_hex = NULL;
    if (!wallet_get_message_hash_hex(message, msg_len, &message_hex) || !message_hex) {
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Failed to convert message to btc hex format", NULL);
        goto cleanup;
    }
    jade_process_call_on_exit(process, wally_free_string_wrapper, message_hex);

    // NOTE: for signing the root key (empty bip32 path) is not allowed.
    uint32_t path_len = 0;
    uint32_t path[MAX_PATH_LEN];
    const bool has_path = rpc_get_bip32_path("path", &params, path, MAX_PATH_LEN, &path_len);
    if (!has_path || path_len == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid path from parameters", NULL);
        goto cleanup;
    }

    char path_as_str[64];
    if (!bip32_path_as_str(path, path_len, path_as_str, sizeof(path_as_str))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to convert path to string format", NULL);
        goto cleanup;
    }

    // If the path and message suggest a gdk login challenge, just sign
    // the message without prompting the user to explicitly confirm.
    // (Otherwise the user has to confirm message hash and path.)
    if (isGdkLoginChallenge(path, path_len, message, msg_len)) {
        JADE_LOGI("Auto-signing GDK login challenge message");
    } else {
        gui_activity_t* activity;
        make_sign_message_activity(&activity, message_hex, path_as_str);
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
            jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign message", NULL);
            goto cleanup;
        }

        JADE_LOGD("User pressed accept");
    }

    size_t written = 0;
    char sig_output[EC_SIGNATURE_LEN * 2]; // Should be len * 4/3 plus any padding, so * 2 is plenty.
    if (!wallet_sign_message(
            path, path_len, (char*)message, msg_len, (unsigned char*)sig_output, EC_SIGNATURE_LEN * 2, &written)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to sign message", NULL);
        goto cleanup;
    }

    JADE_ASSERT(written < EC_SIGNATURE_LEN * 2);
    JADE_ASSERT(strnlen(sig_output, EC_SIGNATURE_LEN * 2) + 1 == written);

    jade_process_reply_to_message_result(process->ctx, sig_output, cbor_result_string_cb);

    JADE_LOGI("Success");

cleanup:
    return;
}
