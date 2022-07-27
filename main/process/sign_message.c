#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"

#include "../button_events.h"

#include "process_utils.h"

#include <wally_anti_exfil.h>

// GDK logon parameters
static const uint32_t GDK_CHALLENGE_LENGTH = 32;
static const char GDK_CHALLENGE_PREFIX[] = "greenaddress.it      login ";
static const uint32_t GDK_CHALLENGE_PATH = 0x4741b11e;

// Return true if the path and message-prefix match a gdk login challenge
static inline bool isGdkLoginChallenge(
    const uint32_t* path, const size_t path_len, const char* message, const size_t msg_len)
{
    JADE_ASSERT(message);
    return path_len == 1 && path[0] == GDK_CHALLENGE_PATH && msg_len == GDK_CHALLENGE_LENGTH
        && !strncmp(message, GDK_CHALLENGE_PREFIX, sizeof(GDK_CHALLENGE_PREFIX) - 1);
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
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_message");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    const char* message = NULL;
    size_t msg_len = 0;
    rpc_get_string_ptr("message", &params, &message, &msg_len);
    if (msg_len == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract message from parameters", NULL);
        goto cleanup;
    }

    uint8_t message_hash[SHA256_LEN];
    if (!wallet_get_message_hash((const uint8_t*)message, msg_len, message_hash, sizeof(message_hash))) {
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Failed to convert message to btc hex format", NULL);
        goto cleanup;
    }

    // NOTE: for signing the root key (empty bip32 path) is not allowed.
    uint32_t path_len = 0;
    uint32_t path[MAX_PATH_LEN];
    const size_t max_path_len = sizeof(path) / sizeof(path[0]);
    const bool has_path = rpc_get_bip32_path("path", &params, path, max_path_len, &path_len);
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

    // Read any anti-exfil host commitment data (optional)
    // If present implies the use of the anti-exfil protocol and new message flow
    size_t ae_host_commitment_len = 0;
    const uint8_t* ae_host_commitment = NULL;
    const bool use_ae_signatures = rpc_has_field_data("ae_host_commitment", &params);
    if (use_ae_signatures) {
        rpc_get_bytes_ptr("ae_host_commitment", &params, &ae_host_commitment, &ae_host_commitment_len);
        if (!ae_host_commitment || ae_host_commitment_len != WALLY_HOST_COMMITMENT_LEN) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid host commitment from parameters", NULL);
            goto cleanup;
        }
    }

    // If the path and message suggest a gdk login challenge, just sign
    // the message without prompting the user to explicitly confirm.
    // (Otherwise the user has to confirm message or hash and the path.)
    const bool auto_sign = isGdkLoginChallenge(path, path_len, message, msg_len);
    if (auto_sign) {
        JADE_LOGI("Auto-signing GDK login challenge message");
    } else {
        gui_activity_t* activity = NULL;
        if (msg_len < MAX_DISPLAY_MESSAGE_LEN) {
            // Sufficiently short message - display the message
            make_sign_message_activity(&activity, message, msg_len, false, path_as_str);
        } else {
            // Overlong message - display the hash
            char* message_hex = NULL;
            JADE_WALLY_VERIFY(wally_hex_from_bytes(message_hash, sizeof(message_hash), &message_hex));
            jade_process_wally_free_string_on_exit(process, message_hex);
            make_sign_message_activity(&activity, message_hex, strlen(message_hex), true, path_as_str);
        }
        JADE_ASSERT(activity);
        gui_set_current_activity(activity);

        int32_t ev_id;
        // In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
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

        if (!auto_sign) {
            display_message_activity("Processing...");
        }

        // Compute signer-commitment
        uint8_t ae_signer_commitment[WALLY_S2C_OPENING_LEN];
        if (!wallet_get_signer_commitment(message_hash, sizeof(message_hash), path, path_len, ae_host_commitment,
                ae_host_commitment_len, ae_signer_commitment, sizeof(ae_signer_commitment))) {
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to make ae signer commitment", NULL);
            goto cleanup;
        }

        // Return signer commitment to caller
        uint8_t buffer[256];
        jade_process_reply_to_message_bytes(
            process->ctx, ae_signer_commitment, sizeof(ae_signer_commitment), buffer, sizeof(buffer));

        // Await 'get_signature' message containing host entropy
        jade_process_load_in_message(process, true);
        if (!IS_CURRENT_MESSAGE(process, "get_signature")) {
            // Protocol error
            jade_process_reject_message(
                process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'get_signature'", NULL);
            goto cleanup;
        }

        GET_MSG_PARAMS(process);
        rpc_get_bytes_ptr("ae_host_entropy", &params, &ae_host_entropy, &ae_host_entropy_len);
        if (!ae_host_entropy || ae_host_entropy_len != WALLY_S2C_DATA_LEN) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract host entropy from parameters", NULL);
            goto cleanup;
        }
    }

    // Compute the signature and send back to caller
    size_t written = 0;
    uint8_t sig_output[EC_SIGNATURE_LEN * 2]; // Should be len * 4/3 plus any padding, so * 2 is plenty.
    if (!wallet_sign_message_hash(message_hash, sizeof(message_hash), path, path_len, ae_host_entropy,
            ae_host_entropy_len, sig_output, sizeof(sig_output), &written)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to sign message", NULL);
        goto cleanup;
    }
    JADE_ASSERT(written < EC_SIGNATURE_LEN * 2);
    JADE_ASSERT(strnlen((const char*)sig_output, EC_SIGNATURE_LEN * 2) + 1 == written);

    jade_process_reply_to_message_result(process->ctx, (const char*)sig_output, cbor_result_string_cb);

    JADE_LOGI("Success");

cleanup:
    return;
}
