#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include <wally_crypto.h>

#include "process_utils.h"

static void wally_free_string_wrapper(void* str) { wally_free_string((char*)str); }

void update_pinserver_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "update_pinserver");
    GET_MSG_PARAMS(process);

    char urlA[MAX_PINSVR_URL_LENGTH] = { 0 };
    char urlB[MAX_PINSVR_URL_LENGTH] = { 0 };
    char cert[MAX_PINSVR_CERTIFICATE_LENGTH] = { 0 };

    const uint8_t* pubkey;
    size_t pubkey_len = 0;

    // 1. update or erase the pinserver details
    bool reset_details = false;
    rpc_get_boolean("reset_details", &params, &reset_details);

    size_t urlA_len = 0, urlB_len = 0;
    rpc_get_string("urlA", sizeof(urlA), &params, urlA, &urlA_len);
    rpc_get_string("urlB", sizeof(urlB), &params, urlB, &urlB_len);
    rpc_get_bytes_ptr("pubkey", &params, &pubkey, &pubkey_len);

    if (urlA_len == 0 && rpc_has_field_data("urlA", &params)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Cannot set empty URL", NULL);
        goto cleanup;
    }
    if (urlB_len && !urlA_len) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Can only set second URL if also setting first URL", NULL);
        goto cleanup;
    }
    if ((urlA_len || pubkey) && reset_details) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Cannot both set and reset pinserver details", NULL);
        goto cleanup;
    }
    if (pubkey) {
        if (!urlA_len) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Cannot set pinserver pubkey without setting URL", NULL);
            goto cleanup;
        }
        if (pubkey_len != EC_PUBLIC_KEY_LEN || wally_ec_public_key_verify(pubkey, pubkey_len) != WALLY_OK) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid pubkey", NULL);
            goto cleanup;
        }
#ifndef CONFIG_DEBUG_MODE
        if (keychain_has_pin()) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Cannot change pinserver pubkey on initialised unit", NULL);
            goto cleanup;
        }
#endif // CONFIG_DEBUG_MODE
    }

    if (urlA_len) {
        char* pubkey_hex = NULL;
        if (pubkey && pubkey_len > 0) {
            JADE_WALLY_VERIFY(wally_hex_from_bytes(pubkey, pubkey_len, &pubkey_hex));
            jade_process_call_on_exit(process, wally_free_string_wrapper, pubkey_hex);
        }

        gui_activity_t* activity;
        make_confirm_pinserver_details_activity(&activity, urlA, urlB, pubkey_hex);
        JADE_ASSERT(activity);
        gui_set_current_activity(activity);

        int32_t ev_id;
        // In a debug unattended ci build, assume 'confirm' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_PINSERVER_DETAILS_CONFIRM;
#endif
        if (!ret || ev_id != BTN_PINSERVER_DETAILS_CONFIRM) {
            JADE_LOGW("User declined to confirm pinserver details");
            jade_process_reject_message(
                process, CBOR_RPC_USER_CANCELLED, "User did not confirm PinServer details", NULL);
            goto cleanup;
        }
    } else if (reset_details) {
        if (!await_yesno_activity("Reset PinServer", "Reset pin-server details?")) {
            JADE_LOGW("User declined to confirm resetting pinserver details");
            jade_process_reject_message(
                process, CBOR_RPC_USER_CANCELLED, "User did not confirm resetting PinServer details", NULL);
            goto cleanup;
        }
    }

    // 2. update or erase the certificate
    bool reset_certificate = false;
    rpc_get_boolean("reset_certificate", &params, &reset_certificate);
    const bool set_certificate = rpc_has_field_data("certificate", &params);

    if (set_certificate && reset_certificate) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Cannot both set and reset pinserver certificate", NULL);
        goto cleanup;
    }

    if (set_certificate) {
        size_t cert_len = 0;
        rpc_get_string("certificate", sizeof(cert), &params, cert, &cert_len);

        char* cert_hash_hex = NULL;
        if (cert_len > 0) {
            uint8_t cert_hash[SHA256_LEN];
            JADE_WALLY_VERIFY(wally_sha256((unsigned char*)cert, cert_len, cert_hash, sizeof(cert_hash)));
            JADE_WALLY_VERIFY(wally_hex_from_bytes(cert_hash, sizeof(cert_hash), &cert_hash_hex));
            jade_process_call_on_exit(process, wally_free_string_wrapper, cert_hash_hex);
        }

        gui_activity_t* activity;
        make_confirm_pinserver_certificate_activity(&activity, cert_hash_hex);
        JADE_ASSERT(activity);
        gui_set_current_activity(activity);

        int32_t ev_id;
        // In a debug unattended ci build, assume 'confirm' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_PINSERVER_DETAILS_CONFIRM;
#endif
        if (!ret || ev_id != BTN_PINSERVER_DETAILS_CONFIRM) {
            JADE_LOGW("User declined to confirm pinserver certificate");
            jade_process_reject_message(
                process, CBOR_RPC_USER_CANCELLED, "User did not confirm PinServer certificate", NULL);
            goto cleanup;
        }
    } else if (reset_certificate) {
        if (!await_yesno_activity("Certificate", "Reset pin-server certificate?")) {
            JADE_LOGW("User declined to confirm resetting pinserver certificate");
            jade_process_reject_message(
                process, CBOR_RPC_USER_CANCELLED, "User did not confirm resetting PinServer certificate", NULL);
            goto cleanup;
        }
    }

    // Ok, now user confirmed actions, actually set the pinserver details in storage
    if (urlA_len) {
        JADE_LOGI("Setting user pinserver details");
        if (!storage_set_pinserver_details(urlA, urlB, pubkey, pubkey_len)) {
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to persist pinserver details", NULL);
            goto cleanup;
        }
    } else if (reset_details) {
        JADE_LOGI("Erasing user pinserver details - resetting to default");
        if (!storage_erase_pinserver_details()) {
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to erase pinserver details", NULL);
            goto cleanup;
        }
    }

    if (set_certificate) {
        JADE_LOGI("Setting user pinserver certificate");
        if (!storage_set_pinserver_cert(cert)) {
            jade_process_reject_message(
                process, CBOR_RPC_INTERNAL_ERROR, "Failed to persist pinserver certificate", NULL);
            goto cleanup;
        }
    } else if (reset_certificate) {
        JADE_LOGI("Erasing user pinserver certificate - resetting to default");
        if (!storage_erase_pinserver_cert()) {
            jade_process_reject_message(
                process, CBOR_RPC_INTERNAL_ERROR, "Failed to erase pinserver certificate", NULL);
            goto cleanup;
        }
    }

    // Reply ok
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    return;
}
